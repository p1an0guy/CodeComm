//go:build linux

package credentialstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	linuxProvider         = "linux-secret-service"
	secretServiceName     = "org.freedesktop.secrets"
	secretServicePath     = dbus.ObjectPath("/org/freedesktop/secrets")
	defaultCollectionPath = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	mutationLockName      = "dev.codecomm.CredentialStore.MutationLock.v1"
	codeCommService       = "dev.codecomm.credentials.v1"
	secretContentType     = "application/octet-stream"
	openNativeTimeout     = 5 * time.Second
	mutationLockRetry     = 20 * time.Millisecond
)

const (
	dbusServiceName = "org.freedesktop.DBus"
	dbusServicePath = dbus.ObjectPath("/org/freedesktop/DBus")

	propertiesGet  = "org.freedesktop.DBus.Properties.Get"
	nameHasOwner   = "org.freedesktop.DBus.NameHasOwner"
	requestName    = "org.freedesktop.DBus.RequestName"
	releaseName    = "org.freedesktop.DBus.ReleaseName"
	openSession    = "org.freedesktop.Secret.Service.OpenSession"
	searchItems    = "org.freedesktop.Secret.Collection.SearchItems"
	createItem     = "org.freedesktop.Secret.Collection.CreateItem"
	getSecret      = "org.freedesktop.Secret.Item.GetSecret"
	deleteItem     = "org.freedesktop.Secret.Item.Delete"
	closeSession   = "org.freedesktop.Secret.Session.Close"
	collectionKind = "org.freedesktop.Secret.Collection"
	itemKind       = "org.freedesktop.Secret.Item"
)

type linuxBus interface {
	call(context.Context, string, dbus.ObjectPath, string, dbus.Flags, ...any) ([]any, error)
	close() error
}

type godbusLinuxBus struct {
	connection *dbus.Conn
}

func (bus *godbusLinuxBus) call(
	ctx context.Context,
	destination string,
	path dbus.ObjectPath,
	method string,
	flags dbus.Flags,
	args ...any,
) ([]any, error) {
	call := bus.connection.Object(destination, path).CallWithContext(ctx, method, flags, args...)
	return call.Body, call.Err
}

func (bus *godbusLinuxBus) close() error {
	return bus.connection.Close()
}

type linuxSecretService struct {
	bus linuxBus

	mutationOnce sync.Once
	mutationGate chan struct{}
}

type linuxSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func nativeProviderName() string {
	return linuxProvider
}

// OpenNative opens the existing same-user Secret Service without starting a
// bus, service, collection, unlock flow, or prompt.
func OpenNative(parent context.Context) (*Store, error) {
	if err := linuxContextError(parent); err != nil {
		return nil, err
	}
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if address != "" && !localUnixBusAddress(address) {
		return nil, fmt.Errorf("%w: session bus is not local Unix transport", ErrUnavailable)
	}

	connection, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return nil, fmt.Errorf("%w: connect to existing session bus: %v", ErrUnavailable, err)
	}
	fail := func(cause error) (*Store, error) {
		_ = connection.Close()
		return nil, cause
	}
	if !localUnixBusAddress(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) {
		return fail(fmt.Errorf("%w: session bus is not local Unix transport", ErrUnavailable))
	}
	if err := connection.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}); err != nil {
		return fail(fmt.Errorf("%w: authenticate same-user session bus: %v", ErrAccessDenied, err))
	}
	if err := connection.Hello(); err != nil {
		return fail(fmt.Errorf("%w: enter existing session bus: %v", ErrUnavailable, err))
	}

	backend := &linuxSecretService{bus: &godbusLinuxBus{connection: connection}}
	ctx, cancel := context.WithTimeout(parent, openNativeTimeout)
	defer cancel()
	if err := backend.ready(ctx); err != nil {
		return fail(err)
	}
	store, err := newStore(backend)
	if err != nil {
		return fail(err)
	}
	return store, nil
}

func (service *linuxSecretService) Name() string {
	return linuxProvider
}

func (service *linuxSecretService) Close() error {
	return service.bus.close()
}

func (service *linuxSecretService) Get(ctx context.Context, account string) ([]byte, error) {
	if err := linuxContextError(ctx); err != nil {
		return nil, err
	}
	if err := service.ready(ctx); err != nil {
		return nil, err
	}
	items, err := service.find(ctx, account)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	session, err := service.openPlainSession(ctx)
	if err != nil {
		return nil, err
	}
	defer service.closePlainSession(session)

	body, err := service.secretCall(ctx, items[0], getSecret, session)
	if err != nil {
		return nil, classifyLinuxError(err, ErrNotFound)
	}
	var secret linuxSecret
	if err := storeBody(body, &secret); err != nil ||
		secret.Session != session ||
		len(secret.Parameters) != 0 ||
		secret.ContentType != secretContentType {
		return nil, fmt.Errorf("%w: malformed GetSecret response", ErrCorrupt)
	}
	result := append([]byte(nil), secret.Value...)
	clear(secret.Value)
	return result, nil
}

func (service *linuxSecretService) Create(
	ctx context.Context,
	account string,
	value []byte,
) (result error) {
	releaseLocal, err := service.acquireLocalMutation(ctx)
	if err != nil {
		return err
	}
	defer releaseLocal()

	releaseBus, err := service.acquireMutationLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, releaseBus())
	}()

	if err := service.ready(ctx); err != nil {
		return err
	}
	items, err := service.find(ctx, account)
	if err != nil {
		return err
	}
	if len(items) != 0 {
		return ErrAlreadyExists
	}

	session, err := service.openPlainSession(ctx)
	if err != nil {
		return err
	}
	defer service.closePlainSession(session)

	properties := map[string]dbus.Variant{
		itemKind + ".Label": dbus.MakeVariant("CodeComm " + account),
		itemKind + ".Attributes": dbus.MakeVariant(map[string]string{
			"service": codeCommService,
			"account": account,
		}),
	}
	secret := linuxSecret{
		Session:     session,
		Parameters:  []byte{},
		Value:       append([]byte(nil), value...),
		ContentType: secretContentType,
	}
	defer clear(secret.Value)
	body, err := service.secretCall(
		ctx,
		defaultCollectionPath,
		createItem,
		properties,
		secret,
		false,
	)
	if err != nil {
		return classifyLinuxError(err, ErrUnreadable)
	}
	var item, prompt dbus.ObjectPath
	if err := storeBody(body, &item, &prompt); err != nil {
		return fmt.Errorf("%w: malformed CreateItem response", ErrCorrupt)
	}
	if prompt != "/" {
		return fmt.Errorf("%w: CreateItem requires an interactive prompt", ErrAccessDenied)
	}
	if !usableObjectPath(item) {
		return fmt.Errorf("%w: malformed CreateItem response", ErrCorrupt)
	}
	return nil
}

func (service *linuxSecretService) Delete(
	ctx context.Context,
	account string,
) (result error) {
	releaseLocal, err := service.acquireLocalMutation(ctx)
	if err != nil {
		return err
	}
	defer releaseLocal()

	releaseBus, err := service.acquireMutationLock(ctx)
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, releaseBus())
	}()

	if err := service.ready(ctx); err != nil {
		return err
	}
	items, err := service.find(ctx, account)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return ErrNotFound
	}
	body, err := service.secretCall(ctx, items[0], deleteItem)
	if err != nil {
		return classifyLinuxError(err, ErrNotFound)
	}
	var prompt dbus.ObjectPath
	if err := storeBody(body, &prompt); err != nil {
		return fmt.Errorf("%w: malformed Delete response", ErrCorrupt)
	}
	if prompt != "/" {
		return fmt.Errorf("%w: Delete requires an interactive prompt", ErrAccessDenied)
	}
	return nil
}

func (service *linuxSecretService) ready(ctx context.Context) error {
	if err := linuxContextError(ctx); err != nil {
		return err
	}
	body, err := service.bus.call(
		ctx,
		dbusServiceName,
		dbusServicePath,
		nameHasOwner,
		0,
		secretServiceName,
	)
	if err != nil {
		return classifyLinuxError(err, ErrUnavailable)
	}
	var owned bool
	if err := storeBody(body, &owned); err != nil {
		return fmt.Errorf("%w: malformed NameHasOwner response", ErrCorrupt)
	}
	if !owned {
		return fmt.Errorf("%w: Secret Service is not running", ErrUnavailable)
	}
	return service.unlocked(ctx, defaultCollectionPath, collectionKind, ErrUnavailable)
}

func (service *linuxSecretService) unlocked(
	ctx context.Context,
	path dbus.ObjectPath,
	objectKind string,
	missing error,
) error {
	body, err := service.secretCall(ctx, path, propertiesGet, objectKind, "Locked")
	if err != nil {
		return classifyLinuxError(err, missing)
	}
	var property dbus.Variant
	if err := storeBody(body, &property); err != nil {
		return fmt.Errorf("%w: malformed Locked property response", ErrCorrupt)
	}
	locked, ok := property.Value().(bool)
	if !ok {
		return fmt.Errorf("%w: Locked property is not boolean", ErrCorrupt)
	}
	if locked {
		return ErrLocked
	}
	return nil
}

func (service *linuxSecretService) find(
	ctx context.Context,
	account string,
) ([]dbus.ObjectPath, error) {
	attributes := map[string]string{
		"service": codeCommService,
		"account": account,
	}
	body, err := service.secretCall(ctx, defaultCollectionPath, searchItems, attributes)
	if err != nil {
		return nil, classifyLinuxError(err, ErrUnavailable)
	}
	var items []dbus.ObjectPath
	if err := storeBody(body, &items); err != nil {
		return nil, fmt.Errorf("%w: malformed SearchItems response", ErrCorrupt)
	}
	if len(items) > 1 {
		return nil, fmt.Errorf("%w: %d items match one account", ErrCorrupt, len(items))
	}
	if len(items) == 1 && !usableObjectPath(items[0]) {
		return nil, fmt.Errorf("%w: invalid item path", ErrCorrupt)
	}
	if len(items) == 1 {
		if err := service.unlocked(ctx, items[0], itemKind, ErrNotFound); err != nil {
			return nil, err
		}
		exact, err := service.exactAttributes(ctx, items[0], attributes)
		if err != nil {
			return nil, err
		}
		if !exact {
			return nil, fmt.Errorf("%w: item attributes are not exact", ErrCorrupt)
		}
	}
	return items, nil
}

func (service *linuxSecretService) exactAttributes(
	ctx context.Context,
	item dbus.ObjectPath,
	want map[string]string,
) (bool, error) {
	body, err := service.secretCall(ctx, item, propertiesGet, itemKind, "Attributes")
	if err != nil {
		return false, classifyLinuxError(err, ErrNotFound)
	}
	var property dbus.Variant
	if err := storeBody(body, &property); err != nil {
		return false, fmt.Errorf("%w: malformed Attributes response", ErrCorrupt)
	}
	got, ok := property.Value().(map[string]string)
	if !ok || len(got) != len(want) {
		return false, nil
	}
	for key, value := range want {
		if got[key] != value {
			return false, nil
		}
	}
	return true, nil
}

func (service *linuxSecretService) openPlainSession(
	ctx context.Context,
) (dbus.ObjectPath, error) {
	body, err := service.secretCall(
		ctx,
		secretServicePath,
		openSession,
		"plain",
		dbus.MakeVariant(""),
	)
	if err != nil {
		return "", classifyLinuxError(err, ErrUnavailable)
	}
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := storeBody(body, &output, &session); err != nil ||
		output.Value() != "" ||
		!usableObjectPath(session) {
		return "", fmt.Errorf("%w: malformed OpenSession response", ErrCorrupt)
	}
	return session, nil
}

func (service *linuxSecretService) closePlainSession(session dbus.ObjectPath) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = service.secretCall(ctx, session, closeSession)
}

func (service *linuxSecretService) secretCall(
	ctx context.Context,
	path dbus.ObjectPath,
	method string,
	args ...any,
) ([]any, error) {
	return service.bus.call(
		ctx,
		secretServiceName,
		path,
		method,
		dbus.FlagNoAutoStart,
		args...,
	)
}

func (service *linuxSecretService) acquireLocalMutation(
	ctx context.Context,
) (func(), error) {
	if err := linuxContextError(ctx); err != nil {
		return nil, err
	}
	service.mutationOnce.Do(func() {
		service.mutationGate = make(chan struct{}, 1)
		service.mutationGate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-service.mutationGate:
		return func() {
			service.mutationGate <- struct{}{}
		}, nil
	}
}

func (service *linuxSecretService) acquireMutationLock(
	ctx context.Context,
) (func() error, error) {
	if err := linuxContextError(ctx); err != nil {
		return nil, err
	}
	for {
		body, err := service.bus.call(
			ctx,
			dbusServiceName,
			dbusServicePath,
			requestName,
			0,
			mutationLockName,
			uint32(dbus.NameFlagDoNotQueue),
		)
		if err != nil {
			return nil, classifyLinuxError(err, ErrUnavailable)
		}
		var raw uint32
		if err := storeBody(body, &raw); err != nil {
			return nil, fmt.Errorf("%w: malformed RequestName response", ErrCorrupt)
		}
		reply := dbus.RequestNameReply(raw)
		switch reply {
		case dbus.RequestNameReplyPrimaryOwner, dbus.RequestNameReplyAlreadyOwner:
			return service.releaseMutationLock, nil
		case dbus.RequestNameReplyExists:
			timer := time.NewTimer(mutationLockRetry)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		default:
			return nil, fmt.Errorf("%w: unexpected RequestName reply %d", ErrUnreadable, raw)
		}
	}
}

func (service *linuxSecretService) releaseMutationLock() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	body, err := service.bus.call(
		ctx,
		dbusServiceName,
		dbusServicePath,
		releaseName,
		0,
		mutationLockName,
	)
	if err != nil {
		return classifyLinuxError(err, ErrUnavailable)
	}
	var raw uint32
	if err := storeBody(body, &raw); err != nil {
		return fmt.Errorf("%w: malformed ReleaseName response", ErrCorrupt)
	}
	if dbus.ReleaseNameReply(raw) != dbus.ReleaseNameReplyReleased {
		return fmt.Errorf("%w: unexpected ReleaseName reply %d", ErrUnreadable, raw)
	}
	return nil
}

func classifyLinuxError(err, missing error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, dbus.ErrClosed) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: session bus disconnected: %w", ErrUnavailable, err)
	}
	name := dbusErrorName(err)
	switch name {
	case "org.freedesktop.DBus.Error.ServiceUnknown",
		"org.freedesktop.DBus.Error.NameHasNoOwner",
		"org.freedesktop.DBus.Error.Disconnected",
		"org.freedesktop.DBus.Error.NoServer",
		"org.freedesktop.DBus.Error.FileNotFound":
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case "org.freedesktop.DBus.Error.AccessDenied",
		"org.freedesktop.DBus.Error.AuthFailed",
		"org.freedesktop.DBus.Error.InteractiveAuthorizationRequired":
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	case "org.freedesktop.Secret.Error.IsLocked":
		return fmt.Errorf("%w: %w", ErrLocked, err)
	case "org.freedesktop.Secret.Error.NoSuchObject",
		"org.freedesktop.DBus.Error.UnknownObject":
		return fmt.Errorf("%w: %w", missing, err)
	case "org.freedesktop.DBus.Error.InvalidArgs",
		"org.freedesktop.DBus.Error.InvalidSignature":
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	default:
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
}

func linuxContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	return ctx.Err()
}

func dbusErrorName(err error) string {
	var pointer *dbus.Error
	if errors.As(err, &pointer) {
		return pointer.Name
	}
	var value dbus.Error
	if errors.As(err, &value) {
		return value.Name
	}
	return ""
}

func storeBody(body []any, destinations ...any) error {
	if len(body) != len(destinations) {
		return fmt.Errorf("got %d values, want %d", len(body), len(destinations))
	}
	return dbus.Store(body, destinations...)
}

func localUnixBusAddress(address string) bool {
	if address == "" || address == "autolaunch:" {
		return false
	}
	for _, candidate := range strings.Split(address, ";") {
		if !strings.HasPrefix(candidate, "unix:") {
			return false
		}
	}
	return true
}

func usableObjectPath(path dbus.ObjectPath) bool {
	return path != "" && path != "/" && path.IsValid()
}
