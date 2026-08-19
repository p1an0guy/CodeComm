// Package endpointservice publishes the local device's signed endpoint set.
package endpointservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const refreshTimeout = 5 * time.Second

var (
	ErrInvalidOptions = errors.New(
		"endpoint service: invalid options",
	)
	ErrInvalidRefresh = errors.New(
		"endpoint service: invalid refresh",
	)
	ErrInvalidClock = errors.New(
		"endpoint service: invalid clock",
	)
	ErrClosed = errors.New(
		"endpoint service: closed",
	)
)

// LocalState is the local durable boundary needed by the publisher.
// AllocateOwnEndpointSequence must persist the returned sequence before
// returning it.
type LocalState interface {
	AllocateOwnEndpointSequence(
		context.Context,
		domain.DeviceID,
		domain.Timestamp,
	) (uint64, error)
}

// Options binds one publisher to an immutable session generation and device
// identity. The service owns a private clone of IdentityPrivateKey.
type Options struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	DeviceID           domain.DeviceID
	IdentityPrivateKey []byte
	LocalState         LocalState
}

// RefreshInput is one applied-policy and selected-listener snapshot.
// SelectedListeners may include link-local listeners; those are deliberately
// omitted because signed endpoint sets are portable and carry no interface
// binding. Every remaining listener must use the same port.
type RefreshInput struct {
	AdvertisementInterval time.Duration
	SelectedListeners     []netip.AddrPort
}

type serviceOptions struct {
	Options
	now              func() time.Time
	operationTimeout time.Duration
}

// Service serializes publication so a slower refresh cannot replace a newer
// endpoint set. It borrows LocalState and owns all other retained material.
type Service struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	deviceID           domain.DeviceID
	identityPrivateKey []byte
	localState         LocalState

	now              func() time.Time
	operationTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	lifecycleMu sync.Mutex
	closed      bool
	operations  sync.WaitGroup
	closeOnce   sync.Once
	releaseOnce sync.Once

	refreshToken chan struct{}

	publicationMu sync.RWMutex
	current       []byte
}

// New validates the immutable binding without performing storage I/O.
func New(options Options) (*Service, error) {
	return newService(serviceOptions{
		Options:          options,
		now:              time.Now,
		operationTimeout: refreshTimeout,
	})
}

func newService(options serviceOptions) (*Service, error) {
	if !options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(options.RecoveryGeneration) ||
		!options.DeviceID.Valid() ||
		nilInterface(options.LocalState) ||
		options.now == nil ||
		options.operationTimeout <= 0 {
		return nil, ErrInvalidOptions
	}

	privateKey := bytes.Clone(options.IdentityPrivateKey)
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		clear(privateKey)
		return nil, fmt.Errorf("%w: identity key: %v", ErrInvalidOptions, err)
	}
	derivedDeviceID, err := device.DeriveID(ed25519.PublicKey(publicKey))
	clear(publicKey)
	if err != nil || derivedDeviceID != options.DeviceID {
		clear(privateKey)
		return nil, fmt.Errorf(
			"%w: identity key does not match device",
			ErrInvalidOptions,
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	service := &Service{
		sessionID:          options.SessionID,
		workspaceID:        options.WorkspaceID,
		recoveryGeneration: options.RecoveryGeneration,
		deviceID:           options.DeviceID,
		identityPrivateKey: privateKey,
		localState:         options.LocalState,
		now:                options.now,
		operationTimeout:   options.operationTimeout,
		ctx:                ctx,
		cancel:             cancel,
		refreshToken:       make(chan struct{}, 1),
	}
	service.refreshToken <- struct{}{}
	return service, nil
}

// Refresh persists a fresh sequence, signs the complete endpoint set, and
// atomically replaces the current publication. Any error leaves the last
// valid publication unchanged.
func (service *Service) Refresh(
	ctx context.Context,
	input RefreshInput,
) error {
	operationCtx, finish, err := service.beginOperation(ctx)
	if err != nil {
		return err
	}
	defer finish()

	select {
	case <-operationCtx.Done():
		return service.contextError(operationCtx.Err())
	case <-service.refreshToken:
	}
	defer func() {
		service.refreshToken <- struct{}{}
	}()
	if err := operationCtx.Err(); err != nil {
		return service.contextError(err)
	}

	signer, endpoints, err := prepareRefresh(input)
	if err != nil {
		return err
	}
	observedAt, issuedAt, expiresAt, err := publicationTimes(
		service.now(),
		input.AdvertisementInterval,
	)
	if err != nil {
		return err
	}
	sequence, err := service.localState.AllocateOwnEndpointSequence(
		operationCtx,
		service.deviceID,
		observedAt,
	)
	if err != nil {
		if contextErr := operationCtx.Err(); contextErr != nil {
			return service.contextError(contextErr)
		}
		return fmt.Errorf(
			"endpoint service: allocate endpoint sequence: %w",
			err,
		)
	}
	if err := operationCtx.Err(); err != nil {
		return service.contextError(err)
	}

	canonical, err := signer.Sign(
		discovery.EndpointSet{
			SessionID:          service.sessionID,
			WorkspaceID:        service.workspaceID,
			RecoveryGeneration: service.recoveryGeneration,
			DeviceID:           service.deviceID,
			EndpointSequence:   sequence,
			IssuedAt:           issuedAt,
			ExpiresAt:          expiresAt,
			Endpoints:          endpoints,
		},
		service.identityPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("endpoint service: sign endpoint set: %w", err)
	}
	defer clear(canonical)
	if err := operationCtx.Err(); err != nil {
		return service.contextError(err)
	}

	service.lifecycleMu.Lock()
	defer service.lifecycleMu.Unlock()
	if service.closed {
		return ErrClosed
	}
	if err := operationCtx.Err(); err != nil {
		return service.contextErrorLocked(err)
	}
	service.publicationMu.Lock()
	old := service.current
	service.current = bytes.Clone(canonical)
	service.publicationMu.Unlock()
	clear(old)
	return nil
}

// CurrentEndpointSet returns a private copy of the exact current signed JCS
// object. A closed or not-yet-published service reports no value.
func (service *Service) CurrentEndpointSet() ([]byte, bool) {
	if service == nil {
		return nil, false
	}
	service.lifecycleMu.Lock()
	closed := service.closed
	service.lifecycleMu.Unlock()
	if closed {
		return nil, false
	}
	service.publicationMu.RLock()
	current := bytes.Clone(service.current)
	service.publicationMu.RUnlock()
	if len(current) == 0 {
		return nil, false
	}
	return current, true
}

// BeginClose prevents new refreshes and cancels in-flight work.
func (service *Service) BeginClose() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.closeOnce.Do(func() {
		service.lifecycleMu.Lock()
		service.closed = true
		service.cancel()
		service.lifecycleMu.Unlock()
	})
	return nil
}

// Wait closes the service, joins in-flight refreshes, and clears owned keys.
func (service *Service) Wait() error {
	if service == nil {
		return ErrInvalidOptions
	}
	if err := service.BeginClose(); err != nil {
		return err
	}
	service.operations.Wait()
	service.releaseOnce.Do(func() {
		service.publicationMu.Lock()
		clear(service.current)
		service.current = nil
		service.publicationMu.Unlock()

		service.lifecycleMu.Lock()
		clear(service.identityPrivateKey)
		service.identityPrivateKey = nil
		service.localState = nil
		service.now = nil
		service.ctx = nil
		service.cancel = nil
		service.refreshToken = nil
		service.sessionID = ""
		service.workspaceID = ""
		service.recoveryGeneration = 0
		service.deviceID = ""
		service.lifecycleMu.Unlock()
	})
	return nil
}

// Close performs both shutdown phases.
func (service *Service) Close() error {
	return service.Wait()
}

func (service *Service) beginOperation(
	ctx context.Context,
) (context.Context, func(), error) {
	if service == nil || ctx == nil {
		return nil, nil, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	service.lifecycleMu.Lock()
	if service.closed {
		service.lifecycleMu.Unlock()
		return nil, nil, ErrClosed
	}
	service.operations.Add(1)
	serviceContext := service.ctx
	timeout := service.operationTimeout
	service.lifecycleMu.Unlock()

	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	stopCloseCancellation := context.AfterFunc(serviceContext, cancel)
	finish := func() {
		stopCloseCancellation()
		cancel()
		service.operations.Done()
	}
	if err := operationCtx.Err(); err != nil {
		finish()
		return nil, nil, service.contextError(err)
	}
	return operationCtx, finish, nil
}

func (service *Service) contextError(err error) error {
	service.lifecycleMu.Lock()
	defer service.lifecycleMu.Unlock()
	return service.contextErrorLocked(err)
}

func (service *Service) contextErrorLocked(err error) error {
	if service.closed && errors.Is(err, context.Canceled) {
		return ErrClosed
	}
	return err
}

func prepareRefresh(
	input RefreshInput,
) (*discovery.EndpointSigner, []discovery.Endpoint, error) {
	if len(input.SelectedListeners) == 0 {
		return nil, nil, ErrInvalidRefresh
	}
	listeners := slices.Clone(input.SelectedListeners)
	port := listeners[0].Port()
	if port == 0 {
		return nil, nil, ErrInvalidRefresh
	}
	selectedAddresses := make(
		[]netip.Addr,
		0,
		len(listeners),
	)
	for _, listener := range listeners {
		if listener.Port() != port {
			return nil, nil, fmt.Errorf(
				"%w: selected listeners use different ports",
				ErrInvalidRefresh,
			)
		}
		address := listener.Addr()
		if address.IsLinkLocalUnicast() {
			continue
		}
		selectedAddresses = append(selectedAddresses, address)
	}
	if len(selectedAddresses) == 0 {
		return nil, nil, fmt.Errorf(
			"%w: no non-link-local selected listener",
			ErrInvalidRefresh,
		)
	}
	signer, err := discovery.NewEndpointSigner(
		input.AdvertisementInterval,
		port,
		selectedAddresses,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: endpoint signer: %w",
			ErrInvalidRefresh,
			err,
		)
	}
	slices.SortFunc(selectedAddresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	endpoints := make([]discovery.Endpoint, len(selectedAddresses))
	for index, address := range selectedAddresses {
		endpoints[index] = discovery.Endpoint{
			IP:   address,
			Port: port,
		}
	}
	return signer, endpoints, nil
}

func publicationTimes(
	now time.Time,
	advertisementInterval time.Duration,
) (
	domain.Timestamp,
	domain.WholeSecondTimestamp,
	domain.WholeSecondTimestamp,
	error,
) {
	if now.IsZero() {
		return "", "", "", ErrInvalidClock
	}
	now = now.UTC()
	milliseconds := now.UnixMilli()
	if milliseconds < 0 ||
		uint64(milliseconds) > domain.MaxSafeInteger {
		return "", "", "", ErrInvalidClock
	}
	observedAt, err := domain.ParseTimestamp(
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return "", "", "", ErrInvalidClock
	}
	issuedTime := now.Truncate(time.Second)
	issuedAt, err := domain.ParseWholeSecondTimestamp(
		issuedTime.Format(time.RFC3339),
	)
	if err != nil {
		return "", "", "", ErrInvalidClock
	}
	expiresAt, err := domain.ParseWholeSecondTimestamp(
		issuedTime.Add(
			discovery.EndpointHintTTLIntervals *
				advertisementInterval,
		).Format(time.RFC3339),
	)
	if err != nil {
		return "", "", "", ErrInvalidClock
	}
	return observedAt, issuedAt, expiresAt, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
