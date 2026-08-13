package credentialstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unicode"

	codecrypto "github.com/ijonahch/codecomm/internal/crypto"
)

// MaxSecretBytes stays below every supported native provider's payload limit.
const MaxSecretBytes = 1024

var (
	ErrInvalidBackend = errors.New("credentialstore: invalid backend")
	ErrInvalidContext = errors.New("credentialstore: invalid context")
	ErrInvalidSecret  = errors.New("credentialstore: invalid secret")
	ErrClosed         = errors.New("credentialstore: store closed")
	ErrNotFound       = errors.New("credentialstore: secret not found")
	ErrAlreadyExists  = errors.New("credentialstore: secret already exists")
	ErrLocked         = errors.New("credentialstore: provider locked")
	ErrUnavailable    = errors.New("credentialstore: provider unavailable")
	ErrAccessDenied   = errors.New("credentialstore: access denied")
	ErrUnreadable     = errors.New("credentialstore: provider unreadable")
	ErrCorrupt        = errors.New("credentialstore: corrupt secret")
)

// backend is implemented only by closed native adapters and same-package test
// doubles. Production callers can obtain a Store only through OpenNative.
type backend interface {
	Name() string
	// Get returns a caller-owned buffer. Create consumes value synchronously
	// and must not retain or mutate it after returning.
	Get(context.Context, string) ([]byte, error)
	Create(context.Context, string, []byte) error
	Delete(context.Context, string) error
	Close() error
}

// Store validates all values and normalizes provider failures.
type Store struct {
	backend backend

	mu       sync.RWMutex
	closed   bool
	closeErr error
}

func newStore(backend backend) (*Store, error) {
	if nilInterface(backend) || !validProviderName(backend.Name()) {
		return nil, ErrInvalidBackend
	}
	return &Store{backend: backend}, nil
}

// Provider returns the stable native-provider name.
func (store *Store) Provider() string {
	if store == nil || nilInterface(store.backend) {
		return ""
	}
	return store.backend.Name()
}

// Get retrieves a nonempty bounded secret and returns a private copy.
func (store *Store) Get(ctx context.Context, reference Reference) ([]byte, error) {
	selectedBackend, release, err := store.acquire(ctx, reference)
	if err != nil {
		return nil, err
	}
	defer release()

	value, err := selectedBackend.Get(ctx, reference.key)
	if err != nil {
		return nil, store.operationError("read", reference, err)
	}
	if err := ctx.Err(); err != nil {
		clear(value)
		return nil, store.operationError("read", reference, err)
	}
	if len(value) < 1 || len(value) > MaxSecretBytes {
		length := len(value)
		clear(value)
		return nil, store.operationError(
			"read",
			reference,
			fmt.Errorf("%w: got %d bytes", ErrCorrupt, length),
		)
	}
	if _, err := codecrypto.Ed25519PublicKeyFromPrivateKey(value); err != nil {
		clear(value)
		return nil, store.operationError(
			"read",
			reference,
			fmt.Errorf("%w: %w", ErrCorrupt, err),
		)
	}
	result := append([]byte(nil), value...)
	clear(value)
	return result, nil
}

// Create stores a private copy of one nonempty bounded secret. Native backends
// must atomically return ErrAlreadyExists instead of replacing any value.
func (store *Store) Create(ctx context.Context, reference Reference, value []byte) error {
	selectedBackend, release, err := store.acquire(ctx, reference)
	if err != nil {
		return err
	}
	defer release()

	if len(value) < 1 || len(value) > MaxSecretBytes {
		return fmt.Errorf(
			"%w: got %d bytes, want 1..%d",
			ErrInvalidSecret,
			len(value),
			MaxSecretBytes,
		)
	}
	if _, err = codecrypto.Ed25519PublicKeyFromPrivateKey(value); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSecret, err)
	}
	ownedValue := append([]byte(nil), value...)
	defer clear(ownedValue)
	if err = selectedBackend.Create(ctx, reference.key, ownedValue); err != nil {
		return store.operationError("create", reference, err)
	}
	if err := ctx.Err(); err != nil {
		return store.operationError("create", reference, err)
	}
	return nil
}

// Delete erases a reference. Repeating an already completed erasure succeeds.
func (store *Store) Delete(ctx context.Context, reference Reference) error {
	selectedBackend, release, err := store.acquire(ctx, reference)
	if err != nil {
		return err
	}
	defer release()

	if err = selectedBackend.Delete(ctx, reference.key); err != nil && !errors.Is(err, ErrNotFound) {
		return store.operationError("delete", reference, err)
	}
	return ctx.Err()
}

// Close releases native provider resources. It is idempotent; later
// operations return ErrClosed.
func (store *Store) Close() error {
	if store == nil || nilInterface(store.backend) {
		return ErrInvalidBackend
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return store.closeErr
	}
	store.closed = true
	if err := store.backend.Close(); err != nil {
		store.closeErr = store.operationError(
			"close",
			Reference{kind: KindIdentity},
			err,
		)
	}
	return store.closeErr
}

func (store *Store) acquire(
	ctx context.Context,
	reference Reference,
) (backend, func(), error) {
	if store == nil || nilInterface(store.backend) {
		return nil, nil, ErrInvalidBackend
	}
	if err := reference.Validate(); err != nil {
		return nil, nil, err
	}
	if ctx == nil {
		return nil, nil, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return nil, nil, ErrClosed
	}
	return store.backend, store.mu.RUnlock, nil
}

func (store *Store) operationError(operation string, reference Reference, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf(
			"credentialstore: %s %s with %s: %w",
			operation,
			reference.kind,
			store.backend.Name(),
			err,
		)
	}
	if !canonicalBackendError(err) {
		err = fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return fmt.Errorf(
		"credentialstore: %s %s with %s: %w",
		operation,
		reference.kind,
		store.backend.Name(),
		err,
	)
}

func canonicalBackendError(err error) bool {
	for _, candidate := range []error{
		ErrNotFound,
		ErrAlreadyExists,
		ErrLocked,
		ErrUnavailable,
		ErrAccessDenied,
		ErrUnreadable,
		ErrCorrupt,
	} {
		if errors.Is(err, candidate) {
			return true
		}
	}
	return false
}

func validProviderName(name string) bool {
	if name == "" || len(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for _, character := range name {
		if character > unicode.MaxASCII || unicode.IsControl(character) {
			return false
		}
	}
	return true
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
