package credentialstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"
)

type fakeBackend struct {
	name        string
	values      map[string][]byte
	getErr      error
	createErr   error
	deleteErr   error
	getCalls    int
	createCalls int
	deleteCalls int
	closeCalls  int
	lastCreate  []byte
	onGet       func()
	closeErr    error
}

func (backend *fakeBackend) Name() string {
	return backend.name
}

func (backend *fakeBackend) Get(_ context.Context, key string) ([]byte, error) {
	backend.getCalls++
	if backend.getErr != nil {
		return nil, backend.getErr
	}
	if backend.onGet != nil {
		backend.onGet()
	}
	value, found := backend.values[key]
	if !found {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (backend *fakeBackend) Create(_ context.Context, key string, value []byte) error {
	backend.createCalls++
	backend.lastCreate = append([]byte(nil), value...)
	if backend.createErr != nil {
		return backend.createErr
	}
	if backend.values == nil {
		backend.values = make(map[string][]byte)
	}
	if _, found := backend.values[key]; found {
		return ErrAlreadyExists
	}
	backend.values[key] = append([]byte(nil), value...)
	return nil
}

func (backend *fakeBackend) Delete(_ context.Context, key string) error {
	backend.deleteCalls++
	if backend.deleteErr != nil {
		return backend.deleteErr
	}
	if _, found := backend.values[key]; !found {
		return ErrNotFound
	}
	delete(backend.values, key)
	return nil
}

func (backend *fakeBackend) Close() error {
	backend.closeCalls++
	return backend.closeErr
}

func TestNewRejectsMissingOrUnnamedBackend(t *testing.T) {
	t.Parallel()

	var typedNil *fakeBackend
	for _, backend := range []backend{nil, typedNil, &fakeBackend{}} {
		store, err := newStore(backend)
		if !errors.Is(err, ErrInvalidBackend) {
			t.Fatalf("newStore(%T) error = %v, want %v", backend, err, ErrInvalidBackend)
		}
		if store != nil {
			t.Fatalf("newStore(%T) = %v after error, want nil", backend, store)
		}
	}
}

func TestStoreCreateAndGetDefensivelyCopySecrets(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test", values: make(map[string][]byte)}
	store := mustStore(t, backend)
	reference := IdentityReference()
	secret := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	want := append([]byte(nil), secret...)

	if err := store.Create(context.Background(), reference, secret); err != nil {
		t.Fatalf("Store.Create() error = %v", err)
	}
	secret[0] = 'x'

	got, err := store.Get(context.Background(), reference)
	if err != nil {
		t.Fatalf("Store.Get() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Store.Get() = %x, want %x", got, want)
	}
	got[0] = 'z'
	if backend.values[reference.key][0] != want[0] {
		t.Fatal("mutating Store.Get() result changed backend value")
	}
}

func TestStoreRejectsInvalidReferenceAndSecretBeforeBackend(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test", values: make(map[string][]byte)}
	store := mustStore(t, backend)

	if _, err := store.Get(context.Background(), Reference{}); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("Store.Get() error = %v, want %v", err, ErrInvalidReference)
	}
	if err := store.Create(context.Background(), Reference{}, []byte("secret")); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("Store.Create(invalid reference) error = %v, want %v", err, ErrInvalidReference)
	}
	if err := store.Create(context.Background(), IdentityReference(), nil); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Store.Create(empty) error = %v, want %v", err, ErrInvalidSecret)
	}
	if err := store.Create(
		context.Background(),
		IdentityReference(),
		make([]byte, ed25519.PrivateKeySize),
	); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Store.Create(inconsistent key) error = %v, want %v", err, ErrInvalidSecret)
	}
	if err := store.Create(
		context.Background(),
		IdentityReference(),
		make([]byte, MaxSecretBytes+1),
	); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("Store.Create(oversize) error = %v, want %v", err, ErrInvalidSecret)
	}
	if err := store.Delete(context.Background(), Reference{}); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("Store.Delete() error = %v, want %v", err, ErrInvalidReference)
	}
	if backend.getCalls != 0 || backend.createCalls != 0 || backend.deleteCalls != 0 {
		t.Fatalf(
			"backend calls = get %d, create %d, delete %d; want zero",
			backend.getCalls,
			backend.createCalls,
			backend.deleteCalls,
		)
	}
}

func TestStoreRejectsCorruptBackendValues(t *testing.T) {
	t.Parallel()

	reference := IdentityReference()
	for _, value := range [][]byte{
		nil,
		make([]byte, ed25519.PrivateKeySize),
		make([]byte, MaxSecretBytes+1),
	} {
		backend := &fakeBackend{
			name:   "test",
			values: map[string][]byte{reference.key: value},
		}
		store := mustStore(t, backend)
		if _, err := store.Get(context.Background(), reference); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Store.Get(%d bytes) error = %v, want %v", len(value), err, ErrCorrupt)
		}
	}
}

func TestStoreClassifiesUnknownBackendErrorsAsUnreadable(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{
		name:      "test",
		getErr:    errors.New("opaque read failure"),
		createErr: errors.New("opaque write failure"),
		deleteErr: errors.New("opaque delete failure"),
	}
	store := mustStore(t, backend)
	reference := IdentityReference()

	if _, err := store.Get(context.Background(), reference); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Store.Get() error = %v, want %v", err, ErrUnreadable)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := store.Create(context.Background(), reference, privateKey); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Store.Create() error = %v, want %v", err, ErrUnreadable)
	}
	if err := store.Delete(context.Background(), reference); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Store.Delete() error = %v, want %v", err, ErrUnreadable)
	}
}

func TestStorePreservesCanonicalBackendFailures(t *testing.T) {
	t.Parallel()

	for _, want := range []error{ErrNotFound, ErrLocked, ErrUnavailable, ErrAccessDenied, ErrUnreadable} {
		backend := &fakeBackend{name: "test", getErr: fmt.Errorf("provider: %w", want)}
		store := mustStore(t, backend)
		_, err := store.Get(context.Background(), IdentityReference())
		if !errors.Is(err, want) {
			t.Errorf("Store.Get() error = %v, want errors.Is(_, %v)", err, want)
		}
	}
}

func TestStoreDeleteIsIdempotent(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test", deleteErr: ErrNotFound}
	store := mustStore(t, backend)
	if err := store.Delete(context.Background(), IdentityReference()); err != nil {
		t.Fatalf("Store.Delete() error = %v, want nil", err)
	}
}

func TestStoreCreateNeverOverwrites(t *testing.T) {
	t.Parallel()

	reference := IdentityReference()
	backend := &fakeBackend{
		name: "test",
		values: map[string][]byte{
			reference.key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		},
	}
	store := mustStore(t, backend)
	replacementSeed := make([]byte, ed25519.SeedSize)
	replacementSeed[0] = 1
	err := store.Create(
		context.Background(),
		reference,
		ed25519.NewKeyFromSeed(replacementSeed),
	)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Store.Create() error = %v, want %v", err, ErrAlreadyExists)
	}
	if bytes.Equal(backend.values[reference.key], ed25519.NewKeyFromSeed(replacementSeed)) {
		t.Fatal("Store.Create() overwrote an existing identity")
	}
}

func TestStorePreservesContextCancellation(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer expire()

	contexts := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "cancelled", ctx: cancelled, want: context.Canceled},
		{name: "deadline", ctx: expired, want: context.DeadlineExceeded},
	}

	for _, test := range contexts {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			backend := &fakeBackend{name: "test"}
			store := mustStore(t, backend)
			if _, err := store.Get(test.ctx, IdentityReference()); !errors.Is(err, test.want) {
				t.Fatalf("Store.Get() error = %v, want %v", err, test.want)
			}
			if backend.getCalls != 0 {
				t.Fatalf("backend get calls = %d, want 0", backend.getCalls)
			}
		})
	}
}

func TestStoreObservesCancellationDuringBackendRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	reference := IdentityReference()
	backend := &fakeBackend{
		name: "test",
		values: map[string][]byte{
			reference.key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		},
		onGet: cancel,
	}
	store := mustStore(t, backend)
	value, err := store.Get(ctx, reference)
	if value != nil {
		t.Fatalf("Store.Get() = %x after cancellation, want nil", value)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Store.Get() error = %v, want %v", err, context.Canceled)
	}
}

func TestStoreCloseIsIdempotentAndPreventsLaterOperations(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test"}
	store := mustStore(t, backend)
	if err := store.Close(); err != nil {
		t.Fatalf("Store.Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Store.Close() error = %v", err)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls = %d, want 1", backend.closeCalls)
	}
	if _, err := store.Get(context.Background(), IdentityReference()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Store.Get() after close error = %v, want %v", err, ErrClosed)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := store.Create(
		context.Background(),
		IdentityReference(),
		privateKey,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("Store.Create() after close error = %v, want %v", err, ErrClosed)
	}
	if err := store.Delete(
		context.Background(),
		IdentityReference(),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("Store.Delete() after close error = %v, want %v", err, ErrClosed)
	}
}

func TestStoreClosePreservesBackendFailure(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close failed")
	backend := &fakeBackend{name: "test", closeErr: closeErr}
	store := mustStore(t, backend)
	for attempt := 0; attempt < 2; attempt++ {
		err := store.Close()
		if !errors.Is(err, closeErr) {
			t.Fatalf("Store.Close() attempt %d error = %v, want %v", attempt+1, err, closeErr)
		}
		if !errors.Is(err, ErrUnreadable) {
			t.Fatalf("Store.Close() attempt %d error = %v, want %v", attempt+1, err, ErrUnreadable)
		}
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls = %d, want 1", backend.closeCalls)
	}
}

func mustStore(t *testing.T, backend backend) *Store {
	t.Helper()
	store, err := newStore(backend)
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	return store
}
