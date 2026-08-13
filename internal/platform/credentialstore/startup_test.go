package credentialstore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestLoadRequiredReturnsSecret(t *testing.T) {
	t.Parallel()

	reference := IdentityReference()
	backend := &fakeBackend{
		name: "test-provider",
		values: map[string][]byte{
			reference.key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		},
	}
	got, err := LoadRequired(context.Background(), mustStore(t, backend), reference)
	if err != nil {
		t.Fatalf("LoadRequired() error = %v", err)
	}
	if len(got) != ed25519.PrivateKeySize {
		t.Fatalf("LoadRequired() returned %d bytes, want %d", len(got), ed25519.PrivateKeySize)
	}
}

func TestLoadRequiredReturnsNonRetryableActionableBlocker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "missing", err: ErrNotFound},
		{name: "locked", err: ErrLocked},
		{name: "unavailable", err: ErrUnavailable},
		{name: "access denied", err: ErrAccessDenied},
		{name: "unreadable", err: ErrUnreadable},
		{name: "corrupt", err: ErrCorrupt},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			backend := &fakeBackend{name: "test-provider", getErr: test.err}
			_, err := LoadRequired(
				context.Background(),
				mustStore(t, backend),
				IdentityReference(),
			)
			if !errors.Is(err, test.err) {
				t.Fatalf("LoadRequired() error = %v, want errors.Is(_, %v)", err, test.err)
			}
			var blocker *StartupError
			if !errors.As(err, &blocker) {
				t.Fatalf("LoadRequired() error type = %T, want *StartupError", err)
			}
			if blocker.Retryable() {
				t.Fatal("StartupError.Retryable() = true, want false")
			}
			if blocker.Provider != "test-provider" || blocker.ReferenceKind != KindIdentity {
				t.Fatalf("StartupError = %+v, want provider and identity kind", blocker)
			}
			if strings.TrimSpace(blocker.Action()) == "" {
				t.Fatal("StartupError.Action() is empty")
			}
			if !strings.Contains(blocker.Error(), "test-provider") ||
				!strings.Contains(blocker.Error(), blocker.Action()) {
				t.Fatalf("StartupError.Error() = %q, want provider and action", blocker.Error())
			}
		})
	}
}

func TestLoadRequiredDoesNotConvertProgrammerErrorsToStartupBlockers(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test-provider"}
	_, err := LoadRequired(context.Background(), mustStore(t, backend), Reference{})
	if !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("LoadRequired() error = %v, want %v", err, ErrInvalidReference)
	}
	var blocker *StartupError
	if errors.As(err, &blocker) {
		t.Fatalf("LoadRequired() returned StartupError for invalid reference: %v", err)
	}
}

func TestLoadRequiredRejectsMalformedEd25519PrivateKey(t *testing.T) {
	t.Parallel()

	reference := IdentityReference()
	backend := &fakeBackend{
		name:   "test-provider",
		values: map[string][]byte{reference.key: []byte("not a private key")},
	}
	_, err := LoadRequired(context.Background(), mustStore(t, backend), reference)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadRequired() error = %v, want %v", err, ErrCorrupt)
	}
	var blocker *StartupError
	if !errors.As(err, &blocker) || blocker.Retryable() {
		t.Fatalf("LoadRequired() error = %v, want non-retryable StartupError", err)
	}
}

func TestLoadRequiredPreservesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := LoadRequired(ctx, mustStore(t, &fakeBackend{name: "test-provider"}), IdentityReference())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadRequired() error = %v, want %v", err, context.Canceled)
	}
	var blocker *StartupError
	if errors.As(err, &blocker) {
		t.Fatalf("LoadRequired() converted cancellation to blocker: %v", err)
	}
}

func TestStartupActionDistinguishesMissingIdentityAndEpoch(t *testing.T) {
	t.Parallel()

	identity := (&StartupError{ReferenceKind: KindIdentity, Cause: ErrNotFound}).Action()
	epoch := (&StartupError{ReferenceKind: KindEpoch, Cause: ErrNotFound}).Action()
	if identity == epoch {
		t.Fatalf("missing identity and epoch actions are equal: %q", identity)
	}
	if !strings.Contains(identity, "re-pair") || !strings.Contains(epoch, "renew") {
		t.Fatalf("actions = identity %q, epoch %q; want re-pair and renew", identity, epoch)
	}
}

func TestOpenRequiredClassifiesProviderOpenFailure(t *testing.T) {
	t.Parallel()

	openErr := errors.New("session service unavailable")
	_, _, err := openRequired(
		context.Background(),
		IdentityReference(),
		"test-provider",
		func(context.Context) (*Store, error) {
			return nil, errors.Join(ErrUnavailable, openErr)
		},
	)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, openErr) {
		t.Fatalf("openRequired() error = %v, want unavailable and native cause", err)
	}
	var blocker *StartupError
	if !errors.As(err, &blocker) || blocker.Retryable() {
		t.Fatalf("openRequired() error = %v, want non-retryable StartupError", err)
	}
	if blocker.Provider != "test-provider" || blocker.ReferenceKind != KindIdentity {
		t.Fatalf("StartupError = %+v, want provider and identity kind", blocker)
	}
}

func TestOpenRequiredClosesStoreAfterLoadFailure(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{name: "test-provider", getErr: ErrLocked}
	_, _, err := openRequired(
		context.Background(),
		IdentityReference(),
		"test-provider",
		func(context.Context) (*Store, error) {
			return mustStore(t, backend), nil
		},
	)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("openRequired() error = %v, want %v", err, ErrLocked)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls = %d, want 1", backend.closeCalls)
	}
}

func TestOpenRequiredPreservesProgrammerAndContextErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ctx       context.Context
		reference Reference
		want      error
	}{
		{
			name:      "invalid reference",
			ctx:       context.Background(),
			reference: Reference{},
			want:      ErrInvalidReference,
		},
		func() struct {
			name      string
			ctx       context.Context
			reference Reference
			want      error
		} {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return struct {
				name      string
				ctx       context.Context
				reference Reference
				want      error
			}{
				name:      "cancelled",
				ctx:       ctx,
				reference: IdentityReference(),
				want:      context.Canceled,
			}
		}(),
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, _, err := openRequired(
				test.ctx,
				test.reference,
				"test-provider",
				func(context.Context) (*Store, error) {
					called = true
					return nil, errors.New("must not open")
				},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("openRequired() error = %v, want %v", err, test.want)
			}
			if called {
				t.Fatal("openRequired() invoked provider for invalid input")
			}
		})
	}
}
