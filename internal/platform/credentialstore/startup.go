package credentialstore

import (
	"context"
	"errors"
	"fmt"
)

type nativeOpener func(context.Context) (*Store, error)

// StartupError is an operator-actionable blocker. Supervisors must not count
// it as a crash or retry it on backoff.
type StartupError struct {
	Provider      string
	ReferenceKind Kind
	Cause         error
}

// Error describes the blocked provider and required operator action.
func (failure *StartupError) Error() string {
	if failure == nil {
		return "credentialstore: startup blocked"
	}
	return fmt.Sprintf(
		"credentialstore: startup blocked for %s key in %s: %v; action: %s",
		failure.ReferenceKind,
		failure.Provider,
		failure.Cause,
		failure.Action(),
	)
}

// Unwrap preserves the canonical provider failure for errors.Is.
func (failure *StartupError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// Retryable is always false: an operator or OS-session state change is needed.
func (*StartupError) Retryable() bool {
	return false
}

// Action returns stable remediation text suitable for CLI, TUI, or supervisor
// status output.
func (failure *StartupError) Action() string {
	switch {
	case failure == nil:
		return "inspect the OS credential store"
	case errors.Is(failure.Cause, ErrNotFound):
		if failure.ReferenceKind == KindEpoch {
			return "renew this session credential through the consensus plane, then retry explicitly"
		}
		return "restore access to the original credential store or re-pair this device; CodeComm will not generate a replacement identity"
	case errors.Is(failure.Cause, ErrLocked):
		return "unlock the OS credential store for this login session, then retry explicitly"
	case errors.Is(failure.Cause, ErrUnavailable):
		return "start or restore the native OS credential-store service for this login session, then retry explicitly"
	case errors.Is(failure.Cause, ErrAccessDenied):
		return "grant this OS user and CodeComm access to the existing credential, then retry explicitly"
	case errors.Is(failure.Cause, ErrCorrupt):
		return "repair access to the original credential or re-pair this device; do not delete it until membership and voter recovery are planned"
	default:
		return "inspect and repair the native OS credential-store entry, then retry explicitly"
	}
}

// LoadRequired reads a startup-critical key. It never creates a missing key
// and converts operational provider failures into non-retryable blockers.
func LoadRequired(
	ctx context.Context,
	store *Store,
	reference Reference,
) ([]byte, error) {
	if store == nil {
		return nil, ErrInvalidBackend
	}
	value, err := store.Get(ctx, reference)
	if err == nil {
		return value, nil
	}
	if errors.Is(err, ErrInvalidReference) ||
		errors.Is(err, ErrInvalidBackend) ||
		errors.Is(err, ErrInvalidContext) ||
		errors.Is(err, ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	return nil, &StartupError{
		Provider:      store.Provider(),
		ReferenceKind: reference.Kind(),
		Cause:         err,
	}
}

// OpenRequired opens the native provider and loads one startup-critical key.
// Provider and key failures are always non-retryable StartupError values;
// invalid input and caller cancellation remain ordinary errors.
func OpenRequired(
	ctx context.Context,
	reference Reference,
) (*Store, []byte, error) {
	return openRequired(
		ctx,
		reference,
		nativeProviderName(),
		OpenNative,
	)
}

func openRequired(
	ctx context.Context,
	reference Reference,
	provider string,
	open nativeOpener,
) (*Store, []byte, error) {
	if err := reference.Validate(); err != nil {
		return nil, nil, err
	}
	if ctx == nil {
		return nil, nil, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !validProviderName(provider) || open == nil {
		return nil, nil, ErrInvalidBackend
	}

	store, err := open(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, ErrInvalidContext) {
			return nil, nil, err
		}
		if !canonicalBackendError(err) {
			err = fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return nil, nil, &StartupError{
			Provider:      provider,
			ReferenceKind: reference.Kind(),
			Cause:         err,
		}
	}
	if store == nil {
		return nil, nil, ErrInvalidBackend
	}

	value, err := LoadRequired(ctx, store, reference)
	if err != nil {
		return nil, nil, errors.Join(err, store.Close())
	}
	return store, value, nil
}
