package pairingservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
)

var errSecretCleanupRetry = errors.New("pairing service: secret cleanup retry")

// CleanupOneSecret performs one durable idempotent native-store deletion. A
// provider failure is recorded before it is returned, so restart never loses
// cleanup work. The boolean reports whether queue work existed.
func (service *Service) CleanupOneSecret(
	ctx context.Context,
) (bool, error) {
	failedAt, err := service.callTime(ctx)
	if err != nil {
		return false, err
	}
	return service.cleanupOneSecretAt(ctx, failedAt)
}

func (service *Service) cleanupOneSecretAt(
	ctx context.Context,
	failedAt domain.Timestamp,
) (bool, error) {
	deletion, found, err := service.state.NextPairingSecretDeletion(ctx)
	if err != nil {
		return false, service.stateError(ctx, err)
	}
	if !found {
		return false, nil
	}
	reference, err := credentialstore.InviteReference(deletion.SessionID, deletion.InviteID)
	if err != nil {
		return true, fmt.Errorf("%w: invalid queued secret reference", ErrUnavailable)
	}
	if err := service.secrets.Delete(ctx, reference); err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		code := cleanupFailureCode(err)
		if _, _, recordErr := service.state.FailPairingSecretDeletion(
			ctx, deletion.SessionID, deletion.InviteID, code, failedAt,
		); recordErr != nil {
			return true, service.stateError(ctx, recordErr)
		}
		return true, errors.Join(
			errSecretCleanupRetry,
			fmt.Errorf("%w: native secret deletion (%s)", ErrUnavailable, code),
		)
	}
	if _, err := service.state.CompletePairingSecretDeletion(
		ctx, deletion.SessionID, deletion.InviteID,
	); err != nil {
		return true, service.stateError(ctx, err)
	}
	return true, nil
}

func (service *Service) drainSecretCleanup(ctx context.Context) error {
	for {
		now, err := service.currentTime()
		if err != nil {
			return err
		}
		processed, err := service.cleanupOneSecretAt(ctx, now)
		if err != nil {
			return err
		}
		if !processed {
			return nil
		}
	}
}

func cleanupFailureCode(err error) string {
	switch {
	case errors.Is(err, credentialstore.ErrLocked):
		return "credential_locked"
	case errors.Is(err, credentialstore.ErrUnavailable):
		return "credential_unavailable"
	case errors.Is(err, credentialstore.ErrAccessDenied):
		return "credential_access_denied"
	case errors.Is(err, credentialstore.ErrCorrupt):
		return "credential_corrupt"
	case errors.Is(err, credentialstore.ErrUnreadable):
		return "credential_unreadable"
	default:
		return "credential_delete_failed"
	}
}
