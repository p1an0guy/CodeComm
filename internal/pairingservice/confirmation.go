package pairingservice

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

// ConfirmRemote records or polls the joiner's exact SAS decision. The local
// receive time, never a peer-supplied timestamp, enforces the invite deadline.
func (service *Service) ConfirmRemote(
	ctx context.Context,
	canonicalConfirmation []byte,
	peer transport.IdentityCertificate,
) (pairing.ConfirmationResult, error) {
	observedAt, err := service.callTime(ctx)
	if err != nil {
		return pairing.ConfirmationResult{}, err
	}
	confirmation, err := pairing.ParseConfirmation(canonicalConfirmation)
	if err != nil {
		return pairing.ConfirmationResult{}, ErrRequestRejected
	}
	details, err := service.attemptDetails(ctx, confirmation.AttemptID)
	if err != nil {
		return pairing.ConfirmationResult{}, err
	}
	if err := peer.VerifyIdentity(
		details.Invite.SessionID, details.Invite.RecoveryGeneration,
		details.Core.JoinerDeviceID, details.Core.JoinerIdentityPublicKey[:],
	); err != nil {
		return pairing.ConfirmationResult{}, ErrRequestRejected
	}
	if details.Attempt.RequestDigest != store.Digest(confirmation.RequestDigest) {
		return pairing.ConfirmationResult{}, ErrRequestRejected
	}
	if result, handled, err := existingRemoteDecision(details.Attempt, confirmation); handled {
		if err != nil {
			return pairing.ConfirmationResult{}, service.remoteError(ctx, err)
		}
		return result, nil
	}
	updated, _, err := service.state.RecordPairingConfirmation(
		ctx,
		store.PairingConfirmationInput{
			AttemptID: confirmation.AttemptID, Party: store.PairingConfirmationRemote,
			Confirmed: confirmation.Confirmed, DecidedAt: observedAt,
		},
	)
	if err != nil {
		return pairing.ConfirmationResult{}, service.remoteError(
			ctx,
			service.stateError(ctx, err),
		)
	}
	return confirmationResult(updated)
}

func (service *Service) remoteError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrRequestRejected) ||
		errors.Is(err, ErrConfirmationConflict) {
		return ErrRequestRejected
	}
	return err
}

// ConfirmLocal records the inviter operator's decision. Acceptance is allowed
// only after the joiner accepted, making the inviter confirmation the final
// human authorization from which membership admission can be proposed.
func (service *Service) ConfirmLocal(
	ctx context.Context,
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	confirmed bool,
) (AttemptDetails, error) {
	decidedAt, err := service.callTime(ctx)
	if err != nil || !attemptID.Valid() {
		if err != nil {
			return AttemptDetails{}, err
		}
		return AttemptDetails{}, ErrInvalidInput
	}
	details, err := service.attemptDetails(ctx, attemptID)
	if err != nil {
		return AttemptDetails{}, err
	}
	if details.Attempt.RequestDigest != store.Digest(requestDigest) {
		return AttemptDetails{}, ErrConfirmationConflict
	}
	if result, handled, err := existingLocalDecision(details, confirmed); handled {
		if err != nil || !confirmed || result.Attempt.State != store.PairingAttemptFinalizing {
			return result, err
		}
		return service.finalizeAttempt(ctx, result)
	}
	if confirmed && !details.Attempt.RemoteConfirmed {
		return AttemptDetails{}, ErrAwaitingJoinerConfirmation
	}
	updated, _, err := service.state.RecordPairingConfirmation(
		ctx,
		store.PairingConfirmationInput{
			AttemptID: attemptID, Party: store.PairingConfirmationLocal,
			Confirmed: confirmed, DecidedAt: decidedAt,
		},
	)
	if err != nil {
		return AttemptDetails{}, service.stateError(ctx, err)
	}
	details.Attempt = updated
	if updated.State == store.PairingAttemptFinalizing {
		return service.finalizeAttempt(ctx, details)
	}
	return details, nil
}

// Attempt returns the exact identity, role, version, initial key, and SAS that
// the inviter operator must inspect before local confirmation.
func (service *Service) Attempt(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (AttemptDetails, error) {
	if service == nil || service.state == nil || ctx == nil || !attemptID.Valid() {
		return AttemptDetails{}, ErrInvalidInput
	}
	if err := service.validateCall(ctx); err != nil {
		return AttemptDetails{}, err
	}
	return service.attemptDetails(ctx, attemptID)
}

func (service *Service) attemptDetails(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (AttemptDetails, error) {
	attempt, found, err := service.state.PairingAttempt(ctx, attemptID)
	if err != nil {
		return AttemptDetails{}, service.stateError(ctx, err)
	}
	if !found || attempt.State == store.PairingAttemptProofRejected {
		return AttemptDetails{}, ErrRequestRejected
	}
	invite, found, err := service.state.PairingInvite(ctx, attempt.InviteID)
	if err != nil {
		return AttemptDetails{}, service.stateError(ctx, err)
	}
	if !found || invite.IssuerDeviceID != service.deviceID ||
		invite.ConsumedAttemptID != attempt.AttemptID {
		return AttemptDetails{}, ErrRequestRejected
	}
	core, err := pairing.ParseRequestCore(attempt.RequestCore, invite.SessionID)
	if err != nil {
		return AttemptDetails{}, ErrUnavailable
	}
	return AttemptDetails{
		Invite: invite, Attempt: attempt, Core: core.Value(),
		SAS: pairing.RenderSAS([sha256.Size]byte(attempt.TranscriptHash)),
	}, nil
}

func existingRemoteDecision(
	attempt store.PairingAttemptRecord,
	confirmation pairing.Confirmation,
) (pairing.ConfirmationResult, bool, error) {
	switch attempt.State {
	case store.PairingAttemptAwaitingSAS:
		if !attempt.RemoteConfirmed {
			return pairing.ConfirmationResult{}, false, nil
		}
		if !confirmation.Confirmed {
			return pairing.ConfirmationResult{}, true, ErrConfirmationConflict
		}
		result, err := confirmationResult(attempt)
		return result, true, err
	case store.PairingAttemptFinalizing:
		if !confirmation.Confirmed || !attempt.RemoteConfirmed {
			return pairing.ConfirmationResult{}, true, ErrConfirmationConflict
		}
		result, err := confirmationResult(attempt)
		return result, true, err
	case store.PairingAttemptCompleted:
		if !confirmation.Confirmed || !attempt.RemoteConfirmed {
			return pairing.ConfirmationResult{}, true, ErrConfirmationConflict
		}
		result, err := confirmationResult(attempt)
		return result, true, err
	case store.PairingAttemptDeclined:
		if attempt.DeclinedBy == store.PairingConfirmationRemote && confirmation.Confirmed {
			return pairing.ConfirmationResult{}, true, ErrConfirmationConflict
		}
		result, err := confirmationResult(attempt)
		return result, true, err
	case store.PairingAttemptExpired, store.PairingAttemptRevoked:
		result, err := confirmationResult(attempt)
		return result, true, err
	default:
		return pairing.ConfirmationResult{}, true, ErrRequestRejected
	}
}

func existingLocalDecision(
	details AttemptDetails,
	confirmed bool,
) (AttemptDetails, bool, error) {
	attempt := details.Attempt
	switch attempt.State {
	case store.PairingAttemptAwaitingSAS:
		if !attempt.LocalConfirmed {
			return AttemptDetails{}, false, nil
		}
		if !confirmed {
			return AttemptDetails{}, true, ErrConfirmationConflict
		}
		return details, true, nil
	case store.PairingAttemptFinalizing, store.PairingAttemptCompleted:
		if !confirmed || !attempt.LocalConfirmed {
			return AttemptDetails{}, true, ErrConfirmationConflict
		}
		return details, true, nil
	case store.PairingAttemptDeclined:
		if attempt.DeclinedBy == store.PairingConfirmationLocal && confirmed {
			return AttemptDetails{}, true, ErrConfirmationConflict
		}
		return details, true, nil
	case store.PairingAttemptExpired, store.PairingAttemptRevoked:
		return details, true, nil
	default:
		return AttemptDetails{}, true, ErrRequestRejected
	}
}

func confirmationResult(
	attempt store.PairingAttemptRecord,
) (pairing.ConfirmationResult, error) {
	var status pairing.ConfirmationStatus
	switch attempt.State {
	case store.PairingAttemptAwaitingSAS:
		if !attempt.RemoteConfirmed {
			return pairing.ConfirmationResult{}, ErrRequestRejected
		}
		status = pairing.StatusAwaitingInviter
	case store.PairingAttemptFinalizing:
		status = pairing.StatusFinalizing
	case store.PairingAttemptCompleted:
		status = pairing.StatusConfirmed
	case store.PairingAttemptDeclined:
		status = pairing.StatusDeclined
	case store.PairingAttemptExpired:
		status = pairing.StatusExpired
	case store.PairingAttemptRevoked:
		status = pairing.StatusRevoked
	default:
		return pairing.ConfirmationResult{}, ErrRequestRejected
	}
	result, err := pairing.NewConfirmationResult(
		attempt.AttemptID, [sha256.Size]byte(attempt.RequestDigest), status,
	)
	if err != nil {
		return pairing.ConfirmationResult{}, errors.Join(ErrUnavailable, err)
	}
	return result, nil
}
