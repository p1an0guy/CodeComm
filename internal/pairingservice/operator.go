package pairingservice

import (
	"context"
	"crypto/sha256"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

// Operator composes local invite lifecycle with the exact SAS review service.
type Operator struct {
	inviter *Inviter
	service *Service
}

func NewOperator(inviter *Inviter, service *Service) (*Operator, error) {
	if inviter == nil || service == nil {
		return nil, ErrInvalidOptions
	}
	return &Operator{inviter: inviter, service: service}, nil
}

func (operator *Operator) CreateInvite(
	ctx context.Context,
	request CreateInviteRequest,
) (IssuedInvite, error) {
	if operator == nil || operator.inviter == nil {
		return IssuedInvite{}, ErrInvalidInput
	}
	return operator.inviter.Create(ctx, request)
}

func (operator *Operator) ListInvites(
	ctx context.Context,
) ([]store.PairingInviteRecord, error) {
	if operator == nil || operator.inviter == nil {
		return nil, ErrInvalidInput
	}
	return operator.inviter.List(ctx)
}

func (operator *Operator) RevokeInvite(
	ctx context.Context,
	inviteID domain.UUIDv7,
) (store.PairingInviteRecord, bool, error) {
	if operator == nil || operator.inviter == nil {
		return store.PairingInviteRecord{}, false, ErrInvalidInput
	}
	return operator.inviter.Revoke(ctx, inviteID)
}

func (operator *Operator) PairingAttempt(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (AttemptDetails, error) {
	if operator == nil || operator.service == nil {
		return AttemptDetails{}, ErrInvalidInput
	}
	return operator.service.Attempt(ctx, attemptID)
}

func (operator *Operator) ConfirmPairing(
	ctx context.Context,
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	confirmed bool,
) (AttemptDetails, error) {
	if operator == nil || operator.service == nil {
		return AttemptDetails{}, ErrInvalidInput
	}
	return operator.service.ConfirmLocal(
		ctx,
		attemptID,
		requestDigest,
		confirmed,
	)
}
