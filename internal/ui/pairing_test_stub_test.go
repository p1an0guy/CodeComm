package ui

import (
	"context"
	"crypto/sha256"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/store"
)

type testPairingOperator struct{}

func (testPairingOperator) CreateInvite(
	context.Context,
	pairingservice.CreateInviteRequest,
) (pairingservice.IssuedInvite, error) {
	return pairingservice.IssuedInvite{}, pairingservice.ErrUnavailable
}

func (testPairingOperator) ListInvites(
	context.Context,
) ([]store.PairingInviteRecord, error) {
	return []store.PairingInviteRecord{}, nil
}

func (testPairingOperator) RevokeInvite(
	context.Context,
	domain.UUIDv7,
) (store.PairingInviteRecord, bool, error) {
	return store.PairingInviteRecord{}, false, pairingservice.ErrRequestRejected
}

func (testPairingOperator) PairingAttempt(
	context.Context,
	domain.UUIDv7,
) (pairingservice.AttemptDetails, error) {
	return pairingservice.AttemptDetails{}, pairingservice.ErrRequestRejected
}

func (testPairingOperator) ConfirmPairing(
	context.Context,
	domain.UUIDv7,
	[sha256.Size]byte,
	bool,
) (pairingservice.AttemptDetails, error) {
	return pairingservice.AttemptDetails{}, pairingservice.ErrRequestRejected
}
