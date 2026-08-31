package store

import (
	"bytes"
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"zombiezen.com/go/sqlite"
)

// RevalidateRebootstrapEligibility rechecks the exact consumed invite and all
// committed-state eligibility immediately before inviter-side finalization.
// The caller separately holds live Raft-configuration exclusion.
func (state LocalState) RevalidateRebootstrapEligibility(
	ctx context.Context,
	expected PairingInviteRecord,
	core pairing.RequestCore,
) error {
	if expected.validate() != nil ||
		expected.Mode != pairing.ModeRebootstrap ||
		expected.State != PairingInviteConsumed ||
		expected.ConsumedAttemptID != core.AttemptID {
		return ErrInvalidPairingState
	}
	if _, err := pairing.NewRequestCore(core); err != nil {
		return ErrInvalidPairingState
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		current, found, err := readPairingInvite(conn, expected.InviteID)
		if err != nil {
			return err
		}
		if !found ||
			!samePairingInvite(current, expected) ||
			current.State != PairingInviteConsumed ||
			current.ProofFailures != expected.ProofFailures ||
			current.ConsumedAttemptID != expected.ConsumedAttemptID ||
			current.TerminalAt != expected.TerminalAt {
			return ErrPairingStateIntegrity
		}
		if err := requirePairingRecordLineage(conn, current); err != nil {
			return err
		}
		if !pairingCoreMatchesInvite(core, current) {
			return ErrPairingStateIntegrity
		}
		return requirePairingEligibility(conn, current, core)
	})
}

// requirePairingEligibility rechecks every committed-state precondition in the
// same transaction that consumes an invite. Live Raft configuration exclusion
// is guarded by pairingservice because it is deliberately not SQLite state.
func requirePairingEligibility(
	conn *sqlite.Conn,
	invite PairingInviteRecord,
	core pairing.RequestCore,
) error {
	issuer, found, err := readStatusMember(conn, invite.IssuerDeviceID)
	if err != nil {
		return err
	}
	if !found || issuer.Status != device.StatusActive || issuer.Role != device.RoleOwner {
		return ErrPairingEligibility
	}

	subject, found, err := readStatusMember(conn, core.JoinerDeviceID)
	if err != nil {
		return err
	}
	switch invite.Mode {
	case pairing.ModeNew:
		if found || invite.InitialCredentialEpoch != 1 {
			return ErrPairingEligibility
		}
		return nil
	case pairing.ModeRebootstrap, pairing.ModeReadmission:
		if !found || invite.SubjectDeviceID == nil ||
			*invite.SubjectDeviceID != subject.ID ||
			!bytes.Equal(subject.IdentityPublicKey, core.JoinerIdentityPublicKey[:]) {
			return ErrPairingEligibility
		}
	default:
		return ErrPairingEligibility
	}

	target, err := readStatusVoterSet(conn, invite.SessionID)
	if err != nil {
		return err
	}
	if target.Contains(subject.ID) {
		return ErrPairingEligibility
	}

	switch invite.Mode {
	case pairing.ModeRebootstrap:
		if subject.Status != device.StatusActive || subject.Role != invite.Role {
			return ErrPairingEligibility
		}
		nextEpoch, err := nextCredentialEpoch(conn, invite.SessionID, subject.ID)
		if err != nil {
			return err
		}
		if invite.InitialCredentialEpoch != nextEpoch {
			return ErrPairingEligibility
		}
	case pairing.ModeReadmission:
		if subject.Status != device.StatusRequiresReadmission ||
			invite.ExpectedEntityVersion == nil ||
			subject.EntityVersion != *invite.ExpectedEntityVersion ||
			invite.InitialCredentialEpoch != 1 {
			return ErrPairingEligibility
		}
	}
	return nil
}

func nextCredentialEpoch(
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
) (uint64, error) {
	var latest int64
	if err := queryOneArgs(
		conn,
		`SELECT coalesce(max(epoch), 0)
		   FROM credential_authorizations
		  WHERE session_id = ?1 AND device_id = ?2;`,
		[]any{string(sessionID), string(deviceID)},
		func(stmt *sqlite.Stmt) { latest = stmt.ColumnInt64(0) },
	); err != nil {
		return 0, err
	}
	if latest < 0 || uint64(latest) >= domain.MaxSafeInteger {
		return 0, ErrPairingEligibility
	}
	return uint64(latest) + 1, nil
}
