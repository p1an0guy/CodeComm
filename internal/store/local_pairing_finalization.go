package store

import (
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// NextPairingFinalization returns the oldest SAS-approved attempt that still
// needs mode-specific durable finalization.
func (state LocalState) NextPairingFinalization(
	ctx context.Context,
) (PairingAttemptRecord, bool, error) {
	var (
		attempt PairingAttemptRecord
		found   bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var (
			attemptID domain.UUIDv7
			rows      int
		)
		if err := queryArgs(
			conn,
			`SELECT finalizations.attempt_id
			   FROM pairing_attempt_finalizations AS finalizations
			   JOIN pairing_attempts AS attempts
			     ON attempts.attempt_id = finalizations.attempt_id
			   JOIN pairing_invites AS invites
			     ON invites.invite_id = attempts.invite_id
			   JOIN consensus_state AS consensus
			     ON consensus.session_id = invites.session_id
			    AND consensus.recovery_generation = invites.recovery_generation
			   JOIN genesis_records AS genesis
			     ON genesis.session_id = consensus.session_id
			    AND genesis.recovery_generation = consensus.recovery_generation
			    AND genesis.workspace_id = invites.workspace_id
			  WHERE finalizations.state = 'finalizing'
			  ORDER BY finalizations.started_at, finalizations.attempt_id
			  LIMIT 1;`,
			nil,
			func(stmt *sqlite.Stmt) {
				rows++
				attemptID = domain.UUIDv7(stmt.ColumnText(0))
			},
		); err != nil {
			return err
		}
		if rows == 0 {
			return nil
		}
		if rows != 1 || !attemptID.Valid() {
			return ErrPairingStateIntegrity
		}
		var err error
		attempt, found, err = readPairingAttempt(conn, attemptID)
		if err != nil {
			return err
		}
		if !found || attempt.State != PairingAttemptFinalizing {
			return ErrPairingStateIntegrity
		}
		return nil
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	return clonePairingAttempt(attempt), found, nil
}

// CompletePairingFinalization records completion only after the caller's
// mode-specific finalizer has durably succeeded. A retry preserves the first
// completion timestamp.
func (state LocalState) CompletePairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
	completedAt domain.Timestamp,
) (PairingAttemptRecord, bool, error) {
	if !attemptID.Valid() || !completedAt.Valid() {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	var (
		result    PairingAttemptRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingAttempt(conn, attemptID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingAttemptNotFound
		}
		invite, found, err := readPairingInvite(conn, record.InviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingStateIntegrity
		}
		if err := requirePairingRecordLineage(conn, invite); err != nil {
			return err
		}
		switch record.State {
		case PairingAttemptCompleted:
			result = record
			duplicate = true
			return nil
		case PairingAttemptFinalizing:
			// Continue below.
		default:
			return ErrPairingNotFinalizing
		}
		before, err := timestampBefore(completedAt, record.TerminalAt)
		if err != nil || before {
			return ErrInvalidPairingState
		}
		if err := execute(
			conn,
			`UPDATE pairing_attempt_finalizations
			    SET state = 'completed', completed_at = ?2
			  WHERE attempt_id = ?1 AND state = 'finalizing';`,
			string(attemptID), string(completedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		result, found, err = readPairingAttempt(conn, attemptID)
		if err != nil {
			return err
		}
		if !found || result.State != PairingAttemptCompleted {
			return ErrPairingStateIntegrity
		}
		return nil
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	return clonePairingAttempt(result), duplicate, nil
}

// RejectPairingFinalization terminally revokes an attempt after its
// authoritative mode-specific operation returns a durable rejection.
func (state LocalState) RejectPairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (PairingAttemptRecord, bool, error) {
	if !attemptID.Valid() {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	var (
		result    PairingAttemptRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingAttempt(conn, attemptID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingAttemptNotFound
		}
		invite, found, err := readPairingInvite(conn, record.InviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingStateIntegrity
		}
		if err := requirePairingRecordLineage(conn, invite); err != nil {
			return err
		}
		switch record.State {
		case PairingAttemptRevoked:
			result = record
			duplicate = true
			return nil
		case PairingAttemptFinalizing:
			// Continue below.
		default:
			return ErrPairingNotFinalizing
		}
		if err := execute(
			conn,
			`UPDATE pairing_attempts
			    SET state = 'revoked'
			  WHERE attempt_id = ?1 AND state = 'confirmed';`,
			string(attemptID),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		if err := execute(
			conn,
			`DELETE FROM pairing_attempt_finalizations
			  WHERE attempt_id = ?1 AND state = 'finalizing';`,
			string(attemptID),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		result, found, err = readPairingAttempt(conn, attemptID)
		if err != nil {
			return err
		}
		if !found || result.State != PairingAttemptRevoked {
			return ErrPairingStateIntegrity
		}
		return nil
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	return clonePairingAttempt(result), duplicate, nil
}
