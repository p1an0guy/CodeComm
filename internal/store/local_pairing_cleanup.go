package store

import (
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// NextPairingSecretDeletion returns the next idempotent native-store cleanup item.
func (state LocalState) NextPairingSecretDeletion(
	ctx context.Context,
) (PairingSecretDeletion, bool, error) {
	var (
		record PairingSecretDeletion
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var rowErr error
		err := queryArgs(
			conn,
			`SELECT invite_id, session_id, reason, queued_at, failure_count,
			        last_failure_at, last_error_code
			   FROM pairing_secret_deletions
			  ORDER BY failure_count, queued_at, invite_id LIMIT 1;`,
			nil,
			func(stmt *sqlite.Stmt) {
				if found {
					rowErr = ErrPairingStateIntegrity
					return
				}
				found = true
				record, rowErr = scanPairingSecretDeletion(stmt)
			},
		)
		if err != nil {
			return err
		}
		return rowErr
	})
	if err != nil {
		return PairingSecretDeletion{}, false, err
	}
	return record, found, nil
}

// CompletePairingSecretDeletion removes queue state after an idempotent native
// delete succeeds. Repeating an already completed deletion succeeds.
func (state LocalState) CompletePairingSecretDeletion(
	ctx context.Context,
	sessionID domain.UUIDv7,
	inviteID domain.UUIDv7,
) (bool, error) {
	if !sessionID.Valid() || !inviteID.Valid() {
		return false, ErrInvalidPairingState
	}
	duplicate := false
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var count int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*) FROM pairing_secret_deletions
			  WHERE invite_id = ?1 AND session_id = ?2;`,
			[]any{string(inviteID), string(sessionID)},
			func(stmt *sqlite.Stmt) { count = stmt.ColumnInt64(0) },
		); err != nil {
			return err
		}
		if count == 0 {
			duplicate = true
			return nil
		}
		if count != 1 {
			return ErrPairingStateIntegrity
		}
		if err := execute(
			conn,
			"DELETE FROM pairing_secret_deletions WHERE invite_id = ?1 AND session_id = ?2;",
			string(inviteID), string(sessionID),
		); err != nil {
			return err
		}
		return requireOneChangedRow(conn)
	})
	return duplicate, err
}

// FailPairingSecretDeletion records one stable failure without discarding work.
func (state LocalState) FailPairingSecretDeletion(
	ctx context.Context,
	sessionID domain.UUIDv7,
	inviteID domain.UUIDv7,
	errorCode string,
	failedAt domain.Timestamp,
) (PairingSecretDeletion, bool, error) {
	if !sessionID.Valid() || !inviteID.Valid() || !validCode(errorCode, false) ||
		!failedAt.Valid() {
		return PairingSecretDeletion{}, false, ErrInvalidPairingState
	}
	var (
		result    PairingSecretDeletion
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingSecretDeletion(conn, inviteID)
		if err != nil {
			return err
		}
		if !found || record.SessionID != sessionID {
			return ErrPairingDeletionNotFound
		}
		if record.LastFailureAt == failedAt && record.LastErrorCode == errorCode {
			result = record
			duplicate = true
			return nil
		}
		if record.FailureCount == domain.MaxSafeInteger {
			return ErrPairingDeletionExhausted
		}
		if before, err := timestampBefore(failedAt, record.QueuedAt); err != nil || before {
			return ErrInvalidPairingState
		}
		if record.LastFailureAt != "" {
			before, err := timestampBefore(failedAt, record.LastFailureAt)
			if err != nil || before || failedAt == record.LastFailureAt {
				return ErrPairingConflict
			}
		}
		if err := execute(
			conn,
			`UPDATE pairing_secret_deletions
			    SET failure_count = failure_count + 1,
			        last_failure_at = ?3, last_error_code = ?4
			  WHERE invite_id = ?1 AND session_id = ?2;`,
			string(inviteID), string(sessionID), string(failedAt), errorCode,
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		updated, found, err := readPairingSecretDeletion(conn, inviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingStateIntegrity
		}
		result = updated
		return nil
	})
	if err != nil {
		return PairingSecretDeletion{}, false, err
	}
	return result, duplicate, nil
}

func readPairingSecretDeletion(
	conn *sqlite.Conn,
	inviteID domain.UUIDv7,
) (PairingSecretDeletion, bool, error) {
	var (
		record PairingSecretDeletion
		found  bool
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT invite_id, session_id, reason, queued_at, failure_count,
		        last_failure_at, last_error_code
		   FROM pairing_secret_deletions WHERE invite_id = ?1;`,
		[]any{string(inviteID)},
		func(stmt *sqlite.Stmt) {
			if found {
				rowErr = ErrPairingStateIntegrity
				return
			}
			found = true
			record, rowErr = scanPairingSecretDeletion(stmt)
		},
	)
	if err != nil {
		return PairingSecretDeletion{}, false, err
	}
	if rowErr != nil {
		return PairingSecretDeletion{}, false, rowErr
	}
	return record, found, nil
}

func scanPairingSecretDeletion(stmt *sqlite.Stmt) (PairingSecretDeletion, error) {
	failures := stmt.ColumnInt64(4)
	if failures < 0 {
		return PairingSecretDeletion{}, ErrPairingStateIntegrity
	}
	record := PairingSecretDeletion{
		InviteID:  domain.UUIDv7(stmt.ColumnText(0)),
		SessionID: domain.UUIDv7(stmt.ColumnText(1)),
		Reason:    stmt.ColumnText(2), QueuedAt: domain.Timestamp(stmt.ColumnText(3)),
		FailureCount: uint64(failures),
	}
	if stmt.ColumnType(5) != sqlite.TypeNull {
		record.LastFailureAt = domain.Timestamp(stmt.ColumnText(5))
	}
	if stmt.ColumnType(6) != sqlite.TypeNull {
		record.LastErrorCode = stmt.ColumnText(6)
	}
	if !record.InviteID.Valid() || !record.SessionID.Valid() || !record.QueuedAt.Valid() ||
		!validPairingDeletionReason(record.Reason) {
		return PairingSecretDeletion{}, ErrPairingStateIntegrity
	}
	if record.FailureCount == 0 &&
		(record.LastFailureAt != "" || record.LastErrorCode != "") {
		return PairingSecretDeletion{}, ErrPairingStateIntegrity
	}
	if record.FailureCount > 0 &&
		(!record.LastFailureAt.Valid() || !validCode(record.LastErrorCode, false)) {
		return PairingSecretDeletion{}, ErrPairingStateIntegrity
	}
	return record, nil
}

func validPairingDeletionReason(reason string) bool {
	switch reason {
	case "consumed", "revoked", "expired", "proof_exhausted",
		"abandoned", "generation_changed":
		return true
	default:
		return false
	}
}
