package store

import (
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// RecoverPairingState performs startup-only repair, including abandoning
// reservations whose native-secret creation may have been interrupted.
func (state LocalState) RecoverPairingState(
	ctx context.Context,
	now domain.Timestamp,
) (PairingMaintenanceResult, error) {
	return state.maintainPairingState(ctx, now, true)
}

// MaintainPairingState expires invite/SAS state even when no peer request is
// arriving. It deliberately leaves preparing rows for startup recovery or the
// issuing operation's compensating cleanup.
func (state LocalState) MaintainPairingState(
	ctx context.Context,
	now domain.Timestamp,
) (PairingMaintenanceResult, error) {
	return state.maintainPairingState(ctx, now, false)
}

func (state LocalState) maintainPairingState(
	ctx context.Context,
	now domain.Timestamp,
	recoverPreparing bool,
) (PairingMaintenanceResult, error) {
	if !now.Valid() {
		return PairingMaintenanceResult{}, ErrInvalidPairingState
	}
	var result PairingMaintenanceResult
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		result, err = maintainPairingRows(conn, now, recoverPreparing)
		return err
	})
	return result, err
}

func maintainPairingRows(
	conn *sqlite.Conn,
	now domain.Timestamp,
	recoverPreparing bool,
) (PairingMaintenanceResult, error) {
	lineage, err := readLocalLineage(conn)
	if err != nil {
		return PairingMaintenanceResult{}, err
	}
	var result PairingMaintenanceResult
	if recoverPreparing {
		if err := execute(
			conn,
			`UPDATE pairing_invites
			    SET state = 'abandoned',
			        terminal_at = CASE WHEN created_at > ?3 THEN created_at ELSE ?3 END
			  WHERE session_id = ?1 AND recovery_generation = ?2
			    AND state = 'preparing';`,
			string(lineage.sessionID), lineage.recoveryGeneration, string(now),
		); err != nil {
			return PairingMaintenanceResult{}, err
		}
		result.AbandonedPreparing, err = changedRowCount(conn)
		if err != nil {
			return PairingMaintenanceResult{}, err
		}
	}

	if err := execute(
		conn,
		`DELETE FROM pairing_attempts
		  WHERE state = 'proof_rejected'
		    AND invite_id IN (
		        SELECT invite_id FROM pairing_invites
		         WHERE session_id = ?1 AND recovery_generation = ?2
		           AND state = 'outstanding'
		           AND unixepoch(expires_at) <= unixepoch(?3)
		    );`,
		string(lineage.sessionID), lineage.recoveryGeneration, string(now),
	); err != nil {
		return PairingMaintenanceResult{}, err
	}
	if err := execute(
		conn,
		`UPDATE pairing_invites
		    SET state = 'expired', terminal_at = ?3
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND state = 'outstanding'
		    AND unixepoch(expires_at) <= unixepoch(?3);`,
		string(lineage.sessionID), lineage.recoveryGeneration, string(now),
	); err != nil {
		return PairingMaintenanceResult{}, err
	}
	result.ExpiredInvites, err = changedRowCount(conn)
	if err != nil {
		return PairingMaintenanceResult{}, err
	}

	if err := execute(
		conn,
		`UPDATE pairing_attempts
		    SET state = 'expired', terminal_at = ?3
		  WHERE state = 'awaiting_sas'
		    AND invite_id IN (
		        SELECT invite_id FROM pairing_invites
		         WHERE session_id = ?1 AND recovery_generation = ?2
		           AND state = 'consumed'
		           AND unixepoch(expires_at) <= unixepoch(?3)
		    );`,
		string(lineage.sessionID), lineage.recoveryGeneration, string(now),
	); err != nil {
		return PairingMaintenanceResult{}, err
	}
	result.ExpiredAttempts, err = changedRowCount(conn)
	if err != nil {
		return PairingMaintenanceResult{}, err
	}
	return result, nil
}

func changedRowCount(conn *sqlite.Conn) (uint64, error) {
	var count int64
	if err := queryOne(
		conn,
		"SELECT changes();",
		func(stmt *sqlite.Stmt) { count = stmt.ColumnInt64(0) },
	); err != nil {
		return 0, err
	}
	if count < 0 {
		return 0, ErrPairingStateIntegrity
	}
	return uint64(count), nil
}
