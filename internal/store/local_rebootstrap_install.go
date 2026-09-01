package store

import (
	"context"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"zombiezen.com/go/sqlite"
)

var ErrRebootstrapInstallMarker = errors.New(
	"store: rebootstrap install marker integrity failure",
)

// RebootstrapInstallMarker blocks local agent recovery until every stale
// session owned by DeviceID has been durably crash-reaped.
type RebootstrapInstallMarker struct {
	SessionID             domain.UUIDv7
	WorkspaceID           domain.UUIDv4
	RecoveryGeneration    uint64
	DeviceID              domain.DeviceID
	SnapshotAttestationID string
	InstalledAt           domain.Timestamp
}

// RebootstrapInstallMarker returns the pending local crash-reap gate.
func (state LocalState) RebootstrapInstallMarker(
	ctx context.Context,
) (RebootstrapInstallMarker, bool, error) {
	var (
		marker RebootstrapInstallMarker
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		marker, found, err = readRebootstrapInstallMarker(conn)
		return err
	})
	if err != nil {
		return RebootstrapInstallMarker{}, false, err
	}
	return marker, found, nil
}

// ClearRebootstrapInstallMarker removes the exact completed crash-reap gate.
func (state LocalState) ClearRebootstrapInstallMarker(
	ctx context.Context,
	expected RebootstrapInstallMarker,
) error {
	if expected.validate() != nil {
		return ErrInvalidLocalState
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		current, found, err := readRebootstrapInstallMarker(conn)
		if err != nil {
			return err
		}
		if !found || current != expected {
			return ErrRebootstrapInstallMarker
		}
		return deleteRebootstrapInstallMarker(conn, expected)
	})
}

func writeRebootstrapInstallMarker(
	conn *sqlite.Conn,
	cut LogicalSnapshotCut,
	deviceID domain.DeviceID,
	attestationID string,
	installedAt domain.Timestamp,
) error {
	marker := RebootstrapInstallMarker{
		SessionID:             cut.SessionID,
		WorkspaceID:           cut.WorkspaceID,
		RecoveryGeneration:    cut.RecoveryGeneration,
		DeviceID:              deviceID,
		SnapshotAttestationID: attestationID,
		InstalledAt:           installedAt,
	}
	if marker.validate() != nil {
		return ErrRebootstrapInstallMarker
	}
	member, found, err := readStatusMember(conn, deviceID)
	if err != nil {
		return err
	}
	if !found || member.Status != device.StatusActive {
		return ErrRebootstrapInstallMarker
	}
	target, err := readStatusVoterSet(conn, cut.SessionID)
	if err != nil {
		return err
	}
	authority, err := readStatusCredentialAuthority(conn, cut.SessionID)
	if err != nil {
		return err
	}
	if target.Contains(deviceID) || authority.Contains(deviceID) {
		return ErrRebootstrapInstallMarker
	}
	return insertRebootstrapInstallMarker(conn, marker)
}

func insertRebootstrapInstallMarker(
	conn *sqlite.Conn,
	marker RebootstrapInstallMarker,
) error {
	if conn == nil || marker.validate() != nil {
		return ErrRebootstrapInstallMarker
	}
	return execute(
		conn,
		`INSERT INTO rebootstrap_install_marker(
		    singleton, session_id, workspace_id, recovery_generation,
		    device_id, snapshot_attestation_id, installed_at
		) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6);`,
		string(marker.SessionID),
		string(marker.WorkspaceID),
		marker.RecoveryGeneration,
		string(marker.DeviceID),
		marker.SnapshotAttestationID,
		string(marker.InstalledAt),
	)
}

func deleteRebootstrapInstallMarker(
	conn *sqlite.Conn,
	expected RebootstrapInstallMarker,
) error {
	if conn == nil || expected.validate() != nil {
		return ErrRebootstrapInstallMarker
	}
	if err := execute(
		conn,
		`DELETE FROM rebootstrap_install_marker
		  WHERE singleton = 1
		    AND session_id = ?1
		    AND workspace_id = ?2
		    AND recovery_generation = ?3
		    AND device_id = ?4
		    AND snapshot_attestation_id = ?5
		    AND installed_at = ?6;`,
		string(expected.SessionID),
		string(expected.WorkspaceID),
		expected.RecoveryGeneration,
		string(expected.DeviceID),
		expected.SnapshotAttestationID,
		string(expected.InstalledAt),
	); err != nil {
		return err
	}
	return requireOneChangedRow(conn)
}

func readRebootstrapInstallMarker(
	conn *sqlite.Conn,
) (RebootstrapInstallMarker, bool, error) {
	var (
		marker RebootstrapInstallMarker
		found  bool
		rowErr error
	)
	err := query(
		conn,
		`SELECT marker.session_id, marker.workspace_id,
		        marker.recovery_generation, marker.device_id,
		        marker.snapshot_attestation_id, marker.installed_at,
		        settled.session_id, settled.workspace_id,
		        settled.recovery_generation, attestations.attestation_kind,
		        attestations.session_id, attestations.workspace_id,
		        attestations.recovery_generation
		   FROM rebootstrap_install_marker AS marker
		   LEFT JOIN settled_nonvoter_state AS settled
		     ON settled.singleton = marker.singleton
		   LEFT JOIN replication_attestations AS attestations
		     ON attestations.attestation_id =
		            marker.snapshot_attestation_id
		  ORDER BY marker.singleton;`,
		func(stmt *sqlite.Stmt) {
			if found {
				rowErr = ErrRebootstrapInstallMarker
				return
			}
			found = true
			generation := stmt.ColumnInt64(2)
			settledGeneration := stmt.ColumnInt64(8)
			attestationGeneration := stmt.ColumnInt64(12)
			if generation < 0 ||
				stmt.ColumnType(6) == sqlite.TypeNull ||
				stmt.ColumnType(7) == sqlite.TypeNull ||
				stmt.ColumnType(8) == sqlite.TypeNull ||
				stmt.ColumnType(9) == sqlite.TypeNull ||
				stmt.ColumnType(10) == sqlite.TypeNull ||
				stmt.ColumnType(11) == sqlite.TypeNull ||
				stmt.ColumnType(12) == sqlite.TypeNull ||
				settledGeneration != generation ||
				attestationGeneration != generation ||
				stmt.ColumnText(6) != stmt.ColumnText(0) ||
				stmt.ColumnText(7) != stmt.ColumnText(1) ||
				stmt.ColumnText(9) != "snapshot" ||
				stmt.ColumnText(10) != stmt.ColumnText(0) ||
				stmt.ColumnText(11) != stmt.ColumnText(1) {
				rowErr = ErrRebootstrapInstallMarker
				return
			}
			marker = RebootstrapInstallMarker{
				SessionID:             domain.UUIDv7(stmt.ColumnText(0)),
				WorkspaceID:           domain.UUIDv4(stmt.ColumnText(1)),
				RecoveryGeneration:    uint64(generation),
				DeviceID:              domain.DeviceID(stmt.ColumnText(3)),
				SnapshotAttestationID: stmt.ColumnText(4),
				InstalledAt:           domain.Timestamp(stmt.ColumnText(5)),
			}
			if marker.validate() != nil {
				rowErr = ErrRebootstrapInstallMarker
			}
		},
	)
	if err != nil {
		return RebootstrapInstallMarker{}, false, err
	}
	if rowErr != nil {
		return RebootstrapInstallMarker{}, false, rowErr
	}
	if !found {
		return RebootstrapInstallMarker{}, false, nil
	}
	return marker, true, nil
}

func (marker RebootstrapInstallMarker) validate() error {
	if !marker.SessionID.Valid() ||
		!marker.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(marker.RecoveryGeneration) ||
		!marker.DeviceID.Valid() ||
		len(marker.SnapshotAttestationID) < 1 ||
		len(marker.SnapshotAttestationID) > 128 ||
		!marker.InstalledAt.Valid() {
		return ErrRebootstrapInstallMarker
	}
	return nil
}
