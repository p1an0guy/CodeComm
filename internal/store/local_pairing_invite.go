package store

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"zombiezen.com/go/sqlite"
)

// ReservePairingInvite atomically reserves issuer capacity before the caller
// creates the native-store secret. SQLite retains only the signed invite digest.
func (state LocalState) ReservePairingInvite(
	ctx context.Context,
	invite pairing.SignedInvite,
) (PairingInviteRecord, bool, error) {
	if err := invite.Validate(); err != nil {
		return PairingInviteRecord{}, false, ErrInvalidPairingState
	}
	value := invite.Invite()
	defer clear(value.Secret[:])
	record := PairingInviteRecord{
		InviteID: value.InviteID, SessionID: value.SessionID, WorkspaceID: value.WorkspaceID,
		RecoveryGeneration: value.RecoveryGeneration, IssuerDeviceID: value.InviterDeviceID,
		InviteDigest: Digest(invite.Digest()), Mode: value.Mode,
		SubjectDeviceID:       cloneDeviceIDPointer(value.SubjectDeviceID),
		ExpectedEntityVersion: cloneUint64Pointer(value.ExpectedEntityVersion),
		Role:                  value.Role, InitialCredentialEpoch: value.InitialCredentialEpoch,
		State: PairingInvitePreparing, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt,
	}
	if err := record.validate(); err != nil {
		return PairingInviteRecord{}, false, ErrInvalidPairingState
	}

	var (
		result    PairingInviteRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		if err := requirePairingLineage(conn, record); err != nil {
			return err
		}
		if err := requirePairingGenesisDigest(
			conn,
			record,
			Digest(value.SignedGenesisDigest),
		); err != nil {
			return err
		}
		if err := requirePairingIssuerOwner(
			conn,
			record.IssuerDeviceID,
			value.InviterIdentityPublicKey[:],
		); err != nil {
			return err
		}
		if _, err := maintainPairingRows(
			conn,
			domain.Timestamp(record.CreatedAt),
			false,
		); err != nil {
			return err
		}
		existing, found, err := readPairingInvite(conn, record.InviteID)
		if err != nil {
			return err
		}
		if found {
			if !samePairingInvite(existing, record) ||
				(existing.State != PairingInvitePreparing &&
					existing.State != PairingInviteOutstanding) {
				return ErrPairingConflict
			}
			result = existing
			duplicate = true
			return nil
		}

		var active int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*) FROM pairing_invites
			  WHERE issuer_device_id = ?1
			    AND state IN ('preparing', 'outstanding');`,
			[]any{string(record.IssuerDeviceID)},
			func(stmt *sqlite.Stmt) { active = stmt.ColumnInt64(0) },
		); err != nil {
			return err
		}
		if active >= MaxOutstandingPairingInvites {
			return ErrPairingInviteLimit
		}
		if _, err := prunePairingHistory(
			conn,
			MaxPairingHistoryEntries-1,
		); err != nil {
			return err
		}
		historyEntries, err := pairingHistoryCount(conn)
		if err != nil {
			return err
		}
		if historyEntries >= MaxPairingHistoryEntries {
			return ErrPairingInviteLimit
		}
		if err := execute(
			conn,
			`INSERT INTO pairing_invites(
			    invite_id, session_id, workspace_id, recovery_generation,
			    issuer_device_id, invite_digest, mode, subject_device_id,
			    expected_entity_version, role, initial_credential_epoch,
			    state, proof_failures, consumed_attempt_id, created_at, expires_at, terminal_at
			) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
			          'preparing', 0, NULL, ?12, ?13, NULL);`,
			string(record.InviteID), string(record.SessionID), string(record.WorkspaceID),
			record.RecoveryGeneration, string(record.IssuerDeviceID), record.InviteDigest[:],
			string(record.Mode), nullableDeviceIDPointer(record.SubjectDeviceID),
			nullableUint64Pointer(record.ExpectedEntityVersion), string(record.Role),
			record.InitialCredentialEpoch, string(record.CreatedAt), string(record.ExpiresAt),
		); err != nil {
			return err
		}
		result = clonePairingInvite(record)
		return nil
	})
	if err != nil {
		return PairingInviteRecord{}, false, err
	}
	return clonePairingInvite(result), duplicate, nil
}

// ActivatePairingInvite marks a reservation outstanding only after its secret
// has been durably created in the native credential store.
func (state LocalState) ActivatePairingInvite(
	ctx context.Context,
	inviteID domain.UUIDv7,
	inviteDigest Digest,
) (PairingInviteRecord, bool, error) {
	if !inviteID.Valid() {
		return PairingInviteRecord{}, false, ErrInvalidPairingState
	}
	var (
		result    PairingInviteRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingInvite(conn, inviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingInviteNotFound
		}
		if err := requirePairingRecordLineage(conn, record); err != nil {
			return err
		}
		if record.InviteDigest != inviteDigest {
			return ErrPairingConflict
		}
		switch record.State {
		case PairingInviteOutstanding:
			result = record
			duplicate = true
			return nil
		case PairingInvitePreparing:
			// Continue below.
		default:
			return ErrPairingInviteUnavailable
		}
		if err := execute(
			conn,
			"UPDATE pairing_invites SET state = 'outstanding' WHERE invite_id = ?1 AND state = 'preparing';",
			string(inviteID),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		record.State = PairingInviteOutstanding
		result = record
		return nil
	})
	if err != nil {
		return PairingInviteRecord{}, false, err
	}
	return clonePairingInvite(result), duplicate, nil
}

// TerminatePairingInvite revokes, expires, or abandons one unused invite and
// transactionally queues native secret deletion through the schema trigger.
func (state LocalState) TerminatePairingInvite(
	ctx context.Context,
	inviteID domain.UUIDv7,
	inviteDigest Digest,
	target PairingInviteState,
	terminatedAt domain.Timestamp,
) (PairingInviteRecord, bool, error) {
	if !inviteID.Valid() || !terminatedAt.Valid() ||
		(target != PairingInviteRevoked && target != PairingInviteExpired &&
			target != PairingInviteAbandoned) {
		return PairingInviteRecord{}, false, ErrInvalidPairingState
	}
	var (
		result    PairingInviteRecord
		duplicate bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingInvite(conn, inviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingInviteNotFound
		}
		if err := requirePairingRecordLineage(conn, record); err != nil {
			return err
		}
		if record.InviteDigest != inviteDigest {
			return ErrPairingConflict
		}
		if record.State == target {
			if record.TerminalAt != terminatedAt {
				return ErrPairingConflict
			}
			result = record
			duplicate = true
			return nil
		}
		if record.State != PairingInvitePreparing && record.State != PairingInviteOutstanding {
			return ErrPairingInviteUnavailable
		}
		createdAt := domain.Timestamp(record.CreatedAt)
		beforeCreated, err := timestampBefore(terminatedAt, createdAt)
		if err != nil || beforeCreated {
			return ErrInvalidPairingState
		}
		if target == PairingInviteExpired {
			beforeExpiry, err := timestampBefore(terminatedAt, domain.Timestamp(record.ExpiresAt))
			if err != nil || beforeExpiry {
				return ErrInvalidPairingState
			}
		}
		if err := deleteRejectedPairingAttempts(conn, record.InviteID); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE pairing_invites SET state = ?2, terminal_at = ?3
			  WHERE invite_id = ?1 AND state IN ('preparing', 'outstanding');`,
			string(inviteID), string(target), string(terminatedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		record.State = target
		record.TerminalAt = terminatedAt
		result = record
		return nil
	})
	if err != nil {
		return PairingInviteRecord{}, false, err
	}
	return clonePairingInvite(result), duplicate, nil
}

// PairingInvites returns issuer-local invite metadata in stable creation order.
func (state LocalState) PairingInvites(
	ctx context.Context,
	issuerDeviceID domain.DeviceID,
) ([]PairingInviteRecord, error) {
	if !issuerDeviceID.Valid() {
		return nil, ErrInvalidPairingState
	}
	var records []PairingInviteRecord
	var rowErr error
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if err := queryArgs(
			conn,
			`SELECT invite_id, session_id, workspace_id, recovery_generation,
			        issuer_device_id, invite_digest, mode, subject_device_id,
			        expected_entity_version, role, initial_credential_epoch,
			        state, proof_failures, consumed_attempt_id, created_at, expires_at, terminal_at
			   FROM pairing_invites
			  WHERE issuer_device_id = ?1 AND session_id = ?2 AND recovery_generation = ?3
			  ORDER BY created_at, invite_id;`,
			[]any{string(issuerDeviceID), string(lineage.sessionID), lineage.recoveryGeneration},
			func(stmt *sqlite.Stmt) {
				if rowErr != nil {
					return
				}
				record, scanErr := scanPairingInvite(stmt)
				if scanErr != nil {
					records = nil
					rowErr = scanErr
					return
				}
				records = append(records, record)
			},
		); err != nil {
			return err
		}
		return rowErr
	})
	if err != nil {
		return nil, err
	}
	result := make([]PairingInviteRecord, len(records))
	for index := range records {
		result[index] = clonePairingInvite(records[index])
	}
	return result, nil
}

// PairingInvite reads one current-generation invite without exposing its secret.
func (state LocalState) PairingInvite(
	ctx context.Context,
	inviteID domain.UUIDv7,
) (PairingInviteRecord, bool, error) {
	if !inviteID.Valid() {
		return PairingInviteRecord{}, false, ErrInvalidPairingState
	}
	var (
		record PairingInviteRecord
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		record, found, err = readPairingInvite(conn, inviteID)
		if err != nil || !found {
			return err
		}
		return requirePairingRecordLineage(conn, record)
	})
	if err != nil {
		return PairingInviteRecord{}, false, err
	}
	return clonePairingInvite(record), found, nil
}

func readPairingInvite(
	conn *sqlite.Conn,
	inviteID domain.UUIDv7,
) (PairingInviteRecord, bool, error) {
	var (
		record PairingInviteRecord
		found  bool
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT invite_id, session_id, workspace_id, recovery_generation,
		        issuer_device_id, invite_digest, mode, subject_device_id,
		        expected_entity_version, role, initial_credential_epoch,
		        state, proof_failures, consumed_attempt_id, created_at, expires_at, terminal_at
		   FROM pairing_invites WHERE invite_id = ?1;`,
		[]any{string(inviteID)},
		func(stmt *sqlite.Stmt) {
			if found {
				rowErr = ErrPairingStateIntegrity
				return
			}
			found = true
			record, rowErr = scanPairingInvite(stmt)
		},
	)
	if err != nil {
		return PairingInviteRecord{}, false, err
	}
	if rowErr != nil {
		return PairingInviteRecord{}, false, rowErr
	}
	return record, found, nil
}

func scanPairingInvite(stmt *sqlite.Stmt) (PairingInviteRecord, error) {
	record := PairingInviteRecord{
		InviteID: domain.UUIDv7(stmt.ColumnText(0)), SessionID: domain.UUIDv7(stmt.ColumnText(1)),
		WorkspaceID: domain.UUIDv4(stmt.ColumnText(2)), IssuerDeviceID: domain.DeviceID(stmt.ColumnText(4)),
		Mode: pairing.Mode(stmt.ColumnText(6)), Role: device.Role(stmt.ColumnText(9)),
		State:     PairingInviteState(stmt.ColumnText(11)),
		CreatedAt: domain.WholeSecondTimestamp(stmt.ColumnText(14)),
		ExpiresAt: domain.WholeSecondTimestamp(stmt.ColumnText(15)),
	}
	generation, epoch, failures := stmt.ColumnInt64(3), stmt.ColumnInt64(10), stmt.ColumnInt64(12)
	if generation < 0 || epoch < 0 || failures < 0 ||
		copyDigestColumn(&record.InviteDigest, stmt, 5) != nil {
		return PairingInviteRecord{}, ErrPairingStateIntegrity
	}
	record.RecoveryGeneration = uint64(generation)
	record.InitialCredentialEpoch = uint64(epoch)
	record.ProofFailures = uint64(failures)
	if stmt.ColumnType(7) != sqlite.TypeNull {
		value := domain.DeviceID(stmt.ColumnText(7))
		record.SubjectDeviceID = &value
	}
	if stmt.ColumnType(8) != sqlite.TypeNull {
		value := stmt.ColumnInt64(8)
		if value < 0 {
			return PairingInviteRecord{}, ErrPairingStateIntegrity
		}
		unsigned := uint64(value)
		record.ExpectedEntityVersion = &unsigned
	}
	if stmt.ColumnType(13) != sqlite.TypeNull {
		record.ConsumedAttemptID = domain.UUIDv7(stmt.ColumnText(13))
	}
	if stmt.ColumnType(16) != sqlite.TypeNull {
		record.TerminalAt = domain.Timestamp(stmt.ColumnText(16))
	}
	if err := record.validate(); err != nil {
		return PairingInviteRecord{}, err
	}
	return record, nil
}

func requirePairingLineage(conn *sqlite.Conn, record PairingInviteRecord) error {
	lineage, err := readLocalLineage(conn)
	if err != nil {
		return err
	}
	if lineage.sessionID != record.SessionID || lineage.workspaceID != record.WorkspaceID ||
		lineage.recoveryGeneration != record.RecoveryGeneration {
		return ErrPairingLineageMismatch
	}
	return nil
}

func requirePairingRecordLineage(conn *sqlite.Conn, record PairingInviteRecord) error {
	return requirePairingLineage(conn, record)
}

func requirePairingGenesisDigest(
	conn *sqlite.Conn,
	record PairingInviteRecord,
	expected Digest,
) error {
	var (
		found  bool
		digest Digest
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT genesis_digest FROM genesis_records
		  WHERE recovery_generation = ?1 AND session_id = ?2 AND workspace_id = ?3;`,
		[]any{record.RecoveryGeneration, string(record.SessionID), string(record.WorkspaceID)},
		func(stmt *sqlite.Stmt) {
			if found {
				rowErr = ErrPairingStateIntegrity
				return
			}
			found = true
			rowErr = copyDigestColumn(&digest, stmt, 0)
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	if !found || digest != expected {
		return ErrPairingGenesisMismatch
	}
	return nil
}

func requirePairingIssuerOwner(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	identityPublicKey []byte,
) error {
	var (
		found bool
		key   []byte
	)
	err := queryArgs(
		conn,
		`SELECT identity_public_key FROM devices
		  WHERE device_id = ?1 AND role = 'owner' AND status = 'active';`,
		[]any{string(deviceID)},
		func(stmt *sqlite.Stmt) {
			if found {
				key = nil
				return
			}
			found = true
			key = columnBytes(stmt, 0)
		},
	)
	if err != nil {
		return err
	}
	if !found || len(key) != ed25519.PublicKeySize || !bytes.Equal(key, identityPublicKey) {
		return ErrPairingInviteUnavailable
	}
	return nil
}

func nullableDeviceIDPointer(value *domain.DeviceID) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func nullableUint64Pointer(value *uint64) any {
	if value == nil {
		return nil
	}
	return *value
}

func cloneDeviceIDPointer(value *domain.DeviceID) *domain.DeviceID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneUint64Pointer(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func clonePairingInvite(record PairingInviteRecord) PairingInviteRecord {
	record.SubjectDeviceID = cloneDeviceIDPointer(record.SubjectDeviceID)
	record.ExpectedEntityVersion = cloneUint64Pointer(record.ExpectedEntityVersion)
	return record
}
