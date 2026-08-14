package store

import (
	"bytes"
	"context"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/pairing"
	"zombiezen.com/go/sqlite"
)

// ConsumePairingInvite atomically creates the sole SAS attempt and consumes
// the invite after the caller has verified its exporter-bound proof.
func (state LocalState) ConsumePairingInvite(
	ctx context.Context,
	verified pairing.VerifiedRequest,
	observedAt domain.Timestamp,
) (PairingAttemptRecord, bool, error) {
	core := verified.Core()
	coreValue := core.Value()
	coreBytes := core.CanonicalBytes()
	if !observedAt.Valid() || !verified.InviteID().Valid() ||
		!coreValue.AttemptID.Valid() || len(coreBytes) == 0 {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	requestDigest := Digest(verified.RequestDigest())
	transcriptHash := Digest(verified.TranscriptHash())
	inviteDigest := Digest(verified.InviteDigest())

	var (
		result       PairingAttemptRecord
		duplicate    bool
		operationErr error
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		existing, found, err := readPairingAttempt(conn, coreValue.AttemptID)
		if err != nil {
			return err
		}
		if found {
			if existing.State == PairingAttemptProofRejected ||
				!samePairingAttemptInput(
					existing, verified.InviteID(), requestDigest, coreBytes,
					transcriptHash, coreValue.JoinerDeviceID,
				) {
				return ErrPairingConflict
			}
			result = existing
			duplicate = true
			return nil
		}

		invite, found, err := readPairingInvite(conn, verified.InviteID())
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingInviteNotFound
		}
		if err := requirePairingRecordLineage(conn, invite); err != nil {
			return err
		}
		if invite.InviteDigest != inviteDigest ||
			!pairingCoreMatchesInvite(coreValue, invite) {
			return ErrPairingConflict
		}
		if err := requirePairingEligibility(conn, invite, coreValue); err != nil {
			return err
		}
		if invite.State == PairingInviteExpired {
			return ErrPairingInviteExpired
		}
		if invite.State != PairingInviteOutstanding {
			return ErrPairingInviteUnavailable
		}
		usable, err := pairingInviteUsableAt(invite, observedAt)
		if err != nil {
			return err
		}
		if !usable {
			if err := expirePairingInvite(conn, invite, observedAt); err != nil {
				return err
			}
			operationErr = ErrPairingInviteExpired
			return nil
		}

		record := PairingAttemptRecord{
			AttemptID: coreValue.AttemptID, InviteID: verified.InviteID(),
			RequestDigest: requestDigest, RequestCore: bytes.Clone(coreBytes),
			TranscriptHash: transcriptHash, JoinerDeviceID: coreValue.JoinerDeviceID,
			State: PairingAttemptAwaitingSAS, CreatedAt: observedAt,
		}
		if err := insertPairingAttempt(conn, record); err != nil {
			return err
		}
		if err := deleteRejectedPairingAttempts(conn, invite.InviteID); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE pairing_invites
			    SET state = 'consumed', consumed_attempt_id = ?2, terminal_at = ?3
			  WHERE invite_id = ?1 AND state = 'outstanding';`,
			string(invite.InviteID), string(record.AttemptID), string(observedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		result = record
		return nil
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	if operationErr != nil {
		return PairingAttemptRecord{}, false, operationErr
	}
	return clonePairingAttempt(result), duplicate, nil
}

// RecordPairingProofFailure durably charges one structurally valid failed proof.
// The third distinct failure voids the invite in the same transaction.
func (state LocalState) RecordPairingProofFailure(
	ctx context.Context,
	input PairingProofFailureInput,
) (PairingAttemptRecord, bool, error) {
	coreValue := input.RequestCore.Value()
	coreBytes := input.RequestCore.CanonicalBytes()
	if !input.InviteID.Valid() || !coreValue.AttemptID.Valid() ||
		!input.ObservedAt.Valid() || len(coreBytes) == 0 {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	var (
		result             PairingAttemptRecord
		duplicate          bool
		attemptIDCollision bool
		operationErr       error
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		existing, found, err := readPairingAttempt(conn, coreValue.AttemptID)
		if err != nil {
			return err
		}
		if found {
			if existing.State == PairingAttemptProofRejected &&
				samePairingAttemptInput(
					existing,
					input.InviteID,
					input.RequestDigest,
					coreBytes,
					input.TranscriptHash,
					coreValue.JoinerDeviceID,
				) {
				result = existing
				duplicate = true
				return nil
			}
			attemptIDCollision = true
		}

		invite, found, err := readPairingInvite(conn, input.InviteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrPairingInviteNotFound
		}
		if err := requirePairingRecordLineage(conn, invite); err != nil {
			return err
		}
		if invite.InviteDigest != input.InviteDigest ||
			!pairingCoreMatchesInvite(coreValue, invite) {
			return ErrPairingConflict
		}
		if invite.State == PairingInviteExpired {
			return ErrPairingInviteExpired
		}
		if invite.State != PairingInviteOutstanding {
			return ErrPairingInviteUnavailable
		}
		usable, err := pairingInviteUsableAt(invite, input.ObservedAt)
		if err != nil {
			return err
		}
		if !usable {
			if err := expirePairingInvite(conn, invite, input.ObservedAt); err != nil {
				return err
			}
			operationErr = ErrPairingInviteExpired
			return nil
		}
		if invite.ProofFailures >= MaxPairingProofFailures {
			return ErrPairingStateIntegrity
		}

		if !attemptIDCollision {
			record := PairingAttemptRecord{
				AttemptID: coreValue.AttemptID, InviteID: input.InviteID,
				RequestDigest: input.RequestDigest, RequestCore: bytes.Clone(coreBytes),
				TranscriptHash: input.TranscriptHash, JoinerDeviceID: coreValue.JoinerDeviceID,
				State: PairingAttemptProofRejected, CreatedAt: input.ObservedAt,
				TerminalAt: input.ObservedAt,
			}
			if err := insertPairingAttempt(conn, record); err != nil {
				return err
			}
			result = record
		}
		nextFailures := invite.ProofFailures + 1
		if nextFailures == MaxPairingProofFailures {
			if err := execute(
				conn,
				`UPDATE pairing_invites
				    SET proof_failures = ?2, state = 'proof_exhausted', terminal_at = ?3
				  WHERE invite_id = ?1 AND state = 'outstanding';`,
				string(invite.InviteID), nextFailures, string(input.ObservedAt),
			); err != nil {
				return err
			}
		} else if err := execute(
			conn,
			`UPDATE pairing_invites SET proof_failures = ?2
			  WHERE invite_id = ?1 AND state = 'outstanding';`,
			string(invite.InviteID), nextFailures,
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		if nextFailures == MaxPairingProofFailures {
			if err := deleteRejectedPairingAttempts(conn, invite.InviteID); err != nil {
				return err
			}
		}
		if attemptIDCollision {
			operationErr = ErrPairingConflict
		}
		return nil
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	if operationErr != nil {
		return PairingAttemptRecord{}, false, operationErr
	}
	return clonePairingAttempt(result), duplicate, nil
}

// RecordPairingConfirmation records one side of the SAS comparison. A decline
// is terminal; two confirmations authorize durable finalization.
func (state LocalState) RecordPairingConfirmation(
	ctx context.Context,
	input PairingConfirmationInput,
) (PairingAttemptRecord, bool, error) {
	if !input.AttemptID.Valid() || !input.Party.valid() || !input.DecidedAt.Valid() {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	var (
		result       PairingAttemptRecord
		duplicate    bool
		operationErr error
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		record, found, err := readPairingAttempt(conn, input.AttemptID)
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
		if exactPairingConfirmation(record, input) {
			result = record
			duplicate = true
			return nil
		}
		if record.State != PairingAttemptAwaitingSAS {
			return ErrPairingConflict
		}
		beforeExpiry, err := timestampBefore(
			input.DecidedAt,
			domain.Timestamp(invite.ExpiresAt),
		)
		if err != nil {
			return ErrInvalidPairingState
		}
		if !beforeExpiry {
			if err := execute(
				conn,
				`UPDATE pairing_attempts
				    SET state = 'expired', terminal_at = ?2
				  WHERE attempt_id = ?1 AND state = 'awaiting_sas';`,
				string(input.AttemptID), string(input.DecidedAt),
			); err != nil {
				return err
			}
			if err := requireOneChangedRow(conn); err != nil {
				return err
			}
			operationErr = ErrPairingInviteExpired
			return nil
		}
		if input.Party == PairingConfirmationLocal && record.LocalConfirmed ||
			input.Party == PairingConfirmationRemote && record.RemoteConfirmed {
			return ErrPairingConflict
		}
		if before, err := timestampBefore(input.DecidedAt, record.CreatedAt); err != nil || before {
			return ErrInvalidPairingState
		}
		if !input.Confirmed {
			if err := execute(
				conn,
				`UPDATE pairing_attempts
				    SET state = 'declined', declined_by = ?2, terminal_at = ?3
				  WHERE attempt_id = ?1 AND state = 'awaiting_sas';`,
				string(input.AttemptID), string(input.Party), string(input.DecidedAt),
			); err != nil {
				return err
			}
		} else {
			nextLocal := record.LocalConfirmed || input.Party == PairingConfirmationLocal
			nextRemote := record.RemoteConfirmed || input.Party == PairingConfirmationRemote
			nextState := string(PairingAttemptAwaitingSAS)
			var terminalAt any
			if nextLocal && nextRemote {
				nextState = "confirmed"
				terminalAt = string(input.DecidedAt)
			}
			localAt, remoteAt := nullableTimestampValue(record.LocalConfirmedAt), nullableTimestampValue(record.RemoteConfirmedAt)
			if input.Party == PairingConfirmationLocal {
				localAt = string(input.DecidedAt)
			} else {
				remoteAt = string(input.DecidedAt)
			}
			if err := execute(
				conn,
				`UPDATE pairing_attempts
				    SET state = ?2, local_confirmed = ?3, remote_confirmed = ?4,
				        local_confirmed_at = ?5, remote_confirmed_at = ?6, terminal_at = ?7
				  WHERE attempt_id = ?1 AND state = 'awaiting_sas';`,
				string(input.AttemptID), string(nextState), nextLocal, nextRemote,
				localAt, remoteAt, terminalAt,
			); err != nil {
				return err
			}
			if nextLocal && nextRemote {
				if err := execute(
					conn,
					`INSERT INTO pairing_attempt_finalizations(
					    attempt_id, mode, state, started_at, completed_at
					) VALUES (?1, ?2, 'finalizing', ?3, NULL);`,
					string(record.AttemptID), string(invite.Mode), string(input.DecidedAt),
				); err != nil {
					return err
				}
			}
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		updated, found, err := readPairingAttempt(conn, input.AttemptID)
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
		return PairingAttemptRecord{}, false, err
	}
	if operationErr != nil {
		return PairingAttemptRecord{}, false, operationErr
	}
	return clonePairingAttempt(result), duplicate, nil
}

// TerminatePairingAttempt expires or revokes an unfinished SAS comparison.
func (state LocalState) TerminatePairingAttempt(
	ctx context.Context,
	attemptID domain.UUIDv7,
	target PairingAttemptState,
	terminatedAt domain.Timestamp,
) (PairingAttemptRecord, bool, error) {
	if !attemptID.Valid() || !terminatedAt.Valid() ||
		(target != PairingAttemptExpired && target != PairingAttemptRevoked) {
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
		if record.State == target {
			if record.TerminalAt != terminatedAt {
				return ErrPairingConflict
			}
			result = record
			duplicate = true
			return nil
		}
		if record.State != PairingAttemptAwaitingSAS {
			return ErrPairingConflict
		}
		beforeCreated, err := timestampBefore(terminatedAt, record.CreatedAt)
		if err != nil || beforeCreated {
			return ErrInvalidPairingState
		}
		if target == PairingAttemptExpired {
			beforeExpiry, err := timestampBefore(
				terminatedAt,
				domain.Timestamp(invite.ExpiresAt),
			)
			if err != nil || beforeExpiry {
				return ErrInvalidPairingState
			}
		}
		if err := execute(
			conn,
			`UPDATE pairing_attempts SET state = ?2, terminal_at = ?3
			  WHERE attempt_id = ?1 AND state = 'awaiting_sas';`,
			string(attemptID), string(target), string(terminatedAt),
		); err != nil {
			return err
		}
		if err := requireOneChangedRow(conn); err != nil {
			return err
		}
		updated, found, err := readPairingAttempt(conn, attemptID)
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
		return PairingAttemptRecord{}, false, err
	}
	return clonePairingAttempt(result), duplicate, nil
}

// PairingAttempt reads one durable proof/SAS attempt.
func (state LocalState) PairingAttempt(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (PairingAttemptRecord, bool, error) {
	if !attemptID.Valid() {
		return PairingAttemptRecord{}, false, ErrInvalidPairingState
	}
	var (
		record PairingAttemptRecord
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		record, found, err = readPairingAttempt(conn, attemptID)
		return err
	})
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	return clonePairingAttempt(record), found, nil
}

func insertPairingAttempt(conn *sqlite.Conn, record PairingAttemptRecord) error {
	if err := execute(
		conn,
		`INSERT INTO pairing_attempts(
		    attempt_id, invite_id, request_digest, request_core_json, transcript_hash,
		    joiner_device_id, state, local_confirmed, remote_confirmed,
		    local_confirmed_at, remote_confirmed_at, declined_by, created_at, terminal_at
		) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);`,
		string(record.AttemptID), string(record.InviteID), record.RequestDigest[:],
		string(record.RequestCore), record.TranscriptHash[:], string(record.JoinerDeviceID),
		string(record.State), record.LocalConfirmed, record.RemoteConfirmed,
		nullableTimestampValue(record.LocalConfirmedAt),
		nullableTimestampValue(record.RemoteConfirmedAt), nullableConfirmationParty(record.DeclinedBy),
		string(record.CreatedAt), nullableTimestampValue(record.TerminalAt),
	); err != nil {
		return err
	}
	return nil
}

func readPairingAttempt(
	conn *sqlite.Conn,
	attemptID domain.UUIDv7,
) (PairingAttemptRecord, bool, error) {
	var (
		record                PairingAttemptRecord
		finalizationMode      pairing.Mode
		finalizationStartedAt domain.Timestamp
		found                 bool
		rowErr                error
	)
	err := queryArgs(
		conn,
		`SELECT attempts.attempt_id, attempts.invite_id, attempts.request_digest,
		        attempts.request_core_json, attempts.transcript_hash,
		        attempts.joiner_device_id, attempts.state,
		        attempts.local_confirmed, attempts.remote_confirmed,
		        attempts.local_confirmed_at, attempts.remote_confirmed_at,
		        attempts.declined_by, attempts.created_at, attempts.terminal_at,
		        finalizations.mode, finalizations.state, finalizations.started_at,
		        finalizations.completed_at
		   FROM pairing_attempts AS attempts
		   LEFT JOIN pairing_attempt_finalizations AS finalizations
		     ON finalizations.attempt_id = attempts.attempt_id
		  WHERE attempts.attempt_id = ?1;`,
		[]any{string(attemptID)},
		func(stmt *sqlite.Stmt) {
			if found {
				rowErr = ErrPairingStateIntegrity
				return
			}
			found = true
			persistedState := stmt.ColumnText(6)
			record = PairingAttemptRecord{
				AttemptID: domain.UUIDv7(stmt.ColumnText(0)), InviteID: domain.UUIDv7(stmt.ColumnText(1)),
				RequestCore: []byte(stmt.ColumnText(3)), JoinerDeviceID: domain.DeviceID(stmt.ColumnText(5)),
				LocalConfirmed: stmt.ColumnInt64(7) == 1, RemoteConfirmed: stmt.ColumnInt64(8) == 1,
				CreatedAt: domain.Timestamp(stmt.ColumnText(12)),
			}
			switch persistedState {
			case "confirmed":
				if stmt.ColumnType(14) == sqlite.TypeNull ||
					stmt.ColumnType(15) == sqlite.TypeNull ||
					stmt.ColumnType(16) == sqlite.TypeNull {
					rowErr = ErrPairingStateIntegrity
					return
				}
				finalizationMode = pairing.Mode(stmt.ColumnText(14))
				finalizationStartedAt = domain.Timestamp(stmt.ColumnText(16))
				if !finalizationMode.Valid() {
					rowErr = ErrPairingStateIntegrity
					return
				}
				switch stmt.ColumnText(15) {
				case "finalizing":
					record.State = PairingAttemptFinalizing
				case "completed":
					record.State = PairingAttemptCompleted
				default:
					rowErr = ErrPairingStateIntegrity
					return
				}
			default:
				if stmt.ColumnType(14) != sqlite.TypeNull ||
					stmt.ColumnType(15) != sqlite.TypeNull ||
					stmt.ColumnType(16) != sqlite.TypeNull ||
					stmt.ColumnType(17) != sqlite.TypeNull {
					rowErr = ErrPairingStateIntegrity
					return
				}
				record.State = PairingAttemptState(persistedState)
			}
			if copyDigestColumn(&record.RequestDigest, stmt, 2) != nil ||
				copyDigestColumn(&record.TranscriptHash, stmt, 4) != nil {
				rowErr = ErrPairingStateIntegrity
				return
			}
			if stmt.ColumnType(9) != sqlite.TypeNull {
				record.LocalConfirmedAt = domain.Timestamp(stmt.ColumnText(9))
			}
			if stmt.ColumnType(10) != sqlite.TypeNull {
				record.RemoteConfirmedAt = domain.Timestamp(stmt.ColumnText(10))
			}
			if stmt.ColumnType(11) != sqlite.TypeNull {
				record.DeclinedBy = PairingConfirmationParty(stmt.ColumnText(11))
			}
			if stmt.ColumnType(13) != sqlite.TypeNull {
				record.TerminalAt = domain.Timestamp(stmt.ColumnText(13))
			}
			if stmt.ColumnType(17) != sqlite.TypeNull {
				record.FinalizedAt = domain.Timestamp(stmt.ColumnText(17))
			}
		},
	)
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	if rowErr != nil || !found {
		return PairingAttemptRecord{}, found, rowErr
	}
	invite, inviteFound, err := readPairingInvite(conn, record.InviteID)
	if err != nil {
		return PairingAttemptRecord{}, false, err
	}
	if !inviteFound {
		return PairingAttemptRecord{}, false, ErrPairingStateIntegrity
	}
	if (record.State == PairingAttemptFinalizing ||
		record.State == PairingAttemptCompleted) &&
		(finalizationMode != invite.Mode ||
			finalizationStartedAt != record.TerminalAt) {
		return PairingAttemptRecord{}, false, ErrPairingStateIntegrity
	}
	if err := record.validate(invite.SessionID); err != nil {
		return PairingAttemptRecord{}, false, err
	}
	if record.State == PairingAttemptProofRejected {
		if invite.ConsumedAttemptID == record.AttemptID {
			return PairingAttemptRecord{}, false, ErrPairingStateIntegrity
		}
	} else if invite.State != PairingInviteConsumed ||
		invite.ConsumedAttemptID != record.AttemptID {
		return PairingAttemptRecord{}, false, ErrPairingStateIntegrity
	}
	return record, true, nil
}

func pairingCoreMatchesInvite(core pairing.RequestCore, invite PairingInviteRecord) bool {
	return core.InitialEpochBinding.SessionID == invite.SessionID &&
		core.InitialEpochBinding.Epoch == invite.InitialCredentialEpoch &&
		(invite.SubjectDeviceID == nil || *invite.SubjectDeviceID == core.JoinerDeviceID)
}

func pairingInviteUsableAt(
	invite PairingInviteRecord,
	observedAt domain.Timestamp,
) (bool, error) {
	beforeCreated, err := timestampBefore(observedAt, domain.Timestamp(invite.CreatedAt))
	if err != nil || beforeCreated {
		return false, ErrInvalidPairingState
	}
	beforeExpiry, err := timestampBefore(observedAt, domain.Timestamp(invite.ExpiresAt))
	if err != nil {
		return false, ErrInvalidPairingState
	}
	return beforeExpiry, nil
}

func expirePairingInvite(
	conn *sqlite.Conn,
	invite PairingInviteRecord,
	expiredAt domain.Timestamp,
) error {
	if err := deleteRejectedPairingAttempts(conn, invite.InviteID); err != nil {
		return err
	}
	if err := execute(
		conn,
		`UPDATE pairing_invites SET state = 'expired', terminal_at = ?2
		  WHERE invite_id = ?1 AND state = 'outstanding';`,
		string(invite.InviteID), string(expiredAt),
	); err != nil {
		return err
	}
	return requireOneChangedRow(conn)
}

func deleteRejectedPairingAttempts(
	conn *sqlite.Conn,
	inviteID domain.UUIDv7,
) error {
	return execute(
		conn,
		`DELETE FROM pairing_attempts
		  WHERE invite_id = ?1 AND state = 'proof_rejected';`,
		string(inviteID),
	)
}

func exactPairingConfirmation(
	record PairingAttemptRecord,
	input PairingConfirmationInput,
) bool {
	if input.Confirmed {
		if input.Party == PairingConfirmationLocal {
			return record.LocalConfirmed && record.LocalConfirmedAt == input.DecidedAt
		}
		return record.RemoteConfirmed && record.RemoteConfirmedAt == input.DecidedAt
	}
	return record.State == PairingAttemptDeclined &&
		record.DeclinedBy == input.Party && record.TerminalAt == input.DecidedAt
}

func nullableTimestampValue(value domain.Timestamp) any {
	if value == "" {
		return nil
	}
	return string(value)
}

func nullableConfirmationParty(value PairingConfirmationParty) any {
	if value == "" {
		return nil
	}
	return string(value)
}

func clonePairingAttempt(record PairingAttemptRecord) PairingAttemptRecord {
	record.RequestCore = bytes.Clone(record.RequestCore)
	return record
}
