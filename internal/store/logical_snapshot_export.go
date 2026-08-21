package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var (
	ErrLogicalSnapshotNotCovered = errors.New(
		"store: logical snapshot checkpoint is not the current covered result",
	)
	ErrLogicalSnapshotSignerUnauthorized = errors.New(
		"store: logical snapshot signer is not active in the checkpoint authority",
	)
	ErrLogicalSnapshotIntegrity = errors.New(
		"store: logical snapshot export integrity failure",
	)
)

// LogicalSnapshotExportOptions selects one terminal checkpoint and the device
// that will sign the resulting root. The store verifies signer authority but
// never receives the signer's private key.
type LogicalSnapshotExportOptions struct {
	CheckpointEventID domain.UUIDv7
	SignerDeviceID    domain.DeviceID
}

func (options LogicalSnapshotExportOptions) validate() error {
	if !options.CheckpointEventID.Valid() ||
		!options.SignerDeviceID.Valid() {
		return fmt.Errorf(
			"%w: invalid logical-snapshot export options",
			ErrInvalidOptions,
		)
	}
	return nil
}

// LogicalSnapshotCut is the immutable signed-root state derived from the
// exported record stream. It describes the post-apply checkpoint result; the
// terminal checkpoint record itself attests the immediate pre-command cut.
type LogicalSnapshotCut struct {
	SessionID               domain.UUIDv7
	WorkspaceID             domain.UUIDv4
	RecoveryGeneration      uint64
	CheckpointEventID       domain.UUIDv7
	ChainIndex              uint64
	ChainHash               Digest
	ResultIndex             uint64
	ResultHash              Digest
	ProjectionAccumulator   Digest
	ProjectionStateDigest   Digest
	AuthorityVersion        uint64
	SignerDeviceID          domain.DeviceID
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
	RecordCount             uint64
}

// LogicalSnapshotRecordSink consumes one record synchronously. A failed
// export may already have emitted a prefix; callers must keep that prefix in
// quarantine until the complete artifact and signed root verify.
type LogicalSnapshotRecordSink func(
	context.Context,
	logicalsnapshot.Record,
) error

// ExportLogicalSnapshotRecords streams one complete, deterministic logical
// snapshot from a stable SQLite read transaction. It intentionally does not
// take applyMu: WAL readers retain their original cut while a concurrent FSM
// apply proceeds on another connection.
func (store *Store) ExportLogicalSnapshotRecords(
	ctx context.Context,
	options LogicalSnapshotExportOptions,
	sink LogicalSnapshotRecordSink,
) (LogicalSnapshotCut, error) {
	if ctx == nil {
		return LogicalSnapshotCut{}, fmt.Errorf(
			"%w: nil context",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return LogicalSnapshotCut{}, err
	}
	if err := options.validate(); err != nil {
		return LogicalSnapshotCut{}, err
	}
	if sink == nil {
		return LogicalSnapshotCut{}, fmt.Errorf(
			"%w: nil logical-snapshot record sink",
			ErrInvalidOptions,
		)
	}

	var cut LogicalSnapshotCut
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		operationContext, interrupt := context.WithCancel(ctx)
		defer interrupt()
		previousInterrupt := conn.SetInterrupt(operationContext.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return logicalSnapshotIntegrity(
				"active generation is missing",
				ErrLogicalSnapshotNotCovered,
			)
		}
		if state.digestVersion !=
			logicalsnapshot.SupportedDigestVersion ||
			state.projectionSchemaVersion !=
				logicalsnapshot.SupportedProjectionSchemaVersion {
			return logicalSnapshotIntegrity(
				"active commitment versions are unsupported",
				logicalsnapshot.ErrUnsupportedVersion,
			)
		}
		_, isSettled, err := verifyLogicalSnapshotEvidence(
			conn,
			state,
		)
		if err != nil {
			return err
		}
		checkpoint, err := verifyLogicalSnapshotCheckpoint(
			conn,
			state,
			options.CheckpointEventID,
			isSettled,
		)
		if err != nil {
			return err
		}
		if err := verifyLogicalSnapshotCheckpointKeepsAuthority(
			conn,
			checkpoint.CheckpointEventID,
		); err != nil {
			return err
		}

		authority, err := readStatusCredentialAuthority(
			conn,
			state.sessionID,
		)
		if err != nil {
			return logicalSnapshotIntegrity(
				"read checkpoint authority",
				err,
			)
		}
		if authority.VoterSetVersion !=
			checkpoint.AuthorityVoterSetVersion {
			return logicalSnapshotIntegrity(
				"checkpoint authority version differs from current cut",
				nil,
			)
		}
		if _, err := requireLogicalSnapshotSigner(
			conn,
			authority,
			options.SignerDeviceID,
		); err != nil {
			return err
		}
		checkpointSigner, err := requireLogicalSnapshotSigner(
			conn,
			authority,
			checkpoint.SignerDeviceID,
		)
		if err != nil {
			return logicalSnapshotIntegrity(
				"checkpoint signer authorization",
				err,
			)
		}
		if err := codecommcrypto.VerifyEd25519(
			checkpointSigner.IdentityPublicKey,
			codec.SignatureCheckpoint,
			checkpoint.CheckpointJSON,
			checkpoint.AuthoritySignature[:],
		); err != nil {
			return logicalSnapshotIntegrity(
				"checkpoint signature",
				err,
			)
		}

		emitter := logicalSnapshotEmitter{
			ctx:       ctx,
			sink:      sink,
			interrupt: interrupt,
		}
		if err := streamLogicalSnapshotGenesis(
			conn,
			state,
			checkpoint.WorkspaceID,
			&emitter,
		); err != nil {
			return err
		}
		if err := streamLogicalSnapshotResults(
			conn,
			state,
			&emitter,
		); err != nil {
			return err
		}
		if err := streamLogicalSnapshotEvents(
			conn,
			state,
			&emitter,
		); err != nil {
			return err
		}
		stateDigest, err := streamLogicalSnapshotProjections(
			conn,
			state,
			&emitter,
		)
		if err != nil {
			return err
		}
		signedCheckpoint, err := checkpoint.canonicalJSON(true)
		if err != nil {
			return logicalSnapshotIntegrity(
				"encode terminal checkpoint",
				err,
			)
		}
		checkpointPayload, err := logicalsnapshot.EncodeCheckpointPayload(
			logicalsnapshot.CheckpointPayload{
				CheckpointEventID: checkpoint.CheckpointEventID,
				SignedPayload:     signedCheckpoint,
			},
		)
		if err != nil {
			return logicalSnapshotIntegrity(
				"encode checkpoint record",
				err,
			)
		}
		if err := emitter.emit(
			logicalsnapshot.RecordCheckpoint,
			checkpointPayload,
		); err != nil {
			return err
		}

		cut = LogicalSnapshotCut{
			SessionID:               state.sessionID,
			WorkspaceID:             checkpoint.WorkspaceID,
			RecoveryGeneration:      state.recoveryGeneration,
			CheckpointEventID:       checkpoint.CheckpointEventID,
			ChainIndex:              state.chainIndex,
			ChainHash:               state.chainHash,
			ResultIndex:             state.resultIndex,
			ResultHash:              state.resultHash,
			ProjectionAccumulator:   state.projectionAccumulator,
			ProjectionStateDigest:   stateDigest,
			AuthorityVersion:        authority.VoterSetVersion,
			SignerDeviceID:          options.SignerDeviceID,
			DigestVersion:           state.digestVersion,
			ProjectionSchemaVersion: state.projectionSchemaVersion,
			RecordCount:             emitter.count,
		}
		return nil
	})
	if err != nil {
		return LogicalSnapshotCut{}, err
	}
	return cut, nil
}

// ExportLogicalSnapshotRecords exposes snapshot export through the restricted
// local-state capability used by content-plane services.
func (state LocalState) ExportLogicalSnapshotRecords(
	ctx context.Context,
	options LogicalSnapshotExportOptions,
	sink LogicalSnapshotRecordSink,
) (LogicalSnapshotCut, error) {
	if err := state.validate(); err != nil {
		return LogicalSnapshotCut{}, ErrInvalidLocalState
	}
	release, err := state.beginOperation()
	if err != nil {
		return LogicalSnapshotCut{}, err
	}
	defer release()
	return state.store.ExportLogicalSnapshotRecords(ctx, options, sink)
}

type logicalSnapshotEmitter struct {
	ctx       context.Context
	sink      LogicalSnapshotRecordSink
	interrupt context.CancelFunc
	count     uint64
}

type logicalSnapshotSinkError struct {
	recordType logicalsnapshot.RecordType
	index      uint64
	cause      error
}

func (failure *logicalSnapshotSinkError) Error() string {
	return fmt.Sprintf(
		"store: emit logical snapshot %s record %d: %v",
		failure.recordType,
		failure.index,
		failure.cause,
	)
}

func (failure *logicalSnapshotSinkError) Unwrap() error {
	return failure.cause
}

func (emitter *logicalSnapshotEmitter) emit(
	recordType logicalsnapshot.RecordType,
	payload []byte,
) error {
	if err := emitter.ctx.Err(); err != nil {
		return err
	}
	if emitter.count >= domain.MaxSafeInteger {
		return logicalSnapshotIntegrity(
			"record count exceeds exact protocol range",
			nil,
		)
	}
	if err := emitter.sink(emitter.ctx, logicalsnapshot.Record{
		Type:    recordType,
		Payload: payload,
	}); err != nil {
		emitter.interrupt()
		return &logicalSnapshotSinkError{
			recordType: recordType,
			index:      emitter.count,
			cause:      err,
		}
	}
	emitter.count++
	return emitter.ctx.Err()
}

func verifyLogicalSnapshotEvidence(
	conn *sqlite.Conn,
	state consensusState,
) (settledNonvoterState, bool, error) {
	if err := verifyCommitmentHistory(conn, state); err != nil {
		return settledNonvoterState{}, false,
			logicalSnapshotIntegrity("commitment history", err)
	}
	settled, isSettled, err := readSettledNonvoterState(conn)
	if err != nil {
		return settledNonvoterState{}, false, err
	}
	if isSettled {
		if err := verifySettledNonvoterEvidence(
			conn,
			state,
			settled,
		); err != nil {
			return settledNonvoterState{}, false,
				logicalSnapshotIntegrity(
					"settled-nonvoter evidence",
					err,
				)
		}
		return settled, true, nil
	}
	if err := verifyRaftCommandLedger(conn, state); err != nil {
		return settledNonvoterState{}, false,
			logicalSnapshotIntegrity("Raft command ledger", err)
	}
	return settledNonvoterState{}, false, nil
}

func verifyLogicalSnapshotCheckpoint(
	conn *sqlite.Conn,
	state consensusState,
	eventID domain.UUIDv7,
	settled bool,
) (CheckpointRecord, error) {
	checkpoint, found, err := readCheckpointRecord(conn, eventID)
	if err != nil {
		return CheckpointRecord{}, err
	}
	if !found {
		return CheckpointRecord{}, fmt.Errorf(
			"%w: checkpoint %s is missing",
			ErrLogicalSnapshotNotCovered,
			eventID,
		)
	}
	if err := checkpoint.Validate(); err != nil {
		return CheckpointRecord{},
			logicalSnapshotIntegrity("stored checkpoint", err)
	}
	if err := verifyCheckpointResultBinding(conn, checkpoint); err != nil {
		return CheckpointRecord{},
			logicalSnapshotIntegrity("checkpoint result binding", err)
	}
	if checkpoint.CoveredChainIndex >= domain.MaxSafeInteger ||
		checkpoint.CoveredResultIndex >= domain.MaxSafeInteger ||
		checkpoint.SessionID != state.sessionID ||
		checkpoint.RecoveryGeneration != state.recoveryGeneration ||
		checkpoint.DigestVersion != state.digestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			state.projectionSchemaVersion ||
		state.chainIndex != checkpoint.CoveredChainIndex+1 ||
		state.resultIndex != checkpoint.CoveredResultIndex+1 {
		return CheckpointRecord{}, ErrLogicalSnapshotNotCovered
	}

	result, found, err := readStoredCommandResult(
		conn,
		checkpoint.CheckpointEventID,
	)
	if err != nil {
		return CheckpointRecord{}, err
	}
	if !found ||
		result.chainIndex == nil ||
		result.chainHash == nil ||
		result.resultIndex != state.resultIndex ||
		*result.chainIndex != state.chainIndex ||
		result.resultHash != state.resultHash ||
		*result.chainHash != state.chainHash {
		return CheckpointRecord{},
			logicalSnapshotIntegrity(
				"checkpoint is not the current result head",
				ErrLogicalSnapshotNotCovered,
			)
	}

	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return CheckpointRecord{}, err
	}
	pre, err := resultRangeStart(
		conn,
		state,
		genesis,
		checkpoint.CoveredResultIndex,
	)
	if err != nil {
		return CheckpointRecord{}, err
	}
	accumulator, err := projectionAccumulatorAtResultCut(
		conn,
		state,
		genesis,
		checkpoint.CoveredResultIndex,
	)
	if err != nil {
		return CheckpointRecord{},
			logicalSnapshotIntegrity(
				"checkpoint projection cut",
				err,
			)
	}
	if pre.chainIndex != checkpoint.CoveredChainIndex ||
		pre.chainHash != checkpoint.CoveredChainHash ||
		pre.resultHash != checkpoint.CoveredResultHash ||
		accumulator != checkpoint.ProjectionAccumulator {
		return CheckpointRecord{},
			logicalSnapshotIntegrity(
				"checkpoint pre-command cut differs",
				nil,
			)
	}
	if !settled {
		if err := verifyLogicalSnapshotRaftCheckpointBinding(
			conn,
			checkpoint,
		); err != nil {
			return CheckpointRecord{}, err
		}
	}
	return checkpoint, nil
}

func verifyLogicalSnapshotRaftCheckpointBinding(
	conn *sqlite.Conn,
	checkpoint CheckpointRecord,
) error {
	if checkpoint.CoveredAppliedLogIndex >= domain.MaxSafeInteger {
		return logicalSnapshotIntegrity(
			"checkpoint Raft position is exhausted",
			nil,
		)
	}
	var count int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM command_results AS r
		   JOIN raft_command_applications AS a
		     ON a.recovery_generation = r.recovery_generation
		    AND a.event_id = r.event_id
		    AND a.proposal_digest = r.proposal_digest
		  WHERE r.event_id = ?1
		    AND r.session_id = ?2
		    AND r.workspace_id = ?3
		    AND r.recovery_generation = ?4
		    AND r.kind = 'consensus.checkpoint'
		    AND r.outcome_status = 'accepted'
		    AND r.chain_index = ?5
		    AND r.result_index = ?6
		    AND a.log_index = ?7
		    AND a.term = ?8;`,
		[]any{
			string(checkpoint.CheckpointEventID),
			string(checkpoint.SessionID),
			string(checkpoint.WorkspaceID),
			checkpoint.RecoveryGeneration,
			checkpoint.CoveredChainIndex + 1,
			checkpoint.CoveredResultIndex + 1,
			checkpoint.CoveredAppliedLogIndex + 1,
			checkpoint.Term,
		},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if count != 1 {
		return logicalSnapshotIntegrity(
			"checkpoint lacks its exact Raft command binding",
			nil,
		)
	}
	return nil
}

func verifyLogicalSnapshotCheckpointKeepsAuthority(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) error {
	var (
		encoded []byte
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT projection_mutations_json
		   FROM command_results
		  WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			encoded = []byte(stmt.ColumnText(0))
		},
	); err != nil {
		return err
	}
	if count != 1 {
		return logicalSnapshotIntegrity(
			"checkpoint mutation record is missing or duplicated",
			nil,
		)
	}
	mutations, err := chain.DecodeMutations(encoded)
	if err != nil {
		return logicalSnapshotIntegrity(
			"decode checkpoint mutations",
			err,
		)
	}
	canonical, err := chain.EncodeMutations(mutations)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return logicalSnapshotIntegrity(
			"checkpoint mutations do not round trip",
			err,
		)
	}
	for _, mutation := range mutations {
		if mutation.Table == "devices" ||
			mutation.Table == "credential_authority" {
			return logicalSnapshotIntegrity(
				"checkpoint command changes signer authority",
				nil,
			)
		}
	}
	return nil
}

func requireLogicalSnapshotSigner(
	conn *sqlite.Conn,
	authority interface {
		Contains(domain.DeviceID) bool
	},
	deviceID domain.DeviceID,
) (device.Device, error) {
	member, found, err := readStatusMember(conn, deviceID)
	if err != nil {
		return device.Device{}, err
	}
	if !found ||
		member.Status != device.StatusActive ||
		!authority.Contains(deviceID) {
		return device.Device{}, fmt.Errorf(
			"%w: %s",
			ErrLogicalSnapshotSignerUnauthorized,
			deviceID,
		)
	}
	return member, nil
}

func streamLogicalSnapshotGenesis(
	conn *sqlite.Conn,
	state consensusState,
	workspaceID domain.UUIDv4,
	emitter *logicalSnapshotEmitter,
) error {
	var (
		nextGeneration uint64
		lastSessionID  domain.UUIDv7
		rowErr         error
	)
	err := queryArgs(
		conn,
		`SELECT recovery_generation, session_id, workspace_id,
		        genesis_json, recovery_authorization_json,
		        boundary_transform_digest
		   FROM genesis_records
		  WHERE recovery_generation <= ?1
		  ORDER BY recovery_generation;`,
		[]any{state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			generation := stmt.ColumnInt64(0)
			sessionID := domain.UUIDv7(stmt.ColumnText(1))
			storedWorkspaceID := domain.UUIDv4(stmt.ColumnText(2))
			if generation < 0 ||
				uint64(generation) != nextGeneration ||
				!sessionID.Valid() ||
				storedWorkspaceID != workspaceID {
				rowErr = errors.New(
					"genesis lineage is not dense or changes workspace",
				)
				return
			}
			var transform Digest
			if rowErr = copyDigestColumn(&transform, stmt, 5); rowErr != nil {
				return
			}
			var recovery []byte
			if stmt.ColumnType(4) != sqlite.TypeNull {
				recovery = []byte(stmt.ColumnText(4))
			}
			payload, err := logicalsnapshot.EncodeGenesisPayload(
				logicalsnapshot.GenesisPayload{
					GenesisJSON:               []byte(stmt.ColumnText(3)),
					RecoveryAuthorizationJSON: recovery,
					BoundaryTransformDigest: chain.Digest(
						transform,
					),
				},
			)
			if err != nil {
				rowErr = err
				return
			}
			rowErr = emitter.emit(logicalsnapshot.RecordGenesis, payload)
			if rowErr != nil {
				return
			}
			nextGeneration++
			lastSessionID = sessionID
		},
	)
	if rowErr != nil {
		return classifyLogicalSnapshotStreamError(
			"stream genesis lineage",
			rowErr,
		)
	}
	if err != nil {
		return err
	}
	if nextGeneration != state.recoveryGeneration+1 ||
		lastSessionID != state.sessionID {
		return logicalSnapshotIntegrity(
			"genesis lineage does not reach active generation",
			nil,
		)
	}
	return nil
}

func streamLogicalSnapshotResults(
	conn *sqlite.Conn,
	state consensusState,
	emitter *logicalSnapshotEmitter,
) error {
	nextResult := uint64(1)
	var rowErr error
	err := queryArgs(
		conn,
		`SELECT event_id, projection_mutations_json
		   FROM command_results
		  WHERE result_index <= ?1
		  ORDER BY result_index;`,
		[]any{state.resultIndex},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			if !eventID.Valid() {
				rowErr = errors.New("invalid result event ID")
				return
			}
			stored, found, err := readStoredCommandResult(conn, eventID)
			if err != nil {
				rowErr = err
				return
			}
			if !found || stored.resultIndex != nextResult {
				rowErr = errors.New("result indexes are not a dense prefix")
				return
			}
			if err := verifyStoredCommandResult(conn, stored); err != nil {
				rowErr = err
				return
			}
			mutationJSON := []byte(stmt.ColumnText(1))
			mutations, err := chain.DecodeMutations(mutationJSON)
			if err != nil {
				rowErr = err
				return
			}
			result := chain.Result{
				ResultIndex:    stored.resultIndex,
				Proposal:       stored.proposalJSON,
				Outcome:        stored.outcome.JSON,
				ProposalDigest: chain.Digest(stored.proposalDigest),
			}
			if stored.chainIndex != nil {
				index := *stored.chainIndex
				hash := chain.Digest(*stored.chainHash)
				result.ChainIndex = &index
				result.ChainHash = &hash
			}
			resultPayload, encodedMutations, err :=
				logicalsnapshot.NewResultPayload(result, mutations)
			if err != nil {
				rowErr = err
				return
			}
			if !bytes.Equal(encodedMutations, mutationJSON) {
				rowErr = errors.New(
					"projection mutations do not round trip",
				)
				return
			}
			encodedResult, err := logicalsnapshot.EncodeResultPayload(
				resultPayload,
			)
			if err != nil {
				rowErr = err
				return
			}
			if err := emitter.emit(
				logicalsnapshot.RecordResult,
				encodedResult,
			); err != nil {
				rowErr = err
				return
			}
			for offset, chunkIndex := 0, uint64(0); offset < len(encodedMutations); chunkIndex++ {
				end := offset + logicalsnapshot.MaxMutationChunkBytes
				if end > len(encodedMutations) {
					end = len(encodedMutations)
				}
				payload, err :=
					logicalsnapshot.EncodeMutationChunkPayload(
						logicalsnapshot.MutationChunkPayload{
							ResultIndex: stored.resultIndex,
							ChunkIndex:  chunkIndex,
							Data: bytes.Clone(
								encodedMutations[offset:end],
							),
						},
					)
				if err != nil {
					rowErr = err
					return
				}
				if err := emitter.emit(
					logicalsnapshot.RecordMutation,
					payload,
				); err != nil {
					rowErr = err
					return
				}
				offset = end
			}
			nextResult++
		},
	)
	if rowErr != nil {
		return classifyLogicalSnapshotStreamError(
			"stream result history",
			rowErr,
		)
	}
	if err != nil {
		return err
	}
	if nextResult != state.resultIndex+1 {
		return logicalSnapshotIntegrity(
			"result history does not reach current head",
			nil,
		)
	}
	return nil
}

func streamLogicalSnapshotEvents(
	conn *sqlite.Conn,
	state consensusState,
	emitter *logicalSnapshotEmitter,
) error {
	nextEvent := uint64(1)
	var rowErr error
	err := queryArgs(
		conn,
		`SELECT event_id
		   FROM command_results
		  WHERE chain_index IS NOT NULL AND chain_index <= ?1
		  ORDER BY chain_index;`,
		[]any{state.chainIndex},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			stored, found, err := readStoredCommandResult(conn, eventID)
			if err != nil {
				rowErr = err
				return
			}
			if !found ||
				stored.chainIndex == nil ||
				stored.chainHash == nil ||
				*stored.chainIndex != nextEvent {
				rowErr = errors.New("event indexes are not a dense prefix")
				return
			}
			if err := verifyStoredCommandResult(conn, stored); err != nil {
				rowErr = err
				return
			}
			payload, err := logicalsnapshot.EncodeEventPayload(
				logicalsnapshot.EventPayload{
					ChainIndex: *stored.chainIndex,
					ChainHash: chain.Digest(
						*stored.chainHash,
					),
					Proposal: stored.proposalJSON,
				},
			)
			if err != nil {
				rowErr = err
				return
			}
			if err := emitter.emit(
				logicalsnapshot.RecordEvent,
				payload,
			); err != nil {
				rowErr = err
				return
			}
			nextEvent++
		},
	)
	if rowErr != nil {
		return classifyLogicalSnapshotStreamError(
			"stream accepted events",
			rowErr,
		)
	}
	if err != nil {
		return err
	}
	if nextEvent != state.chainIndex+1 {
		return logicalSnapshotIntegrity(
			"event history does not reach current head",
			nil,
		)
	}
	return nil
}

func streamLogicalSnapshotProjections(
	conn *sqlite.Conn,
	state consensusState,
	emitter *logicalSnapshotEmitter,
) (Digest, error) {
	counts, err := projectionTableRowCounts(conn)
	if err != nil {
		return Digest{}, err
	}
	digester, err := chain.NewStateDigester(chain.Versions{
		Digest:           state.digestVersion,
		ProjectionSchema: state.projectionSchemaVersion,
	}, counts)
	if err != nil {
		return Digest{}, logicalSnapshotIntegrity(
			"prepare projection-state digest",
			err,
		)
	}
	err = streamProjectionLogicalRows(
		conn,
		func(row chain.LogicalRow) error {
			if err := digester.Append(row); err != nil {
				return err
			}
			payload, err := logicalsnapshot.EncodeProjectionPayload(
				logicalsnapshot.ProjectionPayload{Row: row},
			)
			if err != nil {
				return err
			}
			return emitter.emit(
				logicalsnapshot.RecordProjection,
				payload,
			)
		},
	)
	if err != nil {
		return Digest{}, classifyLogicalSnapshotStreamError(
			"stream projection state",
			err,
		)
	}
	digest, err := digester.Sum()
	if err != nil {
		return Digest{}, logicalSnapshotIntegrity(
			"finish projection-state digest",
			err,
		)
	}
	return Digest(digest), nil
}

func logicalSnapshotIntegrity(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrLogicalSnapshotIntegrity, detail)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrLogicalSnapshotIntegrity,
		detail,
		cause,
	)
}

func classifyLogicalSnapshotStreamError(
	detail string,
	err error,
) error {
	var sinkError *logicalSnapshotSinkError
	if errors.As(err, &sinkError) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return logicalSnapshotIntegrity(detail, err)
}
