package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrInvalidResultBatchImport = errors.New(
	"store: invalid settled-nonvoter result batch import",
)

// ResultBatchLocalWrites contains local rows derived while scratch-replaying
// one replicated command. AppliedAt is local observation time, not Raft
// provenance.
type ResultBatchLocalWrites struct {
	AppliedAt            domain.Timestamp
	RecordActivity       bool
	ActivityTaskID       domain.UUIDv7
	Audit                []AuditRecord
	Checkpoint           *CheckpointRecord
	LeaseDeadlines       []LeaseDeadlineRecord
	DeleteLeaseDeadlines []LeaseDeadlineKey
}

// ResultBatchCommand is one fully scratch-verified command and its exact
// deterministic persistence artifacts.
type ResultBatchCommand struct {
	Proposal    event.SignedEvent
	Outcome     CommandOutcome
	Projections ProjectionWrites
	Mutations   []chain.Mutation
	Heads       ApplyHeads
	Local       ResultBatchLocalWrites
}

// VerifiedResultBatchImport is the complete input to one atomic
// settled-nonvoter import. RelayPeerID identifies the authenticated transport
// peer and may differ from the authority device that signed Batch.
type VerifiedResultBatchImport struct {
	RelayPeerID           domain.DeviceID
	Batch                 replication.Batch
	Commands              []ResultBatchCommand
	VerifiedAt            domain.Timestamp
	FinalProjectionDigest Digest
}

// ResultBatchImportResult names the newly durable cut.
type ResultBatchImportResult struct {
	Heads             ApplyHeads
	AttestationID     string
	AdmissionRevision uint64
}

// ImportSettledNonvoterResultBatch atomically persists a batch already
// cryptographically and semantically verified by the consensus layer. The
// store independently re-derives all SQLite mutations and commitments.
func (store *Store) ImportSettledNonvoterResultBatch(
	ctx context.Context,
	request VerifiedResultBatchImport,
) (ResultBatchImportResult, error) {
	if err := validateResultBatchImportInput(ctx, request); err != nil {
		return ResultBatchImportResult{}, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var result ResultBatchImportResult
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return resultBatchImportError("active generation is missing")
		}
		settled, found, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: %w",
				ErrInvalidResultBatchImport,
				ErrReplicaEvidenceMode,
			)
		}
		if err := validateSettledNonvoterState(conn, state, settled); err != nil {
			return fmt.Errorf(
				"%w: validate settled-nonvoter state: %w",
				ErrInvalidResultBatchImport,
				err,
			)
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return fmt.Errorf(
				"%w: verify existing commitment history: %w",
				ErrInvalidResultBatchImport,
				err,
			)
		}
		if err := verifySettledNonvoterEvidence(conn, state, settled); err != nil {
			return fmt.Errorf(
				"%w: verify existing settled-nonvoter evidence: %w",
				ErrInvalidResultBatchImport,
				err,
			)
		}

		input := request.Batch.Unsigned().Input()
		startProjectionDigest, err := projectionStateDigest(
			conn,
			chain.Versions{
				Digest:           state.digestVersion,
				ProjectionSchema: state.projectionSchemaVersion,
			},
		)
		if err != nil {
			return err
		}
		if err := validateResultBatchStart(
			state,
			settled,
			input,
			startProjectionDigest,
		); err != nil {
			return err
		}
		if err := validateReplicationCursorStart(
			conn,
			request.RelayPeerID,
			input,
		); err != nil {
			return err
		}

		prior := state
		var finalHeads ApplyHeads
		for index := range request.Commands {
			command := request.Commands[index]
			encodedResult := input.Results[index]
			decoded, err := chain.DecodeResult(encodedResult)
			if err != nil {
				return resultBatchCommandError(index, "decode result", err)
			}
			applyRequest, err := validateResultBatchCommand(
				prior,
				input.WorkspaceID,
				command,
				decoded,
			)
			if err != nil {
				return resultBatchCommandError(index, "validate", err)
			}
			prepared, err := prepareProjectionWrites(command.Projections)
			if err != nil {
				return resultBatchCommandError(index, "prepare projections", err)
			}
			mutations, err := projectionMutations(conn, prepared)
			if err != nil {
				return resultBatchCommandError(index, "apply projections", err)
			}
			if !equalResultBatchMutations(mutations, command.Mutations) {
				return resultBatchCommandError(
					index,
					"projection mutations",
					errors.New("SQLite before/after images differ from scratch replay"),
				)
			}
			if err := store.reachApplyStage(
				applyAfterProjections,
			); err != nil {
				return err
			}
			heads, mutationJSON, err := deriveResultBatchCommitments(
				prior,
				decoded,
				encodedResult,
				mutations,
			)
			if err != nil {
				return resultBatchCommandError(index, "derive commitments", err)
			}
			if heads != command.Heads {
				return resultBatchCommandError(
					index,
					"compare heads",
					errors.New("scratch-replayed heads differ from SQLite derivation"),
				)
			}
			if err := validateResultBatchLocalWrites(
				prior,
				applyRequest,
				heads,
				prepared,
			); err != nil {
				return resultBatchCommandError(index, "validate local rows", err)
			}

			if applyRequest.Outcome.Status == OutcomeAccepted {
				if err := writeAcceptedEvent(conn, applyRequest); err != nil {
					return resultBatchCommandError(index, "write event", err)
				}
			}
			if err := store.reachApplyStage(applyAfterEvent); err != nil {
				return err
			}
			if err := store.reachApplyStage(
				applyAfterProvenance,
			); err != nil {
				return err
			}
			if err := ensurePendingControlFileApprovals(
				conn,
				prior.sessionID,
				prepared.controlFileProposalRows,
			); err != nil {
				return resultBatchCommandError(
					index,
					"write control-file approvals",
					err,
				)
			}
			if err := writeCommandResult(
				conn,
				applyRequest,
				heads,
				encodedResult,
				mutationJSON,
			); err != nil {
				return resultBatchCommandError(index, "write result", err)
			}
			if err := store.reachApplyStage(applyAfterResult); err != nil {
				return err
			}
			if err := store.writeResultBatchLocalRows(
				conn,
				applyRequest,
			); err != nil {
				return resultBatchCommandError(index, "write local rows", err)
			}
			if err := writePostCommandLocalCleanup(
				conn,
				applyRequest,
			); err != nil {
				return resultBatchCommandError(
					index,
					"clean local command state",
					err,
				)
			}
			if err := store.reachApplyStage(applyAfterOutbox); err != nil {
				return err
			}
			finalHeads = heads
			prior = consensusStateFromImportedHeads(prior, heads)
		}

		if err := validateResultBatchEnd(input, finalHeads); err != nil {
			return err
		}
		digest, err := projectionStateDigest(conn, chain.Versions{
			Digest:           prior.digestVersion,
			ProjectionSchema: prior.projectionSchemaVersion,
		})
		if err != nil {
			return err
		}
		if digest != request.FinalProjectionDigest ||
			digest != Digest(input.EndProjectionStateDigest) {
			return resultBatchImportError(
				"final SQLite projection digest differs from verified batch",
			)
		}
		if err := writeImportedConsensusHeads(conn, state, finalHeads); err != nil {
			return err
		}
		if err := writeResultBatchAttestation(
			conn,
			request.Batch,
			request.VerifiedAt,
		); err != nil {
			return err
		}
		if err := writeReplicationCursor(
			conn,
			request.RelayPeerID,
			input,
			request.VerifiedAt,
		); err != nil {
			return err
		}
		if err := store.reachApplyStage(applyAfterConsensus); err != nil {
			return err
		}

		persisted, _, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if persisted.currentTerm != settled.frozenCurrentTerm ||
			persisted.lastAppliedLogIndex !=
				settled.frozenLastRaftAppliedLogIndex {
			return resultBatchImportError("Raft watermark changed during import")
		}
		result.Heads = finalHeads
		result.AttestationID = request.Batch.AttestationID()
		return nil
	})
	if err != nil {
		return ResultBatchImportResult{}, err
	}
	result.AdmissionRevision = store.advanceAdmissionRevision()
	return result, nil
}

func validateResultBatchImportInput(
	ctx context.Context,
	request VerifiedResultBatchImport,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.RelayPeerID.Valid() ||
		!request.VerifiedAt.Valid() ||
		request.Batch.EncodedLen() == 0 ||
		request.Batch.AttestationID() == "" ||
		len(request.Commands) == 0 {
		return resultBatchImportError("invalid relay, batch, time, or commands")
	}
	input := request.Batch.Unsigned().Input()
	if len(request.Commands) != len(input.Results) {
		return resultBatchImportError("command count differs from signed results")
	}
	return nil
}

func validateResultBatchStart(
	state consensusState,
	settled settledNonvoterState,
	input replication.BatchInput,
	projectionStateDigest Digest,
) error {
	if input.SessionID != state.sessionID ||
		input.WorkspaceID != settled.workspaceID ||
		input.RecoveryGeneration != state.recoveryGeneration ||
		state.resultIndex == domain.MaxSafeInteger ||
		input.FromResultIndex != state.resultIndex+1 ||
		input.StartResultHash != chain.Digest(state.resultHash) ||
		input.StartChainIndex != state.chainIndex ||
		input.StartChainHash != chain.Digest(state.chainHash) ||
		input.StartProjectionAccumulator !=
			chain.Digest(state.projectionAccumulator) ||
		input.StartProjectionStateDigest !=
			chain.Digest(projectionStateDigest) {
		return resultBatchImportError(
			"batch does not exactly extend the durable lineage and heads",
		)
	}
	return nil
}

func validateResultBatchCommand(
	prior consensusState,
	workspaceID domain.UUIDv4,
	command ResultBatchCommand,
	result chain.Result,
) (ApplyRequest, error) {
	local := command.Local
	request := ApplyRequest{
		AppliedAt:            local.AppliedAt,
		RecoveryGeneration:   prior.recoveryGeneration,
		Proposal:             command.Proposal,
		Outcome:              command.Outcome,
		Projections:          command.Projections,
		RecordActivity:       local.RecordActivity,
		ActivityTaskID:       local.ActivityTaskID,
		Audit:                local.Audit,
		Checkpoint:           local.Checkpoint,
		LeaseDeadlines:       local.LeaseDeadlines,
		DeleteLeaseDeadlines: local.DeleteLeaseDeadlines,
	}
	proposal := request.Proposal.Proposal()
	if !request.AppliedAt.Valid() ||
		proposal.SessionID != prior.sessionID ||
		proposal.WorkspaceID != workspaceID ||
		proposal.ValidateEnvelope() != nil ||
		len(request.Proposal.OriginSignature()) != ed25519.SignatureSize {
		return ApplyRequest{}, ErrInvalidApply
	}
	canonical := request.Proposal.CanonicalBytes()
	reencoded, err := codec.CanonicalizeSignedObject(canonical)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return ApplyRequest{}, fmt.Errorf(
			"%w: proposal bytes are not canonical",
			ErrInvalidApply,
		)
	}
	if !bytes.Equal(result.Proposal, canonical) ||
		result.ProposalDigest != chain.Digest(proposalDigest(request.Proposal)) {
		return ApplyRequest{}, resultBatchImportError(
			"result proposal binding differs from signed proposal",
		)
	}
	if err := request.Outcome.validate(); err != nil {
		return ApplyRequest{}, err
	}
	if !bytes.Equal(result.Outcome, request.Outcome.JSON) {
		return ApplyRequest{}, resultBatchImportError(
			"result outcome differs from scratch replay",
		)
	}
	accepted := request.Outcome.Status == OutcomeAccepted
	if accepted != (result.ChainIndex != nil && result.ChainHash != nil) {
		return ApplyRequest{}, resultBatchImportError(
			"outcome and accepted event tuple disagree",
		)
	}
	expectedActivity := accepted &&
		(proposal.RationaleSummary != "" || len(proposal.Actions) != 0)
	if request.RecordActivity != expectedActivity {
		return ApplyRequest{}, fmt.Errorf(
			"%w: activity directive does not match proposal",
			ErrInvalidApply,
		)
	}
	if request.RecordActivity {
		if request.ActivityTaskID != "" &&
			!request.ActivityTaskID.Valid() {
			return ApplyRequest{}, ErrInvalidApply
		}
		expectedTaskID, err := activityTaskID(proposal)
		if err != nil ||
			proposal.Kind == event.KindActivityRecorded &&
				request.ActivityTaskID != expectedTaskID {
			return ApplyRequest{}, ErrInvalidApply
		}
	} else if request.ActivityTaskID != "" {
		return ApplyRequest{}, ErrInvalidApply
	}
	for index := range request.Audit {
		if err := request.Audit[index].Validate(); err != nil {
			return ApplyRequest{}, fmt.Errorf(
				"%w: audit[%d]: %v",
				ErrInvalidApply,
				index,
				err,
			)
		}
	}
	for index := range request.LeaseDeadlines {
		if err := request.LeaseDeadlines[index].Validate(); err != nil {
			return ApplyRequest{}, fmt.Errorf(
				"%w: lease deadline[%d]: %v",
				ErrInvalidApply,
				index,
				err,
			)
		}
	}
	for index := range request.DeleteLeaseDeadlines {
		if err := request.DeleteLeaseDeadlines[index].Validate(); err != nil {
			return ApplyRequest{}, fmt.Errorf(
				"%w: lease deadline delete[%d]: %v",
				ErrInvalidApply,
				index,
				err,
			)
		}
	}
	return request, nil
}

func deriveResultBatchCommitments(
	prior consensusState,
	result chain.Result,
	encodedResult []byte,
	mutations []chain.Mutation,
) (ApplyHeads, []byte, error) {
	if prior.resultIndex == domain.MaxSafeInteger ||
		result.ResultIndex != prior.resultIndex+1 {
		return ApplyHeads{}, nil, resultBatchImportError(
			"result position is not the next dense index",
		)
	}
	heads := headsFromConsensus(prior)
	heads.PreviousResultHash = prior.resultHash
	heads.ResultIndex = result.ResultIndex
	if result.ChainIndex != nil {
		if prior.chainIndex == domain.MaxSafeInteger ||
			*result.ChainIndex != prior.chainIndex+1 ||
			result.ChainHash == nil {
			return ApplyHeads{}, nil, resultBatchImportError(
				"accepted event position is not dense",
			)
		}
		eventHash, err := chain.AppendEvent(
			chain.Digest(prior.chainHash),
			result.Proposal,
		)
		if err != nil || eventHash != *result.ChainHash {
			return ApplyHeads{}, nil, resultBatchImportError(
				"accepted event commitment differs",
			)
		}
		heads.ChainIndex = *result.ChainIndex
		heads.ChainHash = Digest(*result.ChainHash)
	}
	resultHash, canonicalResult, err := chain.AppendResult(
		chain.Digest(prior.resultHash),
		result,
	)
	if err != nil || !bytes.Equal(canonicalResult, encodedResult) {
		return ApplyHeads{}, nil, resultBatchImportError(
			"result commitment does not round trip",
		)
	}
	heads.ResultHash = Digest(resultHash)
	accumulator, mutationJSON, err := chain.AppendAccumulator(
		chain.Digest(prior.projectionAccumulator),
		result.ResultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		return ApplyHeads{}, nil, fmt.Errorf(
			"%w: append projection accumulator: %v",
			ErrInvalidResultBatchImport,
			err,
		)
	}
	heads.ProjectionAccumulator = Digest(accumulator)
	return heads, mutationJSON, nil
}

func validateResultBatchLocalWrites(
	prior consensusState,
	request ApplyRequest,
	heads ApplyHeads,
	prepared preparedProjectionWrites,
) error {
	if err := validateAppliedControlFileProjections(
		request,
		heads,
		prepared.controlFileProposalRows,
	); err != nil {
		return err
	}
	if err := request.validateAuditBinding(
		request.Proposal.Proposal(),
		heads.ResultIndex,
	); err != nil {
		return err
	}
	checkpoint := request.Checkpoint
	isCheckpoint := request.Proposal.Proposal().Kind ==
		event.KindConsensusCheckpoint
	if isCheckpoint &&
		request.Outcome.Status == OutcomeAccepted &&
		checkpoint == nil {
		return fmt.Errorf(
			"%w: accepted checkpoint requires a checkpoint row",
			ErrInvalidApply,
		)
	}
	if checkpoint == nil {
		return nil
	}
	if err := checkpoint.Validate(); err != nil {
		return fmt.Errorf("%w: checkpoint: %v", ErrInvalidApply, err)
	}
	proposal := request.Proposal.Proposal()
	if request.Outcome.Status != OutcomeAccepted ||
		!isCheckpoint ||
		checkpoint.CheckpointEventID != proposal.EventID ||
		checkpoint.SessionID != proposal.SessionID ||
		checkpoint.WorkspaceID != proposal.WorkspaceID ||
		checkpoint.RecoveryGeneration != prior.recoveryGeneration ||
		!checkpoint.matchesPayload(proposal.Payload) ||
		checkpoint.CoveredChainIndex != prior.chainIndex ||
		checkpoint.CoveredChainHash != prior.chainHash ||
		checkpoint.CoveredResultIndex != prior.resultIndex ||
		checkpoint.CoveredResultHash != prior.resultHash ||
		checkpoint.ProjectionAccumulator != prior.projectionAccumulator ||
		checkpoint.DigestVersion != prior.digestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			prior.projectionSchemaVersion {
		return fmt.Errorf(
			"%w: checkpoint does not match proposal and pre-command cut",
			ErrApplyConflict,
		)
	}
	return nil
}

func (store *Store) writeResultBatchLocalRows(
	conn *sqlite.Conn,
	request ApplyRequest,
) error {
	if request.RecordActivity {
		if err := writeActivity(conn, request); err != nil {
			return err
		}
	}
	if err := store.reachApplyStage(applyAfterActivity); err != nil {
		return err
	}
	if err := writeAudit(conn, request.Audit); err != nil {
		return err
	}
	if err := store.reachApplyStage(applyAfterAudit); err != nil {
		return err
	}
	if request.Checkpoint != nil {
		if err := writeCheckpoint(conn, *request.Checkpoint); err != nil {
			return err
		}
	}
	if err := store.reachApplyStage(applyAfterCheckpoint); err != nil {
		return err
	}
	if err := writeLeaseDeadlines(
		conn,
		request.LeaseDeadlines,
		request.DeleteLeaseDeadlines,
	); err != nil {
		return err
	}
	return store.reachApplyStage(applyAfterLeaseDeadlines)
}

func consensusStateFromImportedHeads(
	prior consensusState,
	heads ApplyHeads,
) consensusState {
	prior.chainIndex = heads.ChainIndex
	prior.chainHash = heads.ChainHash
	prior.resultIndex = heads.ResultIndex
	prior.resultHash = heads.ResultHash
	prior.projectionAccumulator = heads.ProjectionAccumulator
	return prior
}

func validateResultBatchEnd(
	input replication.BatchInput,
	heads ApplyHeads,
) error {
	if heads.ResultIndex != input.ToResultIndex ||
		heads.ResultHash != Digest(input.EndResultHash) ||
		heads.ChainIndex != input.EndChainIndex ||
		heads.ChainHash != Digest(input.EndChainHash) ||
		heads.ProjectionAccumulator !=
			Digest(input.EndProjectionAccumulator) {
		return resultBatchImportError(
			"derived ending heads differ from signed envelope",
		)
	}
	return nil
}

func writeImportedConsensusHeads(
	conn *sqlite.Conn,
	start consensusState,
	heads ApplyHeads,
) error {
	if err := execute(
		conn,
		`UPDATE consensus_state
		    SET chain_index = ?1, chain_hash = ?2, result_index = ?3,
		        result_hash = ?4, projection_accumulator = ?5
		  WHERE singleton = 1
		    AND session_id = ?6 AND recovery_generation = ?7
		    AND chain_index = ?8 AND chain_hash = ?9
		    AND result_index = ?10 AND result_hash = ?11
		    AND projection_accumulator = ?12;`,
		heads.ChainIndex,
		heads.ChainHash[:],
		heads.ResultIndex,
		heads.ResultHash[:],
		heads.ProjectionAccumulator[:],
		string(start.sessionID),
		start.recoveryGeneration,
		start.chainIndex,
		start.chainHash[:],
		start.resultIndex,
		start.resultHash[:],
		start.projectionAccumulator[:],
	); err != nil {
		return err
	}
	var changed int64
	if err := queryOne(
		conn,
		"SELECT changes();",
		func(stmt *sqlite.Stmt) {
			changed = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if changed != 1 {
		return resultBatchImportError(
			"durable consensus heads changed before update",
		)
	}
	return nil
}

func writeResultBatchAttestation(
	conn *sqlite.Conn,
	batch replication.Batch,
	verifiedAt domain.Timestamp,
) error {
	metadata := batch.Unsigned().Metadata()
	signature := batch.Signature()
	return execute(
		conn,
		`INSERT INTO replication_attestations(
		    attestation_id, attestation_kind, session_id, workspace_id,
		    recovery_generation, signer_device_id,
		    authority_voter_set_version, from_result_index, to_result_index,
		    start_result_hash, end_result_hash, start_chain_index,
		    end_chain_index, start_chain_hash, end_chain_hash,
		    start_projection_accumulator, end_projection_accumulator,
		    start_projection_state_digest, end_projection_state_digest,
		    checkpoint_event_id, envelope_json, signature, verified_at,
		    server_applied_result_index
		) VALUES (
		    ?1, 'batch', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
		    ?12, ?13, ?14, ?15, ?16, ?17, ?18, NULL, ?19, ?20, ?21, ?22
		);`,
		batch.AttestationID(),
		string(metadata.SessionID),
		string(metadata.WorkspaceID),
		metadata.RecoveryGeneration,
		string(metadata.ServerDeviceID),
		metadata.ServerAuthorityVersion,
		metadata.FromResultIndex,
		metadata.ToResultIndex,
		metadata.StartResultHash[:],
		metadata.EndResultHash[:],
		metadata.StartChainIndex,
		metadata.EndChainIndex,
		metadata.StartChainHash[:],
		metadata.EndChainHash[:],
		metadata.StartProjectionAccumulator[:],
		metadata.EndProjectionAccumulator[:],
		metadata.StartProjectionStateDigest[:],
		metadata.EndProjectionStateDigest[:],
		string(batch.AttestationEnvelope()),
		signature[:],
		string(verifiedAt),
		metadata.ServerAppliedResultIndex,
	)
}

func validateReplicationCursorStart(
	conn *sqlite.Conn,
	relayPeerID domain.DeviceID,
	input replication.BatchInput,
) error {
	var (
		found       bool
		authority   uint64
		chainIndex  uint64
		chainHash   Digest
		resultIndex uint64
		resultHash  Digest
		rowErr      error
	)
	err := queryArgs(
		conn,
		`SELECT authority_voter_set_version, chain_index, chain_hash,
		        result_index, result_hash
		   FROM replication_cursors
		  WHERE peer_device_id = ?1 AND session_id = ?2
		    AND recovery_generation = ?3;`,
		[]any{
			string(relayPeerID),
			string(input.SessionID),
			input.RecoveryGeneration,
		},
		func(stmt *sqlite.Stmt) {
			found = true
			targets := [...]*uint64{
				&authority,
				&chainIndex,
				&resultIndex,
			}
			for index, column := range [...]int{0, 1, 3} {
				target := targets[index]
				value := stmt.ColumnInt64(column)
				if value < 0 {
					rowErr = errors.New("negative replication cursor")
					return
				}
				*target = uint64(value)
			}
			if rowErr = copyDigestColumn(&chainHash, stmt, 2); rowErr != nil {
				return
			}
			rowErr = copyDigestColumn(&resultHash, stmt, 4)
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return fmt.Errorf("%w: %v", ErrIntegrityCheck, rowErr)
	}
	if !found {
		return nil
	}
	if resultIndex > input.FromResultIndex-1 ||
		authority > input.ServerAuthorityVersion {
		return resultBatchImportError("relay cursor would roll back")
	}
	if resultIndex == input.FromResultIndex-1 &&
		(resultHash != Digest(input.StartResultHash) ||
			chainIndex != input.StartChainIndex ||
			chainHash != Digest(input.StartChainHash)) {
		return resultBatchImportError(
			"relay cursor at starting position has different heads",
		)
	}
	return nil
}

func writeReplicationCursor(
	conn *sqlite.Conn,
	relayPeerID domain.DeviceID,
	input replication.BatchInput,
	verifiedAt domain.Timestamp,
) error {
	return execute(
		conn,
		`INSERT INTO replication_cursors(
		    peer_device_id, session_id, recovery_generation,
		    authority_voter_set_version, chain_index, chain_hash,
		    result_index, result_hash, updated_at
		) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
		ON CONFLICT(peer_device_id, session_id, recovery_generation)
		DO UPDATE SET
		    authority_voter_set_version =
		        excluded.authority_voter_set_version,
		    chain_index = excluded.chain_index,
		    chain_hash = excluded.chain_hash,
		    result_index = excluded.result_index,
		    result_hash = excluded.result_hash,
		    updated_at = excluded.updated_at;`,
		string(relayPeerID),
		string(input.SessionID),
		input.RecoveryGeneration,
		input.ServerAuthorityVersion,
		input.EndChainIndex,
		input.EndChainHash[:],
		input.ToResultIndex,
		input.EndResultHash[:],
		string(verifiedAt),
	)
}

func equalResultBatchMutations(
	left []chain.Mutation,
	right []chain.Mutation,
) bool {
	leftJSON, leftErr := chain.EncodeMutations(left)
	rightJSON, rightErr := chain.EncodeMutations(right)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftJSON, rightJSON)
}

func resultBatchCommandError(index int, operation string, err error) error {
	return fmt.Errorf(
		"%w: command %d %s: %w",
		ErrInvalidResultBatchImport,
		index,
		operation,
		err,
	)
}

func resultBatchImportError(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResultBatchImport, message)
}
