package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var (
	ErrInvalidApply         = errors.New("store: invalid apply request")
	ErrApplyConflict        = errors.New("store: apply does not extend current state")
	ErrIdempotencyConflict  = errors.New("store: event ID maps to another proposal")
	ErrCommandResultCorrupt = errors.New("store: command result integrity failure")
)

type applyStage uint8

const (
	applyAfterEvent applyStage = iota + 1
	applyAfterProvenance
	applyAfterProjections
	applyAfterResult
	applyAfterActivity
	applyAfterAudit
	applyAfterCheckpoint
	applyAfterLeaseDeadlines
	applyAfterOutbox
	applyAfterConsensus
)

func (stage applyStage) String() string {
	switch stage {
	case applyAfterEvent:
		return "after_event"
	case applyAfterProvenance:
		return "after_provenance"
	case applyAfterProjections:
		return "after_projections"
	case applyAfterResult:
		return "after_result"
	case applyAfterActivity:
		return "after_activity"
	case applyAfterAudit:
		return "after_audit"
	case applyAfterCheckpoint:
		return "after_checkpoint"
	case applyAfterLeaseDeadlines:
		return "after_lease_deadlines"
	case applyAfterOutbox:
		return "after_outbox"
	case applyAfterConsensus:
		return "after_consensus"
	default:
		return fmt.Sprintf("apply_stage_%d", stage)
	}
}

// ApplyResult is the durable outcome of applying one Raft command. Duplicate
// commands return their original Outcome while Heads names the current store
// head after advancing only the local Raft watermark.
type ApplyResult struct {
	Heads             ApplyHeads
	Outcome           CommandOutcome
	AdmissionRevision uint64
	Duplicate         bool
}

// Apply commits one Raft command and its complete deterministic write set.
// The store owns event/result hashing, projection mutation capture, and the
// accumulator; none of those commitments are accepted from the caller.
func (store *Store) Apply(
	ctx context.Context,
	request ApplyRequest,
) (ApplyResult, error) {
	if err := request.validateApplyIdentity(); err != nil {
		return ApplyResult{}, err
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	var result ApplyResult
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		prior, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: generation must be initialized before apply",
				ErrApplyConflict,
			)
		}
		if err := ensureRaftEvidenceMode(conn); err != nil {
			return err
		}

		stored, duplicate, err := readStoredCommandResult(
			conn,
			request.Proposal.Proposal().EventID,
		)
		if err != nil {
			return err
		}
		if duplicate {
			if err := validateDuplicateApplyPosition(
				prior,
				request,
			); err != nil {
				return err
			}
			if err := verifyStoredCommandResult(conn, stored); err != nil {
				return err
			}
			incomingDigest := proposalDigest(request.Proposal)
			if incomingDigest != stored.proposalDigest ||
				!bytes.Equal(
					request.Proposal.CanonicalBytes(),
					stored.proposalJSON,
				) {
				return ErrIdempotencyConflict
			}
			result = ApplyResult{
				Heads:     headsFromConsensus(prior),
				Outcome:   stored.outcome,
				Duplicate: true,
			}
			if err := compactLocalProposal(
				conn,
				stored.recoveryGeneration,
				request.Proposal,
				stored.proposalJSON,
				stored.proposalDigest,
				stored.outcome.Status,
				stored.outcome.Code,
			); err != nil {
				return err
			}
			application := request
			application.RecoveryGeneration = prior.recoveryGeneration
			if err := writeRaftCommandApplication(conn, application); err != nil {
				return err
			}
			return advanceRaftWatermark(conn, request)
		}
		if err := validateApplyPosition(prior, request); err != nil {
			return err
		}
		if err := request.validate(); err != nil {
			return err
		}
		prepared, err := prepareProjectionWrites(request.Projections)
		if err != nil {
			return err
		}
		if prior.resultIndex >= domain.MaxSafeInteger ||
			request.Outcome.Status == OutcomeAccepted &&
				prior.chainIndex >= domain.MaxSafeInteger {
			return fmt.Errorf("%w: chain capacity exhausted", ErrApplyConflict)
		}

		heads, _, _, err := computeApplyCommitments(
			prior,
			request,
			nil,
		)
		if err != nil {
			return err
		}
		if request.Outcome.Status == OutcomeAccepted {
			if err := writeAcceptedEvent(conn, request); err != nil {
				return err
			}
		}
		if err := store.reachApplyStage(applyAfterEvent); err != nil {
			return err
		}
		if request.Outcome.Status == OutcomeAccepted {
			if err := writeEventProvenance(conn, request, heads); err != nil {
				return err
			}
		}
		if err := store.reachApplyStage(applyAfterProvenance); err != nil {
			return err
		}
		mutations, err := projectionMutations(conn, prepared)
		if err != nil {
			return err
		}
		heads, commandResult, mutationJSON, err := computeApplyCommitments(
			prior,
			request,
			mutations,
		)
		if err != nil {
			return err
		}
		if err := validateAppliedControlFileProjections(
			request,
			heads,
			prepared.controlFileProposalRows,
		); err != nil {
			return err
		}
		if err := ensurePendingControlFileApprovals(
			conn,
			prior.sessionID,
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
		if err := validateCheckpointCut(prior, request); err != nil {
			return err
		}
		if err := store.reachApplyStage(applyAfterProjections); err != nil {
			return err
		}
		if err := writeCommandResult(
			conn,
			request,
			heads,
			commandResult,
			mutationJSON,
		); err != nil {
			return err
		}
		if err := writeRaftCommandApplication(conn, request); err != nil {
			return err
		}
		if err := store.reachApplyStage(applyAfterResult); err != nil {
			return err
		}
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
			if err := writeCheckpointCadenceCheckpoint(
				conn,
				request,
				heads,
			); err != nil {
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
		if err := store.reachApplyStage(applyAfterLeaseDeadlines); err != nil {
			return err
		}
		if err := writePostCommandLocalCleanup(conn, request); err != nil {
			return err
		}
		if err := store.reachApplyStage(applyAfterOutbox); err != nil {
			return err
		}
		if err := writeConsensusState(conn, request, heads); err != nil {
			return err
		}
		if err := store.reachApplyStage(applyAfterConsensus); err != nil {
			return err
		}
		result = ApplyResult{
			Heads:   heads,
			Outcome: request.Outcome,
		}
		return nil
	})
	if err != nil {
		return ApplyResult{}, err
	}
	if result.Duplicate {
		result.AdmissionRevision = store.admissionRevision.Load()
	} else {
		result.AdmissionRevision = store.advanceAdmissionRevision()
		store.signalResultHeadChange()
	}
	return result, nil
}

func writePostCommandLocalCleanup(
	conn *sqlite.Conn,
	request ApplyRequest,
) error {
	if request.Outcome.Status == OutcomeAccepted &&
		request.Proposal.Proposal().Kind == event.KindAgentSessionEnded {
		entityID, present := request.Proposal.Proposal().EntityID.Value()
		if !present {
			return fmt.Errorf(
				"%w: accepted agent end has no session ID",
				ErrInvalidApply,
			)
		}
		if err := execute(
			conn,
			"DELETE FROM agent_resume_tokens WHERE agent_session_id = ?1;",
			entityID,
		); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE agent_launches SET state = 'cleared'
				  WHERE agent_session_id = ?1
				    AND state IN ('reserved', 'consumed');`,
			entityID,
		); err != nil {
			return err
		}
	}
	return compactLocalProposal(
		conn,
		request.RecoveryGeneration,
		request.Proposal,
		request.Proposal.CanonicalBytes(),
		proposalDigest(request.Proposal),
		request.Outcome.Status,
		request.Outcome.Code,
	)
}

func (store *Store) reachApplyStage(stage applyStage) error {
	if store.applyFailpoint == nil {
		return nil
	}
	return store.applyFailpoint(stage)
}

type consensusState struct {
	sessionID               domain.UUIDv7
	recoveryGeneration      uint64
	currentTerm             uint64
	lastAppliedLogIndex     uint64
	chainIndex              uint64
	chainHash               Digest
	resultIndex             uint64
	resultHash              Digest
	projectionAccumulator   Digest
	digestVersion           uint64
	projectionSchemaVersion uint64
}

func readConsensusState(conn *sqlite.Conn) (state consensusState, found bool, err error) {
	var rowErr error
	err = query(
		conn,
		`SELECT session_id, recovery_generation, current_term,
		        last_raft_applied_log_index, chain_index, chain_hash,
		        result_index, result_hash, projection_accumulator,
		        digest_version, projection_schema_version
		   FROM consensus_state WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			found = true
			state.sessionID = domain.UUIDv7(stmt.ColumnText(0))
			if !state.sessionID.Valid() {
				rowErr = errors.New("invalid session ID")
				return
			}
			if stmt.ColumnInt64(1) < 0 {
				rowErr = errors.New("negative recovery generation")
				return
			}
			state.recoveryGeneration = uint64(stmt.ColumnInt64(1))
			if stmt.ColumnType(2) != sqlite.TypeNull {
				if stmt.ColumnInt64(2) < 1 {
					rowErr = errors.New("invalid current term")
					return
				}
				state.currentTerm = uint64(stmt.ColumnInt64(2))
			}
			if stmt.ColumnType(3) != sqlite.TypeNull {
				if stmt.ColumnInt64(3) < 1 {
					rowErr = errors.New("invalid last applied log index")
					return
				}
				state.lastAppliedLogIndex = uint64(stmt.ColumnInt64(3))
			}
			if stmt.ColumnInt64(4) < 0 {
				rowErr = errors.New("negative chain index")
				return
			}
			state.chainIndex = uint64(stmt.ColumnInt64(4))
			if rowErr = copyDigestColumn(&state.chainHash, stmt, 5); rowErr != nil {
				return
			}
			if stmt.ColumnInt64(6) < 0 {
				rowErr = errors.New("negative result index")
				return
			}
			state.resultIndex = uint64(stmt.ColumnInt64(6))
			if rowErr = copyDigestColumn(&state.resultHash, stmt, 7); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&state.projectionAccumulator,
				stmt,
				8,
			); rowErr != nil {
				return
			}
			if stmt.ColumnInt64(9) < 1 || stmt.ColumnInt64(10) < 1 {
				rowErr = errors.New("invalid commitment version")
				return
			}
			state.digestVersion = uint64(stmt.ColumnInt64(9))
			state.projectionSchemaVersion = uint64(stmt.ColumnInt64(10))
			if !domain.ValidUnsignedInteger(state.recoveryGeneration) ||
				!domain.ValidUnsignedInteger(state.chainIndex) ||
				!domain.ValidUnsignedInteger(state.resultIndex) ||
				!domain.ValidUnsignedInteger(state.digestVersion) ||
				!domain.ValidUnsignedInteger(state.projectionSchemaVersion) ||
				state.chainIndex > state.resultIndex {
				rowErr = errors.New("consensus position exceeds protocol bounds")
			}
		},
	)
	if err == nil && rowErr != nil {
		err = commitmentIntegrityError("invalid consensus state", rowErr)
	}
	return state, found, err
}

func validateApplyPosition(
	prior consensusState,
	request ApplyRequest,
) error {
	proposal := request.Proposal.Proposal()
	if prior.sessionID != proposal.SessionID ||
		prior.recoveryGeneration != request.RecoveryGeneration {
		return fmt.Errorf("%w: session or generation changed", ErrApplyConflict)
	}
	if prior.lastAppliedLogIndex >= request.LogIndex ||
		prior.currentTerm > request.Term {
		return fmt.Errorf("%w: Raft term or index regressed", ErrApplyConflict)
	}
	return nil
}

func validateDuplicateApplyPosition(
	prior consensusState,
	request ApplyRequest,
) error {
	if request.RecoveryGeneration > prior.recoveryGeneration ||
		request.LogIndex < prior.lastAppliedLogIndex ||
		request.Term < prior.currentTerm ||
		request.LogIndex == prior.lastAppliedLogIndex &&
			request.Term != prior.currentTerm {
		return fmt.Errorf(
			"%w: duplicate generation, Raft term, or index conflicts with current watermark",
			ErrApplyConflict,
		)
	}
	return nil
}

func computeApplyCommitments(
	prior consensusState,
	request ApplyRequest,
	mutations []chain.Mutation,
) (ApplyHeads, []byte, []byte, error) {
	heads := headsFromConsensus(prior)
	heads.PreviousResultHash = prior.resultHash
	heads.ResultIndex = prior.resultIndex + 1
	if request.Outcome.Status == OutcomeAccepted {
		eventHash, err := chain.AppendEvent(
			chain.Digest(prior.chainHash),
			request.Proposal.CanonicalBytes(),
		)
		if err != nil {
			return ApplyHeads{}, nil, nil, fmt.Errorf(
				"%w: append event chain: %v",
				ErrInvalidApply,
				err,
			)
		}
		heads.ChainIndex = prior.chainIndex + 1
		heads.ChainHash = Digest(eventHash)
	}

	resultInput := chain.Result{
		ResultIndex: heads.ResultIndex,
		Proposal:    request.Proposal.CanonicalBytes(),
		Outcome:     request.Outcome.JSON,
		ProposalDigest: chain.Digest(
			proposalDigest(request.Proposal),
		),
	}
	if request.Outcome.Status == OutcomeAccepted {
		chainIndex := heads.ChainIndex
		chainHash := chain.Digest(heads.ChainHash)
		resultInput.ChainIndex = &chainIndex
		resultInput.ChainHash = &chainHash
	}
	resultHash, resultJSON, err := chain.AppendResult(
		chain.Digest(prior.resultHash),
		resultInput,
	)
	if err != nil {
		return ApplyHeads{}, nil, nil, fmt.Errorf(
			"%w: append result chain: %v",
			ErrInvalidApply,
			err,
		)
	}
	heads.ResultHash = Digest(resultHash)
	accumulator, mutationJSON, err := chain.AppendAccumulator(
		chain.Digest(prior.projectionAccumulator),
		heads.ResultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		return ApplyHeads{}, nil, nil, fmt.Errorf(
			"%w: append projection accumulator: %v",
			ErrInvalidApply,
			err,
		)
	}
	heads.ProjectionAccumulator = Digest(accumulator)
	return heads, resultJSON, mutationJSON, nil
}

func headsFromConsensus(state consensusState) ApplyHeads {
	return ApplyHeads{
		ChainIndex:              state.chainIndex,
		ChainHash:               state.chainHash,
		ResultIndex:             state.resultIndex,
		ResultHash:              state.resultHash,
		ProjectionAccumulator:   state.projectionAccumulator,
		DigestVersion:           state.digestVersion,
		ProjectionSchemaVersion: state.projectionSchemaVersion,
	}
}

func validateCheckpointCut(
	prior consensusState,
	request ApplyRequest,
) error {
	if request.Checkpoint == nil {
		return nil
	}
	checkpoint := request.Checkpoint
	if checkpoint.Term != request.Term ||
		checkpoint.CoveredAppliedLogIndex != request.LogIndex-1 ||
		checkpoint.CoveredChainIndex != prior.chainIndex ||
		checkpoint.CoveredChainHash != prior.chainHash ||
		checkpoint.CoveredResultIndex != prior.resultIndex ||
		checkpoint.CoveredResultHash != prior.resultHash ||
		checkpoint.ProjectionAccumulator != prior.projectionAccumulator ||
		checkpoint.DigestVersion != prior.digestVersion ||
		checkpoint.ProjectionSchemaVersion != prior.projectionSchemaVersion {
		return fmt.Errorf(
			"%w: accepted checkpoint does not match the pre-command cut",
			ErrApplyConflict,
		)
	}
	return nil
}

type storedCommandResult struct {
	eventID            domain.UUIDv7
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
	proposalJSON       []byte
	proposalDigest     Digest
	outcome            CommandOutcome
	chainIndex         *uint64
	chainHash          *Digest
	resultIndex        uint64
	previousResultHash Digest
	resultHash         Digest
}

func readStoredCommandResult(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) (storedCommandResult, bool, error) {
	var (
		result storedCommandResult
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT session_id, recovery_generation, proposal_json, proposal_digest,
		        outcome_status, outcome_code,
		        outcome_json, chain_index, chain_hash, result_index,
		        previous_result_hash, result_hash
		   FROM command_results WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				return
			}
			result.eventID = eventID
			result.sessionID = domain.UUIDv7(stmt.ColumnText(0))
			generation := stmt.ColumnInt64(1)
			if !result.sessionID.Valid() || generation < 0 {
				rowErr = errors.New("invalid result lineage")
				return
			}
			result.recoveryGeneration = uint64(generation)
			result.proposalJSON = []byte(stmt.ColumnText(2))
			if rowErr = copyDigestColumn(
				&result.proposalDigest,
				stmt,
				3,
			); rowErr != nil {
				return
			}
			result.outcome = CommandOutcome{
				Status: OutcomeStatus(stmt.ColumnText(4)),
				Code:   stmt.ColumnText(5),
				JSON:   []byte(stmt.ColumnText(6)),
			}
			chainIndexNull := stmt.ColumnType(7) == sqlite.TypeNull
			chainHashNull := stmt.ColumnType(8) == sqlite.TypeNull
			if chainIndexNull != chainHashNull {
				rowErr = errors.New("partial accepted chain tuple")
				return
			}
			if !chainIndexNull {
				value := stmt.ColumnInt64(7)
				if value < 1 {
					rowErr = errors.New("invalid accepted chain index")
					return
				}
				index := uint64(value)
				hash := new(Digest)
				if rowErr = copyDigestColumn(hash, stmt, 8); rowErr != nil {
					return
				}
				result.chainIndex = &index
				result.chainHash = hash
			}
			value := stmt.ColumnInt64(9)
			if value < 1 {
				rowErr = errors.New("invalid result index")
				return
			}
			result.resultIndex = uint64(value)
			if rowErr = copyDigestColumn(
				&result.previousResultHash,
				stmt,
				10,
			); rowErr != nil {
				return
			}
			rowErr = copyDigestColumn(&result.resultHash, stmt, 11)
		},
	)
	if err != nil {
		return storedCommandResult{}, false, err
	}
	if rowErr != nil {
		return storedCommandResult{}, false, fmt.Errorf(
			"%w: %v",
			ErrCommandResultCorrupt,
			rowErr,
		)
	}
	if count > 1 {
		return storedCommandResult{}, false, fmt.Errorf(
			"%w: duplicate event ID rows",
			ErrCommandResultCorrupt,
		)
	}
	return result, count == 1, nil
}

func copyDigestColumn(
	destination *Digest,
	stmt *sqlite.Stmt,
	column int,
) error {
	if stmt.ColumnType(column) != sqlite.TypeBlob ||
		stmt.ColumnLen(column) != len(Digest{}) {
		return fmt.Errorf("column %d is not a 32-byte digest", column)
	}
	copy(destination[:], columnBytes(stmt, column))
	return nil
}

func verifyStoredCommandResult(
	conn *sqlite.Conn,
	stored storedCommandResult,
) error {
	if proposalDigestBytes := proposalDigestFromBytes(stored.proposalJSON); proposalDigestBytes != stored.proposalDigest {
		return fmt.Errorf(
			"%w: proposal digest mismatch",
			ErrCommandResultCorrupt,
		)
	}
	if err := stored.outcome.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrCommandResultCorrupt, err)
	}
	accepted := stored.outcome.Status == OutcomeAccepted
	if accepted != (stored.chainIndex != nil && stored.chainHash != nil) {
		return fmt.Errorf(
			"%w: outcome and chain tuple disagree",
			ErrCommandResultCorrupt,
		)
	}
	genesis, eventSeed, resultSeed, err := storedBoundarySeeds(conn, stored)
	if err != nil {
		return err
	}
	resultInput := chain.Result{
		ResultIndex:    stored.resultIndex,
		Proposal:       stored.proposalJSON,
		Outcome:        stored.outcome.JSON,
		ProposalDigest: chain.Digest(stored.proposalDigest),
	}
	if accepted {
		chainIndex := *stored.chainIndex
		chainHash := chain.Digest(*stored.chainHash)
		resultInput.ChainIndex = &chainIndex
		resultInput.ChainHash = &chainHash
	}
	resultHash, _, err := chain.AppendResult(
		chain.Digest(stored.previousResultHash),
		resultInput,
	)
	if err != nil || resultHash != chain.Digest(stored.resultHash) {
		return fmt.Errorf(
			"%w: result link mismatch: %v",
			ErrCommandResultCorrupt,
			err,
		)
	}
	expectedPreviousResult := resultSeed
	switch {
	case stored.resultIndex <= genesis.predecessorResultIndex:
		return fmt.Errorf(
			"%w: result index does not follow its generation boundary",
			ErrCommandResultCorrupt,
		)
	case stored.resultIndex > genesis.predecessorResultIndex+1:
		previous, err := storedResultAtResultIndex(
			conn,
			stored.resultIndex-1,
		)
		if err != nil {
			return err
		}
		if previous.sessionID != stored.sessionID ||
			previous.recoveryGeneration != stored.recoveryGeneration {
			return fmt.Errorf(
				"%w: previous result crosses the generation boundary",
				ErrCommandResultCorrupt,
			)
		}
		expectedPreviousResult = chain.Digest(previous.resultHash)
	}
	if chain.Digest(stored.previousResultHash) != expectedPreviousResult {
		return fmt.Errorf(
			"%w: result predecessor mismatch",
			ErrCommandResultCorrupt,
		)
	}
	if accepted {
		var eventMatches bool
		err = queryOneArgs(
			conn,
			`SELECT proposal_json = ?2 AND proposal_digest = ?3
			   FROM events WHERE event_id = ?1;`,
			[]any{
				string(stored.eventID),
				string(stored.proposalJSON),
				stored.proposalDigest[:],
			},
			func(stmt *sqlite.Stmt) {
				eventMatches = stmt.ColumnBool(0)
			},
		)
		if err != nil || !eventMatches {
			return fmt.Errorf(
				"%w: accepted event row mismatch: %v",
				ErrCommandResultCorrupt,
				err,
			)
		}
		expectedPreviousEvent := eventSeed
		switch {
		case *stored.chainIndex <= genesis.predecessorChainIndex:
			return fmt.Errorf(
				"%w: event index does not follow its generation boundary",
				ErrCommandResultCorrupt,
			)
		case *stored.chainIndex > genesis.predecessorChainIndex+1:
			previous, err := storedResultAtChainIndex(
				conn,
				*stored.chainIndex-1,
			)
			if err != nil {
				return err
			}
			if previous.sessionID != stored.sessionID ||
				previous.recoveryGeneration != stored.recoveryGeneration ||
				previous.chainHash == nil {
				return fmt.Errorf(
					"%w: previous event crosses the generation boundary",
					ErrCommandResultCorrupt,
				)
			}
			expectedPreviousEvent = chain.Digest(*previous.chainHash)
		}
		computedEvent, err := chain.AppendEvent(
			expectedPreviousEvent,
			stored.proposalJSON,
		)
		if err != nil || computedEvent != chain.Digest(*stored.chainHash) {
			return fmt.Errorf(
				"%w: event link mismatch: %v",
				ErrCommandResultCorrupt,
				err,
			)
		}
	}
	return nil
}

func storedBoundarySeeds(
	conn *sqlite.Conn,
	stored storedCommandResult,
) (storedGenesisBoundary, chain.Digest, chain.Digest, error) {
	genesis, err := readGenesisBoundary(
		conn,
		stored.recoveryGeneration,
		stored.sessionID,
	)
	if err != nil {
		return storedGenesisBoundary{}, chain.Digest{}, chain.Digest{}, err
	}
	genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil ||
		genesisDigest != chain.Digest(genesis.genesisDigest) {
		return storedGenesisBoundary{}, chain.Digest{}, chain.Digest{},
			commitmentIntegrityError("result genesis digest mismatch", err)
	}
	boundary := chain.Boundary{
		Genesis:     genesisDigest,
		Generation:  stored.recoveryGeneration,
		ChainIndex:  genesis.predecessorChainIndex,
		ResultIndex: genesis.predecessorResultIndex,
		ChainHash:   chain.Digest(genesis.predecessorChainHash),
		ResultHash:  chain.Digest(genesis.predecessorResultHash),
	}
	eventSeed, err := chain.EventSeed(boundary)
	if err != nil {
		return storedGenesisBoundary{}, chain.Digest{}, chain.Digest{},
			commitmentIntegrityError("event seed", err)
	}
	resultSeed, err := chain.ResultSeed(boundary)
	if err != nil {
		return storedGenesisBoundary{}, chain.Digest{}, chain.Digest{},
			commitmentIntegrityError("result seed", err)
	}
	return genesis, eventSeed, resultSeed, nil
}

func storedResultAtResultIndex(
	conn *sqlite.Conn,
	resultIndex uint64,
) (storedCommandResult, error) {
	var eventID string
	if err := queryOneArgs(
		conn,
		"SELECT event_id FROM command_results WHERE result_index = ?1;",
		[]any{resultIndex},
		func(stmt *sqlite.Stmt) {
			eventID = stmt.ColumnText(0)
		},
	); err != nil {
		return storedCommandResult{}, commitmentIntegrityError(
			fmt.Sprintf("missing command result at result_index %d", resultIndex),
			err,
		)
	}
	result, found, err := readStoredCommandResult(
		conn,
		domain.UUIDv7(eventID),
	)
	if err != nil {
		return storedCommandResult{}, err
	}
	if !found {
		return storedCommandResult{}, commitmentIntegrityError(
			"position lookup lost its command result",
			nil,
		)
	}
	return result, nil
}

func proposalDigestFromBytes(proposal []byte) Digest {
	return Digest(sha256.Sum256(proposal))
}

func advanceRaftWatermark(
	conn *sqlite.Conn,
	request ApplyRequest,
) error {
	return execute(
		conn,
		`UPDATE consensus_state
		    SET current_term = ?1, last_raft_applied_log_index = ?2
		  WHERE singleton = 1;`,
		request.Term,
		request.LogIndex,
	)
}

func writeAcceptedEvent(
	conn *sqlite.Conn,
	request ApplyRequest,
) error {
	signed := request.Proposal
	proposal := signed.Proposal()
	entityID, present := proposal.EntityID.Value()
	var entityValue any
	if present {
		entityValue = entityID
	}
	scopeKind, scopeID := proposalScope(proposal)
	digest := proposalDigest(signed)
	return execute(
		conn,
		`INSERT INTO events(
		    event_id, session_id, workspace_id, schema_version, min_apply_level,
		    kind, entity_id, origin_device_id, origin_scope_kind,
		    origin_scope_id, origin_sequence, actor_type, created_at,
		    proposal_json, proposal_digest, origin_signature
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
		    ?14, ?15, ?16
		);`,
		string(proposal.EventID),
		string(proposal.SessionID),
		string(proposal.WorkspaceID),
		proposal.SchemaVersion,
		proposal.MinApplyLevel,
		string(proposal.Kind),
		entityValue,
		string(proposal.Origin.DeviceID()),
		string(scopeKind),
		scopeID,
		proposal.Origin.Sequence(),
		string(proposal.Origin.ActorType()),
		string(proposal.CreatedAt),
		string(signed.CanonicalBytes()),
		digest[:],
		signed.OriginSignature(),
	)
}

func writeEventProvenance(
	conn *sqlite.Conn,
	request ApplyRequest,
	heads ApplyHeads,
) error {
	proposal := request.Proposal.Proposal()
	return execute(
		conn,
		`INSERT INTO event_provenance(
		    event_id, term, log_index, applied_at, chain_index, chain_hash
		) VALUES (?1, ?2, ?3, ?4, ?5, ?6);`,
		string(proposal.EventID),
		request.Term,
		request.LogIndex,
		string(request.AppliedAt),
		heads.ChainIndex,
		heads.ChainHash[:],
	)
}

func writeCommandResult(
	conn *sqlite.Conn,
	request ApplyRequest,
	heads ApplyHeads,
	resultJSON []byte,
	mutationJSON []byte,
) error {
	signed := request.Proposal
	proposal := signed.Proposal()
	scopeKind, scopeID := proposalScope(proposal)
	digest := proposalDigest(signed)
	var chainIndex, chainHash any
	if request.Outcome.Status == OutcomeAccepted {
		chainIndex = heads.ChainIndex
		chainHash = heads.ChainHash[:]
	}
	expectedResult, err := chain.EncodeResult(chain.Result{
		ResultIndex:    heads.ResultIndex,
		Proposal:       signed.CanonicalBytes(),
		Outcome:        request.Outcome.JSON,
		ProposalDigest: chain.Digest(digest),
		ChainIndex: func() *uint64 {
			if request.Outcome.Status != OutcomeAccepted {
				return nil
			}
			value := heads.ChainIndex
			return &value
		}(),
		ChainHash: func() *chain.Digest {
			if request.Outcome.Status != OutcomeAccepted {
				return nil
			}
			value := chain.Digest(heads.ChainHash)
			return &value
		}(),
	})
	if err != nil || !bytes.Equal(expectedResult, resultJSON) {
		return fmt.Errorf("%w: command-result preimage changed", ErrIntegrityCheck)
	}
	return execute(
		conn,
		`INSERT INTO command_results(
		    event_id, session_id, workspace_id, recovery_generation,
		    schema_version, kind, origin_device_id, origin_scope_kind,
		    origin_scope_id, origin_sequence, proposal_json, proposal_digest,
		    outcome_status, outcome_code, outcome_json,
		    projection_mutations_json, chain_index, chain_hash, result_index,
		    previous_result_hash, result_hash
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
		    ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
		);`,
		string(proposal.EventID),
		string(proposal.SessionID),
		string(proposal.WorkspaceID),
		request.RecoveryGeneration,
		proposal.SchemaVersion,
		string(proposal.Kind),
		string(proposal.Origin.DeviceID()),
		string(scopeKind),
		scopeID,
		proposal.Origin.Sequence(),
		string(signed.CanonicalBytes()),
		digest[:],
		string(request.Outcome.Status),
		request.Outcome.Code,
		string(request.Outcome.JSON),
		string(mutationJSON),
		chainIndex,
		chainHash,
		heads.ResultIndex,
		heads.PreviousResultHash[:],
		heads.ResultHash[:],
	)
}

func writeRaftCommandApplication(
	conn *sqlite.Conn,
	request ApplyRequest,
) error {
	digest := proposalDigest(request.Proposal)
	if err := execute(
		conn,
		`INSERT INTO raft_command_applications(
		    recovery_generation, log_index, term, event_id, proposal_digest
		) VALUES (?1, ?2, ?3, ?4, ?5)
		ON CONFLICT(recovery_generation, log_index) DO NOTHING;`,
		request.RecoveryGeneration,
		request.LogIndex,
		request.Term,
		string(request.Proposal.Proposal().EventID),
		digest[:],
	); err != nil {
		return err
	}
	var matches bool
	if err := queryOneArgs(
		conn,
		`SELECT term = ?3 AND event_id = ?4 AND proposal_digest = ?5
		   FROM raft_command_applications
		  WHERE recovery_generation = ?1 AND log_index = ?2;`,
		[]any{
			request.RecoveryGeneration,
			request.LogIndex,
			request.Term,
			string(request.Proposal.Proposal().EventID),
			digest[:],
		},
		func(stmt *sqlite.Stmt) {
			matches = stmt.ColumnBool(0)
		},
	); err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf(
			"%w: Raft command position is already bound to different bytes",
			ErrApplyConflict,
		)
	}
	return nil
}

func writeActivity(conn *sqlite.Conn, request ApplyRequest) error {
	signed := request.Proposal
	proposal := signed.Proposal()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(signed.CanonicalBytes(), &members); err != nil {
		return err
	}
	var agentSessionID any
	if proposal.Origin.ActorType() == event.ActorAgent {
		agentSessionID = string(proposal.Origin.AgentSessionID())
	}
	var taskID any
	if request.ActivityTaskID != "" {
		taskID = string(request.ActivityTaskID)
	}
	return execute(
		conn,
		`INSERT INTO activity(
		    event_id, session_id, device_id, actor_type, agent_session_id,
		    event_kind, task_id, rationale_summary, capture_level,
		    actions_json, redaction_json, created_at
		) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);`,
		string(proposal.EventID),
		string(proposal.SessionID),
		string(proposal.Origin.DeviceID()),
		string(proposal.Origin.ActorType()),
		agentSessionID,
		string(proposal.Kind),
		taskID,
		proposal.RationaleSummary,
		string(proposal.CaptureLevel),
		string(members["actions"]),
		string(members["redaction"]),
		string(proposal.CreatedAt),
	)
}

func writeAudit(conn *sqlite.Conn, records []AuditRecord) error {
	for _, record := range records {
		var resultIndex any
		if record.ResultIndex != 0 {
			resultIndex = record.ResultIndex
		}
		var credentialEpoch any
		if record.SubjectCredentialEpoch != nil {
			credentialEpoch = *record.SubjectCredentialEpoch
		}
		if err := execute(
			conn,
			`INSERT INTO audit_events(
			    session_id, source_kind, event_id, result_index,
			    reporter_device_id, subject_device_id, subject_credential_epoch,
			    actor_type, ipc_channel, action_code, outcome_code, subject,
			    details_json, first_seen_at, last_seen_at, observation_count
			) VALUES (
			    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
			    ?13, ?14, ?15, ?16
			);`,
			string(record.SessionID),
			string(record.SourceKind),
			nullableDomainString(record.EventID),
			resultIndex,
			nullableDomainString(record.ReporterDeviceID),
			nullableDomainString(record.SubjectDeviceID),
			credentialEpoch,
			nullableDomainString(record.ActorType),
			nullablePlainString(record.IPCChannel),
			record.ActionCode,
			record.OutcomeCode,
			record.Subject,
			string(record.DetailsJSON),
			string(record.FirstSeenAt),
			string(record.LastSeenAt),
			record.ObservationCount,
		); err != nil {
			return err
		}
	}
	return nil
}

func writeCheckpoint(conn *sqlite.Conn, record CheckpointRecord) error {
	return execute(
		conn,
		`INSERT INTO chain_checkpoints(
		    checkpoint_event_id, session_id, workspace_id, recovery_generation,
		    authority_voter_set_version, signer_device_id, term,
		    covered_applied_log_index, covered_chain_index, covered_chain_hash,
		    covered_result_index, covered_result_hash, projection_accumulator,
		    digest_version, projection_schema_version, checkpoint_json,
		    authority_signature
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
		    ?14, ?15, ?16, ?17
		);`,
		string(record.CheckpointEventID),
		string(record.SessionID),
		string(record.WorkspaceID),
		record.RecoveryGeneration,
		record.AuthorityVoterSetVersion,
		string(record.SignerDeviceID),
		record.Term,
		record.CoveredAppliedLogIndex,
		record.CoveredChainIndex,
		record.CoveredChainHash[:],
		record.CoveredResultIndex,
		record.CoveredResultHash[:],
		record.ProjectionAccumulator[:],
		record.DigestVersion,
		record.ProjectionSchemaVersion,
		string(record.CheckpointJSON),
		record.AuthoritySignature[:],
	)
}

func writeLeaseDeadlines(
	conn *sqlite.Conn,
	upserts []LeaseDeadlineRecord,
	deletes []LeaseDeadlineKey,
) error {
	for _, key := range deletes {
		if err := execute(
			conn,
			"DELETE FROM lease_deadlines WHERE lease_id = ?1 AND entity_version = ?2;",
			string(key.LeaseID),
			key.EntityVersion,
		); err != nil {
			return err
		}
	}
	for _, record := range upserts {
		if err := execute(
			conn,
			`INSERT INTO lease_deadlines(
			    lease_id, entity_version, origin_boot_id,
			    monotonic_deadline_ns, display_deadline_at
			) VALUES (?1, ?2, ?3, ?4, ?5)
			ON CONFLICT(lease_id, entity_version) DO UPDATE SET
			    origin_boot_id = excluded.origin_boot_id,
			    monotonic_deadline_ns = excluded.monotonic_deadline_ns,
			    display_deadline_at = excluded.display_deadline_at;`,
			string(record.LeaseID),
			record.EntityVersion,
			string(record.OriginBootID),
			record.MonotonicDeadlineNS,
			string(record.DisplayDeadlineAt),
		); err != nil {
			return err
		}
	}
	return nil
}

func writeConsensusState(
	conn *sqlite.Conn,
	request ApplyRequest,
	heads ApplyHeads,
) error {
	proposal := request.Proposal.Proposal()
	return execute(
		conn,
		`INSERT INTO consensus_state(
		    singleton, session_id, recovery_generation, current_term,
		    last_raft_applied_log_index, chain_index, chain_hash,
		    result_index, result_hash, projection_accumulator,
		    digest_version, projection_schema_version
		) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
		ON CONFLICT(singleton) DO UPDATE SET
		    session_id = excluded.session_id,
		    recovery_generation = excluded.recovery_generation,
		    current_term = excluded.current_term,
		    last_raft_applied_log_index = excluded.last_raft_applied_log_index,
		    chain_index = excluded.chain_index,
		    chain_hash = excluded.chain_hash,
		    result_index = excluded.result_index,
		    result_hash = excluded.result_hash,
		    projection_accumulator = excluded.projection_accumulator,
		    digest_version = excluded.digest_version,
		    projection_schema_version = excluded.projection_schema_version;`,
		string(proposal.SessionID),
		request.RecoveryGeneration,
		request.Term,
		request.LogIndex,
		heads.ChainIndex,
		heads.ChainHash[:],
		heads.ResultIndex,
		heads.ResultHash[:],
		heads.ProjectionAccumulator[:],
		heads.DigestVersion,
		heads.ProjectionSchemaVersion,
	)
}

func nullableDomainString[T ~string](value T) any {
	if value == "" {
		return nil
	}
	return string(value)
}

func nullablePlainString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
