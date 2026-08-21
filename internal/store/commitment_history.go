package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// VerifyCommitmentHistory replays every retained event/result link in the
// active recovery generation and compares the reconstructed heads with the
// durable consensus state. It is required before Raft log compaction.
func (store *Store) VerifyCommitmentHistory(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	return store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)

		end := sqlitex.Transaction(conn)
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrCommandResultCorrupt,
			)
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		settledState, settled, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if settled {
			if err := verifySettledNonvoterEvidence(
				conn,
				state,
				settledState,
			); err != nil {
				return historyIntegrityError(
					"settled-nonvoter evidence",
					err,
				)
			}
			return nil
		}
		if err := verifyRaftCommandLedger(conn, state); err != nil {
			return historyIntegrityError("Raft command ledger", err)
		}
		return nil
	})
}

func verifyCommitmentHistory(
	conn *sqlite.Conn,
	state consensusState,
) error {
	return verifyCommitmentHistoryWithProjectionRewind(conn, state, true)
}

// verifyHistoricalGenerationCommitments verifies immutable event/result
// links and the projection accumulator for a predecessor generation. Its
// terminal projection rows were deliberately replaced by the next recovery
// transform, so only the active generation can additionally rewind mutations
// from the current covered rows.
func verifyHistoricalGenerationCommitments(
	conn *sqlite.Conn,
	state consensusState,
) error {
	return verifyCommitmentHistoryWithProjectionRewind(conn, state, false)
}

func verifyCommitmentHistoryWithProjectionRewind(
	conn *sqlite.Conn,
	state consensusState,
	verifyProjectionRewind bool,
) error {
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil ||
		genesisDigest != chain.Digest(genesis.genesisDigest) {
		return historyIntegrityError("generation boundary", err)
	}
	boundary := chain.Boundary{
		Genesis:     genesisDigest,
		Generation:  state.recoveryGeneration,
		ChainIndex:  genesis.predecessorChainIndex,
		ResultIndex: genesis.predecessorResultIndex,
		ChainHash:   chain.Digest(genesis.predecessorChainHash),
		ResultHash:  chain.Digest(genesis.predecessorResultHash),
	}
	eventHead, err := chain.EventSeed(boundary)
	if err != nil {
		return historyIntegrityError("event seed", err)
	}
	resultHead, err := chain.ResultSeed(boundary)
	if err != nil {
		return historyIntegrityError("result seed", err)
	}
	accumulatorHead := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(genesis.stateDigest),
	)
	if genesis.hasPredecessor {
		accumulatorHead = chain.AccumulatorSeedSuccessor(
			chain.Digest(genesis.predecessorAccumulator),
			genesisDigest,
			chain.Digest(genesis.stateDigest),
		)
	}

	resultIndex := genesis.predecessorResultIndex
	chainIndex := genesis.predecessorChainIndex
	var rowErr error
	err = queryArgs(
		conn,
		`SELECT r.event_id, r.proposal_json, r.proposal_digest,
		        r.outcome_status, r.outcome_code, r.outcome_json,
		        r.projection_mutations_json, r.chain_index, r.chain_hash,
		        r.result_index, r.previous_result_hash, r.result_hash,
		        e.event_id, e.proposal_json, e.proposal_digest
		   FROM command_results AS r
		   LEFT JOIN events AS e ON e.event_id = r.event_id
		  WHERE r.session_id = ?1 AND r.recovery_generation = ?2
		  ORDER BY r.result_index;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			eventID := domain.UUIDv7(stmt.ColumnText(0))
			proposal := []byte(stmt.ColumnText(1))
			var proposalDigest Digest
			if !eventID.Valid() {
				rowErr = errors.New("invalid event ID")
				return
			}
			if rowErr = copyDigestColumn(&proposalDigest, stmt, 2); rowErr != nil {
				return
			}
			canonical, canonicalErr := codec.CanonicalizeSignedObject(proposal)
			if canonicalErr != nil || !bytes.Equal(canonical, proposal) ||
				proposalDigestFromBytes(proposal) != proposalDigest {
				rowErr = errors.New("proposal bytes or digest differ")
				return
			}
			outcome := CommandOutcome{
				Status: OutcomeStatus(stmt.ColumnText(3)),
				Code:   stmt.ColumnText(4),
				JSON:   []byte(stmt.ColumnText(5)),
			}
			if outcomeErr := outcome.validate(); outcomeErr != nil {
				rowErr = outcomeErr
				return
			}

			mutationJSON := []byte(stmt.ColumnText(6))
			mutations, mutationErr := chain.DecodeMutations(mutationJSON)
			if mutationErr != nil {
				rowErr = fmt.Errorf(
					"invalid projection mutations: %w",
					mutationErr,
				)
				return
			}

			storedResultIndex := stmt.ColumnInt64(9)
			if storedResultIndex < 1 ||
				resultIndex == domain.MaxSafeInteger ||
				uint64(storedResultIndex) != resultIndex+1 {
				rowErr = errors.New("result indexes are not dense")
				return
			}
			resultIndex++
			var previousResultHash, storedResultHash Digest
			if rowErr = copyDigestColumn(
				&previousResultHash,
				stmt,
				10,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&storedResultHash,
				stmt,
				11,
			); rowErr != nil {
				return
			}
			if chain.Digest(previousResultHash) != resultHead {
				rowErr = errors.New("result predecessor differs")
				return
			}

			accepted := outcome.Status == OutcomeAccepted
			chainIndexNull := stmt.ColumnType(7) == sqlite.TypeNull
			chainHashNull := stmt.ColumnType(8) == sqlite.TypeNull
			eventRowNull := stmt.ColumnType(12) == sqlite.TypeNull
			if accepted == chainIndexNull ||
				chainIndexNull != chainHashNull ||
				accepted == eventRowNull {
				rowErr = errors.New("outcome, chain tuple, and event row disagree")
				return
			}
			resultInput := chain.Result{
				ResultIndex:    resultIndex,
				Proposal:       proposal,
				Outcome:        outcome.JSON,
				ProposalDigest: chain.Digest(proposalDigest),
			}
			if accepted {
				storedChainIndex := stmt.ColumnInt64(7)
				if storedChainIndex < 1 ||
					chainIndex == domain.MaxSafeInteger ||
					uint64(storedChainIndex) != chainIndex+1 {
					rowErr = errors.New("event indexes are not dense")
					return
				}
				chainIndex++
				var storedChainHash, eventRowDigest Digest
				if rowErr = copyDigestColumn(
					&storedChainHash,
					stmt,
					8,
				); rowErr != nil {
					return
				}
				if stmt.ColumnText(12) != string(eventID) ||
					!bytes.Equal([]byte(stmt.ColumnText(13)), proposal) {
					rowErr = errors.New("accepted event bytes differ")
					return
				}
				if rowErr = copyDigestColumn(
					&eventRowDigest,
					stmt,
					14,
				); rowErr != nil {
					return
				}
				if eventRowDigest != proposalDigest {
					rowErr = errors.New("accepted event commitment differs")
					return
				}
				nextEvent, appendErr := chain.AppendEvent(eventHead, proposal)
				if appendErr != nil {
					rowErr = fmt.Errorf("event link differs: %w", appendErr)
					return
				}
				if nextEvent != chain.Digest(storedChainHash) {
					rowErr = errors.New("event link differs")
					return
				}
				eventHead = nextEvent
				index := chainIndex
				hash := chain.Digest(storedChainHash)
				resultInput.ChainIndex = &index
				resultInput.ChainHash = &hash
			}

			nextResult, _, appendErr := chain.AppendResult(
				resultHead,
				resultInput,
			)
			if appendErr != nil {
				rowErr = fmt.Errorf("result link differs: %w", appendErr)
				return
			}
			if nextResult != chain.Digest(storedResultHash) {
				rowErr = errors.New("result link differs")
				return
			}
			resultHead = nextResult
			nextAccumulator, replayedMutations, appendErr :=
				chain.AppendAccumulator(
					accumulatorHead,
					resultIndex,
					nextResult,
					mutations,
				)
			if appendErr != nil {
				rowErr = fmt.Errorf(
					"projection accumulator input differs: %w",
					appendErr,
				)
				return
			}
			if !bytes.Equal(replayedMutations, mutationJSON) {
				rowErr = errors.New(
					"projection accumulator mutation bytes differ",
				)
				return
			}
			accumulatorHead = nextAccumulator
		},
	)
	if err != nil {
		return err
	}
	if rowErr != nil {
		return historyIntegrityError("command history", rowErr)
	}
	if resultIndex != state.resultIndex ||
		chainIndex != state.chainIndex ||
		resultHead != chain.Digest(state.resultHash) ||
		eventHead != chain.Digest(state.chainHash) ||
		accumulatorHead != chain.Digest(state.projectionAccumulator) {
		return historyIntegrityError(
			"reconstructed heads differ from consensus state",
			nil,
		)
	}

	var foreignRows int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM command_results
		  WHERE recovery_generation = ?1 AND session_id <> ?2;`,
		[]any{state.recoveryGeneration, string(state.sessionID)},
		func(stmt *sqlite.Stmt) {
			foreignRows = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if foreignRows != 0 {
		return historyIntegrityError(
			"generation contains another session",
			nil,
		)
	}
	if err := queryOne(
		conn,
		`SELECT count(*)
		   FROM events AS e
		  WHERE NOT EXISTS (
		        SELECT 1
		          FROM command_results AS r
		         WHERE r.event_id = e.event_id
		           AND r.outcome_status = 'accepted'
		  );`,
		func(stmt *sqlite.Stmt) {
			foreignRows = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if foreignRows != 0 {
		return historyIntegrityError(
			"accepted event lacks an accepted result",
			nil,
		)
	}
	if verifyProjectionRewind {
		if err := verifyProjectionMutationHistory(
			conn,
			state,
			genesis,
		); err != nil {
			return err
		}
	}
	return nil
}

func verifyProjectionMutationHistory(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
) error {
	digest, err := projectionStateDigestAtResultCut(
		conn,
		state,
		genesis,
		genesis.predecessorResultIndex,
		nil,
	)
	if err != nil {
		return historyIntegrityError("projection mutation history", err)
	}
	if digest != chain.Digest(genesis.stateDigest) {
		return historyIntegrityError(
			"reconstructed boundary projection state differs",
			nil,
		)
	}
	return nil
}

func historyIntegrityError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrCommandResultCorrupt, detail)
	}
	return fmt.Errorf("%w: %s: %w", ErrCommandResultCorrupt, detail, cause)
}
