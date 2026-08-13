package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrCommitmentCutNotCovered = errors.New(
	"store: commitment cut is not covered",
)

// CommitmentCut identifies one historical event/result-chain position in the
// active lineage.
type CommitmentCut struct {
	SessionID               domain.UUIDv7
	RecoveryGeneration      uint64
	ChainIndex              uint64
	ChainHash               Digest
	ResultIndex             uint64
	ResultHash              Digest
	ProjectionAccumulator   Digest
	ProjectionStateDigest   Digest
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

func (cut CommitmentCut) validate() error {
	if !cut.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(cut.RecoveryGeneration) ||
		!domain.ValidUnsignedInteger(cut.ChainIndex) ||
		!domain.ValidUnsignedInteger(cut.ResultIndex) ||
		cut.ChainIndex > cut.ResultIndex ||
		cut.DigestVersion < 1 ||
		!domain.ValidUnsignedInteger(cut.DigestVersion) ||
		cut.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(cut.ProjectionSchemaVersion) {
		return fmt.Errorf("%w: invalid commitment cut", ErrInvalidOptions)
	}
	return nil
}

// VerifyCommitmentCut proves that cut is an exact historical chain position
// covered by the current active lineage.
func (store *Store) VerifyCommitmentCut(
	ctx context.Context,
	cut CommitmentCut,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cut.validate(); err != nil {
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
		if !found ||
			state.sessionID != cut.SessionID ||
			state.recoveryGeneration != cut.RecoveryGeneration ||
			state.chainIndex < cut.ChainIndex ||
			state.resultIndex < cut.ResultIndex ||
			state.digestVersion != cut.DigestVersion ||
			state.projectionSchemaVersion !=
				cut.ProjectionSchemaVersion {
			return commitmentCutError("current lineage does not cover cut", nil)
		}
		genesis, err := readGenesisBoundary(
			conn,
			state.recoveryGeneration,
			state.sessionID,
		)
		if err != nil {
			return commitmentCutError("read generation boundary", err)
		}
		genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
		if err != nil ||
			genesisDigest != chain.Digest(genesis.genesisDigest) {
			return commitmentCutError("verify generation boundary", err)
		}
		boundary := chain.Boundary{
			Genesis:     genesisDigest,
			Generation:  state.recoveryGeneration,
			ChainIndex:  genesis.predecessorChainIndex,
			ResultIndex: genesis.predecessorResultIndex,
			ChainHash:   chain.Digest(genesis.predecessorChainHash),
			ResultHash:  chain.Digest(genesis.predecessorResultHash),
		}
		eventSeed, err := chain.EventSeed(boundary)
		if err != nil {
			return commitmentCutError("derive event seed", err)
		}
		resultSeed, err := chain.ResultSeed(boundary)
		if err != nil {
			return commitmentCutError("derive result seed", err)
		}
		if err := verifyResultCut(conn, genesis, resultSeed, cut); err != nil {
			return err
		}
		if err := verifyCoherentEventHead(
			conn,
			genesis,
			eventSeed,
			cut,
		); err != nil {
			return err
		}
		if err := verifyEventCut(conn, genesis, eventSeed, cut); err != nil {
			return err
		}
		if err := verifyAccumulatorCut(
			conn,
			genesis,
			genesisDigest,
			cut,
		); err != nil {
			return err
		}
		return verifyProjectionStateCut(conn, state, cut)
	})
}

func verifyAccumulatorCut(
	conn *sqlite.Conn,
	genesis storedGenesisBoundary,
	genesisDigest chain.Digest,
	cut CommitmentCut,
) error {
	accumulator := chain.AccumulatorSeedInitial(
		genesisDigest,
		chain.Digest(genesis.stateDigest),
	)
	if genesis.hasPredecessor {
		accumulator = chain.AccumulatorSeedSuccessor(
			chain.Digest(genesis.predecessorAccumulator),
			genesisDigest,
			chain.Digest(genesis.stateDigest),
		)
	}
	resultIndex := genesis.predecessorResultIndex
	var rowErr error
	err := queryArgs(
		conn,
		`SELECT result_index, result_hash, projection_mutations_json
		   FROM command_results
		  WHERE session_id = ?1
		    AND recovery_generation = ?2
		    AND result_index <= ?3
		  ORDER BY result_index;`,
		[]any{
			string(cut.SessionID),
			cut.RecoveryGeneration,
			cut.ResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			storedIndex := stmt.ColumnInt64(0)
			if storedIndex < 1 ||
				resultIndex == domain.MaxSafeInteger ||
				uint64(storedIndex) != resultIndex+1 {
				rowErr = errors.New("result indexes are not dense")
				return
			}
			resultIndex++
			var resultHash Digest
			if rowErr = copyDigestColumn(&resultHash, stmt, 1); rowErr != nil {
				return
			}
			mutations, err := chain.DecodeMutations(
				[]byte(stmt.ColumnText(2)),
			)
			if err != nil {
				rowErr = err
				return
			}
			accumulator, _, rowErr = chain.AppendAccumulator(
				accumulator,
				resultIndex,
				chain.Digest(resultHash),
				mutations,
			)
		},
	)
	if err != nil {
		return commitmentCutError("read projection accumulator cut", err)
	}
	if rowErr != nil {
		return commitmentCutError("replay projection accumulator cut", rowErr)
	}
	if resultIndex != cut.ResultIndex ||
		accumulator != chain.Digest(cut.ProjectionAccumulator) {
		return commitmentCutError("projection accumulator cut differs", nil)
	}
	return nil
}

func verifyProjectionStateCut(
	conn *sqlite.Conn,
	state consensusState,
	cut CommitmentCut,
) error {
	rows, err := projectionRowsAtResultCut(conn, state, cut.ResultIndex)
	if err != nil {
		return commitmentCutError("rewind projection state cut", err)
	}
	digest, err := chain.StateDigest(chain.Versions{
		Digest:           cut.DigestVersion,
		ProjectionSchema: cut.ProjectionSchemaVersion,
	}, rows)
	if err != nil {
		return commitmentCutError("digest projection state cut", err)
	}
	if digest != chain.Digest(cut.ProjectionStateDigest) {
		return commitmentCutError("projection state cut differs", nil)
	}
	return nil
}

func verifyResultCut(
	conn *sqlite.Conn,
	genesis storedGenesisBoundary,
	resultSeed chain.Digest,
	cut CommitmentCut,
) error {
	if cut.ResultIndex == genesis.predecessorResultIndex {
		if chain.Digest(cut.ResultHash) != resultSeed {
			return commitmentCutError("result boundary hash differs", nil)
		}
		return nil
	}
	if cut.ResultIndex < genesis.predecessorResultIndex {
		return commitmentCutError("result index precedes boundary", nil)
	}
	stored, err := storedResultAtResultIndex(conn, cut.ResultIndex)
	if err != nil {
		return commitmentCutError("read result cut", err)
	}
	if err := verifyStoredCommandResult(conn, stored); err != nil {
		return commitmentCutError("verify result cut", err)
	}
	if stored.sessionID != cut.SessionID ||
		stored.recoveryGeneration != cut.RecoveryGeneration ||
		stored.resultHash != cut.ResultHash {
		return commitmentCutError("result cut differs", nil)
	}
	return nil
}

func verifyCoherentEventHead(
	conn *sqlite.Conn,
	genesis storedGenesisBoundary,
	eventSeed chain.Digest,
	cut CommitmentCut,
) error {
	expectedIndex := genesis.predecessorChainIndex
	expectedHash := Digest(eventSeed)
	var (
		count  int
		rowErr error
	)
	err := queryArgs(
		conn,
		`SELECT chain_index, chain_hash
		   FROM command_results
		  WHERE session_id = ?1
		    AND recovery_generation = ?2
		    AND result_index <= ?3
		    AND chain_index IS NOT NULL
		  ORDER BY result_index DESC
		  LIMIT 1;`,
		[]any{
			string(cut.SessionID),
			cut.RecoveryGeneration,
			cut.ResultIndex,
		},
		func(stmt *sqlite.Stmt) {
			count++
			value := stmt.ColumnInt64(0)
			if value < 1 {
				rowErr = errors.New("invalid accepted chain index")
				return
			}
			expectedIndex = uint64(value)
			rowErr = copyDigestColumn(&expectedHash, stmt, 1)
		},
	)
	if err != nil {
		return commitmentCutError("read event head at result cut", err)
	}
	if rowErr != nil || count > 1 {
		return commitmentCutError("invalid event head at result cut", rowErr)
	}
	if cut.ChainIndex != expectedIndex || cut.ChainHash != expectedHash {
		return commitmentCutError(
			"event head does not belong to the result cut",
			nil,
		)
	}
	return nil
}

func verifyEventCut(
	conn *sqlite.Conn,
	genesis storedGenesisBoundary,
	eventSeed chain.Digest,
	cut CommitmentCut,
) error {
	if cut.ChainIndex == genesis.predecessorChainIndex {
		if chain.Digest(cut.ChainHash) != eventSeed {
			return commitmentCutError("event boundary hash differs", nil)
		}
		return nil
	}
	if cut.ChainIndex < genesis.predecessorChainIndex {
		return commitmentCutError("event index precedes boundary", nil)
	}
	stored, err := storedResultAtChainIndex(conn, cut.ChainIndex)
	if err != nil {
		return commitmentCutError("read event cut", err)
	}
	if err := verifyStoredCommandResult(conn, stored); err != nil {
		return commitmentCutError("verify event cut", err)
	}
	if stored.sessionID != cut.SessionID ||
		stored.recoveryGeneration != cut.RecoveryGeneration ||
		stored.chainHash == nil ||
		*stored.chainHash != cut.ChainHash {
		return commitmentCutError("event cut differs", nil)
	}
	return nil
}

func commitmentCutError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrCommitmentCutNotCovered, detail)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrCommitmentCutNotCovered,
		detail,
		cause,
	)
}
