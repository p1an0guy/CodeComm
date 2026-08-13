package store

import (
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

type storedGenesisBoundary struct {
	genesisJSON            []byte
	genesisDigest          Digest
	stateDigest            Digest
	predecessorChainIndex  uint64
	predecessorChainHash   Digest
	predecessorResultIndex uint64
	predecessorResultHash  Digest
	predecessorAccumulator Digest
	hasPredecessor         bool
}

func verifyCurrentCommitmentTip(conn *sqlite.Conn) error {
	state, found, err := readConsensusState(conn)
	if err != nil || !found {
		return err
	}
	if err := verifyRaftCommandLedger(conn, state); err != nil {
		return err
	}
	genesis, err := readGenesisBoundary(
		conn,
		state.recoveryGeneration,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	computedGenesis, err := chain.GenesisDigest(genesis.genesisJSON)
	if err != nil {
		return commitmentIntegrityError("invalid current genesis", err)
	}
	if computedGenesis != chain.Digest(genesis.genesisDigest) {
		return commitmentIntegrityError("genesis digest mismatch", nil)
	}

	boundary := chain.Boundary{
		Genesis:     computedGenesis,
		Generation:  state.recoveryGeneration,
		ChainIndex:  genesis.predecessorChainIndex,
		ResultIndex: genesis.predecessorResultIndex,
		ChainHash:   chain.Digest(genesis.predecessorChainHash),
		ResultHash:  chain.Digest(genesis.predecessorResultHash),
	}
	eventSeed, err := chain.EventSeed(boundary)
	if err != nil {
		return commitmentIntegrityError("event seed", err)
	}
	resultSeed, err := chain.ResultSeed(boundary)
	if err != nil {
		return commitmentIntegrityError("result seed", err)
	}

	latestResult, hasCurrentResult, err := storedCurrentResultAtIndex(
		conn,
		state.resultIndex,
		state.sessionID,
	)
	if err != nil {
		return err
	}
	if !hasCurrentResult {
		return verifyBoundaryOnlyState(
			conn,
			state,
			genesis,
			computedGenesis,
			eventSeed,
			resultSeed,
		)
	}
	if latestResult.recoveryGeneration != state.recoveryGeneration {
		return commitmentIntegrityError("latest result has wrong generation", nil)
	}
	if err := verifyStoredCommandResult(conn, latestResult); err != nil {
		return err
	}
	if latestResult.resultHash != state.resultHash {
		return commitmentIntegrityError(
			"consensus result head differs from latest result",
			nil,
		)
	}

	if state.chainIndex == genesis.predecessorChainIndex {
		if chain.Digest(state.chainHash) != eventSeed {
			return commitmentIntegrityError(
				"boundary event head changed without an accepted successor event",
				nil,
			)
		}
		return nil
	}
	if state.chainIndex < genesis.predecessorChainIndex {
		return commitmentIntegrityError("event index precedes generation boundary", nil)
	}
	latestEvent, err := storedResultAtChainIndex(conn, state.chainIndex)
	if err != nil {
		return err
	}
	if err := verifyStoredCommandResult(conn, latestEvent); err != nil {
		return err
	}
	if latestEvent.sessionID != state.sessionID ||
		latestEvent.recoveryGeneration != state.recoveryGeneration ||
		latestEvent.chainHash == nil ||
		*latestEvent.chainHash != state.chainHash {
		return commitmentIntegrityError(
			"consensus event head differs from latest accepted result",
			nil,
		)
	}
	previousHash := eventSeed
	if state.chainIndex > genesis.predecessorChainIndex+1 {
		previousEvent, err := storedResultAtChainIndex(
			conn,
			state.chainIndex-1,
		)
		if err != nil {
			return err
		}
		if previousEvent.sessionID != state.sessionID ||
			previousEvent.recoveryGeneration != state.recoveryGeneration ||
			previousEvent.chainHash == nil {
			return commitmentIntegrityError(
				"previous accepted result crosses the generation boundary",
				nil,
			)
		}
		previousHash = chain.Digest(*previousEvent.chainHash)
	}
	computedEvent, err := chain.AppendEvent(previousHash, latestEvent.proposalJSON)
	if err != nil || computedEvent != chain.Digest(state.chainHash) {
		return commitmentIntegrityError("current event link mismatch", err)
	}
	return nil
}

func verifyBoundaryOnlyState(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
	genesisDigest chain.Digest,
	eventSeed chain.Digest,
	resultSeed chain.Digest,
) error {
	if state.chainIndex != genesis.predecessorChainIndex ||
		state.resultIndex != genesis.predecessorResultIndex ||
		chain.Digest(state.chainHash) != eventSeed ||
		chain.Digest(state.resultHash) != resultSeed {
		return commitmentIntegrityError("generation boundary heads mismatch", nil)
	}
	currentStateDigest, err := projectionStateDigest(conn, chain.Versions{
		Digest:           state.digestVersion,
		ProjectionSchema: state.projectionSchemaVersion,
	})
	if err != nil {
		return err
	}
	if currentStateDigest != genesis.stateDigest {
		return commitmentIntegrityError(
			"boundary projection-state digest mismatch",
			nil,
		)
	}
	var accumulator chain.Digest
	if genesis.hasPredecessor {
		accumulator = chain.AccumulatorSeedSuccessor(
			chain.Digest(genesis.predecessorAccumulator),
			genesisDigest,
			chain.Digest(currentStateDigest),
		)
	} else {
		accumulator = chain.AccumulatorSeedInitial(
			genesisDigest,
			chain.Digest(currentStateDigest),
		)
	}
	if accumulator != chain.Digest(state.projectionAccumulator) {
		return commitmentIntegrityError("boundary accumulator mismatch", nil)
	}
	return nil
}

func readGenesisBoundary(
	conn *sqlite.Conn,
	recoveryGeneration uint64,
	sessionID domain.UUIDv7,
) (storedGenesisBoundary, error) {
	var (
		result storedGenesisBoundary
		rowErr error
	)
	err := queryOneArgs(
		conn,
		`SELECT genesis_json, genesis_digest, boundary_transform_digest,
		        predecessor_chain_index, predecessor_chain_hash,
		        predecessor_result_index, predecessor_result_hash,
		        predecessor_projection_accumulator
		   FROM genesis_records
		  WHERE recovery_generation = ?1 AND session_id = ?2;`,
		[]any{recoveryGeneration, string(sessionID)},
		func(stmt *sqlite.Stmt) {
			result.genesisJSON = []byte(stmt.ColumnText(0))
			if rowErr = copyDigestColumn(
				&result.genesisDigest,
				stmt,
				1,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&result.stateDigest,
				stmt,
				2,
			); rowErr != nil {
				return
			}
			nullCount := 0
			for _, column := range []int{3, 4, 5, 6, 7} {
				if stmt.ColumnType(column) == sqlite.TypeNull {
					nullCount++
				}
			}
			if nullCount == 5 {
				return
			}
			if nullCount != 0 {
				rowErr = fmt.Errorf("partial predecessor tuple")
				return
			}
			chainIndex := stmt.ColumnInt64(3)
			resultIndex := stmt.ColumnInt64(5)
			if chainIndex < 0 || resultIndex < 0 || chainIndex > resultIndex {
				rowErr = fmt.Errorf("invalid predecessor indices")
				return
			}
			result.predecessorChainIndex = uint64(chainIndex)
			result.predecessorResultIndex = uint64(resultIndex)
			if rowErr = copyDigestColumn(
				&result.predecessorChainHash,
				stmt,
				4,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&result.predecessorResultHash,
				stmt,
				6,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&result.predecessorAccumulator,
				stmt,
				7,
			); rowErr != nil {
				return
			}
			result.hasPredecessor = true
		},
	)
	if err != nil {
		return storedGenesisBoundary{}, commitmentIntegrityError(
			"current genesis row is missing",
			err,
		)
	}
	if rowErr != nil {
		return storedGenesisBoundary{}, commitmentIntegrityError(
			"invalid genesis boundary row",
			rowErr,
		)
	}
	if result.hasPredecessor != (recoveryGeneration > 0) {
		return storedGenesisBoundary{}, commitmentIntegrityError(
			"genesis predecessor shape disagrees with generation",
			nil,
		)
	}
	return result, nil
}

func storedCurrentResultAtIndex(
	conn *sqlite.Conn,
	resultIndex uint64,
	sessionID domain.UUIDv7,
) (storedCommandResult, bool, error) {
	var (
		eventID string
		count   int
	)
	err := queryArgs(
		conn,
		`SELECT event_id FROM command_results
		  WHERE result_index = ?1 AND session_id = ?2;`,
		[]any{resultIndex, string(sessionID)},
		func(stmt *sqlite.Stmt) {
			count++
			eventID = stmt.ColumnText(0)
		},
	)
	if err != nil {
		return storedCommandResult{}, false, err
	}
	if count == 0 {
		return storedCommandResult{}, false, nil
	}
	if count != 1 {
		return storedCommandResult{}, false, commitmentIntegrityError(
			"duplicate current result position",
			nil,
		)
	}
	result, found, err := readStoredCommandResult(
		conn,
		domain.UUIDv7(eventID),
	)
	if err != nil {
		return storedCommandResult{}, false, err
	}
	if !found {
		return storedCommandResult{}, false, commitmentIntegrityError(
			"position lookup lost its command result",
			nil,
		)
	}
	return result, true, nil
}

func storedResultAtChainIndex(
	conn *sqlite.Conn,
	chainIndex uint64,
) (storedCommandResult, error) {
	var eventID string
	err := queryOneArgs(
		conn,
		"SELECT event_id FROM command_results WHERE chain_index = ?1;",
		[]any{chainIndex},
		func(stmt *sqlite.Stmt) {
			eventID = stmt.ColumnText(0)
		},
	)
	if err != nil {
		return storedCommandResult{}, commitmentIntegrityError(
			fmt.Sprintf(
				"missing command result at chain_index %d",
				chainIndex,
			),
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

func commitmentIntegrityError(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrCommandResultCorrupt, detail)
	}
	return fmt.Errorf("%w: %s: %v", ErrCommandResultCorrupt, detail, cause)
}
