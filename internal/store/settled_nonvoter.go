package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrReplicaEvidenceMode = errors.New(
	"store: incompatible replica evidence mode",
)

type ReplicaEvidenceMode string

const (
	ReplicaEvidenceRaft            ReplicaEvidenceMode = "raft"
	ReplicaEvidenceSettledNonvoter ReplicaEvidenceMode = "settled_nonvoter"
)

type settledNonvoterState struct {
	sessionID                     domain.UUIDv7
	workspaceID                   domain.UUIDv4
	recoveryGeneration            uint64
	baselineHeads                 ApplyHeads
	frozenCurrentTerm             uint64
	frozenLastRaftAppliedLogIndex uint64
	enteredAt                     domain.Timestamp
}

// ReplicaEvidenceMode reports which mutually exclusive provenance contract
// covers the active generation.
func (store *Store) ReplicaEvidenceMode(
	ctx context.Context,
) (ReplicaEvidenceMode, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: nil context", ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var mode ReplicaEvidenceMode
	err := store.withConn(ctx, func(conn *sqlite.Conn) error {
		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrReplicaEvidenceMode,
			)
		}
		settled, found, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if !found {
			mode = ReplicaEvidenceRaft
			return nil
		}
		if err := validateSettledNonvoterState(conn, state, settled); err != nil {
			return err
		}
		mode = ReplicaEvidenceSettledNonvoter
		return nil
	})
	return mode, err
}

// EnterSettledNonvoter freezes the current Raft evidence cut before signed
// result batches may extend it. Repeated calls return the original cut.
func (store *Store) EnterSettledNonvoter(
	ctx context.Context,
	enteredAt domain.Timestamp,
) (ApplyHeads, error) {
	if ctx == nil || !enteredAt.Valid() {
		return ApplyHeads{}, fmt.Errorf(
			"%w: invalid settled-nonvoter transition",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return ApplyHeads{}, err
	}
	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var baseline ApplyHeads
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
			return fmt.Errorf(
				"%w: active generation is missing",
				ErrReplicaEvidenceMode,
			)
		}
		existing, settled, err := readSettledNonvoterState(conn)
		if err != nil {
			return err
		}
		if settled {
			if err := validateSettledNonvoterState(
				conn,
				state,
				existing,
			); err != nil {
				return err
			}
			baseline = existing.baselineHeads
			return nil
		}
		if err := verifyRaftCommandLedger(conn, state); err != nil {
			return err
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
			return err
		}
		workspaceID, err := activeWorkspaceID(conn, state)
		if err != nil {
			return err
		}
		baseline = headsFromConsensus(state)
		return execute(
			conn,
			`INSERT INTO settled_nonvoter_state(
			    singleton, session_id, workspace_id, recovery_generation,
			    baseline_chain_index, baseline_chain_hash,
			    baseline_result_index, baseline_result_hash,
			    baseline_projection_accumulator, digest_version,
			    projection_schema_version, frozen_current_term,
			    frozen_last_raft_applied_log_index, entered_at
			) VALUES (
			    1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
			    ?11, ?12, ?13
			);`,
			string(state.sessionID),
			string(workspaceID),
			state.recoveryGeneration,
			state.chainIndex,
			state.chainHash[:],
			state.resultIndex,
			state.resultHash[:],
			state.projectionAccumulator[:],
			state.digestVersion,
			state.projectionSchemaVersion,
			nullablePositive(state.currentTerm),
			nullablePositive(state.lastAppliedLogIndex),
			string(enteredAt),
		)
	})
	if err != nil {
		return ApplyHeads{}, err
	}
	return baseline, nil
}

func readSettledNonvoterState(
	conn *sqlite.Conn,
) (settledNonvoterState, bool, error) {
	var (
		result settledNonvoterState
		found  bool
		rowErr error
	)
	err := query(
		conn,
		`SELECT session_id, workspace_id, recovery_generation,
		        baseline_chain_index, baseline_chain_hash,
		        baseline_result_index, baseline_result_hash,
		        baseline_projection_accumulator, digest_version,
		        projection_schema_version, frozen_current_term,
		        frozen_last_raft_applied_log_index, entered_at
		   FROM settled_nonvoter_state WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			found = true
			result.sessionID = domain.UUIDv7(stmt.ColumnText(0))
			result.workspaceID = domain.UUIDv4(stmt.ColumnText(1))
			numbers := []*uint64{
				&result.recoveryGeneration,
				&result.baselineHeads.ChainIndex,
				&result.baselineHeads.ResultIndex,
				&result.baselineHeads.DigestVersion,
				&result.baselineHeads.ProjectionSchemaVersion,
			}
			for index, column := range [...]int{2, 3, 5, 8, 9} {
				value := stmt.ColumnInt64(column)
				if value < 0 {
					rowErr = errors.New("negative settled-nonvoter number")
					return
				}
				*numbers[index] = uint64(value)
			}
			if rowErr = copyDigestColumn(
				&result.baselineHeads.ChainHash,
				stmt,
				4,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&result.baselineHeads.ResultHash,
				stmt,
				6,
			); rowErr != nil {
				return
			}
			if rowErr = copyDigestColumn(
				&result.baselineHeads.ProjectionAccumulator,
				stmt,
				7,
			); rowErr != nil {
				return
			}
			if stmt.ColumnType(10) != sqlite.TypeNull {
				value := stmt.ColumnInt64(10)
				if value < 1 {
					rowErr = errors.New("invalid frozen current term")
					return
				}
				result.frozenCurrentTerm = uint64(value)
			}
			if stmt.ColumnType(11) != sqlite.TypeNull {
				value := stmt.ColumnInt64(11)
				if value < 1 {
					rowErr = errors.New("invalid frozen applied index")
					return
				}
				result.frozenLastRaftAppliedLogIndex = uint64(value)
			}
			result.enteredAt = domain.Timestamp(stmt.ColumnText(12))
		},
	)
	if err != nil {
		return settledNonvoterState{}, false, err
	}
	if rowErr != nil {
		return settledNonvoterState{}, false, fmt.Errorf(
			"%w: %v",
			ErrReplicaEvidenceMode,
			rowErr,
		)
	}
	return result, found, nil
}

func validateSettledNonvoterState(
	conn *sqlite.Conn,
	state consensusState,
	settled settledNonvoterState,
) error {
	workspaceID, err := activeWorkspaceID(conn, state)
	if err != nil {
		return err
	}
	baseline := settled.baselineHeads
	if settled.sessionID != state.sessionID ||
		settled.workspaceID != workspaceID ||
		settled.recoveryGeneration != state.recoveryGeneration ||
		settled.frozenCurrentTerm != state.currentTerm ||
		settled.frozenLastRaftAppliedLogIndex !=
			state.lastAppliedLogIndex ||
		baseline.DigestVersion != state.digestVersion ||
		baseline.ProjectionSchemaVersion !=
			state.projectionSchemaVersion ||
		baseline.ChainIndex > state.chainIndex ||
		baseline.ResultIndex > state.resultIndex ||
		baseline.ChainIndex > baseline.ResultIndex ||
		!settled.enteredAt.Valid() {
		return ErrReplicaEvidenceMode
	}
	return nil
}

func activeWorkspaceID(
	conn *sqlite.Conn,
	state consensusState,
) (domain.UUIDv4, error) {
	var workspaceID domain.UUIDv4
	if err := queryOneArgs(
		conn,
		`SELECT workspace_id
		   FROM genesis_records
		  WHERE session_id = ?1 AND recovery_generation = ?2;`,
		[]any{string(state.sessionID), state.recoveryGeneration},
		func(stmt *sqlite.Stmt) {
			workspaceID = domain.UUIDv4(stmt.ColumnText(0))
		},
	); err != nil {
		return "", err
	}
	if !workspaceID.Valid() {
		return "", fmt.Errorf(
			"%w: active workspace identity is malformed",
			ErrReplicaEvidenceMode,
		)
	}
	return workspaceID, nil
}

func nullablePositive(value uint64) any {
	if value == 0 {
		return nil
	}
	return value
}

func ensureRaftEvidenceMode(conn *sqlite.Conn) error {
	_, settled, err := readSettledNonvoterState(conn)
	if err != nil {
		return err
	}
	if settled {
		return ErrReplicaEvidenceMode
	}
	return nil
}
