package store

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// StateView is one immutable, transactionally consistent view of the active
// generation and every digest-covered logical projection row. It contains no
// SQLite representation details and is suitable for reconstructing reducer
// state after a process restart.
type StateView struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	GenesisJSON        []byte
	// AdmissionRevision is process-local and names the store cut covered by
	// this view. It is not replicated or digest-covered state.
	AdmissionRevision uint64

	CurrentTerm             *uint64
	LastRaftAppliedLogIndex *uint64
	Heads                   ApplyHeads
	ProjectionStateDigest   Digest
	ProjectionRows          []chain.LogicalRow
}

// View returns the current active generation and logical projections under
// the same apply lock and SQLite transaction. Callers own all returned memory.
func (store *Store) View(ctx context.Context) (StateView, error) {
	return store.stateView(ctx, false)
}

// VerifiedSettledNonvoterView returns a view only after revalidating the
// complete Raft baseline and contiguous signed replication evidence in the
// same transaction. It is the trusted scratch-replay starting point for a
// settled application nonvoter.
func (store *Store) VerifiedSettledNonvoterView(
	ctx context.Context,
) (StateView, error) {
	return store.stateView(ctx, true)
}

func (store *Store) stateView(
	ctx context.Context,
	verifySettledEvidence bool,
) (StateView, error) {
	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var view StateView
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
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
				"%w: store has no active generation",
				ErrApplyConflict,
			)
		}
		if verifySettledEvidence {
			settled, found, err := readSettledNonvoterState(conn)
			if err != nil {
				return err
			}
			if !found {
				return ErrReplicaEvidenceMode
			}
			if err := verifyCommitmentHistory(conn, state); err != nil {
				return err
			}
			if err := verifySettledNonvoterEvidence(
				conn,
				state,
				settled,
			); err != nil {
				return err
			}
		}

		var (
			workspaceID domain.UUIDv4
			genesisJSON []byte
		)
		if err := queryOneArgs(
			conn,
			`SELECT workspace_id, genesis_json
			   FROM genesis_records
			  WHERE recovery_generation = ?1 AND session_id = ?2;`,
			[]any{state.recoveryGeneration, string(state.sessionID)},
			func(stmt *sqlite.Stmt) {
				workspaceID = domain.UUIDv4(stmt.ColumnText(0))
				genesisJSON = []byte(stmt.ColumnText(1))
			},
		); err != nil {
			return err
		}
		if !state.sessionID.Valid() ||
			!workspaceID.Valid() ||
			len(genesisJSON) == 0 {
			return fmt.Errorf(
				"%w: active lineage identity is malformed",
				ErrIntegrityCheck,
			)
		}

		rows, err := projectionLogicalRows(conn)
		if err != nil {
			return err
		}
		digest, err := chain.StateDigest(
			chain.Versions{
				Digest:           state.digestVersion,
				ProjectionSchema: state.projectionSchemaVersion,
			},
			rows,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: validate logical projection view: %v",
				ErrIntegrityCheck,
				err,
			)
		}

		view = StateView{
			SessionID:          state.sessionID,
			WorkspaceID:        workspaceID,
			RecoveryGeneration: state.recoveryGeneration,
			GenesisJSON:        bytes.Clone(genesisJSON),
			AdmissionRevision:  store.admissionRevision.Load(),
			Heads:              headsFromConsensus(state),
			ProjectionStateDigest: Digest(
				digest,
			),
			ProjectionRows: cloneLogicalRows(rows),
		}
		if state.currentTerm != 0 {
			value := state.currentTerm
			view.CurrentTerm = &value
		}
		if state.lastAppliedLogIndex != 0 {
			value := state.lastAppliedLogIndex
			view.LastRaftAppliedLogIndex = &value
		}
		return nil
	})
	if err != nil {
		return StateView{}, err
	}
	return view, nil
}

func cloneLogicalRows(rows []chain.LogicalRow) []chain.LogicalRow {
	result := make([]chain.LogicalRow, len(rows))
	for index, row := range rows {
		result[index] = chain.LogicalRow{
			Table:      row.Table,
			PrimaryKey: bytes.Clone(row.PrimaryKey),
			Row:        bytes.Clone(row.Row),
		}
	}
	return result
}
