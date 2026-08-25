package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrGenerationZeroStateUnavailable = errors.New(
	"store: verified generation-zero state unavailable",
)

// VerifiedGenerationZeroView fully scrubs the retained lineage and returns
// its exact initial projection cut. Later generations use the immutable
// genesis-digest-bound baseline because a recovery transform is intentionally
// non-invertible.
func (store *Store) VerifiedGenerationZeroView(
	ctx context.Context,
) (StateView, error) {
	if store == nil || ctx == nil {
		return StateView{}, fmt.Errorf(
			"%w: invalid generation-zero query",
			ErrGenerationZeroStateUnavailable,
		)
	}
	if err := ctx.Err(); err != nil {
		return StateView{}, err
	}

	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var view StateView
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
			return ErrGenerationZeroStateUnavailable
		}
		if err := verifyFullCommitmentState(conn, state); err != nil {
			return err
		}
		sessionID, workspaceID, err := historicalGenesisIdentity(conn, 0)
		if err != nil {
			return err
		}
		genesis, err := readGenesisBoundary(conn, 0, sessionID)
		if err != nil {
			return err
		}
		if genesis.hasPredecessor ||
			genesis.predecessorChainIndex != 0 ||
			genesis.predecessorResultIndex != 0 {
			return fmt.Errorf(
				"%w: initial genesis carries predecessor state",
				ErrGenerationZeroStateUnavailable,
			)
		}
		genesisDigest, err := chain.GenesisDigest(genesis.genesisJSON)
		if err != nil ||
			genesisDigest != chain.Digest(genesis.genesisDigest) {
			return fmt.Errorf(
				"%w: invalid initial genesis commitment: %v",
				ErrGenerationZeroStateUnavailable,
				err,
			)
		}

		rows := make([]chain.LogicalRow, 0)
		versions := chain.Versions{
			Digest:           state.digestVersion,
			ProjectionSchema: state.projectionSchemaVersion,
		}
		_, retained, err := readInitialProjectionBoundary(
			conn,
			versions,
			genesis.stateDigest,
			func(row chain.LogicalRow) error {
				rows = append(rows, cloneLogicalRow(row))
				return nil
			},
		)
		if err != nil {
			return err
		}
		stateDigest := genesis.stateDigest
		if !retained {
			if state.recoveryGeneration != 0 ||
				state.sessionID != sessionID {
				return fmt.Errorf(
					"%w: initial projection boundary was not retained",
					ErrGenerationZeroStateUnavailable,
				)
			}
			stateDigest, err = projectionStateDigestAtResultCut(
				conn,
				state,
				genesis,
				0,
				func(row chain.LogicalRow) error {
					rows = append(rows, cloneLogicalRow(row))
					return nil
				},
			)
			if err != nil {
				return err
			}
			if !bytes.Equal(stateDigest[:], genesis.stateDigest[:]) {
				return fmt.Errorf(
					"%w: reconstructed initial projection digest differs",
					ErrGenerationZeroStateUnavailable,
				)
			}
			if err := writeInitialProjectionBoundary(
				conn,
				rows,
				versions,
				stateDigest,
			); err != nil {
				return fmt.Errorf(
					"%w: retain reconstructed initial projection boundary: %v",
					ErrGenerationZeroStateUnavailable,
					err,
				)
			}
		}
		if state.recoveryGeneration == 0 &&
			sessionID != state.sessionID {
			return fmt.Errorf(
				"%w: initial and active session differ",
				ErrGenerationZeroStateUnavailable,
			)
		}
		boundary := chain.Boundary{Genesis: genesisDigest}
		eventSeed, err := chain.EventSeed(boundary)
		if err != nil {
			return err
		}
		resultSeed, err := chain.ResultSeed(boundary)
		if err != nil {
			return err
		}
		accumulator := chain.AccumulatorSeedInitial(
			genesisDigest,
			chain.Digest(stateDigest),
		)
		view = StateView{
			SessionID:          sessionID,
			WorkspaceID:        workspaceID,
			RecoveryGeneration: 0,
			GenesisJSON:        bytes.Clone(genesis.genesisJSON),
			Heads: ApplyHeads{
				ChainHash:               Digest(eventSeed),
				ResultHash:              Digest(resultSeed),
				ProjectionAccumulator:   Digest(accumulator),
				DigestVersion:           state.digestVersion,
				ProjectionSchemaVersion: state.projectionSchemaVersion,
			},
			ProjectionStateDigest: stateDigest,
			ProjectionRows:        rows,
		}
		return nil
	})
	if err != nil {
		return StateView{}, err
	}
	return view, nil
}
