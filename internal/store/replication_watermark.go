package store

import (
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// ReplicationWatermark is one fully verified current result/projection cut
// suitable for an identity-signed equal-cursor acknowledgement.
type ReplicationWatermark struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64

	ResultIndex           uint64
	ResultHash            Digest
	ChainIndex            uint64
	ChainHash             Digest
	ProjectionAccumulator Digest
	ProjectionStateDigest Digest

	Authority voterset.Set
}

// ExportReplicationWatermark returns the current commitment cut only when the
// required signer is active in the authority at that exact result position.
func (store *Store) ExportReplicationWatermark(
	ctx context.Context,
	requiredSigner domain.DeviceID,
) (ReplicationWatermark, error) {
	if ctx == nil || !requiredSigner.Valid() {
		return ReplicationWatermark{}, fmt.Errorf(
			"%w: invalid replication watermark request",
			ErrInvalidOptions,
		)
	}
	if err := ctx.Err(); err != nil {
		return ReplicationWatermark{}, err
	}

	var watermark ReplicationWatermark
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
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
				ErrResultRangeNotCovered,
			)
		}
		if err := verifyCommitmentHistory(conn, state); err != nil {
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
		authorization, err := resultRangeAuthorizationAt(
			conn,
			state,
			state.resultIndex,
			requiredSigner,
		)
		if err != nil {
			return err
		}
		if !authorization.permits(requiredSigner) {
			return fmt.Errorf(
				"%w: device %s is not active in authority version %d",
				ErrResultRangeAuthorityNotCovered,
				requiredSigner,
				authorization.authority.VoterSetVersion,
			)
		}
		workspaceID, err := resultRangeWorkspaceID(conn, state)
		if err != nil {
			return err
		}
		projection, err := resultRangeProjectionCommitmentsAt(
			conn,
			state,
			genesis,
			state.resultIndex,
		)
		if err != nil {
			return err
		}
		if projection.accumulator != state.projectionAccumulator {
			return historyIntegrityError(
				"current projection accumulator differs",
				nil,
			)
		}
		watermark = ReplicationWatermark{
			SessionID:             state.sessionID,
			WorkspaceID:           workspaceID,
			RecoveryGeneration:    state.recoveryGeneration,
			ResultIndex:           state.resultIndex,
			ResultHash:            state.resultHash,
			ChainIndex:            state.chainIndex,
			ChainHash:             state.chainHash,
			ProjectionAccumulator: projection.accumulator,
			ProjectionStateDigest: projection.stateDigest,
			Authority:             authorization.authority,
		}
		return nil
	})
	if err != nil {
		return ReplicationWatermark{}, err
	}
	return watermark, nil
}

// ExportReplicationWatermark exposes the verified current cut through the
// restricted local-state capability.
func (state LocalState) ExportReplicationWatermark(
	ctx context.Context,
	requiredSigner domain.DeviceID,
) (ReplicationWatermark, error) {
	if err := state.validate(); err != nil {
		return ReplicationWatermark{}, ErrInvalidLocalState
	}
	release, err := state.beginOperation()
	if err != nil {
		return ReplicationWatermark{}, err
	}
	defer release()
	return state.store.ExportReplicationWatermark(ctx, requiredSigner)
}
