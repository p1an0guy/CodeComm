package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

func (service *daemonContentService) Replication(
	ctx context.Context,
	afterResultIndex uint64,
) (replication.Batch, error) {
	if service == nil ||
		service.state == nil ||
		service.signResultBatch == nil ||
		ctx == nil ||
		!domain.ValidUnsignedInteger(afterResultIndex) {
		return replication.Batch{},
			contenthttp.ErrInvalidReplicationCursor
	}
	if err := ctx.Err(); err != nil {
		return replication.Batch{}, err
	}

	exported, found, err := service.state.ExportResultRange(
		ctx,
		store.ResultRangeOptions{
			AfterResultIndex:          afterResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: service.localDeviceID,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrResultRangeNotCovered):
			return replication.Batch{},
				contenthttp.ErrInvalidReplicationCursor
		case errors.Is(err, store.ErrResultRangeSnapshotRequired):
			return replication.Batch{},
				contenthttp.ErrReplicationSnapshotRequired
		case errors.Is(err, store.ErrResultRangeAuthorityNotCovered):
			snapshot, snapshotErr := service.snapshot(ctx)
			if snapshotErr != nil {
				return replication.Batch{}, snapshotErr
			}
			if snapshot.CredentialAuthority.Contains(
				service.localDeviceID,
			) &&
				snapshot.Member.ID == service.localDeviceID &&
				snapshot.Member.Status == device.StatusActive {
				return replication.Batch{},
					contenthttp.ErrReplicationSnapshotRequired
			}
			return replication.Batch{},
				contenthttp.ErrReplicationUnavailable
		case errors.Is(err, store.ErrResultRangeTooLarge):
			return replication.Batch{},
				contenthttp.ErrReplicationSnapshotRequired
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return replication.Batch{}, err
		default:
			return replication.Batch{}, fmt.Errorf(
				"%w: export result range: %v",
				errDaemonContentConstruction,
				err,
			)
		}
	}
	if !found {
		return replication.Batch{}, contenthttp.ErrReplicationUnavailable
	}
	if exported.SessionID != service.sessionID ||
		exported.WorkspaceID != service.workspaceID ||
		exported.RecoveryGeneration != service.recoveryGeneration ||
		exported.FromResultIndex != afterResultIndex+1 ||
		!exported.Authority.Contains(service.localDeviceID) {
		return replication.Batch{}, fmt.Errorf(
			"%w: inconsistent result range",
			errDaemonContentConstruction,
		)
	}

	unsigned, err := replication.NewUnsignedBatch(
		replication.BatchInput{
			FromResultIndex:          exported.FromResultIndex,
			ToResultIndex:            exported.ToResultIndex,
			StartResultHash:          chain.Digest(exported.StartResultHash),
			EndResultHash:            chain.Digest(exported.EndResultHash),
			StartChainIndex:          exported.StartChainIndex,
			StartChainHash:           chain.Digest(exported.StartChainHash),
			EndChainIndex:            exported.EndChainIndex,
			EndChainHash:             chain.Digest(exported.EndChainHash),
			Results:                  exported.Results,
			SessionID:                exported.SessionID,
			WorkspaceID:              exported.WorkspaceID,
			RecoveryGeneration:       exported.RecoveryGeneration,
			ServerDeviceID:           service.localDeviceID,
			ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
			ServerAuthorityVersion:   exported.Authority.VoterSetVersion,
		},
	)
	if err != nil {
		if errors.Is(err, replication.ErrBatchTooLarge) {
			return replication.Batch{},
				contenthttp.ErrReplicationSnapshotRequired
		}
		return replication.Batch{}, fmt.Errorf(
			"%w: build result batch: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	signed, err := service.signResultBatch(unsigned)
	if err != nil ||
		!signed.MatchesUnsigned(unsigned) ||
		signed.EncodedLen() == 0 {
		return replication.Batch{}, fmt.Errorf(
			"%w: sign result batch",
			errDaemonContentConstruction,
		)
	}
	return signed, nil
}
