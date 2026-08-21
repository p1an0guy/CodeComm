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
			FromResultIndex: exported.FromResultIndex,
			ToResultIndex:   exported.ToResultIndex,
			StartResultHash: chain.Digest(exported.StartResultHash),
			EndResultHash:   chain.Digest(exported.EndResultHash),
			StartChainIndex: exported.StartChainIndex,
			StartChainHash:  chain.Digest(exported.StartChainHash),
			EndChainIndex:   exported.EndChainIndex,
			EndChainHash:    chain.Digest(exported.EndChainHash),
			StartProjectionAccumulator: chain.Digest(
				exported.StartProjectionAccumulator,
			),
			EndProjectionAccumulator: chain.Digest(
				exported.EndProjectionAccumulator,
			),
			StartProjectionStateDigest: chain.Digest(
				exported.StartProjectionStateDigest,
			),
			EndProjectionStateDigest: chain.Digest(
				exported.EndProjectionStateDigest,
			),
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

func (service *daemonContentService) ReplicationAcknowledgement(
	ctx context.Context,
	atResultIndex uint64,
) (replication.Acknowledgement, error) {
	if service == nil ||
		service.state == nil ||
		service.signAcknowledgement == nil ||
		ctx == nil ||
		!domain.ValidUnsignedInteger(atResultIndex) {
		return replication.Acknowledgement{},
			contenthttp.ErrInvalidReplicationCursor
	}
	if err := ctx.Err(); err != nil {
		return replication.Acknowledgement{}, err
	}
	watermark, err := service.state.ExportReplicationWatermark(
		ctx,
		service.localDeviceID,
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrResultRangeAuthorityNotCovered):
			return replication.Acknowledgement{},
				contenthttp.ErrReplicationUnavailable
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return replication.Acknowledgement{}, err
		default:
			return replication.Acknowledgement{}, fmt.Errorf(
				"%w: export replication watermark: %v",
				errDaemonContentConstruction,
				err,
			)
		}
	}
	if watermark.SessionID != service.sessionID ||
		watermark.WorkspaceID != service.workspaceID ||
		watermark.RecoveryGeneration != service.recoveryGeneration ||
		watermark.ResultIndex != atResultIndex ||
		!watermark.Authority.Contains(service.localDeviceID) {
		return replication.Acknowledgement{},
			contenthttp.ErrReplicationUnavailable
	}
	unsigned, err := replication.NewUnsignedAcknowledgement(
		replication.AcknowledgementInput{
			SessionID:                watermark.SessionID,
			WorkspaceID:              watermark.WorkspaceID,
			RecoveryGeneration:       watermark.RecoveryGeneration,
			ServerDeviceID:           service.localDeviceID,
			ServerAuthorityVersion:   watermark.Authority.VoterSetVersion,
			ResultIndex:              watermark.ResultIndex,
			ResultHash:               chain.Digest(watermark.ResultHash),
			ChainIndex:               watermark.ChainIndex,
			ChainHash:                chain.Digest(watermark.ChainHash),
			ProjectionAccumulator:    chain.Digest(watermark.ProjectionAccumulator),
			ProjectionStateDigest:    chain.Digest(watermark.ProjectionStateDigest),
			ServerAppliedResultIndex: watermark.ResultIndex,
		},
	)
	if err != nil {
		return replication.Acknowledgement{}, fmt.Errorf(
			"%w: build replication acknowledgement: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	signed, err := service.signAcknowledgement(unsigned)
	if err != nil || !signed.MatchesUnsigned(unsigned) ||
		len(signed.CanonicalBytes()) == 0 {
		return replication.Acknowledgement{}, fmt.Errorf(
			"%w: sign replication acknowledgement",
			errDaemonContentConstruction,
		)
	}
	return signed, nil
}
