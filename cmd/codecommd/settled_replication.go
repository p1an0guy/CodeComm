package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

const daemonSettledReplicationPagesPerPass = 64

var (
	errDaemonSettledReplication = errors.New(
		"codecommd: settled replication failed",
	)
	errDaemonReplicationSnapshotRequired = errors.New(
		"codecommd: settled replication requires a snapshot",
	)
)

type daemonSettledReplica interface {
	ReplicationHeads(context.Context) (store.ApplyHeads, error)
	ImportResultBatch(
		context.Context,
		domain.DeviceID,
		replication.Batch,
	) (store.ResultBatchImportResult, error)
	FatalError() error
}

type daemonReplicationClient interface {
	Replication(context.Context, uint64) (replication.Batch, error)
}

// daemonSettledReplication serializes authenticated peer fetch/import passes.
// This prevents a stale page from being excused by an unrelated peer's
// concurrent progress.
type daemonSettledReplication struct {
	replica daemonSettledReplica
	gate    chan struct{}
}

func newDaemonSettledReplication(
	ctx context.Context,
	replica daemonSettledReplica,
) (*daemonSettledReplication, error) {
	if ctx == nil || replica == nil {
		return nil, errDaemonSettledReplication
	}
	if _, err := replica.ReplicationHeads(ctx); err != nil {
		return nil, err
	}
	return &daemonSettledReplication{
		replica: replica,
		gate:    make(chan struct{}, 1),
	}, nil
}

func (runtime *daemonSettledReplication) acquire(ctx context.Context) error {
	if runtime == nil || runtime.gate == nil || ctx == nil {
		return errDaemonSettledReplication
	}
	select {
	case runtime.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *daemonSettledReplication) release() {
	if runtime == nil || runtime.gate == nil {
		return
	}
	<-runtime.gate
}

// Sync fetches and imports a bounded contiguous tail from one authenticated
// relay while holding the process-wide settled-import turn.
func (runtime *daemonSettledReplication) Sync(
	ctx context.Context,
	relayPeerID domain.DeviceID,
	client daemonReplicationClient,
) error {
	if runtime == nil ||
		runtime.replica == nil ||
		ctx == nil ||
		!relayPeerID.Valid() ||
		client == nil {
		return errDaemonSettledReplication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtime.acquire(ctx); err != nil {
		return err
	}
	defer runtime.release()

	for page := 0; page < daemonSettledReplicationPagesPerPass; page++ {
		before, err := runtime.replica.ReplicationHeads(ctx)
		if err != nil {
			return runtime.replicaError("read cursor", err)
		}
		if before.ResultIndex == domain.MaxSafeInteger {
			return fmt.Errorf(
				"%w: result cursor exhausted",
				errDaemonSettledReplication,
			)
		}
		batch, err := client.Replication(ctx, before.ResultIndex)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			switch {
			case errors.Is(err, contenthttp.ErrInvalidReplicationCursor):
				return fmt.Errorf(
					"%w: peer %s rejected cursor %d: %w",
					errDaemonSettledReplication,
					relayPeerID,
					before.ResultIndex,
					err,
				)
			case errors.Is(err, contenthttp.ErrReplicationUnavailable):
				// The peer may be exactly at this cursor or temporarily unable
				// to sign a page. Neither condition invalidates the authenticated
				// connection or establishes replica currency.
				return nil
			case errors.Is(err, contenthttp.ErrReplicationSnapshotRequired):
				return fmt.Errorf(
					"%w: peer %s",
					errDaemonReplicationSnapshotRequired,
					relayPeerID,
				)
			default:
				return fmt.Errorf(
					"%w: fetch from %s: %w",
					errDaemonSettledReplication,
					relayPeerID,
					err,
				)
			}
		}
		metadata := batch.Unsigned().Metadata()
		if metadata.FromResultIndex != before.ResultIndex+1 {
			return fmt.Errorf(
				"%w: peer %s returned a noncontiguous page",
				errDaemonSettledReplication,
				relayPeerID,
			)
		}
		imported, err := runtime.replica.ImportResultBatch(
			ctx,
			relayPeerID,
			batch,
		)
		if err != nil {
			if fatal := runtime.replica.FatalError(); fatal != nil {
				return fmt.Errorf(
					"%w: settled replica: %w",
					errDaemonContentPeerState,
					fatal,
				)
			}
			if errors.Is(err, consensus.ErrInvalidReplicationReplay) ||
				errors.Is(err, store.ErrInvalidResultBatchImport) {
				return fmt.Errorf(
					"%w: peer %s supplied an invalid page: %w",
					errDaemonSettledReplication,
					relayPeerID,
					err,
				)
			}
			return fmt.Errorf(
				"%w: import page: %w",
				errDaemonSettledReplication,
				err,
			)
		}
		if imported.Heads.ResultIndex != metadata.ToResultIndex {
			return fmt.Errorf(
				"%w: imported cursor differs from signed page",
				errDaemonSettledReplication,
			)
		}
		if metadata.ToResultIndex >= metadata.ServerAppliedResultIndex {
			return nil
		}
	}
	return nil
}

func (runtime *daemonSettledReplication) replicaError(
	operation string,
	err error,
) error {
	if fatal := runtime.replica.FatalError(); fatal != nil {
		return fmt.Errorf(
			"%w: settled replica: %w",
			errDaemonContentPeerState,
			fatal,
		)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		errDaemonSettledReplication,
		operation,
		err,
	)
}
