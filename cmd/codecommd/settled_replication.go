package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/peerauth"
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
	VerifiedGenerationZeroView(context.Context) (store.StateView, error)
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	ReplicationHeads(context.Context) (store.ApplyHeads, error)
	ImportResultBatch(
		context.Context,
		domain.DeviceID,
		replication.Batch,
	) (store.ResultBatchImportResult, error)
	InstallLogicalSnapshot(
		context.Context,
		*consensus.VerifiedLogicalSnapshotStage,
		domain.Timestamp,
	) (store.StandaloneLogicalSnapshotInstallResult, error)
	ObserveReplicationAcknowledgement(
		context.Context,
		domain.DeviceID,
		replication.Acknowledgement,
	) error
	ForgetReplicationPeer(domain.DeviceID)
	FatalError() error
}

type daemonReplicationClient interface {
	Replication(context.Context, uint64) (replication.Batch, error)
	ReplicationAcknowledgement(
		context.Context,
		uint64,
	) (replication.Acknowledgement, error)
	LatestSnapshot(context.Context) (logicalsnapshot.Root, error)
	OpenSnapshotBulk(
		context.Context,
		logicalsnapshot.Root,
	) (daemonSnapshotBulkClient, error)
}

type daemonSnapshotBulkClient interface {
	SnapshotManifestPage(
		context.Context,
		uint64,
	) (logicalsnapshot.DescriptorPage, error)
	SnapshotChunk(
		context.Context,
		uint64,
	) (contenthttp.SnapshotChunk, error)
	Close() error
}

type daemonSettledReplicationOptions struct {
	Replica      daemonSettledReplica
	ScratchRoot  string
	OriginBootID domain.UUIDv7
	Clock        consensus.ApplyClock
}

// daemonSettledReplication serializes authenticated peer fetch/import passes.
// This prevents a stale page from being excused by an unrelated peer's
// concurrent progress.
type daemonSettledReplication struct {
	replica      daemonSettledReplica
	scratchRoot  string
	originBootID domain.UUIDv7
	clock        consensus.ApplyClock
	gate         chan struct{}
	fatalMu      sync.Mutex
	fatal        error
}

func newDaemonSettledReplication(
	ctx context.Context,
	options daemonSettledReplicationOptions,
) (*daemonSettledReplication, error) {
	if ctx == nil ||
		options.Replica == nil ||
		!cleanAbsolutePath(options.ScratchRoot) ||
		!options.OriginBootID.Valid() ||
		options.Clock == nil {
		return nil, errDaemonSettledReplication
	}
	if _, err := options.Replica.ReplicationHeads(ctx); err != nil {
		return nil, err
	}
	if err := prepareDaemonSettledSnapshotScratch(options.ScratchRoot); err != nil {
		return nil, err
	}
	return &daemonSettledReplication{
		replica:      options.Replica,
		scratchRoot:  options.ScratchRoot,
		originBootID: options.OriginBootID,
		clock:        options.Clock,
		gate:         make(chan struct{}, 1),
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
	if fatal := runtime.fatalError(); fatal != nil {
		return fatal
	}
	if fatal := runtime.replica.FatalError(); fatal != nil {
		return fmt.Errorf(
			"%w: settled replica: %w",
			errDaemonContentPeerState,
			fatal,
		)
	}
	runtime.replica.ForgetReplicationPeer(relayPeerID)
	snapshotInstalled := false

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
				acknowledgement, acknowledgementErr :=
					client.ReplicationAcknowledgement(
						ctx,
						before.ResultIndex,
					)
				if acknowledgementErr != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						return ctxErr
					}
					if errors.Is(
						acknowledgementErr,
						contenthttp.ErrReplicationUnavailable,
					) {
						return nil
					}
					return fmt.Errorf(
						"%w: fetch acknowledgement from %s: %w",
						errDaemonSettledReplication,
						relayPeerID,
						acknowledgementErr,
					)
				}
				if err := runtime.replica.
					ObserveReplicationAcknowledgement(
						ctx,
						relayPeerID,
						acknowledgement,
					); err != nil {
					return runtime.replicaError(
						"record acknowledgement",
						err,
					)
				}
				return nil
			case errors.Is(err, contenthttp.ErrReplicationSnapshotRequired):
				if snapshotInstalled {
					return fmt.Errorf(
						"%w: peer %s still requires a snapshot after replacement",
						errDaemonReplicationSnapshotRequired,
						relayPeerID,
					)
				}
				if err := runtime.installLatestSnapshot(
					ctx,
					relayPeerID,
					client,
					before,
				); err != nil {
					return err
				}
				snapshotInstalled = true
				continue
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

func (runtime *daemonSettledReplication) fatalError() error {
	if runtime == nil {
		return nil
	}
	runtime.fatalMu.Lock()
	defer runtime.fatalMu.Unlock()
	return runtime.fatal
}

func (runtime *daemonSettledReplication) failContentPeerState(
	operation string,
	err error,
) error {
	if runtime == nil {
		return errDaemonContentPeerState
	}
	runtime.fatalMu.Lock()
	defer runtime.fatalMu.Unlock()
	if runtime.fatal == nil {
		runtime.fatal = fmt.Errorf(
			"%w: %s: %w",
			errDaemonContentPeerState,
			operation,
			err,
		)
	}
	return runtime.fatal
}

func (runtime *daemonSettledReplication) ForgetPeer(
	peerID domain.DeviceID,
) {
	if runtime == nil || runtime.replica == nil || !peerID.Valid() {
		return
	}
	runtime.replica.ForgetReplicationPeer(peerID)
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
