package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/consensus"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	daemonSnapshotPublicationInterval = 30 * time.Minute
	daemonSnapshotLeadershipRetry     = 5 * time.Second
	daemonSnapshotBuildTimeout        = 5 * time.Minute
)

var errDaemonSnapshotPublication = errors.New(
	"codecommd: logical snapshot publication failed",
)

type daemonSnapshotCheckpointSource interface {
	ForceCheckpoint(
		context.Context,
	) (store.AppliedCheckpointLookup, error)
	SnapshotPublicationChanges() <-chan struct{}
}

type daemonSnapshotBuild func(
	context.Context,
	snapshotbuilder.RecordSource,
	snapshotbuilder.Options,
) (snapshotbuilder.Snapshot, error)

type daemonLogicalSnapshotPublisher struct {
	checkpoints  daemonSnapshotCheckpointSource
	records      snapshotbuilder.RecordSource
	repository   *daemonLogicalSnapshotRepository
	deviceID     domain.DeviceID
	publicKey    ed25519.PublicKey
	privateKey   ed25519.PrivateKey
	build        daemonSnapshotBuild
	interval     time.Duration
	retry        time.Duration
	buildTimeout time.Duration

	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	fatalMu   sync.Mutex
	fatal     error

	diagnosticMu sync.Mutex
	attempts     uint64
	successes    uint64
	lastError    error
	lastAttempt  time.Time
	lastSuccess  time.Time
}

type daemonSnapshotPublicationStats struct {
	Attempts    uint64
	Successes   uint64
	LastError   error
	LastAttempt time.Time
	LastSuccess time.Time
}

func newDaemonLogicalSnapshotPublisher(
	ctx context.Context,
	checkpoints daemonSnapshotCheckpointSource,
	records snapshotbuilder.RecordSource,
	repository *daemonLogicalSnapshotRepository,
	deviceID domain.DeviceID,
	identityPrivateKey ed25519.PrivateKey,
) (*daemonLogicalSnapshotPublisher, error) {
	if ctx == nil ||
		checkpoints == nil ||
		records == nil ||
		repository == nil ||
		!deviceID.Valid() ||
		len(identityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errDaemonSnapshotPublication
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		identityPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: derive signer key: %v",
			errDaemonSnapshotPublication,
			err,
		)
	}
	runContext, cancel := context.WithCancel(ctx)
	publisher := &daemonLogicalSnapshotPublisher{
		checkpoints:  checkpoints,
		records:      records,
		repository:   repository,
		deviceID:     deviceID,
		publicKey:    bytesClonePublicKey(publicKey),
		privateKey:   identityPrivateKey,
		build:        snapshotbuilder.Build,
		interval:     daemonSnapshotPublicationInterval,
		retry:        daemonSnapshotLeadershipRetry,
		buildTimeout: daemonSnapshotBuildTimeout,
		cancel:       cancel,
		done:         make(chan struct{}),
	}
	go publisher.run(runContext)
	return publisher, nil
}

func (publisher *daemonLogicalSnapshotPublisher) run(ctx context.Context) {
	defer close(publisher.done)
	changes := publisher.checkpoints.SnapshotPublicationChanges()
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case _, open := <-changes:
				if !timer.Stop() {
					<-timer.C
				}
				if !open {
					return
				}
			case <-timer.C:
			}
		}
		err := publisher.publishOnce(ctx)
		publisher.recordAttempt(err)
		switch {
		case err == nil:
			delay = publisher.interval
		case ctx.Err() != nil:
			return
		case retryableDaemonSnapshotPublication(err):
			delay = publisher.retry
		default:
			publisher.setFatal(err)
			return
		}
	}
}

func (publisher *daemonLogicalSnapshotPublisher) recordAttempt(err error) {
	if publisher == nil {
		return
	}
	publisher.diagnosticMu.Lock()
	defer publisher.diagnosticMu.Unlock()
	publisher.attempts++
	publisher.lastError = err
	publisher.lastAttempt = time.Now()
	if err == nil {
		publisher.successes++
		publisher.lastSuccess = publisher.lastAttempt
	}
}

func (publisher *daemonLogicalSnapshotPublisher) publicationStats() daemonSnapshotPublicationStats {
	if publisher == nil {
		return daemonSnapshotPublicationStats{}
	}
	publisher.diagnosticMu.Lock()
	defer publisher.diagnosticMu.Unlock()
	return daemonSnapshotPublicationStats{
		Attempts:    publisher.attempts,
		Successes:   publisher.successes,
		LastError:   publisher.lastError,
		LastAttempt: publisher.lastAttempt,
		LastSuccess: publisher.lastSuccess,
	}
}

func (publisher *daemonLogicalSnapshotPublisher) publishOnce(
	ctx context.Context,
) (err error) {
	if publisher == nil ||
		ctx == nil ||
		publisher.checkpoints == nil ||
		publisher.records == nil ||
		publisher.repository == nil ||
		!publisher.deviceID.Valid() ||
		len(publisher.publicKey) != ed25519.PublicKeySize ||
		len(publisher.privateKey) != ed25519.PrivateKeySize ||
		publisher.build == nil {
		return errDaemonSnapshotPublication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publisher.repository.requireNewSnapshotPublicationCapacity(); err != nil {
		return err
	}
	checkpoint, err := publisher.checkpoints.ForceCheckpoint(ctx)
	if err != nil {
		return err
	}
	record := checkpoint.Record
	if err := record.Validate(); err != nil ||
		record.SessionID != publisher.repository.sessionID ||
		record.WorkspaceID != publisher.repository.workspaceID ||
		record.RecoveryGeneration !=
			publisher.repository.recoveryGeneration {
		return fmt.Errorf(
			"%w: forced checkpoint differs from publisher lineage",
			errDaemonSnapshotPublication,
		)
	}
	artifactID := daemonSnapshotArtifactID(record.CheckpointEventID)
	buildTimeout := publisher.buildTimeout
	if buildTimeout <= 0 {
		buildTimeout = daemonSnapshotBuildTimeout
	}
	buildContext, cancelBuild := context.WithTimeout(ctx, buildTimeout)
	defer cancelBuild()
	_, err = publisher.repository.publish(
		buildContext,
		publisher.records,
		snapshotbuilder.Options{
			ArtifactID:        artifactID,
			CheckpointEventID: record.CheckpointEventID,
			SignerDeviceID:    publisher.deviceID,
			SignerPublicKey:   publisher.publicKey,
			SignRoot: func(
				signContext context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				if err := signContext.Err(); err != nil {
					return logicalsnapshot.Root{}, err
				}
				return logicalsnapshot.SignRoot(
					unsigned,
					publisher.privateKey,
				)
			},
		},
		publisher.build,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", errDaemonSnapshotPublication, err)
	}
	return nil
}

func retryableDaemonSnapshotPublication(err error) bool {
	return errors.Is(err, raft.ErrNotLeader) ||
		errors.Is(err, raft.ErrLeadershipLost) ||
		errors.Is(err, raft.ErrLeadershipTransferInProgress) ||
		errors.Is(err, consensus.ErrProposalForwardingUnavailable) ||
		errors.Is(err, consensus.ErrLeadershipEpochChanged) ||
		errors.Is(err, consensus.ErrCheckpointProofUnavailable) ||
		errors.Is(err, store.ErrLogicalSnapshotNotCovered) ||
		errors.Is(err, store.ErrLogicalSnapshotSignerUnauthorized) ||
		errors.Is(err, errDaemonSnapshotCleanupPending)
}

func (publisher *daemonLogicalSnapshotPublisher) BeginClose() error {
	if publisher == nil || publisher.cancel == nil {
		return errDaemonSnapshotPublication
	}
	publisher.closeOnce.Do(publisher.cancel)
	return nil
}

func (publisher *daemonLogicalSnapshotPublisher) Wait() error {
	if publisher == nil || publisher.done == nil {
		return errDaemonSnapshotPublication
	}
	<-publisher.done
	return nil
}

func (publisher *daemonLogicalSnapshotPublisher) FatalError() error {
	if publisher == nil {
		return errDaemonSnapshotPublication
	}
	publisher.fatalMu.Lock()
	defer publisher.fatalMu.Unlock()
	return publisher.fatal
}

func (publisher *daemonLogicalSnapshotPublisher) setFatal(err error) {
	if err == nil {
		err = errDaemonSnapshotPublication
	}
	publisher.fatalMu.Lock()
	if publisher.fatal == nil {
		publisher.fatal = err
	}
	publisher.fatalMu.Unlock()
}

func daemonSnapshotArtifactID(eventID domain.UUIDv7) string {
	if !eventID.Valid() {
		return ""
	}
	return "snapshot-" + strings.ReplaceAll(string(eventID), "-", "")
}

func bytesClonePublicKey(value []byte) ed25519.PublicKey {
	result := make([]byte, len(value))
	copy(result, value)
	return ed25519.PublicKey(result)
}

var (
	_ phasedDaemonComponent = (*daemonLogicalSnapshotPublisher)(nil)
	_ daemonFatalComponent  = (*daemonLogicalSnapshotPublisher)(nil)
	_ daemonSnapshotBuild   = snapshotbuilder.Build
)
