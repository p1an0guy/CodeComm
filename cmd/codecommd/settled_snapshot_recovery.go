package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	daemonSettledSnapshotScratchDirectoryName = "logical-snapshot-imports"

	daemonSnapshotOperationalMaxBytes      uint64 = 256 << 20
	daemonSnapshotOperationalMaxRecords    uint64 = 100_000
	daemonSnapshotOperationalMaxChunks     uint64 = 4_096
	daemonSnapshotOperationalMaxPages      uint64 = 1
	daemonSnapshotOperationalMaxGeneration uint64 = 255
)

var errDaemonSnapshotReceiveQuota = errors.New(
	"codecommd: logical snapshot exceeds daemon receive quota",
)

type daemonSettledSnapshotScratch struct {
	base      string
	directory string
	expanded  *os.File
	sequence  *os.File
	boundary  *os.File
	stagePath string
	cache     *daemonSettledSnapshotCache
}

func daemonSettledSnapshotScratchRoot(statePath string) string {
	return filepath.Join(
		filepath.Dir(statePath),
		daemonSettledSnapshotScratchDirectoryName,
	)
}

func prepareDaemonSettledSnapshotScratch(path string) error {
	return prepareDaemonSettledSnapshotScratchAt(path, time.Now())
}

func prepareDaemonSettledSnapshotRecoveryScratchAt(
	path string,
	now time.Time,
) error {
	return prepareDaemonSettledSnapshotScratchAt(path, now)
}

func newDaemonSettledSnapshotScratch(
	root string,
	snapshotRoot logicalsnapshot.Root,
) (_ *daemonSettledSnapshotScratch, err error) {
	if err := prepareDaemonSettledSnapshotScratch(root); err != nil {
		return nil, err
	}
	cache, err := openDaemonSettledSnapshotCache(root, snapshotRoot)
	if err != nil {
		return nil, err
	}
	if err := requireDaemonSnapshotDirectoryUnder(
		filepath.Dir(root),
		root,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: insecure snapshot quarantine root: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	directory, err := createDaemonSnapshotTempDirectoryUnder(
		filepath.Dir(root),
		root,
		daemonSettledSnapshotAttemptPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create snapshot quarantine: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	scratch := &daemonSettledSnapshotScratch{
		base:      filepath.Dir(root),
		directory: directory,
		stagePath: filepath.Join(directory, "stage.db"),
		cache:     cache,
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, scratch.Close())
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf(
			"%w: secure snapshot quarantine: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	scratch.expanded, err = openDaemonSettledSnapshotScratchFile(
		scratch.base,
		directory,
		"expanded.bin",
	)
	if err != nil {
		return nil, err
	}
	scratch.sequence, err = openDaemonSettledSnapshotScratchFile(
		scratch.base,
		directory,
		"sequence.bin",
	)
	if err != nil {
		return nil, err
	}
	scratch.boundary, err = openDaemonSettledSnapshotScratchFile(
		scratch.base,
		directory,
		"boundary.bin",
	)
	if err != nil {
		return nil, err
	}
	return scratch, nil
}

func openDaemonSettledSnapshotScratchFile(
	base string,
	directory string,
	name string,
) (*os.File, error) {
	file, err := createDaemonSnapshotFileUnder(
		base,
		filepath.Join(directory, name),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create snapshot scratch %s: %v",
			errDaemonSettledReplication,
			name,
			err,
		)
	}
	return file, nil
}

func (scratch *daemonSettledSnapshotScratch) Close() error {
	if scratch == nil {
		return nil
	}
	var result error
	for _, file := range []*os.File{
		scratch.expanded,
		scratch.sequence,
		scratch.boundary,
	} {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	if scratch.directory != "" {
		result = errors.Join(
			result,
			removeDaemonSnapshotTreeUnder(
				scratch.base,
				scratch.directory,
			),
		)
	}
	return result
}

func (scratch *daemonSettledSnapshotScratch) discardCache() error {
	if scratch == nil || scratch.cache == nil {
		return nil
	}
	return scratch.cache.discard()
}

func (runtime *daemonSettledReplication) installLatestSnapshot(
	ctx context.Context,
	relayPeerID domain.DeviceID,
	client daemonReplicationClient,
	before store.ApplyHeads,
) (resultErr error) {
	if runtime == nil ||
		runtime.replica == nil ||
		ctx == nil ||
		!relayPeerID.Valid() ||
		client == nil ||
		!cleanAbsolutePath(runtime.scratchRoot) ||
		!runtime.originBootID.Valid() ||
		runtime.clock == nil {
		return errDaemonSettledReplication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := client.LatestSnapshot(ctx)
	if err != nil {
		return fmt.Errorf(
			"%w: peer %s did not provide a snapshot: %w",
			errDaemonReplicationSnapshotRequired,
			relayPeerID,
			err,
		)
	}
	if err := runtime.preflightSnapshotRoot(relayPeerID, root); err != nil {
		return fmt.Errorf(
			"%w: reject snapshot root from %s: %w",
			errDaemonSettledReplication,
			relayPeerID,
			err,
		)
	}
	input := root.Unsigned().Input()
	if input.ResultIndex <= before.ResultIndex {
		return fmt.Errorf(
			"%w: peer %s offered non-advancing snapshot result %d at cursor %d",
			errDaemonReplicationSnapshotRequired,
			relayPeerID,
			input.ResultIndex,
			before.ResultIndex,
		)
	}
	boundaries, err := consensus.NewGenerationZeroBoundaryVerifier(
		runtime.replica,
	)
	if err != nil {
		return runtime.replicaError(
			"construct snapshot boundary verifier",
			err,
		)
	}
	scratch, err := newDaemonSettledSnapshotScratch(
		runtime.scratchRoot,
		root,
	)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, scratch.Close())
	}()
	var bulk daemonSnapshotBulkClient
	defer func() {
		if bulk != nil {
			resultErr = errors.Join(resultErr, bulk.Close())
		}
	}()
	openBulk := func(
		openContext context.Context,
	) (daemonSnapshotBulkClient, error) {
		if bulk != nil {
			return bulk, nil
		}
		var openErr error
		bulk, openErr = client.OpenSnapshotBulk(openContext, root)
		return bulk, openErr
	}

	verified, err := consensus.VerifyAndStageLogicalSnapshot(
		ctx,
		root,
		consensus.LogicalSnapshotImportOptions{
			ExpandedArtifact: scratch.expanded,
			SequenceScratch:  scratch.sequence,
			BoundaryScratch:  scratch.boundary,
			OpenPage: func(
				openContext context.Context,
				pageIndex uint64,
			) (io.ReadCloser, error) {
				return scratch.cache.openPage(
					openContext,
					pageIndex,
					func(
						fetchContext context.Context,
						fetchIndex uint64,
					) (logicalsnapshot.DescriptorPage, error) {
						transfer, openErr := openBulk(fetchContext)
						if openErr != nil {
							return logicalsnapshot.DescriptorPage{},
								openErr
						}
						return transfer.SnapshotManifestPage(
							fetchContext,
							fetchIndex,
						)
					},
				)
			},
			OpenChunk: func(
				openContext context.Context,
				chunkIndex uint64,
			) (io.ReadCloser, error) {
				return scratch.cache.openChunk(
					openContext,
					chunkIndex,
					func(
						fetchContext context.Context,
						fetchIndex uint64,
					) (contenthttp.SnapshotChunk, error) {
						transfer, openErr := openBulk(fetchContext)
						if openErr != nil {
							return contenthttp.SnapshotChunk{},
								openErr
						}
						return transfer.SnapshotChunk(
							fetchContext,
							fetchIndex,
						)
					},
				)
			},
			PreflightRoot: func(
				_ context.Context,
				candidate logicalsnapshot.Root,
			) error {
				return runtime.preflightSnapshotRoot(
					relayPeerID,
					candidate,
				)
			},
			StagePath:    scratch.stagePath,
			OriginBootID: runtime.originBootID,
			Clock:        runtime.clock,
			Boundaries:   boundaries,
		},
	)
	if err != nil {
		if !scratch.cache.fetchFailed && ctx.Err() == nil {
			err = errors.Join(err, scratch.discardCache())
		}
		if fatal := runtime.replica.FatalError(); fatal != nil {
			return fmt.Errorf(
				"%w: settled replica: %w",
				errDaemonContentPeerState,
				fatal,
			)
		}
		return fmt.Errorf(
			"%w: verify snapshot from %s: %w",
			errDaemonSettledReplication,
			relayPeerID,
			err,
		)
	}
	defer func() {
		resultErr = errors.Join(resultErr, verified.Close())
	}()
	verifiedAt, _, err := runtime.clock()
	if err != nil {
		return fmt.Errorf(
			"%w: read snapshot verification clock: %v",
			errDaemonSettledReplication,
			err,
		)
	}
	installed, err := runtime.replica.InstallLogicalSnapshot(
		ctx,
		verified,
		verifiedAt,
	)
	if err != nil {
		return runtime.replicaError("install logical snapshot", err)
	}
	if err := runtime.validateInstalledSnapshotCut(installed, input); err != nil {
		return err
	}
	return scratch.discardCache()
}

func (runtime *daemonSettledReplication) preflightSnapshotRoot(
	relayPeerID domain.DeviceID,
	root logicalsnapshot.Root,
) error {
	if runtime == nil ||
		runtime.replica == nil ||
		!relayPeerID.Valid() ||
		len(root.CanonicalBytes()) == 0 {
		return errDaemonSettledReplication
	}
	if err := validateDaemonSnapshotOperationalLimits(root); err != nil {
		return err
	}
	input := root.Unsigned().Input()
	admission, err := runtime.replica.PeerAdmissionSnapshot()
	if err != nil {
		return fmt.Errorf("read snapshot signer identity: %w", err)
	}
	sessionID, generation, valid := admission.Lineage()
	if !valid ||
		input.SessionID != sessionID ||
		input.RecoveryGeneration != generation ||
		input.SignerDeviceID != relayPeerID {
		return errors.New("logical snapshot signer or lineage differs from peer")
	}
	signer, exists := admission.Member(input.SignerDeviceID)
	if !exists || signer.Status != device.StatusActive {
		return errors.New("logical snapshot signer is not an active member")
	}
	if err := logicalsnapshot.VerifyRoot(
		root,
		signer.IdentityPublicKey,
	); err != nil {
		return fmt.Errorf("verify snapshot root before transfer: %w", err)
	}
	authority, valid := admission.CredentialAuthority()
	if !valid ||
		input.AuthorityVersion < authority.VoterSetVersion ||
		input.AuthorityVersion == authority.VoterSetVersion &&
			!authority.Contains(input.SignerDeviceID) {
		return errors.New(
			"logical snapshot signer is not valid for the applied authority",
		)
	}
	return nil
}

func validateDaemonSnapshotOperationalLimits(
	root logicalsnapshot.Root,
) error {
	if len(root.CanonicalBytes()) == 0 {
		return errDaemonSettledReplication
	}
	input := root.Unsigned().Input()
	if input.ExpandedBytes > daemonSnapshotOperationalMaxBytes ||
		input.CompressedBytes > daemonSnapshotOperationalMaxBytes ||
		input.RecordCount > daemonSnapshotOperationalMaxRecords ||
		input.ChunkCount > daemonSnapshotOperationalMaxChunks ||
		input.DescriptorPageCount > daemonSnapshotOperationalMaxPages ||
		input.RecoveryGeneration >
			daemonSnapshotOperationalMaxGeneration {
		return errDaemonSnapshotReceiveQuota
	}
	return nil
}

func (runtime *daemonSettledReplication) validateInstalledSnapshotCut(
	installed store.StandaloneLogicalSnapshotInstallResult,
	input logicalsnapshot.RootInput,
) error {
	if err := validateDaemonInstalledSnapshotCut(installed, input); err != nil {
		return runtime.failContentPeerState(
			"validate installed snapshot cut",
			err,
		)
	}
	return nil
}

func validateDaemonInstalledSnapshotCut(
	installed store.StandaloneLogicalSnapshotInstallResult,
	input logicalsnapshot.RootInput,
) error {
	expected := store.LogicalSnapshotCut{
		SessionID:               input.SessionID,
		WorkspaceID:             input.WorkspaceID,
		RecoveryGeneration:      input.RecoveryGeneration,
		CheckpointEventID:       input.CheckpointEventID,
		ChainIndex:              input.ChainIndex,
		ChainHash:               store.Digest(input.ChainHash),
		ResultIndex:             input.ResultIndex,
		ResultHash:              store.Digest(input.ResultHash),
		ProjectionAccumulator:   store.Digest(input.ProjectionAccumulator),
		ProjectionStateDigest:   store.Digest(input.ProjectionStateDigest),
		AuthorityVersion:        input.AuthorityVersion,
		SignerDeviceID:          input.SignerDeviceID,
		DigestVersion:           input.DigestVersion,
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
		RecordCount:             input.RecordCount,
	}
	if installed.Cut != expected {
		return errors.New("installed cut differs from signed root")
	}
	if installed.Heads.ChainIndex != expected.ChainIndex ||
		installed.Heads.ChainHash != expected.ChainHash ||
		installed.Heads.ResultIndex != expected.ResultIndex ||
		installed.Heads.ResultHash != expected.ResultHash ||
		installed.Heads.ProjectionAccumulator !=
			expected.ProjectionAccumulator ||
		installed.Heads.DigestVersion != expected.DigestVersion ||
		installed.Heads.ProjectionSchemaVersion !=
			expected.ProjectionSchemaVersion {
		return errors.New("installed heads differ from signed root")
	}
	return nil
}
