package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestFSMSemanticRaftSnapshotCaptureAndRestoreUsesCommandWatermark(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	t.Cleanup(func() { clear(fixture.signerPrivate) })
	if fixture.source == nil ||
		fixture.sourceView.LastRaftAppliedLogIndex == nil ||
		fixture.sourceView.CurrentTerm == nil {
		t.Fatal("fixture lacks source Raft state")
	}
	baselineIndex := *fixture.sourceView.LastRaftAppliedLogIndex
	baselineTerm := *fixture.sourceView.CurrentTerm
	lookup, found, err := fixture.source.LookupCommandResult(
		context.Background(),
		fixture.snapshot.Cut.CheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf("LookupCommandResult(checkpoint) = (%#v, %t, %v)", lookup, found, err)
	}
	logs := raft.NewInmemStore()
	if err := logs.StoreLogs([]*raft.Log{
		{
			Index: baselineIndex,
			Term:  baselineTerm,
			Type:  raft.LogCommand,
			Data:  bytes.Clone(lookup.CanonicalProposal),
		},
		{
			Index: baselineIndex + 1,
			Term:  baselineTerm,
			Type:  raft.LogBarrier,
		},
	}); err != nil {
		t.Fatalf("StoreLogs(): %v", err)
	}
	sourceSnapshotDir := filepath.Join(t.TempDir(), "source-snapshots")
	if _, err := prepareConsensusDirectory(sourceSnapshotDir); err != nil {
		t.Fatalf("prepare source snapshot directory: %v", err)
	}
	sourceFSM, err := NewFSM(FSMOptions{
		Store:        fixture.source,
		OriginBootID: nodeTestBootID1,
		Clock:        nodeTestClock(),
		LogStore:     logs,
		SnapshotDir:  sourceSnapshotDir,
		SnapshotSigner: RaftSnapshotSignerAdapter{
			SignerDeviceID: fixture.signerID,
			SignerPublicKey: bytes.Clone(
				fixture.signerKey,
			),
			Sign: func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(
					unsigned,
					fixture.signerPrivate,
				)
			},
		},
		ValidateConfiguration: validateDeviceAddressedSnapshotConfiguration,
	})
	if err != nil {
		t.Fatalf("NewFSM(source): %v", err)
	}
	snapshot, err := sourceFSM.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	defer snapshot.Release()
	if _, ok := snapshot.(*logicalFSMSnapshot); !ok {
		t.Fatalf("Snapshot() type = %T", snapshot)
	}

	configuration := raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(fixture.signerID),
		Address:  raft.ServerAddress(fixture.signerID),
	}}}
	delegate := raft.NewInmemSnapshotStore()
	adapter, err := newRaftSnapshotStore(delegate)
	if err != nil {
		t.Fatalf("newRaftSnapshotStore(): %v", err)
	}
	_, transport := raft.NewInmemTransport(
		raft.ServerAddress(fixture.signerID),
	)
	defer transport.Close()
	sink, err := adapter.Create(
		raft.SnapshotVersionMax,
		baselineIndex+1,
		baselineTerm,
		configuration,
		1,
		transport,
	)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	if err := snapshot.Persist(sink); err != nil {
		t.Fatalf("Persist(): %v", err)
	}
	t.Run("startup quarantines finalized unbound snapshot", func(t *testing.T) {
		assertFinalizedUnboundRaftSnapshotQuarantined(
			t,
			snapshot,
			fixture.initial,
			configuration,
			baselineIndex,
			baselineTerm,
			foreignRaftSnapshotLocalID(t, fixture.signerID),
		)
	})
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		fixture.source,
		fixture.sourceView,
		fixture.signerID,
		sourceSnapshotDir,
		nil,
	); err != nil {
		t.Fatalf("verify local source snapshot: %v", err)
	}

	target, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "target", "state.db"),
	})
	if err != nil {
		t.Fatalf("store.Open(target): %v", err)
	}
	t.Cleanup(func() {
		if err := target.Close(); err != nil {
			t.Errorf("target.Close(): %v", err)
		}
	})
	if _, err := target.Initialize(
		context.Background(),
		fixture.initial,
	); err != nil {
		t.Fatalf("target.Initialize(): %v", err)
	}
	targetInitialView, err := target.View(context.Background())
	if err != nil {
		t.Fatalf("target.View(initial): %v", err)
	}
	targetSnapshotDir := filepath.Join(t.TempDir(), "target-snapshots")
	if _, err := prepareConsensusDirectory(targetSnapshotDir); err != nil {
		t.Fatalf("prepare target snapshot directory: %v", err)
	}
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		target,
		targetInitialView,
		fixture.signerID,
		targetSnapshotDir,
		nil,
	); !errors.Is(err, ErrSnapshotAnchorCoverage) {
		t.Fatalf("uncovered local snapshot startup error = %v", err)
	}
	foreignLocalID := foreignRaftSnapshotLocalID(t, fixture.signerID)
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		target,
		targetInitialView,
		foreignLocalID,
		targetSnapshotDir,
		nil,
	); !errors.Is(err, ErrSnapshotAnchorCoverage) {
		t.Fatalf("uninstalled foreign snapshot startup error = %v", err)
	}
	targetLogs := raft.NewInmemStore()
	if err := targetLogs.StoreLog(&raft.Log{
		Index: baselineIndex + 2,
		Term:  baselineTerm,
		Type:  raft.LogBarrier,
	}); err != nil {
		t.Fatalf("StoreLog(post-snapshot retained entry): %v", err)
	}
	targetFSM, err := NewFSM(FSMOptions{
		Store:        target,
		OriginBootID: nodeTestBootID2,
		Clock:        nodeTestClock(),
		LogStore:     targetLogs,
		SnapshotDir:  targetSnapshotDir,
		SnapshotSigner: raftSnapshotTestSigner(
			fixture.signerID,
			fixture.signerKey,
			fixture.signerPrivate,
		),
		ValidateConfiguration: validateDeviceAddressedSnapshotConfiguration,
	})
	if err != nil {
		t.Fatalf("NewFSM(target): %v", err)
	}
	_, reader, err := adapter.Open(sink.ID())
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer reader.Close()
	if err := targetFSM.Restore(reader); err != nil {
		t.Fatalf("Restore(): %v", err)
	}
	restored, err := target.View(context.Background())
	if err != nil {
		t.Fatalf("target.View(): %v", err)
	}
	if restored.LastRaftAppliedLogIndex == nil ||
		*restored.LastRaftAppliedLogIndex != baselineIndex ||
		restored.CurrentTerm == nil ||
		*restored.CurrentTerm != baselineTerm {
		t.Fatalf(
			"restored command watermark = term/index %v/%v, want %d/%d",
			restored.CurrentTerm,
			restored.LastRaftAppliedLogIndex,
			baselineTerm,
			baselineIndex,
		)
	}
	if *restored.LastRaftAppliedLogIndex == baselineIndex+1 {
		t.Fatal("restore used SnapshotMeta.Index as the SQLite command watermark")
	}
	if _, err := targetFSM.Snapshot(); !errors.Is(
		err,
		raft.ErrNothingNewToSnapshot,
	) {
		t.Fatalf("Snapshot(compacted restored baseline) error = %v", err)
	}
	if err := targetFSM.HaltError(); err != nil {
		t.Fatalf("compacted restored baseline halted FSM: %v", err)
	}
	if restored.Heads != fixture.sourceView.Heads ||
		restored.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatal("restored semantic cut differs from source")
	}
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		target,
		restored,
		fixture.signerID,
		targetSnapshotDir,
		nil,
	); err != nil {
		t.Fatalf("verifyLatestLogicalRaftSnapshot(): %v", err)
	}
	newerSnapshot, err := sourceFSM.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(newer): %v", err)
	}
	defer newerSnapshot.Release()
	newerSink, err := adapter.Create(
		raft.SnapshotVersionMax,
		baselineIndex+1,
		baselineTerm,
		configuration,
		1,
		transport,
	)
	if err != nil {
		t.Fatalf("Create(newer): %v", err)
	}
	if err := newerSnapshot.Persist(newerSink); err != nil {
		t.Fatalf("Persist(newer): %v", err)
	}
	metas, err := delegate.List()
	if err != nil ||
		len(metas) != 1 ||
		metas[0].ID != newerSink.ID() ||
		metas[0].ID == sink.ID() {
		t.Fatalf(
			"delegate.List(after reaping) = (%#v, %v)",
			metas,
			err,
		)
	}
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		target,
		restored,
		fixture.signerID,
		targetSnapshotDir,
		nil,
	); err != nil {
		t.Fatalf("verify after installed snapshot reaping: %v", err)
	}
	beforeRebindRevision := target.AdmissionRevision()
	_, replayReader, err := adapter.Open(newerSink.ID())
	if err != nil {
		t.Fatalf("Open(exact replay): %v", err)
	}
	if err := targetFSM.Restore(replayReader); err != nil {
		_ = replayReader.Close()
		t.Fatalf("Restore(exact replay): %v", err)
	}
	if err := replayReader.Close(); err != nil {
		t.Fatalf("Close(exact replay): %v", err)
	}
	rebound, found, err := target.VerifiedRaftSnapshotInstall(
		context.Background(),
	)
	if err != nil || !found ||
		rebound.SnapshotID != newerSink.ID() ||
		target.AdmissionRevision() != beforeRebindRevision {
		t.Fatalf(
			"exact replay rebind = (%#v, %t, %v), revision %d -> %d",
			rebound,
			found,
			err,
			beforeRebindRevision,
			target.AdmissionRevision(),
		)
	}
	mismatchedStore := raftSnapshotMetadataMutatingStore{
		SnapshotStore: adapter,
		replacementID: "receiver-local-id-mismatch",
	}
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		mismatchedStore,
		target,
		restored,
		fixture.signerID,
		targetSnapshotDir,
		nil,
	); !errors.Is(err, ErrSnapshotAnchorCoverage) {
		t.Fatalf("receiver-local snapshot ID mismatch error = %v", err)
	}
}

func TestFSMSnapshotIneligibleSignerDoesNotHalt(t *testing.T) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	t.Cleanup(func() { clear(fixture.signerPrivate) })
	if fixture.source == nil ||
		fixture.sourceView.LastRaftAppliedLogIndex == nil ||
		fixture.sourceView.CurrentTerm == nil {
		t.Fatal("fixture lacks source Raft state")
	}
	lookup, found, err := fixture.source.LookupCommandResult(
		context.Background(),
		fixture.snapshot.Cut.CheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf("LookupCommandResult(checkpoint) = (%#v, %t, %v)", lookup, found, err)
	}
	logs := raft.NewInmemStore()
	if err := logs.StoreLog(&raft.Log{
		Index: *fixture.sourceView.LastRaftAppliedLogIndex,
		Term:  *fixture.sourceView.CurrentTerm,
		Type:  raft.LogCommand,
		Data:  bytes.Clone(lookup.CanonicalProposal),
	}); err != nil {
		t.Fatalf("StoreLog(): %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x9a}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	snapshotDir := filepath.Join(t.TempDir(), "snapshots")
	if _, err := prepareConsensusDirectory(snapshotDir); err != nil {
		t.Fatalf("prepare snapshot directory: %v", err)
	}
	fsm, err := NewFSM(FSMOptions{
		Store:                 fixture.source,
		OriginBootID:          nodeTestBootID1,
		Clock:                 nodeTestClock(),
		LogStore:              logs,
		SnapshotDir:           snapshotDir,
		SnapshotSigner:        raftSnapshotTestSigner(deviceID, publicKey, privateKey),
		ValidateConfiguration: validateDeviceAddressedSnapshotConfiguration,
	})
	if err != nil {
		t.Fatalf("NewFSM(): %v", err)
	}
	if _, err := fsm.Snapshot(); !errors.Is(err, raft.ErrNothingNewToSnapshot) {
		t.Fatalf("Snapshot(ineligible signer) error = %v", err)
	}
	if err := fsm.HaltError(); err != nil {
		t.Fatalf("ineligible signer halted FSM: %v", err)
	}
	clear(privateKey)
}

func assertFinalizedUnboundRaftSnapshotQuarantined(
	t *testing.T,
	snapshot raft.FSMSnapshot,
	initial store.InitialState,
	configuration raft.Configuration,
	baselineIndex uint64,
	baselineTerm uint64,
	localDeviceID domain.DeviceID,
) {
	t.Helper()

	root := filepath.Join(t.TempDir(), "consensus")
	if _, err := prepareConsensusDirectory(root); err != nil {
		t.Fatalf("prepare consensus directory: %v", err)
	}
	delegate, err := raft.NewFileSnapshotStore(root, 2, io.Discard)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore(): %v", err)
	}
	reject, err := newRaftSnapshotFileRejecter(root)
	if err != nil {
		t.Fatalf("newRaftSnapshotFileRejecter(): %v", err)
	}
	adapter, err := newRaftSnapshotStoreWithReject(delegate, reject)
	if err != nil {
		t.Fatalf("newRaftSnapshotStoreWithReject(): %v", err)
	}
	_, transport := raft.NewInmemTransport(
		raft.ServerAddress(configuration.Servers[0].ID),
	)
	defer transport.Close()
	sink, err := adapter.Create(
		raft.SnapshotVersionMax,
		baselineIndex+1,
		baselineTerm,
		configuration,
		1,
		transport,
	)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}
	if err := snapshot.Persist(sink); err != nil {
		t.Fatalf("Persist(): %v", err)
	}

	database, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	defer database.Close()
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if err := verifyLatestLogicalRaftSnapshot(
		context.Background(),
		adapter,
		database,
		view,
		localDeviceID,
		root,
		reject,
	); err != nil {
		t.Fatalf("verifyLatestLogicalRaftSnapshot(): %v", err)
	}
	metas, err := adapter.List()
	if err != nil || len(metas) != 0 {
		t.Fatalf("List(after startup quarantine) = (%#v, %v)", metas, err)
	}
	if _, err := os.Stat(filepath.Join(
		root,
		raftSnapshotQuarantineDirectory,
		sink.ID(),
	)); err != nil {
		t.Fatalf("quarantined snapshot Stat(): %v", err)
	}
}

func foreignRaftSnapshotLocalID(
	t *testing.T,
	sourceID domain.DeviceID,
) domain.DeviceID {
	t.Helper()
	localID := meshTestDeviceID('f')
	if localID == sourceID {
		t.Fatal("foreign local test identity matches snapshot source")
	}
	return localID
}

func raftSnapshotTestSigner(
	deviceID domain.DeviceID,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
) RaftSnapshotSignerAdapter {
	return RaftSnapshotSignerAdapter{
		SignerDeviceID:  deviceID,
		SignerPublicKey: bytes.Clone(publicKey),
		Sign: func(
			_ context.Context,
			unsigned logicalsnapshot.UnsignedRoot,
		) (logicalsnapshot.Root, error) {
			return logicalsnapshot.SignRoot(unsigned, privateKey)
		},
	}
}

type raftSnapshotMetadataMutatingStore struct {
	raft.SnapshotStore
	replacementID string
}

func (store raftSnapshotMetadataMutatingStore) List() (
	[]*raft.SnapshotMeta,
	error,
) {
	metas, err := store.SnapshotStore.List()
	if err != nil || len(metas) == 0 {
		return metas, err
	}
	mutated := make([]*raft.SnapshotMeta, len(metas))
	for index, meta := range metas {
		clone := *meta
		mutated[index] = &clone
	}
	mutated[0].ID = store.replacementID
	return mutated, nil
}

func TestInstalledRaftSnapshotBindingRejectsMetadataMismatch(t *testing.T) {
	t.Parallel()

	configuration, sourceID := raftSnapshotTestConfiguration()
	payload := []byte("semantic payload")
	envelope := raftSnapshotTestEnvelope(
		t,
		configuration,
		sourceID,
		payload,
	)
	meta := raft.SnapshotMeta{
		Version:            raft.SnapshotVersionMax,
		ID:                 "3-11-123456789",
		Index:              envelope.SnapshotIndex,
		Term:               envelope.SnapshotTerm,
		Configuration:      configuration,
		ConfigurationIndex: envelope.ConfigurationIndex,
		Size:               1,
	}
	record := store.RaftSnapshotInstallRecord{
		SourceServerID:          envelope.SourceServerID,
		SnapshotID:              meta.ID,
		SnapshotIndex:           meta.Index,
		SnapshotTerm:            meta.Term,
		ConfigurationIndex:      meta.ConfigurationIndex,
		ConfigurationDigest:     store.Digest(envelope.ConfigurationDigest),
		PayloadDigest:           store.Digest(envelope.PayloadDigest),
		BaselineCommandLogIndex: cloneUint64Pointer(envelope.BaselineCommandLogIndex),
		BaselineCommandTerm:     cloneUint64Pointer(envelope.BaselineCommandTerm),
	}
	metadata := raftSnapshotRestoreMetadata{
		Meta:     meta,
		Envelope: envelope,
	}
	if err := validateInstalledRaftSnapshotBinding(
		record,
		metadata,
	); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*store.RaftSnapshotInstallRecord)
	}{
		{
			name: "receiver-local ID",
			mutate: func(value *store.RaftSnapshotInstallRecord) {
				value.SnapshotID += "-other"
			},
		},
		{
			name: "snapshot position",
			mutate: func(value *store.RaftSnapshotInstallRecord) {
				value.SnapshotIndex++
			},
		},
		{
			name: "configuration digest",
			mutate: func(value *store.RaftSnapshotInstallRecord) {
				value.ConfigurationDigest[0] ^= 1
			},
		},
		{
			name: "payload digest",
			mutate: func(value *store.RaftSnapshotInstallRecord) {
				value.PayloadDigest[0] ^= 1
			},
		},
		{
			name: "command watermark",
			mutate: func(value *store.RaftSnapshotInstallRecord) {
				index := *value.BaselineCommandLogIndex - 1
				value.BaselineCommandLogIndex = &index
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := record
			changed.BaselineCommandLogIndex = cloneUint64Pointer(
				record.BaselineCommandLogIndex,
			)
			changed.BaselineCommandTerm = cloneUint64Pointer(
				record.BaselineCommandTerm,
			)
			test.mutate(&changed)
			if err := validateInstalledRaftSnapshotBinding(
				changed,
				metadata,
			); !errors.Is(err, ErrRaftSnapshotMetadataMismatch) {
				t.Fatalf("mismatch error = %v", err)
			}
		})
	}
}

func TestRaftSnapshotSignerAdapterRejectsForeignIdentity(t *testing.T) {
	t.Parallel()

	_, privateKey, deviceID := nodeTestInitialState(t)
	foreign := domain.DeviceID(
		"cc1" + string(bytes.Repeat([]byte{'f'}, 64)),
	)
	signer := RaftSnapshotSignerAdapter{
		SignerDeviceID:  foreign,
		SignerPublicKey: privateKey.Public().(ed25519.PublicKey),
	}
	if err := validateRaftSnapshotSigner(deviceID, signer); err == nil {
		t.Fatal("foreign snapshot signer was accepted")
	}
}
