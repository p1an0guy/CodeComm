package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

const raftSnapshotRootLengthBytes = 4

type raftSnapshotSinkMetadata interface {
	raft.SnapshotSink
	SnapshotMetadata() *raft.SnapshotMeta
}

type logicalFSMSnapshot struct {
	sourceID      domain.DeviceID
	baselineIndex uint64
	baselineTerm  uint64
	tail          []snapshotRaftEntry
	root          logicalsnapshot.Root
	artifact      *os.File
	artifactPath  string
	payloadDigest [sha256.Size]byte
	payloadBytes  uint64

	releaseOnce sync.Once
	releaseErr  error
}

func (fsm *FSM) captureLogicalRaftSnapshot(
	view store.StateView,
	tail []snapshotRaftEntry,
) (*logicalFSMSnapshot, error) {
	if fsm == nil ||
		fsm.snapshotSigner == nil ||
		fsm.logStore == nil ||
		fsm.snapshotDir == "" ||
		view.CurrentTerm == nil ||
		view.LastRaftAppliedLogIndex == nil {
		return nil, raft.ErrNothingNewToSnapshot
	}
	baselineIndex := *view.LastRaftAppliedLogIndex
	var latest raft.Log
	if err := fsm.logStore.GetLog(baselineIndex, &latest); err != nil {
		if errors.Is(err, raft.ErrLogNotFound) {
			// Startup proves that any missing prefix is covered by a verified
			// local or installed snapshot. A repeated snapshot request before
			// a newer checkpoint is therefore ineligible, not fatal.
			return nil, raft.ErrNothingNewToSnapshot
		}
		return nil, fmt.Errorf(
			"consensus: read checkpoint command for snapshot: %w",
			err,
		)
	}
	if latest.Type != raft.LogCommand ||
		latest.Term != *view.CurrentTerm {
		return nil, raft.ErrNothingNewToSnapshot
	}
	proposal, err := event.InspectUnverifiedProposal(latest.Data)
	if err != nil || proposal.Kind != event.KindConsensusCheckpoint {
		return nil, raft.ErrNothingNewToSnapshot
	}

	artifact, err := os.CreateTemp(
		fsm.snapshotDir,
		".raft-snapshot-artifact-*",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"consensus: create Raft snapshot artifact: %w",
			err,
		)
	}
	artifactPath := artifact.Name()
	succeeded := false
	defer func() {
		if !succeeded {
			_ = artifact.Close()
			_ = os.Remove(artifactPath)
		}
	}()
	sequence, err := os.CreateTemp(
		fsm.snapshotDir,
		".raft-snapshot-sequence-*",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"consensus: create Raft snapshot sequence scratch: %w",
			err,
		)
	}
	sequencePath := sequence.Name()
	defer func() {
		_ = sequence.Close()
		_ = os.Remove(sequencePath)
	}()

	signer := fsm.snapshotSigner
	built, err := snapshotbuilder.Build(
		context.Background(),
		fsm.store,
		snapshotbuilder.Options{
			ArtifactID:        "raft-" + string(proposal.EventID),
			CheckpointEventID: proposal.EventID,
			SignerDeviceID:    signer.DeviceID(),
			SignerPublicKey:   signer.PublicKey(),
			ArtifactScratch:   artifact,
			SequenceScratch:   sequence,
			ChunkSink:         consumeRaftSnapshotBuildPart,
			PageSink:          consumeRaftSnapshotBuildPage,
			SignRoot:          signer.SignRoot,
		},
	)
	if err != nil {
		if errors.Is(err, store.ErrLogicalSnapshotNotCovered) ||
			errors.Is(err, store.ErrLogicalSnapshotSignerUnauthorized) {
			return nil, raft.ErrNothingNewToSnapshot
		}
		return nil, fmt.Errorf(
			"consensus: build Raft logical snapshot: %w",
			err,
		)
	}
	if built.Cut.SessionID != view.SessionID ||
		built.Cut.WorkspaceID != view.WorkspaceID ||
		built.Cut.RecoveryGeneration != view.RecoveryGeneration ||
		built.Cut.ChainIndex != view.Heads.ChainIndex ||
		built.Cut.ChainHash != view.Heads.ChainHash ||
		built.Cut.ResultIndex != view.Heads.ResultIndex ||
		built.Cut.ResultHash != view.Heads.ResultHash ||
		built.Cut.ProjectionAccumulator !=
			view.Heads.ProjectionAccumulator ||
		built.Cut.ProjectionStateDigest !=
			view.ProjectionStateDigest {
		return nil, ErrSnapshotStateMismatch
	}
	payloadDigest, payloadBytes, err := digestRaftSnapshotPayload(
		built.Root,
		artifact,
	)
	if err != nil {
		return nil, err
	}
	succeeded = true
	return &logicalFSMSnapshot{
		sourceID:      signer.DeviceID(),
		baselineIndex: baselineIndex,
		baselineTerm:  latest.Term,
		tail:          append([]snapshotRaftEntry(nil), tail...),
		root:          built.Root,
		artifact:      artifact,
		artifactPath:  artifactPath,
		payloadDigest: payloadDigest,
		payloadBytes:  payloadBytes,
	}, nil
}

func consumeRaftSnapshotBuildPart(
	_ context.Context,
	_ logicalsnapshot.ChunkDescriptor,
	content io.Reader,
) error {
	_, err := io.Copy(io.Discard, content)
	return err
}

func consumeRaftSnapshotBuildPage(
	_ context.Context,
	_ logicalsnapshot.DescriptorPage,
	content io.Reader,
) error {
	_, err := io.Copy(io.Discard, content)
	return err
}

func digestRaftSnapshotPayload(
	root logicalsnapshot.Root,
	artifact *os.File,
) ([sha256.Size]byte, uint64, error) {
	if artifact == nil {
		return [sha256.Size]byte{}, 0, ErrInvalidRaftSnapshotEnvelope
	}
	rootBytes := root.CanonicalBytes()
	input := root.Unsigned().Input()
	if len(rootBytes) == 0 ||
		len(rootBytes) > logicalsnapshot.MaxRootBytes ||
		input.ExpandedBytes < 1 {
		return [sha256.Size]byte{}, 0, ErrInvalidRaftSnapshotEnvelope
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	hasher := sha256.New()
	var rootLength [raftSnapshotRootLengthBytes]byte
	binary.BigEndian.PutUint32(rootLength[:], uint32(len(rootBytes)))
	if err := writeRaftSnapshotFrameBytes(hasher, rootLength[:]); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	if err := writeRaftSnapshotFrameBytes(hasher, rootBytes); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	written, err := io.Copy(hasher, artifact)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	if written != int64(input.ExpandedBytes) {
		return [sha256.Size]byte{}, 0, ErrRaftSnapshotPayloadIntegrity
	}
	payloadBytes := uint64(raftSnapshotRootLengthBytes+len(rootBytes)) +
		input.ExpandedBytes
	if payloadBytes > maxRaftSnapshotPayloadBytes {
		return [sha256.Size]byte{}, 0, ErrRaftSnapshotPayloadIntegrity
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, payloadBytes, nil
}

func (snapshot *logicalFSMSnapshot) Persist(sink raft.SnapshotSink) error {
	metadataSink, ok := sink.(raftSnapshotSinkMetadata)
	if snapshot == nil || !ok || snapshot.artifact == nil {
		if sink != nil {
			_ = sink.Cancel()
		}
		return ErrInvalidRaftSnapshotStore
	}
	meta := metadataSink.SnapshotMetadata()
	anchor := snapshotAnchor{
		CurrentTerm:             snapshot.baselineTerm,
		LastRaftAppliedLogIndex: snapshot.baselineIndex,
		RaftTail:                snapshot.tail,
	}
	if err := validateSnapshotMetaAnchor(meta, anchor); err != nil {
		_ = sink.Cancel()
		return err
	}
	configurationDigest, err := raftSnapshotConfigurationDigest(
		meta.Configuration,
	)
	if err != nil {
		_ = sink.Cancel()
		return err
	}
	if _, err := snapshot.artifact.Seek(0, io.SeekStart); err != nil {
		_ = sink.Cancel()
		return err
	}
	rootBytes := snapshot.root.CanonicalBytes()
	var rootLength [raftSnapshotRootLengthBytes]byte
	binary.BigEndian.PutUint32(rootLength[:], uint32(len(rootBytes)))
	baselineIndex := snapshot.baselineIndex
	baselineTerm := snapshot.baselineTerm
	envelope := raftSnapshotEnvelope{
		SchemaVersion:           raftSnapshotEnvelopeSchemaVersion,
		SourceServerID:          snapshot.sourceID,
		SnapshotIndex:           meta.Index,
		SnapshotTerm:            meta.Term,
		ConfigurationIndex:      meta.ConfigurationIndex,
		ConfigurationDigest:     configurationDigest,
		BaselineCommandLogIndex: &baselineIndex,
		BaselineCommandTerm:     &baselineTerm,
		PayloadDigest:           snapshot.payloadDigest,
		PayloadBytes:            snapshot.payloadBytes,
	}
	payload := io.MultiReader(
		bytes.NewReader(rootLength[:]),
		bytes.NewReader(rootBytes),
		snapshot.artifact,
	)
	if err := writeRaftSnapshotFrame(sink, envelope, payload); err != nil {
		_ = sink.Cancel()
		return err
	}
	if err := sink.Close(); err != nil {
		_ = sink.Cancel()
		return err
	}
	return nil
}

func (snapshot *logicalFSMSnapshot) Release() {
	if snapshot == nil {
		return
	}
	snapshot.releaseOnce.Do(func() {
		if snapshot.artifact != nil {
			snapshot.releaseErr = snapshot.artifact.Close()
		}
		if snapshot.artifactPath != "" {
			snapshot.releaseErr = errors.Join(
				snapshot.releaseErr,
				os.Remove(snapshot.artifactPath),
			)
			if errors.Is(snapshot.releaseErr, os.ErrNotExist) {
				snapshot.releaseErr = nil
			}
		}
		snapshot.artifact = nil
		snapshot.artifactPath = ""
	})
}

func (fsm *FSM) restoreLogicalRaftSnapshot(
	reader io.ReadCloser,
	metadata raftSnapshotRestoreMetadata,
) error {
	envelope, _, err := readRaftSnapshotFrameHeader(reader)
	if err != nil {
		return err
	}
	if !sameRaftSnapshotEnvelopeValue(envelope, metadata.Envelope) {
		return ErrRaftSnapshotMetadataMismatch
	}
	payload := &io.LimitedReader{
		R: reader,
		N: int64(envelope.PayloadBytes),
	}
	hasher := sha256.New()
	payloadReader := io.TeeReader(payload, hasher)
	var rootLengthBytes [raftSnapshotRootLengthBytes]byte
	if _, err := io.ReadFull(payloadReader, rootLengthBytes[:]); err != nil {
		return ErrRaftSnapshotPayloadIntegrity
	}
	rootLength := binary.BigEndian.Uint32(rootLengthBytes[:])
	if rootLength < 1 || rootLength > logicalsnapshot.MaxRootBytes {
		return ErrRaftSnapshotPayloadIntegrity
	}
	rootBytes := make([]byte, int(rootLength))
	if _, err := io.ReadFull(payloadReader, rootBytes); err != nil {
		return ErrRaftSnapshotPayloadIntegrity
	}
	root, err := logicalsnapshot.ParseRoot(rootBytes)
	if err != nil {
		return err
	}
	input := root.Unsigned().Input()
	if input.SignerDeviceID != envelope.SourceServerID ||
		envelope.PayloadBytes !=
			uint64(raftSnapshotRootLengthBytes)+uint64(rootLength)+
				input.ExpandedBytes {
		return ErrRaftSnapshotPayloadIntegrity
	}

	artifact, artifactPath, err := createRaftSnapshotScratch(
		fsm.snapshotDir,
		".raft-restore-artifact-*",
	)
	if err != nil {
		return err
	}
	defer closeAndRemoveRaftSnapshotScratch(artifact, artifactPath)
	written, err := io.CopyN(artifact, payloadReader, int64(input.ExpandedBytes))
	if err != nil || written != int64(input.ExpandedBytes) || payload.N != 0 {
		return ErrRaftSnapshotPayloadIntegrity
	}
	var trailing [1]byte
	trailingBytes, trailingErr := reader.Read(trailing[:])
	if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) ||
		!bytes.Equal(hasher.Sum(nil), envelope.PayloadDigest[:]) {
		return ErrRaftSnapshotPayloadIntegrity
	}
	rebound, matched, err := fsm.store.RebindVerifiedRaftSnapshotInstall(
		context.Background(),
		store.RaftSnapshotInstallRebindOptions{
			SourceServerID:          envelope.SourceServerID,
			SnapshotID:              metadata.Meta.ID,
			SnapshotIndex:           metadata.Meta.Index,
			SnapshotTerm:            metadata.Meta.Term,
			ConfigurationIndex:      metadata.Meta.ConfigurationIndex,
			ConfigurationDigest:     store.Digest(envelope.ConfigurationDigest),
			PayloadDigest:           store.Digest(envelope.PayloadDigest),
			BaselineCommandLogIndex: cloneUint64Pointer(envelope.BaselineCommandLogIndex),
			BaselineCommandTerm:     cloneUint64Pointer(envelope.BaselineCommandTerm),
		},
	)
	if err != nil {
		return err
	}
	if matched {
		return fsm.publishRestoredRaftSnapshot(
			metadata,
			rebound.BaselineCommandLogIndex,
			fsm.store.AdmissionRevision(),
		)
	}

	sequence, sequencePath, err := createRaftSnapshotScratch(
		fsm.snapshotDir,
		".raft-restore-sequence-*",
	)
	if err != nil {
		return err
	}
	defer closeAndRemoveRaftSnapshotScratch(sequence, sequencePath)
	proof, err := logicalsnapshot.VerifyExpandedArtifact(
		context.Background(),
		root,
		artifact,
		sequence,
	)
	if err != nil {
		return err
	}
	boundaryScratch, boundaryPath, err := createRaftSnapshotScratch(
		fsm.snapshotDir,
		".raft-restore-boundary-*",
	)
	if err != nil {
		return err
	}
	defer closeAndRemoveRaftSnapshotScratch(
		boundaryScratch,
		boundaryPath,
	)
	stagePath := filepath.Join(
		fsm.snapshotDir,
		".raft-restore-stage-"+metadata.Meta.ID+".db",
	)
	_ = removeLogicalSnapshotStageFiles(stagePath)
	boundaries, err := NewGenerationZeroBoundaryVerifier(fsm.store)
	if err != nil {
		return err
	}
	verified, err := verifyAndStageExpandedRaftSnapshot(
		context.Background(),
		root,
		proof,
		artifact,
		boundaryScratch,
		stagePath,
		fsm.originBootID,
		fsm.clock,
		boundaries,
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = verified.Close()
		_ = removeLogicalSnapshotStageFiles(stagePath)
	}()
	configurationJSON, err := encodeRaftConfiguration(
		metadata.Meta.Configuration,
	)
	if err != nil {
		return err
	}
	verifiedAt, monotonicNow, err := fsm.clock()
	if err != nil {
		return err
	}
	result, err := fsm.store.InstallRaftLogicalSnapshot(
		context.Background(),
		verified.stage,
		store.RaftLogicalSnapshotInstallOptions{
			VerifiedAt:              verifiedAt,
			OriginBootID:            fsm.originBootID,
			InstalledAt:             verifiedAt,
			MonotonicNowNS:          monotonicNow,
			SourceServerID:          envelope.SourceServerID,
			SnapshotID:              metadata.Meta.ID,
			SnapshotIndex:           metadata.Meta.Index,
			SnapshotTerm:            metadata.Meta.Term,
			ConfigurationIndex:      metadata.Meta.ConfigurationIndex,
			ConfigurationJSON:       configurationJSON,
			ConfigurationDigest:     store.Digest(envelope.ConfigurationDigest),
			PayloadDigest:           store.Digest(envelope.PayloadDigest),
			BaselineCommandLogIndex: cloneUint64Pointer(envelope.BaselineCommandLogIndex),
			BaselineCommandTerm:     cloneUint64Pointer(envelope.BaselineCommandTerm),
		},
	)
	if err != nil {
		return err
	}
	return fsm.publishRestoredRaftSnapshot(
		metadata,
		envelope.BaselineCommandLogIndex,
		result.AdmissionRevision,
	)
}

func (fsm *FSM) publishRestoredRaftSnapshot(
	metadata raftSnapshotRestoreMetadata,
	baselineCommandLogIndex *uint64,
	admissionRevision uint64,
) error {
	if fsm == nil || fsm.store == nil || admissionRevision == 0 {
		return ErrInvalidFSMOptions
	}
	fsm.applyMu.Lock()
	defer fsm.applyMu.Unlock()
	view, err := fsm.store.View(context.Background())
	if err != nil {
		return err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return err
	}
	if view.AdmissionRevision != admissionRevision {
		return ErrRaftSnapshotMetadataMismatch
	}
	fsm.applyState = newFSMApplyState(view, decoded)
	fsm.admissionMu.Lock()
	fsm.publishPeerAdmissionLocked(
		decoded.Admission,
		admissionRevision,
		true,
	)
	fsm.admissionMu.Unlock()
	if baselineCommandLogIndex == nil {
		fsm.appliedCommandIndex.Store(0)
	} else {
		fsm.appliedCommandIndex.Store(*baselineCommandLogIndex)
	}
	fsm.committedConfig.Store(&committedRaftConfiguration{
		Index:         metadata.Meta.ConfigurationIndex,
		Configuration: metadata.Meta.Configuration.Clone(),
	})
	return nil
}

func verifyAndStageExpandedRaftSnapshot(
	ctx context.Context,
	root logicalsnapshot.Root,
	proof logicalsnapshot.VerifiedExpandedArtifact,
	artifact LogicalSnapshotImportScratch,
	boundaryScratch LogicalSnapshotReadWriteScratch,
	stagePath string,
	originBootID domain.UUIDv7,
	clock ApplyClock,
	boundaries LogicalSnapshotBoundaryVerifier,
) (_ *VerifiedLogicalSnapshotStage, err error) {
	stage, err := store.OpenLogicalSnapshotStage(ctx, stagePath)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			err = errors.Join(
				err,
				stage.Close(),
				removeLogicalSnapshotStageFiles(stage.Path()),
			)
		}
	}()
	replay := logicalSnapshotSemanticReplay{
		ctx:              ctx,
		root:             root,
		rootInput:        root.Unsigned().Input(),
		stage:            stage,
		boundaries:       boundaries,
		boundaryScratch:  boundaryScratch,
		originBootID:     originBootID,
		clock:            clock,
		section:          snapshotSectionGenesis,
		expectedBoundary: 0,
	}
	if err := replay.consumeExpandedArtifact(artifact); err != nil {
		return nil, err
	}
	if err := replay.finish(); err != nil {
		return nil, snapshotSemanticError("finish semantic replay", err)
	}
	if err := stage.VerifyArtifact(ctx, root, proof); err != nil {
		return nil, snapshotSemanticError(
			"freeze staged SQLite state",
			err,
		)
	}
	succeeded = true
	return &VerifiedLogicalSnapshotStage{
		stage:        stage,
		root:         root,
		cut:          logicalSnapshotCutFromRoot(root.Unsigned().Input()),
		originBootID: originBootID,
		clock:        clock,
	}, nil
}

func verifyLocalLogicalRaftSnapshot(
	ctx context.Context,
	snapshots raft.SnapshotStore,
	metadata raftSnapshotRestoreMetadata,
	state *store.Store,
	view store.StateView,
	localServerID domain.DeviceID,
	snapshotDir string,
) error {
	if ctx == nil ||
		snapshots == nil ||
		state == nil ||
		!localServerID.Valid() ||
		metadata.Envelope.SourceServerID != localServerID {
		return ErrRaftSnapshotMetadataMismatch
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return err
	}
	publicKey, found := decoded.IdentityPublicKey(localServerID)
	if !found {
		return ErrRaftSnapshotMetadataMismatch
	}
	meta, reader, err := snapshots.Open(metadata.Meta.ID)
	if err != nil {
		return err
	}
	defer reader.Close()
	carried, err := raftSnapshotMetadataFromReader(reader)
	if err != nil ||
		meta == nil ||
		meta.ID != metadata.Meta.ID ||
		!sameRaftSnapshotEnvelopeValue(
			carried.Envelope,
			metadata.Envelope,
		) {
		return ErrRaftSnapshotMetadataMismatch
	}
	envelope, _, err := readRaftSnapshotFrameHeader(reader)
	if err != nil {
		return err
	}
	if !sameRaftSnapshotEnvelopeValue(envelope, metadata.Envelope) {
		return ErrRaftSnapshotMetadataMismatch
	}
	payload := &io.LimitedReader{
		R: reader,
		N: int64(envelope.PayloadBytes),
	}
	var rootLengthBytes [raftSnapshotRootLengthBytes]byte
	if _, err := io.ReadFull(payload, rootLengthBytes[:]); err != nil {
		return ErrRaftSnapshotPayloadIntegrity
	}
	rootLength := binary.BigEndian.Uint32(rootLengthBytes[:])
	if rootLength < 1 || rootLength > logicalsnapshot.MaxRootBytes {
		return ErrRaftSnapshotPayloadIntegrity
	}
	rootBytes := make([]byte, int(rootLength))
	if _, err := io.ReadFull(payload, rootBytes); err != nil {
		return ErrRaftSnapshotPayloadIntegrity
	}
	root, err := logicalsnapshot.ParseRoot(rootBytes)
	if err != nil {
		return err
	}
	input := root.Unsigned().Input()
	if input.SignerDeviceID != localServerID ||
		input.WorkspaceID != view.WorkspaceID ||
		envelope.PayloadBytes !=
			uint64(raftSnapshotRootLengthBytes)+uint64(rootLength)+
				input.ExpandedBytes {
		return ErrRaftSnapshotPayloadIntegrity
	}
	if err := logicalsnapshot.VerifyRoot(root, publicKey); err != nil {
		return err
	}
	artifact, artifactPath, err := createRaftSnapshotScratch(
		snapshotDir,
		".raft-startup-artifact-*",
	)
	if err != nil {
		return err
	}
	defer closeAndRemoveRaftSnapshotScratch(artifact, artifactPath)
	written, err := io.CopyN(artifact, payload, int64(input.ExpandedBytes))
	if err != nil || written != int64(input.ExpandedBytes) || payload.N != 0 {
		return ErrRaftSnapshotPayloadIntegrity
	}
	var trailing [1]byte
	trailingBytes, trailingErr := reader.Read(trailing[:])
	if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) {
		return ErrRaftSnapshotPayloadIntegrity
	}
	sequence, sequencePath, err := createRaftSnapshotScratch(
		snapshotDir,
		".raft-startup-sequence-*",
	)
	if err != nil {
		return err
	}
	defer closeAndRemoveRaftSnapshotScratch(sequence, sequencePath)
	if _, err := logicalsnapshot.VerifyExpandedArtifact(
		ctx,
		root,
		artifact,
		sequence,
	); err != nil {
		return err
	}
	if err := verifyLocalRaftSnapshotCommandBaseline(
		view,
		envelope,
	); err != nil {
		return err
	}
	return state.VerifyCommitmentCut(ctx, store.CommitmentCut{
		SessionID:               input.SessionID,
		RecoveryGeneration:      input.RecoveryGeneration,
		ChainIndex:              input.ChainIndex,
		ChainHash:               store.Digest(input.ChainHash),
		ResultIndex:             input.ResultIndex,
		ResultHash:              store.Digest(input.ResultHash),
		ProjectionAccumulator:   store.Digest(input.ProjectionAccumulator),
		ProjectionStateDigest:   store.Digest(input.ProjectionStateDigest),
		DigestVersion:           input.DigestVersion,
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
	})
}

func verifyLocalRaftSnapshotCommandBaseline(
	view store.StateView,
	envelope raftSnapshotEnvelope,
) error {
	if envelope.BaselineCommandLogIndex == nil ||
		envelope.BaselineCommandTerm == nil ||
		view.LastRaftAppliedLogIndex == nil ||
		view.CurrentTerm == nil ||
		*view.LastRaftAppliedLogIndex <
			*envelope.BaselineCommandLogIndex ||
		*view.LastRaftAppliedLogIndex ==
			*envelope.BaselineCommandLogIndex &&
			*view.CurrentTerm != *envelope.BaselineCommandTerm {
		return ErrRaftSnapshotMetadataMismatch
	}
	return nil
}

func createRaftSnapshotScratch(
	directory string,
	pattern string,
) (*os.File, string, error) {
	if directory == "" {
		return nil, "", ErrInvalidFSMOptions
	}
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return nil, "", err
	}
	return file, file.Name(), nil
}

func closeAndRemoveRaftSnapshotScratch(file *os.File, path string) {
	if file != nil {
		_ = file.Close()
	}
	if path != "" {
		_ = os.Remove(path)
	}
}

func sameRaftSnapshotEnvelopeValue(
	left raftSnapshotEnvelope,
	right raftSnapshotEnvelope,
) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.SourceServerID == right.SourceServerID &&
		left.SnapshotIndex == right.SnapshotIndex &&
		left.SnapshotTerm == right.SnapshotTerm &&
		left.ConfigurationIndex == right.ConfigurationIndex &&
		left.ConfigurationDigest == right.ConfigurationDigest &&
		left.PayloadDigest == right.PayloadDigest &&
		left.PayloadBytes == right.PayloadBytes &&
		sameRaftSnapshotOptionalUint64(
			left.BaselineCommandLogIndex,
			right.BaselineCommandLogIndex,
		) &&
		sameRaftSnapshotOptionalUint64(
			left.BaselineCommandTerm,
			right.BaselineCommandTerm,
		)
}

func sameRaftSnapshotOptionalUint64(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

var _ raft.FSMSnapshot = (*logicalFSMSnapshot)(nil)
