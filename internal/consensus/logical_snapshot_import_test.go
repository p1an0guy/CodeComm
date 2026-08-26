package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	logicalSnapshotSuccessorSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000081",
	)
	logicalSnapshotSuccessorCheckpointID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000082",
	)
	logicalSnapshotSuccessorBootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000083",
	)
)

func TestVerifyAndStageLogicalSnapshotReplaysRealReducerHistory(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	boundaries := &logicalSnapshotTestBoundaries{
		initial: fixture.initial,
	}
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, boundaries),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	if boundaries.initialCalls != 1 ||
		boundaries.successorCalls != 0 {
		t.Fatalf(
			"boundary calls = (%d, %d), want (1, 0)",
			boundaries.initialCalls,
			boundaries.successorCalls,
		)
	}
	if !bytes.Equal(
		verified.Root().CanonicalBytes(),
		fixture.snapshot.Root.CanonicalBytes(),
	) ||
		verified.Cut() != fixture.snapshot.Cut {
		t.Fatal("verified stage did not retain the exact root and cut")
	}
	view, err := verified.View(testContext(t))
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.SessionID != fixture.sourceView.SessionID ||
		view.WorkspaceID != fixture.sourceView.WorkspaceID ||
		view.RecoveryGeneration != fixture.sourceView.RecoveryGeneration ||
		view.Heads != fixture.sourceView.Heads ||
		view.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"staged/source mismatch:\nstaged=%+v\nsource=%+v",
			view,
			fixture.sourceView,
		)
	}
	if view.Heads.ResultIndex != 3 || view.Heads.ChainIndex != 2 {
		t.Fatalf(
			"staged heads = %+v, want accepted/rejected/checkpoint history",
			view.Heads,
		)
	}
}

func TestVerifyAndStageLogicalSnapshotRejectsStructuralInputBeforeBoundary(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	fixture.chunks[0][0] ^= 0xff
	boundaries := &logicalSnapshotTestBoundaries{
		initial: fixture.initial,
	}
	options := fixture.importOptions(t, boundaries)
	_, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		options,
	)
	if !errors.Is(err, logicalsnapshot.ErrExpandedArtifactIntegrity) {
		t.Fatalf(
			"VerifyAndStageLogicalSnapshot(corrupt) error = %v, want artifact integrity",
			err,
		)
	}
	if boundaries.initialCalls != 0 || boundaries.successorCalls != 0 {
		t.Fatalf(
			"corrupt structural input reached boundary verifier: (%d, %d)",
			boundaries.initialCalls,
			boundaries.successorCalls,
		)
	}
	if _, statErr := os.Stat(options.StagePath); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"corrupt structural input created stage: %v",
			statErr,
		)
	}
}

func TestVerifyAndStageLogicalSnapshotAppliesSuccessorAtExactCut(
	t *testing.T,
) {
	t.Parallel()

	fixture, successor, predecessor := newLogicalSnapshotSuccessorFixture(t)
	boundaries := &logicalSnapshotTestBoundaries{
		initial:    fixture.initial,
		successors: []store.SuccessorState{successor},
	}
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, boundaries),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	if boundaries.initialCalls != 1 ||
		boundaries.successorCalls != 1 ||
		len(boundaries.predecessors) != 1 {
		t.Fatalf(
			"boundary calls/views = (%d, %d, %d), want (1, 1, 1)",
			boundaries.initialCalls,
			boundaries.successorCalls,
			len(boundaries.predecessors),
		)
	}
	gotPredecessor := boundaries.predecessors[0]
	if gotPredecessor.Heads != predecessor.Heads ||
		gotPredecessor.ProjectionStateDigest !=
			predecessor.ProjectionStateDigest ||
		gotPredecessor.SessionID != predecessor.SessionID {
		t.Fatalf(
			"successor predecessor view = %+v, want %+v",
			gotPredecessor,
			predecessor,
		)
	}
	view, err := verified.View(testContext(t))
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.SessionID != logicalSnapshotSuccessorSessionID ||
		view.RecoveryGeneration != 1 ||
		view.Heads != fixture.sourceView.Heads ||
		view.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"successor staged/source mismatch:\nstaged=%+v\nsource=%+v",
			view,
			fixture.sourceView,
		)
	}
	if view.Heads.ResultIndex != 2 || view.Heads.ChainIndex != 2 {
		t.Fatalf("successor heads = %+v", view.Heads)
	}
}

func TestVerifyAndStageLogicalSnapshotVerifiesSignedSuccessorEndToEnd(
	t *testing.T,
) {
	t.Parallel()

	recovery := newLogicalSnapshotRecoveryFixture(t, device.RoleOwner)
	creator, err := NewGenerationZeroBoundaryVerifier(recovery.source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(creator): %v", err)
	}
	successor, err := creator.VerifySuccessorBoundary(
		testContext(t),
		recovery.predecessor,
		recovery.payload,
	)
	if err != nil {
		t.Fatalf("VerifySuccessorBoundary(creator): %v", err)
	}
	if _, err := recovery.source.InstallSuccessor(
		testContext(t),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	successorView, err := recovery.source.View(testContext(t))
	if err != nil {
		t.Fatalf("View(successor): %v", err)
	}
	checkpointEvent := logicalSnapshotTestCheckpointEvent(
		t,
		recovery.recoveringPrivate,
		recovery.recoveringID,
		successorView,
	)
	checkpointResult := applyLogicalSnapshotTestCommand(
		t,
		recovery.source,
		checkpointEvent,
		1,
		2,
		true,
	)
	if checkpointResult.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("checkpoint outcome = %+v", checkpointResult.Outcome)
	}
	sourceView, err := recovery.source.View(testContext(t))
	if err != nil {
		t.Fatalf("View(source): %v", err)
	}
	fixture := buildLogicalSnapshotImportFixture(
		t,
		recovery.source,
		recovery.initial,
		sourceView,
		logicalSnapshotSuccessorCheckpointID,
		"signed-successor-import-test",
		recovery.recoveringID,
		recovery.recoveringPrivate,
	)
	verifier, err := NewGenerationZeroBoundaryVerifier(recovery.source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(import): %v", err)
	}
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, verifier),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	view, err := verified.View(testContext(t))
	if err != nil {
		t.Fatalf("View(staged): %v", err)
	}
	if view.SessionID != sourceView.SessionID ||
		view.WorkspaceID != sourceView.WorkspaceID ||
		view.RecoveryGeneration != 1 ||
		view.Heads != sourceView.Heads ||
		view.ProjectionStateDigest != sourceView.ProjectionStateDigest {
		t.Fatalf(
			"signed-successor staged/source mismatch:\nstaged=%+v\nsource=%+v",
			view,
			sourceView,
		)
	}
}

func TestVerifyAndStageLogicalSnapshotRejectsRootSignatureAndAliasedScratch(
	t *testing.T,
) {
	t.Parallel()

	t.Run("root signature", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotImportFixture(t)
		var invalidSignature [ed25519.SignatureSize]byte
		invalidSignature[0] = 1
		root, err := logicalsnapshot.NewRoot(
			fixture.snapshot.Root.Unsigned(),
			invalidSignature,
		)
		if err != nil {
			t.Fatalf("NewRoot(): %v", err)
		}
		boundaries := &logicalSnapshotTestBoundaries{
			initial: fixture.initial,
		}
		options := fixture.importOptions(t, boundaries)
		_, err = VerifyAndStageLogicalSnapshot(
			logicalSnapshotTestContext(t),
			root,
			options,
		)
		if !errors.Is(err, ErrLogicalSnapshotSemanticMismatch) {
			t.Fatalf(
				"VerifyAndStageLogicalSnapshot(bad signature) error = %v",
				err,
			)
		}
		if boundaries.initialCalls != 0 {
			t.Fatalf(
				"invalid signature reached initial boundary %d times",
				boundaries.initialCalls,
			)
		}
		if _, statErr := os.Stat(options.StagePath); !errors.Is(
			statErr,
			os.ErrNotExist,
		) {
			t.Fatalf("failed semantic stage remains on disk: %v", statErr)
		}
	})

	t.Run("aliased scratch", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotImportFixture(t)
		boundaries := &logicalSnapshotTestBoundaries{
			initial: fixture.initial,
		}
		options := fixture.importOptions(t, boundaries)
		options.SequenceScratch = fixture.artifact
		if _, err := VerifyAndStageLogicalSnapshot(
			logicalSnapshotTestContext(t),
			fixture.snapshot.Root,
			options,
		); !errors.Is(err, ErrInvalidLogicalSnapshotImport) {
			t.Fatalf(
				"VerifyAndStageLogicalSnapshot(alias) error = %v",
				err,
			)
		}
		if boundaries.initialCalls != 0 {
			t.Fatal("invalid scratch reached boundary verifier")
		}
	})
}

func TestVerifyAndStageLogicalSnapshotRejectsBoundarySubstitution(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	substituted := fixture.initial
	substituted.SessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000099",
	)
	boundaries := &logicalSnapshotTestBoundaries{initial: substituted}
	_, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, boundaries),
	)
	if !errors.Is(err, ErrLogicalSnapshotSemanticMismatch) {
		t.Fatalf(
			"VerifyAndStageLogicalSnapshot(substitution) error = %v",
			err,
		)
	}
	if boundaries.initialCalls != 1 {
		t.Fatalf(
			"initial boundary calls = %d, want 1",
			boundaries.initialCalls,
		)
	}
}

type logicalSnapshotImportFixture struct {
	snapshot      snapshotbuilder.Snapshot
	artifact      *os.File
	pages         [][]byte
	chunks        [][]byte
	initial       store.InitialState
	sourceView    store.StateView
	batch         replication.Batch
	signerID      domain.DeviceID
	signerKey     ed25519.PublicKey
	signerPrivate ed25519.PrivateKey
	source        *store.Store
}

func newLogicalSnapshotImportFixture(
	t *testing.T,
) logicalSnapshotImportFixture {
	t.Helper()
	return newLogicalSnapshotImportFixtureWithInitial(t, nil)
}

func newLogicalSnapshotImportFixtureWithInitial(
	t *testing.T,
	configureInitial func(*store.InitialState),
) logicalSnapshotImportFixture {
	t.Helper()

	node, origin, privateKey, deviceID :=
		openCheckpointCommitNodeWithInitial(
			t,
			nil,
			configureInitial,
		)
	initial, _, initialDeviceID := nodeTestInitialState(t)
	if initialDeviceID != deviceID {
		t.Fatal("deterministic initial device changed")
	}
	if configureInitial != nil {
		configureInitial(&initial)
	}
	first := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"snapshot task",
	)
	if result, err := node.Apply(testContext(t), first); err != nil ||
		result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(first) = (%+v, %v)", result, err)
	}
	second := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"duplicate snapshot task",
	)
	if result, err := node.Apply(testContext(t), second); err != nil ||
		result.Outcome.Status != store.OutcomeRejected {
		t.Fatalf("Apply(second) = (%+v, %v)", result, err)
	}
	origin.nextSequence = 3
	checkpoint, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	sourceView, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(source): %v", err)
	}

	artifact := newLogicalSnapshotScratch(t, "expanded-artifact-*")
	builderSequence := newLogicalSnapshotScratch(t, "builder-sequence-*")
	publicKey := bytes.Clone(
		privateKey.Public().(ed25519.PublicKey),
	)
	var pages [][]byte
	var chunks [][]byte
	snapshot, err := snapshotbuilder.Build(
		testContext(t),
		node.state,
		snapshotbuilder.Options{
			ArtifactID:        "semantic-import-test",
			CheckpointEventID: checkpoint.Record.CheckpointEventID,
			SignerDeviceID:    deviceID,
			SignerPublicKey:   publicKey,
			ArtifactScratch:   artifact,
			SequenceScratch:   builderSequence,
			ChunkSink: func(
				_ context.Context,
				_ logicalsnapshot.ChunkDescriptor,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err == nil {
					chunks = append(chunks, bytes.Clone(encoded))
				}
				return err
			},
			PageSink: func(
				_ context.Context,
				_ logicalsnapshot.DescriptorPage,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err == nil {
					pages = append(pages, bytes.Clone(encoded))
				}
				return err
			},
			SignRoot: func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(unsigned, privateKey)
			},
		},
	)
	if err != nil {
		t.Fatalf("snapshotbuilder.Build(): %v", err)
	}
	batch := signedReplayBatch(
		t,
		node.state,
		0,
		deviceID,
		privateKey,
	)
	return logicalSnapshotImportFixture{
		snapshot:      snapshot,
		artifact:      artifact,
		pages:         pages,
		chunks:        chunks,
		initial:       initial,
		sourceView:    sourceView,
		batch:         batch,
		signerID:      deviceID,
		signerKey:     publicKey,
		signerPrivate: bytes.Clone(privateKey),
		source:        node.state,
	}
}

func newLogicalSnapshotSuccessorFixture(
	t *testing.T,
) (
	logicalSnapshotImportFixture,
	store.SuccessorState,
	store.StateView,
) {
	return newLogicalSnapshotSuccessorFixtureWithMutations(t, nil, nil)
}

func newLogicalSnapshotSuccessorFixtureWithMutations(
	t *testing.T,
	mutateInitial func(*store.InitialState),
	mutateSuccessor func(*store.ProjectionWrites),
) (
	logicalSnapshotImportFixture,
	store.SuccessorState,
	store.StateView,
) {
	t.Helper()

	initial, privateKey, deviceID := nodeTestInitialState(t)
	if mutateInitial != nil {
		mutateInitial(&initial)
	}
	database, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(
				t.TempDir(),
				"successor-source",
				"state.db",
			),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Initialize(
		context.Background(),
		initial,
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	first := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"pre-recovery task",
	)
	applyLogicalSnapshotTestCommand(t, database, first, 1, 1, false)
	predecessor, err := database.View(testContext(t))
	if err != nil {
		t.Fatalf("View(predecessor): %v", err)
	}

	successor := logicalSnapshotTestSuccessor(
		t,
		initial,
		predecessor,
		deviceID,
		mutateSuccessor,
	)
	if _, err := database.InstallSuccessor(
		testContext(t),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	successorView, err := database.View(testContext(t))
	if err != nil {
		t.Fatalf("View(successor): %v", err)
	}
	checkpointEvent := logicalSnapshotTestCheckpointEvent(
		t,
		privateKey,
		deviceID,
		successorView,
	)
	checkpointResult := applyLogicalSnapshotTestCommand(
		t,
		database,
		checkpointEvent,
		1,
		2,
		true,
	)
	if checkpointResult.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("checkpoint outcome = %+v", checkpointResult.Outcome)
	}
	sourceView, err := database.View(testContext(t))
	if err != nil {
		t.Fatalf("View(source): %v", err)
	}

	fixture := buildLogicalSnapshotImportFixture(
		t,
		database,
		initial,
		sourceView,
		logicalSnapshotSuccessorCheckpointID,
		"semantic-successor-import-test",
		deviceID,
		privateKey,
	)
	return fixture, successor, predecessor
}

func buildLogicalSnapshotImportFixture(
	t *testing.T,
	database *store.Store,
	initial store.InitialState,
	sourceView store.StateView,
	checkpointEventID domain.UUIDv7,
	artifactID string,
	deviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) logicalSnapshotImportFixture {
	t.Helper()

	artifact := newLogicalSnapshotScratch(t, "successor-artifact-*")
	builderSequence := newLogicalSnapshotScratch(
		t,
		"successor-builder-sequence-*",
	)
	publicKey := bytes.Clone(
		privateKey.Public().(ed25519.PublicKey),
	)
	var pages [][]byte
	var chunks [][]byte
	snapshot, err := snapshotbuilder.Build(
		testContext(t),
		database,
		snapshotbuilder.Options{
			ArtifactID:        artifactID,
			CheckpointEventID: checkpointEventID,
			SignerDeviceID:    deviceID,
			SignerPublicKey:   publicKey,
			ArtifactScratch:   artifact,
			SequenceScratch:   builderSequence,
			ChunkSink: func(
				_ context.Context,
				_ logicalsnapshot.ChunkDescriptor,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err == nil {
					chunks = append(chunks, bytes.Clone(encoded))
				}
				return err
			},
			PageSink: func(
				_ context.Context,
				_ logicalsnapshot.DescriptorPage,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err == nil {
					pages = append(pages, bytes.Clone(encoded))
				}
				return err
			},
			SignRoot: func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(unsigned, privateKey)
			},
		},
	)
	if err != nil {
		t.Fatalf("snapshotbuilder.Build(%q): %v", artifactID, err)
	}
	return logicalSnapshotImportFixture{
		snapshot:      snapshot,
		artifact:      artifact,
		pages:         pages,
		chunks:        chunks,
		initial:       initial,
		sourceView:    sourceView,
		signerID:      deviceID,
		signerKey:     publicKey,
		signerPrivate: bytes.Clone(privateKey),
		source:        database,
	}
}

func logicalSnapshotTestSuccessor(
	t *testing.T,
	initial store.InitialState,
	predecessor store.StateView,
	deviceID domain.DeviceID,
	mutate func(*store.ProjectionWrites),
) store.SuccessorState {
	t.Helper()

	baseline, _, baselineDeviceID := nodeTestInitialState(t)
	if baselineDeviceID != deviceID {
		t.Fatal("deterministic successor device changed")
	}
	baseline.Projections.Devices = append(
		[]device.Device(nil),
		initial.Projections.Devices...,
	)
	baseline.Projections.AuditCounters = append(
		baseline.Projections.AuditCounters[:0],
		initial.Projections.AuditCounters...,
	)
	baseline.Projections.PlanCurrent[0].SessionID =
		logicalSnapshotSuccessorSessionID
	voterSet, err := voterset.New(
		logicalSnapshotSuccessorSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(successor): %v", err)
	}
	baseline.Projections.VoterSet[0] = voterSet
	baseline.Projections.CredentialAuthority[0].SessionID =
		logicalSnapshotSuccessorSessionID
	baseline.Projections.SessionPolicy[0].SessionID =
		logicalSnapshotSuccessorSessionID
	if mutate != nil {
		mutate(&baseline.Projections)
	}

	scratch, err := store.NewProjectionScratch(
		nil,
		chain.Versions{Digest: 1, ProjectionSchema: 1},
	)
	if err != nil {
		t.Fatalf("NewProjectionScratch(): %v", err)
	}
	if _, err := scratch.Apply(baseline.Projections); err != nil {
		t.Fatalf("ProjectionScratch.Apply(): %v", err)
	}
	transformDigest, err := scratch.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
	)
	if err != nil {
		t.Fatalf("ProjectionScratch.StateDigest(): %v", err)
	}
	predecessorGenesis, err := chain.GenesisDigest(initial.GenesisJSON)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(): %v", err)
	}
	recoveryPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	defer clear(recoveryPrivate)
	genesis := canonicalLogicalSnapshotJSON(t, map[string]any{
		"digest_version": uint64(1),
		"post_transform_state_digest": codec.EncodeBase64URL(
			transformDigest[:],
		),
		"predecessor_chain_hash": codec.EncodeBase64URL(
			predecessor.Heads.ChainHash[:],
		),
		"predecessor_chain_index": predecessor.Heads.ChainIndex,
		"predecessor_genesis_digest": codec.EncodeBase64URL(
			predecessorGenesis[:],
		),
		"predecessor_projection_accumulator": codec.EncodeBase64URL(
			predecessor.Heads.ProjectionAccumulator[:],
		),
		"predecessor_result_hash": codec.EncodeBase64URL(
			predecessor.Heads.ResultHash[:],
		),
		"predecessor_result_index":  predecessor.Heads.ResultIndex,
		"projection_schema_version": uint64(1),
		"quorum_recovery_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x52}, ed25519.SignatureSize),
		),
		"recovering_identity_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x49}, ed25519.SignatureSize),
		),
		"recovery_generation": uint64(1),
		"recovery_public_key": codec.EncodeBase64URL(
			recoveryPrivate.Public().(ed25519.PublicKey),
		),
		"session_id":   string(logicalSnapshotSuccessorSessionID),
		"workspace_id": string(nodeTestWorkspaceID),
	})
	return store.SuccessorState{
		SessionID:                 logicalSnapshotSuccessorSessionID,
		WorkspaceID:               nodeTestWorkspaceID,
		RecoveryGeneration:        1,
		GenesisJSON:               genesis,
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		ObservedAt:                nodeTestTimestamp2,
		Predecessor:               predecessor.Heads,
		Projections:               baseline.Projections,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
}

func logicalSnapshotTestCheckpointEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	view store.StateView,
) event.SignedEvent {
	t.Helper()
	checkpoint := domain.Checkpoint{
		SessionID:                view.SessionID,
		WorkspaceID:              view.WorkspaceID,
		RecoveryGeneration:       view.RecoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		CoveredChainIndex:        view.Heads.ChainIndex,
		CoveredChainHash:         chain.Digest(view.Heads.ChainHash),
		CoveredResultIndex:       view.Heads.ResultIndex,
		CoveredResultHash:        chain.Digest(view.Heads.ResultHash),
		ProjectionAccumulator: chain.Digest(
			view.Heads.ProjectionAccumulator,
		),
		DigestVersion:           view.Heads.DigestVersion,
		ProjectionSchemaVersion: view.Heads.ProjectionSchemaVersion,
	}
	signature, err := event.SignCheckpoint(checkpoint, privateKey)
	if err != nil {
		t.Fatalf("event.SignCheckpoint(): %v", err)
	}
	payload, err := event.EncodeCheckpointPayload(checkpoint, signature)
	if err != nil {
		t.Fatalf("event.EncodeCheckpointPayload(): %v", err)
	}
	authority, err := event.NewLocalAuthority(
		deviceID,
		logicalSnapshotSuccessorBootID,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding(): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindConsensusCheckpoint,
			EntityID: event.NullEntityID(),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        logicalSnapshotSuccessorCheckpointID,
			SessionID:      view.SessionID,
			WorkspaceID:    view.WorkspaceID,
			CreatedAt:      nodeTestTimestamp2,
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(checkpoint): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(checkpoint): %v", err)
	}
	return signed
}

func applyLogicalSnapshotTestCommand(
	t *testing.T,
	database *store.Store,
	signed event.SignedEvent,
	term uint64,
	logIndex uint64,
	checkpoint bool,
) store.ApplyResult {
	t.Helper()
	view, err := database.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before apply): %v", err)
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("decodeStateView(): %v", err)
	}
	var outcome reducer.Outcome
	if checkpoint {
		outcome, err = reducer.ReduceCheckpoint(
			decoded.Reducer,
			signed,
			reducer.CheckpointApplyContext{
				Term:                    term,
				LogIndex:                logIndex,
				ChainIndex:              view.Heads.ChainIndex,
				ChainHash:               view.Heads.ChainHash,
				ResultIndex:             view.Heads.ResultIndex,
				ResultHash:              view.Heads.ResultHash,
				ProjectionAccumulator:   view.Heads.ProjectionAccumulator,
				DigestVersion:           view.Heads.DigestVersion,
				ProjectionSchemaVersion: view.Heads.ProjectionSchemaVersion,
			},
		)
	} else {
		outcome, err = reducer.Reduce(decoded.Reducer, signed)
	}
	if err != nil {
		t.Fatalf("Reduce(): %v", err)
	}
	request, err := BuildApplyRequest(
		signed,
		outcome,
		ApplyContext{
			Term:               term,
			LogIndex:           logIndex,
			RecoveryGeneration: view.RecoveryGeneration,
			AppliedAt:          nodeTestTimestamp2,
			OriginBootID:       signed.Proposal().Origin.OriginBootID(),
			MonotonicNowNS:     int64(logIndex),
			PriorHeads:         view.Heads,
		},
	)
	if err != nil {
		t.Fatalf("BuildApplyRequest(): %v", err)
	}
	result, err := database.Apply(testContext(t), request)
	if err != nil {
		t.Fatalf("Store.Apply(): %v", err)
	}
	return result
}

func canonicalLogicalSnapshotJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("codec.CanonicalizeSignedObject(): %v", err)
	}
	return canonical
}

func (fixture logicalSnapshotImportFixture) importOptions(
	t *testing.T,
	boundaries LogicalSnapshotBoundaryVerifier,
) LogicalSnapshotImportOptions {
	t.Helper()
	return LogicalSnapshotImportOptions{
		ExpandedArtifact: fixture.artifact,
		SequenceScratch: newLogicalSnapshotScratch(
			t,
			"import-sequence-*",
		),
		BoundaryScratch: newLogicalSnapshotScratch(
			t,
			"import-boundaries-*",
		),
		OpenPage: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.pages)) {
				return nil, io.EOF
			}
			return io.NopCloser(bytes.NewReader(
				bytes.Clone(fixture.pages[index]),
			)), nil
		},
		OpenChunk: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.chunks)) {
				return nil, io.EOF
			}
			return io.NopCloser(bytes.NewReader(
				bytes.Clone(fixture.chunks[index]),
			)), nil
		},
		PreflightRoot: func(
			ctx context.Context,
			root logicalsnapshot.Root,
		) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if root.Unsigned().Input().SignerDeviceID != fixture.signerID {
				return logicalsnapshot.ErrRootSigner
			}
			return logicalsnapshot.VerifyRoot(root, fixture.signerKey)
		},
		StagePath: filepath.Join(
			t.TempDir(),
			"quarantine",
			"state.db",
		),
		OriginBootID: nodeTestBootID1,
		Clock:        nodeTestClock(),
		Boundaries:   boundaries,
	}
}

type logicalSnapshotTestBoundaries struct {
	initial        store.InitialState
	successors     []store.SuccessorState
	predecessors   []store.StateView
	initialCalls   int
	successorCalls int
}

func (boundaries *logicalSnapshotTestBoundaries) VerifyInitialBoundary(
	ctx context.Context,
	_ logicalsnapshot.GenesisPayload,
) (store.InitialState, error) {
	if err := ctx.Err(); err != nil {
		return store.InitialState{}, err
	}
	boundaries.initialCalls++
	return boundaries.initial, nil
}

func (boundaries *logicalSnapshotTestBoundaries) VerifySuccessorBoundary(
	ctx context.Context,
	predecessor store.StateView,
	_ logicalsnapshot.GenesisPayload,
) (store.SuccessorState, error) {
	if err := ctx.Err(); err != nil {
		return store.SuccessorState{}, err
	}
	boundaries.successorCalls++
	boundaries.predecessors = append(
		boundaries.predecessors,
		predecessor,
	)
	index := boundaries.successorCalls - 1
	if index >= len(boundaries.successors) {
		return store.SuccessorState{}, errors.New(
			"unexpected successor boundary",
		)
	}
	return boundaries.successors[index], nil
}

func newLogicalSnapshotScratch(t *testing.T, pattern string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("os.CreateTemp(%q): %v", pattern, err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil &&
			!errors.Is(err, os.ErrClosed) {
			t.Errorf("Close(%q): %v", pattern, err)
		}
	})
	return file
}
