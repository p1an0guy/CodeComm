package snapshotbuilder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	builderSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000002",
	)
	builderWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	builderBootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000004",
	)
	builderRejectedEventID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000011",
	)
	builderCheckpointEventID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000012",
	)
	builderAppliedAt = domain.Timestamp("2026-08-10T12:00:00Z")
)

func TestBuildProducesReplayVerifiedSignedSnapshot(t *testing.T) {
	t.Parallel()

	fixture := newBuilderFixture(t)
	var (
		descriptors []logicalsnapshot.ChunkDescriptor
		chunks      [][]byte
		pages       []logicalsnapshot.DescriptorPage
		pageBytes   [][]byte
		signCalls   int
	)
	options := fixture.options(
		t,
		func(
			_ context.Context,
			descriptor logicalsnapshot.ChunkDescriptor,
			content io.Reader,
		) error {
			raw, err := io.ReadAll(content)
			if err != nil {
				return err
			}
			descriptors = append(descriptors, descriptor)
			chunks = append(chunks, raw)
			return nil
		},
		func(
			_ context.Context,
			page logicalsnapshot.DescriptorPage,
			content io.Reader,
		) error {
			raw, err := io.ReadAll(content)
			if err != nil {
				return err
			}
			pages = append(pages, page)
			pageBytes = append(pageBytes, raw)
			return nil
		},
		func(
			_ context.Context,
			unsigned logicalsnapshot.UnsignedRoot,
		) (logicalsnapshot.Root, error) {
			signCalls++
			return logicalsnapshot.SignRoot(unsigned, fixture.privateKey)
		},
	)
	snapshot, err := Build(context.Background(), fixture.database, options)
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}
	if signCalls != 1 {
		t.Fatalf("root signer calls = %d, want 1", signCalls)
	}
	if err := logicalsnapshot.VerifyRoot(
		snapshot.Root,
		fixture.publicKey,
	); err != nil {
		t.Fatalf("VerifyRoot(): %v", err)
	}
	rootInput := snapshot.Root.Unsigned().Input()
	if rootInput.ArtifactID != options.ArtifactID ||
		rootInput.CheckpointEventID != builderCheckpointEventID ||
		rootInput.SignerDeviceID != fixture.deviceID ||
		rootInput.RecordCount != snapshot.Artifact.RecordCount ||
		rootInput.ChunkCount != uint64(len(chunks)) ||
		rootInput.DescriptorPageCount != uint64(len(pages)) ||
		rootInput.ArtifactDigest != snapshot.Artifact.ArtifactDigest ||
		rootInput.FinalDescriptorPageHash !=
			snapshot.Manifest.FinalDescriptorPageHash {
		t.Fatalf("signed root input = %+v", rootInput)
	}
	if err := logicalsnapshot.ValidateDescriptorPages(
		snapshot.Root,
		pages,
	); err != nil {
		t.Fatalf("ValidateDescriptorPages(): %v", err)
	}
	for index, page := range pages {
		parsed, err := logicalsnapshot.ParseDescriptorPage(
			pageBytes[index],
		)
		if err != nil || parsed.Hash() != page.Hash() {
			t.Fatalf(
				"ParseDescriptorPage(%d) = hash %x, err %v",
				index,
				parsed.Hash(),
				err,
			)
		}
	}

	var expanded bytes.Buffer
	for index, chunk := range chunks {
		descriptor := descriptors[index]
		if descriptor.ChunkIndex != uint64(index) ||
			descriptor.CompressedLength != uint64(len(chunk)) ||
			descriptor.ExpandedLength != uint64(len(chunk)) ||
			descriptor.SHA256 != sha256.Sum256(chunk) {
			t.Fatalf("chunk %d descriptor = %+v", index, descriptor)
		}
		expanded.Write(chunk)
	}
	if sha256.Sum256(expanded.Bytes()) != rootInput.ArtifactDigest ||
		uint64(expanded.Len()) != rootInput.ExpandedBytes {
		t.Fatal("expanded artifact differs from signed root")
	}
	reader := logicalsnapshot.NewRecordReader(
		bytes.NewReader(expanded.Bytes()),
	)
	var recordCount uint64
	for {
		_, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("RecordReader.Next(%d): %v", recordCount, err)
		}
		recordCount++
	}
	if recordCount != rootInput.RecordCount {
		t.Fatalf(
			"expanded record count = %d, want %d",
			recordCount,
			rootInput.RecordCount,
		)
	}
}

func TestBuildNeverSignsCorruptExpandedScratch(t *testing.T) {
	t.Parallel()

	fixture := newBuilderFixture(t)
	artifactFile := newScratchFile(t, "corrupt-artifact-*")
	options := fixture.options(
		t,
		discardChunk,
		discardPage,
		func(
			context.Context,
			logicalsnapshot.UnsignedRoot,
		) (logicalsnapshot.Root, error) {
			t.Fatal("root signer called before corrupt scratch was rejected")
			return logicalsnapshot.Root{}, nil
		},
	)
	options.ArtifactScratch = &corruptingScratch{
		Scratch: artifactFile,
	}
	if _, err := Build(
		context.Background(),
		fixture.database,
		options,
	); !errors.Is(err, ErrArtifactReplay) {
		t.Fatalf("Build(corrupt scratch) = %v, want ErrArtifactReplay", err)
	}
}

func TestBuildRejectsSignerMismatchAndAliasedScratch(t *testing.T) {
	t.Parallel()

	t.Run("signer result", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		wrongKey := builderPrivateKey(41)
		defer clear(wrongKey)
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(unsigned, wrongKey)
			},
		)
		if _, err := Build(
			context.Background(),
			fixture.database,
			options,
		); !errors.Is(err, ErrRootSigner) {
			t.Fatalf("Build(wrong signer) = %v, want ErrRootSigner", err)
		}
	})

	t.Run("same scratch", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(
					unsigned,
					fixture.privateKey,
				)
			},
		)
		options.SequenceScratch = options.ArtifactScratch
		if _, err := Build(
			context.Background(),
			fixture.database,
			options,
		); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("Build(same scratch) = %v, want ErrInvalidOptions", err)
		}
	})
}

func TestBuildRejectsUntrustedCompositionInputsBeforeReturningRoot(
	t *testing.T,
) {
	t.Parallel()

	t.Run("source cut", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		signCalls := 0
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				signCalls++
				return logicalsnapshot.SignRoot(
					unsigned,
					fixture.privateKey,
				)
			},
		)
		source := mutatingRecordSource{
			source: fixture.database,
			mutate: func(cut *store.LogicalSnapshotCut) {
				cut.CheckpointEventID = builderRejectedEventID
			},
		}
		if _, err := Build(
			context.Background(),
			source,
			options,
		); !errors.Is(err, ErrSourceCut) {
			t.Fatalf("Build(mismatched cut) = %v, want ErrSourceCut", err)
		}
		if signCalls != 0 {
			t.Fatalf("mismatched source invoked signer %d times", signCalls)
		}
	})

	t.Run("trailing scratch", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		artifactFile := newScratchFile(t, "trailing-artifact-*")
		if _, err := artifactFile.Write(make([]byte, 8<<20)); err != nil {
			t.Fatalf("seed artifact scratch: %v", err)
		}
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				context.Context,
				logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				t.Fatal("root signer called before trailing scratch was rejected")
				return logicalsnapshot.Root{}, nil
			},
		)
		options.ArtifactScratch = nonTruncatingScratch{
			Scratch: artifactFile,
		}
		if _, err := Build(
			context.Background(),
			fixture.database,
			options,
		); !errors.Is(err, ErrArtifactReplay) {
			t.Fatalf(
				"Build(trailing scratch) = %v, want ErrArtifactReplay",
				err,
			)
		}
	})

	t.Run("signer cancellation", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				root, err := logicalsnapshot.SignRoot(
					unsigned,
					fixture.privateKey,
				)
				cancel()
				return root, err
			},
		)
		if _, err := Build(
			ctx,
			fixture.database,
			options,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"Build(canceled signer) = %v, want context.Canceled",
				err,
			)
		}
	})

	t.Run("signer error", func(t *testing.T) {
		t.Parallel()
		fixture := newBuilderFixture(t)
		injected := errors.New("injected signer failure")
		options := fixture.options(
			t,
			discardChunk,
			discardPage,
			func(
				context.Context,
				logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.Root{}, injected
			},
		)
		_, err := Build(context.Background(), fixture.database, options)
		if !errors.Is(err, ErrRootSigner) ||
			!errors.Is(err, injected) {
			t.Fatalf(
				"Build(signer error) = %v, want both signer errors",
				err,
			)
		}
	})
}

type builderFixture struct {
	database   *store.Store
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	deviceID   domain.DeviceID
}

func newBuilderFixture(t *testing.T) builderFixture {
	t.Helper()
	privateKey := builderPrivateKey(1)
	publicKey := bytes.Clone(privateKey.Public().(ed25519.PublicKey))
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	database, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "session", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("Store.Close(): %v", err)
		}
		clear(privateKey)
	})

	target, err := voterset.New(
		builderSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	heads, err := database.Initialize(
		context.Background(),
		store.InitialState{
			SessionID:   builderSessionID,
			WorkspaceID: builderWorkspaceID,
			GenesisJSON: []byte(
				`{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000002","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`,
			),
			Projections: store.ProjectionWrites{
				Devices: []device.Device{{
					ID:                deviceID,
					Role:              device.RoleOwner,
					IdentityPublicKey: publicKey,
					DaemonVersion:     "1.0.0",
					MaxApplyLevel:     1,
					Status:            device.StatusActive,
					EntityVersion:     1,
				}},
				VoterSet: []voterset.Set{target},
				CredentialAuthority: []store.CredentialAuthorityRow{{
					SessionID:        builderSessionID,
					VoterDeviceIDs:   []domain.DeviceID{deviceID},
					VoterSetVersion:  1,
					ActivationSource: credentialauthority.ActivationGenesis,
				}},
			},
			DigestVersion:           1,
			ProjectionSchemaVersion: 1,
		},
	)
	if err != nil {
		t.Fatalf("Store.Initialize(): %v", err)
	}
	binding := builderDaemonBinding(t, deviceID)
	rejected := builderSignedEvent(
		t,
		privateKey,
		binding,
		builderRejectedEventID,
		event.KindActivityRecorded,
		event.NullEntityID(),
		1,
		"test rejected setup",
		[]byte(`{}`),
	)
	rejectedResult, err := database.Apply(
		context.Background(),
		store.ApplyRequest{
			Term:               1,
			LogIndex:           1,
			AppliedAt:          builderAppliedAt,
			RecoveryGeneration: 0,
			Proposal:           rejected,
			Outcome: store.CommandOutcome{
				Status: store.OutcomeRejected,
				Code:   "test_rejected",
				JSON: []byte(
					`{"code":"test_rejected","status":"rejected"}`,
				),
			},
		},
	)
	if err != nil {
		t.Fatalf("Store.Apply(rejected): %v", err)
	}
	if rejectedResult.Heads.ResultIndex != heads.ResultIndex+1 {
		t.Fatal("rejected setup command did not advance result head")
	}

	checkpoint := domain.Checkpoint{
		SessionID:                builderSessionID,
		WorkspaceID:              builderWorkspaceID,
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		CoveredChainIndex:        rejectedResult.Heads.ChainIndex,
		CoveredChainHash:         rejectedResult.Heads.ChainHash,
		CoveredResultIndex:       rejectedResult.Heads.ResultIndex,
		CoveredResultHash:        rejectedResult.Heads.ResultHash,
		ProjectionAccumulator: rejectedResult.Heads.
			ProjectionAccumulator,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
	checkpointJSON, err := event.EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatalf("event.EncodeCheckpoint(): %v", err)
	}
	checkpointSignature, err := event.SignCheckpoint(
		checkpoint,
		privateKey,
	)
	if err != nil {
		t.Fatalf("event.SignCheckpoint(): %v", err)
	}
	checkpointPayload, err := event.EncodeCheckpointPayload(
		checkpoint,
		checkpointSignature,
	)
	if err != nil {
		t.Fatalf("event.EncodeCheckpointPayload(): %v", err)
	}
	signedCheckpoint := builderSignedEvent(
		t,
		privateKey,
		binding,
		builderCheckpointEventID,
		event.KindConsensusCheckpoint,
		event.NullEntityID(),
		2,
		"",
		checkpointPayload,
	)
	record := store.CheckpointRecord{
		CheckpointEventID:        builderCheckpointEventID,
		SessionID:                builderSessionID,
		WorkspaceID:              builderWorkspaceID,
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		CoveredChainIndex:        checkpoint.CoveredChainIndex,
		CoveredChainHash:         checkpoint.CoveredChainHash,
		CoveredResultIndex:       checkpoint.CoveredResultIndex,
		CoveredResultHash:        checkpoint.CoveredResultHash,
		ProjectionAccumulator:    checkpoint.ProjectionAccumulator,
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
		CheckpointJSON:           checkpointJSON,
		AuthoritySignature: store.Signature(
			checkpointSignature,
		),
	}
	if _, err := database.Apply(
		context.Background(),
		store.ApplyRequest{
			Term:               1,
			LogIndex:           2,
			AppliedAt:          builderAppliedAt,
			RecoveryGeneration: 0,
			Proposal:           signedCheckpoint,
			Outcome: store.CommandOutcome{
				Status: store.OutcomeAccepted,
				Code:   "accepted",
				JSON: []byte(
					`{"code":"accepted","status":"accepted"}`,
				),
			},
			Checkpoint: &record,
		},
	); err != nil {
		t.Fatalf("Store.Apply(checkpoint): %v", err)
	}
	return builderFixture{
		database:   database,
		privateKey: privateKey,
		publicKey:  publicKey,
		deviceID:   deviceID,
	}
}

func (fixture builderFixture) options(
	t *testing.T,
	chunkSink logicalsnapshot.ArtifactChunkSink,
	pageSink logicalsnapshot.DescriptorPageSink,
	signer RootSigner,
) Options {
	t.Helper()
	return Options{
		ArtifactID:        "builder-test-artifact",
		CheckpointEventID: builderCheckpointEventID,
		SignerDeviceID:    fixture.deviceID,
		SignerPublicKey:   bytes.Clone(fixture.publicKey),
		ArtifactScratch:   newScratchFile(t, "artifact-*"),
		SequenceScratch:   newScratchFile(t, "sequence-*"),
		ChunkSink:         chunkSink,
		PageSink:          pageSink,
		SignRoot:          signer,
	}
}

func builderDaemonBinding(
	t *testing.T,
	deviceID domain.DeviceID,
) event.Binding {
	t.Helper()
	authority, err := event.NewLocalAuthority(deviceID, builderBootID)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("LocalAuthority.DaemonBinding(): %v", err)
	}
	return binding
}

func builderSignedEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	binding event.Binding,
	eventID domain.UUIDv7,
	kind event.Kind,
	entityID event.EntityID,
	sequence uint64,
	rationale string,
	payload []byte,
) event.SignedEvent {
	t.Helper()
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             kind,
			EntityID:         entityID,
			RationaleSummary: rationale,
			Actions:          []event.Action{},
			Payload:          payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      builderSessionID,
			WorkspaceID:    builderWorkspaceID,
			CreatedAt:      builderAppliedAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(%s): %v", kind, err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(%s): %v", kind, err)
	}
	return signed
}

func builderPrivateKey(offset byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index+1) + offset - 1
	}
	return ed25519.NewKeyFromSeed(seed)
}

func newScratchFile(t *testing.T, pattern string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("os.CreateTemp(): %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("scratch Close(): %v", err)
		}
	})
	return file
}

type corruptingScratch struct {
	Scratch
	corrupted bool
}

func (scratch *corruptingScratch) Write(value []byte) (int, error) {
	copy := bytes.Clone(value)
	if !scratch.corrupted && len(copy) != 0 {
		copy[0] ^= 0xff
		scratch.corrupted = true
	}
	return scratch.Scratch.Write(copy)
}

type nonTruncatingScratch struct {
	Scratch
}

type mutatingRecordSource struct {
	source RecordSource
	mutate func(*store.LogicalSnapshotCut)
}

func (source mutatingRecordSource) ExportLogicalSnapshotRecords(
	ctx context.Context,
	options store.LogicalSnapshotExportOptions,
	sink store.LogicalSnapshotRecordSink,
) (store.LogicalSnapshotCut, error) {
	cut, err := source.source.ExportLogicalSnapshotRecords(ctx, options, sink)
	if err == nil && source.mutate != nil {
		source.mutate(&cut)
	}
	return cut, err
}

func discardChunk(
	_ context.Context,
	_ logicalsnapshot.ChunkDescriptor,
	content io.Reader,
) error {
	_, err := io.Copy(io.Discard, content)
	return err
}

func discardPage(
	_ context.Context,
	_ logicalsnapshot.DescriptorPage,
	content io.Reader,
) error {
	_, err := io.Copy(io.Discard, content)
	return err
}
