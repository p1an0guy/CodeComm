package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

type daemonSnapshotRecordSourceStub struct{}

func (daemonSnapshotRecordSourceStub) ExportLogicalSnapshotRecords(
	context.Context,
	store.LogicalSnapshotExportOptions,
	store.LogicalSnapshotRecordSink,
) (store.LogicalSnapshotCut, error) {
	return store.LogicalSnapshotCut{}, errors.New("unexpected record export")
}

type daemonSnapshotCheckpointSourceStub struct {
	lookup store.AppliedCheckpointLookup
	err    error
	calls  int
}

func (source *daemonSnapshotCheckpointSourceStub) ForceCheckpoint(
	context.Context,
) (store.AppliedCheckpointLookup, error) {
	source.calls++
	return source.lookup, source.err
}

func TestDaemonLogicalSnapshotPublisherPersistsAndServesArtifact(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpointEventID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-6123456789ab",
	)
	checkpoint := daemonSnapshotTestCheckpoint(
		t,
		initial,
		deviceID,
		checkpointEventID,
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{
		lookup: store.AppliedCheckpointLookup{
			Record:          checkpoint,
			AppliedLogIndex: 2,
		},
	}
	var captured snapshotbuilder.Options
	publisher := &daemonLogicalSnapshotPublisher{
		checkpoints: checkpoints,
		records:     daemonSnapshotRecordSourceStub{},
		repository:  repository,
		deviceID:    deviceID,
		publicKey: bytesClonePublicKey(
			privateKey.Public().(ed25519.PublicKey),
		),
		privateKey: privateKey,
		build: func(
			ctx context.Context,
			_ snapshotbuilder.RecordSource,
			options snapshotbuilder.Options,
		) (snapshotbuilder.Snapshot, error) {
			captured = options
			return daemonSnapshotTestBuild(ctx, initial, options)
		},
	}
	if err := publisher.publishOnce(context.Background()); err != nil {
		t.Fatalf("publishOnce(): %v", err)
	}
	if checkpoints.calls != 1 ||
		captured.CheckpointEventID != checkpointEventID ||
		captured.ArtifactID != daemonSnapshotArtifactID(checkpointEventID) ||
		captured.SignerDeviceID != deviceID {
		t.Fatalf(
			"checkpoint/build capture = (%d, %s, %q, %s)",
			checkpoints.calls,
			captured.CheckpointEventID,
			captured.ArtifactID,
			captured.SignerDeviceID,
		)
	}

	root, err := repository.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot(): %v", err)
	}
	if root.Unsigned().Input().CheckpointEventID != checkpointEventID {
		t.Fatalf(
			"latest checkpoint = %s",
			root.Unsigned().Input().CheckpointEventID,
		)
	}
	scope, err := contenthttp.NewSnapshotRequestScope(root)
	if err != nil {
		t.Fatalf("NewSnapshotRequestScope(): %v", err)
	}
	artifact := repository.artifacts[scope.ArtifactID]
	if artifact == nil {
		t.Fatal("published artifact is absent from repository metadata")
	}
	artifactType := reflect.TypeOf(artifact).Elem()
	for index := 0; index < artifactType.NumField(); index++ {
		field := artifactType.Field(index)
		if field.Type.Kind() == reflect.Slice ||
			field.Type.Kind() == reflect.Map {
			t.Fatalf(
				"artifact metadata retains collection field %s %s",
				field.Name,
				field.Type,
			)
		}
	}
	openContext, cancelOpen := context.WithCancel(context.Background())
	transfer, err := repository.OpenSnapshotTransfer(openContext, scope)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(): %v", err)
	}
	cancelOpen()
	defer transfer.Close()
	page, err := transfer.SnapshotManifestPage(context.Background(), 0)
	if err != nil || page.Page().Input().PageIndex != 0 {
		t.Fatalf("SnapshotManifestPage() = (%#v, %v)", page, err)
	}
	chunk, err := transfer.SnapshotChunk(context.Background(), 0)
	if err != nil ||
		!bytes.Equal(chunk.Bytes(), daemonSnapshotTestArtifactBytes) {
		t.Fatalf("SnapshotChunk() = (%q, %v)", chunk.Bytes(), err)
	}

	reopened := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	reopenedRoot, err := reopened.LatestSnapshot(context.Background())
	if err != nil ||
		!bytes.Equal(reopenedRoot.CanonicalBytes(), root.CanonicalBytes()) {
		t.Fatalf("reopened LatestSnapshot() = (%#v, %v)", reopenedRoot, err)
	}
	reopenedTransfer, err := reopened.OpenSnapshotTransfer(
		context.Background(),
		scope,
	)
	if err != nil {
		t.Fatalf("reopened OpenSnapshotTransfer(): %v", err)
	}
	defer reopenedTransfer.Close()
	reopenedPage, err := reopenedTransfer.SnapshotManifestPage(
		context.Background(),
		0,
	)
	if err != nil || !bytes.Equal(
		reopenedPage.Page().CanonicalBytes(),
		page.Page().CanonicalBytes(),
	) {
		t.Fatalf(
			"reopened SnapshotManifestPage() = (%#v, %v)",
			reopenedPage,
			err,
		)
	}
	reopenedChunk, err := reopenedTransfer.SnapshotChunk(context.Background(), 0)
	if err != nil ||
		!bytes.Equal(
			reopenedChunk.Bytes(),
			daemonSnapshotTestArtifactBytes,
		) {
		t.Fatalf(
			"reopened SnapshotChunk() = (%q, %v)",
			reopenedChunk.Bytes(),
			err,
		)
	}
	wrongScope := scope
	wrongScope.WorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440099",
	)
	if _, err := reopened.OpenSnapshotTransfer(
		context.Background(),
		wrongScope,
	); !errors.Is(err, contenthttp.ErrSnapshotNotFound) {
		t.Fatalf("OpenSnapshotTransfer(wrong scope) error = %v", err)
	}

	chunkPath := filepath.Join(
		daemonLogicalSnapshotRepositoryPath(statePath, 0),
		"artifacts",
		scope.ArtifactID,
		"chunks",
		daemonSnapshotIndexedFilename(0, ".bin"),
	)
	if err := os.WriteFile(chunkPath, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper chunk: %v", err)
	}
	if _, err := reopenedTransfer.SnapshotChunk(
		context.Background(),
		0,
	); !errors.Is(err, errDaemonSnapshotIntegrity) {
		t.Fatalf("SnapshotChunk(tampered) error = %v", err)
	}
	if _, err := openDaemonLogicalSnapshotRepository(
		context.Background(),
		statePath,
		initial.SessionID,
		initial.WorkspaceID,
		0,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	); !errors.Is(err, errDaemonSnapshotIntegrity) {
		t.Fatalf("reopen tampered repository error = %v", err)
	}
}

func TestDaemonLogicalSnapshotPublicationFailureIsNotVisible(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpointEventID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-6223456789ab",
	)
	buildFailure := errors.New("injected build failure")
	publisher := &daemonLogicalSnapshotPublisher{
		checkpoints: &daemonSnapshotCheckpointSourceStub{
			lookup: store.AppliedCheckpointLookup{
				Record: daemonSnapshotTestCheckpoint(
					t,
					initial,
					deviceID,
					checkpointEventID,
				),
				AppliedLogIndex: 2,
			},
		},
		records:    daemonSnapshotRecordSourceStub{},
		repository: repository,
		deviceID:   deviceID,
		publicKey: bytesClonePublicKey(
			privateKey.Public().(ed25519.PublicKey),
		),
		privateKey: privateKey,
		build: func(
			context.Context,
			snapshotbuilder.RecordSource,
			snapshotbuilder.Options,
		) (snapshotbuilder.Snapshot, error) {
			return snapshotbuilder.Snapshot{}, buildFailure
		},
	}
	if err := publisher.publishOnce(context.Background()); !errors.Is(
		err,
		errDaemonSnapshotPublication,
	) || !errors.Is(err, buildFailure) {
		t.Fatalf("publishOnce() error = %v", err)
	}
	if _, err := repository.LatestSnapshot(
		context.Background(),
	); !errors.Is(err, contenthttp.ErrSnapshotUnavailable) {
		t.Fatalf("LatestSnapshot() error = %v", err)
	}
	entries, err := os.ReadDir(repository.artifactsDirectory)
	if err != nil {
		t.Fatalf("ReadDir(artifacts): %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed publication left entries: %#v", entries)
	}
}

func TestDaemonLogicalSnapshotPublicationBuildDeadlineIsBounded(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{
		lookup: store.AppliedCheckpointLookup{
			Record: daemonSnapshotTestCheckpoint(
				t,
				initial,
				deviceID,
				"018f47de-89ab-7def-8123-6223456789ac",
			),
			AppliedLogIndex: 2,
		},
	}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	publisher.buildTimeout = 10 * time.Millisecond
	publisher.build = func(
		ctx context.Context,
		_ snapshotbuilder.RecordSource,
		_ snapshotbuilder.Options,
	) (snapshotbuilder.Snapshot, error) {
		<-ctx.Done()
		return snapshotbuilder.Snapshot{}, ctx.Err()
	}

	if err := publisher.publishOnce(context.Background()); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("bounded publication error = %v", err)
	}
	if checkpoints.calls != 1 {
		t.Fatalf("checkpoint calls = %d, want 1", checkpoints.calls)
	}
	if _, err := repository.LatestSnapshot(
		context.Background(),
	); !errors.Is(err, contenthttp.ErrSnapshotUnavailable) {
		t.Fatalf("deadline made a snapshot visible: %v", err)
	}
}

func TestDaemonLogicalSnapshotPublicationClassifiesCutRacesForRetry(
	t *testing.T,
) {
	for _, err := range []error{
		raft.ErrLeadershipTransferInProgress,
		store.ErrLogicalSnapshotNotCovered,
		store.ErrLogicalSnapshotSignerUnauthorized,
		errDaemonSnapshotCleanupPending,
	} {
		wrapped := fmt.Errorf("%w: %w", errDaemonSnapshotPublication, err)
		if !retryableDaemonSnapshotPublication(wrapped) {
			t.Fatalf("publication error %v is not retryable", err)
		}
	}
	if retryableDaemonSnapshotPublication(
		fmt.Errorf("%w: disk corruption", errDaemonSnapshotPublication),
	) {
		t.Fatal("generic publication failure is retryable")
	}
}

func TestDaemonLogicalSnapshotPublisherAllowsDistinctCheckpointSigner(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	repository := openDaemonSnapshotTestRepository(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpointSigner := daemonContentTestDeviceID(t, 0xe7)
	checkpointEventID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-62123456789a",
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{
		lookup: store.AppliedCheckpointLookup{
			Record: daemonSnapshotTestCheckpoint(
				t,
				initial,
				checkpointSigner,
				checkpointEventID,
			),
			AppliedLogIndex: 2,
		},
	}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	if err := publisher.publishOnce(context.Background()); err != nil {
		t.Fatalf("publishOnce(distinct checkpoint signer): %v", err)
	}
	root, err := repository.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot(): %v", err)
	}
	input := root.Unsigned().Input()
	if input.CheckpointEventID != checkpointEventID ||
		input.SignerDeviceID != deviceID ||
		checkpointSigner == deviceID {
		t.Fatalf(
			"published root = checkpoint %s signer %s; checkpoint signer %s",
			input.CheckpointEventID,
			input.SignerDeviceID,
			checkpointSigner,
		)
	}
}

func TestDaemonLogicalSnapshotRepositoryRetainsNewestTwoArtifacts(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := &daemonLogicalSnapshotPublisher{
		checkpoints: checkpoints,
		records:     daemonSnapshotRecordSourceStub{},
		repository:  repository,
		deviceID:    deviceID,
		publicKey: bytesClonePublicKey(
			privateKey.Public().(ed25519.PublicKey),
		),
		privateKey: privateKey,
		build: func(
			ctx context.Context,
			_ snapshotbuilder.RecordSource,
			options snapshotbuilder.Options,
		) (snapshotbuilder.Snapshot, error) {
			return daemonSnapshotTestBuild(ctx, initial, options)
		},
	}
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-63123456789a",
		"018f47de-89ab-7def-8123-64123456789a",
		"018f47de-89ab-7def-8123-65123456789a",
	}
	for _, eventID := range eventIDs {
		checkpoints.lookup = store.AppliedCheckpointLookup{
			Record: daemonSnapshotTestCheckpoint(
				t,
				initial,
				deviceID,
				eventID,
			),
			AppliedLogIndex: 2,
		}
		if err := publisher.publishOnce(context.Background()); err != nil {
			t.Fatalf("publishOnce(%s): %v", eventID, err)
		}
	}
	if len(repository.artifacts) != daemonSnapshotRetention {
		t.Fatalf("retained artifacts = %d", len(repository.artifacts))
	}
	oldestArtifactID := daemonSnapshotArtifactID(eventIDs[0])
	if _, exists := repository.artifacts[oldestArtifactID]; exists {
		t.Fatal("oldest artifact remains addressable")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := os.ReadDir(repository.artifactsDirectory)
		if err != nil {
			t.Fatalf("ReadDir(artifacts): %v", err)
		}
		if len(entries) == daemonSnapshotRetention {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("artifact directory count = %d", len(entries))
		}
		time.Sleep(10 * time.Millisecond)
	}
	reopened := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	latest, err := reopened.LatestSnapshot(context.Background())
	if err != nil ||
		latest.Unsigned().Input().CheckpointEventID != eventIDs[2] {
		t.Fatalf(
			"reopened latest checkpoint = (%s, %v)",
			latest.Unsigned().Input().CheckpointEventID,
			err,
		)
	}
}

func TestDaemonLogicalSnapshotRepositoryPruneRetiresActiveTransfer(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-66123456789a",
		"018f47de-89ab-7def-8123-67123456789a",
		"018f47de-89ab-7def-8123-68123456789a",
	}
	for _, eventID := range eventIDs[:2] {
		daemonSnapshotTestPublish(
			t,
			publisher,
			checkpoints,
			initial,
			deviceID,
			eventID,
		)
	}

	oldestID := daemonSnapshotArtifactID(eventIDs[0])
	repository.mu.RLock()
	oldest := repository.artifacts[oldestID]
	repository.mu.RUnlock()
	if oldest == nil {
		t.Fatal("oldest artifact is absent before pruning")
	}
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		oldest.scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(oldest): %v", err)
	}

	checkpoints.lookup = store.AppliedCheckpointLookup{
		Record: daemonSnapshotTestCheckpoint(
			t,
			initial,
			deviceID,
			eventIDs[2],
		),
		AppliedLogIndex: 2,
	}
	published := make(chan error, 1)
	go func() {
		published <- publisher.publishOnce(context.Background())
	}()
	select {
	case err := <-published:
		if err != nil {
			t.Fatalf("publishOnce(with active transfer): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication blocked on an active snapshot transfer")
	}

	repository.mu.RLock()
	_, available := repository.artifacts[oldestID]
	retired := repository.retired[oldestID] == oldest
	repository.mu.RUnlock()
	if available || !retired {
		t.Fatalf("retirement state = available %t, retired %t", available, retired)
	}
	if fresh, err := repository.OpenSnapshotTransfer(
		context.Background(),
		oldest.scope,
	); !errors.Is(err, contenthttp.ErrSnapshotNotFound) || fresh != nil {
		t.Fatalf("fresh retired transfer = (%v, %v)", fresh, err)
	}
	if _, err := os.Stat(oldest.directory); err != nil {
		t.Fatalf("transferred artifact was removed early: %v", err)
	}
	if page, err := transfer.SnapshotManifestPage(
		context.Background(),
		0,
	); err != nil || page.Scope() != oldest.scope {
		t.Fatalf("retired transfer page = (%#v, %v)", page, err)
	}
	if chunk, err := transfer.SnapshotChunk(
		context.Background(),
		0,
	); err != nil ||
		!bytes.Equal(chunk.Bytes(), daemonSnapshotTestArtifactBytes) {
		t.Fatalf("retired transfer chunk = (%q, %v)", chunk.Bytes(), err)
	}
	if err := transfer.Close(); err != nil {
		t.Fatalf("SnapshotTransfer.Close(): %v", err)
	}
	if err := transfer.Close(); err != nil {
		t.Fatalf("SnapshotTransfer.Close(second): %v", err)
	}
	waitForDaemonSnapshotCondition(t, func() bool {
		_, err := os.Stat(oldest.directory)
		return errors.Is(err, os.ErrNotExist)
	}, "retired artifact was not removed after transfer close")
}

func TestDaemonLogicalSnapshotRepositoryRetriesRetiredCleanup(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-69123456789a",
		"018f47de-89ab-7def-8123-6a123456789a",
		"018f47de-89ab-7def-8123-6b123456789a",
	}
	for _, eventID := range eventIDs[:2] {
		daemonSnapshotTestPublish(
			t,
			publisher,
			checkpoints,
			initial,
			deviceID,
			eventID,
		)
	}
	oldestID := daemonSnapshotArtifactID(eventIDs[0])
	repository.mu.RLock()
	oldest := repository.artifacts[oldestID]
	repository.mu.RUnlock()
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		oldest.scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(): %v", err)
	}
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		eventIDs[2],
	)

	cleanupFailure := errors.New("injected retired cleanup failure")
	removeArtifact := repository.removeArtifact
	cleanupAttempted := make(chan struct{}, 1)
	repository.removeArtifact = func(context.Context, string) error {
		cleanupAttempted <- struct{}{}
		return cleanupFailure
	}
	if err := transfer.Close(); err != nil {
		t.Fatalf("SnapshotTransfer.Close() error = %v", err)
	}
	select {
	case <-cleanupAttempted:
	case <-time.After(5 * time.Second):
		t.Fatal("retired cleanup was not attempted")
	}
	waitForDaemonSnapshotCondition(t, func() bool {
		repository.mu.RLock()
		defer repository.mu.RUnlock()
		return !oldest.cleanupInProgress &&
			errors.Is(oldest.cleanupErr, cleanupFailure)
	}, "retired cleanup failure was not retained")
	repository.mu.RLock()
	retired := repository.retired[oldestID]
	retainedErr := retired.cleanupErr
	repository.mu.RUnlock()
	if retired != oldest || !errors.Is(retainedErr, cleanupFailure) {
		t.Fatalf("retained cleanup state = (%p, %v)", retired, retainedErr)
	}
	if _, err := os.Stat(oldest.directory); err != nil {
		t.Fatalf("failed cleanup removed artifact: %v", err)
	}

	repository.removeArtifact = removeArtifact
	if err := repository.prune(context.Background()); err != nil {
		t.Fatalf("prune(retry cleanup): %v", err)
	}
	repository.mu.RLock()
	_, stillRetired := repository.retired[oldestID]
	repository.mu.RUnlock()
	if stillRetired {
		t.Fatal("successful cleanup retry retained metadata")
	}
	if _, err := os.Stat(oldest.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retried cleanup retained directory: %v", err)
	}
}

func TestDaemonLogicalSnapshotRepositoryHonorsCancellation(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		"018f47de-89ab-7def-8123-6c123456789a",
	)
	root, err := repository.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot(): %v", err)
	}
	scope, err := contenthttp.NewSnapshotRequestScope(root)
	if err != nil {
		t.Fatalf("NewSnapshotRequestScope(): %v", err)
	}
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(): %v", err)
	}
	defer transfer.Close()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transfer.SnapshotManifestPage(
		canceled,
		0,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("SnapshotManifestPage(canceled) error = %v", err)
	}
	if _, err := transfer.SnapshotChunk(
		canceled,
		0,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("SnapshotChunk(canceled) error = %v", err)
	}
	if _, err := repository.loadArtifact(
		canceled,
		repository.artifacts[scope.ArtifactID].directory,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("loadArtifact(canceled) error = %v", err)
	}
	if err := repository.prune(canceled); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("prune(canceled) error = %v", err)
	}
	if _, err := readDaemonSnapshotFileContext(
		canceled,
		filepath.Join(
			repository.artifacts[scope.ArtifactID].directory,
			daemonSnapshotRootFilename,
		),
		logicalsnapshot.MaxRootBytes,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("readDaemonSnapshotFileContext(canceled) error = %v", err)
	}
}

func TestReadDaemonSnapshotDirectorySortsIndexedInventory(t *testing.T) {
	directory := t.TempDir()
	const entryCount = 300
	for index := entryCount; index > 0; index-- {
		name := daemonSnapshotIndexedFilename(uint64(index-1), ".bin")
		if err := os.WriteFile(
			filepath.Join(directory, name),
			[]byte{byte(index)},
			0o600,
		); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	entries, err := readDaemonSnapshotDirectory(
		context.Background(),
		directory,
		entryCount,
	)
	if err != nil {
		t.Fatalf("readDaemonSnapshotDirectory(): %v", err)
	}
	if len(entries) != entryCount {
		t.Fatalf("entry count = %d, want %d", len(entries), entryCount)
	}
	for index, entry := range entries {
		want := daemonSnapshotIndexedFilename(uint64(index), ".bin")
		if entry.Name() != want {
			t.Fatalf("entry %d = %q, want %q", index, entry.Name(), want)
		}
	}
}

func TestDaemonLogicalSnapshotRepositoryRetriesInventorySyncFailure(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-6d123456789a",
		"018f47de-89ab-7def-8123-6e123456789a",
		"018f47de-89ab-7def-8123-6f123456789a",
	}
	for _, eventID := range eventIDs[:2] {
		daemonSnapshotTestPublish(
			t,
			publisher,
			checkpoints,
			initial,
			deviceID,
			eventID,
		)
	}
	oldestID := daemonSnapshotArtifactID(eventIDs[0])
	oldest := repository.artifacts[oldestID]
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		oldest.scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(): %v", err)
	}
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		eventIDs[2],
	)

	syncFailure := errors.New("injected inventory sync failure")
	syncInventory := repository.syncInventory
	syncAttempted := make(chan struct{}, 1)
	repository.syncInventory = func(context.Context, string) error {
		syncAttempted <- struct{}{}
		return syncFailure
	}
	if err := transfer.Close(); err != nil {
		t.Fatalf("SnapshotTransfer.Close() error = %v", err)
	}
	select {
	case <-syncAttempted:
	case <-time.After(5 * time.Second):
		t.Fatal("retired inventory sync was not attempted")
	}
	waitForDaemonSnapshotCondition(t, func() bool {
		repository.mu.RLock()
		defer repository.mu.RUnlock()
		return !oldest.cleanupInProgress &&
			errors.Is(oldest.cleanupErr, syncFailure)
	}, "retired inventory sync failure was not retained")
	if _, err := os.Stat(oldest.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired directory survived removal: %v", err)
	}
	repository.mu.RLock()
	retired := repository.retired[oldestID]
	repository.mu.RUnlock()
	if retired != oldest || !errors.Is(oldest.cleanupErr, syncFailure) {
		t.Fatalf("retired sync-failure state = (%p, %v)", retired, oldest.cleanupErr)
	}

	repository.syncInventory = syncInventory
	if err := repository.prune(context.Background()); err != nil {
		t.Fatalf("prune(retry inventory sync): %v", err)
	}
	repository.mu.RLock()
	_, stillRetired := repository.retired[oldestID]
	repository.mu.RUnlock()
	if stillRetired {
		t.Fatal("successful inventory retry retained metadata")
	}
}

func TestDaemonLogicalSnapshotRepositoryTransferCloseDoesNotWaitForCleanup(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-70123456789a",
		"018f47de-89ab-7def-8123-71123456789a",
		"018f47de-89ab-7def-8123-72123456789a",
		"018f47de-89ab-7def-8123-73123456789a",
	}
	for _, eventID := range eventIDs[:2] {
		daemonSnapshotTestPublish(
			t,
			publisher,
			checkpoints,
			initial,
			deviceID,
			eventID,
		)
	}
	oldest := repository.artifacts[daemonSnapshotArtifactID(eventIDs[0])]
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		oldest.scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(): %v", err)
	}
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		eventIDs[2],
	)

	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var cleanupStartedOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseCleanup) }) })
	repository.removeArtifact = func(
		ctx context.Context,
		path string,
	) error {
		cleanupStartedOnce.Do(func() { close(cleanupStarted) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-releaseCleanup:
			return os.RemoveAll(path)
		}
	}
	closed := make(chan error, 1)
	go func() {
		closed <- transfer.Close()
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("SnapshotTransfer.Close(): %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SnapshotTransfer.Close() waited for artifact deletion")
	}
	select {
	case <-cleanupStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("asynchronous artifact cleanup did not start")
	}
	if _, err := os.Stat(oldest.directory); err != nil {
		t.Fatalf("blocked cleanup changed artifact: %v", err)
	}
	checkpoints.lookup = store.AppliedCheckpointLookup{
		Record: daemonSnapshotTestCheckpoint(
			t,
			initial,
			deviceID,
			eventIDs[3],
		),
		AppliedLogIndex: 2,
	}
	checkpointCalls := checkpoints.calls
	if err := publisher.publishOnce(context.Background()); !errors.Is(
		err,
		errDaemonSnapshotCleanupPending,
	) {
		t.Fatalf("publishOnce(with cleanup backlog) error = %v", err)
	}
	if checkpoints.calls != checkpointCalls {
		t.Fatalf(
			"cleanup-blocked retry forced %d checkpoints, want none",
			checkpoints.calls-checkpointCalls,
		)
	}
	releaseOnce.Do(func() { close(releaseCleanup) })
	repository.cleanupWait.Wait()
	if _, err := os.Stat(oldest.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released cleanup retained artifact: %v", err)
	}
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		eventIDs[3],
	)
}

func TestDaemonLogicalSnapshotRepositoryPinsRootThroughBulkHandoff(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	statePath := filepath.Join(t.TempDir(), "session", "state.db")
	repository := openDaemonSnapshotTestRepository(
		t,
		statePath,
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	checkpoints := &daemonSnapshotCheckpointSourceStub{}
	publisher := daemonSnapshotTestPublisher(
		initial,
		deviceID,
		privateKey,
		checkpoints,
		repository,
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-74123456789a",
		"018f47de-89ab-7def-8123-75123456789a",
		"018f47de-89ab-7def-8123-76123456789a",
	}
	daemonSnapshotTestPublish(
		t,
		publisher,
		checkpoints,
		initial,
		deviceID,
		eventIDs[0],
	)
	root, err := repository.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot(): %v", err)
	}
	scope, err := contenthttp.NewSnapshotRequestScope(root)
	if err != nil {
		t.Fatalf("NewSnapshotRequestScope(): %v", err)
	}
	oldest := repository.artifacts[scope.ArtifactID]
	for _, eventID := range eventIDs[1:] {
		daemonSnapshotTestPublish(
			t,
			publisher,
			checkpoints,
			initial,
			deviceID,
			eventID,
		)
	}
	transfer, err := repository.OpenSnapshotTransfer(
		context.Background(),
		scope,
	)
	if err != nil {
		t.Fatalf("OpenSnapshotTransfer(handoff root): %v", err)
	}

	repository.mu.Lock()
	oldest.handoffUntil = time.Now().Add(-time.Second)
	if oldest.handoffTimer != nil {
		oldest.handoffTimer.Stop()
	}
	repository.mu.Unlock()
	repository.expireSnapshotHandoff(oldest)
	if fresh, err := repository.OpenSnapshotTransfer(
		context.Background(),
		scope,
	); !errors.Is(err, contenthttp.ErrSnapshotNotFound) || fresh != nil {
		t.Fatalf("OpenSnapshotTransfer(expired handoff) = (%v, %v)", fresh, err)
	}
	if chunk, err := transfer.SnapshotChunk(
		context.Background(),
		0,
	); err != nil ||
		!bytes.Equal(chunk.Bytes(), daemonSnapshotTestArtifactBytes) {
		t.Fatalf("pinned transfer chunk = (%q, %v)", chunk.Bytes(), err)
	}
	if err := transfer.Close(); err != nil {
		t.Fatalf("SnapshotTransfer.Close(): %v", err)
	}
	waitForDaemonSnapshotCondition(t, func() bool {
		_, err := os.Stat(oldest.directory)
		return errors.Is(err, os.ErrNotExist)
	}, "expired handoff artifact was not cleaned after transfer close")
}

func TestDaemonSnapshotStorageRejectsSymlinkedPaths(t *testing.T) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "session")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Join(
		stateDirectory,
		daemonSnapshotDirectoryName,
	)
	if err := os.Symlink(external, repositoryRoot); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if repository, err := openDaemonLogicalSnapshotRepository(
		context.Background(),
		filepath.Join(stateDirectory, "state.db"),
		initial.SessionID,
		initial.WorkspaceID,
		0,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	); err == nil || repository != nil {
		t.Fatalf("symlinked repository opened: (%v, %v)", repository, err)
	}

	target := filepath.Join(external, "root.json")
	if err := os.WriteFile(target, []byte(`{"test":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stateDirectory, "root.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}
	if _, err := readDaemonSnapshotFile(link, 1024); err == nil {
		t.Fatal("symlinked snapshot file was read")
	}

	managed := filepath.Join(root, "managed")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	disposable := filepath.Join(managed, "disposable")
	if err := os.Mkdir(disposable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeDaemonSnapshotTreeUnder(managed, disposable); err != nil {
		t.Fatalf("remove rooted snapshot tree: %v", err)
	}
	if err := removeDaemonSnapshotTreeUnder(managed, disposable); err != nil {
		t.Fatalf("repeat rooted snapshot cleanup: %v", err)
	}
	externalArtifact := filepath.Join(external, "artifact")
	if err := os.Mkdir(externalArtifact, 0o700); err != nil {
		t.Fatal(err)
	}
	externalRoot := filepath.Join(
		externalArtifact,
		daemonSnapshotRootFilename,
	)
	if err := os.WriteFile(
		externalRoot,
		[]byte(`{"external":true}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	linkedInventory := filepath.Join(managed, "inventory")
	if err := os.Symlink(external, linkedInventory); err != nil {
		t.Skipf("intermediate directory symlinks unavailable: %v", err)
	}
	linkedRoot := filepath.Join(
		linkedInventory,
		"artifact",
		daemonSnapshotRootFilename,
	)
	if _, err := readDaemonSnapshotFileContextUnder(
		context.Background(),
		managed,
		linkedRoot,
		1024,
	); err == nil {
		t.Fatal("snapshot read followed an intermediate directory symlink")
	}
	escapedFile := filepath.Join(external, "escaped.bin")
	if file, err := createDaemonSnapshotFileUnder(
		managed,
		filepath.Join(linkedInventory, "escaped.bin"),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	); err == nil {
		_ = file.Close()
		t.Fatal("snapshot create followed an intermediate directory symlink")
	}
	if _, err := os.Lstat(escapedFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed rooted create left an external file: %v", err)
	}
	source := filepath.Join(managed, "rename-source.bin")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameDaemonSnapshotPathUnder(
		managed,
		source,
		filepath.Join(linkedInventory, "renamed.bin"),
		false,
	); err == nil {
		t.Fatal("snapshot rename followed an intermediate directory symlink")
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("failed rooted rename lost its source: %v", err)
	}
	if err := removeDaemonSnapshotTreeUnder(
		managed,
		filepath.Join(linkedInventory, "artifact"),
	); err == nil {
		t.Fatal("snapshot cleanup followed an intermediate directory symlink")
	}
	if content, err := os.ReadFile(externalRoot); err != nil ||
		!bytes.Equal(content, []byte(`{"external":true}`)) {
		t.Fatalf(
			"failed cleanup altered external artifact: content=%q err=%v",
			content,
			err,
		)
	}
}

func TestDaemonSnapshotArtifactWriterEnforcesOperationalQuota(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "chunks"), 0o700); err != nil {
		t.Fatal(err)
	}
	writer := &daemonSnapshotArtifactWriter{
		artifactID: "bounded-artifact",
		directory:  directory,
		chunkCount: daemonSnapshotOperationalMaxChunks,
	}
	if err := writer.writeChunk(
		context.Background(),
		logicalsnapshot.ChunkDescriptor{
			ChunkIndex:       daemonSnapshotOperationalMaxChunks,
			CompressedLength: 1,
			ExpandedLength:   1,
			SHA256:           sha256.Sum256([]byte{1}),
		},
		bytes.NewReader([]byte{1}),
	); !errors.Is(err, errDaemonSnapshotReceiveQuota) {
		t.Fatalf("chunk-count quota error = %v", err)
	}
	writer.chunkCount = 0
	writer.compressedBytes = daemonSnapshotOperationalMaxBytes
	writer.expandedBytes = daemonSnapshotOperationalMaxBytes
	if err := writer.writeChunk(
		context.Background(),
		logicalsnapshot.ChunkDescriptor{
			CompressedLength: 1,
			ExpandedLength:   1,
			SHA256:           sha256.Sum256([]byte{1}),
		},
		bytes.NewReader([]byte{1}),
	); !errors.Is(err, errDaemonSnapshotReceiveQuota) {
		t.Fatalf("byte quota error = %v", err)
	}
}

func daemonSnapshotTestPublisher(
	initial store.InitialState,
	deviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
	checkpoints *daemonSnapshotCheckpointSourceStub,
	repository *daemonLogicalSnapshotRepository,
) *daemonLogicalSnapshotPublisher {
	return &daemonLogicalSnapshotPublisher{
		checkpoints: checkpoints,
		records:     daemonSnapshotRecordSourceStub{},
		repository:  repository,
		deviceID:    deviceID,
		publicKey: bytesClonePublicKey(
			privateKey.Public().(ed25519.PublicKey),
		),
		privateKey: privateKey,
		build: func(
			ctx context.Context,
			_ snapshotbuilder.RecordSource,
			options snapshotbuilder.Options,
		) (snapshotbuilder.Snapshot, error) {
			return daemonSnapshotTestBuild(ctx, initial, options)
		},
	}
}

func daemonSnapshotTestPublish(
	t *testing.T,
	publisher *daemonLogicalSnapshotPublisher,
	checkpoints *daemonSnapshotCheckpointSourceStub,
	initial store.InitialState,
	deviceID domain.DeviceID,
	eventID domain.UUIDv7,
) {
	t.Helper()
	checkpoints.lookup = store.AppliedCheckpointLookup{
		Record: daemonSnapshotTestCheckpoint(
			t,
			initial,
			deviceID,
			eventID,
		),
		AppliedLogIndex: 2,
	}
	if err := publisher.publishOnce(context.Background()); err != nil {
		t.Fatalf("publishOnce(%s): %v", eventID, err)
	}
}

var daemonSnapshotTestArtifactBytes = []byte(
	"logical snapshot artifact fixture",
)

func daemonSnapshotTestBuild(
	ctx context.Context,
	initial store.InitialState,
	options snapshotbuilder.Options,
) (snapshotbuilder.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	digest := sha256.Sum256(daemonSnapshotTestArtifactBytes)
	descriptor := logicalsnapshot.ChunkDescriptor{
		ChunkIndex:       0,
		CompressedLength: uint64(len(daemonSnapshotTestArtifactBytes)),
		ExpandedLength:   uint64(len(daemonSnapshotTestArtifactBytes)),
		SHA256:           chain.Digest(digest),
	}
	if err := options.ChunkSink(
		ctx,
		descriptor,
		bytes.NewReader(daemonSnapshotTestArtifactBytes),
	); err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	page, err := logicalsnapshot.NewDescriptorPage(
		logicalsnapshot.DescriptorPageInput{
			ArtifactID:  options.ArtifactID,
			PageIndex:   0,
			Descriptors: []logicalsnapshot.ChunkDescriptor{descriptor},
		},
	)
	if err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	if err := options.PageSink(
		ctx,
		page,
		bytes.NewReader(page.CanonicalBytes()),
	); err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	unsigned, err := logicalsnapshot.NewUnsignedRoot(
		logicalsnapshot.RootInput{
			ArtifactID:        options.ArtifactID,
			SessionID:         initial.SessionID,
			WorkspaceID:       initial.WorkspaceID,
			CheckpointEventID: options.CheckpointEventID,
			ResultIndex:       1,
			AuthorityVersion:  1,
			SignerDeviceID:    options.SignerDeviceID,
			DigestVersion:     initial.DigestVersion,
			ProjectionSchemaVersion: initial.
				ProjectionSchemaVersion,
			ContentEncoding:         logicalsnapshot.EncodingIdentity,
			ExpandedBytes:           uint64(len(daemonSnapshotTestArtifactBytes)),
			CompressedBytes:         uint64(len(daemonSnapshotTestArtifactBytes)),
			RecordCount:             1,
			DescriptorPageCount:     1,
			ChunkCount:              1,
			ArtifactDigest:          chain.Digest(digest),
			FinalDescriptorPageHash: page.Hash(),
		},
	)
	if err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	root, err := options.SignRoot(ctx, unsigned)
	if err != nil {
		return snapshotbuilder.Snapshot{}, err
	}
	return snapshotbuilder.Snapshot{Root: root}, nil
}

func daemonSnapshotTestCheckpoint(
	t *testing.T,
	initial store.InitialState,
	deviceID domain.DeviceID,
	eventID domain.UUIDv7,
) store.CheckpointRecord {
	t.Helper()
	checkpoint := domain.Checkpoint{
		SessionID:                initial.SessionID,
		WorkspaceID:              initial.WorkspaceID,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		CoveredResultIndex:       1,
		DigestVersion:            initial.DigestVersion,
		ProjectionSchemaVersion:  initial.ProjectionSchemaVersion,
	}
	encoded, err := event.EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatalf("event.EncodeCheckpoint(): %v", err)
	}
	return store.CheckpointRecord{
		CheckpointEventID:        eventID,
		SessionID:                checkpoint.SessionID,
		WorkspaceID:              checkpoint.WorkspaceID,
		AuthorityVoterSetVersion: checkpoint.AuthorityVoterSetVersion,
		SignerDeviceID:           checkpoint.SignerDeviceID,
		Term:                     checkpoint.Term,
		CoveredAppliedLogIndex:   checkpoint.CoveredAppliedLogIndex,
		CoveredResultIndex:       checkpoint.CoveredResultIndex,
		DigestVersion:            checkpoint.DigestVersion,
		ProjectionSchemaVersion:  checkpoint.ProjectionSchemaVersion,
		CheckpointJSON:           encoded,
	}
}

func openDaemonSnapshotTestRepository(
	t *testing.T,
	statePath string,
	initial store.InitialState,
	deviceID domain.DeviceID,
	publicKey ed25519.PublicKey,
) *daemonLogicalSnapshotRepository {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("create snapshot test state directory: %v", err)
	}
	repository, err := openDaemonLogicalSnapshotRepository(
		context.Background(),
		statePath,
		initial.SessionID,
		initial.WorkspaceID,
		0,
		deviceID,
		publicKey,
	)
	if err != nil {
		t.Fatalf("openDaemonLogicalSnapshotRepository(): %v", err)
	}
	t.Cleanup(func() {
		if err := repository.Wait(); err != nil {
			t.Errorf("snapshot repository Wait(): %v", err)
		}
	})
	return repository
}

func waitForDaemonSnapshotCondition(
	t *testing.T,
	condition func() bool,
	message string,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var _ snapshotbuilder.RecordSource = daemonSnapshotRecordSourceStub{}
