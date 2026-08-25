package consensus

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/store"
)

func TestGenerationZeroBoundaryVerifierStagesMatchingArtifact(t *testing.T) {
	fixture := newLogicalSnapshotImportFixture(t)
	source, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "boundary", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if _, err := source.Initialize(
		context.Background(),
		fixture.initial,
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	verifier, err := NewGenerationZeroBoundaryVerifier(source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(): %v", err)
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
	view, err := verified.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.SessionID != fixture.sourceView.SessionID ||
		view.WorkspaceID != fixture.sourceView.WorkspaceID ||
		view.RecoveryGeneration != 0 ||
		view.Heads != fixture.sourceView.Heads ||
		view.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatalf(
			"verified view differs:\ngot=%+v\nwant=%+v",
			view,
			fixture.sourceView,
		)
	}
}

func TestGenerationZeroBoundaryVerifierRejectsLegacySuccessorArtifact(
	t *testing.T,
) {
	fixture, _, _ := newLogicalSnapshotSuccessorFixture(t)
	source, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "boundary", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if _, err := source.Initialize(
		context.Background(),
		fixture.initial,
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	verifier, err := NewGenerationZeroBoundaryVerifier(source)
	if err != nil {
		t.Fatalf("NewGenerationZeroBoundaryVerifier(): %v", err)
	}

	if _, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, verifier),
	); !errors.Is(err, ErrLogicalSnapshotSuccessorBoundaryInvalid) {
		t.Fatalf(
			"VerifyAndStageLogicalSnapshot(successor) error = %v, want %v",
			err,
			ErrLogicalSnapshotSuccessorBoundaryInvalid,
		)
	}
}

func TestNewGenerationZeroBoundaryVerifierRejectsNil(t *testing.T) {
	if _, err := NewGenerationZeroBoundaryVerifier(
		(*store.Store)(nil),
	); !errors.Is(err, ErrLogicalSnapshotBoundaryUnavailable) {
		t.Fatalf(
			"NewGenerationZeroBoundaryVerifier(nil) error = %v",
			err,
		)
	}
}
