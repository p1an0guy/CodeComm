package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestVerifiedGenerationZeroViewRewindsExactInitialCut(t *testing.T) {
	t.Parallel()

	fixture := newResultBatchAtomicityFixture(t)
	got, err := fixture.source.store.VerifiedGenerationZeroView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedGenerationZeroView(): %v", err)
	}

	expectedStore := openTestStore(
		t,
		filepath.Join(t.TempDir(), "expected", "state.db"),
		nil,
	)
	initial := resultBatchInitialState(t, fixture.source.authorityDeviceID)
	expectedHeads, err := expectedStore.Initialize(
		context.Background(),
		initial,
	)
	if err != nil {
		t.Fatalf("Initialize(expected): %v", err)
	}
	expected, err := expectedStore.View(context.Background())
	if err != nil {
		t.Fatalf("View(expected): %v", err)
	}
	if got.SessionID != expected.SessionID ||
		got.WorkspaceID != expected.WorkspaceID ||
		got.RecoveryGeneration != 0 ||
		!reflect.DeepEqual(got.GenesisJSON, expected.GenesisJSON) ||
		got.Heads != expectedHeads ||
		got.Heads != expected.Heads ||
		got.ProjectionStateDigest != expected.ProjectionStateDigest ||
		!reflect.DeepEqual(got.ProjectionRows, expected.ProjectionRows) ||
		got.CurrentTerm != nil ||
		got.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"generation-zero view differs:\ngot=%+v\nwant=%+v",
			got,
			expected,
		)
	}
}

func TestVerifiedGenerationZeroViewUsesRetainedBoundaryAfterSuccessor(t *testing.T) {
	t.Parallel()

	database, _ := installHistoricalLogicalSnapshotFixture(t)
	view, err := database.VerifiedGenerationZeroView(context.Background())
	if err != nil {
		t.Fatalf(
			"VerifiedGenerationZeroView(successor): %v",
			err,
		)
	}
	if view.RecoveryGeneration != 0 ||
		view.SessionID != domain.UUIDv7(testSessionID) ||
		view.Heads.ChainIndex != 0 ||
		view.Heads.ResultIndex != 0 ||
		len(view.ProjectionRows) == 0 {
		t.Fatalf("retained generation-zero view = %+v", view)
	}
}

func TestVerifiedGenerationZeroViewRejectsTamperedRetainedBoundary(
	t *testing.T,
) {
	t.Parallel()

	database, _ := installHistoricalLogicalSnapshotFixture(t)
	err := database.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE initial_projection_rows
			    SET row_json = X'7b7d'
			  WHERE (table_index, primary_key) = (
			        SELECT table_index, primary_key
			          FROM initial_projection_rows
			         ORDER BY table_index, primary_key
			         LIMIT 1
			  );`,
		)
	})
	if err != nil {
		t.Fatalf("tamper retained boundary: %v", err)
	}
	if _, err := database.VerifiedGenerationZeroView(
		context.Background(),
	); err == nil {
		t.Fatal("tampered retained generation-zero boundary succeeded")
	}
}
