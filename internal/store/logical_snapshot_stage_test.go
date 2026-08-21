package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
)

func TestLogicalSnapshotStageRebuildsAndFreezesVerifiedCut(t *testing.T) {
	fixture := newResultBatchAtomicityFixture(t)
	cut := exportLogicalSnapshotTestCut(t, fixture)
	stage := openLogicalSnapshotTestStage(t)

	initial, err := stage.Initialize(
		context.Background(),
		resultBatchInitialState(t, fixture.source.authorityDeviceID),
	)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	if initial != fixture.initial {
		t.Fatalf("initial heads = %+v, want %+v", initial, fixture.initial)
	}
	for index, command := range fixture.request.Commands {
		heads, err := stage.ImportCommand(context.Background(), command)
		if err != nil {
			t.Fatalf("ImportCommand(%d): %v", index, err)
		}
		if heads != command.Heads {
			t.Fatalf(
				"ImportCommand(%d) heads = %+v, want %+v",
				index,
				heads,
				command.Heads,
			)
		}
	}
	if err := stage.Verify(context.Background(), cut); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	view, err := stage.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	sourceView, err := fixture.source.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(source): %v", err)
	}
	if view.Heads != sourceView.Heads ||
		view.ProjectionStateDigest != sourceView.ProjectionStateDigest ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil {
		t.Fatalf("staged view = %+v, source = %+v", view, sourceView)
	}
	assertCounts(t, stage.store, map[string]int64{
		"events":                    2,
		"command_results":           3,
		"event_provenance":          0,
		"raft_command_applications": 0,
		"raft_snapshot_installs":    0,
		"replication_attestations":  0,
		"settled_nonvoter_state":    0,
		"chain_checkpoints":         1,
		"tasks":                     1,
		"leases":                    1,
	})
	if _, err := stage.ImportCommand(
		context.Background(),
		fixture.request.Commands[0],
	); !errors.Is(err, ErrLogicalSnapshotStageFinalized) {
		t.Fatalf(
			"ImportCommand(after verify) error = %v, want finalized",
			err,
		)
	}
	if _, err := stage.InstallSuccessor(
		context.Background(),
		SuccessorState{},
	); !errors.Is(err, ErrLogicalSnapshotStageFinalized) {
		t.Fatalf(
			"InstallSuccessor(after verify) error = %v, want finalized",
			err,
		)
	}
}

func TestLogicalSnapshotStageRollsBackOneCommandAndCanResume(t *testing.T) {
	fixture := newResultBatchAtomicityFixture(t)
	stage := openLogicalSnapshotTestStage(t)
	if _, err := stage.Initialize(
		context.Background(),
		resultBatchInitialState(t, fixture.source.authorityDeviceID),
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	if _, err := stage.ImportCommand(
		context.Background(),
		fixture.request.Commands[0],
	); err != nil {
		t.Fatalf("ImportCommand(first): %v", err)
	}
	firstView, err := stage.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	tampered := fixture.request.Commands[1]
	tampered.Mutations = []chain.Mutation{{
		Table:      "tasks",
		PrimaryKey: []byte(`{"task_id":"tampered"}`),
	}}
	if _, err := stage.ImportCommand(
		context.Background(),
		tampered,
	); !errors.Is(err, ErrInvalidLogicalSnapshotStage) {
		t.Fatalf("tampered ImportCommand() error = %v", err)
	}
	afterTamper, err := stage.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if afterTamper.Heads != firstView.Heads ||
		afterTamper.ProjectionStateDigest !=
			firstView.ProjectionStateDigest {
		t.Fatal("failed command changed the staged cut")
	}
	assertCounts(t, stage.store, map[string]int64{
		"command_results": 1,
		"events":          1,
		"tasks":           1,
	})

	if _, err := stage.ImportCommand(
		context.Background(),
		fixture.request.Commands[1],
	); err != nil {
		t.Fatalf("ImportCommand(second): %v", err)
	}
	secondView, err := stage.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected stage failure")
	stage.store.applyFailpoint = func(current applyStage) error {
		if current == applyAfterResult {
			return injected
		}
		return nil
	}
	if _, err := stage.ImportCommand(
		context.Background(),
		fixture.request.Commands[2],
	); !errors.Is(err, injected) {
		t.Fatalf("injected ImportCommand() error = %v", err)
	}
	stage.store.applyFailpoint = nil
	afterFailure, err := stage.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure.Heads != secondView.Heads ||
		afterFailure.ProjectionStateDigest !=
			secondView.ProjectionStateDigest {
		t.Fatal("failpoint changed the staged cut")
	}
	assertCounts(t, stage.store, map[string]int64{
		"command_results":   2,
		"chain_checkpoints": 0,
		"leases":            0,
	})
	if _, err := stage.ImportCommand(
		context.Background(),
		fixture.request.Commands[2],
	); err != nil {
		t.Fatalf("ImportCommand(resume): %v", err)
	}

	cut := exportLogicalSnapshotTestCut(t, fixture)
	wrong := cut
	wrong.ResultHash[0] ^= 0xff
	if err := stage.Verify(
		context.Background(),
		wrong,
	); !errors.Is(err, ErrInvalidLogicalSnapshotStage) {
		t.Fatalf("Verify(wrong cut) error = %v", err)
	}
	if err := stage.Verify(context.Background(), cut); err != nil {
		t.Fatalf("Verify(retry): %v", err)
	}
}

func TestOpenLogicalSnapshotStageRequiresUnusedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage", "state.db")
	first, err := OpenLogicalSnapshotStage(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenLogicalSnapshotStage(first): %v", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Errorf("Close(first): %v", err)
		}
	})
	if _, err := OpenLogicalSnapshotStage(
		context.Background(),
		path,
	); !errors.Is(err, ErrDatabaseExists) {
		t.Fatalf(
			"OpenLogicalSnapshotStage(existing) error = %v, want ErrDatabaseExists",
			err,
		)
	}
}

func TestVerifyCompleteLogicalSnapshotHistoryScansPredecessorGenerations(
	t *testing.T,
) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "history", "state.db"),
		nil,
	)
	initializeTestStore(t, database)
	fixture := newProjectionFixture(t)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections.Tasks = fixture.initialWrites.Tasks
	firstResult, err := database.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	second := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		firstResult.Heads,
	)
	secondResult, err := database.Apply(context.Background(), second)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	predecessorGenesis, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, domain.UUIDv7(testSessionID), 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	emptyDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.InstallSuccessor(
		context.Background(),
		SuccessorState{
			SessionID:          commitmentSuccessorSessionID,
			WorkspaceID:        testWorkspaceID,
			RecoveryGeneration: 1,
			GenesisJSON: commitmentSuccessorGenesisJSON(
				t,
				secondResult.Heads,
				predecessorGenesis,
				emptyDigest,
			),
			RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
			Predecessor:               secondResult.Heads,
			DigestVersion:             1,
			ProjectionSchemaVersion:   1,
		},
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}

	verify := func() error {
		return database.withConn(
			context.Background(),
			func(conn *sqlite.Conn) error {
				state, found, err := readConsensusState(conn)
				if err != nil {
					return err
				}
				if !found {
					return errors.New("consensus state is missing")
				}
				return verifyCompleteLogicalSnapshotHistory(conn, state)
			},
		)
	}
	if err := verify(); err != nil {
		t.Fatalf("verify complete history: %v", err)
	}
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE command_results
				    SET outcome_code = 'tampered'
				  WHERE result_index = 1;`,
			)
		},
	); err != nil {
		t.Fatalf("tamper predecessor result: %v", err)
	}
	if err := verify(); err == nil {
		t.Fatal("complete history verification ignored predecessor corruption")
	}
}

func openLogicalSnapshotTestStage(t *testing.T) *LogicalSnapshotStage {
	t.Helper()
	stage, err := OpenLogicalSnapshotStage(
		context.Background(),
		filepath.Join(t.TempDir(), "stage", "state.db"),
	)
	if err != nil {
		t.Fatalf("OpenLogicalSnapshotStage(): %v", err)
	}
	t.Cleanup(func() {
		if err := stage.Close(); err != nil {
			t.Errorf("Close(stage): %v", err)
		}
	})
	return stage
}

func exportLogicalSnapshotTestCut(
	t *testing.T,
	fixture resultBatchImportFixture,
) LogicalSnapshotCut {
	t.Helper()
	cut, err := fixture.source.store.ExportLogicalSnapshotRecords(
		context.Background(),
		LogicalSnapshotExportOptions{
			CheckpointEventID: testCheckpointEventID,
			SignerDeviceID:    fixture.source.authorityDeviceID,
		},
		func(context.Context, logicalsnapshot.Record) error {
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ExportLogicalSnapshotRecords(): %v", err)
	}
	return cut
}
