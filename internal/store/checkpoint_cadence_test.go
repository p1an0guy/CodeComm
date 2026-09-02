package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"zombiezen.com/go/sqlite"
)

func TestCheckpointCadenceBoundaryApplyCheckpointAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	initialHeads := initializeCheckpointCadenceTestStore(t, database)
	values := checkpointCadenceTestPolicyValues()
	migrationObservedAt := checkpointCadenceMigrationTime(
		t,
		database,
		10,
	)

	boundary := CheckpointCadence{
		SessionID:                 domain.UUIDv7(testSessionID),
		WorkspaceID:               testWorkspaceID,
		RecoveryGeneration:        0,
		HeadChainIndex:            initialHeads.ChainIndex,
		HeadResultIndex:           initialHeads.ResultIndex,
		BaselineChainIndex:        initialHeads.ChainIndex,
		BaselineResultIndex:       initialHeads.ResultIndex,
		BaselineObservedAt:        migrationObservedAt,
		CheckpointEvents:          values.CheckpointEvents,
		CheckpointIntervalSeconds: values.CheckpointIntervalSeconds,
	}
	assertCheckpointCadence(t, database, boundary)

	ordinary, err := database.Apply(
		context.Background(),
		acceptedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID, 1),
		),
	)
	if err != nil {
		t.Fatalf("Apply(ordinary): %v", err)
	}
	afterOrdinary := boundary
	afterOrdinary.HeadChainIndex = ordinary.Heads.ChainIndex
	afterOrdinary.HeadResultIndex = ordinary.Heads.ResultIndex
	assertCheckpointCadence(t, database, afterOrdinary)

	checkpointAppliedAt := domain.Timestamp("2026-08-10T12:00:01Z")
	checkpointRequest := nextCheckpointApplyRequest(
		t,
		ordinary.Heads,
		testCheckpointEventID,
		1,
		2,
		checkpointAppliedAt,
	)
	checkpoint, err := database.Apply(
		context.Background(),
		checkpointRequest,
	)
	if err != nil {
		t.Fatalf("Apply(checkpoint): %v", err)
	}
	afterCheckpoint := afterOrdinary
	afterCheckpoint.HeadChainIndex = checkpoint.Heads.ChainIndex
	afterCheckpoint.HeadResultIndex = checkpoint.Heads.ResultIndex
	afterCheckpoint.CheckpointEventID = testCheckpointEventID
	afterCheckpoint.BaselineChainIndex = checkpoint.Heads.ChainIndex
	afterCheckpoint.BaselineResultIndex = checkpoint.Heads.ResultIndex
	afterCheckpoint.BaselineObservedAt = checkpointAppliedAt
	assertCheckpointCadence(t, database, afterCheckpoint)

	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(reopen): %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	})
	assertCheckpointCadence(t, reopened, afterCheckpoint)
}

func TestCheckpointCadenceRejectsCorruptionOnReadAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	heads := initializeCheckpointCadenceTestStore(t, database)
	applyCheckpointCadenceTestCheckpoint(t, database, heads)
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE checkpoint_cadence_state
				    SET checkpoint_event_id = NULL,
				        baseline_chain_index = 0,
				        baseline_result_index = 0;`,
			)
		},
	); err != nil {
		t.Fatalf("corrupt cadence baseline: %v", err)
	}

	if _, err := database.LocalState().CheckpointCadence(
		context.Background(),
	); !errors.Is(err, ErrCheckpointCadenceIntegrity) {
		t.Fatalf(
			"CheckpointCadence(corrupt) error = %v, want integrity failure",
			err,
		)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(corrupt): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrCheckpointCadenceIntegrity) {
		t.Fatalf(
			"Open(corrupt cadence) error = %v, want integrity failure",
			err,
		)
	}
}

func TestCheckpointCadenceSuccessorResetsToBoundary(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := checkpointCadenceTestInitialState(
		t,
		domain.UUIDv7(testSessionID),
	)
	initialHeads, err := database.Initialize(context.Background(), initial)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	checkpoint := applyCheckpointCadenceTestCheckpoint(
		t,
		database,
		initialHeads,
	)

	values := checkpointCadenceTestPolicyValues()
	successorProjections := ProjectionWrites{
		SessionPolicy: []policy.Policy{{
			SessionID:     commitmentSuccessorSessionID,
			Values:        values,
			EntityVersion: 1,
		}},
	}
	predecessorGenesisDigest, err := chain.GenesisDigest(
		initial.GenesisJSON,
	)
	if err != nil {
		t.Fatalf("GenesisDigest(predecessor): %v", err)
	}
	successorObservedAt := domain.Timestamp("2026-08-10T12:00:02Z")
	successor := SuccessorState{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		GenesisJSON: commitmentSuccessorGenesisJSON(
			t,
			checkpoint.Heads,
			Digest(predecessorGenesisDigest),
			projectionWritesDigest(t, successorProjections),
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		ObservedAt:                successorObservedAt,
		Predecessor:               checkpoint.Heads,
		Projections:               successorProjections,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	successorHeads, err := database.InstallSuccessor(
		context.Background(),
		successor,
	)
	if err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}

	assertCheckpointCadence(
		t,
		database,
		CheckpointCadence{
			SessionID:                 commitmentSuccessorSessionID,
			WorkspaceID:               testWorkspaceID,
			RecoveryGeneration:        1,
			HeadChainIndex:            successorHeads.ChainIndex,
			HeadResultIndex:           successorHeads.ResultIndex,
			BaselineChainIndex:        successorHeads.ChainIndex,
			BaselineResultIndex:       successorHeads.ResultIndex,
			BaselineObservedAt:        successorObservedAt,
			CheckpointEvents:          values.CheckpointEvents,
			CheckpointIntervalSeconds: values.CheckpointIntervalSeconds,
		},
	)
}

func TestCheckpointCadenceLogicalSnapshotUsesReceiverLocalBaseline(
	t *testing.T,
) {
	fixture, stage, _, cut := logicalSnapshotInstallFixture(t)
	sourceCadence := readCheckpointCadenceTest(t, fixture.source.store)
	installedAt := domain.Timestamp("2026-08-20T01:00:02Z")
	options := logicalSnapshotInstallOptions(installedAt)
	options.VerifiedAt = "2026-08-20T01:00:01Z"
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		options,
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	if sourceCadence.BaselineObservedAt == installedAt ||
		options.VerifiedAt == installedAt {
		t.Fatal("test timestamps do not distinguish source and receiver state")
	}

	values := policy.DefaultValues()
	assertCheckpointCadence(
		t,
		fixture.target,
		CheckpointCadence{
			SessionID:                 cut.SessionID,
			WorkspaceID:               cut.WorkspaceID,
			RecoveryGeneration:        cut.RecoveryGeneration,
			HeadChainIndex:            installed.Heads.ChainIndex,
			HeadResultIndex:           installed.Heads.ResultIndex,
			CheckpointEventID:         cut.CheckpointEventID,
			BaselineChainIndex:        cut.ChainIndex,
			BaselineResultIndex:       cut.ResultIndex,
			BaselineObservedAt:        installedAt,
			CheckpointEvents:          values.CheckpointEvents,
			CheckpointIntervalSeconds: values.CheckpointIntervalSeconds,
		},
	)
}

func initializeCheckpointCadenceTestStore(
	t *testing.T,
	database *Store,
) ApplyHeads {
	t.Helper()
	heads, err := database.Initialize(
		context.Background(),
		checkpointCadenceTestInitialState(
			t,
			domain.UUIDv7(testSessionID),
		),
	)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	return heads
}

func applyCheckpointCadenceTestCheckpoint(
	t *testing.T,
	database *Store,
	initialHeads ApplyHeads,
) ApplyResult {
	t.Helper()
	ordinary, err := database.Apply(
		context.Background(),
		acceptedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID, 1),
		),
	)
	if err != nil {
		t.Fatalf("Apply(ordinary): %v", err)
	}
	if ordinary.Heads.ChainIndex != initialHeads.ChainIndex+1 ||
		ordinary.Heads.ResultIndex != initialHeads.ResultIndex+1 {
		t.Fatalf(
			"ordinary heads = %+v, want successor of %+v",
			ordinary.Heads,
			initialHeads,
		)
	}
	request := nextCheckpointApplyRequest(
		t,
		ordinary.Heads,
		testCheckpointEventID,
		1,
		2,
		"2026-08-10T12:00:01Z",
	)
	checkpoint, err := database.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply(checkpoint): %v", err)
	}
	return checkpoint
}

func checkpointCadenceTestInitialState(
	t *testing.T,
	sessionID domain.UUIDv7,
) InitialState {
	t.Helper()
	return commitmentInitialState(
		t,
		sessionID,
		0,
		ProjectionWrites{
			SessionPolicy: []policy.Policy{{
				SessionID:     sessionID,
				Values:        checkpointCadenceTestPolicyValues(),
				EntityVersion: 1,
			}},
		},
	)
}

func checkpointCadenceTestPolicyValues() policy.Values {
	values := policy.DefaultValues()
	values.CheckpointEvents = 321
	values.CheckpointIntervalSeconds = 123
	return values
}

func checkpointCadenceMigrationTime(
	t *testing.T,
	database *Store,
	version int64,
) domain.Timestamp {
	t.Helper()
	var result domain.Timestamp
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOneArgs(
				conn,
				`SELECT applied_at FROM schema_migrations
				  WHERE version = ?1;`,
				[]any{version},
				func(stmt *sqlite.Stmt) {
					result = domain.Timestamp(stmt.ColumnText(0))
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("read migration %d time: %v", version, err)
	}
	if !result.Valid() {
		t.Fatalf("invalid migration %d time %q", version, result)
	}
	return result
}

func readCheckpointCadenceTest(
	t *testing.T,
	database *Store,
) CheckpointCadence {
	t.Helper()
	got, err := database.LocalState().CheckpointCadence(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("CheckpointCadence(): %v", err)
	}
	return got
}

func assertCheckpointCadence(
	t *testing.T,
	database *Store,
	want CheckpointCadence,
) {
	t.Helper()
	if got := readCheckpointCadenceTest(t, database); got != want {
		t.Fatalf("CheckpointCadence() = %+v, want %+v", got, want)
	}
}
