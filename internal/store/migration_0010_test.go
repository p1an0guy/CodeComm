package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestMigration0010FreshAndV9UpgradeBackfill(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		conn := openMigrationTestConnection(t)
		if err := applyMigrations(
			conn,
			embeddedMigrations,
			fixedMigrationTestClock,
		); err != nil {
			t.Fatalf("apply fresh migrations: %v", err)
		}
		assertIntQuery(
			t,
			conn,
			`SELECT count(*) FROM sqlite_schema
			  WHERE type = 'table'
			    AND name = 'checkpoint_cadence_state';`,
			1,
		)
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM checkpoint_cadence_state;",
			0,
		)
		assertIntQuery(
			t,
			conn,
			`SELECT count(*) FROM schema_migrations
			  WHERE version = 10 AND name = 'checkpoint_cadence';`,
			1,
		)
	})

	for _, test := range []struct {
		name       string
		checkpoint bool
	}{
		{name: "generation boundary"},
		{name: "latest checkpoint", checkpoint: true},
	} {
		t.Run("v9 upgrade/"+test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session", "state.db")
			database := openTestStore(t, path, nil)
			heads := initializeCheckpointCadenceTestStore(t, database)
			checkpointEventID := domain.UUIDv7("")
			if test.checkpoint {
				result := applyCheckpointCadenceTestCheckpoint(
					t,
					database,
					heads,
				)
				heads = result.Heads
				checkpointEventID = testCheckpointEventID
			}

			v9AppliedAt := downgradeCheckpointCadenceTestStoreToV9(
				t,
				database,
			)
			if err := database.Close(); err != nil {
				t.Fatalf("Close(v9 store): %v", err)
			}
			reopened, err := Open(
				context.Background(),
				Options{Path: path},
			)
			if err != nil {
				t.Fatalf("Open(v9 upgrade): %v", err)
			}
			t.Cleanup(func() {
				if err := reopened.Close(); err != nil {
					t.Errorf("Close(upgraded store): %v", err)
				}
			})

			values := checkpointCadenceTestPolicyValues()
			assertCheckpointCadence(
				t,
				reopened,
				CheckpointCadence{
					SessionID:                 domain.UUIDv7(testSessionID),
					WorkspaceID:               testWorkspaceID,
					RecoveryGeneration:        0,
					HeadChainIndex:            heads.ChainIndex,
					HeadResultIndex:           heads.ResultIndex,
					CheckpointEventID:         checkpointEventID,
					BaselineChainIndex:        heads.ChainIndex,
					BaselineResultIndex:       heads.ResultIndex,
					BaselineObservedAt:        v9AppliedAt,
					CheckpointEvents:          values.CheckpointEvents,
					CheckpointIntervalSeconds: values.CheckpointIntervalSeconds,
				},
			)
		})
	}
}

func downgradeCheckpointCadenceTestStoreToV9(
	t *testing.T,
	database *Store,
) domain.Timestamp {
	t.Helper()
	var appliedAt domain.Timestamp
	err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			if err := downgradeCommandResultPayloadsForTest(conn); err != nil {
				return err
			}
			if err := queryOne(
				conn,
				`SELECT applied_at FROM schema_migrations
				  WHERE version = 9;`,
				func(stmt *sqlite.Stmt) {
					appliedAt = domain.Timestamp(stmt.ColumnText(0))
				},
			); err != nil {
				return err
			}
			if err := execute(
				conn,
				"DROP TABLE checkpoint_cadence_state;",
			); err != nil {
				return err
			}
			return execute(
				conn,
				"DELETE FROM schema_migrations WHERE version = 10;",
			)
		},
	)
	if err != nil {
		t.Fatalf("restore v9 schema: %v", err)
	}
	if !appliedAt.Valid() {
		t.Fatalf("invalid v9 migration time %q", appliedAt)
	}
	return appliedAt
}
