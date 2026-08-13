package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"zombiezen.com/go/sqlite"
)

const testSessionID = "01890f47-3e72-7000-8000-000000000002"

var requiredTables = []string{
	"activity",
	"agent_launches",
	"agent_resume_tokens",
	"agent_sessions",
	"audit_counters",
	"audit_events",
	"canonical_refs",
	"chain_checkpoints",
	"command_results",
	"consensus_state",
	"control_file_approvals",
	"control_file_proposals",
	"credential_authority",
	"credential_authorizations",
	"devices",
	"event_provenance",
	"events",
	"genesis_records",
	"git_artifacts",
	"lease_deadlines",
	"leases",
	"local_requests",
	"managed_roots",
	"memory_records",
	"merge_conflicts",
	"origin_counters",
	"origin_scopes",
	"outbox",
	"owner_recovery_challenges",
	"pairing_attempts",
	"pairing_invites",
	"pairing_secret_deletions",
	"peer_acks",
	"peer_endpoints",
	"plan_current",
	"plan_revisions",
	"publications",
	"raft_command_applications",
	"raft_snapshot_installs",
	"replication_attestations",
	"replication_cursors",
	"schema_migrations",
	"session_policy",
	"tasks",
	"voter_set",
}

func TestOpenConfiguresAndMigratesStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)

	if got := store.Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", info.Mode().Perm())
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && parentInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database parent mode = %04o, want no group/other access", parentInfo.Mode().Perm())
	}

	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(t, conn, "PRAGMA journal_mode;", "wal")
		assertIntQuery(t, conn, "PRAGMA synchronous;", 2)
		assertIntQuery(t, conn, "PRAGMA foreign_keys;", 1)
		assertIntQuery(t, conn, "PRAGMA busy_timeout;", 5000)
		assertIntQuery(t, conn, "PRAGMA trusted_schema;", 0)

		version := queryText(t, conn, "SELECT sqlite_version();")
		if compareSQLiteVersion(version, minimumSQLiteVersion) < 0 {
			t.Fatalf("SQLite version = %q, want >= %s", version, minimumSQLiteVersion)
		}

		gotTables := queryTextColumn(
			t,
			conn,
			"SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;",
		)
		if len(gotTables) != len(requiredTables) {
			t.Fatalf("table count = %d, want %d\ngot: %v", len(gotTables), len(requiredTables), gotTables)
		}
		for i := range requiredTables {
			if gotTables[i] != requiredTables[i] {
				t.Fatalf("table[%d] = %q, want %q", i, gotTables[i], requiredTables[i])
			}
		}

		type migrationRow struct {
			version  int64
			name     string
			checksum []byte
		}
		var migrations []migrationRow
		err := query(
			conn,
			"SELECT version, name, checksum FROM schema_migrations ORDER BY version;",
			func(stmt *sqlite.Stmt) {
				migrations = append(migrations, migrationRow{
					version:  stmt.ColumnInt64(0),
					name:     stmt.ColumnText(1),
					checksum: columnBytes(stmt, 2),
				})
			},
		)
		if err != nil {
			return err
		}
		wantNames := []string{"initial", "phase3_foundations"}
		if len(migrations) != len(wantNames) {
			t.Fatalf("migration count = %d, want %d", len(migrations), len(wantNames))
		}
		for index, row := range migrations {
			wantVersion := int64(index + 1)
			if row.version != wantVersion || row.name != wantNames[index] {
				t.Fatalf(
					"migration[%d] = (%d, %q), want (%d, %q)",
					index, row.version, row.name, wantVersion, wantNames[index],
				)
			}
			if !bytes.Equal(row.checksum, embeddedMigrations[index].checksum[:]) {
				t.Fatalf(
					"migration[%d] checksum = %x, want %x",
					index, row.checksum, embeddedMigrations[index].checksum,
				)
			}
		}

		if err := execute(conn, "PRAGMA writable_schema = ON;"); err != nil {
			return err
		}
		defer func() {
			if err := execute(conn, "PRAGMA writable_schema = OFF;"); err != nil {
				t.Errorf("disable writable_schema: %v", err)
			}
		}()
		err = execute(
			conn,
			`INSERT INTO sqlite_schema(type, name, tbl_name, rootpage, sql)
			 VALUES ('table', 'forbidden', 'forbidden', 0, 'CREATE TABLE forbidden(x)');`,
		)
		if err == nil {
			t.Fatal("defensive mode permitted a direct sqlite_schema write")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenIsIdempotentAndChecksMigrationChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)

	var firstAppliedAt string
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		firstAppliedAt = queryText(t, conn, "SELECT applied_at FROM schema_migrations WHERE version = 1;")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openTestStore(t, path, nil)
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		if got := queryText(t, conn, "SELECT applied_at FROM schema_migrations WHERE version = 1;"); got != firstAppliedAt {
			t.Fatalf("reopen changed applied_at from %q to %q", firstAppliedAt, got)
		}
		return execute(conn, "UPDATE schema_migrations SET checksum = zeroblob(32) WHERE version = 1;")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(context.Background(), Options{Path: path})
	if !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf("Open() after checksum corruption error = %v, want ErrMigrationChecksum", err)
	}
}

func TestMigrationFailureRollsBackOneMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)
	broken := migrationFromText(
		3,
		"broken",
		"CREATE TABLE rolled_back(value TEXT) STRICT; INSERT INTO missing_table VALUES (1);",
	)

	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return applyMigrations(conn, append(embeddedMigrations, broken), systemClock)
	})
	if err == nil {
		t.Fatal("applyMigrations() succeeded for a broken migration")
	}
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'rolled_back';",
			0,
		)
		assertIntQuery(t, conn, "SELECT count(*) FROM schema_migrations WHERE version = 3;", 0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsAppliedIndexAheadOfRaft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)
	initializeTestStore(t, store)
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE consensus_state
			    SET current_term = 2, last_raft_applied_log_index = 5
			  WHERE singleton = 1;`,
		)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(context.Background(), Options{
		Path:    path,
		RaftLog: fixedRaftLog{lastIndex: 4},
	})
	if !errors.Is(err, ErrRaftIndexAhead) {
		t.Fatalf("Open() error = %v, want ErrRaftIndexAhead", err)
	}

	for _, raftLog := range []RaftLog{
		fixedRaftLog{lastIndex: 5},
		nil,
	} {
		if _, err := Open(
			context.Background(),
			Options{Path: path, RaftLog: raftLog},
		); !errors.Is(err, ErrRaftCommandBinding) {
			t.Fatalf(
				"Open(inconsistent watermark) error = %v, want ErrRaftCommandBinding",
				err,
			)
		}
	}
}

func TestOpenRejectsCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Options{Path: path})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context.Canceled", err)
	}
}

func TestCloseIsConcurrentAndIdempotent(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	const goroutines = 32
	errs := make(chan error, goroutines)
	var group sync.WaitGroup
	group.Add(goroutines)
	for range goroutines {
		go func() {
			defer group.Done()
			errs <- store.Close()
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}

	err := store.withConn(context.Background(), func(*sqlite.Conn) error { return nil })
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("operation after Close() error = %v, want ErrClosed", err)
	}
}

func TestOpenDatabaseFileSyncsParentOnlyOnCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	var synced []string
	syncFn := func(path string) error {
		synced = append(synced, path)
		return nil
	}
	created, err := openDatabaseFile(path, syncFn)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("openDatabaseFile() created = false, want true")
	}
	if len(synced) != 1 || synced[0] != filepath.Dir(path) {
		t.Fatalf("synced directories = %v, want [%q]", synced, filepath.Dir(path))
	}

	synced = nil
	created, err = openDatabaseFile(path, syncFn)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second openDatabaseFile() created = true, want false")
	}
	if len(synced) != 0 {
		t.Fatalf("second open synced directories = %v, want none", synced)
	}
}

func openTestStore(t *testing.T, path string, raftLog RaftLog) *Store {
	t.Helper()
	store, err := Open(context.Background(), Options{Path: path, RaftLog: raftLog})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return store
}

func queryText(t *testing.T, conn *sqlite.Conn, statement string) string {
	t.Helper()
	var value string
	if err := queryOne(conn, statement, func(stmt *sqlite.Stmt) {
		value = stmt.ColumnText(0)
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

func queryTextColumn(t *testing.T, conn *sqlite.Conn, statement string) []string {
	t.Helper()
	var values []string
	if err := query(conn, statement, func(stmt *sqlite.Stmt) {
		values = append(values, stmt.ColumnText(0))
	}); err != nil {
		t.Fatal(err)
	}
	return values
}

func assertTextQuery(t *testing.T, conn *sqlite.Conn, statement, want string) {
	t.Helper()
	if got := queryText(t, conn, statement); got != want {
		t.Fatalf("%s = %q, want %q", statement, got, want)
	}
}

func assertIntQuery(t *testing.T, conn *sqlite.Conn, statement string, want int64) {
	t.Helper()
	var got int64
	if err := queryOne(conn, statement, func(stmt *sqlite.Stmt) {
		got = stmt.ColumnInt64(0)
	}); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s = %d, want %d", statement, got, want)
	}
}

type fixedRaftLog struct {
	lastIndex uint64
	err       error
}

func (log fixedRaftLog) LastIndex() (uint64, error) {
	return log.lastIndex, log.err
}
