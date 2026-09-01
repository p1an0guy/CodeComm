package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestMigration0008FreshUpgradeAndLedgerBehavior(t *testing.T) {
	t.Parallel()

	fresh := openMigrationTestConnection(t)
	if err := applyMigrations(
		fresh,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply fresh migrations: %v", err)
	}
	wantSchema := migration0008Schema(t, fresh)
	assertMigration0008Ledger(t, fresh)
	assertMigration0008NoArtifacts(t, fresh)

	upgraded := openMigrationTestConnection(t)
	if err := applyMigrations(
		upgraded,
		embeddedMigrations[:7],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v7 migrations: %v", err)
	}
	initializeMigrationV7GenerationZero(
		t,
		upgraded,
		domain.UUIDv7(testSessionID),
		ProjectionWrites{
			SessionPolicy: newProjectionFixture(t).
				initialWrites.SessionPolicy,
		},
	)
	if err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("upgrade v7 to v8: %v", err)
	}
	if got := migration0008Schema(t, upgraded); !bytes.Equal(got, wantSchema) {
		t.Fatalf(
			"v7 upgrade schema differs from fresh v8\n got:\n%s\nwant:\n%s",
			got,
			wantSchema,
		)
	}
	assertIntQuery(
		t,
		upgraded,
		"SELECT count(*) FROM initial_projection_boundary;",
		1,
	)
	assertIntQuery(
		t,
		upgraded,
		"SELECT count(*) FROM initial_projection_rows;",
		1,
	)
	assertMigration0008Ledger(t, upgraded)
	assertMigration0008NoArtifacts(t, upgraded)

	if err := execute(
		fresh,
		`UPDATE schema_migrations
		    SET checksum = zeroblob(32)
		  WHERE version = 8;`,
	); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(
		fresh,
		embeddedMigrations,
		fixedMigrationTestClock,
	); !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf(
			"migration with changed v8 checksum error = %v, want ErrMigrationChecksum",
			err,
		)
	}

	if err := execute(
		upgraded,
		"DELETE FROM schema_migrations WHERE version = 8;",
	); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err == nil {
		t.Fatal("migration with missing v8 ledger succeeded over existing schema")
	}
	assertIntQuery(
		t,
		upgraded,
		"SELECT count(*) FROM schema_migrations WHERE version = 8;",
		0,
	)
	if got := migration0008Schema(t, upgraded); !bytes.Equal(got, wantSchema) {
		t.Fatalf(
			"ledger rejection changed v8 schema\n got:\n%s\nwant:\n%s",
			got,
			wantSchema,
		)
	}
	assertMigration0008NoArtifacts(t, upgraded)
}

func TestMigration0008RejectsRecoveredV7WithoutInitialBoundary(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations[:7],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v7 migrations: %v", err)
	}
	initializeMigrationV7GenerationZero(
		t,
		conn,
		domain.UUIDv7("01890f47-3e72-7000-8000-000000000080"),
		ProjectionWrites{},
	)
	if err := execute(
		conn,
		`UPDATE consensus_state
		    SET session_id = '01890f47-3e72-7000-8000-000000000081',
		        recovery_generation = 1
		  WHERE singleton = 1;`,
	); err != nil {
		t.Fatalf("mark v7 store recovered: %v", err)
	}

	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); !errors.Is(err, ErrGenerationZeroStateUnavailable) {
		t.Fatalf(
			"recovered v7 migration error = %v, want generation-zero refusal",
			err,
		)
	}
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM schema_migrations WHERE version = 8;",
		0,
	)
	for _, table := range []string{
		"initial_projection_boundary",
		"initial_projection_rows",
	} {
		exists, err := tableExists(conn, table)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("failed migration retained table %q", table)
		}
	}
	assertIntQuery(
		t,
		conn,
		`SELECT count(*) FROM sqlite_schema
		  WHERE name = 'audit_events_recovery_boundary_session';`,
		0,
	)
}

func TestMigration0008ChecksumBindsPostSQLHook(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply current migrations: %v", err)
	}
	changed := append([]migration(nil), embeddedMigrations...)
	changed[7] = bindMigrationPostSQL(
		changed[7],
		"retain_initial_projection_boundary/v2",
		retainInitialProjectionBoundaryMigrationDigest,
		retainInitialProjectionBoundaryMigration,
	)
	if changed[7].checksum == embeddedMigrations[7].checksum {
		t.Fatal("post-SQL hook identity did not change the migration checksum")
	}
	if err := applyMigrations(
		conn,
		changed,
		fixedMigrationTestClock,
	); !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf(
			"changed post-SQL hook error = %v, want ErrMigrationChecksum",
			err,
		)
	}
}

func TestMigration0008ChecksumBindsPostSQLImplementation(t *testing.T) {
	t.Parallel()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration test source")
	}
	source, err := os.ReadFile(
		filepath.Join(filepath.Dir(testFile), "initial_projection_boundary.go"),
	)
	if err != nil {
		t.Fatalf("read post-SQL implementation source: %v", err)
	}
	digest := sha256.Sum256(source)
	want, err := hex.DecodeString(
		retainInitialProjectionBoundaryMigrationDigest,
	)
	if err != nil {
		t.Fatalf("decode bound implementation digest: %v", err)
	}
	if !bytes.Equal(digest[:], want) {
		t.Fatalf(
			"migration 0008 post-SQL source digest = %x, want %x; "+
				"review the change and update the bound digest",
			digest,
			want,
		)
	}

	changed := append([]migration(nil), embeddedMigrations...)
	changed[7] = bindMigrationPostSQL(
		changed[7],
		changed[7].postSQLID,
		"0000000000000000000000000000000000000000000000000000000000000000",
		retainInitialProjectionBoundaryMigration,
	)
	if changed[7].checksum == embeddedMigrations[7].checksum {
		t.Fatal("post-SQL implementation digest did not change the checksum")
	}
}

func TestMigrationPolicyRequiresReviewOrVerifiedBackup(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply current migrations: %v", err)
	}
	nextVersion := int64(len(embeddedMigrations) + 1)
	unclassified := migrationFromText(
		nextVersion,
		"unclassified",
		"CREATE TABLE unclassified_migration(value INTEGER) STRICT;",
	)
	if err := applyMigrations(
		conn,
		append(embeddedMigrations, unclassified),
		fixedMigrationTestClock,
	); !errors.Is(err, errMigrationUnclassified) {
		t.Fatalf("unclassified migration error = %v", err)
	}
	assertMigrationTableAbsent(
		t,
		conn,
		"unclassified_migration",
		nextVersion,
	)

	irreversible := migrationFromText(
		nextVersion,
		"irreversible",
		"CREATE TABLE backed_up_migration(value INTEGER) STRICT;",
	)
	irreversible.policy = migrationPolicyRequiresVerifiedBackup
	migrations := append(embeddedMigrations, irreversible)
	if err := applyMigrations(
		conn,
		migrations,
		fixedMigrationTestClock,
	); !errors.Is(err, errMigrationBackupRequired) {
		t.Fatalf("migration without backup error = %v", err)
	}
	assertMigrationTableAbsent(
		t,
		conn,
		"backed_up_migration",
		nextVersion,
	)

	backupErr := errors.New("backup verification failed")
	if err := applyMigrationsWithBackup(
		conn,
		migrations,
		fixedMigrationTestClock,
		func(*sqlite.Conn, migration) error {
			return backupErr
		},
	); !errors.Is(err, errMigrationBackupRequired) ||
		!errors.Is(err, backupErr) {
		t.Fatalf("failed backup verification error = %v", err)
	}
	assertMigrationTableAbsent(
		t,
		conn,
		"backed_up_migration",
		nextVersion,
	)

	var verified migration
	if err := applyMigrationsWithBackup(
		conn,
		migrations,
		fixedMigrationTestClock,
		func(_ *sqlite.Conn, candidate migration) error {
			verified = candidate
			return nil
		},
	); err != nil {
		t.Fatalf("migration with verified backup: %v", err)
	}
	if verified.version != irreversible.version ||
		verified.name != irreversible.name ||
		verified.checksum != irreversible.checksum {
		t.Fatalf("verified migration = %+v, want %+v", verified, irreversible)
	}
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM schema_migrations WHERE version = "+
			strconv.FormatInt(nextVersion, 10)+";",
		1,
	)
}

func TestMigration0008RecoveryBoundaryConstraints(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	insert := func(
		sessionID string,
		eventID any,
		actionCode string,
	) error {
		return execute(
			conn,
			`INSERT INTO audit_events(
			    session_id, source_kind, event_id, actor_type, ipc_channel,
			    action_code, outcome_code, subject, details_json,
			    first_seen_at, last_seen_at, observation_count
			) VALUES (
			    ?1, 'recovery_boundary', ?2, 'human', 'operator',
			    ?3, 'accepted', 'session:test',
			    '{"genesis_digest":"test","recovery_generation":1}',
			    '2026-08-21T00:00:00Z', '2026-08-21T00:00:00Z', 1
			);`,
			sessionID,
			eventID,
			actionCode,
		)
	}
	if err := insert(
		"01890f47-3e72-7000-8000-000000000081",
		nil,
		"cluster.quorum_recovered",
	); err != nil {
		t.Fatalf("insert valid recovery boundary: %v", err)
	}
	if err := insert(
		"01890f47-3e72-7000-8000-000000000081",
		nil,
		"cluster.quorum_recovered",
	); err == nil {
		t.Fatal("duplicate recovery boundary session succeeded")
	}
	if err := insert(
		"01890f47-3e72-7000-8000-000000000082",
		"01890f47-3e72-7000-8000-000000000083",
		"cluster.quorum_recovered",
	); err == nil {
		t.Fatal("recovery boundary with event ID succeeded")
	}
	if err := insert(
		"01890f47-3e72-7000-8000-000000000084",
		nil,
		"cluster.recovered",
	); err == nil {
		t.Fatal("recovery boundary with another action succeeded")
	}
	if err := execute(
		conn,
		`INSERT INTO audit_events(
		    session_id, source_kind, event_id, result_index, ipc_channel,
		    action_code, outcome_code, subject, details_json,
		    first_seen_at, last_seen_at, observation_count
		) VALUES (
		    '01890f47-3e72-7000-8000-000000000085',
		    'local_aggregate',
		    '01890f47-3e72-7000-8000-000000000086',
		    NULL, 'daemon', 'alarm.conflict_integrity', 'rejected',
		    'conflict:test', '{"class":"conflict_integrity"}',
		    '2026-08-21T00:00:00Z', '2026-08-21T00:00:00Z', 1
		);`,
	); err == nil {
		t.Fatal("partially bound local aggregate succeeded")
	}
}

func TestMigration0008InitialProjectionBoundaryConstraints(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := execute(
		conn,
		`INSERT INTO initial_projection_boundary(
		    singleton, digest_version, projection_schema_version,
		    projection_state_digest, row_count
		) VALUES (1, 1, 1, zeroblob(32), 0);`,
	); err != nil {
		t.Fatalf("insert valid projection boundary: %v", err)
	}
	for name, statement := range map[string]string{
		"duplicate singleton": `INSERT INTO initial_projection_boundary(
		    singleton, digest_version, projection_schema_version,
		    projection_state_digest, row_count
		) VALUES (1, 1, 1, zeroblob(32), 0);`,
		"invalid singleton": `INSERT INTO initial_projection_boundary(
		    singleton, digest_version, projection_schema_version,
		    projection_state_digest, row_count
		) VALUES (2, 1, 1, zeroblob(32), 0);`,
		"zero digest version": `UPDATE initial_projection_boundary
		    SET digest_version = 0 WHERE singleton = 1;`,
		"zero projection version": `UPDATE initial_projection_boundary
		    SET projection_schema_version = 0 WHERE singleton = 1;`,
		"short digest": `UPDATE initial_projection_boundary
		    SET projection_state_digest = zeroblob(31)
		  WHERE singleton = 1;`,
		"negative row count": `UPDATE initial_projection_boundary
		    SET row_count = -1 WHERE singleton = 1;`,
	} {
		if err := execute(conn, statement); err == nil {
			t.Fatalf("%s succeeded", name)
		}
	}

	if err := execute(
		conn,
		`INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (0, 'agent_sessions', X'7b7d', X'7b7d');`,
	); err != nil {
		t.Fatalf("insert valid projection row: %v", err)
	}
	for name, statement := range map[string]string{
		"duplicate key": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (0, 'agent_sessions', X'7b7d', X'7b7d');`,
		"table index too large": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (64, 'agent_sessions', X'7b7e', X'7b7d');`,
		"invalid table name": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (1, 'AgentSessions', X'7b7e', X'7b7d');`,
		"short primary key": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (1, 'tasks', X'7b', X'7b7d');`,
		"short row": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (1, 'tasks', X'7b7e', X'7b');`,
		"duplicate table key": `INSERT INTO initial_projection_rows(
		    table_index, table_name, primary_key, row_json
		) VALUES (1, 'agent_sessions', X'7b7d', X'7b7d');`,
	} {
		if err := execute(conn, statement); err == nil {
			t.Fatalf("%s succeeded", name)
		}
	}
}

func migration0008Schema(t *testing.T, conn *sqlite.Conn) []byte {
	t.Helper()
	var result []byte
	if err := query(
		conn,
		`SELECT type, name, sql
		   FROM sqlite_schema
		  WHERE name = 'audit_events'
		     OR name LIKE 'audit_events_%'
		     OR name = 'initial_projection_boundary'
		     OR name = 'initial_projection_rows'
		  ORDER BY type, name;`,
		func(stmt *sqlite.Stmt) {
			result = append(result, stmt.ColumnText(0)...)
			result = append(result, 0)
			result = append(result, stmt.ColumnText(1)...)
			result = append(result, 0)
			result = append(result, stmt.ColumnText(2)...)
			result = append(result, '\n')
		},
	); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertMigration0008Ledger(t *testing.T, conn *sqlite.Conn) {
	t.Helper()
	var (
		name     string
		checksum []byte
	)
	if err := queryOne(
		conn,
		`SELECT name, checksum
		   FROM schema_migrations
		  WHERE version = 8;`,
		func(stmt *sqlite.Stmt) {
			name = stmt.ColumnText(0)
			checksum = bytes.Clone(columnBytes(stmt, 1))
		},
	); err != nil {
		t.Fatal(err)
	}
	if name != "recovery_boundary_audit" ||
		!bytes.Equal(checksum, embeddedMigrations[7].checksum[:]) {
		t.Fatalf(
			"migration 8 ledger = (%q, %x), want (%q, %x)",
			name,
			checksum,
			"recovery_boundary_audit",
			embeddedMigrations[7].checksum,
		)
	}
}

func assertMigration0008NoArtifacts(t *testing.T, conn *sqlite.Conn) {
	t.Helper()
	assertIntQuery(
		t,
		conn,
		`SELECT count(*)
		   FROM sqlite_schema
		  WHERE name IN (
		      'migration_0008_schema_guard',
		      'audit_events_legacy'
		  );`,
		0,
	)
}

func assertMigrationTableAbsent(
	t *testing.T,
	conn *sqlite.Conn,
	name string,
	version int64,
) {
	t.Helper()
	exists, err := tableExists(conn, name)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("migration created table %q before satisfying policy", name)
	}
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM schema_migrations WHERE version = "+
			strconv.FormatInt(version, 10)+";",
		0,
	)
}

func initializeMigrationV7GenerationZero(
	t *testing.T,
	conn *sqlite.Conn,
	sessionID domain.UUIDv7,
	projections ProjectionWrites,
) {
	t.Helper()
	initial := commitmentInitialState(
		t,
		sessionID,
		0,
		projections,
	)
	prepared, err := prepareProjectionWrites(projections)
	if err != nil {
		t.Fatalf("prepare v7 initial projections: %v", err)
	}
	if err := writePreparedProjections(conn, prepared); err != nil {
		t.Fatalf("write v7 initial projections: %v", err)
	}
	stateDigest, err := projectionStateDigest(conn, chain.Versions{
		Digest:           initial.DigestVersion,
		ProjectionSchema: initial.ProjectionSchemaVersion,
	})
	if err != nil {
		t.Fatalf("digest v7 initial projections: %v", err)
	}
	genesisDigest, err := chain.GenesisDigest(initial.GenesisJSON)
	if err != nil {
		t.Fatalf("digest v7 genesis: %v", err)
	}
	eventSeed, err := chain.EventSeed(chain.Boundary{
		Genesis: genesisDigest,
	})
	if err != nil {
		t.Fatalf("seed v7 event chain: %v", err)
	}
	resultSeed, err := chain.ResultSeed(chain.Boundary{
		Genesis: genesisDigest,
	})
	if err != nil {
		t.Fatalf("seed v7 result chain: %v", err)
	}
	heads := ApplyHeads{
		ChainHash:  Digest(eventSeed),
		ResultHash: Digest(resultSeed),
		ProjectionAccumulator: Digest(chain.AccumulatorSeedInitial(
			genesisDigest,
			chain.Digest(stateDigest),
		)),
		DigestVersion:           initial.DigestVersion,
		ProjectionSchemaVersion: initial.ProjectionSchemaVersion,
	}
	if err := execute(
		conn,
		`INSERT INTO genesis_records(
		    recovery_generation, session_id, workspace_id, genesis_kind,
		    genesis_json, genesis_digest, recovery_authorization_json,
		    predecessor_chain_index, predecessor_chain_hash,
		    predecessor_result_index, predecessor_result_hash,
		    predecessor_projection_accumulator,
		    boundary_transform_digest
		) VALUES (
		    0, ?1, ?2, 'initial', ?3, ?4, NULL,
		    NULL, NULL, NULL, NULL, NULL, ?5
		);`,
		string(initial.SessionID),
		string(initial.WorkspaceID),
		string(initial.GenesisJSON),
		genesisDigest[:],
		stateDigest[:],
	); err != nil {
		t.Fatalf("write v7 genesis: %v", err)
	}
	if err := writeBoundaryConsensusState(conn, initial, heads); err != nil {
		t.Fatalf("write v7 consensus state: %v", err)
	}
}
