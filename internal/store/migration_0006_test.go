package store

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"zombiezen.com/go/sqlite"
)

func TestMigration0006SchemaParityAndRejectsLedgerLoss(t *testing.T) {
	fresh := openMigrationTestConnection(t)
	if err := applyMigrations(
		fresh,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply fresh migrations: %v", err)
	}
	want := migration0006Schema(t, fresh)

	upgraded := openMigrationTestConnection(t)
	if err := applyMigrations(
		upgraded,
		embeddedMigrations[:5],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v5 migrations: %v", err)
	}
	if err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("upgrade v5 to v6: %v", err)
	}
	if got := migration0006Schema(t, upgraded); !bytes.Equal(got, want) {
		t.Fatalf("v5 upgrade schema differs from fresh v6\n got:\n%s\nwant:\n%s", got, want)
	}

	if err := execute(
		upgraded,
		"DELETE FROM schema_migrations WHERE version = 6;",
	); err != nil {
		t.Fatal(err)
	}
	err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	)
	if err == nil || !strings.Contains(err.Error(), "already_v6 = 0") {
		t.Fatalf(
			"migration with missing v6 ledger error = %v, want schema guard failure",
			err,
		)
	}
	if got := migration0006Schema(t, upgraded); !bytes.Equal(got, want) {
		t.Fatalf("rejected v6 replay changed schema\n got:\n%s\nwant:\n%s", got, want)
	}
	assertIntQuery(
		t,
		upgraded,
		"SELECT count(*) FROM schema_migrations WHERE version = 6;",
		0,
	)
	assertIntQuery(
		t,
		upgraded,
		`SELECT count(*) FROM sqlite_schema
		  WHERE type = 'table'
		    AND name IN ('migration_0006_schema_guard',
		                 'migration_0006_attestation_guard');`,
		0,
	)
}

func TestMigration0006RejectsNonemptyLegacyAttestations(t *testing.T) {
	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations[:5],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v5 migrations: %v", err)
	}
	if err := execute(
		conn,
		`INSERT INTO replication_attestations(
		    attestation_id, attestation_kind, session_id, workspace_id,
		    recovery_generation, signer_device_id,
		    authority_voter_set_version, from_result_index, to_result_index,
		    start_result_hash, end_result_hash, start_chain_index,
		    end_chain_index, start_chain_hash, end_chain_hash,
		    checkpoint_event_id, envelope_json, signature, verified_at
		) VALUES (
		    'legacy-batch', 'batch',
		    '01890f47-3e72-7000-8000-000000000002',
		    '123e4567-e89b-42d3-a456-426614174000',
		    0, 'cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
		    1, 1, 1, zeroblob(32), zeroblob(32), 0, 1,
		    zeroblob(32), zeroblob(32), NULL, '{}', zeroblob(64),
		    '2026-08-19T12:00:00Z'
		);`,
	); err != nil {
		t.Fatalf("insert legacy attestation: %v", err)
	}

	err := applyMigrations(conn, embeddedMigrations, fixedMigrationTestClock)
	if err == nil ||
		!strings.Contains(err.Error(), "legacy_row_count = 0") {
		t.Fatalf("upgrade with legacy evidence error = %v, want guard failure", err)
	}
	assertIntQuery(t, conn, "SELECT count(*) FROM replication_attestations;", 1)
	assertIntQuery(t, conn, "SELECT count(*) FROM schema_migrations WHERE version = 6;", 0)
	assertIntQuery(
		t,
		conn,
		`SELECT count(*) FROM pragma_table_info('replication_attestations')
		  WHERE name = 'server_applied_result_index';`,
		0,
	)
	assertIntQuery(
		t,
		conn,
		`SELECT count(*) FROM sqlite_schema
		  WHERE type = 'table'
		    AND name IN ('migration_0006_attestation_guard',
		                 'settled_nonvoter_state');`,
		0,
	)
}

func TestMigration0006AttestationKindConstraints(t *testing.T) {
	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	insert := func(
		id string,
		kind string,
		serverResultIndex any,
		checkpointEventID any,
	) error {
		return execute(
			conn,
			`INSERT INTO replication_attestations(
			    attestation_id, attestation_kind, session_id, workspace_id,
			    recovery_generation, signer_device_id,
			    authority_voter_set_version, from_result_index,
				    to_result_index, server_applied_result_index,
				    start_result_hash, end_result_hash, start_chain_index,
				    end_chain_index, start_chain_hash, end_chain_hash,
				    start_projection_accumulator,
				    end_projection_accumulator,
				    start_projection_state_digest,
				    end_projection_state_digest,
				    checkpoint_event_id, envelope_json, signature, verified_at
				) VALUES (
				    ?1, ?2, '01890f47-3e72-7000-8000-000000000002',
				    '123e4567-e89b-42d3-a456-426614174000', 0,
				    'cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
				    1, 1, 1, ?3, zeroblob(32), zeroblob(32), 0, 1,
				    zeroblob(32), zeroblob(32),
				    zeroblob(32), zeroblob(32),
				    zeroblob(32), zeroblob(32),
				    ?4, '{}', zeroblob(64),
				    '2026-08-19T12:00:00Z'
				);`,
			id,
			kind,
			serverResultIndex,
			checkpointEventID,
		)
	}

	if err := insert("valid-batch", "batch", int64(1), nil); err != nil {
		t.Fatalf("insert valid batch: %v", err)
	}
	if err := insert("batch-without-watermark", "batch", nil, nil); err == nil {
		t.Fatal("batch without server watermark succeeded")
	}
	checkpointID := "01890f47-3e72-7000-8000-000000000003"
	if err := insert(
		"batch-with-checkpoint",
		"batch",
		int64(1),
		checkpointID,
	); err == nil {
		t.Fatal("batch with checkpoint succeeded")
	}
	if err := insert(
		"valid-snapshot",
		"snapshot",
		nil,
		checkpointID,
	); err != nil {
		t.Fatalf("insert valid snapshot: %v", err)
	}
	if err := insert(
		"snapshot-with-watermark",
		"snapshot",
		int64(1),
		checkpointID,
	); err == nil {
		t.Fatal("snapshot with batch-only server watermark succeeded")
	}
	assertIntQuery(t, conn, "SELECT count(*) FROM replication_attestations;", 2)
}

func openMigrationTestConnection(t *testing.T) *sqlite.Conn {
	t.Helper()
	conn, err := sqlite.OpenConn(
		":memory:",
		sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenMemory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close migration test database: %v", err)
		}
	})
	if err := configurePooledConnection(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

func migration0006Schema(t *testing.T, conn *sqlite.Conn) []byte {
	t.Helper()
	var schema []byte
	if err := query(
		conn,
		`SELECT type, name, tbl_name, sql
		   FROM sqlite_schema
		  WHERE name IN (
		      'replication_attestations',
		      'replication_attestations_coverage',
		      'settled_nonvoter_state'
		  )
		  ORDER BY type, name;`,
		func(stmt *sqlite.Stmt) {
			for column := 0; column < 4; column++ {
				schema = append(schema, stmt.ColumnText(column)...)
				schema = append(schema, 0)
			}
		},
	); err != nil {
		t.Fatal(err)
	}
	return schema
}

func downgradeTestReplicationEvidenceToV5(conn *sqlite.Conn) error {
	legacy, err := sqlite.OpenConn(
		":memory:",
		sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenMemory,
	)
	if err != nil {
		return err
	}
	defer legacy.Close()
	if err := configurePooledConnection(legacy); err != nil {
		return err
	}
	if err := applyMigrations(
		legacy,
		embeddedMigrations[:5],
		fixedMigrationTestClock,
	); err != nil {
		return err
	}
	var tableSQL, indexSQL string
	for _, target := range []struct {
		name string
		sql  *string
	}{
		{name: "replication_attestations", sql: &tableSQL},
		{name: "replication_attestations_coverage", sql: &indexSQL},
	} {
		if err := queryOneArgs(
			legacy,
			"SELECT sql FROM sqlite_schema WHERE name = ?1;",
			[]any{target.name},
			func(stmt *sqlite.Stmt) {
				*target.sql = stmt.ColumnText(0)
			},
		); err != nil {
			return err
		}
	}
	var attestationCount, settledCount int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM replication_attestations;",
		func(stmt *sqlite.Stmt) {
			attestationCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if err := queryOne(
		conn,
		"SELECT count(*) FROM settled_nonvoter_state;",
		func(stmt *sqlite.Stmt) {
			settledCount = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if attestationCount != 0 || settledCount != 0 {
		return errors.New("test downgrade would discard replication evidence")
	}
	for _, statement := range []string{
		"DROP TABLE settled_nonvoter_state;",
		"DROP INDEX replication_attestations_coverage;",
		"DROP TABLE replication_attestations;",
		tableSQL,
		indexSQL,
	} {
		if err := execute(conn, statement); err != nil {
			return err
		}
	}
	return nil
}

func fixedMigrationTestClock() time.Time {
	return time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
}
