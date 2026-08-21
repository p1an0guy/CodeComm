package store

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"zombiezen.com/go/sqlite"
)

func TestMigration0007FreshUpgradeAndLedgerBehavior(t *testing.T) {
	fresh := openMigrationTestConnection(t)
	if err := applyMigrations(
		fresh,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply fresh migrations: %v", err)
	}
	wantSchema := migration0007Schema(t, fresh)
	assertMigration0007Ledger(t, fresh)
	assertMigration0007NoGuardArtifacts(t, fresh)

	upgraded := openMigrationTestConnection(t)
	if err := applyMigrations(
		upgraded,
		embeddedMigrations[:6],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v6 migrations: %v", err)
	}
	if err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("upgrade v6 to v7: %v", err)
	}
	if got := migration0007Schema(t, upgraded); !bytes.Equal(got, wantSchema) {
		t.Fatalf(
			"v6 upgrade schema differs from fresh v7\n got:\n%s\nwant:\n%s",
			got,
			wantSchema,
		)
	}
	assertMigration0007Ledger(t, upgraded)
	assertMigration0007NoGuardArtifacts(t, upgraded)

	if err := execute(
		fresh,
		"UPDATE schema_migrations SET checksum = zeroblob(32) WHERE version = 7;",
	); err != nil {
		t.Fatal(err)
	}
	err := applyMigrations(fresh, embeddedMigrations, fixedMigrationTestClock)
	if !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf(
			"migration with changed v7 checksum error = %v, want ErrMigrationChecksum",
			err,
		)
	}
	if got := migration0007Schema(t, fresh); !bytes.Equal(got, wantSchema) {
		t.Fatalf("checksum rejection changed v7 schema\n got:\n%s\nwant:\n%s", got, wantSchema)
	}

	if err := execute(
		upgraded,
		"DELETE FROM schema_migrations WHERE version = 7;",
	); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(
		upgraded,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err == nil {
		t.Fatal("migration with missing v7 ledger succeeded over existing schema")
	}
	assertIntQuery(
		t,
		upgraded,
		"SELECT count(*) FROM schema_migrations WHERE version = 7;",
		0,
	)
	if got := migration0007Schema(t, upgraded); !bytes.Equal(got, wantSchema) {
		t.Fatalf("ledger rejection changed v7 schema\n got:\n%s\nwant:\n%s", got, wantSchema)
	}
	assertMigration0007NoGuardArtifacts(t, upgraded)
}

func TestMigration0007WatermarkObservationConstraints(t *testing.T) {
	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	assertIntQuery(
		t,
		conn,
		`SELECT strict
		   FROM pragma_table_list
		  WHERE schema = 'main'
		    AND name = 'replication_watermark_observations';`,
		1,
	)

	valid := validMigration0007Observation()
	if err := insertMigration0007Observation(conn, valid); err != nil {
		t.Fatalf("insert valid observation: %v", err)
	}
	fractional := valid
	fractional.observationID = "valid-fractional"
	fractional.authorityVersion = int64(2)
	fractional.verifiedAt = "2024-02-29T23:59:59.123456789Z"
	if err := insertMigration0007Observation(conn, fractional); err != nil {
		t.Fatalf("insert valid fractional observation: %v", err)
	}
	boundary := valid
	boundary.observationID = strings.Repeat("x", 128)
	boundary.recoveryGeneration = int64(9007199254740991)
	boundary.authorityVersion = int64(9007199254740991)
	boundary.resultIndex = int64(9007199254740991)
	boundary.chainIndex = int64(9007199254740991)
	boundary.serverAppliedResultIndex = int64(9007199254740991)
	if err := insertMigration0007Observation(conn, boundary); err != nil {
		t.Fatalf("insert valid boundary observation: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*migration0007Observation)
	}{
		{
			name: "duplicate signer authority slot",
			mutate: func(row *migration0007Observation) {
				row.authorityVersion = int64(1)
			},
		},
		{
			name: "duplicate observation ID",
			mutate: func(row *migration0007Observation) {
				row.observationID = "valid"
			},
		},
		{
			name: "empty observation ID",
			mutate: func(row *migration0007Observation) {
				row.observationID = ""
			},
		},
		{
			name: "observation ID over byte limit",
			mutate: func(row *migration0007Observation) {
				row.observationID = strings.Repeat("\u00e9", 65)
			},
		},
		{
			name: "session is not UUIDv7",
			mutate: func(row *migration0007Observation) {
				row.sessionID = "123e4567-e89b-42d3-a456-426614174000"
			},
		},
		{
			name: "workspace is not UUIDv4",
			mutate: func(row *migration0007Observation) {
				row.workspaceID = "01890f47-3e72-7000-8000-000000000002"
			},
		},
		{
			name: "negative recovery generation",
			mutate: func(row *migration0007Observation) {
				row.recoveryGeneration = int64(-1)
			},
		},
		{
			name: "unsafe recovery generation",
			mutate: func(row *migration0007Observation) {
				row.recoveryGeneration = int64(9007199254740992)
			},
		},
		{
			name: "invalid relay peer device ID",
			mutate: func(row *migration0007Observation) {
				row.relayPeerDeviceID = "cc1" + strings.Repeat("g", 64)
			},
		},
		{
			name: "invalid signer device ID",
			mutate: func(row *migration0007Observation) {
				row.signerDeviceID = "cc2" + strings.Repeat("b", 64)
			},
		},
		{
			name: "zero authority version",
			mutate: func(row *migration0007Observation) {
				row.authorityVersion = int64(0)
			},
		},
		{
			name: "unsafe authority version",
			mutate: func(row *migration0007Observation) {
				row.authorityVersion = int64(9007199254740992)
			},
		},
		{
			name: "negative result index",
			mutate: func(row *migration0007Observation) {
				row.resultIndex = int64(-1)
			},
		},
		{
			name: "unsafe result index",
			mutate: func(row *migration0007Observation) {
				row.resultIndex = int64(9007199254740992)
			},
		},
		{
			name: "noninteger result index",
			mutate: func(row *migration0007Observation) {
				row.resultIndex = "not-an-integer"
			},
		},
		{
			name: "short result hash",
			mutate: func(row *migration0007Observation) {
				row.resultHash = bytes.Repeat([]byte{1}, 31)
			},
		},
		{
			name: "text result hash",
			mutate: func(row *migration0007Observation) {
				row.resultHash = strings.Repeat("1", 32)
			},
		},
		{
			name: "negative chain index",
			mutate: func(row *migration0007Observation) {
				row.chainIndex = int64(-1)
			},
		},
		{
			name: "chain index after result",
			mutate: func(row *migration0007Observation) {
				row.chainIndex = int64(8)
			},
		},
		{
			name: "short chain hash",
			mutate: func(row *migration0007Observation) {
				row.chainHash = bytes.Repeat([]byte{2}, 31)
			},
		},
		{
			name: "short projection accumulator",
			mutate: func(row *migration0007Observation) {
				row.projectionAccumulator = bytes.Repeat([]byte{3}, 31)
			},
		},
		{
			name: "short projection state digest",
			mutate: func(row *migration0007Observation) {
				row.projectionStateDigest = bytes.Repeat([]byte{4}, 31)
			},
		},
		{
			name: "server watermark before result",
			mutate: func(row *migration0007Observation) {
				row.serverAppliedResultIndex = int64(6)
			},
		},
		{
			name: "server watermark after result",
			mutate: func(row *migration0007Observation) {
				row.serverAppliedResultIndex = int64(8)
			},
		},
		{
			name: "unsafe server watermark",
			mutate: func(row *migration0007Observation) {
				row.serverAppliedResultIndex = int64(9007199254740992)
			},
		},
		{
			name: "invalid envelope JSON",
			mutate: func(row *migration0007Observation) {
				row.envelopeJSON = "{"
			},
		},
		{
			name: "envelope is not object",
			mutate: func(row *migration0007Observation) {
				row.envelopeJSON = "[]"
			},
		},
		{
			name: "short signature",
			mutate: func(row *migration0007Observation) {
				row.signature = bytes.Repeat([]byte{5}, 63)
			},
		},
		{
			name: "timestamp not UTC",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-08-19T12:00:00+00:00"
			},
		},
		{
			name: "invalid calendar date",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-02-29T12:00:00Z"
			},
		},
		{
			name: "invalid hour",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-08-19T24:00:00Z"
			},
		},
		{
			name: "invalid second",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-08-19T12:00:60Z"
			},
		},
		{
			name: "empty fractional seconds",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-08-19T12:00:00.Z"
			},
		},
		{
			name: "too many fractional digits",
			mutate: func(row *migration0007Observation) {
				row.verifiedAt = "2026-08-19T12:00:00.1234567890Z"
			},
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := valid
			row.observationID = fmt.Sprintf("invalid-%02d", index)
			row.authorityVersion = int64(100 + index)
			test.mutate(&row)
			if err := insertMigration0007Observation(conn, row); err == nil {
				t.Fatal("insert succeeded")
			}
		})
	}
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM replication_watermark_observations;",
		3,
	)
}

type migration0007Observation struct {
	observationID            string
	sessionID                string
	workspaceID              string
	recoveryGeneration       any
	relayPeerDeviceID        string
	signerDeviceID           string
	authorityVersion         any
	resultIndex              any
	resultHash               any
	chainIndex               any
	chainHash                []byte
	projectionAccumulator    []byte
	projectionStateDigest    []byte
	serverAppliedResultIndex any
	envelopeJSON             string
	signature                []byte
	verifiedAt               string
}

func validMigration0007Observation() migration0007Observation {
	return migration0007Observation{
		observationID:            "valid",
		sessionID:                "01890f47-3e72-7000-8000-000000000002",
		workspaceID:              "123e4567-e89b-42d3-a456-426614174000",
		recoveryGeneration:       int64(0),
		relayPeerDeviceID:        "cc1" + strings.Repeat("a", 64),
		signerDeviceID:           "cc1" + strings.Repeat("b", 64),
		authorityVersion:         int64(1),
		resultIndex:              int64(7),
		resultHash:               bytes.Repeat([]byte{1}, 32),
		chainIndex:               int64(5),
		chainHash:                bytes.Repeat([]byte{2}, 32),
		projectionAccumulator:    bytes.Repeat([]byte{3}, 32),
		projectionStateDigest:    bytes.Repeat([]byte{4}, 32),
		serverAppliedResultIndex: int64(7),
		envelopeJSON:             "{}",
		signature:                bytes.Repeat([]byte{5}, 64),
		verifiedAt:               "2026-08-19T12:00:00Z",
	}
}

func insertMigration0007Observation(
	conn *sqlite.Conn,
	row migration0007Observation,
) error {
	return execute(
		conn,
		`INSERT INTO replication_watermark_observations(
		    observation_id, session_id, workspace_id, recovery_generation,
		    relay_peer_device_id, signer_device_id,
		    authority_voter_set_version, result_index, result_hash,
		    chain_index, chain_hash, projection_accumulator,
		    projection_state_digest, server_applied_result_index,
		    envelope_json, signature, verified_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
		    ?14, ?15, ?16, ?17
		);`,
		row.observationID,
		row.sessionID,
		row.workspaceID,
		row.recoveryGeneration,
		row.relayPeerDeviceID,
		row.signerDeviceID,
		row.authorityVersion,
		row.resultIndex,
		row.resultHash,
		row.chainIndex,
		row.chainHash,
		row.projectionAccumulator,
		row.projectionStateDigest,
		row.serverAppliedResultIndex,
		row.envelopeJSON,
		row.signature,
		row.verifiedAt,
	)
}

func migration0007Schema(t *testing.T, conn *sqlite.Conn) []byte {
	t.Helper()
	var schema []byte
	if err := query(
		conn,
		`SELECT type, name, tbl_name, sql
		   FROM sqlite_schema
		  WHERE name IN (
		      'replication_watermark_observations',
		      'replication_watermark_observations_lineage_signer_authority',
		      'replication_watermark_observations_watermark'
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

func assertMigration0007Ledger(t *testing.T, conn *sqlite.Conn) {
	t.Helper()
	var version int64
	var name, appliedAt string
	var checksum []byte
	if err := queryOne(
		conn,
		`SELECT version, name, checksum, applied_at
		   FROM schema_migrations
		  WHERE version = 7;`,
		func(stmt *sqlite.Stmt) {
			version = stmt.ColumnInt64(0)
			name = stmt.ColumnText(1)
			checksum = columnBytes(stmt, 2)
			appliedAt = stmt.ColumnText(3)
		},
	); err != nil {
		t.Fatal(err)
	}
	if version != 7 || name != "replication_watermark_observations" {
		t.Fatalf(
			"migration ledger = (%d, %q), want (7, %q)",
			version,
			name,
			"replication_watermark_observations",
		)
	}
	if !bytes.Equal(checksum, embeddedMigrations[6].checksum[:]) {
		t.Fatalf(
			"migration checksum = %x, want %x",
			checksum,
			embeddedMigrations[6].checksum,
		)
	}
	if appliedAt != "2026-08-19T12:00:00Z" {
		t.Fatalf(
			"migration applied_at = %q, want %q",
			appliedAt,
			"2026-08-19T12:00:00Z",
		)
	}
}

func assertMigration0007NoGuardArtifacts(t *testing.T, conn *sqlite.Conn) {
	t.Helper()
	assertIntQuery(
		t,
		conn,
		`SELECT count(*)
		   FROM sqlite_schema
		  WHERE name GLOB 'migration_0007_*';`,
		0,
	)
}
