package store

import (
	"testing"
)

func TestMigration0009AddsEmptyRebootstrapCrashGate(t *testing.T) {
	t.Parallel()

	conn := openMigrationTestConnection(t)
	if err := applyMigrations(
		conn,
		embeddedMigrations[:8],
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v8 migrations: %v", err)
	}
	assertMigrationTableAbsent(
		t,
		conn,
		"rebootstrap_install_marker",
		9,
	)

	if err := applyMigrations(
		conn,
		embeddedMigrations,
		fixedMigrationTestClock,
	); err != nil {
		t.Fatalf("apply v9 migration: %v", err)
	}
	assertIntQuery(
		t,
		conn,
		`SELECT count(*) FROM sqlite_schema
		  WHERE type = 'table'
		    AND name = 'rebootstrap_install_marker';`,
		1,
	)
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM rebootstrap_install_marker;",
		0,
	)
	assertIntQuery(
		t,
		conn,
		"SELECT count(*) FROM schema_migrations WHERE version = 9;",
		1,
	)
}
