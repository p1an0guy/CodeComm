package store

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version  int64
	name     string
	sql      string
	checksum [sha256.Size]byte
}

var embeddedMigrations = mustLoadMigrations()

func migrationFromText(version int64, name, sqlText string) migration {
	return migration{
		version:  version,
		name:     name,
		sql:      sqlText,
		checksum: sha256.Sum256([]byte(sqlText)),
	}
}

func mustLoadMigrations() []migration {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		panic(fmt.Sprintf("store: read embedded migrations: %v", err))
	}
	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".sql")
		separator := strings.IndexByte(base, '_')
		if separator != 4 || separator == len(base)-1 {
			panic(fmt.Sprintf("store: invalid migration filename %q", entry.Name()))
		}
		version, err := strconv.ParseInt(base[:separator], 10, 64)
		if err != nil || version < 1 {
			panic(fmt.Sprintf("store: invalid migration version in %q", entry.Name()))
		}
		name := base[separator+1:]
		if !validMigrationName(name) {
			panic(fmt.Sprintf("store: invalid migration name in %q", entry.Name()))
		}
		content, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			panic(fmt.Sprintf("store: read migration %q: %v", entry.Name(), err))
		}
		migrations = append(migrations, migrationFromText(version, name, string(content)))
	}
	if len(migrations) == 0 {
		panic("store: no embedded migrations")
	}
	for index, migration := range migrations {
		want := int64(index + 1)
		if migration.version != want {
			panic(fmt.Sprintf(
				"store: migration sequence has version %d at position %d, want %d",
				migration.version,
				index,
				want,
			))
		}
	}
	return migrations
}

func validMigrationName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return false
		}
	}
	return true
}

type clock func() time.Time

func systemClock() time.Time {
	return time.Now().UTC()
}

func applyMigrations(conn *sqlite.Conn, migrations []migration, now clock) error {
	if conn == nil || len(migrations) == 0 || now == nil {
		return ErrInvalidOptions
	}
	hasTable, err := tableExists(conn, "schema_migrations")
	if err != nil {
		return err
	}
	if !hasTable {
		var tableCount int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
			func(stmt *sqlite.Stmt) {
				tableCount = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if tableCount != 0 {
			return fmt.Errorf("%w: schema_migrations is absent from a nonempty database", ErrMigrationState)
		}
	}

	applied := make(map[int64]migration)
	if hasTable {
		err := query(
			conn,
			"SELECT version, name, checksum FROM schema_migrations ORDER BY version;",
			func(stmt *sqlite.Stmt) {
				version := stmt.ColumnInt64(0)
				checksumBytes := columnBytes(stmt, 2)
				var checksum [sha256.Size]byte
				copy(checksum[:], checksumBytes)
				applied[version] = migration{
					version:  version,
					name:     stmt.ColumnText(1),
					checksum: checksum,
				}
			},
		)
		if err != nil {
			return err
		}
	}
	if len(applied) > 0 {
		latest := migrations[len(migrations)-1].version
		for version := range applied {
			if version < 1 || version > latest {
				return fmt.Errorf("%w: found applied migration %d", ErrSchemaTooNew, version)
			}
		}
	}

	for _, candidate := range migrations {
		if existing, ok := applied[candidate.version]; ok {
			if existing.name != candidate.name || existing.checksum != candidate.checksum {
				return fmt.Errorf(
					"%w: version %d has name %q and checksum %x, want %q and %x",
					ErrMigrationChecksum,
					candidate.version,
					existing.name,
					existing.checksum,
					candidate.name,
					candidate.checksum,
				)
			}
			continue
		}
		for version := range applied {
			if version > candidate.version {
				return fmt.Errorf(
					"%w: migration %d is missing before applied version %d",
					ErrMigrationState,
					candidate.version,
					version,
				)
			}
		}
		if err := applyMigration(conn, candidate, now()); err != nil {
			return fmt.Errorf("store: apply migration %04d_%s: %w", candidate.version, candidate.name, err)
		}
	}
	return nil
}

func applyMigration(conn *sqlite.Conn, candidate migration, appliedAt time.Time) (err error) {
	end, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return err
	}
	defer end(&err)
	if err = sqlitex.ExecuteScript(conn, candidate.sql, nil); err != nil {
		return err
	}
	return execute(
		conn,
		`INSERT INTO schema_migrations(version, name, checksum, applied_at)
		 VALUES (?1, ?2, ?3, ?4);`,
		candidate.version,
		candidate.name,
		candidate.checksum[:],
		appliedAt.UTC().Format(time.RFC3339Nano),
	)
}

func tableExists(conn *sqlite.Conn, name string) (bool, error) {
	var count int64
	err := queryOneArgs(
		conn,
		"SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1;",
		[]any{name},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	)
	return count == 1, err
}
