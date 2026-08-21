package store

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
)

const minimumSQLiteVersion = "3.42.0"

func configureStartupConnection(conn *sqlite.Conn) error {
	if err := configurePooledConnection(conn); err != nil {
		return err
	}
	var journalMode string
	if err := queryOne(conn, "PRAGMA journal_mode = WAL;", func(stmt *sqlite.Stmt) {
		journalMode = strings.ToLower(stmt.ColumnText(0))
	}); err != nil {
		return err
	}
	if journalMode != "wal" {
		return fmt.Errorf("journal_mode = %q, want wal", journalMode)
	}
	var version string
	if err := queryOne(conn, "SELECT sqlite_version();", func(stmt *sqlite.Stmt) {
		version = stmt.ColumnText(0)
	}); err != nil {
		return err
	}
	if compareSQLiteVersion(version, minimumSQLiteVersion) < 0 {
		return fmt.Errorf("%w: got %s, want >= %s", ErrSQLiteVersion, version, minimumSQLiteVersion)
	}
	return nil
}

func configurePooledConnection(conn *sqlite.Conn) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	conn.SetBusyTimeout(5 * time.Second)
	if err := conn.SetDefensive(true); err != nil {
		return fmt.Errorf("enable defensive mode: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA synchronous = FULL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA trusted_schema = OFF;",
		"PRAGMA temp_store = FILE;",
	} {
		if err := execute(conn, statement); err != nil {
			return err
		}
	}
	checks := []struct {
		query string
		want  int64
	}{
		{"PRAGMA synchronous;", 2},
		{"PRAGMA foreign_keys;", 1},
		{"PRAGMA busy_timeout;", 5000},
		{"PRAGMA trusted_schema;", 0},
		{"PRAGMA temp_store;", 1},
	}
	for _, check := range checks {
		var got int64
		if err := queryOne(conn, check.query, func(stmt *sqlite.Stmt) {
			got = stmt.ColumnInt64(0)
		}); err != nil {
			return err
		}
		if got != check.want {
			return fmt.Errorf("%s returned %d, want %d", check.query, got, check.want)
		}
	}
	return nil
}

func checkIntegrity(conn *sqlite.Conn) error {
	var results []string
	if err := query(conn, "PRAGMA quick_check;", func(stmt *sqlite.Stmt) {
		results = append(results, stmt.ColumnText(0))
	}); err != nil {
		return err
	}
	if len(results) != 1 || results[0] != "ok" {
		return fmt.Errorf("%w: %v", ErrIntegrityCheck, results)
	}
	return nil
}

func compareSQLiteVersion(left, right string) int {
	leftParts := parseSQLiteVersion(left)
	rightParts := parseSQLiteVersion(right)
	for index := range leftParts {
		switch {
		case leftParts[index] < rightParts[index]:
			return -1
		case leftParts[index] > rightParts[index]:
			return 1
		}
	}
	return 0
}

func parseSQLiteVersion(version string) [3]int64 {
	var parsed [3]int64
	parts := strings.Split(version, ".")
	for index := 0; index < len(parsed) && index < len(parts); index++ {
		value, err := strconv.ParseInt(parts[index], 10, 32)
		if err != nil {
			return [3]int64{}
		}
		parsed[index] = value
	}
	return parsed
}

func execute(conn *sqlite.Conn, statement string, args ...any) error {
	return runStatement(conn, statement, args, nil)
}

func query(conn *sqlite.Conn, statement string, row func(*sqlite.Stmt)) error {
	return runStatement(conn, statement, nil, row)
}

func queryArgs(
	conn *sqlite.Conn,
	statement string,
	args []any,
	row func(*sqlite.Stmt),
) error {
	return runStatement(conn, statement, args, row)
}

func queryOne(conn *sqlite.Conn, statement string, row func(*sqlite.Stmt)) error {
	return queryOneArgs(conn, statement, nil, row)
}

func queryOneArgs(
	conn *sqlite.Conn,
	statement string,
	args []any,
	row func(*sqlite.Stmt),
) error {
	count := 0
	err := queryArgs(conn, statement, args, func(stmt *sqlite.Stmt) {
		count++
		if count == 1 && row != nil {
			row(stmt)
		}
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("%w: got %d for %q, want 1", ErrUnexpectedRowCount, count, statement)
	}
	return nil
}

func runStatement(
	conn *sqlite.Conn,
	statement string,
	args []any,
	row func(*sqlite.Stmt),
) (err error) {
	if conn == nil {
		return ErrInvalidOptions
	}
	stmt, err := conn.Prepare(statement)
	if err != nil {
		return err
	}
	defer func() {
		resetErr := stmt.Reset()
		clearErr := stmt.ClearBindings()
		if err == nil {
			err = resetErr
		}
		if err == nil {
			err = clearErr
		}
	}()
	if stmt.BindParamCount() != len(args) {
		return fmt.Errorf(
			"store: bind %q: got %d arguments, want %d",
			statement,
			len(args),
			stmt.BindParamCount(),
		)
	}
	for index, value := range args {
		if err := bindValue(stmt, index+1, value); err != nil {
			return fmt.Errorf("store: bind argument %d: %w", index+1, err)
		}
	}
	for {
		hasRow, err := stmt.Step()
		if err != nil {
			return err
		}
		if !hasRow {
			return nil
		}
		if row != nil {
			row(stmt)
		}
	}
}

func bindValue(stmt *sqlite.Stmt, index int, value any) error {
	switch value := value.(type) {
	case nil:
		stmt.BindNull(index)
	case string:
		stmt.BindText(index, value)
	case []byte:
		stmt.BindBytes(index, value)
	case int:
		stmt.BindInt64(index, int64(value))
	case int32:
		stmt.BindInt64(index, int64(value))
	case int64:
		stmt.BindInt64(index, value)
	case uint:
		if uint64(value) > math.MaxInt64 {
			return fmt.Errorf("unsigned integer %d exceeds SQLite range", value)
		}
		stmt.BindInt64(index, int64(value))
	case uint32:
		stmt.BindInt64(index, int64(value))
	case uint64:
		if value > math.MaxInt64 {
			return fmt.Errorf("unsigned integer %d exceeds SQLite range", value)
		}
		stmt.BindInt64(index, int64(value))
	case bool:
		stmt.BindBool(index, value)
	default:
		return fmt.Errorf("unsupported value type %T", value)
	}
	return nil
}

func columnBytes(stmt *sqlite.Stmt, column int) []byte {
	value := make([]byte, stmt.ColumnLen(column))
	stmt.ColumnBytes(column, value)
	return value
}
