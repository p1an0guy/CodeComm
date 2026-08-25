package store

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

const (
	initialProjectionBoundaryTable = "initial_projection_boundary"
	initialProjectionRowsTable     = "initial_projection_rows"
)

func retainInitialProjectionBoundaryMigration(conn *sqlite.Conn) error {
	state, found, err := readConsensusState(conn)
	if err != nil {
		return err
	}
	if !found {
		var genesisCount int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM genesis_records;",
			func(stmt *sqlite.Stmt) {
				genesisCount = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if genesisCount != 0 {
			return fmt.Errorf(
				"%w: genesis exists without active consensus state",
				ErrGenerationZeroStateUnavailable,
			)
		}
		return nil
	}
	return ensureInitialProjectionBoundary(conn, state)
}

// ensureInitialProjectionBoundary authenticates the immutable generation-zero
// cut, reconstructing it only while generation zero is still active.
func ensureInitialProjectionBoundary(
	conn *sqlite.Conn,
	active consensusState,
) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	sessionID, _, err := historicalGenesisIdentity(conn, 0)
	if err != nil {
		return fmt.Errorf(
			"%w: read initial genesis identity: %v",
			ErrGenerationZeroStateUnavailable,
			err,
		)
	}
	genesis, err := readGenesisBoundary(conn, 0, sessionID)
	if err != nil {
		return err
	}
	if genesis.hasPredecessor ||
		genesis.predecessorChainIndex != 0 ||
		genesis.predecessorResultIndex != 0 {
		return fmt.Errorf(
			"%w: initial genesis carries predecessor state",
			ErrGenerationZeroStateUnavailable,
		)
	}
	versions := chain.Versions{
		Digest:           active.digestVersion,
		ProjectionSchema: active.projectionSchemaVersion,
	}
	_, retained, err := readInitialProjectionBoundary(
		conn,
		versions,
		genesis.stateDigest,
		nil,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: authenticate retained initial projection boundary: %v",
			ErrGenerationZeroStateUnavailable,
			err,
		)
	}
	if retained {
		return nil
	}
	if active.recoveryGeneration != 0 || active.sessionID != sessionID {
		return fmt.Errorf(
			"%w: recovery already replaced the reconstructible projection cut",
			ErrGenerationZeroStateUnavailable,
		)
	}
	if err := verifyFullCommitmentState(conn, active); err != nil {
		return err
	}

	rows := make([]chain.LogicalRow, 0)
	digest, err := projectionStateDigestAtResultCut(
		conn,
		active,
		genesis,
		0,
		func(row chain.LogicalRow) error {
			rows = append(rows, cloneLogicalRow(row))
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf(
			"%w: reconstruct initial projection boundary: %v",
			ErrGenerationZeroStateUnavailable,
			err,
		)
	}
	if digest != genesis.stateDigest {
		return fmt.Errorf(
			"%w: reconstructed initial projection digest differs from genesis",
			ErrGenerationZeroStateUnavailable,
		)
	}
	if err := writeInitialProjectionBoundary(
		conn,
		rows,
		versions,
		genesis.stateDigest,
	); err != nil {
		return fmt.Errorf(
			"%w: retain initial projection boundary: %v",
			ErrGenerationZeroStateUnavailable,
			err,
		)
	}
	if _, retained, err := readInitialProjectionBoundary(
		conn,
		versions,
		genesis.stateDigest,
		nil,
	); err != nil || !retained {
		return fmt.Errorf(
			"%w: verify retained initial projection boundary: %v",
			ErrGenerationZeroStateUnavailable,
			err,
		)
	}
	return nil
}

// writeInitialProjectionBoundary stores the exact generation-zero projection
// baseline once. Its digest is independently bound by genesis_records.
func writeInitialProjectionBoundary(
	conn *sqlite.Conn,
	rows []chain.LogicalRow,
	versions chain.Versions,
	expected Digest,
) error {
	if conn == nil || uint64(len(rows)) > domain.MaxSafeInteger {
		return errors.New("store: invalid initial projection boundary")
	}
	var existingBoundary, existingRows int64
	if err := queryOne(
		conn,
		"SELECT count(*) FROM "+initialProjectionBoundaryTable+";",
		func(stmt *sqlite.Stmt) {
			existingBoundary = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if err := queryOne(
		conn,
		"SELECT count(*) FROM "+initialProjectionRowsTable+";",
		func(stmt *sqlite.Stmt) {
			existingRows = stmt.ColumnInt64(0)
		},
	); err != nil {
		return err
	}
	if existingBoundary != 0 || existingRows != 0 {
		return errors.New("store: initial projection boundary already exists")
	}

	tables := chain.CoveredTables()
	indexes := make(map[string]int, len(tables))
	counts := make([]chain.TableRowCount, len(tables))
	for index, table := range tables {
		indexes[table] = index
		counts[index].Table = table
	}
	for _, row := range rows {
		index, found := indexes[row.Table]
		if !found ||
			counts[index].Count == domain.MaxSafeInteger {
			return fmt.Errorf(
				"store: invalid initial projection table %q",
				row.Table,
			)
		}
		counts[index].Count++
	}
	digester, err := chain.NewStateDigester(versions, counts)
	if err != nil {
		return fmt.Errorf(
			"store: initialize projection-boundary digest: %w",
			err,
		)
	}
	for _, row := range rows {
		if err := digester.Append(row); err != nil {
			return fmt.Errorf(
				"store: validate initial projection boundary: %w",
				err,
			)
		}
	}
	digest, err := digester.Sum()
	if err != nil {
		return fmt.Errorf(
			"store: finish initial projection-boundary digest: %w",
			err,
		)
	}
	if Digest(digest) != expected {
		return errors.New(
			"store: initial projection boundary digest differs from genesis",
		)
	}

	for _, row := range rows {
		if err := execute(
			conn,
			`INSERT INTO initial_projection_rows(
			    table_index, table_name, primary_key, row_json
			) VALUES (?1, ?2, ?3, ?4);`,
			indexes[row.Table],
			row.Table,
			row.PrimaryKey,
			row.Row,
		); err != nil {
			return fmt.Errorf(
				"store: persist initial projection row %s: %w",
				row.Table,
				err,
			)
		}
	}
	return execute(
		conn,
		`INSERT INTO initial_projection_boundary(
		    singleton, digest_version, projection_schema_version,
		    projection_state_digest, row_count
		) VALUES (1, ?1, ?2, ?3, ?4);`,
		versions.Digest,
		versions.ProjectionSchema,
		expected[:],
		len(rows),
	)
}

// readInitialProjectionBoundary streams and authenticates the immutable
// generation-zero baseline without consulting the active-generation rows.
func readInitialProjectionBoundary(
	conn *sqlite.Conn,
	versions chain.Versions,
	expected Digest,
	visit func(chain.LogicalRow) error,
) (uint64, bool, error) {
	if conn == nil {
		return 0, false, ErrInvalidOptions
	}
	var (
		markerCount   int
		markerVersion uint64
		markerSchema  uint64
		markerDigest  Digest
		markerRows    uint64
		markerErr     error
	)
	if err := query(
		conn,
		`SELECT digest_version, projection_schema_version,
		        projection_state_digest, row_count
		   FROM initial_projection_boundary
		  WHERE singleton = 1;`,
		func(stmt *sqlite.Stmt) {
			markerCount++
			if markerCount != 1 {
				return
			}
			digestVersion := stmt.ColumnInt64(0)
			projectionVersion := stmt.ColumnInt64(1)
			rowCount := stmt.ColumnInt64(3)
			if digestVersion < 1 ||
				projectionVersion < 1 ||
				rowCount < 0 {
				markerErr = errors.New(
					"initial projection boundary marker is invalid",
				)
				return
			}
			markerVersion = uint64(digestVersion)
			markerSchema = uint64(projectionVersion)
			markerRows = uint64(rowCount)
			markerErr = copyDigestColumn(&markerDigest, stmt, 2)
		},
	); err != nil {
		return 0, false, err
	}
	if markerErr != nil {
		return 0, false, markerErr
	}
	if markerCount == 0 {
		var orphanRows int64
		if err := queryOne(
			conn,
			"SELECT count(*) FROM "+initialProjectionRowsTable+";",
			func(stmt *sqlite.Stmt) {
				orphanRows = stmt.ColumnInt64(0)
			},
		); err != nil {
			return 0, false, err
		}
		if orphanRows != 0 {
			return 0, false, errors.New(
				"initial projection rows lack their commitment marker",
			)
		}
		return 0, false, nil
	}
	if markerCount != 1 ||
		markerVersion != versions.Digest ||
		markerSchema != versions.ProjectionSchema ||
		markerDigest != expected ||
		!domain.ValidUnsignedInteger(markerRows) {
		return 0, false, errors.New(
			"initial projection boundary marker differs from genesis",
		)
	}
	tables := chain.CoveredTables()
	counts := make([]chain.TableRowCount, len(tables))
	for index, table := range tables {
		counts[index].Table = table
	}

	var (
		countErr error
		total    uint64
	)
	if err := query(
		conn,
		`SELECT table_index, table_name, count(*)
		   FROM initial_projection_rows
		  GROUP BY table_index, table_name
		  ORDER BY table_index, table_name;`,
		func(stmt *sqlite.Stmt) {
			if countErr != nil {
				return
			}
			tableIndex := stmt.ColumnInt64(0)
			tableName := stmt.ColumnText(1)
			rowCount := stmt.ColumnInt64(2)
			if tableIndex < 0 ||
				tableIndex >= int64(len(tables)) ||
				tables[tableIndex] != tableName ||
				rowCount < 1 ||
				uint64(rowCount) > domain.MaxSafeInteger ||
				counts[tableIndex].Count != 0 ||
				total > domain.MaxSafeInteger-uint64(rowCount) {
				countErr = errors.New(
					"initial projection boundary has an invalid table inventory",
				)
				return
			}
			counts[tableIndex].Count = uint64(rowCount)
			total += uint64(rowCount)
		},
	); err != nil {
		return 0, false, err
	}
	if countErr != nil {
		return 0, false, countErr
	}
	if total != markerRows {
		return 0, false, errors.New(
			"initial projection boundary row count differs from marker",
		)
	}

	digester, err := chain.NewStateDigester(versions, counts)
	if err != nil {
		return 0, false, fmt.Errorf(
			"store: initialize retained projection-boundary digest: %w",
			err,
		)
	}
	var (
		rowErr error
		seen   uint64
	)
	if err := query(
		conn,
		`SELECT table_index, table_name, primary_key, row_json
		   FROM initial_projection_rows
		  ORDER BY table_index, primary_key;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			tableIndex := stmt.ColumnInt64(0)
			row := chain.LogicalRow{
				Table:      stmt.ColumnText(1),
				PrimaryKey: bytes.Clone(columnBytes(stmt, 2)),
				Row:        bytes.Clone(columnBytes(stmt, 3)),
			}
			if tableIndex < 0 ||
				tableIndex >= int64(len(tables)) ||
				tables[tableIndex] != row.Table {
				rowErr = errors.New(
					"initial projection boundary row has an invalid table",
				)
				return
			}
			if rowErr = digester.Append(row); rowErr != nil {
				return
			}
			seen++
			if visit != nil {
				rowErr = visit(row)
			}
		},
	); err != nil {
		return 0, false, err
	}
	if rowErr != nil {
		return 0, false, rowErr
	}
	if seen != total {
		return 0, false, errors.New(
			"initial projection boundary inventory changed during verification",
		)
	}
	digest, err := digester.Sum()
	if err != nil {
		return 0, false, err
	}
	if Digest(digest) != expected {
		return 0, false, errors.New(
			"initial projection boundary digest differs from genesis",
		)
	}
	return seen, true, nil
}
