package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"zombiezen.com/go/sqlite"
)

const projectionRewindTable = "codecomm_projection_rewind"

// projectionStateDigestAtResultCut reconstructs a historical projection cut
// in SQLite's file-backed temporary store. Memory remains bounded by SQLite's
// page cache and one command's immutable mutation encoding.
func projectionStateDigestAtResultCut(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
	resultCut uint64,
	visit func(chain.LogicalRow) error,
) (_ Digest, err error) {
	if conn == nil ||
		resultCut < genesis.predecessorResultIndex ||
		resultCut > state.resultIndex {
		return Digest{}, errors.New(
			"projection rewind cut is outside the active generation",
		)
	}
	if err := execute(
		conn,
		"DROP TABLE IF EXISTS temp."+projectionRewindTable+";",
	); err != nil {
		return Digest{}, fmt.Errorf(
			"drop stale projection rewind table: %w",
			err,
		)
	}
	if err := execute(
		conn,
		`CREATE TEMP TABLE `+projectionRewindTable+` (
		    table_index INTEGER NOT NULL CHECK (table_index >= 0),
		    table_name TEXT NOT NULL,
		    primary_key BLOB NOT NULL,
		    row_json BLOB NOT NULL,
		    PRIMARY KEY (table_index, primary_key),
		    UNIQUE (table_name, primary_key)
		) STRICT, WITHOUT ROWID;`,
	); err != nil {
		return Digest{}, fmt.Errorf(
			"create projection rewind table: %w",
			err,
		)
	}
	defer func() {
		dropErr := execute(
			conn,
			"DROP TABLE IF EXISTS temp."+projectionRewindTable+";",
		)
		if err == nil && dropErr != nil {
			err = fmt.Errorf(
				"drop projection rewind table: %w",
				dropErr,
			)
		}
	}()

	tables := chain.CoveredTables()
	tableIndexes := make(map[string]int, len(tables))
	for index, table := range tables {
		tableIndexes[table] = index
	}
	if err := streamProjectionLogicalRows(
		conn,
		func(row chain.LogicalRow) error {
			tableIndex, exists := tableIndexes[row.Table]
			if !exists {
				return fmt.Errorf(
					"projection table %q is not covered",
					row.Table,
				)
			}
			return execute(
				conn,
				`INSERT INTO temp.`+projectionRewindTable+`(
				    table_index, table_name, primary_key, row_json
				) VALUES (?1, ?2, ?3, ?4);`,
				tableIndex,
				row.Table,
				row.PrimaryKey,
				row.Row,
			)
		},
	); err != nil {
		return Digest{}, fmt.Errorf(
			"copy current projection rows into rewind table: %w",
			err,
		)
	}

	expectedResult := state.resultIndex
	var rowErr error
	queryErr := queryArgs(
		conn,
		`SELECT result_index, projection_mutations_json
		   FROM command_results
		  WHERE session_id = ?1 AND recovery_generation = ?2
		    AND result_index > ?3
		  ORDER BY result_index DESC;`,
		[]any{
			string(state.sessionID),
			state.recoveryGeneration,
			resultCut,
		},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			storedIndex := stmt.ColumnInt64(0)
			if storedIndex < 1 ||
				expectedResult <= resultCut ||
				uint64(storedIndex) != expectedResult {
				rowErr = errors.New(
					"projection rewind result indexes are not dense",
				)
				return
			}
			encoded := []byte(stmt.ColumnText(1))
			mutations, decodeErr := chain.DecodeMutations(encoded)
			if decodeErr != nil {
				rowErr = decodeErr
				return
			}
			canonical, encodeErr := chain.EncodeMutations(mutations)
			if encodeErr != nil || !bytes.Equal(canonical, encoded) {
				rowErr = errors.New(
					"projection rewind mutations do not round trip",
				)
				return
			}
			for _, mutation := range mutations {
				if mutationErr := rewindProjectionMutation(
					conn,
					tableIndexes,
					mutation,
				); mutationErr != nil {
					rowErr = mutationErr
					return
				}
			}
			expectedResult--
		},
	)
	if queryErr != nil {
		return Digest{}, queryErr
	}
	if rowErr != nil {
		return Digest{}, rowErr
	}
	if expectedResult != resultCut {
		return Digest{}, errors.New(
			"projection rewind did not reach requested cut",
		)
	}

	counts := make([]chain.TableRowCount, len(tables))
	for index, table := range tables {
		counts[index].Table = table
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM temp.`+projectionRewindTable+`
			  WHERE table_index = ?1 AND table_name = ?2;`,
			[]any{index, table},
			func(stmt *sqlite.Stmt) {
				value := stmt.ColumnInt64(0)
				if value < 0 {
					counts[index].Count = domain.MaxSafeInteger + 1
					return
				}
				counts[index].Count = uint64(value)
			},
		); err != nil {
			return Digest{}, err
		}
		if !domain.ValidUnsignedInteger(counts[index].Count) {
			return Digest{}, errors.New(
				"projection rewind row count exceeds exact range",
			)
		}
	}
	digester, err := chain.NewStateDigester(chain.Versions{
		Digest:           state.digestVersion,
		ProjectionSchema: state.projectionSchemaVersion,
	}, counts)
	if err != nil {
		return Digest{}, err
	}
	queryErr = query(
		conn,
		`SELECT table_name, primary_key, row_json
		   FROM temp.`+projectionRewindTable+`
		  ORDER BY table_index, primary_key;`,
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			row := chain.LogicalRow{
				Table:      stmt.ColumnText(0),
				PrimaryKey: bytes.Clone(columnBytes(stmt, 1)),
				Row:        bytes.Clone(columnBytes(stmt, 2)),
			}
			if rowErr = digester.Append(row); rowErr != nil {
				return
			}
			if visit != nil {
				rowErr = visit(row)
			}
		},
	)
	if queryErr != nil {
		return Digest{}, queryErr
	}
	if rowErr != nil {
		return Digest{}, rowErr
	}
	digest, err := digester.Sum()
	return Digest(digest), err
}

func projectionAuthorityRowsAtResultCut(
	conn *sqlite.Conn,
	state consensusState,
	genesis storedGenesisBoundary,
	resultCut uint64,
) ([]chain.LogicalRow, Digest, error) {
	var authorityRow chain.LogicalRow
	digest, err := projectionStateDigestAtResultCut(
		conn,
		state,
		genesis,
		resultCut,
		func(row chain.LogicalRow) error {
			if row.Table == "credential_authority" {
				if authorityRow.Table != "" {
					return errors.New(
						"projection cut has duplicate credential authority",
					)
				}
				authorityRow = cloneLogicalRow(row)
			}
			return nil
		},
	)
	if err != nil {
		return nil, Digest{}, err
	}
	if authorityRow.Table == "" {
		return nil, Digest{}, errors.New(
			"projection cut is missing credential authority",
		)
	}
	authority, err := projectionCutAuthority(
		authorityRow.Row,
		state.sessionID,
	)
	if err != nil {
		return nil, Digest{}, fmt.Errorf(
			"decode projection-cut credential authority: %w",
			err,
		)
	}

	rows := make(
		[]chain.LogicalRow,
		0,
		2*int(policy.MaxMemberDevices)+1,
	)
	rows = append(rows, authorityRow)
	activeCount := 0
	secondDigest, err := projectionStateDigestAtResultCut(
		conn,
		state,
		genesis,
		resultCut,
		func(row chain.LogicalRow) error {
			if row.Table != "devices" {
				return nil
			}
			member, err := decodeEvidenceDevice(row.Row)
			if err != nil {
				return err
			}
			if member.Status == device.StatusActive {
				activeCount++
				if activeCount > int(policy.MaxMemberDevices) {
					return errors.New(
						"projection cut exceeds the active device limit",
					)
				}
			}
			if member.Status == device.StatusActive ||
				authority.Contains(member.ID) {
				rows = append(rows, cloneLogicalRow(row))
			}
			return nil
		},
	)
	if err != nil {
		return nil, Digest{}, err
	}
	if secondDigest != digest {
		return nil, Digest{}, errors.New(
			"projection cut changed during authority reconstruction",
		)
	}
	return rows, digest, nil
}

func projectionCutAuthority(
	raw []byte,
	sessionID domain.UUIDv7,
) (voterset.Set, error) {
	var wire struct {
		SessionID       string   `json:"session_id"`
		VoterDeviceIDs  []string `json:"voter_device_ids"`
		VoterSetVersion uint64   `json:"voter_set_version"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return voterset.Set{}, err
	}
	if domain.UUIDv7(wire.SessionID) != sessionID {
		return voterset.Set{}, errors.New(
			"credential authority changes session",
		)
	}
	voters := make([]domain.DeviceID, len(wire.VoterDeviceIDs))
	for index, encoded := range wire.VoterDeviceIDs {
		voters[index] = domain.DeviceID(encoded)
	}
	return voterset.New(sessionID, voters, wire.VoterSetVersion)
}

func rewindProjectionMutation(
	conn *sqlite.Conn,
	tableIndexes map[string]int,
	mutation chain.Mutation,
) error {
	tableIndex, exists := tableIndexes[mutation.Table]
	if !exists {
		return fmt.Errorf(
			"projection mutation table %q is not covered",
			mutation.Table,
		)
	}
	var (
		current []byte
		count   int
	)
	if err := queryArgs(
		conn,
		`SELECT row_json
		   FROM temp.`+projectionRewindTable+`
		  WHERE table_index = ?1 AND table_name = ?2
		    AND primary_key = ?3;`,
		[]any{tableIndex, mutation.Table, mutation.PrimaryKey},
		func(stmt *sqlite.Stmt) {
			count++
			current = bytes.Clone(columnBytes(stmt, 0))
		},
	); err != nil {
		return err
	}
	if count > 1 ||
		(mutation.After == nil) != (count == 0) ||
		mutation.After != nil && !bytes.Equal(current, mutation.After) {
		return fmt.Errorf(
			"projection mutation after-image differs from later state: "+
				"table=%q key_sha256=%x expected_present=%t "+
				"current_rows=%d expected_sha256=%x current_sha256=%x",
			mutation.Table,
			sha256.Sum256(mutation.PrimaryKey),
			mutation.After != nil,
			count,
			sha256.Sum256(mutation.After),
			sha256.Sum256(current),
		)
	}
	if mutation.Before == nil {
		return execute(
			conn,
			`DELETE FROM temp.`+projectionRewindTable+`
			  WHERE table_index = ?1 AND table_name = ?2
			    AND primary_key = ?3;`,
			tableIndex,
			mutation.Table,
			mutation.PrimaryKey,
		)
	}
	return execute(
		conn,
		`INSERT INTO temp.`+projectionRewindTable+`(
		    table_index, table_name, primary_key, row_json
		) VALUES (?1, ?2, ?3, ?4)
		ON CONFLICT(table_index, primary_key) DO UPDATE
		    SET table_name = excluded.table_name,
		        row_json = excluded.row_json;`,
		tableIndex,
		mutation.Table,
		mutation.PrimaryKey,
		mutation.Before,
	)
}
