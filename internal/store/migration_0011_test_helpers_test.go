package store

import (
	"fmt"

	"zombiezen.com/go/sqlite"
)

func rewriteCommandResultPayloadForTest(
	conn *sqlite.Conn,
	resultIndex uint64,
	mutate func(*commandResultPayload),
) error {
	payload, err := requireCommandResultPayload(conn, resultIndex)
	if err != nil {
		return err
	}
	mutate(&payload)
	encoded, err := encodeCommandResultPayload(payload)
	if err != nil {
		return err
	}
	return execute(
		conn,
		`UPDATE command_result_payloads
		    SET codec_version = ?1, uncompressed_size = ?2,
		        uncompressed_sha256 = ?3, compressed_payload = ?4
		  WHERE result_index = ?5;`,
		uint64(encoded.codecVersion),
		encoded.uncompressedSize,
		encoded.checksum[:],
		encoded.compressed,
		resultIndex,
	)
}

// downgradeCommandResultPayloadsForTest restores the exact v10
// representation so older-migration tests do not leave v11 schema behind.
func downgradeCommandResultPayloadsForTest(conn *sqlite.Conn) error {
	var indexes []uint64
	var rowErr error
	if err := query(
		conn,
		"SELECT result_index FROM command_results ORDER BY result_index;",
		func(stmt *sqlite.Stmt) {
			value := stmt.ColumnInt64(0)
			if value < 1 {
				rowErr = fmt.Errorf("invalid result index %d", value)
				return
			}
			indexes = append(indexes, uint64(value))
		},
	); err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	for _, index := range indexes {
		payload, err := requireCommandResultPayload(conn, index)
		if err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE command_results
			    SET proposal_json = ?1, outcome_json = ?2,
			        projection_mutations_json = ?3
			  WHERE result_index = ?4;`,
			string(payload.proposal),
			string(payload.outcome),
			string(payload.mutations),
			index,
		); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE events
			    SET proposal_json = ?1
			  WHERE event_id = (
			        SELECT event_id
			          FROM command_results
			         WHERE result_index = ?2
			           AND outcome_status = 'accepted'
			  );`,
			string(payload.proposal),
			index,
		); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		"DROP TABLE command_result_payloads;",
		"DROP TABLE command_result_payload_migration;",
		"DROP INDEX local_requests_session_state;",
		"DROP INDEX local_requests_scope_state;",
		`CREATE INDEX local_requests_session_state
		    ON local_requests (session_id, recovery_generation, state);`,
		`CREATE INDEX local_requests_scope_state
		    ON local_requests (origin_scope_kind, origin_scope_id, state);`,
		"DELETE FROM schema_migrations WHERE version = 11;",
	} {
		if err := execute(conn, statement); err != nil {
			return err
		}
	}
	return nil
}
