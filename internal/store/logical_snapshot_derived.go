package store

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"zombiezen.com/go/sqlite"
)

var logicalSnapshotDerivedDomain = []byte(
	"codecomm/v1/logical-snapshot-derived-views",
)

type logicalSnapshotDerivedQuery struct {
	table   string
	columns int
	query   string
}

var logicalSnapshotDerivedQueries = [...]logicalSnapshotDerivedQuery{
	{
		table:   "activity",
		columns: 12,
		query: `SELECT event_id, session_id, device_id, actor_type,
		              agent_session_id, event_kind, task_id,
		              rationale_summary, capture_level, actions_json,
		              redaction_json, created_at
		         FROM activity
		        ORDER BY event_id;`,
	},
	{
		table:   "audit_events",
		columns: 16,
		query: `SELECT session_id, source_kind, event_id, result_index,
		              reporter_device_id, subject_device_id,
		              subject_credential_epoch, actor_type, ipc_channel,
		              action_code, outcome_code, subject, details_json,
		              first_seen_at, last_seen_at, observation_count
		         FROM audit_events
		        ORDER BY session_id, source_kind, event_id, result_index,
		                 reporter_device_id, subject_device_id,
		                 subject_credential_epoch, actor_type, ipc_channel,
		                 action_code, outcome_code, subject, details_json,
		                 first_seen_at, last_seen_at, observation_count,
		                 audit_id;`,
	},
}

func logicalSnapshotDerivedViewsDigest(
	conn *sqlite.Conn,
) (Digest, error) {
	if conn == nil {
		return Digest{}, errors.New(
			"store: nil logical snapshot derived-view connection",
		)
	}
	digester := sha256.New()
	writeDerivedDigestBytes(digester, logicalSnapshotDerivedDomain)
	for _, specification := range logicalSnapshotDerivedQueries {
		writeDerivedDigestBytes(digester, []byte(specification.table))
		var rowErr error
		if err := query(
			conn,
			specification.query,
			func(stmt *sqlite.Stmt) {
				if rowErr != nil {
					return
				}
				writeDerivedDigestBytes(digester, []byte{0xff})
				for column := 0; column < specification.columns; column++ {
					if err := writeDerivedDigestColumn(
						digester,
						stmt,
						column,
					); err != nil {
						rowErr = err
						return
					}
				}
			},
		); err != nil {
			return Digest{}, err
		}
		if rowErr != nil {
			return Digest{}, rowErr
		}
		writeDerivedDigestBytes(digester, []byte{0x00})
	}
	var result Digest
	copy(result[:], digester.Sum(nil))
	return result, nil
}

func writeDerivedDigestColumn(
	digester hash.Hash,
	stmt *sqlite.Stmt,
	column int,
) error {
	columnType := stmt.ColumnType(column)
	if _, err := digester.Write([]byte{byte(columnType)}); err != nil {
		return err
	}
	switch columnType {
	case sqlite.TypeNull:
		writeDerivedDigestBytes(digester, nil)
	case sqlite.TypeInteger:
		var encoded [8]byte
		binary.BigEndian.PutUint64(
			encoded[:],
			uint64(stmt.ColumnInt64(column)),
		)
		writeDerivedDigestBytes(digester, encoded[:])
	case sqlite.TypeText:
		writeDerivedDigestBytes(
			digester,
			[]byte(stmt.ColumnText(column)),
		)
	case sqlite.TypeBlob:
		writeDerivedDigestBytes(
			digester,
			columnBytes(stmt, column),
		)
	default:
		return errors.New(
			"store: unsupported logical snapshot derived-view column type",
		)
	}
	return nil
}

func writeDerivedDigestBytes(digester hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digester.Write(size[:])
	_, _ = digester.Write(value)
}
