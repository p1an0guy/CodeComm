package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type projectionValueKind uint8

const (
	projectionText projectionValueKind = iota + 1
	projectionInteger
	projectionJSON
	projectionBlob
	projectionBoolean
)

type projectionColumn struct {
	storageName string
	logicalName string
	kind        projectionValueKind
	primaryKey  bool
}

type projectionTable struct {
	name    string
	columns []projectionColumn
}

func column(name string, kind projectionValueKind) projectionColumn {
	return projectionColumn{
		storageName: name,
		logicalName: name,
		kind:        kind,
	}
}

func renamedColumn(
	storageName string,
	logicalName string,
	kind projectionValueKind,
) projectionColumn {
	return projectionColumn{
		storageName: storageName,
		logicalName: logicalName,
		kind:        kind,
	}
}

func primaryColumn(name string, kind projectionValueKind) projectionColumn {
	result := column(name, kind)
	result.primaryKey = true
	return result
}

var projectionTables = []projectionTable{
	{
		name: "origin_scopes",
		columns: []projectionColumn{
			primaryColumn("device_id", projectionText),
			primaryColumn("scope_kind", projectionText),
			primaryColumn("scope_id", projectionText),
			column("last_sequence", projectionInteger),
		},
	},
	{
		name: "audit_counters",
		columns: []projectionColumn{
			primaryColumn("device_id", projectionText),
			column("credential_epoch", projectionInteger),
			column("accepted_count", projectionInteger),
		},
	},
	{
		name: "tasks",
		columns: []projectionColumn{
			primaryColumn("task_id", projectionText),
			column("title", projectionText),
			column("body", projectionText),
			column("state", projectionText),
			column("state_reason", projectionText),
			column("priority", projectionInteger),
			renamedColumn("blocked_by_json", "blocked_by", projectionJSON),
			renamedColumn("labels_json", "labels", projectionJSON),
			column("owner_device_id", projectionText),
			column("owner_agent_session_id", projectionText),
			column("intended_device_id", projectionText),
			column("last_release_reason", projectionText),
			column("entity_version", projectionInteger),
			column("created_at", projectionText),
			column("updated_at", projectionText),
		},
	},
	{
		name: "plan_revisions",
		columns: []projectionColumn{
			primaryColumn("plan_revision_id", projectionText),
			column("supersedes", projectionText),
			column("title", projectionText),
			column("body", projectionText),
			renamedColumn("task_ids_json", "task_ids", projectionJSON),
			column("proposed_by_device_id", projectionText),
			column("created_at", projectionText),
		},
	},
	{
		name: "plan_current",
		columns: []projectionColumn{
			primaryColumn("session_id", projectionText),
			column("plan_revision_id", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "memory_records",
		columns: []projectionColumn{
			primaryColumn("memory_id", projectionText),
			column("scope", projectionText),
			column("task_id", projectionText),
			column("key", projectionText),
			column("body", projectionText),
			column("supersedes", projectionText),
			column("created_at", projectionText),
		},
	},
	{
		name: "leases",
		columns: []projectionColumn{
			primaryColumn("lease_id", projectionText),
			column("holder_device_id", projectionText),
			column("holder_agent_session_id", projectionText),
			column("scope", projectionText),
			column("task_id", projectionText),
			renamedColumn("path_globs_json", "path_globs", projectionJSON),
			column("ttl_seconds", projectionInteger),
			column("status", projectionText),
			column("release_reason", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "devices",
		columns: []projectionColumn{
			primaryColumn("device_id", projectionText),
			column("role", projectionText),
			column("identity_public_key", projectionBlob),
			column("daemon_version", projectionText),
			column("max_apply_level", projectionInteger),
			column("status", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "voter_set",
		columns: []projectionColumn{
			primaryColumn("session_id", projectionText),
			renamedColumn(
				"voter_device_ids_json",
				"voter_device_ids",
				projectionJSON,
			),
			column("voter_set_version", projectionInteger),
		},
	},
	{
		name: "credential_authority",
		columns: []projectionColumn{
			primaryColumn("session_id", projectionText),
			renamedColumn(
				"voter_device_ids_json",
				"voter_device_ids",
				projectionJSON,
			),
			column("voter_set_version", projectionInteger),
			column("activation_source", projectionText),
			column("activation_checkpoint_event_id", projectionText),
			renamedColumn(
				"activation_proofs_json",
				"activation_proofs",
				projectionJSON,
			),
			column("prior_authority_signer", projectionText),
			column("prior_authority_handoff", projectionBlob),
		},
	},
	{
		name: "agent_sessions",
		columns: []projectionColumn{
			primaryColumn("agent_session_id", projectionText),
			column("device_id", projectionText),
			column("client_kind", projectionText),
			column("agent_profile_id", projectionText),
			column("state", projectionText),
			column("resume_state", projectionText),
			column("working_root_id", projectionText),
			column("end_reason", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "canonical_refs",
		columns: []projectionColumn{
			primaryColumn("ref_name", projectionText),
			column("commit_oid", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "credential_authorizations",
		columns: []projectionColumn{
			primaryColumn("session_id", projectionText),
			primaryColumn("device_id", projectionText),
			primaryColumn("epoch", projectionInteger),
			column("epoch_public_key", projectionBlob),
			column("key_digest", projectionBlob),
			column("role", projectionText),
			column("issued_at", projectionText),
			column("not_before", projectionText),
			column("validity_seconds", projectionInteger),
			column("authority_voter_set_version", projectionInteger),
			renamedColumn(
				"clock_endorsements_json",
				"clock_endorsements",
				projectionJSON,
			),
			column("binding_signature", projectionBlob),
			column("authorization_chain_index", projectionInteger),
		},
	},
	{
		name: "publications",
		columns: []projectionColumn{
			primaryColumn("publication_id", projectionText),
			column("proposal_event_id", projectionText),
			column("supersedes_publication_id", projectionText),
			column("task_id", projectionText),
			column("author_device_id", projectionText),
			column("author_agent_session_id", projectionText),
			column("base_commit", projectionText),
			column("commit_oid", projectionText),
			column("tree_oid", projectionText),
			renamedColumn("parent_oids_json", "parent_oids", projectionJSON),
			renamedColumn("paths_json", "paths", projectionJSON),
			column("artifact_digest", projectionBlob),
			renamedColumn(
				"resolves_conflict_ids_json",
				"resolves_conflict_ids",
				projectionJSON,
			),
			column("working_root_id", projectionText),
			renamedColumn(
				"staging_receipts_json",
				"staging_receipts",
				projectionJSON,
			),
			column("state", projectionText),
			column("terminal_source", projectionText),
			column("canonical_lineage_member", projectionBoolean),
			column("review_verdict", projectionText),
			column("reviewer_device_id", projectionText),
			column("reviewer_agent_session_id", projectionText),
			column("review_actor_type", projectionText),
			column("decision_reason", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "control_file_proposals",
		columns: []projectionColumn{
			primaryColumn("proposal_event_id", projectionText),
			column("session_id", projectionText),
			column("path", projectionText),
			column("operation", projectionText),
			column("content_digest", projectionBlob),
			column("content_size", projectionInteger),
			column("diff", projectionText),
			column("proposed_by_device_id", projectionText),
			column("chain_index", projectionInteger),
		},
	},
	{
		name: "merge_conflicts",
		columns: []projectionColumn{
			primaryColumn("conflict_id", projectionText),
			column("publication_id", projectionText),
			column("merge_kind", projectionText),
			column("replay_commit_oid", projectionText),
			renamedColumn(
				"merge_base_oids_json",
				"merge_base_oids",
				projectionJSON,
			),
			column("canonical_commit", projectionText),
			column("candidate_commit", projectionText),
			renamedColumn("paths_json", "paths", projectionJSON),
			column("status", projectionText),
			column("resolution_kind", projectionText),
			column("resolution_publication_id", projectionText),
			column("force_reason", projectionText),
			column("resolved_by_device_id", projectionText),
			column("entity_version", projectionInteger),
		},
	},
	{
		name: "session_policy",
		columns: []projectionColumn{
			primaryColumn("session_id", projectionText),
			renamedColumn("values_json", "values", projectionJSON),
			column("entity_version", projectionInteger),
		},
	},
}

func init() {
	covered := chain.CoveredTables()
	if len(covered) != len(projectionTables) {
		panic("store: projection registry length differs from chain registry")
	}
	for index := range covered {
		if covered[index] != projectionTables[index].name {
			panic("store: projection registry order differs from chain registry")
		}
	}
}

type projectionTarget struct {
	table         projectionTable
	keyArguments  []any
	primaryKey    []byte
	expectedAfter []byte
}

func projectionMutations(
	conn *sqlite.Conn,
	prepared preparedProjectionWrites,
) ([]chain.Mutation, error) {
	targets, err := projectionTargets(prepared)
	if err != nil {
		return nil, err
	}
	mutations := make([]chain.Mutation, len(targets))
	for index, target := range targets {
		before, found, err := readProjectionRow(
			conn,
			target.table,
			target.keyArguments,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"store: read %s before image: %w",
				target.table.name,
				err,
			)
		}
		mutations[index] = chain.Mutation{
			Table:      target.table.name,
			PrimaryKey: bytes.Clone(target.primaryKey),
		}
		if found {
			mutations[index].Before = before.Row
		}
	}

	if err := writePreparedProjections(conn, prepared); err != nil {
		return nil, err
	}
	for index, target := range targets {
		after, found, err := readProjectionRow(
			conn,
			target.table,
			target.keyArguments,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"store: read %s after image: %w",
				target.table.name,
				err,
			)
		}
		if !found {
			return nil, fmt.Errorf(
				"%w: %s write produced no row",
				ErrIntegrityCheck,
				target.table.name,
			)
		}
		if !bytes.Equal(after.PrimaryKey, target.primaryKey) ||
			!bytes.Equal(after.Row, target.expectedAfter) {
			return nil, fmt.Errorf(
				"%w: %s after image differs from validated write",
				ErrIntegrityCheck,
				target.table.name,
			)
		}
		mutations[index].After = after.Row
	}
	return mutations, nil
}

func projectionTargets(
	prepared preparedProjectionWrites,
) ([]projectionTarget, error) {
	rowsByTable := preparedProjectionRows(prepared)
	var targets []projectionTarget
	seen := make(map[string]struct{})
	for _, table := range projectionTables {
		for rowIndex, values := range rowsByTable[table.name] {
			logical, keyArguments, err := logicalProjectionRowFromValues(
				table,
				values,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"store: encode %s row %d: %w",
					table.name,
					rowIndex,
					err,
				)
			}
			identity := table.name + "\x00" + string(logical.PrimaryKey)
			if _, exists := seen[identity]; exists {
				return nil, fmt.Errorf(
					"%w: duplicate %s primary key in one write set",
					ErrInvalidApply,
					table.name,
				)
			}
			seen[identity] = struct{}{}
			targets = append(targets, projectionTarget{
				table:         table,
				keyArguments:  keyArguments,
				primaryKey:    logical.PrimaryKey,
				expectedAfter: logical.Row,
			})
		}
	}
	return targets, nil
}

func preparedProjectionRows(
	prepared preparedProjectionWrites,
) map[string][][]any {
	return map[string][][]any{
		"origin_scopes":             prepared.originScopes,
		"audit_counters":            prepared.auditCounters,
		"tasks":                     prepared.tasks,
		"plan_revisions":            prepared.planRevisions,
		"plan_current":              prepared.planCurrent,
		"memory_records":            prepared.memoryRecords,
		"leases":                    prepared.leases,
		"devices":                   prepared.devices,
		"voter_set":                 prepared.voterSet,
		"credential_authority":      prepared.credentialAuthority,
		"agent_sessions":            prepared.agentSessions,
		"canonical_refs":            prepared.canonicalRefs,
		"credential_authorizations": prepared.credentialAuthorizations,
		"publications":              prepared.publications,
		"control_file_proposals":    prepared.controlFileProposals,
		"merge_conflicts":           prepared.mergeConflicts,
		"session_policy":            prepared.sessionPolicy,
	}
}

func logicalProjectionRowFromValues(
	table projectionTable,
	values []any,
) (chain.LogicalRow, []any, error) {
	if len(values) != len(table.columns) {
		return chain.LogicalRow{}, nil, fmt.Errorf(
			"got %d values, want %d",
			len(values),
			len(table.columns),
		)
	}
	object := make(map[string]any, len(values))
	var (
		primaryKey   []any
		keyArguments []any
	)
	for index, value := range values {
		column := table.columns[index]
		logical, err := logicalProjectionValue(column.kind, value)
		if err != nil {
			return chain.LogicalRow{}, nil, fmt.Errorf(
				"column %s: %w",
				column.storageName,
				err,
			)
		}
		object[column.logicalName] = logical
		if column.primaryKey {
			if value == nil {
				return chain.LogicalRow{}, nil, fmt.Errorf(
					"primary-key column %s is null",
					column.storageName,
				)
			}
			primaryKey = append(primaryKey, logical)
			keyArguments = append(keyArguments, value)
		}
	}
	pkBytes, rowBytes, err := encodeLogicalProjectionRow(primaryKey, object)
	return chain.LogicalRow{
		Table:      table.name,
		PrimaryKey: pkBytes,
		Row:        rowBytes,
	}, keyArguments, err
}

func logicalProjectionValue(kind projectionValueKind, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch kind {
	case projectionText:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("got %T, want text", value)
		}
		if !utf8.ValidString(text) {
			return nil, errors.New("text is not valid UTF-8")
		}
		return text, nil
	case projectionInteger:
		switch value := value.(type) {
		case int:
			if value < 0 {
				return nil, errors.New("negative integer")
			}
			return uint64(value), nil
		case int32:
			if value < 0 {
				return nil, errors.New("negative integer")
			}
			return uint64(value), nil
		case int64:
			if value < 0 {
				return nil, errors.New("negative integer")
			}
			return uint64(value), nil
		case uint:
			return uint64(value), nil
		case uint32:
			return uint64(value), nil
		case uint64:
			return value, nil
		default:
			return nil, fmt.Errorf("got %T, want integer", value)
		}
	case projectionJSON:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("got %T, want canonical JSON text", value)
		}
		canonical, err := codec.Canonicalize([]byte(text))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(canonical, []byte(text)) {
			return nil, errors.New("JSON text is not canonical")
		}
		return json.RawMessage(canonical), nil
	case projectionBlob:
		value, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("got %T, want blob", value)
		}
		return codec.EncodeBase64URL(value), nil
	case projectionBoolean:
		value, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("got %T, want boolean", value)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("unknown logical kind %d", kind)
	}
}

func encodeLogicalProjectionRow(
	primaryKey []any,
	object map[string]any,
) ([]byte, []byte, error) {
	if len(primaryKey) == 0 {
		return nil, nil, errors.New("empty primary key")
	}
	encodedPK, err := json.Marshal(primaryKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal primary key: %w", err)
	}
	canonicalPK, err := codec.Canonicalize(encodedPK)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize primary key: %w", err)
	}
	encodedRow, err := json.Marshal(object)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal row: %w", err)
	}
	canonicalRow, err := codec.CanonicalizeSignedObject(encodedRow)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize row: %w", err)
	}
	return canonicalPK, canonicalRow, nil
}

func readProjectionRow(
	conn *sqlite.Conn,
	table projectionTable,
	keyArguments []any,
) (chain.LogicalRow, bool, error) {
	primaryColumns := projectionPrimaryColumns(table)
	if len(keyArguments) != len(primaryColumns) {
		return chain.LogicalRow{}, false, fmt.Errorf(
			"got %d key values, want %d",
			len(keyArguments),
			len(primaryColumns),
		)
	}
	statement := "SELECT " + projectionColumnList(table) +
		" FROM " + table.name + " WHERE " +
		projectionKeyPredicate(primaryColumns) + ";"
	var (
		result chain.LogicalRow
		count  int
		rowErr error
	)
	err := queryArgs(conn, statement, keyArguments, func(stmt *sqlite.Stmt) {
		count++
		if count != 1 {
			return
		}
		result, rowErr = logicalProjectionRowFromStatement(table, stmt)
	})
	if err != nil {
		return chain.LogicalRow{}, false, err
	}
	if rowErr != nil {
		return chain.LogicalRow{}, false, rowErr
	}
	if count > 1 {
		return chain.LogicalRow{}, false, fmt.Errorf(
			"%w: %s primary key returned %d rows",
			ErrIntegrityCheck,
			table.name,
			count,
		)
	}
	return result, count == 1, nil
}

func logicalProjectionRowFromStatement(
	table projectionTable,
	stmt *sqlite.Stmt,
) (chain.LogicalRow, error) {
	object := make(map[string]any, len(table.columns))
	var primaryKey []any
	for index, column := range table.columns {
		value, err := logicalProjectionColumn(stmt, index, column.kind)
		if err != nil {
			return chain.LogicalRow{}, fmt.Errorf(
				"column %s: %w",
				column.storageName,
				err,
			)
		}
		object[column.logicalName] = value
		if column.primaryKey {
			if value == nil {
				return chain.LogicalRow{}, fmt.Errorf(
					"primary-key column %s is null",
					column.storageName,
				)
			}
			primaryKey = append(primaryKey, value)
		}
	}
	pkBytes, rowBytes, err := encodeLogicalProjectionRow(primaryKey, object)
	if err != nil {
		return chain.LogicalRow{}, err
	}
	return chain.LogicalRow{
		Table:      table.name,
		PrimaryKey: pkBytes,
		Row:        rowBytes,
	}, nil
}

func logicalProjectionColumn(
	stmt *sqlite.Stmt,
	index int,
	kind projectionValueKind,
) (any, error) {
	if stmt.ColumnType(index) == sqlite.TypeNull {
		return nil, nil
	}
	switch kind {
	case projectionText:
		if stmt.ColumnType(index) != sqlite.TypeText {
			return nil, fmt.Errorf("got SQLite type %v, want text", stmt.ColumnType(index))
		}
		text := stmt.ColumnText(index)
		if !utf8.ValidString(text) {
			return nil, errors.New("stored text is not valid UTF-8")
		}
		return text, nil
	case projectionInteger:
		if stmt.ColumnType(index) != sqlite.TypeInteger {
			return nil, fmt.Errorf("got SQLite type %v, want integer", stmt.ColumnType(index))
		}
		value := stmt.ColumnInt64(index)
		if value < 0 {
			return nil, errors.New("negative integer")
		}
		return uint64(value), nil
	case projectionJSON:
		if stmt.ColumnType(index) != sqlite.TypeText {
			return nil, fmt.Errorf("got SQLite type %v, want JSON text", stmt.ColumnType(index))
		}
		text := stmt.ColumnText(index)
		canonical, err := codec.Canonicalize([]byte(text))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(canonical, []byte(text)) {
			return nil, errors.New("stored JSON text is not canonical")
		}
		return json.RawMessage(canonical), nil
	case projectionBlob:
		if stmt.ColumnType(index) != sqlite.TypeBlob {
			return nil, fmt.Errorf("got SQLite type %v, want blob", stmt.ColumnType(index))
		}
		return codec.EncodeBase64URL(columnBytes(stmt, index)), nil
	case projectionBoolean:
		if stmt.ColumnType(index) != sqlite.TypeInteger {
			return nil, fmt.Errorf("got SQLite type %v, want boolean integer", stmt.ColumnType(index))
		}
		value := stmt.ColumnInt64(index)
		if value != 0 && value != 1 {
			return nil, fmt.Errorf("boolean integer is %d", value)
		}
		return value == 1, nil
	default:
		return nil, fmt.Errorf("unknown logical kind %d", kind)
	}
}

func projectionPrimaryColumns(table projectionTable) []projectionColumn {
	var columns []projectionColumn
	for _, column := range table.columns {
		if column.primaryKey {
			columns = append(columns, column)
		}
	}
	return columns
}

func projectionColumnList(table projectionTable) string {
	names := make([]string, len(table.columns))
	for index, column := range table.columns {
		names[index] = column.storageName
	}
	return strings.Join(names, ", ")
}

func projectionKeyPredicate(columns []projectionColumn) string {
	predicates := make([]string, len(columns))
	for index, column := range columns {
		predicates[index] = fmt.Sprintf("%s = ?%d", column.storageName, index+1)
	}
	return strings.Join(predicates, " AND ")
}

func projectionLogicalRows(conn *sqlite.Conn) ([]chain.LogicalRow, error) {
	var rows []chain.LogicalRow
	for _, table := range projectionTables {
		statement := "SELECT " + projectionColumnList(table) +
			" FROM " + table.name + ";"
		var rowErr error
		err := query(conn, statement, func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			var row chain.LogicalRow
			row, rowErr = logicalProjectionRowFromStatement(table, stmt)
			if rowErr == nil {
				rows = append(rows, row)
			}
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", table.name, err)
		}
		if rowErr != nil {
			return nil, fmt.Errorf("encode %s: %w", table.name, rowErr)
		}
	}
	return rows, nil
}

func projectionStateDigest(
	conn *sqlite.Conn,
	versions chain.Versions,
) (Digest, error) {
	rows, err := projectionLogicalRows(conn)
	if err != nil {
		return Digest{}, err
	}
	digest, err := chain.StateDigest(versions, rows)
	if err != nil {
		return Digest{}, fmt.Errorf("store: projection state digest: %w", err)
	}
	return Digest(digest), nil
}

// ProjectionStateDigest computes the full logical digest of all 17 covered
// projections using the versions bound to the active generation.
func (store *Store) ProjectionStateDigest(ctx context.Context) (Digest, error) {
	store.applyMu.Lock()
	defer store.applyMu.Unlock()

	var digest Digest
	err := store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)

		state, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("%w: store has no active generation", ErrApplyConflict)
		}
		digest, err = projectionStateDigest(conn, chain.Versions{
			Digest:           state.digestVersion,
			ProjectionSchema: state.projectionSchemaVersion,
		})
		return err
	})
	return digest, err
}
