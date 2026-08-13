package store

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"zombiezen.com/go/sqlite"
)

const (
	MaxLocalTaskQuery = 200

	// MaxLocalAgentSessionQuery bounds one local session projection read to
	// the design's maximum active agent-session population.
	MaxLocalAgentSessionQuery = int(policy.MaxActiveAgentSessions)
)

// AgentContextSnapshot is the typed, transactionally consistent core used by
// one bound agent's context response.
type AgentContextSnapshot struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	Heads              ApplyHeads
	Self               agentsession.Session
	Tasks              []task.Task
}

// ListAgentSessions returns a stable, bounded set of validated agent-session
// projections.
func (state LocalState) ListAgentSessions(
	ctx context.Context,
	limit int,
) ([]agentsession.Session, error) {
	if limit < 1 || limit > MaxLocalAgentSessionQuery {
		return nil, ErrInvalidLocalState
	}
	var sessions []agentsession.Session
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		ids := make([]domain.UUIDv7, 0, limit)
		if err := queryArgs(
			conn,
			`SELECT agent_session_id
			   FROM agent_sessions
			  ORDER BY agent_session_id
			  LIMIT ?1;`,
			[]any{limit},
			func(stmt *sqlite.Stmt) {
				ids = append(ids, domain.UUIDv7(stmt.ColumnText(0)))
			},
		); err != nil {
			return err
		}
		for _, id := range ids {
			session, found, err := readCommittedAgentSession(conn, id)
			if err != nil {
				return err
			}
			if !found {
				return ErrLocalStateIntegrity
			}
			sessions = append(sessions, session)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// NonterminalAgentSessions returns every live or resumable session. The
// committed policy hard ceiling makes an overflow an integrity failure.
func (state LocalState) NonterminalAgentSessions(
	ctx context.Context,
) ([]agentsession.Session, error) {
	var sessions []agentsession.Session
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		ids := make([]domain.UUIDv7, 0, MaxLocalAgentSessionQuery+1)
		if err := queryArgs(
			conn,
			`SELECT agent_session_id
			   FROM agent_sessions
			  WHERE state <> 'ended'
			  ORDER BY agent_session_id
			  LIMIT ?1;`,
			[]any{MaxLocalAgentSessionQuery + 1},
			func(stmt *sqlite.Stmt) {
				ids = append(ids, domain.UUIDv7(stmt.ColumnText(0)))
			},
		); err != nil {
			return err
		}
		if len(ids) > MaxLocalAgentSessionQuery {
			return ErrLocalStateIntegrity
		}
		for _, id := range ids {
			session, found, err := readCommittedAgentSession(conn, id)
			if err != nil {
				return err
			}
			if !found || session.State == agentsession.StateEnded {
				return ErrLocalStateIntegrity
			}
			sessions = append(sessions, session)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// AgentContextSnapshot returns one agent and a bounded task view under the
// same apply lock and SQLite transaction as the commitment heads.
func (state LocalState) AgentContextSnapshot(
	ctx context.Context,
	agentSessionID domain.UUIDv7,
	taskLimit int,
) (AgentContextSnapshot, bool, error) {
	if !agentSessionID.Valid() ||
		taskLimit < 1 ||
		taskLimit > MaxLocalTaskQuery {
		return AgentContextSnapshot{}, false, ErrInvalidLocalState
	}
	var (
		snapshot AgentContextSnapshot
		found    bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		committed, committedFound, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !committedFound ||
			committed.sessionID != lineage.sessionID ||
			committed.recoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalStateIntegrity
		}
		self, selfFound, err := readCommittedAgentSession(
			conn,
			agentSessionID,
		)
		if err != nil {
			return err
		}
		if !selfFound {
			return nil
		}
		tasks, err := readTaskProjections(conn, taskLimit)
		if err != nil {
			return err
		}
		snapshot = AgentContextSnapshot{
			SessionID:          lineage.sessionID,
			WorkspaceID:        lineage.workspaceID,
			RecoveryGeneration: lineage.recoveryGeneration,
			Heads:              headsFromConsensus(committed),
			Self:               self,
			Tasks:              tasks,
		}
		found = true
		return nil
	})
	if err != nil {
		return AgentContextSnapshot{}, false, err
	}
	return snapshot, found, nil
}

// ListTasks returns a stable, bounded set of validated task projections.
func (state LocalState) ListTasks(
	ctx context.Context,
	limit int,
) ([]task.Task, error) {
	if limit < 1 || limit > MaxLocalTaskQuery {
		return nil, ErrInvalidLocalState
	}
	var tasks []task.Task
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		tasks, err = readTaskProjections(conn, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

func readTaskProjections(
	conn *sqlite.Conn,
	limit int,
) ([]task.Task, error) {
	var (
		tasks  []task.Task
		rowErr error
	)
	if err := queryArgs(
		conn,
		`SELECT task_id, title, body, state, state_reason, priority,
		        blocked_by_json, labels_json, owner_device_id,
		        owner_agent_session_id, intended_device_id,
		        last_release_reason, entity_version, created_at, updated_at
		   FROM tasks
		  ORDER BY priority, task_id
		  LIMIT ?1;`,
		[]any{limit},
		func(stmt *sqlite.Stmt) {
			if rowErr != nil {
				return
			}
			value, err := decodeTaskProjection(stmt)
			if err != nil {
				rowErr = err
				return
			}
			tasks = append(tasks, value)
		},
	); err != nil {
		return nil, err
	}
	if rowErr != nil {
		return nil, rowErr
	}
	return tasks, nil
}

// Task returns one validated task projection.
func (state LocalState) Task(
	ctx context.Context,
	taskID domain.UUIDv7,
) (task.Task, bool, error) {
	if !taskID.Valid() {
		return task.Task{}, false, ErrInvalidLocalState
	}
	var (
		value task.Task
		found bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var rowErr error
		count := 0
		if err := queryArgs(
			conn,
			`SELECT task_id, title, body, state, state_reason, priority,
			        blocked_by_json, labels_json, owner_device_id,
			        owner_agent_session_id, intended_device_id,
			        last_release_reason, entity_version, created_at, updated_at
			   FROM tasks
			  WHERE task_id = ?1;`,
			[]any{string(taskID)},
			func(stmt *sqlite.Stmt) {
				count++
				found = true
				value, rowErr = decodeTaskProjection(stmt)
			},
		); err != nil {
			return err
		}
		if rowErr != nil || count > 1 {
			return ErrLocalStateIntegrity
		}
		return nil
	})
	if err != nil {
		return task.Task{}, false, err
	}
	return value, found, nil
}

func decodeTaskProjection(stmt *sqlite.Stmt) (task.Task, error) {
	blockedBy, err := decodeCanonicalJSONArray[domain.UUIDv7](
		stmt.ColumnText(6),
	)
	if err != nil {
		return task.Task{}, ErrLocalStateIntegrity
	}
	labels, err := decodeCanonicalJSONArray[string](stmt.ColumnText(7))
	if err != nil {
		return task.Task{}, ErrLocalStateIntegrity
	}
	priority := stmt.ColumnInt64(5)
	version := stmt.ColumnInt64(12)
	if priority < 0 || priority > int64(task.MaxPriority) || version < 1 {
		return task.Task{}, ErrLocalStateIntegrity
	}
	value := task.Task{
		ID:            domain.UUIDv7(stmt.ColumnText(0)),
		Title:         stmt.ColumnText(1),
		Body:          stmt.ColumnText(2),
		State:         task.State(stmt.ColumnText(3)),
		Priority:      task.Priority(priority),
		BlockedBy:     blockedBy,
		Labels:        labels,
		EntityVersion: uint64(version),
		CreatedAt:     domain.Timestamp(stmt.ColumnText(13)),
		UpdatedAt:     domain.Timestamp(stmt.ColumnText(14)),
	}
	if stmt.ColumnType(4) != sqlite.TypeNull {
		text := stmt.ColumnText(4)
		value.StateReason = &text
	}
	if stmt.ColumnType(8) != sqlite.TypeNull {
		value.OwnerDeviceID = domain.DeviceID(stmt.ColumnText(8))
	}
	if stmt.ColumnType(9) != sqlite.TypeNull {
		value.OwnerAgentSessionID = domain.UUIDv7(stmt.ColumnText(9))
	}
	if stmt.ColumnType(10) != sqlite.TypeNull {
		value.IntendedDeviceID = domain.DeviceID(stmt.ColumnText(10))
	}
	if stmt.ColumnType(11) != sqlite.TypeNull {
		value.LastReleaseReason = task.ReleaseReason(stmt.ColumnText(11))
	}
	if err := value.Validate(); err != nil {
		return task.Task{}, ErrLocalStateIntegrity
	}
	return value, nil
}

func decodeCanonicalJSONArray[T any](text string) ([]T, error) {
	encoded := []byte(text)
	if len(encoded) < 2 || encoded[0] != '[' {
		return nil, ErrLocalStateIntegrity
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrLocalStateIntegrity
	}
	var values []T
	if err := json.Unmarshal(encoded, &values); err != nil || values == nil {
		return nil, ErrLocalStateIntegrity
	}
	return values, nil
}
