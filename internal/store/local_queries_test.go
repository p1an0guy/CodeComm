package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"zombiezen.com/go/sqlite"
)

var localQueryDeviceID = domain.DeviceID("cc1" + strings.Repeat("1", 64))

const (
	localQueryCreatedAt = domain.Timestamp("2026-08-12T10:00:00Z")
	localQueryUpdatedAt = domain.Timestamp("2026-08-12T10:01:00Z")
)

func TestLocalTaskQueriesReturnValidatedRowsInStableOrder(t *testing.T) {
	state := openLocalQueryTestState(t)

	first := newLocalQueryTask(1, task.PriorityHigh, "later priority")
	blockedReason := "waiting for dependency"
	second := newLocalQueryTask(2, task.PriorityHighest, "first by ID")
	second.State = task.StateBlocked
	second.StateReason = &blockedReason
	second.BlockedBy = []domain.UUIDv7{localQueryUUID(10), localQueryUUID(11)}
	second.Labels = []string{"backend", "urgent"}
	second.OwnerDeviceID = localQueryDeviceID
	second.OwnerAgentSessionID = localQueryUUID(20)
	third := newLocalQueryTask(3, task.PriorityHighest, "second by ID")
	third.State = task.StateReady
	third.IntendedDeviceID = localQueryDeviceID
	third.LastReleaseReason = task.ReleaseForced
	third.Labels = []string{"sync"}

	writeLocalQueryProjections(
		t,
		state,
		[]task.Task{first, third, second},
		nil,
	)
	want := []task.Task{second, third, first}

	got, err := state.ListTasks(context.Background(), MaxLocalTaskQuery)
	if err != nil {
		t.Fatalf("ListTasks(max): %v", err)
	}
	assertLocalQueryValues(t, got, want)
	for index := range got {
		if err := got[index].Validate(); err != nil {
			t.Fatalf("ListTasks(max)[%d].Validate(): %v", index, err)
		}
	}

	limited, err := state.ListTasks(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListTasks(2): %v", err)
	}
	assertLocalQueryValues(t, limited, want[:2])
	again, err := state.ListTasks(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListTasks(2) repeat: %v", err)
	}
	assertLocalQueryValues(t, again, want[:2])

	found, ok, err := state.Task(context.Background(), second.ID)
	if err != nil {
		t.Fatalf("Task(existing): %v", err)
	}
	if !ok || !reflect.DeepEqual(found, second) {
		t.Fatalf("Task(existing) = (%#v, %t), want (%#v, true)", found, ok, second)
	}
}

func TestLocalTaskQueriesRejectInvalidInputAndReportNotFound(t *testing.T) {
	state := openLocalQueryTestState(t)

	for _, limit := range []int{-1, 0, MaxLocalTaskQuery + 1} {
		if _, err := state.ListTasks(context.Background(), limit); !errors.Is(
			err,
			ErrInvalidLocalState,
		) {
			t.Fatalf("ListTasks(%d) error = %v, want %v", limit, err, ErrInvalidLocalState)
		}
	}
	//lint:ignore SA1012 This test verifies the public nil-context rejection.
	if _, err := state.ListTasks(nil, 1); !errors.Is(err, ErrInvalidLocalState) {
		t.Fatalf("ListTasks(nil context) error = %v, want %v", err, ErrInvalidLocalState)
	}
	if _, _, err := state.Task(
		context.Background(),
		domain.UUIDv7("invalid"),
	); !errors.Is(err, ErrInvalidLocalState) {
		t.Fatalf("Task(invalid ID) error = %v, want %v", err, ErrInvalidLocalState)
	}
	//lint:ignore SA1012 This test verifies the public nil-context rejection.
	if _, _, err := state.Task(nil, localQueryUUID(1)); !errors.Is(
		err,
		ErrInvalidLocalState,
	) {
		t.Fatalf("Task(nil context) error = %v, want %v", err, ErrInvalidLocalState)
	}

	got, err := state.ListTasks(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListTasks(empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListTasks(empty) = %#v, want no rows", got)
	}
	found, ok, err := state.Task(context.Background(), localQueryUUID(99))
	if err != nil {
		t.Fatalf("Task(missing): %v", err)
	}
	if ok || !reflect.DeepEqual(found, task.Task{}) {
		t.Fatalf("Task(missing) = (%#v, %t), want (zero, false)", found, ok)
	}
}

func TestLocalTaskQueriesFailClosedOnMalformedProjection(t *testing.T) {
	tests := []struct {
		name   string
		update string
	}{
		{
			name:   "wrong label type",
			update: "UPDATE tasks SET labels_json = '[1]' WHERE task_id = ?1;",
		},
		{
			name:   "null labels",
			update: "UPDATE tasks SET labels_json = 'null' WHERE task_id = ?1;",
		},
		{
			name:   "noncanonical labels",
			update: "UPDATE tasks SET labels_json = '[ ]' WHERE task_id = ?1;",
		},
		{
			name:   "null blocked by",
			update: "UPDATE tasks SET blocked_by_json = 'null' WHERE task_id = ?1;",
		},
		{
			name:   "noncanonical blocked by",
			update: "UPDATE tasks SET blocked_by_json = '[ ]' WHERE task_id = ?1;",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := openLocalQueryTestState(t)
			value := newLocalQueryTask(1, task.PriorityNormal, "malformed arrays")
			writeLocalQueryProjections(t, state, []task.Task{value}, nil)
			updateLocalQueryRow(t, state, test.update, string(value.ID))

			if _, err := state.ListTasks(context.Background(), 1); !errors.Is(
				err,
				ErrLocalStateIntegrity,
			) {
				t.Fatalf(
					"ListTasks(malformed) error = %v, want %v",
					err,
					ErrLocalStateIntegrity,
				)
			}
			if _, _, err := state.Task(
				context.Background(),
				value.ID,
			); !errors.Is(err, ErrLocalStateIntegrity) {
				t.Fatalf(
					"Task(malformed) error = %v, want %v",
					err,
					ErrLocalStateIntegrity,
				)
			}
		})
	}
}

func TestListAgentSessionsReturnsValidatedRowsInStableBoundedOrder(t *testing.T) {
	state := openLocalQueryTestState(t)
	want := make([]agentsession.Session, MaxLocalAgentSessionQuery+1)
	for index := range want {
		want[index] = newLocalQueryAgentSession(index)
	}
	input := make([]agentsession.Session, len(want))
	for index := range want {
		input[len(input)-1-index] = want[index]
	}
	writeLocalQueryProjections(t, state, nil, input)

	got, err := state.ListAgentSessions(
		context.Background(),
		MaxLocalAgentSessionQuery,
	)
	if err != nil {
		t.Fatalf("ListAgentSessions(max): %v", err)
	}
	assertLocalQueryValues(t, got, want[:MaxLocalAgentSessionQuery])
	for index := range got {
		if err := got[index].Validate(); err != nil {
			t.Fatalf("ListAgentSessions(max)[%d].Validate(): %v", index, err)
		}
	}

	limited, err := state.ListAgentSessions(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListAgentSessions(2): %v", err)
	}
	assertLocalQueryValues(t, limited, want[:2])
	again, err := state.ListAgentSessions(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListAgentSessions(2) repeat: %v", err)
	}
	assertLocalQueryValues(t, again, want[:2])
}

func TestListAgentSessionsRejectsInvalidInputAndReturnsEmptyResult(t *testing.T) {
	state := openLocalQueryTestState(t)

	for _, limit := range []int{-1, 0, MaxLocalAgentSessionQuery + 1} {
		if _, err := state.ListAgentSessions(
			context.Background(),
			limit,
		); !errors.Is(err, ErrInvalidLocalState) {
			t.Fatalf(
				"ListAgentSessions(%d) error = %v, want %v",
				limit,
				err,
				ErrInvalidLocalState,
			)
		}
	}
	//lint:ignore SA1012 This test verifies the public nil-context rejection.
	if _, err := state.ListAgentSessions(nil, 1); !errors.Is(
		err,
		ErrInvalidLocalState,
	) {
		t.Fatalf(
			"ListAgentSessions(nil context) error = %v, want %v",
			err,
			ErrInvalidLocalState,
		)
	}

	got, err := state.ListAgentSessions(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAgentSessions(empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListAgentSessions(empty) = %#v, want no rows", got)
	}
}

func TestListAgentSessionsFailsClosedOnMalformedProjection(t *testing.T) {
	state := openLocalQueryTestState(t)
	value := newLocalQueryAgentSession(0)
	writeLocalQueryProjections(t, state, nil, []agentsession.Session{value})

	updateLocalQueryRow(
		t,
		state,
		`UPDATE agent_sessions
		    SET agent_profile_id = CAST(X'80' AS TEXT)
		  WHERE agent_session_id = ?1;`,
		string(value.ID),
	)

	if _, err := state.ListAgentSessions(context.Background(), 1); !errors.Is(
		err,
		ErrLocalStateIntegrity,
	) {
		t.Fatalf(
			"ListAgentSessions(malformed) error = %v, want %v",
			err,
			ErrLocalStateIntegrity,
		)
	}
}

func TestNonterminalAgentSessionsIgnoresTerminalHistoryAndRejectsOverflow(
	t *testing.T,
) {
	state := openLocalQueryTestState(t)
	rows := make([]agentsession.Session, 0, MaxLocalAgentSessionQuery+1)
	for index := 0; index < MaxLocalAgentSessionQuery; index++ {
		value := newLocalQueryAgentSession(200 + index)
		value.State = agentsession.StateEnded
		value.ResumeState = agentsession.StateAbsent
		value.EndReason = agentsession.EndReasonClean
		rows = append(rows, value)
	}
	live := newLocalQueryAgentSession(500)
	live.State = agentsession.StateWorking
	live.ResumeState = agentsession.StateAbsent
	live.EndReason = agentsession.EndReasonAbsent
	rows = append(rows, live)
	writeLocalQueryProjections(t, state, nil, rows)

	got, err := state.NonterminalAgentSessions(context.Background())
	if err != nil {
		t.Fatalf("NonterminalAgentSessions(): %v", err)
	}
	assertLocalQueryValues(t, got, []agentsession.Session{live})

	overflowState := openLocalQueryTestState(t)
	overflow := make([]agentsession.Session, MaxLocalAgentSessionQuery+1)
	for index := range overflow {
		overflow[index] = newLocalQueryAgentSession(600 + index)
		overflow[index].State = agentsession.StateIdle
		overflow[index].ResumeState = agentsession.StateAbsent
		overflow[index].EndReason = agentsession.EndReasonAbsent
	}
	writeLocalQueryProjections(t, overflowState, nil, overflow)
	if _, err := overflowState.NonterminalAgentSessions(
		context.Background(),
	); !errors.Is(err, ErrLocalStateIntegrity) {
		t.Fatalf(
			"NonterminalAgentSessions(overflow) error = %v, want %v",
			err,
			ErrLocalStateIntegrity,
		)
	}
	//lint:ignore SA1012 This test verifies the public nil-context rejection.
	if _, err := state.NonterminalAgentSessions(nil); !errors.Is(
		err,
		ErrInvalidLocalState,
	) {
		t.Fatalf(
			"NonterminalAgentSessions(nil) error = %v, want %v",
			err,
			ErrInvalidLocalState,
		)
	}
}

func TestAgentContextSnapshotReturnsOneTypedTransactionalView(t *testing.T) {
	state, _, _ := newLocalStateFixture(t)
	self := newLocalQueryAgentSession(0)
	self.State = agentsession.StateWorking
	self.ResumeState = agentsession.StateAbsent
	tasks := []task.Task{
		newLocalQueryTask(2, task.PriorityNormal, "second"),
		newLocalQueryTask(1, task.PriorityHighest, "first"),
	}
	writeLocalQueryProjections(t, state, tasks, []agentsession.Session{self})

	snapshot, found, err := state.AgentContextSnapshot(
		context.Background(),
		self.ID,
		MaxLocalTaskQuery,
	)
	if err != nil {
		t.Fatalf("AgentContextSnapshot(): %v", err)
	}
	if !found ||
		snapshot.SessionID != domain.UUIDv7(testSessionID) ||
		snapshot.WorkspaceID != testWorkspaceID ||
		snapshot.RecoveryGeneration != 0 ||
		snapshot.Self.ID != self.ID ||
		snapshot.Heads.DigestVersion != 1 ||
		snapshot.Heads.ProjectionSchemaVersion != 1 {
		t.Fatalf("AgentContextSnapshot() = (%#v, %t)", snapshot, found)
	}
	assertLocalQueryValues(t, snapshot.Tasks, []task.Task{tasks[1], tasks[0]})

	missing, found, err := state.AgentContextSnapshot(
		context.Background(),
		localQueryUUID(999),
		1,
	)
	if err != nil {
		t.Fatalf("AgentContextSnapshot(missing): %v", err)
	}
	if found || !reflect.DeepEqual(missing, AgentContextSnapshot{}) {
		t.Fatalf("AgentContextSnapshot(missing) = (%#v, %t)", missing, found)
	}
	for _, limit := range []int{0, MaxLocalTaskQuery + 1} {
		if _, _, err := state.AgentContextSnapshot(
			context.Background(),
			self.ID,
			limit,
		); !errors.Is(err, ErrInvalidLocalState) {
			t.Fatalf(
				"AgentContextSnapshot(limit %d) error = %v, want %v",
				limit,
				err,
				ErrInvalidLocalState,
			)
		}
	}
}

func openLocalQueryTestState(t *testing.T) LocalState {
	t.Helper()
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	return store.LocalState()
}

func writeLocalQueryProjections(
	t *testing.T,
	state LocalState,
	taskRows []task.Task,
	agentSessionRows []agentsession.Session,
) {
	t.Helper()
	prepared, err := prepareProjectionWrites(ProjectionWrites{
		Tasks:         taskRows,
		AgentSessions: agentSessionRows,
	})
	if err != nil {
		t.Fatalf("prepareProjectionWrites(): %v", err)
	}
	err = state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		if err := writeProjectionRows(conn, upsertTaskSQL, prepared.tasks); err != nil {
			return err
		}
		return writeProjectionRows(
			conn,
			upsertAgentSessionSQL,
			prepared.agentSessions,
		)
	})
	if err != nil {
		t.Fatalf("write local query projections: %v", err)
	}
}

func updateLocalQueryRow(
	t *testing.T,
	state LocalState,
	statement string,
	args ...any,
) {
	t.Helper()
	state.store.applyMu.Lock()
	defer state.store.applyMu.Unlock()
	if err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) (err error) {
		if err := execute(conn, "PRAGMA ignore_check_constraints = ON;"); err != nil {
			return err
		}
		defer func() {
			err = errors.Join(
				err,
				execute(conn, "PRAGMA ignore_check_constraints = OFF;"),
			)
		}()
		return execute(conn, statement, args...)
	}); err != nil {
		t.Fatalf("update local query row: %v", err)
	}
}

func newLocalQueryTask(index int, priority task.Priority, title string) task.Task {
	return task.Task{
		ID:            localQueryUUID(index),
		Title:         title,
		Body:          "query projection body",
		State:         task.StateBacklog,
		Priority:      priority,
		BlockedBy:     []domain.UUIDv7{},
		Labels:        []string{},
		EntityVersion: uint64(index + 1),
		CreatedAt:     localQueryCreatedAt,
		UpdatedAt:     localQueryUpdatedAt,
	}
}

func newLocalQueryAgentSession(index int) agentsession.Session {
	value := agentsession.Session{
		ID:            localQueryUUID(100 + index),
		DeviceID:      localQueryDeviceID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateEnded,
		WorkingRootID: localQueryUUID(1_000 + index),
		EndReason:     agentsession.EndReasonClean,
		EntityVersion: uint64(index + 1),
	}
	switch index % 3 {
	case 0:
		value.ClientKind = agentsession.ClientKindCodex
	case 1:
		value.ClientKind = agentsession.ClientKindClaude
	default:
		value.ClientKind = agentsession.ClientKindOther
	}
	if index == 0 {
		profile := "codex-local"
		value.AgentProfileID = &profile
		value.State = agentsession.StateDisconnected
		value.ResumeState = agentsession.StateWorking
		value.EndReason = agentsession.EndReasonAbsent
	}
	if index == 1 {
		value.State = agentsession.StateIdle
		value.EndReason = agentsession.EndReasonAbsent
	}
	return value
}

func localQueryUUID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"01890f47-3e72-7000-8000-%012x",
		index,
	))
}

func assertLocalQueryValues[T any](t *testing.T, got, want []T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("query values = %#v, want %#v", got, want)
	}
}
