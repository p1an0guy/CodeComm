package reducer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestTaskPayloadSchemasRejectClosedSchemaViolations(t *testing.T) {
	t.Parallel()

	tooManyLabels := make([]string, task.MaxLabels+1)
	for index := range tooManyLabels {
		tooManyLabels[index] = fmt.Sprintf("label-%02d", index)
	}
	labelJSON := `["` + strings.Join(tooManyLabels, `","`) + `"]`

	tests := []struct {
		name    string
		kind    event.Kind
		actor   event.ActorType
		payload string
		want    Code
	}{
		{
			"create unknown field",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"priority":2,"title":"task","unknown":true}`,
			CodeUnknownPayloadField,
		},
		{
			"create missing title",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"priority":2}`,
			CodeMissingPayloadField,
		},
		{
			"create null optional",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"body":null,"priority":2,"title":"task"}`,
			CodeInvalidPayload,
		},
		{
			"create empty title",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"priority":2,"title":""}`,
			CodeInvalidPayload,
		},
		{
			"create invalid priority",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"priority":4,"title":"task"}`,
			CodeInvalidPayload,
		},
		{
			"create too many labels",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"labels":` + labelJSON + `,"priority":2,"title":"task"}`,
			CodeInvalidPayload,
		},
		{
			"create unsorted dependencies",
			event.KindTaskCreated,
			event.ActorAgent,
			`{"blocked_by":["` + string(testOtherTaskID) + `","` + string(testTaskID) + `"],"priority":2,"title":"task"}`,
			CodeDependencyCycle,
		},
		{
			"empty update",
			event.KindTaskUpdated,
			event.ActorAgent,
			`{}`,
			CodeInvalidPayload,
		},
		{
			"blocked entry missing reason",
			event.KindTaskStateChanged,
			event.ActorAgent,
			`{"to_state":"blocked"}`,
			CodeMissingPayloadField,
		},
		{
			"nonblocked reason prohibited",
			event.KindTaskStateChanged,
			event.ActorAgent,
			`{"reason":"not allowed","to_state":"done"}`,
			CodeInvalidPayload,
		},
		{
			"claim payload not empty",
			event.KindTaskClaimed,
			event.ActorAgent,
			`{"device_id":"spoof"}`,
			CodeUnknownPayloadField,
		},
		{
			"invalid release reason",
			event.KindTaskReleased,
			event.ActorAgent,
			`{"release_reason":"session_ended"}`,
			CodeInvalidReleaseReason,
		},
		{
			"malformed reassignment target",
			event.KindTaskReassigned,
			event.ActorHuman,
			`{"to_device_id":"not-a-device"}`,
			CodeInvalidPayload,
		},
		{
			"cancel payload not empty",
			event.KindTaskCancelled,
			event.ActorHuman,
			`{"reason":"not supported"}`,
			CodeUnknownPayloadField,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			version := uint64(0)
			if test.kind != event.KindTaskCreated {
				version = 4
				fixture.state.tasks[testTaskID] = taskForPayloadTest(fixture, test.kind)
			}
			proposal := buildTaskProposal(
				t,
				fixture,
				test.actor,
				test.kind,
				version,
				test.payload,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusRejected || outcome.Code != test.want {
				t.Fatalf("outcome = %#v, want %q", outcome, test.want)
			}
			if len(outcome.Changes.OriginScopes) != 1 ||
				len(outcome.Changes.Tasks) != 0 {
				t.Fatalf("payload rejection changes = %#v", outcome.Changes)
			}
		})
	}
}

func TestPayloadFailurePrecedenceIsIndependentOfMapIteration(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	for iteration := 0; iteration < 1_000; iteration++ {
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskCreated,
			0,
			`{"body":null,"priority":2,"title":"task","unknown":true}`,
		)
		outcome, err := Reduce(fixture.state, proposal)
		if err != nil {
			t.Fatalf("iteration %d: Reduce() error = %v", iteration, err)
		}
		if outcome.Code != CodeUnknownPayloadField {
			t.Fatalf(
				"iteration %d: outcome code = %q, want %q",
				iteration,
				outcome.Code,
				CodeUnknownPayloadField,
			)
		}
	}
}

func TestTaskEntityAndCASRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    event.Kind
		version uint64
		prepare func(*reducerFixture)
		want    Code
	}{
		{
			name: "create collision",
			kind: event.KindTaskCreated,
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 1)
			},
			want: CodeEntityAlreadyExists,
		},
		{
			name:    "missing entity",
			kind:    event.KindTaskUpdated,
			version: 1,
			want:    CodeEntityNotFound,
		},
		{
			name:    "stale version",
			kind:    event.KindTaskUpdated,
			version: 3,
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			want: CodeEntityVersionMismatch,
		},
		{
			name:    "exhausted version",
			kind:    event.KindTaskUpdated,
			version: domain.MaxSafeInteger,
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(
					task.StateBacklog,
					domain.MaxSafeInteger,
				)
			},
			want: CodeEntityVersionExhausted,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			if test.prepare != nil {
				test.prepare(&fixture)
			}
			payload := `{"title":"updated"}`
			if test.kind == event.KindTaskCreated {
				payload = `{"priority":2,"title":"task"}`
			}
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				test.kind,
				test.version,
				payload,
			)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want {
				t.Fatalf("outcome = %#v, want %q", outcome, test.want)
			}
			if len(outcome.Changes.OriginScopes) != 1 {
				t.Fatalf("CAS rejection did not consume sequence: %#v", outcome)
			}
		})
	}
}

func TestTaskActorAndOwnershipAuthorization(t *testing.T) {
	t.Parallel()

	t.Run("agent update foreign task", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := taskForReducerState(fixture, task.StateInProgress, 4)
		value.OwnerDeviceID = fixture.targetDevice
		value.OwnerAgentSessionID = testOtherAgentID
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskUpdated,
			4,
			`{"title":"changed"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeTaskHolderRequired)
	})

	t.Run("human editor may update owned task", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := taskForReducerState(fixture, task.StateInProgress, 4)
		value.OwnerDeviceID = fixture.targetDevice
		value.OwnerAgentSessionID = testOtherAgentID
		fixture.state.tasks[testTaskID] = value
		proposal := buildHumanTaskProposal(
			t,
			fixture,
			fixture.editorDevice,
			event.KindTaskUpdated,
			4,
			`{"title":"changed"}`,
		)
		assertAccepted(t, fixture.state, proposal)
	})

	t.Run("agent state change requires holder", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskStateChanged,
			4,
			`{"to_state":"ready"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeTaskHolderRequired)
	})

	t.Run("human work edge requires unowned task", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = taskForReducerState(
			fixture,
			task.StateClaimed,
			4,
		)
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorHuman,
			event.KindTaskStateChanged,
			4,
			`{"to_state":"in_progress"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeTaskMustBeUnowned)
	})

	t.Run("voluntary release requires agent actor", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = taskForReducerState(
			fixture,
			task.StateClaimed,
			4,
		)
		proposal := buildHumanTaskProposal(
			t,
			fixture,
			fixture.editorDevice,
			event.KindTaskReleased,
			4,
			`{"release_reason":"voluntary"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeReleaseActorMismatch)
	})

	t.Run("forced release requires human actor", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = taskForReducerState(
			fixture,
			task.StateClaimed,
			4,
		)
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskReleased,
			4,
			`{"release_reason":"forced"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeReleaseActorMismatch)
	})

	t.Run("voluntary release requires exact holder", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := taskForReducerState(fixture, task.StateClaimed, 4)
		value.OwnerAgentSessionID = testOtherAgentID
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskReleased,
			4,
			`{"release_reason":"voluntary"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeTaskHolderRequired)
	})

	t.Run("editor cannot force release foreign task", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := taskForReducerState(fixture, task.StateClaimed, 4)
		value.OwnerDeviceID = fixture.targetDevice
		value.OwnerAgentSessionID = testOtherAgentID
		fixture.state.tasks[testTaskID] = value
		proposal := buildHumanTaskProposal(
			t,
			fixture,
			fixture.editorDevice,
			event.KindTaskReleased,
			4,
			`{"release_reason":"forced"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeReleaseNotAuthorized)
	})

	t.Run("owner may force release foreign task", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := taskForReducerState(fixture, task.StateClaimed, 4)
		value.OwnerDeviceID = fixture.targetDevice
		value.OwnerAgentSessionID = testOtherAgentID
		fixture.state.tasks[testTaskID] = value
		proposal := buildHumanTaskProposal(
			t,
			fixture,
			fixture.ownerDevice,
			event.KindTaskReleased,
			4,
			`{"release_reason":"forced"}`,
		)
		assertAccepted(t, fixture.state, proposal)
	})

	t.Run("editor may clear its own stranded intent", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := testTask(task.StateReady, 4)
		value.IntendedDeviceID = fixture.editorDevice
		fixture.state.tasks[testTaskID] = value
		proposal := buildHumanTaskProposal(
			t,
			fixture,
			fixture.editorDevice,
			event.KindTaskReleased,
			4,
			`{"release_reason":"forced"}`,
		)
		assertAccepted(t, fixture.state, proposal)
	})
}

func TestTaskDomainGatesRejectUnsafeTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*reducerFixture)
		kind    event.Kind
		actor   event.ActorType
		payload string
		want    Code
	}{
		{
			name: "state change cannot release",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = taskForReducerState(
					*fixture,
					task.StateClaimed,
					4,
				)
			},
			kind:    event.KindTaskStateChanged,
			actor:   event.ActorAgent,
			payload: `{"to_state":"ready"}`,
			want:    CodeInvalidTaskTransition,
		},
		{
			name: "release cannot move backlog",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			kind:    event.KindTaskReleased,
			actor:   event.ActorHuman,
			payload: `{"release_reason":"forced"}`,
			want:    CodeInvalidTaskTransition,
		},
		{
			name: "reassign cannot move backlog",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			kind:    event.KindTaskReassigned,
			actor:   event.ActorHuman,
			payload: "",
			want:    CodeInvalidTaskTransition,
		},
		{
			name: "cancel cannot leave done",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateDone, 4)
			},
			kind:    event.KindTaskCancelled,
			actor:   event.ActorHuman,
			payload: `{}`,
			want:    CodeInvalidTaskTransition,
		},
		{
			name: "unresolved conflict blocks done",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = taskForReducerState(
					*fixture,
					task.StateInProgress,
					4,
				)
				fixture.state.unresolvedConflictsByTask[testTaskID] = 1
			},
			kind:    event.KindTaskStateChanged,
			actor:   event.ActorAgent,
			payload: `{"to_state":"done"}`,
			want:    CodeTaskHasUnresolvedConflict,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			test.prepare(&fixture)
			payload := test.payload
			if test.kind == event.KindTaskReassigned {
				payload = `{"to_device_id":"` + string(fixture.targetDevice) + `"}`
			}
			var proposal event.SignedEvent
			if test.name == "release cannot move backlog" {
				proposal = buildHumanTaskProposal(
					t,
					fixture,
					fixture.ownerDevice,
					test.kind,
					4,
					payload,
				)
			} else {
				proposal = buildTaskProposal(
					t,
					fixture,
					test.actor,
					test.kind,
					4,
					payload,
				)
			}
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestReassignmentRequiresActiveTarget(t *testing.T) {
	t.Parallel()

	for _, status := range []device.Status{
		device.StatusRequiresReadmission,
		device.StatusRevoked,
	} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
			target := fixture.state.devices[fixture.targetDevice]
			target.Status = status
			target.EntityVersion++
			fixture.state.devices[fixture.targetDevice] = target
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorHuman,
				event.KindTaskReassigned,
				4,
				`{"to_device_id":"`+string(fixture.targetDevice)+`"}`,
			)
			assertRejectedCode(
				t,
				fixture.state,
				proposal,
				CodeReassignmentTargetNotActive,
			)
		})
	}
}

func taskForPayloadTest(fixture reducerFixture, kind event.Kind) task.Task {
	switch kind {
	case event.KindTaskUpdated:
		return testTask(task.StateBacklog, 4)
	case event.KindTaskStateChanged:
		return taskForReducerState(fixture, task.StateInProgress, 4)
	case event.KindTaskClaimed:
		return testTask(task.StateReady, 4)
	case event.KindTaskReleased:
		return taskForReducerState(fixture, task.StateClaimed, 4)
	case event.KindTaskReassigned:
		return testTask(task.StateReady, 4)
	case event.KindTaskCancelled:
		return testTask(task.StateBacklog, 4)
	default:
		panic("unsupported payload-test kind")
	}
}

func assertRejectedCode(
	t *testing.T,
	state State,
	proposal event.SignedEvent,
	want Code,
) {
	t.Helper()
	outcome, err := Reduce(state, proposal)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if outcome.Status != StatusRejected || outcome.Code != want {
		t.Fatalf("outcome = %#v, want rejected/%s", outcome, want)
	}
}

func assertAccepted(t *testing.T, state State, proposal event.SignedEvent) Outcome {
	t.Helper()
	outcome, err := Reduce(state, proposal)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() {
		t.Fatalf("outcome = %#v, want accepted", outcome)
	}
	return outcome
}
