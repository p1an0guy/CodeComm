package reducer

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestTaskDependencyReducerMapsMissingAndCycles(t *testing.T) {
	t.Parallel()

	t.Run("missing dependency", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskCreated,
			0,
			`{"blocked_by":["`+string(testOtherTaskID)+`"],"priority":2,"title":"task"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeDependencyNotFound)
	})

	t.Run("direct self cycle", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskCreated,
			0,
			`{"blocked_by":["`+string(testTaskID)+`"],"priority":2,"title":"task"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeDependencyCycle)
	})

	t.Run("indirect cycle", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		dependency := testTask(task.StateDone, 1)
		dependency.ID = testOtherTaskID
		dependency.BlockedBy = []domain.UUIDv7{testTaskID}
		fixture.state.tasks[testOtherTaskID] = dependency
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskCreated,
			0,
			`{"blocked_by":["`+string(testOtherTaskID)+`"],"priority":2,"title":"task"}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeDependencyCycle)
	})
}

func TestTaskDependencyReducerEnforcesExactWalkBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		chainLength int
		closeCycle  bool
		want        Code
	}{
		{
			name:        "exact limit accepted",
			chainLength: task.DependencyWalkMax,
			want:        CodeAccepted,
		},
		{
			name:        "one past rejected",
			chainLength: task.DependencyWalkMax + 1,
			want:        CodeDependencyGraphTooComplex,
		},
		{
			name:        "cycle at last allowed row wins",
			chainLength: task.DependencyWalkMax,
			closeCycle:  true,
			want:        CodeDependencyCycle,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			for index := 1; index <= test.chainLength; index++ {
				id := reducerDependencyID(index)
				value := testTask(task.StateDone, 1)
				value.ID = id
				if index < test.chainLength {
					value.BlockedBy = []domain.UUIDv7{
						reducerDependencyID(index + 1),
					}
				} else if test.closeCycle {
					value.BlockedBy = []domain.UUIDv7{testTaskID}
				}
				fixture.state.tasks[id] = value
			}
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				`{"blocked_by":["`+string(reducerDependencyID(1))+`"],"priority":2,"title":"task"}`,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want {
				t.Fatalf("outcome = %#v, want %q", outcome, test.want)
			}
		})
	}
}

func TestTaskClaimRequiresActionableTaskAndMatchingIntent(t *testing.T) {
	t.Parallel()

	t.Run("CAS precedes actionability and intent", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := testTask(task.StateBacklog, 4)
		value.IntendedDeviceID = fixture.targetDevice
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			3,
			`{}`,
		)
		assertRejectedCode(
			t,
			fixture.state,
			proposal,
			CodeEntityVersionMismatch,
		)
	})

	t.Run("unfinished dependency", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		dependency := testTask(task.StateReady, 1)
		dependency.ID = testOtherTaskID
		fixture.state.tasks[testOtherTaskID] = dependency
		value := testTask(task.StateReady, 4)
		value.BlockedBy = []domain.UUIDv7{testOtherTaskID}
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeTaskNotActionable)
	})

	t.Run("unresolved conflict", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
		fixture.state.unresolvedConflictsByTask[testTaskID] = 1
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		assertRejectedCode(
			t,
			fixture.state,
			proposal,
			CodeTaskHasUnresolvedConflict,
		)
	})

	t.Run("wrong intended device", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := testTask(task.StateReady, 4)
		value.IntendedDeviceID = fixture.targetDevice
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeIntendedDeviceMismatch)
	})

	t.Run("matching intent is one shot", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		value := testTask(task.StateReady, 4)
		value.IntendedDeviceID = fixture.editorDevice
		value.LastReleaseReason = task.ReleaseForced
		fixture.state.tasks[testTaskID] = value
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		outcome := assertAccepted(t, fixture.state, proposal)
		got := outcome.Changes.Tasks[0]
		if got.IntendedDeviceID != "" || got.LastReleaseReason != "" {
			t.Fatalf("claim did not clear one-shot fields: %#v", got)
		}
	})
}

func TestTaskClaimEnforcesAgentAndDeviceCapsIndependently(t *testing.T) {
	t.Parallel()

	t.Run("agent cap", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
		addIndexedClaim(
			&fixture,
			testOtherTaskID,
			fixture.editorDevice,
			testAgentSessionID,
		)
		currentPolicy := fixture.state.sessionPolicy
		currentPolicy.Values.AgentClaimLimit = 1
		currentPolicy.Values.DeviceClaimLimit = 2
		fixture.state.sessionPolicy = currentPolicy
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeAgentClaimLimitReached)
	})

	t.Run("device cap from another local agent", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
		addIndexedClaim(
			&fixture,
			testOtherTaskID,
			fixture.editorDevice,
			testOtherAgentID,
		)
		delete(fixture.state.claimsByAgent, testOtherAgentID)
		currentPolicy := fixture.state.sessionPolicy
		currentPolicy.Values.AgentClaimLimit = 1
		currentPolicy.Values.DeviceClaimLimit = 1
		fixture.state.sessionPolicy = currentPolicy
		proposal := buildTaskProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindTaskClaimed,
			4,
			`{}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeDeviceClaimLimitReached)
	})
}

func TestTaskClaimRejectsMalformedBoundedIndexesAsIntegrityErrors(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
	fixture.state.claimsByAgent[testAgentSessionID] = []domain.UUIDv7{
		testOtherTaskID,
	}
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
	)

	if _, err := Reduce(fixture.state, proposal); !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("Reduce() error = %v, want ErrInvalidCommittedState", err)
	}
}

func TestTaskReducerIsDeterministicAndDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	reason := "waiting"
	value := testTask(task.StateBlocked, 4)
	value.StateReason = &reason
	ownTask(&value, fixture.editorDevice)
	value.Labels = []string{"one"}
	value.BlockedBy = []domain.UUIDv7{testOtherTaskID}
	dependency := testTask(task.StateDone, 1)
	dependency.ID = testOtherTaskID
	fixture.state.tasks[testTaskID] = value
	fixture.state.tasks[testOtherTaskID] = dependency
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskUpdated,
		4,
		`{"body":"changed","labels":["two"]}`,
	)

	first := assertAccepted(t, fixture.state, proposal)
	second := assertAccepted(t, fixture.state, proposal)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated outcomes differ:\nfirst: %#v\nsecond: %#v", first, second)
	}
	first.Changes.Tasks[0].Labels[0] = "mutated"
	*first.Changes.Tasks[0].StateReason = "mutated"
	if fixture.state.tasks[testTaskID].Labels[0] != "one" ||
		*fixture.state.tasks[testTaskID].StateReason != "waiting" {
		t.Fatal("outcome aliases committed input")
	}
}

func addIndexedClaim(
	fixture *reducerFixture,
	id domain.UUIDv7,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
) {
	value := testTask(task.StateClaimed, 1)
	value.ID = id
	value.OwnerDeviceID = deviceID
	value.OwnerAgentSessionID = agentSessionID
	fixture.state.tasks[id] = value
	fixture.state.claimsByAgent[agentSessionID] = []domain.UUIDv7{id}
	fixture.state.claimsByDevice[deviceID] = []domain.UUIDv7{id}
}

func reducerDependencyID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"01890f47-3e72-7000-8001-%012x",
		0x1000+index,
	))
}
