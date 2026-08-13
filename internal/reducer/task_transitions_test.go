package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestTaskStateChangedAcceptsExactlyItsDocumentedEdges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		from      task.State
		to        task.State
		actor     event.ActorType
		reason    string
		wantOwner bool
	}{
		{"backlog to ready", task.StateBacklog, task.StateReady, event.ActorHuman, "", false},
		{"ready to backlog", task.StateReady, task.StateBacklog, event.ActorHuman, "", false},
		{"claimed to in progress", task.StateClaimed, task.StateInProgress, event.ActorAgent, "", true},
		{"in progress to blocked", task.StateInProgress, task.StateBlocked, event.ActorAgent, "waiting", true},
		{"in progress to done", task.StateInProgress, task.StateDone, event.ActorAgent, "", false},
		{"blocked to in progress", task.StateBlocked, task.StateInProgress, event.ActorAgent, "", true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			before := taskForReducerState(fixture, test.from, 7)
			fixture.state.tasks[testTaskID] = before
			payload := `{"to_state":"` + string(test.to) + `"}`
			if test.reason != "" {
				payload = `{"reason":"` + test.reason + `","to_state":"` + string(test.to) + `"}`
			}
			proposal := buildTaskProposal(
				t,
				fixture,
				test.actor,
				event.KindTaskStateChanged,
				7,
				payload,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if !outcome.Accepted() || len(outcome.Changes.Tasks) != 1 {
				t.Fatalf("outcome = %#v", outcome)
			}
			got := outcome.Changes.Tasks[0]
			if got.State != test.to || got.EntityVersion != 8 ||
				(got.OwnerDeviceID != "") != test.wantOwner {
				t.Fatalf("task = %#v", got)
			}
			if test.to == task.StateBlocked {
				if got.StateReason == nil || *got.StateReason != test.reason {
					t.Fatalf("blocked reason = %#v", got.StateReason)
				}
			} else if got.StateReason != nil {
				t.Fatalf("non-blocked state retained reason %q", *got.StateReason)
			}
			if fixture.state.tasks[testTaskID].State != before.State ||
				fixture.state.tasks[testTaskID].EntityVersion != before.EntityVersion {
				t.Fatal("Reduce mutated its input task")
			}
		})
	}
}

func TestTaskReleasedAcceptsVoluntaryAndForcedEdges(t *testing.T) {
	t.Parallel()

	for _, reason := range []task.ReleaseReason{
		task.ReleaseVoluntary,
		task.ReleaseForced,
	} {
		reason := reason
		states := []task.State{
			task.StateClaimed,
			task.StateInProgress,
			task.StateBlocked,
		}
		if reason == task.ReleaseForced {
			states = append([]task.State{task.StateReady}, states...)
		}
		for _, from := range states {
			from := from
			t.Run(string(reason)+"/"+string(from), func(t *testing.T) {
				t.Parallel()
				fixture := newReducerFixture(t)
				fixture.state.tasks[testTaskID] = taskForReducerState(fixture, from, 7)
				actor := event.ActorAgent
				if reason == task.ReleaseForced {
					actor = event.ActorHuman
				}
				var proposal event.SignedEvent
				if reason == task.ReleaseForced {
					proposal = buildHumanTaskProposal(
						t,
						fixture,
						fixture.ownerDevice,
						event.KindTaskReleased,
						7,
						`{"release_reason":"forced"}`,
					)
				} else {
					proposal = buildTaskProposal(
						t,
						fixture,
						actor,
						event.KindTaskReleased,
						7,
						`{"release_reason":"voluntary"}`,
					)
				}

				outcome, err := Reduce(fixture.state, proposal)
				if err != nil {
					t.Fatalf("Reduce() error = %v", err)
				}
				if !outcome.Accepted() {
					t.Fatalf("outcome = %#v", outcome)
				}
				got := outcome.Changes.Tasks[0]
				if got.State != task.StateReady ||
					got.StateReason != nil ||
					got.OwnerDeviceID != "" ||
					got.OwnerAgentSessionID != "" ||
					got.IntendedDeviceID != "" ||
					got.LastReleaseReason != reason ||
					got.EntityVersion != 8 {
					t.Fatalf("released task = %#v", got)
				}
				if reason == task.ReleaseForced && outcome.Audit == nil {
					t.Fatal("forced release omitted operator-override audit directive")
				}
				if reason == task.ReleaseVoluntary && outcome.Audit != nil {
					t.Fatalf("voluntary release emitted audit directive %#v", outcome.Audit)
				}
			})
		}
	}
}

func TestTaskReassignedAcceptsEveryOverrideEdge(t *testing.T) {
	t.Parallel()

	for _, from := range []task.State{
		task.StateReady,
		task.StateClaimed,
		task.StateInProgress,
		task.StateBlocked,
	} {
		from := from
		t.Run(string(from), func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			fixture.state.tasks[testTaskID] = taskForReducerState(fixture, from, 7)
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorHuman,
				event.KindTaskReassigned,
				7,
				`{"to_device_id":"`+string(fixture.targetDevice)+`"}`,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if !outcome.Accepted() || outcome.Audit == nil {
				t.Fatalf("outcome = %#v", outcome)
			}
			got := outcome.Changes.Tasks[0]
			if got.State != task.StateReady ||
				got.StateReason != nil ||
				got.OwnerDeviceID != "" ||
				got.OwnerAgentSessionID != "" ||
				got.IntendedDeviceID != fixture.targetDevice ||
				got.LastReleaseReason != task.ReleaseForced ||
				got.EntityVersion != 8 {
				t.Fatalf("reassigned task = %#v", got)
			}
		})
	}
}

func TestTaskCancelledAcceptsEveryNonterminalStateAndCleansOwnership(t *testing.T) {
	t.Parallel()

	for _, from := range []task.State{
		task.StateBacklog,
		task.StateReady,
		task.StateClaimed,
		task.StateInProgress,
		task.StateBlocked,
	} {
		from := from
		t.Run(string(from), func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			before := taskForReducerState(fixture, from, 7)
			if from == task.StateReady {
				before.IntendedDeviceID = fixture.targetDevice
				before.LastReleaseReason = task.ReleaseVoluntary
			}
			fixture.state.tasks[testTaskID] = before
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorHuman,
				event.KindTaskCancelled,
				7,
				`{}`,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if !outcome.Accepted() || outcome.Audit == nil {
				t.Fatalf("outcome = %#v", outcome)
			}
			got := outcome.Changes.Tasks[0]
			if got.State != task.StateCancelled ||
				got.StateReason != nil ||
				got.OwnerDeviceID != "" ||
				got.OwnerAgentSessionID != "" ||
				got.IntendedDeviceID != "" ||
				got.EntityVersion != 8 {
				t.Fatalf("cancelled task = %#v", got)
			}
			if from == task.StateReady &&
				got.LastReleaseReason != task.ReleaseVoluntary {
				t.Fatalf("cancellation lost prior release provenance: %#v", got)
			}
		})
	}
}

func taskForReducerState(
	fixture reducerFixture,
	state task.State,
	version uint64,
) task.Task {
	value := testTask(state, version)
	switch state {
	case task.StateClaimed, task.StateInProgress, task.StateBlocked:
		ownTask(&value, fixture.editorDevice)
	}
	if state == task.StateBlocked {
		reason := "waiting"
		value.StateReason = &reason
	}
	return value
}
