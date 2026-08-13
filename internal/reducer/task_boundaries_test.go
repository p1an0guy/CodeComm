package reducer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestTaskCreateAndUpdateFieldBoundsAtAndOnePast(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload func(int) string
		at      int
	}{
		{
			name: "title bytes",
			payload: func(size int) string {
				return fmt.Sprintf(
					`{"priority":2,"title":"%s"}`,
					strings.Repeat("t", size),
				)
			},
			at: task.MaxTitleBytes,
		},
		{
			name: "body bytes",
			payload: func(size int) string {
				return fmt.Sprintf(
					`{"body":"%s","priority":2,"title":"task"}`,
					strings.Repeat("b", size),
				)
			},
			at: task.MaxBodyBytes,
		},
		{
			name: "label bytes",
			payload: func(size int) string {
				return fmt.Sprintf(
					`{"labels":["%s"],"priority":2,"title":"task"}`,
					strings.Repeat("l", size),
				)
			},
			at: task.MaxLabelBytes,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name+"/at", func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				test.payload(test.at),
			)
			assertAccepted(t, fixture.state, proposal)
		})
		t.Run(test.name+"/one past", func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				test.payload(test.at+1),
			)
			assertRejectedCode(t, fixture.state, proposal, CodeInvalidPayload)
		})
	}
}

func TestTaskArrayAndBlockedReasonBoundsAtAndOnePast(t *testing.T) {
	t.Parallel()

	t.Run("labels", func(t *testing.T) {
		t.Parallel()
		for _, count := range []int{task.MaxLabels, task.MaxLabels + 1} {
			count := count
			t.Run(fmt.Sprintf("%d", count), func(t *testing.T) {
				t.Parallel()
				fixture := newReducerFixture(t)
				labels := make([]string, count)
				for index := range labels {
					labels[index] = fmt.Sprintf("l%02d", index)
				}
				payload := `{"labels":["` +
					strings.Join(labels, `","`) +
					`"],"priority":2,"title":"task"}`
				proposal := buildTaskProposal(
					t,
					fixture,
					event.ActorAgent,
					event.KindTaskCreated,
					0,
					payload,
				)
				if count == task.MaxLabels {
					assertAccepted(t, fixture.state, proposal)
				} else {
					assertRejectedCode(
						t,
						fixture.state,
						proposal,
						CodeInvalidPayload,
					)
				}
			})
		}
	})

	t.Run("blocked by", func(t *testing.T) {
		t.Parallel()
		for _, count := range []int{task.MaxBlockedBy, task.MaxBlockedBy + 1} {
			count := count
			t.Run(fmt.Sprintf("%d", count), func(t *testing.T) {
				t.Parallel()
				fixture := newReducerFixture(t)
				ids := make([]string, count)
				for index := range ids {
					id := reducerDependencyID(index + 1)
					ids[index] = string(id)
					value := testTask(task.StateDone, 1)
					value.ID = id
					fixture.state.tasks[id] = value
				}
				payload := `{"blocked_by":["` +
					strings.Join(ids, `","`) +
					`"],"priority":2,"title":"task"}`
				proposal := buildTaskProposal(
					t,
					fixture,
					event.ActorAgent,
					event.KindTaskCreated,
					0,
					payload,
				)
				if count == task.MaxBlockedBy {
					assertAccepted(t, fixture.state, proposal)
				} else {
					assertRejectedCode(
						t,
						fixture.state,
						proposal,
						CodeInvalidPayload,
					)
				}
			})
		}
	})

	t.Run("blocked reason", func(t *testing.T) {
		t.Parallel()
		for _, size := range []int{
			task.MaxStateReasonBytes,
			task.MaxStateReasonBytes + 1,
		} {
			size := size
			t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
				t.Parallel()
				fixture := newReducerFixture(t)
				fixture.state.tasks[testTaskID] = taskForReducerState(
					fixture,
					task.StateInProgress,
					4,
				)
				payload := fmt.Sprintf(
					`{"reason":"%s","to_state":"blocked"}`,
					strings.Repeat("r", size),
				)
				proposal := buildTaskProposal(
					t,
					fixture,
					event.ActorAgent,
					event.KindTaskStateChanged,
					4,
					payload,
				)
				if size == task.MaxStateReasonBytes {
					assertAccepted(t, fixture.state, proposal)
				} else {
					assertRejectedCode(
						t,
						fixture.state,
						proposal,
						CodeInvalidPayload,
					)
				}
			})
		}
	})
}

func TestTaskUpdatedAppliesSparsePatchAndRetainsOmittedFields(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	dependency := testTask(task.StateDone, 1)
	dependency.ID = testOtherTaskID
	fixture.state.tasks[testOtherTaskID] = dependency
	before := testTask(task.StateReady, 4)
	before.Title = "old title"
	before.Body = "keep body"
	before.Priority = task.PriorityLowest
	before.Labels = []string{"keep"}
	fixture.state.tasks[testTaskID] = before
	signed := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskUpdated,
		4,
		`{"blocked_by":["`+string(testOtherTaskID)+`"],"priority":0}`,
	)
	proposal := resignEvent(t, fixture, signed, func(object map[string]json.RawMessage) {
		object["created_at"] = json.RawMessage(`"2026-08-11T12:00:01Z"`)
	})
	createdAt := domain.Timestamp("2026-08-11T12:00:01Z")

	outcome := assertAccepted(t, fixture.state, proposal)
	got := outcome.Changes.Tasks[0]
	if got.Title != before.Title ||
		got.Body != before.Body ||
		got.Priority != task.PriorityHighest ||
		len(got.Labels) != 1 || got.Labels[0] != "keep" ||
		len(got.BlockedBy) != 1 || got.BlockedBy[0] != testOtherTaskID ||
		got.UpdatedAt != createdAt {
		t.Fatalf("patched task = %#v", got)
	}
}

func TestSequentialTaskClaimRaceHasOneCASWinner(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
	firstProposal := buildTaskProposalAtSequence(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
		2,
	)
	first := assertAccepted(t, fixture.state, firstProposal)
	fixture.state.tasks[testTaskID] = first.Changes.Tasks[0]
	scope := first.Changes.OriginScopes[0]
	fixture.state.originScopes[scope.OriginScopeKey] = scope
	fixture.state.claimsByAgent[testAgentSessionID] = []domain.UUIDv7{testTaskID}
	fixture.state.claimsByDevice[fixture.editorDevice] = []domain.UUIDv7{testTaskID}

	secondProposal := buildTaskProposalAtSequence(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
		3,
	)
	second, err := Reduce(fixture.state, secondProposal)
	if err != nil {
		t.Fatalf("second Reduce() error = %v", err)
	}
	if second.Code != CodeEntityVersionMismatch ||
		len(second.Changes.OriginScopes) != 1 ||
		len(second.Changes.Tasks) != 0 {
		t.Fatalf("second outcome = %#v", second)
	}
}
