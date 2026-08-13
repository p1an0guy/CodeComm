package reducer

import (
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestActivityRecordedAcceptsOptionalTaskAssociation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  map[string]any
		withTask bool
	}{
		{name: "session activity", payload: map[string]any{}},
		{
			name:     "task activity",
			payload:  map[string]any{"task_id": testTaskID},
			withTask: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			if test.withTask {
				fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
			}
			context := activityReductionContext(t, fixture, test.payload)

			outcome, err := reduceActivityRecorded(context)
			if err != nil {
				t.Fatalf("reduceActivityRecorded() error = %v", err)
			}
			wantTaskID := testTaskID
			if !test.withTask {
				wantTaskID = ""
			}
			if !outcome.Accepted() ||
				len(outcome.Changes.OriginScopes) != 1 ||
				outcome.ActivityTaskID != wantTaskID {
				t.Fatalf("outcome = %#v", outcome)
			}
		})
	}
}

func TestActivityRecordedRejectsInvalidTaskAssociation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload map[string]any
		want    Code
	}{
		{
			name:    "missing task",
			payload: map[string]any{"task_id": testTaskID},
			want:    CodeActivityTaskNotFound,
		},
		{
			name:    "invalid task ID",
			payload: map[string]any{"task_id": "not-a-task"},
			want:    CodeInvalidPayload,
		},
		{
			name:    "unknown field",
			payload: map[string]any{"summary": "duplicate envelope data"},
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "null task",
			payload: map[string]any{"task_id": nil},
			want:    CodeInvalidPayload,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			context := activityReductionContext(t, fixture, test.payload)

			outcome, err := reduceActivityRecorded(context)
			if err != nil {
				t.Fatalf("reduceActivityRecorded() error = %v", err)
			}
			if outcome.Code != test.want || outcome.Accepted() {
				t.Fatalf("outcome = %#v, want %q", outcome, test.want)
			}
		})
	}
}

func TestActivityRecordedDispatchesAndAppliesTasklessActivity(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := signedActivityRecorded(t, fixture, map[string]any{})
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		!outcome.RecordActivity ||
		!outcome.Changes.AdvancesEventChain ||
		outcome.ActivityTaskID != "" ||
		len(outcome.Changes.OriginScopes) != 1 {
		t.Fatalf("outcome = %#v", outcome)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	if fixture.state.currentChainIndex != 1 ||
		fixture.state.currentResultIndex != 2 {
		t.Fatalf(
			"applied heads = (%d, %d)",
			fixture.state.currentChainIndex,
			fixture.state.currentResultIndex,
		)
	}
}

func activityReductionContext(
	t *testing.T,
	fixture reducerFixture,
	payload map[string]any,
) reductionContext {
	t.Helper()
	signed := signedActivityRecorded(t, fixture, payload)
	context, outcome, done, err := beginReduction(fixture.state, signed)
	if err != nil {
		t.Fatalf("beginReduction() error = %v", err)
	}
	if done {
		t.Fatalf("beginReduction() outcome = %#v", outcome)
	}
	return context
}

func signedActivityRecorded(
	t *testing.T,
	fixture reducerFixture,
	payload map[string]any,
) event.SignedEvent {
	t.Helper()
	binding, err := event.NewMCPBinding(
		fixture.editorDevice,
		testAgentSessionID,
		nil,
	)
	if err != nil {
		t.Fatalf("event.NewMCPBinding() error = %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	proposal, err := event.BuildProposal(event.Command{
		Kind:             event.KindActivityRecorded,
		EntityID:         event.NullEntityID(),
		RationaleSummary: "reported activity",
		Actions:          []event.Action{},
		Payload:          encoded,
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}, binding, event.BuildContext{
		EventID:        domainEventID(150),
		SessionID:      fixture.state.sessionID,
		WorkspaceID:    fixture.state.workspaceID,
		CreatedAt:      testTimestamp,
		OriginSequence: 2,
	})
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	signed, err := event.Sign(
		proposal,
		fixture.privateKeys[fixture.editorDevice],
	)
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}
