package reducer

import (
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPlanRevisionPayloadRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		prepare func(*testing.T, reducerFixture, *Snapshot)
		want    Code
	}{
		{
			name:    "missing body",
			payload: `{"title":"plan"}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "unknown field",
			payload: `{"body":"","title":"plan","unknown":true}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "null optional field",
			payload: `{"body":"","supersedes":null,"title":"plan"}`,
			want:    CodeInvalidPayload,
		},
		{
			name: "title one byte over",
			payload: `{"body":"","title":"` +
				strings.Repeat("x", plan.MaxTitleBytes+1) + `"}`,
			want: CodeInvalidPayload,
		},
		{
			name: `body one byte over`,
			payload: `{"body":"` +
				strings.Repeat("x", plan.MaxBodyBytes+1) +
				`","title":"plan"}`,
			want: CodeInvalidPayload,
		},
		{
			name: "duplicate task IDs",
			payload: `{"body":"","task_ids":["` + string(testTaskID) +
				`","` + string(testTaskID) + `"],"title":"plan"}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "entity collision",
			payload: `{"body":"","title":"plan"}`,
			prepare: func(
				t *testing.T,
				fixture reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
					t,
					testPlanRevisionID,
					"",
					nil,
					fixture.editorDevice,
				)
			},
			want: CodeEntityAlreadyExists,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			if test.prepare != nil {
				test.prepare(t, fixture, &snapshot)
			}
			state := mustReducerState(t, snapshot)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				event.KindPlanRevisionProposed,
				string(testPlanRevisionID),
				0,
				test.payload,
				2,
			)
			outcome, err := Reduce(state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 1 ||
				outcome.Changes.OriginScopes[0].LastSequence != 2 ||
				len(outcome.Changes.PlanRevisions) != 0 {
				t.Fatalf("outcome = %#v, want %s", outcome, test.want)
			}
		})
	}
}

func TestMemoryPayloadRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		prepare func(*testing.T, *Snapshot)
		want    Code
	}{
		{
			name:    "missing body",
			payload: `{"key":"key","scope":"session"}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "unknown field",
			payload: `{"body":"","key":"key","scope":"session","unknown":true}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "null optional field",
			payload: `{"body":"","key":"key","scope":"session","task_id":null}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "session scope with task",
			payload: `{"body":"","key":"key","scope":"session","task_id":"` + string(testTaskID) + `"}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "task scope without task",
			payload: `{"body":"","key":"key","scope":"task"}`,
			want:    CodeInvalidPayload,
		},
		{
			name: "key one byte over",
			payload: `{"body":"","key":"` +
				strings.Repeat("x", memory.MaxKeyBytes+1) +
				`","scope":"session"}`,
			want: CodeInvalidPayload,
		},
		{
			name: "body one byte over",
			payload: `{"body":"` +
				strings.Repeat("x", memory.MaxBodyBytes+1) +
				`","key":"key","scope":"session"}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "entity collision",
			payload: `{"body":"","key":"key","scope":"session"}`,
			prepare: func(t *testing.T, snapshot *Snapshot) {
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					"",
				)
			},
			want: CodeEntityAlreadyExists,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			if test.prepare != nil {
				test.prepare(t, &snapshot)
			}
			state := mustReducerState(t, snapshot)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				event.KindMemoryAppended,
				string(testMemoryID),
				0,
				test.payload,
				2,
			)
			outcome, err := Reduce(state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 1 ||
				outcome.Changes.OriginScopes[0].LastSequence != 2 ||
				len(outcome.Changes.MemoryRecords) != 0 {
				t.Fatalf("outcome = %#v, want %s", outcome, test.want)
			}
		})
	}
}

func TestPlanAndMemoryAcceptExactTextBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		kind     event.Kind
		entityID string
		payload  string
	}{
		{
			name:     "plan",
			kind:     event.KindPlanRevisionProposed,
			entityID: string(testPlanRevisionID),
			payload: `{"body":"` + strings.Repeat("x", plan.MaxBodyBytes) +
				`","title":"` + strings.Repeat("x", plan.MaxTitleBytes) + `"}`,
		},
		{
			name:     "memory",
			kind:     event.KindMemoryAppended,
			entityID: string(testMemoryID),
			payload: `{"body":"` + strings.Repeat("x", memory.MaxBodyBytes) +
				`","key":"` + strings.Repeat("x", memory.MaxKeyBytes) +
				`","scope":"session"}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				test.kind,
				test.entityID,
				0,
				test.payload,
				2,
			)
			assertAccepted(t, fixture.state, proposal)
		})
	}
}

func TestHumanEditorsCanProposePlansAndMemory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		kind     event.Kind
		entityID string
		payload  string
	}{
		{
			name:     "plan",
			kind:     event.KindPlanRevisionProposed,
			entityID: string(testPlanRevisionID),
			payload:  `{"body":"","title":"plan"}`,
		},
		{
			name:     "memory",
			kind:     event.KindMemoryAppended,
			entityID: string(testMemoryID),
			payload:  `{"body":"","key":"key","scope":"session"}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorHuman,
				fixture.editorDevice,
				test.kind,
				test.entityID,
				0,
				test.payload,
				2,
			)
			assertAccepted(t, fixture.state, proposal)
		})
	}
}

func TestPlanCurrentPayloadSchemaRejections(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		payload string
		want    Code
	}{
		{
			name:    "missing revision",
			payload: `{}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "unknown field",
			payload: `{"plan_revision_id":"` + string(testPlanRevisionID) + `","unknown":true}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "malformed revision",
			payload: `{"plan_revision_id":"not-a-uuid"}`,
			want:    CodeInvalidPayload,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorHuman,
				fixture.ownerDevice,
				event.KindPlanCurrentSelected,
				string(testSessionID),
				1,
				test.payload,
				2,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}
