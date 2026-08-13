package reducer

import (
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testPlanRevisionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000060",
	)
	testPriorPlanRevisionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000061",
	)
	testMemoryID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000070",
	)
	testPriorMemoryID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000071",
	)
	testMemorySuccessorID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000072",
	)
)

func TestPlanRevisionProposedCreatesImmutableRevision(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.Tasks[testTaskID] = testTask(task.StateReady, 1)
	snapshot.PlanRevisions[testPriorPlanRevisionID] = mustPlanRevision(
		t,
		testPriorPlanRevisionID,
		"",
		nil,
		fixture.ownerDevice,
	)
	state := mustReducerState(t, snapshot)
	payload := `{"body":"next","supersedes":"` +
		string(testPriorPlanRevisionID) +
		`","task_ids":["` + string(testTaskID) +
		`"],"title":"Iteration 2"}`
	proposal := buildCoordinationProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		event.KindPlanRevisionProposed,
		string(testPlanRevisionID),
		0,
		payload,
		2,
	)

	outcome := assertAccepted(t, state, proposal)
	if len(outcome.Changes.PlanRevisions) != 1 ||
		len(outcome.Changes.PlanCurrent) != 0 ||
		len(outcome.Changes.MemoryRecords) != 0 {
		t.Fatalf("plan revision changes = %#v", outcome.Changes)
	}
	got := outcome.Changes.PlanRevisions[0]
	supersedes, hasSupersedes := got.Supersedes()
	if got.ID() != testPlanRevisionID ||
		supersedes != testPriorPlanRevisionID ||
		!hasSupersedes ||
		got.Title() != "Iteration 2" ||
		got.Body() != "next" ||
		len(got.TaskIDs()) != 1 ||
		got.TaskIDs()[0] != testTaskID ||
		got.ProposedByDeviceID() != fixture.editorDevice ||
		got.CreatedAt() != testTimestamp {
		t.Fatalf("plan revision = %#v", got)
	}
	if err := state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if stored, exists := state.planRevisions[testPlanRevisionID]; !exists ||
		stored.ID() != testPlanRevisionID {
		t.Fatalf("stored plan revision = %#v", stored)
	}
}

func TestPlanCurrentSelectedAdvancesPointerWithAudit(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
		t,
		testPlanRevisionID,
		"",
		nil,
		fixture.editorDevice,
	)
	state := mustReducerState(t, snapshot)
	proposal := buildCoordinationProposal(
		t,
		fixture,
		event.ActorHuman,
		fixture.ownerDevice,
		event.KindPlanCurrentSelected,
		string(testSessionID),
		1,
		`{"plan_revision_id":"`+string(testPlanRevisionID)+`"}`,
		2,
	)

	outcome := assertAccepted(t, state, proposal)
	if len(outcome.Changes.PlanCurrent) != 1 ||
		len(outcome.Changes.PlanRevisions) != 0 {
		t.Fatalf("plan-current changes = %#v", outcome.Changes)
	}
	got := outcome.Changes.PlanCurrent[0]
	if got.SessionID != testSessionID ||
		got.RevisionID != testPlanRevisionID ||
		got.EntityVersion != 2 {
		t.Fatalf("current plan = %#v", got)
	}
	if outcome.Audit == nil ||
		outcome.Audit.Class != AuditOperatorOverride {
		t.Fatalf("plan selection audit = %#v", outcome.Audit)
	}
	if err := state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if state.planCurrent != got {
		t.Fatalf("stored current plan = %#v", state.planCurrent)
	}
}

func TestMemoryAppendedExtendsCorrectionChain(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.Tasks[testTaskID] = testTask(task.StateReady, 1)
	snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
		t,
		testPriorMemoryID,
		memory.ScopeTask,
		testTaskID,
		"architecture",
		"old",
		"",
	)
	state := mustReducerState(t, snapshot)
	payload := `{"body":"new","key":"architecture","scope":"task","supersedes":"` +
		string(testPriorMemoryID) +
		`","task_id":"` + string(testTaskID) + `"}`
	proposal := buildCoordinationProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		event.KindMemoryAppended,
		string(testMemoryID),
		0,
		payload,
		2,
	)

	outcome := assertAccepted(t, state, proposal)
	if len(outcome.Changes.MemoryRecords) != 1 ||
		outcome.ActivityTaskID != testTaskID {
		t.Fatalf("memory changes = %#v", outcome)
	}
	got := outcome.Changes.MemoryRecords[0]
	taskID, hasTask := got.TaskID()
	supersedes, hasSupersedes := got.Supersedes()
	if got.ID() != testMemoryID ||
		got.Scope() != memory.ScopeTask ||
		taskID != testTaskID ||
		!hasTask ||
		got.Key() != "architecture" ||
		got.Body() != "new" ||
		supersedes != testPriorMemoryID ||
		!hasSupersedes ||
		got.CreatedAt() != testTimestamp {
		t.Fatalf("memory record = %#v", got)
	}
	if err := state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if state.memorySuccessors[testPriorMemoryID] != testMemoryID {
		t.Fatalf("memory successor index = %#v", state.memorySuccessors)
	}
}

func TestPlanAndMemoryReferenceRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		kind     event.Kind
		entityID domain.UUIDv7
		payload  func(reducerFixture) string
		prepare  func(*testing.T, reducerFixture, *Snapshot)
		want     Code
	}{
		{
			name:     "plan task missing",
			kind:     event.KindPlanRevisionProposed,
			entityID: testPlanRevisionID,
			payload: func(reducerFixture) string {
				return `{"body":"","task_ids":["` +
					string(testTaskID) + `"],"title":"plan"}`
			},
			want: CodePlanTaskNotFound,
		},
		{
			name:     "plan predecessor missing",
			kind:     event.KindPlanRevisionProposed,
			entityID: testPlanRevisionID,
			payload: func(reducerFixture) string {
				return `{"body":"","supersedes":"` +
					string(testPriorPlanRevisionID) + `","title":"plan"}`
			},
			want: CodePlanRevisionNotFound,
		},
		{
			name:     "memory task missing",
			kind:     event.KindMemoryAppended,
			entityID: testMemoryID,
			payload: func(reducerFixture) string {
				return `{"body":"","key":"key","scope":"task","task_id":"` +
					string(testTaskID) + `"}`
			},
			want: CodeMemoryTaskNotFound,
		},
		{
			name:     "memory predecessor missing",
			kind:     event.KindMemoryAppended,
			entityID: testMemoryID,
			payload: func(reducerFixture) string {
				return `{"body":"","key":"key","scope":"session","supersedes":"` +
					string(testPriorMemoryID) + `"}`
			},
			want: CodeMemoryPredecessorNotFound,
		},
		{
			name:     "memory predecessor already superseded",
			kind:     event.KindMemoryAppended,
			entityID: testMemoryID,
			payload: func(reducerFixture) string {
				return `{"body":"latest","key":"key","scope":"session","supersedes":"` +
					string(testPriorMemoryID) + `"}`
			},
			prepare: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
					t,
					testPriorMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"old",
					"",
				)
				snapshot.MemoryRecords[testMemorySuccessorID] = mustMemoryRecord(
					t,
					testMemorySuccessorID,
					memory.ScopeSession,
					"",
					"key",
					"new",
					testPriorMemoryID,
				)
			},
			want: CodeMemoryPredecessorAlreadySuperseded,
		},
		{
			name:     "memory predecessor key mismatch",
			kind:     event.KindMemoryAppended,
			entityID: testMemoryID,
			payload: func(reducerFixture) string {
				return `{"body":"latest","key":"other","scope":"session","supersedes":"` +
					string(testPriorMemoryID) + `"}`
			},
			prepare: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
					t,
					testPriorMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"old",
					"",
				)
			},
			want: CodeMemoryPredecessorMismatch,
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
				test.kind,
				string(test.entityID),
				0,
				test.payload(fixture),
				2,
			)
			assertRejectedCode(t, state, proposal, test.want)
		})
	}
}

func TestPlanCurrentSelectionRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		device     func(reducerFixture) domain.DeviceID
		entityID   domain.UUIDv7
		version    uint64
		revisionID domain.UUIDv7
		prepare    func(*testing.T, reducerFixture, *Snapshot)
		want       Code
	}{
		{
			name: "editor is not owner",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.editorDevice
			},
			entityID:   testSessionID,
			version:    1,
			revisionID: testPlanRevisionID,
			want:       CodeInsufficientRole,
		},
		{
			name: "entity session mismatch",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID:   testPlanRevisionID,
			version:    1,
			revisionID: testPlanRevisionID,
			want:       CodeSessionBindingMismatch,
		},
		{
			name: "CAS mismatch",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID:   testSessionID,
			version:    2,
			revisionID: testPlanRevisionID,
			want:       CodeEntityVersionMismatch,
		},
		{
			name: "revision missing",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID:   testSessionID,
			version:    1,
			revisionID: testPriorPlanRevisionID,
			want:       CodePlanRevisionNotFound,
		},
		{
			name: "version exhausted",
			device: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			entityID:   testSessionID,
			version:    domain.MaxSafeInteger,
			revisionID: testPlanRevisionID,
			prepare: func(
				_ *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanCurrent.EntityVersion = domain.MaxSafeInteger
				snapshot.PlanCurrent.RevisionID = testPlanRevisionID
			},
			want: CodeEntityVersionExhausted,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
				t,
				testPlanRevisionID,
				"",
				nil,
				fixture.editorDevice,
			)
			if test.prepare != nil {
				test.prepare(t, fixture, &snapshot)
			}
			state := mustReducerState(t, snapshot)
			proposal := buildCoordinationProposal(
				t,
				fixture,
				event.ActorHuman,
				test.device(fixture),
				event.KindPlanCurrentSelected,
				string(test.entityID),
				test.version,
				`{"plan_revision_id":"`+string(test.revisionID)+`"}`,
				2,
			)
			assertRejectedCode(t, state, proposal, test.want)
		})
	}
}

func mustPlanRevision(
	t *testing.T,
	id domain.UUIDv7,
	supersedes domain.UUIDv7,
	taskIDs []domain.UUIDv7,
	deviceID domain.DeviceID,
) plan.Revision {
	t.Helper()
	value, err := plan.NewRevision(
		id,
		supersedes,
		"plan",
		"",
		taskIDs,
		deviceID,
		testTimestamp,
	)
	if err != nil {
		t.Fatalf("plan.NewRevision() error = %v", err)
	}
	return value
}

func mustMemoryRecord(
	t *testing.T,
	id domain.UUIDv7,
	scope memory.Scope,
	taskID domain.UUIDv7,
	key string,
	body string,
	supersedes domain.UUIDv7,
) memory.Record {
	t.Helper()
	value, err := memory.NewRecord(
		id,
		scope,
		taskID,
		key,
		body,
		supersedes,
		testTimestamp,
	)
	if err != nil {
		t.Fatalf("memory.NewRecord() error = %v", err)
	}
	return value
}

func mustReducerState(t *testing.T, snapshot Snapshot) State {
	t.Helper()
	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	return state
}

func buildCoordinationProposal(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	deviceID domain.DeviceID,
	kind event.Kind,
	entityID string,
	version uint64,
	payload string,
	sequence uint64,
) event.SignedEvent {
	t.Helper()

	var binding event.Binding
	var err error
	switch actor {
	case event.ActorAgent:
		binding, err = event.NewMCPBinding(
			deviceID,
			testAgentSessionID,
			nil,
		)
	case event.ActorHuman:
		var authority event.LocalAuthority
		authority, err = event.NewLocalAuthority(deviceID, testBootID)
		if err == nil {
			binding, err = authority.OperatorBinding()
		}
	default:
		t.Fatalf("unsupported coordination actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct binding: %v", err)
	}

	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(entityID),
		RationaleSummary: "",
		Actions:          []event.Action{},
		Payload:          json.RawMessage(payload),
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}
	if version != 0 {
		command.ExpectedEntityVersion = &version
	}
	proposal, err := event.BuildProposal(command, binding, event.BuildContext{
		EventID:        testEventID,
		SessionID:      testSessionID,
		WorkspaceID:    testWorkspaceID,
		CreatedAt:      testTimestamp,
		OriginSequence: sequence,
	})
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	signed, err := event.Sign(proposal, fixture.privateKeys[deviceID])
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}
