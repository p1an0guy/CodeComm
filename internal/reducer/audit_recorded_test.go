package reducer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPrepareAuditRecordedAcceptsLatestEpochAndAdvancesCounter(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	context := auditReductionContext(
		t,
		fixture,
		validAuditPayload(fixture.ownerDevice, 0),
	)
	counter, directive, code, err := prepareAuditRecorded(context)
	if err != nil || code != "" {
		t.Fatalf("prepareAuditRecorded() = (%#v, %#v, %q, %v)", counter, directive, code, err)
	}
	if counter.DeviceID != fixture.ownerDevice ||
		counter.CredentialEpoch != 0 ||
		counter.AcceptedCount != 1 ||
		directive.ReporterDeviceID != fixture.editorDevice ||
		directive.SubjectDeviceID != fixture.ownerDevice ||
		directive.SubjectCredentialEpoch != 0 ||
		directive.ActionCode != "api.mutate" ||
		directive.OutcomeCode != "invalid.request" ||
		directive.Subject != "task:01890f47" {
		t.Fatalf("counter = %#v, directive = %#v", counter, directive)
	}
}

func TestPrepareAuditRecordedRejectionMatrix(t *testing.T) {
	t.Parallel()

	unknown, _ := testDevice(t, 9, device.RoleEditor)
	tests := []struct {
		name    string
		prepare func(*reducerFixture)
		payload func(reducerFixture) map[string]any
		want    Code
	}{
		{
			name: "unknown subject",
			payload: func(reducerFixture) map[string]any {
				return validAuditPayload(unknown.ID, 0)
			},
			want: CodeAuditSubjectNotFound,
		},
		{
			name: "inactive subject",
			prepare: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.targetDevice]
				member.Status = device.StatusRevoked
				fixture.state.devices[fixture.targetDevice] = member
			},
			payload: func(fixture reducerFixture) map[string]any {
				return validAuditPayload(fixture.targetDevice, 0)
			},
			want: CodeAuditSubjectNotActive,
		},
		{
			name: "stale epoch",
			payload: func(fixture reducerFixture) map[string]any {
				return validAuditPayload(fixture.ownerDevice, 1)
			},
			want: CodeAuditCredentialEpochMismatch,
		},
		{
			name: "depth exhausted",
			prepare: func(fixture *reducerFixture) {
				counter := fixture.state.auditCounters[fixture.ownerDevice]
				counter.AcceptedCount = uint64(
					fixture.state.sessionPolicy.Values.
						AuditDepthPerDevicePerEpoch,
				)
				fixture.state.auditCounters[fixture.ownerDevice] = counter
			},
			payload: func(fixture reducerFixture) map[string]any {
				return validAuditPayload(fixture.ownerDevice, 0)
			},
			want: CodeAuditDepthExceeded,
		},
		{
			name: "invalid action code",
			payload: func(fixture reducerFixture) map[string]any {
				payload := validAuditPayload(fixture.ownerDevice, 0)
				payload["action"] = "invalid action"
				return payload
			},
			want: CodeInvalidPayload,
		},
		{
			name: "subject too long",
			payload: func(fixture reducerFixture) map[string]any {
				payload := validAuditPayload(fixture.ownerDevice, 0)
				payload["subject"] = strings.Repeat("x", 257)
				return payload
			},
			want: CodeInvalidPayload,
		},
		{
			name: "unknown field",
			payload: func(fixture reducerFixture) map[string]any {
				payload := validAuditPayload(fixture.ownerDevice, 0)
				payload["details"] = "not allowed"
				return payload
			},
			want: CodeUnknownPayloadField,
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
			context := auditReductionContext(
				t,
				fixture,
				test.payload(fixture),
			)

			_, _, code, err := prepareAuditRecorded(context)
			if err != nil || code != test.want {
				t.Fatalf(
					"prepareAuditRecorded() = (%q, %v), want (%q, nil)",
					code,
					err,
					test.want,
				)
			}
		})
	}
}

func TestAuditRecordedDispatchesAndAppliesTypedDirective(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := signedAuditRecorded(
		t,
		fixture,
		validAuditPayload(fixture.ownerDevice, 0),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		outcome.RecordActivity ||
		!outcome.Changes.AdvancesEventChain ||
		len(outcome.Changes.AuditCounters) != 1 ||
		outcome.RecordedAudit == nil ||
		outcome.RecordedAudit.SubjectDeviceID != fixture.ownerDevice {
		t.Fatalf("outcome = %#v", outcome)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	if got := fixture.state.auditCounters[fixture.ownerDevice]; got.AcceptedCount != 1 {
		t.Fatalf("applied audit counter = %#v", got)
	}
}

func TestStateApplyRejectsAuditIncrementWithUnrelatedMutation(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := signedAuditRecorded(
		t,
		fixture,
		validAuditPayload(fixture.ownerDevice, 0),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil || !outcome.Accepted() {
		t.Fatalf("Reduce() = %#v, %v", outcome, err)
	}
	outcome.Changes.Tasks = []task.Task{testTask(task.StateReady, 1)}

	err = fixture.state.Apply(outcome.Changes)
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid state", err)
	}
	_, taskExists := fixture.state.tasks[testTaskID]
	if fixture.state.auditCounters[fixture.ownerDevice].AcceptedCount != 0 ||
		taskExists {
		t.Fatalf("invalid audit changes partially applied: %#v", fixture.state)
	}
}

func validAuditPayload(
	subjectDeviceID domain.DeviceID,
	epoch uint64,
) map[string]any {
	return map[string]any{
		"action":                   "api.mutate",
		"outcome":                  "invalid.request",
		"subject":                  "task:01890f47",
		"subject_device_id":        subjectDeviceID,
		"subject_credential_epoch": epoch,
	}
}

func auditReductionContext(
	t *testing.T,
	fixture reducerFixture,
	payload map[string]any,
) reductionContext {
	t.Helper()
	signed := signedAuditRecorded(t, fixture, payload)
	context, outcome, done, err := beginReduction(fixture.state, signed)
	if err != nil {
		t.Fatalf("beginReduction() error = %v", err)
	}
	if done {
		t.Fatalf("beginReduction() outcome = %#v", outcome)
	}
	return context
}

func signedAuditRecorded(
	t *testing.T,
	fixture reducerFixture,
	payload map[string]any,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		fixture.editorDevice,
		testBootID,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority() error = %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding() error = %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	proposal, err := event.BuildProposal(event.Command{
		Kind:     event.KindAuditRecorded,
		EntityID: event.NullEntityID(),
		Actions:  []event.Action{},
		Payload:  encoded,
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}, binding, event.BuildContext{
		EventID:        domainEventID(140),
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
