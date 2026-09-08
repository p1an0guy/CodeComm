package reducer

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPreflightRejectsInactiveOrUnboundOriginsWithoutConsumingSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*reducerFixture)
		want   Code
	}{
		{
			name: "revoked device",
			mutate: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.editorDevice]
				member.Status = device.StatusRevoked
				member.EntityVersion++
				fixture.state.devices[fixture.editorDevice] = member
			},
			want: CodeOriginDeviceNotActive,
		},
		{
			name: "missing agent session",
			mutate: func(fixture *reducerFixture) {
				delete(fixture.state.agentSessions, testAgentSessionID)
			},
			want: CodeAgentSessionNotFound,
		},
		{
			name: "profile mismatch",
			mutate: func(fixture *reducerFixture) {
				session := fixture.state.agentSessions[testAgentSessionID]
				profile := "reviewer"
				session.AgentProfileID = &profile
				fixture.state.agentSessions[testAgentSessionID] = session
			},
			want: CodeAgentSessionBindingMismatch,
		},
		{
			name: "disconnected agent",
			mutate: func(fixture *reducerFixture) {
				session := fixture.state.agentSessions[testAgentSessionID]
				session.State = agentsession.StateDisconnected
				session.ResumeState = agentsession.StateIdle
				session.EntityVersion++
				fixture.state.agentSessions[testAgentSessionID] = session
			},
			want: CodeAgentSessionNotConnected,
		},
		{
			name: "missing agent scope",
			mutate: func(fixture *reducerFixture) {
				delete(fixture.state.originScopes, OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				})
			},
			want: CodeOriginScopeNotFound,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			test.mutate(&fixture)
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				`{"priority":2,"title":"new task"}`,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusRejected || outcome.Code != test.want {
				t.Fatalf("outcome = %#v", outcome)
			}
			if len(outcome.Changes.OriginScopes) != 0 {
				t.Fatalf("pre-sequence rejection consumed scope: %#v", outcome.Changes)
			}
		})
	}
}

func TestFirstBootSequenceCreatesScopeEvenWhenRoleRejects(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	delete(fixture.state.originScopes, OriginScopeKey{
		DeviceID: fixture.editorDevice,
		Kind:     ScopeBoot,
		ScopeID:  testBootID,
	})
	fixture.state.tasks[testTaskID] = testTask("backlog", 1)
	proposal := buildTaskProposalForDeviceAtSequence(
		t,
		fixture,
		event.ActorHuman,
		fixture.editorDevice,
		event.KindTaskCancelled,
		1,
		`{}`,
		1,
	)

	outcome, err := Reduce(fixture.state, proposal)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if outcome.Code != CodeInsufficientRole ||
		len(outcome.Changes.OriginScopes) != 1 ||
		outcome.Changes.OriginScopes[0].LastSequence != 1 {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestPreflightConsumesBeforeActorCASAndRoleRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		proposal func(*testing.T, reducerFixture) event.SignedEvent
		want     Code
	}{
		{
			name: "actor not allowed",
			proposal: func(t *testing.T, fixture reducerFixture) event.SignedEvent {
				signed := buildTaskProposal(
					t,
					fixture,
					event.ActorAgent,
					event.KindTaskUpdated,
					1,
					`{"title":"task"}`,
				)
				return resignEvent(t, fixture, signed, func(object map[string]json.RawMessage) {
					object["kind"] = json.RawMessage(`"task.cancelled"`)
					object["payload"] = json.RawMessage(`{}`)
				})
			},
			want: CodeActorNotAllowed,
		},
		{
			name: "missing CAS",
			proposal: func(t *testing.T, fixture reducerFixture) event.SignedEvent {
				signed := buildTaskProposal(
					t,
					fixture,
					event.ActorAgent,
					event.KindTaskCreated,
					0,
					`{"priority":2,"title":"task"}`,
				)
				return resignEvent(t, fixture, signed, func(object map[string]json.RawMessage) {
					object["kind"] = json.RawMessage(`"task.updated"`)
					object["payload"] = json.RawMessage(`{"title":"task"}`)
				})
			},
			want: CodeExpectedEntityVersion,
		},
		{
			name: "insufficient role",
			proposal: func(t *testing.T, fixture reducerFixture) event.SignedEvent {
				return buildHumanTaskProposal(
					t,
					fixture,
					fixture.editorDevice,
					event.KindTaskCancelled,
					1,
					`{}`,
				)
			},
			want: CodeInsufficientRole,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			fixture.state.tasks[testTaskID] = testTask("backlog", 1)
			outcome, err := Reduce(fixture.state, test.proposal(t, fixture))
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 1 ||
				outcome.Changes.OriginScopes[0].LastSequence != 2 {
				t.Fatalf("outcome = %#v", outcome)
			}
		})
	}
}

func TestPreflightHaltsBeforeUnknownKindOrUnsupportedApplyLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   error
	}{
		{
			name: "unknown kind at supported level",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.unknown"`)
			},
			want: ErrKindNotImplemented,
		},
		{
			name: "unsupported apply level before kind dispatch",
			mutate: func(object map[string]json.RawMessage) {
				object["kind"] = json.RawMessage(`"task.unknown"`)
				object["min_apply_level"] = json.RawMessage(`2`)
			},
			want: ErrApplyLevelUnsupported,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			signed := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				`{"priority":2,"title":"task"}`,
			)
			signed = resignEvent(t, fixture, signed, test.mutate)

			outcome, err := Reduce(fixture.state, signed)
			if !errors.Is(err, test.want) {
				t.Fatalf("Reduce() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(outcome, Outcome{}) {
				t.Fatalf("Reduce() outcome = %#v, want zero outcome", outcome)
			}
		})
	}
}

func TestPreflightHaltsWhenCommittedFloorExceedsBinary(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.sessionPolicy.Values.ClusterMinApplyLevel =
		int64(event.MaxSupportedApplyLevel + 1)
	for id, member := range fixture.state.devices {
		member.MaxApplyLevel = event.MaxSupportedApplyLevel + 1
		fixture.state.devices[id] = member
	}
	signed := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskCreated,
		0,
		`{"priority":2,"title":"task"}`,
	)
	outcome, err := Reduce(fixture.state, signed)
	if !errors.Is(err, ErrApplyLevelUnsupported) {
		t.Fatalf(
			"Reduce() = (%#v, %v), want ErrApplyLevelUnsupported",
			outcome,
			err,
		)
	}
	if !reflect.DeepEqual(outcome, Outcome{}) {
		t.Fatalf("unsupported binary produced outcome %#v", outcome)
	}
}

func TestSessionBindingMismatchConsumesNothing(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskCreated,
		0,
		`{"priority":2,"title":"task"}`,
	)
	proposal := resignEvent(t, fixture, signed, func(object map[string]json.RawMessage) {
		object["session_id"] = json.RawMessage(
			`"01890f47-3e72-7000-8000-000000000099"`,
		)
	})

	outcome, err := Reduce(fixture.state, proposal)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if outcome.Code != CodeSessionBindingMismatch ||
		len(outcome.Changes.OriginScopes) != 0 {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestReduceReverifiesCanonicalSignedBytes(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskCreated,
		0,
		`{"priority":2,"title":"task"}`,
	)

	// SignedEvent deliberately hides its storage. Reflection here simulates
	// corrupted or incorrectly constructed FSM input and proves the reducer
	// does not trust prior transport verification.
	canonical := reflect.ValueOf(&signed).
		Elem().
		FieldByName("canonical").
		Bytes()
	marker := []byte(`"origin_signature":"`)
	signatureOffset := bytes.Index(canonical, marker)
	if signatureOffset < 0 {
		t.Fatal("signed event has no origin_signature")
	}
	signatureOffset += len(marker)
	if canonical[signatureOffset] == 'A' {
		canonical[signatureOffset] = 'B'
	} else {
		canonical[signatureOffset] = 'A'
	}

	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if outcome.Code != CodeInvalidOriginSignature ||
		len(outcome.Changes.OriginScopes) != 0 {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestEveryRegisteredKindHasReducerDispatch(t *testing.T) {
	t.Parallel()

	for _, kind := range event.Kinds() {
		if !implementedKind(kind) {
			t.Errorf("registered kind %q has no reducer dispatch", kind)
		}
	}
}

func TestMalformedCommittedRowsReturnIntegrityErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*reducerFixture)
	}{
		{
			name: "state identity",
			mutate: func(fixture *reducerFixture) {
				fixture.state.sessionID = ""
			},
		},
		{
			name: "device row",
			mutate: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.editorDevice]
				member.EntityVersion = 0
				fixture.state.devices[fixture.editorDevice] = member
			},
		},
		{
			name: "scope row",
			mutate: func(fixture *reducerFixture) {
				key := OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				}
				scope := fixture.state.originScopes[key]
				scope.LastSequence = 0
				fixture.state.originScopes[key] = scope
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			test.mutate(&fixture)
			proposal := buildTaskProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				`{"priority":2,"title":"task"}`,
			)

			if _, err := Reduce(fixture.state, proposal); !errors.Is(err, ErrInvalidCommittedState) {
				t.Fatalf("Reduce() error = %v, want ErrInvalidCommittedState", err)
			}
		})
	}
}
