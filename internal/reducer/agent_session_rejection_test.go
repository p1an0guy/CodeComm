package reducer

import (
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestAgentSessionStartPayloadAndCapRejectionsBurnTheID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		prepare func(*reducerFixture)
		want    Code
	}{
		{
			name: "unknown field",
			payload: `{"client_kind":"codex","unknown":true,"working_root_id":"` +
				string(testNewWorkingRootID) + `"}`,
			want: CodeUnknownPayloadField,
		},
		{
			name: "null field",
			payload: `{"client_kind":null,"working_root_id":"` +
				string(testNewWorkingRootID) + `"}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "missing root",
			payload: `{"client_kind":"codex"}`,
			want:    CodeMissingPayloadField,
		},
		{
			name: "invalid client",
			payload: `{"client_kind":"unknown","working_root_id":"` +
				string(testNewWorkingRootID) + `"}`,
			want: CodeInvalidPayload,
		},
		{
			name:    "malformed root",
			payload: `{"client_kind":"codex","working_root_id":"bad"}`,
			want:    CodeInvalidPayload,
		},
		{
			name: "active session cap",
			payload: `{"client_kind":"codex","working_root_id":"` +
				string(testNewWorkingRootID) + `"}`,
			prepare: func(fixture *reducerFixture) {
				fixture.state.sessionPolicy.Values.MaxActiveAgentSessions = 1
			},
			want: CodeAgentSessionLimitReached,
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
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testNewAgentSessionID,
				nil,
				event.KindAgentSessionStarted,
				testNewAgentSessionID,
				0,
				test.payload,
				1,
			)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce(start) error = %v", err)
			}
			if outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 1 ||
				len(outcome.Changes.AgentSessions) != 0 {
				t.Fatalf("start rejection = %#v", outcome)
			}
			if err := fixture.state.Apply(outcome.Changes); err != nil {
				t.Fatalf("Apply(rejected start) error = %v", err)
			}

			retry := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testNewAgentSessionID,
				nil,
				event.KindAgentSessionStarted,
				testNewAgentSessionID,
				0,
				`{"client_kind":"codex","working_root_id":"`+
					string(testNewWorkingRootID)+`"}`,
				1,
			)
			retried, err := Reduce(fixture.state, retry)
			if err != nil {
				t.Fatalf("Reduce(retry) error = %v", err)
			}
			if retried.Code != CodeEntityAlreadyExists ||
				len(retried.Changes.OriginScopes) != 0 {
				t.Fatalf("burned-ID retry = %#v", retried)
			}
		})
	}
}

func TestAgentSessionStartEnforcesThirtyTwoSessionBoundary(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		active     int
		wantAccept bool
	}{
		{name: "thirty second accepted", active: 31, wantAccept: true},
		{name: "thirty third rejected", active: 32},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			for index := 1; fixture.state.activeAgentSessionCount < test.active; index++ {
				addReducerAgent(
					&fixture.state,
					reducerAgentID(100+index),
					fixture.editorDevice,
				)
			}
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testNewAgentSessionID,
				nil,
				event.KindAgentSessionStarted,
				testNewAgentSessionID,
				0,
				`{"client_kind":"codex","working_root_id":"`+
					string(testNewWorkingRootID)+`"}`,
				1,
			)
			if test.wantAccept {
				assertAccepted(t, fixture.state, proposal)
				return
			}
			assertRejectedCode(
				t,
				fixture.state,
				proposal,
				CodeAgentSessionLimitReached,
			)
		})
	}
}

func TestStructurallyInvalidAgentStartDoesNotBurnScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   Code
	}{
		{
			name: "forbidden CAS",
			mutate: func(object map[string]json.RawMessage) {
				object["expected_entity_version"] = json.RawMessage(`1`)
			},
			want: CodeExpectedEntityVersion,
		},
		{
			name: "entity does not match origin session",
			mutate: func(object map[string]json.RawMessage) {
				object["entity_id"] = json.RawMessage(
					`"` + string(reducerAgentID(9)) + `"`,
				)
			},
			want: CodeInvalidKindContract,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			valid := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testNewAgentSessionID,
				nil,
				event.KindAgentSessionStarted,
				testNewAgentSessionID,
				0,
				`{"client_kind":"codex","working_root_id":"`+
					string(testNewWorkingRootID)+`"}`,
				1,
			)
			proposal := resignEvent(t, fixture, valid, test.mutate)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.want ||
				len(outcome.Changes.OriginScopes) != 0 {
				t.Fatalf("structural rejection = %#v", outcome)
			}
			if _, exists := fixture.state.agentScopeDevices[testNewAgentSessionID]; exists {
				t.Fatal("structural rejection burned the agent ID")
			}
		})
	}
}

func TestAgentSessionMutationPayloadSchemas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    event.Kind
		payload string
		want    Code
	}{
		{
			name:    "state unknown field",
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"note":true,"to_state":"working"}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "state null",
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":null}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "state missing",
			kind:    event.KindAgentSessionStateChanged,
			payload: `{}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "state unknown value",
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":"paused"}`,
			want:    CodeInvalidPayload,
		},
		{
			name:    "end unknown field",
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"clean","note":true}`,
			want:    CodeUnknownPayloadField,
		},
		{
			name:    "end missing",
			kind:    event.KindAgentSessionEnded,
			payload: `{}`,
			want:    CodeMissingPayloadField,
		},
		{
			name:    "end unknown value",
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"lost"}`,
			want:    CodeInvalidEndReason,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				nil,
				test.kind,
				testAgentSessionID,
				1,
				test.payload,
				2,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestAgentSessionMutationEntityAndAuthorizationRejections(t *testing.T) {
	t.Parallel()

	t.Run("missing entity", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		proposal := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorDaemon,
			fixture.editorDevice,
			"",
			nil,
			event.KindAgentSessionEnded,
			testOtherAgentID,
			1,
			`{"end_reason":"operator"}`,
			2,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeEntityNotFound)
	})

	t.Run("stale CAS", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		proposal := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			nil,
			event.KindAgentSessionStateChanged,
			testAgentSessionID,
			2,
			`{"to_state":"working"}`,
			2,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeEntityVersionMismatch)
	})

	t.Run("exhausted session version", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		session := fixture.state.agentSessions[testAgentSessionID]
		session.EntityVersion = domain.MaxSafeInteger
		fixture.state.agentSessions[testAgentSessionID] = session
		proposal := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			nil,
			event.KindAgentSessionEnded,
			testAgentSessionID,
			domain.MaxSafeInteger,
			`{"end_reason":"clean"}`,
			2,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeEntityVersionExhausted)
	})

	t.Run("agent targets another session", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		addReducerAgent(&fixture.state, testOtherAgentID, fixture.editorDevice)
		proposal := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			nil,
			event.KindAgentSessionStateChanged,
			testOtherAgentID,
			1,
			`{"to_state":"working"}`,
			2,
		)
		assertRejectedCode(
			t,
			fixture.state,
			proposal,
			CodeAgentSessionBindingMismatch,
		)
	})

	t.Run("foreign daemon targets session", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		proposal := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorDaemon,
			fixture.targetDevice,
			"",
			nil,
			event.KindAgentSessionEnded,
			testAgentSessionID,
			1,
			`{"end_reason":"operator"}`,
			1,
		)
		assertRejectedCode(
			t,
			fixture.state,
			proposal,
			CodeAgentSessionBindingMismatch,
		)
	})
}

func TestAgentSessionActorTransitionAndReasonRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actor   event.ActorType
		kind    event.Kind
		payload string
		prepare func(*reducerFixture)
		want    Code
	}{
		{
			name:    "agent cannot disconnect",
			actor:   event.ActorAgent,
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":"disconnected"}`,
			want:    CodeInvalidAgentSessionTransition,
		},
		{
			name:    "daemon cannot report connected status",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":"working"}`,
			want:    CodeInvalidAgentSessionTransition,
		},
		{
			name:    "daemon cannot resume to a different state",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":"working"}`,
			prepare: func(fixture *reducerFixture) {
				session := fixture.state.agentSessions[testAgentSessionID]
				session.State = agentsession.StateDisconnected
				session.ResumeState = agentsession.StateIdle
				session.EntityVersion = 2
				fixture.state.agentSessions[testAgentSessionID] = session
			},
			want: CodeInvalidAgentSessionTransition,
		},
		{
			name:    "state changed cannot enter ended",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionStateChanged,
			payload: `{"to_state":"ended"}`,
			want:    CodeInvalidAgentSessionTransition,
		},
		{
			name:    "agent cannot claim crash reap",
			actor:   event.ActorAgent,
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"crash_reap"}`,
			want:    CodeEndActorMismatch,
		},
		{
			name:    "daemon cannot claim clean end",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"clean"}`,
			want:    CodeEndActorMismatch,
		},
		{
			name:    "recovery is transform only",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"recovery"}`,
			want:    CodeInvalidEndReason,
		},
		{
			name:    "disconnect timeout requires disconnected",
			actor:   event.ActorDaemon,
			kind:    event.KindAgentSessionEnded,
			payload: `{"end_reason":"disconnect_timeout"}`,
			want:    CodeInvalidAgentSessionTransition,
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
			version := fixture.state.agentSessions[testAgentSessionID].EntityVersion
			originAgentID := domain.UUIDv7("")
			if test.actor == event.ActorAgent {
				originAgentID = testAgentSessionID
			}
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				test.actor,
				fixture.editorDevice,
				originAgentID,
				nil,
				test.kind,
				testAgentSessionID,
				version,
				test.payload,
				2,
			)
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestAgentSessionEndRejectsCascadeVersionExhaustionAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*testing.T, *reducerFixture)
	}{
		{
			name: "task",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				value := taskForReducerState(
					*fixture,
					task.StateClaimed,
					domain.MaxSafeInteger,
				)
				fixture.state.tasks[value.ID] = value
				fixture.state.addClaim(value)
			},
		},
		{
			name: "lease",
			prepare: func(t *testing.T, fixture *reducerFixture) {
				value := mustReducerLease(
					t,
					testLeaseID,
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					domain.MaxSafeInteger,
					"src/**",
				)
				addReducerLease(&fixture.state, value)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			test.prepare(t, &fixture)
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				nil,
				event.KindAgentSessionEnded,
				testAgentSessionID,
				1,
				`{"end_reason":"clean"}`,
				2,
			)
			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != CodeEntityVersionExhausted ||
				len(outcome.Changes.OriginScopes) != 1 ||
				len(outcome.Changes.AgentSessions) != 0 ||
				len(outcome.Changes.Tasks) != 0 ||
				len(outcome.Changes.Leases) != 0 {
				t.Fatalf("exhausted cascade outcome = %#v", outcome)
			}
		})
	}
}
