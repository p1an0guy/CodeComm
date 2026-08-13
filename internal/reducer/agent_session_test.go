package reducer

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testNewAgentSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000050",
	)
	testNewWorkingRootID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000051",
	)
)

func TestAgentSessionStartedCreatesSessionAndOriginScope(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	profile := "planner"
	proposal := buildAgentSessionProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testNewAgentSessionID,
		&profile,
		event.KindAgentSessionStarted,
		testNewAgentSessionID,
		0,
		`{"client_kind":"claude","working_root_id":"`+
			string(testNewWorkingRootID)+`"}`,
		1,
	)

	outcome := assertAccepted(t, fixture.state, proposal)
	if len(outcome.Changes.OriginScopes) != 1 ||
		len(outcome.Changes.AgentSessions) != 1 ||
		len(outcome.Changes.Tasks) != 0 ||
		len(outcome.Changes.Leases) != 0 {
		t.Fatalf("start changes = %#v", outcome.Changes)
	}
	scope := outcome.Changes.OriginScopes[0]
	if scope.Kind != ScopeAgent ||
		scope.DeviceID != fixture.editorDevice ||
		scope.ScopeID != testNewAgentSessionID ||
		scope.LastSequence != 1 {
		t.Fatalf("start scope = %#v", scope)
	}
	got := outcome.Changes.AgentSessions[0]
	if got.ID != testNewAgentSessionID ||
		got.DeviceID != fixture.editorDevice ||
		got.ClientKind != agentsession.ClientKindClaude ||
		got.AgentProfileID == nil ||
		*got.AgentProfileID != profile ||
		got.State != agentsession.StateStarting ||
		got.ResumeState != agentsession.StateAbsent ||
		got.WorkingRootID != testNewWorkingRootID ||
		got.EndReason != agentsession.EndReasonAbsent ||
		got.EntityVersion != 1 {
		t.Fatalf("started session = %#v", got)
	}

	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply(start) error = %v", err)
	}
	profile = "mutated"
	stored := fixture.state.agentSessions[testNewAgentSessionID]
	if stored.AgentProfileID == nil || *stored.AgentProfileID != "planner" ||
		fixture.state.activeAgentSessionCount != 2 ||
		fixture.state.agentScopeDevices[testNewAgentSessionID] !=
			fixture.editorDevice {
		t.Fatalf("stored start = %#v", fixture.state)
	}
}

func TestAgentSessionStateChangesDisconnectAndResume(t *testing.T) {
	t.Parallel()

	t.Run("agent status", func(t *testing.T) {
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
			1,
			`{"to_state":"working"}`,
			2,
		)
		outcome := assertAccepted(t, fixture.state, proposal)
		got := outcome.Changes.AgentSessions[0]
		if got.State != agentsession.StateWorking ||
			got.ResumeState != agentsession.StateAbsent ||
			got.EntityVersion != 2 {
			t.Fatalf("agent status change = %#v", got)
		}
	})

	t.Run("daemon disconnect and resume", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		disconnect := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorDaemon,
			fixture.editorDevice,
			"",
			nil,
			event.KindAgentSessionStateChanged,
			testAgentSessionID,
			1,
			`{"to_state":"disconnected"}`,
			2,
		)
		disconnected := assertAccepted(t, fixture.state, disconnect)
		got := disconnected.Changes.AgentSessions[0]
		if got.State != agentsession.StateDisconnected ||
			got.ResumeState != agentsession.StateIdle ||
			got.EntityVersion != 2 {
			t.Fatalf("disconnected session = %#v", got)
		}
		if err := fixture.state.Apply(disconnected.Changes); err != nil {
			t.Fatalf("Apply(disconnect) error = %v", err)
		}

		resume := buildAgentSessionProposal(
			t,
			fixture,
			event.ActorDaemon,
			fixture.editorDevice,
			"",
			nil,
			event.KindAgentSessionStateChanged,
			testAgentSessionID,
			2,
			`{"to_state":"idle"}`,
			3,
		)
		resumed := assertAccepted(t, fixture.state, resume)
		got = resumed.Changes.AgentSessions[0]
		if got.State != agentsession.StateIdle ||
			got.ResumeState != agentsession.StateAbsent ||
			got.EntityVersion != 3 {
			t.Fatalf("resumed session = %#v", got)
		}
	})
}

func TestAgentSessionEndedAtomicallyReleasesClaimsAndLeases(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	session := fixture.state.agentSessions[testAgentSessionID]
	session.State = agentsession.StateWorking
	session.EntityVersion = 4
	fixture.state.agentSessions[testAgentSessionID] = session

	firstTask := taskForReducerState(fixture, task.StateInProgress, 7)
	firstTask.ID = testTaskID
	secondTask := taskForReducerState(fixture, task.StateBlocked, 3)
	secondTask.ID = testOtherTaskID
	reason := "waiting"
	secondTask.StateReason = &reason
	fixture.state.tasks[firstTask.ID] = firstTask
	fixture.state.tasks[secondTask.ID] = secondTask
	fixture.state.addClaim(firstTask)
	fixture.state.addClaim(secondTask)

	firstLease := mustReducerLease(
		t,
		reducerLeaseID(1),
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		5,
		"docs/**",
	)
	secondLease := mustReducerLease(
		t,
		reducerLeaseID(2),
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		2,
		"src/**",
	)
	addReducerLease(&fixture.state, firstLease)
	addReducerLease(&fixture.state, secondLease)

	proposal := buildAgentSessionProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		nil,
		event.KindAgentSessionEnded,
		testAgentSessionID,
		4,
		`{"end_reason":"clean"}`,
		2,
	)
	outcome := assertAccepted(t, fixture.state, proposal)
	if len(outcome.Changes.AgentSessions) != 1 ||
		len(outcome.Changes.Tasks) != 2 ||
		len(outcome.Changes.Leases) != 2 {
		t.Fatalf("end changes = %#v", outcome.Changes)
	}
	if !slices.IsSortedFunc(
		outcome.Changes.Tasks,
		func(left, right task.Task) int {
			return compareUUIDv7(left.ID, right.ID)
		},
	) || !slices.IsSortedFunc(
		outcome.Changes.Leases,
		func(left, right lease.Lease) int {
			return compareUUIDv7(left.ID, right.ID)
		},
	) {
		t.Fatalf("cascade rows are not in primary-key order: %#v", outcome.Changes)
	}
	for _, got := range outcome.Changes.Tasks {
		if got.State != task.StateReady ||
			got.StateReason != nil ||
			got.OwnerDeviceID != "" ||
			got.OwnerAgentSessionID != "" ||
			got.IntendedDeviceID != "" ||
			got.LastReleaseReason != task.ReleaseSessionEnd {
			t.Fatalf("released task = %#v", got)
		}
	}
	for _, got := range outcome.Changes.Leases {
		if got.Status != lease.StatusReleased ||
			got.ReleaseReason != lease.ReleaseSessionEnded {
			t.Fatalf("released lease = %#v", got)
		}
	}
	ended := outcome.Changes.AgentSessions[0]
	if ended.State != agentsession.StateEnded ||
		ended.EndReason != agentsession.EndReasonClean ||
		ended.EntityVersion != 5 {
		t.Fatalf("ended session = %#v", ended)
	}

	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("Apply(end) error = %v", err)
	}
	if fixture.state.activeAgentSessionCount != 0 ||
		len(fixture.state.claimsByAgent[testAgentSessionID]) != 0 ||
		len(fixture.state.activeLeasesByAgent[testAgentSessionID]) != 0 {
		t.Fatalf("indexes after end = %#v", fixture.state)
	}
}

func TestAgentSessionDaemonEndReasons(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		reason       agentsession.EndReason
		disconnected bool
	}{
		{
			name:   "operator",
			reason: agentsession.EndReasonOperator,
		},
		{
			name:   "crash reap",
			reason: agentsession.EndReasonCrashReap,
		},
		{
			name:         "disconnect timeout",
			reason:       agentsession.EndReasonDisconnectTimeout,
			disconnected: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			version := uint64(1)
			if test.disconnected {
				session := fixture.state.agentSessions[testAgentSessionID]
				session.State = agentsession.StateDisconnected
				session.ResumeState = agentsession.StateIdle
				session.EntityVersion = 2
				fixture.state.agentSessions[testAgentSessionID] = session
				version = 2
			}
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorDaemon,
				fixture.editorDevice,
				"",
				nil,
				event.KindAgentSessionEnded,
				testAgentSessionID,
				version,
				`{"end_reason":"`+string(test.reason)+`"}`,
				2,
			)
			outcome := assertAccepted(t, fixture.state, proposal)
			got := outcome.Changes.AgentSessions[0]
			if got.State != agentsession.StateEnded ||
				got.EndReason != test.reason ||
				got.ResumeState != agentsession.StateAbsent ||
				got.EntityVersion != version+1 ||
				outcome.Audit != nil {
				t.Fatalf("daemon-ended session = %#v, audit = %#v", got, outcome.Audit)
			}
		})
	}
}

func compareUUIDv7(left, right domain.UUIDv7) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func buildAgentSessionProposal(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	deviceID domain.DeviceID,
	originAgentID domain.UUIDv7,
	profile *string,
	kind event.Kind,
	targetID domain.UUIDv7,
	version uint64,
	payload string,
	sequence uint64,
) event.SignedEvent {
	t.Helper()

	var binding event.Binding
	var err error
	switch actor {
	case event.ActorAgent:
		binding, err = event.NewMCPBinding(deviceID, originAgentID, profile)
	case event.ActorDaemon:
		var authority event.LocalAuthority
		authority, err = event.NewLocalAuthority(deviceID, testBootID)
		if err == nil {
			binding, err = authority.DaemonBinding()
		}
	default:
		t.Fatalf("unsupported agent-session actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct agent-session binding: %v", err)
	}
	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(string(targetID)),
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
	privateKey, exists := fixture.privateKeys[deviceID]
	if !exists {
		t.Fatalf("no private key for origin device %q", deviceID)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}
