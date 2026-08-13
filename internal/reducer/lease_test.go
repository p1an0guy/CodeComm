package reducer

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testLeaseID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000040")
)

func TestLeaseReducersAcceptAcquisitionRenewalAndRelease(t *testing.T) {
	t.Parallel()

	t.Run("path acquisition", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 1)
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseAcquired,
			testLeaseID,
			0,
			`{"path_globs":["src/**","README.md","src/**"],"scope":"path","task_id":"`+
				string(testTaskID)+`","ttl_seconds":900}`,
		)

		outcome := assertAccepted(t, fixture.state, proposal)
		if len(outcome.Changes.Leases) != 1 ||
			len(outcome.Changes.Tasks) != 0 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("outcome = %#v", outcome)
		}
		got := outcome.Changes.Leases[0]
		if got.ID != testLeaseID ||
			got.HolderDeviceID != fixture.editorDevice ||
			got.HolderAgentSessionID != testAgentSessionID ||
			got.Scope != lease.ScopePath ||
			got.TaskID != testTaskID ||
			got.TTLSeconds != 900 ||
			got.Status != lease.StatusActive ||
			got.ReleaseReason != lease.ReleaseReasonAbsent ||
			got.EntityVersion != 1 ||
			!slices.Equal(
				pathPatternTexts(got),
				[]string{"README.md", "src/**"},
			) {
			t.Fatalf("acquired lease = %#v, paths = %v", got, pathPatternTexts(got))
		}
	})

	t.Run("task acquisition", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = taskForReducerState(
			fixture,
			task.StateInProgress,
			2,
		)
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseAcquired,
			testLeaseID,
			0,
			`{"scope":"task","task_id":"`+string(testTaskID)+`","ttl_seconds":30}`,
		)

		outcome := assertAccepted(t, fixture.state, proposal)
		got := outcome.Changes.Leases[0]
		if got.Scope != lease.ScopeTask ||
			got.TaskID != testTaskID ||
			got.PathPatterns() != nil ||
			got.TTLSeconds != 30 {
			t.Fatalf("acquired task lease = %#v", got)
		}
	})

	t.Run("renewal", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := mustReducerLease(
			t,
			testLeaseID,
			fixture.editorDevice,
			testAgentSessionID,
			lease.ScopePath,
			"",
			4,
			"src/**",
		)
		addReducerLease(&fixture.state, current)
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseRenewed,
			testLeaseID,
			4,
			`{"ttl_seconds":3600}`,
		)

		outcome := assertAccepted(t, fixture.state, proposal)
		got := outcome.Changes.Leases[0]
		if got.TTLSeconds != 3600 ||
			got.EntityVersion != 5 ||
			got.Status != lease.StatusActive ||
			!sameLeaseReservation(current, got) {
			t.Fatalf("renewed lease = %#v", got)
		}
	})

	tests := []struct {
		name      string
		actor     event.ActorType
		deviceID  domain.DeviceID
		reason    lease.ReleaseReason
		wantAudit bool
		agentID   domain.UUIDv7
	}{
		{
			name:    "voluntary",
			actor:   event.ActorAgent,
			reason:  lease.ReleaseVoluntary,
			agentID: testAgentSessionID,
		},
		{
			name:      "forced by owner",
			actor:     event.ActorHuman,
			reason:    lease.ReleaseForced,
			wantAudit: true,
		},
		{
			name:   "expired by daemon",
			actor:  event.ActorDaemon,
			reason: lease.ReleaseExpired,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			holderDevice := fixture.editorDevice
			holderAgent := testAgentSessionID
			current := mustReducerLease(
				t,
				testLeaseID,
				holderDevice,
				holderAgent,
				lease.ScopePath,
				"",
				4,
				"src/**",
			)
			addReducerLease(&fixture.state, current)
			proposal := buildLeaseProposalForOrigin(
				t,
				fixture,
				test.actor,
				test.deviceID,
				test.agentID,
				event.KindLeaseReleased,
				testLeaseID,
				4,
				`{"release_reason":"`+string(test.reason)+`"}`,
				2,
			)

			outcome := assertAccepted(t, fixture.state, proposal)
			got := outcome.Changes.Leases[0]
			if got.Status != lease.StatusReleased ||
				got.ReleaseReason != test.reason ||
				got.EntityVersion != 5 ||
				got.TTLSeconds != current.TTLSeconds ||
				!sameLeaseReservation(current, got) {
				t.Fatalf("released lease = %#v", got)
			}
			if (outcome.Audit != nil) != test.wantAudit {
				t.Fatalf("audit = %#v, want present %t", outcome.Audit, test.wantAudit)
			}
			if test.wantAudit &&
				outcome.Audit.Subject != "lease:"+string(testLeaseID) {
				t.Fatalf("audit = %#v", outcome.Audit)
			}
		})
	}
}

func addReducerAgent(
	state *State,
	id domain.UUIDv7,
	deviceID domain.DeviceID,
) {
	state.agentSessions[id] = agentsession.Session{
		ID:            id,
		DeviceID:      deviceID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateIdle,
		WorkingRootID: testWorkingRootID,
		EntityVersion: 1,
	}
	key := OriginScopeKey{
		DeviceID: deviceID,
		Kind:     ScopeAgent,
		ScopeID:  id,
	}
	state.originScopes[key] = OriginScope{
		OriginScopeKey: key,
		LastSequence:   1,
	}
	state.agentScopeDevices[id] = deviceID
	state.activeAgentSessionCount++
}

func addReducerLease(state *State, value lease.Lease) {
	state.leases[value.ID] = value
	state.addActiveLease(value)
}

func mustReducerLease(
	t *testing.T,
	id domain.UUIDv7,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
	scope lease.Scope,
	taskID domain.UUIDv7,
	version uint64,
	pathGlobs ...string,
) lease.Lease {
	t.Helper()
	value, err := lease.New(lease.Fields{
		ID:                   id,
		HolderDeviceID:       deviceID,
		HolderAgentSessionID: agentSessionID,
		Scope:                scope,
		TaskID:               taskID,
		TTLSeconds:           900,
		Status:               lease.StatusActive,
		EntityVersion:        version,
	}, pathGlobs)
	if err != nil {
		t.Fatalf("lease.New() error = %v", err)
	}
	return value
}

func reducerLeaseID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"01890f47-3e72-7000-8002-%012x",
		0x1000+index,
	))
}

func reducerAgentID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"01890f47-3e72-7000-8003-%012x",
		0x1000+index,
	))
}

func buildLeaseProposal(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	kind event.Kind,
	id domain.UUIDv7,
	version uint64,
	payload string,
) event.SignedEvent {
	t.Helper()
	return buildLeaseProposalForOrigin(
		t,
		fixture,
		actor,
		"",
		"",
		kind,
		id,
		version,
		payload,
		2,
	)
}

func buildLeaseProposalForOrigin(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
	kind event.Kind,
	id domain.UUIDv7,
	version uint64,
	payload string,
	sequence uint64,
) event.SignedEvent {
	t.Helper()

	var binding event.Binding
	var err error
	switch actor {
	case event.ActorAgent:
		if deviceID == "" {
			deviceID = fixture.editorDevice
		}
		if agentSessionID == "" {
			agentSessionID = testAgentSessionID
		}
		binding, err = event.NewMCPBinding(deviceID, agentSessionID, nil)
	case event.ActorHuman, event.ActorDaemon:
		if deviceID == "" {
			if actor == event.ActorHuman {
				deviceID = fixture.ownerDevice
			} else {
				deviceID = fixture.editorDevice
			}
		}
		var authority event.LocalAuthority
		authority, err = event.NewLocalAuthority(deviceID, testBootID)
		if err == nil && actor == event.ActorHuman {
			binding, err = authority.OperatorBinding()
		}
		if err == nil && actor == event.ActorDaemon {
			binding, err = authority.DaemonBinding()
		}
	default:
		t.Fatalf("unsupported actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct lease binding: %v", err)
	}

	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(string(id)),
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
