package reducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

const (
	testSessionID      = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	testAgentSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000002")
	testWorkingRootID  = domain.UUIDv7("01890f47-3e72-7000-8000-000000000003")
	testBootID         = domain.UUIDv7("01890f47-3e72-7000-8000-000000000004")
	testTaskID         = domain.UUIDv7("01890f47-3e72-7000-8000-000000000010")
	testOtherTaskID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000011")
	testOtherAgentID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000012")
	testEventID        = domain.UUIDv7("01890f47-3e72-7000-8000-000000000020")
	testWorkspaceID    = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	testTimestamp      = domain.Timestamp("2026-08-11T12:00:00Z")
)

type reducerFixture struct {
	state              State
	ownerDevice        domain.DeviceID
	editorDevice       domain.DeviceID
	targetDevice       domain.DeviceID
	privateKeys        map[domain.DeviceID]ed25519.PrivateKey
	recoveryPrivateKey ed25519.PrivateKey
}

func TestTaskReducersAcceptMinimalPayloadsAndEmitCanonicalOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*reducerFixture)
		kind    event.Kind
		actor   event.ActorType
		payload string
		verify  func(*testing.T, task.Task)
	}{
		{
			name:    "created",
			kind:    event.KindTaskCreated,
			actor:   event.ActorHuman,
			payload: `{"priority":2,"title":"new task"}`,
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateBacklog || got.Title != "new task" ||
					got.Body != "" || got.Priority != task.PriorityNormal ||
					got.EntityVersion != 1 {
					t.Fatalf("created task = %#v", got)
				}
			},
		},
		{
			name: "updated",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			kind:    event.KindTaskUpdated,
			actor:   event.ActorAgent,
			payload: `{"body":"detail","labels":["z","a","z"],"title":"updated"}`,
			verify: func(t *testing.T, got task.Task) {
				if got.Title != "updated" || got.Body != "detail" ||
					!slices.Equal(got.Labels, []string{"a", "z"}) ||
					got.EntityVersion != 5 {
					t.Fatalf("updated task = %#v", got)
				}
			},
		},
		{
			name: "state changed",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			kind:    event.KindTaskStateChanged,
			actor:   event.ActorHuman,
			payload: `{"to_state":"ready"}`,
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateReady || got.EntityVersion != 5 {
					t.Fatalf("state-changed task = %#v", got)
				}
			},
		},
		{
			name: "claimed",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateReady, 4)
			},
			kind:    event.KindTaskClaimed,
			actor:   event.ActorAgent,
			payload: `{}`,
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateClaimed ||
					got.OwnerAgentSessionID != testAgentSessionID ||
					got.OwnerDeviceID == "" ||
					got.EntityVersion != 5 {
					t.Fatalf("claimed task = %#v", got)
				}
			},
		},
		{
			name: "released",
			prepare: func(fixture *reducerFixture) {
				value := testTask(task.StateClaimed, 4)
				ownTask(&value, fixture.editorDevice)
				fixture.state.tasks[testTaskID] = value
				fixture.state.claimsByAgent[testAgentSessionID] = []domain.UUIDv7{testTaskID}
				fixture.state.claimsByDevice[fixture.editorDevice] = []domain.UUIDv7{testTaskID}
			},
			kind:    event.KindTaskReleased,
			actor:   event.ActorAgent,
			payload: `{"release_reason":"voluntary"}`,
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateReady ||
					got.OwnerDeviceID != "" ||
					got.LastReleaseReason != task.ReleaseVoluntary ||
					got.EntityVersion != 5 {
					t.Fatalf("released task = %#v", got)
				}
			},
		},
		{
			name: "reassigned",
			prepare: func(fixture *reducerFixture) {
				value := testTask(task.StateClaimed, 4)
				ownTask(&value, fixture.editorDevice)
				fixture.state.tasks[testTaskID] = value
			},
			kind:    event.KindTaskReassigned,
			actor:   event.ActorHuman,
			payload: "",
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateReady ||
					got.IntendedDeviceID == "" ||
					got.LastReleaseReason != task.ReleaseForced ||
					got.EntityVersion != 5 {
					t.Fatalf("reassigned task = %#v", got)
				}
			},
		},
		{
			name: "cancelled",
			prepare: func(fixture *reducerFixture) {
				fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
			},
			kind:    event.KindTaskCancelled,
			actor:   event.ActorHuman,
			payload: `{}`,
			verify: func(t *testing.T, got task.Task) {
				if got.State != task.StateCancelled || got.EntityVersion != 5 {
					t.Fatalf("cancelled task = %#v", got)
				}
			},
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
			payload := test.payload
			if test.kind == event.KindTaskReassigned {
				payload = `{"to_device_id":"` + string(fixture.targetDevice) + `"}`
			}
			entityVersion := uint64(4)
			if test.kind == event.KindTaskCreated {
				entityVersion = 0
			}
			proposal := buildTaskProposal(
				t,
				fixture,
				test.actor,
				test.kind,
				entityVersion,
				payload,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusAccepted || outcome.Code != CodeAccepted {
				t.Fatalf("outcome = %#v", outcome)
			}
			if len(outcome.Changes.OriginScopes) != 1 ||
				len(outcome.Changes.Tasks) != 1 ||
				outcome.ActivityTaskID != testTaskID {
				t.Fatalf("changes = %#v", outcome)
			}
			test.verify(t, outcome.Changes.Tasks[0])

			gotJSON, err := outcome.ResultJSON()
			if err != nil {
				t.Fatalf("ResultJSON() error = %v", err)
			}
			if string(gotJSON) != `{"code":"accepted","status":"accepted"}` {
				t.Fatalf("ResultJSON() = %s", gotJSON)
			}
		})
	}
}

func TestPostSequenceDomainRejectionStillConsumesSequence(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateBacklog, 4)
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
	)

	outcome, err := Reduce(fixture.state, proposal)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if outcome.Status != StatusRejected || outcome.Code != CodeTaskNotActionable {
		t.Fatalf("outcome = %#v", outcome)
	}
	if len(outcome.Changes.OriginScopes) != 1 ||
		outcome.Changes.OriginScopes[0].LastSequence != 2 ||
		len(outcome.Changes.Tasks) != 0 {
		t.Fatalf("rejection changes = %#v", outcome.Changes)
	}
}

func TestGapAndReuseConsumeNothing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		sequence uint64
		want     Code
	}{
		{name: "reuse", sequence: 1, want: CodeOriginSequenceReused},
		{name: "gap", sequence: 3, want: CodeOriginSequenceGap},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			proposal := buildTaskProposalAtSequence(
				t,
				fixture,
				event.ActorAgent,
				event.KindTaskCreated,
				0,
				`{"priority":2,"title":"new task"}`,
				test.sequence,
			)

			outcome, err := Reduce(fixture.state, proposal)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Status != StatusRejected || outcome.Code != test.want {
				t.Fatalf("outcome = %#v", outcome)
			}
			if len(outcome.Changes.OriginScopes) != 0 ||
				len(outcome.Changes.Tasks) != 0 {
				t.Fatalf("sequence rejection changed projections: %#v", outcome.Changes)
			}
		})
	}
}

func newReducerFixture(t *testing.T) reducerFixture {
	t.Helper()

	owner, ownerPrivateKey := testDevice(t, 1, device.RoleOwner)
	editor, editorPrivateKey := testDevice(t, 2, device.RoleEditor)
	target, targetPrivateKey := testDevice(t, 3, device.RoleEditor)
	session := agentsession.Session{
		ID:            testAgentSessionID,
		DeviceID:      editor.ID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateIdle,
		WorkingRootID: testWorkingRootID,
		EntityVersion: 1,
	}
	sessionPolicy := policy.Policy{
		SessionID:     testSessionID,
		Values:        policy.DefaultValues(),
		EntityVersion: 1,
	}
	initialVoterSet, err := voterset.New(
		testSessionID,
		[]domain.DeviceID{owner.ID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	recoveryPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x44}, ed25519.SeedSize),
	)
	recoveryPublicKey := recoveryPrivateKey.Public().(ed25519.PublicKey)
	snapshot := Snapshot{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		RecoveryPublicKey:  append(ed25519.PublicKey(nil), recoveryPublicKey...),
		CurrentResultIndex: 1,
		OriginScopes:       make(map[OriginScopeKey]OriginScope),
		Devices: map[domain.DeviceID]device.Device{
			owner.ID:  owner,
			editor.ID: editor,
			target.ID: target,
		},
		AuditCounters: map[domain.DeviceID]auditcounter.Counter{
			owner.ID:  {DeviceID: owner.ID},
			editor.ID: {DeviceID: editor.ID},
			target.ID: {DeviceID: target.ID},
		},
		VoterSet: initialVoterSet,
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        testSessionID,
			VoterDeviceIDs:   []domain.DeviceID{owner.ID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		AgentSessions: map[domain.UUIDv7]agentsession.Session{
			session.ID: session,
		},
		Tasks:         make(map[domain.UUIDv7]task.Task),
		PlanRevisions: make(map[domain.UUIDv7]plan.Revision),
		PlanCurrent: plan.Current{
			SessionID:     testSessionID,
			EntityVersion: 1,
		},
		MemoryRecords: make(map[domain.UUIDv7]memory.Record),
		SessionPolicy: sessionPolicy,
		CanonicalRef: publication.CanonicalRef{
			RefName:       publication.CanonicalRefName,
			CommitOID:     testReducerGitOID(1),
			EntityVersion: 1,
		},
		Publications:   nil,
		MergeConflicts: nil,
	}
	agentKey := OriginScopeKey{
		DeviceID: editor.ID,
		Kind:     ScopeAgent,
		ScopeID:  testAgentSessionID,
	}
	snapshot.OriginScopes[agentKey] = OriginScope{
		OriginScopeKey: agentKey,
		LastSequence:   1,
	}
	for _, member := range []device.Device{owner, editor} {
		key := OriginScopeKey{
			DeviceID: member.ID,
			Kind:     ScopeBoot,
			ScopeID:  testBootID,
		}
		snapshot.OriginScopes[key] = OriginScope{
			OriginScopeKey: key,
			LastSequence:   1,
		}
	}
	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	return reducerFixture{
		state:        state,
		ownerDevice:  owner.ID,
		editorDevice: editor.ID,
		targetDevice: target.ID,
		privateKeys: map[domain.DeviceID]ed25519.PrivateKey{
			owner.ID:  ownerPrivateKey,
			editor.ID: editorPrivateKey,
			target.ID: targetPrivateKey,
		},
		recoveryPrivateKey: append(
			ed25519.PrivateKey(nil),
			recoveryPrivateKey...,
		),
	}
}

func testDevice(
	t *testing.T,
	fill byte,
	role device.Role,
) (device.Device, ed25519.PrivateKey) {
	t.Helper()

	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	id, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID() error = %v", err)
	}
	value := device.Device{
		ID:                id,
		Role:              role,
		IdentityPublicKey: append(ed25519.PublicKey(nil), publicKey...),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("device.Validate() error = %v", err)
	}
	return value, append(ed25519.PrivateKey(nil), privateKey...)
}

func testTask(state task.State, version uint64) task.Task {
	value := task.Task{
		ID:            testTaskID,
		Title:         "task",
		State:         state,
		Priority:      task.PriorityNormal,
		EntityVersion: version,
		CreatedAt:     testTimestamp,
		UpdatedAt:     testTimestamp,
	}
	return value
}

func ownTask(value *task.Task, deviceID domain.DeviceID) {
	value.OwnerDeviceID = deviceID
	value.OwnerAgentSessionID = testAgentSessionID
}

func buildTaskProposal(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	kind event.Kind,
	version uint64,
	payload string,
) event.SignedEvent {
	t.Helper()
	return buildTaskProposalAtSequence(t, fixture, actor, kind, version, payload, 2)
}

func buildTaskProposalAtSequence(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	kind event.Kind,
	version uint64,
	payload string,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	return buildTaskProposalForDeviceAtSequence(
		t,
		fixture,
		actor,
		"",
		kind,
		version,
		payload,
		sequence,
	)
}

func buildHumanTaskProposal(
	t *testing.T,
	fixture reducerFixture,
	deviceID domain.DeviceID,
	kind event.Kind,
	version uint64,
	payload string,
) event.SignedEvent {
	t.Helper()
	return buildTaskProposalForDeviceAtSequence(
		t,
		fixture,
		event.ActorHuman,
		deviceID,
		kind,
		version,
		payload,
		2,
	)
}

func buildTaskProposalForDeviceAtSequence(
	t *testing.T,
	fixture reducerFixture,
	actor event.ActorType,
	humanDeviceID domain.DeviceID,
	kind event.Kind,
	version uint64,
	payload string,
	sequence uint64,
) event.SignedEvent {
	t.Helper()

	var binding event.Binding
	var originDeviceID domain.DeviceID
	var err error
	switch actor {
	case event.ActorAgent:
		originDeviceID = fixture.editorDevice
		binding, err = event.NewMCPBinding(
			originDeviceID,
			testAgentSessionID,
			nil,
		)
	case event.ActorHuman:
		if humanDeviceID == "" {
			humanDeviceID = fixture.editorDevice
			if kind == event.KindTaskReassigned || kind == event.KindTaskCancelled {
				humanDeviceID = fixture.ownerDevice
			}
		}
		originDeviceID = humanDeviceID
		var authority event.LocalAuthority
		authority, err = event.NewLocalAuthority(humanDeviceID, testBootID)
		if err == nil {
			binding, err = authority.OperatorBinding()
		}
	default:
		t.Fatalf("unsupported test actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct binding: %v", err)
	}

	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(string(testTaskID)),
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
	privateKey, exists := fixture.privateKeys[originDeviceID]
	if !exists {
		t.Fatalf("no private key for origin device %q", originDeviceID)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}

func TestOutcomeResultJSONRejectsInvalidShape(t *testing.T) {
	t.Parallel()

	if _, err := (Outcome{}).ResultJSON(); err == nil {
		t.Fatal("ResultJSON() accepted an empty outcome")
	}
	if !errors.Is(ErrKindNotImplemented, ErrKindNotImplemented) {
		t.Fatal("sentinel error is not comparable")
	}
}
