package reducer

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestNewStateDerivesClaimLimitsFromTaskRows(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.SessionPolicy.Values.AgentClaimLimit = 1

	claimed := taskForReducerState(fixture, task.StateClaimed, 1)
	claimed.ID = testOtherTaskID
	snapshot.Tasks[testOtherTaskID] = claimed
	snapshot.Tasks[testTaskID] = testTask(task.StateReady, 4)

	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	fixture.state = state
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskClaimed,
		4,
		`{}`,
	)
	assertRejectedCode(t, state, proposal, CodeAgentClaimLimitReached)
}

func TestNewStateDerivesConflictGateFromPublicationRows(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.Tasks[testTaskID] = taskForReducerState(
		fixture,
		task.StateInProgress,
		4,
	)

	const publicationID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000030",
	)
	value := testProposedPublication(
		t,
		fixture,
		publicationID,
		domain.UUIDv7("01890f47-3e72-7000-8000-000000000031"),
		testTaskID,
	)
	snapshot.Publications[publicationID] = value

	conflictValue := testConflictForPublication(
		t,
		fixture,
		value,
		testReducerGitOID(5),
	)
	snapshot.MergeConflicts[conflictValue.ID] = conflictValue

	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	fixture.state = state
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskStateChanged,
		4,
		`{"to_state":"done"}`,
	)
	assertRejectedCode(t, state, proposal, CodeTaskHasUnresolvedConflict)
}

func TestNewStateDeepCopiesRowsUsedByDerivedIndexes(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	claimed := taskForReducerState(fixture, task.StateClaimed, 1)
	claimed.ID = testOtherTaskID
	snapshot.Tasks[testOtherTaskID] = claimed

	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	delete(snapshot.Tasks, testOtherTaskID)
	member := snapshot.Devices[fixture.editorDevice]
	member.IdentityPublicKey[0] ^= 0xff
	snapshot.Devices[fixture.editorDevice] = member

	if len(state.claimsByAgent[testAgentSessionID]) != 1 ||
		len(state.claimsByDevice[fixture.editorDevice]) != 1 {
		t.Fatalf("derived claim indexes changed with input snapshot: %#v", state)
	}
	if err := state.devices[fixture.editorDevice].Validate(); err != nil {
		t.Fatalf("committed device aliases input snapshot: %v", err)
	}
}

func TestStateApplyUsesExplicitAcceptedEventChainMarker(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	key := OriginScopeKey{
		DeviceID: fixture.ownerDevice,
		Kind:     ScopeBoot,
		ScopeID:  testBootID,
	}
	rejected := fixture.state.originScopes[key]
	rejected.LastSequence++
	if err := fixture.state.Apply(Changes{
		OriginScopes: []OriginScope{rejected},
	}); err != nil {
		t.Fatalf("Apply(rejected origin-only result) error = %v", err)
	}
	if fixture.state.currentChainIndex != 0 ||
		fixture.state.currentResultIndex != 2 {
		t.Fatalf(
			"rejected indices = chain %d, result %d",
			fixture.state.currentChainIndex,
			fixture.state.currentResultIndex,
		)
	}

	accepted := fixture.state.originScopes[key]
	accepted.LastSequence++
	if err := fixture.state.Apply(Changes{
		AdvancesEventChain: true,
		OriginScopes:       []OriginScope{accepted},
	}); err != nil {
		t.Fatalf("Apply(accepted origin-only result) error = %v", err)
	}
	if fixture.state.currentChainIndex != 1 ||
		fixture.state.currentResultIndex != 3 {
		t.Fatalf(
			"accepted indices = chain %d, result %d",
			fixture.state.currentChainIndex,
			fixture.state.currentResultIndex,
		)
	}
}

func TestReduceRefusesFirstSeenCommandAtResultChainCapacity(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.currentChainIndex = domain.MaxSafeInteger
	fixture.state.currentResultIndex = domain.MaxSafeInteger
	proposal := buildTaskProposal(
		t,
		fixture,
		event.ActorAgent,
		event.KindTaskCreated,
		0,
		`{"priority":2,"title":"task"}`,
	)

	outcome, err := Reduce(fixture.state, proposal)
	if !errors.Is(err, ErrReducerCapacityExhausted) {
		t.Fatalf("Reduce() error = %v, want capacity exhaustion", err)
	}
	if !reflect.DeepEqual(outcome, Outcome{}) {
		t.Fatalf("Reduce() outcome = %#v, want zero outcome", outcome)
	}
}

func snapshotFromState(state State) Snapshot {
	snapshot := Snapshot{
		SessionID:           state.sessionID,
		WorkspaceID:         state.workspaceID,
		RecoveryGeneration:  state.recoveryGeneration,
		RecoveryPublicKey:   append(ed25519.PublicKey(nil), state.recoveryPublicKey...),
		CurrentChainIndex:   state.currentChainIndex,
		CurrentResultIndex:  state.currentResultIndex,
		OriginScopes:        make(map[OriginScopeKey]OriginScope, len(state.originScopes)),
		AuditCounters:       make(map[domain.DeviceID]auditcounter.Counter, len(state.auditCounters)),
		Devices:             make(map[domain.DeviceID]device.Device, len(state.devices)),
		VoterSet:            state.voterSet,
		CredentialAuthority: state.credentialAuthority.Clone(),
		CredentialAuthorizations: make(
			map[credentialauthorization.Key]credentialauthorization.Authorization,
			len(state.credentialAuthorizations),
		),
		AgentSessions: make(map[domain.UUIDv7]agentsession.Session, len(state.agentSessions)),
		Tasks:         make(map[domain.UUIDv7]task.Task, len(state.tasks)),
		PlanRevisions: make(map[domain.UUIDv7]plan.Revision, len(state.planRevisions)),
		PlanCurrent:   state.planCurrent,
		MemoryRecords: make(map[domain.UUIDv7]memory.Record, len(state.memoryRecords)),
		Leases:        make(map[domain.UUIDv7]lease.Lease, len(state.leases)),
		SessionPolicy: state.sessionPolicy,
		CanonicalRef:  state.canonicalRef,
		Publications:  make(map[domain.UUIDv7]publication.Publication, len(state.publications)),
		ControlFileProposals: make(
			map[domain.UUIDv7]controlfile.Proposal,
			len(state.controlFileProposals),
		),
		MergeConflicts: make(map[domain.ConflictID]conflict.Conflict, len(state.mergeConflicts)),
	}
	for key, value := range state.originScopes {
		snapshot.OriginScopes[key] = value
	}
	for id, value := range state.devices {
		snapshot.Devices[id] = value
	}
	for id, value := range state.auditCounters {
		snapshot.AuditCounters[id] = value
	}
	for key, value := range state.credentialAuthorizations {
		snapshot.CredentialAuthorizations[key] = value.Clone()
	}
	for id, value := range state.agentSessions {
		snapshot.AgentSessions[id] = cloneAgentSession(value)
	}
	for id, value := range state.tasks {
		snapshot.Tasks[id] = cloneTask(value)
	}
	for id, value := range state.planRevisions {
		snapshot.PlanRevisions[id] = value
	}
	for id, value := range state.memoryRecords {
		snapshot.MemoryRecords[id] = value
	}
	for id, value := range state.leases {
		snapshot.Leases[id] = value
	}
	for id, value := range state.publications {
		snapshot.Publications[id] = clonePublication(value)
	}
	for id, value := range state.controlFileProposals {
		snapshot.ControlFileProposals[id] = value.Clone()
	}
	for id, value := range state.mergeConflicts {
		snapshot.MergeConflicts[id] = cloneConflict(value)
	}
	return snapshot
}

func testReducerGitOID(value int) domain.GitOID {
	return domain.GitOID(fmt.Sprintf("sha1:%040x", value))
}
