package event

import (
	"slices"
	"testing"
)

func TestKindRegistryIsCompleteAndExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind            Kind
		role            RoleRequirement
		actors          []ActorType
		cas             CASPolicy
		entity          EntityIDType
		leaderScheduled bool
	}{
		{KindTaskCreated, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASForbidden, EntityUUIDv7, false},
		{KindTaskUpdated, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindTaskStateChanged, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindTaskClaimed, RoleEditor, []ActorType{ActorAgent}, CASRequired, EntityUUIDv7, false},
		{KindTaskReleased, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindTaskReassigned, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindTaskCancelled, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindWorkspaceConflictDetected, RoleEditor, []ActorType{ActorDaemon}, CASForbidden, EntityConflictID, false},
		{KindWorkspaceConflictForceResolved, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntityConflictID, false},
		{KindWorkspaceConflictResolved, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityConflictID, false},
		{KindPublicationProposed, RoleEditor, []ActorType{ActorAgent}, CASForbidden, EntityUUIDv7, false},
		{KindPublicationReviewed, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindPublicationApplied, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindPublicationWithdrawn, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASRequired, EntityUUIDv7, false},
		{KindPlanRevisionProposed, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASForbidden, EntityUUIDv7, false},
		{KindPlanCurrentSelected, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntitySessionID, false},
		{KindMemoryAppended, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASForbidden, EntityUUIDv7, false},
		{KindActivityRecorded, RoleEditor, []ActorType{ActorAgent, ActorHuman, ActorDaemon}, CASForbidden, EntityNull, false},
		{KindLeaseAcquired, RoleEditor, []ActorType{ActorAgent}, CASForbidden, EntityUUIDv7, false},
		{KindLeaseRenewed, RoleEditor, []ActorType{ActorAgent}, CASRequired, EntityUUIDv7, false},
		{KindLeaseReleased, RoleEditor, []ActorType{ActorAgent, ActorHuman, ActorDaemon}, CASRequired, EntityUUIDv7, true},
		{KindAgentSessionStarted, RoleEditor, []ActorType{ActorAgent}, CASForbidden, EntityUUIDv7, false},
		{KindAgentSessionStateChanged, RoleEditor, []ActorType{ActorAgent, ActorDaemon}, CASRequired, EntityUUIDv7, false},
		{KindAgentSessionEnded, RoleEditor, []ActorType{ActorAgent, ActorDaemon}, CASRequired, EntityUUIDv7, false},
		{KindMembershipDeviceAdmitted, RoleOwner, []ActorType{ActorHuman}, CASConditional, EntityDeviceID, false},
		{KindMembershipVersionReported, RoleMember, []ActorType{ActorDaemon}, CASRequired, EntityDeviceID, false},
		{KindMembershipRoleChanged, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntityDeviceID, false},
		{KindMembershipOwnerRecovered, RoleNone, []ActorType{ActorHuman}, CASRequired, EntityDeviceID, false},
		{KindMembershipDeviceRevoked, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntityDeviceID, false},
		{KindMembershipVoterSetChanged, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntitySessionID, false},
		{KindMembershipVoterSetActivated, RoleNone, []ActorType{ActorDaemon}, CASPayload, EntitySessionID, true},
		{KindPolicyChanged, RoleOwner, []ActorType{ActorHuman}, CASRequired, EntitySessionID, false},
		{KindCredentialAuthorized, RoleMember, []ActorType{ActorDaemon}, CASForbidden, EntityDeviceID, true},
		{KindControlFileChangeProposed, RoleEditor, []ActorType{ActorAgent, ActorHuman}, CASForbidden, EntityRepositoryPath, false},
		{KindConsensusCheckpoint, RoleNone, []ActorType{ActorDaemon}, CASForbidden, EntityNull, true},
		{KindAuditRecorded, RoleNone, []ActorType{ActorDaemon}, CASForbidden, EntityNull, false},
	}

	gotKinds := Kinds()
	if len(gotKinds) != len(tests) {
		t.Fatalf("Kinds() count = %d, want %d", len(gotKinds), len(tests))
	}
	seen := make(map[Kind]struct{}, len(gotKinds))
	for index, test := range tests {
		if gotKinds[index] != test.kind {
			t.Errorf("Kinds()[%d] = %q, want %q", index, gotKinds[index], test.kind)
		}
		if _, duplicate := seen[test.kind]; duplicate {
			t.Errorf("duplicate kind %q", test.kind)
		}
		seen[test.kind] = struct{}{}

		spec, ok := LookupKind(test.kind)
		if !ok {
			t.Errorf("LookupKind(%q) did not find registered kind", test.kind)
			continue
		}
		if spec.Kind() != test.kind ||
			spec.MinimumRole() != test.role ||
			spec.CASPolicy() != test.cas ||
			spec.EntityIDType() != test.entity ||
			spec.MinApplyLevel() != 1 ||
			spec.LeaderScheduled() != test.leaderScheduled {
			t.Errorf(
				"LookupKind(%q) = kind %q role %q CAS %q entity %q level %d leader %t",
				test.kind,
				spec.Kind(),
				spec.MinimumRole(),
				spec.CASPolicy(),
				spec.EntityIDType(),
				spec.MinApplyLevel(),
				spec.LeaderScheduled(),
			)
		}
		if got := spec.AllowedActors(); !slices.Equal(got, test.actors) {
			t.Errorf("LookupKind(%q).AllowedActors() = %v, want %v", test.kind, got, test.actors)
		}
		for _, actor := range ActorTypes() {
			if got, want := spec.AllowsActor(actor), slices.Contains(test.actors, actor); got != want {
				t.Errorf("LookupKind(%q).AllowsActor(%q) = %t, want %t", test.kind, actor, got, want)
			}
		}
	}
	if _, ok := LookupKind("task.deleted"); ok {
		t.Fatal("LookupKind accepted an unknown kind")
	}
}

func TestKindRegistryReturnsIndependentSlices(t *testing.T) {
	t.Parallel()

	kinds := Kinds()
	kinds[0] = "changed"
	if Kinds()[0] != KindTaskCreated {
		t.Fatal("Kinds returned mutable registry storage")
	}

	spec, ok := LookupKind(KindTaskCreated)
	if !ok {
		t.Fatal("task.created missing")
	}
	actors := spec.AllowedActors()
	actors[0] = ActorDaemon
	if !spec.AllowsActor(ActorAgent) || spec.AllowsActor(ActorDaemon) {
		t.Fatal("AllowedActors returned mutable registry storage")
	}
}

func TestKindRegistryDoesNotExceedBinaryApplyLevel(t *testing.T) {
	t.Parallel()

	var highest uint64
	for _, kind := range Kinds() {
		spec, ok := LookupKind(kind)
		if !ok {
			t.Fatalf("LookupKind(%q) missing", kind)
		}
		if spec.MinApplyLevel() > MaxSupportedApplyLevel {
			t.Errorf(
				"LookupKind(%q).MinApplyLevel() = %d, binary supports %d",
				kind,
				spec.MinApplyLevel(),
				MaxSupportedApplyLevel,
			)
		}
		highest = max(highest, spec.MinApplyLevel())
	}
	if highest != MaxSupportedApplyLevel {
		t.Fatalf(
			"highest registered apply level = %d, binary declares %d",
			highest,
			MaxSupportedApplyLevel,
		)
	}
}
