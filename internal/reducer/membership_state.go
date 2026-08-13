package reducer

import (
	"bytes"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

type pendingMembershipChanges struct {
	devices             map[domain.DeviceID]device.Device
	auditCounters       map[domain.DeviceID]auditcounter.Counter
	voterSet            *voterset.Set
	credentialAuthority *credentialauthority.Authority
	deviceOperation     device.Operation
	hasDeviceOperation  bool
}

func (state *State) loadMembershipSnapshot(
	counters map[domain.DeviceID]auditcounter.Counter,
	target voterset.Set,
	authority credentialauthority.Authority,
) error {
	if state == nil {
		return invalidState("nil reducer state")
	}
	for id, counter := range counters {
		if id != counter.DeviceID {
			return invalidState("audit-counter map key does not match row")
		}
		if err := counter.Validate(); err != nil {
			return invalidState("audit counter %q: %v", id, err)
		}
		if _, exists := state.devices[id]; !exists {
			return invalidState(
				"audit counter references missing device %q",
				id,
			)
		}
		state.auditCounters[id] = counter
	}
	for id := range state.devices {
		if _, exists := state.auditCounters[id]; !exists {
			return invalidState("device %q has no audit counter", id)
		}
	}
	if len(state.auditCounters) != len(state.devices) {
		return invalidState("device and audit-counter sets disagree")
	}

	state.voterSet = target
	state.credentialAuthority = authority.Clone()
	if err := state.validateMembershipTopology(
		state.devices,
		state.auditCounters,
		state.voterSet,
		state.credentialAuthority,
	); err != nil {
		return err
	}
	return nil
}

func (state State) validateMembershipChanges(
	changes Changes,
) (pendingMembershipChanges, error) {
	pending := pendingMembershipChanges{
		devices:       make(map[domain.DeviceID]device.Device, len(changes.Devices)),
		auditCounters: make(map[domain.DeviceID]auditcounter.Counter, len(changes.AuditCounters)),
	}
	if len(changes.Devices) > 1 {
		return pending, invalidState("device change set contains more than one row")
	}
	if len(changes.VoterSet) > 1 {
		return pending, invalidState("voter-set change set contains more than one row")
	}
	if len(changes.CredentialAuthority) > 1 {
		return pending, invalidState(
			"credential-authority change set contains more than one row",
		)
	}
	if len(changes.VoterSet) != 0 && len(changes.CredentialAuthority) != 0 {
		return pending, invalidState(
			"voter target and credential authority cannot change together",
		)
	}

	for _, next := range changes.Devices {
		if err := next.Validate(); err != nil {
			return pending, invalidState("device change %q: %v", next.ID, err)
		}
		if _, duplicate := pending.devices[next.ID]; duplicate {
			return pending, invalidState("duplicate device change %q", next.ID)
		}
		current, exists := state.devices[next.ID]
		if !exists {
			if err := device.ValidateTransition(
				device.OperationAdmission,
				nil,
				next,
			); err != nil {
				return pending, invalidState(
					"device admission %q: %v",
					next.ID,
					err,
				)
			}
		} else {
			operation, valid := deviceMutationOperation(current, next)
			if !valid {
				return pending, invalidState(
					"device change %q is not an ordinary membership transition",
					next.ID,
				)
			}
			pending.deviceOperation = operation
			pending.hasDeviceOperation = true
		}
		next.IdentityPublicKey = bytes.Clone(next.IdentityPublicKey)
		pending.devices[next.ID] = next
	}

	auditCountIncrements := 0
	for _, next := range changes.AuditCounters {
		if err := next.Validate(); err != nil {
			return pending, invalidState(
				"audit-counter change %q: %v",
				next.DeviceID,
				err,
			)
		}
		if _, duplicate := pending.auditCounters[next.DeviceID]; duplicate {
			return pending, invalidState(
				"duplicate audit-counter change %q",
				next.DeviceID,
			)
		}
		current, exists := state.auditCounters[next.DeviceID]
		if !exists {
			if _, admitted := pending.devices[next.DeviceID]; !admitted ||
				next.CredentialEpoch != 0 ||
				next.AcceptedCount != 0 {
				return pending, invalidState(
					"new audit counter %q is not an admission baseline",
					next.DeviceID,
				)
			}
		} else {
			if !validAuditCounterMutation(current, next) {
				return pending, invalidState(
					"audit counter %q has an invalid transition",
					next.DeviceID,
				)
			}
			if next.CredentialEpoch == current.CredentialEpoch {
				auditCountIncrements++
			}
		}
		pending.auditCounters[next.DeviceID] = next
	}
	if auditCountIncrements != 0 &&
		(auditCountIncrements != 1 ||
			hasNonAuditCounterDomainChanges(changes)) {
		return pending, invalidState(
			"audit count increment must be the event's sole domain mutation",
		)
	}
	for id := range pending.devices {
		if _, existed := state.devices[id]; existed {
			continue
		}
		if _, exists := pending.auditCounters[id]; !exists {
			return pending, invalidState(
				"device admission %q omits its audit counter",
				id,
			)
		}
	}

	effectiveVoterSet := state.voterSet
	if pending.hasDeviceOperation &&
		pending.deviceOperation == device.OperationRevocation {
		var revokedID domain.DeviceID
		for id := range pending.devices {
			revokedID = id
		}
		targetRevocation := state.voterSet.Contains(revokedID)
		if targetRevocation != (len(changes.VoterSet) == 1) {
			return pending, invalidState(
				"device revocation has inconsistent voter-target changes",
			)
		}
	}
	if len(changes.VoterSet) == 1 {
		next := changes.VoterSet[0]
		operation := voterset.OperationChange
		if len(pending.devices) != 0 {
			if !pending.hasDeviceOperation ||
				pending.deviceOperation != device.OperationRevocation {
				return pending, invalidState(
					"voter-target change accompanies a non-revocation device change",
				)
			}
			operation = voterset.OperationTargetVoterRevocation
		}
		if err := voterset.ValidateTransition(
			operation,
			state.voterSet,
			next,
		); err != nil {
			return pending, invalidState("voter-set change: %v", err)
		}
		pending.voterSet = &next
		effectiveVoterSet = next
	}

	effectiveAuthority := state.credentialAuthority
	if len(changes.CredentialAuthority) == 1 {
		next := changes.CredentialAuthority[0].Clone()
		if err := credentialauthority.ValidateTransition(
			credentialauthority.OperationActivate,
			state.credentialAuthority,
			next,
		); err != nil {
			return pending, invalidState(
				"credential-authority change: %v",
				err,
			)
		}
		if next.VoterSetVersion != effectiveVoterSet.VoterSetVersion ||
			!sameDeviceIDs(
				next.VoterDeviceIDs,
				effectiveVoterSet.VoterDeviceIDs(),
			) {
			return pending, invalidState(
				"credential authority does not activate the current voter target",
			)
		}
		pending.credentialAuthority = &next
		effectiveAuthority = next
	}

	effectiveDevices := make(
		map[domain.DeviceID]device.Device,
		len(state.devices)+len(pending.devices),
	)
	for id, member := range state.devices {
		effectiveDevices[id] = member
	}
	for id, member := range pending.devices {
		effectiveDevices[id] = member
	}
	effectiveCounters := make(
		map[domain.DeviceID]auditcounter.Counter,
		len(state.auditCounters)+len(pending.auditCounters),
	)
	for id, counter := range state.auditCounters {
		effectiveCounters[id] = counter
	}
	for id, counter := range pending.auditCounters {
		effectiveCounters[id] = counter
	}
	if err := state.validateMembershipTopology(
		effectiveDevices,
		effectiveCounters,
		effectiveVoterSet,
		effectiveAuthority,
	); err != nil {
		return pending, err
	}
	return pending, nil
}

func hasNonAuditCounterDomainChanges(changes Changes) bool {
	return len(changes.Tasks) != 0 ||
		len(changes.PlanRevisions) != 0 ||
		len(changes.PlanCurrent) != 0 ||
		len(changes.MemoryRecords) != 0 ||
		len(changes.Leases) != 0 ||
		len(changes.Devices) != 0 ||
		len(changes.VoterSet) != 0 ||
		len(changes.CredentialAuthority) != 0 ||
		len(changes.AgentSessions) != 0 ||
		len(changes.CanonicalRefs) != 0 ||
		len(changes.CredentialAuthorizations) != 0 ||
		len(changes.Publications) != 0 ||
		len(changes.ControlFileProposals) != 0 ||
		len(changes.MergeConflicts) != 0 ||
		len(changes.SessionPolicy) != 0
}

func (state State) validateMembershipTopology(
	devices map[domain.DeviceID]device.Device,
	counters map[domain.DeviceID]auditcounter.Counter,
	target voterset.Set,
	authority credentialauthority.Authority,
) error {
	if err := target.Validate(); err != nil {
		return invalidState("voter set: %v", err)
	}
	if target.SessionID != state.sessionID {
		return invalidState("voter-set row has wrong session")
	}
	if err := authority.Validate(); err != nil {
		return invalidState("credential authority: %v", err)
	}
	if authority.SessionID != state.sessionID {
		return invalidState("credential-authority row has wrong session")
	}
	if err := validateCanonicalAuthorityProofs(authority); err != nil {
		return err
	}
	if authority.ActivationSource == credentialauthority.ActivationGenesis &&
		authority.VoterSetVersion != 1 {
		return invalidState("genesis credential authority must be version 1")
	}
	if authority.VoterSetVersion > target.VoterSetVersion {
		return invalidState(
			"credential authority is ahead of the voter target",
		)
	}
	if authority.VoterSetVersion == target.VoterSetVersion &&
		!sameDeviceIDs(
			authority.VoterDeviceIDs,
			target.VoterDeviceIDs(),
		) {
		return invalidState(
			"equal-version voter target and credential authority disagree",
		)
	}

	activeOwners := 0
	for id, member := range devices {
		if id != member.ID {
			return invalidState("device map key does not match row")
		}
		if err := member.Validate(); err != nil {
			return invalidState("device %q: %v", id, err)
		}
		counter, exists := counters[id]
		if !exists || counter.DeviceID != id {
			return invalidState("device %q has no matching audit counter", id)
		}
		if member.Status == device.StatusActive &&
			member.Role == device.RoleOwner {
			activeOwners++
		}
	}
	if len(counters) != len(devices) {
		return invalidState("device and audit-counter sets disagree")
	}
	for id, counter := range counters {
		if id != counter.DeviceID {
			return invalidState("audit-counter map key does not match row")
		}
		if err := counter.Validate(); err != nil {
			return invalidState("audit counter %q: %v", id, err)
		}
		if _, exists := devices[id]; !exists {
			return invalidState(
				"audit counter references missing device %q",
				id,
			)
		}
	}
	if activeOwners == 0 {
		return invalidState("membership has no active owner")
	}

	for _, id := range target.VoterDeviceIDs() {
		member, exists := devices[id]
		if !exists || member.Status != device.StatusActive {
			return invalidState(
				"voter target contains non-active device %q",
				id,
			)
		}
	}
	activeAuthorityMembers := 0
	for _, id := range authority.VoterDeviceIDs {
		member, exists := devices[id]
		if !exists {
			return invalidState(
				"credential authority contains missing device %q",
				id,
			)
		}
		if member.Status == device.StatusActive {
			activeAuthorityMembers++
		}
	}
	requiredAuthorityMajority := len(authority.VoterDeviceIDs)/2 + 1
	if activeAuthorityMembers < requiredAuthorityMajority {
		return invalidState(
			"credential authority has %d active members, needs %d",
			activeAuthorityMembers,
			requiredAuthorityMajority,
		)
	}
	return nil
}

func deviceMutationOperation(
	current,
	next device.Device,
) (device.Operation, bool) {
	operations := [...]device.Operation{
		device.OperationReadmission,
		device.OperationVersionReport,
		device.OperationRoleChange,
		device.OperationOwnerRecovery,
		device.OperationRevocation,
	}
	for _, operation := range operations {
		if device.ValidateTransition(operation, &current, next) == nil {
			return operation, true
		}
	}
	return "", false
}

func validAuditCounterMutation(
	current auditcounter.Counter,
	next auditcounter.Counter,
) bool {
	if current.DeviceID != next.DeviceID {
		return false
	}
	if next.CredentialEpoch == current.CredentialEpoch {
		return current.AcceptedCount < auditcounter.MaxAcceptedCount &&
			next.AcceptedCount == current.AcceptedCount+1
	}
	return current.CredentialEpoch < domain.MaxSafeInteger &&
		next.CredentialEpoch == current.CredentialEpoch+1 &&
		next.AcceptedCount == 0
}

func validateCanonicalAuthorityProofs(
	authority credentialauthority.Authority,
) error {
	for index, proof := range authority.ActivationProofs {
		canonical, err := codec.CanonicalizeSignedObject(proof.CanonicalJSON)
		if err != nil {
			return invalidState(
				"credential-authority proof %d: %v",
				index,
				err,
			)
		}
		if !bytes.Equal(canonical, proof.CanonicalJSON) {
			return invalidState(
				"credential-authority proof %d is not canonical",
				index,
			)
		}
	}
	return nil
}

func sameDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
