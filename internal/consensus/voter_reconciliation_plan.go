package consensus

import (
	"sort"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

type voterReconciliationActionKind uint8

const (
	voterReconciliationInvalid voterReconciliationActionKind = iota
	voterReconciliationStalled
	voterReconciliationAddNonvoter
	voterReconciliationProveNonvoter
	voterReconciliationPromoteVoter
	voterReconciliationActivateAuthority
	voterReconciliationTransferLeadership
	voterReconciliationRemoveVoter
	voterReconciliationRemoveNonvoter
	voterReconciliationStable
)

type voterReconciliationReason uint8

const (
	voterReconciliationNoReason voterReconciliationReason = iota
	voterReconciliationInvalidTarget
	voterReconciliationInvalidAuthority
	voterReconciliationInvalidConfiguration
	voterReconciliationInvalidLeader
	voterReconciliationInvalidMembers
	voterReconciliationInvalidReachability
	voterReconciliationInvalidEligibility
	voterReconciliationTargetUnavailable
	voterReconciliationNoTransferTarget
	voterReconciliationNoRemovableVoter
)

type voterReconciliationInput struct {
	target        voterset.Set
	authority     credentialauthority.Authority
	configuration committedRaftConfiguration
	localLeaderID domain.DeviceID
	memberStatus  map[domain.DeviceID]device.Status
	reachable     map[domain.DeviceID]struct{}
	eligible      map[domain.DeviceID]struct{}
}

type voterReconciliationPlan struct {
	action             voterReconciliationActionKind
	deviceID           domain.DeviceID
	configurationIndex uint64
	reason             voterReconciliationReason
}

func planVoterReconciliation(
	input voterReconciliationInput,
) voterReconciliationPlan {
	plan, state, valid := validateVoterReconciliationInput(input)
	if !valid {
		return plan
	}

	for _, deviceID := range state.targetIDs {
		if _, exists := state.servers[deviceID]; !exists {
			return state.action(voterReconciliationAddNonvoter, deviceID)
		}
	}
	var unavailableTarget domain.DeviceID
	for _, deviceID := range state.targetIDs {
		server := state.servers[deviceID]
		if server.Suffrage != raft.Nonvoter {
			continue
		}
		if !containsDevice(input.reachable, deviceID) {
			if !unavailableTarget.Valid() {
				unavailableTarget = deviceID
			}
			continue
		}
		if containsDevice(input.eligible, deviceID) {
			return state.action(voterReconciliationPromoteVoter, deviceID)
		}
		return state.action(voterReconciliationProveNonvoter, deviceID)
	}
	if unavailableTarget.Valid() {
		return state.stalled(
			voterReconciliationTargetUnavailable,
			unavailableTarget,
		)
	}

	if !state.authorityActivated {
		return state.action(voterReconciliationActivateAuthority, "")
	}
	if !input.target.Contains(input.localLeaderID) {
		for _, deviceID := range state.targetIDs {
			if containsDevice(input.reachable, deviceID) &&
				containsDevice(input.eligible, deviceID) {
				return state.action(
					voterReconciliationTransferLeadership,
					deviceID,
				)
			}
		}
		return state.stalled(voterReconciliationNoTransferTarget, "")
	}

	extraVoters := state.extraServers(input.target, raft.Voter)
	sort.Slice(extraVoters, func(left, right int) bool {
		leftStatus := input.memberStatus[extraVoters[left]]
		rightStatus := input.memberStatus[extraVoters[right]]
		leftRevoked := leftStatus == device.StatusRevoked
		rightRevoked := rightStatus == device.StatusRevoked
		if leftRevoked != rightRevoked {
			return leftRevoked
		}
		leftReachable := containsDevice(input.reachable, extraVoters[left])
		rightReachable := containsDevice(input.reachable, extraVoters[right])
		if leftReachable != rightReachable {
			return !leftReachable
		}
		return extraVoters[left] < extraVoters[right]
	})
	for _, deviceID := range extraVoters {
		if deviceID != input.localLeaderID &&
			state.postRemovalHasReachableActiveQuorum(input, deviceID) {
			return state.action(voterReconciliationRemoveVoter, deviceID)
		}
	}
	if len(extraVoters) != 0 {
		return state.stalled(voterReconciliationNoRemovableVoter, "")
	}

	extraNonvoters := state.extraServers(input.target, raft.Nonvoter)
	if len(extraNonvoters) != 0 {
		sort.Slice(extraNonvoters, func(left, right int) bool {
			return extraNonvoters[left] < extraNonvoters[right]
		})
		return state.action(
			voterReconciliationRemoveNonvoter,
			extraNonvoters[0],
		)
	}
	return state.action(voterReconciliationStable, "")
}

type voterReconciliationState struct {
	configurationIndex uint64
	targetIDs          []domain.DeviceID
	servers            map[domain.DeviceID]raft.Server
	authorityActivated bool
}

func validateVoterReconciliationInput(
	input voterReconciliationInput,
) (voterReconciliationPlan, voterReconciliationState, bool) {
	invalid := func(reason voterReconciliationReason) (
		voterReconciliationPlan,
		voterReconciliationState,
		bool,
	) {
		return voterReconciliationPlan{
			action: voterReconciliationInvalid,
			reason: reason,
		}, voterReconciliationState{}, false
	}
	if input.target.Validate() != nil {
		return invalid(voterReconciliationInvalidTarget)
	}
	if input.authority.Validate() != nil ||
		input.authority.SessionID != input.target.SessionID ||
		input.authority.VoterSetVersion > input.target.VoterSetVersion {
		return invalid(voterReconciliationInvalidAuthority)
	}
	authorityActivated := input.authority.VoterSetVersion ==
		input.target.VoterSetVersion
	if authorityActivated &&
		!sameDeviceIDs(
			input.authority.VoterDeviceIDs,
			input.target.VoterDeviceIDs(),
		) {
		return invalid(voterReconciliationInvalidAuthority)
	}
	if input.configuration.Index < 1 ||
		!domain.ValidUnsignedInteger(input.configuration.Index) ||
		validateDeviceAddressedSnapshotConfiguration(
			input.configuration.Configuration,
		) != nil {
		return invalid(voterReconciliationInvalidConfiguration)
	}

	servers := make(
		map[domain.DeviceID]raft.Server,
		len(input.configuration.Configuration.Servers),
	)
	leaderIsVoter := false
	for _, server := range input.configuration.Configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		servers[deviceID] = server
		leaderIsVoter = leaderIsVoter ||
			deviceID == input.localLeaderID && server.Suffrage == raft.Voter
	}
	if !input.localLeaderID.Valid() ||
		!leaderIsVoter ||
		!containsDevice(input.reachable, input.localLeaderID) {
		return invalid(voterReconciliationInvalidLeader)
	}
	for deviceID, status := range input.memberStatus {
		if !deviceID.Valid() || !status.Valid() {
			return invalid(voterReconciliationInvalidMembers)
		}
	}
	for deviceID := range servers {
		if _, exists := input.memberStatus[deviceID]; !exists {
			return invalid(voterReconciliationInvalidMembers)
		}
	}
	for _, deviceID := range input.target.VoterDeviceIDs() {
		if input.memberStatus[deviceID] != device.StatusActive {
			return invalid(voterReconciliationInvalidMembers)
		}
	}
	for _, deviceID := range input.authority.VoterDeviceIDs {
		if _, exists := input.memberStatus[deviceID]; !exists {
			return invalid(voterReconciliationInvalidMembers)
		}
	}
	if input.memberStatus[input.localLeaderID] != device.StatusActive {
		return invalid(voterReconciliationInvalidLeader)
	}
	for deviceID := range input.reachable {
		if !deviceID.Valid() {
			return invalid(voterReconciliationInvalidReachability)
		}
		if _, exists := input.memberStatus[deviceID]; !exists {
			return invalid(voterReconciliationInvalidReachability)
		}
	}
	for deviceID := range input.eligible {
		server, configured := servers[deviceID]
		if !deviceID.Valid() ||
			!input.target.Contains(deviceID) ||
			input.memberStatus[deviceID] != device.StatusActive ||
			!configured ||
			server.Suffrage != raft.Voter &&
				server.Suffrage != raft.Nonvoter {
			return invalid(voterReconciliationInvalidEligibility)
		}
	}
	if authorityActivated {
		for _, deviceID := range input.target.VoterDeviceIDs() {
			server, exists := servers[deviceID]
			if !exists || server.Suffrage != raft.Voter {
				return invalid(voterReconciliationInvalidAuthority)
			}
		}
	}
	return voterReconciliationPlan{}, voterReconciliationState{
		configurationIndex: input.configuration.Index,
		targetIDs:          input.target.VoterDeviceIDs(),
		servers:            servers,
		authorityActivated: authorityActivated,
	}, true
}

func (state voterReconciliationState) action(
	action voterReconciliationActionKind,
	deviceID domain.DeviceID,
) voterReconciliationPlan {
	return voterReconciliationPlan{
		action:             action,
		deviceID:           deviceID,
		configurationIndex: state.configurationIndex,
	}
}

func (state voterReconciliationState) stalled(
	reason voterReconciliationReason,
	deviceID domain.DeviceID,
) voterReconciliationPlan {
	plan := state.action(voterReconciliationStalled, deviceID)
	plan.reason = reason
	return plan
}

func (state voterReconciliationState) extraServers(
	target voterset.Set,
	suffrage raft.ServerSuffrage,
) []domain.DeviceID {
	result := make([]domain.DeviceID, 0, len(state.servers))
	for deviceID, server := range state.servers {
		if server.Suffrage == suffrage && !target.Contains(deviceID) {
			result = append(result, deviceID)
		}
	}
	return result
}

func (state voterReconciliationState) postRemovalHasReachableActiveQuorum(
	input voterReconciliationInput,
	removed domain.DeviceID,
) bool {
	voterCount := 0
	reachableActive := 0
	for deviceID, server := range state.servers {
		if server.Suffrage != raft.Voter || deviceID == removed {
			continue
		}
		voterCount++
		if input.memberStatus[deviceID] == device.StatusActive &&
			containsDevice(input.reachable, deviceID) {
			reachableActive++
		}
	}
	return voterCount > 0 && reachableActive >= voterCount/2+1
}

func containsDevice(
	set map[domain.DeviceID]struct{},
	deviceID domain.DeviceID,
) bool {
	_, exists := set[deviceID]
	return exists
}
