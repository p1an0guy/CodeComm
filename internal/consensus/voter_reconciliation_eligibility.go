package consensus

import (
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

type voterEligibilityKind uint8

const (
	voterEligibilityExisting voterEligibilityKind = iota + 1
	voterEligibilityStagingProof
)

type voterEligibilityEvidence struct {
	kind                        voterEligibilityKind
	deviceID                    domain.DeviceID
	targetVoterSetVersion       uint64
	stagedConfigurationIndex    uint64
	stagingCheckpointApplyProof stagingApplyProof
}

type voterEligibilitySet map[domain.DeviceID]voterEligibilityEvidence

func initialVoterEligibility(
	state decodedState,
	configuration raft.Configuration,
) voterEligibilitySet {
	result := make(voterEligibilitySet)
	for _, server := range configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		if server.Suffrage != raft.Voter ||
			!state.VoterSet.Contains(deviceID) {
			continue
		}
		result[deviceID] = voterEligibilityEvidence{
			kind:                  voterEligibilityExisting,
			deviceID:              deviceID,
			targetVoterSetVersion: state.VoterSet.VoterSetVersion,
		}
	}
	return result
}

func newStagingVoterEligibility(
	state decodedState,
	configuration *committedRaftConfiguration,
	target domain.DeviceID,
	proof stagingApplyProof,
) (voterEligibilityEvidence, error) {
	evidence := voterEligibilityEvidence{
		kind:                        voterEligibilityStagingProof,
		deviceID:                    target,
		targetVoterSetVersion:       state.VoterSet.VoterSetVersion,
		stagedConfigurationIndex:    configurationIndex(configuration),
		stagingCheckpointApplyProof: proof,
	}
	if !evidence.validFor(state, configuration) ||
		proof.expectation.record.AuthorityVoterSetVersion !=
			state.CredentialAuthority.VoterSetVersion ||
		!configurationHasDeviceSuffrage(
			configuration.Configuration,
			target,
			raft.Nonvoter,
		) {
		return voterEligibilityEvidence{},
			ErrVoterReconciliationInvalid
	}
	return evidence, nil
}

func (set voterEligibilitySet) plannerSet(
	state decodedState,
	configuration *committedRaftConfiguration,
) map[domain.DeviceID]struct{} {
	result := make(map[domain.DeviceID]struct{}, len(set))
	for deviceID, evidence := range set {
		if deviceID == evidence.deviceID &&
			evidence.validFor(state, configuration) {
			result[deviceID] = struct{}{}
		}
	}
	return result
}

func (set voterEligibilitySet) clone() voterEligibilitySet {
	result := make(voterEligibilitySet, len(set))
	for deviceID, evidence := range set {
		result[deviceID] = evidence
	}
	return result
}

func (evidence voterEligibilityEvidence) validFor(
	state decodedState,
	configuration *committedRaftConfiguration,
) bool {
	if configuration == nil ||
		!evidence.deviceID.Valid() ||
		evidence.targetVoterSetVersion !=
			state.VoterSet.VoterSetVersion ||
		!state.VoterSet.Contains(evidence.deviceID) {
		return false
	}
	member, exists := state.Admission.Member(evidence.deviceID)
	if !exists || member.Status != device.StatusActive {
		return false
	}
	server, exists := configurationServer(
		configuration.Configuration,
		evidence.deviceID,
	)
	if !exists {
		return false
	}

	switch evidence.kind {
	case voterEligibilityExisting:
		return evidence.stagedConfigurationIndex == 0 &&
			evidence.stagingCheckpointApplyProof.expectation.
				targetDeviceID == "" &&
			evidence.stagingCheckpointApplyProof.appliedLogIndex == 0 &&
			server.Suffrage == raft.Voter
	case voterEligibilityStagingProof:
		proof := evidence.stagingCheckpointApplyProof
		record := proof.expectation.record
		if evidence.stagedConfigurationIndex < 1 ||
			!domain.ValidUnsignedInteger(
				evidence.stagedConfigurationIndex,
			) ||
			proof.expectation.validate() != nil ||
			proof.expectation.targetDeviceID != evidence.deviceID ||
			proof.appliedLogIndex != record.CoveredAppliedLogIndex+1 ||
			record.SessionID != state.VoterSet.SessionID ||
			record.WorkspaceID != state.workspaceID ||
			record.RecoveryGeneration != state.recoveryGeneration ||
			record.AuthorityVoterSetVersion >
				evidence.targetVoterSetVersion ||
			record.CoveredAppliedLogIndex <
				evidence.stagedConfigurationIndex {
			return false
		}
		switch server.Suffrage {
		case raft.Voter:
			return true
		case raft.Nonvoter:
			return record.CoveredAppliedLogIndex >= configuration.Index
		default:
			return false
		}
	default:
		return false
	}
}

func configurationIndex(
	configuration *committedRaftConfiguration,
) uint64 {
	if configuration == nil {
		return 0
	}
	return configuration.Index
}

func configurationServer(
	configuration raft.Configuration,
	deviceID domain.DeviceID,
) (raft.Server, bool) {
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(deviceID) {
			return server, true
		}
	}
	return raft.Server{}, false
}

func configurationHasDeviceSuffrage(
	configuration raft.Configuration,
	deviceID domain.DeviceID,
	suffrage raft.ServerSuffrage,
) bool {
	server, exists := configurationServer(configuration, deviceID)
	return exists &&
		server.Address == raft.ServerAddress(deviceID) &&
		server.Suffrage == suffrage
}
