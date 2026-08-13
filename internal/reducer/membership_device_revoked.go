package reducer

import (
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const maxMembershipReasonBytes = 1024

func reduceMembershipDeviceRevoked(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"device_id",
			"reason",
			"voter_set",
			"expected_voter_set_version",
		},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	payloadDeviceID, deviceOK := decodeValue[string](payload, "device_id")
	reason, reasonOK := decodeValue[string](payload, "reason")
	voterIDs, votersOK := decodeDeviceIDs(payload, "voter_set")
	expectedVoterVersion, voterVersionOK := decodeValue[uint64](
		payload,
		"expected_voter_set_version",
	)
	payloadSubjectID := domain.DeviceID(payloadDeviceID)
	if !deviceOK || !payloadSubjectID.Valid() || !reasonOK ||
		len(reason) < 1 || len(reason) > maxMembershipReasonBytes ||
		!utf8.ValidString(reason) ||
		!votersOK || !voterVersionOK {
		return context.reject(CodeInvalidPayload), nil
	}
	subjectID := context.subjectDeviceID()
	if payloadSubjectID != subjectID {
		return context.reject(CodeMembershipSubjectMismatch), nil
	}
	current, exists := context.state.devices[subjectID]
	if !exists {
		return context.reject(CodeMembershipSubjectNotFound), nil
	}
	if current.Status != device.StatusActive &&
		current.Status != device.StatusRequiresReadmission {
		return context.reject(CodeMembershipSubjectNotActive), nil
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	currentTarget := context.state.voterSet
	if expectedVoterVersion != currentTarget.VoterSetVersion {
		return context.reject(CodeVoterSetVersionMismatch), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}

	nextDevice := current
	nextDevice.Status = device.StatusRevoked
	nextDevice.EntityVersion++
	if err := device.ValidateTransition(
		device.OperationRevocation,
		&current,
		nextDevice,
	); err != nil {
		return context.reject(CodeInvalidMembershipTransition), nil
	}
	if activeOwnerCount(context.state.devices, &nextDevice) == 0 {
		return context.reject(CodeLastActiveOwner), nil
	}

	var targetChanges []voterset.Set
	if currentTarget.Contains(subjectID) {
		if len(currentTarget.VoterDeviceIDs()) == 1 {
			return context.reject(CodeSoleVoterRevocation), nil
		}
		if currentTarget.VoterSetVersion == domain.MaxSafeInteger {
			return context.reject(CodeVoterSetVersionExhausted), nil
		}
		nextTarget, err := voterset.New(
			context.state.sessionID,
			voterIDs,
			currentTarget.VoterSetVersion+1,
		)
		if err != nil ||
			nextTarget.Contains(subjectID) ||
			voterset.ValidateTransition(
				voterset.OperationTargetVoterRevocation,
				currentTarget,
				nextTarget,
			) != nil {
			return context.reject(CodeInvalidVoterSet), nil
		}
		for _, id := range voterIDs {
			member, exists := context.state.devices[id]
			if !exists || member.Status != device.StatusActive {
				return context.reject(CodeVoterTargetNotActive), nil
			}
		}
		targetChanges = []voterset.Set{nextTarget}
	} else {
		sameTarget, err := voterset.New(
			context.state.sessionID,
			voterIDs,
			currentTarget.VoterSetVersion,
		)
		if err != nil ||
			voterset.ValidateTransition(
				voterset.OperationNonvoterRevocation,
				currentTarget,
				sameTarget,
			) != nil {
			return context.reject(CodeInvalidVoterSet), nil
		}
	}
	if activeAuthorityCountAfter(
		context.state,
		nextDevice,
	) < len(context.state.credentialAuthority.VoterDeviceIDs)/2+1 {
		return context.reject(CodeCredentialAuthorityQuorumLost), nil
	}
	return context.acceptMembership(
		[]device.Device{nextDevice},
		nil,
		targetChanges,
		nil,
		deviceMembershipOverride(subjectID),
	)
}

func activeAuthorityCountAfter(state State, replacement device.Device) int {
	count := 0
	for _, id := range state.credentialAuthority.VoterDeviceIDs {
		member, exists := state.devices[id]
		if !exists {
			continue
		}
		if id == replacement.ID {
			member = replacement
		}
		if member.Status == device.StatusActive {
			count++
		}
	}
	return count
}
