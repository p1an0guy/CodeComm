package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func reduceMembershipRoleChanged(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"device_id", "role"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	payloadDeviceID, deviceOK := decodeValue[string](payload, "device_id")
	roleText, roleOK := decodeValue[string](payload, "role")
	role := device.Role(roleText)
	payloadSubjectID := domain.DeviceID(payloadDeviceID)
	if !deviceOK || !payloadSubjectID.Valid() ||
		!roleOK || !role.Valid() {
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
	if current.Status != device.StatusActive {
		return context.reject(CodeMembershipSubjectNotActive), nil
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}

	next := current
	next.Role = role
	next.EntityVersion++
	if err := device.ValidateTransition(
		device.OperationRoleChange,
		&current,
		next,
	); err != nil {
		return context.reject(CodeInvalidMembershipTransition), nil
	}
	if activeOwnerCount(context.state.devices, &next) == 0 {
		return context.reject(CodeLastActiveOwner), nil
	}
	return context.acceptMembership(
		[]device.Device{next},
		nil,
		nil,
		nil,
		deviceMembershipOverride(subjectID),
	)
}
