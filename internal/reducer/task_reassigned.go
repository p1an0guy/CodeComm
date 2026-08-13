package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func reduceTaskReassigned(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"to_device_id"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	targetText, ok := decodeValue[string](payload, "to_device_id")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	targetID := domain.DeviceID(targetText)
	if !targetID.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}

	current, outcome, done, err := loadMutableTask(context)
	if err != nil || done {
		return outcome, err
	}
	target, exists := context.state.devices[targetID]
	if !exists {
		return context.reject(CodeReassignmentTargetNotActive), nil
	}
	if target.ID != targetID {
		return Outcome{}, invalidState("device map key does not match reassignment target")
	}
	if err := target.Validate(); err != nil {
		return Outcome{}, invalidState("reassignment target %q: %v", targetID, err)
	}
	if target.Status != device.StatusActive {
		return context.reject(CodeReassignmentTargetNotActive), nil
	}
	if err := task.ValidateTransition(
		task.OperationReassign,
		current.State,
		task.StateReady,
	); err != nil {
		return context.reject(CodeInvalidTaskTransition), nil
	}

	next := cloneTask(current)
	next.State = task.StateReady
	next.StateReason = nil
	next.OwnerDeviceID = ""
	next.OwnerAgentSessionID = ""
	next.IntendedDeviceID = targetID
	next.LastReleaseReason = task.ReleaseForced
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	return context.acceptTask(next, operatorOverride(next.ID))
}
