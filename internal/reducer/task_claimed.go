package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func reduceTaskClaimed(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(context.proposal.Payload, nil, nil)
	if code != "" {
		return context.reject(code), nil
	}
	if len(payload) != 0 {
		return context.reject(CodeUnknownPayloadField), nil
	}

	current, outcome, done, err := loadMutableTask(context)
	if err != nil || done {
		return outcome, err
	}
	dependenciesDone, err := allDependenciesDone(context, current)
	if err != nil {
		return Outcome{}, err
	}
	if current.State != task.StateReady || !dependenciesDone {
		return context.reject(CodeTaskNotActionable), nil
	}
	if taskHasUnresolvedConflict(context, current.ID) {
		return context.reject(CodeTaskHasUnresolvedConflict), nil
	}
	if current.IntendedDeviceID != "" &&
		current.IntendedDeviceID != context.device.ID {
		return context.reject(CodeIntendedDeviceMismatch), nil
	}

	values, err := validatePolicy(context)
	if err != nil {
		return Outcome{}, err
	}
	agentClaims, deviceClaims, err := validateClaimIndexes(context)
	if err != nil {
		return Outcome{}, err
	}
	if int64(agentClaims) >= values.AgentClaimLimit {
		return context.reject(CodeAgentClaimLimitReached), nil
	}
	if int64(deviceClaims) >= values.DeviceClaimLimit {
		return context.reject(CodeDeviceClaimLimitReached), nil
	}
	if err := task.ValidateTransition(
		task.OperationClaim,
		current.State,
		task.StateClaimed,
	); err != nil {
		return context.reject(CodeInvalidTaskTransition), nil
	}

	next := cloneTask(current)
	next.State = task.StateClaimed
	next.StateReason = nil
	next.OwnerDeviceID = context.device.ID
	next.OwnerAgentSessionID = context.agentSession.ID
	next.IntendedDeviceID = ""
	next.LastReleaseReason = ""
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	return context.acceptTask(next, nil)
}
