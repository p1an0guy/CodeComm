package reducer

import "github.com/ijonahch/codecomm/internal/domain/task"

func reduceTaskCancelled(context reductionContext) (Outcome, error) {
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
	if err := task.ValidateTransition(
		task.OperationCancel,
		current.State,
		task.StateCancelled,
	); err != nil {
		return context.reject(CodeInvalidTaskTransition), nil
	}

	next := cloneTask(current)
	next.State = task.StateCancelled
	next.StateReason = nil
	next.OwnerDeviceID = ""
	next.OwnerAgentSessionID = ""
	next.IntendedDeviceID = ""
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	return context.acceptTask(next, operatorOverride(next.ID))
}
