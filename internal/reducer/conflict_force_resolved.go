package reducer

import "github.com/ijonahch/codecomm/internal/domain/conflict"

func reduceWorkspaceConflictForceResolved(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"reason"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	reason, ok := decodeValue[string](payload, "reason")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	current, outcome, done, err := loadMutableConflict(context)
	if err != nil || done {
		return outcome, err
	}

	next := cloneConflict(current)
	next.Status = conflict.StatusResolved
	next.ResolutionKind = conflict.ResolutionKindForced
	next.ForceReason = reason
	next.ResolvedByDeviceID = context.device.ID
	next.EntityVersion++
	if err := conflict.ValidateTransition(
		conflict.OperationForceResolve,
		&current,
		next,
	); err != nil {
		if next.Validate() != nil {
			return context.reject(CodeInvalidPayload), nil
		}
		return context.reject(CodeInvalidConflictTransition), nil
	}
	return context.acceptConflict(
		&next,
		conflictOperatorOverride(current.ID),
	)
}
