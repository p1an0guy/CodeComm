package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceTaskStateChanged(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"to_state"},
		[]string{"reason"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	stateText, ok := decodeValue[string](payload, "to_state")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	toState := task.State(stateText)
	reason, reasonPresent := decodeValue[string](payload, "reason")
	if _, supplied := payload["reason"]; supplied && !reasonPresent {
		return context.reject(CodeInvalidPayload), nil
	}
	if toState == task.StateBlocked {
		if !reasonPresent {
			return context.reject(CodeMissingPayloadField), nil
		}
	} else if reasonPresent {
		return context.reject(CodeInvalidPayload), nil
	}

	current, outcome, done, err := loadMutableTask(context)
	if err != nil || done {
		return outcome, err
	}
	switch context.proposal.Origin.ActorType() {
	case event.ActorAgent:
		if !heldByOrigin(current, context) {
			return context.reject(CodeTaskHolderRequired), nil
		}
	case event.ActorHuman:
		if !whollyUnowned(current) {
			return context.reject(CodeTaskMustBeUnowned), nil
		}
	default:
		return context.reject(CodeActorNotAllowed), nil
	}
	if err := task.ValidateTransition(
		task.OperationStateChange,
		current.State,
		toState,
	); err != nil {
		return context.reject(CodeInvalidTaskTransition), nil
	}
	if toState == task.StateDone &&
		taskHasUnresolvedConflict(context, current.ID) {
		return context.reject(CodeTaskHasUnresolvedConflict), nil
	}

	next := cloneTask(current)
	next.State = toState
	next.StateReason = nil
	if toState == task.StateBlocked {
		next.StateReason = &reason
	}
	if toState.Terminal() {
		next.OwnerDeviceID = ""
		next.OwnerAgentSessionID = ""
		next.IntendedDeviceID = ""
	}
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	return context.acceptTask(next, nil)
}
