package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceAgentSessionStateChanged(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"to_state"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	stateText, ok := decodeValue[string](payload, "to_state")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	toState := agentsession.State(stateText)
	if !toState.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}

	current, outcome, done, err := loadMutableAgentSession(context)
	if err != nil || done {
		return outcome, err
	}
	next := cloneAgentSession(current)
	next.State = toState
	next.ResumeState = agentsession.StateAbsent
	next.EndReason = agentsession.EndReasonAbsent

	var operation agentsession.Operation
	switch context.proposal.Origin.ActorType() {
	case event.ActorAgent:
		if context.agentSession == nil ||
			context.agentSession.ID != current.ID {
			return context.reject(CodeAgentSessionBindingMismatch), nil
		}
		operation = agentsession.OperationAgentStatusChange
	case event.ActorDaemon:
		if context.device.ID != current.DeviceID {
			return context.reject(CodeAgentSessionBindingMismatch), nil
		}
		if toState == agentsession.StateDisconnected {
			operation = agentsession.OperationDaemonDisconnect
			next.ResumeState = current.State
		} else {
			operation = agentsession.OperationDaemonResume
		}
	default:
		return context.reject(CodeActorNotAllowed), nil
	}
	if err := agentsession.ValidateTransition(
		operation,
		current.Lifecycle(),
		next.Lifecycle(),
	); err != nil {
		return context.reject(CodeInvalidAgentSessionTransition), nil
	}
	next.EntityVersion++
	return context.acceptAgentSession(next, nil, nil)
}
