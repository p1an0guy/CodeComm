package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceAgentSessionEnded(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"end_reason"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	reasonText, ok := decodeValue[string](payload, "end_reason")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	reason := agentsession.EndReason(reasonText)
	if !reason.Valid() || reason == agentsession.EndReasonRecovery {
		return context.reject(CodeInvalidEndReason), nil
	}

	current, outcome, done, err := loadMutableAgentSession(context)
	if err != nil || done {
		return outcome, err
	}
	var operation agentsession.Operation
	switch context.proposal.Origin.ActorType() {
	case event.ActorAgent:
		if reason != agentsession.EndReasonClean {
			return context.reject(CodeEndActorMismatch), nil
		}
		if context.agentSession == nil ||
			context.agentSession.ID != current.ID {
			return context.reject(CodeAgentSessionBindingMismatch), nil
		}
		operation = agentsession.OperationCleanEnd
	case event.ActorDaemon:
		if reason == agentsession.EndReasonClean {
			return context.reject(CodeEndActorMismatch), nil
		}
		if context.device.ID != current.DeviceID {
			return context.reject(CodeAgentSessionBindingMismatch), nil
		}
		operation = agentsession.OperationDaemonEnd
	default:
		return context.reject(CodeActorNotAllowed), nil
	}

	next := cloneAgentSession(current)
	next.State = agentsession.StateEnded
	next.ResumeState = agentsession.StateAbsent
	next.EndReason = reason
	if err := agentsession.ValidateTransition(
		operation,
		current.Lifecycle(),
		next.Lifecycle(),
	); err != nil {
		return context.reject(CodeInvalidAgentSessionTransition), nil
	}
	tasks, leases, code, err := buildSessionEndCascade(context, current)
	if err != nil {
		return Outcome{}, err
	}
	if code != "" {
		return context.reject(code), nil
	}
	next.EntityVersion++
	return context.acceptAgentSession(next, tasks, leases)
}
