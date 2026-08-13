package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceTaskReleased(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"release_reason"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	reasonText, ok := decodeValue[string](payload, "release_reason")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	reason := task.ReleaseReason(reasonText)
	if reason != task.ReleaseVoluntary && reason != task.ReleaseForced {
		return context.reject(CodeInvalidReleaseReason), nil
	}

	current, outcome, done, err := loadMutableTask(context)
	if err != nil || done {
		return outcome, err
	}
	var operation task.Operation
	var audit *AuditDirective
	switch reason {
	case task.ReleaseVoluntary:
		if context.proposal.Origin.ActorType() != event.ActorAgent {
			return context.reject(CodeReleaseActorMismatch), nil
		}
		if !heldByOrigin(current, context) {
			return context.reject(CodeTaskHolderRequired), nil
		}
		operation = task.OperationReleaseVoluntary
	case task.ReleaseForced:
		if context.proposal.Origin.ActorType() != event.ActorHuman {
			return context.reject(CodeReleaseActorMismatch), nil
		}
		if context.device.Role != device.RoleOwner &&
			current.OwnerDeviceID != context.device.ID &&
			current.IntendedDeviceID != context.device.ID {
			return context.reject(CodeReleaseNotAuthorized), nil
		}
		operation = task.OperationReleaseForced
		audit = operatorOverride(current.ID)
	}
	if err := task.ValidateTransition(
		operation,
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
	next.IntendedDeviceID = ""
	next.LastReleaseReason = reason
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	return context.acceptTask(next, audit)
}
