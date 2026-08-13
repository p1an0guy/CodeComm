package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceLeaseReleased(context reductionContext) (Outcome, error) {
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
	reason := lease.ReleaseReason(reasonText)
	if reason != lease.ReleaseVoluntary &&
		reason != lease.ReleaseForced &&
		reason != lease.ReleaseExpired {
		return context.reject(CodeInvalidReleaseReason), nil
	}

	current, outcome, done, err := loadMutableLease(context)
	if err != nil || done {
		return outcome, err
	}
	var operation lease.Operation
	var audit *AuditDirective
	switch reason {
	case lease.ReleaseVoluntary:
		if context.proposal.Origin.ActorType() != event.ActorAgent {
			return context.reject(CodeReleaseActorMismatch), nil
		}
		if !leaseHeldByOrigin(current, context) {
			return context.reject(CodeLeaseHolderRequired), nil
		}
		operation = lease.OperationReleaseVoluntary
	case lease.ReleaseForced:
		if context.proposal.Origin.ActorType() != event.ActorHuman {
			return context.reject(CodeReleaseActorMismatch), nil
		}
		if context.device.Role != device.RoleOwner &&
			current.HolderDeviceID != context.device.ID {
			return context.reject(CodeReleaseNotAuthorized), nil
		}
		operation = lease.OperationReleaseForced
		audit = leaseOperatorOverride(current.ID)
	case lease.ReleaseExpired:
		if context.proposal.Origin.ActorType() != event.ActorDaemon {
			return context.reject(CodeReleaseActorMismatch), nil
		}
		// Leader identity is consensus/ingress state, not reducer input. The
		// proposal boundary admits this daemon-originated reason only from the
		// current leader; replicas deterministically enforce actor, CAS, and
		// lifecycle here.
		operation = lease.OperationReleaseExpired
	}
	if err := lease.ValidateTransition(
		operation,
		current.Lifecycle(),
		lease.Lifecycle{
			Status:        lease.StatusReleased,
			ReleaseReason: reason,
		},
	); err != nil {
		return context.reject(CodeInvalidLeaseTransition), nil
	}

	next := current
	next.Status = lease.StatusReleased
	next.ReleaseReason = reason
	next.EntityVersion++
	return context.acceptLease(next, audit)
}
