package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

func reduceMembershipVoterSetChanged(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"voter_set"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	voterIDs, ok := decodeDeviceIDs(payload, "voter_set")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	entityText, _ := context.proposal.EntityID.Value()
	if domain.UUIDv7(entityText) != context.state.sessionID {
		return context.reject(CodeSessionBindingMismatch), nil
	}
	current := context.state.voterSet
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.VoterSetVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if current.VoterSetVersion == domain.MaxSafeInteger {
		return context.reject(CodeVoterSetVersionExhausted), nil
	}

	next, err := voterset.New(
		context.state.sessionID,
		voterIDs,
		current.VoterSetVersion+1,
	)
	if err != nil {
		return context.reject(CodeInvalidVoterSet), nil
	}
	if current.SameTarget(next) {
		return context.reject(CodeVoterTargetUnchanged), nil
	}
	for _, id := range voterIDs {
		member, exists := context.state.devices[id]
		if !exists || member.Status != device.StatusActive {
			return context.reject(CodeVoterTargetNotActive), nil
		}
	}
	if err := voterset.ValidateTransition(
		voterset.OperationChange,
		current,
		next,
	); err != nil {
		return context.reject(CodeInvalidVoterSet), nil
	}
	return context.acceptMembership(
		nil,
		nil,
		[]voterset.Set{next},
		nil,
		voterSetMembershipOverride(context.state.sessionID),
	)
}
