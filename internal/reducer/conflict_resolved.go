package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceWorkspaceConflictResolved(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"resolution_publication_id"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	resolutionText, ok := decodeValue[string](
		payload,
		"resolution_publication_id",
	)
	resolutionID := domain.UUIDv7(resolutionText)
	if !ok || !resolutionID.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}
	current, outcome, done, err := loadMutableConflict(context)
	if err != nil || done {
		return outcome, err
	}
	resolution, exists := context.state.publications[resolutionID]
	if !exists {
		return context.reject(CodeConflictResolutionNotFound), nil
	}
	if resolution.State != publication.StateApplied {
		return context.reject(CodeConflictResolutionNotApplied), nil
	}
	if !resolutionPublicationDeclares(resolution, current.ID) {
		return context.reject(CodeConflictResolutionNotDeclared), nil
	}
	if context.proposal.Origin.ActorType() == event.ActorAgent &&
		(context.agentSession == nil ||
			resolution.Metadata.AuthorDeviceID != context.device.ID ||
			resolution.Metadata.AuthorAgentSessionID != context.agentSession.ID) {
		return context.reject(CodeConflictResolutionAuthorMismatch), nil
	}

	next := cloneConflict(current)
	next.Status = conflict.StatusResolved
	next.ResolutionKind = conflict.ResolutionKindPublication
	next.ResolutionPublicationID = resolutionID
	next.ResolvedByDeviceID = context.device.ID
	next.EntityVersion++
	if err := conflict.ValidateTransition(
		conflict.OperationPublicationResolve,
		&current,
		next,
	); err != nil {
		return context.reject(CodeInvalidConflictTransition), nil
	}
	return context.acceptConflict(&next, nil)
}
