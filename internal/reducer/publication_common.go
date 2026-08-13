package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/event"
)

func proposalPublicationID(context reductionContext) domain.UUIDv7 {
	value, _ := context.proposal.EntityID.Value()
	return domain.UUIDv7(value)
}

func loadMutablePublication(
	context reductionContext,
) (publication.Publication, Outcome, bool, error) {
	id := proposalPublicationID(context)
	current, exists := context.state.publications[id]
	if !exists {
		return publication.Publication{},
			context.reject(CodeEntityNotFound),
			true,
			nil
	}
	if current.Metadata.PublicationID != id {
		return publication.Publication{}, Outcome{}, false, invalidState(
			"publication map key does not match row",
		)
	}
	if err := current.Validate(); err != nil {
		return publication.Publication{}, Outcome{}, false, invalidState(
			"publication %q: %v",
			id,
			err,
		)
	}
	if err := context.state.validatePublicationReferences(current); err != nil {
		return publication.Publication{}, Outcome{}, false, invalidState(
			"publication %q: %v",
			id,
			err,
		)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return publication.Publication{},
			context.reject(CodeEntityVersionMismatch),
			true,
			nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return publication.Publication{},
			context.reject(CodeEntityVersionExhausted),
			true,
			nil
	}
	return clonePublication(current), Outcome{}, false, nil
}

func (context reductionContext) acceptPublication(
	value publication.Publication,
	canonicalRef *publication.CanonicalRef,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid publication %q: %v",
			value.Metadata.PublicationID,
			err,
		)
	}
	changes := Changes{
		OriginScopes: []OriginScope{context.scope},
		Publications: []publication.Publication{clonePublication(value)},
	}
	if canonicalRef != nil {
		if err := canonicalRef.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid canonical ref: %v",
				err,
			)
		}
		changes.CanonicalRefs = []publication.CanonicalRef{*canonicalRef}
	}
	return Outcome{
		Status:         StatusAccepted,
		Code:           CodeAccepted,
		Changes:        changes,
		ActivityTaskID: value.Metadata.TaskID,
	}, nil
}

func publicationPathsCovered(
	context reductionContext,
	paths []domain.RepositoryPath,
) (bool, error) {
	if context.agentSession == nil {
		return false, invalidState("publication reduction has no agent session")
	}
	if _, _, err := validateActiveLeaseIndexes(context); err != nil {
		return false, err
	}
	for _, path := range paths {
		covered := false
		for _, leaseID := range context.state.activeLeasesByAgent[context.agentSession.ID] {
			value := context.state.leases[leaseID]
			if value.Status != lease.StatusActive ||
				value.Scope != lease.ScopePath {
				continue
			}
			for _, pattern := range value.PathPatterns() {
				if !pattern.Prefix() && pattern.Path() == path ||
					pattern.Prefix() && pattern.Path().Contains(path) {
					covered = true
					break
				}
			}
			if covered {
				break
			}
		}
		if !covered {
			return false, nil
		}
	}
	return true, nil
}

func publicationReviewer(
	context reductionContext,
) (
	domain.DeviceID,
	domain.UUIDv7,
	publication.ReviewActorType,
	error,
) {
	switch context.proposal.Origin.ActorType() {
	case event.ActorAgent:
		if context.agentSession == nil {
			return "", "", "", invalidState(
				"agent publication review has no bound session",
			)
		}
		return context.device.ID,
			context.agentSession.ID,
			publication.ReviewActorAgent,
			nil
	case event.ActorHuman:
		return context.device.ID,
			"",
			publication.ReviewActorHuman,
			nil
	default:
		return "", "", "", invalidState(
			"unexpected publication review actor %q",
			context.proposal.Origin.ActorType(),
		)
	}
}

func publicationWithdrawalAuthorized(
	context reductionContext,
	value publication.Publication,
) bool {
	switch context.proposal.Origin.ActorType() {
	case event.ActorAgent:
		return context.agentSession != nil &&
			value.Metadata.AuthorDeviceID == context.device.ID &&
			value.Metadata.AuthorAgentSessionID == context.agentSession.ID
	case event.ActorHuman:
		return context.device.Role == device.RoleOwner ||
			value.Metadata.AuthorDeviceID == context.device.ID
	default:
		return false
	}
}

func samePublicationLineage(
	left,
	right publication.Metadata,
) bool {
	return left.TaskID == right.TaskID &&
		left.AuthorDeviceID == right.AuthorDeviceID &&
		left.AuthorAgentSessionID == right.AuthorAgentSessionID &&
		left.WorkingRootID == right.WorkingRootID
}
