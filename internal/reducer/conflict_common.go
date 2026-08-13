package reducer

import (
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

func proposalConflictID(context reductionContext) domain.ConflictID {
	value, _ := context.proposal.EntityID.Value()
	return domain.ConflictID(value)
}

func loadMutableConflict(
	context reductionContext,
) (conflict.Conflict, Outcome, bool, error) {
	id := proposalConflictID(context)
	current, exists := context.state.mergeConflicts[id]
	if !exists {
		return conflict.Conflict{},
			context.reject(CodeEntityNotFound),
			true,
			nil
	}
	if current.ID != id {
		return conflict.Conflict{}, Outcome{}, false, invalidState(
			"conflict map key does not match row",
		)
	}
	if err := current.Validate(); err != nil {
		return conflict.Conflict{}, Outcome{}, false, invalidState(
			"conflict %q: %v",
			id,
			err,
		)
	}
	if err := context.state.validateConflictReferences(current); err != nil {
		return conflict.Conflict{}, Outcome{}, false, invalidState(
			"conflict %q: %v",
			id,
			err,
		)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return conflict.Conflict{},
			context.reject(CodeEntityVersionMismatch),
			true,
			nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return conflict.Conflict{},
			context.reject(CodeEntityVersionExhausted),
			true,
			nil
	}
	return cloneConflict(current), Outcome{}, false, nil
}

func (context reductionContext) acceptConflict(
	value *conflict.Conflict,
	audit *AuditDirective,
) (Outcome, error) {
	changes := Changes{OriginScopes: []OriginScope{context.scope}}
	var candidatePublicationID domain.UUIDv7
	if value != nil {
		if err := value.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid conflict %q: %v",
				value.ID,
				err,
			)
		}
		changes.MergeConflicts = []conflict.Conflict{cloneConflict(*value)}
		candidatePublicationID = value.PublicationID
	} else {
		current, exists := context.state.mergeConflicts[proposalConflictID(context)]
		if !exists {
			return Outcome{}, invalidState(
				"accepted conflict redetection has no committed row",
			)
		}
		candidatePublicationID = current.PublicationID
	}
	var taskID domain.UUIDv7
	if candidate, exists := context.state.publications[candidatePublicationID]; exists {
		taskID = candidate.Metadata.TaskID
	}
	return Outcome{
		Status:         StatusAccepted,
		Code:           CodeAccepted,
		Changes:        changes,
		ActivityTaskID: taskID,
		Audit:          audit,
	}, nil
}

func conflictOperatorOverride(id domain.ConflictID) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: fmt.Sprintf("conflict:%s", id),
	}
}

func conflictAlarm(
	id domain.ConflictID,
	class AlarmClass,
) *AlarmDirective {
	return &AlarmDirective{
		Class:   class,
		Subject: fmt.Sprintf("conflict:%s", id),
	}
}

func resolutionPublicationDeclares(
	value publication.Publication,
	conflictID domain.ConflictID,
) bool {
	for _, candidate := range value.Metadata.ResolvesConflictIDs {
		if candidate == conflictID {
			return true
		}
	}
	return false
}
