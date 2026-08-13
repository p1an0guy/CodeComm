package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

func reduceTaskUpdated(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		nil,
		[]string{"title", "body", "priority", "labels", "blocked_by"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	if len(payload) == 0 {
		return context.reject(CodeInvalidPayload), nil
	}

	current, outcome, done, err := loadMutableTask(context)
	if err != nil || done {
		return outcome, err
	}
	if context.proposal.Origin.ActorType() == event.ActorAgent &&
		!heldByOrigin(current, context) &&
		!whollyUnowned(current) {
		return context.reject(CodeTaskHolderRequired), nil
	}

	next := cloneTask(current)
	if _, present := payload["title"]; present {
		value, ok := decodeValue[string](payload, "title")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		next.Title = value
	}
	if _, present := payload["body"]; present {
		value, ok := decodeValue[string](payload, "body")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		next.Body = value
	}
	if _, present := payload["priority"]; present {
		value, ok := decodePriority(payload, "priority")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		next.Priority = value
	}
	if _, present := payload["labels"]; present {
		value, ok := decodeLabels(payload, "labels")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		next.Labels = value
	}
	blockedByChanged := false
	if _, present := payload["blocked_by"]; present {
		value, ok := decodeTaskIDs(payload, "blocked_by")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		next.BlockedBy = append([]domain.UUIDv7(nil), value...)
		blockedByChanged = true
	}
	next.EntityVersion++
	next.UpdatedAt = context.proposal.CreatedAt

	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	if blockedByChanged {
		if code, err := validateTaskDependencies(context, next.ID, next.BlockedBy); err != nil {
			return Outcome{}, err
		} else if code != "" {
			return context.reject(code), nil
		}
	}
	return context.acceptTask(next, nil)
}
