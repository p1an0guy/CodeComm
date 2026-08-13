package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func reduceTaskCreated(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"title", "priority"},
		[]string{"body", "labels", "blocked_by"},
	)
	if code != "" {
		return context.reject(code), nil
	}

	title, ok := decodeValue[string](payload, "title")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	priority, ok := decodePriority(payload, "priority")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	body := ""
	if _, present := payload["body"]; present {
		body, ok = decodeValue[string](payload, "body")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
	}
	var labels []string
	if _, present := payload["labels"]; present {
		labels, ok = decodeLabels(payload, "labels")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
	}
	var blockedBy []domain.UUIDv7
	if _, present := payload["blocked_by"]; present {
		blockedBy, ok = decodeTaskIDs(payload, "blocked_by")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
	}

	id := taskID(context)
	if existing, exists := context.state.tasks[id]; exists {
		if existing.ID != id {
			return Outcome{}, invalidState("task map key does not match collided row")
		}
		if err := existing.Validate(); err != nil {
			return Outcome{}, invalidState("collided task %q: %v", id, err)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	next := task.Task{
		ID:            id,
		Title:         title,
		Body:          body,
		State:         task.StateBacklog,
		Priority:      priority,
		BlockedBy:     blockedBy,
		Labels:        labels,
		EntityVersion: 1,
		CreatedAt:     context.proposal.CreatedAt,
		UpdatedAt:     context.proposal.CreatedAt,
	}
	if code := validateTaskCandidate(next); code != "" {
		return context.reject(code), nil
	}
	if code, err := validateTaskDependencies(context, id, next.BlockedBy); err != nil {
		return Outcome{}, err
	} else if code != "" {
		return context.reject(code), nil
	}
	if err := task.ValidateTransition(task.OperationCreate, task.StateAbsent, next.State); err != nil {
		return context.reject(CodeInvalidTaskTransition), nil
	}
	return context.acceptTask(next, nil)
}
