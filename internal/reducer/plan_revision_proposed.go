package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/plan"
)

func reducePlanRevisionProposed(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"title", "body"},
		[]string{"task_ids", "supersedes"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	title, ok := decodeValue[string](payload, "title")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	body, ok := decodeValue[string](payload, "body")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	var taskIDs []domain.UUIDv7
	if _, present := payload["task_ids"]; present {
		taskIDs, ok = decodeTaskIDs(payload, "task_ids")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
	}
	var supersedes domain.UUIDv7
	if _, present := payload["supersedes"]; present {
		value, decoded := decodeValue[string](payload, "supersedes")
		if !decoded {
			return context.reject(CodeInvalidPayload), nil
		}
		supersedes = domain.UUIDv7(value)
	}

	id := proposalUUIDv7(context)
	if _, exists := context.state.planRevisions[id]; exists {
		if _, err := context.state.validateRetainedPlanRevision(id); err != nil {
			return Outcome{}, invalidState("%v", err)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	next, err := plan.NewRevision(
		id,
		supersedes,
		title,
		body,
		taskIDs,
		context.device.ID,
		context.proposal.CreatedAt,
	)
	if err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	if supersedes != "" {
		if _, exists := context.state.planRevisions[supersedes]; !exists {
			return context.reject(CodePlanRevisionNotFound), nil
		}
		if _, err := context.state.validateRetainedPlanRevision(
			supersedes,
		); err != nil {
			return Outcome{}, invalidState("%v", err)
		}
	}
	for _, taskID := range next.TaskIDs() {
		_, exists := context.state.tasks[taskID]
		if !exists {
			return context.reject(CodePlanTaskNotFound), nil
		}
		if err := context.state.validatePlanMemoryTaskReference(
			taskID,
			nil,
		); err != nil {
			return Outcome{}, invalidState(
				"plan task %q: %v",
				taskID,
				err,
			)
		}
	}
	return context.acceptPlanRevision(next)
}
