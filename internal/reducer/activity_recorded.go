package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
)

const CodeActivityTaskNotFound Code = "activity_task_not_found"

func reduceActivityRecorded(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		nil,
		[]string{"task_id"},
	)
	if code != "" {
		return context.reject(code), nil
	}

	var taskID domain.UUIDv7
	if _, present := payload["task_id"]; present {
		taskText, ok := decodeValue[string](payload, "task_id")
		taskID = domain.UUIDv7(taskText)
		if !ok || !taskID.Valid() {
			return context.reject(CodeInvalidPayload), nil
		}
		if _, exists := context.state.tasks[taskID]; !exists {
			return context.reject(CodeActivityTaskNotFound), nil
		}
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
		},
		ActivityTaskID: taskID,
	}, nil
}
