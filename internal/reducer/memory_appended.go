package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/memory"
)

func reduceMemoryAppended(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"scope", "key", "body"},
		[]string{"task_id", "supersedes"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	scopeText, ok := decodeValue[string](payload, "scope")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	key, ok := decodeValue[string](payload, "key")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	body, ok := decodeValue[string](payload, "body")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	var taskID domain.UUIDv7
	if _, present := payload["task_id"]; present {
		value, decoded := decodeValue[string](payload, "task_id")
		if !decoded {
			return context.reject(CodeInvalidPayload), nil
		}
		taskID = domain.UUIDv7(value)
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
	if _, exists := context.state.memoryRecords[id]; exists {
		if _, err := context.state.validateRetainedMemoryRecord(id); err != nil {
			return Outcome{}, invalidState("%v", err)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	next, err := memory.NewRecord(
		id,
		memory.Scope(scopeText),
		taskID,
		key,
		body,
		supersedes,
		context.proposal.CreatedAt,
	)
	if err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	if taskID != "" {
		_, exists := context.state.tasks[taskID]
		if !exists {
			return context.reject(CodeMemoryTaskNotFound), nil
		}
		if err := context.state.validatePlanMemoryTaskReference(
			taskID,
			nil,
		); err != nil {
			return Outcome{}, invalidState(
				"memory task %q: %v",
				taskID,
				err,
			)
		}
	}
	if supersedes != "" {
		predecessor, exists := context.state.memoryRecords[supersedes]
		if !exists {
			return context.reject(CodeMemoryPredecessorNotFound), nil
		}
		validated, err := context.state.validateRetainedMemoryRecord(
			supersedes,
		)
		if err != nil {
			return Outcome{}, invalidState("%v", err)
		}
		if validated.ID() != predecessor.ID() {
			return Outcome{}, invalidState(
				"memory predecessor lookup changed identity",
			)
		}
		if err := memory.ValidatePredecessor(next, predecessor); err != nil {
			return context.reject(CodeMemoryPredecessorMismatch), nil
		}
		if successorID, occupied := context.state.memorySuccessors[supersedes]; occupied {
			successor, err := context.state.validateRetainedMemoryRecord(
				successorID,
			)
			if err != nil {
				return Outcome{}, invalidState("%v", err)
			}
			actualPredecessor, present := successor.Supersedes()
			if !present || actualPredecessor != supersedes {
				return Outcome{}, invalidState(
					"memory successor index disagrees with row",
				)
			}
			return context.reject(
				CodeMemoryPredecessorAlreadySuperseded,
			), nil
		}
	}
	return context.acceptMemory(next)
}
