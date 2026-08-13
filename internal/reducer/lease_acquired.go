package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
)

func reduceLeaseAcquired(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"scope", "ttl_seconds"},
		[]string{"task_id", "path_globs"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	scopeText, ok := decodeValue[string](payload, "scope")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	ttl, ok := decodeValue[int64](payload, "ttl_seconds")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	scope := lease.Scope(scopeText)

	taskID := domain.UUIDv7("")
	if _, present := payload["task_id"]; present {
		taskText, valid := decodeValue[string](payload, "task_id")
		if !valid {
			return context.reject(CodeInvalidPayload), nil
		}
		taskID = domain.UUIDv7(taskText)
		if !taskID.Valid() {
			return context.reject(CodeInvalidPayload), nil
		}
	}
	var pathGlobs []string
	if _, present := payload["path_globs"]; present {
		pathGlobs, ok = decodeValue[[]string](payload, "path_globs")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
	}
	switch scope {
	case lease.ScopeTask:
		if _, present := payload["task_id"]; !present {
			return context.reject(CodeMissingPayloadField), nil
		}
		if _, present := payload["path_globs"]; present {
			return context.reject(CodeInvalidPayload), nil
		}
	case lease.ScopePath:
		if _, present := payload["path_globs"]; !present {
			return context.reject(CodeMissingPayloadField), nil
		}
	default:
		return context.reject(CodeInvalidPayload), nil
	}

	id := proposalLeaseID(context)
	if existing, exists := context.state.leases[id]; exists {
		if existing.ID != id {
			return Outcome{}, invalidState("lease map key does not match collided row")
		}
		if err := existing.Validate(); err != nil {
			return Outcome{}, invalidState("collided lease %q: %v", id, err)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	values, code, err := validateLeaseTTL(context, ttl)
	if err != nil {
		return Outcome{}, err
	}
	if code != "" {
		return context.reject(code), nil
	}

	if taskID != "" {
		associated, exists := context.state.tasks[taskID]
		if !exists {
			return context.reject(CodeLeaseTaskNotFound), nil
		}
		if associated.ID != taskID {
			return Outcome{}, invalidState(
				"task map key does not match lease association",
			)
		}
		if err := associated.Validate(); err != nil {
			return Outcome{}, invalidState("associated task %q: %v", taskID, err)
		}
		if scope == lease.ScopeTask && !heldByOrigin(associated, context) {
			return context.reject(CodeTaskHolderRequired), nil
		}
	}

	next, err := lease.New(lease.Fields{
		ID:                   id,
		HolderDeviceID:       context.device.ID,
		HolderAgentSessionID: context.agentSession.ID,
		Scope:                scope,
		TaskID:               taskID,
		TTLSeconds:           ttl,
		Status:               lease.StatusActive,
		EntityVersion:        1,
	}, pathGlobs)
	if err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	agentCount, deviceCount, err := validateActiveLeaseIndexes(context)
	if err != nil {
		return Outcome{}, err
	}
	if int64(agentCount) >= values.AgentLeaseLimit {
		return context.reject(CodeAgentLeaseLimitReached), nil
	}
	if int64(deviceCount) >= values.DeviceLeaseLimit {
		return context.reject(CodeDeviceLeaseLimitReached), nil
	}
	conflicts, err := findActiveLeaseConflict(context, next)
	if err != nil {
		return Outcome{}, err
	}
	if conflicts {
		return context.reject(CodeLeaseScopeConflict), nil
	}
	if err := lease.ValidateTransition(
		lease.OperationCreate,
		lease.Lifecycle{},
		next.Lifecycle(),
	); err != nil {
		return context.reject(CodeInvalidLeaseTransition), nil
	}
	return context.acceptLease(next, nil)
}
