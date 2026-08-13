package reducer

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func taskID(context reductionContext) domain.UUIDv7 {
	value, _ := context.proposal.EntityID.Value()
	return domain.UUIDv7(value)
}

func proposalUUIDv7(context reductionContext) domain.UUIDv7 {
	value, _ := context.proposal.EntityID.Value()
	return domain.UUIDv7(value)
}

func loadMutableTask(
	context reductionContext,
) (task.Task, Outcome, bool, error) {
	id := taskID(context)
	current, exists := context.state.tasks[id]
	if !exists {
		return task.Task{}, context.reject(CodeEntityNotFound), true, nil
	}
	if current.ID != id {
		return task.Task{}, Outcome{}, false, invalidState(
			"task map key does not match row",
		)
	}
	if err := current.Validate(); err != nil {
		return task.Task{}, Outcome{}, false, invalidState("task %q: %v", id, err)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return task.Task{}, context.reject(CodeEntityVersionMismatch), true, nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return task.Task{}, context.reject(CodeEntityVersionExhausted), true, nil
	}
	return cloneTask(current), Outcome{}, false, nil
}

func cloneTask(value task.Task) task.Task {
	result := value
	result.BlockedBy = append([]domain.UUIDv7(nil), value.BlockedBy...)
	result.Labels = append([]string(nil), value.Labels...)
	if value.StateReason != nil {
		reason := *value.StateReason
		result.StateReason = &reason
	}
	return result
}

func validateTaskCandidate(value task.Task) Code {
	if err := value.Validate(); err != nil {
		switch {
		case errors.Is(err, task.ErrDependencyCycle):
			return CodeDependencyCycle
		default:
			return CodeInvalidPayload
		}
	}
	return ""
}

func validateTaskDependencies(
	context reductionContext,
	subject domain.UUIDv7,
	dependencies []domain.UUIDv7,
) (Code, error) {
	var stateErr error
	direct := make(map[domain.UUIDv7]struct{}, len(dependencies))
	for _, id := range dependencies {
		direct[id] = struct{}{}
	}
	err := task.ValidateDependencyGraph(
		subject,
		dependencies,
		func(id domain.UUIDv7) ([]domain.UUIDv7, bool) {
			value, exists := context.state.tasks[id]
			if !exists {
				if _, proposedDirectly := direct[id]; !proposedDirectly {
					stateErr = invalidState(
						"retained dependency graph references missing task %q",
						id,
					)
				}
				return nil, false
			}
			if value.ID != id {
				stateErr = invalidState("task map key does not match dependency row")
				return nil, false
			}
			if err := value.Validate(); err != nil {
				stateErr = invalidState("dependency task %q: %v", id, err)
				return nil, false
			}
			return append([]domain.UUIDv7(nil), value.BlockedBy...), true
		},
	)
	if stateErr != nil {
		return "", stateErr
	}
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, task.ErrDependencyCycle):
		return CodeDependencyCycle, nil
	case errors.Is(err, task.ErrDependencyNotFound):
		return CodeDependencyNotFound, nil
	case errors.Is(err, task.ErrDependencyGraphTooComplex):
		return CodeDependencyGraphTooComplex, nil
	default:
		return CodeInvalidPayload, nil
	}
}

func heldByOrigin(value task.Task, context reductionContext) bool {
	return context.agentSession != nil &&
		value.OwnerDeviceID == context.proposal.Origin.DeviceID() &&
		value.OwnerAgentSessionID == context.agentSession.ID
}

func whollyUnowned(value task.Task) bool {
	return value.OwnerDeviceID == "" && value.OwnerAgentSessionID == ""
}

func taskHasUnresolvedConflict(context reductionContext, id domain.UUIDv7) bool {
	return context.state.unresolvedConflictsByTask[id] != 0
}

func allDependenciesDone(
	context reductionContext,
	value task.Task,
) (bool, error) {
	for _, dependencyID := range value.BlockedBy {
		dependency, exists := context.state.tasks[dependencyID]
		if !exists {
			return false, invalidState(
				"task %q references missing dependency %q",
				value.ID,
				dependencyID,
			)
		}
		if dependency.ID != dependencyID {
			return false, invalidState("task map key does not match dependency row")
		}
		if err := dependency.Validate(); err != nil {
			return false, invalidState(
				"dependency task %q: %v",
				dependencyID,
				err,
			)
		}
		if dependency.State != task.StateDone {
			return false, nil
		}
	}
	return true, nil
}

func validateClaimIndexes(
	context reductionContext,
) (int, int, error) {
	if context.agentSession == nil {
		return 0, 0, invalidState("claim reduction has no agent session")
	}
	agentClaims := context.state.claimsByAgent[context.agentSession.ID]
	deviceClaims := context.state.claimsByDevice[context.device.ID]
	if err := validateClaimList(
		context,
		agentClaims,
		policy.MaxAgentClaimLimit,
		context.device.ID,
		context.agentSession.ID,
	); err != nil {
		return 0, 0, err
	}
	if err := validateClaimList(
		context,
		deviceClaims,
		policy.MaxDeviceClaimLimit,
		context.device.ID,
		"",
	); err != nil {
		return 0, 0, err
	}
	for _, id := range agentClaims {
		if _, present := slices.BinarySearch(deviceClaims, id); !present {
			return 0, 0, invalidState(
				"agent claim %q is absent from its device index",
				id,
			)
		}
	}
	return len(agentClaims), len(deviceClaims), nil
}

func validateClaimList(
	context reductionContext,
	ids []domain.UUIDv7,
	maximum int64,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
) error {
	if int64(len(ids)) > maximum {
		return invalidState("claim index exceeds hard limit %d", maximum)
	}
	for index, id := range ids {
		if !id.Valid() || index > 0 && ids[index-1] >= id {
			return invalidState("claim index is not sorted and unique")
		}
		value, exists := context.state.tasks[id]
		if !exists {
			return invalidState("claim index references missing task %q", id)
		}
		if value.ID != id {
			return invalidState("task map key does not match claim row")
		}
		if err := value.Validate(); err != nil {
			return invalidState("claimed task %q: %v", id, err)
		}
		if value.OwnerDeviceID != deviceID ||
			agentSessionID != "" && value.OwnerAgentSessionID != agentSessionID {
			return invalidState("claim index owner mismatch for task %q", id)
		}
	}
	return nil
}

func validatePolicy(context reductionContext) (policy.Values, error) {
	current := context.state.sessionPolicy
	if current.SessionID != context.state.sessionID {
		return policy.Values{}, invalidState("session-policy row has wrong session")
	}
	if err := current.Validate(); err != nil {
		return policy.Values{}, invalidState("session policy: %v", err)
	}
	agentClaims := len(context.state.claimsByAgent[context.proposal.Origin.AgentSessionID()])
	deviceClaims := len(context.state.claimsByDevice[context.proposal.Origin.DeviceID()])
	if int64(agentClaims) > current.Values.AgentClaimLimit ||
		int64(deviceClaims) > current.Values.DeviceClaimLimit {
		return policy.Values{}, invalidState(
			"current claim depth exceeds committed policy",
		)
	}
	return current.Values, nil
}

func operatorOverride(id domain.UUIDv7) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: fmt.Sprintf("task:%s", id),
	}
}
