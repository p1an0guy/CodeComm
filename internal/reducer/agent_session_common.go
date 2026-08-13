package reducer

import (
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func proposalAgentSessionID(context reductionContext) domain.UUIDv7 {
	value, _ := context.proposal.EntityID.Value()
	return domain.UUIDv7(value)
}

func loadMutableAgentSession(
	context reductionContext,
) (agentsession.Session, Outcome, bool, error) {
	id := proposalAgentSessionID(context)
	current, exists := context.state.agentSessions[id]
	if !exists {
		return agentsession.Session{}, context.reject(CodeEntityNotFound), true, nil
	}
	if current.ID != id {
		return agentsession.Session{}, Outcome{}, false, invalidState(
			"agent-session map key does not match row",
		)
	}
	if err := current.Validate(); err != nil {
		return agentsession.Session{}, Outcome{}, false, invalidState(
			"agent session %q: %v",
			id,
			err,
		)
	}
	if err := context.state.validateAgentSessionReferences(current); err != nil {
		return agentsession.Session{}, Outcome{}, false, invalidState(
			"agent session %q: %v",
			id,
			err,
		)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return agentsession.Session{},
			context.reject(CodeEntityVersionMismatch),
			true,
			nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return agentsession.Session{},
			context.reject(CodeEntityVersionExhausted),
			true,
			nil
	}
	return cloneAgentSession(current), Outcome{}, false, nil
}

func cloneAgentSession(value agentsession.Session) agentsession.Session {
	result := value
	if value.AgentProfileID != nil {
		profile := *value.AgentProfileID
		result.AgentProfileID = &profile
	}
	return result
}

func sameAgentSessionIdentity(left, right agentsession.Session) bool {
	if left.ID != right.ID ||
		left.DeviceID != right.DeviceID ||
		left.ClientKind != right.ClientKind ||
		left.WorkingRootID != right.WorkingRootID {
		return false
	}
	if left.AgentProfileID == nil || right.AgentProfileID == nil {
		return left.AgentProfileID == nil && right.AgentProfileID == nil
	}
	return *left.AgentProfileID == *right.AgentProfileID
}

func validateActiveAgentSessionCount(
	context reductionContext,
) (int, error) {
	count := 0
	for id, value := range context.state.agentSessions {
		if id != value.ID {
			return 0, invalidState("agent-session map key does not match row")
		}
		if err := value.Validate(); err != nil {
			return 0, invalidState("agent session %q: %v", id, err)
		}
		if err := context.state.validateAgentSessionReferences(value); err != nil {
			return 0, invalidState("agent session %q: %v", id, err)
		}
		if value.State != agentsession.StateEnded {
			count++
		}
	}
	if int64(count) > policy.MaxActiveAgentSessions {
		return 0, invalidState(
			"active agent-session count exceeds hard limit %d",
			policy.MaxActiveAgentSessions,
		)
	}
	if count != context.state.activeAgentSessionCount {
		return 0, invalidState(
			"active agent-session count disagrees with derived state",
		)
	}
	return count, nil
}

func buildSessionEndCascade(
	context reductionContext,
	current agentsession.Session,
) ([]task.Task, []lease.Lease, Code, error) {
	claimIDs := context.state.claimsByAgent[current.ID]
	deviceClaimIDs := context.state.claimsByDevice[current.DeviceID]
	if err := validateClaimList(
		context,
		claimIDs,
		policy.MaxAgentClaimLimit,
		current.DeviceID,
		current.ID,
	); err != nil {
		return nil, nil, "", err
	}
	if err := validateClaimList(
		context,
		deviceClaimIDs,
		policy.MaxDeviceClaimLimit,
		current.DeviceID,
		"",
	); err != nil {
		return nil, nil, "", err
	}
	for _, id := range claimIDs {
		if _, present := slices.BinarySearch(deviceClaimIDs, id); !present {
			return nil, nil, "", invalidState(
				"agent claim %q is absent from its device index",
				id,
			)
		}
	}

	leaseIDs := context.state.activeLeasesByAgent[current.ID]
	deviceLeaseIDs := context.state.activeLeasesByDevice[current.DeviceID]
	if err := validateActiveLeaseList(
		context,
		leaseIDs,
		policy.MaxAgentLeaseLimit,
		current.DeviceID,
		current.ID,
	); err != nil {
		return nil, nil, "", err
	}
	if err := validateActiveLeaseList(
		context,
		deviceLeaseIDs,
		policy.MaxDeviceLeaseLimit,
		current.DeviceID,
		"",
	); err != nil {
		return nil, nil, "", err
	}
	for _, id := range leaseIDs {
		if _, present := slices.BinarySearch(deviceLeaseIDs, id); !present {
			return nil, nil, "", invalidState(
				"agent lease %q is absent from its device index",
				id,
			)
		}
	}
	if err := validateGlobalActiveLeaseIndex(context.state); err != nil {
		return nil, nil, "", err
	}

	tasks := make([]task.Task, 0, len(claimIDs))
	for _, id := range claimIDs {
		value := context.state.tasks[id]
		if value.EntityVersion == domain.MaxSafeInteger {
			return nil, nil, CodeEntityVersionExhausted, nil
		}
		if err := task.ValidateTransition(
			task.OperationSessionEnded,
			value.State,
			task.StateReady,
		); err != nil {
			return nil, nil, "", invalidState(
				"claimed task %q cannot be released on session end: %v",
				id,
				err,
			)
		}
		next := cloneTask(value)
		next.State = task.StateReady
		next.StateReason = nil
		next.OwnerDeviceID = ""
		next.OwnerAgentSessionID = ""
		next.IntendedDeviceID = ""
		next.LastReleaseReason = task.ReleaseSessionEnd
		next.EntityVersion++
		next.UpdatedAt = context.proposal.CreatedAt
		if code := validateTaskCandidate(next); code != "" {
			return nil, nil, "", invalidState(
				"session-end task %q is invalid: %s",
				id,
				code,
			)
		}
		tasks = append(tasks, next)
	}

	leases := make([]lease.Lease, 0, len(leaseIDs))
	for _, id := range leaseIDs {
		value := context.state.leases[id]
		if value.EntityVersion == domain.MaxSafeInteger {
			return nil, nil, CodeEntityVersionExhausted, nil
		}
		next := value
		next.Status = lease.StatusReleased
		next.ReleaseReason = lease.ReleaseSessionEnded
		next.EntityVersion++
		if err := lease.ValidateTransition(
			lease.OperationSessionEnded,
			value.Lifecycle(),
			next.Lifecycle(),
		); err != nil {
			return nil, nil, "", invalidState(
				"active lease %q cannot be released on session end: %v",
				id,
				err,
			)
		}
		leases = append(leases, next)
	}
	return tasks, leases, "", nil
}

func invalidAgentSessionChange(id domain.UUIDv7, format string, args ...any) error {
	return invalidState(
		"agent-session change %q: %s",
		id,
		fmt.Sprintf(format, args...),
	)
}
