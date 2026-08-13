package reducer

import (
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

func proposalLeaseID(context reductionContext) domain.UUIDv7 {
	value, _ := context.proposal.EntityID.Value()
	return domain.UUIDv7(value)
}

func loadMutableLease(
	context reductionContext,
) (lease.Lease, Outcome, bool, error) {
	id := proposalLeaseID(context)
	current, exists := context.state.leases[id]
	if !exists {
		return lease.Lease{}, context.reject(CodeEntityNotFound), true, nil
	}
	if current.ID != id {
		return lease.Lease{}, Outcome{}, false, invalidState(
			"lease map key does not match row",
		)
	}
	if err := current.Validate(); err != nil {
		return lease.Lease{}, Outcome{}, false, invalidState(
			"lease %q: %v",
			id,
			err,
		)
	}
	if err := context.state.validateLeaseReferences(current); err != nil {
		return lease.Lease{}, Outcome{}, false, invalidState(
			"lease %q: %v",
			id,
			err,
		)
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return lease.Lease{}, context.reject(CodeEntityVersionMismatch), true, nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return lease.Lease{}, context.reject(CodeEntityVersionExhausted), true, nil
	}
	return current, Outcome{}, false, nil
}

func leaseHeldByOrigin(value lease.Lease, context reductionContext) bool {
	return context.agentSession != nil &&
		value.HolderDeviceID == context.proposal.Origin.DeviceID() &&
		value.HolderAgentSessionID == context.agentSession.ID
}

func validateLeaseTTL(
	context reductionContext,
	ttl int64,
) (policy.Values, Code, error) {
	values, err := validatePolicy(context)
	if err != nil {
		return policy.Values{}, "", err
	}
	if err := lease.ValidateRequestedTTL(
		ttl,
		values.LeaseMinTTLSeconds,
		values.LeaseMaxTTLSeconds,
	); err != nil {
		return policy.Values{}, CodeInvalidPayload, nil
	}
	return values, "", nil
}

func validateActiveLeaseIndexes(
	context reductionContext,
) (int, int, error) {
	if context.agentSession == nil {
		return 0, 0, invalidState("lease reduction has no agent session")
	}
	agentIDs := context.state.activeLeasesByAgent[context.agentSession.ID]
	deviceIDs := context.state.activeLeasesByDevice[context.device.ID]
	if err := validateActiveLeaseList(
		context,
		agentIDs,
		policy.MaxAgentLeaseLimit,
		context.device.ID,
		context.agentSession.ID,
	); err != nil {
		return 0, 0, err
	}
	if err := validateActiveLeaseList(
		context,
		deviceIDs,
		policy.MaxDeviceLeaseLimit,
		context.device.ID,
		"",
	); err != nil {
		return 0, 0, err
	}
	for _, id := range agentIDs {
		if _, present := slices.BinarySearch(deviceIDs, id); !present {
			return 0, 0, invalidState(
				"agent lease %q is absent from its device index",
				id,
			)
		}
	}
	if err := validateGlobalActiveLeaseIndex(context.state); err != nil {
		return 0, 0, err
	}
	return len(agentIDs), len(deviceIDs), nil
}

func validateActiveLeaseList(
	context reductionContext,
	ids []domain.UUIDv7,
	maximum int64,
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
) error {
	if int64(len(ids)) > maximum {
		return invalidState("active lease index exceeds hard limit %d", maximum)
	}
	for index, id := range ids {
		if !id.Valid() || index > 0 && ids[index-1] >= id {
			return invalidState("active lease index is not sorted and unique")
		}
		value, exists := context.state.leases[id]
		if !exists {
			return invalidState("active lease index references missing lease %q", id)
		}
		if value.ID != id || value.Status != lease.StatusActive {
			return invalidState("active lease index references invalid row %q", id)
		}
		if err := value.Validate(); err != nil {
			return invalidState("active lease %q: %v", id, err)
		}
		if value.HolderDeviceID != deviceID ||
			agentSessionID != "" &&
				value.HolderAgentSessionID != agentSessionID {
			return invalidState("active lease index owner mismatch for %q", id)
		}
	}
	return nil
}

func validateGlobalActiveLeaseIndex(state State) error {
	maximum := policy.MaxMemberDevices * policy.MaxDeviceLeaseLimit
	if int64(len(state.activeLeaseIDs)) > maximum {
		return invalidState("global active lease index exceeds hard limit %d", maximum)
	}
	activeRows := 0
	for id, value := range state.leases {
		if value.Status != lease.StatusActive {
			continue
		}
		activeRows++
		if _, present := slices.BinarySearch(state.activeLeaseIDs, id); !present {
			return invalidState("active lease %q is absent from global index", id)
		}
	}
	if activeRows != len(state.activeLeaseIDs) {
		return invalidState("global active lease index count mismatch")
	}
	for index, id := range state.activeLeaseIDs {
		if !id.Valid() || index > 0 && state.activeLeaseIDs[index-1] >= id {
			return invalidState("global active lease index is not sorted and unique")
		}
		value, exists := state.leases[id]
		if !exists || value.ID != id || value.Status != lease.StatusActive {
			return invalidState("global active lease index references invalid row %q", id)
		}
	}
	return nil
}

func findActiveLeaseConflict(
	context reductionContext,
	candidate lease.Lease,
) (bool, error) {
	for _, id := range context.state.activeLeaseIDs {
		current, exists := context.state.leases[id]
		if !exists || current.ID != id || current.Status != lease.StatusActive {
			return false, invalidState(
				"global active lease index references invalid row %q",
				id,
			)
		}
		if err := context.state.validateLeaseReferences(current); err != nil {
			return false, invalidState("lease %q: %v", id, err)
		}
		intersects, err := lease.ActiveLeasesIntersect(candidate, current)
		if err != nil {
			return false, invalidState("lease intersection: %v", err)
		}
		if intersects {
			return true, nil
		}
	}
	return false, nil
}

func pathPatternTexts(value lease.Lease) []string {
	patterns := value.PathPatterns()
	result := make([]string, len(patterns))
	for index, pattern := range patterns {
		result[index] = pattern.String()
	}
	return result
}

func leaseOperatorOverride(id domain.UUIDv7) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: fmt.Sprintf("lease:%s", id),
	}
}
