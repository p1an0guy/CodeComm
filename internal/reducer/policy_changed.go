package reducer

import (
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

var policyValueFields = [...]string{
	"checkpoint_events",
	"checkpoint_interval_seconds",
	"lease_min_ttl_seconds",
	"lease_default_ttl_seconds",
	"lease_max_ttl_seconds",
	"agent_claim_limit",
	"agent_lease_limit",
	"device_claim_limit",
	"device_lease_limit",
	"advertisement_interval_seconds",
	"audit_depth_per_device_per_epoch",
	"max_member_devices",
	"max_active_agent_sessions",
	"cluster_min_apply_level",
}

func reducePolicyChanged(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		policyValueFields[:],
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	values, ok := decodePolicyValues(payload)
	if !ok || values.Validate() != nil {
		return context.reject(CodeInvalidPayload), nil
	}

	entityText, _ := context.proposal.EntityID.Value()
	if domain.UUIDv7(entityText) != context.state.sessionID {
		return context.reject(CodeSessionBindingMismatch), nil
	}
	current := context.state.sessionPolicy
	if current.SessionID != context.state.sessionID {
		return Outcome{}, invalidState("session-policy row has wrong session")
	}
	if err := current.Validate(); err != nil {
		return Outcome{}, invalidState("session policy: %v", err)
	}
	if err := context.state.validateDerivedBounds(); err != nil {
		return Outcome{}, err
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}
	if values.ClusterMinApplyLevel < current.Values.ClusterMinApplyLevel {
		return context.reject(CodeClusterApplyLevelDecrease), nil
	}

	switch context.state.policyUseViolation(values, nil, nil, nil, nil, nil) {
	case policyUseWithinLimits:
	case policyUseExceedsLimit:
		return context.reject(CodePolicyLimitBelowCurrentUse), nil
	case policyUseUnsupportedApplyLevel:
		return context.reject(CodeClusterApplyLevelUnsupported), nil
	default:
		return Outcome{}, invalidState("unknown policy-use validation result")
	}

	next := policy.Policy{
		SessionID:     current.SessionID,
		Values:        values,
		EntityVersion: current.EntityVersion + 1,
	}
	if err := policy.ValidateTransition(
		policy.OperationChange,
		current,
		next,
	); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid policy transition: %v",
			err,
		)
	}
	return context.acceptPolicy(next, policyOperatorOverride(next.SessionID))
}

func decodePolicyValues(object payloadObject) (policy.Values, bool) {
	var values policy.Values
	destinations := [...]*int64{
		&values.CheckpointEvents,
		&values.CheckpointIntervalSeconds,
		&values.LeaseMinTTLSeconds,
		&values.LeaseDefaultTTLSeconds,
		&values.LeaseMaxTTLSeconds,
		&values.AgentClaimLimit,
		&values.AgentLeaseLimit,
		&values.DeviceClaimLimit,
		&values.DeviceLeaseLimit,
		&values.AdvertisementIntervalSeconds,
		&values.AuditDepthPerDevicePerEpoch,
		&values.MaxMemberDevices,
		&values.MaxActiveAgentSessions,
		&values.ClusterMinApplyLevel,
	}
	for index, field := range policyValueFields {
		value, ok := decodeValue[int64](object, field)
		if !ok {
			return policy.Values{}, false
		}
		*destinations[index] = value
	}
	return values, true
}

func policyOperatorOverride(sessionID domain.UUIDv7) *AuditDirective {
	return &AuditDirective{
		Class:   AuditOperatorOverride,
		Subject: fmt.Sprintf("session_policy:%s", sessionID),
	}
}
