// Package policy defines the complete mutable V1 session-policy value.
package policy

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MinCheckpointEvents     int64 = 100
	DefaultCheckpointEvents int64 = 500
	MaxCheckpointEvents     int64 = 10_000

	MinCheckpointIntervalSeconds     int64 = 60
	DefaultCheckpointIntervalSeconds int64 = 300
	MaxCheckpointIntervalSeconds     int64 = 3_600

	MinLeaseTTLSeconds        int64 = 30
	DefaultLeaseMinTTLSeconds int64 = 30
	DefaultLeaseTTLSeconds    int64 = 900
	DefaultLeaseMaxTTLSeconds int64 = 3_600
	MaxLeaseTTLSeconds        int64 = 86_400

	MinAgentClaimLimit     int64 = 1
	DefaultAgentClaimLimit int64 = 8
	MaxAgentClaimLimit     int64 = 64

	MinAgentLeaseLimit     int64 = 1
	DefaultAgentLeaseLimit int64 = 32
	MaxAgentLeaseLimit     int64 = 256

	MinDeviceClaimLimit     int64 = 1
	DefaultDeviceClaimLimit int64 = 64
	MaxDeviceClaimLimit     int64 = 256

	MinDeviceLeaseLimit     int64 = 1
	DefaultDeviceLeaseLimit int64 = 256
	MaxDeviceLeaseLimit     int64 = 1_024

	MinAdvertisementIntervalSeconds     int64 = 5
	DefaultAdvertisementIntervalSeconds int64 = 20
	MaxAdvertisementIntervalSeconds     int64 = 300

	MinAuditDepthPerDevicePerEpoch     int64 = 16
	DefaultAuditDepthPerDevicePerEpoch int64 = 256
	MaxAuditDepthPerDevicePerEpoch     int64 = 1_024

	MinMemberDevices     int64 = 1
	DefaultMemberDevices int64 = 8
	MaxMemberDevices     int64 = 8

	MinActiveAgentSessions     int64 = 1
	DefaultActiveAgentSessions int64 = 32
	MaxActiveAgentSessions     int64 = 32

	MinClusterMinApplyLevel     int64 = 1
	DefaultClusterMinApplyLevel int64 = 1
	MaxClusterMinApplyLevel     int64 = domain.MaxApplyLevel
)

var (
	ErrInvalidSessionID                    = errors.New("policy: invalid session ID")
	ErrInvalidEntityVersion                = errors.New("policy: invalid entity version")
	ErrInvalidCheckpointEvents             = errors.New("policy: invalid checkpoint_events")
	ErrInvalidCheckpointIntervalSeconds    = errors.New("policy: invalid checkpoint_interval_seconds")
	ErrInvalidLeaseMinTTLSeconds           = errors.New("policy: invalid lease_min_ttl_seconds")
	ErrInvalidLeaseDefaultTTLSeconds       = errors.New("policy: invalid lease_default_ttl_seconds")
	ErrInvalidLeaseMaxTTLSeconds           = errors.New("policy: invalid lease_max_ttl_seconds")
	ErrInvalidLeaseTTLOrder                = errors.New("policy: invalid lease TTL order")
	ErrInvalidAgentClaimLimit              = errors.New("policy: invalid agent_claim_limit")
	ErrInvalidAgentLeaseLimit              = errors.New("policy: invalid agent_lease_limit")
	ErrInvalidDeviceClaimLimit             = errors.New("policy: invalid device_claim_limit")
	ErrInvalidDeviceLeaseLimit             = errors.New("policy: invalid device_lease_limit")
	ErrInvalidClaimLimitRelation           = errors.New("policy: device_claim_limit is below agent_claim_limit")
	ErrInvalidLeaseLimitRelation           = errors.New("policy: device_lease_limit is below agent_lease_limit")
	ErrInvalidAdvertisementIntervalSeconds = errors.New("policy: invalid advertisement_interval_seconds")
	ErrInvalidAuditDepthPerDevicePerEpoch  = errors.New("policy: invalid audit_depth_per_device_per_epoch")
	ErrInvalidMaxMemberDevices             = errors.New("policy: invalid max_member_devices")
	ErrInvalidMaxActiveAgentSessions       = errors.New("policy: invalid max_active_agent_sessions")
	ErrInvalidClusterMinApplyLevel         = errors.New("policy: invalid cluster_min_apply_level")
	ErrClusterMinApplyLevelDecrease        = errors.New("policy: cluster_min_apply_level cannot decrease")
	ErrInvalidOperation                    = errors.New("policy: invalid transition operation")
	ErrInvalidTransition                   = errors.New("policy: invalid transition")
	ErrSessionChanged                      = errors.New("policy: session changed outside recovery")
	ErrInvalidVersionTransition            = errors.New("policy: invalid entity-version transition")
	ErrRecoveryValuesChanged               = errors.New("policy: recovery changed committed values")
)

// Values is the complete closed set of policy.changed values in V1. It is a
// full resulting value, not a sparse patch.
type Values struct {
	CheckpointEvents             int64
	CheckpointIntervalSeconds    int64
	LeaseMinTTLSeconds           int64
	LeaseDefaultTTLSeconds       int64
	LeaseMaxTTLSeconds           int64
	AgentClaimLimit              int64
	AgentLeaseLimit              int64
	DeviceClaimLimit             int64
	DeviceLeaseLimit             int64
	AdvertisementIntervalSeconds int64
	AuditDepthPerDevicePerEpoch  int64
	MaxMemberDevices             int64
	MaxActiveAgentSessions       int64
	ClusterMinApplyLevel         int64
}

// DefaultValues returns the authoritative V1 genesis defaults.
func DefaultValues() Values {
	return Values{
		CheckpointEvents:             DefaultCheckpointEvents,
		CheckpointIntervalSeconds:    DefaultCheckpointIntervalSeconds,
		LeaseMinTTLSeconds:           DefaultLeaseMinTTLSeconds,
		LeaseDefaultTTLSeconds:       DefaultLeaseTTLSeconds,
		LeaseMaxTTLSeconds:           DefaultLeaseMaxTTLSeconds,
		AgentClaimLimit:              DefaultAgentClaimLimit,
		AgentLeaseLimit:              DefaultAgentLeaseLimit,
		DeviceClaimLimit:             DefaultDeviceClaimLimit,
		DeviceLeaseLimit:             DefaultDeviceLeaseLimit,
		AdvertisementIntervalSeconds: DefaultAdvertisementIntervalSeconds,
		AuditDepthPerDevicePerEpoch:  DefaultAuditDepthPerDevicePerEpoch,
		MaxMemberDevices:             DefaultMemberDevices,
		MaxActiveAgentSessions:       DefaultActiveAgentSessions,
		ClusterMinApplyLevel:         DefaultClusterMinApplyLevel,
	}
}

// Validate checks immutable V1 bounds and relations. Current-use and active
// device capability checks require committed rows and belong in reducers.
func (values Values) Validate() error {
	checks := [...]struct {
		value int64
		min   int64
		max   int64
		err   error
	}{
		{values.CheckpointEvents, MinCheckpointEvents, MaxCheckpointEvents, ErrInvalidCheckpointEvents},
		{
			values.CheckpointIntervalSeconds,
			MinCheckpointIntervalSeconds,
			MaxCheckpointIntervalSeconds,
			ErrInvalidCheckpointIntervalSeconds,
		},
		{values.LeaseMinTTLSeconds, MinLeaseTTLSeconds, MaxLeaseTTLSeconds, ErrInvalidLeaseMinTTLSeconds},
		{
			values.LeaseDefaultTTLSeconds,
			MinLeaseTTLSeconds,
			MaxLeaseTTLSeconds,
			ErrInvalidLeaseDefaultTTLSeconds,
		},
		{values.LeaseMaxTTLSeconds, MinLeaseTTLSeconds, MaxLeaseTTLSeconds, ErrInvalidLeaseMaxTTLSeconds},
		{values.AgentClaimLimit, MinAgentClaimLimit, MaxAgentClaimLimit, ErrInvalidAgentClaimLimit},
		{values.AgentLeaseLimit, MinAgentLeaseLimit, MaxAgentLeaseLimit, ErrInvalidAgentLeaseLimit},
		{values.DeviceClaimLimit, MinDeviceClaimLimit, MaxDeviceClaimLimit, ErrInvalidDeviceClaimLimit},
		{values.DeviceLeaseLimit, MinDeviceLeaseLimit, MaxDeviceLeaseLimit, ErrInvalidDeviceLeaseLimit},
		{
			values.AdvertisementIntervalSeconds,
			MinAdvertisementIntervalSeconds,
			MaxAdvertisementIntervalSeconds,
			ErrInvalidAdvertisementIntervalSeconds,
		},
		{
			values.AuditDepthPerDevicePerEpoch,
			MinAuditDepthPerDevicePerEpoch,
			MaxAuditDepthPerDevicePerEpoch,
			ErrInvalidAuditDepthPerDevicePerEpoch,
		},
		{values.MaxMemberDevices, MinMemberDevices, MaxMemberDevices, ErrInvalidMaxMemberDevices},
		{
			values.MaxActiveAgentSessions,
			MinActiveAgentSessions,
			MaxActiveAgentSessions,
			ErrInvalidMaxActiveAgentSessions,
		},
		{
			values.ClusterMinApplyLevel,
			MinClusterMinApplyLevel,
			MaxClusterMinApplyLevel,
			ErrInvalidClusterMinApplyLevel,
		},
	}
	for _, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%w: got %d, want %d..%d", check.err, check.value, check.min, check.max)
		}
	}

	if values.LeaseMinTTLSeconds > values.LeaseDefaultTTLSeconds ||
		values.LeaseDefaultTTLSeconds > values.LeaseMaxTTLSeconds {
		return fmt.Errorf(
			"%w: got %d <= %d <= %d",
			ErrInvalidLeaseTTLOrder,
			values.LeaseMinTTLSeconds,
			values.LeaseDefaultTTLSeconds,
			values.LeaseMaxTTLSeconds,
		)
	}
	if values.DeviceClaimLimit < values.AgentClaimLimit {
		return fmt.Errorf(
			"%w: got %d < %d",
			ErrInvalidClaimLimitRelation,
			values.DeviceClaimLimit,
			values.AgentClaimLimit,
		)
	}
	if values.DeviceLeaseLimit < values.AgentLeaseLimit {
		return fmt.Errorf(
			"%w: got %d < %d",
			ErrInvalidLeaseLimitRelation,
			values.DeviceLeaseLimit,
			values.AgentLeaseLimit,
		)
	}
	return nil
}

// Policy is the sole mutable-policy entity for a session.
type Policy struct {
	SessionID     domain.UUIDv7
	Values        Values
	EntityVersion uint64
}

// Operation identifies an event or recovery transform that mutates Policy.
type Operation string

const (
	OperationChange        Operation = "policy.changed"
	OperationRecoveryReset Operation = "recovery.session_policy"
)

var operations = [...]Operation{OperationChange, OperationRecoveryReset}

// Valid reports whether operation is a closed V1 policy operation.
func (operation Operation) Valid() bool {
	return operation == OperationChange || operation == OperationRecoveryReset
}

// Operations returns all policy operations in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// Validate verifies the policy's pure persisted invariants.
func (policy Policy) Validate() error {
	if !policy.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, policy.SessionID)
	}
	if policy.EntityVersion < 1 || !domain.ValidUnsignedInteger(policy.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	return policy.Values.Validate()
}

// ValidateTransition checks a complete policy mutation. Actor authority,
// expected-version CAS, current-use guards, and active-device capability checks
// remain reducer concerns.
func ValidateTransition(operation Operation, before, after Policy) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if err := before.Validate(); err != nil {
		return fmt.Errorf("%w: invalid source: %w", ErrInvalidTransition, err)
	}
	if err := after.Validate(); err != nil {
		return fmt.Errorf("%w: invalid destination: %w", ErrInvalidTransition, err)
	}

	switch operation {
	case OperationChange:
		if after.SessionID != before.SessionID {
			return fmt.Errorf(
				"%w: %q -> %q",
				ErrSessionChanged,
				before.SessionID,
				after.SessionID,
			)
		}
		if before.EntityVersion >= domain.MaxSafeInteger ||
			after.EntityVersion != before.EntityVersion+1 {
			return fmt.Errorf(
				"%w: got %d -> %d",
				ErrInvalidVersionTransition,
				before.EntityVersion,
				after.EntityVersion,
			)
		}
		if err := ValidateClusterMinApplyLevelChange(
			before.Values.ClusterMinApplyLevel,
			after.Values.ClusterMinApplyLevel,
		); err != nil {
			return err
		}
	case OperationRecoveryReset:
		if after.SessionID == before.SessionID || after.EntityVersion != 1 {
			return fmt.Errorf(
				"%w: recovery must remap the session and reset version to 1",
				ErrInvalidTransition,
			)
		}
		if after.Values != before.Values {
			return ErrRecoveryValuesChanged
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

// ValidateClusterMinApplyLevelChange checks the pure monotonicity rule. Whether
// active devices support next requires committed device rows and is deliberately
// outside this package.
func ValidateClusterMinApplyLevelChange(current, next int64) error {
	if current < MinClusterMinApplyLevel || current > MaxClusterMinApplyLevel {
		return fmt.Errorf(
			"%w: current %d is outside %d..%d",
			ErrInvalidClusterMinApplyLevel,
			current,
			MinClusterMinApplyLevel,
			MaxClusterMinApplyLevel,
		)
	}
	if next < MinClusterMinApplyLevel || next > MaxClusterMinApplyLevel {
		return fmt.Errorf(
			"%w: next %d is outside %d..%d",
			ErrInvalidClusterMinApplyLevel,
			next,
			MinClusterMinApplyLevel,
			MaxClusterMinApplyLevel,
		)
	}
	if next < current {
		return fmt.Errorf("%w: %d to %d", ErrClusterMinApplyLevelDecrease, current, next)
	}
	return nil
}
