package policy

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	otherSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
)

func TestDefaultValuesAreExactAndValid(t *testing.T) {
	t.Parallel()

	want := Values{
		CheckpointEvents:             500,
		CheckpointIntervalSeconds:    300,
		LeaseMinTTLSeconds:           30,
		LeaseDefaultTTLSeconds:       900,
		LeaseMaxTTLSeconds:           3600,
		AgentClaimLimit:              8,
		AgentLeaseLimit:              32,
		DeviceClaimLimit:             64,
		DeviceLeaseLimit:             256,
		AdvertisementIntervalSeconds: 20,
		AuditDepthPerDevicePerEpoch:  256,
		MaxMemberDevices:             8,
		MaxActiveAgentSessions:       32,
		ClusterMinApplyLevel:         1,
	}

	got := DefaultValues()
	if got != want {
		t.Fatalf("DefaultValues() = %+v, want %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("DefaultValues().Validate() error = %v", err)
	}
}

func TestValuesValidateAcceptsInclusiveRawBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values Values
	}{
		{
			name: "all minima",
			values: Values{
				CheckpointEvents:             100,
				CheckpointIntervalSeconds:    60,
				LeaseMinTTLSeconds:           30,
				LeaseDefaultTTLSeconds:       30,
				LeaseMaxTTLSeconds:           30,
				AgentClaimLimit:              1,
				AgentLeaseLimit:              1,
				DeviceClaimLimit:             1,
				DeviceLeaseLimit:             1,
				AdvertisementIntervalSeconds: 5,
				AuditDepthPerDevicePerEpoch:  16,
				MaxMemberDevices:             1,
				MaxActiveAgentSessions:       1,
				ClusterMinApplyLevel:         1,
			},
		},
		{
			name: "all maxima",
			values: Values{
				CheckpointEvents:             10_000,
				CheckpointIntervalSeconds:    3_600,
				LeaseMinTTLSeconds:           86_400,
				LeaseDefaultTTLSeconds:       86_400,
				LeaseMaxTTLSeconds:           86_400,
				AgentClaimLimit:              64,
				AgentLeaseLimit:              256,
				DeviceClaimLimit:             256,
				DeviceLeaseLimit:             1_024,
				AdvertisementIntervalSeconds: 300,
				AuditDepthPerDevicePerEpoch:  1_024,
				MaxMemberDevices:             8,
				MaxActiveAgentSessions:       32,
				ClusterMinApplyLevel:         2_147_483_647,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.values.Validate(); err != nil {
				t.Fatalf("Values.Validate() error = %v", err)
			}
		})
	}
}

func TestValuesValidateRejectsOnePastEveryRawBound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Values)
		want   error
	}{
		{"checkpoint events below", func(v *Values) { v.CheckpointEvents = 99 }, ErrInvalidCheckpointEvents},
		{"checkpoint events above", func(v *Values) { v.CheckpointEvents = 10_001 }, ErrInvalidCheckpointEvents},
		{"checkpoint interval below", func(v *Values) { v.CheckpointIntervalSeconds = 59 }, ErrInvalidCheckpointIntervalSeconds},
		{"checkpoint interval above", func(v *Values) { v.CheckpointIntervalSeconds = 3_601 }, ErrInvalidCheckpointIntervalSeconds},
		{"lease minimum below", func(v *Values) { v.LeaseMinTTLSeconds = 29 }, ErrInvalidLeaseMinTTLSeconds},
		{"lease minimum above", func(v *Values) { v.LeaseMinTTLSeconds = 86_401 }, ErrInvalidLeaseMinTTLSeconds},
		{"lease default below", func(v *Values) { v.LeaseDefaultTTLSeconds = 29 }, ErrInvalidLeaseDefaultTTLSeconds},
		{"lease default above", func(v *Values) { v.LeaseDefaultTTLSeconds = 86_401 }, ErrInvalidLeaseDefaultTTLSeconds},
		{"lease maximum below", func(v *Values) { v.LeaseMaxTTLSeconds = 29 }, ErrInvalidLeaseMaxTTLSeconds},
		{"lease maximum above", func(v *Values) { v.LeaseMaxTTLSeconds = 86_401 }, ErrInvalidLeaseMaxTTLSeconds},
		{"agent claim below", func(v *Values) { v.AgentClaimLimit = 0 }, ErrInvalidAgentClaimLimit},
		{"agent claim above", func(v *Values) { v.AgentClaimLimit = 65 }, ErrInvalidAgentClaimLimit},
		{"agent lease below", func(v *Values) { v.AgentLeaseLimit = 0 }, ErrInvalidAgentLeaseLimit},
		{"agent lease above", func(v *Values) { v.AgentLeaseLimit = 257 }, ErrInvalidAgentLeaseLimit},
		{"device claim below", func(v *Values) { v.DeviceClaimLimit = 0 }, ErrInvalidDeviceClaimLimit},
		{"device claim above", func(v *Values) { v.DeviceClaimLimit = 257 }, ErrInvalidDeviceClaimLimit},
		{"device lease below", func(v *Values) { v.DeviceLeaseLimit = 0 }, ErrInvalidDeviceLeaseLimit},
		{"device lease above", func(v *Values) { v.DeviceLeaseLimit = 1_025 }, ErrInvalidDeviceLeaseLimit},
		{"advertisement interval below", func(v *Values) { v.AdvertisementIntervalSeconds = 4 }, ErrInvalidAdvertisementIntervalSeconds},
		{"advertisement interval above", func(v *Values) { v.AdvertisementIntervalSeconds = 301 }, ErrInvalidAdvertisementIntervalSeconds},
		{"audit depth below", func(v *Values) { v.AuditDepthPerDevicePerEpoch = 15 }, ErrInvalidAuditDepthPerDevicePerEpoch},
		{"audit depth above", func(v *Values) { v.AuditDepthPerDevicePerEpoch = 1_025 }, ErrInvalidAuditDepthPerDevicePerEpoch},
		{"member limit below", func(v *Values) { v.MaxMemberDevices = 0 }, ErrInvalidMaxMemberDevices},
		{"member limit above", func(v *Values) { v.MaxMemberDevices = 9 }, ErrInvalidMaxMemberDevices},
		{"agent session limit below", func(v *Values) { v.MaxActiveAgentSessions = 0 }, ErrInvalidMaxActiveAgentSessions},
		{"agent session limit above", func(v *Values) { v.MaxActiveAgentSessions = 33 }, ErrInvalidMaxActiveAgentSessions},
		{"cluster floor below", func(v *Values) { v.ClusterMinApplyLevel = 0 }, ErrInvalidClusterMinApplyLevel},
		{"cluster floor above", func(v *Values) { v.ClusterMinApplyLevel = 2_147_483_648 }, ErrInvalidClusterMinApplyLevel},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := DefaultValues()
			test.mutate(&values)
			if err := values.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Values.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValuesValidateRejectsRelationalViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Values)
		want   error
	}{
		{
			name: "lease minimum exceeds default",
			mutate: func(values *Values) {
				values.LeaseMinTTLSeconds = values.LeaseDefaultTTLSeconds + 1
			},
			want: ErrInvalidLeaseTTLOrder,
		},
		{
			name: "lease default exceeds maximum",
			mutate: func(values *Values) {
				values.LeaseDefaultTTLSeconds = values.LeaseMaxTTLSeconds + 1
			},
			want: ErrInvalidLeaseTTLOrder,
		},
		{
			name: "device claim below agent claim",
			mutate: func(values *Values) {
				values.DeviceClaimLimit = values.AgentClaimLimit - 1
			},
			want: ErrInvalidClaimLimitRelation,
		},
		{
			name: "device lease below agent lease",
			mutate: func(values *Values) {
				values.DeviceLeaseLimit = values.AgentLeaseLimit - 1
			},
			want: ErrInvalidLeaseLimitRelation,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := DefaultValues()
			test.mutate(&values)
			if err := values.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Values.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPolicyValidateChecksCompleteEntity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Policy)
		want   error
	}{
		{
			name: "empty session ID",
			mutate: func(policy *Policy) {
				policy.SessionID = ""
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "non-v7 session ID",
			mutate: func(policy *Policy) {
				policy.SessionID = "550e8400-e29b-41d4-a716-446655440000"
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "zero entity version",
			mutate: func(policy *Policy) {
				policy.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version over signed JSON limit",
			mutate: func(policy *Policy) {
				policy.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "invalid values",
			mutate: func(policy *Policy) {
				policy.Values.CheckpointEvents = 99
			},
			want: ErrInvalidCheckpointEvents,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entity := validPolicy()
			test.mutate(&entity)
			if err := entity.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Policy.Validate() error = %v, want %v", err, test.want)
			}
		})
	}

	if err := validPolicy().Validate(); err != nil {
		t.Fatalf("valid Policy.Validate() error = %v", err)
	}
}

func TestPolicyValidateAcceptsEntityVersionBoundaries(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		entity := validPolicy()
		entity.EntityVersion = version
		if err := entity.Validate(); err != nil {
			t.Errorf("Policy.Validate() at entity version %d error = %v", version, err)
		}
	}
}

func TestValidateClusterMinApplyLevelChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current int64
		next    int64
		want    error
	}{
		{name: "minimum unchanged", current: 1, next: 1},
		{name: "increase", current: 1, next: 2},
		{name: "maximum unchanged", current: 2_147_483_647, next: 2_147_483_647},
		{name: "increase to maximum", current: 1, next: 2_147_483_647},
		{name: "current below range", current: 0, next: 1, want: ErrInvalidClusterMinApplyLevel},
		{name: "current above range", current: 2_147_483_648, next: 2_147_483_648, want: ErrInvalidClusterMinApplyLevel},
		{name: "next below range", current: 1, next: 0, want: ErrInvalidClusterMinApplyLevel},
		{name: "next above range", current: 1, next: 2_147_483_648, want: ErrInvalidClusterMinApplyLevel},
		{name: "decrease", current: 2, next: 1, want: ErrClusterMinApplyLevelDecrease},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateClusterMinApplyLevelChange(test.current, test.next)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"ValidateClusterMinApplyLevelChange(%d, %d) error = %v, want %v",
					test.current,
					test.next,
					err,
					test.want,
				)
			}
		})
	}
}

func TestPolicyTransitionAcceptsChangeAndRecoveryReset(t *testing.T) {
	t.Parallel()

	before := validPolicy()
	after := before
	after.Values.CheckpointEvents++
	after.EntityVersion++
	if err := ValidateTransition(OperationChange, before, after); err != nil {
		t.Fatalf("policy change error = %v", err)
	}

	before.EntityVersion = domain.MaxSafeInteger
	recovered := before
	recovered.SessionID = otherSessionID
	recovered.EntityVersion = 1
	if err := ValidateTransition(OperationRecoveryReset, before, recovered); err != nil {
		t.Fatalf("policy recovery reset error = %v", err)
	}
}

func TestPolicyTransitionRejectsUnsafeMutations(t *testing.T) {
	t.Parallel()

	before := validPolicy()
	before.EntityVersion = 7
	changed := before
	changed.Values.CheckpointEvents++
	changed.EntityVersion++
	recovered := before
	recovered.SessionID = otherSessionID
	recovered.EntityVersion = 1

	tests := []struct {
		name      string
		operation Operation
		before    Policy
		after     Policy
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("policy.unknown"),
			before:    before,
			after:     changed,
			want:      ErrInvalidOperation,
		},
		{
			name:      "invalid source",
			operation: OperationChange,
			before:    Policy{},
			after:     changed,
			want:      ErrInvalidTransition,
		},
		{
			name:      "invalid destination",
			operation: OperationChange,
			before:    before,
			after:     Policy{},
			want:      ErrInvalidTransition,
		},
		{
			name:      "change replaces session",
			operation: OperationChange,
			before:    before,
			after: func() Policy {
				value := changed
				value.SessionID = otherSessionID
				return value
			}(),
			want: ErrSessionChanged,
		},
		{
			name:      "change repeats version",
			operation: OperationChange,
			before:    before,
			after: func() Policy {
				value := changed
				value.EntityVersion = before.EntityVersion
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "change skips version",
			operation: OperationChange,
			before:    before,
			after: func() Policy {
				value := changed
				value.EntityVersion++
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "change from maximum version",
			operation: OperationChange,
			before: func() Policy {
				value := before
				value.EntityVersion = domain.MaxSafeInteger
				return value
			}(),
			after: func() Policy {
				value := changed
				value.EntityVersion = domain.MaxSafeInteger
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "cluster floor decreases",
			operation: OperationChange,
			before: func() Policy {
				value := before
				value.Values.ClusterMinApplyLevel = 2
				return value
			}(),
			after: func() Policy {
				value := changed
				value.Values.ClusterMinApplyLevel = 1
				return value
			}(),
			want: ErrClusterMinApplyLevelDecrease,
		},
		{
			name:      "recovery keeps session",
			operation: OperationRecoveryReset,
			before:    before,
			after: func() Policy {
				value := recovered
				value.SessionID = validSessionID
				return value
			}(),
			want: ErrInvalidTransition,
		},
		{
			name:      "recovery does not reset version",
			operation: OperationRecoveryReset,
			before:    before,
			after: func() Policy {
				value := recovered
				value.EntityVersion = 2
				return value
			}(),
			want: ErrInvalidTransition,
		},
		{
			name:      "recovery changes values",
			operation: OperationRecoveryReset,
			before:    before,
			after: func() Policy {
				value := recovered
				value.Values.CheckpointEvents++
				return value
			}(),
			want: ErrRecoveryValuesChanged,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.operation, test.before, test.after); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOperationsReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	operations := Operations()
	operations[0] = Operation("corrupt")
	if got := Operations()[0]; got != OperationChange {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationChange)
	}
}

func validPolicy() Policy {
	return Policy{
		SessionID:     validSessionID,
		Values:        DefaultValues(),
		EntityVersion: 1,
	}
}
