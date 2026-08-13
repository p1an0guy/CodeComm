package device

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestTransitionTableAcceptsExactlyDocumentedRules(t *testing.T) {
	t.Parallel()

	type transition struct {
		operation Operation
		from      Status
		to        Status
	}
	legal := map[transition]struct{}{
		{OperationAdmission, StatusAbsent, StatusActive}:                     {},
		{OperationReadmission, StatusRequiresReadmission, StatusActive}:      {},
		{OperationVersionReport, StatusActive, StatusActive}:                 {},
		{OperationRoleChange, StatusActive, StatusActive}:                    {},
		{OperationOwnerRecovery, StatusActive, StatusActive}:                 {},
		{OperationRevocation, StatusActive, StatusRevoked}:                   {},
		{OperationRevocation, StatusRequiresReadmission, StatusRevoked}:      {},
		{OperationRecoveryRetain, StatusActive, StatusActive}:                {},
		{OperationRecoveryDemotion, StatusActive, StatusRequiresReadmission}: {},
		{
			OperationRecoveryDemotion,
			StatusRequiresReadmission,
			StatusRequiresReadmission,
		}: {},
		{OperationRecoveryPreserve, StatusRevoked, StatusRevoked}: {},
	}

	statuses := append([]Status{StatusAbsent}, Statuses()...)
	for _, operation := range Operations() {
		for _, from := range statuses {
			for _, to := range Statuses() {
				candidate := transition{operation: operation, from: from, to: to}
				_, want := legal[candidate]
				before, after := transitionEntities(operation, from, to)

				err := ValidateTransition(operation, before, after)
				if got := err == nil; got != want {
					t.Errorf(
						"ValidateTransition(%q, %q, %q) error = %v, accepted = %t, want %t",
						operation,
						from,
						to,
						err,
						got,
						want,
					)
				}
			}
		}
	}
}

func TestRevokedIsTerminal(t *testing.T) {
	t.Parallel()

	if !StatusRevoked.Terminal() {
		t.Fatal("StatusRevoked.Terminal() = false")
	}
	for _, operation := range Operations() {
		for _, to := range Statuses() {
			if operation == OperationRecoveryPreserve && to == StatusRevoked {
				continue
			}
			before, after := transitionEntities(operation, StatusRevoked, to)
			if err := ValidateTransition(operation, before, after); !errors.Is(err, ErrInvalidTransition) {
				t.Errorf(
					"ValidateTransition(%q, %q, %q) error = %v, want %v",
					operation,
					StatusRevoked,
					to,
					err,
					ErrInvalidTransition,
				)
			}
		}
	}

	before, after := transitionEntities(
		OperationRecoveryPreserve,
		StatusRevoked,
		StatusRevoked,
	)
	if err := ValidateTransition(OperationRecoveryPreserve, before, after); err != nil {
		t.Fatalf("recovery preservation of revoked row error = %v", err)
	}
}

func TestReadmissionRequiresSameEnrolledIdentity(t *testing.T) {
	t.Parallel()

	before := deviceWithStatus(StatusRequiresReadmission)
	after := validDevice()
	after.Status = StatusActive
	after.Role = RoleOwner
	after.DaemonVersion = "2.0.0"
	after.MaxApplyLevel = 2
	after.EntityVersion = before.EntityVersion + 1

	if err := ValidateTransition(OperationReadmission, before, after); err != nil {
		t.Fatalf("ValidateTransition() with same identity error = %v", err)
	}

	changedKey := append([]byte(nil), after.IdentityPublicKey...)
	changedKey[0] ^= 0xff
	after.IdentityPublicKey = changedKey
	derivedID, err := DeriveID(after.IdentityPublicKey)
	if err != nil {
		t.Fatalf("DeriveID(changed key) error = %v", err)
	}
	after.ID = derivedID

	if err := ValidateTransition(OperationReadmission, before, after); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("ValidateTransition() with changed identity error = %v, want %v", err, ErrIdentityChanged)
	}
}

func TestLifecycleEnforcesEntityVersionProgression(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		before    *Device
		after     Device
	}{
		{
			name:      "admission does not start at one",
			operation: OperationAdmission,
			before:    nil,
			after: func() Device {
				value := validDevice()
				value.EntityVersion = 2
				return value
			}(),
		},
		{
			name:      "existing mutation does not increment",
			operation: OperationRevocation,
			before:    deviceWithStatus(StatusActive),
			after: func() Device {
				value := deviceValueWithStatus(StatusRevoked)
				value.EntityVersion = 1
				return value
			}(),
		},
		{
			name:      "existing mutation skips a version",
			operation: OperationRevocation,
			before:    deviceWithStatus(StatusActive),
			after: func() Device {
				value := deviceValueWithStatus(StatusRevoked)
				value.EntityVersion = 3
				return value
			}(),
		},
		{
			name:      "recovery does not reset to one",
			operation: OperationRecoveryDemotion,
			before: func() *Device {
				value := deviceValueWithStatus(StatusActive)
				value.EntityVersion = 42
				return &value
			}(),
			after: func() Device {
				value := deviceValueWithStatus(StatusRequiresReadmission)
				value.EntityVersion = 2
				return value
			}(),
		},
		{
			name:      "mutation from maximum version",
			operation: OperationRevocation,
			before: func() *Device {
				value := deviceValueWithStatus(StatusActive)
				value.EntityVersion = domain.MaxSafeInteger
				return &value
			}(),
			after: func() Device {
				value := deviceValueWithStatus(StatusRevoked)
				value.EntityVersion = domain.MaxSafeInteger
				return value
			}(),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.operation, test.before, test.after); !errors.Is(err, ErrInvalidVersionTransition) {
				t.Fatalf("ValidateTransition() error = %v, want ErrInvalidVersionTransition", err)
			}
		})
	}
}

func TestRecoveryTransitionsResetEntityVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      Status
		to        Status
	}{
		{
			name:      "recovering member retained",
			operation: OperationRecoveryRetain,
			from:      StatusActive,
			to:        StatusActive,
		},
		{
			name:      "active peer demoted",
			operation: OperationRecoveryDemotion,
			from:      StatusActive,
			to:        StatusRequiresReadmission,
		},
		{
			name:      "readmission-required peer preserved",
			operation: OperationRecoveryDemotion,
			from:      StatusRequiresReadmission,
			to:        StatusRequiresReadmission,
		},
		{
			name:      "revoked peer preserved",
			operation: OperationRecoveryPreserve,
			from:      StatusRevoked,
			to:        StatusRevoked,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			before, after := transitionEntities(test.operation, test.from, test.to)
			before.EntityVersion = domain.MaxSafeInteger
			after.EntityVersion = 1
			if err := ValidateTransition(test.operation, before, after); err != nil {
				t.Fatalf("ValidateTransition() error = %v", err)
			}
		})
	}
}

func TestMembershipMutationOperationsEnforceFieldChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		mutate    func(*Device, *Device)
		want      error
	}{
		{
			name:      "version report must change",
			operation: OperationVersionReport,
			mutate: func(before, after *Device) {
				after.DaemonVersion = before.DaemonVersion
			},
			want: ErrRequiredMutation,
		},
		{
			name:      "version report cannot change role",
			operation: OperationVersionReport,
			mutate: func(_ *Device, after *Device) {
				after.Role = RoleOwner
			},
			want: ErrUnexpectedMutation,
		},
		{
			name:      "role change must change role",
			operation: OperationRoleChange,
			mutate: func(before, after *Device) {
				after.Role = before.Role
			},
			want: ErrRequiredMutation,
		},
		{
			name:      "role change cannot change version report",
			operation: OperationRoleChange,
			mutate: func(_ *Device, after *Device) {
				after.MaxApplyLevel++
			},
			want: ErrUnexpectedMutation,
		},
		{
			name:      "owner recovery requires editor source",
			operation: OperationOwnerRecovery,
			mutate: func(before, _ *Device) {
				before.Role = RoleOwner
			},
			want: ErrRequiredMutation,
		},
		{
			name:      "owner recovery requires owner destination",
			operation: OperationOwnerRecovery,
			mutate: func(_, after *Device) {
				after.Role = RoleEditor
			},
			want: ErrRequiredMutation,
		},
		{
			name:      "owner recovery cannot change version report",
			operation: OperationOwnerRecovery,
			mutate: func(_ *Device, after *Device) {
				after.DaemonVersion = "3.0.0"
			},
			want: ErrUnexpectedMutation,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			before, after := transitionEntities(
				test.operation,
				StatusActive,
				StatusActive,
			)
			test.mutate(before, &after)
			if err := ValidateTransition(test.operation, before, after); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNonReadmissionTransitionsChangeOnlyLifecycleFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		to        Status
		mutate    func(*Device)
	}{
		{
			name:      "revocation changes role",
			operation: OperationRevocation,
			to:        StatusRevoked,
			mutate: func(after *Device) {
				after.Role = RoleOwner
			},
		},
		{
			name:      "recovery changes daemon version",
			operation: OperationRecoveryDemotion,
			to:        StatusRequiresReadmission,
			mutate: func(after *Device) {
				after.DaemonVersion = "2.0.0"
			},
		},
		{
			name:      "recovery changes apply level",
			operation: OperationRecoveryDemotion,
			to:        StatusRequiresReadmission,
			mutate: func(after *Device) {
				after.MaxApplyLevel = 2
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := deviceWithStatus(StatusActive)
			after := *before
			after.Status = test.to
			if test.operation.recoveryBoundary() {
				after.EntityVersion = 1
			} else {
				after.EntityVersion++
			}
			test.mutate(&after)
			if err := ValidateTransition(test.operation, before, after); !errors.Is(err, ErrUnexpectedMutation) {
				t.Fatalf("ValidateTransition() error = %v, want ErrUnexpectedMutation", err)
			}
		})
	}
}

func TestLifecycleTransitionDoesNotMutateEntities(t *testing.T) {
	t.Parallel()

	before := deviceWithStatus(StatusRequiresReadmission)
	after := validDevice()
	after.Status = StatusActive
	after.EntityVersion = before.EntityVersion + 1
	beforeKey := append([]byte(nil), before.IdentityPublicKey...)
	afterKey := append([]byte(nil), after.IdentityPublicKey...)

	if err := ValidateTransition(OperationReadmission, before, after); err != nil {
		t.Fatalf("ValidateTransition() error = %v", err)
	}
	if !bytes.Equal(before.IdentityPublicKey, beforeKey) {
		t.Fatal("ValidateTransition() mutated before.IdentityPublicKey")
	}
	if !bytes.Equal(after.IdentityPublicKey, afterKey) {
		t.Fatal("ValidateTransition() mutated after.IdentityPublicKey")
	}
}

func TestTransitionTableRejectsUnknownAndMalformedValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		before    *Device
		after     Device
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("membership.unknown"),
			before:    nil,
			after:     validDevice(),
			want:      ErrInvalidOperation,
		},
		{
			name:      "unknown source status",
			operation: OperationRevocation,
			before:    deviceWithStatus(Status("unknown")),
			after:     deviceValueWithStatus(StatusRevoked),
			want:      ErrInvalidStatus,
		},
		{
			name:      "unknown destination status",
			operation: OperationAdmission,
			before:    nil,
			after:     deviceValueWithStatus(Status("unknown")),
			want:      ErrInvalidStatus,
		},
		{
			name:      "absent destination",
			operation: OperationRevocation,
			before:    deviceWithStatus(StatusActive),
			after:     deviceValueWithStatus(StatusAbsent),
			want:      ErrInvalidStatus,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateTransition(test.operation, test.before, test.after)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestTransitionValidatesLegalEdgeEntities(t *testing.T) {
	t.Parallel()

	before := deviceWithStatus(StatusRequiresReadmission)
	after := validDevice()
	after.Status = StatusActive
	after.EntityVersion = before.EntityVersion + 1
	after.DaemonVersion = "invalid"
	if err := ValidateTransition(OperationReadmission, before, after); !errors.Is(err, ErrInvalidDaemonVersion) {
		t.Fatalf("ValidateTransition() error = %v, want %v", err, ErrInvalidDaemonVersion)
	}

	before.DaemonVersion = "invalid"
	after.DaemonVersion = "1.2.3"
	if err := ValidateTransition(OperationReadmission, before, after); !errors.Is(err, ErrInvalidDaemonVersion) {
		t.Fatalf("ValidateTransition() with invalid prior entity error = %v, want %v", err, ErrInvalidDaemonVersion)
	}
}

func TestOperationsReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	operations := Operations()
	operations[0] = Operation("corrupt")
	if got := Operations()[0]; got != OperationAdmission {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationAdmission)
	}
}

func deviceWithStatus(status Status) *Device {
	if status == StatusAbsent {
		return nil
	}
	device := validDevice()
	device.Status = status
	return &device
}

func deviceValueWithStatus(status Status) Device {
	device := validDevice()
	device.Status = status
	if status != StatusActive {
		device.EntityVersion = 2
	}
	return device
}

func transitionEntities(operation Operation, from, to Status) (*Device, Device) {
	before := deviceWithStatus(from)
	after := validDevice()
	after.Status = to
	if before != nil {
		after = *before
		after.Status = to
		after.EntityVersion = before.EntityVersion + 1
	}

	switch operation {
	case OperationVersionReport:
		after.DaemonVersion = "2.0.0"
	case OperationRoleChange, OperationOwnerRecovery:
		after.Role = RoleOwner
	case OperationRecoveryRetain:
		after.Role = RoleOwner
		after.EntityVersion = 1
	case OperationRecoveryDemotion, OperationRecoveryPreserve:
		after.EntityVersion = 1
	}
	return before, after
}
