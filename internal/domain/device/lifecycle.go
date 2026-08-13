package device

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

// Status is a device's committed membership lifecycle state.
type Status string

const (
	// StatusAbsent is the source sentinel used only by initial admission.
	StatusAbsent Status = ""

	StatusActive              Status = "active"
	StatusRequiresReadmission Status = "requires_readmission"
	StatusRevoked             Status = "revoked"
)

var statuses = [...]Status{
	StatusActive,
	StatusRequiresReadmission,
	StatusRevoked,
}

// Valid reports whether status is a committed device status. StatusAbsent is
// not a committed status.
func (status Status) Valid() bool {
	switch status {
	case StatusActive, StatusRequiresReadmission, StatusRevoked:
		return true
	default:
		return false
	}
}

// Terminal reports whether no lifecycle operation may leave status.
func (status Status) Terminal() bool {
	return status == StatusRevoked
}

// Statuses returns all committed device statuses in stable lifecycle order.
func Statuses() []Status {
	result := make([]Status, len(statuses))
	copy(result, statuses[:])
	return result
}

// Operation identifies the authority path responsible for a status change.
type Operation string

const (
	OperationAdmission        Operation = "membership.device_admitted.new"
	OperationReadmission      Operation = "membership.device_admitted.readmission"
	OperationVersionReport    Operation = "membership.version_reported"
	OperationRoleChange       Operation = "membership.role_changed"
	OperationOwnerRecovery    Operation = "membership.owner_recovered"
	OperationRevocation       Operation = "membership.device_revoked"
	OperationRecoveryRetain   Operation = "recovery.device_retained"
	OperationRecoveryDemotion Operation = "recovery.device_demoted"
	OperationRecoveryPreserve Operation = "recovery.device_preserved"
)

var operations = [...]Operation{
	OperationAdmission,
	OperationReadmission,
	OperationVersionReport,
	OperationRoleChange,
	OperationOwnerRecovery,
	OperationRevocation,
	OperationRecoveryRetain,
	OperationRecoveryDemotion,
	OperationRecoveryPreserve,
}

// Valid reports whether operation is a closed V1 device lifecycle operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationAdmission,
		OperationReadmission,
		OperationVersionReport,
		OperationRoleChange,
		OperationOwnerRecovery,
		OperationRevocation,
		OperationRecoveryRetain,
		OperationRecoveryDemotion,
		OperationRecoveryPreserve:
		return true
	default:
		return false
	}
}

// Operations returns all device lifecycle operations in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

var (
	ErrInvalidStatus            = errors.New("device: invalid status")
	ErrInvalidOperation         = errors.New("device: invalid transition operation")
	ErrInvalidTransition        = errors.New("device: invalid transition")
	ErrIdentityChanged          = errors.New("device: enrolled identity changed")
	ErrInvalidVersionTransition = errors.New("device: invalid entity-version transition")
	ErrUnexpectedMutation       = errors.New("device: lifecycle operation changed an unrelated field")
	ErrRequiredMutation         = errors.New("device: lifecycle operation did not make its required change")
)

type edge struct {
	from Status
	to   Status
}

var legalTransitions = map[Operation]map[edge]struct{}{
	OperationAdmission: {
		{from: StatusAbsent, to: StatusActive}: {},
	},
	OperationReadmission: {
		{from: StatusRequiresReadmission, to: StatusActive}: {},
	},
	OperationVersionReport: {
		{from: StatusActive, to: StatusActive}: {},
	},
	OperationRoleChange: {
		{from: StatusActive, to: StatusActive}: {},
	},
	OperationOwnerRecovery: {
		{from: StatusActive, to: StatusActive}: {},
	},
	OperationRevocation: {
		{from: StatusActive, to: StatusRevoked}:              {},
		{from: StatusRequiresReadmission, to: StatusRevoked}: {},
	},
	OperationRecoveryRetain: {
		{from: StatusActive, to: StatusActive}: {},
	},
	OperationRecoveryDemotion: {
		{from: StatusActive, to: StatusRequiresReadmission}:              {},
		{from: StatusRequiresReadmission, to: StatusRequiresReadmission}: {},
	},
	OperationRecoveryPreserve: {
		{from: StatusRevoked, to: StatusRevoked}: {},
	},
}

// ValidateTransition validates one operation-specific lifecycle edge and both
// entity values. A nil before value denotes an identity that has never been
// admitted. Existing identity and key fields are immutable. Recovery
// operations implement §3.1's version-one successor baseline; actor,
// authorization, version-CAS, and cross-row checks remain reducer concerns.
func ValidateTransition(operation Operation, before *Device, after Device) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}

	from := StatusAbsent
	if before != nil {
		from = before.Status
		if !from.Valid() {
			return fmt.Errorf("%w: source %q", ErrInvalidStatus, from)
		}
	}
	if !after.Status.Valid() {
		return fmt.Errorf("%w: destination %q", ErrInvalidStatus, after.Status)
	}
	if _, ok := legalTransitions[operation][edge{from: from, to: after.Status}]; !ok {
		return fmt.Errorf(
			"%w: %s %q -> %q",
			ErrInvalidTransition,
			operation,
			from,
			after.Status,
		)
	}

	if before != nil {
		if err := before.Validate(); err != nil {
			return fmt.Errorf("device: invalid source entity: %w", err)
		}
		if before.ID != after.ID ||
			!bytes.Equal(before.IdentityPublicKey, after.IdentityPublicKey) {
			return fmt.Errorf("%w: %q -> %q", ErrIdentityChanged, before.ID, after.ID)
		}
	}
	if err := after.Validate(); err != nil {
		return fmt.Errorf("device: invalid destination entity: %w", err)
	}
	if before == nil {
		if after.EntityVersion != 1 {
			return fmt.Errorf(
				"%w: admission starts at 1, got %d",
				ErrInvalidVersionTransition,
				after.EntityVersion,
			)
		}
		return nil
	}
	if operation.recoveryBoundary() {
		if after.EntityVersion != 1 {
			return fmt.Errorf(
				"%w: recovery resets to 1, got %d",
				ErrInvalidVersionTransition,
				after.EntityVersion,
			)
		}
	} else if before.EntityVersion >= domain.MaxSafeInteger ||
		after.EntityVersion != before.EntityVersion+1 {
		return fmt.Errorf(
			"%w: got %d -> %d",
			ErrInvalidVersionTransition,
			before.EntityVersion,
			after.EntityVersion,
		)
	}

	switch operation {
	case OperationReadmission:
		return nil
	case OperationVersionReport:
		if before.Role != after.Role {
			return fmt.Errorf("%w: %s changed role", ErrUnexpectedMutation, operation)
		}
		if before.DaemonVersion == after.DaemonVersion &&
			before.MaxApplyLevel == after.MaxApplyLevel {
			return fmt.Errorf("%w: %s", ErrRequiredMutation, operation)
		}
	case OperationRoleChange:
		if !sameVersionReport(*before, after) {
			return fmt.Errorf("%w: %s changed version report", ErrUnexpectedMutation, operation)
		}
		if before.Role == after.Role {
			return fmt.Errorf("%w: %s", ErrRequiredMutation, operation)
		}
	case OperationOwnerRecovery:
		if !sameVersionReport(*before, after) {
			return fmt.Errorf("%w: %s changed version report", ErrUnexpectedMutation, operation)
		}
		if before.Role != RoleEditor || after.Role != RoleOwner {
			return fmt.Errorf("%w: %s requires editor -> owner", ErrRequiredMutation, operation)
		}
	case OperationRecoveryRetain:
		if !sameVersionReport(*before, after) {
			return fmt.Errorf("%w: %s changed version report", ErrUnexpectedMutation, operation)
		}
		if after.Role != RoleOwner {
			return fmt.Errorf("%w: %s requires owner destination", ErrRequiredMutation, operation)
		}
	case OperationRevocation, OperationRecoveryDemotion, OperationRecoveryPreserve:
		if before.Role != after.Role || !sameVersionReport(*before, after) {
			return fmt.Errorf("%w: %s", ErrUnexpectedMutation, operation)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

func (operation Operation) recoveryBoundary() bool {
	switch operation {
	case OperationRecoveryRetain, OperationRecoveryDemotion, OperationRecoveryPreserve:
		return true
	default:
		return false
	}
}

func sameVersionReport(left, right Device) bool {
	return left.DaemonVersion == right.DaemonVersion &&
		left.MaxApplyLevel == right.MaxApplyLevel
}
