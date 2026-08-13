package lease

import (
	"errors"
	"fmt"
)

// Status is a committed lease lifecycle status.
type Status string

const (
	// StatusAbsent is the source sentinel used only by lease creation.
	StatusAbsent Status = ""

	StatusActive   Status = "active"
	StatusReleased Status = "released"
)

var statuses = [...]Status{StatusActive, StatusReleased}

// Valid reports whether status is a committed status. StatusAbsent is not a
// committed status.
func (status Status) Valid() bool {
	switch status {
	case StatusActive, StatusReleased:
		return true
	default:
		return false
	}
}

// Terminal reports whether no lifecycle transition may leave status.
func (status Status) Terminal() bool {
	return status == StatusReleased
}

// Statuses returns every committed status in stable lifecycle order.
func Statuses() []Status {
	result := make([]Status, len(statuses))
	copy(result, statuses[:])
	return result
}

// ReleaseReason records why an active lease became terminal.
type ReleaseReason string

const (
	// ReleaseReasonAbsent represents null on an active lease.
	ReleaseReasonAbsent ReleaseReason = ""

	ReleaseVoluntary    ReleaseReason = "voluntary"
	ReleaseForced       ReleaseReason = "forced"
	ReleaseExpired      ReleaseReason = "expired"
	ReleaseSessionEnded ReleaseReason = "session_ended"
	ReleaseRecovery     ReleaseReason = "recovery"
)

var releaseReasons = [...]ReleaseReason{
	ReleaseVoluntary,
	ReleaseForced,
	ReleaseExpired,
	ReleaseSessionEnded,
	ReleaseRecovery,
}

// Valid reports whether reason is a closed V1 lease release reason.
func (reason ReleaseReason) Valid() bool {
	switch reason {
	case ReleaseVoluntary,
		ReleaseForced,
		ReleaseExpired,
		ReleaseSessionEnded,
		ReleaseRecovery:
		return true
	default:
		return false
	}
}

// ReleaseReasons returns every release reason in stable order.
func ReleaseReasons() []ReleaseReason {
	result := make([]ReleaseReason, len(releaseReasons))
	copy(result, releaseReasons[:])
	return result
}

// Operation identifies the event or boundary transform responsible for a
// lifecycle edge. Actor and role checks remain reducer concerns.
type Operation string

const (
	OperationCreate           Operation = "lease.acquired"
	OperationRenew            Operation = "lease.renewed"
	OperationReleaseVoluntary Operation = "lease.released.voluntary"
	OperationReleaseForced    Operation = "lease.released.forced"
	OperationReleaseExpired   Operation = "lease.released.expired"
	OperationSessionEnded     Operation = "agent.session.ended"
	OperationRecoveryRelease  Operation = "recovery.release"
)

var operations = [...]Operation{
	OperationCreate,
	OperationRenew,
	OperationReleaseVoluntary,
	OperationReleaseForced,
	OperationReleaseExpired,
	OperationSessionEnded,
	OperationRecoveryRelease,
}

// Valid reports whether operation is a closed V1 lifecycle operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationCreate,
		OperationRenew,
		OperationReleaseVoluntary,
		OperationReleaseForced,
		OperationReleaseExpired,
		OperationSessionEnded,
		OperationRecoveryRelease:
		return true
	default:
		return false
	}
}

// Operations returns every lifecycle operation in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// Lifecycle contains fields changed by lease lifecycle operations.
type Lifecycle struct {
	Status        Status
	ReleaseReason ReleaseReason
}

var (
	ErrInvalidStatus        = errors.New("lease: invalid status")
	ErrInvalidReleaseReason = errors.New("lease: invalid release reason")
	ErrInvalidOperation     = errors.New("lease: invalid transition operation")
	ErrInvalidTransition    = errors.New("lease: invalid transition")
)

// Validate verifies persisted status and release-reason consistency.
func (lifecycle Lifecycle) Validate() error {
	if !lifecycle.Status.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, lifecycle.Status)
	}
	switch lifecycle.Status {
	case StatusActive:
		if lifecycle.ReleaseReason != ReleaseReasonAbsent {
			return fmt.Errorf(
				"%w: prohibited in status %q",
				ErrInvalidReleaseReason,
				lifecycle.Status,
			)
		}
	case StatusReleased:
		if !lifecycle.ReleaseReason.Valid() {
			return fmt.Errorf(
				"%w: released lease requires a closed reason, got %q",
				ErrInvalidReleaseReason,
				lifecycle.ReleaseReason,
			)
		}
	}
	return nil
}

type lifecycleTransition struct {
	from Lifecycle
	to   Lifecycle
}

var legalLifecycleTransitions = map[Operation]lifecycleTransition{
	OperationCreate: {
		from: Lifecycle{},
		to:   Lifecycle{Status: StatusActive},
	},
	OperationRenew: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusActive},
	},
	OperationReleaseVoluntary: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusReleased, ReleaseReason: ReleaseVoluntary},
	},
	OperationReleaseForced: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusReleased, ReleaseReason: ReleaseForced},
	},
	OperationReleaseExpired: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusReleased, ReleaseReason: ReleaseExpired},
	},
	OperationSessionEnded: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusReleased, ReleaseReason: ReleaseSessionEnded},
	},
	OperationRecoveryRelease: {
		from: Lifecycle{Status: StatusActive},
		to:   Lifecycle{Status: StatusReleased, ReleaseReason: ReleaseRecovery},
	},
}

// ValidateTransition rejects every lifecycle edge not assigned to operation.
// Actor binding, authorization, CAS, and version increments remain reducer
// concerns.
func ValidateTransition(operation Operation, from, to Lifecycle) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if err := validateTransitionSource(from); err != nil {
		return err
	}
	if err := to.Validate(); err != nil {
		return err
	}
	want := legalLifecycleTransitions[operation]
	if from != want.from || to != want.to {
		return fmt.Errorf(
			"%w: %s %#v -> %#v",
			ErrInvalidTransition,
			operation,
			from,
			to,
		)
	}
	return nil
}

func validateTransitionSource(from Lifecycle) error {
	if from.Status == StatusAbsent {
		if from.ReleaseReason != ReleaseReasonAbsent {
			return fmt.Errorf(
				"%w: absent source cannot carry %q",
				ErrInvalidReleaseReason,
				from.ReleaseReason,
			)
		}
		return nil
	}
	return from.Validate()
}
