// Package lease defines the advisory lease entity, its bounded path-pattern
// grammar, and its pure lifecycle and intersection rules.
package lease

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MinTTLSeconds   int64 = 30
	MaxTTLSeconds   int64 = 86_400
	MaxPathPatterns       = 32
)

// Scope identifies the resource class reserved by a lease.
type Scope string

const (
	ScopeTask Scope = "task"
	ScopePath Scope = "path"
)

var scopes = [...]Scope{ScopeTask, ScopePath}

// Valid reports whether scope is a closed V1 lease scope.
func (scope Scope) Valid() bool {
	switch scope {
	case ScopeTask, ScopePath:
		return true
	default:
		return false
	}
}

// Scopes returns every lease scope in stable order.
func Scopes() []Scope {
	result := make([]Scope, len(scopes))
	copy(result, scopes[:])
	return result
}

// Fields contains the scalar fields used to construct a Lease. TaskID is
// required for task scope and is an optional association for path scope.
type Fields struct {
	ID                   domain.UUIDv7
	HolderDeviceID       domain.DeviceID
	HolderAgentSessionID domain.UUIDv7
	Scope                Scope
	TaskID               domain.UUIDv7
	TTLSeconds           int64
	Status               Status
	ReleaseReason        ReleaseReason
	EntityVersion        uint64
}

// Lease is a committed advisory reservation. Its path patterns use
// fixed-capacity value storage so a Lease cannot alias caller-owned slices.
type Lease struct {
	ID                   domain.UUIDv7
	HolderDeviceID       domain.DeviceID
	HolderAgentSessionID domain.UUIDv7
	Scope                Scope
	TaskID               domain.UUIDv7
	TTLSeconds           int64
	Status               Status
	ReleaseReason        ReleaseReason
	EntityVersion        uint64

	pathPatterns     [MaxPathPatterns]PathPattern
	pathPatternCount uint8
}

var (
	ErrInvalidID                   = errors.New("lease: invalid ID")
	ErrInvalidHolderDeviceID       = errors.New("lease: invalid holder device ID")
	ErrInvalidHolderAgentSessionID = errors.New("lease: invalid holder agent session ID")
	ErrInvalidScope                = errors.New("lease: invalid scope")
	ErrInvalidTaskID               = errors.New("lease: invalid task ID")
	ErrInvalidTTL                  = errors.New("lease: invalid TTL")
	ErrInvalidTTLPolicy            = errors.New("lease: invalid TTL policy")
	ErrInvalidEntityVersion        = errors.New("lease: invalid entity version")
)

// New validates scalar fields, validates raw pattern cardinality, normalizes
// path patterns, and copies all values into a Lease.
func New(fields Fields, rawPathPatterns []string) (Lease, error) {
	lease := Lease{
		ID:                   fields.ID,
		HolderDeviceID:       fields.HolderDeviceID,
		HolderAgentSessionID: fields.HolderAgentSessionID,
		Scope:                fields.Scope,
		TaskID:               fields.TaskID,
		TTLSeconds:           fields.TTLSeconds,
		Status:               fields.Status,
		ReleaseReason:        fields.ReleaseReason,
		EntityVersion:        fields.EntityVersion,
	}

	switch fields.Scope {
	case ScopeTask:
		if len(rawPathPatterns) != 0 {
			return Lease{}, fmt.Errorf(
				"%w: task scope requires zero, got %d",
				ErrInvalidPathPatternCount,
				len(rawPathPatterns),
			)
		}
	case ScopePath:
		patterns, err := NormalizePathPatterns(rawPathPatterns)
		if err != nil {
			return Lease{}, err
		}
		copy(lease.pathPatterns[:], patterns)
		lease.pathPatternCount = uint8(len(patterns))
	default:
		return Lease{}, fmt.Errorf("%w: %q", ErrInvalidScope, fields.Scope)
	}

	if err := lease.Validate(); err != nil {
		return Lease{}, err
	}
	return lease, nil
}

// Validate verifies local persisted invariants. Actor binding, task
// ownership, active-lease caps, CAS, and committed-set scans belong in
// reducers.
func (lease Lease) Validate() error {
	if !lease.ID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, lease.ID)
	}
	if !lease.HolderDeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidHolderDeviceID, lease.HolderDeviceID)
	}
	if !lease.HolderAgentSessionID.Valid() {
		return fmt.Errorf(
			"%w: %q",
			ErrInvalidHolderAgentSessionID,
			lease.HolderAgentSessionID,
		)
	}
	if !lease.Scope.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidScope, lease.Scope)
	}
	if err := lease.validateScopedValues(); err != nil {
		return err
	}
	if err := ValidateRequestedTTL(lease.TTLSeconds, MinTTLSeconds, MaxTTLSeconds); err != nil {
		return err
	}
	if err := lease.Lifecycle().Validate(); err != nil {
		return err
	}
	if lease.EntityVersion < 1 || !domain.ValidUnsignedInteger(lease.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// PathPatterns returns a copy of the lease's sorted unique patterns.
func (lease Lease) PathPatterns() []PathPattern {
	if lease.pathPatternCount == 0 {
		return nil
	}
	result := make([]PathPattern, int(lease.pathPatternCount))
	copy(result, lease.pathPatterns[:lease.pathPatternCount])
	return result
}

// Lifecycle returns the fields governed by lifecycle operations.
func (lease Lease) Lifecycle() Lifecycle {
	return Lifecycle{
		Status:        lease.Status,
		ReleaseReason: lease.ReleaseReason,
	}
}

func (lease Lease) validateScopedValues() error {
	count := int(lease.pathPatternCount)
	switch lease.Scope {
	case ScopeTask:
		if !lease.TaskID.Valid() {
			return fmt.Errorf("%w: task scope requires UUIDv7", ErrInvalidTaskID)
		}
		if count != 0 {
			return fmt.Errorf(
				"%w: task scope requires zero, got %d",
				ErrInvalidPathPatternCount,
				count,
			)
		}
	case ScopePath:
		if lease.TaskID != "" && !lease.TaskID.Valid() {
			return fmt.Errorf("%w: malformed optional association", ErrInvalidTaskID)
		}
		if count < 1 || count > MaxPathPatterns {
			return fmt.Errorf(
				"%w: got %d, want 1..%d",
				ErrInvalidPathPatternCount,
				count,
				MaxPathPatterns,
			)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidScope, lease.Scope)
	}

	var previous string
	for index, pattern := range lease.pathPatterns[:count] {
		if !pattern.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidPathPattern, index)
		}
		current := pattern.String()
		if index > 0 && previous >= current {
			return fmt.Errorf(
				"%w: entries %d and %d",
				ErrPathPatternsNotSortedUnique,
				index-1,
				index,
			)
		}
		previous = current
	}
	return nil
}

// ValidateRequestedTTL validates an event TTL against both immutable V1 hard
// bounds and the current committed minimum and maximum.
func ValidateRequestedTTL(ttl, minimum, maximum int64) error {
	if minimum < MinTTLSeconds ||
		minimum > MaxTTLSeconds ||
		maximum < MinTTLSeconds ||
		maximum > MaxTTLSeconds ||
		minimum > maximum {
		return fmt.Errorf(
			"%w: minimum=%d maximum=%d, hard range %d..%d",
			ErrInvalidTTLPolicy,
			minimum,
			maximum,
			MinTTLSeconds,
			MaxTTLSeconds,
		)
	}
	if ttl < minimum || ttl > maximum {
		return fmt.Errorf(
			"%w: got %d, want %d..%d",
			ErrInvalidTTL,
			ttl,
			minimum,
			maximum,
		)
	}
	return nil
}
