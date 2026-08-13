// Package voterset defines the committed consensus-target value.
package voterset

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxVoters = 5

var (
	ErrInvalidSessionID        = errors.New("voterset: invalid session ID")
	ErrInvalidVoterCount       = errors.New("voterset: invalid voter count")
	ErrInvalidVoterDeviceID    = errors.New("voterset: invalid voter device ID")
	ErrVotersNotSortedUnique   = errors.New("voterset: voters are not sorted and unique")
	ErrInvalidVoterSetVersion  = errors.New("voterset: invalid voter-set version")
	ErrInvalidOperation        = errors.New("voterset: invalid transition operation")
	ErrInvalidTransition       = errors.New("voterset: invalid transition")
	ErrSessionChanged          = errors.New("voterset: session changed outside recovery")
	ErrTargetUnchanged         = errors.New("voterset: voter target is unchanged")
	ErrTargetChanged           = errors.New("voterset: voter target changed")
	ErrInvalidVersionChange    = errors.New("voterset: invalid voter-set version transition")
	ErrInvalidRevocationTarget = errors.New("voterset: invalid target-voter revocation target")
	ErrInvalidRecoveryTarget   = errors.New("voterset: recovery target must contain one voter")
)

// Set is a committed voter target, not the Raft library's live configuration.
// Voter IDs use private fixed-capacity storage so copies of Set cannot alias a
// caller-owned slice.
type Set struct {
	SessionID       domain.UUIDv7
	VoterSetVersion uint64

	voterDeviceIDs [MaxVoters]domain.DeviceID
	voterCount     uint8
}

// Operation identifies an event or recovery transform that mutates Set.
type Operation string

const (
	OperationChange                Operation = "membership.voter_set_changed"
	OperationTargetVoterRevocation Operation = "membership.device_revoked.target_voter"
	OperationNonvoterRevocation    Operation = "membership.device_revoked.nonvoter"
	OperationRecoveryReset         Operation = "recovery.voter_set"
)

var operations = [...]Operation{
	OperationChange,
	OperationTargetVoterRevocation,
	OperationNonvoterRevocation,
	OperationRecoveryReset,
}

// Valid reports whether operation is a closed V1 voter-set operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationChange,
		OperationTargetVoterRevocation,
		OperationNonvoterRevocation,
		OperationRecoveryReset:
		return true
	default:
		return false
	}
}

// Operations returns all voter-set operations in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// New validates and copies a complete active-form voter target.
func New(sessionID domain.UUIDv7, voterDeviceIDs []domain.DeviceID, version uint64) (Set, error) {
	if !validVoterCount(len(voterDeviceIDs)) {
		return Set{}, fmt.Errorf(
			"%w: got %d, want 1, 3, or 5",
			ErrInvalidVoterCount,
			len(voterDeviceIDs),
		)
	}

	set := Set{
		SessionID:       sessionID,
		VoterSetVersion: version,
		voterCount:      uint8(len(voterDeviceIDs)),
	}
	copy(set.voterDeviceIDs[:], voterDeviceIDs)
	if err := set.Validate(); err != nil {
		return Set{}, err
	}
	return set, nil
}

// Validate checks the target's pure persisted invariants. Membership status
// and admission checks require committed device rows and belong in reducers.
func (set Set) Validate() error {
	if !set.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, set.SessionID)
	}
	if set.VoterSetVersion < 1 || !domain.ValidUnsignedInteger(set.VoterSetVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidVoterSetVersion,
			domain.MaxSafeInteger,
		)
	}
	count := int(set.voterCount)
	if !validVoterCount(count) {
		return fmt.Errorf("%w: got %d, want 1, 3, or 5", ErrInvalidVoterCount, count)
	}

	var previous domain.DeviceID
	for index, id := range set.voterDeviceIDs[:count] {
		if !id.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidVoterDeviceID, index)
		}
		if index > 0 && previous >= id {
			return fmt.Errorf("%w: entries %d and %d", ErrVotersNotSortedUnique, index-1, index)
		}
		previous = id
	}
	return nil
}

// VoterDeviceIDs returns a copy of the sorted voter target.
func (set Set) VoterDeviceIDs() []domain.DeviceID {
	result := make([]domain.DeviceID, set.voterCount)
	copy(result, set.voterDeviceIDs[:set.voterCount])
	return result
}

// Contains reports whether deviceID belongs to this valid target.
func (set Set) Contains(deviceID domain.DeviceID) bool {
	if !deviceID.Valid() || set.Validate() != nil {
		return false
	}
	for _, candidate := range set.voterDeviceIDs[:set.voterCount] {
		if candidate == deviceID {
			return true
		}
	}
	return false
}

// SameTarget reports whether both valid sets contain the same sorted voter
// IDs. Session identity and voter-set version are deliberately ignored.
func (set Set) SameTarget(other Set) bool {
	if set.Validate() != nil || other.Validate() != nil ||
		set.voterCount != other.voterCount {
		return false
	}
	for index := range set.voterCount {
		if set.voterDeviceIDs[index] != other.voterDeviceIDs[index] {
			return false
		}
	}
	return true
}

// ValidateTransition checks a complete voter-target mutation. Active
// membership, actor authority, expected-version CAS, the revoked subject, and
// revocation-specific authority checks remain reducer concerns.
func ValidateTransition(operation Operation, before, after Set) error {
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
		if err := validateSameSession(before, after); err != nil {
			return err
		}
		if before.VoterSetVersion >= domain.MaxSafeInteger ||
			after.VoterSetVersion != before.VoterSetVersion+1 {
			return fmt.Errorf(
				"%w: got %d -> %d",
				ErrInvalidVersionChange,
				before.VoterSetVersion,
				after.VoterSetVersion,
			)
		}
		if before.SameTarget(after) {
			return ErrTargetUnchanged
		}
	case OperationTargetVoterRevocation:
		if err := validateSameSession(before, after); err != nil {
			return err
		}
		if before.VoterSetVersion >= domain.MaxSafeInteger ||
			after.VoterSetVersion != before.VoterSetVersion+1 {
			return fmt.Errorf(
				"%w: got %d -> %d",
				ErrInvalidVersionChange,
				before.VoterSetVersion,
				after.VoterSetVersion,
			)
		}
		if int(after.voterCount) != nextLowerVoterCount(int(before.voterCount)) ||
			!targetContains(before, after) {
			return fmt.Errorf(
				"%w: target count %d -> %d",
				ErrInvalidRevocationTarget,
				before.voterCount,
				after.voterCount,
			)
		}
	case OperationNonvoterRevocation:
		if err := validateSameSession(before, after); err != nil {
			return err
		}
		if after.VoterSetVersion != before.VoterSetVersion {
			return fmt.Errorf(
				"%w: got %d -> %d",
				ErrInvalidVersionChange,
				before.VoterSetVersion,
				after.VoterSetVersion,
			)
		}
		if !before.SameTarget(after) {
			return ErrTargetChanged
		}
	case OperationRecoveryReset:
		if after.SessionID == before.SessionID || after.VoterSetVersion != 1 {
			return fmt.Errorf(
				"%w: recovery must remap the session and reset version to 1",
				ErrInvalidTransition,
			)
		}
		if after.voterCount != 1 {
			return fmt.Errorf("%w: got %d", ErrInvalidRecoveryTarget, after.voterCount)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

func validateSameSession(before, after Set) error {
	if after.SessionID == before.SessionID {
		return nil
	}
	return fmt.Errorf(
		"%w: %q -> %q",
		ErrSessionChanged,
		before.SessionID,
		after.SessionID,
	)
}

func nextLowerVoterCount(count int) int {
	switch count {
	case 5:
		return 3
	case 3:
		return 1
	default:
		return 0
	}
}

func targetContains(superset, subset Set) bool {
	for _, candidate := range subset.voterDeviceIDs[:subset.voterCount] {
		if !superset.Contains(candidate) {
			return false
		}
	}
	return true
}

func validVoterCount(count int) bool {
	return count == 1 || count == 3 || count == 5
}
