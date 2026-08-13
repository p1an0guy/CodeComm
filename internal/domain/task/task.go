package task

import (
	"errors"
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxTitleBytes       = 200
	MaxBodyBytes        = 8192
	MaxStateReasonBytes = 1024
	MaxBlockedBy        = 16
	MaxLabels           = 16
	MaxLabelBytes       = 32
	MaxPriority         = PriorityLowest
)

// Priority is a display-order hint. Lower values sort first.
type Priority uint8

const (
	PriorityHighest Priority = iota
	PriorityHigh
	PriorityNormal
	PriorityLowest
)

// ReleaseReason records why an owned task returned to ready.
type ReleaseReason string

const (
	ReleaseVoluntary  ReleaseReason = "voluntary"
	ReleaseForced     ReleaseReason = "forced"
	ReleaseSessionEnd ReleaseReason = "session_ended"
	ReleaseRecovery   ReleaseReason = "recovery"
)

// Valid reports whether reason is a closed V1 task release reason.
func (reason ReleaseReason) Valid() bool {
	switch reason {
	case ReleaseVoluntary, ReleaseForced, ReleaseSessionEnd, ReleaseRecovery:
		return true
	default:
		return false
	}
}

// Task is the committed projection of one unit of claimable work. CreatedAt
// and UpdatedAt are display-only canonical timestamps; reducers must not make
// decisions from their values.
type Task struct {
	ID                  domain.UUIDv7
	Title               string
	Body                string
	State               State
	StateReason         *string
	Priority            Priority
	BlockedBy           []domain.UUIDv7
	Labels              []string
	OwnerDeviceID       domain.DeviceID
	OwnerAgentSessionID domain.UUIDv7
	IntendedDeviceID    domain.DeviceID
	LastReleaseReason   ReleaseReason
	EntityVersion       uint64
	CreatedAt           domain.Timestamp
	UpdatedAt           domain.Timestamp
}

var (
	ErrInvalidID            = errors.New("task: invalid ID")
	ErrInvalidTitle         = errors.New("task: invalid title")
	ErrInvalidBody          = errors.New("task: invalid body")
	ErrInvalidStateReason   = errors.New("task: invalid state reason")
	ErrInvalidPriority      = errors.New("task: invalid priority")
	ErrInvalidBlockedBy     = errors.New("task: invalid blocked_by")
	ErrInvalidLabels        = errors.New("task: invalid labels")
	ErrInvalidOwnership     = errors.New("task: invalid ownership")
	ErrInvalidReleaseReason = errors.New("task: invalid release reason")
	ErrInvalidEntityVersion = errors.New("task: invalid entity version")
	ErrInvalidTimestamp     = errors.New("task: invalid timestamp")
)

// Validate verifies the task's local, persisted invariants. Checks requiring
// other committed rows, actor authorization, or policy belong in reducers.
func (task Task) Validate() error {
	if !task.ID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, task.ID)
	}
	if err := validateTitle(task.Title); err != nil {
		return err
	}
	if !validUTF8Bytes(task.Body, 0, MaxBodyBytes) {
		return fmt.Errorf("%w: must be valid UTF-8 and at most %d bytes", ErrInvalidBody, MaxBodyBytes)
	}
	if !task.State.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidState, task.State)
	}
	if err := task.validateStateReason(); err != nil {
		return err
	}
	if task.Priority > MaxPriority {
		return fmt.Errorf("%w: %d is outside 0..%d", ErrInvalidPriority, task.Priority, MaxPriority)
	}
	if err := task.validateBlockedBy(); err != nil {
		return err
	}
	if err := task.validateLabels(); err != nil {
		return err
	}
	if err := task.validateOwnership(); err != nil {
		return err
	}
	if task.LastReleaseReason != "" && !task.LastReleaseReason.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidReleaseReason, task.LastReleaseReason)
	}
	if task.EntityVersion < 1 || !domain.ValidUnsignedInteger(task.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	if !task.CreatedAt.Valid() {
		return fmt.Errorf("%w: created_at", ErrInvalidTimestamp)
	}
	if !task.UpdatedAt.Valid() {
		return fmt.Errorf("%w: updated_at", ErrInvalidTimestamp)
	}
	return nil
}

func validateTitle(title string) error {
	if !validUTF8Bytes(title, 1, MaxTitleBytes) {
		return fmt.Errorf(
			"%w: must be valid UTF-8 and between 1 and %d bytes",
			ErrInvalidTitle,
			MaxTitleBytes,
		)
	}
	for _, char := range title {
		if unicode.IsControl(char) || unicode.In(char, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%w: line/control character U+%04X", ErrInvalidTitle, char)
		}
	}
	return nil
}

func (task Task) validateStateReason() error {
	if task.State == StateBlocked {
		if task.StateReason == nil ||
			!validUTF8Bytes(*task.StateReason, 1, MaxStateReasonBytes) {
			return fmt.Errorf(
				"%w: blocked tasks require 1..%d UTF-8 bytes",
				ErrInvalidStateReason,
				MaxStateReasonBytes,
			)
		}
		return nil
	}
	if task.StateReason != nil {
		return fmt.Errorf("%w: prohibited in state %q", ErrInvalidStateReason, task.State)
	}
	return nil
}

func (task Task) validateBlockedBy() error {
	if len(task.BlockedBy) > MaxBlockedBy {
		return fmt.Errorf("%w: got %d entries, limit %d", ErrInvalidBlockedBy, len(task.BlockedBy), MaxBlockedBy)
	}
	var previous domain.UUIDv7
	for index, dependency := range task.BlockedBy {
		if !dependency.Valid() {
			return fmt.Errorf("%w: entry %d is not UUIDv7", ErrInvalidBlockedBy, index)
		}
		if dependency == task.ID {
			return fmt.Errorf("%w: task cannot depend on itself", ErrDependencyCycle)
		}
		if index > 0 && previous >= dependency {
			return fmt.Errorf("%w: entries must be sorted and unique", ErrInvalidBlockedBy)
		}
		previous = dependency
	}
	return nil
}

func (task Task) validateLabels() error {
	if len(task.Labels) > MaxLabels {
		return fmt.Errorf("%w: got %d entries, limit %d", ErrInvalidLabels, len(task.Labels), MaxLabels)
	}
	for index, label := range task.Labels {
		if !validUTF8Bytes(label, 0, MaxLabelBytes) {
			return fmt.Errorf(
				"%w: entry %d must be valid UTF-8 and at most %d bytes",
				ErrInvalidLabels,
				index,
				MaxLabelBytes,
			)
		}
		if index > 0 && task.Labels[index-1] >= label {
			return fmt.Errorf("%w: entries must be sorted and unique", ErrInvalidLabels)
		}
	}
	return nil
}

func (task Task) validateOwnership() error {
	hasDeviceOwner := task.OwnerDeviceID != ""
	hasSessionOwner := task.OwnerAgentSessionID != ""
	if hasDeviceOwner != hasSessionOwner {
		return fmt.Errorf("%w: owner IDs must both be set or both be null", ErrInvalidOwnership)
	}
	if hasDeviceOwner && (!task.OwnerDeviceID.Valid() || !task.OwnerAgentSessionID.Valid()) {
		return fmt.Errorf("%w: malformed owner ID", ErrInvalidOwnership)
	}

	requiresOwner := task.State == StateClaimed ||
		task.State == StateInProgress ||
		task.State == StateBlocked
	if requiresOwner != hasDeviceOwner {
		return fmt.Errorf("%w: state %q owner mismatch", ErrInvalidOwnership, task.State)
	}
	if hasDeviceOwner && task.LastReleaseReason != "" {
		return fmt.Errorf("%w: owned tasks cannot carry a release reason", ErrInvalidOwnership)
	}
	if task.IntendedDeviceID != "" && !task.IntendedDeviceID.Valid() {
		return fmt.Errorf("%w: malformed intended device ID", ErrInvalidOwnership)
	}
	if hasDeviceOwner && task.IntendedDeviceID != "" {
		return fmt.Errorf("%w: an owned task cannot retain an intended device", ErrInvalidOwnership)
	}
	if task.State.Terminal() && task.IntendedDeviceID != "" {
		return fmt.Errorf("%w: terminal tasks cannot name an intended device", ErrInvalidOwnership)
	}
	return nil
}

// NormalizeLabels validates the raw array before returning a sorted,
// deduplicated copy suitable for projection.
func NormalizeLabels(labels []string) ([]string, error) {
	if len(labels) > MaxLabels {
		return nil, fmt.Errorf("%w: got %d entries, limit %d", ErrInvalidLabels, len(labels), MaxLabels)
	}
	for index, label := range labels {
		if !validUTF8Bytes(label, 0, MaxLabelBytes) {
			return nil, fmt.Errorf(
				"%w: entry %d must be valid UTF-8 and at most %d bytes",
				ErrInvalidLabels,
				index,
				MaxLabelBytes,
			)
		}
	}
	if len(labels) == 0 {
		return nil, nil
	}
	result := append([]string(nil), labels...)
	sort.Strings(result)
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write], nil
}

// Actionable reports the derived predicate after the reducer has evaluated
// cross-entity dependency and conflict state.
func (task Task) Actionable(allDependenciesDone, hasUnresolvedConflict bool) bool {
	return task.State == StateReady && allDependenciesDone && !hasUnresolvedConflict
}

// ClaimableBy adds the one-shot intended-device restriction to Actionable.
func (task Task) ClaimableBy(
	deviceID domain.DeviceID,
	allDependenciesDone bool,
	hasUnresolvedConflict bool,
) bool {
	if !deviceID.Valid() || !task.Actionable(allDependenciesDone, hasUnresolvedConflict) {
		return false
	}
	return task.IntendedDeviceID == "" || task.IntendedDeviceID == deviceID
}

func validUTF8Bytes(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum
}
