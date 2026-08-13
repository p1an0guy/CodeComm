// Package plan defines immutable plan revisions and the current-plan pointer.
package plan

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	// MaxTitleBytes is the inclusive UTF-8 byte limit for a revision title.
	MaxTitleBytes = 200
	// MaxBodyBytes is the inclusive UTF-8 byte limit for a revision body.
	MaxBodyBytes = 65_536
	// MaxTaskIDs is the inclusive number of tasks a revision may organize.
	MaxTaskIDs = 512
)

var (
	// ErrInvalidRevisionID reports a malformed plan revision identifier.
	ErrInvalidRevisionID = errors.New("plan: invalid revision ID")
	// ErrInvalidSupersedes reports a malformed superseded revision identifier.
	ErrInvalidSupersedes = errors.New("plan: invalid supersedes ID")
	// ErrSelfSupersession reports a revision that names itself as its predecessor.
	ErrSelfSupersession = errors.New("plan: revision cannot supersede itself")
	// ErrInvalidTitle reports a title outside the documented UTF-8 byte bounds.
	ErrInvalidTitle = errors.New("plan: invalid title")
	// ErrInvalidBody reports a body outside the documented UTF-8 byte bounds.
	ErrInvalidBody = errors.New("plan: invalid body")
	// ErrTooManyTaskIDs reports a task array above the immutable V1 limit.
	ErrTooManyTaskIDs = errors.New("plan: too many task IDs")
	// ErrInvalidTaskID reports a malformed task identifier.
	ErrInvalidTaskID = errors.New("plan: invalid task ID")
	// ErrTaskIDsNotSortedUnique reports a noncanonical task identifier array.
	ErrTaskIDsNotSortedUnique = errors.New("plan: task IDs are not sorted and unique")
	// ErrInvalidProposerDeviceID reports a malformed committed proposer.
	ErrInvalidProposerDeviceID = errors.New("plan: invalid proposer device ID")
	// ErrInvalidCreatedAt reports a noncanonical display timestamp.
	ErrInvalidCreatedAt = errors.New("plan: invalid created_at timestamp")
	// ErrInvalidSessionID reports a malformed current-pointer session identifier.
	ErrInvalidSessionID = errors.New("plan: invalid session ID")
	// ErrInvalidCurrentRevisionID reports a malformed non-null current revision.
	ErrInvalidCurrentRevisionID = errors.New("plan: invalid current revision ID")
	// ErrInvalidEntityVersion reports a current pointer outside the signed JSON range.
	ErrInvalidEntityVersion = errors.New("plan: invalid entity version")
	// ErrInvalidUnselectedVersion reports an unselected pointer beyond its only reachable version.
	ErrInvalidUnselectedVersion = errors.New(
		"plan: unselected current pointer must have entity version 1",
	)
	// ErrInvalidOperation reports an unknown current-pointer operation.
	ErrInvalidOperation = errors.New("plan: invalid current-pointer operation")
	// ErrInvalidTransition reports a malformed current-pointer mutation.
	ErrInvalidTransition = errors.New("plan: invalid current-pointer transition")
	// ErrCurrentSessionChanged reports a normal selection that changes row identity.
	ErrCurrentSessionChanged = errors.New("plan: current-pointer session changed")
	// ErrCurrentRevisionRequired reports a selection with a null revision.
	ErrCurrentRevisionRequired = errors.New("plan: current selection requires a revision")
	// ErrInvalidVersionTransition reports a skipped, repeated, or overflowing version.
	ErrInvalidVersionTransition = errors.New("plan: invalid current-pointer version transition")
)

// Revision is an immutable proposal for organizing work. Its fields are
// private so accepted revisions can only be created through NewRevision.
type Revision struct {
	id                 domain.UUIDv7
	supersedes         domain.UUIDv7
	title              string
	body               string
	taskIDs            []domain.UUIDv7
	proposedByDeviceID domain.DeviceID
	createdAt          domain.Timestamp
}

// NewRevision validates and defensively copies an immutable plan revision.
// An empty supersedes value represents null.
func NewRevision(
	id domain.UUIDv7,
	supersedes domain.UUIDv7,
	title string,
	body string,
	taskIDs []domain.UUIDv7,
	proposedByDeviceID domain.DeviceID,
	createdAt domain.Timestamp,
) (Revision, error) {
	revision := Revision{
		id:                 id,
		supersedes:         supersedes,
		title:              title,
		body:               body,
		taskIDs:            append([]domain.UUIDv7(nil), taskIDs...),
		proposedByDeviceID: proposedByDeviceID,
		createdAt:          createdAt,
	}
	if err := revision.Validate(); err != nil {
		return Revision{}, err
	}
	return revision, nil
}

// Validate verifies the revision's pure persisted invariants. Task and
// predecessor existence require committed rows and remain reducer concerns.
func (revision Revision) Validate() error {
	if !revision.id.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRevisionID, revision.id)
	}
	if revision.supersedes != "" {
		if !revision.supersedes.Valid() {
			return fmt.Errorf("%w: %q", ErrInvalidSupersedes, revision.supersedes)
		}
		if revision.supersedes == revision.id {
			return fmt.Errorf("%w: %q", ErrSelfSupersession, revision.id)
		}
	}
	if !validUTF8Bytes(revision.title, 1, MaxTitleBytes) {
		return fmt.Errorf(
			"%w: must be 1..%d UTF-8 bytes",
			ErrInvalidTitle,
			MaxTitleBytes,
		)
	}
	if !validUTF8Bytes(revision.body, 0, MaxBodyBytes) {
		return fmt.Errorf(
			"%w: must be at most %d UTF-8 bytes",
			ErrInvalidBody,
			MaxBodyBytes,
		)
	}
	if len(revision.taskIDs) > MaxTaskIDs {
		return fmt.Errorf(
			"%w: got %d, limit %d",
			ErrTooManyTaskIDs,
			len(revision.taskIDs),
			MaxTaskIDs,
		)
	}
	var previous domain.UUIDv7
	for index, taskID := range revision.taskIDs {
		if !taskID.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidTaskID, index)
		}
		if index > 0 && previous >= taskID {
			return fmt.Errorf(
				"%w: entries %d and %d",
				ErrTaskIDsNotSortedUnique,
				index-1,
				index,
			)
		}
		previous = taskID
	}
	if !revision.proposedByDeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidProposerDeviceID, revision.proposedByDeviceID)
	}
	if !revision.createdAt.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCreatedAt, revision.createdAt)
	}
	return nil
}

// ID returns the immutable revision identifier.
func (revision Revision) ID() domain.UUIDv7 {
	return revision.id
}

// Supersedes returns the drafted-against revision and whether it is present.
func (revision Revision) Supersedes() (domain.UUIDv7, bool) {
	return revision.supersedes, revision.supersedes != ""
}

// Title returns the immutable revision title.
func (revision Revision) Title() string {
	return revision.title
}

// Body returns the immutable revision body.
func (revision Revision) Body() string {
	return revision.body
}

// TaskIDs returns a defensive copy of the canonical task identifier array.
func (revision Revision) TaskIDs() []domain.UUIDv7 {
	return append([]domain.UUIDv7(nil), revision.taskIDs...)
}

// ProposedByDeviceID returns the committed proposer device identifier.
func (revision Revision) ProposedByDeviceID() domain.DeviceID {
	return revision.proposedByDeviceID
}

// CreatedAt returns the display-only canonical creation timestamp.
func (revision Revision) CreatedAt() domain.Timestamp {
	return revision.createdAt
}

// Current is the sole mutable pointer to a session's selected plan revision.
// RevisionID is empty until a revision is selected.
type Current struct {
	SessionID     domain.UUIDv7
	RevisionID    domain.UUIDv7
	EntityVersion uint64
}

// Operation identifies an event or recovery transform that mutates Current.
type Operation string

const (
	OperationSelect        Operation = "plan.current_selected"
	OperationRecoveryReset Operation = "recovery.plan_current"
)

var operations = [...]Operation{OperationSelect, OperationRecoveryReset}

// Valid reports whether operation is a closed V1 current-pointer operation.
func (operation Operation) Valid() bool {
	return operation == OperationSelect || operation == OperationRecoveryReset
}

// Operations returns all current-pointer operations in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// Validate verifies the current pointer's pure persisted invariants. Revision
// existence and compare-and-set authorization remain reducer concerns.
func (current Current) Validate() error {
	if !current.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, current.SessionID)
	}
	if current.RevisionID != "" && !current.RevisionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCurrentRevisionID, current.RevisionID)
	}
	if current.EntityVersion < 1 || !domain.ValidUnsignedInteger(current.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	if current.RevisionID == "" && current.EntityVersion != 1 {
		return fmt.Errorf(
			"%w: got %d",
			ErrInvalidUnselectedVersion,
			current.EntityVersion,
		)
	}
	return nil
}

// ValidateTransition checks a complete current-plan mutation. Revision
// existence, actor authority, and expected-version CAS remain reducer
// concerns.
func ValidateTransition(operation Operation, before, after Current) error {
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
	case OperationSelect:
		if after.SessionID != before.SessionID {
			return fmt.Errorf(
				"%w: %q -> %q",
				ErrCurrentSessionChanged,
				before.SessionID,
				after.SessionID,
			)
		}
		if after.RevisionID == "" {
			return ErrCurrentRevisionRequired
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
	case OperationRecoveryReset:
		if after.SessionID == before.SessionID ||
			after.RevisionID != before.RevisionID ||
			after.EntityVersion != 1 {
			return fmt.Errorf(
				"%w: recovery must remap the session, preserve the revision, and reset version to 1",
				ErrInvalidTransition,
			)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

func validUTF8Bytes(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum
}
