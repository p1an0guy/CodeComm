// Package memory defines immutable shared-context records and supersession
// compatibility.
package memory

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	// MaxKeyBytes is the inclusive UTF-8 byte limit for a memory key.
	MaxKeyBytes = 128
	// MaxBodyBytes is the inclusive UTF-8 byte limit for a memory body.
	MaxBodyBytes = 16_384
)

// Scope determines whether a memory record belongs to the whole session or
// one task.
type Scope string

const (
	// ScopeSession requires a null task identifier.
	ScopeSession Scope = "session"
	// ScopeTask requires a valid task identifier.
	ScopeTask Scope = "task"
)

var scopes = [...]Scope{ScopeSession, ScopeTask}

// Valid reports whether scope is a closed V1 memory scope.
func (scope Scope) Valid() bool {
	return scope == ScopeSession || scope == ScopeTask
}

// Scopes returns all V1 memory scopes in stable order.
func Scopes() []Scope {
	result := make([]Scope, len(scopes))
	copy(result, scopes[:])
	return result
}

var (
	// ErrInvalidID reports a malformed memory record identifier.
	ErrInvalidID = errors.New("memory: invalid ID")
	// ErrInvalidScope reports a scope outside the closed V1 enum.
	ErrInvalidScope = errors.New("memory: invalid scope")
	// ErrInvalidTaskID reports a malformed or scope-inconsistent task ID.
	ErrInvalidTaskID = errors.New("memory: invalid task ID")
	// ErrInvalidKey reports a key outside the documented UTF-8 byte bounds.
	ErrInvalidKey = errors.New("memory: invalid key")
	// ErrInvalidBody reports a body outside the documented UTF-8 byte bounds.
	ErrInvalidBody = errors.New("memory: invalid body")
	// ErrInvalidSupersedes reports a malformed superseded record identifier.
	ErrInvalidSupersedes = errors.New("memory: invalid supersedes ID")
	// ErrSelfSupersession reports a record that names itself as predecessor.
	ErrSelfSupersession = errors.New("memory: record cannot supersede itself")
	// ErrInvalidCreatedAt reports a noncanonical display timestamp.
	ErrInvalidCreatedAt = errors.New("memory: invalid created_at timestamp")
	// ErrPredecessorMismatch reports a supplied row other than the declared predecessor.
	ErrPredecessorMismatch = errors.New("memory: supplied predecessor does not match supersedes ID")
	// ErrIncompatiblePredecessor reports a cross-scope, cross-task, or cross-key correction.
	ErrIncompatiblePredecessor = errors.New("memory: incompatible predecessor")
)

// Record is one immutable durable shared-context value. Its fields are private
// so accepted records can only be created through NewRecord.
type Record struct {
	id         domain.UUIDv7
	scope      Scope
	taskID     domain.UUIDv7
	key        string
	body       string
	supersedes domain.UUIDv7
	createdAt  domain.Timestamp
}

// NewRecord validates an immutable memory record. Empty taskID and supersedes
// values represent null.
func NewRecord(
	id domain.UUIDv7,
	scope Scope,
	taskID domain.UUIDv7,
	key string,
	body string,
	supersedes domain.UUIDv7,
	createdAt domain.Timestamp,
) (Record, error) {
	record := Record{
		id:         id,
		scope:      scope,
		taskID:     taskID,
		key:        key,
		body:       body,
		supersedes: supersedes,
		createdAt:  createdAt,
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Validate verifies the record's pure persisted invariants. Task and
// predecessor existence and predecessor-chain occupancy remain reducer
// concerns.
func (record Record) Validate() error {
	if !record.id.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, record.id)
	}
	if !record.scope.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidScope, record.scope)
	}
	switch record.scope {
	case ScopeSession:
		if record.taskID != "" {
			return fmt.Errorf("%w: session scope requires null", ErrInvalidTaskID)
		}
	case ScopeTask:
		if !record.taskID.Valid() {
			return fmt.Errorf("%w: task scope requires UUIDv7", ErrInvalidTaskID)
		}
	}
	if !validUTF8Bytes(record.key, 1, MaxKeyBytes) {
		return fmt.Errorf("%w: must be 1..%d UTF-8 bytes", ErrInvalidKey, MaxKeyBytes)
	}
	if !validUTF8Bytes(record.body, 0, MaxBodyBytes) {
		return fmt.Errorf("%w: must be at most %d UTF-8 bytes", ErrInvalidBody, MaxBodyBytes)
	}
	if record.supersedes != "" {
		if !record.supersedes.Valid() {
			return fmt.Errorf("%w: %q", ErrInvalidSupersedes, record.supersedes)
		}
		if record.supersedes == record.id {
			return fmt.Errorf("%w: %q", ErrSelfSupersession, record.id)
		}
	}
	if !record.createdAt.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCreatedAt, record.createdAt)
	}
	return nil
}

// ValidatePredecessor checks a supplied predecessor against the successor's
// declaration and immutable correction-chain key. Lookup, existence, and
// already-superseded checks require committed state and remain reducer work.
func ValidatePredecessor(successor, predecessor Record) error {
	if successor.id == predecessor.id {
		return fmt.Errorf("%w: %q", ErrSelfSupersession, successor.id)
	}
	if err := successor.Validate(); err != nil {
		return fmt.Errorf("memory: invalid successor: %w", err)
	}
	if err := predecessor.Validate(); err != nil {
		return fmt.Errorf("memory: invalid predecessor: %w", err)
	}
	if successor.supersedes == "" || successor.supersedes != predecessor.id {
		return fmt.Errorf(
			"%w: declared %q, supplied %q",
			ErrPredecessorMismatch,
			successor.supersedes,
			predecessor.id,
		)
	}
	if successor.scope != predecessor.scope ||
		successor.taskID != predecessor.taskID ||
		successor.key != predecessor.key {
		return fmt.Errorf(
			"%w: (%q, %q, %q) != (%q, %q, %q)",
			ErrIncompatiblePredecessor,
			successor.scope,
			successor.taskID,
			successor.key,
			predecessor.scope,
			predecessor.taskID,
			predecessor.key,
		)
	}
	return nil
}

// ID returns the immutable memory identifier.
func (record Record) ID() domain.UUIDv7 {
	return record.id
}

// Scope returns the immutable memory scope.
func (record Record) Scope() Scope {
	return record.scope
}

// TaskID returns the task identifier and whether one is present.
func (record Record) TaskID() (domain.UUIDv7, bool) {
	return record.taskID, record.taskID != ""
}

// Key returns the immutable memory namespace hint.
func (record Record) Key() string {
	return record.key
}

// Body returns the immutable memory body.
func (record Record) Body() string {
	return record.body
}

// Supersedes returns the predecessor identifier and whether one is present.
func (record Record) Supersedes() (domain.UUIDv7, bool) {
	return record.supersedes, record.supersedes != ""
}

// CreatedAt returns the display-only canonical creation timestamp.
func (record Record) CreatedAt() domain.Timestamp {
	return record.createdAt
}

func validUTF8Bytes(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum
}
