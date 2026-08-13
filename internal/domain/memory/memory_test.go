package memory

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validMemoryID     = domain.UUIDv7("01890f47-3e72-7000-8000-000000000101")
	predecessorID     = domain.UUIDv7("01890f47-3e72-7000-8000-000000000102")
	otherMemoryID     = domain.UUIDv7("01890f47-3e72-7000-8000-000000000103")
	validTaskID       = domain.UUIDv7("01890f47-3e72-7000-8000-000000000104")
	otherTaskID       = domain.UUIDv7("01890f47-3e72-7000-8000-000000000105")
	validCreatedAt    = domain.Timestamp("2026-08-10T12:34:56.123456789Z")
	invalidUUIDv7     = domain.UUIDv7("550e8400-e29b-41d4-a716-446655440000")
	invalidCreatedAt  = domain.Timestamp("2026-08-10T12:34:56-07:00")
	defaultMemoryKey  = "architecture"
	defaultMemoryBody = ""
)

type recordInput struct {
	id         domain.UUIDv7
	scope      Scope
	taskID     domain.UUIDv7
	key        string
	body       string
	supersedes domain.UUIDv7
	createdAt  domain.Timestamp
}

func TestNewRecordAcceptsScopesNullabilityAndExactBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input recordInput
	}{
		{
			name: "session minimum",
			input: recordInput{
				id:        validMemoryID,
				scope:     ScopeSession,
				key:       "x",
				body:      "",
				createdAt: validCreatedAt,
			},
		},
		{
			name: "session maximum",
			input: recordInput{
				id:         validMemoryID,
				scope:      ScopeSession,
				key:        strings.Repeat("\u00e9", MaxKeyBytes/2),
				body:       strings.Repeat("\u00e9", MaxBodyBytes/2),
				supersedes: predecessorID,
				createdAt:  validCreatedAt,
			},
		},
		{
			name: "task",
			input: recordInput{
				id:        validMemoryID,
				scope:     ScopeTask,
				taskID:    validTaskID,
				key:       defaultMemoryKey,
				body:      defaultMemoryBody,
				createdAt: validCreatedAt,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRecord(test.input)
			if err != nil {
				t.Fatalf("NewRecord() error = %v", err)
			}
			if got.ID() != test.input.id {
				t.Errorf("Record.ID() = %q, want %q", got.ID(), test.input.id)
			}
			if got.Scope() != test.input.scope {
				t.Errorf("Record.Scope() = %q, want %q", got.Scope(), test.input.scope)
			}
			taskID, hasTaskID := got.TaskID()
			if taskID != test.input.taskID || hasTaskID != (test.input.taskID != "") {
				t.Errorf(
					"Record.TaskID() = (%q, %t), want (%q, %t)",
					taskID,
					hasTaskID,
					test.input.taskID,
					test.input.taskID != "",
				)
			}
			if got.Key() != test.input.key {
				t.Errorf("Record.Key() = %q, want %q", got.Key(), test.input.key)
			}
			if got.Body() != test.input.body {
				t.Errorf("Record.Body() differs from input")
			}
			supersedes, hasSupersedes := got.Supersedes()
			if supersedes != test.input.supersedes ||
				hasSupersedes != (test.input.supersedes != "") {
				t.Errorf(
					"Record.Supersedes() = (%q, %t), want (%q, %t)",
					supersedes,
					hasSupersedes,
					test.input.supersedes,
					test.input.supersedes != "",
				)
			}
			if got.CreatedAt() != test.input.createdAt {
				t.Errorf("Record.CreatedAt() = %q, want %q", got.CreatedAt(), test.input.createdAt)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Record.Validate() error = %v", err)
			}
		})
	}
}

func TestNewRecordRejectsInvalidFieldsAndOnePastBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*recordInput)
		want   error
	}{
		{
			name: "memory ID",
			mutate: func(input *recordInput) {
				input.id = invalidUUIDv7
			},
			want: ErrInvalidID,
		},
		{
			name: "unknown scope",
			mutate: func(input *recordInput) {
				input.scope = Scope("project")
			},
			want: ErrInvalidScope,
		},
		{
			name: "session with task ID",
			mutate: func(input *recordInput) {
				input.taskID = validTaskID
			},
			want: ErrInvalidTaskID,
		},
		{
			name: "task without task ID",
			mutate: func(input *recordInput) {
				input.scope = ScopeTask
			},
			want: ErrInvalidTaskID,
		},
		{
			name: "task with malformed task ID",
			mutate: func(input *recordInput) {
				input.scope = ScopeTask
				input.taskID = invalidUUIDv7
			},
			want: ErrInvalidTaskID,
		},
		{
			name: "empty key",
			mutate: func(input *recordInput) {
				input.key = ""
			},
			want: ErrInvalidKey,
		},
		{
			name: "key one byte over",
			mutate: func(input *recordInput) {
				input.key = strings.Repeat("x", MaxKeyBytes+1)
			},
			want: ErrInvalidKey,
		},
		{
			name: "body one byte over",
			mutate: func(input *recordInput) {
				input.body = strings.Repeat("x", MaxBodyBytes+1)
			},
			want: ErrInvalidBody,
		},
		{
			name: "malformed supersedes",
			mutate: func(input *recordInput) {
				input.supersedes = invalidUUIDv7
			},
			want: ErrInvalidSupersedes,
		},
		{
			name: "self supersession",
			mutate: func(input *recordInput) {
				input.supersedes = input.id
			},
			want: ErrSelfSupersession,
		},
		{
			name: "created timestamp",
			mutate: func(input *recordInput) {
				input.createdAt = invalidCreatedAt
			},
			want: ErrInvalidCreatedAt,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := validRecordInput()
			test.mutate(&input)
			got, err := newRecord(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRecord() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(got, Record{}) {
				t.Fatalf("NewRecord() returned nonzero Record after error")
			}
		})
	}
}

func TestNewRecordUsesUTF8ByteBoundsAndRejectsMalformedUTF8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		body string
		want error
	}{
		{
			name: "multibyte exact key",
			key:  strings.Repeat("\u00e9", MaxKeyBytes/2),
		},
		{
			name: "multibyte key over",
			key:  strings.Repeat("\u00e9", MaxKeyBytes/2+1),
			want: ErrInvalidKey,
		},
		{
			name: "malformed key",
			key:  string([]byte{0xff}),
			want: ErrInvalidKey,
		},
		{
			name: "multibyte exact body",
			key:  defaultMemoryKey,
			body: strings.Repeat("\u00e9", MaxBodyBytes/2),
		},
		{
			name: "multibyte body over",
			key:  defaultMemoryKey,
			body: strings.Repeat("\u00e9", MaxBodyBytes/2+1),
			want: ErrInvalidBody,
		},
		{
			name: "malformed body",
			key:  defaultMemoryKey,
			body: string([]byte{0xff}),
			want: ErrInvalidBody,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := validRecordInput()
			input.key = test.key
			input.body = test.body
			_, err := newRecord(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRecord() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestScopeIsClosedAndScopesReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	if !ScopeSession.Valid() || !ScopeTask.Valid() {
		t.Fatal("documented scope reported invalid")
	}
	for _, scope := range []Scope{"", "project", "TASK"} {
		if scope.Valid() {
			t.Errorf("Scope(%q).Valid() = true", scope)
		}
	}

	first := Scopes()
	if want := []Scope{ScopeSession, ScopeTask}; !reflect.DeepEqual(first, want) {
		t.Fatalf("Scopes() = %v, want %v", first, want)
	}
	first[0] = Scope("changed")
	if got := Scopes(); !reflect.DeepEqual(got, []Scope{ScopeSession, ScopeTask}) {
		t.Fatalf("mutation of Scopes result changed package state: %v", got)
	}
}

func TestValidatePredecessorAcceptsCompatibleSessionAndTaskRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope Scope
		task  domain.UUIDv7
	}{
		{name: "session", scope: ScopeSession},
		{name: "task", scope: ScopeTask, task: validTaskID},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			predecessor := mustRecord(t, recordInput{
				id:        predecessorID,
				scope:     test.scope,
				taskID:    test.task,
				key:       defaultMemoryKey,
				body:      "old",
				createdAt: validCreatedAt,
			})
			successor := mustRecord(t, recordInput{
				id:         validMemoryID,
				scope:      test.scope,
				taskID:     test.task,
				key:        defaultMemoryKey,
				body:       "new",
				supersedes: predecessorID,
				createdAt:  validCreatedAt,
			})

			if err := ValidatePredecessor(successor, predecessor); err != nil {
				t.Fatalf("ValidatePredecessor() error = %v", err)
			}
		})
	}
}

func TestValidatePredecessorRejectsRelationshipMismatch(t *testing.T) {
	t.Parallel()

	compatiblePredecessor := mustRecord(t, recordInput{
		id:        predecessorID,
		scope:     ScopeTask,
		taskID:    validTaskID,
		key:       defaultMemoryKey,
		body:      "old",
		createdAt: validCreatedAt,
	})

	tests := []struct {
		name        string
		successor   recordInput
		predecessor Record
		want        error
	}{
		{
			name:        "missing declared predecessor",
			successor:   taskSuccessorInput(),
			predecessor: compatiblePredecessor,
			want:        ErrPredecessorMismatch,
		},
		{
			name: "different declared predecessor",
			successor: func() recordInput {
				input := taskSuccessorInput()
				input.supersedes = otherMemoryID
				return input
			}(),
			predecessor: compatiblePredecessor,
			want:        ErrPredecessorMismatch,
		},
		{
			name: "different scope",
			successor: func() recordInput {
				input := taskSuccessorInput()
				input.scope = ScopeSession
				input.taskID = ""
				input.supersedes = predecessorID
				return input
			}(),
			predecessor: compatiblePredecessor,
			want:        ErrIncompatiblePredecessor,
		},
		{
			name: "different task",
			successor: func() recordInput {
				input := taskSuccessorInput()
				input.taskID = otherTaskID
				input.supersedes = predecessorID
				return input
			}(),
			predecessor: compatiblePredecessor,
			want:        ErrIncompatiblePredecessor,
		},
		{
			name: "different key",
			successor: func() recordInput {
				input := taskSuccessorInput()
				input.key = "different"
				input.supersedes = predecessorID
				return input
			}(),
			predecessor: compatiblePredecessor,
			want:        ErrIncompatiblePredecessor,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			successor := mustRecord(t, test.successor)
			if err := ValidatePredecessor(successor, test.predecessor); !errors.Is(err, test.want) {
				t.Fatalf("ValidatePredecessor() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidatePredecessorRejectsSelf(t *testing.T) {
	t.Parallel()

	record := mustRecord(t, validRecordInput())
	record.supersedes = record.id

	if err := ValidatePredecessor(record, record); !errors.Is(err, ErrSelfSupersession) {
		t.Fatalf("ValidatePredecessor() error = %v, want %v", err, ErrSelfSupersession)
	}
}

func TestValidatePredecessorRejectsInvalidRecordsWithStableErrors(t *testing.T) {
	t.Parallel()

	predecessor := mustRecord(t, recordInput{
		id:        predecessorID,
		scope:     ScopeSession,
		key:       defaultMemoryKey,
		body:      "old",
		createdAt: validCreatedAt,
	})
	successorInput := validRecordInput()
	successorInput.supersedes = predecessorID
	successor := mustRecord(t, successorInput)

	invalidSuccessor := successor
	invalidSuccessor.key = ""
	if err := ValidatePredecessor(invalidSuccessor, predecessor); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid successor error = %v, want %v", err, ErrInvalidKey)
	}

	invalidPredecessor := predecessor
	invalidPredecessor.createdAt = invalidCreatedAt
	if err := ValidatePredecessor(successor, invalidPredecessor); !errors.Is(err, ErrInvalidCreatedAt) {
		t.Fatalf("invalid predecessor error = %v, want %v", err, ErrInvalidCreatedAt)
	}
}

func validRecordInput() recordInput {
	return recordInput{
		id:        validMemoryID,
		scope:     ScopeSession,
		key:       defaultMemoryKey,
		body:      defaultMemoryBody,
		createdAt: validCreatedAt,
	}
}

func taskSuccessorInput() recordInput {
	return recordInput{
		id:        validMemoryID,
		scope:     ScopeTask,
		taskID:    validTaskID,
		key:       defaultMemoryKey,
		body:      "new",
		createdAt: validCreatedAt,
	}
}

func mustRecord(t *testing.T, input recordInput) Record {
	t.Helper()

	record, err := newRecord(input)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	return record
}

func newRecord(input recordInput) (Record, error) {
	return NewRecord(
		input.id,
		input.scope,
		input.taskID,
		input.key,
		input.body,
		input.supersedes,
		input.createdAt,
	)
}
