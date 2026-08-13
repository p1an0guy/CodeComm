package plan

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	validRevisionID  = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	otherRevisionID  = domain.UUIDv7("01890f47-3e72-7000-8000-000000000002")
	validSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000003")
	otherSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000004")
	validProposerID  = domain.DeviceID("cc10000000000000000000000000000000000000000000000000000000000000000")
	validCreatedAt   = domain.Timestamp("2026-08-10T12:34:56.123456789Z")
	invalidUUIDv7    = domain.UUIDv7("550e8400-e29b-41d4-a716-446655440000")
	invalidDeviceID  = domain.DeviceID("not-a-device")
	invalidTimestamp = domain.Timestamp("2026-08-10T12:34:56-07:00")
)

type revisionInput struct {
	id         domain.UUIDv7
	supersedes domain.UUIDv7
	title      string
	body       string
	taskIDs    []domain.UUIDv7
	proposerID domain.DeviceID
	createdAt  domain.Timestamp
}

func TestNewRevisionAcceptsExactBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input revisionInput
	}{
		{
			name:  "minimum",
			input: validRevisionInput(),
		},
		{
			name: "maximum",
			input: revisionInput{
				id:         validRevisionID,
				supersedes: otherRevisionID,
				title:      strings.Repeat("\u00e9", MaxTitleBytes/2),
				body:       strings.Repeat("\u00e9", MaxBodyBytes/2),
				taskIDs:    makeTaskIDs(MaxTaskIDs),
				proposerID: validProposerID,
				createdAt:  validCreatedAt,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRevision(test.input)
			if err != nil {
				t.Fatalf("NewRevision() error = %v", err)
			}
			if got.ID() != test.input.id {
				t.Errorf("Revision.ID() = %q, want %q", got.ID(), test.input.id)
			}
			supersedes, hasSupersedes := got.Supersedes()
			if hasSupersedes != (test.input.supersedes != "") ||
				supersedes != test.input.supersedes {
				t.Errorf(
					"Revision.Supersedes() = (%q, %t), want (%q, %t)",
					supersedes,
					hasSupersedes,
					test.input.supersedes,
					test.input.supersedes != "",
				)
			}
			if got.Title() != test.input.title {
				t.Errorf("Revision.Title() = %q, want %q", got.Title(), test.input.title)
			}
			if got.Body() != test.input.body {
				t.Errorf("Revision.Body() differs from input")
			}
			if taskIDs := got.TaskIDs(); !reflect.DeepEqual(taskIDs, test.input.taskIDs) {
				t.Errorf("Revision.TaskIDs() = %v, want %v", taskIDs, test.input.taskIDs)
			}
			if got.ProposedByDeviceID() != test.input.proposerID {
				t.Errorf(
					"Revision.ProposedByDeviceID() = %q, want %q",
					got.ProposedByDeviceID(),
					test.input.proposerID,
				)
			}
			if got.CreatedAt() != test.input.createdAt {
				t.Errorf("Revision.CreatedAt() = %q, want %q", got.CreatedAt(), test.input.createdAt)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Revision.Validate() error = %v", err)
			}
		})
	}
}

func TestNewRevisionRejectsInvalidFieldsAndOnePastBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*revisionInput)
		want   error
	}{
		{
			name: "revision ID",
			mutate: func(input *revisionInput) {
				input.id = invalidUUIDv7
			},
			want: ErrInvalidRevisionID,
		},
		{
			name: "supersedes ID",
			mutate: func(input *revisionInput) {
				input.supersedes = invalidUUIDv7
			},
			want: ErrInvalidSupersedes,
		},
		{
			name: "self supersession",
			mutate: func(input *revisionInput) {
				input.supersedes = input.id
			},
			want: ErrSelfSupersession,
		},
		{
			name: "empty title",
			mutate: func(input *revisionInput) {
				input.title = ""
			},
			want: ErrInvalidTitle,
		},
		{
			name: "title one byte over",
			mutate: func(input *revisionInput) {
				input.title = strings.Repeat("x", MaxTitleBytes+1)
			},
			want: ErrInvalidTitle,
		},
		{
			name: "body one byte over",
			mutate: func(input *revisionInput) {
				input.body = strings.Repeat("x", MaxBodyBytes+1)
			},
			want: ErrInvalidBody,
		},
		{
			name: "task count one over",
			mutate: func(input *revisionInput) {
				input.taskIDs = makeTaskIDs(MaxTaskIDs + 1)
			},
			want: ErrTooManyTaskIDs,
		},
		{
			name: "invalid task ID",
			mutate: func(input *revisionInput) {
				input.taskIDs = []domain.UUIDv7{invalidUUIDv7}
			},
			want: ErrInvalidTaskID,
		},
		{
			name: "unsorted task IDs",
			mutate: func(input *revisionInput) {
				input.taskIDs = []domain.UUIDv7{otherRevisionID, validRevisionID}
			},
			want: ErrTaskIDsNotSortedUnique,
		},
		{
			name: "duplicate task IDs",
			mutate: func(input *revisionInput) {
				input.taskIDs = []domain.UUIDv7{validRevisionID, validRevisionID}
			},
			want: ErrTaskIDsNotSortedUnique,
		},
		{
			name: "proposer device ID",
			mutate: func(input *revisionInput) {
				input.proposerID = invalidDeviceID
			},
			want: ErrInvalidProposerDeviceID,
		},
		{
			name: "created timestamp",
			mutate: func(input *revisionInput) {
				input.createdAt = invalidTimestamp
			},
			want: ErrInvalidCreatedAt,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := validRevisionInput()
			test.mutate(&input)
			got, err := newRevision(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRevision() error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(got, Revision{}) {
				t.Fatalf("NewRevision() returned nonzero Revision after error")
			}
		})
	}
}

func TestNewRevisionUsesUTF8ByteBoundsAndRejectsMalformedUTF8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		title string
		body  string
		want  error
	}{
		{
			name:  "multibyte exact title",
			title: strings.Repeat("\u00e9", MaxTitleBytes/2),
		},
		{
			name:  "multibyte title over",
			title: strings.Repeat("\u00e9", MaxTitleBytes/2+1),
			want:  ErrInvalidTitle,
		},
		{
			name:  "malformed title",
			title: string([]byte{0xff}),
			want:  ErrInvalidTitle,
		},
		{
			name:  "multibyte exact body",
			title: "title",
			body:  strings.Repeat("\u00e9", MaxBodyBytes/2),
		},
		{
			name:  "multibyte body over",
			title: "title",
			body:  strings.Repeat("\u00e9", MaxBodyBytes/2+1),
			want:  ErrInvalidBody,
		},
		{
			name:  "malformed body",
			title: "title",
			body:  string([]byte{0xff}),
			want:  ErrInvalidBody,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := validRevisionInput()
			input.title = test.title
			input.body = test.body
			_, err := newRevision(input)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRevision() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRevisionDefensivelyCopiesTaskIDs(t *testing.T) {
	t.Parallel()

	input := validRevisionInput()
	input.taskIDs = makeTaskIDs(3)
	want := append([]domain.UUIDv7(nil), input.taskIDs...)

	revision, err := newRevision(input)
	if err != nil {
		t.Fatalf("NewRevision() error = %v", err)
	}

	input.taskIDs[0] = otherRevisionID
	if got := revision.TaskIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("input mutation changed Revision.TaskIDs(): got %v, want %v", got, want)
	}

	exposed := revision.TaskIDs()
	exposed[0] = otherRevisionID
	if got := revision.TaskIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("returned-slice mutation changed Revision.TaskIDs(): got %v, want %v", got, want)
	}
}

func TestCurrentValidateAcceptsOptionalRevisionAndVersionBounds(t *testing.T) {
	t.Parallel()

	for _, current := range []Current{
		{
			SessionID:     validSessionID,
			EntityVersion: 1,
		},
		{
			SessionID:     validSessionID,
			RevisionID:    validRevisionID,
			EntityVersion: 1,
		},
		{
			SessionID:     validSessionID,
			RevisionID:    validRevisionID,
			EntityVersion: domain.MaxSafeInteger,
		},
	} {
		if err := current.Validate(); err != nil {
			t.Errorf("Current.Validate(%+v) error = %v", current, err)
		}
	}
}

func TestCurrentValidateRejectsInvalidFieldsAndVersionBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current Current
		want    error
	}{
		{
			name: "invalid session",
			current: Current{
				SessionID:     invalidUUIDv7,
				EntityVersion: 1,
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "invalid optional revision",
			current: Current{
				SessionID:     validSessionID,
				RevisionID:    invalidUUIDv7,
				EntityVersion: 1,
			},
			want: ErrInvalidCurrentRevisionID,
		},
		{
			name: "zero entity version",
			current: Current{
				SessionID:     validSessionID,
				EntityVersion: 0,
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version one over",
			current: Current{
				SessionID:     validSessionID,
				EntityVersion: domain.MaxSafeInteger + 1,
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "null revision after initial version",
			current: Current{
				SessionID:     validSessionID,
				EntityVersion: 2,
			},
			want: ErrInvalidUnselectedVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.current.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Current.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCurrentTransitionAcceptsSelectionAndRecoveryReset(t *testing.T) {
	t.Parallel()

	selections := []struct {
		name   string
		before Current
		after  Current
	}{
		{
			name: "first selection",
			before: Current{
				SessionID:     validSessionID,
				EntityVersion: 1,
			},
			after: Current{
				SessionID:     validSessionID,
				RevisionID:    validRevisionID,
				EntityVersion: 2,
			},
		},
		{
			name: "replacement selection",
			before: Current{
				SessionID:     validSessionID,
				RevisionID:    validRevisionID,
				EntityVersion: 41,
			},
			after: Current{
				SessionID:     validSessionID,
				RevisionID:    otherRevisionID,
				EntityVersion: 42,
			},
		},
	}
	for _, test := range selections {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(OperationSelect, test.before, test.after); err != nil {
				t.Fatalf("ValidateTransition() error = %v", err)
			}
		})
	}

	recoveries := []struct {
		before Current
		after  Current
	}{
		{
			before: Current{
				SessionID:     validSessionID,
				EntityVersion: 1,
			},
			after: Current{
				SessionID:     otherSessionID,
				EntityVersion: 1,
			},
		},
		{
			before: Current{
				SessionID:     validSessionID,
				RevisionID:    validRevisionID,
				EntityVersion: domain.MaxSafeInteger,
			},
			after: Current{
				SessionID:     otherSessionID,
				RevisionID:    validRevisionID,
				EntityVersion: 1,
			},
		},
	}
	for _, recovery := range recoveries {
		if err := ValidateTransition(
			OperationRecoveryReset,
			recovery.before,
			recovery.after,
		); err != nil {
			t.Errorf(
				"recovery from %+v to %+v error = %v",
				recovery.before,
				recovery.after,
				err,
			)
		}
	}
}

func TestCurrentTransitionRejectsUnsafeMutations(t *testing.T) {
	t.Parallel()

	validBefore := Current{
		SessionID:     validSessionID,
		RevisionID:    validRevisionID,
		EntityVersion: 3,
	}
	validSelection := Current{
		SessionID:     validSessionID,
		RevisionID:    otherRevisionID,
		EntityVersion: 4,
	}
	validRecovery := Current{
		SessionID:     otherSessionID,
		RevisionID:    validRevisionID,
		EntityVersion: 1,
	}

	tests := []struct {
		name      string
		operation Operation
		before    Current
		after     Current
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("plan.unknown"),
			before:    validBefore,
			after:     validSelection,
			want:      ErrInvalidOperation,
		},
		{
			name:      "invalid source",
			operation: OperationSelect,
			before:    Current{},
			after:     validSelection,
			want:      ErrInvalidTransition,
		},
		{
			name:      "invalid destination",
			operation: OperationSelect,
			before:    validBefore,
			after:     Current{},
			want:      ErrInvalidTransition,
		},
		{
			name:      "selection changes session",
			operation: OperationSelect,
			before:    validBefore,
			after: func() Current {
				value := validSelection
				value.SessionID = otherSessionID
				return value
			}(),
			want: ErrCurrentSessionChanged,
		},
		{
			name:      "selection clears revision",
			operation: OperationSelect,
			before:    validBefore,
			after: func() Current {
				value := validSelection
				value.RevisionID = ""
				return value
			}(),
			want: ErrInvalidTransition,
		},
		{
			name:      "selection repeats version",
			operation: OperationSelect,
			before:    validBefore,
			after: func() Current {
				value := validSelection
				value.EntityVersion = validBefore.EntityVersion
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "selection skips version",
			operation: OperationSelect,
			before:    validBefore,
			after: func() Current {
				value := validSelection
				value.EntityVersion++
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "selection from maximum version",
			operation: OperationSelect,
			before: func() Current {
				value := validBefore
				value.EntityVersion = domain.MaxSafeInteger
				return value
			}(),
			after: func() Current {
				value := validSelection
				value.EntityVersion = domain.MaxSafeInteger
				return value
			}(),
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "recovery keeps session",
			operation: OperationRecoveryReset,
			before:    validBefore,
			after: func() Current {
				value := validRecovery
				value.SessionID = validSessionID
				return value
			}(),
			want: ErrInvalidTransition,
		},
		{
			name:      "recovery changes revision",
			operation: OperationRecoveryReset,
			before:    validBefore,
			after: func() Current {
				value := validRecovery
				value.RevisionID = otherRevisionID
				return value
			}(),
			want: ErrInvalidTransition,
		},
		{
			name:      "recovery does not reset version",
			operation: OperationRecoveryReset,
			before:    validBefore,
			after: func() Current {
				value := validRecovery
				value.EntityVersion = 2
				return value
			}(),
			want: ErrInvalidTransition,
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
	if got := Operations()[0]; got != OperationSelect {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationSelect)
	}
}

func validRevisionInput() revisionInput {
	return revisionInput{
		id:         validRevisionID,
		title:      "x",
		proposerID: validProposerID,
		createdAt:  validCreatedAt,
	}
}

func newRevision(input revisionInput) (Revision, error) {
	return NewRevision(
		input.id,
		input.supersedes,
		input.title,
		input.body,
		input.taskIDs,
		input.proposerID,
		input.createdAt,
	)
}

func makeTaskIDs(count int) []domain.UUIDv7 {
	ids := make([]domain.UUIDv7, count)
	for index := range ids {
		ids[index] = domain.UUIDv7(
			"01890f47-3e72-7000-8000-" + leftPadHex(index, 12),
		)
	}
	return ids
}

func leftPadHex(value, width int) string {
	const digits = "0123456789abcdef"
	result := make([]byte, width)
	for index := width - 1; index >= 0; index-- {
		result[index] = digits[value&0xf]
		value >>= 4
	}
	return string(result)
}
