package voterset

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	voterSetSessionID      = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abc")
	otherVoterSetSessionID = domain.UUIDv7("01890f47-3e72-7d5a-8c9b-123456789abd")
)

func TestNewAcceptsExactlyActiveFormCounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		count int
	}{
		{name: "one voter", count: 1},
		{name: "three voters", count: 3},
		{name: "five voters", count: 5},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ids := voterIDs(test.count)
			got, err := New(voterSetSessionID, ids, 1)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if got.SessionID != voterSetSessionID {
				t.Fatalf("Set.SessionID = %q, want %q", got.SessionID, voterSetSessionID)
			}
			if got.VoterSetVersion != 1 {
				t.Fatalf("Set.VoterSetVersion = %d, want 1", got.VoterSetVersion)
			}
			if gotIDs := got.VoterDeviceIDs(); !reflect.DeepEqual(gotIDs, ids) {
				t.Fatalf("Set.VoterDeviceIDs() = %v, want %v", gotIDs, ids)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Set.Validate() error = %v", err)
			}
		})
	}
}

func TestNewRejectsEveryOtherCountThroughOnePastMaximum(t *testing.T) {
	t.Parallel()

	for _, count := range []int{0, 2, 4, 6} {
		count := count
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			t.Parallel()
			got, err := New(voterSetSessionID, voterIDs(count), 1)
			if !errors.Is(err, ErrInvalidVoterCount) {
				t.Fatalf("New() error = %v, want %v", err, ErrInvalidVoterCount)
			}
			if got != (Set{}) {
				t.Fatalf("New() = %+v after error, want zero Set", got)
			}
		})
	}
}

func TestNewRejectsInvalidSessionIDAndVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sessionID domain.UUIDv7
		version   uint64
		want      error
	}{
		{name: "empty session ID", sessionID: "", version: 1, want: ErrInvalidSessionID},
		{
			name:      "non-v7 session ID",
			sessionID: "550e8400-e29b-41d4-a716-446655440000",
			version:   1,
			want:      ErrInvalidSessionID,
		},
		{name: "zero version", sessionID: voterSetSessionID, version: 0, want: ErrInvalidVoterSetVersion},
		{
			name:      "version over signed JSON limit",
			sessionID: voterSetSessionID,
			version:   domain.MaxSafeInteger + 1,
			want:      ErrInvalidVoterSetVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(test.sessionID, voterIDs(1), test.version)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
			if got != (Set{}) {
				t.Fatalf("New() = %+v after error, want zero Set", got)
			}
		})
	}
}

func TestNewAcceptsVoterSetVersionBoundaries(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		got, err := New(voterSetSessionID, voterIDs(1), version)
		if err != nil {
			t.Fatalf("New() at voter-set version %d error = %v", version, err)
		}
		if got.VoterSetVersion != version {
			t.Fatalf("Set.VoterSetVersion = %d, want %d", got.VoterSetVersion, version)
		}
	}
}

func TestNewRejectsMalformedUnsortedAndDuplicateVoters(t *testing.T) {
	t.Parallel()

	valid := voterIDs(3)
	tests := []struct {
		name string
		ids  []domain.DeviceID
		want error
	}{
		{
			name: "empty device ID",
			ids:  []domain.DeviceID{"", valid[1], valid[2]},
			want: ErrInvalidVoterDeviceID,
		},
		{
			name: "uppercase device ID",
			ids: []domain.DeviceID{
				domain.DeviceID("cc1" + strings.Repeat("A", 64)),
				valid[1],
				valid[2],
			},
			want: ErrInvalidVoterDeviceID,
		},
		{
			name: "unsorted",
			ids:  []domain.DeviceID{valid[1], valid[0], valid[2]},
			want: ErrVotersNotSortedUnique,
		},
		{
			name: "duplicate",
			ids:  []domain.DeviceID{valid[0], valid[0], valid[2]},
			want: ErrVotersNotSortedUnique,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(voterSetSessionID, test.ids, 1)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
			if got != (Set{}) {
				t.Fatalf("New() = %+v after error, want zero Set", got)
			}
		})
	}
}

func TestSetValidateDetectsMutatedExportedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Set)
		want   error
	}{
		{
			name: "session ID",
			mutate: func(set *Set) {
				set.SessionID = ""
			},
			want: ErrInvalidSessionID,
		},
		{
			name: "voter set version",
			mutate: func(set *Set) {
				set.VoterSetVersion = 0
			},
			want: ErrInvalidVoterSetVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set, err := New(voterSetSessionID, voterIDs(3), 1)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			test.mutate(&set)
			if err := set.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Set.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSetDefensivelyCopiesVoterDeviceIDs(t *testing.T) {
	t.Parallel()

	input := voterIDs(3)
	want := append([]domain.DeviceID(nil), input...)
	set, err := New(voterSetSessionID, input, 1)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	input[0] = domain.DeviceID("cc1" + strings.Repeat("f", 64))
	if got := set.VoterDeviceIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("input mutation changed Set: got %v, want %v", got, want)
	}

	exposed := set.VoterDeviceIDs()
	exposed[0] = domain.DeviceID("cc1" + strings.Repeat("e", 64))
	if got := set.VoterDeviceIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("returned-slice mutation changed Set: got %v, want %v", got, want)
	}
}

func TestSetMembershipQueries(t *testing.T) {
	t.Parallel()

	set := mustSet(t, voterSetSessionID, voterIDs(3), 4)
	for _, id := range voterIDs(3) {
		if !set.Contains(id) {
			t.Errorf("Set.Contains(%q) = false", id)
		}
	}
	if set.Contains(domain.DeviceID("cc1" + strings.Repeat("f", 64))) {
		t.Fatal("Set.Contains() accepted a nonmember")
	}
	if set.Contains("invalid") {
		t.Fatal("Set.Contains() accepted an invalid device ID")
	}

	same := mustSet(t, otherVoterSetSessionID, voterIDs(3), 99)
	if !set.SameTarget(same) || !same.SameTarget(set) {
		t.Fatal("SameTarget() considered matching targets different")
	}
	different := mustSet(t, voterSetSessionID, voterIDs(1), 5)
	if set.SameTarget(different) {
		t.Fatal("SameTarget() considered different targets equal")
	}
	if set.SameTarget(Set{}) || (Set{}).SameTarget(set) || (Set{}).Contains(voterIDs(1)[0]) {
		t.Fatal("membership query accepted an invalid set")
	}
}

func TestSetTransitionAcceptsChangeAndRecoveryReset(t *testing.T) {
	t.Parallel()

	before := mustSet(t, voterSetSessionID, voterIDs(1), 7)
	after := mustSet(t, voterSetSessionID, voterIDs(3), 8)
	if err := ValidateTransition(OperationChange, before, after); err != nil {
		t.Fatalf("voter-set change error = %v", err)
	}

	revoked := mustSet(t, voterSetSessionID, voterIDs(1), 9)
	if err := ValidateTransition(OperationTargetVoterRevocation, after, revoked); err != nil {
		t.Fatalf("target-voter revocation error = %v", err)
	}
	if err := ValidateTransition(OperationNonvoterRevocation, revoked, revoked); err != nil {
		t.Fatalf("nonvoter revocation validation error = %v", err)
	}

	before = mustSet(t, voterSetSessionID, voterIDs(5), domain.MaxSafeInteger)
	recovered := mustSet(t, otherVoterSetSessionID, voterIDs(1), 1)
	if err := ValidateTransition(OperationRecoveryReset, before, recovered); err != nil {
		t.Fatalf("voter-set recovery reset error = %v", err)
	}
}

func TestSetTransitionRejectsUnsafeMutations(t *testing.T) {
	t.Parallel()

	before := mustSet(t, voterSetSessionID, voterIDs(1), 7)
	changed := mustSet(t, voterSetSessionID, voterIDs(3), 8)
	recovered := mustSet(t, otherVoterSetSessionID, voterIDs(1), 1)

	invalidSource := before
	invalidSource.voterCount = 2
	invalidDestination := changed
	invalidDestination.voterCount = 2

	tests := []struct {
		name      string
		operation Operation
		before    Set
		after     Set
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("membership.unknown"),
			before:    before,
			after:     changed,
			want:      ErrInvalidOperation,
		},
		{
			name:      "invalid source",
			operation: OperationChange,
			before:    invalidSource,
			after:     changed,
			want:      ErrInvalidTransition,
		},
		{
			name:      "invalid destination",
			operation: OperationChange,
			before:    before,
			after:     invalidDestination,
			want:      ErrInvalidTransition,
		},
		{
			name:      "change replaces session",
			operation: OperationChange,
			before:    before,
			after:     mustSet(t, otherVoterSetSessionID, voterIDs(3), 8),
			want:      ErrSessionChanged,
		},
		{
			name:      "change repeats version",
			operation: OperationChange,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(3), 7),
			want:      ErrInvalidVersionChange,
		},
		{
			name:      "change skips version",
			operation: OperationChange,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(3), 9),
			want:      ErrInvalidVersionChange,
		},
		{
			name:      "change from maximum version",
			operation: OperationChange,
			before:    mustSet(t, voterSetSessionID, voterIDs(1), domain.MaxSafeInteger),
			after:     mustSet(t, voterSetSessionID, voterIDs(3), domain.MaxSafeInteger),
			want:      ErrInvalidVersionChange,
		},
		{
			name:      "change keeps target",
			operation: OperationChange,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(1), 8),
			want:      ErrTargetUnchanged,
		},
		{
			name:      "target-voter revocation adds voters",
			operation: OperationTargetVoterRevocation,
			before:    before,
			after:     changed,
			want:      ErrInvalidRevocationTarget,
		},
		{
			name:      "target-voter revocation skips legal count",
			operation: OperationTargetVoterRevocation,
			before:    mustSet(t, voterSetSessionID, voterIDs(5), 7),
			after:     mustSet(t, voterSetSessionID, voterIDs(1), 8),
			want:      ErrInvalidRevocationTarget,
		},
		{
			name:      "target-voter revocation introduces voter",
			operation: OperationTargetVoterRevocation,
			before:    mustSet(t, voterSetSessionID, voterIDs(3), 7),
			after: mustSet(
				t,
				voterSetSessionID,
				[]domain.DeviceID{domain.DeviceID("cc1" + strings.Repeat("f", 64))},
				8,
			),
			want: ErrInvalidRevocationTarget,
		},
		{
			name:      "nonvoter revocation changes target",
			operation: OperationNonvoterRevocation,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(3), 7),
			want:      ErrTargetChanged,
		},
		{
			name:      "nonvoter revocation increments target version",
			operation: OperationNonvoterRevocation,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(1), 8),
			want:      ErrInvalidVersionChange,
		},
		{
			name:      "recovery keeps session",
			operation: OperationRecoveryReset,
			before:    before,
			after:     mustSet(t, voterSetSessionID, voterIDs(1), 1),
			want:      ErrInvalidTransition,
		},
		{
			name:      "recovery does not reset version",
			operation: OperationRecoveryReset,
			before:    before,
			after:     mustSet(t, otherVoterSetSessionID, voterIDs(1), 2),
			want:      ErrInvalidTransition,
		},
		{
			name:      "recovery has three voters",
			operation: OperationRecoveryReset,
			before:    before,
			after:     mustSet(t, otherVoterSetSessionID, voterIDs(3), 1),
			want:      ErrInvalidRecoveryTarget,
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

	if err := ValidateTransition(OperationRecoveryReset, before, recovered); err != nil {
		t.Fatalf("valid recovery rejected after negative cases: %v", err)
	}
}

func TestOperationsReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	operations := Operations()
	operations[0] = Operation("corrupt")
	if got := Operations()[0]; got != OperationChange {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationChange)
	}
}

func mustSet(
	t *testing.T,
	sessionID domain.UUIDv7,
	ids []domain.DeviceID,
	version uint64,
) Set {
	t.Helper()
	set, err := New(sessionID, ids, version)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return set
}

func voterIDs(count int) []domain.DeviceID {
	ids := make([]domain.DeviceID, count)
	for index := range ids {
		ids[index] = domain.DeviceID("cc1" + strings.Repeat(string(rune('0'+index)), 64))
	}
	return ids
}
