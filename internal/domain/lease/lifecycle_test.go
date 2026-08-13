package lease

import (
	"errors"
	"reflect"
	"testing"
)

func TestTransitionTableAcceptsExactlyDocumentedRules(t *testing.T) {
	t.Parallel()

	type transition struct {
		operation Operation
		from      Lifecycle
		to        Lifecycle
	}
	legal := map[transition]struct{}{
		{
			operation: OperationCreate,
			from:      Lifecycle{},
			to:        activeLifecycle(),
		}: {},
		{
			operation: OperationRenew,
			from:      activeLifecycle(),
			to:        activeLifecycle(),
		}: {},
		{
			operation: OperationReleaseVoluntary,
			from:      activeLifecycle(),
			to:        releasedLifecycle(ReleaseVoluntary),
		}: {},
		{
			operation: OperationReleaseForced,
			from:      activeLifecycle(),
			to:        releasedLifecycle(ReleaseForced),
		}: {},
		{
			operation: OperationReleaseExpired,
			from:      activeLifecycle(),
			to:        releasedLifecycle(ReleaseExpired),
		}: {},
		{
			operation: OperationSessionEnded,
			from:      activeLifecycle(),
			to:        releasedLifecycle(ReleaseSessionEnded),
		}: {},
		{
			operation: OperationRecoveryRelease,
			from:      activeLifecycle(),
			to:        releasedLifecycle(ReleaseRecovery),
		}: {},
	}

	for _, operation := range Operations() {
		for _, from := range transitionLifecycles() {
			for _, to := range transitionLifecycles() {
				candidate := transition{operation: operation, from: from, to: to}
				_, want := legal[candidate]
				err := ValidateTransition(operation, from, to)
				if got := err == nil; got != want {
					t.Errorf(
						"ValidateTransition(%q, %#v, %#v) error = %v, accepted = %t, want %t",
						operation,
						from,
						to,
						err,
						got,
						want,
					)
				}
			}
		}
	}
}

func TestReleasedIsTerminalForEveryOperation(t *testing.T) {
	t.Parallel()

	for _, reason := range ReleaseReasons() {
		from := releasedLifecycle(reason)
		if !from.Status.Terminal() {
			t.Fatalf("%q Terminal() = false", from.Status)
		}
		for _, operation := range Operations() {
			for _, to := range persistedLifecycles() {
				if err := ValidateTransition(operation, from, to); !errors.Is(err, ErrInvalidTransition) {
					t.Errorf(
						"ValidateTransition(%q, %#v, %#v) error = %v, want %v",
						operation,
						from,
						to,
						err,
						ErrInvalidTransition,
					)
				}
			}
		}
	}
}

func TestReleaseOperationsEnforceReasonProvenance(t *testing.T) {
	t.Parallel()

	operations := []struct {
		operation Operation
		reason    ReleaseReason
	}{
		{operation: OperationReleaseVoluntary, reason: ReleaseVoluntary},
		{operation: OperationReleaseForced, reason: ReleaseForced},
		{operation: OperationReleaseExpired, reason: ReleaseExpired},
		{operation: OperationSessionEnded, reason: ReleaseSessionEnded},
		{operation: OperationRecoveryRelease, reason: ReleaseRecovery},
	}

	for _, source := range operations {
		for _, destinationReason := range ReleaseReasons() {
			err := ValidateTransition(
				source.operation,
				activeLifecycle(),
				releasedLifecycle(destinationReason),
			)
			if destinationReason == source.reason {
				if err != nil {
					t.Errorf("%q with %q error = %v", source.operation, destinationReason, err)
				}
				continue
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf(
					"%q with %q error = %v, want %v",
					source.operation,
					destinationReason,
					err,
					ErrInvalidTransition,
				)
			}
		}
	}
}

func TestValidateTransitionRejectsInvalidOperationAndLifecycleValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      Lifecycle
		to        Lifecycle
		want      error
	}{
		{
			name:      "unknown operation",
			operation: "unknown",
			from:      activeLifecycle(),
			to:        activeLifecycle(),
			want:      ErrInvalidOperation,
		},
		{
			name:      "invalid source status",
			operation: OperationRenew,
			from:      Lifecycle{Status: "unknown"},
			to:        activeLifecycle(),
			want:      ErrInvalidStatus,
		},
		{
			name:      "absent source with reason",
			operation: OperationCreate,
			from:      Lifecycle{ReleaseReason: ReleaseVoluntary},
			to:        activeLifecycle(),
			want:      ErrInvalidReleaseReason,
		},
		{
			name:      "invalid destination status",
			operation: OperationRenew,
			from:      activeLifecycle(),
			to:        Lifecycle{Status: "unknown"},
			want:      ErrInvalidStatus,
		},
		{
			name:      "active destination with reason",
			operation: OperationRenew,
			from:      activeLifecycle(),
			to:        Lifecycle{Status: StatusActive, ReleaseReason: ReleaseExpired},
			want:      ErrInvalidReleaseReason,
		},
		{
			name:      "released destination without reason",
			operation: OperationReleaseExpired,
			from:      activeLifecycle(),
			to:        Lifecycle{Status: StatusReleased},
			want:      ErrInvalidReleaseReason,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.operation, test.from, test.to); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOperationCollectionIsClosedAndDefensivelyCopied(t *testing.T) {
	t.Parallel()

	want := []Operation{
		OperationCreate,
		OperationRenew,
		OperationReleaseVoluntary,
		OperationReleaseForced,
		OperationReleaseExpired,
		OperationSessionEnded,
		OperationRecoveryRelease,
	}
	got := Operations()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Operations() = %v, want %v", got, want)
	}
	got[0] = "changed"
	if Operations()[0] != OperationCreate {
		t.Fatal("Operations() returned aliased storage")
	}

	for _, operation := range want {
		if !operation.Valid() {
			t.Errorf("Operation(%q).Valid() = false", operation)
		}
	}
	for _, invalid := range []Operation{"", "lease.released", "unknown"} {
		if invalid.Valid() {
			t.Errorf("Operation(%q).Valid() = true", invalid)
		}
	}
}

func transitionLifecycles() []Lifecycle {
	return append([]Lifecycle{{}}, persistedLifecycles()...)
}

func persistedLifecycles() []Lifecycle {
	result := []Lifecycle{activeLifecycle()}
	for _, reason := range ReleaseReasons() {
		result = append(result, releasedLifecycle(reason))
	}
	return result
}

func activeLifecycle() Lifecycle {
	return Lifecycle{Status: StatusActive}
}

func releasedLifecycle(reason ReleaseReason) Lifecycle {
	return Lifecycle{Status: StatusReleased, ReleaseReason: reason}
}
