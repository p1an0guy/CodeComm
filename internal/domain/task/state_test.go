package task

import (
	"errors"
	"testing"
)

func TestTransitionTableAcceptsExactlyDocumentedRules(t *testing.T) {
	t.Parallel()

	type transition struct {
		operation Operation
		from      State
		to        State
	}
	legal := map[transition]struct{}{
		{OperationCreate, StateAbsent, StateBacklog}: {},

		{OperationStateChange, StateBacklog, StateReady}:      {},
		{OperationStateChange, StateReady, StateBacklog}:      {},
		{OperationStateChange, StateClaimed, StateInProgress}: {},
		{OperationStateChange, StateInProgress, StateBlocked}: {},
		{OperationStateChange, StateInProgress, StateDone}:    {},
		{OperationStateChange, StateBlocked, StateInProgress}: {},

		{OperationClaim, StateReady, StateClaimed}: {},

		{OperationReleaseVoluntary, StateClaimed, StateReady}:    {},
		{OperationReleaseVoluntary, StateInProgress, StateReady}: {},
		{OperationReleaseVoluntary, StateBlocked, StateReady}:    {},

		{OperationReleaseForced, StateReady, StateReady}:        {},
		{OperationReleaseForced, StateClaimed, StateReady}:      {},
		{OperationReleaseForced, StateInProgress, StateReady}:   {},
		{OperationReleaseForced, StateBlocked, StateReady}:      {},
		{OperationReassign, StateReady, StateReady}:             {},
		{OperationReassign, StateClaimed, StateReady}:           {},
		{OperationReassign, StateInProgress, StateReady}:        {},
		{OperationReassign, StateBlocked, StateReady}:           {},
		{OperationSessionEnded, StateClaimed, StateReady}:       {},
		{OperationSessionEnded, StateInProgress, StateReady}:    {},
		{OperationSessionEnded, StateBlocked, StateReady}:       {},
		{OperationRecoveryRelease, StateClaimed, StateReady}:    {},
		{OperationRecoveryRelease, StateInProgress, StateReady}: {},
		{OperationRecoveryRelease, StateBlocked, StateReady}:    {},

		{OperationCancel, StateBacklog, StateCancelled}:    {},
		{OperationCancel, StateReady, StateCancelled}:      {},
		{OperationCancel, StateClaimed, StateCancelled}:    {},
		{OperationCancel, StateInProgress, StateCancelled}: {},
		{OperationCancel, StateBlocked, StateCancelled}:    {},
	}

	states := append([]State{StateAbsent}, States()...)
	for _, operation := range Operations() {
		for _, from := range states {
			for _, to := range states {
				candidate := transition{operation: operation, from: from, to: to}
				_, want := legal[candidate]
				err := ValidateTransition(operation, from, to)
				if got := err == nil; got != want {
					t.Errorf(
						"ValidateTransition(%q, %q, %q) error = %v, accepted = %t, want %t",
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

func TestTerminalStatesHaveNoOutgoingTransition(t *testing.T) {
	t.Parallel()

	for _, terminal := range []State{StateDone, StateCancelled} {
		if !terminal.Terminal() {
			t.Fatalf("%q Terminal() = false", terminal)
		}
		for _, operation := range Operations() {
			for _, to := range States() {
				if err := ValidateTransition(operation, terminal, to); !errors.Is(err, ErrInvalidTransition) {
					t.Errorf(
						"ValidateTransition(%q, %q, %q) error = %v, want ErrInvalidTransition",
						operation,
						terminal,
						to,
						err,
					)
				}
			}
		}
	}
}

func TestTransitionTableRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      State
		to        State
		want      error
	}{
		{
			name:      "unknown operation",
			operation: Operation("task.unknown"),
			from:      StateReady,
			to:        StateClaimed,
			want:      ErrInvalidOperation,
		},
		{
			name:      "unknown source",
			operation: OperationClaim,
			from:      State("unknown"),
			to:        StateClaimed,
			want:      ErrInvalidState,
		},
		{
			name:      "unknown destination",
			operation: OperationClaim,
			from:      StateReady,
			to:        State("unknown"),
			want:      ErrInvalidState,
		},
		{
			name:      "absent destination",
			operation: OperationClaim,
			from:      StateReady,
			to:        StateAbsent,
			want:      ErrInvalidState,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateTransition(test.operation, test.from, test.to)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStatesAndOperationsReturnDefensiveCopies(t *testing.T) {
	t.Parallel()

	states := States()
	states[0] = State("corrupt")
	if got := States()[0]; got != StateBacklog {
		t.Fatalf("States()[0] = %q after caller mutation, want %q", got, StateBacklog)
	}

	operations := Operations()
	operations[0] = Operation("corrupt")
	if got := Operations()[0]; got != OperationCreate {
		t.Fatalf("Operations()[0] = %q after caller mutation, want %q", got, OperationCreate)
	}
}
