package agentsession

import (
	"errors"
	"testing"
)

func TestTransitionTableAcceptsExactlyDocumentedRules(t *testing.T) {
	t.Parallel()

	type transition struct {
		operation Operation
		from      Lifecycle
		to        Lifecycle
	}

	legal := make(map[transition]struct{})
	add := func(operation Operation, from, to Lifecycle) {
		legal[transition{operation: operation, from: from, to: to}] = struct{}{}
	}

	add(OperationCreate, Lifecycle{}, lifecycle(StateStarting))
	add(OperationAgentStatusChange, lifecycle(StateStarting), lifecycle(StateIdle))

	statusStates := []State{StateIdle, StateClaimed, StateWorking, StateBlocked}
	for _, from := range statusStates {
		for _, to := range statusStates {
			if from != to {
				add(OperationAgentStatusChange, lifecycle(from), lifecycle(to))
			}
		}
	}

	for _, connected := range ConnectedStates() {
		add(
			OperationDaemonDisconnect,
			lifecycle(connected),
			Lifecycle{State: StateDisconnected, ResumeState: connected},
		)
		add(
			OperationDaemonResume,
			Lifecycle{State: StateDisconnected, ResumeState: connected},
			lifecycle(connected),
		)
		add(
			OperationCleanEnd,
			lifecycle(connected),
			endedLifecycle(EndReasonClean),
		)
	}

	for _, from := range nonterminalLifecycles() {
		add(OperationDaemonEnd, from, endedLifecycle(EndReasonOperator))
		add(OperationDaemonEnd, from, endedLifecycle(EndReasonCrashReap))
		add(OperationRecoveryEnd, from, endedLifecycle(EndReasonRecovery))
		if from.State == StateDisconnected {
			add(OperationDaemonEnd, from, endedLifecycle(EndReasonDisconnectTimeout))
		}
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

func TestEndedIsTerminalForEveryOperation(t *testing.T) {
	t.Parallel()

	for _, reason := range EndReasons() {
		from := endedLifecycle(reason)
		if !from.State.Terminal() {
			t.Fatalf("%q Terminal() = false", from.State)
		}
		for _, operation := range Operations() {
			for _, to := range persistedLifecycles() {
				if err := ValidateTransition(operation, from, to); !errors.Is(err, ErrInvalidTransition) {
					t.Errorf(
						"ValidateTransition(%q, %#v, %#v) error = %v, want ErrInvalidTransition",
						operation,
						from,
						to,
						err,
					)
				}
			}
		}
	}
}

func TestDaemonResumeRequiresExactStoredState(t *testing.T) {
	t.Parallel()

	for _, stored := range ConnectedStates() {
		from := Lifecycle{State: StateDisconnected, ResumeState: stored}
		for _, destination := range ConnectedStates() {
			err := ValidateTransition(OperationDaemonResume, from, lifecycle(destination))
			if destination == stored {
				if err != nil {
					t.Errorf("resume from %q to stored state error = %v", stored, err)
				}
				continue
			}
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf(
					"resume from stored %q to %q error = %v, want ErrInvalidTransition",
					stored,
					destination,
					err,
				)
			}
		}
	}
}

func TestEndOperationsEnforceReasonProvenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      Lifecycle
		reason    EndReason
	}{
		{
			name:      "clean operation cannot claim daemon timeout",
			operation: OperationCleanEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonDisconnectTimeout,
		},
		{
			name:      "clean operation cannot claim operator",
			operation: OperationCleanEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonOperator,
		},
		{
			name:      "daemon operation cannot claim clean",
			operation: OperationDaemonEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonClean,
		},
		{
			name:      "daemon operation cannot claim recovery",
			operation: OperationDaemonEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonRecovery,
		},
		{
			name:      "disconnect timeout requires disconnected",
			operation: OperationDaemonEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonDisconnectTimeout,
		},
		{
			name:      "recovery operation cannot claim crash reap",
			operation: OperationRecoveryEnd,
			from:      lifecycle(StateWorking),
			reason:    EndReasonCrashReap,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateTransition(test.operation, test.from, endedLifecycle(test.reason))
			if !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("ValidateTransition() error = %v, want ErrInvalidTransition", err)
			}
		})
	}
}

func TestTransitionTableRejectsUnknownAndInconsistentValues(t *testing.T) {
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
			operation: Operation("unknown"),
			from:      lifecycle(StateStarting),
			to:        lifecycle(StateIdle),
			want:      ErrInvalidOperation,
		},
		{
			name:      "unknown source state",
			operation: OperationAgentStatusChange,
			from:      lifecycle(State("unknown")),
			to:        lifecycle(StateIdle),
			want:      ErrInvalidState,
		},
		{
			name:      "unknown destination state",
			operation: OperationAgentStatusChange,
			from:      lifecycle(StateIdle),
			to:        lifecycle(State("unknown")),
			want:      ErrInvalidState,
		},
		{
			name:      "absent source outside create",
			operation: OperationAgentStatusChange,
			from:      Lifecycle{},
			to:        lifecycle(StateIdle),
			want:      ErrInvalidTransition,
		},
		{
			name:      "absent destination",
			operation: OperationAgentStatusChange,
			from:      lifecycle(StateIdle),
			to:        Lifecycle{},
			want:      ErrInvalidState,
		},
		{
			name:      "inconsistent source lifecycle",
			operation: OperationDaemonResume,
			from:      Lifecycle{State: StateDisconnected},
			to:        lifecycle(StateWorking),
			want:      ErrInvalidResumeState,
		},
		{
			name:      "inconsistent destination lifecycle",
			operation: OperationDaemonDisconnect,
			from:      lifecycle(StateWorking),
			to:        Lifecycle{State: StateDisconnected},
			want:      ErrInvalidResumeState,
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

func transitionLifecycles() []Lifecycle {
	return append([]Lifecycle{{}}, persistedLifecycles()...)
}

func persistedLifecycles() []Lifecycle {
	result := nonterminalLifecycles()
	for _, reason := range EndReasons() {
		result = append(result, endedLifecycle(reason))
	}
	return result
}

func nonterminalLifecycles() []Lifecycle {
	result := make([]Lifecycle, 0, len(ConnectedStates())*2)
	for _, state := range ConnectedStates() {
		result = append(result, lifecycle(state))
	}
	for _, resumeState := range ConnectedStates() {
		result = append(result, Lifecycle{
			State:       StateDisconnected,
			ResumeState: resumeState,
		})
	}
	return result
}

func lifecycle(state State) Lifecycle {
	return Lifecycle{State: state}
}

func endedLifecycle(reason EndReason) Lifecycle {
	return Lifecycle{State: StateEnded, EndReason: reason}
}
