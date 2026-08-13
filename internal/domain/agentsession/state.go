// Package agentsession defines the agent-session entity and its pure state
// machine.
package agentsession

import (
	"errors"
	"fmt"
)

// State is a committed agent-session lifecycle state.
type State string

const (
	// StateAbsent is the source sentinel used only by session creation.
	StateAbsent State = ""

	StateStarting     State = "starting"
	StateIdle         State = "idle"
	StateClaimed      State = "claimed"
	StateWorking      State = "working"
	StateBlocked      State = "blocked"
	StateDisconnected State = "disconnected"
	StateEnded        State = "ended"
)

var states = [...]State{
	StateStarting,
	StateIdle,
	StateClaimed,
	StateWorking,
	StateBlocked,
	StateDisconnected,
	StateEnded,
}

var connectedStates = [...]State{
	StateStarting,
	StateIdle,
	StateClaimed,
	StateWorking,
	StateBlocked,
}

// Valid reports whether state is a committed state. StateAbsent is not a
// committed state.
func (state State) Valid() bool {
	switch state {
	case StateStarting,
		StateIdle,
		StateClaimed,
		StateWorking,
		StateBlocked,
		StateDisconnected,
		StateEnded:
		return true
	default:
		return false
	}
}

// Connected reports whether state is one of the live IPC-connected states.
func (state State) Connected() bool {
	switch state {
	case StateStarting, StateIdle, StateClaimed, StateWorking, StateBlocked:
		return true
	default:
		return false
	}
}

// Terminal reports whether no transition may leave state.
func (state State) Terminal() bool {
	return state == StateEnded
}

// States returns every committed state in stable lifecycle order.
func States() []State {
	result := make([]State, len(states))
	copy(result, states[:])
	return result
}

// ConnectedStates returns every connected state in stable lifecycle order.
func ConnectedStates() []State {
	result := make([]State, len(connectedStates))
	copy(result, connectedStates[:])
	return result
}

// EndReason records why an agent session entered its terminal state.
type EndReason string

const (
	// EndReasonAbsent represents a null reason on a nonterminal session.
	EndReasonAbsent EndReason = ""

	EndReasonClean             EndReason = "clean"
	EndReasonDisconnectTimeout EndReason = "disconnect_timeout"
	EndReasonOperator          EndReason = "operator"
	EndReasonCrashReap         EndReason = "crash_reap"
	EndReasonRecovery          EndReason = "recovery"
)

var endReasons = [...]EndReason{
	EndReasonClean,
	EndReasonDisconnectTimeout,
	EndReasonOperator,
	EndReasonCrashReap,
	EndReasonRecovery,
}

// Valid reports whether reason is a closed V1 end reason.
func (reason EndReason) Valid() bool {
	switch reason {
	case EndReasonClean,
		EndReasonDisconnectTimeout,
		EndReasonOperator,
		EndReasonCrashReap,
		EndReasonRecovery:
		return true
	default:
		return false
	}
}

// EndReasons returns every end reason in stable order.
func EndReasons() []EndReason {
	result := make([]EndReason, len(endReasons))
	copy(result, endReasons[:])
	return result
}

// Operation identifies the authority class and purpose of a lifecycle edge.
// Reducers still validate the concrete event actor and owning-device binding.
type Operation string

const (
	OperationCreate            Operation = "agent.session.started"
	OperationAgentStatusChange Operation = "agent.session.state_changed.agent"
	OperationDaemonDisconnect  Operation = "agent.session.state_changed.daemon_disconnect"
	OperationDaemonResume      Operation = "agent.session.state_changed.daemon_resume"
	OperationCleanEnd          Operation = "agent.session.ended.clean"
	OperationDaemonEnd         Operation = "agent.session.ended.daemon"
	OperationRecoveryEnd       Operation = "agent.session.ended.recovery"
)

var operations = [...]Operation{
	OperationCreate,
	OperationAgentStatusChange,
	OperationDaemonDisconnect,
	OperationDaemonResume,
	OperationCleanEnd,
	OperationDaemonEnd,
	OperationRecoveryEnd,
}

// Valid reports whether operation is a closed V1 lifecycle operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationCreate,
		OperationAgentStatusChange,
		OperationDaemonDisconnect,
		OperationDaemonResume,
		OperationCleanEnd,
		OperationDaemonEnd,
		OperationRecoveryEnd:
		return true
	default:
		return false
	}
}

// Operations returns every lifecycle operation in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// Lifecycle contains the three fields changed by agent-session lifecycle
// operations. Zero ResumeState and EndReason values represent null.
type Lifecycle struct {
	State       State
	ResumeState State
	EndReason   EndReason
}

var (
	ErrInvalidState       = errors.New("agentsession: invalid state")
	ErrInvalidResumeState = errors.New("agentsession: invalid resume state")
	ErrInvalidEndReason   = errors.New("agentsession: invalid end reason")
	ErrInvalidOperation   = errors.New("agentsession: invalid transition operation")
	ErrInvalidTransition  = errors.New("agentsession: invalid transition")
)

type edge struct {
	from State
	to   State
}

var agentStatusTransitions = map[edge]struct{}{
	{from: StateStarting, to: StateIdle}: {},

	{from: StateIdle, to: StateClaimed}:    {},
	{from: StateIdle, to: StateWorking}:    {},
	{from: StateIdle, to: StateBlocked}:    {},
	{from: StateClaimed, to: StateIdle}:    {},
	{from: StateClaimed, to: StateWorking}: {},
	{from: StateClaimed, to: StateBlocked}: {},
	{from: StateWorking, to: StateIdle}:    {},
	{from: StateWorking, to: StateClaimed}: {},
	{from: StateWorking, to: StateBlocked}: {},
	{from: StateBlocked, to: StateIdle}:    {},
	{from: StateBlocked, to: StateClaimed}: {},
	{from: StateBlocked, to: StateWorking}: {},
}

// Validate verifies persisted resume-state and end-reason consistency.
func (lifecycle Lifecycle) Validate() error {
	if !lifecycle.State.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidState, lifecycle.State)
	}
	if lifecycle.State == StateDisconnected {
		if !lifecycle.ResumeState.Connected() {
			return fmt.Errorf(
				"%w: disconnected session requires a connected state, got %q",
				ErrInvalidResumeState,
				lifecycle.ResumeState,
			)
		}
	} else if lifecycle.ResumeState != StateAbsent {
		return fmt.Errorf(
			"%w: prohibited in state %q",
			ErrInvalidResumeState,
			lifecycle.State,
		)
	}

	if lifecycle.State == StateEnded {
		if !lifecycle.EndReason.Valid() {
			return fmt.Errorf(
				"%w: ended session requires a reason, got %q",
				ErrInvalidEndReason,
				lifecycle.EndReason,
			)
		}
	} else if lifecycle.EndReason != EndReasonAbsent {
		return fmt.Errorf(
			"%w: prohibited in state %q",
			ErrInvalidEndReason,
			lifecycle.State,
		)
	}
	return nil
}

// ValidateTransition rejects every lifecycle edge not assigned to operation.
// Actor authorization, capability validation, CAS, and end cascades remain
// reducer concerns.
func ValidateTransition(operation Operation, from, to Lifecycle) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}

	if from.State == StateAbsent {
		if from.ResumeState != StateAbsent {
			return fmt.Errorf("%w: absent source carries %q", ErrInvalidResumeState, from.ResumeState)
		}
		if from.EndReason != EndReasonAbsent {
			return fmt.Errorf("%w: absent source carries %q", ErrInvalidEndReason, from.EndReason)
		}
		if operation != OperationCreate {
			return invalidTransition(operation, from, to)
		}
	} else if err := from.Validate(); err != nil {
		return err
	}
	if err := to.Validate(); err != nil {
		return err
	}

	if legalTransition(operation, from, to) {
		return nil
	}
	return invalidTransition(operation, from, to)
}

func legalTransition(operation Operation, from, to Lifecycle) bool {
	switch operation {
	case OperationCreate:
		return from == (Lifecycle{}) && to == (Lifecycle{State: StateStarting})
	case OperationAgentStatusChange:
		_, ok := agentStatusTransitions[edge{from: from.State, to: to.State}]
		return ok && from.ResumeState == StateAbsent &&
			from.EndReason == EndReasonAbsent &&
			to.ResumeState == StateAbsent &&
			to.EndReason == EndReasonAbsent
	case OperationDaemonDisconnect:
		return from.State.Connected() &&
			to.State == StateDisconnected &&
			to.ResumeState == from.State &&
			to.EndReason == EndReasonAbsent
	case OperationDaemonResume:
		return from.State == StateDisconnected &&
			to.State == from.ResumeState &&
			to.ResumeState == StateAbsent &&
			to.EndReason == EndReasonAbsent
	case OperationCleanEnd:
		return from.State.Connected() &&
			to == (Lifecycle{State: StateEnded, EndReason: EndReasonClean})
	case OperationDaemonEnd:
		if from.State == StateEnded {
			return false
		}
		switch to.EndReason {
		case EndReasonDisconnectTimeout:
			return from.State == StateDisconnected &&
				to == (Lifecycle{State: StateEnded, EndReason: EndReasonDisconnectTimeout})
		case EndReasonOperator, EndReasonCrashReap:
			return to == (Lifecycle{State: StateEnded, EndReason: to.EndReason})
		default:
			return false
		}
	case OperationRecoveryEnd:
		return from.State != StateEnded &&
			to == (Lifecycle{State: StateEnded, EndReason: EndReasonRecovery})
	default:
		return false
	}
}

func invalidTransition(operation Operation, from, to Lifecycle) error {
	return fmt.Errorf(
		"%w: %s %#v -> %#v",
		ErrInvalidTransition,
		operation,
		from,
		to,
	)
}
