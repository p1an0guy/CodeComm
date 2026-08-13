// Package task defines the task entity and its pure state machine.
package task

import (
	"errors"
	"fmt"
)

// State is a committed task lifecycle state.
type State string

const (
	// StateAbsent is the source sentinel used only by task creation.
	StateAbsent State = ""

	StateBacklog    State = "backlog"
	StateReady      State = "ready"
	StateClaimed    State = "claimed"
	StateInProgress State = "in_progress"
	StateBlocked    State = "blocked"
	StateDone       State = "done"
	StateCancelled  State = "cancelled"
)

var states = [...]State{
	StateBacklog,
	StateReady,
	StateClaimed,
	StateInProgress,
	StateBlocked,
	StateDone,
	StateCancelled,
}

// Valid reports whether state is a committed state. StateAbsent is not a
// committed state.
func (state State) Valid() bool {
	switch state {
	case StateBacklog, StateReady, StateClaimed, StateInProgress, StateBlocked, StateDone, StateCancelled:
		return true
	default:
		return false
	}
}

// Terminal reports whether no transition may leave state.
func (state State) Terminal() bool {
	return state == StateDone || state == StateCancelled
}

// States returns all committed states in stable lifecycle order.
func States() []State {
	result := make([]State, len(states))
	copy(result, states[:])
	return result
}

// Operation identifies why an edge is being traversed. Forced and voluntary
// releases are distinct because only the forced form may use ready -> ready.
type Operation string

const (
	OperationCreate           Operation = "task.created"
	OperationStateChange      Operation = "task.state_changed"
	OperationClaim            Operation = "task.claimed"
	OperationReleaseVoluntary Operation = "task.released.voluntary"
	OperationReleaseForced    Operation = "task.released.forced"
	OperationReassign         Operation = "task.reassigned"
	OperationCancel           Operation = "task.cancelled"
	OperationSessionEnded     Operation = "agent.session.ended"
	OperationRecoveryRelease  Operation = "recovery.release"
)

var operations = [...]Operation{
	OperationCreate,
	OperationStateChange,
	OperationClaim,
	OperationReleaseVoluntary,
	OperationReleaseForced,
	OperationReassign,
	OperationCancel,
	OperationSessionEnded,
	OperationRecoveryRelease,
}

// Valid reports whether operation is a closed V1 task transition operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationCreate,
		OperationStateChange,
		OperationClaim,
		OperationReleaseVoluntary,
		OperationReleaseForced,
		OperationReassign,
		OperationCancel,
		OperationSessionEnded,
		OperationRecoveryRelease:
		return true
	default:
		return false
	}
}

// Operations returns all task transition operations in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

var (
	ErrInvalidState      = errors.New("task: invalid state")
	ErrInvalidOperation  = errors.New("task: invalid transition operation")
	ErrInvalidTransition = errors.New("task: invalid transition")
)

type edge struct {
	from State
	to   State
}

var legalTransitions = map[Operation]map[edge]struct{}{
	OperationCreate: {
		{from: StateAbsent, to: StateBacklog}: {},
	},
	OperationStateChange: {
		{from: StateBacklog, to: StateReady}:      {},
		{from: StateReady, to: StateBacklog}:      {},
		{from: StateClaimed, to: StateInProgress}: {},
		{from: StateInProgress, to: StateBlocked}: {},
		{from: StateInProgress, to: StateDone}:    {},
		{from: StateBlocked, to: StateInProgress}: {},
	},
	OperationClaim: {
		{from: StateReady, to: StateClaimed}: {},
	},
	OperationReleaseVoluntary: releaseEdges(false),
	OperationReleaseForced:    releaseEdges(true),
	OperationReassign:         releaseEdges(true),
	OperationCancel: {
		{from: StateBacklog, to: StateCancelled}:    {},
		{from: StateReady, to: StateCancelled}:      {},
		{from: StateClaimed, to: StateCancelled}:    {},
		{from: StateInProgress, to: StateCancelled}: {},
		{from: StateBlocked, to: StateCancelled}:    {},
	},
	OperationSessionEnded:    releaseEdges(false),
	OperationRecoveryRelease: releaseEdges(false),
}

func releaseEdges(includeReadySelfEdge bool) map[edge]struct{} {
	edges := map[edge]struct{}{
		{from: StateClaimed, to: StateReady}:    {},
		{from: StateInProgress, to: StateReady}: {},
		{from: StateBlocked, to: StateReady}:    {},
	}
	if includeReadySelfEdge {
		edges[edge{from: StateReady, to: StateReady}] = struct{}{}
	}
	return edges
}

// ValidateTransition rejects every edge not assigned to the given operation.
// Actor, role, CAS, dependency, and conflict checks remain reducer concerns.
func ValidateTransition(operation Operation, from, to State) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if from != StateAbsent && !from.Valid() {
		return fmt.Errorf("%w: source %q", ErrInvalidState, from)
	}
	if !to.Valid() {
		return fmt.Errorf("%w: destination %q", ErrInvalidState, to)
	}
	if _, ok := legalTransitions[operation][edge{from: from, to: to}]; !ok {
		return fmt.Errorf("%w: %s %q -> %q", ErrInvalidTransition, operation, from, to)
	}
	return nil
}
