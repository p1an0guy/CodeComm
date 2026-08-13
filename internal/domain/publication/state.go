package publication

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
)

// State is a committed publication lifecycle state.
type State string

const (
	StateProposed  State = "proposed"
	StateApproved  State = "approved"
	StateApplied   State = "applied"
	StateRejected  State = "rejected"
	StateWithdrawn State = "withdrawn"
)

var states = [...]State{
	StateProposed,
	StateApproved,
	StateApplied,
	StateRejected,
	StateWithdrawn,
}

// Valid reports whether state is a closed V1 publication state.
func (state State) Valid() bool {
	switch state {
	case StateProposed, StateApproved, StateApplied, StateRejected, StateWithdrawn:
		return true
	default:
		return false
	}
}

// Terminal reports whether normal or recovery withdrawal cannot leave state.
func (state State) Terminal() bool {
	return state == StateApplied || state == StateRejected || state == StateWithdrawn
}

// States returns every committed state in stable order.
func States() []State {
	result := make([]State, len(states))
	copy(result, states[:])
	return result
}

// TerminalSource records the operation that entered a terminal state.
type TerminalSource string

const (
	TerminalSourceAbsent   TerminalSource = ""
	TerminalSourceReview   TerminalSource = "review"
	TerminalSourceApply    TerminalSource = "apply"
	TerminalSourceWithdraw TerminalSource = "withdraw"
	TerminalSourceRecovery TerminalSource = "recovery"
)

// Valid reports whether source is a closed, non-null V1 terminal source.
func (source TerminalSource) Valid() bool {
	switch source {
	case TerminalSourceReview,
		TerminalSourceApply,
		TerminalSourceWithdraw,
		TerminalSourceRecovery:
		return true
	default:
		return false
	}
}

// ReviewVerdict is a retained publication-review decision.
type ReviewVerdict string

const (
	ReviewVerdictAbsent  ReviewVerdict = ""
	ReviewVerdictApprove ReviewVerdict = "approve"
	ReviewVerdictReject  ReviewVerdict = "reject"
)

// Valid reports whether verdict is a closed, non-null V1 verdict.
func (verdict ReviewVerdict) Valid() bool {
	return verdict == ReviewVerdictApprove || verdict == ReviewVerdictReject
}

// ReviewActorType identifies whether a review was explicit human judgment or
// came from an agent binding.
type ReviewActorType string

const (
	ReviewActorAbsent ReviewActorType = ""
	ReviewActorAgent  ReviewActorType = "agent"
	ReviewActorHuman  ReviewActorType = "human"
)

// Valid reports whether actorType is a closed, non-null V1 review actor.
func (actorType ReviewActorType) Valid() bool {
	return actorType == ReviewActorAgent || actorType == ReviewActorHuman
}

// RecoveryDecisionReason is the deterministic reason used by the recovery
// boundary transform for nonterminal publications.
const RecoveryDecisionReason = "session recovery invalidated author binding and staging receipts"

// Operation identifies the event or boundary transform driving a lifecycle
// edge.
type Operation string

const (
	OperationReviewApprove    Operation = "publication.reviewed.approve"
	OperationReviewReject     Operation = "publication.reviewed.reject"
	OperationWithdraw         Operation = "publication.withdrawn"
	OperationApply            Operation = "publication.applied"
	OperationRecoveryWithdraw Operation = "recovery.publication.withdrawn"
)

var operations = [...]Operation{
	OperationReviewApprove,
	OperationReviewReject,
	OperationWithdraw,
	OperationApply,
	OperationRecoveryWithdraw,
}

// Valid reports whether operation is a closed V1 transition operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationReviewApprove,
		OperationReviewReject,
		OperationWithdraw,
		OperationApply,
		OperationRecoveryWithdraw:
		return true
	default:
		return false
	}
}

// Operations returns every operation in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

var (
	ErrInvalidState             = errors.New("publication: invalid state")
	ErrInvalidTerminalSource    = errors.New("publication: invalid terminal source")
	ErrInvalidOperation         = errors.New("publication: invalid transition operation")
	ErrInvalidTransition        = errors.New("publication: invalid transition")
	ErrImmutableMetadataChanged = errors.New("publication: immutable metadata changed")
	ErrStagingReceiptsChanged   = errors.New("publication: staging receipts changed outside apply")
)

type stateEdge struct {
	from State
	to   State
}

var legalEdges = map[Operation]map[stateEdge]struct{}{
	OperationReviewApprove: {
		{from: StateProposed, to: StateApproved}: {},
	},
	OperationReviewReject: {
		{from: StateProposed, to: StateRejected}: {},
		{from: StateApproved, to: StateRejected}: {},
	},
	OperationWithdraw: {
		{from: StateProposed, to: StateWithdrawn}: {},
		{from: StateApproved, to: StateWithdrawn}: {},
	},
	OperationApply: {
		{from: StateApproved, to: StateApplied}: {},
	},
	OperationRecoveryWithdraw: {
		{from: StateProposed, to: StateWithdrawn}: {},
		{from: StateApproved, to: StateWithdrawn}: {},
	},
}

// ValidateTransition checks one complete publication mutation. It enforces
// immutable metadata, operation-specific mutable fields, receipt replacement
// only at apply, and normal-versus-recovery entity-version rules. Reducer
// authority and CAS checks remain outside this package.
func ValidateTransition(operation Operation, from, to Publication) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if err := from.Validate(); err != nil {
		return err
	}
	if err := to.Validate(); err != nil {
		return fmt.Errorf("%w: invalid destination: %w", ErrInvalidTransition, err)
	}
	if !from.Metadata.Equal(to.Metadata) {
		return ErrImmutableMetadataChanged
	}
	if _, ok := legalEdges[operation][stateEdge{from: from.State, to: to.State}]; !ok {
		return invalidTransition(operation, from, to)
	}

	if operation == OperationRecoveryWithdraw {
		if to.EntityVersion != 1 {
			return invalidTransition(operation, from, to)
		}
	} else if from.EntityVersion >= domain.MaxSafeInteger ||
		to.EntityVersion != from.EntityVersion+1 {
		return invalidTransition(operation, from, to)
	}

	receiptsEqual := slices.Equal(from.StagingReceipts, to.StagingReceipts)
	if operation != OperationApply && !receiptsEqual {
		return ErrStagingReceiptsChanged
	}

	switch operation {
	case OperationReviewApprove, OperationReviewReject:
		// The operation sets the review tuple. Complete destination validation
		// enforces the operation's required verdict through its target state.
	case OperationWithdraw:
		if !sameReview(from, to) {
			return invalidTransition(operation, from, to)
		}
	case OperationApply:
		if !sameReview(from, to) || !to.CanonicalLineageMember {
			return invalidTransition(operation, from, to)
		}
	case OperationRecoveryWithdraw:
		if !sameReview(from, to) ||
			to.DecisionReason == nil ||
			*to.DecisionReason != RecoveryDecisionReason {
			return invalidTransition(operation, from, to)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

func sameReview(left, right Publication) bool {
	return left.ReviewVerdict == right.ReviewVerdict &&
		left.ReviewerDeviceID == right.ReviewerDeviceID &&
		left.ReviewerAgentSessionID == right.ReviewerAgentSessionID &&
		left.ReviewActorType == right.ReviewActorType
}

func invalidTransition(operation Operation, from, to Publication) error {
	return fmt.Errorf(
		"%w: %s %q(v%d) -> %q(v%d)",
		ErrInvalidTransition,
		operation,
		from.State,
		from.EntityVersion,
		to.State,
		to.EntityVersion,
	)
}
