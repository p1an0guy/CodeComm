package publication

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestValidateTransitionAcceptsExactlyDocumentedStateEdges(t *testing.T) {
	t.Parallel()

	type edge struct {
		operation Operation
		from      State
		to        State
	}
	legal := map[edge]struct{}{
		{OperationReviewApprove, StateProposed, StateApproved}:     {},
		{OperationReviewReject, StateProposed, StateRejected}:      {},
		{OperationReviewReject, StateApproved, StateRejected}:      {},
		{OperationWithdraw, StateProposed, StateWithdrawn}:         {},
		{OperationWithdraw, StateApproved, StateWithdrawn}:         {},
		{OperationApply, StateApproved, StateApplied}:              {},
		{OperationRecoveryWithdraw, StateProposed, StateWithdrawn}: {},
		{OperationRecoveryWithdraw, StateApproved, StateWithdrawn}: {},
	}

	for _, operation := range Operations() {
		for _, fromState := range States() {
			for _, toState := range States() {
				from := publicationInState(fromState)
				to := transitionDestination(operation, from, toState)
				candidate := edge{operation, fromState, toState}
				_, want := legal[candidate]
				err := ValidateTransition(operation, from, to)
				if got := err == nil; got != want {
					t.Errorf(
						"ValidateTransition(%q, %q, %q) error = %v, accepted = %t, want %t",
						operation,
						fromState,
						toState,
						err,
						got,
						want,
					)
				}
			}
		}
	}
}

func TestTerminalStatesHaveNoOutgoingNormalOrRecoveryTransition(t *testing.T) {
	t.Parallel()

	for _, state := range []State{StateApplied, StateRejected, StateWithdrawn} {
		from := publicationInState(state)
		for _, operation := range Operations() {
			for _, toState := range States() {
				to := transitionDestination(operation, from, toState)
				if err := ValidateTransition(operation, from, to); !errors.Is(err, ErrInvalidTransition) {
					t.Errorf(
						"ValidateTransition(%q, %q, %q) error = %v, want ErrInvalidTransition",
						operation,
						state,
						toState,
						err,
					)
				}
			}
		}
	}
}

func TestValidateTransitionEnforcesVersionRules(t *testing.T) {
	t.Parallel()

	from := validProposed()
	to := destinationApproved(from)

	for _, version := range []uint64{from.EntityVersion, from.EntityVersion + 2, 0, domain.MaxSafeInteger + 1} {
		candidate := to
		candidate.EntityVersion = version
		if err := ValidateTransition(OperationReviewApprove, from, candidate); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("normal transition to version %d error = %v, want ErrInvalidTransition", version, err)
		}
	}

	from.EntityVersion = domain.MaxSafeInteger
	to = destinationApproved(from)
	to.EntityVersion = domain.MaxSafeInteger
	if err := ValidateTransition(OperationReviewApprove, from, to); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("transition from maximum version error = %v, want ErrInvalidTransition", err)
	}

	for _, startVersion := range []uint64{1, 42, domain.MaxSafeInteger} {
		from := validProposed()
		from.EntityVersion = startVersion
		to := destinationRecoveryWithdrawn(from)
		if err := ValidateTransition(OperationRecoveryWithdraw, from, to); err != nil {
			t.Errorf("recovery from version %d error = %v", startVersion, err)
		}
		to.EntityVersion = 2
		if err := ValidateTransition(OperationRecoveryWithdraw, from, to); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("recovery to version 2 error = %v, want ErrInvalidTransition", err)
		}
	}
}

func TestValidateTransitionEnforcesImmutableMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Metadata)
	}{
		{"publication ID", func(value *Metadata) { value.PublicationID = testReviewerSession }},
		{"proposal event ID", func(value *Metadata) { value.ProposalEventID = testSupersedesID }},
		{"supersedes ID", func(value *Metadata) { value.SupersedesPublicationID = "" }},
		{"task ID", func(value *Metadata) { value.TaskID = "" }},
		{"author device", func(value *Metadata) { value.AuthorDeviceID = testVoterE }},
		{"author session", func(value *Metadata) { value.AuthorAgentSessionID = testReviewerSession }},
		{"base", func(value *Metadata) {
			value.BaseCommit = "sha1:0000000000000000000000000000000000000005"
			value.ParentOIDs[0] = value.BaseCommit
		}},
		{"commit", func(value *Metadata) { value.CommitOID = value.ParentOIDs[1] }},
		{"tree", func(value *Metadata) { value.TreeOID = value.ParentOIDs[1] }},
		{"parents", func(value *Metadata) { value.ParentOIDs = append(value.ParentOIDs, value.ParentOIDs[1]) }},
		{"paths", func(value *Metadata) { value.Paths = append(value.Paths, "z.txt") }},
		{"artifact digest", func(value *Metadata) { value.ArtifactDigest[0]++ }},
		{"conflicts", func(value *Metadata) { value.ResolvesConflictIDs = nil }},
		{"working root", func(value *Metadata) { value.WorkingRootID = testReviewerSession }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			from := validProposed()
			to := destinationApproved(from)
			test.mutate(&to.Metadata)
			if err := ValidateTransition(OperationReviewApprove, from, to); !errors.Is(err, ErrImmutableMetadataChanged) {
				t.Fatalf("ValidateTransition() error = %v, want ErrImmutableMetadataChanged", err)
			}
		})
	}
}

func TestOnlyApplyMayReplaceStagingReceipts(t *testing.T) {
	t.Parallel()

	newReceipts := []StagingReceipt{validReceipt(testVoterB)}
	tests := []struct {
		name      string
		operation Operation
		from      Publication
		to        func(Publication) Publication
	}{
		{"approve", OperationReviewApprove, validProposed(), destinationApproved},
		{"reject", OperationReviewReject, validProposed(), destinationRejected},
		{"withdraw", OperationWithdraw, validProposed(), destinationWithdrawn},
		{"recovery", OperationRecoveryWithdraw, validProposed(), destinationRecoveryWithdrawn},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			to := test.to(test.from)
			to.StagingReceipts = newReceipts
			if err := ValidateTransition(test.operation, test.from, to); !errors.Is(err, ErrStagingReceiptsChanged) {
				t.Fatalf("ValidateTransition() error = %v, want ErrStagingReceiptsChanged", err)
			}
		})
	}

	from := validApproved(ReviewActorHuman)
	to := destinationApplied(from)
	to.StagingReceipts = newReceipts
	if err := ValidateTransition(OperationApply, from, to); err != nil {
		t.Fatalf("apply replacing receipts error = %v", err)
	}
}

func TestTransitionOperationsPermitOnlyTheirOwnFieldChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      Publication
		to        func(Publication) Publication
		mutate    func(*Publication)
	}{
		{"approve changes decision reason", OperationReviewApprove, validProposed(), destinationApproved, func(value *Publication) {
			reason := "not allowed"
			value.DecisionReason = &reason
		}},
		{"approve sets lineage", OperationReviewApprove, validProposed(), destinationApproved, func(value *Publication) {
			value.CanonicalLineageMember = true
		}},
		{"reject uses approve verdict", OperationReviewReject, validProposed(), destinationRejected, func(value *Publication) {
			value.ReviewVerdict = ReviewVerdictApprove
		}},
		{"withdraw changes review", OperationWithdraw, validApproved(ReviewActorHuman), destinationWithdrawn, func(value *Publication) {
			value.ReviewerDeviceID = testVoterC
		}},
		{"apply drops review", OperationApply, validApproved(ReviewActorHuman), destinationApplied, func(value *Publication) {
			clearReview(value)
		}},
		{"apply leaves lineage false", OperationApply, validApproved(ReviewActorHuman), destinationApplied, func(value *Publication) {
			value.CanonicalLineageMember = false
		}},
		{"recovery changes review", OperationRecoveryWithdraw, validApproved(ReviewActorHuman), destinationRecoveryWithdrawn, func(value *Publication) {
			clearReview(value)
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			to := test.to(test.from)
			test.mutate(&to)
			if err := ValidateTransition(test.operation, test.from, to); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("ValidateTransition() error = %v, want ErrInvalidTransition", err)
			}
		})
	}
}

func TestValidateTransitionRejectsUnknownAndInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation Operation
		from      Publication
		to        Publication
		want      error
	}{
		{"unknown operation", "unknown", validProposed(), destinationApproved(validProposed()), ErrInvalidOperation},
		{"invalid source", OperationReviewApprove, Publication{}, destinationApproved(validProposed()), ErrInvalidPublicationID},
		{"invalid destination", OperationReviewApprove, validProposed(), Publication{}, ErrInvalidPublicationID},
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

func TestOperationsReturnsClosedDefensiveSet(t *testing.T) {
	t.Parallel()

	want := []Operation{
		OperationReviewApprove,
		OperationReviewReject,
		OperationWithdraw,
		OperationApply,
		OperationRecoveryWithdraw,
	}
	if got := Operations(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Operations() = %v, want %v", got, want)
	}
	for _, operation := range want {
		if !operation.Valid() {
			t.Errorf("%q.Valid() = false", operation)
		}
	}
	operations := Operations()
	operations[0] = "corrupt"
	if Operations()[0] != OperationReviewApprove {
		t.Fatal("Operations() did not return a defensive copy")
	}
}

func publicationInState(state State) Publication {
	switch state {
	case StateProposed:
		return validProposed()
	case StateApproved:
		return validApproved(ReviewActorHuman)
	case StateApplied:
		return validApplied(true)
	case StateRejected:
		return validRejected()
	case StateWithdrawn:
		return validWithdrawn(false)
	default:
		panic("unhandled state " + state)
	}
}

func transitionDestination(operation Operation, from Publication, state State) Publication {
	var to Publication
	switch state {
	case StateProposed:
		to = validProposed()
	case StateApproved:
		to = destinationApproved(from)
	case StateApplied:
		to = destinationApplied(from)
	case StateRejected:
		to = destinationRejected(from)
	case StateWithdrawn:
		if operation == OperationRecoveryWithdraw {
			to = destinationRecoveryWithdrawn(from)
		} else {
			to = destinationWithdrawn(from)
		}
	default:
		panic("unhandled state " + state)
	}
	to.State = state
	return to
}

func destinationApproved(from Publication) Publication {
	to := clonePublication(from)
	to.State = StateApproved
	to.EntityVersion = from.EntityVersion + 1
	setHumanApproval(&to)
	return to
}

func destinationRejected(from Publication) Publication {
	to := clonePublication(from)
	to.State = StateRejected
	to.TerminalSource = TerminalSourceReview
	to.CanonicalLineageMember = false
	to.ReviewVerdict = ReviewVerdictReject
	to.ReviewerDeviceID = testVoterB
	to.ReviewerAgentSessionID = ""
	to.ReviewActorType = ReviewActorHuman
	to.DecisionReason = nil
	to.EntityVersion = from.EntityVersion + 1
	return to
}

func destinationWithdrawn(from Publication) Publication {
	to := clonePublication(from)
	to.State = StateWithdrawn
	to.TerminalSource = TerminalSourceWithdraw
	to.CanonicalLineageMember = false
	reason := "withdrawn"
	to.DecisionReason = &reason
	to.EntityVersion = from.EntityVersion + 1
	return to
}

func destinationApplied(from Publication) Publication {
	to := clonePublication(from)
	to.State = StateApplied
	to.TerminalSource = TerminalSourceApply
	to.CanonicalLineageMember = true
	to.DecisionReason = nil
	to.EntityVersion = from.EntityVersion + 1
	return to
}

func destinationRecoveryWithdrawn(from Publication) Publication {
	to := clonePublication(from)
	to.State = StateWithdrawn
	to.TerminalSource = TerminalSourceRecovery
	to.CanonicalLineageMember = false
	reason := RecoveryDecisionReason
	to.DecisionReason = &reason
	to.EntityVersion = 1
	return to
}

func clonePublication(value Publication) Publication {
	cloned := value
	cloned.Metadata.ParentOIDs = append([]domain.GitOID(nil), value.Metadata.ParentOIDs...)
	cloned.Metadata.Paths = append([]domain.RepositoryPath(nil), value.Metadata.Paths...)
	cloned.Metadata.ResolvesConflictIDs = append([]domain.ConflictID(nil), value.Metadata.ResolvesConflictIDs...)
	cloned.StagingReceipts = append([]StagingReceipt(nil), value.StagingReceipts...)
	if value.DecisionReason != nil {
		reason := *value.DecisionReason
		cloned.DecisionReason = &reason
	}
	return cloned
}
