package conflict

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestClosedEnums(t *testing.T) {
	t.Parallel()

	if got, want := MergeKinds(), []MergeKind{MergeKindMerge, MergeKindRebase}; !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeKinds() = %v, want %v", got, want)
	}
	if got, want := Statuses(), []Status{StatusUnresolved, StatusResolved}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Statuses() = %v, want %v", got, want)
	}
	if got, want := ResolutionKinds(), []ResolutionKind{
		ResolutionKindPublication,
		ResolutionKindForced,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolutionKinds() = %v, want %v", got, want)
	}
	if got, want := Operations(), []Operation{
		OperationDetect,
		OperationPublicationResolve,
		OperationForceResolve,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Operations() = %v, want %v", got, want)
	}

	for _, kind := range MergeKinds() {
		if !kind.Valid() {
			t.Errorf("MergeKind(%q).Valid() = false", kind)
		}
	}
	for _, status := range Statuses() {
		if !status.Valid() {
			t.Errorf("Status(%q).Valid() = false", status)
		}
	}
	for _, kind := range ResolutionKinds() {
		if !kind.Valid() {
			t.Errorf("ResolutionKind(%q).Valid() = false", kind)
		}
	}
	for _, operation := range Operations() {
		if !operation.Valid() {
			t.Errorf("Operation(%q).Valid() = false", operation)
		}
	}

	if MergeKind("").Valid() || MergeKind("octopus").Valid() {
		t.Error("MergeKind.Valid() accepted an open value")
	}
	if Status("").Valid() || Status("dismissed").Valid() {
		t.Error("Status.Valid() accepted an open value")
	}
	if ResolutionKindAbsent.Valid() || ResolutionKind("manual").Valid() {
		t.Error("ResolutionKind.Valid() accepted an absent or open value")
	}
	if Operation("").Valid() || Operation("workspace.conflict.deleted").Valid() {
		t.Error("Operation.Valid() accepted an open value")
	}

	mergeKinds := MergeKinds()
	mergeKinds[0] = "changed"
	if MergeKinds()[0] != MergeKindMerge {
		t.Error("MergeKinds() did not return a defensive copy")
	}
}

func TestResolvedIsTerminal(t *testing.T) {
	t.Parallel()

	if StatusUnresolved.Terminal() {
		t.Error("unresolved status is terminal")
	}
	if !StatusResolved.Terminal() {
		t.Error("resolved status is not terminal")
	}
	if Status("unknown").Terminal() {
		t.Error("unknown status is terminal")
	}
}

func TestValidateTransitionAcceptsLegalOperations(t *testing.T) {
	t.Parallel()

	unresolved := validUnresolvedConflict()
	publicationResolved := cloneConflict(unresolved)
	setPublicationResolution(&publicationResolved)
	forcedResolved := cloneConflict(unresolved)
	setForcedResolution(&forcedResolved, "cannot stage resolution")

	tests := []struct {
		name      string
		operation Operation
		before    *Conflict
		after     Conflict
	}{
		{
			name:      "first detection",
			operation: OperationDetect,
			after:     unresolved,
		},
		{
			name:      "exact unresolved redetection",
			operation: OperationDetect,
			before:    conflictPointer(unresolved),
			after:     cloneConflict(unresolved),
		},
		{
			name:      "publication resolution",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
		},
		{
			name:      "forced resolution",
			operation: OperationForceResolve,
			before:    conflictPointer(unresolved),
			after:     forcedResolved,
		},
		{
			name:      "exact resolved redetection is no-op",
			operation: OperationDetect,
			before:    conflictPointer(publicationResolved),
			after:     cloneConflict(publicationResolved),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateTransition(test.operation, test.before, test.after); err != nil {
				t.Fatalf("ValidateTransition() error = %v", err)
			}
		})
	}
}

func TestValidateTransitionRejectsWrongOperationAndIllegalEdges(t *testing.T) {
	t.Parallel()

	unresolved := validUnresolvedConflict()
	publicationResolved := cloneConflict(unresolved)
	setPublicationResolution(&publicationResolved)
	forcedResolved := cloneConflict(unresolved)
	setForcedResolution(&forcedResolved, "reason")

	tests := []struct {
		name      string
		operation Operation
		before    *Conflict
		after     Conflict
		mutate    func(*Conflict)
		want      error
	}{
		{
			name:      "unknown operation",
			operation: "workspace.conflict.deleted",
			after:     unresolved,
			want:      ErrInvalidOperation,
		},
		{
			name:      "detect starts unresolved",
			operation: OperationDetect,
			after:     publicationResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "detect starts at version one",
			operation: OperationDetect,
			after:     unresolved,
			mutate: func(after *Conflict) {
				after.EntityVersion = 2
			},
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "publication resolve requires source",
			operation: OperationPublicationResolve,
			after:     publicationResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "force resolve requires source",
			operation: OperationForceResolve,
			after:     forcedResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "publication operation cannot force resolve",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     forcedResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "force operation cannot publication resolve",
			operation: OperationForceResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "publication resolution cannot leave resolved",
			operation: OperationPublicationResolve,
			before:    conflictPointer(publicationResolved),
			after:     publicationResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "force resolution cannot leave resolved",
			operation: OperationForceResolve,
			before:    conflictPointer(forcedResolved),
			after:     forcedResolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "resolved redetection cannot reset",
			operation: OperationDetect,
			before:    conflictPointer(publicationResolved),
			after:     unresolved,
			want:      ErrInvalidTransition,
		},
		{
			name:      "resolution must increment version",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
			mutate: func(after *Conflict) {
				after.EntityVersion = 1
			},
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "resolution cannot skip version",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
			mutate: func(after *Conflict) {
				after.EntityVersion = 3
			},
			want: ErrInvalidVersionTransition,
		},
		{
			name:      "resolution cannot mutate immutable tuple",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
			mutate: func(after *Conflict) {
				after.CandidateCommit = testGitOID(8)
			},
			want: ErrImmutableTupleChanged,
		},
		{
			name:      "resolution cannot mutate detector paths",
			operation: OperationPublicationResolve,
			before:    conflictPointer(unresolved),
			after:     publicationResolved,
			mutate: func(after *Conflict) {
				after.Paths = []domain.RepositoryPath{"README.md", "src/other.go"}
			},
			want: ErrDetectorPathsChanged,
		},
		{
			name:      "redetection cannot mutate immutable tuple",
			operation: OperationDetect,
			before:    conflictPointer(unresolved),
			after:     unresolved,
			mutate: func(after *Conflict) {
				after.CandidateCommit = testGitOID(8)
			},
			want: ErrImmutableTupleChanged,
		},
		{
			name:      "redetection cannot mutate paths",
			operation: OperationDetect,
			before:    conflictPointer(unresolved),
			after:     unresolved,
			mutate: func(after *Conflict) {
				after.Paths = []domain.RepositoryPath{"README.md", "src/other.go"}
			},
			want: ErrDetectorPathsChanged,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			after := cloneConflict(test.after)
			if test.mutate != nil {
				test.mutate(&after)
			}
			if err := ValidateTransition(test.operation, test.before, after); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateTransitionRejectsVersionOverflow(t *testing.T) {
	t.Parallel()

	before := validUnresolvedConflict()
	before.EntityVersion = domain.MaxSafeInteger
	after := cloneConflict(before)
	setPublicationResolution(&after)
	after.EntityVersion = domain.MaxSafeInteger

	if err := ValidateTransition(OperationPublicationResolve, &before, after); !errors.Is(
		err,
		ErrInvalidVersionTransition,
	) {
		t.Fatalf("ValidateTransition() error = %v, want %v", err, ErrInvalidVersionTransition)
	}
}

func TestCompareRedetectionClassifiesWithoutMutatingResolvedRow(t *testing.T) {
	t.Parallel()

	existing := validUnresolvedConflict()
	setPublicationResolution(&existing)
	before := cloneConflict(existing)

	tests := []struct {
		name   string
		mutate func(*Detection)
		want   RedetectionComparison
	}{
		{
			name: "identical",
			want: RedetectionIdentical,
		},
		{
			name: "immutable tuple mismatch",
			mutate: func(incoming *Detection) {
				incoming.CandidateCommit = testGitOID(8)
			},
			want: RedetectionImmutableTupleMismatch,
		},
		{
			name: "conflict ID mismatch",
			mutate: func(incoming *Detection) {
				incoming.ID = domain.ConflictID("ccf1" +
					"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			},
			want: RedetectionImmutableTupleMismatch,
		},
		{
			name: "path mismatch",
			mutate: func(incoming *Detection) {
				incoming.Paths = []domain.RepositoryPath{"README.md", "src/other.go"}
			},
			want: RedetectionPathMismatch,
		},
		{
			name: "tuple mismatch takes precedence over path mismatch",
			mutate: func(incoming *Detection) {
				incoming.CandidateCommit = testGitOID(8)
				incoming.Paths = []domain.RepositoryPath{"README.md", "src/other.go"}
			},
			want: RedetectionImmutableTupleMismatch,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			incoming := existing.Detection()
			if test.mutate != nil {
				test.mutate(&incoming)
			}
			got, err := CompareRedetection(existing, incoming)
			if err != nil {
				t.Fatalf("CompareRedetection() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("CompareRedetection() = %q, want %q", got, test.want)
			}
		})
	}

	if !reflect.DeepEqual(existing, before) {
		t.Fatalf("CompareRedetection() mutated resolved row: got %+v, want %+v", existing, before)
	}
}

func TestCompareRedetectionRejectsMalformedInputs(t *testing.T) {
	t.Parallel()

	existing := validUnresolvedConflict()
	incoming := existing.Detection()
	incoming.Paths[0] = "bad//path"
	if _, err := CompareRedetection(existing, incoming); !errors.Is(err, ErrInvalidPaths) {
		t.Fatalf("CompareRedetection() error = %v, want %v", err, ErrInvalidPaths)
	}

	existing.ID = "invalid"
	if _, err := CompareRedetection(existing, validUnresolvedConflict().Detection()); !errors.Is(
		err,
		ErrInvalidID,
	) {
		t.Fatalf("CompareRedetection() existing error = %v, want %v", err, ErrInvalidID)
	}
}

func TestDetectionReturnsDefensiveCopies(t *testing.T) {
	t.Parallel()

	value := validUnresolvedConflict()
	wantBases := append([]domain.GitOID(nil), value.MergeBaseOIDs...)
	wantPaths := append([]domain.RepositoryPath(nil), value.Paths...)
	detection := value.Detection()
	detection.MergeBaseOIDs[0] = testGitOID(9)
	detection.Paths[0] = "other.txt"

	if !reflect.DeepEqual(value.MergeBaseOIDs, wantBases) {
		t.Fatalf("Detection merge-base mutation changed Conflict: got %v, want %v", value.MergeBaseOIDs, wantBases)
	}
	if !reflect.DeepEqual(value.Paths, wantPaths) {
		t.Fatalf("Detection path mutation changed Conflict: got %v, want %v", value.Paths, wantPaths)
	}
}

func cloneConflict(value Conflict) Conflict {
	value.MergeBaseOIDs = append([]domain.GitOID(nil), value.MergeBaseOIDs...)
	value.Paths = append([]domain.RepositoryPath(nil), value.Paths...)
	return value
}

func conflictPointer(value Conflict) *Conflict {
	cloned := cloneConflict(value)
	return &cloned
}
