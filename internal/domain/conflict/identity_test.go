package conflict

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const testWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")

func TestNewIdentityInputExposesExactHashPreimageFields(t *testing.T) {
	t.Parallel()

	bases := []domain.GitOID{testGitOID(1), testGitOID(2)}
	input, err := NewIdentityInput(
		testWorkspaceID,
		1,
		MergeKindRebase,
		testPublicationID,
		testGitOID(5),
		bases,
		testGitOID(3),
		testGitOID(4),
	)
	if err != nil {
		t.Fatalf("NewIdentityInput() error = %v", err)
	}

	if got := input.WorkspaceID(); got != testWorkspaceID {
		t.Errorf("IdentityInput.WorkspaceID() = %q, want %q", got, testWorkspaceID)
	}
	if got := input.MergeInputsVersion(); got != 1 {
		t.Errorf("IdentityInput.MergeInputsVersion() = %d, want 1", got)
	}
	if got := input.MergeKind(); got != MergeKindRebase {
		t.Errorf("IdentityInput.MergeKind() = %q, want %q", got, MergeKindRebase)
	}
	if got := input.PublicationID(); got != testPublicationID {
		t.Errorf("IdentityInput.PublicationID() = %q, want %q", got, testPublicationID)
	}
	if got := input.ReplayCommitOID(); got != testGitOID(5) {
		t.Errorf("IdentityInput.ReplayCommitOID() = %q, want %q", got, testGitOID(5))
	}
	if got := input.MergeBaseOIDs(); !reflect.DeepEqual(got, bases) {
		t.Errorf("IdentityInput.MergeBaseOIDs() = %v, want %v", got, bases)
	}
	if got := input.CanonicalCommit(); got != testGitOID(3) {
		t.Errorf("IdentityInput.CanonicalCommit() = %q, want %q", got, testGitOID(3))
	}
	if got := input.CandidateCommit(); got != testGitOID(4) {
		t.Errorf("IdentityInput.CandidateCommit() = %q, want %q", got, testGitOID(4))
	}
	if err := input.Validate(); err != nil {
		t.Fatalf("IdentityInput.Validate() error = %v", err)
	}
}

func TestNewIdentityInputValidatesAmbientIdentityFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		workspace domain.UUIDv4
		version   uint64
		want      error
	}{
		{
			name:      "workspace ID",
			workspace: "01890f47-3e72-7d5a-8c9b-123456789abc",
			version:   1,
			want:      ErrInvalidWorkspaceID,
		},
		{
			name:      "zero merge-inputs version",
			workspace: testWorkspaceID,
			version:   0,
			want:      ErrInvalidMergeInputsVersion,
		},
		{
			name:      "merge-inputs version over signed JSON limit",
			workspace: testWorkspaceID,
			version:   domain.MaxSafeInteger + 1,
			want:      ErrInvalidMergeInputsVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewIdentityInput(
				test.workspace,
				test.version,
				MergeKindMerge,
				testPublicationID,
				"",
				[]domain.GitOID{testGitOID(1)},
				testGitOID(3),
				testGitOID(4),
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewIdentityInput() error = %v, want %v", err, test.want)
			}
			if got != (IdentityInput{}) {
				t.Fatalf("NewIdentityInput() = %+v after error, want zero value", got)
			}
		})
	}
}

func TestNewIdentityInputValidatesGraphFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		kind      MergeKind
		replay    domain.GitOID
		bases     []domain.GitOID
		canonical domain.GitOID
		candidate domain.GitOID
		want      error
	}{
		{
			name:      "merge replay nullability",
			kind:      MergeKindMerge,
			replay:    testGitOID(5),
			bases:     makeGitOIDs(1),
			canonical: testGitOID(3),
			candidate: testGitOID(4),
			want:      ErrInvalidReplayCommitOID,
		},
		{
			name:      "rebase replay nullability",
			kind:      MergeKindRebase,
			bases:     makeGitOIDs(1),
			canonical: testGitOID(3),
			candidate: testGitOID(4),
			want:      ErrInvalidReplayCommitOID,
		},
		{
			name:      "unsorted merge bases",
			kind:      MergeKindMerge,
			bases:     []domain.GitOID{testGitOID(2), testGitOID(1)},
			canonical: testGitOID(3),
			candidate: testGitOID(4),
			want:      ErrMergeBaseOIDsNotSortedUnique,
		},
		{
			name:      "mixed object formats",
			kind:      MergeKindMerge,
			bases:     []domain.GitOID{testGitOID(1)},
			canonical: testGitOID(3),
			candidate: testSHA256GitOID(4),
			want:      ErrGitObjectFormatMismatch,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewIdentityInput(
				testWorkspaceID,
				1,
				test.kind,
				testPublicationID,
				test.replay,
				test.bases,
				test.canonical,
				test.candidate,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewIdentityInput() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestIdentityInputAcceptsVersionBoundsAndDefensivelyCopiesBases(t *testing.T) {
	t.Parallel()

	for _, version := range []uint64{1, domain.MaxSafeInteger} {
		bases := []domain.GitOID{testGitOID(1), testGitOID(2)}
		wantBases := append([]domain.GitOID(nil), bases...)
		input, err := NewIdentityInput(
			testWorkspaceID,
			version,
			MergeKindMerge,
			testPublicationID,
			"",
			bases,
			testGitOID(3),
			testGitOID(4),
		)
		if err != nil {
			t.Fatalf("NewIdentityInput(version=%d) error = %v", version, err)
		}

		bases[0] = testGitOID(9)
		if got := input.MergeBaseOIDs(); !reflect.DeepEqual(got, wantBases) {
			t.Fatalf("caller mutation changed IdentityInput: got %v, want %v", got, wantBases)
		}
		exposed := input.MergeBaseOIDs()
		exposed[0] = testGitOID(8)
		if got := input.MergeBaseOIDs(); !reflect.DeepEqual(got, wantBases) {
			t.Fatalf("returned-slice mutation changed IdentityInput: got %v, want %v", got, wantBases)
		}
	}
}

func TestIdentityInputContainsNeitherConflictIDNorDetectorPaths(t *testing.T) {
	t.Parallel()

	first := validUnresolvedConflict().Detection()
	second := validUnresolvedConflict().Detection()
	second.ID = domain.ConflictID(
		"ccf1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	second.Paths = []domain.RepositoryPath{"different.txt"}

	firstInput, err := first.IdentityInput(testWorkspaceID, 1)
	if err != nil {
		t.Fatalf("first Detection.IdentityInput() error = %v", err)
	}
	secondInput, err := second.IdentityInput(testWorkspaceID, 1)
	if err != nil {
		t.Fatalf("second Detection.IdentityInput() error = %v", err)
	}
	if firstInput != secondInput {
		t.Error("conflict ID or detector paths changed IdentityInput")
	}

	typ := reflect.TypeOf(IdentityInput{})
	for _, prohibited := range []string{
		"ID",
		"ConflictID",
		"Paths",
		"ResolutionKind",
		"ResolutionPublicationID",
		"ForceReason",
		"ResolvedByDeviceID",
		"EntityVersion",
	} {
		if _, found := typ.FieldByName(prohibited); found {
			t.Errorf("IdentityInput unexpectedly exposes field %q", prohibited)
		}
	}
}
