package conflict

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	testConflictID    = domain.ConflictID("ccf1" + strings.Repeat("a", 64))
	testPublicationID = domain.UUIDv7(
		"01890f47-3e72-7d5a-8c9b-123456789abc",
	)
	testResolutionPublicationID = domain.UUIDv7(
		"01890f47-3e72-7d5a-8c9b-123456789abd",
	)
	testResolverDeviceID = domain.DeviceID("cc1" + strings.Repeat("b", 64))
)

func TestConflictValidateAcceptsMergeAndRebase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Conflict)
	}{
		{name: "merge"},
		{
			name: "rebase",
			mutate: func(value *Conflict) {
				value.MergeKind = MergeKindRebase
				value.ReplayCommitOID = testGitOID(5)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validUnresolvedConflict()
			if test.mutate != nil {
				test.mutate(&value)
			}
			if err := value.Validate(); err != nil {
				t.Fatalf("Conflict.Validate() error = %v", err)
			}
		})
	}
}

func TestConflictValidateRejectsInvalidImmutableFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Conflict)
		want   error
	}{
		{
			name: "conflict ID",
			mutate: func(value *Conflict) {
				value.ID = "ccf1bad"
			},
			want: ErrInvalidID,
		},
		{
			name: "publication ID",
			mutate: func(value *Conflict) {
				value.PublicationID = "not-a-uuid"
			},
			want: ErrInvalidPublicationID,
		},
		{
			name: "merge kind",
			mutate: func(value *Conflict) {
				value.MergeKind = "octopus"
			},
			want: ErrInvalidMergeKind,
		},
		{
			name: "merge with replay commit",
			mutate: func(value *Conflict) {
				value.ReplayCommitOID = testGitOID(5)
			},
			want: ErrInvalidReplayCommitOID,
		},
		{
			name: "rebase without replay commit",
			mutate: func(value *Conflict) {
				value.MergeKind = MergeKindRebase
			},
			want: ErrInvalidReplayCommitOID,
		},
		{
			name: "rebase with malformed replay commit",
			mutate: func(value *Conflict) {
				value.MergeKind = MergeKindRebase
				value.ReplayCommitOID = "sha1:bad"
			},
			want: ErrInvalidReplayCommitOID,
		},
		{
			name: "canonical commit",
			mutate: func(value *Conflict) {
				value.CanonicalCommit = "sha1:bad"
			},
			want: ErrInvalidCanonicalCommit,
		},
		{
			name: "candidate commit",
			mutate: func(value *Conflict) {
				value.CandidateCommit = "sha1:bad"
			},
			want: ErrInvalidCandidateCommit,
		},
		{
			name: "malformed merge base",
			mutate: func(value *Conflict) {
				value.MergeBaseOIDs[0] = "sha1:bad"
			},
			want: ErrInvalidMergeBaseOIDs,
		},
		{
			name: "unsorted merge bases",
			mutate: func(value *Conflict) {
				value.MergeBaseOIDs[0], value.MergeBaseOIDs[1] =
					value.MergeBaseOIDs[1], value.MergeBaseOIDs[0]
			},
			want: ErrMergeBaseOIDsNotSortedUnique,
		},
		{
			name: "duplicate merge bases",
			mutate: func(value *Conflict) {
				value.MergeBaseOIDs[1] = value.MergeBaseOIDs[0]
			},
			want: ErrMergeBaseOIDsNotSortedUnique,
		},
		{
			name: "too many merge bases",
			mutate: func(value *Conflict) {
				value.MergeBaseOIDs = makeGitOIDs(MaxMergeBaseOIDs + 1)
			},
			want: ErrInvalidMergeBaseOIDs,
		},
		{
			name: "mixed candidate format",
			mutate: func(value *Conflict) {
				value.CandidateCommit = testSHA256GitOID(4)
			},
			want: ErrGitObjectFormatMismatch,
		},
		{
			name: "mixed replay format",
			mutate: func(value *Conflict) {
				value.MergeKind = MergeKindRebase
				value.ReplayCommitOID = testSHA256GitOID(5)
			},
			want: ErrGitObjectFormatMismatch,
		},
		{
			name: "mixed merge base format",
			mutate: func(value *Conflict) {
				value.MergeBaseOIDs = []domain.GitOID{testSHA256GitOID(1)}
			},
			want: ErrGitObjectFormatMismatch,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validUnresolvedConflict()
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Conflict.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestConflictValidateRejectsInvalidPathsAndVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Conflict)
		want   error
	}{
		{
			name: "malformed path",
			mutate: func(value *Conflict) {
				value.Paths[0] = "bad//path"
			},
			want: ErrInvalidPaths,
		},
		{
			name: "unsorted paths",
			mutate: func(value *Conflict) {
				value.Paths[0], value.Paths[1] = value.Paths[1], value.Paths[0]
			},
			want: ErrPathsNotSortedUnique,
		},
		{
			name: "duplicate paths",
			mutate: func(value *Conflict) {
				value.Paths[1] = value.Paths[0]
			},
			want: ErrPathsNotSortedUnique,
		},
		{
			name: "too many paths",
			mutate: func(value *Conflict) {
				value.Paths = makePaths(MaxPaths + 1)
			},
			want: ErrInvalidPaths,
		},
		{
			name: "zero entity version",
			mutate: func(value *Conflict) {
				value.EntityVersion = 0
			},
			want: ErrInvalidEntityVersion,
		},
		{
			name: "entity version over signed JSON limit",
			mutate: func(value *Conflict) {
				value.EntityVersion = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidEntityVersion,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validUnresolvedConflict()
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Conflict.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestConflictValidateAcceptsExactCollectionAndVersionBounds(t *testing.T) {
	t.Parallel()

	value := validUnresolvedConflict()
	value.MergeBaseOIDs = makeGitOIDs(MaxMergeBaseOIDs)
	value.Paths = makePaths(MaxPaths)
	value.EntityVersion = domain.MaxSafeInteger
	if err := value.Validate(); err != nil {
		t.Fatalf("Conflict.Validate() at exact bounds error = %v", err)
	}
}

func TestConflictValidateEnforcesResolutionFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Conflict)
		want   error
	}{
		{
			name: "unresolved with resolution kind",
			mutate: func(value *Conflict) {
				value.ResolutionKind = ResolutionKindPublication
			},
			want: ErrInvalidResolutionKind,
		},
		{
			name: "unresolved with resolution publication",
			mutate: func(value *Conflict) {
				value.ResolutionPublicationID = testResolutionPublicationID
			},
			want: ErrInvalidResolutionPublicationID,
		},
		{
			name: "unresolved with force reason",
			mutate: func(value *Conflict) {
				value.ForceReason = "operator decision"
			},
			want: ErrInvalidForceReason,
		},
		{
			name: "unresolved with resolver",
			mutate: func(value *Conflict) {
				value.ResolvedByDeviceID = testResolverDeviceID
			},
			want: ErrInvalidResolverDeviceID,
		},
		{
			name: "resolved without resolution kind",
			mutate: func(value *Conflict) {
				value.Status = StatusResolved
				value.ResolvedByDeviceID = testResolverDeviceID
			},
			want: ErrInvalidResolutionKind,
		},
		{
			name: "publication without publication ID",
			mutate: func(value *Conflict) {
				setPublicationResolution(value)
				value.ResolutionPublicationID = ""
			},
			want: ErrInvalidResolutionPublicationID,
		},
		{
			name: "publication with malformed publication ID",
			mutate: func(value *Conflict) {
				setPublicationResolution(value)
				value.ResolutionPublicationID = "not-a-uuid"
			},
			want: ErrInvalidResolutionPublicationID,
		},
		{
			name: "publication with force reason",
			mutate: func(value *Conflict) {
				setPublicationResolution(value)
				value.ForceReason = "prohibited"
			},
			want: ErrInvalidForceReason,
		},
		{
			name: "forced with publication ID",
			mutate: func(value *Conflict) {
				setForcedResolution(value, "x")
				value.ResolutionPublicationID = testResolutionPublicationID
			},
			want: ErrInvalidResolutionPublicationID,
		},
		{
			name: "forced with empty reason",
			mutate: func(value *Conflict) {
				setForcedResolution(value, "")
			},
			want: ErrInvalidForceReason,
		},
		{
			name: "forced with oversized reason",
			mutate: func(value *Conflict) {
				setForcedResolution(value, strings.Repeat("x", MaxForceReasonBytes+1))
			},
			want: ErrInvalidForceReason,
		},
		{
			name: "forced with invalid UTF-8 reason",
			mutate: func(value *Conflict) {
				setForcedResolution(value, string([]byte{0xff}))
			},
			want: ErrInvalidForceReason,
		},
		{
			name: "resolved without resolver",
			mutate: func(value *Conflict) {
				setPublicationResolution(value)
				value.ResolvedByDeviceID = ""
			},
			want: ErrInvalidResolverDeviceID,
		},
		{
			name: "resolved with malformed resolver",
			mutate: func(value *Conflict) {
				setPublicationResolution(value)
				value.ResolvedByDeviceID = "not-a-device"
			},
			want: ErrInvalidResolverDeviceID,
		},
		{
			name: "unknown status",
			mutate: func(value *Conflict) {
				value.Status = "dismissed"
			},
			want: ErrInvalidStatus,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validUnresolvedConflict()
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Conflict.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestConflictValidateAcceptsResolutionBoundaries(t *testing.T) {
	t.Parallel()

	publication := validUnresolvedConflict()
	setPublicationResolution(&publication)
	if err := publication.Validate(); err != nil {
		t.Fatalf("publication-resolved Conflict.Validate() error = %v", err)
	}

	for _, reason := range []string{"x", strings.Repeat("x", MaxForceReasonBytes)} {
		forced := validUnresolvedConflict()
		setForcedResolution(&forced, reason)
		if err := forced.Validate(); err != nil {
			t.Fatalf("forced Conflict.Validate() with %d-byte reason error = %v", len(reason), err)
		}
	}
}

func validUnresolvedConflict() Conflict {
	return Conflict{
		ID:              testConflictID,
		PublicationID:   testPublicationID,
		MergeKind:       MergeKindMerge,
		MergeBaseOIDs:   []domain.GitOID{testGitOID(1), testGitOID(2)},
		CanonicalCommit: testGitOID(3),
		CandidateCommit: testGitOID(4),
		Paths:           []domain.RepositoryPath{"README.md", "src/main.go"},
		Status:          StatusUnresolved,
		EntityVersion:   1,
	}
}

func setPublicationResolution(value *Conflict) {
	value.Status = StatusResolved
	value.ResolutionKind = ResolutionKindPublication
	value.ResolutionPublicationID = testResolutionPublicationID
	value.ResolvedByDeviceID = testResolverDeviceID
	value.EntityVersion = 2
}

func setForcedResolution(value *Conflict, reason string) {
	value.Status = StatusResolved
	value.ResolutionKind = ResolutionKindForced
	value.ForceReason = reason
	value.ResolvedByDeviceID = testResolverDeviceID
	value.EntityVersion = 2
}

func testGitOID(value int) domain.GitOID {
	return domain.GitOID(fmt.Sprintf("sha1:%040x", value))
}

func testSHA256GitOID(value int) domain.GitOID {
	return domain.GitOID(fmt.Sprintf("sha256:%064x", value))
}

func makeGitOIDs(count int) []domain.GitOID {
	result := make([]domain.GitOID, count)
	for index := range result {
		result[index] = testGitOID(index + 1)
	}
	return result
}

func makePaths(count int) []domain.RepositoryPath {
	result := make([]domain.RepositoryPath, count)
	for index := range result {
		result[index] = domain.RepositoryPath(fmt.Sprintf("path/%04d.txt", index))
	}
	return result
}
