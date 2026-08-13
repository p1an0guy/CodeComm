package conflict

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidWorkspaceID        = errors.New("conflict: invalid workspace ID")
	ErrInvalidMergeInputsVersion = errors.New("conflict: invalid merge-inputs version")
)

// IdentityInput is the exact immutable value consumed by the later conflict-ID
// codec. It intentionally excludes the supplied conflict ID, detector paths,
// and all resolution fields. Private fixed-capacity storage prevents callers
// from mutating the preimage after validation.
type IdentityInput struct {
	workspaceID        domain.UUIDv4
	mergeInputsVersion uint64
	mergeKind          MergeKind
	publicationID      domain.UUIDv7
	replayCommitOID    domain.GitOID
	mergeBaseOIDs      [MaxMergeBaseOIDs]domain.GitOID
	mergeBaseCount     uint8
	canonicalCommit    domain.GitOID
	candidateCommit    domain.GitOID
}

// NewIdentityInput validates and copies the fields in the §8.3 conflict-ID JCS
// object. Hashing and JCS encoding deliberately live outside domain.
func NewIdentityInput(
	workspaceID domain.UUIDv4,
	mergeInputsVersion uint64,
	mergeKind MergeKind,
	publicationID domain.UUIDv7,
	replayCommitOID domain.GitOID,
	mergeBaseOIDs []domain.GitOID,
	canonicalCommit domain.GitOID,
	candidateCommit domain.GitOID,
) (IdentityInput, error) {
	if !workspaceID.Valid() {
		return IdentityInput{}, fmt.Errorf("%w: %q", ErrInvalidWorkspaceID, workspaceID)
	}
	if mergeInputsVersion < 1 || !domain.ValidUnsignedInteger(mergeInputsVersion) {
		return IdentityInput{}, fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidMergeInputsVersion,
			domain.MaxSafeInteger,
		)
	}
	if err := validateGraph(
		publicationID,
		mergeKind,
		replayCommitOID,
		mergeBaseOIDs,
		canonicalCommit,
		candidateCommit,
	); err != nil {
		return IdentityInput{}, err
	}

	input := IdentityInput{
		workspaceID:        workspaceID,
		mergeInputsVersion: mergeInputsVersion,
		mergeKind:          mergeKind,
		publicationID:      publicationID,
		replayCommitOID:    replayCommitOID,
		mergeBaseCount:     uint8(len(mergeBaseOIDs)),
		canonicalCommit:    canonicalCommit,
		candidateCommit:    candidateCommit,
	}
	copy(input.mergeBaseOIDs[:], mergeBaseOIDs)
	return input, nil
}

// Validate verifies the complete identity preimage.
func (input IdentityInput) Validate() error {
	if !input.workspaceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidWorkspaceID, input.workspaceID)
	}
	if input.mergeInputsVersion < 1 ||
		!domain.ValidUnsignedInteger(input.mergeInputsVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidMergeInputsVersion,
			domain.MaxSafeInteger,
		)
	}
	return validateGraph(
		input.publicationID,
		input.mergeKind,
		input.replayCommitOID,
		input.mergeBaseOIDs[:input.mergeBaseCount],
		input.canonicalCommit,
		input.candidateCommit,
	)
}

// WorkspaceID returns the workspace-lineage binding.
func (input IdentityInput) WorkspaceID() domain.UUIDv4 {
	return input.workspaceID
}

// MergeInputsVersion returns the committed merge behavior profile.
func (input IdentityInput) MergeInputsVersion() uint64 {
	return input.mergeInputsVersion
}

// MergeKind returns the merge operation class.
func (input IdentityInput) MergeKind() MergeKind {
	return input.mergeKind
}

// PublicationID returns the candidate publication.
func (input IdentityInput) PublicationID() domain.UUIDv7 {
	return input.publicationID
}

// ReplayCommitOID returns the rebase source commit, or the zero value for a
// merge.
func (input IdentityInput) ReplayCommitOID() domain.GitOID {
	return input.replayCommitOID
}

// MergeBaseOIDs returns a copy of the sorted merge bases.
func (input IdentityInput) MergeBaseOIDs() []domain.GitOID {
	result := make([]domain.GitOID, input.mergeBaseCount)
	copy(result, input.mergeBaseOIDs[:input.mergeBaseCount])
	return result
}

// CanonicalCommit returns the current canonical tip.
func (input IdentityInput) CanonicalCommit() domain.GitOID {
	return input.canonicalCommit
}

// CandidateCommit returns the publication candidate tip.
func (input IdentityInput) CandidateCommit() domain.GitOID {
	return input.candidateCommit
}

// IdentityInput returns the immutable hash input corresponding to detection.
// The supplied conflict ID and detector paths are validated separately and are
// not included.
func (detection Detection) IdentityInput(
	workspaceID domain.UUIDv4,
	mergeInputsVersion uint64,
) (IdentityInput, error) {
	return NewIdentityInput(
		workspaceID,
		mergeInputsVersion,
		detection.MergeKind,
		detection.PublicationID,
		detection.ReplayCommitOID,
		detection.MergeBaseOIDs,
		detection.CanonicalCommit,
		detection.CandidateCommit,
	)
}
