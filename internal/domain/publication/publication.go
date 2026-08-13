// Package publication defines the publication entity, staging-receipt shape,
// canonical repository pointer, and pure lifecycle rules.
package publication

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxParentOIDs          = 16
	MaxPaths               = 2048
	MaxResolvedConflictIDs = 64
	MaxDecisionReasonBytes = 1024
)

// SHA256Digest is an exact SHA-256 output.
type SHA256Digest [sha256.Size]byte

// Metadata is the immutable, digest-covered portion of a publication. Empty
// optional IDs represent null.
type Metadata struct {
	PublicationID           domain.UUIDv7
	ProposalEventID         domain.UUIDv7
	SupersedesPublicationID domain.UUIDv7
	TaskID                  domain.UUIDv7
	AuthorDeviceID          domain.DeviceID
	AuthorAgentSessionID    domain.UUIDv7
	BaseCommit              domain.GitOID
	CommitOID               domain.GitOID
	TreeOID                 domain.GitOID
	ParentOIDs              []domain.GitOID
	Paths                   []domain.RepositoryPath
	ArtifactDigest          SHA256Digest
	ResolvesConflictIDs     []domain.ConflictID
	WorkingRootID           domain.UUIDv7
}

var (
	ErrInvalidPublicationID           = errors.New("publication: invalid publication ID")
	ErrInvalidProposalEventID         = errors.New("publication: invalid proposal event ID")
	ErrInvalidSupersedesPublicationID = errors.New("publication: invalid supersedes publication ID")
	ErrInvalidTaskID                  = errors.New("publication: invalid task ID")
	ErrInvalidAuthorDeviceID          = errors.New("publication: invalid author device ID")
	ErrInvalidAuthorAgentSessionID    = errors.New("publication: invalid author agent-session ID")
	ErrInvalidBaseCommit              = errors.New("publication: invalid base commit")
	ErrInvalidCommitOID               = errors.New("publication: invalid commit OID")
	ErrInvalidTreeOID                 = errors.New("publication: invalid tree OID")
	ErrObjectFormatMismatch           = errors.New("publication: Git object format mismatch")
	ErrInvalidParentOIDs              = errors.New("publication: invalid parent OIDs")
	ErrInvalidPaths                   = errors.New("publication: invalid paths")
	ErrInvalidConflictIDs             = errors.New("publication: invalid resolved conflict IDs")
	ErrInvalidWorkingRootID           = errors.New("publication: invalid working-root ID")
	ErrInvalidReview                  = errors.New("publication: invalid review fields")
	ErrInvalidDecisionReason          = errors.New("publication: invalid decision reason")
	ErrInvalidCanonicalLineage        = errors.New("publication: invalid canonical-lineage membership")
	ErrInvalidEntityVersion           = errors.New("publication: invalid entity version")
)

// Validate checks metadata invariants derivable without repository, actor,
// task, lease, conflict, or event lookups.
func (metadata Metadata) Validate() error {
	if !metadata.PublicationID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidPublicationID, metadata.PublicationID)
	}
	if !metadata.ProposalEventID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidProposalEventID, metadata.ProposalEventID)
	}
	if metadata.SupersedesPublicationID != "" {
		if !metadata.SupersedesPublicationID.Valid() ||
			metadata.SupersedesPublicationID == metadata.PublicationID {
			return fmt.Errorf(
				"%w: %q",
				ErrInvalidSupersedesPublicationID,
				metadata.SupersedesPublicationID,
			)
		}
	}
	if metadata.TaskID != "" && !metadata.TaskID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidTaskID, metadata.TaskID)
	}
	if !metadata.AuthorDeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidAuthorDeviceID, metadata.AuthorDeviceID)
	}
	if !metadata.AuthorAgentSessionID.Valid() {
		return fmt.Errorf(
			"%w: %q",
			ErrInvalidAuthorAgentSessionID,
			metadata.AuthorAgentSessionID,
		)
	}
	if !metadata.BaseCommit.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidBaseCommit, metadata.BaseCommit)
	}
	if !metadata.CommitOID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCommitOID, metadata.CommitOID)
	}
	if !metadata.TreeOID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidTreeOID, metadata.TreeOID)
	}

	objectFormat := metadata.BaseCommit.ObjectFormat()
	if metadata.CommitOID.ObjectFormat() != objectFormat ||
		metadata.TreeOID.ObjectFormat() != objectFormat {
		return fmt.Errorf("%w: base, commit, and tree", ErrObjectFormatMismatch)
	}
	if err := metadata.validateParents(objectFormat); err != nil {
		return err
	}
	if err := metadata.validatePaths(); err != nil {
		return err
	}
	if err := metadata.validateConflictIDs(); err != nil {
		return err
	}
	if !metadata.WorkingRootID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidWorkingRootID, metadata.WorkingRootID)
	}
	return nil
}

func (metadata Metadata) validateParents(objectFormat domain.GitObjectFormat) error {
	if len(metadata.ParentOIDs) < 1 || len(metadata.ParentOIDs) > MaxParentOIDs {
		return fmt.Errorf(
			"%w: got %d entries, want 1..%d",
			ErrInvalidParentOIDs,
			len(metadata.ParentOIDs),
			MaxParentOIDs,
		)
	}
	if metadata.ParentOIDs[0] != metadata.BaseCommit {
		return fmt.Errorf("%w: first parent must equal base commit", ErrInvalidParentOIDs)
	}
	for index, oid := range metadata.ParentOIDs {
		if !oid.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidParentOIDs, index)
		}
		if oid.ObjectFormat() != objectFormat {
			return fmt.Errorf("%w: parent entry %d", ErrObjectFormatMismatch, index)
		}
	}
	return nil
}

func (metadata Metadata) validatePaths() error {
	if len(metadata.Paths) < 1 || len(metadata.Paths) > MaxPaths {
		return fmt.Errorf(
			"%w: got %d entries, want 1..%d",
			ErrInvalidPaths,
			len(metadata.Paths),
			MaxPaths,
		)
	}
	var previous domain.RepositoryPath
	for index, path := range metadata.Paths {
		if !path.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidPaths, index)
		}
		if index > 0 && previous >= path {
			return fmt.Errorf("%w: entries must be sorted and unique", ErrInvalidPaths)
		}
		previous = path
	}
	return nil
}

func (metadata Metadata) validateConflictIDs() error {
	if len(metadata.ResolvesConflictIDs) > MaxResolvedConflictIDs {
		return fmt.Errorf(
			"%w: got %d entries, limit %d",
			ErrInvalidConflictIDs,
			len(metadata.ResolvesConflictIDs),
			MaxResolvedConflictIDs,
		)
	}
	var previous domain.ConflictID
	for index, conflictID := range metadata.ResolvesConflictIDs {
		if !conflictID.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidConflictIDs, index)
		}
		if index > 0 && previous >= conflictID {
			return fmt.Errorf(
				"%w: entries must be sorted and unique",
				ErrInvalidConflictIDs,
			)
		}
		previous = conflictID
	}
	return nil
}

// Equal reports exact immutable metadata equality, including ordered arrays.
func (metadata Metadata) Equal(other Metadata) bool {
	return metadata.PublicationID == other.PublicationID &&
		metadata.ProposalEventID == other.ProposalEventID &&
		metadata.SupersedesPublicationID == other.SupersedesPublicationID &&
		metadata.TaskID == other.TaskID &&
		metadata.AuthorDeviceID == other.AuthorDeviceID &&
		metadata.AuthorAgentSessionID == other.AuthorAgentSessionID &&
		metadata.BaseCommit == other.BaseCommit &&
		metadata.CommitOID == other.CommitOID &&
		metadata.TreeOID == other.TreeOID &&
		slices.Equal(metadata.ParentOIDs, other.ParentOIDs) &&
		slices.Equal(metadata.Paths, other.Paths) &&
		metadata.ArtifactDigest == other.ArtifactDigest &&
		slices.Equal(metadata.ResolvesConflictIDs, other.ResolvesConflictIDs) &&
		metadata.WorkingRootID == other.WorkingRootID
}

// Publication is the committed projection of one canonical-ref proposal.
// Metadata never changes. Receipts may be replaced only by a normal apply.
type Publication struct {
	Metadata               Metadata
	StagingReceipts        []StagingReceipt
	State                  State
	TerminalSource         TerminalSource
	CanonicalLineageMember bool
	ReviewVerdict          ReviewVerdict
	ReviewerDeviceID       domain.DeviceID
	ReviewerAgentSessionID domain.UUIDv7
	ReviewActorType        ReviewActorType
	DecisionReason         *string
	EntityVersion          uint64
}

// Validate checks local persisted invariants. Authorization, actor
// independence, graph and staging verification, receipt cryptography and
// quorum freshness, row lookups, metadata digest computation, and CAS remain
// later-layer responsibilities.
func (publication Publication) Validate() error {
	if err := publication.Metadata.Validate(); err != nil {
		return err
	}
	if err := ValidateStagingReceipts(publication.StagingReceipts); err != nil {
		return err
	}
	if !publication.State.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidState, publication.State)
	}
	if publication.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(publication.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	if err := publication.validateReview(); err != nil {
		return err
	}
	if err := publication.validateLifecycle(); err != nil {
		return err
	}
	return nil
}

func (publication Publication) validateReview() error {
	hasReview := publication.ReviewVerdict != ReviewVerdictAbsent ||
		publication.ReviewerDeviceID != "" ||
		publication.ReviewerAgentSessionID != "" ||
		publication.ReviewActorType != ReviewActorAbsent
	if !hasReview {
		return nil
	}
	if !publication.ReviewVerdict.Valid() ||
		!publication.ReviewerDeviceID.Valid() ||
		!publication.ReviewActorType.Valid() {
		return fmt.Errorf("%w: malformed verdict, device, or actor type", ErrInvalidReview)
	}
	switch publication.ReviewActorType {
	case ReviewActorAgent:
		if !publication.ReviewerAgentSessionID.Valid() {
			return fmt.Errorf("%w: agent review requires agent-session ID", ErrInvalidReview)
		}
	case ReviewActorHuman:
		if publication.ReviewerAgentSessionID != "" {
			return fmt.Errorf("%w: human review prohibits agent-session ID", ErrInvalidReview)
		}
	default:
		return fmt.Errorf("%w: actor type %q", ErrInvalidReview, publication.ReviewActorType)
	}
	return nil
}

func (publication Publication) validateLifecycle() error {
	if publication.TerminalSource != TerminalSourceAbsent &&
		!publication.TerminalSource.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidTerminalSource, publication.TerminalSource)
	}
	if publication.DecisionReason != nil &&
		(!utf8.ValidString(*publication.DecisionReason) ||
			len(*publication.DecisionReason) < 1 ||
			len(*publication.DecisionReason) > MaxDecisionReasonBytes) {
		return fmt.Errorf(
			"%w: must be 1..%d UTF-8 bytes when set",
			ErrInvalidDecisionReason,
			MaxDecisionReasonBytes,
		)
	}

	switch publication.State {
	case StateProposed:
		if publication.TerminalSource != TerminalSourceAbsent {
			return fmt.Errorf("%w: proposed publication", ErrInvalidTerminalSource)
		}
		if publication.CanonicalLineageMember {
			return fmt.Errorf("%w: proposed publication", ErrInvalidCanonicalLineage)
		}
		if publication.hasReview() {
			return fmt.Errorf("%w: proposed publication", ErrInvalidReview)
		}
		if publication.DecisionReason != nil {
			return fmt.Errorf("%w: proposed publication", ErrInvalidDecisionReason)
		}
	case StateApproved:
		if publication.TerminalSource != TerminalSourceAbsent {
			return fmt.Errorf("%w: approved publication", ErrInvalidTerminalSource)
		}
		if publication.CanonicalLineageMember {
			return fmt.Errorf("%w: approved publication", ErrInvalidCanonicalLineage)
		}
		if publication.ReviewVerdict != ReviewVerdictApprove || !publication.hasReview() {
			return fmt.Errorf("%w: approved publication requires approval", ErrInvalidReview)
		}
		if publication.DecisionReason != nil {
			return fmt.Errorf("%w: approved publication", ErrInvalidDecisionReason)
		}
	case StateApplied:
		if publication.TerminalSource != TerminalSourceApply {
			return fmt.Errorf("%w: applied publication", ErrInvalidTerminalSource)
		}
		if publication.ReviewVerdict != ReviewVerdictApprove || !publication.hasReview() {
			return fmt.Errorf("%w: applied publication requires retained approval", ErrInvalidReview)
		}
		if publication.DecisionReason != nil {
			return fmt.Errorf("%w: applied publication", ErrInvalidDecisionReason)
		}
		// CanonicalLineageMember may be false after the recovery transform
		// selects an earlier canonical ancestor.
	case StateRejected:
		if publication.TerminalSource != TerminalSourceReview {
			return fmt.Errorf("%w: rejected publication", ErrInvalidTerminalSource)
		}
		if publication.CanonicalLineageMember {
			return fmt.Errorf("%w: rejected publication", ErrInvalidCanonicalLineage)
		}
		if publication.ReviewVerdict != ReviewVerdictReject || !publication.hasReview() {
			return fmt.Errorf("%w: rejected publication requires rejection review", ErrInvalidReview)
		}
		if publication.DecisionReason != nil {
			return fmt.Errorf("%w: rejected publication", ErrInvalidDecisionReason)
		}
	case StateWithdrawn:
		if publication.TerminalSource != TerminalSourceWithdraw &&
			publication.TerminalSource != TerminalSourceRecovery {
			return fmt.Errorf("%w: withdrawn publication", ErrInvalidTerminalSource)
		}
		if publication.CanonicalLineageMember {
			return fmt.Errorf("%w: withdrawn publication", ErrInvalidCanonicalLineage)
		}
		if publication.hasReview() && publication.ReviewVerdict != ReviewVerdictApprove {
			return fmt.Errorf("%w: withdrawn publication may retain only approval", ErrInvalidReview)
		}
		if publication.TerminalSource == TerminalSourceRecovery &&
			(publication.DecisionReason == nil ||
				*publication.DecisionReason != RecoveryDecisionReason) {
			return fmt.Errorf(
				"%w: recovery withdrawal requires fixed reason",
				ErrInvalidDecisionReason,
			)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidState, publication.State)
	}
	return nil
}

func (publication Publication) hasReview() bool {
	return publication.ReviewVerdict != ReviewVerdictAbsent &&
		publication.ReviewerDeviceID != "" &&
		publication.ReviewActorType != ReviewActorAbsent
}
