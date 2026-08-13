package conflict

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxMergeBaseOIDs    = 16
	MaxPaths            = 2048
	MaxForceReasonBytes = 1024
)

var (
	ErrInvalidID                      = errors.New("conflict: invalid conflict ID")
	ErrInvalidPublicationID           = errors.New("conflict: invalid publication ID")
	ErrInvalidMergeKind               = errors.New("conflict: invalid merge kind")
	ErrInvalidReplayCommitOID         = errors.New("conflict: invalid replay commit OID")
	ErrInvalidMergeBaseOIDs           = errors.New("conflict: invalid merge-base OIDs")
	ErrMergeBaseOIDsNotSortedUnique   = errors.New("conflict: merge-base OIDs are not sorted and unique")
	ErrInvalidCanonicalCommit         = errors.New("conflict: invalid canonical commit")
	ErrInvalidCandidateCommit         = errors.New("conflict: invalid candidate commit")
	ErrGitObjectFormatMismatch        = errors.New("conflict: Git object formats do not match")
	ErrInvalidPaths                   = errors.New("conflict: invalid detector paths")
	ErrPathsNotSortedUnique           = errors.New("conflict: detector paths are not sorted and unique")
	ErrInvalidResolutionPublicationID = errors.New("conflict: invalid resolution publication ID")
	ErrInvalidForceReason             = errors.New("conflict: invalid force reason")
	ErrInvalidResolverDeviceID        = errors.New("conflict: invalid resolver device ID")
	ErrInvalidEntityVersion           = errors.New("conflict: invalid entity version")
)

// Conflict is the committed projection of one detected merge or rebase
// conflict. Publication state, graph ancestry, actor authority, and CAS checks
// require other committed rows and remain reducer concerns.
type Conflict struct {
	ID                      domain.ConflictID
	PublicationID           domain.UUIDv7
	MergeKind               MergeKind
	ReplayCommitOID         domain.GitOID
	MergeBaseOIDs           []domain.GitOID
	CanonicalCommit         domain.GitOID
	CandidateCommit         domain.GitOID
	Paths                   []domain.RepositoryPath
	Status                  Status
	ResolutionKind          ResolutionKind
	ResolutionPublicationID domain.UUIDv7
	ForceReason             string
	ResolvedByDeviceID      domain.DeviceID
	EntityVersion           uint64
}

// Detection is the immutable portion of a conflict row plus detector paths.
// It matches workspace.conflict.detected; lifecycle fields are deliberately
// absent so an exact redetection cannot reset a resolved row.
type Detection struct {
	ID              domain.ConflictID
	PublicationID   domain.UUIDv7
	MergeKind       MergeKind
	ReplayCommitOID domain.GitOID
	MergeBaseOIDs   []domain.GitOID
	CanonicalCommit domain.GitOID
	CandidateCommit domain.GitOID
	Paths           []domain.RepositoryPath
}

// Validate verifies all local persisted invariants.
func (value Conflict) Validate() error {
	if err := value.detectionView().Validate(); err != nil {
		return err
	}
	if !value.Status.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, value.Status)
	}
	if err := value.validateResolution(); err != nil {
		return err
	}
	if value.EntityVersion < 1 || !domain.ValidUnsignedInteger(value.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// Detection returns an independent copy of the conflict's immutable detection
// data.
func (value Conflict) Detection() Detection {
	detection := value.detectionView()
	detection.MergeBaseOIDs = append([]domain.GitOID(nil), detection.MergeBaseOIDs...)
	detection.Paths = append([]domain.RepositoryPath(nil), detection.Paths...)
	return detection
}

func (value Conflict) detectionView() Detection {
	return Detection{
		ID:              value.ID,
		PublicationID:   value.PublicationID,
		MergeKind:       value.MergeKind,
		ReplayCommitOID: value.ReplayCommitOID,
		MergeBaseOIDs:   value.MergeBaseOIDs,
		CanonicalCommit: value.CanonicalCommit,
		CandidateCommit: value.CandidateCommit,
		Paths:           value.Paths,
	}
}

// Validate verifies the event-local detection fields. It validates only the
// supplied ID's format; deriving and matching its digest belongs to codec and
// reducer code.
func (detection Detection) Validate() error {
	if !detection.ID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, detection.ID)
	}
	if err := validateGraph(
		detection.PublicationID,
		detection.MergeKind,
		detection.ReplayCommitOID,
		detection.MergeBaseOIDs,
		detection.CanonicalCommit,
		detection.CandidateCommit,
	); err != nil {
		return err
	}
	return validatePaths(detection.Paths)
}

func (value Conflict) validateResolution() error {
	if value.Status == StatusUnresolved {
		switch {
		case value.ResolutionKind != ResolutionKindAbsent:
			return fmt.Errorf("%w: prohibited while unresolved", ErrInvalidResolutionKind)
		case value.ResolutionPublicationID != "":
			return fmt.Errorf("%w: prohibited while unresolved", ErrInvalidResolutionPublicationID)
		case value.ForceReason != "":
			return fmt.Errorf("%w: prohibited while unresolved", ErrInvalidForceReason)
		case value.ResolvedByDeviceID != "":
			return fmt.Errorf("%w: prohibited while unresolved", ErrInvalidResolverDeviceID)
		default:
			return nil
		}
	}

	if !value.ResolutionKind.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidResolutionKind, value.ResolutionKind)
	}
	switch value.ResolutionKind {
	case ResolutionKindPublication:
		if !value.ResolutionPublicationID.Valid() {
			return fmt.Errorf(
				"%w: %q",
				ErrInvalidResolutionPublicationID,
				value.ResolutionPublicationID,
			)
		}
		if value.ForceReason != "" {
			return fmt.Errorf("%w: prohibited for publication resolution", ErrInvalidForceReason)
		}
	case ResolutionKindForced:
		if value.ResolutionPublicationID != "" {
			return fmt.Errorf(
				"%w: prohibited for forced resolution",
				ErrInvalidResolutionPublicationID,
			)
		}
		if !validUTF8ByteLength(value.ForceReason, 1, MaxForceReasonBytes) {
			return fmt.Errorf(
				"%w: must be 1..%d UTF-8 bytes",
				ErrInvalidForceReason,
				MaxForceReasonBytes,
			)
		}
	}
	if !value.ResolvedByDeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidResolverDeviceID, value.ResolvedByDeviceID)
	}
	return nil
}

func validateGraph(
	publicationID domain.UUIDv7,
	mergeKind MergeKind,
	replayCommitOID domain.GitOID,
	mergeBaseOIDs []domain.GitOID,
	canonicalCommit domain.GitOID,
	candidateCommit domain.GitOID,
) error {
	if !publicationID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidPublicationID, publicationID)
	}
	if !mergeKind.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidMergeKind, mergeKind)
	}
	switch mergeKind {
	case MergeKindMerge:
		if replayCommitOID != "" {
			return fmt.Errorf("%w: prohibited for merge", ErrInvalidReplayCommitOID)
		}
	case MergeKindRebase:
		if !replayCommitOID.Valid() {
			return fmt.Errorf("%w: required for rebase", ErrInvalidReplayCommitOID)
		}
	}
	if !canonicalCommit.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCanonicalCommit, canonicalCommit)
	}
	if !candidateCommit.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidCandidateCommit, candidateCommit)
	}
	if len(mergeBaseOIDs) > MaxMergeBaseOIDs {
		return fmt.Errorf(
			"%w: got %d entries, limit %d",
			ErrInvalidMergeBaseOIDs,
			len(mergeBaseOIDs),
			MaxMergeBaseOIDs,
		)
	}

	for index, oid := range mergeBaseOIDs {
		if !oid.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidMergeBaseOIDs, index)
		}
		if index > 0 && mergeBaseOIDs[index-1] >= oid {
			return fmt.Errorf(
				"%w: entries %d and %d",
				ErrMergeBaseOIDsNotSortedUnique,
				index-1,
				index,
			)
		}
	}

	objectFormat := canonicalCommit.ObjectFormat()
	if candidateCommit.ObjectFormat() != objectFormat {
		return fmt.Errorf(
			"%w: canonical %q, candidate %q",
			ErrGitObjectFormatMismatch,
			objectFormat,
			candidateCommit.ObjectFormat(),
		)
	}
	if replayCommitOID != "" && replayCommitOID.ObjectFormat() != objectFormat {
		return fmt.Errorf(
			"%w: canonical %q, replay %q",
			ErrGitObjectFormatMismatch,
			objectFormat,
			replayCommitOID.ObjectFormat(),
		)
	}
	for index, oid := range mergeBaseOIDs {
		if oid.ObjectFormat() != objectFormat {
			return fmt.Errorf(
				"%w: canonical %q, merge-base entry %d %q",
				ErrGitObjectFormatMismatch,
				objectFormat,
				index,
				oid.ObjectFormat(),
			)
		}
	}
	return nil
}

func validatePaths(paths []domain.RepositoryPath) error {
	if len(paths) > MaxPaths {
		return fmt.Errorf("%w: got %d entries, limit %d", ErrInvalidPaths, len(paths), MaxPaths)
	}
	for index, path := range paths {
		if !path.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidPaths, index)
		}
		if index > 0 && paths[index-1] >= path {
			return fmt.Errorf(
				"%w: entries %d and %d",
				ErrPathsNotSortedUnique,
				index-1,
				index,
			)
		}
	}
	return nil
}

func validUTF8ByteLength(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum
}
