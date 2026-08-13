// Package conflict defines the merge-conflict entity and its pure lifecycle.
package conflict

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
)

// MergeKind identifies the Git operation that detected the conflict.
type MergeKind string

const (
	MergeKindMerge  MergeKind = "merge"
	MergeKindRebase MergeKind = "rebase"
)

var mergeKinds = [...]MergeKind{MergeKindMerge, MergeKindRebase}

// Valid reports whether kind is a closed V1 merge kind.
func (kind MergeKind) Valid() bool {
	return kind == MergeKindMerge || kind == MergeKindRebase
}

// MergeKinds returns every V1 merge kind in stable order.
func MergeKinds() []MergeKind {
	result := make([]MergeKind, len(mergeKinds))
	copy(result, mergeKinds[:])
	return result
}

// Status is the committed conflict lifecycle state.
type Status string

const (
	StatusUnresolved Status = "unresolved"
	StatusResolved   Status = "resolved"
)

var statuses = [...]Status{StatusUnresolved, StatusResolved}

// Valid reports whether status is a closed V1 conflict status.
func (status Status) Valid() bool {
	return status == StatusUnresolved || status == StatusResolved
}

// Terminal reports whether no mutation may leave status.
func (status Status) Terminal() bool {
	return status == StatusResolved
}

// Statuses returns every committed status in lifecycle order.
func Statuses() []Status {
	result := make([]Status, len(statuses))
	copy(result, statuses[:])
	return result
}

// ResolutionKind records how a conflict was resolved.
type ResolutionKind string

const (
	// ResolutionKindAbsent represents null on an unresolved row.
	ResolutionKindAbsent ResolutionKind = ""

	ResolutionKindPublication ResolutionKind = "publication"
	ResolutionKindForced      ResolutionKind = "forced"
)

var resolutionKinds = [...]ResolutionKind{
	ResolutionKindPublication,
	ResolutionKindForced,
}

// Valid reports whether kind is a committed resolution kind.
func (kind ResolutionKind) Valid() bool {
	return kind == ResolutionKindPublication || kind == ResolutionKindForced
}

// ResolutionKinds returns every non-null resolution kind in stable order.
func ResolutionKinds() []ResolutionKind {
	result := make([]ResolutionKind, len(resolutionKinds))
	copy(result, resolutionKinds[:])
	return result
}

// Operation identifies the event kind responsible for a lifecycle action.
type Operation string

const (
	OperationDetect             Operation = "workspace.conflict.detected"
	OperationPublicationResolve Operation = "workspace.conflict.resolved"
	OperationForceResolve       Operation = "workspace.conflict.force_resolved"
)

var operations = [...]Operation{
	OperationDetect,
	OperationPublicationResolve,
	OperationForceResolve,
}

// Valid reports whether operation is a closed V1 conflict operation.
func (operation Operation) Valid() bool {
	switch operation {
	case OperationDetect, OperationPublicationResolve, OperationForceResolve:
		return true
	default:
		return false
	}
}

// Operations returns every conflict operation in stable order.
func Operations() []Operation {
	result := make([]Operation, len(operations))
	copy(result, operations[:])
	return result
}

// RedetectionComparison classifies a detection against an existing row.
type RedetectionComparison string

const (
	RedetectionIdentical              RedetectionComparison = "identical"
	RedetectionImmutableTupleMismatch RedetectionComparison = "immutable_tuple_mismatch"
	RedetectionPathMismatch           RedetectionComparison = "path_mismatch"
)

var (
	ErrInvalidStatus            = errors.New("conflict: invalid status")
	ErrInvalidResolutionKind    = errors.New("conflict: invalid resolution kind")
	ErrInvalidOperation         = errors.New("conflict: invalid transition operation")
	ErrInvalidTransition        = errors.New("conflict: invalid transition")
	ErrInvalidVersionTransition = errors.New("conflict: invalid entity-version transition")
	ErrImmutableTupleChanged    = errors.New("conflict: immutable tuple changed")
	ErrDetectorPathsChanged     = errors.New("conflict: detector paths changed")
)

// CompareRedetection distinguishes an exact idempotent redetection from
// integrity and detector-compatibility failures. Mutable resolution fields are
// intentionally ignored, so comparing an exact detection never resets a
// resolved row.
func CompareRedetection(
	existing Conflict,
	incoming Detection,
) (RedetectionComparison, error) {
	if err := existing.Validate(); err != nil {
		return "", fmt.Errorf("conflict: invalid existing row: %w", err)
	}
	if err := incoming.Validate(); err != nil {
		return "", fmt.Errorf("conflict: invalid incoming detection: %w", err)
	}
	return compareDetection(existing.Detection(), incoming), nil
}

// ValidateTransition validates an operation-specific lifecycle change. A nil
// before value denotes first detection. Expected-version CAS, publication
// existence/state/ancestry, and actor authorization remain reducer concerns.
func ValidateTransition(operation Operation, before *Conflict, after Conflict) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if before != nil {
		if err := before.Validate(); err != nil {
			return fmt.Errorf("conflict: invalid source entity: %w", err)
		}
	}
	if err := after.Validate(); err != nil {
		return fmt.Errorf("conflict: invalid destination entity: %w", err)
	}

	if operation == OperationDetect {
		return validateDetectTransition(before, after)
	}
	if before == nil {
		return invalidTransition(operation, nil, after)
	}

	comparison := compareDetection(before.detectionView(), after.detectionView())
	switch comparison {
	case RedetectionImmutableTupleMismatch:
		return fmt.Errorf("%w: %s", ErrImmutableTupleChanged, operation)
	case RedetectionPathMismatch:
		return fmt.Errorf("%w: %s", ErrDetectorPathsChanged, operation)
	}
	if before.Status != StatusUnresolved || after.Status != StatusResolved {
		return invalidTransition(operation, before, after)
	}
	switch operation {
	case OperationPublicationResolve:
		if after.ResolutionKind != ResolutionKindPublication {
			return invalidTransition(operation, before, after)
		}
	case OperationForceResolve:
		if after.ResolutionKind != ResolutionKindForced {
			return invalidTransition(operation, before, after)
		}
	}
	if before.EntityVersion >= domain.MaxSafeInteger ||
		after.EntityVersion != before.EntityVersion+1 {
		return fmt.Errorf(
			"%w: got %d -> %d",
			ErrInvalidVersionTransition,
			before.EntityVersion,
			after.EntityVersion,
		)
	}
	return nil
}

func validateDetectTransition(before *Conflict, after Conflict) error {
	if before == nil {
		if after.Status != StatusUnresolved {
			return invalidTransition(OperationDetect, nil, after)
		}
		if after.EntityVersion != 1 {
			return fmt.Errorf(
				"%w: detection starts at 1, got %d",
				ErrInvalidVersionTransition,
				after.EntityVersion,
			)
		}
		return nil
	}

	comparison := compareDetection(before.detectionView(), after.detectionView())
	switch comparison {
	case RedetectionImmutableTupleMismatch:
		return fmt.Errorf("%w: redetection", ErrImmutableTupleChanged)
	case RedetectionPathMismatch:
		return fmt.Errorf("%w: redetection", ErrDetectorPathsChanged)
	}
	if !sameMutableFields(*before, after) {
		return invalidTransition(OperationDetect, before, after)
	}
	return nil
}

func compareDetection(left, right Detection) RedetectionComparison {
	if left.ID != right.ID ||
		left.PublicationID != right.PublicationID ||
		left.MergeKind != right.MergeKind ||
		left.ReplayCommitOID != right.ReplayCommitOID ||
		!slices.Equal(left.MergeBaseOIDs, right.MergeBaseOIDs) ||
		left.CanonicalCommit != right.CanonicalCommit ||
		left.CandidateCommit != right.CandidateCommit {
		return RedetectionImmutableTupleMismatch
	}
	if !slices.Equal(left.Paths, right.Paths) {
		return RedetectionPathMismatch
	}
	return RedetectionIdentical
}

func sameMutableFields(left, right Conflict) bool {
	return left.Status == right.Status &&
		left.ResolutionKind == right.ResolutionKind &&
		left.ResolutionPublicationID == right.ResolutionPublicationID &&
		left.ForceReason == right.ForceReason &&
		left.ResolvedByDeviceID == right.ResolvedByDeviceID &&
		left.EntityVersion == right.EntityVersion
}

func invalidTransition(operation Operation, before *Conflict, after Conflict) error {
	from := Status("")
	if before != nil {
		from = before.Status
	}
	return fmt.Errorf(
		"%w: %s %q -> %q",
		ErrInvalidTransition,
		operation,
		from,
		after.Status,
	)
}
