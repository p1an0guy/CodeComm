package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
)

func reduceWorkspaceConflictDetected(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"publication_id",
			"merge_kind",
			"merge_base_oids",
			"canonical_commit",
			"candidate_commit",
			"paths",
		},
		[]string{"replay_commit_oid"},
	)
	if code != "" {
		return context.reject(code), nil
	}
	if len(payload["paths"]) > eventPathArrayMaxBytes {
		return context.reject(CodeInvalidPayload), nil
	}
	publicationText, publicationOK := decodeValue[string](
		payload,
		"publication_id",
	)
	mergeKindText, mergeKindOK := decodeValue[string](payload, "merge_kind")
	baseTexts, basesOK := decodeValue[[]string](payload, "merge_base_oids")
	canonicalText, canonicalOK := decodeValue[string](
		payload,
		"canonical_commit",
	)
	candidateText, candidateOK := decodeValue[string](
		payload,
		"candidate_commit",
	)
	pathTexts, pathsOK := decodeValue[[]string](payload, "paths")
	if !publicationOK || !mergeKindOK || !basesOK ||
		!canonicalOK || !candidateOK || !pathsOK {
		return context.reject(CodeInvalidPayload), nil
	}
	detection := conflict.Detection{
		ID:              proposalConflictID(context),
		PublicationID:   domain.UUIDv7(publicationText),
		MergeKind:       conflict.MergeKind(mergeKindText),
		MergeBaseOIDs:   make([]domain.GitOID, len(baseTexts)),
		CanonicalCommit: domain.GitOID(canonicalText),
		CandidateCommit: domain.GitOID(candidateText),
		Paths:           make([]domain.RepositoryPath, len(pathTexts)),
	}
	for index, value := range baseTexts {
		detection.MergeBaseOIDs[index] = domain.GitOID(value)
	}
	for index, value := range pathTexts {
		detection.Paths[index] = domain.RepositoryPath(value)
	}
	if _, present := payload["replay_commit_oid"]; present {
		value, ok := decodeValue[string](payload, "replay_commit_oid")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		detection.ReplayCommitOID = domain.GitOID(value)
	}
	if err := detection.Validate(); err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	if current, exists := context.state.mergeConflicts[detection.ID]; exists {
		if err := current.Validate(); err != nil {
			return Outcome{}, invalidState(
				"conflict %q: %v",
				current.ID,
				err,
			)
		}
		if err := context.state.validateConflictReferences(current); err != nil {
			return Outcome{}, invalidState(
				"conflict %q: %v",
				current.ID,
				err,
			)
		}
		comparison, err := conflict.CompareRedetection(current, detection)
		if err != nil {
			return Outcome{}, invalidState(
				"compare conflict redetection %q: %v",
				detection.ID,
				err,
			)
		}
		switch comparison {
		case conflict.RedetectionIdentical:
			return context.acceptConflict(nil, nil)
		case conflict.RedetectionImmutableTupleMismatch:
			return context.rejectWithAlarm(
				CodeConflictImmutableTupleMismatch,
				conflictAlarm(
					detection.ID,
					AlarmConflictIntegrity,
				),
			), nil
		case conflict.RedetectionPathMismatch:
			return context.rejectWithAlarm(
				CodeConflictDetectorPathsMismatch,
				conflictAlarm(
					detection.ID,
					AlarmConflictDetectorCompatibility,
				),
			), nil
		default:
			return Outcome{}, invalidState(
				"unknown conflict redetection comparison %q",
				comparison,
			)
		}
	}
	derivedID, err := deriveConflictID(context.state.workspaceID, detection)
	if err != nil {
		return context.reject(CodeInvalidPayload), nil
	}
	if derivedID != detection.ID {
		return context.rejectWithAlarm(
			CodeConflictIDMismatch,
			conflictAlarm(detection.ID, AlarmConflictIntegrity),
		), nil
	}
	candidate, exists := context.state.publications[detection.PublicationID]
	if !exists {
		return context.reject(CodeConflictPublicationNotFound), nil
	}
	if candidate.State.Terminal() {
		return context.reject(CodeConflictPublicationTerminal), nil
	}
	if candidate.Metadata.CommitOID != detection.CandidateCommit {
		return context.reject(CodeInvalidPayload), nil
	}
	if detection.CanonicalCommit != context.state.canonicalRef.CommitOID {
		return context.reject(CodeConflictCanonicalCommitMismatch), nil
	}

	next := conflict.Conflict{
		ID:              detection.ID,
		PublicationID:   detection.PublicationID,
		MergeKind:       detection.MergeKind,
		ReplayCommitOID: detection.ReplayCommitOID,
		MergeBaseOIDs:   append([]domain.GitOID(nil), detection.MergeBaseOIDs...),
		CanonicalCommit: detection.CanonicalCommit,
		CandidateCommit: detection.CandidateCommit,
		Paths:           append([]domain.RepositoryPath(nil), detection.Paths...),
		Status:          conflict.StatusUnresolved,
		EntityVersion:   1,
	}
	if err := conflict.ValidateTransition(
		conflict.OperationDetect,
		nil,
		next,
	); err != nil {
		return context.reject(CodeInvalidConflictTransition), nil
	}
	return context.acceptConflict(&next, nil)
}
