package reducer

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlpath"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

const eventPathArrayMaxBytes = 192 * 1024

func reducePublicationProposed(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{
			"proposal_event_id",
			"author_device_id",
			"author_agent_session_id",
			"base_commit",
			"commit_oid",
			"tree_oid",
			"parent_oids",
			"paths",
			"artifact_digest",
			"working_root_id",
			"staging_receipts",
		},
		[]string{
			"task_id",
			"supersedes_publication_id",
			"resolves_conflict_ids",
		},
	)
	if code != "" {
		return context.reject(code), nil
	}
	if len(payload["paths"]) > eventPathArrayMaxBytes {
		return context.reject(CodeInvalidPayload), nil
	}

	proposalEventText, eventOK := decodeValue[string](
		payload,
		"proposal_event_id",
	)
	authorDeviceText, authorDeviceOK := decodeValue[string](
		payload,
		"author_device_id",
	)
	authorSessionText, authorSessionOK := decodeValue[string](
		payload,
		"author_agent_session_id",
	)
	baseText, baseOK := decodeValue[string](payload, "base_commit")
	commitText, commitOK := decodeValue[string](payload, "commit_oid")
	treeText, treeOK := decodeValue[string](payload, "tree_oid")
	parentTexts, parentsOK := decodeValue[[]string](payload, "parent_oids")
	pathTexts, pathsOK := decodeValue[[]string](payload, "paths")
	artifactText, artifactOK := decodeValue[string](payload, "artifact_digest")
	rootText, rootOK := decodeValue[string](payload, "working_root_id")
	receiptObjects, receiptsOK := decodeValue[[]json.RawMessage](
		payload,
		"staging_receipts",
	)
	artifactBytes, artifactErr := codec.DecodeBase64URLExact(
		artifactText,
		sha256.Size,
	)
	if !eventOK || !authorDeviceOK || !authorSessionOK ||
		!baseOK || !commitOK || !treeOK || !parentsOK ||
		!pathsOK || !artifactOK || artifactErr != nil ||
		!rootOK || !receiptsOK {
		return context.reject(CodeInvalidPayload), nil
	}

	metadata := publication.Metadata{
		PublicationID:        proposalPublicationID(context),
		ProposalEventID:      domain.UUIDv7(proposalEventText),
		AuthorDeviceID:       domain.DeviceID(authorDeviceText),
		AuthorAgentSessionID: domain.UUIDv7(authorSessionText),
		BaseCommit:           domain.GitOID(baseText),
		CommitOID:            domain.GitOID(commitText),
		TreeOID:              domain.GitOID(treeText),
		ParentOIDs:           make([]domain.GitOID, len(parentTexts)),
		Paths:                make([]domain.RepositoryPath, len(pathTexts)),
		WorkingRootID:        domain.UUIDv7(rootText),
	}
	copy(metadata.ArtifactDigest[:], artifactBytes)
	for index, value := range parentTexts {
		metadata.ParentOIDs[index] = domain.GitOID(value)
	}
	for index, value := range pathTexts {
		metadata.Paths[index] = domain.RepositoryPath(value)
	}
	if raw, present := payload["task_id"]; present {
		value, ok := decodeValue[string](payloadObject{"task_id": raw}, "task_id")
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		metadata.TaskID = domain.UUIDv7(value)
	}
	if raw, present := payload["supersedes_publication_id"]; present {
		value, ok := decodeValue[string](
			payloadObject{"supersedes_publication_id": raw},
			"supersedes_publication_id",
		)
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		metadata.SupersedesPublicationID = domain.UUIDv7(value)
	}
	if raw, present := payload["resolves_conflict_ids"]; present {
		values, ok := decodeValue[[]string](
			payloadObject{"resolves_conflict_ids": raw},
			"resolves_conflict_ids",
		)
		if !ok {
			return context.reject(CodeInvalidPayload), nil
		}
		metadata.ResolvesConflictIDs = make(
			[]domain.ConflictID,
			len(values),
		)
		for index, value := range values {
			metadata.ResolvesConflictIDs[index] = domain.ConflictID(value)
		}
	}
	receipts, validReceipts := decodeStagingReceipts(receiptObjects)
	if !validReceipts || metadata.Validate() != nil {
		return context.reject(CodeInvalidPayload), nil
	}

	if current, exists := context.state.publications[metadata.PublicationID]; exists {
		if current.Metadata.PublicationID != metadata.PublicationID ||
			current.Validate() != nil {
			return Outcome{}, invalidState(
				"collided publication %q is invalid",
				metadata.PublicationID,
			)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	if metadata.ProposalEventID != context.proposal.EventID ||
		metadata.AuthorDeviceID != context.device.ID ||
		context.agentSession == nil ||
		metadata.AuthorAgentSessionID != context.agentSession.ID {
		return context.reject(CodePublicationAuthorMismatch), nil
	}
	if context.agentSession.DeviceID != metadata.AuthorDeviceID {
		return context.reject(CodePublicationAuthorBindingMismatch), nil
	}
	if metadata.WorkingRootID != context.agentSession.WorkingRootID {
		return context.reject(CodePublicationWorkingRootMismatch), nil
	}
	if metadata.TaskID != "" {
		taskValue, exists := context.state.tasks[metadata.TaskID]
		if !exists {
			return context.reject(CodePublicationTaskNotFound), nil
		}
		if taskValue.OwnerDeviceID != metadata.AuthorDeviceID ||
			taskValue.OwnerAgentSessionID != metadata.AuthorAgentSessionID {
			return context.reject(CodePublicationTaskHolderRequired), nil
		}
	}
	if metadata.SupersedesPublicationID != "" {
		previous, exists :=
			context.state.publications[metadata.SupersedesPublicationID]
		if !exists {
			return context.reject(CodePublicationSupersedesNotFound), nil
		}
		if previous.State != publication.StateRejected &&
			previous.State != publication.StateWithdrawn {
			return context.reject(CodePublicationSupersedesNotTerminal), nil
		}
		if !samePublicationLineage(previous.Metadata, metadata) {
			return context.reject(
				CodePublicationSupersedesLineageMismatch,
			), nil
		}
	}
	for _, conflictID := range metadata.ResolvesConflictIDs {
		current, exists := context.state.mergeConflicts[conflictID]
		if !exists {
			return context.reject(CodePublicationConflictNotFound), nil
		}
		if current.Status != conflict.StatusUnresolved {
			return context.reject(CodePublicationConflictNotUnresolved), nil
		}
	}
	for _, path := range metadata.Paths {
		if controlpath.IsControlledV1(path) {
			return context.reject(CodePublicationControlPath), nil
		}
	}
	covered, err := publicationPathsCovered(context, metadata.Paths)
	if err != nil {
		return Outcome{}, err
	}
	if !covered {
		return context.reject(CodePublicationPathLeaseRequired), nil
	}
	if code := validatePublicationReceipts(
		context.state,
		metadata,
		receipts,
	); code != "" {
		return context.reject(code), nil
	}

	next := publication.Publication{
		Metadata:        metadata,
		StagingReceipts: receipts,
		State:           publication.StateProposed,
		EntityVersion:   1,
	}
	return context.acceptPublication(next, nil)
}
