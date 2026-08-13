package reducer

import (
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlpath"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

type pendingRepositoryChanges struct {
	canonicalRef            *publication.CanonicalRef
	publications            map[domain.UUIDv7]publication.Publication
	mergeConflicts          map[domain.ConflictID]conflict.Conflict
	conflictTaskID          domain.UUIDv7
	unresolvedConflictCount uint64
}

func (state State) validateRepositoryChanges(
	changes Changes,
) (pendingRepositoryChanges, error) {
	pending := pendingRepositoryChanges{
		publications:   make(map[domain.UUIDv7]publication.Publication, len(changes.Publications)),
		mergeConflicts: make(map[domain.ConflictID]conflict.Conflict, len(changes.MergeConflicts)),
	}
	if len(changes.CanonicalRefs) > 1 ||
		len(changes.Publications) > 1 ||
		len(changes.MergeConflicts) > 1 {
		return pending, invalidState(
			"repository change set contains more than one row per table",
		)
	}
	if len(changes.Publications) != 0 && len(changes.MergeConflicts) != 0 {
		return pending, invalidState(
			"publication and conflict cannot change in one event",
		)
	}

	var publicationOperation publication.Operation
	for _, next := range changes.Publications {
		if err := next.Validate(); err != nil {
			return pending, invalidState(
				"publication change %q: %v",
				next.Metadata.PublicationID,
				err,
			)
		}
		id := next.Metadata.PublicationID
		current, exists := state.publications[id]
		if !exists {
			if next.State != publication.StateProposed ||
				next.EntityVersion != 1 {
				return pending, invalidState(
					"publication %q is not a creation baseline",
					id,
				)
			}
			for existingID, existing := range state.publications {
				if existing.Metadata.ProposalEventID ==
					next.Metadata.ProposalEventID {
					return pending, invalidState(
						"publication %q reuses proposal event %q from %q",
						id,
						next.Metadata.ProposalEventID,
						existingID,
					)
				}
			}
		} else {
			var valid bool
			publicationOperation, valid = classifyPublicationTransition(
				current,
				next,
			)
			if !valid {
				return pending, invalidState(
					"publication %q has an invalid transition",
					id,
				)
			}
		}
		pending.publications[id] = clonePublication(next)
	}

	if len(changes.CanonicalRefs) == 1 {
		if len(changes.Publications) != 1 ||
			publicationOperation != publication.OperationApply {
			return pending, invalidState(
				"canonical ref change requires one publication apply",
			)
		}
		next := changes.CanonicalRefs[0]
		if err := validateCanonicalRefTransition(state.canonicalRef, next); err != nil {
			return pending, err
		}
		applied := changes.Publications[0]
		if applied.Metadata.BaseCommit != state.canonicalRef.CommitOID ||
			applied.Metadata.CommitOID != next.CommitOID {
			return pending, invalidState(
				"canonical ref does not match applied publication",
			)
		}
		copy := next
		pending.canonicalRef = &copy
	} else if publicationOperation == publication.OperationApply {
		return pending, invalidState(
			"publication apply omits canonical ref change",
		)
	}

	for _, next := range changes.MergeConflicts {
		if err := next.Validate(); err != nil {
			return pending, invalidState(
				"conflict change %q: %v",
				next.ID,
				err,
			)
		}
		current, exists := state.mergeConflicts[next.ID]
		if !exists {
			if err := conflict.ValidateTransition(
				conflict.OperationDetect,
				nil,
				next,
			); err != nil {
				return pending, invalidState(
					"conflict detection %q: %v",
					next.ID,
					err,
				)
			}
			candidate, exists := state.publications[next.PublicationID]
			if !exists || candidate.State.Terminal() {
				return pending, invalidState(
					"first conflict detection %q lacks a nonterminal publication",
					next.ID,
				)
			}
		} else {
			operation, valid := classifyConflictTransition(current, next)
			if !valid {
				return pending, invalidState(
					"conflict %q has an invalid transition",
					next.ID,
				)
			}
			if operation == conflict.OperationDetect {
				return pending, invalidState(
					"conflict %q redetection must not emit a row mutation",
					next.ID,
				)
			}
		}
		pending.mergeConflicts[next.ID] = cloneConflict(next)
	}

	for id, value := range pending.publications {
		if err := state.validatePublicationReferences(value); err != nil {
			return pending, invalidState("publication change %q: %v", id, err)
		}
	}
	for id, value := range pending.mergeConflicts {
		if err := state.validateConflictReferences(value); err != nil {
			return pending, invalidState("conflict change %q: %v", id, err)
		}
		candidate := state.publications[value.PublicationID]
		taskID := candidate.Metadata.TaskID
		if taskID == "" {
			continue
		}
		current, existed := state.mergeConflicts[id]
		count := state.unresolvedConflictsByTask[taskID]
		switch {
		case !existed && value.Status == conflict.StatusUnresolved:
			if count == domain.MaxSafeInteger {
				return pending, invalidState(
					"task %q unresolved-conflict count is exhausted",
					taskID,
				)
			}
			count++
		case existed &&
			current.Status == conflict.StatusUnresolved &&
			value.Status == conflict.StatusResolved:
			if count == 0 {
				return pending, invalidState(
					"task %q unresolved-conflict count underflows",
					taskID,
				)
			}
			count--
		}
		pending.conflictTaskID = taskID
		pending.unresolvedConflictCount = count
	}
	return pending, nil
}

func (state State) validatePublicationReferences(
	value publication.Publication,
) error {
	metadata := value.Metadata
	if metadata.BaseCommit.ObjectFormat() != state.canonicalRef.CommitOID.ObjectFormat() {
		return fmt.Errorf("git object format differs from canonical ref")
	}
	member, exists := state.devices[metadata.AuthorDeviceID]
	if !exists || member.ID != metadata.AuthorDeviceID {
		return fmt.Errorf("missing author device %q", metadata.AuthorDeviceID)
	}
	author, exists := state.agentSessions[metadata.AuthorAgentSessionID]
	if !exists ||
		author.DeviceID != metadata.AuthorDeviceID ||
		author.WorkingRootID != metadata.WorkingRootID {
		return fmt.Errorf(
			"invalid author session/root binding %q",
			metadata.AuthorAgentSessionID,
		)
	}
	if metadata.TaskID != "" {
		if _, exists := state.tasks[metadata.TaskID]; !exists {
			return fmt.Errorf("missing task %q", metadata.TaskID)
		}
	}
	if metadata.SupersedesPublicationID != "" {
		previous, exists := state.publications[metadata.SupersedesPublicationID]
		if !exists {
			return fmt.Errorf(
				"missing superseded publication %q",
				metadata.SupersedesPublicationID,
			)
		}
		if previous.State != publication.StateRejected &&
			previous.State != publication.StateWithdrawn {
			return fmt.Errorf(
				"superseded publication %q is not rejected or withdrawn",
				metadata.SupersedesPublicationID,
			)
		}
		if !samePublicationLineage(previous.Metadata, metadata) {
			return fmt.Errorf(
				"superseded publication %q is outside the lineage",
				metadata.SupersedesPublicationID,
			)
		}
	}
	for _, path := range metadata.Paths {
		if controlpath.IsControlledV1(path) {
			return fmt.Errorf("publication contains control path %q", path)
		}
	}
	digest, err := publicationMetadataDigest(metadata)
	if err != nil {
		return fmt.Errorf("metadata digest: %v", err)
	}
	for index, receipt := range value.StagingReceipts {
		if receipt.SessionID != state.sessionID ||
			receipt.WorkspaceID != state.workspaceID ||
			receipt.PublicationMetadataDigest != digest ||
			receipt.StagedResultIndex > state.currentResultIndex {
			return fmt.Errorf("staging receipt %d has invalid context", index)
		}
		signer, exists := state.devices[receipt.VoterDeviceID]
		if !exists || !verifyStagingReceiptSignature(
			receipt,
			signer.IdentityPublicKey,
		) {
			return fmt.Errorf("staging receipt %d has invalid signer", index)
		}
	}
	if value.ReviewerDeviceID != "" {
		if _, exists := state.devices[value.ReviewerDeviceID]; !exists {
			return fmt.Errorf(
				"missing reviewer device %q",
				value.ReviewerDeviceID,
			)
		}
	}
	if value.ReviewActorType == publication.ReviewActorAgent {
		reviewer, exists := state.agentSessions[value.ReviewerAgentSessionID]
		if !exists || reviewer.DeviceID != value.ReviewerDeviceID {
			return fmt.Errorf(
				"invalid reviewer session %q",
				value.ReviewerAgentSessionID,
			)
		}
	}
	for _, conflictID := range metadata.ResolvesConflictIDs {
		if _, exists := state.mergeConflicts[conflictID]; !exists {
			return fmt.Errorf("missing resolved conflict %q", conflictID)
		}
	}
	return nil
}

func (state State) validatePublicationSupersessionGraph() error {
	const (
		unseen = iota
		visiting
		visited
	)
	status := make(map[domain.UUIDv7]int, len(state.publications))
	for start := range state.publications {
		if status[start] != unseen {
			continue
		}
		path := make([]domain.UUIDv7, 0)
		current := start
		for current != "" {
			switch status[current] {
			case visiting:
				return fmt.Errorf(
					"publication supersession cycle reaches %q",
					current,
				)
			case visited:
				current = ""
				continue
			}
			status[current] = visiting
			path = append(path, current)
			current = state.publications[current].
				Metadata.
				SupersedesPublicationID
		}
		for _, id := range path {
			status[id] = visited
		}
	}
	return nil
}

func (state State) validateConflictReferences(value conflict.Conflict) error {
	derivedID, err := deriveConflictID(state.workspaceID, value.Detection())
	if err != nil {
		return fmt.Errorf("derive conflict ID: %v", err)
	}
	if derivedID != value.ID {
		return fmt.Errorf(
			"conflict ID %q does not match immutable tuple",
			value.ID,
		)
	}
	candidate, exists := state.publications[value.PublicationID]
	if !exists {
		return fmt.Errorf("missing candidate publication %q", value.PublicationID)
	}
	if candidate.Metadata.CommitOID != value.CandidateCommit {
		return fmt.Errorf("candidate commit does not match publication")
	}
	if value.CanonicalCommit.ObjectFormat() != state.canonicalRef.CommitOID.ObjectFormat() {
		return fmt.Errorf("git object format differs from canonical ref")
	}
	if value.Status != conflict.StatusResolved {
		return nil
	}
	if _, exists := state.devices[value.ResolvedByDeviceID]; !exists {
		return fmt.Errorf("missing resolver device %q", value.ResolvedByDeviceID)
	}
	if value.ResolutionKind == conflict.ResolutionKindPublication {
		resolution, exists := state.publications[value.ResolutionPublicationID]
		if !exists {
			return fmt.Errorf(
				"missing resolution publication %q",
				value.ResolutionPublicationID,
			)
		}
		if resolution.State != publication.StateApplied ||
			!slices.Contains(
				resolution.Metadata.ResolvesConflictIDs,
				value.ID,
			) {
			return fmt.Errorf(
				"resolution publication %q is not an applied declaration",
				value.ResolutionPublicationID,
			)
		}
	}
	return nil
}

func validateCanonicalRefTransition(
	current,
	next publication.CanonicalRef,
) error {
	if err := current.Validate(); err != nil {
		return invalidState("current canonical ref: %v", err)
	}
	if err := next.Validate(); err != nil {
		return invalidState("canonical-ref change: %v", err)
	}
	if next.RefName != current.RefName ||
		next.CommitOID.ObjectFormat() != current.CommitOID.ObjectFormat() ||
		current.EntityVersion == domain.MaxSafeInteger ||
		next.EntityVersion != current.EntityVersion+1 ||
		next.CommitOID == current.CommitOID {
		return invalidState("canonical ref has an invalid transition")
	}
	return nil
}

func classifyPublicationTransition(
	current,
	next publication.Publication,
) (publication.Operation, bool) {
	for _, operation := range publication.Operations() {
		if operation == publication.OperationRecoveryWithdraw {
			continue
		}
		if publication.ValidateTransition(operation, current, next) == nil {
			return operation, true
		}
	}
	return "", false
}

func classifyConflictTransition(
	current,
	next conflict.Conflict,
) (conflict.Operation, bool) {
	for _, operation := range conflict.Operations() {
		if conflict.ValidateTransition(operation, &current, next) == nil {
			return operation, true
		}
	}
	return "", false
}

func clonePublication(value publication.Publication) publication.Publication {
	result := value
	result.Metadata.ParentOIDs = append(
		[]domain.GitOID(nil),
		value.Metadata.ParentOIDs...,
	)
	result.Metadata.Paths = append(
		[]domain.RepositoryPath(nil),
		value.Metadata.Paths...,
	)
	result.Metadata.ResolvesConflictIDs = append(
		[]domain.ConflictID(nil),
		value.Metadata.ResolvesConflictIDs...,
	)
	result.StagingReceipts = append(
		[]publication.StagingReceipt(nil),
		value.StagingReceipts...,
	)
	if value.DecisionReason != nil {
		reason := *value.DecisionReason
		result.DecisionReason = &reason
	}
	return result
}

func cloneConflict(value conflict.Conflict) conflict.Conflict {
	result := value
	result.MergeBaseOIDs = append(
		[]domain.GitOID(nil),
		value.MergeBaseOIDs...,
	)
	result.Paths = append(
		[]domain.RepositoryPath(nil),
		value.Paths...,
	)
	return result
}
