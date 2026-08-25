package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	recoveryIdentitySignerKind = "identity"
	recoveryKeySignerKind      = "recovery_key"

	// Recovery-boundary audit time is local provenance, not signed authority.
	// Logical snapshot replay has no trustworthy original wall clock, so it
	// uses the same deterministic sentinel as migrated historical boundaries.
	logicalSnapshotRecoveryObservedAt domain.Timestamp = "1970-01-01T00:00:00Z"
)

var successorGenesisMembers = map[string]struct{}{
	"canonical_commit":                   {},
	"digest_version":                     {},
	"object_format":                      {},
	"post_transform_state_digest":        {},
	"predecessor_chain_hash":             {},
	"predecessor_chain_index":            {},
	"predecessor_genesis_digest":         {},
	"predecessor_projection_accumulator": {},
	"predecessor_result_hash":            {},
	"predecessor_result_index":           {},
	"projection_schema_version":          {},
	"quorum_recovery_signature":          {},
	"quorum_recovery_signer_kind":        {},
	"recovering_device_id":               {},
	"recovering_identity_signature":      {},
	"recovering_identity_signer_kind":    {},
	"recovery_generation":                {},
	"recovery_public_key":                {},
	"repository_data_loss_confirmed":     {},
	"session_id":                         {},
	"workspace_id":                       {},
}

type successorRecoveryBinding struct {
	recoveringDeviceID           domain.DeviceID
	recoveringIdentitySignerKind string
	quorumRecoverySignerKind     string
	recoveringIdentitySignature  []byte
	quorumRecoverySignature      []byte
	recoveryPublicKey            ed25519.PublicKey
	canonicalCommit              domain.GitOID
	objectFormat                 domain.GitObjectFormat
	repositoryDataLossConfirmed  bool
	unsignedBody                 []byte
}

func verifyLogicalSnapshotSuccessorBoundary(
	ctx context.Context,
	predecessor store.StateView,
	payload logicalsnapshot.GenesisPayload,
	historicalRecoveryKeys map[[ed25519.PublicKeySize]byte]struct{},
) (store.SuccessorState, error) {
	if historicalRecoveryKeys == nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"recovery-key history is unavailable",
			nil,
		)
	}
	metadata, err := logicalsnapshot.InspectGenesisPayload(payload)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"inspect successor genesis",
			err,
		)
	}
	if !metadata.HasPredecessor ||
		metadata.RecoveryGeneration == 0 ||
		len(payload.RecoveryAuthorizationJSON) == 0 {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"successor record has initial-generation shape",
			nil,
		)
	}
	if predecessor.RecoveryGeneration >= domain.MaxSafeInteger ||
		metadata.RecoveryGeneration != predecessor.RecoveryGeneration+1 ||
		metadata.SessionID == predecessor.SessionID ||
		metadata.WorkspaceID != predecessor.WorkspaceID {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"successor lineage identity does not extend predecessor",
			nil,
		)
	}
	if metadata.PredecessorChainIndex != predecessor.Heads.ChainIndex ||
		metadata.PredecessorChainHash !=
			chain.Digest(predecessor.Heads.ChainHash) ||
		metadata.PredecessorResultIndex != predecessor.Heads.ResultIndex ||
		metadata.PredecessorResultHash !=
			chain.Digest(predecessor.Heads.ResultHash) ||
		metadata.PredecessorProjectionAccumulator !=
			chain.Digest(predecessor.Heads.ProjectionAccumulator) ||
		metadata.DigestVersion != predecessor.Heads.DigestVersion ||
		metadata.ProjectionSchemaVersion !=
			predecessor.Heads.ProjectionSchemaVersion {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"signed predecessor commitments do not match verified cut",
			nil,
		)
	}
	predecessorGenesisDigest, err := chain.GenesisDigest(
		predecessor.GenesisJSON,
	)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"digest predecessor genesis",
			err,
		)
	}
	if metadata.PredecessorGenesisDigest != predecessorGenesisDigest {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"signed predecessor genesis digest does not match verified cut",
			nil,
		)
	}

	predecessorSnapshot, _, err := decodeReducerStateView(predecessor)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"decode verified predecessor projections",
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.SuccessorState{}, err
	}
	binding, err := parseSuccessorRecoveryBinding(payload)
	if err != nil {
		return store.SuccessorState{}, err
	}
	recoveringMember, exists :=
		predecessorSnapshot.Devices[binding.recoveringDeviceID]
	if !exists ||
		recoveringMember.Status != device.StatusActive ||
		(recoveringMember.Role != device.RoleOwner &&
			recoveringMember.Role != device.RoleEditor) {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"recovering identity is not an active predecessor member",
			nil,
		)
	}
	if err := codecommcrypto.VerifyEd25519(
		recoveringMember.IdentityPublicKey,
		codec.SignatureGenesis,
		binding.unsignedBody,
		binding.recoveringIdentitySignature,
	); err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"recovering identity signature",
			err,
		)
	}

	quorumKey := recoveringMember.IdentityPublicKey
	wantQuorumSignerKind := recoveryIdentitySignerKind
	if recoveringMember.Role == device.RoleEditor {
		quorumKey = predecessorSnapshot.RecoveryPublicKey
		wantQuorumSignerKind = recoveryKeySignerKind
	}
	if binding.recoveringIdentitySignerKind !=
		recoveryIdentitySignerKind ||
		binding.quorumRecoverySignerKind != wantQuorumSignerKind {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"signed recovery signer kinds disagree with predecessor role",
			nil,
		)
	}
	if err := codecommcrypto.VerifyEd25519(
		quorumKey,
		codec.SignatureQuorumRecovery,
		binding.unsignedBody,
		binding.quorumRecoverySignature,
	); err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"quorum-recovery signature",
			err,
		)
	}
	var recoveryKey [ed25519.PublicKeySize]byte
	copy(recoveryKey[:], binding.recoveryPublicKey)
	if _, reused := historicalRecoveryKeys[recoveryKey]; reused {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"successor reuses a historical recovery key",
			nil,
		)
	}
	for _, member := range predecessorSnapshot.Devices {
		if bytes.Equal(
			binding.recoveryPublicKey,
			member.IdentityPublicKey,
		) {
			return store.SuccessorState{}, invalidSuccessorBoundary(
				"successor recovery key reuses an enrolled identity key",
				nil,
			)
		}
	}

	transformed, err := recoverySuccessorSnapshot(
		predecessorSnapshot,
		metadata,
		binding,
	)
	if err != nil {
		return store.SuccessorState{}, err
	}
	if _, err := reducer.NewState(transformed); err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"validate transformed successor projections",
			err,
		)
	}
	writes := projectionWrites(snapshotProjectionChanges(transformed))
	versions := chain.Versions{
		Digest:           metadata.DigestVersion,
		ProjectionSchema: metadata.ProjectionSchemaVersion,
	}
	scratch, err := store.NewProjectionScratch(nil, versions)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"create successor projection scratch",
			err,
		)
	}
	if _, err := scratch.Apply(writes); err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"encode transformed successor projections",
			err,
		)
	}
	transformDigest, err := scratch.StateDigest(versions)
	if err != nil {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"digest transformed successor projections",
			err,
		)
	}
	if transformDigest != metadata.BoundaryTransformDigest {
		return store.SuccessorState{}, invalidSuccessorBoundary(
			"signed post-transform digest does not match deterministic transform",
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.SuccessorState{}, err
	}

	return store.SuccessorState{
		SessionID:                 metadata.SessionID,
		WorkspaceID:               metadata.WorkspaceID,
		RecoveryGeneration:        metadata.RecoveryGeneration,
		GenesisJSON:               bytes.Clone(payload.GenesisJSON),
		RecoveryAuthorizationJSON: bytes.Clone(payload.RecoveryAuthorizationJSON),
		ObservedAt:                logicalSnapshotRecoveryObservedAt,
		Predecessor:               predecessor.Heads,
		Projections:               writes,
		DigestVersion:             metadata.DigestVersion,
		ProjectionSchemaVersion:   metadata.ProjectionSchemaVersion,
	}, nil
}

func parseSuccessorRecoveryBinding(
	payload logicalsnapshot.GenesisPayload,
) (successorRecoveryBinding, error) {
	var members map[string]json.RawMessage
	if err := decodeStrictJSON(payload.GenesisJSON, &members); err != nil {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"decode successor genesis",
			err,
		)
	}
	if len(members) != len(successorGenesisMembers) {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			fmt.Sprintf(
				"successor genesis has %d members, want %d",
				len(members),
				len(successorGenesisMembers),
			),
			nil,
		)
	}
	for name := range successorGenesisMembers {
		if _, exists := members[name]; !exists {
			return successorRecoveryBinding{}, invalidSuccessorBoundary(
				"successor genesis omits "+name,
				nil,
			)
		}
	}

	var binding successorRecoveryBinding
	recoveringID, err := successorStringMember(
		members,
		"recovering_device_id",
	)
	if err != nil {
		return successorRecoveryBinding{}, err
	}
	binding.recoveringDeviceID = domain.DeviceID(recoveringID)
	if !binding.recoveringDeviceID.Valid() {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"recovering_device_id is invalid",
			nil,
		)
	}
	if binding.recoveringIdentitySignerKind, err =
		successorStringMember(
			members,
			"recovering_identity_signer_kind",
		); err != nil {
		return successorRecoveryBinding{}, err
	}
	if binding.quorumRecoverySignerKind, err =
		successorStringMember(
			members,
			"quorum_recovery_signer_kind",
		); err != nil {
		return successorRecoveryBinding{}, err
	}
	if binding.recoveringIdentitySignature, err =
		successorBase64Member(
			members,
			"recovering_identity_signature",
			ed25519.SignatureSize,
		); err != nil {
		return successorRecoveryBinding{}, err
	}
	if binding.quorumRecoverySignature, err =
		successorBase64Member(
			members,
			"quorum_recovery_signature",
			ed25519.SignatureSize,
		); err != nil {
		return successorRecoveryBinding{}, err
	}
	recoveryKey, err := successorBase64Member(
		members,
		"recovery_public_key",
		ed25519.PublicKeySize,
	)
	if err != nil {
		return successorRecoveryBinding{}, err
	}
	binding.recoveryPublicKey = ed25519.PublicKey(recoveryKey)
	canonicalCommit, err := successorStringMember(
		members,
		"canonical_commit",
	)
	if err != nil {
		return successorRecoveryBinding{}, err
	}
	binding.canonicalCommit = domain.GitOID(canonicalCommit)
	if !binding.canonicalCommit.Valid() {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"canonical_commit is invalid",
			nil,
		)
	}
	objectFormat, err := successorStringMember(members, "object_format")
	if err != nil {
		return successorRecoveryBinding{}, err
	}
	binding.objectFormat = domain.GitObjectFormat(objectFormat)
	if !binding.objectFormat.Valid() ||
		binding.canonicalCommit.ObjectFormat() != binding.objectFormat {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"canonical commit and object format disagree",
			nil,
		)
	}
	if err := decodeSuccessorMember(
		members,
		"repository_data_loss_confirmed",
		&binding.repositoryDataLossConfirmed,
	); err != nil {
		return successorRecoveryBinding{}, err
	}

	delete(members, "recovering_identity_signature")
	delete(members, "quorum_recovery_signature")
	encodedBody, err := json.Marshal(members)
	if err != nil {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"encode successor authorization body",
			err,
		)
	}
	binding.unsignedBody, err = codec.CanonicalizeSignedObject(encodedBody)
	if err != nil {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"canonicalize successor authorization body",
			err,
		)
	}
	if !bytes.Equal(
		binding.unsignedBody,
		payload.RecoveryAuthorizationJSON,
	) {
		return successorRecoveryBinding{}, invalidSuccessorBoundary(
			"recovery authorization is not the exact signed successor body",
			nil,
		)
	}
	return binding, nil
}

func recoverySuccessorSnapshot(
	predecessor reducer.Snapshot,
	metadata logicalsnapshot.GenesisMetadata,
	binding successorRecoveryBinding,
) (reducer.Snapshot, error) {
	lineage, err := recoveryCanonicalLineage(
		predecessor.Publications,
		predecessor.CanonicalRef.CommitOID,
		binding.canonicalCommit,
	)
	if err != nil {
		return reducer.Snapshot{}, err
	}
	rolledBack := binding.canonicalCommit !=
		predecessor.CanonicalRef.CommitOID
	if binding.repositoryDataLossConfirmed != rolledBack {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"repository-data-loss confirmation disagrees with canonical selection",
			nil,
		)
	}
	if binding.objectFormat !=
		predecessor.CanonicalRef.CommitOID.ObjectFormat() {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"successor changed the Git object format",
			nil,
		)
	}

	successor := reducer.Snapshot{
		SessionID:                metadata.SessionID,
		WorkspaceID:              metadata.WorkspaceID,
		RecoveryGeneration:       metadata.RecoveryGeneration,
		RecoveryPublicKey:        bytes.Clone(binding.recoveryPublicKey),
		CurrentChainIndex:        predecessor.CurrentChainIndex,
		CurrentResultIndex:       predecessor.CurrentResultIndex,
		OriginScopes:             make(map[reducer.OriginScopeKey]reducer.OriginScope),
		AuditCounters:            make(map[domain.DeviceID]auditcounter.Counter, len(predecessor.AuditCounters)),
		Devices:                  make(map[domain.DeviceID]device.Device, len(predecessor.Devices)),
		CredentialAuthorizations: make(map[credentialauthorization.Key]credentialauthorization.Authorization, len(predecessor.CredentialAuthorizations)),
		AgentSessions:            make(map[domain.UUIDv7]agentsession.Session, len(predecessor.AgentSessions)),
		Tasks:                    make(map[domain.UUIDv7]task.Task, len(predecessor.Tasks)),
		PlanRevisions:            make(map[domain.UUIDv7]plan.Revision, len(predecessor.PlanRevisions)),
		MemoryRecords:            make(map[domain.UUIDv7]memory.Record, len(predecessor.MemoryRecords)),
		Leases:                   make(map[domain.UUIDv7]lease.Lease, len(predecessor.Leases)),
		Publications:             make(map[domain.UUIDv7]publication.Publication, len(predecessor.Publications)),
		ControlFileProposals:     make(map[domain.UUIDv7]controlfile.Proposal, len(predecessor.ControlFileProposals)),
		MergeConflicts:           make(map[domain.ConflictID]conflict.Conflict, len(predecessor.MergeConflicts)),
	}

	for id, current := range predecessor.Devices {
		next := current
		next.EntityVersion = 1
		var operation device.Operation
		switch {
		case id == binding.recoveringDeviceID:
			next.Role = device.RoleOwner
			next.Status = device.StatusActive
			operation = device.OperationRecoveryRetain
		case current.Status == device.StatusRevoked:
			operation = device.OperationRecoveryPreserve
		default:
			next.Status = device.StatusRequiresReadmission
			operation = device.OperationRecoveryDemotion
		}
		if err := device.ValidateTransition(
			operation,
			&current,
			next,
		); err != nil {
			return reducer.Snapshot{}, invalidSuccessorBoundary(
				fmt.Sprintf("transform device %s", id),
				err,
			)
		}
		next.IdentityPublicKey = bytes.Clone(next.IdentityPublicKey)
		successor.Devices[id] = next
		successor.AuditCounters[id] = auditcounter.Counter{DeviceID: id}
	}

	target, err := voterset.New(
		metadata.SessionID,
		[]domain.DeviceID{binding.recoveringDeviceID},
		1,
	)
	if err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"construct recovery voter target",
			err,
		)
	}
	if err := voterset.ValidateTransition(
		voterset.OperationRecoveryReset,
		predecessor.VoterSet,
		target,
	); err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"reset recovery voter target",
			err,
		)
	}
	successor.VoterSet = target
	authority := credentialauthority.Authority{
		SessionID:        metadata.SessionID,
		VoterDeviceIDs:   []domain.DeviceID{binding.recoveringDeviceID},
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}
	if err := credentialauthority.ValidateTransition(
		credentialauthority.OperationRecoveryReset,
		predecessor.CredentialAuthority,
		authority,
	); err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"reset recovery credential authority",
			err,
		)
	}
	successor.CredentialAuthority = authority

	for key, value := range predecessor.CredentialAuthorizations {
		successor.CredentialAuthorizations[key] = value.Clone()
	}
	for id, current := range predecessor.AgentSessions {
		next := current
		if current.State != agentsession.StateEnded {
			if err := agentsession.ValidateTransition(
				agentsession.OperationRecoveryEnd,
				current.Lifecycle(),
				agentsession.Lifecycle{
					State:     agentsession.StateEnded,
					EndReason: agentsession.EndReasonRecovery,
				},
			); err != nil {
				return reducer.Snapshot{}, invalidSuccessorBoundary(
					fmt.Sprintf("end agent session %s", id),
					err,
				)
			}
		}
		next.State = agentsession.StateEnded
		next.ResumeState = agentsession.StateAbsent
		next.EndReason = agentsession.EndReasonRecovery
		next.EntityVersion = 1
		successor.AgentSessions[id] = next
	}
	for id, current := range predecessor.Tasks {
		next := current
		if current.OwnerDeviceID != "" {
			if err := task.ValidateTransition(
				task.OperationRecoveryRelease,
				current.State,
				task.StateReady,
			); err != nil {
				return reducer.Snapshot{}, invalidSuccessorBoundary(
					fmt.Sprintf("release task %s", id),
					err,
				)
			}
			next.State = task.StateReady
			next.StateReason = nil
			next.OwnerDeviceID = ""
			next.OwnerAgentSessionID = ""
			next.IntendedDeviceID = ""
			next.LastReleaseReason = task.ReleaseRecovery
		}
		next.EntityVersion = 1
		successor.Tasks[id] = next
	}
	for id, value := range predecessor.PlanRevisions {
		successor.PlanRevisions[id] = value
	}
	nextCurrent := predecessor.PlanCurrent
	nextCurrent.SessionID = metadata.SessionID
	nextCurrent.EntityVersion = 1
	if err := plan.ValidateTransition(
		plan.OperationRecoveryReset,
		predecessor.PlanCurrent,
		nextCurrent,
	); err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"remap current plan",
			err,
		)
	}
	successor.PlanCurrent = nextCurrent
	for id, value := range predecessor.MemoryRecords {
		successor.MemoryRecords[id] = value
	}
	for id, current := range predecessor.Leases {
		next, err := recoveryLease(current)
		if err != nil {
			return reducer.Snapshot{}, invalidSuccessorBoundary(
				fmt.Sprintf("release lease %s", id),
				err,
			)
		}
		successor.Leases[id] = next
	}

	successor.CanonicalRef = publication.CanonicalRef{
		RefName:       predecessor.CanonicalRef.RefName,
		CommitOID:     binding.canonicalCommit,
		EntityVersion: 1,
	}
	if err := successor.CanonicalRef.Validate(); err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"select recovery canonical ref",
			err,
		)
	}
	for id, current := range predecessor.Publications {
		next := current
		if current.State == publication.StateProposed ||
			current.State == publication.StateApproved {
			reason := publication.RecoveryDecisionReason
			next.State = publication.StateWithdrawn
			next.TerminalSource = publication.TerminalSourceRecovery
			next.CanonicalLineageMember = false
			next.DecisionReason = &reason
			next.EntityVersion = 1
			if err := publication.ValidateTransition(
				publication.OperationRecoveryWithdraw,
				current,
				next,
			); err != nil {
				return reducer.Snapshot{}, invalidSuccessorBoundary(
					fmt.Sprintf("withdraw publication %s", id),
					err,
				)
			}
		}
		next.CanonicalLineageMember =
			next.State == publication.StateApplied && lineage[id]
		next.EntityVersion = 1
		if err := next.Validate(); err != nil {
			return reducer.Snapshot{}, invalidSuccessorBoundary(
				fmt.Sprintf("transform publication %s", id),
				err,
			)
		}
		successor.Publications[id] = next
	}
	for id, value := range predecessor.ControlFileProposals {
		successor.ControlFileProposals[id] = value.Clone()
	}
	for id, value := range predecessor.MergeConflicts {
		value.EntityVersion = 1
		successor.MergeConflicts[id] = value
	}
	nextPolicy := predecessor.SessionPolicy
	nextPolicy.SessionID = metadata.SessionID
	nextPolicy.EntityVersion = 1
	if err := policy.ValidateTransition(
		policy.OperationRecoveryReset,
		predecessor.SessionPolicy,
		nextPolicy,
	); err != nil {
		return reducer.Snapshot{}, invalidSuccessorBoundary(
			"remap recovery session policy",
			err,
		)
	}
	successor.SessionPolicy = nextPolicy
	return successor, nil
}

func recoveryLease(current lease.Lease) (lease.Lease, error) {
	status := current.Status
	reason := current.ReleaseReason
	if current.Status == lease.StatusActive {
		status = lease.StatusReleased
		reason = lease.ReleaseRecovery
		if err := lease.ValidateTransition(
			lease.OperationRecoveryRelease,
			current.Lifecycle(),
			lease.Lifecycle{Status: status, ReleaseReason: reason},
		); err != nil {
			return lease.Lease{}, err
		}
	}
	patterns := current.PathPatterns()
	rawPatterns := make([]string, len(patterns))
	for index, pattern := range patterns {
		rawPatterns[index] = pattern.String()
	}
	return lease.New(
		lease.Fields{
			ID:                   current.ID,
			HolderDeviceID:       current.HolderDeviceID,
			HolderAgentSessionID: current.HolderAgentSessionID,
			Scope:                current.Scope,
			TaskID:               current.TaskID,
			TTLSeconds:           current.TTLSeconds,
			Status:               status,
			ReleaseReason:        reason,
			EntityVersion:        1,
		},
		rawPatterns,
	)
}

func recoveryCanonicalLineage(
	publications map[domain.UUIDv7]publication.Publication,
	current domain.GitOID,
	selected domain.GitOID,
) (map[domain.UUIDv7]bool, error) {
	byCommit := make(map[domain.GitOID]domain.UUIDv7)
	for id, value := range publications {
		if value.State != publication.StateApplied {
			continue
		}
		if prior, duplicate := byCommit[value.Metadata.CommitOID]; duplicate {
			return nil, invalidSuccessorBoundary(
				fmt.Sprintf(
					"applied publications %s and %s share commit %s",
					prior,
					id,
					value.Metadata.CommitOID,
				),
				nil,
			)
		}
		byCommit[value.Metadata.CommitOID] = id
	}
	if err := walkRecoveryFirstParents(
		publications,
		byCommit,
		current,
		selected,
		nil,
	); err != nil {
		return nil, err
	}
	lineage := make(map[domain.UUIDv7]bool)
	if err := walkRecoveryFirstParents(
		publications,
		byCommit,
		selected,
		"",
		lineage,
	); err != nil {
		return nil, err
	}
	return lineage, nil
}

func walkRecoveryFirstParents(
	publications map[domain.UUIDv7]publication.Publication,
	byCommit map[domain.GitOID]domain.UUIDv7,
	start domain.GitOID,
	stop domain.GitOID,
	lineage map[domain.UUIDv7]bool,
) error {
	seen := make(map[domain.GitOID]struct{})
	current := start
	for current != stop {
		if _, duplicate := seen[current]; duplicate {
			return invalidSuccessorBoundary(
				"applied publication first-parent lineage is cyclic",
				nil,
			)
		}
		seen[current] = struct{}{}
		id, exists := byCommit[current]
		if !exists {
			if stop == "" {
				return nil
			}
			return invalidSuccessorBoundary(
				"selected canonical commit is not a verified first-parent ancestor",
				nil,
			)
		}
		if lineage != nil {
			lineage[id] = true
		}
		value := publications[id]
		if len(value.Metadata.ParentOIDs) == 0 {
			return invalidSuccessorBoundary(
				"applied publication lacks a first parent",
				nil,
			)
		}
		current = value.Metadata.ParentOIDs[0]
	}
	return nil
}

func successorStringMember(
	members map[string]json.RawMessage,
	name string,
) (string, error) {
	var value string
	if err := decodeSuccessorMember(members, name, &value); err != nil {
		return "", err
	}
	return value, nil
}

func successorBase64Member(
	members map[string]json.RawMessage,
	name string,
	size int,
) ([]byte, error) {
	encoded, err := successorStringMember(members, name)
	if err != nil {
		return nil, err
	}
	value, err := codec.DecodeBase64URLExact(encoded, size)
	if err != nil {
		return nil, invalidSuccessorBoundary(
			"successor genesis "+name,
			err,
		)
	}
	return bytes.Clone(value), nil
}

func decodeSuccessorMember(
	members map[string]json.RawMessage,
	name string,
	destination any,
) error {
	raw, exists := members[name]
	if !exists || bytes.Equal(raw, []byte("null")) {
		return invalidSuccessorBoundary(
			"successor genesis omits "+name,
			nil,
		)
	}
	if err := decodeStrictJSON(raw, destination); err != nil {
		return invalidSuccessorBoundary(
			"decode successor genesis "+name,
			err,
		)
	}
	return nil
}

func invalidSuccessorBoundary(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf(
			"%w: %s",
			ErrLogicalSnapshotSuccessorBoundaryInvalid,
			detail,
		)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrLogicalSnapshotSuccessorBoundaryInvalid,
		detail,
		cause,
	)
}
