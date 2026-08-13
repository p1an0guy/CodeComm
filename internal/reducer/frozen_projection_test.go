package reducer

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

type frozenProjectionRow struct {
	Table      string          `json:"table"`
	PrimaryKey json.RawMessage `json:"primary_key"`
	Row        json.RawMessage `json:"row"`
}

func frozenProjectionRows(t *testing.T, state State) []frozenProjectionRow {
	t.Helper()
	var rows []frozenProjectionRow
	add := func(table string, key []any, row map[string]any) {
		rows = append(rows, frozenProjectionRow{
			Table:      table,
			PrimaryKey: frozenCanonicalJSON(t, key),
			Row:        frozenCanonicalJSON(t, row),
		})
	}

	for _, value := range state.originScopes {
		add("origin_scopes", []any{
			string(value.DeviceID), string(value.Kind), string(value.ScopeID),
		}, map[string]any{
			"device_id":     value.DeviceID,
			"scope_kind":    value.Kind,
			"scope_id":      value.ScopeID,
			"last_sequence": value.LastSequence,
		})
	}
	for _, value := range state.auditCounters {
		add("audit_counters", []any{string(value.DeviceID)}, map[string]any{
			"device_id":        value.DeviceID,
			"credential_epoch": value.CredentialEpoch,
			"accepted_count":   value.AcceptedCount,
		})
	}
	for _, value := range state.tasks {
		add("tasks", []any{string(value.ID)}, map[string]any{
			"task_id":                value.ID,
			"title":                  value.Title,
			"body":                   value.Body,
			"state":                  value.State,
			"state_reason":           frozenStringPointer(value.StateReason),
			"priority":               value.Priority,
			"blocked_by":             frozenStrings(value.BlockedBy),
			"labels":                 frozenStrings(value.Labels),
			"owner_device_id":        frozenNullable(value.OwnerDeviceID),
			"owner_agent_session_id": frozenNullable(value.OwnerAgentSessionID),
			"intended_device_id":     frozenNullable(value.IntendedDeviceID),
			"last_release_reason":    frozenNullable(value.LastReleaseReason),
			"entity_version":         value.EntityVersion,
			"created_at":             value.CreatedAt,
			"updated_at":             value.UpdatedAt,
		})
	}
	for _, value := range state.planRevisions {
		addFrozenPlanRevision(add, value)
	}
	add("plan_current", []any{string(state.planCurrent.SessionID)}, map[string]any{
		"session_id":       state.planCurrent.SessionID,
		"plan_revision_id": frozenNullable(state.planCurrent.RevisionID),
		"entity_version":   state.planCurrent.EntityVersion,
	})
	for _, value := range state.memoryRecords {
		addFrozenMemoryRecord(add, value)
	}
	for _, value := range state.leases {
		var paths any
		if patterns := value.PathPatterns(); patterns != nil {
			texts := make([]string, len(patterns))
			for index, pattern := range patterns {
				texts[index] = pattern.String()
			}
			paths = texts
		}
		add("leases", []any{string(value.ID)}, map[string]any{
			"lease_id":                value.ID,
			"holder_device_id":        value.HolderDeviceID,
			"holder_agent_session_id": value.HolderAgentSessionID,
			"scope":                   value.Scope,
			"task_id":                 frozenNullable(value.TaskID),
			"path_globs":              paths,
			"ttl_seconds":             value.TTLSeconds,
			"status":                  value.Status,
			"release_reason":          frozenNullable(value.ReleaseReason),
			"entity_version":          value.EntityVersion,
		})
	}
	for _, value := range state.devices {
		add("devices", []any{string(value.ID)}, map[string]any{
			"device_id":           value.ID,
			"role":                value.Role,
			"identity_public_key": codec.EncodeBase64URL(value.IdentityPublicKey),
			"daemon_version":      value.DaemonVersion,
			"max_apply_level":     value.MaxApplyLevel,
			"status":              value.Status,
			"entity_version":      value.EntityVersion,
		})
	}
	add("voter_set", []any{string(state.voterSet.SessionID)}, map[string]any{
		"session_id":        state.voterSet.SessionID,
		"voter_device_ids":  frozenStrings(state.voterSet.VoterDeviceIDs()),
		"voter_set_version": state.voterSet.VoterSetVersion,
	})
	authority := state.credentialAuthority
	proofs := make([]json.RawMessage, len(authority.ActivationProofs))
	for index := range authority.ActivationProofs {
		proofs[index] = authority.ActivationProofs[index].CanonicalJSON
	}
	add("credential_authority", []any{string(authority.SessionID)}, map[string]any{
		"session_id":                     authority.SessionID,
		"voter_device_ids":               frozenStrings(authority.VoterDeviceIDs),
		"voter_set_version":              authority.VoterSetVersion,
		"activation_source":              authority.ActivationSource,
		"activation_checkpoint_event_id": frozenNullable(authority.ActivationCheckpointEventID),
		"activation_proofs":              proofs,
		"prior_authority_signer":         frozenNullable(authority.PriorAuthoritySigner),
		"prior_authority_handoff":        frozenSignature(authority.PriorAuthorityHandoff),
	})
	for _, value := range state.agentSessions {
		add("agent_sessions", []any{string(value.ID)}, map[string]any{
			"agent_session_id": value.ID,
			"device_id":        value.DeviceID,
			"client_kind":      value.ClientKind,
			"agent_profile_id": frozenStringPointer(value.AgentProfileID),
			"state":            value.State,
			"resume_state":     frozenNullable(value.ResumeState),
			"working_root_id":  value.WorkingRootID,
			"end_reason":       frozenNullable(value.EndReason),
			"entity_version":   value.EntityVersion,
		})
	}
	add("canonical_refs", []any{state.canonicalRef.RefName}, map[string]any{
		"ref_name":       state.canonicalRef.RefName,
		"commit_oid":     state.canonicalRef.CommitOID,
		"entity_version": state.canonicalRef.EntityVersion,
	})
	for _, value := range state.credentialAuthorizations {
		addFrozenCredentialAuthorization(add, value)
	}
	for _, value := range state.publications {
		addFrozenPublication(add, value)
	}
	for _, value := range state.controlFileProposals {
		var digest any
		if value.ContentDigest != nil {
			digest = codec.EncodeBase64URL(value.ContentDigest[:])
		}
		add("control_file_proposals", []any{string(value.ProposalEventID)}, map[string]any{
			"proposal_event_id":     value.ProposalEventID,
			"session_id":            value.SessionID,
			"path":                  value.Path,
			"operation":             value.Operation,
			"content_digest":        digest,
			"content_size":          value.ContentSize,
			"diff":                  value.Diff,
			"proposed_by_device_id": value.ProposedByDeviceID,
			"chain_index":           value.ChainIndex,
		})
	}
	for _, value := range state.mergeConflicts {
		add("merge_conflicts", []any{string(value.ID)}, map[string]any{
			"conflict_id":               value.ID,
			"publication_id":            value.PublicationID,
			"merge_kind":                value.MergeKind,
			"replay_commit_oid":         frozenNullable(value.ReplayCommitOID),
			"merge_base_oids":           frozenStrings(value.MergeBaseOIDs),
			"canonical_commit":          value.CanonicalCommit,
			"candidate_commit":          value.CandidateCommit,
			"paths":                     frozenStrings(value.Paths),
			"status":                    value.Status,
			"resolution_kind":           frozenNullable(value.ResolutionKind),
			"resolution_publication_id": frozenNullable(value.ResolutionPublicationID),
			"force_reason":              frozenNullable(value.ForceReason),
			"resolved_by_device_id":     frozenNullable(value.ResolvedByDeviceID),
			"entity_version":            value.EntityVersion,
		})
	}
	addFrozenPolicy(add, state.sessionPolicy)

	order := make(map[string]int)
	for index, table := range chain.CoveredTables() {
		order[table] = index
	}
	sort.Slice(rows, func(left, right int) bool {
		if order[rows[left].Table] != order[rows[right].Table] {
			return order[rows[left].Table] < order[rows[right].Table]
		}
		return bytes.Compare(rows[left].PrimaryKey, rows[right].PrimaryKey) < 0
	})
	return rows
}

func frozenMutations(
	t *testing.T,
	before []frozenProjectionRow,
	after []frozenProjectionRow,
) []chain.Mutation {
	t.Helper()
	type key struct {
		table      string
		primaryKey string
	}
	beforeByKey := make(map[key]frozenProjectionRow, len(before))
	afterByKey := make(map[key]frozenProjectionRow, len(after))
	for _, row := range before {
		beforeByKey[key{row.Table, string(row.PrimaryKey)}] = row
	}
	for _, row := range after {
		afterByKey[key{row.Table, string(row.PrimaryKey)}] = row
	}
	keys := make(map[key]struct{}, len(before)+len(after))
	for value := range beforeByKey {
		keys[value] = struct{}{}
	}
	for value := range afterByKey {
		keys[value] = struct{}{}
	}
	mutations := make([]chain.Mutation, 0, len(keys))
	for value := range keys {
		prior, hadPrior := beforeByKey[value]
		next, hasNext := afterByKey[value]
		if hadPrior && hasNext && bytes.Equal(prior.Row, next.Row) {
			continue
		}
		mutation := chain.Mutation{
			Table:      value.table,
			PrimaryKey: []byte(value.primaryKey),
		}
		if hadPrior {
			mutation.Before = prior.Row
		}
		if hasNext {
			mutation.After = next.Row
		}
		mutations = append(mutations, mutation)
	}
	if _, err := chain.EncodeMutations(mutations); err != nil {
		t.Fatalf("encode projection mutations: %v", err)
	}
	return mutations
}

func frozenChainRows(rows []frozenProjectionRow) []chain.LogicalRow {
	result := make([]chain.LogicalRow, len(rows))
	for index, row := range rows {
		result[index] = chain.LogicalRow{
			Table:      row.Table,
			PrimaryKey: row.PrimaryKey,
			Row:        row.Row,
		}
	}
	return result
}

func addFrozenPlanRevision(
	add func(string, []any, map[string]any),
	value plan.Revision,
) {
	supersedes, _ := value.Supersedes()
	add("plan_revisions", []any{string(value.ID())}, map[string]any{
		"plan_revision_id":      value.ID(),
		"supersedes":            frozenNullable(supersedes),
		"title":                 value.Title(),
		"body":                  value.Body(),
		"task_ids":              frozenStrings(value.TaskIDs()),
		"proposed_by_device_id": value.ProposedByDeviceID(),
		"created_at":            value.CreatedAt(),
	})
}

func addFrozenMemoryRecord(
	add func(string, []any, map[string]any),
	value memory.Record,
) {
	taskID, _ := value.TaskID()
	supersedes, _ := value.Supersedes()
	add("memory_records", []any{string(value.ID())}, map[string]any{
		"memory_id":  value.ID(),
		"scope":      value.Scope(),
		"task_id":    frozenNullable(taskID),
		"key":        value.Key(),
		"body":       value.Body(),
		"supersedes": frozenNullable(supersedes),
		"created_at": value.CreatedAt(),
	})
}

func addFrozenCredentialAuthorization(
	add func(string, []any, map[string]any),
	value credentialauthorization.Authorization,
) {
	endorsements := make([]map[string]any, len(value.ClockEndorsements))
	for index, endorsement := range value.ClockEndorsements {
		endorsements[index] = map[string]any{
			"device_id": endorsement.DeviceID,
			"signature": codec.EncodeBase64URL(endorsement.Signature[:]),
		}
	}
	add("credential_authorizations", []any{
		string(value.SessionID), string(value.DeviceID), value.Epoch,
	}, map[string]any{
		"session_id":                  value.SessionID,
		"device_id":                   value.DeviceID,
		"epoch":                       value.Epoch,
		"epoch_public_key":            codec.EncodeBase64URL(value.EpochPublicKey[:]),
		"key_digest":                  codec.EncodeBase64URL(value.KeyDigest[:]),
		"role":                        value.Role,
		"issued_at":                   value.IssuedAt,
		"not_before":                  value.NotBefore,
		"validity_seconds":            value.ValiditySeconds,
		"authority_voter_set_version": value.AuthorityVoterSetVersion,
		"clock_endorsements":          endorsements,
		"binding_signature":           codec.EncodeBase64URL(value.BindingSignature[:]),
		"authorization_chain_index":   value.AuthorizationChainIndex,
	})
}

func addFrozenPublication(
	add func(string, []any, map[string]any),
	value publication.Publication,
) {
	receipts := make([]map[string]any, len(value.StagingReceipts))
	for index, receipt := range value.StagingReceipts {
		receipts[index] = map[string]any{
			"session_id":                  receipt.SessionID,
			"workspace_id":                receipt.WorkspaceID,
			"voter_set_version":           receipt.VoterSetVersion,
			"publication_metadata_digest": codec.EncodeBase64URL(receipt.PublicationMetadataDigest[:]),
			"voter_device_id":             receipt.VoterDeviceID,
			"staged_result_index":         receipt.StagedResultIndex,
			"signature":                   codec.EncodeBase64URL(receipt.Signature[:]),
		}
	}
	metadata := value.Metadata
	add("publications", []any{string(metadata.PublicationID)}, map[string]any{
		"publication_id":            metadata.PublicationID,
		"proposal_event_id":         metadata.ProposalEventID,
		"supersedes_publication_id": frozenNullable(metadata.SupersedesPublicationID),
		"task_id":                   frozenNullable(metadata.TaskID),
		"author_device_id":          metadata.AuthorDeviceID,
		"author_agent_session_id":   metadata.AuthorAgentSessionID,
		"base_commit":               metadata.BaseCommit,
		"commit_oid":                metadata.CommitOID,
		"tree_oid":                  metadata.TreeOID,
		"parent_oids":               frozenStrings(metadata.ParentOIDs),
		"paths":                     frozenStrings(metadata.Paths),
		"artifact_digest":           codec.EncodeBase64URL(metadata.ArtifactDigest[:]),
		"resolves_conflict_ids":     frozenStrings(metadata.ResolvesConflictIDs),
		"working_root_id":           metadata.WorkingRootID,
		"staging_receipts":          receipts,
		"state":                     value.State,
		"terminal_source":           frozenNullable(value.TerminalSource),
		"canonical_lineage_member":  value.CanonicalLineageMember,
		"review_verdict":            frozenNullable(value.ReviewVerdict),
		"reviewer_device_id":        frozenNullable(value.ReviewerDeviceID),
		"reviewer_agent_session_id": frozenNullable(value.ReviewerAgentSessionID),
		"review_actor_type":         frozenNullable(value.ReviewActorType),
		"decision_reason":           frozenStringPointer(value.DecisionReason),
		"entity_version":            value.EntityVersion,
	})
}

func addFrozenPolicy(
	add func(string, []any, map[string]any),
	value policy.Policy,
) {
	values := value.Values
	add("session_policy", []any{string(value.SessionID)}, map[string]any{
		"session_id": value.SessionID,
		"values": map[string]any{
			"checkpoint_events":                values.CheckpointEvents,
			"checkpoint_interval_seconds":      values.CheckpointIntervalSeconds,
			"lease_min_ttl_seconds":            values.LeaseMinTTLSeconds,
			"lease_default_ttl_seconds":        values.LeaseDefaultTTLSeconds,
			"lease_max_ttl_seconds":            values.LeaseMaxTTLSeconds,
			"agent_claim_limit":                values.AgentClaimLimit,
			"agent_lease_limit":                values.AgentLeaseLimit,
			"device_claim_limit":               values.DeviceClaimLimit,
			"device_lease_limit":               values.DeviceLeaseLimit,
			"advertisement_interval_seconds":   values.AdvertisementIntervalSeconds,
			"audit_depth_per_device_per_epoch": values.AuditDepthPerDevicePerEpoch,
			"max_member_devices":               values.MaxMemberDevices,
			"max_active_agent_sessions":        values.MaxActiveAgentSessions,
			"cluster_min_apply_level":          values.ClusterMinApplyLevel,
		},
		"entity_version": value.EntityVersion,
	})
}

func frozenCanonicalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture JSON: %v", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		t.Fatalf("canonicalize fixture JSON: %v", err)
	}
	return canonical
}

func frozenNullable[T ~string](value T) any {
	if value == "" {
		return nil
	}
	return string(value)
}

func frozenStringPointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func frozenSignature(value *[64]byte) any {
	if value == nil {
		return nil
	}
	return codec.EncodeBase64URL(value[:])
}

func frozenStrings[T ~string](values []T) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}
