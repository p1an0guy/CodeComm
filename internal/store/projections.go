package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"zombiezen.com/go/sqlite"
)

const maxControlFileDiffBytes = 64 << 10

// ProjectionWrites is one validated set of logical row writes. The caller
// owns the surrounding SQLite transaction.
type ProjectionWrites struct {
	OriginScopes             []OriginScopeRow
	AuditCounters            []auditcounter.Counter
	Tasks                    []task.Task
	PlanRevisions            []plan.Revision
	PlanCurrent              []plan.Current
	MemoryRecords            []memory.Record
	Leases                   []lease.Lease
	Devices                  []device.Device
	VoterSet                 []voterset.Set
	CredentialAuthority      []CredentialAuthorityRow
	AgentSessions            []agentsession.Session
	CanonicalRefs            []publication.CanonicalRef
	CredentialAuthorizations []CredentialAuthorizationRow
	Publications             []publication.Publication
	ControlFileProposals     []ControlFileProposalRow
	MergeConflicts           []conflict.Conflict
	SessionPolicy            []policy.Policy
}

// OriginScopeKind identifies the sequence namespace consumed by an origin.
type OriginScopeKind = string

const (
	OriginScopeKindAgent = "agent"
	OriginScopeKindBoot  = "boot"
)

func validOriginScopeKind(kind OriginScopeKind) bool {
	return kind == OriginScopeKindAgent || kind == OriginScopeKindBoot
}

// OriginScopeRow is the digest-covered per-origin sequence projection.
type OriginScopeRow struct {
	DeviceID     domain.DeviceID
	ScopeKind    OriginScopeKind
	ScopeID      domain.UUIDv7
	LastSequence uint64
}

// Validate verifies the row's persisted invariants.
func (row OriginScopeRow) Validate() error {
	if !row.DeviceID.Valid() {
		return fmt.Errorf("store: origin scope: invalid device ID %q", row.DeviceID)
	}
	if !validOriginScopeKind(row.ScopeKind) {
		return fmt.Errorf("store: origin scope: invalid scope kind %q", row.ScopeKind)
	}
	if !row.ScopeID.Valid() {
		return fmt.Errorf("store: origin scope: invalid scope ID %q", row.ScopeID)
	}
	if row.LastSequence < 1 || !domain.ValidUnsignedInteger(row.LastSequence) {
		return fmt.Errorf(
			"store: origin scope: last sequence must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// CredentialAuthorityActivationSource identifies how an authority became
// active for the current recovery generation.
type CredentialAuthorityActivationSource = credentialauthority.ActivationSource

const (
	CredentialAuthorityGenesis = credentialauthority.ActivationGenesis
	CredentialAuthorityHandoff = credentialauthority.ActivationHandoff
)

// ActivationProof binds one canonical signed proof to its voter so the
// digest-covered array has the same order as the sorted authority target.
type ActivationProof = credentialauthority.ActivationProof

// CredentialAuthorityRow is the last voter target activated by a proven
// authority handoff. ActivationProofs contain closed signed objects already
// verified by the consensus proof layer.
type CredentialAuthorityRow credentialauthority.Authority

// Validate verifies the row's persisted shape. Cryptographic proof
// verification remains the reducer's responsibility.
func (row CredentialAuthorityRow) Validate() error {
	authority := credentialauthority.Authority(row)
	if err := authority.Validate(); err != nil {
		return fmt.Errorf("store: credential authority: %w", err)
	}
	for index, proof := range row.ActivationProofs {
		canonical, err := codec.CanonicalizeSignedObject(proof.CanonicalJSON)
		if err != nil {
			return fmt.Errorf(
				"store: credential authority: activation proof %d: %w",
				index,
				err,
			)
		}
		if !bytes.Equal(canonical, proof.CanonicalJSON) {
			return fmt.Errorf(
				"store: credential authority: activation proof %d is not canonical",
				index,
			)
		}
	}
	return nil
}

// ClockEndorsement is one authority member's credential-time signature.
type ClockEndorsement struct {
	DeviceID  domain.DeviceID
	Signature [ed25519.SignatureSize]byte
}

// CredentialAuthorizationRow is one immutable content-credential epoch.
type CredentialAuthorizationRow struct {
	SessionID                domain.UUIDv7
	DeviceID                 domain.DeviceID
	Epoch                    uint64
	EpochPublicKey           [ed25519.PublicKeySize]byte
	KeyDigest                [sha256.Size]byte
	Role                     device.Role
	IssuedAt                 domain.WholeSecondTimestamp
	NotBefore                domain.WholeSecondTimestamp
	ValiditySeconds          uint64
	AuthorityVoterSetVersion uint64
	ClockEndorsements        []ClockEndorsement
	BindingSignature         [ed25519.SignatureSize]byte
	AuthorizationChainIndex  uint64
}

// Validate verifies the row's persisted shape. Signature verification and
// authority-majority checks remain reducer responsibilities.
func (row CredentialAuthorizationRow) Validate() error {
	if !row.SessionID.Valid() {
		return fmt.Errorf("store: credential authorization: invalid session ID %q", row.SessionID)
	}
	if !row.DeviceID.Valid() {
		return fmt.Errorf("store: credential authorization: invalid device ID %q", row.DeviceID)
	}
	if row.Epoch < 1 || !domain.ValidUnsignedInteger(row.Epoch) {
		return fmt.Errorf(
			"store: credential authorization: epoch must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	if sha256.Sum256(row.EpochPublicKey[:]) != row.KeyDigest {
		return fmt.Errorf("store: credential authorization: key digest mismatch")
	}
	if !row.Role.Valid() {
		return fmt.Errorf("store: credential authorization: invalid role %q", row.Role)
	}
	if !row.IssuedAt.Valid() || !row.NotBefore.Valid() {
		return fmt.Errorf("store: credential authorization: invalid endorsed timestamp")
	}
	issuedAt, _ := row.IssuedAt.Time()
	notBefore, _ := row.NotBefore.Time()
	if notBefore.Before(issuedAt) {
		return fmt.Errorf("store: credential authorization: not_before precedes issued_at")
	}
	if row.ValiditySeconds < 1 || !domain.ValidUnsignedInteger(row.ValiditySeconds) {
		return fmt.Errorf(
			"store: credential authorization: validity must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	if row.AuthorityVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(row.AuthorityVoterSetVersion) {
		return fmt.Errorf(
			"store: credential authorization: authority version must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	if len(row.ClockEndorsements) < 1 || len(row.ClockEndorsements) > voterset.MaxVoters {
		return fmt.Errorf(
			"store: credential authorization: got %d endorsements, want 1..%d",
			len(row.ClockEndorsements),
			voterset.MaxVoters,
		)
	}
	var previous domain.DeviceID
	for index, endorsement := range row.ClockEndorsements {
		if !endorsement.DeviceID.Valid() {
			return fmt.Errorf(
				"store: credential authorization: endorsement %d has invalid device ID",
				index,
			)
		}
		if index > 0 && previous >= endorsement.DeviceID {
			return fmt.Errorf(
				"store: credential authorization: endorsement device IDs are not sorted and unique",
			)
		}
		previous = endorsement.DeviceID
	}
	if row.AuthorizationChainIndex < 1 ||
		!domain.ValidUnsignedInteger(row.AuthorizationChainIndex) {
		return fmt.Errorf(
			"store: credential authorization: chain index must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// ControlFileOperation is the closed control-file proposal operation.
type ControlFileOperation string

const (
	ControlFileUpsert ControlFileOperation = "upsert"
	ControlFileDelete ControlFileOperation = "delete"
)

func (operation ControlFileOperation) valid() bool {
	return operation == ControlFileUpsert || operation == ControlFileDelete
}

// ControlFileProposalRow is one immutable, replicated control-file review
// proposal. ContentDigest is nil only for a deletion.
type ControlFileProposalRow struct {
	ProposalEventID    domain.UUIDv7
	SessionID          domain.UUIDv7
	Path               domain.RepositoryPath
	Operation          ControlFileOperation
	ContentDigest      *[sha256.Size]byte
	ContentSize        uint64
	Diff               string
	ProposedByDeviceID domain.DeviceID
	ChainIndex         uint64
}

// Validate verifies the row's persisted invariants. The committed policy
// supplies the operation-specific content-size ceiling.
func (row ControlFileProposalRow) Validate() error {
	if !row.ProposalEventID.Valid() {
		return fmt.Errorf(
			"store: control-file proposal: invalid event ID %q",
			row.ProposalEventID,
		)
	}
	if !row.SessionID.Valid() {
		return fmt.Errorf(
			"store: control-file proposal: invalid session ID %q",
			row.SessionID,
		)
	}
	if !row.Path.Valid() {
		return fmt.Errorf("store: control-file proposal: invalid path %q", row.Path)
	}
	if !row.Operation.valid() {
		return fmt.Errorf(
			"store: control-file proposal: invalid operation %q",
			row.Operation,
		)
	}
	if !domain.ValidUnsignedInteger(row.ContentSize) {
		return fmt.Errorf(
			"store: control-file proposal: content size exceeds %d",
			domain.MaxSafeInteger,
		)
	}
	switch row.Operation {
	case ControlFileUpsert:
		if row.ContentDigest == nil {
			return fmt.Errorf("store: control-file proposal: upsert requires a digest")
		}
	case ControlFileDelete:
		if row.ContentDigest != nil || row.ContentSize != 0 {
			return fmt.Errorf(
				"store: control-file proposal: delete requires a null digest and zero size",
			)
		}
	default:
		return fmt.Errorf(
			"store: control-file proposal: invalid operation %q",
			row.Operation,
		)
	}
	if !utf8.ValidString(row.Diff) || len(row.Diff) > maxControlFileDiffBytes {
		return fmt.Errorf(
			"store: control-file proposal: diff must be valid UTF-8 and at most %d bytes",
			maxControlFileDiffBytes,
		)
	}
	if !row.ProposedByDeviceID.Valid() {
		return fmt.Errorf(
			"store: control-file proposal: invalid proposer device ID %q",
			row.ProposedByDeviceID,
		)
	}
	if row.ChainIndex < 1 || !domain.ValidUnsignedInteger(row.ChainIndex) {
		return fmt.Errorf(
			"store: control-file proposal: chain index must be in 1..%d",
			domain.MaxSafeInteger,
		)
	}
	return nil
}

type preparedProjectionWrites struct {
	originScopes             [][]any
	auditCounters            [][]any
	tasks                    [][]any
	planRevisions            [][]any
	planCurrent              [][]any
	memoryRecords            [][]any
	leases                   [][]any
	devices                  [][]any
	voterSet                 [][]any
	credentialAuthority      [][]any
	agentSessions            [][]any
	canonicalRefs            [][]any
	credentialAuthorizations [][]any
	publications             [][]any
	controlFileProposals     [][]any
	controlFileProposalRows  []ControlFileProposalRow
	mergeConflicts           [][]any
	sessionPolicy            [][]any
}

func writePreparedProjections(
	conn *sqlite.Conn,
	rows preparedProjectionWrites,
) error {
	if conn == nil {
		return ErrInvalidOptions
	}
	if err := writeProjectionRows(conn, upsertOriginScopeSQL, rows.originScopes); err != nil {
		return fmt.Errorf("store: write origin_scopes: %w", err)
	}
	if err := writeProjectionRows(conn, upsertAuditCounterSQL, rows.auditCounters); err != nil {
		return fmt.Errorf("store: write audit_counters: %w", err)
	}
	if err := writeProjectionRows(conn, upsertTaskSQL, rows.tasks); err != nil {
		return fmt.Errorf("store: write tasks: %w", err)
	}
	if err := writeProjectionRows(conn, insertPlanRevisionSQL, rows.planRevisions); err != nil {
		return fmt.Errorf("store: write plan_revisions: %w", err)
	}
	if err := writeProjectionRows(conn, upsertPlanCurrentSQL, rows.planCurrent); err != nil {
		return fmt.Errorf("store: write plan_current: %w", err)
	}
	if err := writeProjectionRows(conn, insertMemoryRecordSQL, rows.memoryRecords); err != nil {
		return fmt.Errorf("store: write memory_records: %w", err)
	}
	if err := writeProjectionRows(conn, upsertLeaseSQL, rows.leases); err != nil {
		return fmt.Errorf("store: write leases: %w", err)
	}
	if err := writeProjectionRows(conn, upsertDeviceSQL, rows.devices); err != nil {
		return fmt.Errorf("store: write devices: %w", err)
	}
	if err := writeProjectionRows(conn, upsertVoterSetSQL, rows.voterSet); err != nil {
		return fmt.Errorf("store: write voter_set: %w", err)
	}
	if err := writeProjectionRows(
		conn,
		upsertCredentialAuthoritySQL,
		rows.credentialAuthority,
	); err != nil {
		return fmt.Errorf("store: write credential_authority: %w", err)
	}
	if err := writeProjectionRows(conn, upsertAgentSessionSQL, rows.agentSessions); err != nil {
		return fmt.Errorf("store: write agent_sessions: %w", err)
	}
	if err := writeProjectionRows(conn, upsertCanonicalRefSQL, rows.canonicalRefs); err != nil {
		return fmt.Errorf("store: write canonical_refs: %w", err)
	}
	if err := writeProjectionRows(
		conn,
		insertCredentialAuthorizationSQL,
		rows.credentialAuthorizations,
	); err != nil {
		return fmt.Errorf("store: write credential_authorizations: %w", err)
	}
	if err := writeProjectionRows(conn, upsertPublicationSQL, rows.publications); err != nil {
		return fmt.Errorf("store: write publications: %w", err)
	}
	if err := writeProjectionRows(
		conn,
		insertControlFileProposalSQL,
		rows.controlFileProposals,
	); err != nil {
		return fmt.Errorf("store: write control_file_proposals: %w", err)
	}
	if err := writeProjectionRows(conn, upsertMergeConflictSQL, rows.mergeConflicts); err != nil {
		return fmt.Errorf("store: write merge_conflicts: %w", err)
	}
	if err := writeProjectionRows(conn, upsertSessionPolicySQL, rows.sessionPolicy); err != nil {
		return fmt.Errorf("store: write session_policy: %w", err)
	}
	return nil
}

func prepareProjectionWrites(writes ProjectionWrites) (preparedProjectionWrites, error) {
	var prepared preparedProjectionWrites

	for index, row := range writes.OriginScopes {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("origin_scopes", index, err)
		}
		prepared.originScopes = append(prepared.originScopes, []any{
			string(row.DeviceID),
			string(row.ScopeKind),
			string(row.ScopeID),
			row.LastSequence,
		})
	}
	for index, row := range writes.AuditCounters {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("audit_counters", index, err)
		}
		prepared.auditCounters = append(prepared.auditCounters, []any{
			string(row.DeviceID),
			row.CredentialEpoch,
			row.AcceptedCount,
		})
	}
	for index, row := range writes.Tasks {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("tasks", index, err)
		}
		blockedBy, err := canonicalStringArray(row.BlockedBy)
		if err != nil {
			return prepared, projectionRowError("tasks", index, err)
		}
		labels, err := canonicalStringArray(row.Labels)
		if err != nil {
			return prepared, projectionRowError("tasks", index, err)
		}
		prepared.tasks = append(prepared.tasks, []any{
			string(row.ID),
			row.Title,
			row.Body,
			string(row.State),
			nullableStringPointer(row.StateReason),
			int64(row.Priority),
			blockedBy,
			labels,
			nullableText(row.OwnerDeviceID),
			nullableText(row.OwnerAgentSessionID),
			nullableText(row.IntendedDeviceID),
			nullableText(row.LastReleaseReason),
			row.EntityVersion,
			string(row.CreatedAt),
			string(row.UpdatedAt),
		})
	}
	for index, row := range writes.PlanRevisions {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("plan_revisions", index, err)
		}
		taskIDs, err := canonicalStringArray(row.TaskIDs())
		if err != nil {
			return prepared, projectionRowError("plan_revisions", index, err)
		}
		supersedes, _ := row.Supersedes()
		prepared.planRevisions = append(prepared.planRevisions, []any{
			string(row.ID()),
			nullableText(supersedes),
			row.Title(),
			row.Body(),
			taskIDs,
			string(row.ProposedByDeviceID()),
			string(row.CreatedAt()),
		})
	}
	for index, row := range writes.PlanCurrent {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("plan_current", index, err)
		}
		prepared.planCurrent = append(prepared.planCurrent, []any{
			string(row.SessionID),
			nullableText(row.RevisionID),
			row.EntityVersion,
		})
	}
	for index, row := range writes.MemoryRecords {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("memory_records", index, err)
		}
		taskID, _ := row.TaskID()
		supersedes, _ := row.Supersedes()
		prepared.memoryRecords = append(prepared.memoryRecords, []any{
			string(row.ID()),
			string(row.Scope()),
			nullableText(taskID),
			row.Key(),
			row.Body(),
			nullableText(supersedes),
			string(row.CreatedAt()),
		})
	}
	for index, row := range writes.Leases {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("leases", index, err)
		}
		pathPatterns := row.PathPatterns()
		pathTexts := make([]string, len(pathPatterns))
		for patternIndex, pattern := range pathPatterns {
			pathTexts[patternIndex] = pattern.String()
		}
		var pathGlobs any
		if row.Scope == lease.ScopePath {
			encodedPathGlobs, err := canonicalStringArray(pathTexts)
			if err != nil {
				return prepared, projectionRowError("leases", index, err)
			}
			pathGlobs = encodedPathGlobs
		}
		prepared.leases = append(prepared.leases, []any{
			string(row.ID),
			string(row.HolderDeviceID),
			string(row.HolderAgentSessionID),
			string(row.Scope),
			nullableText(row.TaskID),
			pathGlobs,
			row.TTLSeconds,
			string(row.Status),
			nullableText(row.ReleaseReason),
			row.EntityVersion,
		})
	}
	for index, row := range writes.Devices {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("devices", index, err)
		}
		prepared.devices = append(prepared.devices, []any{
			string(row.ID),
			string(row.Role),
			cloneBytes(row.IdentityPublicKey),
			row.DaemonVersion,
			row.MaxApplyLevel,
			string(row.Status),
			row.EntityVersion,
		})
	}
	for index, row := range writes.VoterSet {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("voter_set", index, err)
		}
		voterIDs, err := canonicalStringArray(row.VoterDeviceIDs())
		if err != nil {
			return prepared, projectionRowError("voter_set", index, err)
		}
		prepared.voterSet = append(prepared.voterSet, []any{
			string(row.SessionID),
			voterIDs,
			row.VoterSetVersion,
		})
	}
	for index, row := range writes.CredentialAuthority {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("credential_authority", index, err)
		}
		voterIDs, err := canonicalStringArray(row.VoterDeviceIDs)
		if err != nil {
			return prepared, projectionRowError("credential_authority", index, err)
		}
		proofObjects := make([]json.RawMessage, len(row.ActivationProofs))
		for proofIndex := range row.ActivationProofs {
			proofObjects[proofIndex] = row.ActivationProofs[proofIndex].CanonicalJSON
		}
		proofs, err := canonicalObjectArray(proofObjects)
		if err != nil {
			return prepared, projectionRowError("credential_authority", index, err)
		}
		prepared.credentialAuthority = append(prepared.credentialAuthority, []any{
			string(row.SessionID),
			voterIDs,
			row.VoterSetVersion,
			string(row.ActivationSource),
			nullableText(row.ActivationCheckpointEventID),
			proofs,
			nullableText(row.PriorAuthoritySigner),
			nullableSignature(row.PriorAuthorityHandoff),
		})
	}
	for index, row := range writes.AgentSessions {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("agent_sessions", index, err)
		}
		prepared.agentSessions = append(prepared.agentSessions, []any{
			string(row.ID),
			string(row.DeviceID),
			string(row.ClientKind),
			nullableStringPointer(row.AgentProfileID),
			string(row.State),
			nullableText(row.ResumeState),
			string(row.WorkingRootID),
			nullableText(row.EndReason),
			row.EntityVersion,
		})
	}
	for index, row := range writes.CanonicalRefs {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("canonical_refs", index, err)
		}
		prepared.canonicalRefs = append(prepared.canonicalRefs, []any{
			row.RefName,
			string(row.CommitOID),
			row.EntityVersion,
		})
	}
	for index, row := range writes.CredentialAuthorizations {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("credential_authorizations", index, err)
		}
		endorsements, err := canonicalClockEndorsements(row.ClockEndorsements)
		if err != nil {
			return prepared, projectionRowError("credential_authorizations", index, err)
		}
		prepared.credentialAuthorizations = append(
			prepared.credentialAuthorizations,
			[]any{
				string(row.SessionID),
				string(row.DeviceID),
				row.Epoch,
				bytesFrom32(row.EpochPublicKey),
				bytesFrom32(row.KeyDigest),
				string(row.Role),
				string(row.IssuedAt),
				string(row.NotBefore),
				row.ValiditySeconds,
				row.AuthorityVoterSetVersion,
				endorsements,
				bytesFrom64(row.BindingSignature),
				row.AuthorizationChainIndex,
			},
		)
	}
	for index, row := range writes.Publications {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("publications", index, err)
		}
		if len(row.StagingReceipts) < 1 {
			return prepared, projectionRowError(
				"publications",
				index,
				fmt.Errorf("committed publication requires at least one staging receipt"),
			)
		}
		parentOIDs, err := canonicalStringArray(row.Metadata.ParentOIDs)
		if err != nil {
			return prepared, projectionRowError("publications", index, err)
		}
		paths, err := canonicalStringArray(row.Metadata.Paths)
		if err != nil {
			return prepared, projectionRowError("publications", index, err)
		}
		conflictIDs, err := canonicalStringArray(row.Metadata.ResolvesConflictIDs)
		if err != nil {
			return prepared, projectionRowError("publications", index, err)
		}
		receipts, err := canonicalStagingReceipts(row.StagingReceipts)
		if err != nil {
			return prepared, projectionRowError("publications", index, err)
		}
		prepared.publications = append(prepared.publications, []any{
			string(row.Metadata.PublicationID),
			string(row.Metadata.ProposalEventID),
			nullableText(row.Metadata.SupersedesPublicationID),
			nullableText(row.Metadata.TaskID),
			string(row.Metadata.AuthorDeviceID),
			string(row.Metadata.AuthorAgentSessionID),
			string(row.Metadata.BaseCommit),
			string(row.Metadata.CommitOID),
			string(row.Metadata.TreeOID),
			parentOIDs,
			paths,
			bytesFrom32(row.Metadata.ArtifactDigest),
			conflictIDs,
			string(row.Metadata.WorkingRootID),
			receipts,
			string(row.State),
			nullableText(row.TerminalSource),
			row.CanonicalLineageMember,
			nullableText(row.ReviewVerdict),
			nullableText(row.ReviewerDeviceID),
			nullableText(row.ReviewerAgentSessionID),
			nullableText(row.ReviewActorType),
			nullableStringPointer(row.DecisionReason),
			row.EntityVersion,
		})
	}
	for index, row := range writes.ControlFileProposals {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("control_file_proposals", index, err)
		}
		cloned := row
		if row.ContentDigest != nil {
			digest := *row.ContentDigest
			cloned.ContentDigest = &digest
		}
		prepared.controlFileProposalRows = append(
			prepared.controlFileProposalRows,
			cloned,
		)
		prepared.controlFileProposals = append(prepared.controlFileProposals, []any{
			string(row.ProposalEventID),
			string(row.SessionID),
			string(row.Path),
			string(row.Operation),
			nullableDigest(row.ContentDigest),
			row.ContentSize,
			row.Diff,
			string(row.ProposedByDeviceID),
			row.ChainIndex,
		})
	}
	for index, row := range writes.MergeConflicts {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("merge_conflicts", index, err)
		}
		mergeBaseOIDs, err := canonicalStringArray(row.MergeBaseOIDs)
		if err != nil {
			return prepared, projectionRowError("merge_conflicts", index, err)
		}
		paths, err := canonicalStringArray(row.Paths)
		if err != nil {
			return prepared, projectionRowError("merge_conflicts", index, err)
		}
		prepared.mergeConflicts = append(prepared.mergeConflicts, []any{
			string(row.ID),
			string(row.PublicationID),
			string(row.MergeKind),
			nullableText(row.ReplayCommitOID),
			mergeBaseOIDs,
			string(row.CanonicalCommit),
			string(row.CandidateCommit),
			paths,
			string(row.Status),
			nullableText(row.ResolutionKind),
			nullableText(row.ResolutionPublicationID),
			nullableText(row.ForceReason),
			nullableText(row.ResolvedByDeviceID),
			row.EntityVersion,
		})
	}
	for index, row := range writes.SessionPolicy {
		if err := row.Validate(); err != nil {
			return prepared, projectionRowError("session_policy", index, err)
		}
		values, err := canonicalPolicyValues(row.Values)
		if err != nil {
			return prepared, projectionRowError("session_policy", index, err)
		}
		prepared.sessionPolicy = append(prepared.sessionPolicy, []any{
			string(row.SessionID),
			values,
			row.EntityVersion,
		})
	}

	return prepared, nil
}

func projectionRowError(table string, index int, err error) error {
	return fmt.Errorf("store: prepare %s row %d: %w", table, index, err)
}

func writeProjectionRows(conn *sqlite.Conn, statement string, rows [][]any) error {
	for index, row := range rows {
		if err := execute(conn, statement, row...); err != nil {
			return fmt.Errorf("row %d: %w", index, err)
		}
	}
	return nil
}

func canonicalStringArray[T ~string](values []T) (string, error) {
	strings := make([]string, len(values))
	for index, value := range values {
		strings[index] = string(value)
	}
	return canonicalJSONText(strings)
}

func canonicalObjectArray(values []json.RawMessage) (string, error) {
	objects := make([]json.RawMessage, len(values))
	for index, value := range values {
		canonical, err := codec.CanonicalizeSignedObject(value)
		if err != nil {
			return "", fmt.Errorf("canonicalize object %d: %w", index, err)
		}
		objects[index] = canonical
	}
	return canonicalJSONText(objects)
}

type clockEndorsementJSON struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

func canonicalClockEndorsements(values []ClockEndorsement) (string, error) {
	objects := make([]clockEndorsementJSON, len(values))
	for index, value := range values {
		objects[index] = clockEndorsementJSON{
			DeviceID:  string(value.DeviceID),
			Signature: codec.EncodeBase64URL(value.Signature[:]),
		}
	}
	return canonicalJSONText(objects)
}

type stagingReceiptJSON struct {
	SessionID                 string `json:"session_id"`
	WorkspaceID               string `json:"workspace_id"`
	VoterSetVersion           uint64 `json:"voter_set_version"`
	PublicationMetadataDigest string `json:"publication_metadata_digest"`
	VoterDeviceID             string `json:"voter_device_id"`
	StagedResultIndex         uint64 `json:"staged_result_index"`
	Signature                 string `json:"signature"`
}

func canonicalStagingReceipts(values []publication.StagingReceipt) (string, error) {
	objects := make([]stagingReceiptJSON, len(values))
	for index, value := range values {
		objects[index] = stagingReceiptJSON{
			SessionID:                 string(value.SessionID),
			WorkspaceID:               string(value.WorkspaceID),
			VoterSetVersion:           value.VoterSetVersion,
			PublicationMetadataDigest: codec.EncodeBase64URL(value.PublicationMetadataDigest[:]),
			VoterDeviceID:             string(value.VoterDeviceID),
			StagedResultIndex:         value.StagedResultIndex,
			Signature:                 codec.EncodeBase64URL(value.Signature[:]),
		}
	}
	return canonicalJSONText(objects)
}

type policyValuesJSON struct {
	CheckpointEvents             int64 `json:"checkpoint_events"`
	CheckpointIntervalSeconds    int64 `json:"checkpoint_interval_seconds"`
	LeaseMinTTLSeconds           int64 `json:"lease_min_ttl_seconds"`
	LeaseDefaultTTLSeconds       int64 `json:"lease_default_ttl_seconds"`
	LeaseMaxTTLSeconds           int64 `json:"lease_max_ttl_seconds"`
	AgentClaimLimit              int64 `json:"agent_claim_limit"`
	AgentLeaseLimit              int64 `json:"agent_lease_limit"`
	DeviceClaimLimit             int64 `json:"device_claim_limit"`
	DeviceLeaseLimit             int64 `json:"device_lease_limit"`
	AdvertisementIntervalSeconds int64 `json:"advertisement_interval_seconds"`
	AuditDepthPerDevicePerEpoch  int64 `json:"audit_depth_per_device_per_epoch"`
	MaxMemberDevices             int64 `json:"max_member_devices"`
	MaxActiveAgentSessions       int64 `json:"max_active_agent_sessions"`
	ClusterMinApplyLevel         int64 `json:"cluster_min_apply_level"`
}

func canonicalPolicyValues(values policy.Values) (string, error) {
	return canonicalJSONText(policyValuesJSON{
		CheckpointEvents:             values.CheckpointEvents,
		CheckpointIntervalSeconds:    values.CheckpointIntervalSeconds,
		LeaseMinTTLSeconds:           values.LeaseMinTTLSeconds,
		LeaseDefaultTTLSeconds:       values.LeaseDefaultTTLSeconds,
		LeaseMaxTTLSeconds:           values.LeaseMaxTTLSeconds,
		AgentClaimLimit:              values.AgentClaimLimit,
		AgentLeaseLimit:              values.AgentLeaseLimit,
		DeviceClaimLimit:             values.DeviceClaimLimit,
		DeviceLeaseLimit:             values.DeviceLeaseLimit,
		AdvertisementIntervalSeconds: values.AdvertisementIntervalSeconds,
		AuditDepthPerDevicePerEpoch:  values.AuditDepthPerDevicePerEpoch,
		MaxMemberDevices:             values.MaxMemberDevices,
		MaxActiveAgentSessions:       values.MaxActiveAgentSessions,
		ClusterMinApplyLevel:         values.ClusterMinApplyLevel,
	})
}

func canonicalJSONText(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical JSON input: %w", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		return "", fmt.Errorf("canonicalize JSON: %w", err)
	}
	return string(canonical), nil
}

func nullableText[T ~string](value T) any {
	if value == "" {
		return nil
	}
	return string(value)
}

func nullableStringPointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableDigest(value *[sha256.Size]byte) any {
	if value == nil {
		return nil
	}
	return bytesFrom32(*value)
}

func nullableSignature(value *[ed25519.SignatureSize]byte) any {
	if value == nil {
		return nil
	}
	return bytesFrom64(*value)
}

func bytesFrom32(value [sha256.Size]byte) []byte {
	result := make([]byte, sha256.Size)
	copy(result, value[:])
	return result
}

func bytesFrom64(value [ed25519.SignatureSize]byte) []byte {
	result := make([]byte, ed25519.SignatureSize)
	copy(result, value[:])
	return result
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

const upsertOriginScopeSQL = `
INSERT INTO origin_scopes (
	device_id, scope_kind, scope_id, last_sequence
) VALUES (?1, ?2, ?3, ?4)
ON CONFLICT (device_id, scope_kind, scope_id) DO UPDATE SET
	last_sequence = excluded.last_sequence;`

const upsertAuditCounterSQL = `
INSERT INTO audit_counters (
	device_id, credential_epoch, accepted_count
) VALUES (?1, ?2, ?3)
ON CONFLICT (device_id) DO UPDATE SET
	credential_epoch = excluded.credential_epoch,
	accepted_count = excluded.accepted_count;`

const upsertTaskSQL = `
INSERT INTO tasks (
	task_id, title, body, state, state_reason, priority, blocked_by_json,
	labels_json, owner_device_id, owner_agent_session_id, intended_device_id,
	last_release_reason, entity_version, created_at, updated_at
) VALUES (
	?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
)
ON CONFLICT (task_id) DO UPDATE SET
	title = excluded.title,
	body = excluded.body,
	state = excluded.state,
	state_reason = excluded.state_reason,
	priority = excluded.priority,
	blocked_by_json = excluded.blocked_by_json,
	labels_json = excluded.labels_json,
	owner_device_id = excluded.owner_device_id,
	owner_agent_session_id = excluded.owner_agent_session_id,
	intended_device_id = excluded.intended_device_id,
	last_release_reason = excluded.last_release_reason,
	entity_version = excluded.entity_version,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at;`

const insertPlanRevisionSQL = `
INSERT INTO plan_revisions (
	plan_revision_id, supersedes, title, body, task_ids_json,
	proposed_by_device_id, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);`

const upsertPlanCurrentSQL = `
INSERT INTO plan_current (
	session_id, plan_revision_id, entity_version
) VALUES (?1, ?2, ?3)
ON CONFLICT (session_id) DO UPDATE SET
	plan_revision_id = excluded.plan_revision_id,
	entity_version = excluded.entity_version;`

const insertMemoryRecordSQL = `
INSERT INTO memory_records (
	memory_id, scope, task_id, key, body, supersedes, created_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);`

const upsertLeaseSQL = `
INSERT INTO leases (
	lease_id, holder_device_id, holder_agent_session_id, scope, task_id,
	path_globs_json, ttl_seconds, status, release_reason, entity_version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT (lease_id) DO UPDATE SET
	holder_device_id = excluded.holder_device_id,
	holder_agent_session_id = excluded.holder_agent_session_id,
	scope = excluded.scope,
	task_id = excluded.task_id,
	path_globs_json = excluded.path_globs_json,
	ttl_seconds = excluded.ttl_seconds,
	status = excluded.status,
	release_reason = excluded.release_reason,
	entity_version = excluded.entity_version;`

const upsertDeviceSQL = `
INSERT INTO devices (
	device_id, role, identity_public_key, daemon_version, max_apply_level,
	status, entity_version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
ON CONFLICT (device_id) DO UPDATE SET
	role = excluded.role,
	identity_public_key = excluded.identity_public_key,
	daemon_version = excluded.daemon_version,
	max_apply_level = excluded.max_apply_level,
	status = excluded.status,
	entity_version = excluded.entity_version;`

const upsertVoterSetSQL = `
INSERT INTO voter_set (
	session_id, voter_device_ids_json, voter_set_version
) VALUES (?1, ?2, ?3)
ON CONFLICT (session_id) DO UPDATE SET
	voter_device_ids_json = excluded.voter_device_ids_json,
	voter_set_version = excluded.voter_set_version;`

const upsertCredentialAuthoritySQL = `
INSERT INTO credential_authority (
	session_id, voter_device_ids_json, voter_set_version, activation_source,
	activation_checkpoint_event_id, activation_proofs_json,
	prior_authority_signer, prior_authority_handoff
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
ON CONFLICT (session_id) DO UPDATE SET
	voter_device_ids_json = excluded.voter_device_ids_json,
	voter_set_version = excluded.voter_set_version,
	activation_source = excluded.activation_source,
	activation_checkpoint_event_id = excluded.activation_checkpoint_event_id,
	activation_proofs_json = excluded.activation_proofs_json,
	prior_authority_signer = excluded.prior_authority_signer,
	prior_authority_handoff = excluded.prior_authority_handoff;`

const upsertAgentSessionSQL = `
INSERT INTO agent_sessions (
	agent_session_id, device_id, client_kind, agent_profile_id, state,
	resume_state, working_root_id, end_reason, entity_version
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT (agent_session_id) DO UPDATE SET
	device_id = excluded.device_id,
	client_kind = excluded.client_kind,
	agent_profile_id = excluded.agent_profile_id,
	state = excluded.state,
	resume_state = excluded.resume_state,
	working_root_id = excluded.working_root_id,
	end_reason = excluded.end_reason,
	entity_version = excluded.entity_version;`

const upsertCanonicalRefSQL = `
INSERT INTO canonical_refs (
	ref_name, commit_oid, entity_version
) VALUES (?1, ?2, ?3)
ON CONFLICT (ref_name) DO UPDATE SET
	commit_oid = excluded.commit_oid,
	entity_version = excluded.entity_version;`

const insertCredentialAuthorizationSQL = `
INSERT INTO credential_authorizations (
	session_id, device_id, epoch, epoch_public_key, key_digest, role,
	issued_at, not_before, validity_seconds, authority_voter_set_version,
	clock_endorsements_json, binding_signature, authorization_chain_index
) VALUES (
	?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
);`

const upsertPublicationSQL = `
INSERT INTO publications (
	publication_id, proposal_event_id, supersedes_publication_id, task_id,
	author_device_id, author_agent_session_id, base_commit, commit_oid,
	tree_oid, parent_oids_json, paths_json, artifact_digest,
	resolves_conflict_ids_json, working_root_id, staging_receipts_json, state,
	terminal_source, canonical_lineage_member, review_verdict,
	reviewer_device_id, reviewer_agent_session_id, review_actor_type,
	decision_reason, entity_version
) VALUES (
	?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
	?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
)
ON CONFLICT (publication_id) DO UPDATE SET
	proposal_event_id = excluded.proposal_event_id,
	supersedes_publication_id = excluded.supersedes_publication_id,
	task_id = excluded.task_id,
	author_device_id = excluded.author_device_id,
	author_agent_session_id = excluded.author_agent_session_id,
	base_commit = excluded.base_commit,
	commit_oid = excluded.commit_oid,
	tree_oid = excluded.tree_oid,
	parent_oids_json = excluded.parent_oids_json,
	paths_json = excluded.paths_json,
	artifact_digest = excluded.artifact_digest,
	resolves_conflict_ids_json = excluded.resolves_conflict_ids_json,
	working_root_id = excluded.working_root_id,
	staging_receipts_json = excluded.staging_receipts_json,
	state = excluded.state,
	terminal_source = excluded.terminal_source,
	canonical_lineage_member = excluded.canonical_lineage_member,
	review_verdict = excluded.review_verdict,
	reviewer_device_id = excluded.reviewer_device_id,
	reviewer_agent_session_id = excluded.reviewer_agent_session_id,
	review_actor_type = excluded.review_actor_type,
	decision_reason = excluded.decision_reason,
	entity_version = excluded.entity_version;`

const insertControlFileProposalSQL = `
INSERT INTO control_file_proposals (
	proposal_event_id, session_id, path, operation, content_digest,
	content_size, diff, proposed_by_device_id, chain_index
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);`

const upsertMergeConflictSQL = `
INSERT INTO merge_conflicts (
	conflict_id, publication_id, merge_kind, replay_commit_oid,
	merge_base_oids_json, canonical_commit, candidate_commit, paths_json,
	status, resolution_kind, resolution_publication_id, force_reason,
	resolved_by_device_id, entity_version
) VALUES (
	?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
)
ON CONFLICT (conflict_id) DO UPDATE SET
	publication_id = excluded.publication_id,
	merge_kind = excluded.merge_kind,
	replay_commit_oid = excluded.replay_commit_oid,
	merge_base_oids_json = excluded.merge_base_oids_json,
	canonical_commit = excluded.canonical_commit,
	candidate_commit = excluded.candidate_commit,
	paths_json = excluded.paths_json,
	status = excluded.status,
	resolution_kind = excluded.resolution_kind,
	resolution_publication_id = excluded.resolution_publication_id,
	force_reason = excluded.force_reason,
	resolved_by_device_id = excluded.resolved_by_device_id,
	entity_version = excluded.entity_version;`

const upsertSessionPolicySQL = `
INSERT INTO session_policy (
	session_id, values_json, entity_version
) VALUES (?1, ?2, ?3)
ON CONFLICT (session_id) DO UPDATE SET
	values_json = excluded.values_json,
	entity_version = excluded.entity_version;`
