// Package reducer applies signed proposals to an immutable view of committed
// state. Reducers perform no I/O and never read local time or configuration.
package reducer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
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
	"github.com/ijonahch/codecomm/internal/event"
)

// Status is the durable command-result class.
type Status string

const (
	StatusAccepted Status = "accepted"
	StatusRejected Status = "rejected"
)

// Code is a stable, non-localized reducer outcome code.
type Code string

const (
	CodeAccepted                             Code = "accepted"
	CodeInvalidEnvelope                      Code = "invalid_envelope"
	CodeInvalidOriginSignature               Code = "invalid_origin_signature"
	CodeSessionBindingMismatch               Code = "session_binding_mismatch"
	CodeOriginDeviceNotActive                Code = "origin_device_not_active"
	CodeOriginScopeNotFound                  Code = "origin_scope_not_found"
	CodeOriginSequenceGap                    Code = "origin_sequence_gap"
	CodeOriginSequenceReused                 Code = "origin_sequence_reused"
	CodeAgentSessionNotFound                 Code = "agent_session_not_found"
	CodeAgentSessionBindingMismatch          Code = "agent_session_binding_mismatch"
	CodeAgentSessionNotConnected             Code = "agent_session_not_connected"
	CodeAgentSessionLimitReached             Code = "agent_session_limit_reached"
	CodeInvalidAgentSessionTransition        Code = "invalid_agent_session_transition"
	CodeInvalidEndReason                     Code = "invalid_end_reason"
	CodeEndActorMismatch                     Code = "end_actor_mismatch"
	CodeActorNotAllowed                      Code = "actor_not_allowed"
	CodeInvalidKindContract                  Code = "invalid_kind_contract"
	CodeExpectedEntityVersion                Code = "invalid_expected_entity_version"
	CodeInsufficientRole                     Code = "insufficient_role"
	CodeInvalidPayload                       Code = "invalid_payload"
	CodeUnknownPayloadField                  Code = "unknown_payload_field"
	CodeMissingPayloadField                  Code = "missing_payload_field"
	CodeEntityAlreadyExists                  Code = "entity_already_exists"
	CodeEntityNotFound                       Code = "entity_not_found"
	CodeEntityVersionMismatch                Code = "entity_version_mismatch"
	CodeEntityVersionExhausted               Code = "entity_version_exhausted"
	CodeInvalidTaskTransition                Code = "invalid_task_transition"
	CodeTaskHolderRequired                   Code = "task_holder_required"
	CodeTaskMustBeUnowned                    Code = "task_must_be_unowned"
	CodeTaskNotActionable                    Code = "task_not_actionable"
	CodeTaskHasUnresolvedConflict            Code = "task_has_unresolved_conflict"
	CodeIntendedDeviceMismatch               Code = "intended_device_mismatch"
	CodeAgentClaimLimitReached               Code = "agent_claim_limit_reached"
	CodeDeviceClaimLimitReached              Code = "device_claim_limit_reached"
	CodeDependencyNotFound                   Code = "dependency_not_found"
	CodeDependencyCycle                      Code = "dependency_cycle"
	CodeDependencyGraphTooComplex            Code = "dependency_graph_too_complex"
	CodeInvalidReleaseReason                 Code = "invalid_release_reason"
	CodeReleaseActorMismatch                 Code = "release_actor_mismatch"
	CodeReleaseNotAuthorized                 Code = "release_not_authorized"
	CodeReassignmentTargetNotActive          Code = "reassignment_target_not_active"
	CodeInvalidLeaseTransition               Code = "invalid_lease_transition"
	CodeLeaseHolderRequired                  Code = "lease_holder_required"
	CodeLeaseScopeConflict                   Code = "lease_scope_conflict"
	CodeLeaseTaskNotFound                    Code = "lease_task_not_found"
	CodeAgentLeaseLimitReached               Code = "agent_lease_limit_reached"
	CodeDeviceLeaseLimitReached              Code = "device_lease_limit_reached"
	CodePlanRevisionNotFound                 Code = "plan_revision_not_found"
	CodePlanTaskNotFound                     Code = "plan_task_not_found"
	CodeMemoryTaskNotFound                   Code = "memory_task_not_found"
	CodeMemoryPredecessorNotFound            Code = "memory_predecessor_not_found"
	CodeMemoryPredecessorMismatch            Code = "memory_predecessor_mismatch"
	CodeMemoryPredecessorAlreadySuperseded   Code = "memory_predecessor_already_superseded"
	CodePolicyLimitBelowCurrentUse           Code = "policy_limit_below_current_use"
	CodeClusterApplyLevelDecrease            Code = "cluster_apply_level_decrease"
	CodeClusterApplyLevelUnsupported         Code = "cluster_apply_level_unsupported"
	CodeMembershipSubjectMismatch            Code = "membership_subject_mismatch"
	CodeMembershipSubjectNotFound            Code = "membership_subject_not_found"
	CodeMembershipSubjectNotActive           Code = "membership_subject_not_active"
	CodeMembershipReportUnchanged            Code = "membership_report_unchanged"
	CodeInvalidMembershipTransition          Code = "invalid_membership_transition"
	CodeLastActiveOwner                      Code = "last_active_owner"
	CodeMemberLimitReached                   Code = "member_limit_reached"
	CodeVoterSetVersionMismatch              Code = "voter_set_version_mismatch"
	CodeVoterSetVersionExhausted             Code = "voter_set_version_exhausted"
	CodeInvalidVoterSet                      Code = "invalid_voter_set"
	CodeVoterTargetUnchanged                 Code = "voter_target_unchanged"
	CodeVoterTargetAlreadyActivated          Code = "voter_target_already_activated"
	CodeVoterTargetNotActive                 Code = "voter_target_not_active"
	CodeSoleVoterRevocation                  Code = "sole_voter_revocation"
	CodeCredentialAuthorityQuorumLost        Code = "credential_authority_quorum_lost"
	CodeInvalidRecoveryAuthorization         Code = "invalid_recovery_authorization"
	CodeCredentialAuthorityVersionMismatch   Code = "credential_authority_version_mismatch"
	CodeInvalidVoterActivationProof          Code = "invalid_voter_activation_proof"
	CodeInvalidCredentialAuthorityHandoff    Code = "invalid_credential_authority_handoff"
	CodeInvalidPublicationTransition         Code = "invalid_publication_transition"
	CodePublicationAuthorMismatch            Code = "publication_author_mismatch"
	CodePublicationAuthorBindingMismatch     Code = "publication_author_binding_mismatch"
	CodePublicationTaskNotFound              Code = "publication_task_not_found"
	CodePublicationTaskHolderRequired        Code = "publication_task_holder_required"
	CodePublicationWorkingRootMismatch       Code = "publication_working_root_mismatch"
	CodePublicationPathLeaseRequired         Code = "publication_path_lease_required"
	CodePublicationControlPath               Code = "publication_control_path"
	CodePublicationSupersedesNotFound        Code = "publication_supersedes_not_found"
	CodePublicationSupersedesNotTerminal     Code = "publication_supersedes_not_terminal"
	CodePublicationSupersedesLineageMismatch Code = "publication_supersedes_lineage_mismatch"
	CodePublicationConflictNotFound          Code = "publication_conflict_not_found"
	CodePublicationConflictNotUnresolved     Code = "publication_conflict_not_unresolved"
	CodeInvalidPublicationReceipts           Code = "invalid_publication_receipts"
	CodePublicationReceiptFromFuture         Code = "publication_receipt_from_future"
	CodePublicationReceiptStale              Code = "publication_receipt_stale"
	CodePublicationReceiptQuorumNotMet       Code = "publication_receipt_quorum_not_met"
	CodePublicationReviewNotIndependent      Code = "publication_review_not_independent"
	CodePublicationWithdrawalNotAuthorized   Code = "publication_withdrawal_not_authorized"
	CodeCanonicalRefVersionMismatch          Code = "canonical_ref_version_mismatch"
	CodeCanonicalRefVersionExhausted         Code = "canonical_ref_version_exhausted"
	CodePublicationBaseCommitMismatch        Code = "publication_base_commit_mismatch"
	CodeConflictIDMismatch                   Code = "conflict_id_mismatch"
	CodeConflictPublicationNotFound          Code = "conflict_publication_not_found"
	CodeConflictPublicationTerminal          Code = "conflict_publication_terminal"
	CodeConflictCanonicalCommitMismatch      Code = "conflict_canonical_commit_mismatch"
	CodeConflictImmutableTupleMismatch       Code = "conflict_immutable_tuple_mismatch"
	CodeConflictDetectorPathsMismatch        Code = "conflict_detector_paths_mismatch"
	CodeInvalidConflictTransition            Code = "invalid_conflict_transition"
	CodeConflictResolutionNotFound           Code = "conflict_resolution_not_found"
	CodeConflictResolutionNotApplied         Code = "conflict_resolution_not_applied"
	CodeConflictResolutionNotDeclared        Code = "conflict_resolution_not_declared"
	CodeConflictResolutionAuthorMismatch     Code = "conflict_resolution_author_mismatch"
	CodeCredentialSubjectMismatch            Code = "credential_subject_mismatch"
	CodeCredentialSubjectNotFound            Code = "credential_subject_not_found"
	CodeCredentialSubjectNotActive           Code = "credential_subject_not_active"
	CodeCredentialEpochMismatch              Code = "credential_epoch_mismatch"
	CodeCredentialEpochExhausted             Code = "credential_epoch_exhausted"
	CodeCredentialKeyDigestMismatch          Code = "credential_key_digest_mismatch"
	CodeCredentialKeyReused                  Code = "credential_key_reused"
	CodeInvalidCredentialBinding             Code = "invalid_credential_binding"
	CodeCredentialRoleMismatch               Code = "credential_role_mismatch"
	CodeInvalidCredentialEndorsements        Code = "invalid_credential_endorsements"
	CodeCredentialEndorsementQuorumNotMet    Code = "credential_endorsement_quorum_not_met"
	CodeCredentialValidityMismatch           Code = "credential_validity_mismatch"
	CodeCredentialRenewalTooEarly            Code = "credential_renewal_too_early"
	CodeCredentialNotBeforeMismatch          Code = "credential_not_before_mismatch"
)

// ScopeKind identifies the signed origin sequence namespace.
type ScopeKind string

const (
	ScopeAgent ScopeKind = "agent"
	ScopeBoot  ScopeKind = "boot"
)

// OriginScopeKey is the complete key of a committed origin scope.
type OriginScopeKey struct {
	DeviceID domain.DeviceID
	Kind     ScopeKind
	ScopeID  domain.UUIDv7
}

// OriginScope is the reducer-owned form of the digest-covered ordering row.
type OriginScope struct {
	OriginScopeKey
	LastSequence uint64
}

// Changes is the ordered logical projection write set produced by reduction.
// Field order follows the fixed digest-covered table order.
type Changes struct {
	// AdvancesEventChain is set centrally for every accepted reducer outcome.
	// It is protocol metadata, not a projection row.
	AdvancesEventChain       bool
	OriginScopes             []OriginScope
	AuditCounters            []auditcounter.Counter
	Tasks                    []task.Task
	PlanRevisions            []plan.Revision
	PlanCurrent              []plan.Current
	MemoryRecords            []memory.Record
	Leases                   []lease.Lease
	Devices                  []device.Device
	VoterSet                 []voterset.Set
	CredentialAuthority      []credentialauthority.Authority
	AgentSessions            []agentsession.Session
	CanonicalRefs            []publication.CanonicalRef
	CredentialAuthorizations []credentialauthorization.Authorization
	Publications             []publication.Publication
	ControlFileProposals     []controlfile.Proposal
	MergeConflicts           []conflict.Conflict
	SessionPolicy            []policy.Policy
}

// AuditClass identifies a committed operation requiring an audit row.
type AuditClass string

const AuditOperatorOverride AuditClass = "operator_override"

// AuditDirective carries reducer-derived audit classification. Event identity,
// actor, result, and apply timestamp are supplied by the apply layer.
type AuditDirective struct {
	Class   AuditClass
	Subject string
}

// AlarmClass identifies a local operational alarm derived from a committed
// result. Alarms are not replicated projection state.
type AlarmClass string

const (
	AlarmConflictIntegrity             AlarmClass = "conflict_integrity"
	AlarmConflictDetectorCompatibility AlarmClass = "conflict_detector_compatibility"
)

// AlarmDirective lets the apply layer emit and deduplicate a local alarm by
// committed result identity.
type AlarmDirective struct {
	Class   AlarmClass
	Subject string
}

// Outcome is the complete pure reducer result. A rejected outcome may still
// contain an origin-scope write because valid next sequences are consumed
// before role, CAS, payload, and domain checks.
type Outcome struct {
	Status         Status
	Code           Code
	Changes        Changes
	RecordActivity bool
	ActivityTaskID domain.UUIDv7
	Audit          *AuditDirective
	RecordedAudit  *AuditRecordedDirective
	Alarm          *AlarmDirective
	Checkpoint     *CheckpointDirective
}

// Accepted reports whether the proposal changes its domain projection.
func (outcome Outcome) Accepted() bool {
	return outcome.Status == StatusAccepted
}

// ResultJSON returns the canonical durable command outcome.
func (outcome Outcome) ResultJSON() ([]byte, error) {
	if outcome.Status != StatusAccepted && outcome.Status != StatusRejected {
		return nil, fmt.Errorf("reducer: invalid outcome status %q", outcome.Status)
	}
	if outcome.Code == "" {
		return nil, errors.New("reducer: empty outcome code")
	}
	encoded, err := json.Marshal(struct {
		Code   Code   `json:"code"`
		Status Status `json:"status"`
	}{
		Code:   outcome.Code,
		Status: outcome.Status,
	})
	if err != nil {
		return nil, fmt.Errorf("reducer: encode outcome: %w", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, fmt.Errorf("reducer: canonicalize outcome: %w", err)
	}
	return canonical, nil
}

var (
	ErrKindNotImplemented             = errors.New("reducer: event kind is not implemented")
	ErrApplyLevelUnsupported          = errors.New("reducer: event apply level is not supported")
	ErrInvalidCommittedState          = errors.New("reducer: invalid committed state")
	ErrCheckpointApplyContextRequired = errors.New(
		"reducer: checkpoint apply context is required",
	)
	ErrCheckpointEventRequired = errors.New(
		"reducer: checkpoint-specific reduction requires a checkpoint event",
	)
	ErrReducerCapacityExhausted = errors.New(
		"reducer: result-chain capacity is exhausted",
	)
)

// Reduce applies one implemented proposal kind to committed state.
func Reduce(state State, signed event.SignedEvent) (Outcome, error) {
	return reduce(state, signed, nil)
}

// ReduceCheckpoint applies a consensus.checkpoint proposal using the local
// pre-command chain and Raft context required for checkpoint verification.
func ReduceCheckpoint(
	state State,
	signed event.SignedEvent,
	applyContext CheckpointApplyContext,
) (Outcome, error) {
	if signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return Outcome{}, fmt.Errorf(
			"%w: %q",
			ErrCheckpointEventRequired,
			signed.Proposal().Kind,
		)
	}
	return reduce(state, signed, &applyContext)
}

// ReduceAttestedRejectedCheckpoint replays a voter-attested rejected
// checkpoint without fabricating the source replica's Raft term or log index.
// Callers must still compare the returned outcome with the signed result and
// authorize that result's batch signer at the batch end.
func ReduceAttestedRejectedCheckpoint(
	state State,
	signed event.SignedEvent,
) (Outcome, error) {
	if signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return Outcome{}, fmt.Errorf(
			"%w: %q",
			ErrCheckpointEventRequired,
			signed.Proposal().Kind,
		)
	}
	context, outcome, done, err := prepareReduction(state, signed)
	if err != nil || done {
		return outcome, err
	}
	if _, ok := decodeCheckpointProof(
		context.state,
		context.proposal.Payload,
	); !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	return context.reject(CodeStaleCheckpoint), nil
}

func reduce(
	state State,
	signed event.SignedEvent,
	checkpointContext *CheckpointApplyContext,
) (Outcome, error) {
	context, outcome, done, err := prepareReduction(state, signed)
	if err != nil || done {
		return outcome, err
	}
	outcome, err = reduceImplemented(context, checkpointContext)
	if err != nil {
		return Outcome{}, err
	}
	if outcome.Status == StatusAccepted {
		proposal := signed.Proposal()
		outcome.RecordActivity = proposal.RationaleSummary != "" ||
			len(proposal.Actions) != 0
		outcome.Changes.AdvancesEventChain = true
	}
	return outcome, nil
}

func prepareReduction(
	state State,
	signed event.SignedEvent,
) (reductionContext, Outcome, bool, error) {
	if !domain.ValidUnsignedInteger(state.currentChainIndex) ||
		!domain.ValidUnsignedInteger(state.currentResultIndex) ||
		state.currentChainIndex > state.currentResultIndex {
		return reductionContext{}, Outcome{}, false, invalidState(
			"chain or result index is outside the protocol bounds",
		)
	}
	if state.currentResultIndex == domain.MaxSafeInteger {
		return reductionContext{}, Outcome{}, false,
			ErrReducerCapacityExhausted
	}
	proposal := signed.Proposal()
	clusterApplyLevel := state.sessionPolicy.Values.ClusterMinApplyLevel
	if clusterApplyLevel < 1 {
		return reductionContext{}, Outcome{}, false,
			invalidState("cluster apply level is below one")
	}
	if proposal.MinApplyLevel > event.MaxSupportedApplyLevel ||
		proposal.MinApplyLevel > uint64(clusterApplyLevel) {
		return reductionContext{}, Outcome{}, false, fmt.Errorf(
			"%w: event requires %d, binary supports %d, cluster enables %d",
			ErrApplyLevelUnsupported,
			proposal.MinApplyLevel,
			event.MaxSupportedApplyLevel,
			clusterApplyLevel,
		)
	}
	if _, registered := event.LookupKind(proposal.Kind); !registered {
		return reductionContext{}, Outcome{}, false, fmt.Errorf(
			"%w: %q",
			ErrKindNotImplemented,
			proposal.Kind,
		)
	}
	if !implementedKind(proposal.Kind) {
		return reductionContext{}, Outcome{}, false, fmt.Errorf(
			"%w: %q",
			ErrKindNotImplemented,
			proposal.Kind,
		)
	}

	context, outcome, done, err := beginReduction(state, signed)
	return context, outcome, done, err
}

func implementedKind(kind event.Kind) bool {
	return taskKind(kind) ||
		activityKind(kind) ||
		leaseKind(kind) ||
		agentSessionKind(kind) ||
		planKind(kind) ||
		memoryKind(kind) ||
		membershipKind(kind) ||
		policyKind(kind) ||
		credentialKind(kind) ||
		controlFileKind(kind) ||
		publicationKind(kind) ||
		conflictKind(kind) ||
		checkpointKind(kind) ||
		auditKind(kind)
}

func reduceImplemented(
	context reductionContext,
	checkpointContext *CheckpointApplyContext,
) (Outcome, error) {
	proposal := context.proposal
	switch proposal.Kind {
	case event.KindTaskCreated:
		return reduceTaskCreated(context)
	case event.KindTaskUpdated:
		return reduceTaskUpdated(context)
	case event.KindTaskStateChanged:
		return reduceTaskStateChanged(context)
	case event.KindTaskClaimed:
		return reduceTaskClaimed(context)
	case event.KindTaskReleased:
		return reduceTaskReleased(context)
	case event.KindTaskReassigned:
		return reduceTaskReassigned(context)
	case event.KindTaskCancelled:
		return reduceTaskCancelled(context)
	case event.KindActivityRecorded:
		return reduceActivityRecorded(context)
	case event.KindLeaseAcquired:
		return reduceLeaseAcquired(context)
	case event.KindLeaseRenewed:
		return reduceLeaseRenewed(context)
	case event.KindLeaseReleased:
		return reduceLeaseReleased(context)
	case event.KindAgentSessionStarted:
		return reduceAgentSessionStarted(context)
	case event.KindAgentSessionStateChanged:
		return reduceAgentSessionStateChanged(context)
	case event.KindAgentSessionEnded:
		return reduceAgentSessionEnded(context)
	case event.KindPlanRevisionProposed:
		return reducePlanRevisionProposed(context)
	case event.KindPlanCurrentSelected:
		return reducePlanCurrentSelected(context)
	case event.KindMemoryAppended:
		return reduceMemoryAppended(context)
	case event.KindMembershipDeviceAdmitted:
		return reduceMembershipDeviceAdmitted(context)
	case event.KindMembershipVersionReported:
		return reduceMembershipVersionReported(context)
	case event.KindMembershipRoleChanged:
		return reduceMembershipRoleChanged(context)
	case event.KindMembershipOwnerRecovered:
		return reduceMembershipOwnerRecovered(context)
	case event.KindMembershipDeviceRevoked:
		return reduceMembershipDeviceRevoked(context)
	case event.KindMembershipVoterSetChanged:
		return reduceMembershipVoterSetChanged(context)
	case event.KindMembershipVoterSetActivated:
		return reduceMembershipVoterSetActivated(context)
	case event.KindPolicyChanged:
		return reducePolicyChanged(context)
	case event.KindCredentialAuthorized:
		return reduceCredentialAuthorized(context)
	case event.KindControlFileChangeProposed:
		return reduceControlFileChangeProposed(context)
	case event.KindPublicationProposed:
		return reducePublicationProposed(context)
	case event.KindPublicationReviewed:
		return reducePublicationReviewed(context)
	case event.KindPublicationApplied:
		return reducePublicationApplied(context)
	case event.KindPublicationWithdrawn:
		return reducePublicationWithdrawn(context)
	case event.KindWorkspaceConflictDetected:
		return reduceWorkspaceConflictDetected(context)
	case event.KindWorkspaceConflictResolved:
		return reduceWorkspaceConflictResolved(context)
	case event.KindWorkspaceConflictForceResolved:
		return reduceWorkspaceConflictForceResolved(context)
	case event.KindConsensusCheckpoint:
		if checkpointContext == nil {
			return Outcome{}, ErrCheckpointApplyContextRequired
		}
		return reduceConsensusCheckpoint(context, *checkpointContext)
	case event.KindAuditRecorded:
		return reduceAuditRecorded(context)
	default:
		return Outcome{}, fmt.Errorf("%w: %q", ErrKindNotImplemented, proposal.Kind)
	}
}

func activityKind(kind event.Kind) bool {
	return kind == event.KindActivityRecorded
}

func credentialKind(kind event.Kind) bool {
	return kind == event.KindCredentialAuthorized
}

func controlFileKind(kind event.Kind) bool {
	return kind == event.KindControlFileChangeProposed
}

func checkpointKind(kind event.Kind) bool {
	return kind == event.KindConsensusCheckpoint
}

func auditKind(kind event.Kind) bool {
	return kind == event.KindAuditRecorded
}

func publicationKind(kind event.Kind) bool {
	switch kind {
	case event.KindPublicationProposed,
		event.KindPublicationReviewed,
		event.KindPublicationApplied,
		event.KindPublicationWithdrawn:
		return true
	default:
		return false
	}
}

func conflictKind(kind event.Kind) bool {
	switch kind {
	case event.KindWorkspaceConflictDetected,
		event.KindWorkspaceConflictResolved,
		event.KindWorkspaceConflictForceResolved:
		return true
	default:
		return false
	}
}

func membershipKind(kind event.Kind) bool {
	switch kind {
	case event.KindMembershipDeviceAdmitted,
		event.KindMembershipVersionReported,
		event.KindMembershipRoleChanged,
		event.KindMembershipOwnerRecovered,
		event.KindMembershipDeviceRevoked,
		event.KindMembershipVoterSetChanged,
		event.KindMembershipVoterSetActivated:
		return true
	default:
		return false
	}
}

func policyKind(kind event.Kind) bool {
	return kind == event.KindPolicyChanged
}

func memoryKind(kind event.Kind) bool {
	return kind == event.KindMemoryAppended
}

func planKind(kind event.Kind) bool {
	return kind == event.KindPlanRevisionProposed ||
		kind == event.KindPlanCurrentSelected
}

func agentSessionKind(kind event.Kind) bool {
	switch kind {
	case event.KindAgentSessionStarted,
		event.KindAgentSessionStateChanged,
		event.KindAgentSessionEnded:
		return true
	default:
		return false
	}
}

func leaseKind(kind event.Kind) bool {
	switch kind {
	case event.KindLeaseAcquired,
		event.KindLeaseRenewed,
		event.KindLeaseReleased:
		return true
	default:
		return false
	}
}

func taskKind(kind event.Kind) bool {
	switch kind {
	case event.KindTaskCreated,
		event.KindTaskUpdated,
		event.KindTaskStateChanged,
		event.KindTaskClaimed,
		event.KindTaskReleased,
		event.KindTaskReassigned,
		event.KindTaskCancelled:
		return true
	default:
		return false
	}
}
