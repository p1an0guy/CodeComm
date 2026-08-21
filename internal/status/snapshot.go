// Package status defines the typed read-only coordination snapshot shared by
// the daemon status API and terminal UI.
package status

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const (
	MaxTasks         = 200
	MaxAgentSessions = int(policy.MaxActiveAgentSessions)
	MaxMembers       = 64
)

var ErrInvalidSnapshot = errors.New("status: invalid snapshot")

// ConsensusState is the operator-facing lifecycle of the local consensus
// participant.
type ConsensusState string

const (
	ConsensusStarting ConsensusState = "starting"
	ConsensusElecting ConsensusState = "electing"
	ConsensusReady    ConsensusState = "ready"
	ConsensusSettled  ConsensusState = "settled"
	ConsensusHalted   ConsensusState = "halted"
)

// ConsensusRole is the local consensus role at the instant of the read.
type ConsensusRole string

const (
	RoleFollower  ConsensusRole = "follower"
	RoleCandidate ConsensusRole = "candidate"
	RoleLeader    ConsensusRole = "leader"
	RoleNonvoter  ConsensusRole = "nonvoter"
	RoleShutdown  ConsensusRole = "shutdown"
)

// LiveConfigurationSource identifies where the volatile voter configuration
// came from. Durable targets are never treated as live observations.
type LiveConfigurationSource string

const (
	LiveConfigurationLocal         LiveConfigurationSource = "local"
	LiveConfigurationVoterReported LiveConfigurationSource = "voter-reported"
	LiveConfigurationUnknown       LiveConfigurationSource = "unknown"
)

// StrongWriteState describes whether this daemon can currently accept a
// strongly ordered mutation.
type StrongWriteState string

const (
	StrongWritesWaiting   StrongWriteState = "waiting"
	StrongWritesAvailable StrongWriteState = "available"
	StrongWritesBlocked   StrongWriteState = "blocked"
)

// ReplicaCurrencyState describes whether the local durable coordination cut
// is known to cover every retained current-authority signed watermark.
type ReplicaCurrencyState string

const (
	ReplicaCurrencyRaft    ReplicaCurrencyState = "raft"
	ReplicaCurrencyCurrent ReplicaCurrencyState = "current"
	ReplicaCurrencyBehind  ReplicaCurrencyState = "behind"
	ReplicaCurrencyUnknown ReplicaCurrencyState = "unknown"
)

// ReconciliationState is the local operator view of voter-set convergence.
type ReconciliationState string

const (
	ReconciliationStable      ReconciliationState = "stable"
	ReconciliationPending     ReconciliationState = "pending"
	ReconciliationReconciling ReconciliationState = "reconciling"
	ReconciliationUnknown     ReconciliationState = "unknown"
)

// ReconciliationStep names the next or currently blocked protocol action.
type ReconciliationStep string

const (
	ReconciliationStepObserve            ReconciliationStep = "observe"
	ReconciliationStepAddNonvoter        ReconciliationStep = "add-nonvoter"
	ReconciliationStepProveNonvoter      ReconciliationStep = "prove-nonvoter"
	ReconciliationStepPromoteVoter       ReconciliationStep = "promote-voter"
	ReconciliationStepActivateAuthority  ReconciliationStep = "activate-authority"
	ReconciliationStepTransferLeadership ReconciliationStep = "transfer-leadership"
	ReconciliationStepRemoveVoter        ReconciliationStep = "remove-voter"
	ReconciliationStepRemoveNonvoter     ReconciliationStep = "remove-nonvoter"
	ReconciliationStepComplete           ReconciliationStep = "complete"
)

// Valid reports whether step belongs to the closed status vocabulary.
func (step ReconciliationStep) Valid() bool {
	switch step {
	case ReconciliationStepObserve,
		ReconciliationStepAddNonvoter,
		ReconciliationStepProveNonvoter,
		ReconciliationStepPromoteVoter,
		ReconciliationStepActivateAuthority,
		ReconciliationStepTransferLeadership,
		ReconciliationStepRemoveVoter,
		ReconciliationStepRemoveNonvoter,
		ReconciliationStepComplete:
		return true
	default:
		return false
	}
}

// ReconciliationBlocker is the bounded, non-sensitive failure class exposed
// to operators while the committed voter target remains unchanged.
type ReconciliationBlocker string

const (
	ReconciliationBlockerNone                  ReconciliationBlocker = "none"
	ReconciliationBlockerCapabilityDisabled    ReconciliationBlocker = "capability-disabled"
	ReconciliationBlockerObjectCoverage        ReconciliationBlocker = "object-coverage-degraded"
	ReconciliationBlockerReadiness             ReconciliationBlocker = "credential-or-reachability"
	ReconciliationBlockerTargetUnavailable     ReconciliationBlocker = "target-unavailable"
	ReconciliationBlockerProofUnavailable      ReconciliationBlocker = "proof-unavailable"
	ReconciliationBlockerActivationUnavailable ReconciliationBlocker = "activation-unavailable"
	ReconciliationBlockerLeadershipTransfer    ReconciliationBlocker = "leadership-transfer-unavailable"
	ReconciliationBlockerQuorum                ReconciliationBlocker = "quorum-unavailable"
	ReconciliationBlockerRetrying              ReconciliationBlocker = "retrying"
)

// Valid reports whether blocker belongs to the closed status vocabulary.
func (blocker ReconciliationBlocker) Valid() bool {
	switch blocker {
	case ReconciliationBlockerNone,
		ReconciliationBlockerCapabilityDisabled,
		ReconciliationBlockerObjectCoverage,
		ReconciliationBlockerReadiness,
		ReconciliationBlockerTargetUnavailable,
		ReconciliationBlockerProofUnavailable,
		ReconciliationBlockerActivationUnavailable,
		ReconciliationBlockerLeadershipTransfer,
		ReconciliationBlockerQuorum,
		ReconciliationBlockerRetrying:
		return true
	default:
		return false
	}
}

// AppliedHeads names the durable positions represented by a status read.
type AppliedHeads struct {
	CurrentTerm             *uint64
	LastRaftAppliedLogIndex *uint64
	ChainIndex              uint64
	ResultIndex             uint64
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

// MemberSummary is the bounded operator projection of one committed device.
// Identity public keys are intentionally excluded from local status output.
type MemberSummary struct {
	ID            domain.DeviceID
	Role          device.Role
	Status        device.Status
	EntityVersion uint64
}

func (member MemberSummary) Validate() error {
	if !member.ID.Valid() ||
		!member.Role.Valid() ||
		!member.Status.Valid() ||
		member.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(member.EntityVersion) {
		return invalid("member")
	}
	return nil
}

// DurableSnapshot is one transactionally consistent read of the local
// coordination projections.
type DurableSnapshot struct {
	SessionID           domain.UUIDv7
	WorkspaceID         domain.UUIDv4
	RecoveryGeneration  uint64
	Heads               AppliedHeads
	Member              device.Device
	Members             []MemberSummary
	MemberTotal         uint64
	MembersTruncated    bool
	VoterSet            voterset.Set
	CredentialAuthority voterset.Set
	AgentSessions       []agentsession.Session
	Tasks               []task.Task
	TaskTotal           uint64
	TasksTruncated      bool
}

// RuntimeSnapshot contains volatile local consensus observations. It does not
// enter reducers or durable commitments.
type RuntimeSnapshot struct {
	State                   ConsensusState
	Role                    ConsensusRole
	LocalDeviceID           domain.DeviceID
	LeaderDeviceID          domain.DeviceID
	LiveConfigurationSource LiveConfigurationSource
	LiveVoterDeviceIDs      []domain.DeviceID
	LiveNonvoterDeviceIDs   []domain.DeviceID
	QuorumRequired          int
	StrongWrites            StrongWriteState
	ReplicaCurrency         ReplicaCurrencyState
	ObservedAuthorityIDs    []domain.DeviceID
	ObservedResultIndex     uint64
	ConfigurationReconciled bool
	ReconciliationState     ReconciliationState
	ReconciliationStep      ReconciliationStep
	ReconciliationBlocker   ReconciliationBlocker
	ReconciliationDeviceID  domain.DeviceID
}

// Snapshot combines one durable cut with a nearby volatile observation.
type Snapshot struct {
	Durable DurableSnapshot
	Runtime RuntimeSnapshot
}

// Validate checks both status layers and their shared local identity.
func (snapshot Snapshot) Validate() error {
	if err := snapshot.Durable.Validate(); err != nil {
		return err
	}
	runtime := snapshot.Runtime
	if runtime.LocalDeviceID != snapshot.Durable.Member.ID {
		return invalid("runtime local device")
	}
	switch runtime.State {
	case ConsensusStarting,
		ConsensusElecting,
		ConsensusReady,
		ConsensusSettled,
		ConsensusHalted:
	default:
		return invalid("consensus state")
	}
	switch runtime.Role {
	case RoleFollower, RoleCandidate, RoleLeader, RoleNonvoter, RoleShutdown:
	default:
		return invalid("consensus role")
	}
	if (runtime.State == ConsensusSettled) !=
		(runtime.Role == RoleNonvoter) {
		return invalid("settled consensus role")
	}
	switch runtime.StrongWrites {
	case StrongWritesWaiting, StrongWritesAvailable, StrongWritesBlocked:
	default:
		return invalid("strong-write state")
	}
	if err := validateReplicaCurrency(snapshot); err != nil {
		return err
	}
	if runtime.LeaderDeviceID != "" &&
		!runtime.LeaderDeviceID.Valid() {
		return invalid("leader device")
	}
	switch runtime.LiveConfigurationSource {
	case LiveConfigurationLocal:
		if runtime.State == ConsensusSettled {
			return invalid("local settled configuration")
		}
		if err := validateKnownLiveConfiguration(runtime); err != nil {
			return err
		}
	case LiveConfigurationVoterReported:
		if runtime.State != ConsensusSettled {
			return invalid("voter-reported consensus state")
		}
		if err := validateKnownLiveConfiguration(runtime); err != nil {
			return err
		}
		if runtime.LeaderDeviceID != "" &&
			!containsDeviceID(
				runtime.LiveVoterDeviceIDs,
				runtime.LeaderDeviceID,
			) {
			return invalid("voter-reported leader")
		}
	case LiveConfigurationUnknown:
		if runtime.State != ConsensusSettled ||
			runtime.LeaderDeviceID != "" ||
			len(runtime.LiveVoterDeviceIDs) != 0 ||
			len(runtime.LiveNonvoterDeviceIDs) != 0 ||
			runtime.QuorumRequired != 0 {
			return invalid("unknown live configuration")
		}
	default:
		return invalid("live configuration source")
	}
	switch runtime.StrongWrites {
	case StrongWritesAvailable:
		if runtime.State != ConsensusReady ||
			runtime.Role != RoleLeader ||
			runtime.LeaderDeviceID != runtime.LocalDeviceID {
			return invalid("available strong writes")
		}
	case StrongWritesBlocked:
		if runtime.State != ConsensusHalted {
			return invalid("blocked strong writes")
		}
	}
	if runtime.State == ConsensusHalted &&
		runtime.StrongWrites != StrongWritesBlocked {
		return invalid("halted strong writes")
	}
	if runtime.State == ConsensusSettled &&
		runtime.StrongWrites != StrongWritesWaiting {
		return invalid("settled strong writes")
	}
	if !runtime.ReconciliationStep.Valid() ||
		!runtime.ReconciliationBlocker.Valid() {
		return invalid("reconciliation detail")
	}
	if runtime.ReconciliationDeviceID != "" &&
		!runtime.ReconciliationDeviceID.Valid() {
		return invalid("reconciliation device")
	}
	if runtime.LiveConfigurationSource != LiveConfigurationLocal {
		if runtime.ConfigurationReconciled ||
			runtime.ReconciliationState != ReconciliationUnknown ||
			runtime.ReconciliationStep != ReconciliationStepObserve ||
			runtime.ReconciliationBlocker != ReconciliationBlockerNone ||
			runtime.ReconciliationDeviceID != "" {
			return invalid("nonlocal reconciliation")
		}
		return nil
	}
	switch runtime.ReconciliationState {
	case ReconciliationStable:
		if !runtime.ConfigurationReconciled ||
			runtime.ReconciliationStep != ReconciliationStepComplete ||
			runtime.ReconciliationBlocker != ReconciliationBlockerNone ||
			runtime.ReconciliationDeviceID != "" {
			return invalid("stable reconciliation")
		}
	case ReconciliationPending, ReconciliationReconciling:
		if runtime.ConfigurationReconciled ||
			runtime.ReconciliationStep == ReconciliationStepComplete {
			return invalid("unfinished reconciliation")
		}
	default:
		return invalid("reconciliation state")
	}
	targetIDs := snapshot.Durable.VoterSet.VoterDeviceIDs()
	authorityIDs := snapshot.Durable.CredentialAuthority.VoterDeviceIDs()
	exactlyReconciled := len(runtime.LiveNonvoterDeviceIDs) == 0 &&
		sameDeviceIDs(runtime.LiveVoterDeviceIDs, targetIDs) &&
		snapshot.Durable.CredentialAuthority.VoterSetVersion ==
			snapshot.Durable.VoterSet.VoterSetVersion &&
		sameDeviceIDs(authorityIDs, targetIDs)
	if runtime.ConfigurationReconciled != exactlyReconciled {
		return invalid("reconciliation exactness")
	}
	return nil
}

func validateReplicaCurrency(snapshot Snapshot) error {
	runtime := snapshot.Runtime
	if runtime.ObservedAuthorityIDs == nil ||
		!domain.ValidUnsignedInteger(runtime.ObservedResultIndex) ||
		!validOrderedDeviceIDs(runtime.ObservedAuthorityIDs) {
		return invalid("replica currency observation")
	}
	if runtime.State != ConsensusSettled {
		if runtime.ReplicaCurrency != ReplicaCurrencyRaft ||
			len(runtime.ObservedAuthorityIDs) != 0 ||
			runtime.ObservedResultIndex != 0 {
			return invalid("Raft replica currency")
		}
		return nil
	}
	switch runtime.ReplicaCurrency {
	case ReplicaCurrencyCurrent,
		ReplicaCurrencyBehind,
		ReplicaCurrencyUnknown:
	default:
		return invalid("settled replica currency")
	}
	authorityIDs := snapshot.Durable.CredentialAuthority.VoterDeviceIDs()
	for _, observed := range runtime.ObservedAuthorityIDs {
		if !containsDeviceID(authorityIDs, observed) {
			return invalid("observed credential authority")
		}
	}
	switch runtime.ReplicaCurrency {
	case ReplicaCurrencyCurrent:
		if len(runtime.ObservedAuthorityIDs) != len(authorityIDs) ||
			runtime.ObservedResultIndex !=
				snapshot.Durable.Heads.ResultIndex {
			return invalid("current settled replica")
		}
	case ReplicaCurrencyBehind:
		if runtime.ObservedResultIndex <=
			snapshot.Durable.Heads.ResultIndex {
			return invalid("behind settled replica")
		}
	case ReplicaCurrencyUnknown:
		if runtime.ObservedResultIndex >
			snapshot.Durable.Heads.ResultIndex {
			return invalid("unknown settled replica")
		}
	}
	return nil
}

func validateKnownLiveConfiguration(runtime RuntimeSnapshot) error {
	if len(runtime.LiveVoterDeviceIDs) < 1 ||
		len(runtime.LiveVoterDeviceIDs) > int(policy.MaxMemberDevices) ||
		len(runtime.LiveVoterDeviceIDs)+
			len(runtime.LiveNonvoterDeviceIDs) >
			int(policy.MaxMemberDevices) ||
		runtime.QuorumRequired != len(runtime.LiveVoterDeviceIDs)/2+1 {
		return invalid("live voter configuration")
	}
	if !validOrderedDeviceIDs(runtime.LiveVoterDeviceIDs) ||
		!validOrderedDeviceIDs(runtime.LiveNonvoterDeviceIDs) {
		return invalid("live configuration order")
	}
	voters := make(map[domain.DeviceID]struct{}, len(runtime.LiveVoterDeviceIDs))
	for _, id := range runtime.LiveVoterDeviceIDs {
		voters[id] = struct{}{}
	}
	for _, id := range runtime.LiveNonvoterDeviceIDs {
		if _, exists := voters[id]; exists {
			return invalid("live configuration overlap")
		}
	}
	return nil
}

func containsDeviceID(values []domain.DeviceID, target domain.DeviceID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// Validate checks the complete durable status contract.
func (snapshot DurableSnapshot) Validate() error {
	if !snapshot.SessionID.Valid() ||
		!snapshot.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(snapshot.RecoveryGeneration) {
		return invalid("lineage")
	}
	if err := snapshot.validateHeads(); err != nil {
		return err
	}
	if err := snapshot.Member.Validate(); err != nil {
		return invalid("local member: %v", err)
	}
	if len(snapshot.Members) < 1 ||
		len(snapshot.Members) > MaxMembers ||
		snapshot.MemberTotal < 1 ||
		!domain.ValidUnsignedInteger(snapshot.MemberTotal) ||
		snapshot.MemberTotal < uint64(len(snapshot.Members)) ||
		snapshot.MembersTruncated !=
			(snapshot.MemberTotal > uint64(len(snapshot.Members))) {
		return invalid("member count")
	}
	var priorMember domain.DeviceID
	for index, member := range snapshot.Members {
		if err := member.Validate(); err != nil ||
			index > 0 && priorMember >= member.ID {
			return invalid("member %d", index)
		}
		priorMember = member.ID
	}
	if err := snapshot.VoterSet.Validate(); err != nil ||
		snapshot.VoterSet.SessionID != snapshot.SessionID {
		return invalid("voter target: %v", err)
	}
	if err := snapshot.CredentialAuthority.Validate(); err != nil ||
		snapshot.CredentialAuthority.SessionID != snapshot.SessionID ||
		snapshot.CredentialAuthority.VoterSetVersion >
			snapshot.VoterSet.VoterSetVersion {
		return invalid("credential authority: %v", err)
	}
	if len(snapshot.AgentSessions) > MaxAgentSessions {
		return invalid("agent-session count")
	}
	var priorAgent domain.UUIDv7
	for index, session := range snapshot.AgentSessions {
		if err := session.Validate(); err != nil ||
			session.State == agentsession.StateEnded ||
			index > 0 && priorAgent >= session.ID {
			return invalid("agent session %d", index)
		}
		priorAgent = session.ID
	}
	if len(snapshot.Tasks) > MaxTasks ||
		!domain.ValidUnsignedInteger(snapshot.TaskTotal) ||
		snapshot.TaskTotal < uint64(len(snapshot.Tasks)) ||
		snapshot.TasksTruncated !=
			(snapshot.TaskTotal > uint64(len(snapshot.Tasks))) {
		return invalid("task count")
	}
	var (
		priorPriority task.Priority
		priorTaskID   domain.UUIDv7
	)
	for index, value := range snapshot.Tasks {
		if err := value.Validate(); err != nil {
			return invalid("task %d: %v", index, err)
		}
		if index > 0 &&
			(value.Priority < priorPriority ||
				value.Priority == priorPriority &&
					value.ID <= priorTaskID) {
			return invalid("task order")
		}
		priorPriority = value.Priority
		priorTaskID = value.ID
	}
	return nil
}

func validOrderedDeviceIDs(values []domain.DeviceID) bool {
	var previous domain.DeviceID
	for index, id := range values {
		if !id.Valid() || index > 0 && previous >= id {
			return false
		}
		previous = id
	}
	return true
}

func sameDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (snapshot DurableSnapshot) validateHeads() error {
	heads := snapshot.Heads
	if (heads.CurrentTerm == nil) !=
		(heads.LastRaftAppliedLogIndex == nil) ||
		heads.CurrentTerm != nil &&
			(*heads.CurrentTerm < 1 ||
				!domain.ValidUnsignedInteger(*heads.CurrentTerm)) ||
		heads.LastRaftAppliedLogIndex != nil &&
			(*heads.LastRaftAppliedLogIndex < 1 ||
				!domain.ValidUnsignedInteger(
					*heads.LastRaftAppliedLogIndex,
				)) ||
		!domain.ValidUnsignedInteger(heads.ChainIndex) ||
		!domain.ValidUnsignedInteger(heads.ResultIndex) ||
		heads.ChainIndex > heads.ResultIndex ||
		heads.DigestVersion < 1 ||
		!domain.ValidUnsignedInteger(heads.DigestVersion) ||
		heads.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(heads.ProjectionSchemaVersion) {
		return invalid("applied heads")
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSnapshot, fmt.Sprintf(format, args...))
}
