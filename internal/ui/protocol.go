package ui

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

// Snapshot is the bounded status object returned over operator local IPC.
type Snapshot struct {
	Session          SessionStatus   `json:"session"`
	Consensus        ConsensusStatus `json:"consensus"`
	Network          NetworkStatus   `json:"network"`
	Members          []MemberStatus  `json:"members"`
	Agents           []AgentStatus   `json:"agents"`
	Tasks            []TaskStatus    `json:"tasks"`
	MemberTotal      uint64          `json:"member_total"`
	MembersTruncated bool            `json:"members_truncated"`
	TaskTotal        uint64          `json:"task_total"`
	Truncated        bool            `json:"tasks_truncated"`
}

type SessionStatus struct {
	SessionID          string  `json:"session_id"`
	WorkspaceID        string  `json:"workspace_id"`
	RecoveryGeneration uint64  `json:"recovery_generation"`
	LocalDeviceID      string  `json:"local_device_id"`
	MemberRole         string  `json:"member_role"`
	MemberStatus       string  `json:"member_status"`
	DaemonVersion      string  `json:"daemon_version"`
	AppliedTerm        *uint64 `json:"applied_term"`
	AppliedRaftIndex   *uint64 `json:"applied_raft_index"`
	EventChainIndex    uint64  `json:"event_chain_index"`
	ResultIndex        uint64  `json:"result_index"`
	DigestVersion      uint64  `json:"digest_version"`
	ProjectionVersion  uint64  `json:"projection_schema_version"`
}

type ConsensusStatus struct {
	State                    string   `json:"state"`
	Role                     string   `json:"role"`
	LeaderDeviceID           *string  `json:"leader_device_id"`
	LiveConfigurationSource  string   `json:"live_configuration_source"`
	LiveVoterDeviceIDs       []string `json:"live_voter_device_ids"`
	LiveNonvoterDeviceIDs    []string `json:"live_nonvoter_device_ids"`
	TargetVoterDeviceIDs     []string `json:"target_voter_device_ids"`
	ActivatedVoterDeviceIDs  []string `json:"activated_voter_device_ids"`
	VoterSetVersion          uint64   `json:"voter_set_version"`
	ActivatedVoterSetVersion uint64   `json:"activated_voter_set_version"`
	QuorumRequired           int      `json:"quorum_required"`
	StrongWrites             string   `json:"strong_writes"`
	ReplicaCurrency          string   `json:"replica_currency"`
	ObservedAuthorityIDs     []string `json:"observed_authority_device_ids"`
	ObservedResultIndex      uint64   `json:"observed_result_index"`
	ConfigurationReconciled  bool     `json:"configuration_reconciled"`
	ReconciliationState      string   `json:"reconciliation_state"`
	ReconciliationStep       string   `json:"reconciliation_step"`
	ReconciliationBlocker    string   `json:"reconciliation_blocker"`
	ReconciliationDeviceID   *string  `json:"reconciliation_device_id"`
}

type AgentStatus struct {
	AgentSessionID string  `json:"agent_session_id"`
	DeviceID       string  `json:"device_id"`
	ClientKind     string  `json:"client_kind"`
	AgentProfileID *string `json:"agent_profile_id"`
	State          string  `json:"state"`
	ResumeState    *string `json:"resume_state"`
	WorkingRootID  string  `json:"working_root_id"`
	EntityVersion  uint64  `json:"entity_version"`
}

type MemberStatus struct {
	DeviceID      string `json:"device_id"`
	Role          string `json:"role"`
	Status        string `json:"status"`
	EntityVersion uint64 `json:"entity_version"`
}

type TaskStatus struct {
	TaskID              string  `json:"task_id"`
	Title               string  `json:"title"`
	State               string  `json:"state"`
	StateReason         *string `json:"state_reason"`
	Priority            uint8   `json:"priority"`
	DependencyCount     int     `json:"dependency_count"`
	OwnerDeviceID       *string `json:"owner_device_id"`
	OwnerAgentSessionID *string `json:"owner_agent_session_id"`
	IntendedDeviceID    *string `json:"intended_device_id"`
	EntityVersion       uint64  `json:"entity_version"`
}

// Validate checks the complete status response before it reaches a terminal.
func (snapshot Snapshot) Validate() error {
	if err := snapshot.Session.validate(); err != nil {
		return err
	}
	if err := snapshot.Consensus.validate(
		snapshot.Session.LocalDeviceID,
		snapshot.Session.ResultIndex,
	); err != nil {
		return err
	}
	if err := snapshot.Network.validate(); err != nil {
		return err
	}
	if len(snapshot.Members) < 1 ||
		len(snapshot.Members) > coordstatus.MaxMembers ||
		snapshot.MemberTotal < 1 ||
		!domain.ValidUnsignedInteger(snapshot.MemberTotal) ||
		snapshot.MemberTotal < uint64(len(snapshot.Members)) ||
		snapshot.MembersTruncated !=
			(snapshot.MemberTotal > uint64(len(snapshot.Members))) {
		return fmt.Errorf("ui: invalid member count")
	}
	var priorMember string
	for index, member := range snapshot.Members {
		if err := member.validate(); err != nil {
			return fmt.Errorf("ui: member %d: %w", index, err)
		}
		if index > 0 && priorMember >= member.DeviceID {
			return fmt.Errorf("ui: members are not ordered")
		}
		priorMember = member.DeviceID
	}
	if snapshot.Agents == nil ||
		len(snapshot.Agents) > coordstatus.MaxAgentSessions {
		return fmt.Errorf("ui: too many agent sessions")
	}
	var priorAgent string
	for index, agent := range snapshot.Agents {
		if err := agent.validate(); err != nil {
			return fmt.Errorf("ui: agent %d: %w", index, err)
		}
		if index > 0 && priorAgent >= agent.AgentSessionID {
			return fmt.Errorf("ui: agent sessions are not ordered")
		}
		priorAgent = agent.AgentSessionID
	}
	if snapshot.Tasks == nil ||
		len(snapshot.Tasks) > coordstatus.MaxTasks ||
		!domain.ValidUnsignedInteger(snapshot.TaskTotal) ||
		snapshot.TaskTotal < uint64(len(snapshot.Tasks)) ||
		snapshot.Truncated !=
			(snapshot.TaskTotal > uint64(len(snapshot.Tasks))) {
		return fmt.Errorf("ui: invalid task count")
	}
	var (
		priorPriority uint8
		priorTaskID   string
	)
	for index, value := range snapshot.Tasks {
		if err := value.validate(); err != nil {
			return fmt.Errorf("ui: task %d: %w", index, err)
		}
		if index > 0 &&
			(value.Priority < priorPriority ||
				value.Priority == priorPriority &&
					value.TaskID <= priorTaskID) {
			return fmt.Errorf("ui: tasks are not ordered")
		}
		priorPriority = value.Priority
		priorTaskID = value.TaskID
	}
	return nil
}

func (value MemberStatus) validate() error {
	if !domain.DeviceID(value.DeviceID).Valid() ||
		!device.Role(value.Role).Valid() ||
		!device.Status(value.Status).Valid() ||
		value.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(value.EntityVersion) {
		return fmt.Errorf("ui: invalid member status")
	}
	return nil
}

func (value SessionStatus) validate() error {
	if !domain.UUIDv7(value.SessionID).Valid() ||
		!domain.UUIDv4(value.WorkspaceID).Valid() ||
		!domain.DeviceID(value.LocalDeviceID).Valid() ||
		!domain.ValidUnsignedInteger(value.RecoveryGeneration) ||
		!device.Role(value.MemberRole).Valid() ||
		!device.Status(value.MemberStatus).Valid() ||
		len(value.DaemonVersion) < 1 ||
		len(value.DaemonVersion) > device.MaxDaemonVersionBytes ||
		(value.AppliedTerm == nil) != (value.AppliedRaftIndex == nil) ||
		value.AppliedTerm != nil &&
			(*value.AppliedTerm < 1 ||
				!domain.ValidUnsignedInteger(*value.AppliedTerm)) ||
		value.AppliedRaftIndex != nil &&
			(*value.AppliedRaftIndex < 1 ||
				!domain.ValidUnsignedInteger(*value.AppliedRaftIndex)) ||
		!domain.ValidUnsignedInteger(value.EventChainIndex) ||
		!domain.ValidUnsignedInteger(value.ResultIndex) ||
		value.EventChainIndex > value.ResultIndex ||
		value.DigestVersion < 1 ||
		!domain.ValidUnsignedInteger(value.DigestVersion) ||
		value.ProjectionVersion < 1 ||
		!domain.ValidUnsignedInteger(value.ProjectionVersion) {
		return fmt.Errorf("ui: invalid session status")
	}
	return nil
}

func (value ConsensusStatus) validate(
	localDeviceID string,
	localResultIndex uint64,
) error {
	switch coordstatus.ConsensusState(value.State) {
	case coordstatus.ConsensusStarting,
		coordstatus.ConsensusElecting,
		coordstatus.ConsensusReady,
		coordstatus.ConsensusSettled,
		coordstatus.ConsensusHalted:
	default:
		return fmt.Errorf("ui: invalid consensus state")
	}
	switch coordstatus.ConsensusRole(value.Role) {
	case coordstatus.RoleFollower,
		coordstatus.RoleCandidate,
		coordstatus.RoleLeader,
		coordstatus.RoleNonvoter,
		coordstatus.RoleShutdown:
	default:
		return fmt.Errorf("ui: invalid consensus role")
	}
	if (value.State == string(coordstatus.ConsensusSettled)) !=
		(value.Role == string(coordstatus.RoleNonvoter)) {
		return fmt.Errorf("ui: inconsistent settled consensus role")
	}
	switch coordstatus.StrongWriteState(value.StrongWrites) {
	case coordstatus.StrongWritesWaiting,
		coordstatus.StrongWritesAvailable,
		coordstatus.StrongWritesBlocked:
	default:
		return fmt.Errorf("ui: invalid strong-write state")
	}
	if value.LiveVoterDeviceIDs == nil ||
		value.LiveNonvoterDeviceIDs == nil ||
		value.TargetVoterDeviceIDs == nil ||
		value.ActivatedVoterDeviceIDs == nil ||
		value.ObservedAuthorityIDs == nil ||
		!validVoterSetSize(len(value.TargetVoterDeviceIDs)) ||
		!validVoterSetSize(len(value.ActivatedVoterDeviceIDs)) ||
		value.VoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(value.VoterSetVersion) ||
		value.ActivatedVoterSetVersion < 1 ||
		value.ActivatedVoterSetVersion > value.VoterSetVersion ||
		!domain.ValidUnsignedInteger(value.ActivatedVoterSetVersion) {
		return fmt.Errorf("ui: invalid voter status")
	}
	if err := validateDeviceIDs(value.LiveVoterDeviceIDs); err != nil {
		return err
	}
	if err := validateDeviceIDs(value.LiveNonvoterDeviceIDs); err != nil {
		return err
	}
	if err := validateDeviceIDs(value.TargetVoterDeviceIDs); err != nil {
		return err
	}
	if err := validateDeviceIDs(value.ActivatedVoterDeviceIDs); err != nil {
		return err
	}
	if err := validateDeviceIDs(value.ObservedAuthorityIDs); err != nil {
		return err
	}
	for _, observed := range value.ObservedAuthorityIDs {
		if !containsString(value.ActivatedVoterDeviceIDs, observed) {
			return fmt.Errorf("ui: observed device is outside authority")
		}
	}
	currency := coordstatus.ReplicaCurrencyState(value.ReplicaCurrency)
	if value.State != string(coordstatus.ConsensusSettled) {
		if currency != coordstatus.ReplicaCurrencyRaft ||
			len(value.ObservedAuthorityIDs) != 0 ||
			value.ObservedResultIndex != 0 {
			return fmt.Errorf("ui: invalid Raft replica currency")
		}
	} else {
		switch currency {
		case coordstatus.ReplicaCurrencyCurrent:
			if len(value.ObservedAuthorityIDs) !=
				len(value.ActivatedVoterDeviceIDs) ||
				value.ObservedResultIndex != localResultIndex {
				return fmt.Errorf("ui: invalid current replica currency")
			}
		case coordstatus.ReplicaCurrencyBehind:
			if value.ObservedResultIndex <= localResultIndex {
				return fmt.Errorf("ui: invalid behind replica currency")
			}
		case coordstatus.ReplicaCurrencyUnknown:
			if value.ObservedResultIndex > localResultIndex {
				return fmt.Errorf("ui: invalid unknown replica currency")
			}
		default:
			return fmt.Errorf("ui: invalid settled replica currency")
		}
	}
	if value.LeaderDeviceID != nil &&
		!domain.DeviceID(*value.LeaderDeviceID).Valid() {
		return fmt.Errorf("ui: invalid leader device")
	}
	source := coordstatus.LiveConfigurationSource(
		value.LiveConfigurationSource,
	)
	switch source {
	case coordstatus.LiveConfigurationLocal:
		if value.State == string(coordstatus.ConsensusSettled) {
			return fmt.Errorf("ui: local settled configuration")
		}
		if err := validateKnownLiveStatus(value); err != nil {
			return err
		}
	case coordstatus.LiveConfigurationVoterReported:
		if value.State != string(coordstatus.ConsensusSettled) {
			return fmt.Errorf("ui: invalid voter-reported state")
		}
		if err := validateKnownLiveStatus(value); err != nil {
			return err
		}
		if value.LeaderDeviceID != nil &&
			!containsString(
				value.LiveVoterDeviceIDs,
				*value.LeaderDeviceID,
			) {
			return fmt.Errorf("ui: invalid voter-reported leader")
		}
	case coordstatus.LiveConfigurationUnknown:
		if value.State != string(coordstatus.ConsensusSettled) ||
			value.LeaderDeviceID != nil ||
			len(value.LiveVoterDeviceIDs) != 0 ||
			len(value.LiveNonvoterDeviceIDs) != 0 ||
			value.QuorumRequired != 0 {
			return fmt.Errorf("ui: invalid unknown live configuration")
		}
	default:
		return fmt.Errorf("ui: invalid live configuration source")
	}
	if value.StrongWrites == string(coordstatus.StrongWritesAvailable) &&
		(value.State != string(coordstatus.ConsensusReady) ||
			value.Role != string(coordstatus.RoleLeader) ||
			value.LeaderDeviceID == nil ||
			*value.LeaderDeviceID != localDeviceID) {
		return fmt.Errorf("ui: inconsistent strong-write availability")
	}
	if value.State == string(coordstatus.ConsensusHalted) &&
		value.StrongWrites != string(coordstatus.StrongWritesBlocked) {
		return fmt.Errorf("ui: halted consensus is not blocked")
	}
	if value.State == string(coordstatus.ConsensusSettled) &&
		value.StrongWrites != string(coordstatus.StrongWritesWaiting) {
		return fmt.Errorf("ui: settled consensus is not waiting")
	}
	reconciliationState := coordstatus.ReconciliationState(
		value.ReconciliationState,
	)
	switch reconciliationState {
	case coordstatus.ReconciliationStable,
		coordstatus.ReconciliationPending,
		coordstatus.ReconciliationReconciling,
		coordstatus.ReconciliationUnknown:
	default:
		return fmt.Errorf("ui: invalid reconciliation state")
	}
	reconciliationStep := coordstatus.ReconciliationStep(
		value.ReconciliationStep,
	)
	reconciliationBlocker := coordstatus.ReconciliationBlocker(
		value.ReconciliationBlocker,
	)
	if !reconciliationStep.Valid() ||
		!reconciliationBlocker.Valid() {
		return fmt.Errorf("ui: invalid reconciliation detail")
	}
	if value.ReconciliationDeviceID != nil &&
		!domain.DeviceID(*value.ReconciliationDeviceID).Valid() {
		return fmt.Errorf("ui: invalid reconciliation device")
	}
	if source != coordstatus.LiveConfigurationLocal {
		if value.ConfigurationReconciled ||
			reconciliationState != coordstatus.ReconciliationUnknown ||
			reconciliationStep != coordstatus.ReconciliationStepObserve ||
			reconciliationBlocker !=
				coordstatus.ReconciliationBlockerNone ||
			value.ReconciliationDeviceID != nil {
			return fmt.Errorf("ui: invalid nonlocal reconciliation")
		}
		return nil
	}
	exactlyReconciled := len(value.LiveNonvoterDeviceIDs) == 0 &&
		value.VoterSetVersion == value.ActivatedVoterSetVersion &&
		sameStrings(
			value.LiveVoterDeviceIDs,
			value.TargetVoterDeviceIDs,
		) &&
		sameStrings(
			value.ActivatedVoterDeviceIDs,
			value.TargetVoterDeviceIDs,
		)
	if value.ConfigurationReconciled != exactlyReconciled {
		return fmt.Errorf("ui: invalid reconciliation exactness")
	}
	switch reconciliationState {
	case coordstatus.ReconciliationStable:
		if !value.ConfigurationReconciled ||
			reconciliationStep != coordstatus.ReconciliationStepComplete ||
			reconciliationBlocker !=
				coordstatus.ReconciliationBlockerNone ||
			value.ReconciliationDeviceID != nil {
			return fmt.Errorf("ui: invalid stable reconciliation")
		}
	case coordstatus.ReconciliationPending,
		coordstatus.ReconciliationReconciling:
		if value.ConfigurationReconciled ||
			reconciliationStep == coordstatus.ReconciliationStepComplete {
			return fmt.Errorf("ui: invalid unfinished reconciliation")
		}
	}
	return nil
}

func validateKnownLiveStatus(value ConsensusStatus) error {
	if len(value.LiveVoterDeviceIDs) < 1 ||
		len(value.LiveVoterDeviceIDs) > int(policy.MaxMemberDevices) ||
		len(value.LiveVoterDeviceIDs)+
			len(value.LiveNonvoterDeviceIDs) >
			int(policy.MaxMemberDevices) ||
		value.QuorumRequired != len(value.LiveVoterDeviceIDs)/2+1 {
		return fmt.Errorf("ui: invalid live voter configuration")
	}
	liveVoters := make(map[string]struct{}, len(value.LiveVoterDeviceIDs))
	for _, id := range value.LiveVoterDeviceIDs {
		liveVoters[id] = struct{}{}
	}
	for _, id := range value.LiveNonvoterDeviceIDs {
		if _, exists := liveVoters[id]; exists {
			return fmt.Errorf("ui: overlapping live voter and nonvoter")
		}
	}
	return nil
}

func validVoterSetSize(size int) bool {
	return size == 1 || size == 3 || size == 5
}

func sameStrings(left, right []string) bool {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateDeviceIDs(values []string) error {
	var prior string
	for index, value := range values {
		if !domain.DeviceID(value).Valid() ||
			index > 0 && prior >= value {
			return fmt.Errorf("ui: invalid or unordered device IDs")
		}
		prior = value
	}
	return nil
}

func (value AgentStatus) validate() error {
	if !domain.UUIDv7(value.AgentSessionID).Valid() ||
		!domain.DeviceID(value.DeviceID).Valid() ||
		!agentsession.ClientKind(value.ClientKind).Valid() ||
		!domain.UUIDv7(value.WorkingRootID).Valid() ||
		value.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(value.EntityVersion) {
		return fmt.Errorf("invalid identity or version")
	}
	if value.AgentProfileID != nil &&
		(!utf8.ValidString(*value.AgentProfileID) ||
			len(*value.AgentProfileID) < 1 ||
			len(*value.AgentProfileID) >
				agentsession.MaxAgentProfileIDBytes) {
		return fmt.Errorf("invalid profile")
	}
	state := agentsession.State(value.State)
	if !state.Valid() || state == agentsession.StateEnded {
		return fmt.Errorf("invalid state")
	}
	if state == agentsession.StateDisconnected {
		if value.ResumeState == nil ||
			!agentsession.State(*value.ResumeState).Connected() {
			return fmt.Errorf("invalid resume state")
		}
	} else if value.ResumeState != nil {
		return fmt.Errorf("unexpected resume state")
	}
	return nil
}

func (value TaskStatus) validate() error {
	if !domain.UUIDv7(value.TaskID).Valid() ||
		!validTaskTitle(value.Title) ||
		!task.State(value.State).Valid() ||
		value.Priority > uint8(task.MaxPriority) ||
		value.DependencyCount < 0 ||
		value.DependencyCount > task.MaxBlockedBy ||
		value.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(value.EntityVersion) {
		return fmt.Errorf("invalid identity, title, state, or version")
	}
	if task.State(value.State) == task.StateBlocked {
		if value.StateReason == nil ||
			!validStatusText(*value.StateReason, 1, task.MaxStateReasonBytes) {
			return fmt.Errorf("invalid blocked reason")
		}
	} else if value.StateReason != nil {
		return fmt.Errorf("unexpected state reason")
	}
	hasDeviceOwner := value.OwnerDeviceID != nil
	hasSessionOwner := value.OwnerAgentSessionID != nil
	if hasDeviceOwner != hasSessionOwner {
		return fmt.Errorf("partial owner")
	}
	if hasDeviceOwner &&
		(!domain.DeviceID(*value.OwnerDeviceID).Valid() ||
			!domain.UUIDv7(*value.OwnerAgentSessionID).Valid()) {
		return fmt.Errorf("invalid owner")
	}
	if value.IntendedDeviceID != nil &&
		!domain.DeviceID(*value.IntendedDeviceID).Valid() {
		return fmt.Errorf("invalid intended device")
	}
	return nil
}

func validTaskTitle(value string) bool {
	if !validStatusText(value, 1, task.MaxTitleBytes) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) ||
			unicode.In(character, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func validStatusText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) &&
		len(value) >= minimum &&
		len(value) <= maximum
}
