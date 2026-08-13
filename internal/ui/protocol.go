package ui

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

// Snapshot is the bounded status object returned over operator local IPC.
type Snapshot struct {
	Session   SessionStatus   `json:"session"`
	Consensus ConsensusStatus `json:"consensus"`
	Agents    []AgentStatus   `json:"agents"`
	Tasks     []TaskStatus    `json:"tasks"`
	TaskTotal uint64          `json:"task_total"`
	Truncated bool            `json:"tasks_truncated"`
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
	State                   string   `json:"state"`
	Role                    string   `json:"role"`
	LeaderDeviceID          *string  `json:"leader_device_id"`
	LiveVoterDeviceIDs      []string `json:"live_voter_device_ids"`
	TargetVoterDeviceIDs    []string `json:"target_voter_device_ids"`
	VoterSetVersion         uint64   `json:"voter_set_version"`
	QuorumRequired          int      `json:"quorum_required"`
	StrongWrites            string   `json:"strong_writes"`
	ConfigurationReconciled bool     `json:"configuration_reconciled"`
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
	if err := snapshot.Consensus.validate(snapshot.Session.LocalDeviceID); err != nil {
		return err
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

func (value ConsensusStatus) validate(localDeviceID string) error {
	switch coordstatus.ConsensusState(value.State) {
	case coordstatus.ConsensusStarting,
		coordstatus.ConsensusElecting,
		coordstatus.ConsensusReady,
		coordstatus.ConsensusHalted:
	default:
		return fmt.Errorf("ui: invalid consensus state")
	}
	switch coordstatus.ConsensusRole(value.Role) {
	case coordstatus.RoleFollower,
		coordstatus.RoleCandidate,
		coordstatus.RoleLeader,
		coordstatus.RoleShutdown:
	default:
		return fmt.Errorf("ui: invalid consensus role")
	}
	switch coordstatus.StrongWriteState(value.StrongWrites) {
	case coordstatus.StrongWritesWaiting,
		coordstatus.StrongWritesAvailable,
		coordstatus.StrongWritesBlocked:
	default:
		return fmt.Errorf("ui: invalid strong-write state")
	}
	if value.LiveVoterDeviceIDs == nil ||
		value.TargetVoterDeviceIDs == nil ||
		len(value.LiveVoterDeviceIDs) < 1 ||
		len(value.LiveVoterDeviceIDs) > 5 ||
		len(value.TargetVoterDeviceIDs) < 1 ||
		len(value.TargetVoterDeviceIDs) > 5 ||
		value.QuorumRequired != len(value.LiveVoterDeviceIDs)/2+1 ||
		value.VoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(value.VoterSetVersion) {
		return fmt.Errorf("ui: invalid voter status")
	}
	if err := validateDeviceIDs(value.LiveVoterDeviceIDs); err != nil {
		return err
	}
	if err := validateDeviceIDs(value.TargetVoterDeviceIDs); err != nil {
		return err
	}
	if value.LeaderDeviceID != nil &&
		!domain.DeviceID(*value.LeaderDeviceID).Valid() {
		return fmt.Errorf("ui: invalid leader device")
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
	return nil
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
