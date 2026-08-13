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
)

var ErrInvalidSnapshot = errors.New("status: invalid snapshot")

// ConsensusState is the operator-facing lifecycle of the local consensus
// participant.
type ConsensusState string

const (
	ConsensusStarting ConsensusState = "starting"
	ConsensusElecting ConsensusState = "electing"
	ConsensusReady    ConsensusState = "ready"
	ConsensusHalted   ConsensusState = "halted"
)

// ConsensusRole is the local Raft role at the instant of the read.
type ConsensusRole string

const (
	RoleFollower  ConsensusRole = "follower"
	RoleCandidate ConsensusRole = "candidate"
	RoleLeader    ConsensusRole = "leader"
	RoleShutdown  ConsensusRole = "shutdown"
)

// StrongWriteState describes whether this daemon can currently accept a
// strongly ordered mutation.
type StrongWriteState string

const (
	StrongWritesWaiting   StrongWriteState = "waiting"
	StrongWritesAvailable StrongWriteState = "available"
	StrongWritesBlocked   StrongWriteState = "blocked"
)

// AppliedHeads names the durable positions represented by a status read.
type AppliedHeads struct {
	CurrentTerm             *uint64
	LastRaftAppliedLogIndex *uint64
	ChainIndex              uint64
	ResultIndex             uint64
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
}

// DurableSnapshot is one transactionally consistent read of the local
// coordination projections.
type DurableSnapshot struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	Heads              AppliedHeads
	Member             device.Device
	VoterSet           voterset.Set
	AgentSessions      []agentsession.Session
	Tasks              []task.Task
	TaskTotal          uint64
	TasksTruncated     bool
}

// RuntimeSnapshot contains volatile local consensus observations. It does not
// enter reducers or durable commitments.
type RuntimeSnapshot struct {
	State                   ConsensusState
	Role                    ConsensusRole
	LocalDeviceID           domain.DeviceID
	LeaderDeviceID          domain.DeviceID
	LiveVoterDeviceIDs      []domain.DeviceID
	QuorumRequired          int
	StrongWrites            StrongWriteState
	ConfigurationReconciled bool
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
	case ConsensusStarting, ConsensusElecting, ConsensusReady, ConsensusHalted:
	default:
		return invalid("consensus state")
	}
	switch runtime.Role {
	case RoleFollower, RoleCandidate, RoleLeader, RoleShutdown:
	default:
		return invalid("consensus role")
	}
	switch runtime.StrongWrites {
	case StrongWritesWaiting, StrongWritesAvailable, StrongWritesBlocked:
	default:
		return invalid("strong-write state")
	}
	if len(runtime.LiveVoterDeviceIDs) < 1 ||
		len(runtime.LiveVoterDeviceIDs) > voterset.MaxVoters ||
		runtime.QuorumRequired != len(runtime.LiveVoterDeviceIDs)/2+1 {
		return invalid("live voter configuration")
	}
	var previous domain.DeviceID
	for index, id := range runtime.LiveVoterDeviceIDs {
		if !id.Valid() || index > 0 && previous >= id {
			return invalid("live voter order")
		}
		previous = id
	}
	if runtime.LeaderDeviceID != "" &&
		!runtime.LeaderDeviceID.Valid() {
		return invalid("leader device")
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
	return nil
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
	if err := snapshot.VoterSet.Validate(); err != nil ||
		snapshot.VoterSet.SessionID != snapshot.SessionID {
		return invalid("voter target: %v", err)
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
