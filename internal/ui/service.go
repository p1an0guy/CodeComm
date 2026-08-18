package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/ipc"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

const statusQueryPath = "/local/v1/query/status"

var (
	ErrInvalidOperatorOptions = errors.New("ui: invalid operator service options")
	ErrOperatorBindRejected   = errors.New("ui: operator bind rejected")
)

// StatusSource is the read-only daemon boundary consumed by operator views.
type StatusSource interface {
	Status(context.Context) (coordstatus.Snapshot, error)
}

type OperatorServiceOptions struct {
	Source      StatusSource
	SessionID   domain.UUIDv7
	WorkspaceID domain.UUIDv4
}

// OperatorService authorizes a read-only operator connection.
type OperatorService struct {
	source      StatusSource
	sessionID   domain.UUIDv7
	workspaceID domain.UUIDv4
}

func NewOperatorService(
	options OperatorServiceOptions,
) (*OperatorService, error) {
	if options.Source == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() {
		return nil, ErrInvalidOperatorOptions
	}
	return &OperatorService{
		source:      options.Source,
		sessionID:   options.SessionID,
		workspaceID: options.WorkspaceID,
	}, nil
}

// Bind implements ipc.Binder without constructing event authority.
func (service *OperatorService) Bind(
	ctx context.Context,
	_ ipc.VerifiedPeer,
	request ipc.BindRequest,
) (ipc.BindResult, error) {
	if service == nil ||
		ctx == nil ||
		request.ProtocolVersion != ipc.LocalProtocolVersion ||
		request.Class != ipc.ClassOperator ||
		request.SessionID != service.sessionID ||
		request.WorkspaceID != service.workspaceID ||
		len(request.AgentProof) != 0 {
		return ipc.BindResult{}, ErrOperatorBindRejected
	}
	if err := ctx.Err(); err != nil {
		return ipc.BindResult{}, err
	}
	return ipc.NewOperatorBindResult(&operatorBoundClient{
		handler: newOperatorHandler(service.source),
	})
}

type operatorBoundClient struct {
	handler http.Handler
}

func (client *operatorBoundClient) Handler() http.Handler {
	return client.handler
}

func (*operatorBoundClient) Disconnected(context.Context) {}

type operatorHandler struct {
	source StatusSource
}

func newOperatorHandler(source StatusSource) http.Handler {
	return &operatorHandler{source: source}
}

func (handler *operatorHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet ||
		request.URL.Path != statusQueryPath ||
		request.URL.RawQuery != "" ||
		request.RequestURI != statusQueryPath {
		writeOperatorError(writer, http.StatusNotFound, "operation_not_found")
		return
	}
	source, err := handler.source.Status(request.Context())
	if err != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"status_unavailable",
		)
		return
	}
	if err := source.Validate(); err != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"status_unavailable",
		)
		return
	}
	snapshot := snapshotFromCoordination(source)
	if err := snapshot.Validate(); err != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"status_unavailable",
		)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(snapshot)
}

func snapshotFromCoordination(source coordstatus.Snapshot) Snapshot {
	durable := source.Durable
	runtime := source.Runtime
	var leader *string
	if runtime.LeaderDeviceID != "" {
		value := string(runtime.LeaderDeviceID)
		leader = &value
	}
	agents := make([]AgentStatus, len(durable.AgentSessions))
	for index, session := range durable.AgentSessions {
		var profile *string
		if session.AgentProfileID != nil {
			value := *session.AgentProfileID
			profile = &value
		}
		var resumeState *string
		if session.ResumeState != agentsession.StateAbsent {
			value := string(session.ResumeState)
			resumeState = &value
		}
		agents[index] = AgentStatus{
			AgentSessionID: string(session.ID),
			DeviceID:       string(session.DeviceID),
			ClientKind:     string(session.ClientKind),
			AgentProfileID: profile,
			State:          string(session.State),
			ResumeState:    resumeState,
			WorkingRootID:  string(session.WorkingRootID),
			EntityVersion:  session.EntityVersion,
		}
	}
	tasks := make([]TaskStatus, len(durable.Tasks))
	for index, value := range durable.Tasks {
		tasks[index] = taskStatus(value)
	}
	var reconciliationDevice *string
	if runtime.ReconciliationDeviceID != "" {
		value := string(runtime.ReconciliationDeviceID)
		reconciliationDevice = &value
	}
	return Snapshot{
		Session: SessionStatus{
			SessionID:          string(durable.SessionID),
			WorkspaceID:        string(durable.WorkspaceID),
			RecoveryGeneration: durable.RecoveryGeneration,
			LocalDeviceID:      string(durable.Member.ID),
			MemberRole:         string(durable.Member.Role),
			MemberStatus:       string(durable.Member.Status),
			DaemonVersion:      durable.Member.DaemonVersion,
			AppliedTerm: cloneUint64(
				durable.Heads.CurrentTerm,
			),
			AppliedRaftIndex: cloneUint64(
				durable.Heads.LastRaftAppliedLogIndex,
			),
			EventChainIndex:   durable.Heads.ChainIndex,
			ResultIndex:       durable.Heads.ResultIndex,
			DigestVersion:     durable.Heads.DigestVersion,
			ProjectionVersion: durable.Heads.ProjectionSchemaVersion,
		},
		Consensus: ConsensusStatus{
			State:              string(runtime.State),
			Role:               string(runtime.Role),
			LeaderDeviceID:     leader,
			LiveVoterDeviceIDs: deviceIDStrings(runtime.LiveVoterDeviceIDs),
			LiveNonvoterDeviceIDs: deviceIDStrings(
				runtime.LiveNonvoterDeviceIDs,
			),
			TargetVoterDeviceIDs: deviceIDStrings(durable.VoterSet.VoterDeviceIDs()),
			ActivatedVoterDeviceIDs: deviceIDStrings(
				durable.CredentialAuthority.VoterDeviceIDs(),
			),
			VoterSetVersion: durable.VoterSet.VoterSetVersion,
			ActivatedVoterSetVersion: durable.CredentialAuthority.
				VoterSetVersion,
			QuorumRequired:          runtime.QuorumRequired,
			StrongWrites:            string(runtime.StrongWrites),
			ConfigurationReconciled: runtime.ConfigurationReconciled,
			ReconciliationState:     string(runtime.ReconciliationState),
			ReconciliationStep:      string(runtime.ReconciliationStep),
			ReconciliationBlocker:   string(runtime.ReconciliationBlocker),
			ReconciliationDeviceID:  reconciliationDevice,
		},
		Agents:    agents,
		Tasks:     tasks,
		TaskTotal: durable.TaskTotal,
		Truncated: durable.TasksTruncated,
	}
}

func taskStatus(value task.Task) TaskStatus {
	var (
		reason         *string
		ownerDevice    *string
		ownerAgent     *string
		intendedDevice *string
	)
	if value.StateReason != nil {
		text := *value.StateReason
		reason = &text
	}
	if value.OwnerDeviceID != "" {
		text := string(value.OwnerDeviceID)
		ownerDevice = &text
	}
	if value.OwnerAgentSessionID != "" {
		text := string(value.OwnerAgentSessionID)
		ownerAgent = &text
	}
	if value.IntendedDeviceID != "" {
		text := string(value.IntendedDeviceID)
		intendedDevice = &text
	}
	return TaskStatus{
		TaskID:              string(value.ID),
		Title:               value.Title,
		State:               string(value.State),
		StateReason:         reason,
		Priority:            uint8(value.Priority),
		DependencyCount:     len(value.BlockedBy),
		OwnerDeviceID:       ownerDevice,
		OwnerAgentSessionID: ownerAgent,
		IntendedDeviceID:    intendedDevice,
		EntityVersion:       value.EntityVersion,
	}
}

func deviceIDStrings(values []domain.DeviceID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func writeOperatorError(
	writer http.ResponseWriter,
	status int,
	code string,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code":   code,
		"status": status,
	})
}
