package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/localcommand"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	statusQueryPath              = "/local/v1/query/status"
	memberQueryPrefix            = "/local/v1/query/members/"
	commandPath                  = "/local/v1/commands"
	pairingInviteCollectionPath  = "/local/v1/pairing/invites"
	pairingInviteRevokePath      = "/local/v1/pairing/invites/revoke"
	pairingAttemptPath           = "/local/v1/pairing/attempt"
	pairingConfirmPath           = "/local/v1/pairing/confirm"
	manualEndpointCollectionPath = "/local/v1/peer/endpoints"
	manualEndpointRemovePath     = "/local/v1/peer/endpoints/remove"
)

var (
	ErrInvalidOperatorOptions = errors.New("ui: invalid operator service options")
	ErrOperatorBindRejected   = errors.New("ui: operator bind rejected")
)

// StatusSource is the read-only daemon boundary consumed by operator views.
type StatusSource interface {
	Status(context.Context) (coordstatus.Snapshot, error)
	Member(
		context.Context,
		domain.DeviceID,
	) (coordstatus.MemberSummary, bool, error)
}

type OperatorServiceOptions struct {
	Source      StatusSource
	Submitter   operatorcommand.Submitter
	Pairing     PairingOperator
	Endpoints   ManualEndpointOperator
	SessionID   domain.UUIDv7
	WorkspaceID domain.UUIDv4
}

// OperatorService authorizes one human operator connection.
type OperatorService struct {
	source      StatusSource
	submitter   operatorcommand.Submitter
	pairing     PairingOperator
	endpoints   ManualEndpointOperator
	sessionID   domain.UUIDv7
	workspaceID domain.UUIDv4
}

func NewOperatorService(
	options OperatorServiceOptions,
) (*OperatorService, error) {
	if options.Source == nil ||
		options.Submitter == nil ||
		options.Pairing == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() {
		return nil, ErrInvalidOperatorOptions
	}
	return &OperatorService{
		source:      options.Source,
		submitter:   options.Submitter,
		pairing:     options.Pairing,
		endpoints:   options.Endpoints,
		sessionID:   options.SessionID,
		workspaceID: options.WorkspaceID,
	}, nil
}

// NewReadOnlyOperatorService serves status and exact-member queries without
// installing any mutation or pairing capability.
func NewReadOnlyOperatorService(
	source StatusSource,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (*OperatorService, error) {
	if source == nil || !sessionID.Valid() || !workspaceID.Valid() {
		return nil, ErrInvalidOperatorOptions
	}
	return &OperatorService{
		source:      source,
		sessionID:   sessionID,
		workspaceID: workspaceID,
	}, nil
}

// NewMutationOperatorService serves status and human commands without
// exposing pairing operations.
func NewMutationOperatorService(
	source StatusSource,
	submitter operatorcommand.Submitter,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (*OperatorService, error) {
	if source == nil ||
		submitter == nil ||
		!sessionID.Valid() ||
		!workspaceID.Valid() {
		return nil, ErrInvalidOperatorOptions
	}
	return &OperatorService{
		source:      source,
		submitter:   submitter,
		sessionID:   sessionID,
		workspaceID: workspaceID,
	}, nil
}

// NewMutationOperatorServiceWithEndpoints additionally serves device-local
// manual peer routing without exposing pairing operations.
func NewMutationOperatorServiceWithEndpoints(
	source StatusSource,
	submitter operatorcommand.Submitter,
	endpoints ManualEndpointOperator,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (*OperatorService, error) {
	if endpoints == nil {
		return nil, ErrInvalidOperatorOptions
	}
	service, err := NewMutationOperatorService(
		source,
		submitter,
		sessionID,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	service.endpoints = endpoints
	return service, nil
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
		handler: newOperatorHandler(
			service.source,
			service.submitter,
			service.pairing,
			service.endpoints,
			request.ClientInstanceID,
		),
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
	source           StatusSource
	submitter        operatorcommand.Submitter
	pairing          PairingOperator
	endpoints        ManualEndpointOperator
	clientInstanceID domain.UUIDv7
}

func newOperatorHandler(
	source StatusSource,
	submitter operatorcommand.Submitter,
	pairing PairingOperator,
	endpoints ManualEndpointOperator,
	clientInstanceID domain.UUIDv7,
) http.Handler {
	return &operatorHandler{
		source:           source,
		submitter:        submitter,
		pairing:          pairing,
		endpoints:        endpoints,
		clientInstanceID: clientInstanceID,
	}
}

func (handler *operatorHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request != nil && request.Method == http.MethodGet {
		if deviceID, ok := operatorMemberRoute(request); ok {
			handler.member(writer, request, deviceID)
			return
		}
	}
	switch {
	case request.Method == http.MethodGet &&
		exactOperatorRoute(request, statusQueryPath):
		handler.status(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, commandPath):
		handler.command(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, pairingInviteCollectionPath):
		handler.createPairingInvite(writer, request)
	case request.Method == http.MethodGet &&
		exactOperatorRoute(request, pairingInviteCollectionPath):
		handler.listPairingInvites(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, pairingInviteRevokePath):
		handler.revokePairingInvite(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, pairingAttemptPath):
		handler.pairingAttempt(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, pairingConfirmPath):
		handler.confirmPairing(writer, request)
	case request.Method == http.MethodGet &&
		exactOperatorRoute(request, manualEndpointCollectionPath):
		handler.listManualEndpoints(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, manualEndpointCollectionPath):
		handler.addManualEndpoint(writer, request)
	case request.Method == http.MethodPost &&
		exactOperatorRoute(request, manualEndpointRemovePath):
		handler.removeManualEndpoint(writer, request)
	default:
		writeOperatorError(writer, http.StatusNotFound, "operation_not_found")
	}
}

func operatorMemberRoute(
	request *http.Request,
) (domain.DeviceID, bool) {
	if request == nil ||
		request.URL == nil ||
		request.URL.RawPath != "" ||
		request.URL.RawQuery != "" ||
		request.URL.Fragment != "" ||
		request.URL.RawFragment != "" ||
		request.URL.ForceQuery ||
		request.RequestURI != request.URL.Path ||
		!strings.HasPrefix(request.URL.Path, memberQueryPrefix) {
		return "", false
	}
	deviceID := domain.DeviceID(strings.TrimPrefix(
		request.URL.Path,
		memberQueryPrefix,
	))
	return deviceID, deviceID.Valid()
}

func exactOperatorRoute(request *http.Request, path string) bool {
	return request != nil &&
		request.URL != nil &&
		request.URL.Path == path &&
		request.URL.RawPath == "" &&
		request.URL.RawQuery == "" &&
		request.URL.Fragment == "" &&
		request.URL.RawFragment == "" &&
		!request.URL.ForceQuery &&
		request.RequestURI == path
}

func (handler *operatorHandler) member(
	writer http.ResponseWriter,
	request *http.Request,
	deviceID domain.DeviceID,
) {
	member, found, err := handler.source.Member(
		request.Context(),
		deviceID,
	)
	if err != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"member_unavailable",
		)
		return
	}
	if !found {
		writeOperatorError(
			writer,
			http.StatusNotFound,
			"member_not_found",
		)
		return
	}
	response := MemberStatus{
		DeviceID:      string(member.ID),
		Role:          string(member.Role),
		Status:        string(member.Status),
		EntityVersion: member.EntityVersion,
	}
	if member.ID != deviceID || response.validate() != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"member_unavailable",
		)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) status(
	writer http.ResponseWriter,
	request *http.Request,
) {
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
	network := disabledNetworkStatus()
	if networkSource, ok := handler.source.(NetworkStatusSource); ok {
		network, err = networkSource.NetworkStatus(request.Context())
		if err != nil || network.validate() != nil {
			writeOperatorError(
				writer,
				http.StatusServiceUnavailable,
				"status_unavailable",
			)
			return
		}
	}
	snapshot := snapshotFromCoordination(source)
	snapshot.Network = network
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

func (handler *operatorHandler) command(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Body == nil ||
		!handler.clientInstanceID.Valid() {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_command")
		return
	}
	if handler.submitter == nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"strong_writes_unavailable",
		)
		return
	}
	command, err := localcommand.DecodeReader(request.Body)
	if err != nil || !validOperatorCommand(command) {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_command")
		return
	}
	result, err := handler.submitter.SubmitOperatorCommand(
		request.Context(),
		operatorcommand.Request{
			ClientInstanceID: handler.clientInstanceID,
			Command:          command,
		},
	)
	if err != nil {
		status := http.StatusInternalServerError
		code := "command_failed"
		switch {
		case errors.Is(err, store.ErrLocalBackpressure):
			status = http.StatusTooManyRequests
			code = "local_backpressure"
		case errors.Is(err, store.ErrLocalIdempotencyConflict):
			status = http.StatusConflict
			code = "local_idempotency_conflict"
		case errors.Is(err, operatorcommand.ErrInvalidCommand):
			status = http.StatusBadRequest
			code = "invalid_command"
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			status = http.StatusRequestTimeout
			code = "command_wait_interrupted"
		}
		writeOperatorError(writer, status, code)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, map[string]any{
		"code":      result.Outcome.Code,
		"duplicate": result.Duplicate,
		"event_id":  result.EventID,
		"result":    json.RawMessage(result.Outcome.JSON),
		"status":    result.Outcome.Status,
	})
}

func validOperatorCommand(request localcommand.Request) bool {
	command := request.Command
	if command.ExpectedEntityVersion == nil {
		return false
	}
	switch request.Operation {
	case operatorcommand.OperationSetVoters:
		return command.Kind == event.KindMembershipVoterSetChanged
	case operatorcommand.OperationRevokePeer:
		return command.Kind == event.KindMembershipDeviceRevoked
	default:
		return false
	}
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
	members := make([]MemberStatus, len(durable.Members))
	for index, member := range durable.Members {
		members[index] = MemberStatus{
			DeviceID:      string(member.ID),
			Role:          string(member.Role),
			Status:        string(member.Status),
			EntityVersion: member.EntityVersion,
		}
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
			State:                   string(runtime.State),
			Role:                    string(runtime.Role),
			LeaderDeviceID:          leader,
			LiveConfigurationSource: string(runtime.LiveConfigurationSource),
			LiveVoterDeviceIDs: deviceIDStrings(
				runtime.LiveVoterDeviceIDs,
			),
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
			QuorumRequired:  runtime.QuorumRequired,
			StrongWrites:    string(runtime.StrongWrites),
			ReplicaCurrency: string(runtime.ReplicaCurrency),
			ObservedAuthorityIDs: deviceIDStrings(
				runtime.ObservedAuthorityIDs,
			),
			ObservedResultIndex:     runtime.ObservedResultIndex,
			ConfigurationReconciled: runtime.ConfigurationReconciled,
			ReconciliationState:     string(runtime.ReconciliationState),
			ReconciliationStep:      string(runtime.ReconciliationStep),
			ReconciliationBlocker:   string(runtime.ReconciliationBlocker),
			ReconciliationDeviceID:  reconciliationDevice,
		},
		Network:          disabledNetworkStatus(),
		Members:          members,
		Agents:           agents,
		Tasks:            tasks,
		MemberTotal:      durable.MemberTotal,
		MembersTruncated: durable.MembersTruncated,
		TaskTotal:        durable.TaskTotal,
		Truncated:        durable.TasksTruncated,
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

func writeOperatorJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	body, err := canonicalOperatorJSON(value)
	if err != nil {
		writeOperatorError(writer, http.StatusInternalServerError, "encoding_failed")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
