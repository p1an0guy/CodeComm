package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	agentSessionQueryPath = "/local/v1/query/agent-session"
	contextQueryPath      = "/local/v1/query/context"
	taskListQueryPath     = "/local/v1/query/tasks"
	commandPath           = "/local/v1/commands"
)

type agentHandler struct {
	client *boundClient
}

func newAgentHandler(client *boundClient) http.Handler {
	return &agentHandler{client: client}
}

func (handler *agentHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	switch {
	case request.Method == http.MethodGet &&
		request.URL.RawQuery == "" &&
		request.URL.Path == agentSessionQueryPath:
		handler.agentSession(writer, request)
	case request.Method == http.MethodGet &&
		request.URL.RawQuery == "" &&
		request.URL.Path == taskListQueryPath:
		handler.tasks(writer, request)
	case request.Method == http.MethodGet &&
		request.URL.RawQuery == "" &&
		request.URL.Path == contextQueryPath:
		handler.context(writer, request)
	case request.Method == http.MethodPost &&
		request.URL.RawQuery == "" &&
		request.URL.Path == commandPath:
		handler.command(writer, request)
	default:
		writeAgentError(writer, http.StatusNotFound, "operation_not_found")
	}
}

func (handler *agentHandler) agentSession(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, found, err := handler.client.service.local.AgentSession(
		request.Context(),
		handler.client.agentSessionID,
	)
	if err != nil {
		writeAgentError(writer, http.StatusInternalServerError, "query_failed")
		return
	}
	if !found {
		writeAgentError(writer, http.StatusNotFound, "agent_session_not_found")
		return
	}
	writeAgentJSON(writer, http.StatusOK, agentSessionResponse(session))
}

func (handler *agentHandler) tasks(
	writer http.ResponseWriter,
	request *http.Request,
) {
	values, err := handler.client.service.local.ListTasks(
		request.Context(),
		store.MaxLocalTaskQuery,
	)
	if err != nil {
		writeAgentError(writer, http.StatusInternalServerError, "query_failed")
		return
	}
	writeAgentJSON(writer, http.StatusOK, map[string]any{
		"tasks": taskResponses(values),
	})
}

func (handler *agentHandler) context(
	writer http.ResponseWriter,
	request *http.Request,
) {
	snapshot, found, err := handler.client.service.local.AgentContextSnapshot(
		request.Context(),
		handler.client.agentSessionID,
		store.MaxLocalTaskQuery,
	)
	if err != nil {
		writeAgentError(writer, http.StatusInternalServerError, "query_failed")
		return
	}
	if !found {
		writeAgentError(writer, http.StatusNotFound, "agent_session_not_found")
		return
	}
	writeAgentJSON(writer, http.StatusOK, map[string]any{
		"session": map[string]any{
			"session_id":          snapshot.SessionID,
			"workspace_id":        snapshot.WorkspaceID,
			"device_id":           handler.client.service.deviceID,
			"recovery_generation": snapshot.RecoveryGeneration,
			"chain_index":         snapshot.Heads.ChainIndex,
			"result_index":        snapshot.Heads.ResultIndex,
		},
		"self":  agentSessionResponse(snapshot.Self),
		"tasks": taskResponses(snapshot.Tasks),
	})
}

type localCommandRequest struct {
	Operation string
	RequestID domain.UUIDv7
	Command   event.Command
	Canonical []byte
}

func (handler *agentHandler) command(
	writer http.ResponseWriter,
	request *http.Request,
) {
	command, err := decodeLocalCommandRequest(request)
	if err != nil {
		writeAgentError(writer, http.StatusBadRequest, "invalid_command")
		return
	}
	result, duplicate, err := handler.client.submitCommand(
		request.Context(),
		command,
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
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			status = http.StatusRequestTimeout
			code = "command_wait_interrupted"
		}
		writeAgentError(writer, status, code)
		return
	}
	if result.Outcome == nil {
		writeAgentError(writer, http.StatusInternalServerError, "command_failed")
		return
	}
	entityID, _ := command.Command.EntityID.Value()
	writeAgentJSON(writer, http.StatusOK, map[string]any{
		"code":      result.Outcome.Code,
		"duplicate": duplicate,
		"entity_id": entityID,
		"event_id":  result.EventID,
		"result":    json.RawMessage(result.Outcome.JSON),
		"status":    result.Outcome.Status,
	})
}

func decodeLocalCommandRequest(
	request *http.Request,
) (localCommandRequest, error) {
	if request.Body == nil {
		return localCommandRequest{}, ErrCommandRejected
	}
	raw, err := readBoundedBody(request.Body, event.MaxLocalCommandBytes)
	if err != nil {
		return localCommandRequest{}, err
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return localCommandRequest{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil ||
		len(members) != 3 {
		return localCommandRequest{}, ErrCommandRejected
	}
	for _, field := range []string{"operation", "request_id", "command"} {
		value, exists := members[field]
		if !exists || bytes.Equal(value, []byte("null")) {
			return localCommandRequest{}, ErrCommandRejected
		}
	}
	var operation, requestIDText string
	if err := json.Unmarshal(members["operation"], &operation); err != nil ||
		json.Unmarshal(members["request_id"], &requestIDText) != nil {
		return localCommandRequest{}, ErrCommandRejected
	}
	requestID := domain.UUIDv7(requestIDText)
	if !requestID.Valid() {
		return localCommandRequest{}, ErrCommandRejected
	}
	command, err := event.DecodeLocalCommand(members["command"])
	if err != nil {
		return localCommandRequest{}, err
	}
	switch operation {
	case "task.create":
		if command.Kind != event.KindTaskCreated ||
			command.ExpectedEntityVersion != nil {
			return localCommandRequest{}, ErrCommandRejected
		}
	case "task.claim":
		if command.Kind != event.KindTaskClaimed ||
			command.ExpectedEntityVersion == nil {
			return localCommandRequest{}, ErrCommandRejected
		}
	default:
		return localCommandRequest{}, ErrCommandRejected
	}
	return localCommandRequest{
		Operation: operation,
		RequestID: requestID,
		Command:   command,
		Canonical: canonical,
	}, nil
}

type submittedCommand struct {
	EventID domain.UUIDv7
	Outcome *store.CommandOutcome
}

func (client *boundClient) submitCommand(
	ctx context.Context,
	request localCommandRequest,
) (submittedCommand, bool, error) {
	now := client.service.clock()
	if !now.Valid() {
		return submittedCommand{}, false, ErrInvalidOptions
	}
	record, duplicate, err := client.service.local.ReserveCommand(
		ctx,
		store.LocalCommandInput{
			ClientInstanceID: client.clientInstanceID,
			RequestID:        request.RequestID,
			SessionID:        client.service.sessionID,
			WorkspaceID:      client.service.workspaceID,
			BindingClass:     store.LocalBindingAgent,
			OriginDeviceID:   client.service.deviceID,
			OriginScopeKind:  store.OriginScopeKindAgent,
			OriginScopeID:    client.agentSessionID,
			RequestKind:      request.Command.Kind,
			CanonicalRequest: request.Canonical,
			CreatedAt:        now,
		},
		func() (domain.UUIDv7, error) {
			return client.service.generateID()
		},
		func(eventID domain.UUIDv7, sequence uint64) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				request.Command,
				client.binding,
				event.BuildContext{
					EventID:        eventID,
					SessionID:      client.service.sessionID,
					WorkspaceID:    client.service.workspaceID,
					CreatedAt:      now,
					OriginSequence: sequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, client.service.privateKey)
		},
	)
	if err != nil {
		return submittedCommand{}, false, err
	}
	client.service.wakeCommand(record)
	resolved, err := client.service.waitResolved(ctx, record)
	if err != nil {
		return submittedCommand{}, false, err
	}
	if resolved.Outcome == nil {
		return submittedCommand{}, false, ErrCommandForwarding
	}
	return submittedCommand{
		EventID: resolved.EventID,
		Outcome: resolved.Outcome,
	}, duplicate, nil
}

type agentSessionJSON struct {
	AgentSessionID string  `json:"agent_session_id"`
	AgentProfileID *string `json:"agent_profile_id"`
	ClientKind     string  `json:"client_kind"`
	DeviceID       string  `json:"device_id"`
	EntityVersion  uint64  `json:"entity_version"`
	ResumeState    *string `json:"resume_state"`
	State          string  `json:"state"`
	WorkingRootID  string  `json:"working_root_id"`
}

func agentSessionResponse(value agentsession.Session) agentSessionJSON {
	var resumeState *string
	if value.ResumeState != agentsession.StateAbsent {
		text := string(value.ResumeState)
		resumeState = &text
	}
	return agentSessionJSON{
		AgentSessionID: string(value.ID),
		AgentProfileID: cloneString(value.AgentProfileID),
		ClientKind:     string(value.ClientKind),
		DeviceID:       string(value.DeviceID),
		EntityVersion:  value.EntityVersion,
		ResumeState:    resumeState,
		State:          string(value.State),
		WorkingRootID:  string(value.WorkingRootID),
	}
}

type taskJSON struct {
	TaskID              string   `json:"task_id"`
	Title               string   `json:"title"`
	Body                string   `json:"body"`
	State               string   `json:"state"`
	StateReason         *string  `json:"state_reason"`
	Priority            uint8    `json:"priority"`
	BlockedBy           []string `json:"blocked_by"`
	Labels              []string `json:"labels"`
	OwnerDeviceID       *string  `json:"owner_device_id"`
	OwnerAgentSessionID *string  `json:"owner_agent_session_id"`
	IntendedDeviceID    *string  `json:"intended_device_id"`
	EntityVersion       uint64   `json:"entity_version"`
}

func taskResponses(values []task.Task) []taskJSON {
	result := make([]taskJSON, len(values))
	for index, value := range values {
		blockedBy := make([]string, len(value.BlockedBy))
		for dependencyIndex, dependency := range value.BlockedBy {
			blockedBy[dependencyIndex] = string(dependency)
		}
		result[index] = taskJSON{
			TaskID:              string(value.ID),
			Title:               value.Title,
			Body:                value.Body,
			State:               string(value.State),
			StateReason:         cloneString(value.StateReason),
			Priority:            uint8(value.Priority),
			BlockedBy:           blockedBy,
			Labels:              append(make([]string, 0, len(value.Labels)), value.Labels...),
			OwnerDeviceID:       optionalString(string(value.OwnerDeviceID)),
			OwnerAgentSessionID: optionalString(string(value.OwnerAgentSessionID)),
			IntendedDeviceID:    optionalString(string(value.IntendedDeviceID)),
			EntityVersion:       value.EntityVersion,
		}
	}
	return result
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func readBoundedBody(body io.Reader, limit int) ([]byte, error) {
	result, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(result) > limit {
		return nil, ErrCommandRejected
	}
	return result, nil
}

func writeAgentJSON(writer http.ResponseWriter, status int, value any) {
	body, err := canonicalObject(value)
	if err != nil {
		writeAgentError(writer, http.StatusInternalServerError, "encoding_failed")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
