package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const launchAcknowledgementPath = "/local/v1/agent-launch/ack"

type boundClient struct {
	service          *Service
	clientInstanceID domain.UUIDv7
	agentSessionID   domain.UUIDv7
	workingRootID    domain.UUIDv7
	binding          event.Binding
	handler          http.Handler
	disconnectOnce   sync.Once
}

func newBoundClient(
	service *Service,
	clientInstanceID domain.UUIDv7,
	agentSessionID domain.UUIDv7,
	workingRootID domain.UUIDv7,
	binding event.Binding,
) *boundClient {
	client := &boundClient{
		service:          service,
		clientInstanceID: clientInstanceID,
		agentSessionID:   agentSessionID,
		workingRootID:    workingRootID,
		binding:          binding,
	}
	client.handler = newAgentHandler(client)
	return client
}

func newLaunchBoundClient(
	service *Service,
	clientInstanceID domain.UUIDv7,
	agentSessionID domain.UUIDv7,
	workingRootID domain.UUIDv7,
	binding event.Binding,
	launchID domain.UUIDv7,
	expectedCommitment store.Digest,
) *boundClient {
	client := newBoundClient(
		service,
		clientInstanceID,
		agentSessionID,
		workingRootID,
		binding,
	)
	client.handler = &launchGateHandler{
		client:             client,
		next:               client.handler,
		launchID:           launchID,
		expectedCommitment: expectedCommitment,
	}
	return client
}

func (client *boundClient) Handler() http.Handler {
	return client.handler
}

func (client *boundClient) Disconnected(context.Context) {
	client.disconnectOnce.Do(func() {
		client.service.onDisconnected(client.agentSessionID)
	})
}

type launchGateHandler struct {
	client             *boundClient
	next               http.Handler
	launchID           domain.UUIDv7
	expectedCommitment store.Digest
	acknowledged       atomic.Bool
}

func (handler *launchGateHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path == launchAcknowledgementPath {
		handler.acknowledge(writer, request)
		return
	}
	if !handler.acknowledged.Load() {
		writeAgentError(writer, http.StatusForbidden, "launch_ack_required")
		return
	}
	handler.next.ServeHTTP(writer, request)
}

func (handler *launchGateHandler) acknowledge(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost ||
		request.URL.RawQuery != "" ||
		request.RequestURI != launchAcknowledgementPath {
		writeAgentError(writer, http.StatusNotFound, "operation_not_found")
		return
	}
	token, err := decodeLaunchAcknowledgement(request.Body)
	if err != nil {
		writeAgentError(writer, http.StatusBadRequest, "invalid_launch_ack")
		return
	}
	defer clear(token)
	commitment := resumeDigest(token)
	if commitment != handler.expectedCommitment {
		writeAgentError(writer, http.StatusForbidden, "launch_ack_rejected")
		return
	}
	if _, err := handler.client.service.local.AcknowledgeLaunch(
		request.Context(),
		handler.launchID,
		handler.client.clientInstanceID,
		commitment,
	); err != nil {
		writeAgentError(writer, http.StatusForbidden, "launch_ack_rejected")
		return
	}
	handler.acknowledged.Store(true)
	writer.WriteHeader(http.StatusNoContent)
}

func decodeLaunchAcknowledgement(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, ErrInvalidProof
	}
	encoded, err := io.ReadAll(io.LimitReader(body, 1025))
	if err != nil || len(encoded) == 0 || len(encoded) > 1024 {
		return nil, ErrInvalidProof
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrInvalidProof
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil || len(members) != 1 {
		return nil, ErrInvalidProof
	}
	raw, exists := members["resume_capability"]
	if !exists || bytes.Equal(raw, []byte("null")) {
		return nil, ErrInvalidProof
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, ErrInvalidProof
	}
	token, err := codec.DecodeBase64URLExact(text, 32)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return token, nil
}

func writeAgentError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code":   code,
		"status": status,
	})
}
