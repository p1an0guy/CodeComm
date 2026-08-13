package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	LocalProtocolVersion uint32 = 1
	bindPath                    = "/local/v1/bind"
)

var (
	ErrInvalidBindRequest = errors.New("ipc: invalid bind request")
	ErrBindRejected       = errors.New("ipc: local bind rejected")
)

// ClientClass is fixed by the first request and cannot change for the
// connection lifetime.
type ClientClass uint8

const (
	ClassOperator ClientClass = iota + 1
	ClassAgent
)

func (class ClientClass) String() string {
	switch class {
	case ClassOperator:
		return "operator"
	case ClassAgent:
		return "agent"
	default:
		return ""
	}
}

// BindRequest is the identity-free, mechanically validated first request.
// AgentProof is one bounded JSON object interpreted exactly once by the agent
// layer; IPC never logs or persists it.
type BindRequest struct {
	ProtocolVersion  uint32
	ClientInstanceID domain.UUIDv7
	SessionID        domain.UUIDv7
	WorkspaceID      domain.UUIDv4
	Class            ClientClass
	AgentProof       json.RawMessage
}

// BoundClient is returned only after the composition root has accepted a
// mechanical bind. Handler must already close over the immutable operator or
// agent authority for this connection.
type BoundClient interface {
	Handler() http.Handler
	Disconnected(context.Context)
}

type bindResultKind uint8

const (
	bindResultOperator bindResultKind = iota + 1
	bindResultAgentLaunch
	bindResultAgentResume
)

// BindResult is a short-lived, sealed authorization result. Only the
// constructors below can create a valid value; the server consumes it before
// retaining the BoundClient for the connection lifetime.
type BindResult struct {
	kind             bindResultKind
	client           BoundClient
	resumeCapability []byte
}

// NewOperatorBindResult constructs an operator authorization result.
func NewOperatorBindResult(client BoundClient) (BindResult, error) {
	return newBindResult(bindResultOperator, client, nil)
}

// NewAgentLaunchBindResult constructs a new-agent authorization result. The
// capability is copied and returned exactly once in the bind response.
func NewAgentLaunchBindResult(
	client BoundClient,
	resumeCapability []byte,
) (BindResult, error) {
	if len(resumeCapability) != 32 {
		return BindResult{}, ErrBindRejected
	}
	return newBindResult(
		bindResultAgentLaunch,
		client,
		bytes.Clone(resumeCapability),
	)
}

// NewAgentResumeBindResult constructs a resumed-agent authorization result.
func NewAgentResumeBindResult(client BoundClient) (BindResult, error) {
	return newBindResult(bindResultAgentResume, client, nil)
}

func newBindResult(
	kind bindResultKind,
	client BoundClient,
	resumeCapability []byte,
) (BindResult, error) {
	if _, ok := safeBoundHandler(client); !ok {
		return BindResult{}, ErrBindRejected
	}
	return BindResult{
		kind:             kind,
		client:           client,
		resumeCapability: resumeCapability,
	}, nil
}

// Binder authorizes a mechanically valid bind against local daemon state.
type Binder interface {
	Bind(context.Context, VerifiedPeer, BindRequest) (BindResult, error)
}

// BinderFunc adapts a function to Binder.
type BinderFunc func(context.Context, VerifiedPeer, BindRequest) (BindResult, error)

func (function BinderFunc) Bind(
	ctx context.Context,
	peer VerifiedPeer,
	request BindRequest,
) (BindResult, error) {
	return function(ctx, peer, request)
}

type bindWire struct {
	LocalProtocolVersion uint32          `json:"local_protocol_version"`
	ClientInstanceID     string          `json:"client_instance_id"`
	SessionID            string          `json:"session_id"`
	WorkspaceID          string          `json:"workspace_id"`
	ClientClass          string          `json:"client_class"`
	AgentProof           json.RawMessage `json:"agent_proof,omitempty"`
}

type bindResponse struct {
	LocalProtocolVersion uint32 `json:"local_protocol_version"`
	ClientInstanceID     string `json:"client_instance_id"`
	SessionID            string `json:"session_id"`
	WorkspaceID          string `json:"workspace_id"`
	ClientClass          string `json:"client_class"`
}

type launchBindResponse struct {
	bindResponse
	ResumeCapability string `json:"resume_capability"`
}

func decodeBindRequest(input []byte) (BindRequest, error) {
	canonical, err := codec.Canonicalize(input)
	if err != nil {
		return BindRequest{}, fmt.Errorf("%w: %w", ErrInvalidBindRequest, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return BindRequest{}, fmt.Errorf("%w: body must be an object", ErrInvalidBindRequest)
	}
	required := [...]string{
		"local_protocol_version",
		"client_instance_id",
		"session_id",
		"workspace_id",
		"client_class",
	}
	allowed := make(map[string]struct{}, len(required)+1)
	for _, field := range required {
		allowed[field] = struct{}{}
		raw, present := members[field]
		if !present || bytes.Equal(raw, []byte("null")) {
			return BindRequest{}, fmt.Errorf(
				"%w: missing or null %q",
				ErrInvalidBindRequest,
				field,
			)
		}
	}
	allowed["agent_proof"] = struct{}{}
	for field := range members {
		if _, ok := allowed[field]; !ok {
			return BindRequest{}, fmt.Errorf(
				"%w: unknown field %q",
				ErrInvalidBindRequest,
				field,
			)
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var wire bindWire
	if err := decoder.Decode(&wire); err != nil {
		return BindRequest{}, fmt.Errorf("%w: %w", ErrInvalidBindRequest, err)
	}

	clientInstanceID := domain.UUIDv7(wire.ClientInstanceID)
	sessionID := domain.UUIDv7(wire.SessionID)
	workspaceID := domain.UUIDv4(wire.WorkspaceID)
	if !clientInstanceID.Valid() || !sessionID.Valid() || !workspaceID.Valid() {
		return BindRequest{}, fmt.Errorf(
			"%w: invalid client, session, or workspace identifier",
			ErrInvalidBindRequest,
		)
	}
	var class ClientClass
	switch wire.ClientClass {
	case "operator":
		class = ClassOperator
		if _, supplied := members["agent_proof"]; supplied {
			return BindRequest{}, fmt.Errorf(
				"%w: operator bind must not contain agent_proof",
				ErrInvalidBindRequest,
			)
		}
	case "agent":
		class = ClassAgent
		proof, supplied := members["agent_proof"]
		if !supplied ||
			bytes.Equal(proof, []byte("null")) ||
			len(proof) < 2 ||
			proof[0] != '{' {
			return BindRequest{}, fmt.Errorf(
				"%w: agent bind requires an object agent_proof",
				ErrInvalidBindRequest,
			)
		}
	default:
		return BindRequest{}, fmt.Errorf(
			"%w: unknown client_class %q",
			ErrInvalidBindRequest,
			wire.ClientClass,
		)
	}
	return BindRequest{
		ProtocolVersion:  wire.LocalProtocolVersion,
		ClientInstanceID: clientInstanceID,
		SessionID:        sessionID,
		WorkspaceID:      workspaceID,
		Class:            class,
		AgentProof:       bytes.Clone(wire.AgentProof),
	}, nil
}
