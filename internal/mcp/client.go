// Package mcp exposes CodeComm's fixed agent tool surface over stdio MCP.
// It reaches the daemon only through one authenticated local IPC connection.
package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
)

const (
	localBindPath         = "/local/v1/bind"
	localLaunchAckPath    = "/local/v1/agent-launch/ack"
	localAgentSessionPath = "/local/v1/query/agent-session"
	localContextPath      = "/local/v1/query/context"
	localTasksPath        = "/local/v1/query/tasks"
	localCommandsPath     = "/local/v1/commands"

	reconnectTimeout      = 10 * time.Second
	reconnectInitialDelay = 25 * time.Millisecond
	reconnectMaximumDelay = 500 * time.Millisecond
)

var (
	ErrInvalidOptions = errors.New("mcp: invalid adapter options")
	ErrClosed         = ipc.ErrClientClosed
	ErrConnectionLost = ipc.ErrClientConnectionLost
	ErrLocalProtocol  = ipc.ErrClientProtocol
)

// DialOptions fixes the daemon endpoint and agent proof for one adapter
// process. Exactly one proof field must be set.
type DialOptions struct {
	Endpoint         ipc.Endpoint
	ClientInstanceID domain.UUIDv7
	SessionID        domain.UUIDv7
	WorkspaceID      domain.UUIDv4
	LaunchSelector   string
	ResumeCapability []byte
}

// LocalError is a bounded daemon error safe to return as an MCP tool error.
type LocalError = ipc.ClientError

type localTransport interface {
	Exchange(
		context.Context,
		string,
		string,
		[]byte,
	) (ipc.ClientResponse, error)
	Close() error
	Usable() bool
}

type localDialer func(context.Context, ipc.Endpoint) (localTransport, error)

// Client owns one bound local IPC transport and its in-memory resume
// capability.
type Client struct {
	requestMu sync.Mutex
	stateMu   sync.Mutex

	transport localTransport
	endpoint  ipc.Endpoint
	dial      localDialer
	closed    bool

	clientInstanceID domain.UUIDv7
	sessionID        domain.UUIDv7
	workspaceID      domain.UUIDv4
	resumeCapability [32]byte
	hasResume        bool
}

type proofKind uint8

const (
	launchProof proofKind = iota + 1
	resumeProof
)

type dialProof struct {
	kind    proofKind
	encoded string
}

// Dial authenticates, binds as an agent, and acknowledges a newly issued
// resume capability before returning.
func Dial(ctx context.Context, options DialOptions) (*Client, error) {
	if ctx == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() {
		return nil, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientInstanceID := options.ClientInstanceID
	if clientInstanceID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("mcp: generate client instance ID: %w", err)
		}
		clientInstanceID = domain.UUIDv7(generated.String())
	}
	if !clientInstanceID.Valid() {
		return nil, ErrInvalidOptions
	}
	proof, err := validateDialProof(options)
	if err != nil {
		return nil, err
	}

	dialer := func(
		ctx context.Context,
		endpoint ipc.Endpoint,
	) (localTransport, error) {
		return ipc.DialClient(ctx, endpoint)
	}
	transport, err := dialer(ctx, options.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcp: dial local daemon: %w", err)
	}
	client := &Client{
		transport:        transport,
		endpoint:         options.Endpoint,
		dial:             dialer,
		clientInstanceID: clientInstanceID,
		sessionID:        options.SessionID,
		workspaceID:      options.WorkspaceID,
	}
	if proof.kind == resumeProof {
		copy(client.resumeCapability[:], options.ResumeCapability)
		client.hasResume = true
	}
	if err := client.bindTransport(ctx, transport, proof); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}

func validateDialProof(options DialOptions) (dialProof, error) {
	hasLaunch := options.LaunchSelector != ""
	hasResume := len(options.ResumeCapability) != 0
	if hasLaunch == hasResume {
		return dialProof{}, ErrInvalidOptions
	}
	if hasLaunch {
		selector, err := codec.DecodeBase64URLExact(
			options.LaunchSelector,
			32,
		)
		if err != nil {
			return dialProof{}, ErrInvalidOptions
		}
		clear(selector)
		return dialProof{
			kind:    launchProof,
			encoded: options.LaunchSelector,
		}, nil
	}
	if len(options.ResumeCapability) != 32 {
		return dialProof{}, ErrInvalidOptions
	}
	return dialProof{
		kind:    resumeProof,
		encoded: codec.EncodeBase64URL(options.ResumeCapability),
	}, nil
}

func (client *Client) bindTransport(
	ctx context.Context,
	transport localTransport,
	proof dialProof,
) error {
	if transport == nil {
		return ErrConnectionLost
	}
	proofObject := map[string]any{}
	switch proof.kind {
	case launchProof:
		proofObject["launch_selector"] = proof.encoded
	case resumeProof:
		proofObject["resume_capability"] = proof.encoded
	default:
		return ErrInvalidOptions
	}
	body, err := canonicalJSON(map[string]any{
		"local_protocol_version": ipc.LocalProtocolVersion,
		"client_instance_id":     client.clientInstanceID,
		"session_id":             client.sessionID,
		"workspace_id":           client.workspaceID,
		"client_class":           "agent",
		"agent_proof":            proofObject,
	})
	if err != nil {
		return fmt.Errorf("mcp: encode local bind: %w", err)
	}
	response, err := transport.Exchange(
		ctx,
		http.MethodPost,
		localBindPath,
		body,
	)
	if err != nil {
		return err
	}
	var capability []byte
	defer func() {
		clear(capability)
	}()
	if proof.kind == launchProof {
		capability, err = decodeBindResponse(
			response,
			client.clientInstanceID,
			client.sessionID,
			client.workspaceID,
			true,
		)
	} else {
		_, err = decodeBindResponse(
			response,
			client.clientInstanceID,
			client.sessionID,
			client.workspaceID,
			false,
		)
	}
	if err != nil {
		return err
	}
	if proof.kind != launchProof {
		return nil
	}

	acknowledgement, err := canonicalJSON(map[string]any{
		"resume_capability": codec.EncodeBase64URL(capability),
	})
	if err != nil {
		return fmt.Errorf("mcp: encode launch acknowledgement: %w", err)
	}
	response, err = transport.Exchange(
		ctx,
		http.MethodPost,
		localLaunchAckPath,
		acknowledgement,
	)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent ||
		len(response.Body) != 0 {
		return ErrLocalProtocol
	}
	client.stateMu.Lock()
	copy(client.resumeCapability[:], capability)
	client.hasResume = true
	client.stateMu.Unlock()
	return nil
}

type bindResponseWire struct {
	LocalProtocolVersion uint32  `json:"local_protocol_version"`
	ClientInstanceID     string  `json:"client_instance_id"`
	SessionID            string  `json:"session_id"`
	WorkspaceID          string  `json:"workspace_id"`
	ClientClass          string  `json:"client_class"`
	ResumeCapability     *string `json:"resume_capability,omitempty"`
}

func decodeBindResponse(
	response ipc.ClientResponse,
	clientInstanceID domain.UUIDv7,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	expectCapability bool,
) ([]byte, error) {
	if response.StatusCode != http.StatusOK {
		return nil, ErrLocalProtocol
	}
	var wire bindResponseWire
	if err := decodeStrictObject(response.Body, &wire); err != nil {
		return nil, err
	}
	if wire.LocalProtocolVersion != ipc.LocalProtocolVersion ||
		wire.ClientInstanceID != string(clientInstanceID) ||
		wire.SessionID != string(sessionID) ||
		wire.WorkspaceID != string(workspaceID) ||
		wire.ClientClass != "agent" ||
		expectCapability != (wire.ResumeCapability != nil) {
		return nil, ErrLocalProtocol
	}
	if !expectCapability {
		return nil, nil
	}
	capability, err := codec.DecodeBase64URLExact(
		*wire.ResumeCapability,
		32,
	)
	if err != nil {
		return nil, ErrLocalProtocol
	}
	return capability, nil
}

// Close drops the bound connection and clears the in-memory resume
// capability. It is safe to call concurrently and repeatedly.
func (client *Client) Close() error {
	if client == nil {
		return ErrInvalidOptions
	}
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil
	}
	client.closed = true
	transport := client.transport
	client.transport = nil
	clear(client.resumeCapability[:])
	client.hasResume = false
	client.stateMu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func (client *Client) get(
	ctx context.Context,
	path string,
	output any,
) error {
	response, err := client.exchange(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return ErrLocalProtocol
	}
	return decodeStrictObject(response.Body, output)
}

func (client *Client) post(
	ctx context.Context,
	path string,
	input any,
	output any,
) error {
	body, err := canonicalJSON(input)
	if err != nil {
		return fmt.Errorf("mcp: encode local command: %w", err)
	}
	response, err := client.exchange(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return ErrLocalProtocol
	}
	return decodeStrictObject(response.Body, output)
}

func (client *Client) exchange(
	ctx context.Context,
	method, path string,
	body []byte,
) (ipc.ClientResponse, error) {
	if client == nil || ctx == nil || !validLocalPath(path) {
		return ipc.ClientResponse{}, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return ipc.ClientResponse{}, err
	}
	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	transport, err := client.currentTransport()
	if errors.Is(err, ErrConnectionLost) {
		transport, err = client.reconnect(ctx, nil)
	}
	if err != nil {
		return ipc.ClientResponse{}, err
	}
	if !transport.Usable() {
		transport, err = client.reconnect(ctx, transport)
		if err != nil {
			return ipc.ClientResponse{}, err
		}
	}
	response, err := transport.Exchange(ctx, method, path, body)
	if errors.Is(err, ipc.ErrClientConnectionLost) {
		transport, reconnectErr := client.reconnect(ctx, transport)
		if reconnectErr != nil {
			return ipc.ClientResponse{}, reconnectErr
		}
		response, err = transport.Exchange(ctx, method, path, body)
	}
	return response, err
}

func (client *Client) currentTransport() (localTransport, error) {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	if client.closed {
		return nil, ErrClosed
	}
	if client.transport == nil {
		return nil, ErrConnectionLost
	}
	return client.transport, nil
}

func (client *Client) reconnect(
	ctx context.Context,
	failed localTransport,
) (localTransport, error) {
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil, ErrClosed
	}
	if client.transport != nil &&
		client.transport != failed &&
		client.transport.Usable() {
		current := client.transport
		client.stateMu.Unlock()
		return current, nil
	}
	if !client.hasResume || client.dial == nil {
		client.stateMu.Unlock()
		return nil, ErrConnectionLost
	}
	var capability [32]byte
	copy(capability[:], client.resumeCapability[:])
	endpoint := client.endpoint
	dialer := client.dial
	clientInstanceID := client.clientInstanceID
	client.transport = nil
	client.stateMu.Unlock()
	defer clear(capability[:])
	if failed != nil {
		_ = failed.Close()
	}

	reconnectContext, cancel := context.WithTimeout(ctx, reconnectTimeout)
	defer cancel()
	proof := dialProof{
		kind:    resumeProof,
		encoded: codec.EncodeBase64URL(capability[:]),
	}
	delay := reconnectInitialDelay
	var attempt uint64
	var lastErr error
	for {
		replacement, err := dialer(reconnectContext, endpoint)
		if err == nil {
			err = client.bindTransport(
				reconnectContext,
				replacement,
				proof,
			)
		}
		if err == nil {
			client.stateMu.Lock()
			if client.closed {
				client.stateMu.Unlock()
				_ = replacement.Close()
				return nil, ErrClosed
			}
			client.transport = replacement
			client.stateMu.Unlock()
			return replacement, nil
		}
		lastErr = err
		if replacement != nil {
			_ = replacement.Close()
		}
		if reconnectContext.Err() != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf(
				"%w: reconnect timed out: %v",
				ErrConnectionLost,
				lastErr,
			)
		}
		if !retryableReconnectError(err) {
			return nil, err
		}
		timer := time.NewTimer(jitteredReconnectDelay(
			delay,
			clientInstanceID,
			attempt,
		))
		attempt++
		select {
		case <-timer.C:
		case <-reconnectContext.Done():
			if !timer.Stop() {
				<-timer.C
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf(
				"%w: reconnect timed out: %v",
				ErrConnectionLost,
				lastErr,
			)
		}
		if delay < reconnectMaximumDelay {
			delay *= 2
			if delay > reconnectMaximumDelay {
				delay = reconnectMaximumDelay
			}
		}
	}
}

func jitteredReconnectDelay(
	base time.Duration,
	clientInstanceID domain.UUIDv7,
	attempt uint64,
) time.Duration {
	digester := sha256.New()
	_, _ = digester.Write([]byte(clientInstanceID))
	var encodedAttempt [8]byte
	binary.BigEndian.PutUint64(encodedAttempt[:], attempt)
	_, _ = digester.Write(encodedAttempt[:])
	sum := digester.Sum(nil)
	percent := 80 + binary.BigEndian.Uint64(sum[:8])%41
	return base * time.Duration(percent) / 100
}

func retryableReconnectError(err error) bool {
	if err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrClosed) ||
		errors.Is(err, ErrInvalidOptions) ||
		errors.Is(err, ErrLocalProtocol) {
		return false
	}
	var localError *ipc.ClientError
	if errors.As(err, &localError) {
		return localError.Retryable ||
			localError.Code == "local_bind_rejected"
	}
	return true
}

func validLocalPath(path string) bool {
	switch path {
	case localBindPath,
		localLaunchAckPath,
		localAgentSessionPath,
		localContextPath,
		localTasksPath,
		localCommandsPath:
		return true
	default:
		return false
	}
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func decodeStrictObject(input []byte, output any) error {
	if output == nil || len(input) == 0 {
		return ErrLocalProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrLocalProtocol
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrLocalProtocol
	}
	return nil
}
