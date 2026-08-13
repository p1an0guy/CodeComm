package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
)

const localBindPath = "/local/v1/bind"

var (
	ErrInvalidOperatorDial = errors.New("ui: invalid operator client options")
	ErrStatusClosed        = ipc.ErrClientClosed
	ErrStatusConnection    = ipc.ErrClientConnectionLost
	ErrStatusProtocol      = errors.New("ui: invalid status protocol response")
)

type OperatorDialOptions struct {
	Endpoint         ipc.Endpoint
	ClientInstanceID domain.UUIDv7
	SessionID        domain.UUIDv7
	WorkspaceID      domain.UUIDv4
}

// OperatorClient owns one operator-bound local connection and transparently
// rebinds read-only status requests after a daemon restart.
type OperatorClient struct {
	requestMu sync.Mutex
	stateMu   sync.Mutex

	options   OperatorDialOptions
	transport *ipc.Client
	closed    bool
}

func DialOperator(
	ctx context.Context,
	options OperatorDialOptions,
) (*OperatorClient, error) {
	if ctx == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() {
		return nil, ErrInvalidOperatorDial
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.ClientInstanceID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("ui: generate client instance ID: %w", err)
		}
		options.ClientInstanceID = domain.UUIDv7(generated.String())
	}
	if !options.ClientInstanceID.Valid() {
		return nil, ErrInvalidOperatorDial
	}
	transport, err := dialOperatorTransport(ctx, options)
	if err != nil {
		return nil, err
	}
	return &OperatorClient{
		options:   options,
		transport: transport,
	}, nil
}

// Status returns one validated status snapshot.
func (client *OperatorClient) Status(
	ctx context.Context,
) (Snapshot, error) {
	if client == nil || ctx == nil {
		return Snapshot{}, ErrInvalidOperatorDial
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	transport, err := client.currentTransport()
	if errors.Is(err, ErrStatusConnection) {
		transport, err = client.reconnect(ctx, nil)
	}
	if err != nil {
		return Snapshot{}, err
	}
	if !transport.Usable() {
		transport, err = client.reconnect(ctx, transport)
		if err != nil {
			return Snapshot{}, err
		}
	}
	response, err := transport.Exchange(
		ctx,
		http.MethodGet,
		statusQueryPath,
		nil,
	)
	if errors.Is(err, ipc.ErrClientConnectionLost) {
		transport, reconnectErr := client.reconnect(ctx, transport)
		if reconnectErr != nil {
			return Snapshot{}, reconnectErr
		}
		response, err = transport.Exchange(
			ctx,
			http.MethodGet,
			statusQueryPath,
			nil,
		)
	}
	if err != nil {
		if errors.Is(err, ipc.ErrClientProtocol) {
			return Snapshot{}, fmt.Errorf("%w: %v", ErrStatusProtocol, err)
		}
		return Snapshot{}, err
	}
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, ErrStatusProtocol
	}
	return decodeStatusResponse(response.Body)
}

func (client *OperatorClient) currentTransport() (*ipc.Client, error) {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	if client.closed {
		return nil, ErrStatusClosed
	}
	if client.transport == nil {
		return nil, ErrStatusConnection
	}
	return client.transport, nil
}

func (client *OperatorClient) reconnect(
	ctx context.Context,
	failed *ipc.Client,
) (*ipc.Client, error) {
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil, ErrStatusClosed
	}
	if client.transport != failed &&
		client.transport != nil &&
		client.transport.Usable() {
		current := client.transport
		client.stateMu.Unlock()
		return current, nil
	}
	client.transport = nil
	options := client.options
	client.stateMu.Unlock()
	if failed != nil {
		_ = failed.Close()
	}

	replacement, err := dialOperatorTransport(ctx, options)
	if err != nil {
		return nil, err
	}
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		_ = replacement.Close()
		return nil, ErrStatusClosed
	}
	client.transport = replacement
	client.stateMu.Unlock()
	return replacement, nil
}

// Close drops the current connection. It is concurrent and idempotent.
func (client *OperatorClient) Close() error {
	if client == nil {
		return ErrInvalidOperatorDial
	}
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil
	}
	client.closed = true
	transport := client.transport
	client.transport = nil
	client.stateMu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func dialOperatorTransport(
	ctx context.Context,
	options OperatorDialOptions,
) (*ipc.Client, error) {
	transport, err := ipc.DialClient(ctx, options.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("ui: dial local daemon: %w", err)
	}
	body, err := canonicalOperatorJSON(map[string]any{
		"local_protocol_version": ipc.LocalProtocolVersion,
		"client_instance_id":     options.ClientInstanceID,
		"session_id":             options.SessionID,
		"workspace_id":           options.WorkspaceID,
		"client_class":           "operator",
	})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	response, err := transport.Exchange(
		ctx,
		http.MethodPost,
		localBindPath,
		body,
	)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	if err := decodeOperatorBind(response.Body, options); err != nil {
		_ = transport.Close()
		return nil, err
	}
	return transport, nil
}

type operatorBindWire struct {
	LocalProtocolVersion uint32 `json:"local_protocol_version"`
	ClientInstanceID     string `json:"client_instance_id"`
	SessionID            string `json:"session_id"`
	WorkspaceID          string `json:"workspace_id"`
	ClientClass          string `json:"client_class"`
}

func decodeOperatorBind(
	input []byte,
	options OperatorDialOptions,
) error {
	var wire operatorBindWire
	if err := decodeStatusObject(input, &wire); err != nil ||
		wire.LocalProtocolVersion != ipc.LocalProtocolVersion ||
		wire.ClientInstanceID != string(options.ClientInstanceID) ||
		wire.SessionID != string(options.SessionID) ||
		wire.WorkspaceID != string(options.WorkspaceID) ||
		wire.ClientClass != "operator" {
		return ErrStatusProtocol
	}
	return nil
}

func decodeStatusResponse(input []byte) (Snapshot, error) {
	var snapshot Snapshot
	if err := decodeStatusObject(input, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrStatusProtocol, err)
	}
	return snapshot, nil
}

func decodeStatusObject(input []byte, output any) error {
	if output == nil || len(input) == 0 {
		return ErrStatusProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrStatusProtocol
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrStatusProtocol
	}
	return nil
}

func canonicalOperatorJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}
