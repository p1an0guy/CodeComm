package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	"github.com/ijonahch/codecomm/internal/store"
)

const localBindPath = "/local/v1/bind"

var (
	ErrInvalidOperatorDial = errors.New("ui: invalid operator client options")
	ErrStatusClosed        = ipc.ErrClientClosed
	ErrStatusConnection    = ipc.ErrClientConnectionLost
	ErrStatusProtocol      = errors.New("ui: invalid status protocol response")
	ErrCommandProtocol     = errors.New("ui: invalid command protocol response")
)

const maxOperatorReasonBytes = 1024

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

type SetVotersRequest struct {
	RequestID               domain.UUIDv7
	ExpectedVoterSetVersion uint64
	VoterDeviceIDs          []domain.DeviceID
}

type RevokePeerRequest struct {
	RequestID               domain.UUIDv7
	DeviceID                domain.DeviceID
	ExpectedEntityVersion   uint64
	ExpectedVoterSetVersion uint64
	VoterDeviceIDs          []domain.DeviceID
	Reason                  string
}

type CommandResult struct {
	EventID   domain.UUIDv7       `json:"event_id"`
	Status    store.OutcomeStatus `json:"status"`
	Code      string              `json:"code"`
	Result    json.RawMessage     `json:"result"`
	Duplicate bool                `json:"duplicate"`
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

// SetVoters commits the complete desired voter target using the caller's
// reviewed voter-set CAS.
func (client *OperatorClient) SetVoters(
	ctx context.Context,
	request SetVotersRequest,
) (CommandResult, error) {
	if client == nil ||
		ctx == nil ||
		request.ExpectedVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(request.ExpectedVoterSetVersion) ||
		!validVoterIDs(request.VoterDeviceIDs) {
		return CommandResult{}, ErrInvalidOperatorDial
	}
	requestID, err := operatorRequestID(request.RequestID)
	if err != nil {
		return CommandResult{}, err
	}
	body, err := operatorCommandBody(
		operatorcommand.OperationSetVoters,
		requestID,
		event.KindMembershipVoterSetChanged,
		string(client.options.SessionID),
		request.ExpectedVoterSetVersion,
		map[string]any{
			"voter_set": deviceIDStrings(request.VoterDeviceIDs),
		},
	)
	if err != nil {
		return CommandResult{}, err
	}
	return client.submitCommand(ctx, body)
}

// RevokePeer commits one membership revocation and its complete resulting
// voter target using both caller-reviewed CAS values.
func (client *OperatorClient) RevokePeer(
	ctx context.Context,
	request RevokePeerRequest,
) (CommandResult, error) {
	if client == nil ||
		ctx == nil ||
		!request.DeviceID.Valid() ||
		request.ExpectedEntityVersion < 1 ||
		!domain.ValidUnsignedInteger(request.ExpectedEntityVersion) ||
		request.ExpectedVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(request.ExpectedVoterSetVersion) ||
		len(request.Reason) < 1 ||
		len(request.Reason) > maxOperatorReasonBytes ||
		!utf8.ValidString(request.Reason) ||
		!validVoterIDs(request.VoterDeviceIDs) {
		return CommandResult{}, ErrInvalidOperatorDial
	}
	requestID, err := operatorRequestID(request.RequestID)
	if err != nil {
		return CommandResult{}, err
	}
	body, err := operatorCommandBody(
		operatorcommand.OperationRevokePeer,
		requestID,
		event.KindMembershipDeviceRevoked,
		string(request.DeviceID),
		request.ExpectedEntityVersion,
		map[string]any{
			"device_id":                  request.DeviceID,
			"expected_voter_set_version": request.ExpectedVoterSetVersion,
			"reason":                     request.Reason,
			"voter_set":                  deviceIDStrings(request.VoterDeviceIDs),
		},
	)
	if err != nil {
		return CommandResult{}, err
	}
	return client.submitCommand(ctx, body)
}

func (client *OperatorClient) submitCommand(
	ctx context.Context,
	body []byte,
) (CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	transport, err := client.currentTransport()
	if errors.Is(err, ErrStatusConnection) {
		transport, err = client.reconnect(ctx, nil)
	}
	if err != nil {
		return CommandResult{}, err
	}
	if !transport.Usable() {
		transport, err = client.reconnect(ctx, transport)
		if err != nil {
			return CommandResult{}, err
		}
	}
	response, err := transport.Exchange(
		ctx,
		http.MethodPost,
		commandPath,
		body,
	)
	if errors.Is(err, ipc.ErrClientConnectionLost) {
		transport, reconnectErr := client.reconnect(ctx, transport)
		if reconnectErr != nil {
			return CommandResult{}, reconnectErr
		}
		response, err = transport.Exchange(
			ctx,
			http.MethodPost,
			commandPath,
			body,
		)
	}
	if err != nil {
		if errors.Is(err, ipc.ErrClientProtocol) {
			return CommandResult{}, fmt.Errorf("%w: %v", ErrCommandProtocol, err)
		}
		return CommandResult{}, err
	}
	if response.StatusCode != http.StatusOK {
		return CommandResult{}, ErrCommandProtocol
	}
	return decodeCommandResponse(response.Body)
}

func operatorCommandBody(
	operation string,
	requestID domain.UUIDv7,
	kind event.Kind,
	entityID string,
	expectedEntityVersion uint64,
	payload map[string]any,
) ([]byte, error) {
	return canonicalOperatorJSON(map[string]any{
		"command": map[string]any{
			"actions":                 []any{},
			"entity_id":               entityID,
			"expected_entity_version": expectedEntityVersion,
			"kind":                    kind,
			"payload":                 payload,
			"rationale_summary":       "",
			"redaction": map[string]any{
				"fields_removed": []string{},
				"policy":         event.RedactionDefault,
			},
		},
		"operation":  operation,
		"request_id": requestID,
	})
}

func operatorRequestID(value domain.UUIDv7) (domain.UUIDv7, error) {
	if value.Valid() {
		return value, nil
	}
	if value != "" {
		return "", ErrInvalidOperatorDial
	}
	generated, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("ui: generate request ID: %w", err)
	}
	result := domain.UUIDv7(generated.String())
	if !result.Valid() {
		return "", ErrInvalidOperatorDial
	}
	return result, nil
}

func validVoterIDs(values []domain.DeviceID) bool {
	if !validVoterSetSize(len(values)) {
		return false
	}
	copyValues := append([]domain.DeviceID(nil), values...)
	sort.Slice(copyValues, func(left, right int) bool {
		return copyValues[left] < copyValues[right]
	})
	for index, value := range values {
		if !value.Valid() ||
			value != copyValues[index] ||
			index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

type commandResultWire struct {
	EventID   string          `json:"event_id"`
	Status    string          `json:"status"`
	Code      string          `json:"code"`
	Result    json.RawMessage `json:"result"`
	Duplicate bool            `json:"duplicate"`
}

func decodeCommandResponse(input []byte) (CommandResult, error) {
	var wire commandResultWire
	if err := decodeStatusObject(input, &wire); err != nil {
		return CommandResult{}, ErrCommandProtocol
	}
	result := CommandResult{
		EventID:   domain.UUIDv7(wire.EventID),
		Status:    store.OutcomeStatus(wire.Status),
		Code:      wire.Code,
		Result:    bytes.Clone(wire.Result),
		Duplicate: wire.Duplicate,
	}
	canonical, err := codec.CanonicalizeSignedObject(result.Result)
	if !result.EventID.Valid() ||
		(result.Status != store.OutcomeAccepted &&
			result.Status != store.OutcomeRejected) ||
		result.Code == "" ||
		err != nil ||
		!bytes.Equal(canonical, result.Result) {
		return CommandResult{}, ErrCommandProtocol
	}
	return result, nil
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
