package pairinghttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

var (
	ErrInvalidClient           = errors.New("pairing HTTP: invalid client")
	ErrClientClosed            = errors.New("pairing HTTP: client closed")
	ErrPeerMismatch            = errors.New("pairing HTTP: peer does not match invite")
	ErrAttemptConflict         = errors.New("pairing HTTP: connection bound to another attempt")
	ErrConfirmationUnavailable = errors.New("pairing HTTP: request not acknowledged")
	ErrDecisionConflict        = errors.New("pairing HTTP: confirmation decision conflicts")
	ErrResponseProtocol        = errors.New("pairing HTTP: invalid response")
	ErrResponseTooLarge        = errors.New("pairing HTTP: response too large")
)

// RemoteError is a bounded structured problem returned by the pinned peer.
type RemoteError struct {
	Type          string
	Title         string
	Status        int
	Code          string
	CorrelationID string
	Retryable     bool
	Detail        string
}

// RequestResult is the exact durable acknowledgment plus the joiner-derived
// SAS that the local operator must compare with the inviter.
type RequestResult struct {
	Acknowledgment pairing.RequestAcknowledgment
	SAS            string
}

func (problem *RemoteError) Error() string {
	if problem == nil {
		return "pairing HTTP: remote error"
	}
	return fmt.Sprintf(
		"pairing HTTP: remote error %s (%d)",
		problem.Code,
		problem.Status,
	)
}

// Client owns one exporter-bound pairing HTTP/2 connection.
type Client struct {
	operationMu         sync.Mutex
	mu                  sync.Mutex
	http2               *http2.ClientConn
	raw                 *tls.Conn
	peer                transport.IdentityCertificate
	exporter            [pairing.ExporterSize]byte
	request             []byte
	confirmation        []byte
	attemptID           domain.UUIDv7
	requestDigest       [sha256.Size]byte
	requestAcknowledged bool
	closed              bool
}

type clientConnection struct {
	http2    *http2.ClientConn
	raw      *tls.Conn
	peer     transport.IdentityCertificate
	exporter [pairing.ExporterSize]byte
}

// OpenClient handshakes one TLS connection and starts an explicit HTTP/2
// client without adding the public-Web "h2" ALPN. The caller must construct
// the connection with transport.NewClientTLSConfig and the invite-pinned peer
// verifier. OpenClient takes ownership of connection on every return path.
func OpenClient(
	ctx context.Context,
	connection *tls.Conn,
) (_ *Client, err error) {
	if connection == nil {
		return nil, ErrInvalidClient
	}
	owned := true
	defer func() {
		if owned {
			_ = connection.Close()
		}
	}()
	if ctx == nil {
		return nil, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handshakeContext, cancel := context.WithTimeout(
		ctx,
		transport.HandshakeTimeout,
	)
	err = connection.HandshakeContext(handshakeContext)
	handshakeContextErr := handshakeContext.Err()
	cancel()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(handshakeContextErr, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("%w: TLS handshake", ErrInvalidClient)
	}
	peer, exporter, err := pairingConnectionState(
		connection.ConnectionState(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClient, err)
	}
	defer clear(exporter)
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear TLS deadline", ErrInvalidClient)
	}

	httpTransport := &http2.Transport{
		DisableCompression:         true,
		MaxHeaderListSize:          HeaderMaxBytes,
		MaxReadFrameSize:           16 << 10,
		MaxDecoderHeaderTableSize:  4 << 10,
		MaxEncoderHeaderTableSize:  4 << 10,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout:            ConnectionIdle,
		ReadIdleTimeout:            StreamNoProgress,
		PingTimeout:                RequestHeaderTimeout,
		WriteByteTimeout:           StreamNoProgress,
	}
	httpConnection, err := httpTransport.NewClientConn(connection)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize HTTP/2", ErrInvalidClient)
	}
	client := &Client{
		http2: httpConnection,
		raw:   connection,
		peer:  peer,
	}
	copy(client.exporter[:], exporter)
	owned = false
	return client, nil
}

// Request sends or same-connection retries the exact exporter-bound pairing
// request. Callers waiting at the SAS screen must retry before the 120-second
// idle deadline; a replacement connection intentionally cannot resume it.
func (client *Client) Request(
	ctx context.Context,
	invite pairing.SignedInvite,
	core pairing.CanonicalRequestCore,
) (RequestResult, error) {
	if ctx == nil {
		return RequestResult{}, ErrInvalidClient
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return RequestResult{}, err
	}
	client.mu.Lock()
	if client.closed || client.http2 == nil {
		client.mu.Unlock()
		return RequestResult{}, ErrClientClosed
	}
	connection := clientConnection{
		http2: client.http2,
		raw:   client.raw,
		peer:  client.peer,
	}
	copy(connection.exporter[:], client.exporter[:])
	inviteValue := invite.Invite()
	peerErr := connection.peer.VerifyIdentity(
		inviteValue.SessionID,
		inviteValue.RecoveryGeneration,
		inviteValue.InviterDeviceID,
		inviteValue.InviterIdentityPublicKey[:],
	)
	clear(inviteValue.Secret[:])
	if peerErr != nil {
		client.mu.Unlock()
		clear(connection.exporter[:])
		return RequestResult{}, ErrPeerMismatch
	}
	request, err := pairing.BuildRequest(invite, core, connection.exporter[:])
	if err != nil {
		client.mu.Unlock()
		clear(connection.exporter[:])
		return RequestResult{}, err
	}
	verified, err := request.Verify(invite, connection.exporter[:])
	if err != nil {
		client.mu.Unlock()
		clear(connection.exporter[:])
		return RequestResult{}, err
	}
	canonical := request.CanonicalBytes()
	if len(client.request) == 0 {
		client.request = bytes.Clone(canonical)
	} else if !bytes.Equal(client.request, canonical) {
		client.mu.Unlock()
		clear(connection.exporter[:])
		clear(canonical)
		return RequestResult{}, ErrAttemptConflict
	}
	client.mu.Unlock()
	defer clear(connection.exporter[:])
	defer clear(canonical)
	body, err := client.post(
		ctx,
		connection,
		RequestPath,
		canonical,
	)
	if err != nil {
		if client.isClosed() {
			return RequestResult{}, ErrClientClosed
		}
		return RequestResult{}, err
	}
	acknowledgment, err := pairing.ParseRequestAcknowledgment(body)
	if err != nil {
		return RequestResult{}, ErrResponseProtocol
	}
	coreValue := core.Value()
	if acknowledgment.AttemptID != coreValue.AttemptID ||
		acknowledgment.RequestDigest != request.Digest() ||
		acknowledgment.InviteDigest != invite.Digest() {
		return RequestResult{}, ErrResponseProtocol
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.http2 != connection.http2 {
		return RequestResult{}, ErrClientClosed
	}
	client.attemptID = acknowledgment.AttemptID
	client.requestDigest = acknowledgment.RequestDigest
	client.requestAcknowledged = true
	return RequestResult{
		Acknowledgment: acknowledgment,
		SAS:            verified.SAS(),
	}, nil
}

// Confirm sends the joiner's irreversible SAS decision or polls its exact
// result on the same exporter-bound connection.
func (client *Client) Confirm(
	ctx context.Context,
	confirmation pairing.Confirmation,
) (pairing.ConfirmationResult, error) {
	if ctx == nil {
		return pairing.ConfirmationResult{}, ErrInvalidClient
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return pairing.ConfirmationResult{}, err
	}
	client.mu.Lock()
	if client.closed || client.http2 == nil {
		client.mu.Unlock()
		return pairing.ConfirmationResult{}, ErrClientClosed
	}
	if !client.requestAcknowledged {
		client.mu.Unlock()
		return pairing.ConfirmationResult{}, ErrConfirmationUnavailable
	}
	canonical := confirmation.CanonicalBytes()
	if len(canonical) == 0 {
		client.mu.Unlock()
		return pairing.ConfirmationResult{}, pairing.ErrInvalidPairingMessage
	}
	if confirmation.AttemptID != client.attemptID ||
		confirmation.RequestDigest != client.requestDigest {
		client.mu.Unlock()
		clear(canonical)
		return pairing.ConfirmationResult{}, ErrAttemptConflict
	}
	if len(client.confirmation) == 0 {
		client.confirmation = bytes.Clone(canonical)
	} else if !bytes.Equal(client.confirmation, canonical) {
		client.mu.Unlock()
		clear(canonical)
		return pairing.ConfirmationResult{}, ErrDecisionConflict
	}
	connection := clientConnection{
		http2: client.http2,
		raw:   client.raw,
		peer:  client.peer,
	}
	copy(connection.exporter[:], client.exporter[:])
	client.mu.Unlock()
	defer clear(connection.exporter[:])
	defer clear(canonical)
	body, err := client.post(ctx, connection, ConfirmPath, canonical)
	if err != nil {
		if client.isClosed() {
			return pairing.ConfirmationResult{}, ErrClientClosed
		}
		return pairing.ConfirmationResult{}, err
	}
	result, err := pairing.ParseConfirmationResult(body)
	if err != nil ||
		result.AttemptID != confirmation.AttemptID ||
		result.RequestDigest != confirmation.RequestDigest ||
		!confirmationStatusMatchesDecision(
			confirmation.Confirmed,
			result.Status,
		) {
		return pairing.ConfirmationResult{}, ErrResponseProtocol
	}
	return result, nil
}

func confirmationStatusMatchesDecision(
	confirmed bool,
	status pairing.ConfirmationStatus,
) bool {
	if confirmed {
		return true
	}
	switch status {
	case pairing.StatusDeclined, pairing.StatusExpired, pairing.StatusRevoked:
		return true
	default:
		return false
	}
}

func (client *Client) post(
	ctx context.Context,
	connection clientConnection,
	path string,
	body []byte,
) ([]byte, error) {
	if connection.http2 == nil ||
		connection.raw == nil ||
		len(body) == 0 ||
		len(body) > pairing.MaxPairingMessageBytes {
		return nil, ErrInvalidClient
	}
	callContext, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		callContext,
		http.MethodPost,
		"https://codecomm.peer"+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, ErrInvalidClient
	}
	request.Header.Set(
		"Accept",
		"application/json, application/problem+json",
	)
	request.Header.Set("Content-Type", "application/json")
	if err := connection.raw.SetReadDeadline(
		time.Now().Add(StreamNoProgress),
	); err != nil {
		return nil, fmt.Errorf("%w: arm response deadline", ErrResponseProtocol)
	}
	defer func() {
		_ = connection.raw.SetReadDeadline(time.Time{})
	}()
	response, err := connection.http2.RoundTrip(request)
	if err != nil {
		if callContext.Err() != nil {
			return nil, callContext.Err()
		}
		return nil, fmt.Errorf("%w: round trip", ErrResponseProtocol)
	}
	if err := validateResponseTLS(response, connection); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		if !validContentType(response.Header, "application/json") {
			_ = response.Body.Close()
			return nil, ErrResponseProtocol
		}
		return readBoundedResponse(response, connection.raw)
	}
	if !validContentType(response.Header, "application/problem+json") {
		_ = response.Body.Close()
		return nil, ErrResponseProtocol
	}
	encoded, err := readBoundedResponse(response, connection.raw)
	if err != nil {
		return nil, err
	}
	problem, err := parseRemoteProblem(encoded, response.StatusCode)
	if err != nil {
		return nil, err
	}
	return nil, problem
}

func validateResponseTLS(
	response *http.Response,
	connection clientConnection,
) error {
	if response == nil || response.TLS == nil {
		return ErrResponseProtocol
	}
	peer, exporter, err := pairingConnectionState(*response.TLS)
	if err != nil {
		return ErrResponseProtocol
	}
	defer clear(exporter)
	if peer.Binding != connection.peer.Binding ||
		!bytes.Equal(peer.PublicKey, connection.peer.PublicKey) ||
		subtle.ConstantTimeCompare(exporter, connection.exporter[:]) != 1 {
		return ErrResponseProtocol
	}
	return nil
}

func (client *Client) isClosed() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closed || client.http2 == nil
}

func readBoundedResponse(
	response *http.Response,
	connection *tls.Conn,
) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, ErrResponseProtocol
	}
	defer response.Body.Close()
	if response.ContentLength == 0 || connection == nil {
		return nil, ErrResponseProtocol
	}
	if response.ContentLength > pairing.MaxPairingMessageBytes {
		return nil, ErrResponseTooLarge
	}
	refreshDeadline := func() error {
		return connection.SetReadDeadline(
			time.Now().Add(StreamNoProgress),
		)
	}
	if err := refreshDeadline(); err != nil {
		return nil, ErrResponseProtocol
	}
	encoded, err := io.ReadAll(&progressReader{
		reader: io.LimitReader(
			response.Body,
			pairing.MaxPairingMessageBytes+1,
		),
		refresh: refreshDeadline,
	})
	if err != nil {
		return nil, ErrResponseProtocol
	}
	if len(encoded) == 0 {
		return nil, ErrResponseProtocol
	}
	if len(encoded) > pairing.MaxPairingMessageBytes {
		return nil, ErrResponseTooLarge
	}
	return encoded, nil
}

type remoteProblemWire struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
	Retryable     bool   `json:"retryable"`
	Detail        string `json:"detail,omitempty"`
}

func parseRemoteProblem(
	encoded []byte,
	responseStatus int,
) (*RemoteError, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return nil, ErrResponseProtocol
	}
	required := [...]string{
		"type",
		"title",
		"status",
		"code",
		"correlation_id",
		"retryable",
	}
	for _, field := range required {
		if _, exists := members[field]; !exists {
			return nil, ErrResponseProtocol
		}
	}
	if len(members) != len(required) {
		if _, detail := members["detail"]; !detail ||
			len(members) != len(required)+1 {
			return nil, ErrResponseProtocol
		}
	}
	var wire remoteProblemWire
	if err := json.Unmarshal(encoded, &wire); err != nil ||
		wire.Status != responseStatus ||
		wire.Status < 400 ||
		wire.Status > 599 ||
		wire.Code == "" ||
		wire.Title == "" ||
		wire.CorrelationID == "" ||
		wire.Type != "urn:codecomm:problem:"+wire.Code {
		return nil, ErrResponseProtocol
	}
	return &RemoteError{
		Type: wire.Type, Title: wire.Title, Status: wire.Status,
		Code: wire.Code, CorrelationID: wire.CorrelationID,
		Retryable: wire.Retryable, Detail: wire.Detail,
	}, nil
}

// Close ends the pairing connection and clears its exporter.
func (client *Client) Close() error {
	if client == nil {
		return ErrInvalidClient
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return nil
	}
	client.closed = true
	clear(client.exporter[:])
	clear(client.request)
	client.request = nil
	clear(client.confirmation)
	client.confirmation = nil
	client.attemptID = ""
	clear(client.requestDigest[:])
	client.requestAcknowledged = false
	httpConnection := client.http2
	client.http2 = nil
	client.raw = nil
	client.mu.Unlock()
	if httpConnection == nil {
		return nil
	}
	return httpConnection.Close()
}
