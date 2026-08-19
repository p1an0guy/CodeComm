package contenthttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const (
	contentPeerAuthority       = "codecomm.peer"
	contentJSONMediaType       = "application/json"
	contentProblemMediaType    = "application/problem+json"
	ProblemResponseMaxBytes    = 64 << 10
	problemCodeMaxBytes        = 64
	problemTitleMaxBytes       = 256
	problemCorrelationMaxBytes = 64
	problemDetailMaxBytes      = 4 << 10
)

var (
	ErrInvalidClient    = errors.New("content HTTP: invalid client")
	ErrClientClosed     = errors.New("content HTTP: client closed")
	ErrPeerMismatch     = errors.New("content HTTP: peer device mismatch")
	ErrLineageMismatch  = errors.New("content HTTP: response lineage mismatch")
	ErrResponseProtocol = errors.New("content HTTP: invalid response protocol")
	ErrResponseTooLarge = errors.New("content HTTP: response too large")
)

// RemoteError is a validated, bounded problem response from the pinned peer.
type RemoteError struct {
	Type          string
	Title         string
	Status        int
	Code          string
	CorrelationID string
	Retryable     bool
	Detail        string
}

func (problem *RemoteError) Error() string {
	if problem == nil {
		return "content HTTP: remote error"
	}
	return fmt.Sprintf(
		"content HTTP: remote error %s (%d)",
		problem.Code,
		problem.Status,
	)
}

// Client owns one authenticated content-control HTTP/2 connection. Calls are
// deliberately serialized because stream progress is enforced with deadlines
// on the shared physical connection.
type Client struct {
	operationMu sync.Mutex
	mu          sync.Mutex

	http2       *http2.ClientConn
	raw         *tls.Conn
	peerBinding transport.ContentBinding
	peerDER     []byte

	lineageSet         bool
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	expiryTimer        *time.Timer
	expiryDone         chan struct{}
	closed             bool
}

type clientConnection struct {
	http2       *http2.ClientConn
	raw         *tls.Conn
	peerBinding transport.ContentBinding
	peerDER     []byte
}

// OpenClient performs a bounded content-plane handshake and starts an explicit
// HTTP/2 client. The caller must create connection with
// transport.NewClientTLSConfig configured with admission.Verify. Admission
// must be unique to this connection attempt. OpenClient takes ownership on
// every return path and independently pins the peer to expectedDeviceID.
func OpenClient(
	ctx context.Context,
	connection *tls.Conn,
	expectedDeviceID domain.DeviceID,
	admission *transport.ContentAdmissionRecorder,
) (_ *Client, err error) {
	return openClient(ctx, connection, expectedDeviceID, admission)
}

func openClient(
	ctx context.Context,
	connection *tls.Conn,
	expectedDeviceID domain.DeviceID,
	admission *transport.ContentAdmissionRecorder,
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
	if ctx == nil || !expectedDeviceID.Valid() || admission == nil {
		return nil, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	setupContext, cancel := context.WithTimeout(
		ctx,
		transport.HandshakeTimeout,
	)
	defer cancel()
	if err := connection.HandshakeContext(setupContext); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(setupContext.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("%w: TLS handshake", ErrInvalidClient)
	}
	state := connection.ConnectionState()
	binding, err := contentConnectionBinding(state)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClient, err)
	}
	if binding.DeviceID != expectedDeviceID {
		return nil, ErrPeerMismatch
	}
	serverCertificate, err := transport.ParseContentCertificate(
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: server certificate", ErrInvalidClient)
	}
	closeAfter, err := admission.Consume(serverCertificate)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: server admission lifetime",
			ErrInvalidClient,
		)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear TLS deadline", ErrInvalidClient)
	}

	expiryTimer := time.NewTimer(closeAfter)
	timerOwned := true
	defer func() {
		if timerOwned {
			expiryTimer.Stop()
		}
	}()
	httpConnection, err := newContentHTTP2ClientConn(setupContext, connection)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(setupContext.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("%w: initialize HTTP/2", ErrInvalidClient)
	}
	select {
	case <-expiryTimer.C:
		_ = httpConnection.Close()
		return nil, fmt.Errorf(
			"%w: server admission expired during setup",
			ErrInvalidClient,
		)
	default:
	}
	client := &Client{
		http2:       httpConnection,
		raw:         connection,
		peerBinding: binding,
		peerDER:     bytes.Clone(state.PeerCertificates[0].Raw),
		expiryTimer: expiryTimer,
		expiryDone:  make(chan struct{}),
	}
	go client.watchExpiry()
	timerOwned = false
	owned = false
	return client, nil
}

func (client *Client) watchExpiry() {
	client.mu.Lock()
	timer := client.expiryTimer
	done := client.expiryDone
	client.mu.Unlock()
	if timer == nil || done == nil {
		return
	}
	select {
	case <-timer.C:
		_ = client.close()
	case <-done:
	}
}

// Session returns a strictly decoded session-capability snapshot.
func (client *Client) Session(ctx context.Context) (SessionResponse, error) {
	if client == nil || ctx == nil {
		return SessionResponse{}, ErrInvalidClient
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()

	body, err := client.get(ctx, SessionPath)
	if err != nil {
		return SessionResponse{}, err
	}
	response, err := decodeSessionResponse(body)
	if err != nil {
		client.invalidate()
		return SessionResponse{}, err
	}
	if err := client.bindLineage(
		response.SessionID(),
		response.WorkspaceID(),
		response.RecoveryGeneration(),
		response.ServerDeviceID(),
	); err != nil {
		client.invalidate()
		return SessionResponse{}, err
	}
	return response, nil
}

// Peers returns a strictly decoded committed roster and opaque endpoint sets.
func (client *Client) Peers(ctx context.Context) (PeersResponse, error) {
	if client == nil || ctx == nil {
		return PeersResponse{}, ErrInvalidClient
	}
	client.operationMu.Lock()
	defer client.operationMu.Unlock()

	body, err := client.get(ctx, PeersPath)
	if err != nil {
		return PeersResponse{}, err
	}
	response, err := decodePeersResponse(body)
	if err != nil {
		client.invalidate()
		return PeersResponse{}, err
	}
	if err := client.bindLineage(
		response.SessionID(),
		response.WorkspaceID(),
		response.RecoveryGeneration(),
		response.ServerDeviceID(),
	); err != nil {
		client.invalidate()
		return PeersResponse{}, err
	}
	return response, nil
}

func (client *Client) get(ctx context.Context, path string) ([]byte, error) {
	if client == nil || ctx == nil ||
		(path != SessionPath && path != PeersPath) {
		return nil, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := client.connection()
	if err != nil {
		return nil, err
	}
	callContext, cancel := context.WithTimeout(ctx, HandlerTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		callContext,
		http.MethodGet,
		"https://"+contentPeerAuthority+path,
		nil,
	)
	if err != nil {
		return nil, ErrInvalidClient
	}
	request.Header.Set("Accept", contentJSONMediaType)
	request.Header.Set("Accept-Encoding", "identity")

	if err := connection.raw.SetReadDeadline(
		time.Now().Add(StreamNoProgress),
	); err != nil {
		client.invalidate()
		return nil, fmt.Errorf(
			"%w: arm response deadline",
			ErrResponseProtocol,
		)
	}
	defer func() {
		_ = connection.raw.SetReadDeadline(time.Time{})
	}()

	response, err := connection.http2.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if callErr := callContext.Err(); callErr != nil {
			return nil, callErr
		}
		if client.isClosed() {
			return nil, ErrClientClosed
		}
		client.invalidate()
		return nil, fmt.Errorf("%w: round trip", ErrResponseProtocol)
	}
	if err := validateClientResponseTLS(response, connection); err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		client.invalidate()
		return nil, err
	}
	limit, problem, err := validateResponseEnvelope(response)
	if err != nil {
		_ = response.Body.Close()
		client.invalidate()
		return nil, err
	}
	body, err := readClientResponse(
		callContext,
		response,
		connection.raw,
		limit,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		client.invalidate()
		return nil, err
	}
	if !problem {
		return body, nil
	}
	remote, err := decodeRemoteProblem(body, response.StatusCode)
	if err != nil {
		client.invalidate()
		return nil, err
	}
	return nil, remote
}

func (client *Client) connection() (clientConnection, error) {
	if client == nil {
		return clientConnection{}, ErrInvalidClient
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.http2 == nil || client.raw == nil {
		return clientConnection{}, ErrClientClosed
	}
	return clientConnection{
		http2:       client.http2,
		raw:         client.raw,
		peerBinding: client.peerBinding,
		peerDER:     bytes.Clone(client.peerDER),
	}, nil
}

func (client *Client) bindLineage(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	serverDeviceID domain.DeviceID,
) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.http2 == nil {
		return ErrClientClosed
	}
	if sessionID != client.peerBinding.SessionID {
		return ErrLineageMismatch
	}
	if serverDeviceID != client.peerBinding.DeviceID {
		return ErrPeerMismatch
	}
	if !client.lineageSet {
		client.workspaceID = workspaceID
		client.recoveryGeneration = recoveryGeneration
		client.lineageSet = true
		return nil
	}
	if client.workspaceID != workspaceID ||
		client.recoveryGeneration != recoveryGeneration {
		return ErrLineageMismatch
	}
	return nil
}

func validateClientResponseTLS(
	response *http.Response,
	connection clientConnection,
) error {
	if response == nil ||
		response.Body == nil ||
		response.ProtoMajor != 2 ||
		response.TLS == nil ||
		connection.raw == nil ||
		connection.http2 == nil {
		return ErrResponseProtocol
	}
	binding, err := contentConnectionBinding(*response.TLS)
	if err != nil ||
		binding != connection.peerBinding ||
		len(response.TLS.PeerCertificates) != 1 ||
		!bytes.Equal(
			response.TLS.PeerCertificates[0].Raw,
			connection.peerDER,
		) {
		return ErrResponseProtocol
	}
	return nil
}

func validateResponseEnvelope(
	response *http.Response,
) (limit int64, problem bool, err error) {
	if response == nil ||
		response.Body == nil ||
		response.StatusCode < http.StatusOK ||
		response.StatusCode > 599 ||
		response.Uncompressed ||
		len(response.TransferEncoding) != 0 ||
		len(response.Trailer) != 0 ||
		!boundedResponseHeader(response.Header) ||
		len(response.Header.Values("Content-Encoding")) != 0 {
		return 0, false, ErrResponseProtocol
	}

	expectedMediaType := contentJSONMediaType
	limit = ResponseMaxBytes
	switch {
	case response.StatusCode == http.StatusOK:
	case response.StatusCode >= http.StatusBadRequest:
		expectedMediaType = contentProblemMediaType
		limit = ProblemResponseMaxBytes
		problem = true
	default:
		return 0, false, ErrResponseProtocol
	}
	if !exactMediaType(response.Header, expectedMediaType) {
		return 0, false, ErrResponseProtocol
	}
	lengthValues := response.Header.Values("Content-Length")
	if len(lengthValues) != 1 {
		return 0, false, ErrResponseProtocol
	}
	length, parseErr := strconv.ParseInt(lengthValues[0], 10, 64)
	if parseErr != nil ||
		length <= 0 ||
		strconv.FormatInt(length, 10) != lengthValues[0] ||
		response.ContentLength != length {
		return 0, false, ErrResponseProtocol
	}
	if length > limit {
		return 0, false, ErrResponseTooLarge
	}
	return limit, problem, nil
}

func boundedResponseHeader(header http.Header) bool {
	if header == nil {
		return false
	}
	total := 0
	fields := 0
	for name, values := range header {
		if name == "" || len(values) == 0 {
			return false
		}
		for _, value := range values {
			fields++
			if fields > 256 {
				return false
			}
			total += len(name) + len(value) + 32
			if total > HeaderMaxBytes {
				return false
			}
		}
	}
	return true
}

func exactMediaType(header http.Header, expected string) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	return err == nil &&
		strings.EqualFold(mediaType, expected) &&
		len(parameters) == 0
}

func readClientResponse(
	ctx context.Context,
	response *http.Response,
	connection *tls.Conn,
	limit int64,
) ([]byte, error) {
	if ctx == nil ||
		response == nil ||
		response.Body == nil ||
		connection == nil ||
		limit < 1 {
		return nil, ErrResponseProtocol
	}
	defer response.Body.Close()
	refresh := func() error {
		return connection.SetReadDeadline(
			time.Now().Add(StreamNoProgress),
		)
	}
	if err := refresh(); err != nil {
		return nil, ErrResponseProtocol
	}
	body, err := io.ReadAll(&clientProgressReader{
		reader:  io.LimitReader(response.Body, limit+1),
		refresh: refresh,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: read body", ErrResponseProtocol)
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	if len(body) == 0 ||
		int64(len(body)) != response.ContentLength ||
		len(response.Trailer) != 0 {
		return nil, ErrResponseProtocol
	}
	return body, nil
}

type clientProgressReader struct {
	reader  io.Reader
	refresh func() error
}

func (reader *clientProgressReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.reader == nil || reader.refresh == nil {
		return 0, ErrResponseProtocol
	}
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		if refreshErr := reader.refresh(); err == nil && refreshErr != nil {
			err = refreshErr
		}
	}
	return count, err
}

func decodeSessionResponse(body []byte) (SessionResponse, error) {
	if !canonicalResponse(body) {
		return SessionResponse{}, ErrResponseProtocol
	}
	var wire sessionWire
	if err := json.Unmarshal(body, &wire); err != nil ||
		wire.SchemaVersion != SchemaVersion {
		return SessionResponse{}, ErrResponseProtocol
	}
	response, err := NewSessionResponse(SessionResponseInput{
		SessionID:            domain.UUIDv7(wire.SessionID),
		WorkspaceID:          domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:   wire.RecoveryGeneration,
		ServerDeviceID:       domain.DeviceID(wire.ServerDeviceID),
		DaemonVersion:        wire.DaemonVersion,
		MaxApplyLevel:        wire.MaxApplyLevel,
		RequiredCapabilities: wire.RequiredCapabilities,
	})
	if err != nil {
		return SessionResponse{}, ErrResponseProtocol
	}
	canonical, err := response.canonicalBytes()
	if err != nil || !bytes.Equal(canonical, body) {
		return SessionResponse{}, ErrResponseProtocol
	}
	return response, nil
}

func decodePeersResponse(body []byte) (PeersResponse, error) {
	if !canonicalResponse(body) {
		return PeersResponse{}, ErrResponseProtocol
	}
	var wire peersWire
	if err := json.Unmarshal(body, &wire); err != nil ||
		wire.SchemaVersion != SchemaVersion ||
		len(wire.Members) < 1 ||
		len(wire.Members) > int(policy.MaxMemberDevices) {
		return PeersResponse{}, ErrResponseProtocol
	}
	members := make([]PeerMember, len(wire.Members))
	for index, encodedMember := range wire.Members {
		var endpointSet []byte
		if encodedMember.EndpointSet != nil {
			if len(*encodedMember.EndpointSet) == 0 ||
				len(*encodedMember.EndpointSet) >
					base64.RawURLEncoding.EncodedLen(
						discovery.MaxEndpointSetBytes,
					) {
				return PeersResponse{}, ErrResponseProtocol
			}
			var err error
			endpointSet, err = codec.DecodeBase64URL(
				*encodedMember.EndpointSet,
			)
			if err != nil {
				return PeersResponse{}, ErrResponseProtocol
			}
		}
		member, err := NewPeerMember(PeerMemberInput{
			DeviceID:      domain.DeviceID(encodedMember.DeviceID),
			Role:          device.Role(encodedMember.Role),
			Status:        device.Status(encodedMember.Status),
			EntityVersion: encodedMember.EntityVersion,
			EndpointSet:   endpointSet,
		})
		if err != nil {
			return PeersResponse{}, ErrResponseProtocol
		}
		members[index] = member
	}
	response, err := NewPeersResponse(PeersResponseInput{
		SessionID:          domain.UUIDv7(wire.SessionID),
		WorkspaceID:        domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration: wire.RecoveryGeneration,
		ServerDeviceID:     domain.DeviceID(wire.ServerDeviceID),
		Members:            members,
	})
	if err != nil {
		return PeersResponse{}, ErrResponseProtocol
	}
	serverValid := false
	for _, member := range response.members {
		if member.deviceID == response.serverDeviceID {
			serverValid = member.status == device.StatusActive &&
				len(member.endpointSet) != 0
			break
		}
	}
	canonical, err := response.canonicalBytes()
	if !serverValid || err != nil || !bytes.Equal(canonical, body) {
		return PeersResponse{}, ErrResponseProtocol
	}
	return response, nil
}

func canonicalResponse(body []byte) bool {
	if len(body) == 0 || len(body) > ResponseMaxBytes {
		return false
	}
	canonical, err := codec.CanonicalizeSignedObject(body)
	return err == nil && bytes.Equal(canonical, body)
}

type remoteProblemWire struct {
	Type          string  `json:"type"`
	Title         string  `json:"title"`
	Status        int     `json:"status"`
	Code          string  `json:"code"`
	CorrelationID string  `json:"correlation_id"`
	Retryable     bool    `json:"retryable"`
	Detail        *string `json:"detail,omitempty"`
}

func decodeRemoteProblem(
	body []byte,
	responseStatus int,
) (*RemoteError, error) {
	if len(body) > ProblemResponseMaxBytes || !canonicalResponse(body) {
		return nil, ErrResponseProtocol
	}
	var wire remoteProblemWire
	if err := json.Unmarshal(body, &wire); err != nil ||
		wire.Status != responseStatus ||
		wire.Status < http.StatusBadRequest ||
		wire.Status > 599 ||
		!validProblemCode(wire.Code) ||
		len(wire.Title) < 1 ||
		len(wire.Title) > problemTitleMaxBytes ||
		len(wire.CorrelationID) < 1 ||
		len(wire.CorrelationID) > problemCorrelationMaxBytes ||
		wire.Type != "urn:codecomm:problem:"+wire.Code {
		return nil, ErrResponseProtocol
	}
	if wire.CorrelationID != "unavailable" {
		if _, err := domain.ParseUUIDv7(wire.CorrelationID); err != nil {
			return nil, ErrResponseProtocol
		}
	}
	detail := ""
	if wire.Detail != nil {
		if len(*wire.Detail) < 1 ||
			len(*wire.Detail) > problemDetailMaxBytes {
			return nil, ErrResponseProtocol
		}
		detail = *wire.Detail
	}
	canonical, err := marshalCanonical(wire)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrResponseProtocol
	}
	return &RemoteError{
		Type: wire.Type, Title: wire.Title, Status: wire.Status,
		Code: wire.Code, CorrelationID: wire.CorrelationID,
		Retryable: wire.Retryable, Detail: detail,
	}, nil
}

func validProblemCode(code string) bool {
	if len(code) < 1 || len(code) > problemCodeMaxBytes ||
		code[0] < 'a' || code[0] > 'z' {
		return false
	}
	for index := 1; index < len(code); index++ {
		char := code[index]
		if char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' ||
			char == '_' {
			continue
		}
		return false
	}
	return true
}

func newContentHTTP2ClientConn(
	ctx context.Context,
	connection *tls.Conn,
) (*http2.ClientConn, error) {
	if ctx == nil || connection == nil {
		return nil, ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cancelDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(cancelDone)
	})
	httpConnection, err := newContentHTTP2Transport().
		NewClientConn(connection)
	if !stopCancellation() {
		<-cancelDone
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		if httpConnection != nil {
			_ = httpConnection.Close()
		}
		return nil, ctxErr
	}
	return httpConnection, err
}

func newContentHTTP2Transport() *http2.Transport {
	return &http2.Transport{
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
}

func (client *Client) isClosed() bool {
	if client == nil {
		return true
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closed || client.http2 == nil
}

func (client *Client) invalidate() {
	if client == nil {
		return
	}
	_ = client.close()
}

// Close immediately interrupts in-flight work and releases the owned
// connection. Repeated calls are idempotent.
func (client *Client) Close() error {
	if client == nil {
		return ErrInvalidClient
	}
	return client.close()
}

func (client *Client) close() error {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return nil
	}
	client.closed = true
	httpConnection := client.http2
	raw := client.raw
	expiryTimer := client.expiryTimer
	expiryDone := client.expiryDone
	client.http2 = nil
	client.raw = nil
	client.expiryTimer = nil
	client.expiryDone = nil
	clear(client.peerDER)
	client.peerDER = nil
	client.peerBinding = transport.ContentBinding{}
	client.workspaceID = ""
	client.recoveryGeneration = 0
	client.lineageSet = false
	if expiryTimer != nil {
		expiryTimer.Stop()
	}
	if expiryDone != nil {
		close(expiryDone)
	}
	client.mu.Unlock()

	var httpErr error
	if httpConnection != nil {
		httpErr = httpConnection.Close()
	}
	if raw != nil {
		_ = raw.Close()
	}
	return httpErr
}
