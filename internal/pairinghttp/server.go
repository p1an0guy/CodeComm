// Package pairinghttp exposes the pre-membership pairing service on its
// dedicated TLS 1.3 HTTP/2 plane.
package pairinghttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const (
	RequestPath = "/v1/pairing/request"
	ConfirmPath = "/v1/pairing/confirm"

	HeaderMaxBytes       = 32 << 10
	ControlStreamsMax    = 32
	ActiveHandlersMax    = 128
	RequestHeaderTimeout = 10 * time.Second
	RequestTimeout       = 120 * time.Second
	ConnectionIdle       = 120 * time.Second
	StreamNoProgress     = 30 * time.Second
)

var (
	ErrInvalidOptions    = errors.New("pairing HTTP: invalid options")
	ErrInvalidConnection = errors.New("pairing HTTP: invalid connection")
	ErrTLSBinding        = errors.New("pairing HTTP: invalid TLS binding")
)

// Service is the exact network-facing pairing surface.
type Service interface {
	HandleRequest(
		context.Context,
		[]byte,
		[]byte,
		transport.IdentityCertificate,
	) (pairingservice.RequestResult, error)
	ConfirmRemote(
		context.Context,
		[]byte,
		[]byte,
		transport.IdentityCertificate,
	) (pairing.ConfirmationResult, error)
}

// Server serves authenticated pairing connections.
type Server struct {
	service          Service
	http2            *http2.Server
	handlers         chan struct{}
	headerTimeout    time.Duration
	requestTimeout   time.Duration
	streamNoProgress time.Duration
}

// New constructs the fixed V1 pairing HTTP/2 server.
func New(service Service) (*Server, error) {
	return newServer(service, ActiveHandlersMax)
}

func newServer(service Service, activeHandlers int) (*Server, error) {
	if service == nil || activeHandlers < 1 ||
		activeHandlers > ActiveHandlersMax {
		return nil, ErrInvalidOptions
	}
	return &Server{
		service: service,
		http2: &http2.Server{
			MaxConcurrentStreams:      ControlStreamsMax,
			MaxDecoderHeaderTableSize: 4 << 10,
			MaxEncoderHeaderTableSize: 4 << 10,
			MaxReadFrameSize:          16 << 10,
			IdleTimeout:               ConnectionIdle,
			ReadIdleTimeout:           StreamNoProgress,
			PingTimeout:               RequestHeaderTimeout,
			WriteByteTimeout:          StreamNoProgress,
			MaxUploadBufferPerConnection: ControlStreamsMax *
				pairing.MaxPairingMessageBytes,
			MaxUploadBufferPerStream: pairing.MaxPairingMessageBytes,
		},
		handlers:         make(chan struct{}, activeHandlers),
		headerTimeout:    RequestHeaderTimeout,
		requestTimeout:   RequestTimeout,
		streamNoProgress: StreamNoProgress,
	}, nil
}

// ServeConn handshakes and serves one admission-limited TLS connection. It
// accepts only the pairing ALPN and fixed identity-certificate profile.
func (server *Server) ServeConn(
	ctx context.Context,
	connection *tls.Conn,
	permit *transport.HandshakePermit,
) error {
	if server == nil || server.service == nil || server.http2 == nil ||
		server.handlers == nil || ctx == nil || connection == nil ||
		permit == nil {
		return ErrInvalidConnection
	}
	if !permit.BeginHandshake() {
		return ErrInvalidConnection
	}
	defer permit.Release()
	defer connection.Close()
	if err := ctx.Err(); err != nil {
		return err
	}

	handshakeContext, cancel := context.WithTimeout(
		ctx,
		transport.HandshakeTimeout,
	)
	err := connection.HandshakeContext(handshakeContext)
	handshakeContextErr := handshakeContext.Err()
	cancel()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(handshakeContextErr, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return fmt.Errorf("%w: handshake", ErrTLSBinding)
	}
	permit.Release()
	return server.ServeAuthenticatedConn(ctx, connection)
}

// ServeAuthenticatedConn serves one connection already handshaken by the
// shared peer ingress. The caller retains connection ownership.
func (server *Server) ServeAuthenticatedConn(
	ctx context.Context,
	connection *tls.Conn,
) error {
	if server == nil || server.service == nil || server.http2 == nil ||
		server.handlers == nil ||
		server.headerTimeout <= 0 ||
		server.requestTimeout <= 0 ||
		server.streamNoProgress <= 0 ||
		ctx == nil || connection == nil {
		return ErrInvalidConnection
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	peer, exporter, err := pairingConnectionState(
		connection.ConnectionState(),
	)
	if err != nil {
		return err
	}
	defer clear(exporter)

	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("%w: clear handshake deadline", ErrInvalidConnection)
	}
	connectionContext, stop := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	serveDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-connectionContext.Done():
			_ = connection.Close()
		case <-serveDone:
		}
	}()

	handler := &connectionHandler{
		server: server,
		peer:   peer,
	}
	defer func() {
		stop()
		handler.close()
		close(serveDone)
		<-watcherDone
	}()
	copy(handler.exporter[:], exporter)
	deadlineConnection, err := newHTTP2DeadlineConn(
		connection,
		server.headerTimeout,
		ConnectionIdle,
		server.streamNoProgress,
	)
	if err != nil {
		return err
	}
	server.http2.ServeConn(deadlineConnection, &http2.ServeConnOpts{
		Context: connectionContext,
		BaseConfig: &http.Server{
			ReadTimeout:       server.requestTimeout,
			ReadHeaderTimeout: RequestHeaderTimeout,
			IdleTimeout:       ConnectionIdle,
			MaxHeaderBytes:    HeaderMaxBytes,
		},
		Handler: handler,
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func pairingConnectionState(
	state tls.ConnectionState,
) (transport.IdentityCertificate, []byte, error) {
	if !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 ||
		state.DidResume ||
		state.NegotiatedProtocol != transport.ALPNPairing ||
		len(state.PeerCertificates) != 1 {
		return transport.IdentityCertificate{}, nil, ErrTLSBinding
	}
	peer, err := transport.ParseIdentityCertificate(
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		return transport.IdentityCertificate{}, nil, fmt.Errorf(
			"%w: peer certificate",
			ErrTLSBinding,
		)
	}
	exporter, err := state.ExportKeyingMaterial(
		pairing.ExporterLabel,
		[]byte{},
		pairing.ExporterSize,
	)
	if err != nil || len(exporter) != pairing.ExporterSize {
		clear(exporter)
		return transport.IdentityCertificate{}, nil, fmt.Errorf(
			"%w: exporter",
			ErrTLSBinding,
		)
	}
	return peer, exporter, nil
}

type connectionHandler struct {
	server   *Server
	peer     transport.IdentityCertificate
	exporter [pairing.ExporterSize]byte

	mu      sync.Mutex
	active  sync.WaitGroup
	closing bool
}

func (handler *connectionHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler == nil || handler.server == nil ||
		handler.server.service == nil || request == nil {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	requestDeadline := time.Now().Add(handler.server.requestTimeout)
	if !handler.begin() {
		return
	}
	defer handler.active.Done()
	select {
	case handler.server.handlers <- struct{}{}:
		defer func() { <-handler.server.handlers }()
	default:
		writeProblem(writer, http.StatusServiceUnavailable, problemCapacity)
		return
	}
	if !validRequestTransport(request) {
		writeProblem(writer, http.StatusBadRequest, problemInvalidTransport)
		return
	}
	if request.URL == nil ||
		request.URL.RawPath != "" ||
		request.URL.RawQuery != "" ||
		request.URL.ForceQuery {
		writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
		return
	}
	switch request.URL.Path {
	case RequestPath, ConfirmPath:
	default:
		writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	if !validJSONContentType(request.Header) {
		writeProblem(
			writer,
			http.StatusUnsupportedMediaType,
			problemMediaType,
		)
		return
	}
	body, err := readPairingBody(
		writer,
		request,
		requestDeadline,
		handler.server.streamNoProgress,
	)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeProblem(
				writer,
				http.StatusRequestEntityTooLarge,
				problemBodyTooLarge,
			)
		} else {
			writeProblem(writer, http.StatusBadRequest, problemInvalidBody)
		}
		return
	}

	callContext, cancel := context.WithDeadline(
		request.Context(),
		requestDeadline,
	)
	defer cancel()
	exporter := handler.exporter
	defer clear(exporter[:])
	var response []byte
	switch request.URL.Path {
	case RequestPath:
		result, err := handler.server.service.HandleRequest(
			callContext,
			body,
			exporter[:],
			handler.peer,
		)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		response = result.Acknowledgment.CanonicalBytes()
	case ConfirmPath:
		result, err := handler.server.service.ConfirmRemote(
			callContext,
			body,
			exporter[:],
			handler.peer,
		)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		response = result.CanonicalBytes()
	}
	if len(response) == 0 || len(response) > pairing.MaxPairingMessageBytes {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func (handler *connectionHandler) begin() bool {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.closing {
		return false
	}
	handler.active.Add(1)
	return true
}

func (handler *connectionHandler) close() {
	handler.mu.Lock()
	handler.closing = true
	handler.mu.Unlock()
	handler.active.Wait()
	clear(handler.exporter[:])
}

func validRequestTransport(request *http.Request) bool {
	return request.ProtoMajor == 2 &&
		request.TLS != nil &&
		request.TLS.HandshakeComplete &&
		request.TLS.Version == tls.VersionTLS13 &&
		!request.TLS.DidResume &&
		request.TLS.NegotiatedProtocol == transport.ALPNPairing &&
		len(request.TLS.PeerCertificates) == 1
}

func validJSONContentType(header http.Header) bool {
	return validContentType(header, "application/json")
}

func validContentType(header http.Header, expected string) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, expected) ||
		len(header.Values("Content-Encoding")) != 0 {
		return false
	}
	if len(parameters) == 0 {
		return true
	}
	charset, exists := parameters["charset"]
	return len(parameters) == 1 &&
		exists &&
		strings.EqualFold(charset, "utf-8")
}

var errBodyTooLarge = errors.New("pairing HTTP: body too large")

func readPairingBody(
	writer http.ResponseWriter,
	request *http.Request,
	requestDeadline time.Time,
	streamNoProgress time.Duration,
) ([]byte, error) {
	if request.Body == nil || request.ContentLength == 0 ||
		request.ContentLength > pairing.MaxPairingMessageBytes ||
		requestDeadline.IsZero() ||
		streamNoProgress <= 0 {
		if request.ContentLength > pairing.MaxPairingMessageBytes {
			return nil, errBodyTooLarge
		}
		return nil, pairing.ErrInvalidPairingMessage
	}
	defer request.Body.Close()
	controller := http.NewResponseController(writer)
	refreshDeadline := func() error {
		return controller.SetReadDeadline(pairingReadDeadline(
			time.Now(),
			requestDeadline,
			streamNoProgress,
		))
	}
	if err := refreshDeadline(); err != nil {
		return nil, err
	}
	defer func() {
		_ = controller.SetReadDeadline(time.Time{})
	}()
	limited := http.MaxBytesReader(
		writer,
		request.Body,
		pairing.MaxPairingMessageBytes,
	)
	body, err := io.ReadAll(&progressReader{
		reader:  limited,
		refresh: refreshDeadline,
	})
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	if len(body) == 0 {
		return nil, pairing.ErrInvalidPairingMessage
	}
	return body, nil
}

func pairingReadDeadline(
	now time.Time,
	requestDeadline time.Time,
	streamNoProgress time.Duration,
) time.Time {
	progressDeadline := now.Add(streamNoProgress)
	if requestDeadline.Before(progressDeadline) {
		return requestDeadline
	}
	return progressDeadline
}

type progressReader struct {
	reader  io.Reader
	refresh func() error
}

func (reader *progressReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if count > 0 && reader.refresh != nil {
		if refreshErr := reader.refresh(); refreshErr != nil && err == nil {
			err = refreshErr
		}
	}
	return count, err
}

type problemDefinition struct {
	code      string
	title     string
	retryable bool
}

var (
	problemInvalidTransport = problemDefinition{
		code: "invalid_transport", title: "Invalid transport",
	}
	problemRouteNotFound = problemDefinition{
		code: "route_not_found", title: "Route not found",
	}
	problemMethod = problemDefinition{
		code: "method_not_allowed", title: "Method not allowed",
	}
	problemMediaType = problemDefinition{
		code: "unsupported_media_type", title: "Unsupported media type",
	}
	problemBodyTooLarge = problemDefinition{
		code: "body_too_large", title: "Request body too large",
	}
	problemInvalidBody = problemDefinition{
		code: "invalid_pairing_message", title: "Invalid pairing message",
	}
	problemRejected = problemDefinition{
		code: "pairing_rejected", title: "Pairing rejected",
	}
	problemUnavailable = problemDefinition{
		code: "pairing_unavailable", title: "Pairing unavailable",
		retryable: true,
	}
	problemCapacity = problemDefinition{
		code: "handler_capacity", title: "Handler capacity reached",
		retryable: true,
	}
	problemInternal = problemDefinition{
		code: "internal_error", title: "Internal server error",
		retryable: true,
	}
)

func writeServiceProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pairingservice.ErrRequestRejected),
		errors.Is(err, pairingservice.ErrConfirmationConflict):
		writeProblem(writer, http.StatusForbidden, problemRejected)
	case errors.Is(err, pairingservice.ErrNotRecovered),
		errors.Is(err, pairingservice.ErrClosed),
		errors.Is(err, pairingservice.ErrUnavailable),
		errors.Is(err, pairingservice.ErrFinalizationPending):
		writeProblem(writer, http.StatusServiceUnavailable, problemUnavailable)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		writeProblem(writer, http.StatusRequestTimeout, problemUnavailable)
	default:
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
	}
}

type problemResponse struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
	Retryable     bool   `json:"retryable"`
}

func writeProblem(
	writer http.ResponseWriter,
	status int,
	definition problemDefinition,
) {
	if writer == nil {
		return
	}
	correlationID := "unavailable"
	if id, err := uuid.NewV7(); err == nil {
		correlationID = id.String()
	}
	body, err := json.Marshal(problemResponse{
		Type:          "urn:codecomm:problem:" + definition.code,
		Title:         definition.title,
		Status:        status,
		Code:          definition.code,
		CorrelationID: correlationID,
		Retryable:     definition.retryable,
	})
	if err != nil {
		body = []byte(
			`{"type":"urn:codecomm:problem:internal_error","title":"Internal server error","status":500,"code":"internal_error","correlation_id":"unavailable","retryable":true}`,
		)
		status = http.StatusInternalServerError
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

var _ http.Handler = (*connectionHandler)(nil)
var _ Service = (*pairingservice.Service)(nil)
var _ transport.ConnectionHandler = (*Server)(nil)
