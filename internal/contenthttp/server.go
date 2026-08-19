package contenthttp

import (
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const (
	SessionPath = "/v1/session"
	PeersPath   = "/v1/peers"
	EventsPath  = "/v1/events"

	proposalHopHeader = "CodeComm-Proposal-Hop"
	proposalHopOnce   = "1"

	HeaderMaxBytes         = 32 << 10
	ResponseMaxBytes       = 1 << 20
	ControlStreamsMax      = 32
	ActiveHandlersMax      = 128
	ReplicationHandlersMax = 1
	RequestHeaderTimeout   = 10 * time.Second
	HandlerTimeout         = 120 * time.Second
	ConnectionIdle         = 120 * time.Second
	StreamNoProgress       = 30 * time.Second
)

var (
	ErrInvalidOptions       = errors.New("content HTTP: invalid options")
	ErrInvalidConnection    = errors.New("content HTTP: invalid connection")
	ErrTLSBinding           = errors.New("content HTTP: invalid TLS binding")
	ErrInvalidEventProposal = errors.New(
		"content HTTP: invalid event proposal",
	)
	ErrEventIdempotencyConflict = errors.New(
		"content HTTP: event idempotency conflict",
	)
	ErrEventProposalUnavailable = errors.New(
		"content HTTP: event proposal unavailable",
	)
	ErrEventProposalRateLimited = errors.New(
		"content HTTP: event proposal rate limited",
	)
)

// Server serves the fixed inbound V1 content-control routes.
type Server struct {
	service             Service
	http2               *http2.Server
	handlers            chan struct{}
	replicationHandlers chan struct{}
	control             *controlRegistry
	headerTimeout       time.Duration
	handlerTimeout      time.Duration
	streamNoProgress    time.Duration
}

// New constructs the fixed V1 content-control HTTP/2 server.
func New(service Service) (*Server, error) {
	return newServer(service, ActiveHandlersMax)
}

func newServer(service Service, activeHandlers int) (*Server, error) {
	if service == nil ||
		activeHandlers < 1 ||
		activeHandlers > ActiveHandlersMax {
		return nil, ErrInvalidOptions
	}
	control, err := newControlRegistry(time.Now)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return &Server{
		service: service,
		http2: &http2.Server{
			MaxConcurrentStreams:         ControlStreamsMax,
			MaxDecoderHeaderTableSize:    4 << 10,
			MaxEncoderHeaderTableSize:    4 << 10,
			MaxReadFrameSize:             16 << 10,
			IdleTimeout:                  ConnectionIdle,
			ReadIdleTimeout:              StreamNoProgress,
			PingTimeout:                  RequestHeaderTimeout,
			WriteByteTimeout:             StreamNoProgress,
			MaxUploadBufferPerConnection: 1 << 16,
			MaxUploadBufferPerStream:     event.MaxEventBytes,
		},
		handlers:            make(chan struct{}, activeHandlers),
		replicationHandlers: make(chan struct{}, ReplicationHandlersMax),
		control:             control,
		headerTimeout:       RequestHeaderTimeout,
		handlerTimeout:      HandlerTimeout,
		streamNoProgress:    StreamNoProgress,
	}, nil
}

// ServeAuthenticatedConn serves one content connection already handshaken and
// authorized by transport.Ingress. The caller owns lifecycle outside this
// connection; cancellation closes this connection to unblock HTTP/2.
func (server *Server) ServeAuthenticatedConn(
	ctx context.Context,
	connection *tls.Conn,
) error {
	if server == nil ||
		server.service == nil ||
		server.http2 == nil ||
		server.handlers == nil ||
		server.replicationHandlers == nil ||
		server.control == nil ||
		server.headerTimeout <= 0 ||
		server.handlerTimeout <= 0 ||
		server.streamNoProgress <= 0 ||
		ctx == nil ||
		connection == nil {
		return ErrInvalidConnection
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	binding, err := contentConnectionBinding(connection.ConnectionState())
	if err != nil {
		return err
	}
	metadata, bound := transport.AuthenticatedPeerFromContext(ctx)
	if !bound ||
		metadata.Plane != transport.PlaneContent ||
		metadata.SessionID != binding.SessionID ||
		metadata.DeviceID != binding.DeviceID ||
		metadata.Epoch != binding.Epoch ||
		metadata.AuthorizationChainIndex != binding.AuthorizationChainIndex {
		return ErrTLSBinding
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf(
			"%w: clear handshake deadline",
			ErrInvalidConnection,
		)
	}

	connectionContext, cancel := context.WithCancel(ctx)
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

	handler := newConnectionHandler(server, metadata, cancel)
	registered := false
	defer func() {
		handler.close()
		if registered {
			server.control.unregister(handler)
		}
		close(serveDone)
		<-watcherDone
	}()
	if err := server.control.register(handler); err != nil {
		return err
	}
	registered = true
	deadlineConnection, err := newDeadlineConn(
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
			ReadTimeout:       server.handlerTimeout,
			ReadHeaderTimeout: server.headerTimeout,
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

func contentConnectionBinding(
	state tls.ConnectionState,
) (transport.ContentBinding, error) {
	if !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 ||
		state.DidResume ||
		state.NegotiatedProtocol != transport.ALPNContent ||
		len(state.PeerCertificates) != 1 {
		return transport.ContentBinding{}, ErrTLSBinding
	}
	certificate, err := transport.ParseContentCertificate(
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		return transport.ContentBinding{}, fmt.Errorf(
			"%w: peer certificate",
			ErrTLSBinding,
		)
	}
	return certificate.Binding, nil
}

type connectionHandler struct {
	server *Server
	peer   transport.AuthenticatedPeer

	mu          sync.Mutex
	active      sync.WaitGroup
	activeCount int
	accepting   bool
	closing     bool
	stop        context.CancelFunc
	stopOnce    sync.Once
}

func (handler *connectionHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler == nil ||
		handler.server == nil ||
		handler.server.service == nil ||
		request == nil {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	switch handler.begin() {
	case handlerClosed:
		return
	case handlerDraining:
		writer.Header().Set("Retry-After", "1")
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemConnectionDraining,
		)
		return
	case handlerAccepted:
	}
	defer handler.end()

	allowed, retryAfter, rateErr := handler.server.control.consume(
		handler.peer.DeviceID,
	)
	if rateErr != nil {
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemUnavailable,
		)
		return
	}
	if !allowed {
		retrySeconds := max(
			int64(1),
			int64((retryAfter+time.Second-1)/time.Second),
		)
		writer.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
		writeProblem(
			writer,
			http.StatusTooManyRequests,
			problemRateLimited,
		)
		return
	}

	if err := transport.ReauthorizeAuthenticatedPeer(request.Context()); err != nil {
		switch {
		case errors.Is(err, transport.ErrPeerAuthorizationDenied):
			writeProblem(writer, http.StatusForbidden, problemRejected)
		default:
			writeProblem(
				writer,
				http.StatusServiceUnavailable,
				problemUnavailable,
			)
		}
		return
	}
	select {
	case handler.server.handlers <- struct{}{}:
		defer func() { <-handler.server.handlers }()
	default:
		writeProblem(writer, http.StatusServiceUnavailable, problemCapacity)
		return
	}
	if !validRequestTransport(request, handler.peer) {
		writeProblem(writer, http.StatusBadRequest, problemInvalidTransport)
		return
	}
	if !validRequestPath(request) {
		writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
		return
	}
	switch request.URL.Path {
	case ReplicationPath:
	case SessionPath, PeersPath, EventsPath:
		if !validRequestTarget(request) {
			writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
			return
		}
	default:
		writeProblem(writer, http.StatusNotFound, problemRouteNotFound)
		return
	}
	switch request.URL.Path {
	case SessionPath, PeersPath:
		handler.serveRead(writer, request)
	case EventsPath:
		handler.serveEvent(writer, request)
	case ReplicationPath:
		handler.serveReplication(writer, request)
	}
}

func (handler *connectionHandler) serveRead(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	if !validBodylessRequest(request) {
		writeProblem(writer, http.StatusBadRequest, problemRequestBody)
		return
	}
	if !validNegotiation(request.Header) {
		writeProblem(writer, http.StatusNotAcceptable, problemNegotiation)
		return
	}

	callContext, cancel := context.WithTimeout(
		request.Context(),
		handler.server.handlerTimeout,
	)
	defer cancel()
	var body []byte
	var err error
	switch request.URL.Path {
	case SessionPath:
		var response SessionResponse
		response, err = handler.server.service.Session(callContext)
		if err == nil && response.SessionID() != handler.peer.SessionID {
			err = ErrInvalidResponse
		}
		if err == nil {
			body, err = response.canonicalBytes()
		}
	case PeersPath:
		var response PeersResponse
		response, err = handler.server.service.Peers(callContext)
		if err == nil && response.SessionID() != handler.peer.SessionID {
			err = ErrInvalidResponse
		}
		if err == nil {
			body, err = response.canonicalBytes()
		}
	}
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	if len(body) == 0 || len(body) > ResponseMaxBytes {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	writeJSON(writer, http.StatusOK, contentJSONMediaType, body)
}

func (handler *connectionHandler) serveEvent(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	allowed, retryAfter, err := handler.server.control.consumeProposal(
		handler.peer.DeviceID,
	)
	if err != nil {
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemUnavailable,
		)
		return
	}
	if !allowed {
		retrySeconds := max(
			int64(1),
			int64((retryAfter+time.Second-1)/time.Second),
		)
		writer.Header().Set("Retry-After", strconv.FormatInt(retrySeconds, 10))
		writeProblem(
			writer,
			http.StatusTooManyRequests,
			problemProposalRateLimited,
		)
		return
	}
	if request.ContentLength > int64(event.MaxEventBytes) {
		writeProblem(
			writer,
			http.StatusRequestEntityTooLarge,
			problemEventTooLarge,
		)
		return
	}
	idempotencyKey, hop, valid := validEventRequest(request)
	if !valid {
		writeProblem(writer, http.StatusBadRequest, problemEventInvalid)
		return
	}
	if !validNegotiation(request.Header) {
		writeProblem(writer, http.StatusNotAcceptable, problemNegotiation)
		return
	}

	callContext, cancel := context.WithTimeout(
		request.Context(),
		handler.server.handlerTimeout,
	)
	defer cancel()
	body, err := readEventRequest(callContext, request)
	if err != nil {
		switch {
		case errors.Is(err, event.ErrEventTooLarge):
			writeProblem(
				writer,
				http.StatusRequestEntityTooLarge,
				problemEventTooLarge,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			writeEventProblem(writer, err)
		default:
			writeProblem(writer, http.StatusBadRequest, problemEventInvalid)
		}
		return
	}
	proposal, err := event.InspectUnverifiedProposal(body)
	if err != nil || proposal.EventID != idempotencyKey {
		writeProblem(writer, http.StatusBadRequest, problemEventInvalid)
		return
	}
	result, err := handler.server.service.ProposeEvent(
		callContext,
		handler.peer.DeviceID,
		body,
		hop,
	)
	if err != nil {
		writeEventProblem(writer, err)
		return
	}
	if !bytes.Equal(result.Proposal(), body) {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	response, err := result.canonicalBytes()
	if err != nil || len(response) == 0 || len(response) > ResponseMaxBytes {
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
		return
	}
	writeJSON(writer, http.StatusOK, contentJSONMediaType, response)
}

func validEventRequest(
	request *http.Request,
) (domain.UUIDv7, ProposalHop, bool) {
	if request == nil ||
		request.Body == nil ||
		request.ContentLength < 1 ||
		len(request.TransferEncoding) != 0 ||
		len(request.Trailer) != 0 ||
		len(request.Header.Values("Content-Encoding")) != 0 ||
		len(request.Header.Values("Trailer")) != 0 ||
		len(request.Header.Values("Expect")) != 0 ||
		!exactMediaType(request.Header, contentJSONMediaType) {
		return "", 0, false
	}
	hop := ProposalHopInitial
	switch values := request.Header.Values(proposalHopHeader); len(values) {
	case 0:
	case 1:
		if values[0] != proposalHopOnce {
			return "", 0, false
		}
		hop = ProposalHopForwarded
	default:
		return "", 0, false
	}
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 {
		return "", 0, false
	}
	eventID := domain.UUIDv7(values[0])
	return eventID, hop, eventID.Valid() && hop.valid()
}

func readEventRequest(
	ctx context.Context,
	request *http.Request,
) ([]byte, error) {
	if ctx == nil || request == nil || request.Body == nil {
		return nil, ErrInvalidEventProposal
	}
	stopClose := context.AfterFunc(ctx, func() {
		_ = request.Body.Close()
	})
	defer stopClose()
	body, err := io.ReadAll(io.LimitReader(
		request.Body,
		int64(event.MaxEventBytes)+1,
	))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, ErrInvalidEventProposal
	}
	if len(body) > event.MaxEventBytes {
		return nil, event.ErrEventTooLarge
	}
	if int64(len(body)) != request.ContentLength {
		return nil, ErrInvalidEventProposal
	}
	return body, nil
}

func validRequestTransport(
	request *http.Request,
	peer transport.AuthenticatedPeer,
) bool {
	if request.ProtoMajor != 2 ||
		request.TLS == nil {
		return false
	}
	binding, err := contentConnectionBinding(*request.TLS)
	return err == nil &&
		peer.Plane == transport.PlaneContent &&
		peer.SessionID == binding.SessionID &&
		peer.DeviceID == binding.DeviceID &&
		peer.Epoch == binding.Epoch &&
		peer.AuthorizationChainIndex == binding.AuthorizationChainIndex
}

func validRequestTarget(request *http.Request) bool {
	return validRequestPath(request) &&
		request.URL.RawQuery == "" &&
		!request.URL.ForceQuery
}

func validRequestPath(request *http.Request) bool {
	return request != nil &&
		request.URL != nil &&
		request.URL.RawPath == "" &&
		request.URL.Fragment == "" &&
		request.URL.RawFragment == ""
}

func validBodylessRequest(request *http.Request) bool {
	return request.ContentLength == 0 &&
		len(request.TransferEncoding) == 0 &&
		len(request.Trailer) == 0 &&
		len(request.Header.Values("Content-Length")) == 0 &&
		len(request.Header.Values("Content-Type")) == 0 &&
		len(request.Header.Values("Content-Encoding")) == 0 &&
		len(request.Header.Values("Trailer")) == 0 &&
		len(request.Header.Values("Expect")) == 0
}

func validNegotiation(header http.Header) bool {
	accept := header.Values("Accept")
	if len(accept) > 1 {
		return false
	}
	if len(accept) == 1 {
		mediaType, parameters, err := mime.ParseMediaType(accept[0])
		if err != nil ||
			!strings.EqualFold(mediaType, "application/json") ||
			len(parameters) != 0 {
			return false
		}
	}
	encoding := header.Values("Accept-Encoding")
	return len(encoding) == 0 ||
		len(encoding) == 1 &&
			strings.EqualFold(strings.TrimSpace(encoding[0]), "identity")
}

func writeServiceProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		writeProblem(writer, http.StatusRequestTimeout, problemUnavailable)
	default:
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
	}
}

func writeEventProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidEventProposal):
		writeProblem(writer, http.StatusBadRequest, problemEventInvalid)
	case errors.Is(err, ErrEventIdempotencyConflict):
		writeProblem(writer, http.StatusConflict, problemEventConflict)
	case errors.Is(err, ErrEventProposalRateLimited):
		writer.Header().Set("Retry-After", "1")
		writeProblem(
			writer,
			http.StatusTooManyRequests,
			problemLeaderProposalRateLimited,
		)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrEventProposalUnavailable):
		writeProblem(
			writer,
			http.StatusServiceUnavailable,
			problemEventUnavailable,
		)
	default:
		writeProblem(writer, http.StatusInternalServerError, problemInternal)
	}
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
	problemRequestBody = problemDefinition{
		code: "request_body_forbidden", title: "Request body forbidden",
	}
	problemNegotiation = problemDefinition{
		code: "not_acceptable", title: "Representation not acceptable",
	}
	problemRejected = problemDefinition{
		code: "authorization_denied", title: "Authorization denied",
	}
	problemUnavailable = problemDefinition{
		code: "content_unavailable", title: "Content service unavailable",
		retryable: true,
	}
	problemCapacity = problemDefinition{
		code: "handler_capacity", title: "Handler capacity reached",
		retryable: true,
	}
	problemConnectionDraining = problemDefinition{
		code: "connection_draining", title: "Connection is draining",
		retryable: true,
	}
	problemRateLimited = problemDefinition{
		code: "control_rate_limited", title: "Control rate limit exceeded",
		retryable: true,
	}
	problemProposalRateLimited = problemDefinition{
		code: "proposal_rate_limited", title: "Proposal rate limit exceeded",
		retryable: true,
	}
	problemLeaderProposalRateLimited = problemDefinition{
		code:      "leader_ingress_rate_limited",
		title:     "Leader proposal rate limit exceeded",
		retryable: true,
	}
	problemEventInvalid = problemDefinition{
		code: "invalid_event", title: "Invalid event proposal",
	}
	problemEventTooLarge = problemDefinition{
		code: "event_too_large", title: "Event proposal exceeds size limit",
	}
	problemEventConflict = problemDefinition{
		code: "idempotency_conflict", title: "Event ID is already bound",
	}
	problemEventUnavailable = problemDefinition{
		code: "event_unavailable", title: "Event proposal unavailable",
		retryable: true,
	}
	problemInternal = problemDefinition{
		code: "internal_error", title: "Internal server error",
		retryable: true,
	}
)

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
	encoded, err := json.Marshal(problemResponse{
		Type:          "urn:codecomm:problem:" + definition.code,
		Title:         definition.title,
		Status:        status,
		Code:          definition.code,
		CorrelationID: correlationID,
		Retryable:     definition.retryable,
	})
	if err == nil {
		encoded, err = codec.CanonicalizeSignedObject(encoded)
	}
	if err != nil {
		encoded = []byte(
			`{"code":"internal_error","correlation_id":"unavailable","retryable":true,"status":500,"title":"Internal server error","type":"urn:codecomm:problem:internal_error"}`,
		)
		status = http.StatusInternalServerError
	}
	writeJSON(writer, status, "application/problem+json", encoded)
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	contentType string,
	body []byte,
) {
	writeJSONHeader(writer, status, contentType, len(body))
	_, _ = writer.Write(body)
}

func writeJSONHeader(
	writer http.ResponseWriter,
	status int,
	contentType string,
	contentLength int,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", strconv.Itoa(contentLength))
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
}

var _ http.Handler = (*connectionHandler)(nil)
var _ transport.ConnectionHandler = (*Server)(nil)
