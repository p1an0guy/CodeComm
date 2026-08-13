package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxConnections = 128
	MaxHandlers    = 64
	MaxHeaderBytes = 32 << 10
	MaxJSONBytes   = 1 << 20
	HeaderTimeout  = 10 * time.Second
	IdleTimeout    = 120 * time.Second
)

var (
	ErrInvalidConfig = errors.New("ipc: invalid server configuration")
	ErrServerStarted = errors.New("ipc: server has already started")
	ErrServerClosed  = errors.New("ipc: server is closed")
)

// Config binds one endpoint to one session and workspace.
type Config struct {
	Endpoint    Endpoint
	SessionID   domain.UUIDv7
	WorkspaceID domain.UUIDv4
	Binder      Binder
}

type serverLimits struct {
	maxConnections int
	maxHandlers    int
	maxHeaderBytes int
	maxJSONBytes   int64
	headerTimeout  time.Duration
	idleTimeout    time.Duration
}

func productionLimits() serverLimits {
	return serverLimits{
		maxConnections: MaxConnections,
		maxHandlers:    MaxHandlers,
		maxHeaderBytes: MaxHeaderBytes,
		maxJSONBytes:   MaxJSONBytes,
		headerTimeout:  HeaderTimeout,
		idleTimeout:    IdleTimeout,
	}
}

// Server serves strict HTTP/1.1 over one authenticated local listener.
type Server struct {
	config   Config
	limits   serverLimits
	listener *Listener

	connectionSlots chan struct{}
	handlerSlots    chan struct{}

	stateMu     sync.Mutex
	started     bool
	stopping    bool
	serveCancel context.CancelFunc
	active      map[*Conn]context.CancelFunc

	stopOnce sync.Once
	stopErr  error
	work     sync.WaitGroup

	doneOnce sync.Once
	done     chan struct{}
}

// NewServer validates configuration and reserves the endpoint. Call Serve to
// begin accepting requests.
func NewServer(config Config) (*Server, error) {
	return newServer(config, productionLimits())
}

func newServer(config Config, limits serverLimits) (*Server, error) {
	if !config.Endpoint.valid() ||
		!config.SessionID.Valid() ||
		!config.WorkspaceID.Valid() ||
		config.Binder == nil ||
		limits.maxConnections < 1 ||
		limits.maxConnections > MaxConnections ||
		limits.maxHandlers < 1 ||
		limits.maxHandlers > MaxHandlers ||
		limits.maxHeaderBytes < 1 ||
		limits.maxHeaderBytes > MaxHeaderBytes ||
		limits.maxJSONBytes < 1 ||
		limits.maxJSONBytes > MaxJSONBytes ||
		limits.headerTimeout <= 0 ||
		limits.idleTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	listener, err := Listen(config.Endpoint)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:          config,
		limits:          limits,
		listener:        listener,
		connectionSlots: make(chan struct{}, limits.maxConnections),
		handlerSlots:    make(chan struct{}, limits.maxHandlers),
		active:          make(map[*Conn]context.CancelFunc),
		done:            make(chan struct{}),
	}, nil
}

// Serve accepts requests until ctx is canceled or Shutdown is called. A
// normal shutdown returns nil.
func (server *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	server.stateMu.Lock()
	if server.started {
		server.stateMu.Unlock()
		return ErrServerStarted
	}
	if server.stopping {
		server.stateMu.Unlock()
		return ErrServerClosed
	}
	server.started = true
	serveContext, cancel := context.WithCancel(ctx)
	server.serveCancel = cancel
	server.stateMu.Unlock()

	contextDone := make(chan struct{})
	go func() {
		select {
		case <-serveContext.Done():
			server.initiateShutdown()
		case <-contextDone:
		}
	}()

	var serveErr error
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			server.stateMu.Lock()
			stopping := server.stopping
			server.stateMu.Unlock()
			if !stopping && !errors.Is(err, ErrListenerClosed) {
				serveErr = err
			}
			break
		}
		if !server.tryConnectionSlot() {
			server.rejectExcessConnection(connection)
			continue
		}
		connectionContext, connectionCancel := context.WithCancel(serveContext)
		if !server.registerConnection(connection, connectionCancel) {
			connectionCancel()
			_ = connection.Close()
			server.releaseConnectionSlot()
			break
		}
		server.work.Add(1)
		go func() {
			defer server.work.Done()
			defer server.unregisterConnection(connection)
			defer server.releaseConnectionSlot()
			server.serveConnection(connectionContext, connection)
		}()
	}

	close(contextDone)
	server.initiateShutdown()
	server.work.Wait()
	server.finish()
	return serveErr
}

// Shutdown closes the listener and active connections, then waits for
// handlers and disconnect callbacks that honor cancellation.
func (server *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	server.initiateShutdown()

	server.stateMu.Lock()
	started := server.started
	server.stateMu.Unlock()
	if !started {
		server.finish()
	}
	select {
	case <-server.done:
		return server.stopErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) initiateShutdown() {
	server.stopOnce.Do(func() {
		server.stateMu.Lock()
		server.stopping = true
		if server.serveCancel != nil {
			server.serveCancel()
		}
		active := make(map[*Conn]context.CancelFunc, len(server.active))
		for connection, cancel := range server.active {
			active[connection] = cancel
		}
		server.stateMu.Unlock()

		server.stopErr = server.listener.Close()
		for connection, cancel := range active {
			cancel()
			_ = connection.Close()
		}
	})
}

func (server *Server) finish() {
	server.doneOnce.Do(func() {
		close(server.done)
	})
}

func (server *Server) registerConnection(
	connection *Conn,
	cancel context.CancelFunc,
) bool {
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	if server.stopping {
		return false
	}
	server.active[connection] = cancel
	return true
}

func (server *Server) unregisterConnection(connection *Conn) {
	server.stateMu.Lock()
	cancel := server.active[connection]
	delete(server.active, connection)
	server.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (server *Server) tryConnectionSlot() bool {
	select {
	case server.connectionSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (server *Server) releaseConnectionSlot() {
	<-server.connectionSlots
}

func (server *Server) tryHandlerSlot() bool {
	select {
	case server.handlerSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (server *Server) releaseHandlerSlot() {
	<-server.handlerSlots
}

func (server *Server) rejectExcessConnection(connection *Conn) {
	defer connection.Close()
	correlationID, err := newCorrelationID()
	if err != nil {
		return
	}
	failure := requestFailure{
		status:    http.StatusServiceUnavailable,
		code:      "local_connection_limit",
		title:     "Local connection limit reached",
		retryable: true,
		close:     true,
	}
	_ = writeResponse(
		connection,
		server.limits.idleTimeout,
		failure.status,
		problemMediaType,
		marshalProblem(failure, correlationID),
		correlationID,
		true,
	)
}

func (server *Server) serveConnection(ctx context.Context, connection *Conn) {
	var (
		bound        BoundClient
		boundHandler http.Handler
		bindState    = connectionAwaitingBind
	)
	defer func() {
		_ = connection.Close()
		if bound != nil {
			server.notifyDisconnected(bound)
		}
	}()

	reader := bufio.NewReader(connection)
	for {
		request, body, err := readRequest(
			connection,
			reader,
			server.limits,
			bindState,
		)
		if errors.Is(err, io.EOF) ||
			errors.Is(err, net.ErrClosed) ||
			errors.Is(err, errIdleConnection) {
			return
		}
		correlationID, correlationErr := newCorrelationID()
		if correlationErr != nil {
			return
		}
		if err != nil {
			var failure *requestFailure
			if !errors.As(err, &failure) {
				value := internalFailure()
				failure = &value
			}
			_ = writeResponse(
				connection,
				server.limits.idleTimeout,
				failure.status,
				problemMediaType,
				marshalProblem(*failure, correlationID),
				correlationID,
				failure.close,
			)
			if failure.close {
				return
			}
			continue
		}

		if !server.tryHandlerSlot() {
			failure := requestFailure{
				status:    http.StatusServiceUnavailable,
				code:      "local_handler_limit",
				title:     "Local handler limit reached",
				retryable: true,
				close:     bound == nil,
			}
			_ = writeResponse(
				connection,
				server.limits.idleTimeout,
				failure.status,
				problemMediaType,
				marshalProblem(failure, correlationID),
				correlationID,
				failure.close || request.Close,
			)
			if failure.close || request.Close {
				return
			}
			continue
		}

		requestContext, requestCancel := context.WithCancel(ctx)
		monitor, monitorErr := startRequestMonitor(
			connection,
			reader,
			requestCancel,
		)
		if monitorErr != nil {
			requestCancel()
			server.releaseHandlerSlot()
			return
		}
		var response localResponse
		func() {
			defer server.releaseHandlerSlot()
			if bound == nil {
				var newlyBound BoundClient
				var newlyBoundHandler http.Handler
				newlyBound, newlyBoundHandler, response = server.handleBind(
					requestContext,
					connection.Peer(),
					request,
					body,
					correlationID,
				)
				if newlyBound != nil {
					bound = newlyBound
					boundHandler = newlyBoundHandler
					bindState = connectionBound
				}
			} else if isBindRequest(request) {
				response = problemResponse(requestFailure{
					status: http.StatusConflict,
					code:   "local_already_bound",
					title:  "Connection is already bound",
					close:  true,
				}, correlationID)
			} else {
				response = invokeHandler(
					requestContext,
					boundHandler,
					request,
					body,
					correlationID,
					server.limits,
				)
			}
		}()
		observation, monitorErr := monitor.stop()
		requestCancel()
		if monitorErr != nil || observation.disconnected {
			return
		}

		closeConnection := response.close || request.Close || observation.pipelined
		if err := writeResponse(
			connection,
			server.limits.idleTimeout,
			response.status,
			response.contentType,
			response.body,
			correlationID,
			closeConnection,
		); err != nil || closeConnection {
			return
		}
	}
}

func (server *Server) handleBind(
	ctx context.Context,
	peer VerifiedPeer,
	request *http.Request,
	body []byte,
	correlationID string,
) (BoundClient, http.Handler, localResponse) {
	if !isBindRequest(request) {
		return nil, nil, problemResponse(requestFailure{
			status: http.StatusConflict,
			code:   "local_bind_required",
			title:  "Connection must bind before use",
			close:  true,
		}, correlationID)
	}
	bindRequest, err := decodeBindRequest(body)
	if err != nil {
		return nil, nil, problemResponse(requestFailure{
			status: http.StatusBadRequest,
			code:   "local_invalid_bind",
			title:  "Invalid local bind request",
			close:  true,
		}, correlationID)
	}
	if bindRequest.ProtocolVersion != LocalProtocolVersion {
		return nil, nil, problemResponse(requestFailure{
			status: http.StatusUpgradeRequired,
			code:   "local_protocol_mismatch",
			title:  "Incompatible local protocol",
			detail: fmt.Sprintf(
				"supported local protocol version is %d",
				LocalProtocolVersion,
			),
			close: true,
		}, correlationID)
	}
	if bindRequest.SessionID != server.config.SessionID ||
		bindRequest.WorkspaceID != server.config.WorkspaceID {
		return nil, nil, problemResponse(requestFailure{
			status: http.StatusForbidden,
			code:   "local_session_mismatch",
			title:  "Endpoint does not serve the selected session",
			close:  true,
		}, correlationID)
	}

	result, bindErr := safeBind(
		server.config.Binder,
		ctx,
		peer,
		bindRequest,
	)
	bound, capability, resultOK := consumeBindResult(result, bindRequest.Class)
	handler, handlerOK := safeBoundHandler(bound)
	if bindErr != nil || !resultOK || !handlerOK {
		if bound != nil {
			server.notifyDisconnected(bound)
		}
		return nil, nil, problemResponse(requestFailure{
			status: http.StatusForbidden,
			code:   "local_bind_rejected",
			title:  "Local bind was rejected",
			close:  true,
		}, correlationID)
	}
	response := bindResponse{
		LocalProtocolVersion: LocalProtocolVersion,
		ClientInstanceID:     string(bindRequest.ClientInstanceID),
		SessionID:            string(bindRequest.SessionID),
		WorkspaceID:          string(bindRequest.WorkspaceID),
		ClientClass:          bindRequest.Class.String(),
	}
	var responseBody any = response
	if result.kind == bindResultAgentLaunch {
		responseBody = launchBindResponse{
			bindResponse:     response,
			ResumeCapability: codec.EncodeBase64URL(capability),
		}
	}
	encoded, err := marshalJSON(responseBody, server.limits.maxJSONBytes)
	if err != nil {
		server.notifyDisconnected(bound)
		return nil, nil, problemResponse(internalFailure(), correlationID)
	}
	return bound, handler, localResponse{
		status:      http.StatusOK,
		contentType: "application/json",
		body:        encoded,
	}
}

func consumeBindResult(
	result BindResult,
	requestClass ClientClass,
) (BoundClient, []byte, bool) {
	compatible := requestClass == ClassOperator &&
		result.kind == bindResultOperator ||
		requestClass == ClassAgent &&
			(result.kind == bindResultAgentLaunch ||
				result.kind == bindResultAgentResume)
	if !compatible || nilBoundClient(result.client) {
		return result.client, nil, false
	}
	switch result.kind {
	case bindResultOperator, bindResultAgentResume:
		if len(result.resumeCapability) != 0 {
			return result.client, nil, false
		}
		return result.client, nil, true
	case bindResultAgentLaunch:
		if len(result.resumeCapability) != 32 {
			return result.client, nil, false
		}
		return result.client, result.resumeCapability, true
	default:
		return result.client, nil, false
	}
}

func isBindRequest(request *http.Request) bool {
	return request.Method == http.MethodPost &&
		request.RequestURI == bindPath &&
		request.URL.Path == bindPath &&
		request.URL.RawQuery == ""
}

func safeBoundHandler(bound BoundClient) (handler http.Handler, ok bool) {
	if nilBoundClient(bound) {
		return nil, false
	}
	defer func() {
		if recover() != nil {
			handler = nil
			ok = false
		}
	}()
	handler = bound.Handler()
	return handler, handler != nil
}

func nilBoundClient(bound BoundClient) bool {
	if bound == nil {
		return true
	}
	value := reflect.ValueOf(bound)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func safeBind(
	binder Binder,
	ctx context.Context,
	peer VerifiedPeer,
	request BindRequest,
) (result BindResult, err error) {
	defer func() {
		if recover() != nil {
			result = BindResult{}
			err = ErrBindRejected
		}
	}()
	return binder.Bind(ctx, peer, request)
}

func (server *Server) notifyDisconnected(bound BoundClient) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		server.limits.headerTimeout,
	)
	defer cancel()
	defer func() {
		_ = recover()
	}()
	bound.Disconnected(ctx)
}
