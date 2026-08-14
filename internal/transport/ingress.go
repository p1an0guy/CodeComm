package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// PeerConnectionsMax is the daemon-wide ceiling across pending and established
// inbound peer connections.
const (
	PeerConnectionsMax = 128

	ingressAcceptRetryBase = 5 * time.Millisecond
	ingressAcceptRetryMax  = time.Second
)

var (
	ErrInvalidIngressConfig = errors.New("transport: invalid peer ingress configuration")
	ErrIngressStarted       = errors.New("transport: peer ingress has already started")
	ErrIngressClosed        = errors.New("transport: peer ingress is closed")
)

// ConnectionHandler owns one fully authenticated connection until it returns.
// It must not repeat the TLS handshake and must honor context cancellation.
type ConnectionHandler interface {
	ServeAuthenticatedConn(context.Context, *tls.Conn) error
}

// ConnectionHandlerFunc adapts a function to ConnectionHandler.
type ConnectionHandlerFunc func(context.Context, *tls.Conn) error

func (function ConnectionHandlerFunc) ServeAuthenticatedConn(
	ctx context.Context,
	connection *tls.Conn,
) error {
	return function(ctx, connection)
}

// IngressOptions configures one shared peer listener. Unregistered planes
// complete no application dispatch and are closed after authentication.
type IngressOptions struct {
	Listener  net.Listener
	TLS       ServerTLSOptions
	Admission *AdmissionLimiter

	Pairing   ConnectionHandler
	Consensus ConnectionHandler
	Content   ConnectionHandler
}

// Ingress owns one TCP listener and dispatches exact authenticated ALPN planes.
type Ingress struct {
	listener  net.Listener
	tlsConfig *tls.Config
	admission *AdmissionLimiter
	handlers  map[Plane]ConnectionHandler
	slots     chan struct{}

	stateMu     sync.Mutex
	started     bool
	stopping    bool
	serveCancel context.CancelFunc
	active      map[net.Conn]context.CancelFunc

	stopOnce sync.Once
	stopErr  error
	work     sync.WaitGroup

	doneOnce sync.Once
	done     chan struct{}

	handshakeErrors atomic.Uint64
	dispatchErrors  atomic.Uint64
	handlerErrors   atomic.Uint64
	recoveredPanics atomic.Uint64
}

// IngressStats is bounded operational state suitable for metrics and tests.
type IngressStats struct {
	ActiveConnections int
	HandshakeErrors   uint64
	DispatchErrors    uint64
	HandlerErrors     uint64
	RecoveredPanics   uint64
}

// NewIngress validates and, on success, takes ownership of one shared peer
// listener.
func NewIngress(options IngressOptions) (*Ingress, error) {
	return newIngress(options, PeerConnectionsMax)
}

func newIngress(
	options IngressOptions,
	maxConnections int,
) (*Ingress, error) {
	if !validIngressListener(options.Listener) ||
		maxConnections < 1 ||
		maxConnections > PeerConnectionsMax {
		return nil, ErrInvalidIngressConfig
	}
	handlers := map[Plane]ConnectionHandler{}
	for plane, handler := range map[Plane]ConnectionHandler{
		PlanePairing:   options.Pairing,
		PlaneConsensus: options.Consensus,
		PlaneContent:   options.Content,
	} {
		if nilConnectionHandler(handler) {
			continue
		}
		handlers[plane] = handler
	}
	if len(handlers) == 0 {
		return nil, ErrInvalidIngressConfig
	}
	tlsConfig, err := NewServerTLSConfig(options.TLS)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIngressConfig, err)
	}
	admission := options.Admission
	if admission == nil {
		admission = NewAdmissionLimiter()
	}
	if admission.now == nil {
		return nil, ErrInvalidIngressConfig
	}
	return &Ingress{
		listener: options.Listener, tlsConfig: tlsConfig,
		admission: admission, handlers: handlers,
		slots:  make(chan struct{}, maxConnections),
		active: make(map[net.Conn]context.CancelFunc),
		done:   make(chan struct{}),
	}, nil
}

// Serve accepts peer connections until cancellation or Shutdown. Individual
// handshake and handler failures close only their connection.
func (ingress *Ingress) Serve(ctx context.Context) error {
	if ingress == nil || ctx == nil {
		return ErrInvalidIngressConfig
	}
	ingress.stateMu.Lock()
	if ingress.started {
		ingress.stateMu.Unlock()
		return ErrIngressStarted
	}
	if ingress.stopping {
		ingress.stateMu.Unlock()
		return ErrIngressClosed
	}
	ingress.started = true
	serveContext, cancel := context.WithCancel(ctx)
	ingress.serveCancel = cancel
	ingress.stateMu.Unlock()

	contextDone := make(chan struct{})
	go func() {
		select {
		case <-serveContext.Done():
			ingress.initiateShutdown()
		case <-contextDone:
		}
	}()

	var (
		serveErr        error
		acceptRetryWait time.Duration
	)
acceptLoop:
	for {
		connection, err := ingress.listener.Accept()
		if err != nil {
			ingress.stateMu.Lock()
			stopping := ingress.stopping
			ingress.stateMu.Unlock()
			if !stopping && temporaryNetworkError(err) {
				if acceptRetryWait == 0 {
					acceptRetryWait = ingressAcceptRetryBase
				} else {
					acceptRetryWait *= 2
				}
				if acceptRetryWait > ingressAcceptRetryMax {
					acceptRetryWait = ingressAcceptRetryMax
				}
				timer := time.NewTimer(
					ingressAcceptRetryDelay(acceptRetryWait),
				)
				select {
				case <-timer.C:
					continue
				case <-serveContext.Done():
					timer.Stop()
					break acceptLoop
				}
			}
			if !stopping {
				serveErr = fmt.Errorf(
					"transport: accept peer connection: %w",
					err,
				)
			}
			break
		}
		acceptRetryWait = 0
		source, ok := ingressSource(connection.RemoteAddr())
		if !ok {
			_ = connection.Close()
			continue
		}
		permit, err := ingress.admission.TryAcquire(source)
		if err != nil {
			_ = connection.Close()
			continue
		}
		if !ingress.tryConnectionSlot() {
			permit.Release()
			_ = connection.Close()
			continue
		}
		connectionContext, connectionCancel := context.WithCancel(serveContext)
		if !ingress.registerConnection(connection, connectionCancel) {
			connectionCancel()
			permit.Release()
			_ = connection.Close()
			ingress.releaseConnectionSlot()
			break
		}
		ingress.work.Add(1)
		go func() {
			defer ingress.work.Done()
			ingress.runConnection(
				connectionContext,
				connection,
				permit,
			)
		}()
	}

	close(contextDone)
	ingress.initiateShutdown()
	ingress.work.Wait()
	ingress.finish()
	return serveErr
}

// Shutdown closes the listener and active connections, then waits for every
// connection handler that honors cancellation.
func (ingress *Ingress) Shutdown(ctx context.Context) error {
	if ingress == nil || ctx == nil {
		return ErrInvalidIngressConfig
	}
	ingress.initiateShutdown()

	ingress.stateMu.Lock()
	started := ingress.started
	ingress.stateMu.Unlock()
	if !started {
		ingress.finish()
	}
	select {
	case <-ingress.done:
		return ingress.stopErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (ingress *Ingress) runConnection(
	ctx context.Context,
	connection net.Conn,
	permit *HandshakePermit,
) {
	defer ingress.recoverConnectionPanic()
	defer ingress.unregisterConnection(connection)
	defer ingress.releaseConnectionSlot()
	ingress.serveConnection(ctx, connection, permit)
}

func (ingress *Ingress) serveConnection(
	ctx context.Context,
	connection net.Conn,
	permit *HandshakePermit,
) {
	defer permit.Release()
	defer connection.Close()
	if !permit.BeginHandshake() {
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	tlsConnection := tls.Server(connection, ingress.tlsConfig)
	handshakeContext, cancel := context.WithTimeout(
		ctx,
		HandshakeTimeout,
	)
	err := tlsConnection.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			ingress.handshakeErrors.Add(1)
		}
		return
	}
	permit.Release()

	state := tlsConnection.ConnectionState()
	if !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 ||
		state.DidResume ||
		len(state.PeerCertificates) != 1 {
		ingress.dispatchErrors.Add(1)
		return
	}
	plane, err := SelectPlane([]string{state.NegotiatedProtocol})
	if err != nil {
		ingress.dispatchErrors.Add(1)
		return
	}
	handler := ingress.handlers[plane]
	if nilConnectionHandler(handler) {
		return
	}
	if err := tlsConnection.SetDeadline(time.Time{}); err != nil {
		ingress.dispatchErrors.Add(1)
		return
	}
	if err := handler.ServeAuthenticatedConn(ctx, tlsConnection); err != nil {
		contextErr := ctx.Err()
		if contextErr == nil || !errors.Is(err, contextErr) {
			ingress.handlerErrors.Add(1)
		}
	}
}

// Stats returns a fixed-size operational snapshot.
func (ingress *Ingress) Stats() IngressStats {
	if ingress == nil {
		return IngressStats{}
	}
	ingress.stateMu.Lock()
	activeConnections := len(ingress.active)
	ingress.stateMu.Unlock()
	return IngressStats{
		ActiveConnections: activeConnections,
		HandshakeErrors:   ingress.handshakeErrors.Load(),
		DispatchErrors:    ingress.dispatchErrors.Load(),
		HandlerErrors:     ingress.handlerErrors.Load(),
		RecoveredPanics:   ingress.recoveredPanics.Load(),
	}
}

func (ingress *Ingress) recoverConnectionPanic() {
	if recover() != nil {
		ingress.recoveredPanics.Add(1)
	}
}

func (ingress *Ingress) initiateShutdown() {
	ingress.stopOnce.Do(func() {
		ingress.stateMu.Lock()
		ingress.stopping = true
		if ingress.serveCancel != nil {
			ingress.serveCancel()
		}
		active := make(map[net.Conn]context.CancelFunc, len(ingress.active))
		for connection, cancel := range ingress.active {
			active[connection] = cancel
		}
		ingress.stateMu.Unlock()

		closeErr := ingress.listener.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		ingress.stopErr = closeErr
		for connection, cancel := range active {
			cancel()
			_ = connection.Close()
		}
	})
}

func (ingress *Ingress) registerConnection(
	connection net.Conn,
	cancel context.CancelFunc,
) bool {
	ingress.stateMu.Lock()
	defer ingress.stateMu.Unlock()
	if ingress.stopping {
		return false
	}
	ingress.active[connection] = cancel
	return true
}

func (ingress *Ingress) unregisterConnection(connection net.Conn) {
	ingress.stateMu.Lock()
	cancel := ingress.active[connection]
	delete(ingress.active, connection)
	ingress.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (ingress *Ingress) tryConnectionSlot() bool {
	select {
	case ingress.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (ingress *Ingress) releaseConnectionSlot() {
	<-ingress.slots
}

func (ingress *Ingress) finish() {
	ingress.doneOnce.Do(func() {
		close(ingress.done)
	})
}

func validIngressListener(listener net.Listener) bool {
	if listener == nil {
		return false
	}
	value := reflect.ValueOf(listener)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	if listener.Addr() == nil {
		return false
	}
	switch listener.Addr().Network() {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func ingressSource(address net.Addr) (netip.Addr, bool) {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil {
		return netip.Addr{}, false
	}
	source := tcpAddress.AddrPort().Addr()
	if !source.IsValid() {
		return netip.Addr{}, false
	}
	return source, true
}

func temporaryNetworkError(err error) bool {
	var networkError interface {
		Temporary() bool
	}
	return errors.As(err, &networkError) && networkError.Temporary()
}

func ingressAcceptRetryDelay(backoff time.Duration) time.Duration {
	if backoff <= time.Nanosecond {
		return backoff
	}
	floor := backoff / 2
	return floor + time.Duration(
		rand.Int64N(int64(backoff-floor)+1),
	)
}

func nilConnectionHandler(handler ConnectionHandler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ ConnectionHandler = ConnectionHandlerFunc(nil)
