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

	ingressAcceptRetryBase          = 5 * time.Millisecond
	ingressAcceptRetryMax           = time.Second
	peerEstablishmentVerifyAttempts = 2
	peerConsensusConnectionsMax     = 1
	// TLS ingress cannot classify content-control versus bulk until HTTP
	// dispatch. Permit three current slots plus one draining predecessor each;
	// the HTTP layer applies the narrower 1-control/2-bulk limits.
	peerContentConnectionsMax = 6
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
	// PeerAccessChanges coalesces applied membership and credential changes.
	// Each signal revalidates all established peers against current policy.
	PeerAccessChanges <-chan struct{}

	Pairing   ConnectionHandler
	Consensus ConnectionHandler
	Content   ConnectionHandler
}

// Ingress owns one TCP listener and dispatches exact authenticated ALPN planes.
type Ingress struct {
	listener          net.Listener
	tlsConfig         *tls.Config
	clearTLSIdentity  func()
	admission         *AdmissionLimiter
	handlers          map[Plane]ConnectionHandler
	slots             chan struct{}
	peerAccessChanges <-chan struct{}

	verifyPairing   IdentityPeerVerifier
	verifyConsensus IdentityPeerVerifier
	verifyContent   ContentPeerVerifier

	stateMu                sync.Mutex
	started                bool
	stopping               bool
	serveCancel            context.CancelFunc
	revalidationGeneration uint64
	memberAccessAvailable  bool
	active                 map[net.Conn]*ingressPeer
	selectedContent        map[net.Conn]ContentCertificate

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

type ingressPeer struct {
	cancel       context.CancelFunc
	credentials  peerCredentials
	localContent ContentCertificate
	established  bool
	closing      bool
}

type ingressPeerSnapshot struct {
	connection   net.Conn
	peer         *ingressPeer
	credentials  peerCredentials
	localContent ContentCertificate
}

// IngressStats is bounded operational state suitable for metrics and tests.
type IngressStats struct {
	ActiveConnections      int
	PendingConnections     int
	EstablishedConnections int
	HandshakeErrors        uint64
	DispatchErrors         uint64
	HandlerErrors          uint64
	RecoveredPanics        uint64
}

// RevalidationResult reports one bounded pass over established peers.
type RevalidationResult struct {
	Checked int
	Closed  int
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
	memberHandlers := handlers[PlaneConsensus] != nil ||
		handlers[PlaneContent] != nil
	if memberHandlers && options.PeerAccessChanges == nil {
		return nil, ErrInvalidIngressConfig
	}
	admission := options.Admission
	if admission == nil {
		admission = NewAdmissionLimiter()
	}
	if admission.now == nil {
		return nil, ErrInvalidIngressConfig
	}
	ingress := &Ingress{
		listener:  options.Listener,
		admission: admission, handlers: handlers,
		slots:                 make(chan struct{}, maxConnections),
		peerAccessChanges:     options.PeerAccessChanges,
		verifyPairing:         options.TLS.VerifyPairingPeer,
		verifyConsensus:       options.TLS.VerifyConsensusPeer,
		verifyContent:         options.TLS.VerifyContentPeer,
		memberAccessAvailable: !memberHandlers || options.PeerAccessChanges != nil,
		active:                make(map[net.Conn]*ingressPeer),
		selectedContent:       make(map[net.Conn]ContentCertificate),
		done:                  make(chan struct{}),
	}
	tlsConfig, clearTLSIdentity, err := newOwnedServerTLSConfig(
		options.TLS,
		ingress.recordSelectedContentCertificate,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIngressConfig, err)
	}
	ingress.tlsConfig = tlsConfig
	ingress.clearTLSIdentity = clearTLSIdentity
	return ingress, nil
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

	if ingress.peerAccessChanges != nil {
		ingress.work.Add(1)
		go func() {
			defer ingress.work.Done()
			ingress.watchPeerAccessChanges(serveContext)
		}()
	}

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

func (ingress *Ingress) watchPeerAccessChanges(ctx context.Context) {
	for {
		select {
		case _, open := <-ingress.peerAccessChanges:
			if !open {
				ingress.disableMemberAccess()
				return
			}
			ingress.RevalidatePeers()
		case <-ctx.Done():
			return
		}
	}
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

// BeginShutdown synchronously stops admission of new connections without
// waiting for active handlers. Shutdown completes the drain.
func (ingress *Ingress) BeginShutdown() error {
	if ingress == nil {
		return ErrInvalidIngressConfig
	}
	ingress.initiateShutdown()

	ingress.stateMu.Lock()
	started := ingress.started
	ingress.stateMu.Unlock()
	if !started {
		ingress.finish()
	}
	return ingress.stopErr
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
	credentials, err := parsePeerCredentials(
		plane,
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		ingress.dispatchErrors.Add(1)
		return
	}
	var localContent ContentCertificate
	if plane == PlaneContent {
		var found bool
		localContent, found =
			ingress.takeSelectedContentCertificate(connection)
		if !found {
			ingress.dispatchErrors.Add(1)
			return
		}
	}
	metadata, trackedPeer, closeAt, ok := ingress.establishPeer(
		connection,
		credentials,
		localContent,
	)
	if !ok {
		ingress.dispatchErrors.Add(1)
		return
	}
	var expiryTimer *time.Timer
	if plane == PlaneContent {
		closeAfter := time.Until(closeAt)
		if closeAfter <= 0 {
			ingress.closeTrackedPeer(connection, trackedPeer)
			ingress.dispatchErrors.Add(1)
			return
		}
		expiryTimer = time.AfterFunc(closeAfter, func() {
			ingress.closeTrackedPeer(connection, trackedPeer)
		})
		defer expiryTimer.Stop()
	}
	handler := ingress.handlers[plane]
	if nilConnectionHandler(handler) {
		return
	}
	if err := tlsConnection.SetDeadline(time.Time{}); err != nil {
		ingress.dispatchErrors.Add(1)
		return
	}
	handlerContext := context.WithValue(
		ctx,
		authenticatedPeerContextKey{},
		&authenticatedPeerContext{
			metadata: metadata,
			reauthorize: func() error {
				return ingress.reauthorizePeer(connection, trackedPeer)
			},
		},
	)
	if err := handler.ServeAuthenticatedConn(handlerContext, tlsConnection); err != nil {
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
	establishedConnections := 0
	for _, peer := range ingress.active {
		if peer.established {
			establishedConnections++
		}
	}
	ingress.stateMu.Unlock()
	return IngressStats{
		ActiveConnections:      activeConnections,
		PendingConnections:     activeConnections - establishedConnections,
		EstablishedConnections: establishedConnections,
		HandshakeErrors:        ingress.handshakeErrors.Load(),
		DispatchErrors:         ingress.dispatchErrors.Load(),
		HandlerErrors:          ingress.handlerErrors.Load(),
		RecoveredPanics:        ingress.recoveredPanics.Load(),
	}
}

// RevalidatePeers reruns current admission policy for every established peer.
// Each call examines at most PeerConnectionsMax peers.
func (ingress *Ingress) RevalidatePeers() RevalidationResult {
	if ingress == nil {
		return RevalidationResult{}
	}
	ingress.stateMu.Lock()
	ingress.revalidationGeneration++
	if ingress.stopping {
		ingress.stateMu.Unlock()
		return RevalidationResult{}
	}
	peers := make([]ingressPeerSnapshot, 0, len(ingress.active))
	for connection, peer := range ingress.active {
		if !peer.established || peer.closing {
			continue
		}
		peers = append(peers, ingressPeerSnapshot{
			connection:   connection,
			peer:         peer,
			credentials:  peer.credentials,
			localContent: peer.localContent,
		})
	}
	ingress.stateMu.Unlock()

	result := RevalidationResult{Checked: len(peers)}
	for _, peer := range peers {
		if _, authorized := ingress.verifyPeer(
			peer.credentials,
			peer.localContent,
		); authorized {
			continue
		}
		if ingress.closeTrackedPeer(peer.connection, peer.peer) {
			result.Closed++
		}
	}
	return result
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
		for connection, peer := range ingress.active {
			peer.closing = true
			active[connection] = peer.cancel
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
	ingress.active[connection] = &ingressPeer{cancel: cancel}
	return true
}

func (ingress *Ingress) unregisterConnection(connection net.Conn) {
	ingress.stateMu.Lock()
	peer := ingress.active[connection]
	delete(ingress.active, connection)
	delete(ingress.selectedContent, connection)
	ingress.stateMu.Unlock()
	if peer != nil {
		peer.cancel()
	}
}

func (ingress *Ingress) establishPeer(
	connection net.Conn,
	credentials peerCredentials,
	localContent ContentCertificate,
) (AuthenticatedPeer, *ingressPeer, time.Time, bool) {
	for range peerEstablishmentVerifyAttempts {
		ingress.stateMu.Lock()
		peer := ingress.active[connection]
		if ingress.stopping ||
			!ingress.memberAccessPermitted(credentials.metadata.Plane) ||
			!ingress.peerConnectionSlotAvailable(connection, credentials.metadata) ||
			peer == nil ||
			peer.closing ||
			peer.established {
			ingress.stateMu.Unlock()
			return AuthenticatedPeer{}, nil, time.Time{}, false
		}
		generation := ingress.revalidationGeneration
		ingress.stateMu.Unlock()

		closeAt, authorized := ingress.verifyPeer(
			credentials,
			localContent,
		)
		if !authorized {
			return AuthenticatedPeer{}, nil, time.Time{}, false
		}

		ingress.stateMu.Lock()
		peer = ingress.active[connection]
		switch {
		case ingress.stopping ||
			!ingress.memberAccessPermitted(credentials.metadata.Plane) ||
			!ingress.peerConnectionSlotAvailable(connection, credentials.metadata) ||
			peer == nil ||
			peer.closing ||
			peer.established:
			ingress.stateMu.Unlock()
			return AuthenticatedPeer{}, nil, time.Time{}, false
		case generation == ingress.revalidationGeneration:
			peer.credentials = credentials
			peer.localContent = localContent
			peer.established = true
			ingress.stateMu.Unlock()
			return credentials.metadata, peer, closeAt, true
		default:
			ingress.stateMu.Unlock()
		}
	}
	return AuthenticatedPeer{}, nil, time.Time{}, false
}

func (ingress *Ingress) verifyPeer(
	credentials peerCredentials,
	localContent ContentCertificate,
) (closeAt time.Time, authorized bool) {
	defer func() {
		if recover() != nil {
			ingress.recoveredPanics.Add(1)
			closeAt = time.Time{}
			authorized = false
		}
	}()
	switch credentials.metadata.Plane {
	case PlanePairing:
		return time.Time{}, ingress.verifyPairing != nil &&
			ingress.verifyPairing(credentials.identity) == nil
	case PlaneConsensus:
		return time.Time{}, ingress.verifyConsensus != nil &&
			ingress.verifyConsensus(credentials.identity) == nil
	case PlaneContent:
		if ingress.verifyContent == nil {
			return time.Time{}, false
		}
		started := time.Now()
		remoteAdmission, err := ingress.verifyContent(
			credentials.content,
		)
		if err != nil ||
			!remoteAdmission.validFor(credentials.content) {
			return time.Time{}, false
		}
		localAdmission, err := ingress.verifyContent(localContent)
		if err != nil || !localAdmission.validFor(localContent) {
			return time.Time{}, false
		}
		closeAfter := min(
			remoteAdmission.CloseAfter,
			localAdmission.CloseAfter,
		)
		closeAt := started.Add(closeAfter)
		if !closeAt.After(time.Now()) {
			return time.Time{}, false
		}
		return closeAt, true
	default:
		return time.Time{}, false
	}
}

func (ingress *Ingress) reauthorizePeer(
	connection net.Conn,
	expected *ingressPeer,
) error {
	for range peerEstablishmentVerifyAttempts {
		ingress.stateMu.Lock()
		peer := ingress.active[connection]
		if ingress.stopping ||
			peer == nil ||
			peer != expected ||
			peer.closing ||
			!peer.established ||
			!ingress.memberAccessPermitted(
				peer.credentials.metadata.Plane,
			) {
			ingress.stateMu.Unlock()
			return ErrPeerAuthorizationUnavailable
		}
		generation := ingress.revalidationGeneration
		credentials := peer.credentials
		localContent := peer.localContent
		ingress.stateMu.Unlock()

		if _, authorized := ingress.verifyPeer(
			credentials,
			localContent,
		); !authorized {
			ingress.closeTrackedPeer(connection, expected)
			return ErrPeerAuthorizationDenied
		}

		ingress.stateMu.Lock()
		peer = ingress.active[connection]
		switch {
		case ingress.stopping ||
			peer == nil ||
			peer != expected ||
			peer.closing ||
			!peer.established ||
			!ingress.memberAccessPermitted(
				peer.credentials.metadata.Plane,
			):
			ingress.stateMu.Unlock()
			return ErrPeerAuthorizationUnavailable
		case generation == ingress.revalidationGeneration:
			ingress.stateMu.Unlock()
			return nil
		default:
			ingress.stateMu.Unlock()
		}
	}
	ingress.closeTrackedPeer(connection, expected)
	return ErrPeerAuthorizationUnavailable
}

func (ingress *Ingress) recordSelectedContentCertificate(
	connection net.Conn,
	certificate ContentCertificate,
) {
	if connection == nil || certificate.Leaf == nil {
		return
	}
	ingress.stateMu.Lock()
	defer ingress.stateMu.Unlock()
	peer := ingress.active[connection]
	if ingress.stopping || peer == nil || peer.established || peer.closing {
		return
	}
	ingress.selectedContent[connection] = certificate
}

func (ingress *Ingress) takeSelectedContentCertificate(
	connection net.Conn,
) (ContentCertificate, bool) {
	ingress.stateMu.Lock()
	defer ingress.stateMu.Unlock()
	certificate, found := ingress.selectedContent[connection]
	delete(ingress.selectedContent, connection)
	return certificate, found
}

func (ingress *Ingress) memberAccessPermitted(plane Plane) bool {
	return plane == PlanePairing || ingress.memberAccessAvailable
}

// peerConnectionSlotAvailable runs only while stateMu is held.
func (ingress *Ingress) peerConnectionSlotAvailable(
	candidate net.Conn,
	metadata AuthenticatedPeer,
) bool {
	limit := 0
	switch metadata.Plane {
	case PlanePairing:
		return true
	case PlaneConsensus:
		limit = peerConsensusConnectionsMax
	case PlaneContent:
		limit = peerContentConnectionsMax
	default:
		return false
	}
	count := 0
	for connection, peer := range ingress.active {
		if connection == candidate ||
			!peer.established ||
			peer.closing ||
			peer.credentials.metadata.Plane != metadata.Plane ||
			peer.credentials.metadata.DeviceID != metadata.DeviceID {
			continue
		}
		count++
		if count >= limit {
			return false
		}
	}
	return true
}

func (ingress *Ingress) disableMemberAccess() {
	ingress.stateMu.Lock()
	if !ingress.memberAccessAvailable {
		ingress.stateMu.Unlock()
		return
	}
	ingress.memberAccessAvailable = false
	ingress.revalidationGeneration++
	peers := make([]ingressPeerSnapshot, 0, len(ingress.active))
	for connection, peer := range ingress.active {
		if peer.closing || !peer.established ||
			peer.credentials.metadata.Plane == PlanePairing {
			continue
		}
		peers = append(peers, ingressPeerSnapshot{
			connection: connection,
			peer:       peer,
		})
	}
	ingress.stateMu.Unlock()

	for _, peer := range peers {
		ingress.closeTrackedPeer(peer.connection, peer.peer)
	}
}

func (ingress *Ingress) closeTrackedPeer(
	connection net.Conn,
	expected *ingressPeer,
) bool {
	ingress.stateMu.Lock()
	peer := ingress.active[connection]
	if peer == nil || peer.closing || expected != nil && peer != expected {
		ingress.stateMu.Unlock()
		return false
	}
	peer.closing = true
	cancel := peer.cancel
	ingress.stateMu.Unlock()

	cancel()
	_ = connection.Close()
	return true
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
		if ingress.clearTLSIdentity != nil {
			ingress.clearTLSIdentity()
			ingress.clearTLSIdentity = nil
		}
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
