package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"golang.org/x/net/http2"
)

const (
	ConsensusRaftPath      = "/v1/consensus/raft"
	ConsensusRaftProtocol  = "codecomm-raft"
	ConsensusRaftAuthority = "codecomm.peer"

	ConsensusStreamsPerConnectionMax = 32
	ConsensusActiveHandlersMax       = 128
	ConsensusEndpointCandidatesMax   = 64
	ConsensusHeaderMaxBytes          = 32 << 10
	ConsensusControlBodyMaxBytes     = 1 << 20

	consensusConnectionIdle = 120 * time.Second
	consensusRequestHeader  = 10 * time.Second
	consensusControlRequest = 30 * time.Second
	consensusStreamProgress = 30 * time.Second
	consensusPingTimeout    = 10 * time.Second
	consensusCopyBufferSize = 32 << 10
)

var (
	ErrInvalidConsensusStreamOptions = errors.New(
		"transport: invalid consensus stream options",
	)
	ErrConsensusStreamClosed = errors.New(
		"transport: consensus stream layer is closed",
	)
	ErrConsensusPeerDenied = errors.New(
		"transport: consensus peer is outside the live configuration",
	)
	ErrConsensusEndpointUnavailable = errors.New(
		"transport: no usable consensus endpoint",
	)
	ErrConsensusStreamCapacity = errors.New(
		"transport: consensus stream capacity reached",
	)
	ErrConsensusStreamRejected = errors.New(
		"transport: consensus stream rejected by peer",
	)
	ErrConsensusRequestHeaderTimeout = errors.New(
		"transport: consensus request header timed out",
	)
	ErrInvalidConsensusControlRequest = errors.New(
		"transport: invalid consensus control request",
	)
	ErrConsensusControlResponse = errors.New(
		"transport: invalid consensus control response",
	)
)

// ConsensusControlResponse is one bounded response from the fixed consensus
// proof route. Body storage belongs to the caller.
type ConsensusControlResponse struct {
	StatusCode int
	MediaType  string
	Body       []byte
}

// ConsensusEndpointResolver supplies bounded, verified literal dial targets
// without coupling the transport to discovery retention or priority policy.
type ConsensusEndpointResolver interface {
	ResolveConsensusEndpoints(
		context.Context,
		domain.DeviceID,
	) ([]netip.AddrPort, error)
}

// ConsensusEndpointDialer enforces local route/interface policy while dialing
// one resolver-approved literal endpoint.
type ConsensusEndpointDialer interface {
	DialConsensusEndpoint(
		context.Context,
		netip.AddrPort,
	) (net.Conn, error)
}

// ConsensusEndpointDialerFunc adapts a function to ConsensusEndpointDialer.
type ConsensusEndpointDialerFunc func(
	context.Context,
	netip.AddrPort,
) (net.Conn, error)

func (function ConsensusEndpointDialerFunc) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	return function(ctx, endpoint)
}

// ExpectedConsensusPeerVerifier pins an outbound TLS connection to the
// device ID carried in the Raft server address.
type ExpectedConsensusPeerVerifier func(
	domain.DeviceID,
	IdentityCertificate,
) error

// ConsensusPeerAuthorizer checks current live Raft configuration. It must be
// concurrency-safe and is intentionally separate from applied-membership TLS
// admission.
type ConsensusPeerAuthorizer func(domain.DeviceID) error

// ConsensusStreamOptions configures the RFC 8441 Raft byte-stream adapter.
// AuthorizationChanges must signal after either applied membership or live
// Raft configuration changes; closing it makes all Raft stream authorization
// fail closed.
type ConsensusStreamOptions struct {
	LocalDeviceID        domain.DeviceID
	IdentityCertificate  tls.Certificate
	Endpoints            ConsensusEndpointResolver
	Dialer               ConsensusEndpointDialer
	VerifyExpectedPeer   ExpectedConsensusPeerVerifier
	AuthorizePeer        ConsensusPeerAuthorizer
	AuthorizationChanges <-chan struct{}
	ControlHandler       http.Handler
}

// ConsensusStreamLayer carries HashiCorp Raft's maintained framing over
// authenticated RFC 8441 streams.
type ConsensusStreamLayer struct {
	localDeviceID        domain.DeviceID
	identityCertificate  tls.Certificate
	endpoints            ConsensusEndpointResolver
	dialer               ConsensusEndpointDialer
	verifyExpectedPeer   ExpectedConsensusPeerVerifier
	authorizePeer        ConsensusPeerAuthorizer
	authorizationChanges <-chan struct{}
	controlHandler       http.Handler
	requestHeaderTimeout time.Duration

	http2    *http2.Server
	handlers chan struct{}
	accept   chan net.Conn

	ctx    context.Context
	cancel context.CancelFunc

	mu                     sync.Mutex
	closed                 bool
	authorizationAvailable bool
	peers                  map[domain.DeviceID]*consensusPeerClient
	streams                map[*consensusStreamConn]struct{}

	watchDone chan struct{}

	closeOnce sync.Once
	closeErr  error
}

type consensusPeerClient struct {
	layer *ConsensusStreamLayer
	slots chan struct{}

	mu          sync.Mutex
	physical    *consensusPhysicalClient
	openStreams int
}

type consensusPhysicalClient struct {
	raw      *tls.Conn
	http2    *http2.ClientConn
	identity IdentityCertificate
}

type consensusPeerSlot struct {
	peer *consensusPeerClient
	once sync.Once
}

// NewConsensusStreamLayer validates and constructs the production stream
// layer. Extended CONNECT cannot be enabled after package initialization, so
// absence of the process-startup flag is a hard startup error.
func NewConsensusStreamLayer(
	options ConsensusStreamOptions,
) (*ConsensusStreamLayer, error) {
	if err := requireExtendedConnectStartup(); err != nil {
		return nil, err
	}
	if !options.LocalDeviceID.Valid() ||
		nilConsensusDependency(options.Endpoints) ||
		nilConsensusDependency(options.Dialer) ||
		options.VerifyExpectedPeer == nil ||
		options.AuthorizePeer == nil ||
		options.AuthorizationChanges == nil ||
		nilConsensusDependency(options.ControlHandler) {
		return nil, ErrInvalidConsensusStreamOptions
	}
	certificate, err := validateAndCloneTLSCertificate(
		options.IdentityCertificate,
		PlaneConsensus,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: identity certificate",
			ErrInvalidConsensusStreamOptions,
		)
	}
	identity, err := ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil ||
		identity.Binding.DeviceID != options.LocalDeviceID {
		return nil, fmt.Errorf(
			"%w: local device ID does not match identity certificate",
			ErrInvalidConsensusStreamOptions,
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	layer := &ConsensusStreamLayer{
		localDeviceID:        options.LocalDeviceID,
		identityCertificate:  certificate,
		endpoints:            options.Endpoints,
		dialer:               options.Dialer,
		verifyExpectedPeer:   options.VerifyExpectedPeer,
		authorizePeer:        options.AuthorizePeer,
		authorizationChanges: options.AuthorizationChanges,
		controlHandler:       options.ControlHandler,
		requestHeaderTimeout: consensusRequestHeader,
		http2: &http2.Server{
			MaxConcurrentStreams:      ConsensusStreamsPerConnectionMax,
			MaxDecoderHeaderTableSize: 4 << 10,
			MaxEncoderHeaderTableSize: 4 << 10,
			MaxReadFrameSize:          16 << 10,
			IdleTimeout:               consensusConnectionIdle,
			ReadIdleTimeout:           consensusStreamProgress,
			PingTimeout:               consensusPingTimeout,
		},
		handlers:               make(chan struct{}, ConsensusActiveHandlersMax),
		accept:                 make(chan net.Conn, ConsensusActiveHandlersMax),
		ctx:                    ctx,
		cancel:                 cancel,
		authorizationAvailable: true,
		peers: make(
			map[domain.DeviceID]*consensusPeerClient,
		),
		streams:   make(map[*consensusStreamConn]struct{}),
		watchDone: make(chan struct{}),
	}
	go layer.watchAuthorizationChanges()
	return layer, nil
}

// Accept returns one authorized logical RFC 8441 stream to Raft.
func (layer *ConsensusStreamLayer) Accept() (net.Conn, error) {
	if layer == nil || layer.ctx == nil {
		return nil, ErrInvalidConsensusStreamOptions
	}
	select {
	case <-layer.ctx.Done():
		return nil, net.ErrClosed
	default:
	}
	select {
	case <-layer.ctx.Done():
		return nil, net.ErrClosed
	case connection := <-layer.accept:
		if connection == nil {
			return nil, net.ErrClosed
		}
		select {
		case <-layer.ctx.Done():
			_ = connection.Close()
			return nil, net.ErrClosed
		default:
			return connection, nil
		}
	}
}

// Dial resolves a Raft device address and opens one logical stream on the
// peer's single reusable outbound HTTP/2 connection.
func (layer *ConsensusStreamLayer) Dial(
	address raft.ServerAddress,
	timeout time.Duration,
) (_ net.Conn, err error) {
	if layer == nil || layer.ctx == nil || timeout <= 0 {
		return nil, ErrInvalidConsensusStreamOptions
	}
	deviceID := domain.DeviceID(address)
	if !deviceID.Valid() || deviceID == layer.localDeviceID {
		return nil, ErrInvalidConsensusStreamOptions
	}
	ctx, cancel := context.WithTimeout(layer.ctx, timeout)
	defer cancel()
	if err := layer.authorize(deviceID); err != nil {
		return nil, err
	}
	peer, err := layer.peer(deviceID)
	if err != nil {
		return nil, err
	}
	if err := peer.acquire(ctx); err != nil {
		return nil, err
	}
	slot := &consensusPeerSlot{peer: peer}
	transferredSlot := false
	defer func() {
		if !transferredSlot {
			slot.release()
		}
	}()

	peer.mu.Lock()
	if err := layer.openError(); err != nil {
		peer.mu.Unlock()
		return nil, err
	}
	if peer.physical == nil || !peer.physical.usable() {
		if peer.openStreams != 0 {
			peer.mu.Unlock()
			return nil, ErrConsensusEndpointUnavailable
		}
		if peer.physical != nil {
			_ = peer.physical.close()
			peer.physical = nil
		}
		physical, dialErr := layer.dialPhysical(ctx, deviceID)
		if dialErr != nil {
			peer.mu.Unlock()
			return nil, dialErr
		}
		peer.physical = physical
	}
	if err := layer.verifyExpected(
		deviceID,
		peer.physical.identity,
	); err != nil {
		physical := peer.physical
		peer.physical = nil
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, err
	}
	if err := layer.authorize(deviceID); err != nil {
		physical := peer.physical
		peer.physical = nil
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, err
	}
	connection, streamErr := layer.openOutboundStream(
		ctx,
		deviceID,
		peer.physical,
	)
	if streamErr != nil {
		if !peer.physical.usable() && peer.openStreams == 0 {
			_ = peer.physical.close()
			peer.physical = nil
		}
		peer.mu.Unlock()
		return nil, streamErr
	}
	peer.openStreams++
	if !layer.register(connection) {
		peer.openStreams--
		peer.mu.Unlock()
		_ = connection.Close()
		return nil, ErrConsensusStreamClosed
	}
	peer.mu.Unlock()
	if !connection.addCloseHook(func() {
		peer.streamClosed()
		slot.release()
		layer.unregister(connection)
	}) {
		return nil, ErrConsensusStreamClosed
	}
	transferredSlot = true
	return connection, nil
}

// Close ends every logical stream and outbound physical connection.
func (layer *ConsensusStreamLayer) Close() error {
	if layer == nil {
		return ErrInvalidConsensusStreamOptions
	}
	layer.closeOnce.Do(func() {
		layer.cancel()
		<-layer.watchDone
		layer.mu.Lock()
		layer.closed = true
		peers := make([]*consensusPeerClient, 0, len(layer.peers))
		for _, peer := range layer.peers {
			peers = append(peers, peer)
		}
		streams := make(
			[]*consensusStreamConn,
			0,
			len(layer.streams),
		)
		for stream := range layer.streams {
			streams = append(streams, stream)
		}
		layer.mu.Unlock()

		var closeErrors []error
		for _, peer := range peers {
			if err := peer.close(); err != nil &&
				!errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		for _, stream := range streams {
			if err := stream.Close(); err != nil &&
				!errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		layer.closeErr = errors.Join(closeErrors...)
	})
	return layer.closeErr
}

// Addr is the stable Raft address persisted in configurations.
func (layer *ConsensusStreamLayer) Addr() net.Addr {
	if layer == nil {
		return consensusDeviceAddr{}
	}
	return consensusDeviceAddr{deviceID: layer.localDeviceID}
}

// ServeAuthenticatedConn serves one consensus-plane connection already
// admitted by Ingress. It never applies deadlines to the shared TLS socket.
func (layer *ConsensusStreamLayer) ServeAuthenticatedConn(
	ctx context.Context,
	connection *tls.Conn,
) error {
	if layer == nil || layer.http2 == nil || layer.handlers == nil ||
		ctx == nil || connection == nil {
		return ErrInvalidConsensusStreamOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := layer.openError(); err != nil {
		return err
	}
	peer, ok := AuthenticatedPeerFromContext(ctx)
	if !ok || peer.Plane != PlaneConsensus ||
		!validConsensusConnectionState(
			connection.ConnectionState(),
			peer,
		) {
		return ErrTLSAdmission
	}

	connectionContext, cancel := context.WithCancel(ctx)
	headerGuard := newConsensusHeaderGuard(
		connection,
		layer.requestHeaderTimeout,
	)
	trackedConnection := &consensusHeaderTrackingConn{
		Conn:  connection,
		guard: headerGuard,
	}
	serveDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-connectionContext.Done():
			_ = connection.Close()
		case <-layer.ctx.Done():
			_ = connection.Close()
		case <-serveDone:
		}
	}()
	defer func() {
		headerGuard.stop()
		cancel()
		close(serveDone)
		<-watcherDone
	}()

	layer.http2.ServeConn(trackedConnection, &http2.ServeConnOpts{
		Context: connectionContext,
		BaseConfig: &http.Server{
			IdleTimeout:    consensusConnectionIdle,
			MaxHeaderBytes: ConsensusHeaderMaxBytes,
		},
		Handler: &consensusConnectionHandler{
			layer: layer,
			peer:  peer,
		},
	})
	if headerGuard.timedOut() {
		return ErrConsensusRequestHeaderTimeout
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := layer.openError(); err != nil {
		return err
	}
	return nil
}

func (layer *ConsensusStreamLayer) peer(
	deviceID domain.DeviceID,
) (*consensusPeerClient, error) {
	layer.mu.Lock()
	defer layer.mu.Unlock()
	if layer.closed {
		return nil, ErrConsensusStreamClosed
	}
	peer := layer.peers[deviceID]
	if peer == nil {
		peer = &consensusPeerClient{
			layer: layer,
			slots: make(
				chan struct{},
				ConsensusStreamsPerConnectionMax,
			),
		}
		layer.peers[deviceID] = peer
	}
	return peer, nil
}

func (layer *ConsensusStreamLayer) register(
	stream *consensusStreamConn,
) bool {
	if stream == nil {
		return false
	}
	layer.mu.Lock()
	defer layer.mu.Unlock()
	if layer.closed {
		return false
	}
	layer.streams[stream] = struct{}{}
	return true
}

func (layer *ConsensusStreamLayer) unregister(
	stream *consensusStreamConn,
) {
	if layer == nil || stream == nil {
		return
	}
	layer.mu.Lock()
	delete(layer.streams, stream)
	layer.mu.Unlock()
}

func (layer *ConsensusStreamLayer) watchAuthorizationChanges() {
	defer close(layer.watchDone)
	for {
		select {
		case _, open := <-layer.authorizationChanges:
			if !open {
				layer.disableAuthorization()
				return
			}
			layer.revalidateAuthorization()
		case <-layer.ctx.Done():
			return
		}
	}
}

func (layer *ConsensusStreamLayer) disableAuthorization() {
	layer.mu.Lock()
	if !layer.authorizationAvailable {
		layer.mu.Unlock()
		return
	}
	layer.authorizationAvailable = false
	peers := make([]*consensusPeerClient, 0, len(layer.peers))
	for _, peer := range layer.peers {
		peers = append(peers, peer)
	}
	streams := make([]*consensusStreamConn, 0, len(layer.streams))
	for stream := range layer.streams {
		streams = append(streams, stream)
	}
	layer.mu.Unlock()
	for _, peer := range peers {
		_ = peer.close()
	}
	for _, stream := range streams {
		_ = stream.Close()
	}
}

func (layer *ConsensusStreamLayer) revalidateAuthorization() {
	layer.mu.Lock()
	devices := make(map[domain.DeviceID]*consensusPeerClient, len(layer.peers))
	for deviceID, peer := range layer.peers {
		devices[deviceID] = peer
	}
	for stream := range layer.streams {
		if _, exists := devices[stream.remote.deviceID]; !exists {
			devices[stream.remote.deviceID] = nil
		}
	}
	layer.mu.Unlock()

	for deviceID, peer := range devices {
		membershipAllowed := true
		if peer != nil {
			peer.mu.Lock()
			physical := peer.physical
			var certificate IdentityCertificate
			if physical != nil {
				certificate = physical.identity
			}
			peer.mu.Unlock()
			if physical != nil &&
				layer.verifyExpected(deviceID, certificate) != nil {
				membershipAllowed = false
				_ = peer.close()
			}
		}
		liveConfigurationAllowed := layer.authorize(deviceID) == nil
		if !membershipAllowed || !liveConfigurationAllowed {
			layer.closeStreamsForDevice(deviceID)
		}
	}
}

func (layer *ConsensusStreamLayer) closeStreamsForDevice(
	deviceID domain.DeviceID,
) {
	layer.mu.Lock()
	streams := make([]*consensusStreamConn, 0)
	for stream := range layer.streams {
		if stream.remote.deviceID == deviceID {
			streams = append(streams, stream)
		}
	}
	layer.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

func (layer *ConsensusStreamLayer) openError() error {
	layer.mu.Lock()
	defer layer.mu.Unlock()
	if layer.closed {
		return ErrConsensusStreamClosed
	}
	return nil
}

func (layer *ConsensusStreamLayer) authorize(
	deviceID domain.DeviceID,
) (err error) {
	if layer == nil || layer.authorizePeer == nil || !deviceID.Valid() {
		return ErrConsensusPeerDenied
	}
	layer.mu.Lock()
	available := layer.authorizationAvailable && !layer.closed
	layer.mu.Unlock()
	if !available {
		return ErrConsensusPeerDenied
	}
	defer func() {
		if recover() != nil {
			err = ErrConsensusPeerDenied
		}
	}()
	if err := layer.authorizePeer(deviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrConsensusPeerDenied, err)
	}
	return nil
}

func (layer *ConsensusStreamLayer) verifyExpected(
	deviceID domain.DeviceID,
	certificate IdentityCertificate,
) (err error) {
	if layer == nil || layer.verifyExpectedPeer == nil {
		return ErrTLSAdmission
	}
	layer.mu.Lock()
	available := layer.authorizationAvailable && !layer.closed
	layer.mu.Unlock()
	if !available {
		return ErrTLSAdmission
	}
	defer func() {
		if recover() != nil {
			err = ErrTLSAdmission
		}
	}()
	if err := layer.verifyExpectedPeer(deviceID, certificate); err != nil {
		return ErrTLSAdmission
	}
	return nil
}

func (peer *consensusPeerClient) acquire(ctx context.Context) error {
	if peer == nil || peer.slots == nil || ctx == nil {
		return ErrInvalidConsensusStreamOptions
	}
	select {
	case peer.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errors.Join(ErrConsensusStreamCapacity, ctx.Err())
	case <-peer.layer.ctx.Done():
		return ErrConsensusStreamClosed
	}
}

func nilConsensusDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func closeConsensusConnectionImmediately(connection net.Conn) error {
	if connection == nil {
		return nil
	}
	type netConnProvider interface {
		NetConn() net.Conn
	}
	if provider, ok := connection.(netConnProvider); ok {
		if underlying := provider.NetConn(); underlying != nil {
			return underlying.Close()
		}
	}
	return connection.Close()
}

func (peer *consensusPeerClient) release() {
	if peer == nil || peer.slots == nil {
		return
	}
	select {
	case <-peer.slots:
	default:
	}
}

func (peer *consensusPeerClient) streamClosed() {
	peer.mu.Lock()
	if peer.openStreams > 0 {
		peer.openStreams--
	}
	peer.mu.Unlock()
}

func (slot *consensusPeerSlot) release() {
	if slot == nil || slot.peer == nil {
		return
	}
	slot.once.Do(slot.peer.release)
}

func (peer *consensusPeerClient) close() error {
	if peer == nil {
		return nil
	}
	peer.mu.Lock()
	physical := peer.physical
	peer.physical = nil
	peer.mu.Unlock()
	if physical == nil {
		return nil
	}
	return physical.close()
}

func (physical *consensusPhysicalClient) usable() bool {
	if physical == nil || physical.raw == nil || physical.http2 == nil {
		return false
	}
	state := physical.http2.State()
	return !state.Closed && !state.Closing
}

func (physical *consensusPhysicalClient) close() error {
	if physical == nil {
		return nil
	}
	var errs []error
	if physical.http2 != nil {
		errs = append(errs, physical.http2.Close())
	}
	if physical.raw != nil {
		errs = append(errs, physical.raw.Close())
	}
	return errors.Join(errs...)
}

func validConsensusConnectionState(
	state tls.ConnectionState,
	peer AuthenticatedPeer,
) bool {
	if !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 ||
		state.DidResume ||
		state.NegotiatedProtocol != ALPNConsensus ||
		len(state.PeerCertificates) != 1 {
		return false
	}
	certificate, err := ParseIdentityCertificate(
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		return false
	}
	return certificate.Binding.SessionID == peer.SessionID &&
		certificate.Binding.DeviceID == peer.DeviceID &&
		certificate.Binding.RecoveryGeneration ==
			peer.RecoveryGeneration
}

var (
	_ raft.StreamLayer  = (*ConsensusStreamLayer)(nil)
	_ ConnectionHandler = (*ConsensusStreamLayer)(nil)
)
