package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const ingressTestTimeout = 5 * time.Second

type ingressTestTLS struct {
	server         ServerTLSOptions
	clients        map[Plane]*tls.Config
	clientIdentity IdentityBinding
	clientContent  ContentBinding
}

type ingressTestCall struct {
	handler  Plane
	protocol string
}

type ingressTestGate struct {
	once sync.Once
	done chan struct{}
}

type runningTestIngress struct {
	ingress *Ingress
	cancel  context.CancelFunc
	done    chan error
}

func TestIngressDispatchesExactALPNPlanes(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	calls := make(chan ingressTestCall, 3)
	handler := func(plane Plane) ConnectionHandler {
		return ConnectionHandlerFunc(func(_ context.Context, connection *tls.Conn) error {
			calls <- ingressTestCall{
				handler:  plane,
				protocol: connection.ConnectionState().NegotiatedProtocol,
			}
			var marker [1]byte
			_, err := io.ReadFull(connection, marker[:])
			return err
		})
	}
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Pairing:   handler(PlanePairing),
		Consensus: handler(PlaneConsensus),
		Content:   handler(PlaneContent),
	}, PeerConnectionsMax)

	for _, plane := range []Plane{PlanePairing, PlaneConsensus, PlaneContent} {
		connection := dialIngressTLS(t, listener.Addr().String(), fixture.clients[plane])
		if _, err := connection.Write([]byte{1}); err != nil {
			t.Fatalf("%s marker write: %v", plane, err)
		}
		call := awaitIngressValue(t, calls, ingressTestTimeout, string(plane)+" dispatch")
		protocol, err := plane.ALPN()
		if err != nil {
			t.Fatal(err)
		}
		if call.handler != plane || call.protocol != protocol {
			t.Fatalf("%s dispatch = %+v, want handler %q and ALPN %q", plane, call, plane, protocol)
		}
		_ = connection.Close()
	}

	stopTestIngress(t, running)
}

func TestIngressProvidesAuthenticatedPeerMetadata(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	calls := make(chan AuthenticatedPeer, 3)
	handler := ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
		peer, ok := AuthenticatedPeerFromContext(ctx)
		if !ok {
			return errors.New("authenticated peer metadata unavailable")
		}
		calls <- peer
		return nil
	})
	running := startTestIngress(t, IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		Pairing:  handler, Consensus: handler, Content: handler,
	}, PeerConnectionsMax)

	if _, ok := AuthenticatedPeerFromContext(context.Background()); ok {
		t.Fatal("unauthenticated context exposed peer metadata")
	}
	wants := map[Plane]AuthenticatedPeer{
		PlanePairing: {
			Plane: PlanePairing, SessionID: fixture.clientIdentity.SessionID,
			DeviceID:           fixture.clientIdentity.DeviceID,
			RecoveryGeneration: fixture.clientIdentity.RecoveryGeneration,
		},
		PlaneConsensus: {
			Plane: PlaneConsensus, SessionID: fixture.clientIdentity.SessionID,
			DeviceID:           fixture.clientIdentity.DeviceID,
			RecoveryGeneration: fixture.clientIdentity.RecoveryGeneration,
		},
		PlaneContent: {
			Plane: PlaneContent, SessionID: fixture.clientContent.SessionID,
			DeviceID:                fixture.clientContent.DeviceID,
			Epoch:                   fixture.clientContent.Epoch,
			AuthorizationChainIndex: fixture.clientContent.AuthorizationChainIndex,
		},
	}
	for _, plane := range []Plane{PlanePairing, PlaneConsensus, PlaneContent} {
		connection := dialIngressTLS(
			t,
			listener.Addr().String(),
			fixture.clients[plane],
		)
		got := awaitIngressValue(
			t,
			calls,
			ingressTestTimeout,
			string(plane)+" metadata",
		)
		if got != wants[plane] {
			t.Fatalf("%s metadata = %+v, want %+v", plane, got, wants[plane])
		}
		expectIngressConnectionClosed(t, connection, ingressTestTimeout)
		_ = connection.Close()
	}

	stopTestIngress(t, running)
}

func TestIngressObservesOnlySuccessfullyAuthenticatedPeers(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	var deny atomic.Bool
	fixture.server.VerifyConsensusPeer = func(IdentityCertificate) error {
		if deny.Load() {
			return ErrTLSAdmission
		}
		return nil
	}
	listener := newIngressTestListener(t)
	observed := make(chan AuthenticatedPeer, 1)
	handled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		PeerAuthenticated: func(peer AuthenticatedPeer) {
			observed <- peer
		},
		Consensus: ConnectionHandlerFunc(
			func(context.Context, *tls.Conn) error {
				handled <- struct{}{}
				return nil
			},
		),
	}, PeerConnectionsMax)

	plaintext := dialIngressTCP(t, listener.Addr().String())
	if _, err := plaintext.Write([]byte("not TLS")); err != nil {
		t.Fatalf("plaintext write: %v", err)
	}
	expectIngressConnectionClosed(t, plaintext, ingressTestTimeout)
	_ = plaintext.Close()

	deny.Store(true)
	rejected, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
		ingressTestTimeout,
	)
	if rejected != nil {
		if err == nil {
			expectIngressConnectionClosed(
				t,
				rejected,
				ingressTestTimeout,
			)
		}
		_ = rejected.Close()
	}
	select {
	case peer := <-observed:
		t.Fatalf("unauthenticated peer was observed: %+v", peer)
	case <-time.After(25 * time.Millisecond):
	}
	select {
	case <-handled:
		t.Fatal("unauthenticated peer reached the handler")
	default:
	}

	deny.Store(false)
	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	defer connection.Close()
	peer := awaitIngressValue(
		t,
		observed,
		ingressTestTimeout,
		"authenticated peer observation",
	)
	if peer.Plane != PlaneConsensus ||
		peer.SessionID != fixture.clientIdentity.SessionID ||
		peer.DeviceID != fixture.clientIdentity.DeviceID ||
		peer.RecoveryGeneration !=
			fixture.clientIdentity.RecoveryGeneration {
		t.Fatalf("authenticated peer observation = %+v", peer)
	}
	awaitIngressValue(
		t,
		handled,
		ingressTestTimeout,
		"authenticated peer handler",
	)
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)

	stopTestIngress(t, running)
}

func TestAuthenticatedPeerReauthorizationUsesCurrentPolicy(t *testing.T) {
	t.Parallel()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() {
		_ = serverConnection.Close()
		_ = clientConnection.Close()
	})
	var revoked atomic.Bool
	connectionContext, cancelConnection := context.WithCancel(
		context.Background(),
	)
	peer := &ingressPeer{
		cancel: cancelConnection,
		credentials: peerCredentials{
			metadata: AuthenticatedPeer{
				Plane:    PlaneConsensus,
				DeviceID: "cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		established: true,
	}
	ingress := &Ingress{
		verifyConsensus: func(IdentityCertificate) error {
			if revoked.Load() {
				return errors.New("revoked")
			}
			return nil
		},
		memberAccessAvailable: true,
		active: map[net.Conn]*ingressPeer{
			serverConnection: peer,
		},
	}
	ctx := context.WithValue(
		connectionContext,
		authenticatedPeerContextKey{},
		&authenticatedPeerContext{
			metadata: peer.credentials.metadata,
			reauthorize: func() error {
				return ingress.reauthorizePeer(serverConnection, peer)
			},
		},
	)

	if metadata, ok := AuthenticatedPeerFromContext(ctx); !ok ||
		metadata != peer.credentials.metadata {
		t.Fatalf(
			"AuthenticatedPeerFromContext() = (%+v, %t)",
			metadata,
			ok,
		)
	}
	if err := ReauthorizeAuthenticatedPeer(ctx); err != nil {
		t.Fatalf("ReauthorizeAuthenticatedPeer(active): %v", err)
	}

	revoked.Store(true)
	if err := ReauthorizeAuthenticatedPeer(ctx); !errors.Is(
		err,
		ErrPeerAuthorizationDenied,
	) {
		t.Fatalf(
			"ReauthorizeAuthenticatedPeer(revoked) error = %v, want %v",
			err,
			ErrPeerAuthorizationDenied,
		)
	}
	select {
	case <-connectionContext.Done():
	default:
		t.Fatal("revoked peer connection was not canceled")
	}
	if err := ReauthorizeAuthenticatedPeer(context.Background()); !errors.Is(
		err,
		ErrPeerAuthorizationUnavailable,
	) {
		t.Fatalf(
			"ReauthorizeAuthenticatedPeer(unbound) error = %v, want %v",
			err,
			ErrPeerAuthorizationUnavailable,
		)
	}
}

func TestContentPeerDeadlineIncludesVerificationTime(t *testing.T) {
	t.Parallel()

	const (
		closeAfter      = 200 * time.Millisecond
		verificationLag = 75 * time.Millisecond
	)
	now := time.Now()
	ingress := &Ingress{
		verifyContent: func(
			ContentCertificate,
		) (ContentPeerAdmission, error) {
			time.Sleep(verificationLag)
			return ContentPeerAdmission{CloseAfter: closeAfter}, nil
		},
	}
	started := time.Now()
	certificate := ContentCertificate{
		NotBefore: now,
		NotAfter:  now.Add(time.Second),
	}
	closeAt, authorized := ingress.verifyPeer(peerCredentials{
		metadata: AuthenticatedPeer{Plane: PlaneContent},
		content:  certificate,
	}, certificate)
	if !authorized {
		t.Fatal("verifyPeer(content) rejected valid test admission")
	}
	elapsed := time.Since(started)
	remaining := time.Until(closeAt)
	if elapsed < verificationLag ||
		remaining >= closeAfter-verificationLag/2 ||
		closeAt.After(started.Add(closeAfter+10*time.Millisecond)) {
		t.Fatalf(
			"content deadline elapsed=%s remaining=%s closeAt-start=%s",
			elapsed,
			remaining,
			closeAt.Sub(started),
		)
	}
}

func TestIngressContentExpiryClosesOnlyContent(t *testing.T) {
	t.Parallel()

	const (
		localCloseAfter  = 100 * time.Millisecond
		remoteCloseAfter = time.Second
	)
	fixture := newIngressTestTLS(t)
	fixture.server.VerifyContentPeer = func(
		certificate ContentCertificate,
	) (ContentPeerAdmission, error) {
		if certificate.Binding.DeviceID == fixture.clientContent.DeviceID {
			return ContentPeerAdmission{CloseAfter: remoteCloseAfter}, nil
		}
		return ContentPeerAdmission{CloseAfter: localCloseAfter}, nil
	}
	listener := newIngressTestListener(t)
	entered := map[Plane]chan struct{}{
		PlanePairing:   make(chan struct{}, 1),
		PlaneConsensus: make(chan struct{}, 1),
		PlaneContent:   make(chan struct{}, 1),
	}
	canceled := map[Plane]chan struct{}{
		PlanePairing:   make(chan struct{}, 1),
		PlaneConsensus: make(chan struct{}, 1),
		PlaneContent:   make(chan struct{}, 1),
	}
	handler := func(plane Plane) ConnectionHandler {
		return ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
			entered[plane] <- struct{}{}
			<-ctx.Done()
			canceled[plane] <- struct{}{}
			return ctx.Err()
		})
	}
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Pairing:   handler(PlanePairing),
		Consensus: handler(PlaneConsensus),
		Content:   handler(PlaneContent),
	}, PeerConnectionsMax)

	connections := map[Plane]*tls.Conn{}
	for _, plane := range []Plane{PlanePairing, PlaneConsensus, PlaneContent} {
		connections[plane] = dialIngressTLS(
			t,
			listener.Addr().String(),
			fixture.clients[plane],
		)
		defer connections[plane].Close()
		awaitIngressValue(
			t,
			entered[plane],
			ingressTestTimeout,
			string(plane)+" handler",
		)
	}

	awaitIngressValue(
		t,
		canceled[PlaneContent],
		ingressTestTimeout,
		"content expiry cancellation",
	)
	expectIngressConnectionClosed(
		t,
		connections[PlaneContent],
		ingressTestTimeout,
	)
	for _, plane := range []Plane{PlanePairing, PlaneConsensus} {
		select {
		case <-canceled[plane]:
			t.Fatalf("%s connection received a content expiry timer", plane)
		case <-time.After(2 * localCloseAfter):
		}
	}
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"content expiry accounting",
		func() bool {
			stats := running.ingress.Stats()
			return stats.ActiveConnections == 2 &&
				stats.PendingConnections == 0 &&
				stats.EstablishedConnections == 2
		},
	)

	stopTestIngress(t, running)
}

func TestIngressMissingHandlerClosesOnlyThatConnection(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	consensusCalls := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Consensus: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			consensusCalls <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)

	missing, handshakeErr := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlanePairing],
		ingressTestTimeout,
	)
	if missing != nil {
		defer missing.Close()
	}
	if handshakeErr == nil {
		expectIngressConnectionClosed(t, missing, ingressTestTimeout)
	}

	valid := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneConsensus])
	awaitIngressValue(t, consensusCalls, ingressTestTimeout, "consensus handler")
	expectIngressConnectionClosed(t, valid, ingressTestTimeout)
	_ = valid.Close()

	stopTestIngress(t, running)
}

func TestIngressHandshakeFailuresDoNotPoisonListener(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	contentCalls := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Content: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			contentCalls <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)

	plaintext := dialIngressTCP(t, listener.Addr().String())
	if _, err := plaintext.Write([]byte("GET / HTTP/1.1\r\nHost: peer\r\n\r\n")); err != nil {
		t.Fatalf("plaintext write: %v", err)
	}
	expectIngressConnectionClosed(t, plaintext, ingressTestTimeout)
	_ = plaintext.Close()

	wrongALPN := fixture.clients[PlanePairing].Clone()
	wrongALPN.NextProtos = []string{"h2"}
	rejected, err := tryIngressTLS(listener.Addr().String(), wrongALPN, ingressTestTimeout)
	if rejected != nil {
		_ = rejected.Close()
	}
	if err == nil {
		t.Fatal("wrong-ALPN TLS handshake succeeded")
	}

	valid := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneContent])
	awaitIngressValue(t, contentCalls, ingressTestTimeout, "content handler after malformed peers")
	expectIngressConnectionClosed(t, valid, ingressTestTimeout)
	_ = valid.Close()

	stopTestIngress(t, running)
}

func TestIngressRecoversTLSVerifierPanic(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	limiter := NewAdmissionLimiter()
	var verifierCalls atomic.Int32
	fixture.server.VerifyConsensusPeer = func(IdentityCertificate) error {
		if verifierCalls.Add(1) == 1 {
			panic("peer-controlled verifier panic")
		}
		return nil
	}
	handled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: limiter,
		Consensus: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			handled <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)

	rejected, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
		ingressTestTimeout,
	)
	if err == nil {
		expectIngressConnectionClosed(t, rejected, ingressTestTimeout)
	}
	if rejected != nil {
		_ = rejected.Close()
	}
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"verifier panic recovery",
		func() bool {
			stats := running.ingress.Stats()
			return stats.RecoveredPanics == 1 &&
				stats.ActiveConnections == 0 &&
				limiter.Stats().PendingHandshakes == 0
		},
	)
	select {
	case <-handled:
		t.Fatal("panicking verifier reached the connection handler")
	default:
	}

	valid := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	awaitIngressValue(t, handled, ingressTestTimeout, "handler after verifier panic")
	expectIngressConnectionClosed(t, valid, ingressTestTimeout)
	_ = valid.Close()

	stopTestIngress(t, running)
}

func TestIngressRecoversHandlerPanicAndAccountsErrors(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	handlerFailure := errors.New("connection-local handler failure")
	calls := make(chan int32, 3)
	var callCount atomic.Int32
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Content: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			call := callCount.Add(1)
			calls <- call
			switch call {
			case 1:
				panic("peer-controlled handler panic")
			case 2:
				return handlerFailure
			default:
				return nil
			}
		}),
	}, PeerConnectionsMax)

	for expectedCall := int32(1); expectedCall <= 3; expectedCall++ {
		connection := dialIngressTLS(
			t,
			listener.Addr().String(),
			fixture.clients[PlaneContent],
		)
		if call := awaitIngressValue(
			t,
			calls,
			ingressTestTimeout,
			"connection handler",
		); call != expectedCall {
			t.Fatalf("handler call = %d, want %d", call, expectedCall)
		}
		expectIngressConnectionClosed(t, connection, ingressTestTimeout)
		_ = connection.Close()
	}
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"handler failure accounting",
		func() bool {
			stats := running.ingress.Stats()
			return stats.RecoveredPanics == 1 &&
				stats.HandlerErrors == 1 &&
				stats.ActiveConnections == 0
		},
	)

	stopTestIngress(t, running)
}

func TestIngressRevalidationClosesRevokedPeers(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	allowedConsensus, allowedIdentity := newIngressIdentityClient(
		t,
		91,
		PlaneConsensus,
	)
	allowedContent, allowedContentBinding := newIngressContentClient(
		t,
		92,
		93,
		3,
		93,
	)
	var revokeConsensus atomic.Bool
	var revokeContent atomic.Bool
	revokedConsensusID := fixture.clientIdentity.DeviceID
	revokedContentID := fixture.clientContent.DeviceID
	revoked := errors.New("peer revoked")
	fixture.server.VerifyConsensusPeer = func(certificate IdentityCertificate) error {
		if revokeConsensus.Load() &&
			certificate.Binding.DeviceID == revokedConsensusID {
			return revoked
		}
		return nil
	}
	fixture.server.VerifyContentPeer = func(
		certificate ContentCertificate,
	) (ContentPeerAdmission, error) {
		if revokeContent.Load() &&
			certificate.Binding.DeviceID == revokedContentID {
			return ContentPeerAdmission{}, revoked
		}
		return admitTestContentPeer(certificate)
	}

	listener := newIngressTestListener(t)
	entered := make(chan AuthenticatedPeer, 4)
	canceled := make(chan AuthenticatedPeer, 4)
	handler := ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
		peer, ok := AuthenticatedPeerFromContext(ctx)
		if !ok {
			return errors.New("authenticated peer metadata unavailable")
		}
		entered <- peer
		<-ctx.Done()
		canceled <- peer
		return ctx.Err()
	})
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Consensus: handler,
		Content:   handler,
	}, PeerConnectionsMax)

	type testPeer struct {
		plane      Plane
		config     *tls.Config
		wantDevice string
	}
	peers := []testPeer{
		{
			plane: PlaneConsensus, config: fixture.clients[PlaneConsensus],
			wantDevice: string(revokedConsensusID),
		},
		{
			plane: PlaneConsensus, config: allowedConsensus,
			wantDevice: string(allowedIdentity.DeviceID),
		},
		{
			plane: PlaneContent, config: fixture.clients[PlaneContent],
			wantDevice: string(revokedContentID),
		},
		{
			plane: PlaneContent, config: allowedContent,
			wantDevice: string(allowedContentBinding.DeviceID),
		},
	}
	connections := make([]*tls.Conn, len(peers))
	for index, peer := range peers {
		connections[index] = dialIngressTLS(
			t,
			listener.Addr().String(),
			peer.config,
		)
		defer connections[index].Close()
		got := awaitIngressValue(
			t,
			entered,
			ingressTestTimeout,
			"revalidation test handler",
		)
		if got.Plane != peer.plane || string(got.DeviceID) != peer.wantDevice {
			t.Fatalf("handler peer = %+v, want plane %s device %s", got, peer.plane, peer.wantDevice)
		}
	}
	if stats := running.ingress.Stats(); stats.ActiveConnections != 4 ||
		stats.PendingConnections != 0 ||
		stats.EstablishedConnections != 4 {
		t.Fatalf("pre-revalidation stats = %+v", stats)
	}

	revokeConsensus.Store(true)
	revokeContent.Store(true)
	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{
		Checked: 4,
		Closed:  2,
	}) {
		t.Fatalf("RevalidatePeers() = %+v, want {Checked:4 Closed:2}", result)
	}
	canceledPeers := map[Plane]string{}
	for range 2 {
		peer := awaitIngressValue(
			t,
			canceled,
			ingressTestTimeout,
			"revoked peer cancellation",
		)
		canceledPeers[peer.Plane] = string(peer.DeviceID)
	}
	if canceledPeers[PlaneConsensus] != string(revokedConsensusID) ||
		canceledPeers[PlaneContent] != string(revokedContentID) ||
		len(canceledPeers) != 2 {
		t.Fatalf("canceled peers = %v", canceledPeers)
	}
	expectIngressConnectionClosed(t, connections[0], ingressTestTimeout)
	expectIngressConnectionClosed(t, connections[2], ingressTestTimeout)

	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{
		Checked: 2,
		Closed:  0,
	}) {
		t.Fatalf("second RevalidatePeers() = %+v, want {Checked:2 Closed:0}", result)
	}
	select {
	case peer := <-canceled:
		t.Fatalf("authorized peer canceled during revalidation: %+v", peer)
	default:
	}
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"post-revalidation accounting",
		func() bool {
			stats := running.ingress.Stats()
			return stats.ActiveConnections == 2 &&
				stats.PendingConnections == 0 &&
				stats.EstablishedConnections == 2
		},
	)

	stopTestIngress(t, running)
}

func TestIngressRevalidationClosesLocallyUnauthorizedContent(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	localCertificate, err := fixture.server.ContentCertificate()
	if err != nil {
		t.Fatalf("server content certificate: %v", err)
	}
	localProfile, err := ParseContentCertificate(
		localCertificate.Certificate[0],
	)
	if err != nil {
		t.Fatalf("ParseContentCertificate(server): %v", err)
	}
	var revokeLocal atomic.Bool
	revoked := errors.New("local member revoked")
	fixture.server.VerifyContentPeer = func(
		certificate ContentCertificate,
	) (ContentPeerAdmission, error) {
		if revokeLocal.Load() &&
			certificate.Binding.DeviceID == localProfile.Binding.DeviceID {
			return ContentPeerAdmission{}, revoked
		}
		return admitTestContentPeer(certificate)
	}

	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	handler := ConnectionHandlerFunc(func(
		ctx context.Context,
		_ *tls.Conn,
	) error {
		entered <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		return ctx.Err()
	})
	running := startTestIngress(t, IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		Content:  handler,
	}, PeerConnectionsMax)
	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneContent],
	)
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "content handler")

	revokeLocal.Store(true)
	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{
		Checked: 1,
		Closed:  1,
	}) {
		t.Fatalf("RevalidatePeers() = %+v, want {Checked:1 Closed:1}", result)
	}
	awaitIngressValue(
		t,
		canceled,
		ingressTestTimeout,
		"local revocation cancellation",
	)
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)
	stopTestIngress(t, running)
}

func TestIngressBoundsEstablishedConnectionsPerPeerPlane(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		plane Plane
		limit int
	}{
		{
			name:  "consensus",
			plane: PlaneConsensus,
			limit: peerConsensusConnectionsMax,
		},
		{
			name:  "content rollover",
			plane: PlaneContent,
			limit: peerContentConnectionsMax,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newIngressTestTLS(t)
			listener := newIngressTestListener(t)
			entered := make(chan struct{}, test.limit+1)
			handler := ConnectionHandlerFunc(func(
				ctx context.Context,
				_ *tls.Conn,
			) error {
				entered <- struct{}{}
				<-ctx.Done()
				return ctx.Err()
			})
			options := IngressOptions{
				Listener: listener,
				TLS:      fixture.server,
			}
			switch test.plane {
			case PlaneConsensus:
				options.Consensus = handler
			case PlaneContent:
				options.Content = handler
			default:
				t.Fatalf("unsupported test plane %q", test.plane)
			}
			running := startTestIngress(
				t,
				options,
				PeerConnectionsMax,
			)

			for range test.limit {
				connection := dialIngressTLS(
					t,
					listener.Addr().String(),
					fixture.clients[test.plane],
				)
				defer connection.Close()
				awaitIngressValue(
					t,
					entered,
					ingressTestTimeout,
					string(test.plane)+" handler",
				)
			}

			rejected := dialIngressTLS(
				t,
				listener.Addr().String(),
				fixture.clients[test.plane],
			)
			defer rejected.Close()
			expectIngressConnectionClosed(
				t,
				rejected,
				ingressTestTimeout,
			)
			select {
			case <-entered:
				t.Fatalf(
					"%s peer exceeded established connection limit %d",
					test.plane,
					test.limit,
				)
			default:
			}

			stopTestIngress(t, running)
		})
	}
}

func TestIngressPeerAccessSignalRevalidatesEstablishedPeers(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	var revoked atomic.Bool
	fixture.server.VerifyConsensusPeer = func(IdentityCertificate) error {
		if revoked.Load() {
			return errors.New("peer revoked")
		}
		return nil
	}
	accessChanges := make(chan struct{}, 1)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:          listener,
		TLS:               fixture.server,
		PeerAccessChanges: accessChanges,
		Consensus: ConnectionHandlerFunc(func(
			ctx context.Context,
			_ *tls.Conn,
		) error {
			entered <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			return ctx.Err()
		}),
	}, PeerConnectionsMax)

	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "consensus handler")

	revoked.Store(true)
	accessChanges <- struct{}{}
	awaitIngressValue(
		t,
		canceled,
		ingressTestTimeout,
		"access-change revalidation",
	)
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"access-change connection retirement",
		func() bool {
			return running.ingress.Stats().ActiveConnections == 0
		},
	)

	close(accessChanges)
	stopTestIngress(t, running)
}

func TestIngressClosedPeerAccessFeedFailsMemberPlanesClosed(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	accessChanges := make(chan struct{})
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 2)
	canceled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:          listener,
		TLS:               fixture.server,
		PeerAccessChanges: accessChanges,
		Consensus: ConnectionHandlerFunc(func(
			ctx context.Context,
			_ *tls.Conn,
		) error {
			entered <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			return ctx.Err()
		}),
	}, PeerConnectionsMax)

	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "consensus handler")

	close(accessChanges)
	awaitIngressValue(
		t,
		canceled,
		ingressTestTimeout,
		"closed access-feed cancellation",
	)
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)

	rejected, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
		ingressTestTimeout,
	)
	if err == nil {
		expectIngressConnectionClosed(t, rejected, ingressTestTimeout)
	}
	if rejected != nil {
		_ = rejected.Close()
	}
	select {
	case <-entered:
		t.Fatal("member peer reached handler after access feed closed")
	default:
	}

	stopTestIngress(t, running)
}

func TestIngressRevalidationRecoversVerifierPanic(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	var panicOnVerify atomic.Bool
	fixture.server.VerifyConsensusPeer = func(IdentityCertificate) error {
		if panicOnVerify.Load() {
			panic("revalidation verifier panic")
		}
		return nil
	}
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 2)
	canceled := make(chan struct{}, 2)
	handler := ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
		entered <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		return ctx.Err()
	})
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Consensus: handler,
	}, PeerConnectionsMax)

	first := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	defer first.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "first consensus handler")
	panicOnVerify.Store(true)
	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{
		Checked: 1,
		Closed:  1,
	}) {
		t.Fatalf("RevalidatePeers() = %+v, want {Checked:1 Closed:1}", result)
	}
	awaitIngressValue(t, canceled, ingressTestTimeout, "panicking verifier cancellation")
	expectIngressConnectionClosed(t, first, ingressTestTimeout)
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"verifier panic accounting",
		func() bool {
			stats := running.ingress.Stats()
			return stats.ActiveConnections == 0 &&
				stats.RecoveredPanics == 1
		},
	)

	panicOnVerify.Store(false)
	second := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	defer second.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "handler after verifier panic")

	stopTestIngress(t, running)
}

func TestIngressRevalidationCoversPendingHandshakeTransition(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	var (
		verifierCalls atomic.Int32
		authorized    atomic.Bool
	)
	authorized.Store(true)
	postHandshakeEntered := make(chan struct{})
	postHandshakeGate := newIngressTestGate()
	fixture.server.VerifyConsensusPeer = func(IdentityCertificate) error {
		allowedAtStart := authorized.Load()
		if verifierCalls.Add(1) == 2 {
			close(postHandshakeEntered)
			<-postHandshakeGate.done
		}
		if !allowedAtStart {
			return errors.New("peer revoked")
		}
		return nil
	}
	listener := newIngressTestListener(t)
	handlerEntered := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		Consensus: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			handlerEntered <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)
	t.Cleanup(postHandshakeGate.open)

	type dialResult struct {
		connection *tls.Conn
		err        error
	}
	dialDone := make(chan dialResult, 1)
	go func() {
		connection, err := tryIngressTLS(
			listener.Addr().String(),
			fixture.clients[PlaneConsensus],
			ingressTestTimeout,
		)
		dialDone <- dialResult{connection: connection, err: err}
	}()
	awaitIngressValue(
		t,
		postHandshakeEntered,
		ingressTestTimeout,
		"post-handshake verifier",
	)
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"pending authenticated connection",
		func() bool {
			stats := running.ingress.Stats()
			return stats.ActiveConnections == 1 &&
				stats.PendingConnections == 1 &&
				stats.EstablishedConnections == 0
		},
	)
	authorized.Store(false)
	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{}) {
		t.Fatalf("RevalidatePeers() during transition = %+v, want zero", result)
	}
	postHandshakeGate.open()

	dial := awaitIngressValue(t, dialDone, ingressTestTimeout, "TLS dial")
	if dial.connection != nil {
		defer dial.connection.Close()
	}
	if dial.err != nil {
		t.Fatalf("client TLS handshake error = %v", dial.err)
	}
	expectIngressConnectionClosed(t, dial.connection, ingressTestTimeout)
	select {
	case <-handlerEntered:
		t.Fatal("peer revoked during handshake reached the handler")
	default:
	}
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"pending handshake fail-closed",
		func() bool {
			return verifierCalls.Load() == 3 &&
				running.ingress.Stats().ActiveConnections == 0
		},
	)

	stopTestIngress(t, running)
}

func TestIngressConcurrentRevalidationAndShutdown(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		Pairing: ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
			entered <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}),
	}, PeerConnectionsMax)

	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlanePairing],
	)
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "pairing handler")

	const (
		workers = 16
		passes  = 32
	)
	var invalidResult atomic.Bool
	var work sync.WaitGroup
	work.Add(workers)
	for range workers {
		go func() {
			defer work.Done()
			for range passes {
				result := running.ingress.RevalidatePeers()
				if result.Checked < 0 ||
					result.Checked > 1 ||
					result.Closed < 0 ||
					result.Closed > result.Checked {
					invalidResult.Store(true)
				}
			}
		}()
	}
	running.cancel()
	work.Wait()
	if invalidResult.Load() {
		t.Fatal("concurrent revalidation returned unbounded accounting")
	}
	awaitIngressServeStopped(t, running, "Serve during concurrent revalidation")
	if result := running.ingress.RevalidatePeers(); result != (RevalidationResult{}) {
		t.Fatalf("RevalidatePeers() after shutdown = %+v, want zero", result)
	}
}

func TestIngressRetriesTemporaryAcceptFailure(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	baseListener := newIngressTestListener(t)
	listener := &temporaryFirstAcceptListener{Listener: baseListener}
	handled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Consensus: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			handled <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)

	connection := dialIngressTLS(
		t,
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
	)
	awaitIngressValue(
		t,
		handled,
		ingressTestTimeout,
		"handler after temporary accept failure",
	)
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)
	_ = connection.Close()
	stopTestIngress(t, running)
}

func TestIngressReportsUnexpectedListenerClosure(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Consensus: ConnectionHandlerFunc(func(
			context.Context,
			*tls.Conn,
		) error {
			return nil
		}),
	}, PeerConnectionsMax)

	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}
	if err := awaitIngressValue(
		t,
		running.done,
		ingressTestTimeout,
		"Serve after unexpected listener closure",
	); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestIngressAcceptRetryDelayUsesBoundedEqualJitter(t *testing.T) {
	t.Parallel()

	for _, backoff := range []time.Duration{
		0,
		time.Nanosecond,
		ingressAcceptRetryBase,
		ingressAcceptRetryMax,
	} {
		for range 100 {
			delay := ingressAcceptRetryDelay(backoff)
			if delay < backoff/2 || delay > backoff {
				t.Fatalf(
					"retry delay for %s = %s, want [%s, %s]",
					backoff,
					delay,
					backoff/2,
					backoff,
				)
			}
		}
	}
}

func TestIngressConnectionCapRefusesWithoutQueueing(t *testing.T) {
	t.Parallel()

	const connectionCap = 2
	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, connectionCap+1)
	gate := newIngressTestGate()
	handler := ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
		entered <- struct{}{}
		select {
		case <-gate.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Pairing:   handler,
	}, connectionCap)
	t.Cleanup(gate.open)

	first := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlanePairing])
	defer first.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "first active handler")
	second := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlanePairing])
	defer second.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "second active handler")

	excess, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlanePairing],
		ingressTestTimeout,
	)
	if excess != nil {
		_ = excess.Close()
	}
	if err == nil {
		t.Fatal("connection above cap completed TLS handshake")
	}
	if errors.Is(err, context.DeadlineExceeded) || isIngressTimeout(err) {
		t.Fatalf("connection above cap waited instead of being refused: %v", err)
	}
	select {
	case <-entered:
		t.Fatal("connection above cap reached a handler")
	default:
	}

	gate.open()
	expectIngressConnectionClosed(t, first, ingressTestTimeout)
	expectIngressConnectionClosed(t, second, ingressTestTimeout)
	stopTestIngress(t, running)
}

func TestIngressStalledHandshakeExpiresAndReleasesCapacity(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	limiter := NewAdmissionLimiter()
	handled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: limiter,
		Pairing: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			handled <- struct{}{}
			return nil
		}),
	}, 1)

	stalled := dialIngressTCP(t, listener.Addr().String())
	defer stalled.Close()
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"stalled handshake admission",
		func() bool { return limiter.Stats().PendingHandshakes == 1 },
	)
	expectIngressConnectionClosed(t, stalled, HandshakeTimeout+ingressTestTimeout)
	awaitIngressCondition(
		t,
		ingressTestTimeout,
		"stalled handshake release",
		func() bool { return limiter.Stats().PendingHandshakes == 0 },
	)

	valid := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlanePairing])
	awaitIngressValue(t, handled, ingressTestTimeout, "handler after stalled handshake")
	expectIngressConnectionClosed(t, valid, ingressTestTimeout)
	_ = valid.Close()

	stopTestIngress(t, running)
}

func TestIngressCancellationClosesConnectionsAndWaitsForHandlers(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	returnGate := newIngressTestGate()
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Content: ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
			entered <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			<-returnGate.done
			return ctx.Err()
		}),
	}, PeerConnectionsMax)
	t.Cleanup(returnGate.open)

	connection := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneContent])
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "active handler")
	running.cancel()
	awaitIngressValue(t, canceled, ingressTestTimeout, "handler cancellation")
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)
	assertIngressStillWaiting(t, running.done, "Serve returned before its active handler")

	returnGate.open()
	awaitIngressServeStopped(t, running, "Serve after cancellation")
}

func TestIngressShutdownClosesConnectionsAndWaitsForHandlers(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	returnGate := newIngressTestGate()
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Pairing: ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
			entered <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			<-returnGate.done
			return ctx.Err()
		}),
	}, PeerConnectionsMax)
	t.Cleanup(returnGate.open)

	connection := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlanePairing])
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "active handler")

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancelShutdown()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- running.ingress.Shutdown(shutdownContext)
		close(shutdownDone)
	}()

	awaitIngressValue(t, canceled, ingressTestTimeout, "handler shutdown")
	expectIngressConnectionClosed(t, connection, ingressTestTimeout)
	assertIngressStillWaiting(t, shutdownDone, "Shutdown returned before its active handler")
	assertIngressStillWaiting(t, running.done, "Serve returned before its active handler")

	returnGate.open()
	if err := awaitIngressValue(t, shutdownDone, ingressTestTimeout, "Shutdown"); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	awaitIngressServeStopped(t, running, "Serve after Shutdown")
}

func TestIngressServeIsSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	entered := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Consensus: ConnectionHandlerFunc(func(ctx context.Context, _ *tls.Conn) error {
			entered <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}),
	}, PeerConnectionsMax)

	connection := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneConsensus])
	defer connection.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "first Serve acceptance")

	secondServe := make(chan error, 1)
	go func() {
		secondServe <- running.ingress.Serve(context.Background())
		close(secondServe)
	}()
	if err := awaitIngressValue(t, secondServe, ingressTestTimeout, "second Serve"); !errors.Is(err, ErrIngressStarted) {
		t.Fatalf("second Serve() error = %v, want %v", err, ErrIngressStarted)
	}

	running.cancel()
	awaitIngressServeStopped(t, running, "first Serve shutdown")
	if err := running.ingress.Serve(context.Background()); !errors.Is(err, ErrIngressStarted) {
		t.Fatalf("Serve() after first use error = %v, want %v", err, ErrIngressStarted)
	}

	closedListener := newIngressTestListener(t)
	closedIngress, err := NewIngress(IngressOptions{
		Listener:          closedListener,
		TLS:               fixture.server,
		Admission:         NewAdmissionLimiter(),
		PeerAccessChanges: make(chan struct{}),
		Consensus: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewIngress() before pre-Serve shutdown: %v", err)
	}
	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		ingressTestTimeout,
	)
	defer cancelShutdown()
	if err := closedIngress.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown() before Serve error = %v", err)
	}
	if err := closedIngress.Serve(context.Background()); !errors.Is(err, ErrIngressClosed) {
		t.Fatalf("Serve() after pre-Serve shutdown error = %v, want %v", err, ErrIngressClosed)
	}
}

func TestIngressShutdownBeforeServeClosesListener(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := newIngressTestListener(t)
	ingress, err := NewIngress(IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Pairing: ConnectionHandlerFunc(func(
			context.Context,
			*tls.Conn,
		) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownContext, cancel := context.WithTimeout(
		context.Background(),
		ingressTestTimeout,
	)
	defer cancel()
	if err := ingress.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := ingress.Serve(context.Background()); !errors.Is(
		err,
		ErrIngressClosed,
	) {
		t.Fatalf("Serve(after Shutdown) error = %v, want %v", err, ErrIngressClosed)
	}
}

func TestIngressBeginShutdownStopsListenerAndClearsOwnedIdentityKeys(
	t *testing.T,
) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	listener := &ingressLifecycleListener{}
	ingress, err := NewIngress(IngressOptions{
		Listener: listener,
		TLS:      fixture.server,
		Pairing: ConnectionHandlerFunc(func(
			context.Context,
			*tls.Conn,
		) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewIngress(): %v", err)
	}
	keys := make([]ed25519.PrivateKey, 0, 2)
	for _, protocol := range []string{ALPNPairing, ALPNConsensus} {
		selected, err := ingress.tlsConfig.GetConfigForClient(
			&tls.ClientHelloInfo{SupportedProtos: []string{protocol}},
		)
		if err != nil {
			t.Fatalf("GetConfigForClient(%s): %v", protocol, err)
		}
		key, ok := selected.Certificates[0].PrivateKey.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			t.Fatalf("selected %s key = %T", protocol, selected.Certificates[0].PrivateKey)
		}
		keys = append(keys, key)
	}

	if err := ingress.BeginShutdown(); err != nil {
		t.Fatalf("BeginShutdown(): %v", err)
	}
	if listener.closeCalls.Load() != 1 {
		t.Fatalf("listener close calls = %d, want 1", listener.closeCalls.Load())
	}
	for index, key := range keys {
		if !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
			t.Fatalf("identity key %d was not cleared", index)
		}
	}
	if err := ingress.BeginShutdown(); err != nil {
		t.Fatalf("second BeginShutdown(): %v", err)
	}
	if listener.closeCalls.Load() != 1 {
		t.Fatalf("listener close calls after retry = %d, want 1", listener.closeCalls.Load())
	}
	if err := ingress.Serve(context.Background()); !errors.Is(
		err,
		ErrIngressClosed,
	) {
		t.Fatalf("Serve(after BeginShutdown) = %v", err)
	}
}

func TestIngressRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if PeerConnectionsMax != 128 {
		t.Fatalf("PeerConnectionsMax = %d, want 128", PeerConnectionsMax)
	}
	fixture := newIngressTestTLS(t)
	handler := ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
		return nil
	})

	t.Run("nil listener", func(t *testing.T) {
		_, err := NewIngress(IngressOptions{
			TLS: fixture.server, Admission: NewAdmissionLimiter(), Pairing: handler,
		})
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf("NewIngress() error = %v, want %v", err, ErrInvalidIngressConfig)
		}
	})
	t.Run("typed nil listener", func(t *testing.T) {
		var listener *net.TCPListener
		_, err := NewIngress(IngressOptions{
			Listener: listener, TLS: fixture.server,
			Admission: NewAdmissionLimiter(), Pairing: handler,
		})
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf(
				"NewIngress() error = %v, want %v",
				err,
				ErrInvalidIngressConfig,
			)
		}
	})
	t.Run("no handlers", func(t *testing.T) {
		listener := newIngressTestListener(t)
		_, err := NewIngress(IngressOptions{
			Listener: listener, TLS: fixture.server, Admission: NewAdmissionLimiter(),
		})
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf("NewIngress() error = %v, want %v", err, ErrInvalidIngressConfig)
		}
	})
	t.Run("invalid TLS", func(t *testing.T) {
		listener := newIngressTestListener(t)
		_, err := NewIngress(IngressOptions{
			Listener: listener, Admission: NewAdmissionLimiter(), Pairing: handler,
		})
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf("NewIngress() error = %v, want %v", err, ErrInvalidIngressConfig)
		}
	})
	t.Run("member handler without access feed", func(t *testing.T) {
		listener := newIngressTestListener(t)
		_, err := NewIngress(IngressOptions{
			Listener: listener, TLS: fixture.server,
			Admission: NewAdmissionLimiter(), Consensus: handler,
		})
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf(
				"NewIngress() error = %v, want %v",
				err,
				ErrInvalidIngressConfig,
			)
		}
	})
	t.Run("zero internal cap", func(t *testing.T) {
		listener := newIngressTestListener(t)
		_, err := newIngress(IngressOptions{
			Listener: listener, TLS: fixture.server, Admission: NewAdmissionLimiter(),
			Pairing: handler,
		}, 0)
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf("newIngress() error = %v, want %v", err, ErrInvalidIngressConfig)
		}
	})
	t.Run("oversized internal cap", func(t *testing.T) {
		listener := newIngressTestListener(t)
		_, err := newIngress(IngressOptions{
			Listener: listener, TLS: fixture.server, Admission: NewAdmissionLimiter(),
			Pairing: handler,
		}, PeerConnectionsMax+1)
		if !errors.Is(err, ErrInvalidIngressConfig) {
			t.Fatalf("newIngress() error = %v, want %v", err, ErrInvalidIngressConfig)
		}
	})
}

func TestIngressRejectsInvalidRemoteSourceAndContinues(t *testing.T) {
	t.Parallel()

	fixture := newIngressTestTLS(t)
	baseListener := newIngressTestListener(t)
	listener := &invalidFirstRemoteListener{
		Listener: baseListener,
		accepted: make(chan struct{}),
	}
	handled := make(chan struct{}, 1)
	running := startTestIngress(t, IngressOptions{
		Listener:  listener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
		Pairing: ConnectionHandlerFunc(func(context.Context, *tls.Conn) error {
			handled <- struct{}{}
			return nil
		}),
	}, PeerConnectionsMax)

	rejected, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlanePairing],
		ingressTestTimeout,
	)
	awaitIngressValue(t, listener.accepted, ingressTestTimeout, "invalid-source acceptance")
	if rejected != nil {
		_ = rejected.Close()
	}
	if err == nil {
		t.Fatal("connection with an unspecified remote source completed TLS")
	}
	select {
	case <-handled:
		t.Fatal("connection with an invalid source reached a handler")
	default:
	}

	valid := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlanePairing])
	awaitIngressValue(t, handled, ingressTestTimeout, "valid source after invalid source")
	expectIngressConnectionClosed(t, valid, ingressTestTimeout)
	_ = valid.Close()

	stopTestIngress(t, running)
}

func newIngressTestTLS(t testing.TB) ingressTestTLS {
	t.Helper()

	serverIdentityKey := certificatePrivateKey(81)
	serverIdentity, _, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		serverIdentityKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(server): %v", err)
	}
	clientIdentityKey := certificatePrivateKey(82)
	clientIdentity, clientIdentityBinding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		clientIdentityKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(client): %v", err)
	}
	serverEpochKey := certificatePrivateKey(83)
	serverAuthorization := certificateAuthorizationForKeys(
		t,
		serverIdentityKey,
		serverEpochKey,
		1,
		81,
	)
	serverContent, _, err := IssueContentCertificate(serverAuthorization, serverEpochKey)
	if err != nil {
		t.Fatalf("IssueContentCertificate(server): %v", err)
	}
	clientEpochKey := certificatePrivateKey(84)
	clientAuthorization := certificateAuthorizationForKeys(
		t,
		clientIdentityKey,
		clientEpochKey,
		1,
		82,
	)
	clientContent, clientContentBinding, err := IssueContentCertificate(
		clientAuthorization,
		clientEpochKey,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate(client): %v", err)
	}

	server := ServerTLSOptions{
		IdentityCertificate: serverIdentity,
		ContentCertificate:  staticContentCertificate(serverContent),
		VerifyPairingPeer:   func(IdentityCertificate) error { return nil },
		VerifyConsensusPeer: func(IdentityCertificate) error { return nil },
		VerifyContentPeer:   admitTestContentPeer,
	}
	clients := make(map[Plane]*tls.Config, 3)
	for _, plane := range []Plane{PlanePairing, PlaneConsensus, PlaneContent} {
		options := ClientTLSOptions{Plane: plane}
		if plane == PlaneContent {
			options.Certificate = clientContent
			options.VerifyContentPeer = admitTestContentPeer
		} else {
			options.Certificate = clientIdentity
			options.VerifyIdentityPeer = func(IdentityCertificate) error { return nil }
		}
		config, err := NewClientTLSConfig(options)
		if err != nil {
			t.Fatalf("NewClientTLSConfig(%s): %v", plane, err)
		}
		clients[plane] = config
	}
	return ingressTestTLS{
		server:         server,
		clients:        clients,
		clientIdentity: clientIdentityBinding,
		clientContent:  clientContentBinding,
	}
}

func newIngressIdentityClient(
	t testing.TB,
	keyByte byte,
	plane Plane,
) (*tls.Config, IdentityBinding) {
	t.Helper()
	privateKey := certificatePrivateKey(keyByte)
	certificate, binding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		privateKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(client): %v", err)
	}
	config, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: plane, Certificate: certificate,
		VerifyIdentityPeer: func(IdentityCertificate) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewClientTLSConfig(%s): %v", plane, err)
	}
	return config, binding
}

func newIngressContentClient(
	t testing.TB,
	identityKeyByte byte,
	epochKeyByte byte,
	epoch uint64,
	chainIndex uint64,
) (*tls.Config, ContentBinding) {
	t.Helper()
	identityKey := certificatePrivateKey(identityKeyByte)
	epochKey := certificatePrivateKey(epochKeyByte)
	authorization := certificateAuthorizationForKeys(
		t,
		identityKey,
		epochKey,
		epoch,
		chainIndex,
	)
	certificate, binding, err := IssueContentCertificate(
		authorization,
		epochKey,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate(client): %v", err)
	}
	config, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: PlaneContent, Certificate: certificate,
		VerifyContentPeer: admitTestContentPeer,
	})
	if err != nil {
		t.Fatalf("NewClientTLSConfig(content): %v", err)
	}
	return config, binding
}

func newIngressTestListener(t testing.TB) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func startTestIngress(
	t testing.TB,
	options IngressOptions,
	connectionCap int,
) *runningTestIngress {
	t.Helper()
	if options.PeerAccessChanges == nil &&
		(!nilConnectionHandler(options.Consensus) ||
			!nilConnectionHandler(options.Content)) {
		options.PeerAccessChanges = make(chan struct{})
	}
	ingress, err := newIngress(options, connectionCap)
	if err != nil {
		t.Fatalf("newIngress(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningTestIngress{
		ingress: ingress,
		cancel:  cancel,
		done:    make(chan error, 1),
	}
	go func() {
		running.done <- ingress.Serve(ctx)
		close(running.done)
	}()
	t.Cleanup(func() {
		cancel()
		shutdownContext, cancelShutdown := context.WithTimeout(
			context.Background(),
			ingressTestTimeout,
		)
		defer cancelShutdown()
		if err := ingress.Shutdown(shutdownContext); err != nil {
			t.Errorf("ingress cleanup Shutdown() error = %v", err)
		}
		select {
		case err := <-running.done:
			if err != nil {
				t.Errorf("ingress cleanup Serve() error = %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("ingress cleanup did not stop: %v", shutdownContext.Err())
		}
	})
	return running
}

func stopTestIngress(t testing.TB, running *runningTestIngress) {
	t.Helper()
	running.cancel()
	awaitIngressServeStopped(t, running, "Serve shutdown")
}

func awaitIngressServeStopped(
	t testing.TB,
	running *runningTestIngress,
	description string,
) {
	t.Helper()
	if err := awaitIngressValue(
		t,
		running.done,
		ingressTestTimeout,
		description,
	); err != nil {
		t.Fatalf("%s error = %v", description, err)
	}
}

func dialIngressTCP(t testing.TB, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), ingressTestTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	return connection
}

func dialIngressTLS(
	t testing.TB,
	address string,
	config *tls.Config,
) *tls.Conn {
	t.Helper()
	connection, err := tryIngressTLS(address, config, ingressTestTimeout)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("TLS dial %s: %v", address, err)
	}
	return connection
}

func tryIngressTLS(
	address string,
	config *tls.Config,
	timeout time.Duration,
) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, config.Clone())
	if err := connection.HandshakeContext(ctx); err != nil {
		return connection, err
	}
	return connection, nil
}

func expectIngressConnectionClosed(
	t testing.TB,
	connection net.Conn,
	timeout time.Duration,
) {
	t.Helper()
	if connection == nil {
		t.Fatal("cannot await closure of a nil connection")
	}
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buffer [256]byte
	for {
		_, err := connection.Read(buffer[:])
		if err == nil {
			continue
		}
		if isIngressTimeout(err) {
			t.Fatalf("peer did not close connection within %s: %v", timeout, err)
		}
		return
	}
}

func awaitIngressCondition(
	t testing.TB,
	timeout time.Duration,
	description string,
	condition func() bool,
) {
	t.Helper()
	if condition() {
		return
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if condition() {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		}
	}
}

func awaitIngressValue[T any](
	t testing.TB,
	channel <-chan T,
	timeout time.Duration,
	description string,
) T {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-channel:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}

func assertIngressStillWaiting[T any](
	t testing.TB,
	channel <-chan T,
	description string,
) {
	t.Helper()
	select {
	case value := <-channel:
		t.Fatalf("%s: returned %+v", description, value)
	default:
	}
}

func isIngressTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func newIngressTestGate() *ingressTestGate {
	return &ingressTestGate{done: make(chan struct{})}
}

func (gate *ingressTestGate) open() {
	gate.once.Do(func() { close(gate.done) })
}

type invalidFirstRemoteListener struct {
	net.Listener
	used     atomic.Bool
	accepted chan struct{}
}

type temporaryFirstAcceptListener struct {
	net.Listener
	used atomic.Bool
}

func (listener *temporaryFirstAcceptListener) Accept() (net.Conn, error) {
	if listener.used.CompareAndSwap(false, true) {
		return nil, temporaryIngressAcceptError{}
	}
	return listener.Listener.Accept()
}

type temporaryIngressAcceptError struct{}

func (temporaryIngressAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryIngressAcceptError) Timeout() bool   { return false }
func (temporaryIngressAcceptError) Temporary() bool { return true }

func (listener *invalidFirstRemoteListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if listener.used.CompareAndSwap(false, true) {
		close(listener.accepted)
		return &invalidRemoteConn{Conn: connection}, nil
	}
	return connection, nil
}

func TestIngressClosesOnlyConnectionsBoundToVanishedAddress(t *testing.T) {
	t.Parallel()

	vanished := netip.MustParseAddr("192.0.2.10")
	retained := netip.MustParseAddr("192.0.2.11")
	vanishedServer, vanishedPeer := net.Pipe()
	retainedServer, retainedPeer := net.Pipe()
	t.Cleanup(func() {
		_ = vanishedServer.Close()
		_ = vanishedPeer.Close()
		_ = retainedServer.Close()
		_ = retainedPeer.Close()
	})
	vanishedConnection := &ingressLocalAddressConn{
		Conn: vanishedServer,
		local: net.TCPAddrFromAddrPort(
			netip.AddrPortFrom(vanished, 47831),
		),
	}
	retainedConnection := &ingressLocalAddressConn{
		Conn: retainedServer,
		local: net.TCPAddrFromAddrPort(
			netip.AddrPortFrom(retained, 47831),
		),
	}
	vanishedContext, cancelVanished := context.WithCancel(t.Context())
	retainedContext, cancelRetained := context.WithCancel(t.Context())
	t.Cleanup(cancelVanished)
	t.Cleanup(cancelRetained)
	ingress := &Ingress{
		active: map[net.Conn]*ingressPeer{
			vanishedConnection: {
				cancel: cancelVanished,
			},
			retainedConnection: {
				cancel: cancelRetained,
			},
		},
	}
	ingress.stateMu.Lock()
	preInvalidationGeneration := ingress.localBindingGeneration
	ingress.stateMu.Unlock()

	result, err := ingress.CloseConnectionsBoundTo(
		[]netip.Addr{vanished},
	)
	if err != nil {
		t.Fatalf("CloseConnectionsBoundTo(): %v", err)
	}
	if result != (LocalAddressCloseResult{Checked: 2, Closed: 1}) {
		t.Fatalf("close result = %+v", result)
	}
	lateServer, latePeer := net.Pipe()
	t.Cleanup(func() {
		_ = lateServer.Close()
		_ = latePeer.Close()
	})
	lateConnection := &ingressLocalAddressConn{
		Conn: lateServer,
		local: net.TCPAddrFromAddrPort(
			netip.AddrPortFrom(vanished, 47831),
		),
	}
	_, cancelLate := context.WithCancel(t.Context())
	t.Cleanup(cancelLate)
	if ingress.registerConnection(
		lateConnection,
		cancelLate,
		preInvalidationGeneration,
	) {
		t.Fatal("pre-invalidation accept registered after invalidation")
	}
	select {
	case <-vanishedContext.Done():
	default:
		t.Fatal("vanished-address connection context remains active")
	}
	select {
	case <-retainedContext.Done():
		t.Fatal("retained-address connection context was canceled")
	default:
	}
	if err := vanishedPeer.SetReadDeadline(
		time.Now().Add(ingressTestTimeout),
	); err == nil {
		var closed [1]byte
		if _, err := vanishedPeer.Read(closed[:]); err == nil ||
			isIngressTimeout(err) {
			t.Fatalf("vanished-address peer remains open: %v", err)
		}
	}

	if err := retainedPeer.SetWriteDeadline(
		time.Now().Add(ingressTestTimeout),
	); err != nil {
		t.Fatalf("SetWriteDeadline(retained): %v", err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := retainedPeer.Write([]byte{0x42})
		writeDone <- writeErr
	}()
	if err := retainedConnection.SetReadDeadline(
		time.Now().Add(ingressTestTimeout),
	); err != nil {
		t.Fatalf("SetReadDeadline(retained): %v", err)
	}
	var value [1]byte
	if _, err := io.ReadFull(retainedConnection, value[:]); err != nil {
		t.Fatalf("read retained connection: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write retained connection: %v", err)
	}
}

type ingressLocalAddressConn struct {
	net.Conn
	local net.Addr
}

func (connection *ingressLocalAddressConn) LocalAddr() net.Addr {
	return connection.local
}

type invalidRemoteConn struct {
	net.Conn
}

func (connection *invalidRemoteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 1}
}

type ingressLifecycleListener struct {
	closeCalls atomic.Int32
}

func (*ingressLifecycleListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected Accept")
}

func (listener *ingressLifecycleListener) Close() error {
	listener.closeCalls.Add(1)
	return nil
}

func (*ingressLifecycleListener) Addr() net.Addr {
	return ingressLifecycleAddress{}
}

type ingressLifecycleAddress struct{}

func (ingressLifecycleAddress) Network() string { return "tcp" }
func (ingressLifecycleAddress) String() string  { return "192.0.2.10:47831" }
