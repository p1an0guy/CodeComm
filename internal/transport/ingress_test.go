package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const ingressTestTimeout = 5 * time.Second

type ingressTestTLS struct {
	server  ServerTLSOptions
	clients map[Plane]*tls.Config
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
		Consensus: handler,
	}, connectionCap)
	t.Cleanup(gate.open)

	first := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneConsensus])
	defer first.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "first active handler")
	second := dialIngressTLS(t, listener.Addr().String(), fixture.clients[PlaneConsensus])
	defer second.Close()
	awaitIngressValue(t, entered, ingressTestTimeout, "second active handler")

	excess, err := tryIngressTLS(
		listener.Addr().String(),
		fixture.clients[PlaneConsensus],
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
		Listener:  closedListener,
		TLS:       fixture.server,
		Admission: NewAdmissionLimiter(),
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
	clientIdentity, _, err := IssueIdentityCertificate(
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
	clientContent, _, err := IssueContentCertificate(clientAuthorization, clientEpochKey)
	if err != nil {
		t.Fatalf("IssueContentCertificate(client): %v", err)
	}

	server := ServerTLSOptions{
		IdentityCertificate: serverIdentity,
		ContentCertificate:  staticContentCertificate(serverContent),
		VerifyPairingPeer:   func(IdentityCertificate) error { return nil },
		VerifyConsensusPeer: func(IdentityCertificate) error { return nil },
		VerifyContentPeer:   func(ContentCertificate) error { return nil },
	}
	clients := make(map[Plane]*tls.Config, 3)
	for _, plane := range []Plane{PlanePairing, PlaneConsensus, PlaneContent} {
		options := ClientTLSOptions{Plane: plane}
		if plane == PlaneContent {
			options.Certificate = clientContent
			options.VerifyContentPeer = func(ContentCertificate) error { return nil }
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
	return ingressTestTLS{server: server, clients: clients}
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

type invalidRemoteConn struct {
	net.Conn
}

func (connection *invalidRemoteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 1}
}
