package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	consensusContractChild = "CODECOMM_CONSENSUS_CONTRACT_CHILD"
	consensusTestTimeout   = 10 * time.Second
)

func TestConsensusStreamProductionContract(t *testing.T) {
	switch mode := os.Getenv(consensusContractChild); mode {
	case "disabled":
		testConsensusStartupDisabled(t)
		return
	case "enabled":
		testConsensusStartupEnabled(t)
		return
	case "":
	default:
		t.Fatalf("unknown child mode %q", mode)
	}

	runConsensusContractChild(t, "disabled", false)
	runConsensusContractChild(t, "enabled", true)
}

func TestConsensusLogicalStreamDeadlinesAndHalfClose(t *testing.T) {
	t.Parallel()

	local := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	remote := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	var bridges consensusStreamBridges
	connection, bridges := newConsensusStreamConn(
		local,
		remote,
		func() {
			_ = bridges.read.Close()
			_ = bridges.write.Close()
		},
	)
	t.Cleanup(func() { _ = connection.Close() })

	if got := connection.LocalAddr().String(); got != string(local) {
		t.Fatalf("LocalAddr() = %q", got)
	}
	if got := connection.RemoteAddr().String(); got != string(remote) {
		t.Fatalf("RemoteAddr() = %q", got)
	}
	if got := connection.LocalAddr().Network(); got != "codecomm-consensus" {
		t.Fatalf("LocalAddr().Network() = %q", got)
	}

	readDeadline := time.Now().Add(20 * time.Millisecond)
	if err := connection.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); !isTimeoutError(err) {
		t.Fatalf("Read() deadline error = %v", err)
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := bridges.read.Write([]byte("request"))
		writeDone <- err
	}()
	assertReadString(t, connection, "request")
	if err := <-writeDone; err != nil {
		t.Fatalf("bridge request write: %v", err)
	}
	if err := bridges.read.Close(); err != nil {
		t.Fatalf("half-close read bridge: %v", err)
	}
	if _, err := connection.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() after half-close error = %v", err)
	}

	responseDone := make(chan error, 1)
	go func() {
		payload := make([]byte, len("response"))
		_, err := io.ReadFull(bridges.write, payload)
		if err == nil && string(payload) != "response" {
			err = errors.New("wrong response")
		}
		responseDone <- err
	}()
	if _, err := connection.Write([]byte("response")); err != nil {
		t.Fatalf("Write() after read half-close: %v", err)
	}
	if err := <-responseDone; err != nil {
		t.Fatalf("bridge response read: %v", err)
	}
}

func TestConsensusStreamRequestValidationIsExact(t *testing.T) {
	t.Parallel()

	peer := AuthenticatedPeer{
		Plane:    PlaneConsensus,
		DeviceID: domain.DeviceID("cc1" + strings.Repeat("3", 64)),
	}
	valid := func() *http.Request {
		request, err := http.NewRequest(
			http.MethodConnect,
			"https://codecomm.peer"+ConsensusRaftPath,
			strings.NewReader("stream"),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.ProtoMajor = 2
		request.ProtoMinor = 0
		request.Header.Set(":protocol", ConsensusRaftProtocol)
		request.TLS = &tls.ConnectionState{
			HandshakeComplete:  true,
			Version:            tls.VersionTLS13,
			NegotiatedProtocol: ALPNConsensus,
			PeerCertificates:   []*x509.Certificate{{}},
		}
		return request
	}
	if !validConsensusStreamRequest(valid(), peer) {
		t.Fatal("valid consensus request was rejected")
	}

	tests := map[string]func(*http.Request){
		"method": func(request *http.Request) { request.Method = http.MethodPost },
		"authority": func(request *http.Request) {
			request.Host = "other.peer"
		},
		"path":     func(request *http.Request) { request.URL.Path = "/v1/consensus" },
		"raw path": func(request *http.Request) { request.URL.RawPath = ConsensusRaftPath },
		"query":    func(request *http.Request) { request.URL.RawQuery = "x=1" },
		"fragment": func(request *http.Request) { request.URL.Fragment = "x" },
		"protocol": func(request *http.Request) { request.Header.Set(":protocol", "other") },
		"duplicate": func(request *http.Request) {
			request.Header[":protocol"] = []string{ConsensusRaftProtocol, ConsensusRaftProtocol}
		},
		"http version":  func(request *http.Request) { request.ProtoMajor = 1 },
		"resumption":    func(request *http.Request) { request.TLS.DidResume = true },
		"wrong ALPN":    func(request *http.Request) { request.TLS.NegotiatedProtocol = ALPNContent },
		"missing body":  func(request *http.Request) { request.Body = nil },
		"missing TLS":   func(request *http.Request) { request.TLS = nil },
		"missing cert":  func(request *http.Request) { request.TLS.PeerCertificates = nil },
		"force query":   func(request *http.Request) { request.URL.ForceQuery = true },
		"missing proto": func(request *http.Request) { request.Header.Del(":protocol") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := valid()
			mutate(request)
			if validConsensusStreamRequest(request, peer) {
				t.Fatal("invalid consensus request was accepted")
			}
		})
	}
}

func TestConsensusEndpointValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		endpoint string
		valid    bool
	}{
		"IPv4":                  {"192.0.2.1:47831", true},
		"IPv6":                  {"[2001:db8::1]:47831", true},
		"manual link local":     {"[fe80::1%en0]:47831", true},
		"link local no zone":    {"[fe80::1]:47831", false},
		"global with zone":      {"[2001:db8::1%en0]:47831", false},
		"loopback":              {"127.0.0.1:47831", false},
		"unspecified":           {"0.0.0.0:47831", false},
		"multicast":             {"[ff02::1]:47831", false},
		"mapped IPv4":           {"[::ffff:192.0.2.1]:47831", false},
		"limited broadcast":     {"255.255.255.255:47831", false},
		"missing listener port": {"192.0.2.1:0", false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint := netip.MustParseAddrPort(test.endpoint)
			if got := validConsensusEndpoint(endpoint); got != test.valid {
				t.Fatalf(
					"validConsensusEndpoint(%q) = %t, want %t",
					test.endpoint,
					got,
					test.valid,
				)
			}
		})
	}
}

func testConsensusStartupDisabled(t *testing.T) {
	if !errors.Is(
		requireExtendedConnectStartup(),
		ErrExtendedConnectStartup,
	) {
		t.Fatal("disabled startup did not fail closed")
	}
	t.Setenv("GODEBUG", "http2xconnect=1")
	if !errors.Is(
		requireExtendedConnectStartup(),
		ErrExtendedConnectStartup,
	) {
		t.Fatal("runtime environment change enabled extended CONNECT")
	}
	if _, err := NewConsensusStreamLayer(
		ConsensusStreamOptions{},
	); !errors.Is(err, ErrExtendedConnectStartup) {
		t.Fatalf("NewConsensusStreamLayer() error = %v", err)
	}
}

func testConsensusStartupEnabled(t *testing.T) {
	if err := requireExtendedConnectStartup(); err != nil {
		t.Fatalf("enabled startup contract: %v", err)
	}
	t.Setenv("GODEBUG", "")
	if err := requireExtendedConnectStartup(); err != nil {
		t.Fatalf("runtime environment removal disabled contract: %v", err)
	}
	t.Run("duplex half-close and reuse", testConsensusDuplexAndReuse)
	t.Run("expected peer binding", testConsensusExpectedPeerBinding)
	t.Run(
		"outbound membership revalidation",
		testConsensusOutboundMembershipRevalidation,
	)
	t.Run("live configuration gate", testConsensusLiveConfigurationGate)
	t.Run("stream capacity", testConsensusStreamCapacity)
	t.Run("maintained raft framing", testConsensusRaftFraming)
	t.Run("local identity binding", testConsensusLocalIdentityBinding)
	t.Run("authorization revalidation", testConsensusAuthorizationRevalidation)
	t.Run(
		"inbound registration revalidation",
		testConsensusInboundRegistrationRevalidation,
	)
	t.Run("replication authorization", testConsensusReplicationAuthorization)
	t.Run("request header timeout", testConsensusRequestHeaderTimeout)
	t.Run(
		"proof control reuse",
		testConsensusProofRequestReusesAuthenticatedConnection,
	)
	t.Run(
		"proof control input bounds",
		testConsensusProofRequestRejectsInvalidInputBeforeDial,
	)
	t.Run(
		"proof control response bounds",
		testConsensusProofRequestBoundsAndClassifiesResponses,
	)
	t.Run(
		"proof control cancellation",
		testConsensusProofRequestHonorsCancellation,
	)
	t.Run(
		"proof control denial closes active streams",
		testConsensusProofDenialClosesActiveStreamsWithoutDeadlock,
	)
	t.Run(
		"authenticated reachability",
		testConsensusReachabilitySuccess,
	)
	t.Run(
		"reachability token invalidation",
		testConsensusReachabilityTokenInvalidation,
	)
	t.Run(
		"reachability cancellation",
		testConsensusReachabilityCancellation,
	)
	t.Run(
		"reachability verification is local",
		testConsensusReachabilityVerificationIsLocal,
	)
}

func testConsensusDuplexAndReuse(t *testing.T) {
	harness := newConsensusHarness(t)
	outbound, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(first): %v", err)
	}
	inbound := acceptConsensusStream(t, harness.server)
	exchangeConsensusPayload(t, outbound, inbound, "request", "response")

	outboundStream := outbound.(*consensusStreamConn)
	if err := outboundStream.write.Close(); err != nil {
		t.Fatalf("close request direction: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := inbound.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("inbound read after request half-close = %v", err)
	}
	responseDone := make(chan error, 1)
	go func() {
		_, err := inbound.Write([]byte("after-eof"))
		responseDone <- err
	}()
	assertReadString(t, outbound, "after-eof")
	if err := <-responseDone; err != nil {
		t.Fatalf("write after request EOF: %v", err)
	}

	sibling, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(sibling): %v", err)
	}
	siblingInbound := acceptConsensusStream(t, harness.server)
	_ = outbound.Close()
	_ = inbound.Close()
	exchangeConsensusPayload(
		t,
		sibling,
		siblingInbound,
		"sibling",
		"survives",
	)
	_ = sibling.Close()
	_ = siblingInbound.Close()

	second, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(second): %v", err)
	}
	secondInbound := acceptConsensusStream(t, harness.server)
	exchangeConsensusPayload(t, second, secondInbound, "again", "reused")
	_ = second.Close()
	_ = secondInbound.Close()
	if count := harness.dialer.count.Load(); count != 1 {
		t.Fatalf("physical connection count = %d, want 1", count)
	}
	if count := harness.dialer.reauthorizationCalls.Load(); count != 6 {
		t.Fatalf("two-phase stream reauthorization calls = %d, want 6", count)
	}
	harness.assertNoActiveSocketDeadlines(t)
}

func testConsensusStreamCapacity(t *testing.T) {
	harness := newConsensusHarness(t)
	outbound := make(
		[]net.Conn,
		0,
		ConsensusStreamsPerConnectionMax,
	)
	inbound := make(
		[]net.Conn,
		0,
		ConsensusStreamsPerConnectionMax,
	)
	defer func() {
		for _, connection := range outbound {
			_ = connection.Close()
		}
		for _, connection := range inbound {
			_ = connection.Close()
		}
	}()
	for range ConsensusStreamsPerConnectionMax {
		connection, err := harness.client.Dial(
			raft.ServerAddress(harness.serverID),
			consensusTestTimeout,
		)
		if err != nil {
			t.Fatalf("Dial(within capacity): %v", err)
		}
		outbound = append(outbound, connection)
		inbound = append(
			inbound,
			acceptConsensusStream(t, harness.server),
		)
	}
	if count := harness.dialer.count.Load(); count != 1 {
		t.Fatalf("physical connection count = %d, want 1", count)
	}
	_, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		50*time.Millisecond,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial(over capacity) error = %v", err)
	}
	harness.assertNoActiveSocketDeadlines(t)
}

func testConsensusRaftFraming(t *testing.T) {
	harness := newConsensusHarness(t)
	clientTransport, err := NewConsensusNetworkTransport(
		ConsensusNetworkTransportOptions{
			Stream:        harness.client,
			LocalServerID: raft.ServerID(harness.clientID),
			Timeout:       time.Second,
			Logger:        hclog.NewNullLogger(),
			AuthorizeReplication: func(domain.DeviceID) error {
				return nil
			},
			AuthorizeCommitProbe: func(domain.DeviceID) error {
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("NewConsensusNetworkTransport(client): %v", err)
	}
	serverTransport, err := NewConsensusNetworkTransport(
		ConsensusNetworkTransportOptions{
			Stream:        harness.server,
			LocalServerID: raft.ServerID(harness.serverID),
			Timeout:       time.Second,
			Logger:        hclog.NewNullLogger(),
			AuthorizeReplication: func(domain.DeviceID) error {
				return nil
			},
			AuthorizeCommitProbe: func(domain.DeviceID) error {
				return nil
			},
		},
	)
	if err != nil {
		_ = clientTransport.Close()
		t.Fatalf("NewConsensusNetworkTransport(server): %v", err)
	}
	defer func() {
		_ = clientTransport.Close()
		_ = serverTransport.Close()
	}()

	responseSent := make(chan struct{})
	go func() {
		defer close(responseSent)
		rpc := <-serverTransport.Consumer()
		if _, ok := rpc.Command.(*raft.RequestVoteRequest); !ok {
			rpc.Respond(nil, errors.New("wrong Raft command type"))
			return
		}
		rpc.Respond(&raft.RequestVoteResponse{
			Term:    7,
			Granted: true,
		}, nil)
	}()
	var response raft.RequestVoteResponse
	if err := clientTransport.RequestVote(
		raft.ServerID(harness.serverID),
		raft.ServerAddress(harness.serverID),
		&raft.RequestVoteRequest{Term: 7},
		&response,
	); err != nil {
		t.Fatalf("RequestVote(): %v", err)
	}
	<-responseSent
	if response.Term != 7 || !response.Granted {
		t.Fatalf("RequestVote() response = %+v", response)
	}
	if got := clientTransport.LocalAddr(); got !=
		raft.ServerAddress(harness.clientID) {
		t.Fatalf("client LocalAddr() = %q", got)
	}
	encodedLocal := clientTransport.EncodePeer(
		raft.ServerID(harness.clientID),
		raft.ServerAddress(harness.clientID),
	)
	if got := clientTransport.DecodePeer(encodedLocal); got !=
		raft.ServerAddress(harness.clientID) {
		t.Fatalf("local EncodePeer/DecodePeer = %q", got)
	}
	if encoded := clientTransport.EncodePeer(
		raft.ServerID(harness.clientID),
		raft.ServerAddress(harness.serverID),
	); encoded != nil {
		t.Fatalf("mismatched EncodePeer() = %q, want nil", encoded)
	}
	harness.assertNoActiveSocketDeadlines(t)
}

func testConsensusLocalIdentityBinding(t *testing.T) {
	key := certificatePrivateKey(94)
	certificate, binding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		key,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(): %v", err)
	}
	otherDeviceID := domain.DeviceID("cc1" + strings.Repeat("9", 64))
	if otherDeviceID == binding.DeviceID {
		t.Fatal("identity fixture unexpectedly matched alternate device ID")
	}
	_, err = NewConsensusStreamLayer(ConsensusStreamOptions{
		LocalDeviceID:       otherDeviceID,
		IdentityCertificate: certificate,
		Endpoints:           consensusStaticResolver{},
		Dialer:              consensusRejectDialer{},
		VerifyExpectedPeer: func(
			domain.DeviceID,
			IdentityCertificate,
		) error {
			return nil
		},
		AuthorizePeer:        func(domain.DeviceID) error { return nil },
		AuthorizationChanges: make(chan struct{}),
		ControlHandler:       http.NotFoundHandler(),
	})
	if !errors.Is(err, ErrInvalidConsensusStreamOptions) {
		t.Fatalf("NewConsensusStreamLayer(mismatched identity) error = %v", err)
	}

	harness := newConsensusHarness(t)
	_, err = NewConsensusNetworkTransport(
		ConsensusNetworkTransportOptions{
			Stream:        harness.client,
			LocalServerID: raft.ServerID(harness.serverID),
			Timeout:       time.Second,
			Logger:        hclog.NewNullLogger(),
			AuthorizeReplication: func(domain.DeviceID) error {
				return nil
			},
			AuthorizeCommitProbe: func(domain.DeviceID) error {
				return nil
			},
		},
	)
	if !errors.Is(err, ErrInvalidConsensusRaftTransport) {
		t.Fatalf("NewConsensusNetworkTransport(mismatched local ID) error = %v", err)
	}
}

func testConsensusAuthorizationRevalidation(t *testing.T) {
	harness := newConsensusHarness(t)
	outbound, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	inbound := acceptConsensusStream(t, harness.server)
	harness.serverAllowed.Store(harness.clientID, false)
	harness.serverChanges <- struct{}{}
	if err := outbound.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := outbound.Read(buffer); err == nil {
		t.Fatal("removed live-configuration peer retained its stream")
	}
	_ = outbound.Close()
	_ = inbound.Close()

	harness.serverAllowed.Store(harness.clientID, true)
	harness.serverChanges <- struct{}{}
	second, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(after readmission): %v", err)
	}
	secondInbound := acceptConsensusStream(t, harness.server)
	_ = second.Close()
	_ = secondInbound.Close()
	if count := harness.dialer.count.Load(); count != 1 {
		t.Fatalf("live-config revalidation replaced physical connection: %d", count)
	}

	third, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(before authorization feed closure): %v", err)
	}
	thirdInbound := acceptConsensusStream(t, harness.server)
	close(harness.serverChanges)
	if err := third.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(feed closure): %v", err)
	}
	if _, err := third.Read(buffer); err == nil {
		t.Fatal("closed authorization feed left an established stream open")
	}
	_ = third.Close()
	_ = thirdInbound.Close()
}

func testConsensusInboundRegistrationRevalidation(t *testing.T) {
	harness := newConsensusHarness(t)
	var authorizationCalls atomic.Uint64
	harness.server.authorizePeer = func(deviceID domain.DeviceID) error {
		if deviceID != harness.clientID {
			return ErrConsensusPeerDenied
		}
		if authorizationCalls.Add(1) == 1 {
			harness.serverAllowed.Store(deviceID, false)
			harness.serverChanges <- struct{}{}
			return nil
		}
		return ErrConsensusPeerDenied
	}
	_, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if !errors.Is(err, ErrConsensusStreamRejected) {
		t.Fatalf("Dial(revoked during registration) error = %v", err)
	}
	select {
	case connection := <-harness.server.accept:
		_ = connection.Close()
		t.Fatal("stream revoked during registration reached Accept")
	default:
	}
	if got := authorizationCalls.Load(); got < 2 {
		t.Fatalf("live-configuration authorization calls = %d, want at least 2", got)
	}
}

func testConsensusExpectedPeerBinding(t *testing.T) {
	harness := newConsensusHarness(t)
	originalVerifier := harness.client.verifyExpectedPeer
	var verifierCalled atomic.Bool
	harness.client.verifyExpectedPeer = func(
		expected domain.DeviceID,
		certificate IdentityCertificate,
	) error {
		verifierCalled.Store(true)
		return originalVerifier(expected, certificate)
	}
	wrongKey := certificatePrivateKey(93)
	_, wrongBinding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		wrongKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(wrong target): %v", err)
	}
	harness.clientAllowed.Store(wrongBinding.DeviceID, true)
	harness.resolver.deviceID = wrongBinding.DeviceID
	_, err = harness.client.Dial(
		raft.ServerAddress(wrongBinding.DeviceID),
		200*time.Millisecond,
	)
	if !errors.Is(err, ErrConsensusEndpointUnavailable) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial(wrong expected peer) error = %v", err)
	}
	if !verifierCalled.Load() {
		t.Fatal("wrong-target TLS handshake did not reach expected-peer verifier")
	}
}

func testConsensusOutboundMembershipRevalidation(t *testing.T) {
	harness := newConsensusHarness(t)
	first, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(first): %v", err)
	}
	firstInbound := acceptConsensusStream(t, harness.server)
	harness.client.verifyExpectedPeer = func(
		domain.DeviceID,
		IdentityCertificate,
	) error {
		return ErrTLSAdmission
	}
	_, err = harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if !errors.Is(err, ErrTLSAdmission) {
		t.Fatalf("Dial(after membership denial) error = %v", err)
	}
	buffer := make([]byte, 1)
	if err := first.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := first.Read(buffer); err == nil {
			t.Fatal("membership denial left a reused physical connection open")
		}
	}
	_ = first.Close()
	_ = firstInbound.Close()
}

func testConsensusLiveConfigurationGate(t *testing.T) {
	harness := newConsensusHarness(t)
	harness.serverAllowed.Store(harness.clientID, false)
	_, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if !errors.Is(err, ErrConsensusStreamRejected) {
		t.Fatalf("Dial(server live-config denial) error = %v", err)
	}
	select {
	case connection := <-harness.server.accept:
		_ = connection.Close()
		t.Fatal("denied stream reached Accept")
	default:
	}

	harness.serverAllowed.Store(harness.clientID, true)
	harness.clientAllowed.Store(harness.serverID, false)
	_, err = harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if !errors.Is(err, ErrConsensusPeerDenied) {
		t.Fatalf("Dial(client live-config denial) error = %v", err)
	}
	harness.assertNoActiveSocketDeadlines(t)
}

type consensusHarness struct {
	client *ConsensusStreamLayer
	server *ConsensusStreamLayer

	clientID domain.DeviceID
	serverID domain.DeviceID

	resolver      *consensusTestResolver
	dialer        *consensusPipeDialer
	clientAllowed sync.Map
	serverAllowed sync.Map
	clientChanges chan struct{}
	serverChanges chan struct{}
}

func newConsensusHarness(t *testing.T) *consensusHarness {
	return newConsensusHarnessWithControlHandler(
		t,
		http.NotFoundHandler(),
	)
}

func newConsensusHarnessWithControlHandler(
	t *testing.T,
	controlHandler http.Handler,
) *consensusHarness {
	t.Helper()
	if controlHandler == nil {
		t.Fatal("nil consensus control handler")
	}
	clientKey := certificatePrivateKey(91)
	clientCertificate, clientBinding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		clientKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(client): %v", err)
	}
	serverKey := certificatePrivateKey(92)
	serverCertificate, serverBinding, err := IssueIdentityCertificate(
		certificateTestSessionID,
		1,
		serverKey,
	)
	if err != nil {
		t.Fatalf("IssueIdentityCertificate(server): %v", err)
	}
	harness := &consensusHarness{
		clientID: clientBinding.DeviceID,
		serverID: serverBinding.DeviceID,
		resolver: &consensusTestResolver{
			deviceID: serverBinding.DeviceID,
			endpoint: netip.MustParseAddrPort("192.0.2.1:47831"),
		},
		clientChanges: make(chan struct{}, 1),
		serverChanges: make(chan struct{}, 1),
	}
	harness.clientAllowed.Store(harness.serverID, true)
	harness.serverAllowed.Store(harness.clientID, true)
	verify := func(
		keys map[domain.DeviceID]ed25519.PublicKey,
	) ExpectedConsensusPeerVerifier {
		return func(
			expected domain.DeviceID,
			certificate IdentityCertificate,
		) error {
			key := keys[expected]
			return certificate.VerifyIdentity(
				certificateTestSessionID,
				1,
				expected,
				key,
			)
		}
	}
	authorize := func(values *sync.Map) ConsensusPeerAuthorizer {
		return func(deviceID domain.DeviceID) error {
			allowed, _ := values.Load(deviceID)
			if allowed != true {
				return ErrConsensusPeerDenied
			}
			return nil
		}
	}
	server, err := NewConsensusStreamLayer(ConsensusStreamOptions{
		LocalDeviceID:       harness.serverID,
		IdentityCertificate: serverCertificate,
		Endpoints:           consensusStaticResolver{},
		Dialer:              consensusRejectDialer{},
		VerifyExpectedPeer: verify(map[domain.DeviceID]ed25519.PublicKey{
			harness.clientID: clientKey.Public().(ed25519.PublicKey),
		}),
		AuthorizePeer:        authorize(&harness.serverAllowed),
		AuthorizationChanges: harness.serverChanges,
		ControlHandler:       controlHandler,
	})
	if err != nil {
		t.Fatalf("NewConsensusStreamLayer(server): %v", err)
	}
	harness.server = server
	harness.dialer = &consensusPipeDialer{
		server:            server,
		serverCertificate: serverCertificate,
		clientID:          harness.clientID,
		clientPublicKey:   clientKey.Public().(ed25519.PublicKey),
	}
	client, err := NewConsensusStreamLayer(ConsensusStreamOptions{
		LocalDeviceID:       harness.clientID,
		IdentityCertificate: clientCertificate,
		Endpoints:           harness.resolver,
		Dialer:              harness.dialer,
		VerifyExpectedPeer: verify(map[domain.DeviceID]ed25519.PublicKey{
			harness.serverID: serverKey.Public().(ed25519.PublicKey),
		}),
		AuthorizePeer:        authorize(&harness.clientAllowed),
		AuthorizationChanges: harness.clientChanges,
		ControlHandler:       http.NotFoundHandler(),
	})
	if err != nil {
		_ = server.Close()
		t.Fatalf("NewConsensusStreamLayer(client): %v", err)
	}
	harness.client = client
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		harness.dialer.wait(t)
	})
	return harness
}

func (harness *consensusHarness) assertNoActiveSocketDeadlines(
	t *testing.T,
) {
	t.Helper()
	if count := harness.dialer.deadlineCalls.Load(); count != 0 {
		t.Fatalf(
			"shared TLS socket deadline calls while active = %d, want 0",
			count,
		)
	}
}

type consensusTestResolver struct {
	deviceID domain.DeviceID
	endpoint netip.AddrPort
}

func (resolver *consensusTestResolver) ResolveConsensusEndpoints(
	_ context.Context,
	deviceID domain.DeviceID,
) ([]netip.AddrPort, error) {
	if resolver == nil || deviceID != resolver.deviceID {
		return nil, ErrConsensusEndpointUnavailable
	}
	return []netip.AddrPort{resolver.endpoint}, nil
}

type consensusStaticResolver struct{}

func (consensusStaticResolver) ResolveConsensusEndpoints(
	context.Context,
	domain.DeviceID,
) ([]netip.AddrPort, error) {
	return nil, ErrConsensusEndpointUnavailable
}

type consensusRejectDialer struct{}

func (consensusRejectDialer) DialConsensusEndpoint(
	context.Context,
	netip.AddrPort,
) (net.Conn, error) {
	return nil, ErrConsensusEndpointUnavailable
}

type consensusPipeDialer struct {
	server            *ConsensusStreamLayer
	serverCertificate tls.Certificate
	clientID          domain.DeviceID
	clientPublicKey   ed25519.PublicKey

	count atomic.Uint64
	work  sync.WaitGroup

	deadlineCalls        atomic.Uint64
	reauthorizationCalls atomic.Uint64
}

func (dialer *consensusPipeDialer) DialConsensusEndpoint(
	ctx context.Context,
	_ netip.AddrPort,
) (net.Conn, error) {
	if dialer == nil || dialer.server == nil {
		return nil, ErrConsensusEndpointUnavailable
	}
	clientConnection, serverConnection := net.Pipe()
	clientConnection = &consensusDeadlineTrackingConn{
		Conn:  clientConnection,
		calls: &dialer.deadlineCalls,
	}
	serverConnection = &consensusDeadlineTrackingConn{
		Conn:  serverConnection,
		calls: &dialer.deadlineCalls,
	}
	dialer.count.Add(1)
	dialer.work.Add(1)
	go func() {
		defer dialer.work.Done()
		serverConfig := baseTLSConfig()
		serverConfig.Certificates = []tls.Certificate{
			cloneTLSCertificate(dialer.serverCertificate),
		}
		serverConfig.ClientAuth = tls.RequireAnyClientCert
		serverConfig.NextProtos = []string{ALPNConsensus}
		serverConfig.VerifyConnection = planeConnectionVerifier(
			PlaneConsensus,
			func(certificate IdentityCertificate) error {
				return certificate.VerifyIdentity(
					certificateTestSessionID,
					1,
					dialer.clientID,
					dialer.clientPublicKey,
				)
			},
			nil,
		)
		tlsConnection := tls.Server(serverConnection, serverConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = tlsConnection.Close()
			return
		}
		state := tlsConnection.ConnectionState()
		certificate, err := ParseIdentityCertificate(
			state.PeerCertificates[0].Raw,
		)
		if err != nil {
			_ = tlsConnection.Close()
			return
		}
		serverContext := context.WithValue(
			context.Background(),
			authenticatedPeerContextKey{},
			&authenticatedPeerContext{
				metadata: AuthenticatedPeer{
					Plane:              PlaneConsensus,
					SessionID:          certificate.Binding.SessionID,
					DeviceID:           certificate.Binding.DeviceID,
					RecoveryGeneration: certificate.Binding.RecoveryGeneration,
				},
				reauthorize: func() error {
					dialer.reauthorizationCalls.Add(1)
					return nil
				},
			},
		)
		_ = dialer.server.ServeAuthenticatedConn(
			serverContext,
			tlsConnection,
		)
	}()
	return clientConnection, nil
}

type consensusDeadlineTrackingConn struct {
	net.Conn
	calls *atomic.Uint64
}

func (connection *consensusDeadlineTrackingConn) SetDeadline(
	deadline time.Time,
) error {
	connection.calls.Add(1)
	return connection.Conn.SetDeadline(deadline)
}

func (connection *consensusDeadlineTrackingConn) SetReadDeadline(
	deadline time.Time,
) error {
	connection.calls.Add(1)
	return connection.Conn.SetReadDeadline(deadline)
}

func (connection *consensusDeadlineTrackingConn) SetWriteDeadline(
	deadline time.Time,
) error {
	connection.calls.Add(1)
	return connection.Conn.SetWriteDeadline(deadline)
}

func (dialer *consensusPipeDialer) wait(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		dialer.work.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(consensusTestTimeout):
		t.Error("consensus server connection did not stop")
	}
}

func acceptConsensusStream(
	t *testing.T,
	layer *ConsensusStreamLayer,
) net.Conn {
	t.Helper()
	result := make(chan struct {
		connection net.Conn
		err        error
	}, 1)
	go func() {
		connection, err := layer.Accept()
		result <- struct {
			connection net.Conn
			err        error
		}{connection: connection, err: err}
	}()
	select {
	case accepted := <-result:
		if accepted.err != nil {
			t.Fatalf("Accept(): %v", accepted.err)
		}
		return accepted.connection
	case <-time.After(consensusTestTimeout):
		t.Fatal("Accept() timed out")
		return nil
	}
}

func exchangeConsensusPayload(
	t *testing.T,
	outbound net.Conn,
	inbound net.Conn,
	request string,
	response string,
) {
	t.Helper()
	requestDone := make(chan error, 1)
	go func() {
		_, err := outbound.Write([]byte(request))
		requestDone <- err
	}()
	assertReadString(t, inbound, request)
	if err := <-requestDone; err != nil {
		t.Fatalf("write request: %v", err)
	}
	responseDone := make(chan error, 1)
	go func() {
		_, err := inbound.Write([]byte(response))
		responseDone <- err
	}()
	assertReadString(t, outbound, response)
	if err := <-responseDone; err != nil {
		t.Fatalf("write response: %v", err)
	}
}

func assertReadString(t *testing.T, reader io.Reader, expected string) {
	t.Helper()
	buffer := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read %q: %v", expected, err)
	}
	if got := string(buffer); got != expected {
		t.Fatalf("read = %q, want %q", got, expected)
	}
}

func isTimeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func runConsensusContractChild(
	t *testing.T,
	mode string,
	enabled bool,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestConsensusStreamProductionContract$",
		"-test.count=1",
	)
	command.Env = consensusContractEnvironment(
		os.Environ(),
		mode,
		enabled,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s child timed out: %v", mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf("%s child failed: %v\n%s", mode, err, output)
	}
}

func consensusContractEnvironment(
	base []string,
	mode string,
	enabled bool,
) []string {
	result := make([]string, 0, len(base)+2)
	var godebug []string
	for _, entry := range base {
		switch {
		case strings.HasPrefix(entry, consensusContractChild+"="):
			continue
		case strings.HasPrefix(entry, "GODEBUG="):
			for _, setting := range strings.Split(
				strings.TrimPrefix(entry, "GODEBUG="),
				",",
			) {
				if setting != "" &&
					!strings.HasPrefix(setting, "http2xconnect=") {
					godebug = append(godebug, setting)
				}
			}
		default:
			result = append(result, entry)
		}
	}
	if enabled {
		godebug = append(godebug, "http2xconnect=1")
	}
	return append(
		result,
		"GODEBUG="+strings.Join(godebug, ","),
		consensusContractChild+"="+mode,
	)
}
