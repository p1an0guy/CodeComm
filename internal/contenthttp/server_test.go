package contenthttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const contentTestTimeout = 5 * time.Second

type contentTestService struct {
	mu sync.Mutex

	session SessionResponse
	peers   PeersResponse

	sessionCalls         int
	peersCalls           int
	eventCalls           int
	peersSeen            []transport.AuthenticatedPeer
	eventPeer            domain.DeviceID
	eventBody            []byte
	eventHop             ProposalHop
	eventResult          EventResult
	eventErr             error
	batch                replication.Batch
	batchErr             error
	batchCalls           int
	batchAfter           []uint64
	acknowledgement      replication.Acknowledgement
	acknowledgementErr   error
	acknowledgementCalls int
	acknowledgementAt    []uint64

	entered  chan struct{}
	release  <-chan struct{}
	canceled chan struct{}
}

func newContentTestService(
	t testing.TB,
	serverDeviceID domain.DeviceID,
) *contentTestService {
	t.Helper()
	session, err := NewSessionResponse(SessionResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 0, ServerDeviceID: serverDeviceID,
		DaemonVersion: "0.3.0", MaxApplyLevel: 1,
		RequiredCapabilities: []string{
			"codecomm/v1/endpoint-hints", "codecomm/v1/events",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := NewPeerMember(PeerMemberInput{
		DeviceID: serverDeviceID, Role: device.RoleOwner,
		Status: device.StatusActive, EntityVersion: 4,
		EndpointSet: []byte(`{"schema_version":1,"signature":"AA"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	peers, err := NewPeersResponse(PeersResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 0, ServerDeviceID: serverDeviceID,
		Members: []PeerMember{member},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &contentTestService{session: session, peers: peers}
}

func (service *contentTestService) Session(
	ctx context.Context,
) (SessionResponse, error) {
	peer, _ := transport.AuthenticatedPeerFromContext(ctx)
	service.mu.Lock()
	service.sessionCalls++
	service.peersSeen = append(service.peersSeen, peer)
	response := service.session
	entered := service.entered
	release := service.release
	canceled := service.canceled
	service.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			if canceled != nil {
				select {
				case canceled <- struct{}{}:
				default:
				}
			}
			return SessionResponse{}, ctx.Err()
		}
	}
	return response, nil
}

func (service *contentTestService) Peers(
	ctx context.Context,
) (PeersResponse, error) {
	peer, _ := transport.AuthenticatedPeerFromContext(ctx)
	service.mu.Lock()
	defer service.mu.Unlock()
	service.peersCalls++
	service.peersSeen = append(service.peersSeen, peer)
	return service.peers, nil
}

func (service *contentTestService) ProposeEvent(
	_ context.Context,
	peerID domain.DeviceID,
	body []byte,
	hop ProposalHop,
) (EventResult, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.eventCalls++
	service.eventPeer = peerID
	service.eventBody = bytes.Clone(body)
	service.eventHop = hop
	return service.eventResult, service.eventErr
}

func (service *contentTestService) Replication(
	ctx context.Context,
	afterResult uint64,
) (replication.Batch, error) {
	service.mu.Lock()
	service.batchCalls++
	service.batchAfter = append(service.batchAfter, afterResult)
	batch := service.batch
	batchErr := service.batchErr
	entered := service.entered
	release := service.release
	canceled := service.canceled
	service.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			if canceled != nil {
				select {
				case canceled <- struct{}{}:
				default:
				}
			}
			return replication.Batch{}, ctx.Err()
		}
	}
	return batch, batchErr
}

func (service *contentTestService) ReplicationAcknowledgement(
	_ context.Context,
	atResult uint64,
) (replication.Acknowledgement, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.acknowledgementCalls++
	service.acknowledgementAt = append(
		service.acknowledgementAt,
		atResult,
	)
	return service.acknowledgement, service.acknowledgementErr
}

func (service *contentTestService) snapshot() (int, int, []transport.AuthenticatedPeer) {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.sessionCalls, service.peersCalls,
		append([]transport.AuthenticatedPeer(nil), service.peersSeen...)
}

type contentPeerPolicy struct {
	revoked       atomic.Bool
	verifications atomic.Uint64
	expected      transport.ContentBinding
}

type contentTLSFixture struct {
	serverOptions   transport.ServerTLSOptions
	clientConfig    *tls.Config
	clientAdmission *transport.ContentAdmissionRecorder
	clientCert      tls.Certificate
	clientBinding   transport.ContentBinding
	serverBinding   transport.ContentBinding
	serverDevice    domain.DeviceID
	serverIdentity  ed25519.PrivateKey
	policy          *contentPeerPolicy
}

func newContentTLSFixture(t testing.TB) contentTLSFixture {
	t.Helper()
	serverIdentityKey := contentPrivateKey(0x71)
	serverIdentity, serverIdentityBinding, err :=
		transport.IssueIdentityCertificate(testSessionID, 0, serverIdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	serverEpochKey := contentPrivateKey(0x72)
	serverAuthorization := contentAuthorization(
		t, serverIdentityKey, serverEpochKey, 3, 21,
	)
	serverContent, serverBinding, err := transport.IssueContentCertificate(
		serverAuthorization,
		serverEpochKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	clientIdentityKey := contentPrivateKey(0x73)
	clientEpochKey := contentPrivateKey(0x74)
	clientAuthorization := contentAuthorization(
		t, clientIdentityKey, clientEpochKey, 5, 34,
	)
	clientContent, clientBinding, err := transport.IssueContentCertificate(
		clientAuthorization,
		clientEpochKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy := &contentPeerPolicy{expected: clientBinding}
	serverVerifier := func(
		certificate transport.ContentCertificate,
	) (transport.ContentPeerAdmission, error) {
		if certificate.Binding == serverBinding {
			return contentAdmission(certificate)
		}
		policy.verifications.Add(1)
		if policy.revoked.Load() || certificate.Binding != policy.expected {
			return transport.ContentPeerAdmission{}, errors.New("content peer denied")
		}
		return contentAdmission(certificate)
	}
	clientVerifier := func(
		certificate transport.ContentCertificate,
	) (transport.ContentPeerAdmission, error) {
		if certificate.Binding != serverBinding {
			return transport.ContentPeerAdmission{}, errors.New("wrong content server")
		}
		return contentAdmission(certificate)
	}
	clientAdmission, err := transport.NewContentAdmissionRecorder(
		clientVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane: transport.PlaneContent, Certificate: clientContent,
			VerifyContentPeer: clientAdmission.Verify,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return contentTLSFixture{
		serverOptions: transport.ServerTLSOptions{
			IdentityCertificate: serverIdentity,
			ContentCertificate: func() (tls.Certificate, error) {
				return serverContent, nil
			},
			VerifyPairingPeer: func(transport.IdentityCertificate) error {
				return nil
			},
			VerifyConsensusPeer: func(transport.IdentityCertificate) error {
				return nil
			},
			VerifyContentPeer: serverVerifier,
		},
		clientConfig: clientConfig, clientAdmission: clientAdmission,
		clientCert:    clientContent,
		clientBinding: clientBinding, serverBinding: serverBinding,
		serverDevice:   serverIdentityBinding.DeviceID,
		serverIdentity: serverIdentityKey,
		policy:         policy,
	}
}

func contentAdmission(
	certificate transport.ContentCertificate,
) (transport.ContentPeerAdmission, error) {
	remaining := time.Until(certificate.NotAfter)
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	if remaining <= 0 || remaining > lifetime {
		return transport.ContentPeerAdmission{}, errors.New("inactive certificate")
	}
	return transport.ContentPeerAdmission{CloseAfter: remaining}, nil
}

func contentAuthorization(
	t testing.TB,
	identityKey ed25519.PrivateKey,
	epochKey ed25519.PrivateKey,
	epoch uint64,
	chainIndex uint64,
) credentialauthorization.Authorization {
	t.Helper()
	deviceID, err := device.DeriveID(identityKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	timestamp := domain.WholeSecondTimestamp(now.Format(time.RFC3339))
	epochPublicKey := epochKey.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID: testSessionID, DeviceID: deviceID, Epoch: epoch,
		Role:     credentialauthorization.RoleOwner,
		IssuedAt: timestamp, NotBefore: timestamp,
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: deviceID,
		}},
		AuthorizationChainIndex: chainIndex,
	}
	copy(authorization.EpochPublicKey[:], epochPublicKey)
	authorization.KeyDigest = sha256.Sum256(epochPublicKey)
	if err := authorization.Validate(); err != nil {
		t.Fatal(err)
	}
	return authorization
}

func contentPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

type contentHarness struct {
	service       *contentTestService
	server        *Server
	fixture       contentTLSFixture
	client        *http2.ClientConn
	clientTLS     *tls.Conn
	ingress       *transport.Ingress
	cancel        context.CancelFunc
	serveDone     <-chan error
	accessChanges chan struct{}
	stopOnce      sync.Once
}

func startContentHarness(
	t testing.TB,
	activeHandlers int,
	configure ...func(*Server),
) *contentHarness {
	t.Helper()
	fixture := newContentTLSFixture(t)
	service := newContentTestService(t, fixture.serverDevice)
	server, err := newServer(service, activeHandlers)
	if err != nil {
		t.Fatal(err)
	}
	for _, apply := range configure {
		if apply != nil {
			apply(server)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accessChanges := make(chan struct{}, 1)
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener: listener, TLS: fixture.serverOptions,
		PeerAccessChanges: accessChanges, Content: server,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- ingress.Serve(serveContext) }()

	dialContext, cancelDial := context.WithTimeout(
		context.Background(), contentTestTimeout,
	)
	defer cancelDial()
	raw, err := (&net.Dialer{}).DialContext(
		dialContext, "tcp", listener.Addr().String(),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	clientTLS := tls.Client(raw, fixture.clientConfig.Clone())
	if err := clientTLS.HandshakeContext(dialContext); err != nil {
		_ = raw.Close()
		cancel()
		t.Fatal(err)
	}
	clientTransport := &http2.Transport{
		DisableCompression: true,
		MaxHeaderListSize:  HeaderMaxBytes,
		ReadIdleTimeout:    StreamNoProgress,
		PingTimeout:        RequestHeaderTimeout,
		WriteByteTimeout:   StreamNoProgress,
	}
	client, err := clientTransport.NewClientConn(clientTLS)
	if err != nil {
		_ = clientTLS.Close()
		cancel()
		t.Fatal(err)
	}
	harness := &contentHarness{
		service: service, server: server, fixture: fixture,
		client: client, clientTLS: clientTLS, ingress: ingress,
		cancel: cancel, serveDone: serveDone, accessChanges: accessChanges,
	}
	awaitContentCondition(t, "ingress establishment", func() bool {
		if ingress.Stats().EstablishedConnections != 1 {
			return false
		}
		server.control.mu.Lock()
		defer server.control.mu.Unlock()
		state := server.control.states[fixture.clientBinding.DeviceID]
		return state != nil && state.current != nil
	})
	t.Cleanup(func() { harness.stop(t) })
	return harness
}

func (harness *contentHarness) stop(t testing.TB) {
	t.Helper()
	harness.stopOnce.Do(func() {
		_ = harness.client.Close()
		_ = harness.clientTLS.Close()
		harness.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), contentTestTimeout)
		defer cancel()
		if err := harness.ingress.Shutdown(ctx); err != nil {
			t.Errorf("Ingress.Shutdown() error = %v", err)
		}
		select {
		case err := <-harness.serveDone:
			if err != nil {
				t.Errorf("Ingress.Serve() error = %v", err)
			}
		case <-ctx.Done():
			t.Errorf("Ingress.Serve() did not return: %v", ctx.Err())
		}
	})
}

func awaitContentCondition(t testing.TB, name string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(contentTestTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

func (harness *contentHarness) request(
	t testing.TB,
	method string,
	target string,
	body io.Reader,
) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, "https://codecomm.invalid"+target, body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := harness.client.RoundTrip(request)
	if err != nil {
		t.Fatalf("RoundTrip(%s %s): %v", method, target, err)
	}
	return response
}

func readContentResponse(t testing.TB, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertContentResponse(
	t testing.TB,
	response *http.Response,
	status int,
	contentType string,
) []byte {
	t.Helper()
	body := readContentResponse(t, response)
	if response.StatusCode != status ||
		response.Header.Get("Content-Type") != contentType ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" ||
		response.Header.Get("Content-Encoding") != "" ||
		response.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("response = %s headers=%v body=%s", response.Status, response.Header, body)
	}
	return body
}

func TestServerServesCanonicalRoutesThroughAuthenticatedIngress(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(t, ActiveHandlersMax)
	before := harness.fixture.policy.verifications.Load()

	request, err := http.NewRequest(
		http.MethodGet, "https://codecomm.invalid"+SessionPath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := harness.client.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	sessionBody := assertContentResponse(
		t, response, http.StatusOK, "application/json",
	)
	wantSession, err := harness.service.session.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sessionBody, wantSession) {
		t.Fatalf("session body = %s, want %s", sessionBody, wantSession)
	}

	response = harness.request(t, http.MethodGet, PeersPath, nil)
	peersBody := assertContentResponse(
		t, response, http.StatusOK, "application/json",
	)
	wantPeers, err := harness.service.peers.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(peersBody, wantPeers) ||
		bytes.Contains(peersBody, []byte{'='}) {
		t.Fatalf("peers body = %s, want %s", peersBody, wantPeers)
	}

	if got := harness.fixture.policy.verifications.Load(); got != before+2 {
		t.Fatalf("per-request verifications = %d, want %d", got-before, 2)
	}
	sessionCalls, peersCalls, peersSeen := harness.service.snapshot()
	if sessionCalls != 1 || peersCalls != 1 || len(peersSeen) != 2 {
		t.Fatalf("service calls = (%d, %d), peers=%+v", sessionCalls, peersCalls, peersSeen)
	}
	for _, peer := range peersSeen {
		if peer.Plane != transport.PlaneContent ||
			peer.SessionID != harness.fixture.clientBinding.SessionID ||
			peer.DeviceID != harness.fixture.clientBinding.DeviceID ||
			peer.Epoch != harness.fixture.clientBinding.Epoch ||
			peer.AuthorizationChainIndex !=
				harness.fixture.clientBinding.AuthorizationChainIndex {
			t.Fatalf("service peer metadata = %+v", peer)
		}
	}
}

func TestServerRejectsUnknownRoutesMethodsBodiesAndNegotiation(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(t, ActiveHandlersMax)
	tests := []struct {
		name   string
		method string
		target string
		body   io.Reader
		header http.Header
		status int
	}{
		{name: "unknown", method: http.MethodGet, target: "/v1/unknown", status: http.StatusNotFound},
		{name: "query", method: http.MethodGet, target: SessionPath + "?x=1", status: http.StatusNotFound},
		{name: "force query", method: http.MethodGet, target: SessionPath + "?", status: http.StatusNotFound},
		{name: "post", method: http.MethodPost, target: SessionPath, status: http.StatusMethodNotAllowed},
		{name: "put", method: http.MethodPut, target: PeersPath, status: http.StatusMethodNotAllowed},
		{name: "delete", method: http.MethodDelete, target: SessionPath, status: http.StatusMethodNotAllowed},
		{name: "patch", method: http.MethodPatch, target: PeersPath, status: http.StatusMethodNotAllowed},
		{name: "options", method: http.MethodOptions, target: SessionPath, status: http.StatusMethodNotAllowed},
		{name: "head", method: http.MethodHead, target: PeersPath, status: http.StatusMethodNotAllowed},
		{name: "body", method: http.MethodGet, target: SessionPath, body: strings.NewReader("x"), status: http.StatusBadRequest},
		{name: "content type", method: http.MethodGet, target: SessionPath, header: http.Header{"Content-Type": {"application/json"}}, status: http.StatusBadRequest},
		{name: "content encoding", method: http.MethodGet, target: SessionPath, header: http.Header{"Content-Encoding": {"gzip"}}, status: http.StatusBadRequest},
		{name: "wildcard accept", method: http.MethodGet, target: SessionPath, header: http.Header{"Accept": {"*/*"}}, status: http.StatusNotAcceptable},
		{name: "parameterized accept", method: http.MethodGet, target: SessionPath, header: http.Header{"Accept": {"application/json; charset=utf-8"}}, status: http.StatusNotAcceptable},
		{name: "compressed response", method: http.MethodGet, target: SessionPath, header: http.Header{"Accept-Encoding": {"gzip"}}, status: http.StatusNotAcceptable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(
				test.method,
				"https://codecomm.invalid"+test.target,
				test.body,
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header = test.header.Clone()
			response, err := harness.client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			body := readContentResponse(t, response)
			if response.StatusCode != test.status {
				t.Fatalf("status = %s body=%s", response.Status, body)
			}
			if test.method != http.MethodHead {
				var problem problemResponse
				if err := json.Unmarshal(body, &problem); err != nil ||
					problem.Status != test.status ||
					problem.Code == "" ||
					problem.CorrelationID == "" {
					t.Fatalf("problem = %+v, error=%v, body=%s", problem, err, body)
				}
			}
		})
	}

	rawPath, err := http.NewRequest(
		http.MethodGet, "https://codecomm.invalid"+SessionPath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawPath.URL.RawPath = "/v1/%73ession"
	response, err := harness.client.RoundTrip(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("raw-path status = %s", response.Status)
	}
	_ = response.Body.Close()

	sessionCalls, peersCalls, _ := harness.service.snapshot()
	if sessionCalls != 0 || peersCalls != 0 {
		t.Fatalf("malformed requests reached service: (%d, %d)", sessionCalls, peersCalls)
	}
}

func TestRequestValidatorsRejectAmbiguousTargetsAndMetadata(t *testing.T) {
	t.Parallel()

	base := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: SessionPath},
		Header: make(http.Header),
	}
	if !validRequestTarget(base) || !validBodylessRequest(base) ||
		!validNegotiation(base.Header) {
		t.Fatal("valid bodyless request was rejected")
	}
	targets := []*url.URL{
		nil,
		{Path: SessionPath, RawPath: "/v1/%73ession"},
		{Path: SessionPath, RawQuery: "x=1"},
		{Path: SessionPath, ForceQuery: true},
		{Path: SessionPath, Fragment: "fragment"},
		{Path: SessionPath, RawFragment: "raw"},
	}
	for index, target := range targets {
		request := *base
		request.URL = target
		if validRequestTarget(&request) {
			t.Fatalf("target %d accepted: %+v", index, target)
		}
	}
	bodyMutations := []func(*http.Request){
		func(r *http.Request) { r.ContentLength = -1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Trailer = http.Header{"X-Test": {"value"}} },
		func(r *http.Request) { r.Header.Set("Content-Length", "0") },
		func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") },
		func(r *http.Request) { r.Header.Set("Trailer", "X-Test") },
		func(r *http.Request) { r.Header.Set("Expect", "100-continue") },
	}
	for index, mutate := range bodyMutations {
		request := base.Clone(context.Background())
		mutate(request)
		if validBodylessRequest(request) {
			t.Fatalf("body mutation %d accepted: %+v", index, request)
		}
	}
	negotiation := []http.Header{
		{"Accept": {"*/*"}},
		{"Accept": {"application/json", "application/problem+json"}},
		{"Accept": {"application/json; q=1"}},
		{"Accept-Encoding": {"gzip"}},
		{"Accept-Encoding": {"identity", "gzip"}},
	}
	for index, header := range negotiation {
		if validNegotiation(header) {
			t.Fatalf("negotiation %d accepted: %v", index, header)
		}
	}
	if !validNegotiation(http.Header{"Accept": {"APPLICATION/JSON"}}) ||
		!validNegotiation(http.Header{"Accept-Encoding": {"identity"}}) {
		t.Fatal("exact supported negotiation was rejected")
	}
}

func TestContentConnectionBindingRequiresExactTLS13ContentProfile(t *testing.T) {
	t.Parallel()

	fixture := newContentTLSFixture(t)
	leaf, err := x509.ParseCertificate(fixture.clientCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	valid := tls.ConnectionState{
		HandshakeComplete:  true,
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: transport.ALPNContent,
		PeerCertificates:   []*x509.Certificate{leaf},
	}
	binding, err := contentConnectionBinding(valid)
	if err != nil || binding != fixture.clientBinding {
		t.Fatalf("valid binding = (%+v, %v)", binding, err)
	}
	tests := []struct {
		name   string
		mutate func(*tls.ConnectionState)
	}{
		{"handshake", func(v *tls.ConnectionState) { v.HandshakeComplete = false }},
		{"TLS version", func(v *tls.ConnectionState) { v.Version = tls.VersionTLS12 }},
		{"resumption", func(v *tls.ConnectionState) { v.DidResume = true }},
		{"ALPN", func(v *tls.ConnectionState) { v.NegotiatedProtocol = transport.ALPNConsensus }},
		{"no certificate", func(v *tls.ConnectionState) { v.PeerCertificates = nil }},
		{"extra certificate", func(v *tls.ConnectionState) { v.PeerCertificates = append(v.PeerCertificates, leaf) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := valid
			state.PeerCertificates = append([]*x509.Certificate(nil), valid.PeerCertificates...)
			test.mutate(&state)
			if _, err := contentConnectionBinding(state); !errors.Is(err, ErrTLSBinding) {
				t.Fatalf("contentConnectionBinding() error = %v", err)
			}
		})
	}
}

func TestServeAuthenticatedConnRejectsDirectConnectionWithoutIngressMetadata(t *testing.T) {
	t.Parallel()

	fixture := newContentTLSFixture(t)
	service := newContentTestService(t, fixture.serverDevice)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	serverTLSConfig, err := transport.NewServerTLSConfig(fixture.serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverTLS := tls.Server(serverRaw, serverTLSConfig)
	clientTLS := tls.Client(clientRaw, fixture.clientConfig.Clone())
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshakeDone; err != nil {
		t.Fatal(err)
	}
	if err := server.ServeAuthenticatedConn(
		context.Background(), serverTLS,
	); !errors.Is(err, ErrTLSBinding) {
		t.Fatalf("ServeAuthenticatedConn(direct) error = %v", err)
	}
	if sessionCalls, peersCalls, _ := service.snapshot(); sessionCalls != 0 || peersCalls != 0 {
		t.Fatal("direct connection reached service")
	}
}

func TestServerUsesFixedBoundsAndRejectsOversizedHeaders(t *testing.T) {
	t.Parallel()

	fixture := newContentTLSFixture(t)
	server, err := New(newContentTestService(t, fixture.serverDevice))
	if err != nil {
		t.Fatal(err)
	}
	if cap(server.handlers) != ActiveHandlersMax ||
		cap(server.replicationHandlers) != ReplicationHandlersMax ||
		server.headerTimeout != RequestHeaderTimeout ||
		server.handlerTimeout != HandlerTimeout ||
		server.streamNoProgress != StreamNoProgress ||
		server.http2.MaxConcurrentStreams != ControlStreamsMax ||
		server.http2.IdleTimeout != ConnectionIdle ||
		server.http2.ReadIdleTimeout != StreamNoProgress ||
		server.http2.WriteByteTimeout != StreamNoProgress ||
		server.http2.MaxUploadBufferPerConnection != 1<<16 ||
		server.http2.MaxUploadBufferPerStream != event.MaxEventBytes ||
		HeaderMaxBytes != 32<<10 ||
		ResponseMaxBytes != 1<<20 ||
		ReplicationHandlersMax != 1 {
		t.Fatalf(
			"server bounds = %+v, handlers=(%d,%d)",
			server.http2,
			cap(server.handlers),
			cap(server.replicationHandlers),
		)
	}
	if _, err := newServer(
		newContentTestService(t, fixture.serverDevice),
		ActiveHandlersMax+1,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("oversized handler configuration error = %v", err)
	}

	harness := startContentHarness(t, ActiveHandlersMax)
	request, err := http.NewRequest(
		http.MethodGet, "https://codecomm.invalid"+SessionPath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Oversized", strings.Repeat("x", HeaderMaxBytes*2))
	response, roundTripErr := harness.client.RoundTrip(request)
	if roundTripErr == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized-header status = %s", response.Status)
		}
	}
	if sessionCalls, peersCalls, _ := harness.service.snapshot(); sessionCalls != 0 || peersCalls != 0 {
		t.Fatal("oversized header reached service")
	}
}

func TestServerReauthorizesEveryRequestAndDeniesRevokedPeer(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(t, ActiveHandlersMax)
	response := harness.request(t, http.MethodGet, SessionPath, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initial status = %s", response.Status)
	}
	_ = response.Body.Close()
	before := harness.fixture.policy.verifications.Load()
	harness.fixture.policy.revoked.Store(true)
	request, err := http.NewRequest(
		http.MethodGet, "https://codecomm.invalid"+PeersPath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, roundTripErr := harness.client.RoundTrip(request)
	if roundTripErr == nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("revoked request succeeded")
		}
	}
	if got := harness.fixture.policy.verifications.Load(); got != before+1 {
		t.Fatalf("revoked request verifications = %d, want 1", got-before)
	}
	if sessionCalls, peersCalls, _ := harness.service.snapshot(); sessionCalls != 1 || peersCalls != 0 {
		t.Fatalf("revoked request reached service: (%d, %d)", sessionCalls, peersCalls)
	}
}

func TestServerEnforcesGlobalHandlerCapacity(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(t, 1)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	harness.service.mu.Lock()
	harness.service.entered = entered
	harness.service.release = release
	harness.service.mu.Unlock()

	type result struct {
		response *http.Response
		err      error
	}
	firstDone := make(chan result, 1)
	go func() {
		request, err := http.NewRequest(
			http.MethodGet, "https://codecomm.invalid"+SessionPath, nil,
		)
		if err != nil {
			firstDone <- result{err: err}
			return
		}
		response, err := harness.client.RoundTrip(request)
		firstDone <- result{response: response, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(contentTestTimeout):
		t.Fatal("first handler did not enter service")
	}
	response := harness.request(t, http.MethodGet, SessionPath, nil)
	body := assertContentResponse(
		t, response, http.StatusServiceUnavailable, "application/problem+json",
	)
	if !bytes.Contains(body, []byte(`"code":"handler_capacity"`)) {
		t.Fatalf("capacity body = %s", body)
	}
	close(release)
	select {
	case first := <-firstDone:
		if first.err != nil {
			t.Fatal(first.err)
		}
		if first.response.StatusCode != http.StatusOK {
			t.Fatalf("first response = %s", first.response.Status)
		}
		_ = first.response.Body.Close()
	case <-time.After(contentTestTimeout):
		t.Fatal("first handler did not complete")
	}
	if sessionCalls, _, _ := harness.service.snapshot(); sessionCalls != 1 {
		t.Fatalf("service calls = %d, want 1", sessionCalls)
	}
}

func TestServerCancelsTimedOutHandlerAndKeepsConnectionUsable(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(
		t,
		ActiveHandlersMax,
		func(server *Server) {
			server.handlerTimeout = 100 * time.Millisecond
		},
	)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	canceled := make(chan struct{}, 1)
	harness.service.mu.Lock()
	harness.service.entered = entered
	harness.service.release = release
	harness.service.canceled = canceled
	harness.service.mu.Unlock()

	response := harness.request(t, http.MethodGet, SessionPath, nil)
	assertContentResponse(
		t, response, http.StatusRequestTimeout, "application/problem+json",
	)
	select {
	case <-canceled:
	case <-time.After(contentTestTimeout):
		t.Fatal("service context was not canceled")
	}
	close(release)
	response = harness.request(t, http.MethodGet, SessionPath, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("post-timeout response = %s", response.Status)
	}
	_ = response.Body.Close()
}

func TestServerFailsClosedOnCrossSessionServiceResponse(t *testing.T) {
	t.Parallel()

	harness := startContentHarness(t, ActiveHandlersMax)
	wrongSession := domain.UUIDv7("01890f47-3e72-7000-8000-000000000702")
	response, err := NewSessionResponse(SessionResponseInput{
		SessionID: wrongSession, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 0,
		ServerDeviceID:     harness.fixture.serverDevice,
		DaemonVersion:      "0.3.0", MaxApplyLevel: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.service.mu.Lock()
	harness.service.session = response
	harness.service.mu.Unlock()

	httpResponse := harness.request(t, http.MethodGet, SessionPath, nil)
	assertContentResponse(
		t, httpResponse, http.StatusInternalServerError,
		"application/problem+json",
	)
}

func TestServeAuthenticatedConnRejectsInvalidArgumentsAndCancellation(t *testing.T) {
	t.Parallel()

	fixture := newContentTLSFixture(t)
	server, err := New(newContentTestService(t, fixture.serverDevice))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ServeAuthenticatedConn(nil, nil); !errors.Is(err, ErrInvalidConnection) {
		t.Fatalf("nil connection error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	connection := tls.Client(&closedConn{}, fixture.clientConfig.Clone())
	if err := server.ServeAuthenticatedConn(ctx, connection); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled connection error = %v", err)
	}
}

type closedConn struct{}

func (*closedConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*closedConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (*closedConn) Close() error                     { return nil }
func (*closedConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*closedConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*closedConn) SetDeadline(time.Time) error      { return nil }
func (*closedConn) SetReadDeadline(time.Time) error  { return nil }
func (*closedConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (address testAddr) Network() string { return "test" }
func (address testAddr) String() string  { return string(address) }
