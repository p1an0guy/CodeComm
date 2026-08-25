package contenthttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const (
	contentClientOtherSession = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000702",
	)
	contentClientOtherWorkspace = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440001",
	)
)

func TestClientReadsSessionAndPeersOverOneReusableConnection(t *testing.T) {
	harness := startRealContentClient(t)

	session, err := harness.client.Session(context.Background())
	if err != nil ||
		session.SessionID() != testSessionID ||
		session.ServerDeviceID() != harness.fixture.serverDevice {
		t.Fatalf("Session() = (%+v, %v)", session, err)
	}
	peers, err := harness.client.Peers(context.Background())
	if err != nil || peers.WorkspaceID() != testWorkspaceID {
		t.Fatalf("Peers() = (%+v, %v)", peers, err)
	}
	members := peers.Members()
	if len(members) != 1 ||
		!bytes.Equal(
			members[0].EndpointSet(),
			[]byte(`{"schema_version":1,"signature":"AA"}`),
		) {
		t.Fatalf("peer endpoint set = %+v", members)
	}

	errorsSeen := make(chan error, 12)
	var calls sync.WaitGroup
	for index := range 12 {
		calls.Add(1)
		go func() {
			defer calls.Done()
			if index%2 == 0 {
				_, callErr := harness.client.Session(context.Background())
				errorsSeen <- callErr
				return
			}
			_, callErr := harness.client.Peers(context.Background())
			errorsSeen <- callErr
		}()
	}
	calls.Wait()
	close(errorsSeen)
	for callErr := range errorsSeen {
		if callErr != nil {
			t.Fatalf("concurrent serialized call: %v", callErr)
		}
	}
	if stats := harness.ingress.Stats(); stats.EstablishedConnections != 1 ||
		stats.ActiveConnections != 1 {
		t.Fatalf("ingress stats after reuse = %+v", stats)
	}
	sessionCalls, peerCalls, _ := harness.service.snapshot()
	if sessionCalls != 7 || peerCalls != 7 {
		t.Fatalf(
			"service calls = session %d peers %d, want 7 each",
			sessionCalls,
			peerCalls,
		)
	}
}

func TestOpenClientPinsContentALPNAndExpectedDevice(t *testing.T) {
	tests := []struct {
		name     string
		expected domain.DeviceID
		mutate   func(*tls.Config)
		want     error
	}{
		{
			name:     "wrong device",
			expected: testPeerDeviceID,
			want:     ErrPeerMismatch,
		},
		{
			name:   "wrong ALPN",
			mutate: func(config *tls.Config) { config.NextProtos = []string{"h2"} },
			want:   ErrInvalidClient,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newContentTLSFixture(t)
			expected := test.expected
			if expected == "" {
				expected = fixture.serverDevice
			}
			harness, client, err := openScriptedContentClient(
				t,
				fixture,
				http.NotFoundHandler(),
				test.mutate,
				expected,
			)
			defer harness.stop(t)
			if client != nil || !errors.Is(err, test.want) {
				t.Fatalf(
					"OpenClient() = (%v, %v), want nil and %v",
					client,
					err,
					test.want,
				)
			}
		})
	}
}

func TestClientRejectsResponseIdentityAndLineageConfusion(t *testing.T) {
	t.Run("TLS session mismatch", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		response, err := NewSessionResponse(SessionResponseInput{
			SessionID: contentClientOtherSession, WorkspaceID: testWorkspaceID,
			RecoveryGeneration: 0, ServerDeviceID: fixture.serverDevice,
			DaemonVersion: "1.0.0", MaxApplyLevel: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := response.canonicalBytes()
		harness := mustOpenScriptedContentClient(
			t,
			fixture,
			staticContentHandler(http.StatusOK, contentJSONMediaType, body, nil),
		)
		defer harness.stop(t)
		if _, err := harness.client.Session(
			context.Background(),
		); !errors.Is(err, ErrLineageMismatch) {
			t.Fatalf("Session() error = %v, want %v", err, ErrLineageMismatch)
		}
		assertContentClientClosed(t, harness.client)
	})

	t.Run("server device mismatch", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		response, err := NewSessionResponse(SessionResponseInput{
			SessionID: testSessionID, WorkspaceID: testWorkspaceID,
			RecoveryGeneration: 0, ServerDeviceID: testPeerDeviceID,
			DaemonVersion: "1.0.0", MaxApplyLevel: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := response.canonicalBytes()
		harness := mustOpenScriptedContentClient(
			t,
			fixture,
			staticContentHandler(http.StatusOK, contentJSONMediaType, body, nil),
		)
		defer harness.stop(t)
		if _, err := harness.client.Session(
			context.Background(),
		); !errors.Is(err, ErrPeerMismatch) {
			t.Fatalf("Session() error = %v, want %v", err, ErrPeerMismatch)
		}
	})

	t.Run("cross-route lineage mismatch", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		service := newContentTestService(t, fixture.serverDevice)
		sessionBody, _ := service.session.canonicalBytes()
		serverMember := mustClientPeerMember(t, fixture.serverDevice)
		peers, err := NewPeersResponse(PeersResponseInput{
			SessionID: testSessionID, WorkspaceID: contentClientOtherWorkspace,
			RecoveryGeneration: 1, ServerDeviceID: fixture.serverDevice,
			Members: []PeerMember{serverMember},
		})
		if err != nil {
			t.Fatal(err)
		}
		peersBody, _ := peers.canonicalBytes()
		handler := http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.URL.Path == SessionPath {
				writeScriptedResponse(
					writer,
					http.StatusOK,
					contentJSONMediaType,
					sessionBody,
					nil,
				)
				return
			}
			writeScriptedResponse(
				writer,
				http.StatusOK,
				contentJSONMediaType,
				peersBody,
				nil,
			)
		})
		harness := mustOpenScriptedContentClient(t, fixture, handler)
		defer harness.stop(t)
		if _, err := harness.client.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.client.Peers(
			context.Background(),
		); !errors.Is(err, ErrLineageMismatch) {
			t.Fatalf("Peers() error = %v, want %v", err, ErrLineageMismatch)
		}
	})
}

func TestClientRejectsMalformedNoncanonicalAndBoundViolations(t *testing.T) {
	fixture := newContentTLSFixture(t)
	service := newContentTestService(t, fixture.serverDevice)
	validSession, _ := service.session.canonicalBytes()
	validPeers, _ := service.peers.canonicalBytes()
	paddedEndpoint := bytes.Replace(
		validPeers,
		[]byte(`"endpoint_set":"`),
		[]byte(`"endpoint_set":"=`),
		1,
	)
	unknownField := canonicalObjectWithField(
		t,
		validSession,
		"unexpected",
		json.RawMessage("true"),
	)
	tests := []struct {
		name        string
		status      int
		contentType string
		body        []byte
		header      http.Header
		want        error
	}{
		{
			name: "malformed JSON", status: http.StatusOK,
			contentType: contentJSONMediaType, body: []byte(`{"broken":`),
			want: ErrResponseProtocol,
		},
		{
			name: "noncanonical JSON", status: http.StatusOK,
			contentType: contentJSONMediaType,
			body:        append(bytes.Clone(validSession), '\n'),
			want:        ErrResponseProtocol,
		},
		{
			name: "unknown field", status: http.StatusOK,
			contentType: contentJSONMediaType, body: unknownField,
			want: ErrResponseProtocol,
		},
		{
			name: "non-base64url endpoint set", status: http.StatusOK,
			contentType: contentJSONMediaType, body: paddedEndpoint,
			want: ErrResponseProtocol,
		},
		{
			name: "wrong content type", status: http.StatusOK,
			contentType: "text/plain", body: validSession,
			want: ErrResponseProtocol,
		},
		{
			name: "content encoding", status: http.StatusOK,
			contentType: contentJSONMediaType, body: validSession,
			header: http.Header{"Content-Encoding": {"gzip"}},
			want:   ErrResponseProtocol,
		},
		{
			name: "redirect status", status: http.StatusFound,
			contentType: contentJSONMediaType, body: validSession,
			want: ErrResponseProtocol,
		},
		{
			name: "oversized body", status: http.StatusOK,
			contentType: contentJSONMediaType,
			body:        bytes.Repeat([]byte{'x'}, ResponseMaxBytes+1),
			want:        ErrResponseTooLarge,
		},
		{
			name: "oversized header", status: http.StatusOK,
			contentType: contentJSONMediaType, body: validSession,
			header: http.Header{
				"X-Oversized": {strings.Repeat("x", HeaderMaxBytes)},
			},
			want: ErrResponseProtocol,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			localFixture := newContentTLSFixture(t)
			harness := mustOpenScriptedContentClient(
				t,
				localFixture,
				staticContentHandler(
					test.status,
					test.contentType,
					test.body,
					test.header,
				),
			)
			defer harness.stop(t)
			if _, err := harness.client.Session(
				context.Background(),
			); !errors.Is(err, test.want) {
				t.Fatalf("Session() error = %v, want %v", err, test.want)
			}
			assertContentClientClosed(t, harness.client)
		})
	}
}

func TestClientReturnsBoundedProblemAndReusesConnection(t *testing.T) {
	fixture := newContentTLSFixture(t)
	service := newContentTestService(t, fixture.serverDevice)
	peersBody, _ := service.peers.canonicalBytes()
	detail := "retry after local state catches up"
	problemBody, err := marshalCanonical(remoteProblemWire{
		Type:          "urn:codecomm:problem:content_unavailable",
		Title:         "Content service unavailable",
		Status:        http.StatusServiceUnavailable,
		Code:          "content_unavailable",
		CorrelationID: "01890f47-3e72-7000-8000-000000000799",
		Retryable:     true,
		Detail:        &detail,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == SessionPath {
			writeScriptedResponse(
				writer,
				http.StatusServiceUnavailable,
				contentProblemMediaType,
				problemBody,
				nil,
			)
			return
		}
		writeScriptedResponse(
			writer,
			http.StatusOK,
			contentJSONMediaType,
			peersBody,
			nil,
		)
	})
	harness := mustOpenScriptedContentClient(t, fixture, handler)
	defer harness.stop(t)

	_, err = harness.client.Session(context.Background())
	var remote *RemoteError
	if !errors.As(err, &remote) ||
		remote.Status != http.StatusServiceUnavailable ||
		remote.Code != "content_unavailable" ||
		!remote.Retryable ||
		remote.Detail != detail {
		t.Fatalf("remote problem = %#v, error = %v", remote, err)
	}
	if _, err := harness.client.Peers(context.Background()); err != nil {
		t.Fatalf("Peers() after problem: %v", err)
	}
}

func TestClassifyRoundTripErrorSeparatesProtocolAndAvailability(t *testing.T) {
	tests := []struct {
		name  string
		input error
		want  error
	}{
		{
			name: "stream protocol",
			input: http2.StreamError{
				StreamID: 1,
				Code:     http2.ErrCodeProtocol,
			},
			want: ErrResponseProtocol,
		},
		{
			name:  "connection protocol",
			input: http2.ConnectionError(http2.ErrCodeCompression),
			want:  ErrResponseProtocol,
		},
		{
			name: "refused stream",
			input: http2.StreamError{
				StreamID: 1,
				Code:     http2.ErrCodeRefusedStream,
			},
			want: ErrConnectionUnavailable,
		},
		{
			name:  "EOF",
			input: io.EOF,
			want:  ErrConnectionUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := classifyRoundTripError(
				test.input,
			); !errors.Is(err, test.want) {
				t.Fatalf(
					"classifyRoundTripError() = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
	if err := classifyRoundTripError(nil); err != nil {
		t.Fatalf("classifyRoundTripError(nil) = %v", err)
	}
}

func TestClientCancellationLeavesReusableConnection(t *testing.T) {
	fixture := newContentTLSFixture(t)
	service := newContentTestService(t, fixture.serverDevice)
	peersBody, _ := service.peers.canonicalBytes()
	entered := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path == SessionPath {
			entered <- struct{}{}
			<-request.Context().Done()
			return
		}
		writeScriptedResponse(
			writer,
			http.StatusOK,
			contentJSONMediaType,
			peersBody,
			nil,
		)
	})
	harness := mustOpenScriptedContentClient(t, fixture, handler)
	defer harness.stop(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := harness.client.Session(ctx); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("Session(canceled) error = %v", err)
	}
	select {
	case <-entered:
	case <-time.After(contentTestTimeout):
		t.Fatal("canceled request did not reach server")
	}
	if _, err := harness.client.Peers(context.Background()); err != nil {
		t.Fatalf("Peers() after stream cancellation: %v", err)
	}
}

func TestClientCloseIsIdempotentAndInterruptsRequest(t *testing.T) {
	fixture := newContentTLSFixture(t)
	entered := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(
		_ http.ResponseWriter,
		request *http.Request,
	) {
		entered <- struct{}{}
		<-request.Context().Done()
	})
	harness := mustOpenScriptedContentClient(t, fixture, handler)
	defer harness.stop(t)

	requestDone := make(chan error, 1)
	go func() {
		_, err := harness.client.Session(context.Background())
		requestDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(contentTestTimeout):
		t.Fatal("request did not reach server")
	}
	if err := harness.client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := harness.client.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
	select {
	case err := <-requestDone:
		if !errors.Is(err, ErrClientClosed) {
			t.Fatalf("interrupted Session() error = %v", err)
		}
	case <-time.After(contentTestTimeout):
		t.Fatal("Close did not interrupt request")
	}
	assertContentClientClosed(t, harness.client)
}

func TestClientClosesAtVerifierAuthorizedBound(t *testing.T) {
	fixture := newContentTLSFixture(t)
	const closeAfter = 500 * time.Millisecond
	recorder, err := transport.NewContentAdmissionRecorder(func(
		certificate transport.ContentCertificate,
	) (transport.ContentPeerAdmission, error) {
		if certificate.Binding != fixture.serverBinding {
			return transport.ContentPeerAdmission{}, errors.New(
				"unexpected content peer",
			)
		}
		return transport.ContentPeerAdmission{CloseAfter: closeAfter}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.clientAdmission = recorder
	fixture.clientConfig, err = transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       fixture.clientCert,
			VerifyContentPeer: recorder.Verify,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	harness, client, err := openScriptedContentClient(
		t,
		fixture,
		http.NotFoundHandler(),
		nil,
		fixture.serverDevice,
	)
	if err != nil {
		harness.stop(t)
		t.Fatal(err)
	}
	harness.client = client
	defer harness.stop(t)

	deadline := time.Now().Add(2 * time.Second)
	for !client.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !client.isClosed() {
		t.Fatal("client remained open past authenticated server certificate bound")
	}
	assertContentClientClosed(t, client)
}

type realContentClientHarness struct {
	client    *Client
	service   *contentTestService
	fixture   contentTLSFixture
	server    *Server
	ingress   *transport.Ingress
	address   string
	cancel    context.CancelFunc
	serveDone <-chan error
	stopOnce  sync.Once
}

func startRealContentClient(t testing.TB) *realContentClientHarness {
	t.Helper()
	return startRealContentClientWithFixture(t, newContentTLSFixture(t))
}

func startRealContentClientWithFixture(
	t testing.TB,
	fixture contentTLSFixture,
) *realContentClientHarness {
	t.Helper()
	service := newContentTestService(t, fixture.serverDevice)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
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

	raw, err := (&net.Dialer{}).DialContext(
		context.Background(),
		"tcp",
		listener.Addr().String(),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	client, err := OpenClient(
		context.Background(),
		tls.Client(raw, fixture.clientConfig.Clone()),
		fixture.serverDevice,
		fixture.clientAdmission,
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	harness := &realContentClientHarness{
		client: client, service: service, fixture: fixture,
		server: server, ingress: ingress,
		address: listener.Addr().String(),
		cancel:  cancel, serveDone: serveDone,
	}
	awaitContentCondition(t, "client ingress establishment", func() bool {
		return ingress.Stats().EstablishedConnections == 1
	})
	t.Cleanup(func() { harness.stop(t) })
	return harness
}

func (harness *realContentClientHarness) stop(t testing.TB) {
	t.Helper()
	harness.stopOnce.Do(func() {
		_ = harness.client.Close()
		harness.cancel()
		ctx, cancel := context.WithTimeout(
			context.Background(),
			contentTestTimeout,
		)
		defer cancel()
		if err := harness.ingress.Shutdown(ctx); err != nil {
			t.Errorf("Ingress.Shutdown(): %v", err)
		}
		select {
		case err := <-harness.serveDone:
			if err != nil {
				t.Errorf("Ingress.Serve(): %v", err)
			}
		case <-ctx.Done():
			t.Errorf("Ingress.Serve() did not return: %v", ctx.Err())
		}
	})
}

type scriptedContentHarness struct {
	client     *Client
	bulk       *SnapshotBulkClient
	listener   net.Listener
	cancel     context.CancelFunc
	serverDone <-chan error
	stopOnce   sync.Once
}

func mustOpenScriptedContentClient(
	t testing.TB,
	fixture contentTLSFixture,
	handler http.Handler,
) *scriptedContentHarness {
	t.Helper()
	harness, client, err := openScriptedContentClient(
		t,
		fixture,
		handler,
		nil,
		fixture.serverDevice,
	)
	if err != nil {
		harness.stop(t)
		t.Fatal(err)
	}
	harness.client = client
	return harness
}

func openScriptedContentClient(
	t testing.TB,
	fixture contentTLSFixture,
	handler http.Handler,
	mutateClientConfig func(*tls.Config),
	expectedDeviceID domain.DeviceID,
) (*scriptedContentHarness, *Client, error) {
	t.Helper()
	serverConfig, err := transport.NewServerTLSConfig(fixture.serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverContext, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go serveScriptedContent(
		serverContext,
		listener,
		serverConfig,
		handler,
		serverDone,
	)
	harness := &scriptedContentHarness{
		listener: listener, cancel: cancel, serverDone: serverDone,
	}
	config := fixture.clientConfig.Clone()
	if mutateClientConfig != nil {
		mutateClientConfig(config)
	}
	dialContext, cancelDial := context.WithTimeout(
		context.Background(),
		contentTestTimeout,
	)
	defer cancelDial()
	raw, err := (&net.Dialer{}).DialContext(
		dialContext,
		"tcp",
		listener.Addr().String(),
	)
	if err != nil {
		return harness, nil, err
	}
	client, err := openClient(
		dialContext,
		tls.Client(raw, config),
		expectedDeviceID,
		fixture.clientAdmission,
	)
	harness.client = client
	return harness, client, err
}

func serveScriptedContent(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config,
	handler http.Handler,
	done chan<- error,
) {
	raw, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	defer raw.Close()
	connection := tls.Server(raw, config)
	handshakeContext, cancel := context.WithTimeout(
		ctx,
		contentTestTimeout,
	)
	err = connection.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		done <- err
		return
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		done <- err
		return
	}
	server := &http2.Server{
		MaxConcurrentStreams:      ControlStreamsMax,
		MaxDecoderHeaderTableSize: 4 << 10,
		MaxEncoderHeaderTableSize: 4 << 10,
		MaxReadFrameSize:          16 << 10,
		IdleTimeout:               ConnectionIdle,
	}
	server.ServeConn(connection, &http2.ServeConnOpts{
		Context: ctx,
		BaseConfig: &http.Server{
			MaxHeaderBytes: HeaderMaxBytes,
		},
		Handler: handler,
	})
	done <- nil
}

func (harness *scriptedContentHarness) stop(t testing.TB) {
	t.Helper()
	harness.stopOnce.Do(func() {
		if harness.client != nil {
			_ = harness.client.Close()
		}
		if harness.bulk != nil {
			_ = harness.bulk.Close()
		}
		harness.cancel()
		_ = harness.listener.Close()
		select {
		case <-harness.serverDone:
		case <-time.After(contentTestTimeout):
			t.Error("scripted content server did not stop")
		}
	})
}

func staticContentHandler(
	status int,
	contentType string,
	body []byte,
	header http.Header,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writeScriptedResponse(writer, status, contentType, body, header)
	})
}

func writeScriptedResponse(
	writer http.ResponseWriter,
	status int,
	contentType string,
	body []byte,
	header http.Header,
) {
	for name, values := range header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func canonicalObjectWithField(
	t testing.TB,
	body []byte,
	name string,
	value json.RawMessage,
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	object[name] = value
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func mustClientPeerMember(
	t testing.TB,
	deviceID domain.DeviceID,
) PeerMember {
	t.Helper()
	member, err := NewPeerMember(PeerMemberInput{
		DeviceID: deviceID, Role: device.RoleOwner,
		Status: device.StatusActive, EntityVersion: 1,
		EndpointSet: []byte(`{"schema_version":1,"signature":"AA"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func assertContentClientClosed(t testing.TB, client *Client) {
	t.Helper()
	if _, err := client.Session(
		context.Background(),
	); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Session(after close) error = %v, want %v", err, ErrClientClosed)
	}
}

func TestOpenClientOwnsConnectionOnInvalidInput(t *testing.T) {
	server, client := net.Pipe()
	connection := tls.Client(client, &tls.Config{ //nolint:gosec -- no handshake occurs
		InsecureSkipVerify: true,
	})
	if _, err := OpenClient(
		context.Background(),
		connection,
		"invalid",
		nil,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("OpenClient(invalid device) error = %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := server.Read(buffer[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("invalid OpenClient left connection open")
		}
	case <-time.After(time.Second):
		_ = server.Close()
		t.Fatal("invalid OpenClient did not close owned connection")
	}
	_ = server.Close()
}

func TestClientProblemBoundsRejectOversizedDetail(t *testing.T) {
	fixture := newContentTLSFixture(t)
	detail := strings.Repeat("x", problemDetailMaxBytes+1)
	body, err := marshalCanonical(remoteProblemWire{
		Type:  "urn:codecomm:problem:content_unavailable",
		Title: "Unavailable", Status: http.StatusServiceUnavailable,
		Code: "content_unavailable", CorrelationID: "unavailable",
		Retryable: true, Detail: &detail,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness := mustOpenScriptedContentClient(
		t,
		fixture,
		staticContentHandler(
			http.StatusServiceUnavailable,
			contentProblemMediaType,
			body,
			nil,
		),
	)
	defer harness.stop(t)
	if _, err := harness.client.Session(
		context.Background(),
	); !errors.Is(err, ErrResponseProtocol) {
		t.Fatalf("Session(oversized detail) error = %v", err)
	}
}
