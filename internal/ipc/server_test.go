package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

type testBoundClient struct {
	handler      http.Handler
	disconnected chan struct{}
	disconnects  atomic.Int32
}

type brokenBoundClient struct {
	disconnected chan struct{}
}

func (*brokenBoundClient) Handler() http.Handler {
	panic("broken bound handler")
}

func (client *brokenBoundClient) Disconnected(context.Context) {
	close(client.disconnected)
}

func (client *testBoundClient) Handler() http.Handler {
	return client.handler
}

func (client *testBoundClient) Disconnected(context.Context) {
	if client.disconnects.Add(1) == 1 {
		close(client.disconnected)
	}
}

type testBinder struct {
	calls    atomic.Int32
	requests chan BindRequest
	peers    chan VerifiedPeer
	handler  http.Handler
	err      error
	panic    bool
	bound    chan *testBoundClient
}

func newTestBinder(handler http.Handler) *testBinder {
	return &testBinder{
		requests: make(chan BindRequest, 16),
		peers:    make(chan VerifiedPeer, 16),
		handler:  handler,
		bound:    make(chan *testBoundClient, 16),
	}
}

func (binder *testBinder) Bind(
	context.Context,
	VerifiedPeer,
	BindRequest,
) (BindResult, error) {
	panic("use bindWithValues")
}

func (binder *testBinder) bindWithValues(
	_ context.Context,
	peer VerifiedPeer,
	request BindRequest,
) (BindResult, error) {
	binder.calls.Add(1)
	if binder.panic {
		panic("binder panic")
	}
	if binder.err != nil {
		return BindResult{}, binder.err
	}
	client := &testBoundClient{
		handler:      binder.handler,
		disconnected: make(chan struct{}),
	}
	binder.requests <- request
	binder.peers <- peer
	binder.bound <- client
	return NewOperatorBindResult(client)
}

type binderAdapter struct {
	binder *testBinder
}

func (adapter binderAdapter) Bind(
	ctx context.Context,
	peer VerifiedPeer,
	request BindRequest,
) (BindResult, error) {
	return adapter.binder.bindWithValues(ctx, peer, request)
}

func TestHandleBindEmitsExactResultVariants(t *testing.T) {
	t.Parallel()

	const (
		operatorResponse = `{"client_class":"operator","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
		resumeResponse   = `{"client_class":"agent","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
		launchResponse   = `{"client_class":"agent","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"resume_capability":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio","session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	)
	tests := []struct {
		name     string
		class    string
		proof    json.RawMessage
		result   func(BoundClient) (BindResult, error)
		expected string
	}{
		{
			name:     "operator base",
			class:    "operator",
			result:   NewOperatorBindResult,
			expected: operatorResponse,
		},
		{
			name:     "agent resume base",
			class:    "agent",
			proof:    json.RawMessage(`{"kind":"resume"}`),
			result:   NewAgentResumeBindResult,
			expected: resumeResponse,
		},
		{
			name:  "agent launch capability",
			class: "agent",
			proof: json.RawMessage(`{"kind":"launch"}`),
			result: func(client BoundClient) (BindResult, error) {
				return NewAgentLaunchBindResult(
					client,
					bytesOf(0x2a, 32),
				)
			},
			expected: launchResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &testBoundClient{
				handler:      http.NotFoundHandler(),
				disconnected: make(chan struct{}),
			}
			result, err := test.result(client)
			if err != nil {
				t.Fatal(err)
			}
			server := bindUnitServer(BinderFunc(func(
				context.Context,
				VerifiedPeer,
				BindRequest,
			) (BindResult, error) {
				return result, nil
			}))
			request := httptest.NewRequest(
				http.MethodPost,
				bindPath,
				nil,
			)
			bound, handler, response := server.handleBind(
				context.Background(),
				VerifiedPeer{processID: 1, userID: "test"},
				request,
				bindBody(
					t,
					testSessionID,
					LocalProtocolVersion,
					test.class,
					test.proof,
				),
				"00112233445566778899aabbccddeeff",
			)
			if bound != client || handler == nil {
				t.Fatalf("accepted bind = (%#v, %#v)", bound, handler)
			}
			if response.status != http.StatusOK ||
				response.contentType != "application/json" ||
				string(response.body) != test.expected {
				t.Fatalf(
					"response = status %d, type %q, body %s",
					response.status,
					response.contentType,
					response.body,
				)
			}
		})
	}
}

func TestHandleBindRejectsMalformedOrMismatchedResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		class      string
		proof      json.RawMessage
		makeResult func(BoundClient) BindResult
		hasClient  bool
	}{
		{
			name:  "zero result",
			class: "operator",
			makeResult: func(BoundClient) BindResult {
				return BindResult{}
			},
		},
		{
			name:      "agent result for operator",
			class:     "operator",
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				result, _ := NewAgentResumeBindResult(client)
				return result
			},
		},
		{
			name:      "operator result for agent",
			class:     "agent",
			proof:     json.RawMessage(`{"kind":"resume"}`),
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				result, _ := NewOperatorBindResult(client)
				return result
			},
		},
		{
			name:      "launch result for operator",
			class:     "operator",
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				result, _ := NewAgentLaunchBindResult(client, make([]byte, 32))
				return result
			},
		},
		{
			name:      "short launch capability",
			class:     "agent",
			proof:     json.RawMessage(`{"kind":"launch"}`),
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				return BindResult{
					kind:             bindResultAgentLaunch,
					client:           client,
					resumeCapability: make([]byte, 31),
				}
			},
		},
		{
			name:      "capability on resume",
			class:     "agent",
			proof:     json.RawMessage(`{"kind":"resume"}`),
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				return BindResult{
					kind:             bindResultAgentResume,
					client:           client,
					resumeCapability: make([]byte, 32),
				}
			},
		},
		{
			name:      "unknown result kind",
			class:     "operator",
			hasClient: true,
			makeResult: func(client BoundClient) BindResult {
				return BindResult{kind: 255, client: client}
			},
		},
		{
			name:  "nil result client",
			class: "operator",
			makeResult: func(BoundClient) BindResult {
				return BindResult{kind: bindResultOperator}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &testBoundClient{
				handler:      http.NotFoundHandler(),
				disconnected: make(chan struct{}),
			}
			result := test.makeResult(client)
			server := bindUnitServer(BinderFunc(func(
				context.Context,
				VerifiedPeer,
				BindRequest,
			) (BindResult, error) {
				return result, nil
			}))
			request := httptest.NewRequest(
				http.MethodPost,
				bindPath,
				nil,
			)
			bound, handler, response := server.handleBind(
				context.Background(),
				VerifiedPeer{processID: 1, userID: "test"},
				request,
				bindBody(
					t,
					testSessionID,
					LocalProtocolVersion,
					test.class,
					test.proof,
				),
				"00112233445566778899aabbccddeeff",
			)
			if bound != nil || handler != nil {
				t.Fatalf("rejected bind retained client or handler")
			}
			var value problem
			if err := json.Unmarshal(response.body, &value); err != nil {
				t.Fatal(err)
			}
			if response.status != http.StatusForbidden ||
				value.Code != "local_bind_rejected" {
				t.Fatalf(
					"response = status %d, problem %#v",
					response.status,
					value,
				)
			}
			wantDisconnects := int32(0)
			if test.hasClient {
				wantDisconnects = 1
			}
			if got := client.disconnects.Load(); got != wantDisconnects {
				t.Fatalf(
					"disconnect calls = %d, want %d",
					got,
					wantDisconnects,
				)
			}
		})
	}
}

func bindUnitServer(binder Binder) *Server {
	return &Server{
		config: Config{
			SessionID:   testSessionID,
			WorkspaceID: testWorkspaceID,
			Binder:      binder,
		},
		limits: productionLimits(),
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

type serverHarness struct {
	server   *Server
	endpoint Endpoint
	cancel   context.CancelFunc
	result   chan error
}

func startServerHarness(
	t *testing.T,
	binder Binder,
	mutate func(*serverLimits),
) *serverHarness {
	t.Helper()
	directory := testRuntimeDirectory(t)
	endpoint, err := ParseEndpoint(testEndpointAddress(directory))
	if err != nil {
		t.Fatalf("ParseEndpoint() error = %v", err)
	}
	limits := productionLimits()
	if mutate != nil {
		mutate(&limits)
	}
	server, err := newServer(Config{
		Endpoint:    endpoint,
		SessionID:   testSessionID,
		WorkspaceID: testWorkspaceID,
		Binder:      binder,
	}, limits)
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- server.Serve(ctx)
	}()
	waitFor(t, time.Second, func() bool {
		server.stateMu.Lock()
		defer server.stateMu.Unlock()
		return server.started
	})
	harness := &serverHarness{
		server:   server,
		endpoint: endpoint,
		cancel:   cancel,
		result:   result,
	}
	t.Cleanup(func() {
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			2*time.Second,
		)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		default:
		}
	})
	return harness
}

type rawClient struct {
	connection *Conn
	reader     *bufio.Reader
}

func dialRawClient(t *testing.T, endpoint Endpoint) *rawClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := Dial(ctx, endpoint)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	client := &rawClient{
		connection: connection,
		reader:     bufio.NewReader(connection),
	}
	t.Cleanup(func() {
		_ = connection.Close()
	})
	return client
}

func (client *rawClient) exchange(
	t *testing.T,
	request string,
) (*http.Response, []byte) {
	t.Helper()
	if _, err := io.WriteString(client.connection, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(client.reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	return response, body
}

func (client *rawClient) bind(
	t *testing.T,
	sessionID domain.UUIDv7,
	version uint32,
	class string,
	proof json.RawMessage,
) (*http.Response, []byte) {
	t.Helper()
	body := bindBody(t, sessionID, version, class, proof)
	return client.exchange(t, jsonPOST(bindPath, body))
}

func bindBody(
	t *testing.T,
	sessionID domain.UUIDv7,
	version uint32,
	class string,
	proof json.RawMessage,
) []byte {
	t.Helper()
	value := map[string]any{
		"local_protocol_version": version,
		"client_instance_id":     string(testClientInstanceID),
		"session_id":             string(sessionID),
		"workspace_id":           string(testWorkspaceID),
		"client_class":           class,
	}
	if proof != nil {
		value["agent_proof"] = proof
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal bind body: %v", err)
	}
	return encoded
}

func jsonPOST(path string, body []byte) string {
	return fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: local.codecomm\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		path,
		len(body),
		body,
	)
}

func getRequest(path string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: local.codecomm\r\n\r\n",
		path,
	)
}

func TestServerRequiresBindPinsItAndDisconnectsExactlyOnce(t *testing.T) {
	t.Parallel()

	var handlerCalls atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerCalls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true}`)
	})
	binder := newTestBinder(handler)
	harness := startServerHarness(t, binderAdapter{binder}, nil)

	unbound := dialRawClient(t, harness.endpoint)
	response, body := unbound.exchange(t, getRequest("/local/v1/query/status"))
	assertProblem(t, response, body, http.StatusConflict, "local_bind_required")
	if binder.calls.Load() != 0 || handlerCalls.Load() != 0 {
		t.Fatal("pre-bind request reached binder or handler")
	}

	client := dialRawClient(t, harness.endpoint)
	response, _ = client.bind(
		t,
		testSessionID,
		LocalProtocolVersion,
		"operator",
		nil,
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bind status = %d, want 200", response.StatusCode)
	}
	bound := <-binder.bound
	request := <-binder.requests
	peer := <-binder.peers
	if request.Class != ClassOperator ||
		request.ClientInstanceID != testClientInstanceID {
		t.Fatalf("binder request = %#v", request)
	}
	if peer.PID() != uint32(os.Getpid()) || peer.UserID() == "" {
		t.Fatalf("verified peer = PID %d, user %q", peer.PID(), peer.UserID())
	}

	response, body = client.exchange(t, getRequest("/local/v1/query/status"))
	if response.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("handler response = %d %s", response.StatusCode, body)
	}
	response, body = client.exchange(
		t,
		jsonPOST(
			bindPath,
			bindBody(
				t,
				testSessionID,
				LocalProtocolVersion,
				"agent",
				json.RawMessage(`{}`),
			),
		),
	)
	assertProblem(t, response, body, http.StatusConflict, "local_already_bound")
	select {
	case <-bound.disconnected:
	case <-time.After(time.Second):
		t.Fatal("bound client was not disconnected")
	}
	if got := bound.disconnects.Load(); got != 1 {
		t.Fatalf("disconnect calls = %d, want 1", got)
	}
	if binder.calls.Load() != 1 || handlerCalls.Load() != 1 {
		t.Fatalf(
			"calls = binder %d, handler %d; want 1 each",
			binder.calls.Load(),
			handlerCalls.Load(),
		)
	}
}

func TestServerRejectsMismatchedAndUnauthorizedBinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sessionID   domain.UUIDv7
		version     uint32
		class       string
		proof       json.RawMessage
		binderError error
		binderPanic bool
		status      int
		code        string
		wantCalls   int32
	}{
		{
			name:      "protocol mismatch",
			sessionID: testSessionID,
			version:   LocalProtocolVersion + 1,
			class:     "operator",
			status:    http.StatusUpgradeRequired,
			code:      "local_protocol_mismatch",
		},
		{
			name:      "session mismatch",
			sessionID: testOtherSessionID,
			version:   LocalProtocolVersion,
			class:     "operator",
			status:    http.StatusForbidden,
			code:      "local_session_mismatch",
		},
		{
			name:        "binder rejection",
			sessionID:   testSessionID,
			version:     LocalProtocolVersion,
			class:       "agent",
			proof:       json.RawMessage(`{"kind":"launch"}`),
			binderError: ErrBindRejected,
			status:      http.StatusForbidden,
			code:        "local_bind_rejected",
			wantCalls:   1,
		},
		{
			name:        "binder panic",
			sessionID:   testSessionID,
			version:     LocalProtocolVersion,
			class:       "operator",
			binderPanic: true,
			status:      http.StatusForbidden,
			code:        "local_bind_rejected",
			wantCalls:   1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			binder.err = test.binderError
			binder.panic = test.binderPanic
			harness := startServerHarness(t, binderAdapter{binder}, nil)
			client := dialRawClient(t, harness.endpoint)
			response, body := client.bind(
				t,
				test.sessionID,
				test.version,
				test.class,
				test.proof,
			)
			assertProblem(t, response, body, test.status, test.code)
			if binder.calls.Load() != test.wantCalls {
				t.Fatalf(
					"binder calls = %d, want %d",
					binder.calls.Load(),
					test.wantCalls,
				)
			}
		})
	}
}

func TestPipelinedBindHasNoSideEffects(t *testing.T) {
	t.Parallel()

	binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("pipelined request reached handler")
	}))
	harness := startServerHarness(t, binderAdapter{binder}, nil)
	client := dialRawClient(t, harness.endpoint)
	bind := jsonPOST(
		bindPath,
		bindBody(
			t,
			testSessionID,
			LocalProtocolVersion,
			"operator",
			nil,
		),
	)
	response, body := client.exchange(
		t,
		bind+getRequest("/local/v1/query/status"),
	)
	assertProblem(
		t,
		response,
		body,
		http.StatusBadRequest,
		"local_pipelining_forbidden",
	)
	if binder.calls.Load() != 0 {
		t.Fatalf("pipelined bind reached binder %d times", binder.calls.Load())
	}
}

func TestRequestPipelinedWhileHandlerRunsIsNeverDispatched(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		_, _ = io.WriteString(writer, `{"ok":true}`)
	})
	binder := newTestBinder(handler)
	harness := startServerHarness(t, binderAdapter{binder}, nil)
	client := dialAndBindOperator(t, harness)

	firstWritten := make(chan error, 1)
	go func() {
		_, err := io.WriteString(
			client.connection,
			getRequest("/local/v1/query/first"),
		)
		firstWritten <- err
	}()
	if err := <-firstWritten; err != nil {
		t.Fatalf("write first request: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}
	if _, err := io.WriteString(
		client.connection,
		getRequest("/local/v1/query/pipelined"),
	); err != nil {
		t.Fatalf("write pipelined request: %v", err)
	}
	close(release)

	response, err := http.ReadResponse(client.reader, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		string(body) != `{"ok":true}` ||
		!response.Close {
		t.Fatalf(
			"first response = status %d, close %t, body %s",
			response.StatusCode,
			response.Close,
			body,
		)
	}
	if _, err := http.ReadResponse(client.reader, nil); err == nil {
		t.Fatal("pipelined request received a response")
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", calls.Load())
	}
}

func TestServerEnforcesHeaderAndBodyBoundaries(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		_, _ = fmt.Fprintf(writer, `{"bytes":%d}`, len(body))
	})
	binder := newTestBinder(handler)
	const (
		headerLimit = 512
		bodyLimit   = 512
	)
	harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
		limits.maxHeaderBytes = headerLimit
		limits.maxJSONBytes = bodyLimit
	})

	client := dialRawClient(t, harness.endpoint)
	response, _ := client.bind(
		t,
		testSessionID,
		LocalProtocolVersion,
		"operator",
		nil,
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bind status = %d", response.StatusCode)
	}
	exactBody := []byte(`"` + strings.Repeat("x", bodyLimit-2) + `"`)
	response, body := client.exchange(
		t,
		jsonPOST("/local/v1/commands", exactBody),
	)
	if response.StatusCode != http.StatusOK ||
		string(body) != `{"bytes":512}` {
		t.Fatalf("exact body response = %d %s", response.StatusCode, body)
	}

	exactHeaderPrefix := "GET /local/v1/query/status HTTP/1.1\r\n" +
		"Host: local.codecomm\r\nX-Pad: "
	exactHeaderSuffix := "\r\n\r\n"
	padding := headerLimit - len(exactHeaderPrefix) - len(exactHeaderSuffix)
	exactHeader := exactHeaderPrefix + strings.Repeat("x", padding) + exactHeaderSuffix
	if len(exactHeader) != headerLimit {
		t.Fatalf("exact header length = %d", len(exactHeader))
	}
	response, _ = client.exchange(t, exactHeader)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exact header status = %d, want 200", response.StatusCode)
	}

	overBodyClient := dialAndBindOperator(t, harness)
	overBodyRequest := fmt.Sprintf(
		"POST /local/v1/commands HTTP/1.1\r\n"+
			"Host: local.codecomm\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n",
		bodyLimit+1,
	)
	response, body = overBodyClient.exchange(t, overBodyRequest)
	assertProblem(
		t,
		response,
		body,
		http.StatusRequestEntityTooLarge,
		"local_body_too_large",
	)

	overHeaderClient := dialAndBindOperator(t, harness)
	overHeader := exactHeaderPrefix +
		strings.Repeat("x", padding+1) +
		exactHeaderSuffix
	response, body = overHeaderClient.exchange(t, overHeader)
	assertProblem(
		t,
		response,
		body,
		http.StatusRequestHeaderFieldsTooLarge,
		"local_headers_too_large",
	)
}

func TestConnectionAndHandlerLimitsRecover(t *testing.T) {
	t.Parallel()

	t.Run("connection", func(t *testing.T) {
		handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, `{}`)
		})
		binder := newTestBinder(handler)
		harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
			limits.maxConnections = 1
		})
		first := dialAndBindOperator(t, harness)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		secondConnection, dialErr := Dial(ctx, harness.endpoint)
		cancel()
		if dialErr == nil {
			second := &rawClient{
				connection: secondConnection,
				reader:     bufio.NewReader(secondConnection),
			}
			defer secondConnection.Close()
			response, err := http.ReadResponse(second.reader, nil)
			if err != nil {
				t.Fatalf("read connection-limit response: %v", err)
			}
			body, _ := io.ReadAll(response.Body)
			assertProblem(
				t,
				response,
				body,
				http.StatusServiceUnavailable,
				"local_connection_limit",
			)
		} else if !errors.Is(dialErr, ErrEndpointUnavailable) {
			t.Fatalf("connection-limit Dial() error = %v", dialErr)
		}
		_ = first.connection.Close()
		waitFor(t, time.Second, func() bool {
			return len(harness.server.connectionSlots) == 0
		})
		recovered := dialAndBindOperator(t, harness)
		response, _ := recovered.exchange(t, getRequest("/local/v1/query/status"))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("recovered request status = %d", response.StatusCode)
		}
	})

	t.Run("handler", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var calls atomic.Int32
		handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				close(started)
				<-release
			}
			_, _ = io.WriteString(writer, `{}`)
		})
		binder := newTestBinder(handler)
		harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
			limits.maxHandlers = 1
		})
		first := dialAndBindOperator(t, harness)
		second := dialAndBindOperator(t, harness)

		type exchangeResult struct {
			response *http.Response
			err      error
		}
		firstResult := make(chan exchangeResult, 1)
		go func() {
			_, err := io.WriteString(
				first.connection,
				getRequest("/local/v1/query/status"),
			)
			if err != nil {
				firstResult <- exchangeResult{err: err}
				return
			}
			response, err := http.ReadResponse(first.reader, nil)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if err == nil {
					err = closeErr
				}
			}
			firstResult <- exchangeResult{response: response, err: err}
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("first handler did not start")
		}
		response, body := second.exchange(t, getRequest("/local/v1/query/status"))
		assertProblem(
			t,
			response,
			body,
			http.StatusServiceUnavailable,
			"local_handler_limit",
		)
		close(release)
		select {
		case result := <-firstResult:
			if result.err != nil {
				t.Fatalf("first request error = %v", result.err)
			}
			if result.response.StatusCode != http.StatusOK {
				t.Fatalf("first response status = %d", result.response.StatusCode)
			}
		case <-time.After(time.Second):
			t.Fatal("first handler did not complete")
		}
		response, _ = second.exchange(t, getRequest("/local/v1/query/status"))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("handler-limit recovery status = %d", response.StatusCode)
		}
	})
}

func TestHandlerPanicAndShutdownCancellationFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("panic", func(t *testing.T) {
		binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("handler panic")
		}))
		harness := startServerHarness(t, binderAdapter{binder}, nil)
		client := dialAndBindOperator(t, harness)
		bound := <-binder.bound
		response, body := client.exchange(t, getRequest("/local/v1/query/status"))
		assertProblem(
			t,
			response,
			body,
			http.StatusInternalServerError,
			"local_internal_error",
		)
		select {
		case <-bound.disconnected:
		case <-time.After(time.Second):
			t.Fatal("panic did not disconnect bound client")
		}
	})

	t.Run("shutdown cancellation", func(t *testing.T) {
		started := make(chan struct{})
		handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			close(started)
			<-request.Context().Done()
			_, _ = io.WriteString(writer, `{}`)
		})
		binder := newTestBinder(handler)
		harness := startServerHarness(t, binderAdapter{binder}, nil)
		client := dialAndBindOperator(t, harness)
		bound := <-binder.bound
		go func() {
			_, _ = io.WriteString(
				client.connection,
				getRequest("/local/v1/query/status"),
			)
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("blocking handler did not start")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := harness.server.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		select {
		case <-bound.disconnected:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not disconnect bound client")
		}
	})

	t.Run("peer disconnect cancellation", func(t *testing.T) {
		started := make(chan struct{})
		canceled := make(chan struct{})
		handler := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			close(started)
			<-request.Context().Done()
			close(canceled)
		})
		binder := newTestBinder(handler)
		harness := startServerHarness(t, binderAdapter{binder}, nil)
		client := dialAndBindOperator(t, harness)
		bound := <-binder.bound
		if _, err := io.WriteString(
			client.connection,
			getRequest("/local/v1/query/status"),
		); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("blocking handler did not start")
		}
		if err := client.connection.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("peer disconnect did not cancel request context")
		}
		select {
		case <-bound.disconnected:
		case <-time.After(time.Second):
			t.Fatal("peer disconnect did not notify bound client")
		}
	})
}

func TestPartialHeaderTimesOut(t *testing.T) {
	t.Parallel()

	binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
		limits.headerTimeout = 50 * time.Millisecond
		limits.idleTimeout = time.Second
	})
	client := dialRawClient(t, harness.endpoint)
	response, body := client.exchange(t, "GET /")
	assertProblem(
		t,
		response,
		body,
		http.StatusRequestTimeout,
		"local_header_timeout",
	)
}

func TestSilentPreBindConnectionUsesHeaderTimeoutAndReleasesSlot(t *testing.T) {
	t.Parallel()

	binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
		limits.maxConnections = 1
		limits.headerTimeout = 40 * time.Millisecond
		limits.idleTimeout = time.Second
	})
	silent := dialRawClient(t, harness.endpoint)
	waitFor(t, time.Second, func() bool {
		return len(harness.server.connectionSlots) == 1
	})
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(harness.server.connectionSlots) == 0
	})

	replacement := dialAndBindOperator(t, harness)
	response, body := replacement.exchange(t, getRequest("/local/v1/query/status"))
	if response.StatusCode != http.StatusOK || string(body) != `{}` {
		t.Fatalf("replacement response = %d %q", response.StatusCode, body)
	}
	_ = silent.connection.Close()
}

func TestBoundConnectionRetainsIdleTimeout(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"ok":true}`)
	})
	binder := newTestBinder(handler)
	harness := startServerHarness(t, binderAdapter{binder}, func(limits *serverLimits) {
		limits.headerTimeout = 40 * time.Millisecond
		limits.idleTimeout = 500 * time.Millisecond
	})
	client := dialAndBindOperator(t, harness)
	time.Sleep(150 * time.Millisecond)

	response, body := client.exchange(t, getRequest("/local/v1/query/status"))
	if response.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("bound response = %d %s", response.StatusCode, body)
	}
}

func TestMalformedBoundClientIsRejectedAndCleanedUp(t *testing.T) {
	t.Parallel()

	disconnected := make(chan struct{})
	binder := BinderFunc(func(
		context.Context,
		VerifiedPeer,
		BindRequest,
	) (BindResult, error) {
		return BindResult{
			kind: bindResultOperator,
			client: &brokenBoundClient{
				disconnected: disconnected,
			},
		}, nil
	})
	harness := startServerHarness(t, binder, nil)
	client := dialRawClient(t, harness.endpoint)
	response, body := client.bind(
		t,
		testSessionID,
		LocalProtocolVersion,
		"operator",
		nil,
	)
	assertProblem(
		t,
		response,
		body,
		http.StatusForbidden,
		"local_bind_rejected",
	)
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("malformed bound client was not cleaned up")
	}
}

func TestConcurrentShutdownIsIdempotentAndServeIsOneShot(t *testing.T) {
	t.Parallel()

	binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	harness := startServerHarness(t, binderAdapter{binder}, nil)
	client := dialAndBindOperator(t, harness)
	bound := <-binder.bound

	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- harness.server.Shutdown(ctx)
		}()
	}
	for range callers {
		if err := <-results; err != nil {
			t.Errorf("concurrent Shutdown() error = %v", err)
		}
	}
	select {
	case <-bound.disconnected:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not disconnect client")
	}
	if err := harness.server.Serve(context.Background()); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("second Serve() error = %v, want ErrServerStarted", err)
	}
	_ = client.connection.Close()
}

func dialAndBindOperator(t *testing.T, harness *serverHarness) *rawClient {
	t.Helper()
	client := dialRawClient(t, harness.endpoint)
	response, body := client.bind(
		t,
		testSessionID,
		LocalProtocolVersion,
		"operator",
		nil,
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("operator bind = %d %s", response.StatusCode, body)
	}
	return client
}

func assertProblem(
	t *testing.T,
	response *http.Response,
	body []byte,
	status int,
	code string,
) {
	t.Helper()
	if response.StatusCode != status {
		t.Fatalf("response status = %d, want %d; body=%s", response.StatusCode, status, body)
	}
	if response.Header.Get("Content-Type") != problemMediaType {
		t.Fatalf("content type = %q, want %q", response.Header.Get("Content-Type"), problemMediaType)
	}
	var value problem
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode problem: %v; body=%s", err, body)
	}
	if value.Status != status ||
		value.Code != code ||
		value.CorrelationID == "" ||
		value.Type != "urn:codecomm:problem:"+code {
		t.Fatalf("problem = %#v", value)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

func TestServerConfigRejectsRaisedProductionLimits(t *testing.T) {
	t.Parallel()

	directory := testRuntimeDirectory(t)
	endpoint, err := ParseEndpoint(testEndpointAddress(directory))
	if err != nil {
		t.Fatal(err)
	}
	binder := BinderFunc(func(
		context.Context,
		VerifiedPeer,
		BindRequest,
	) (BindResult, error) {
		return BindResult{}, errors.New("unused")
	})
	tests := []struct {
		name   string
		mutate func(*serverLimits)
	}{
		{"connections", func(limits *serverLimits) { limits.maxConnections++ }},
		{"handlers", func(limits *serverLimits) { limits.maxHandlers++ }},
		{"headers", func(limits *serverLimits) { limits.maxHeaderBytes++ }},
		{"body", func(limits *serverLimits) { limits.maxJSONBytes++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := productionLimits()
			test.mutate(&limits)
			server, err := newServer(Config{
				Endpoint:    endpoint,
				SessionID:   testSessionID,
				WorkspaceID: testWorkspaceID,
				Binder:      binder,
			}, limits)
			if server != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("newServer() = %#v, %v; want ErrInvalidConfig", server, err)
			}
		})
	}
}

func TestResponseHeadersDoNotPermitHandlerFramingOverrides(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Transfer-Encoding", "chunked")
		writer.Header().Set("Connection", "upgrade")
		writer.Header().Set("Content-Length", "999999")
		_, _ = io.WriteString(writer, `{"safe":true}`)
	})
	binder := newTestBinder(handler)
	harness := startServerHarness(t, binderAdapter{binder}, nil)
	client := dialAndBindOperator(t, harness)
	response, body := client.exchange(t, getRequest("/local/v1/query/status"))
	if response.StatusCode != http.StatusOK ||
		string(body) != `{"safe":true}` ||
		len(response.TransferEncoding) != 0 ||
		response.ContentLength != int64(len(body)) {
		t.Fatalf(
			"response = status %d, length %d, transfer %v, body %s",
			response.StatusCode,
			response.ContentLength,
			response.TransferEncoding,
			body,
		)
	}
}

func TestStrictRequestFramingRejectsSmugglingForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request string
		status  int
		code    string
	}{
		{
			name: "HTTP 1.0",
			request: "POST /local/v1/bind HTTP/1.0\r\n" +
				"Host: local\r\nContent-Length: 0\r\n\r\n",
			status: http.StatusHTTPVersionNotSupported,
			code:   "local_unsupported_http",
		},
		{
			name: "chunked",
			request: "POST /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_unsupported_framing",
		},
		{
			name: "duplicate content length",
			request: "POST /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_unsupported_framing",
		},
		{
			name: "duplicate content type",
			request: "POST /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nContent-Length: 0\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Type: application/json\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_unsupported_framing",
		},
		{
			name: "comma content length",
			request: "POST /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nContent-Type: application/json\r\n" +
				"Content-Length: 2, 2\r\n\r\n{}",
			status: http.StatusBadRequest,
			code:   "local_invalid_http",
		},
		{
			name: "empty JSON body",
			request: "POST /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nContent-Type: application/json\r\n" +
				"Content-Length: 0\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_invalid_json",
		},
		{
			name: "header control byte",
			request: "GET /local/v1/query/status HTTP/1.1\r\n" +
				"Host: local\r\nX-Control: \x01\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_invalid_http",
		},
		{
			name: "unsupported method",
			request: "PUT /local/v1/bind HTTP/1.1\r\n" +
				"Host: local\r\nContent-Length: 0\r\n\r\n",
			status: http.StatusMethodNotAllowed,
			code:   "local_method_not_allowed",
		},
		{
			name: "bind query alias",
			request: "POST /local/v1/bind?class=operator HTTP/1.1\r\n" +
				"Host: local\r\nContent-Type: application/json\r\n" +
				"Content-Length: 2\r\n\r\n{}",
			status: http.StatusConflict,
			code:   "local_bind_required",
		},
		{
			name: "absolute target",
			request: "GET http://local/local/v1/query/status HTTP/1.1\r\n" +
				"Host: local\r\n\r\n",
			status: http.StatusBadRequest,
			code:   "local_unsupported_http",
		},
		{
			name:    "bare LF",
			request: "GET / HTTP/1.1\nHost: local\n\n",
			status:  http.StatusBadRequest,
			code:    "local_invalid_http",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binder := newTestBinder(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			harness := startServerHarness(t, binderAdapter{binder}, nil)
			client := dialRawClient(t, harness.endpoint)
			response, body := client.exchange(t, test.request)
			assertProblem(t, response, body, test.status, test.code)
			if binder.calls.Load() != 0 {
				t.Fatalf("malformed request reached binder %d times", binder.calls.Load())
			}
		})
	}
}

func TestProductionLimitsMatchDesign(t *testing.T) {
	t.Parallel()

	limits := productionLimits()
	if limits.maxConnections != 128 ||
		limits.maxHandlers != 64 ||
		limits.maxHeaderBytes != 32<<10 ||
		limits.maxJSONBytes != 1<<20 ||
		limits.headerTimeout != 10*time.Second ||
		limits.idleTimeout != 120*time.Second {
		t.Fatalf("production limits = %#v", limits)
	}
}
