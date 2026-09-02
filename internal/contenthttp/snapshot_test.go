package contenthttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/transport"
)

type contentSnapshotParts struct {
	root         logicalsnapshot.Root
	page         logicalsnapshot.DescriptorPage
	manifestPage SnapshotManifestPage
	chunk        SnapshotChunk
	scope        SnapshotRequestScope
}

func TestSnapshotServerReturnsExactRepresentations(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	parts := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot-01890f47",
		[]byte("exact transmitted snapshot chunk"),
	)
	setContentSnapshotParts(harness.service, parts)

	response := harness.request(
		t,
		http.MethodGet,
		SnapshotLatestPath,
		nil,
	)
	body := assertContentResponse(
		t,
		response,
		http.StatusOK,
		contentJSONMediaType,
	)
	if !bytes.Equal(body, parts.root.CanonicalBytes()) {
		t.Fatal("latest root bytes changed in transit")
	}

	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		harness.fixture,
		parts.root,
	)
	page, err := bulk.SnapshotManifestPage(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(page.CanonicalBytes(), parts.page.CanonicalBytes()) {
		t.Fatal("descriptor-page bytes changed in transit")
	}
	chunk, err := bulk.SnapshotChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk.Bytes(), parts.chunk.Bytes()) {
		t.Fatal("chunk bytes changed in transit")
	}
}

func TestSnapshotClientRoundTripBindsRootAndArtifact(t *testing.T) {
	fixture := newContentTLSFixture(t)
	harness := startRealContentClientWithFixture(t, fixture)
	parts := newContentSnapshotParts(
		t,
		fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.client-round-trip",
		[]byte{0, 1, 2, 3, 0xff},
	)
	setContentSnapshotParts(harness.service, parts)

	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	root, err := harness.client.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LatestSnapshot() error = %v", err)
	}
	if !bytes.Equal(root.CanonicalBytes(), parts.root.CanonicalBytes()) {
		t.Fatal("LatestSnapshot() changed canonical root bytes")
	}
	if err := logicalsnapshot.VerifyRoot(
		root,
		fixture.serverIdentity.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("VerifyRoot() error = %v", err)
	}

	if _, err := harness.client.SnapshotManifestPage(
		context.Background(),
		root,
		0,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("control SnapshotManifestPage() error = %v", err)
	}
	if _, err := harness.client.SnapshotChunk(
		context.Background(),
		root,
		0,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("control SnapshotChunk() error = %v", err)
	}
	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		fixture,
		root,
	)
	page, err := bulk.SnapshotManifestPage(context.Background(), 0)
	if err != nil {
		t.Fatalf("bulk SnapshotManifestPage() error = %v", err)
	}
	if !bytes.Equal(page.CanonicalBytes(), parts.page.CanonicalBytes()) {
		t.Fatal("SnapshotManifestPage() changed canonical page bytes")
	}
	chunk, err := bulk.SnapshotChunk(
		context.Background(),
		0,
	)
	if err != nil {
		t.Fatalf("bulk SnapshotChunk() error = %v", err)
	}
	if chunk.ArtifactID() != root.Unsigned().Input().ArtifactID ||
		chunk.ChunkIndex() != 0 ||
		!bytes.Equal(chunk.Bytes(), parts.chunk.Bytes()) {
		t.Fatalf(
			"SnapshotChunk() = (%q, %d, %x)",
			chunk.ArtifactID(),
			chunk.ChunkIndex(),
			chunk.Bytes(),
		)
	}
	if err := bulk.Close(); err != nil {
		t.Fatalf("SnapshotBulkClient.Close(): %v", err)
	}
	awaitContentCondition(t, "snapshot transfer close", func() bool {
		harness.service.mu.Lock()
		defer harness.service.mu.Unlock()
		return harness.service.snapshotCloseCalls == 1
	})

	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotRootCalls != 1 ||
		harness.service.snapshotOpenCalls != 1 ||
		harness.service.snapshotCloseCalls != 1 ||
		harness.service.snapshotPageCalls != 1 ||
		harness.service.snapshotChunkCalls != 1 ||
		!slicesEqualStrings(
			harness.service.snapshotPageArtifact,
			[]string{"snapshot.client-round-trip"},
		) ||
		!slicesEqualUint64(harness.service.snapshotPageIndex, []uint64{0}) ||
		!slicesEqualStrings(
			harness.service.snapshotChunkArtifact,
			[]string{"snapshot.client-round-trip"},
		) ||
		!slicesEqualUint64(harness.service.snapshotChunkIndex, []uint64{0}) {
		t.Fatalf(
			"snapshot calls root/open/close/page/chunk=%d/%d/%d/%d/%d page=%v/%v chunk=%v/%v",
			harness.service.snapshotRootCalls,
			harness.service.snapshotOpenCalls,
			harness.service.snapshotCloseCalls,
			harness.service.snapshotPageCalls,
			harness.service.snapshotChunkCalls,
			harness.service.snapshotPageArtifact,
			harness.service.snapshotPageIndex,
			harness.service.snapshotChunkArtifact,
			harness.service.snapshotChunkIndex,
		)
	}
}

func TestSnapshotBulkConnectionRejectsSecondScopeAndClosesTransfer(
	t *testing.T,
) {
	harness := startContentHarness(t, ActiveHandlersMax)
	first := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.scope-first",
		[]byte("first scope"),
	)
	second := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.scope-second",
		[]byte("second scope"),
	)
	setContentSnapshotParts(harness.service, first)
	firstPath, valid := snapshotIndexedPath(
		first.scope.ArtifactID,
		"manifest-pages",
		0,
	)
	if !valid {
		t.Fatal("first descriptor-page path rejected")
	}
	response := harness.request(t, http.MethodGet, firstPath, nil)
	assertContentResponse(
		t,
		response,
		http.StatusOK,
		contentJSONMediaType,
	)

	secondPath, valid := snapshotIndexedPath(
		second.scope.ArtifactID,
		"manifest-pages",
		0,
	)
	if !valid {
		t.Fatal("second descriptor-page path rejected")
	}
	request, err := http.NewRequest(
		http.MethodGet,
		"https://codecomm.invalid"+secondPath,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !setSnapshotScopeHeaders(request.Header, second.scope) {
		t.Fatal("second scope headers rejected")
	}
	response, err = harness.client.RoundTrip(request)
	if err != nil {
		t.Fatalf("scope-mismatch RoundTrip(): %v", err)
	}
	body := assertContentResponse(
		t,
		response,
		http.StatusBadRequest,
		contentProblemMediaType,
	)
	if !bytes.Contains(body, []byte(`"code":"invalid_snapshot_scope"`)) {
		t.Fatalf("scope-mismatch body = %s", body)
	}
	awaitContentCondition(t, "scope-mismatch transfer close", func() bool {
		harness.service.mu.Lock()
		defer harness.service.mu.Unlock()
		return harness.service.snapshotCloseCalls == 1
	})
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotOpenCalls != 1 ||
		len(harness.service.snapshotOpenScopes) != 1 ||
		harness.service.snapshotOpenScopes[0] != first.scope ||
		harness.service.snapshotPageCalls != 1 {
		t.Fatalf(
			"scope transfer calls = opens %d scopes %+v pages %d",
			harness.service.snapshotOpenCalls,
			harness.service.snapshotOpenScopes,
			harness.service.snapshotPageCalls,
		)
	}
}

func TestSnapshotTransferHardDeadlineClosesConnection(t *testing.T) {
	harness := startContentHarness(
		t,
		ActiveHandlersMax,
		func(server *Server) {
			server.snapshotTransferLifetime = 25 * time.Millisecond
		},
	)
	parts := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.hard-deadline",
		[]byte("deadline"),
	)
	setContentSnapshotParts(harness.service, parts)
	pagePath, valid := snapshotIndexedPath(
		parts.scope.ArtifactID,
		"manifest-pages",
		0,
	)
	if !valid {
		t.Fatal("descriptor-page path rejected")
	}
	response := harness.request(t, http.MethodGet, pagePath, nil)
	assertContentResponse(
		t,
		response,
		http.StatusOK,
		contentJSONMediaType,
	)
	awaitContentCondition(t, "hard-deadline transfer close", func() bool {
		harness.service.mu.Lock()
		defer harness.service.mu.Unlock()
		return harness.service.snapshotCloseCalls == 1
	})
	harness.stop(t)
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotOpenCalls != 1 ||
		harness.service.snapshotCloseCalls != 1 {
		t.Fatalf(
			"hard-deadline lifecycle = opens %d closes %d",
			harness.service.snapshotOpenCalls,
			harness.service.snapshotCloseCalls,
		)
	}
}

func openSnapshotBulkClient(
	t testing.TB,
	address string,
	fixture contentTLSFixture,
	root logicalsnapshot.Root,
) *SnapshotBulkClient {
	t.Helper()
	admission, err := transport.NewContentAdmissionRecorder(
		func(
			certificate transport.ContentCertificate,
		) (transport.ContentPeerAdmission, error) {
			if certificate.Binding != fixture.serverBinding {
				return transport.ContentPeerAdmission{},
					errors.New("wrong content server")
			}
			return contentAdmission(certificate)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	config, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       fixture.clientCert,
			VerifyContentPeer: admission.Verify,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	dialContext, cancel := context.WithTimeout(
		context.Background(),
		contentTestTimeout,
	)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(
		dialContext,
		"tcp",
		address,
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := OpenSnapshotBulkClient(
		dialContext,
		tls.Client(raw, config),
		fixture.serverDevice,
		admission,
		root,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("SnapshotBulkClient.Close(): %v", err)
		}
	})
	return client
}

func mustOpenScriptedSnapshotBulkClient(
	t testing.TB,
	fixture contentTLSFixture,
	root logicalsnapshot.Root,
	handler http.Handler,
) *scriptedContentHarness {
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
		listener:   listener,
		cancel:     cancel,
		serverDone: serverDone,
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
		harness.stop(t)
		t.Fatal(err)
	}
	bulk, err := OpenSnapshotBulkClient(
		dialContext,
		tls.Client(raw, fixture.clientConfig.Clone()),
		fixture.serverDevice,
		fixture.clientAdmission,
		root,
	)
	if err != nil {
		harness.stop(t)
		t.Fatal(err)
	}
	harness.bulk = bulk
	return harness
}

func TestSnapshotServerRejectsNoncanonicalTargets(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	parts := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"artifact",
		[]byte("chunk"),
	)
	setContentSnapshotParts(harness.service, parts)

	for _, target := range []string{
		"/v1/snapshots",
		"/v1/snapshots/",
		SnapshotLatestPath + "/",
		SnapshotLatestPath + "?",
		SnapshotLatestPath + "?x=1",
		"/v1/snapshots//chunks/0",
		"/v1/snapshots/./chunks/0",
		"/v1/snapshots/../chunks/0",
		"/v1/snapshots/bad%2Fid/chunks/0",
		"/v1/snapshots/artifact/chunk/0",
		"/v1/snapshots/artifact/chunks/",
		"/v1/snapshots/artifact/chunks/00",
		"/v1/snapshots/artifact/chunks/+1",
		"/v1/snapshots/artifact/chunks/9007199254740992",
		"/v1/snapshots/artifact/chunks/18446744073709551616",
		"/v1/snapshots/artifact/chunks/0/extra",
		"/v1/snapshots/artifact/manifest-pages/0?x=1",
	} {
		t.Run(target, func(t *testing.T) {
			response := harness.request(t, http.MethodGet, target, nil)
			assertContentResponse(
				t,
				response,
				http.StatusNotFound,
				contentProblemMediaType,
			)
		})
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotRootCalls != 0 ||
		harness.service.snapshotPageCalls != 0 ||
		harness.service.snapshotChunkCalls != 0 {
		t.Fatal("noncanonical snapshot target reached service")
	}
}

func TestSnapshotServerEnforcesMethodBodyAndMediaType(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      string
		target      string
		body        io.Reader
		accept      string
		status      int
		contentType string
	}{
		{
			name: "method", method: http.MethodPost,
			target: SnapshotLatestPath,
			status: http.StatusMethodNotAllowed,
		},
		{
			name: "body", method: http.MethodGet,
			target: SnapshotLatestPath, body: strings.NewReader("x"),
			status: http.StatusBadRequest,
		},
		{
			name: "root media", method: http.MethodGet,
			target: SnapshotLatestPath, accept: snapshotChunkMediaType,
			status: http.StatusNotAcceptable,
		},
		{
			name: "chunk media", method: http.MethodGet,
			target: "/v1/snapshots/artifact/chunks/0",
			accept: contentJSONMediaType,
			status: http.StatusNotAcceptable,
		},
		{
			name: "chunk parameter", method: http.MethodGet,
			target: "/v1/snapshots/artifact/chunks/0",
			accept: snapshotChunkMediaType + "; q=1",
			status: http.StatusNotAcceptable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := startContentHarness(t, ActiveHandlersMax)
			parts := newContentSnapshotParts(
				t,
				harness.fixture.serverIdentity,
				testSessionID,
				testWorkspaceID,
				0,
				"artifact",
				[]byte("chunk"),
			)
			setContentSnapshotParts(harness.service, parts)
			request, err := http.NewRequest(
				test.method,
				"https://codecomm.invalid"+test.target,
				test.body,
			)
			if err != nil {
				t.Fatal(err)
			}
			if test.accept != "" {
				request.Header.Set("Accept", test.accept)
			}
			response, err := harness.client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			assertContentResponse(
				t,
				response,
				test.status,
				contentProblemMediaType,
			)
		})
	}
}

func TestSnapshotServerMapsServiceErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		target     string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{
			name: "root not found", target: SnapshotLatestPath,
			err: ErrSnapshotNotFound, status: http.StatusNotFound,
			code: "snapshot_not_found",
		},
		{
			name:   "page unavailable",
			target: "/v1/snapshots/artifact/manifest-pages/0",
			err:    ErrSnapshotUnavailable, status: http.StatusServiceUnavailable,
			code: "snapshot_unavailable", retryAfter: "1",
		},
		{
			name:   "chunk deadline",
			target: "/v1/snapshots/artifact/chunks/0",
			err:    context.DeadlineExceeded,
			status: http.StatusServiceUnavailable,
			code:   "snapshot_unavailable", retryAfter: "1",
		},
		{
			name: "internal", target: SnapshotLatestPath,
			err:    errors.New("storage failed"),
			status: http.StatusInternalServerError,
			code:   "internal_error",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := startContentHarness(t, ActiveHandlersMax)
			parts := newContentSnapshotParts(
				t,
				harness.fixture.serverIdentity,
				testSessionID,
				testWorkspaceID,
				0,
				"artifact",
				[]byte("chunk"),
			)
			setContentSnapshotParts(harness.service, parts)
			harness.service.mu.Lock()
			switch {
			case strings.Contains(test.target, "manifest-pages"):
				harness.service.snapshotPageErr = test.err
			case strings.Contains(test.target, "/chunks/"):
				harness.service.snapshotChunkErr = test.err
			default:
				harness.service.snapshotRootErr = test.err
			}
			harness.service.mu.Unlock()

			response := harness.request(
				t,
				http.MethodGet,
				test.target,
				nil,
			)
			body := assertContentResponse(
				t,
				response,
				test.status,
				contentProblemMediaType,
			)
			var problem problemResponse
			if err := json.Unmarshal(body, &problem); err != nil ||
				problem.Code != test.code ||
				!problem.Retryable ||
				response.Header.Get("Retry-After") != test.retryAfter {
				t.Fatalf(
					"problem=%+v error=%v headers=%v",
					problem,
					err,
					response.Header,
				)
			}
		})
	}
}

func TestSnapshotRoutesShareReplicationCapacity(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	harness.server.replicationHandlers <- struct{}{}
	response := harness.request(
		t,
		http.MethodGet,
		SnapshotLatestPath,
		nil,
	)
	<-harness.server.replicationHandlers
	body := assertContentResponse(
		t,
		response,
		http.StatusServiceUnavailable,
		contentProblemMediaType,
	)
	if !bytes.Contains(body, []byte(`"code":"snapshot_unavailable"`)) ||
		response.Header.Get("Retry-After") != "1" {
		t.Fatalf("capacity response=%s headers=%v", body, response.Header)
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotRootCalls != 0 {
		t.Fatal("over-capacity snapshot request reached service")
	}
}

func TestSnapshotChunkUsesOnlyBulkConnectionCapacity(t *testing.T) {
	harness := startContentHarness(t, 1)
	parts := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.bulk-capacity",
		[]byte("bulk content"),
	)
	setContentSnapshotParts(harness.service, parts)
	harness.ensureControlRegistered(t)

	harness.server.control.mu.Lock()
	state := harness.server.control.states[harness.fixture.clientBinding.DeviceID]
	if state == nil {
		harness.server.control.mu.Unlock()
		t.Fatal("peer control state is unavailable")
	}
	future := time.Now().Add(time.Hour)
	state.bucket = controlTokenBucket{last: future}
	state.lastSeen = future
	harness.server.control.mu.Unlock()

	harness.server.handlers <- struct{}{}
	harness.server.replicationHandlers <- struct{}{}
	defer func() {
		<-harness.server.replicationHandlers
		<-harness.server.handlers
	}()

	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		harness.fixture,
		parts.root,
	)
	chunk, err := bulk.SnapshotChunk(context.Background(), 0)
	if err != nil {
		t.Fatalf("SnapshotChunk() error = %v", err)
	}
	if !bytes.Equal(chunk.Bytes(), parts.chunk.Bytes()) {
		t.Fatalf("SnapshotChunk() = %q, want %q", chunk.Bytes(), parts.chunk.Bytes())
	}

	harness.server.control.mu.Lock()
	state = harness.server.control.states[harness.fixture.clientBinding.DeviceID]
	remainingCredit := state.bucket.credit
	harness.server.control.mu.Unlock()
	if remainingCredit != 0 {
		t.Fatalf("bulk request consumed or refilled control credit: %d", remainingCredit)
	}
}

func TestSnapshotServerRejectsMismatchedServiceResults(t *testing.T) {
	for _, test := range []struct {
		name      string
		target    string
		configure func(testing.TB, *contentHarness, contentSnapshotParts)
	}{
		{
			name:   "root lineage",
			target: SnapshotLatestPath,
			configure: func(
				t testing.TB,
				harness *contentHarness,
				_ contentSnapshotParts,
			) {
				wrong := newContentSnapshotParts(
					t,
					harness.fixture.serverIdentity,
					contentClientOtherSession,
					testWorkspaceID,
					0,
					"artifact",
					[]byte("chunk"),
				)
				harness.service.snapshotRoot = wrong.root
			},
		},
		{
			name:   "root artifact path",
			target: SnapshotLatestPath,
			configure: func(
				t testing.TB,
				harness *contentHarness,
				parts contentSnapshotParts,
			) {
				harness.service.snapshotRoot = snapshotRootWithArtifact(
					t,
					harness.fixture.serverIdentity,
					parts,
					"..",
				)
			},
		},
		{
			name:   "page artifact",
			target: "/v1/snapshots/artifact/manifest-pages/0",
			configure: func(
				t testing.TB,
				harness *contentHarness,
				_ contentSnapshotParts,
			) {
				wrong := newContentSnapshotParts(
					t,
					harness.fixture.serverIdentity,
					testSessionID,
					testWorkspaceID,
					0,
					"other-artifact",
					[]byte("chunk"),
				)
				harness.service.snapshotPage = wrong.manifestPage
			},
		},
		{
			name:   "chunk artifact",
			target: "/v1/snapshots/artifact/chunks/0",
			configure: func(
				t testing.TB,
				harness *contentHarness,
				_ contentSnapshotParts,
			) {
				wrong := newContentSnapshotParts(
					t,
					harness.fixture.serverIdentity,
					testSessionID,
					testWorkspaceID,
					0,
					"other-artifact",
					[]byte("chunk"),
				)
				harness.service.snapshotChunk = wrong.chunk
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := startContentHarness(t, ActiveHandlersMax)
			parts := newContentSnapshotParts(
				t,
				harness.fixture.serverIdentity,
				testSessionID,
				testWorkspaceID,
				0,
				"artifact",
				[]byte("chunk"),
			)
			setContentSnapshotParts(harness.service, parts)
			harness.service.mu.Lock()
			test.configure(t, harness, parts)
			harness.service.mu.Unlock()

			response := harness.request(
				t,
				http.MethodGet,
				test.target,
				nil,
			)
			body := assertContentResponse(
				t,
				response,
				http.StatusInternalServerError,
				contentProblemMediaType,
			)
			if !bytes.Contains(body, []byte(`"code":"internal_error"`)) {
				t.Fatalf("body=%s", body)
			}
		})
	}
}

func TestSnapshotClientRejectsLineageAndPageArtifactMismatch(t *testing.T) {
	t.Run("root lineage", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		service := newContentTestService(t, fixture.serverDevice)
		sessionBody, err := service.session.canonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		wrong := newContentSnapshotParts(
			t,
			fixture.serverIdentity,
			contentClientOtherSession,
			testWorkspaceID,
			0,
			"artifact",
			[]byte("chunk"),
		)
		handler := snapshotScriptedHandler(
			sessionBody,
			wrong.root.CanonicalBytes(),
			nil,
			nil,
			contentJSONMediaType,
		)
		harness := mustOpenScriptedContentClient(t, fixture, handler)
		defer harness.stop(t)
		if _, err := harness.client.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.client.LatestSnapshot(
			context.Background(),
		); !errors.Is(err, ErrLineageMismatch) {
			t.Fatalf("LatestSnapshot() error=%v", err)
		}
		assertContentClientClosed(t, harness.client)
	})

	t.Run("root artifact path", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		service := newContentTestService(t, fixture.serverDevice)
		sessionBody, err := service.session.canonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		parts := newContentSnapshotParts(
			t,
			fixture.serverIdentity,
			testSessionID,
			testWorkspaceID,
			0,
			"artifact",
			[]byte("chunk"),
		)
		unsafeRoot := snapshotRootWithArtifact(
			t,
			fixture.serverIdentity,
			parts,
			"..",
		)
		handler := snapshotScriptedHandler(
			sessionBody,
			unsafeRoot.CanonicalBytes(),
			nil,
			nil,
			contentJSONMediaType,
		)
		harness := mustOpenScriptedContentClient(t, fixture, handler)
		defer harness.stop(t)
		if _, err := harness.client.Session(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.client.LatestSnapshot(
			context.Background(),
		); !errors.Is(err, ErrResponseProtocol) {
			t.Fatalf("LatestSnapshot() error=%v", err)
		}
		assertContentClientClosed(t, harness.client)
	})

	t.Run("page artifact", func(t *testing.T) {
		fixture := newContentTLSFixture(t)
		service := newContentTestService(t, fixture.serverDevice)
		sessionBody, err := service.session.canonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		rootParts := newContentSnapshotParts(
			t,
			fixture.serverIdentity,
			testSessionID,
			testWorkspaceID,
			0,
			"artifact",
			[]byte("chunk"),
		)
		wrong := newContentSnapshotParts(
			t,
			fixture.serverIdentity,
			testSessionID,
			testWorkspaceID,
			0,
			"other-artifact",
			[]byte("chunk"),
		)
		handler := snapshotScriptedHandler(
			sessionBody,
			rootParts.root.CanonicalBytes(),
			wrong.page.CanonicalBytes(),
			rootParts.chunk.Bytes(),
			contentJSONMediaType,
		)
		harness := mustOpenScriptedSnapshotBulkClient(
			t,
			fixture,
			rootParts.root,
			handler,
		)
		defer harness.stop(t)
		if _, err := harness.bulk.SnapshotManifestPage(
			context.Background(),
			0,
		); !errors.Is(err, ErrResponseProtocol) {
			t.Fatalf("SnapshotManifestPage() error=%v", err)
		}
		assertContentClientClosed(t, harness.bulk.client)
	})
}

func TestSnapshotClientRejectsMalformedMediaAndSizeResponses(t *testing.T) {
	for _, test := range []struct {
		name        string
		response    []byte
		contentType string
		call        func(context.Context, *Client, logicalsnapshot.Root) error
		bulkCall    func(context.Context, *SnapshotBulkClient) error
		want        error
		also        error
	}{
		{
			name: "malformed root", response: []byte(`{"invalid":true}`),
			contentType: contentJSONMediaType,
			call: func(ctx context.Context, client *Client, _ logicalsnapshot.Root) error {
				_, err := client.LatestSnapshot(ctx)
				return err
			},
			want: ErrResponseProtocol, also: logicalsnapshot.ErrInvalidRoot,
		},
		{
			name: "root media", response: []byte(`{"invalid":true}`),
			contentType: snapshotChunkMediaType,
			call: func(ctx context.Context, client *Client, _ logicalsnapshot.Root) error {
				_, err := client.LatestSnapshot(ctx)
				return err
			},
			want: ErrResponseProtocol,
		},
		{
			name: "root size",
			response: bytes.Repeat(
				[]byte{'x'},
				logicalsnapshot.MaxRootBytes+1,
			),
			contentType: contentJSONMediaType,
			call: func(ctx context.Context, client *Client, _ logicalsnapshot.Root) error {
				_, err := client.LatestSnapshot(ctx)
				return err
			},
			want: ErrResponseTooLarge,
		},
		{
			name: "malformed page", response: []byte(`{"invalid":true}`),
			contentType: contentJSONMediaType,
			bulkCall: func(ctx context.Context, client *SnapshotBulkClient) error {
				_, err := client.SnapshotManifestPage(ctx, 0)
				return err
			},
			want: ErrResponseProtocol,
			also: logicalsnapshot.ErrInvalidDescriptorPage,
		},
		{
			name: "page media", response: []byte(`{"invalid":true}`),
			contentType: snapshotChunkMediaType,
			bulkCall: func(ctx context.Context, client *SnapshotBulkClient) error {
				_, err := client.SnapshotManifestPage(ctx, 0)
				return err
			},
			want: ErrResponseProtocol,
		},
		{
			name: "page size",
			response: bytes.Repeat(
				[]byte{'x'},
				logicalsnapshot.MaxDescriptorPageBytes+1,
			),
			contentType: contentJSONMediaType,
			bulkCall: func(ctx context.Context, client *SnapshotBulkClient) error {
				_, err := client.SnapshotManifestPage(ctx, 0)
				return err
			},
			want: ErrResponseTooLarge,
		},
		{
			name: "chunk media", response: []byte("chunk"),
			contentType: contentJSONMediaType,
			bulkCall: func(ctx context.Context, client *SnapshotBulkClient) error {
				_, err := client.SnapshotChunk(ctx, 0)
				return err
			},
			want: ErrResponseProtocol,
		},
		{
			name: "chunk size",
			response: bytes.Repeat(
				[]byte{'x'},
				logicalsnapshot.MaxChunkCompressedBytes+1,
			),
			contentType: snapshotChunkMediaType,
			bulkCall: func(ctx context.Context, client *SnapshotBulkClient) error {
				_, err := client.SnapshotChunk(ctx, 0)
				return err
			},
			want: ErrResponseTooLarge,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newContentTLSFixture(t)
			service := newContentTestService(t, fixture.serverDevice)
			sessionBody, err := service.session.canonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			parts := newContentSnapshotParts(
				t,
				fixture.serverIdentity,
				testSessionID,
				testWorkspaceID,
				0,
				"artifact",
				[]byte("chunk"),
			)
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
					test.contentType,
					test.response,
					nil,
				)
			})
			var callErr error
			if test.bulkCall != nil {
				harness := mustOpenScriptedSnapshotBulkClient(
					t,
					fixture,
					parts.root,
					handler,
				)
				defer harness.stop(t)
				callErr = test.bulkCall(
					context.Background(),
					harness.bulk,
				)
			} else {
				harness := mustOpenScriptedContentClient(
					t,
					fixture,
					handler,
				)
				defer harness.stop(t)
				if _, err := harness.client.Session(
					context.Background(),
				); err != nil {
					t.Fatal(err)
				}
				callErr = test.call(
					context.Background(),
					harness.client,
					parts.root,
				)
			}
			if !errors.Is(callErr, test.want) ||
				test.also != nil && !errors.Is(callErr, test.also) {
				t.Fatalf(
					"snapshot client error=%v, want %v and %v",
					callErr,
					test.want,
					test.also,
				)
			}
		})
	}
}

func TestSnapshotClientRejectsTruncatedAndOverlongBodies(t *testing.T) {
	for _, test := range []struct {
		name          string
		body          string
		contentLength int64
	}{
		{name: "truncated", body: "x", contentLength: 2},
		{name: "overlong", body: "xx", contentLength: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			connection := tls.Client(clientRaw, &tls.Config{ //nolint:gosec
				InsecureSkipVerify: true,
			})
			defer connection.Close()
			response := &http.Response{
				StatusCode:    http.StatusOK,
				Body:          io.NopCloser(strings.NewReader(test.body)),
				ContentLength: test.contentLength,
				Trailer:       make(http.Header),
			}
			if _, err := readClientResponse(
				context.Background(),
				response,
				4,
				func() {},
			); !errors.Is(err, ErrResponseProtocol) {
				t.Fatalf("readClientResponse() error=%v", err)
			}
		})
	}
}

func TestSnapshotClientNormalizesStructuredServiceErrors(t *testing.T) {
	fixture := newContentTLSFixture(t)
	harness := startRealContentClientWithFixture(t, fixture)
	parts := newContentSnapshotParts(
		t,
		fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"artifact",
		[]byte("chunk"),
	)
	setContentSnapshotParts(harness.service, parts)
	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatal(err)
	}

	harness.service.mu.Lock()
	harness.service.snapshotPageErr = ErrSnapshotNotFound
	harness.service.mu.Unlock()
	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		fixture,
		parts.root,
	)
	_, err := bulk.SnapshotManifestPage(context.Background(), 0)
	var remote *RemoteError
	if !errors.Is(err, ErrSnapshotNotFound) ||
		!errors.As(err, &remote) ||
		remote.Code != problemSnapshotNotFound.code ||
		!remote.Retryable {
		t.Fatalf("not-found error=%v remote=%+v", err, remote)
	}

	harness.service.mu.Lock()
	harness.service.snapshotChunkErr = ErrSnapshotUnavailable
	harness.service.mu.Unlock()
	_, err = bulk.SnapshotChunk(
		context.Background(),
		0,
	)
	remote = nil
	if !errors.Is(err, ErrSnapshotUnavailable) ||
		!errors.As(err, &remote) ||
		remote.Code != problemSnapshotUnavailable.code ||
		!remote.Retryable {
		t.Fatalf("unavailable error=%v remote=%+v", err, remote)
	}
}

func TestSnapshotClientRejectsInvalidRootAndIndexesLocally(t *testing.T) {
	fixture := newContentTLSFixture(t)
	harness := startRealContentClientWithFixture(t, fixture)
	parts := newContentSnapshotParts(
		t,
		fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"artifact",
		[]byte("chunk"),
	)
	setContentSnapshotParts(harness.service, parts)
	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := harness.client.SnapshotManifestPage(
		context.Background(),
		logicalsnapshot.Root{},
		0,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("zero root error=%v", err)
	}
	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		fixture,
		parts.root,
	)
	if _, err := bulk.SnapshotManifestPage(
		context.Background(),
		1,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("out-of-range page error=%v", err)
	}
	if _, err := bulk.SnapshotChunk(
		context.Background(),
		1,
	); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("out-of-range chunk error=%v", err)
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.snapshotOpenCalls != 0 ||
		harness.service.snapshotPageCalls != 0 ||
		harness.service.snapshotChunkCalls != 0 {
		t.Fatal("locally invalid snapshot request reached service")
	}
}

func TestSnapshotTargetAndChunkBounds(t *testing.T) {
	for _, test := range []struct {
		path  string
		kind  snapshotTargetKind
		id    string
		index uint64
	}{
		{path: SnapshotLatestPath, kind: snapshotTargetLatest},
		{
			path: "/v1/snapshots/a.b_c:d-1/manifest-pages/0",
			kind: snapshotTargetManifestPage, id: "a.b_c:d-1",
		},
		{
			path: "/v1/snapshots/artifact/chunks/42",
			kind: snapshotTargetChunk, id: "artifact", index: 42,
		},
	} {
		target, valid := parseSnapshotTarget(test.path)
		if !valid ||
			target.kind != test.kind ||
			target.artifactID != test.id ||
			target.index != test.index {
			t.Fatalf("parseSnapshotTarget(%q)=(%+v,%t)", test.path, target, valid)
		}
	}
	for _, value := range []string{"", ".", "..", "a/b", "a%2Fb", strings.Repeat("a", 129)} {
		if validSnapshotArtifactID(value) {
			t.Fatalf("invalid artifact ID accepted: %q", value)
		}
	}

	scope := SnapshotRequestScope{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ArtifactID:         "artifact",
	}
	source := []byte("chunk")
	chunk, err := NewSnapshotChunk(scope, 0, source)
	if err != nil {
		t.Fatal(err)
	}
	source[0] = 'X'
	first := chunk.Bytes()
	first[0] = 'Y'
	if string(chunk.Bytes()) != "chunk" || chunk.Len() != len("chunk") {
		t.Fatal("SnapshotChunk did not retain an immutable copy")
	}
	if _, err := NewSnapshotChunk(
		scope,
		0,
		make([]byte, logicalsnapshot.MaxChunkCompressedBytes+1),
	); !errors.Is(err, ErrInvalidSnapshotChunk) {
		t.Fatalf("oversized chunk error=%v", err)
	}
}

func newContentSnapshotParts(
	t testing.TB,
	privateKey ed25519.PrivateKey,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	artifactID string,
	content []byte,
) contentSnapshotParts {
	t.Helper()
	signerDeviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest := chain.Digest(sha256.Sum256(content))
	page, err := logicalsnapshot.NewDescriptorPage(
		logicalsnapshot.DescriptorPageInput{
			ArtifactID: artifactID,
			PageIndex:  0,
			Descriptors: []logicalsnapshot.ChunkDescriptor{{
				ChunkIndex:       0,
				CompressedLength: uint64(len(content)),
				ExpandedLength:   uint64(len(content)),
				SHA256:           contentDigest,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := logicalsnapshot.NewUnsignedRoot(
		logicalsnapshot.RootInput{
			ArtifactID:              artifactID,
			SessionID:               sessionID,
			WorkspaceID:             workspaceID,
			RecoveryGeneration:      recoveryGeneration,
			CheckpointEventID:       "01890f47-3e72-7000-8000-0000000007aa",
			ChainIndex:              1,
			ChainHash:               snapshotTestDigest("chain"),
			ResultIndex:             1,
			ResultHash:              snapshotTestDigest("result"),
			ProjectionAccumulator:   snapshotTestDigest("accumulator"),
			ProjectionStateDigest:   snapshotTestDigest("state"),
			AuthorityVersion:        1,
			SignerDeviceID:          signerDeviceID,
			DigestVersion:           logicalsnapshot.SupportedDigestVersion,
			ProjectionSchemaVersion: logicalsnapshot.SupportedProjectionSchemaVersion,
			ContentEncoding:         logicalsnapshot.EncodingIdentity,
			ExpandedBytes:           uint64(len(content)),
			CompressedBytes:         uint64(len(content)),
			RecordCount:             1,
			DescriptorPageCount:     1,
			ChunkCount:              1,
			ArtifactDigest:          contentDigest,
			FinalDescriptorPageHash: page.Hash(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := logicalsnapshot.SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := NewSnapshotRequestScope(root)
	if err != nil {
		t.Fatal(err)
	}
	manifestPage, err := NewSnapshotManifestPage(scope, page)
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := NewSnapshotChunk(scope, 0, content)
	if err != nil {
		t.Fatal(err)
	}
	return contentSnapshotParts{
		root:         root,
		page:         page,
		manifestPage: manifestPage,
		chunk:        chunk,
		scope:        scope,
	}
}

func setContentSnapshotParts(
	service *contentTestService,
	parts contentSnapshotParts,
) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.snapshotRoot = parts.root
	service.snapshotRootErr = nil
	service.snapshotOpenErr = nil
	service.snapshotPage = parts.manifestPage
	service.snapshotPageErr = nil
	service.snapshotChunk = parts.chunk
	service.snapshotChunkErr = nil
}

func snapshotTestDigest(label string) chain.Digest {
	return chain.Digest(sha256.Sum256([]byte("contenthttp snapshot " + label)))
}

func snapshotRootWithArtifact(
	t testing.TB,
	privateKey ed25519.PrivateKey,
	parts contentSnapshotParts,
	artifactID string,
) logicalsnapshot.Root {
	t.Helper()
	pageInput := parts.page.Input()
	pageInput.ArtifactID = artifactID
	page, err := logicalsnapshot.NewDescriptorPage(pageInput)
	if err != nil {
		t.Fatal(err)
	}
	rootInput := parts.root.Unsigned().Input()
	rootInput.ArtifactID = artifactID
	rootInput.FinalDescriptorPageHash = page.Hash()
	unsigned, err := logicalsnapshot.NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatal(err)
	}
	root, err := logicalsnapshot.SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func snapshotScriptedHandler(
	sessionBody []byte,
	rootBody []byte,
	pageBody []byte,
	chunkBody []byte,
	pageMediaType string,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch {
		case request.URL.Path == SessionPath:
			writeScriptedResponse(
				writer,
				http.StatusOK,
				contentJSONMediaType,
				sessionBody,
				nil,
			)
		case request.URL.Path == SnapshotLatestPath:
			writeScriptedResponse(
				writer,
				http.StatusOK,
				contentJSONMediaType,
				rootBody,
				nil,
			)
		case strings.Contains(request.URL.Path, "/manifest-pages/"):
			writeScriptedResponse(
				writer,
				http.StatusOK,
				pageMediaType,
				pageBody,
				nil,
			)
		case strings.Contains(request.URL.Path, "/chunks/"):
			writeScriptedResponse(
				writer,
				http.StatusOK,
				snapshotChunkMediaType,
				chunkBody,
				nil,
			)
		default:
			http.NotFound(writer, request)
		}
	})
}

func slicesEqualStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func slicesEqualUint64(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestSnapshotResponseEnvelopeUsesEndpointMediaAndBounds(t *testing.T) {
	for _, test := range []struct {
		name      string
		mediaType string
		limit     int64
		length    int64
		want      error
	}{
		{
			name:      "root",
			mediaType: contentJSONMediaType,
			limit:     int64(logicalsnapshot.MaxRootBytes),
			length:    int64(logicalsnapshot.MaxRootBytes),
		},
		{
			name:      "chunk",
			mediaType: snapshotChunkMediaType,
			limit:     int64(logicalsnapshot.MaxChunkCompressedBytes),
			length:    int64(logicalsnapshot.MaxChunkCompressedBytes),
		},
		{
			name:      "wrong chunk media",
			mediaType: contentJSONMediaType,
			limit:     int64(logicalsnapshot.MaxChunkCompressedBytes),
			length:    1,
			want:      ErrResponseProtocol,
		},
		{
			name:      "over limit",
			mediaType: snapshotChunkMediaType,
			limit:     int64(logicalsnapshot.MaxChunkCompressedBytes),
			length:    int64(logicalsnapshot.MaxChunkCompressedBytes) + 1,
			want:      ErrResponseTooLarge,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			responseMedia := test.mediaType
			expectedMedia := test.mediaType
			if test.name == "wrong chunk media" {
				expectedMedia = snapshotChunkMediaType
			}
			response := &http.Response{
				StatusCode:    http.StatusOK,
				Body:          io.NopCloser(strings.NewReader("x")),
				ContentLength: test.length,
				Header: http.Header{
					"Content-Type": {responseMedia},
					"Content-Length": {
						strconv.FormatInt(test.length, 10),
					},
				},
			}
			limit, problem, err := validateResponseEnvelopeForMediaType(
				response,
				test.limit,
				expectedMedia,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("validate response error=%v, want %v", err, test.want)
			}
			if test.want == nil && (problem || limit != test.limit) {
				t.Fatalf("validate response=(%d,%t)", limit, problem)
			}
		})
	}
}
