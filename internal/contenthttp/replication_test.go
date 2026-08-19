package contenthttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/replication"
)

func TestReplicationRoundTripUsesExpandedBatchBound(t *testing.T) {
	fixture := newContentTLSFixture(t)
	harness := startRealContentClientWithFixture(t, fixture)
	batch := contentReplicationBatch(
		t,
		fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		ResponseMaxBytes+1024,
		nil,
	)
	if len(batch.CanonicalBytes()) <= ResponseMaxBytes {
		t.Fatal("test batch does not exceed the generic response bound")
	}
	harness.service.mu.Lock()
	harness.service.batch = batch
	harness.service.mu.Unlock()

	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	got, err := harness.client.Replication(context.Background(), 0)
	if err != nil {
		t.Fatalf("Replication() error = %v", err)
	}
	if !bytes.Equal(got.CanonicalBytes(), batch.CanonicalBytes()) {
		t.Fatal("Replication() changed the canonical batch bytes")
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.batchCalls != 1 ||
		len(harness.service.batchAfter) != 1 ||
		harness.service.batchAfter[0] != 0 {
		t.Fatalf(
			"Replication service calls = %d, cursors = %v",
			harness.service.batchCalls,
			harness.service.batchAfter,
		)
	}
}

func TestClientReplicationDefersRelayedSignerTrustToScratchReplay(
	t *testing.T,
) {
	fixture := newContentTLSFixture(t)
	relayIdentity := contentPrivateKey(0x96)
	defer clear(relayIdentity)
	harness := startRealContentClientWithFixture(t, fixture)
	valid := contentReplicationBatch(
		t,
		relayIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		0,
		nil,
	)
	signature := valid.Signature()
	signature[0] ^= 0xff
	batch, err := replication.NewBatch(valid.Unsigned(), signature)
	if err != nil {
		t.Fatal(err)
	}
	harness.service.mu.Lock()
	harness.service.batch = batch
	harness.service.mu.Unlock()

	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	got, err := harness.client.Replication(context.Background(), 0)
	if err != nil {
		t.Fatalf("Replication(relayed) error = %v", err)
	}
	metadata := got.Unsigned().Metadata()
	if metadata.ServerDeviceID == fixture.serverDevice ||
		!bytes.Equal(got.CanonicalBytes(), batch.CanonicalBytes()) {
		t.Fatalf(
			"relayed signer/batch = %s, match=%t",
			metadata.ServerDeviceID,
			bytes.Equal(got.CanonicalBytes(), batch.CanonicalBytes()),
		)
	}
}

func TestClientReplicationRequiresSessionCall(t *testing.T) {
	fixture := newContentTLSFixture(t)
	harness := startRealContentClientWithFixture(t, fixture)
	harness.service.mu.Lock()
	harness.service.batch = contentReplicationBatch(
		t,
		fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		0,
		nil,
	)
	harness.service.mu.Unlock()

	if _, err := harness.client.Replication(
		context.Background(),
		0,
	); !errors.Is(err, ErrLineageMismatch) {
		t.Fatalf(
			"Replication(before Session) error = %v, want %v",
			err,
			ErrLineageMismatch,
		)
	}
	if _, err := harness.client.Peers(context.Background()); err != nil {
		t.Fatalf("Peers() error = %v", err)
	}
	if _, err := harness.client.Replication(
		context.Background(),
		0,
	); !errors.Is(err, ErrLineageMismatch) {
		t.Fatalf(
			"Replication(after Peers only) error = %v, want %v",
			err,
			ErrLineageMismatch,
		)
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.batchCalls != 0 {
		t.Fatalf(
			"unbound Replication reached service %d times",
			harness.service.batchCalls,
		)
	}
}

func TestServerReplicationRejectsNoncanonicalCursorGrammar(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	tests := []string{
		ReplicationPath,
		ReplicationPath + "?",
		ReplicationPath + "?after_result=",
		ReplicationPath + "?after_result=00",
		ReplicationPath + "?after_result=01",
		ReplicationPath + "?after_result=+1",
		ReplicationPath + "?after_result=-1",
		ReplicationPath + "?after_result=%31",
		ReplicationPath + "?after_result=1&after_result=1",
		ReplicationPath + "?after_result=1&extra=2",
		ReplicationPath + "?extra=2&after_result=1",
		ReplicationPath + "?after_result=9007199254740992",
		ReplicationPath + "?after_result=18446744073709551616",
	}
	for _, target := range tests {
		target := target
		t.Run(target, func(t *testing.T) {
			response := harness.request(
				t,
				http.MethodGet,
				target,
				nil,
			)
			body := assertContentResponse(
				t,
				response,
				http.StatusBadRequest,
				contentProblemMediaType,
			)
			var problem problemResponse
			if err := json.Unmarshal(body, &problem); err != nil ||
				problem.Code != "invalid_replication_cursor" ||
				problem.Retryable {
				t.Fatalf(
					"cursor problem = %+v, error = %v",
					problem,
					err,
				)
			}
		})
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.batchCalls != 0 {
		t.Fatalf(
			"invalid cursors reached service %d times",
			harness.service.batchCalls,
		)
	}
}

func TestReplicationCursorRejectsAmbiguousURLMetadata(t *testing.T) {
	valid := &http.Request{URL: &url.URL{
		Path: ReplicationPath,
		RawQuery: "after_result=" + strconv.FormatUint(
			domain.MaxSafeInteger,
			10,
		),
	}}
	if value, ok := replicationCursor(valid); !ok ||
		value != domain.MaxSafeInteger {
		t.Fatalf("replicationCursor(valid) = (%d, %t)", value, ok)
	}
	for index, request := range []*http.Request{
		nil,
		{},
		{URL: &url.URL{
			Path: SessionPath, RawQuery: "after_result=0",
		}},
		{URL: &url.URL{
			Path: ReplicationPath, RawPath: "/v1/%72eplication",
			RawQuery: "after_result=0",
		}},
		{URL: &url.URL{
			Path: ReplicationPath, RawQuery: "after_result=0",
			Fragment: "fragment",
		}},
		{URL: &url.URL{
			Path: ReplicationPath, RawQuery: "after_result=0",
			RawFragment: "fragment",
		}},
		{URL: &url.URL{
			Path: ReplicationPath, RawQuery: "after_result=0",
			ForceQuery: true,
		}},
		{URL: &url.URL{
			Path: ReplicationPath, RawQuery: "after_result=1%",
		}},
	} {
		if value, ok := replicationCursor(request); ok {
			t.Fatalf(
				"replicationCursor(ambiguous %d) = (%d, true)",
				index,
				value,
			)
		}
	}
}

func TestServerReplicationEnforcesMethodBodyAndNegotiation(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	harness.service.mu.Lock()
	harness.service.batch = contentReplicationBatch(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		0,
		nil,
	)
	harness.service.mu.Unlock()

	tests := []struct {
		name   string
		method string
		body   io.Reader
		header http.Header
		status int
	}{
		{
			name: "method", method: http.MethodPost,
			status: http.StatusMethodNotAllowed,
		},
		{
			name: "body", method: http.MethodGet,
			body: strings.NewReader("x"), status: http.StatusBadRequest,
		},
		{
			name: "content type", method: http.MethodGet,
			header: http.Header{"Content-Type": {contentJSONMediaType}},
			status: http.StatusBadRequest,
		},
		{
			name: "content encoding", method: http.MethodGet,
			header: http.Header{"Content-Encoding": {"identity"}},
			status: http.StatusBadRequest,
		},
		{
			name: "accept", method: http.MethodGet,
			header: http.Header{"Accept": {"*/*"}},
			status: http.StatusNotAcceptable,
		},
		{
			name: "accept encoding", method: http.MethodGet,
			header: http.Header{"Accept-Encoding": {"gzip"}},
			status: http.StatusNotAcceptable,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(
				test.method,
				"https://codecomm.invalid"+
					ReplicationPath+"?after_result=0",
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
				t.Fatalf(
					"status = %s, want %d, body=%s",
					response.Status,
					test.status,
					body,
				)
			}
			if test.name == "method" &&
				response.Header.Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q", response.Header.Get("Allow"))
			}
		})
	}
}

func TestServerReplicationEnforcesDedicatedCapacity(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	harness.service.mu.Lock()
	harness.service.batch = contentReplicationBatch(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		0,
		nil,
	)
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
			http.MethodGet,
			"https://codecomm.invalid"+
				ReplicationPath+"?after_result=0",
			nil,
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
		t.Fatal("first replication handler did not enter service")
	}

	response := harness.request(
		t,
		http.MethodGet,
		ReplicationPath+"?after_result=0",
		nil,
	)
	body := assertContentResponse(
		t,
		response,
		http.StatusServiceUnavailable,
		contentProblemMediaType,
	)
	if !bytes.Contains(
		body,
		[]byte(`"code":"replication_unavailable"`),
	) || response.Header.Get("Retry-After") != "1" {
		t.Fatalf("capacity response = %s, headers=%v", body, response.Header)
	}

	close(release)
	select {
	case first := <-firstDone:
		if first.err != nil {
			t.Fatal(first.err)
		}
		body := assertContentResponse(
			t,
			first.response,
			http.StatusOK,
			contentJSONMediaType,
		)
		if len(body) == 0 {
			t.Fatal("first replication response is empty")
		}
	case <-time.After(contentTestTimeout):
		t.Fatal("first replication handler did not complete")
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.batchCalls != 1 {
		t.Fatalf(
			"replication service calls = %d, want 1",
			harness.service.batchCalls,
		)
	}
}

func TestServerReplicationMapsServiceErrors(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{
			name: "invalid cursor", err: ErrInvalidReplicationCursor,
			status: http.StatusBadRequest,
			code:   "invalid_replication_cursor",
		},
		{
			name: "snapshot", err: ErrReplicationSnapshotRequired,
			status: http.StatusConflict,
			code:   "snapshot_required",
		},
		{
			name: "unavailable", err: ErrReplicationUnavailable,
			status: http.StatusServiceUnavailable,
			code:   "replication_unavailable", retryable: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness.service.mu.Lock()
			harness.service.batchErr = test.err
			harness.service.mu.Unlock()
			response := harness.request(
				t,
				http.MethodGet,
				ReplicationPath+"?after_result=0",
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
				problem.Type != "urn:codecomm:problem:"+test.code ||
				problem.Status != test.status ||
				problem.Code != test.code ||
				problem.Retryable != test.retryable {
				t.Fatalf(
					"problem = %+v, error = %v",
					problem,
					err,
				)
			}
		})
	}
}

func TestServerReplicationRejectsInvalidServiceBatch(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	tests := []struct {
		name   string
		after  uint64
		mutate func(*replication.BatchInput)
	}{
		{
			name: "cross session",
			mutate: func(input *replication.BatchInput) {
				input.SessionID = contentClientOtherSession
			},
		},
		{name: "wrong range", after: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			batch := contentReplicationBatch(
				t,
				harness.fixture.serverIdentity,
				testSessionID,
				testWorkspaceID,
				0,
				0,
				test.mutate,
			)
			harness.service.mu.Lock()
			harness.service.batch = batch
			harness.service.batchErr = nil
			harness.service.mu.Unlock()
			response := harness.request(
				t,
				http.MethodGet,
				ReplicationPath+"?after_result="+
					strconv.FormatUint(test.after, 10),
				nil,
			)
			body := assertContentResponse(
				t,
				response,
				http.StatusInternalServerError,
				contentProblemMediaType,
			)
			if !bytes.Contains(body, []byte(`"code":"internal_error"`)) {
				t.Fatalf("internal problem = %s", body)
			}
		})
	}
}

func TestClientReplicationRejectsLineageMismatch(
	t *testing.T,
) {
	tests := []struct {
		name  string
		batch func(testing.TB, contentTLSFixture) replication.Batch
		want  error
	}{
		{
			name: "session",
			batch: func(t testing.TB, fixture contentTLSFixture) replication.Batch {
				return contentReplicationBatch(
					t,
					fixture.serverIdentity,
					contentClientOtherSession,
					testWorkspaceID,
					0,
					0,
					nil,
				)
			},
			want: ErrLineageMismatch,
		},
		{
			name: "workspace",
			batch: func(t testing.TB, fixture contentTLSFixture) replication.Batch {
				return contentReplicationBatch(
					t,
					fixture.serverIdentity,
					testSessionID,
					contentClientOtherWorkspace,
					0,
					0,
					nil,
				)
			},
			want: ErrLineageMismatch,
		},
		{
			name: "generation",
			batch: func(t testing.TB, fixture contentTLSFixture) replication.Batch {
				return contentReplicationBatch(
					t,
					fixture.serverIdentity,
					testSessionID,
					testWorkspaceID,
					1,
					0,
					nil,
				)
			},
			want: ErrLineageMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newContentTLSFixture(t)
			service := newContentTestService(t, fixture.serverDevice)
			sessionBody, err := service.session.canonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			batchBody := test.batch(t, fixture).CanonicalBytes()
			handler := http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				switch request.URL.Path {
				case SessionPath:
					writeScriptedResponse(
						writer,
						http.StatusOK,
						contentJSONMediaType,
						sessionBody,
						nil,
					)
				case ReplicationPath:
					writeScriptedResponse(
						writer,
						http.StatusOK,
						contentJSONMediaType,
						batchBody,
						nil,
					)
				default:
					http.NotFound(writer, request)
				}
			})
			harness := mustOpenScriptedContentClient(t, fixture, handler)
			defer harness.stop(t)
			if _, err := harness.client.Session(
				context.Background(),
			); err != nil {
				t.Fatal(err)
			}
			_, err = harness.client.Replication(context.Background(), 0)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"Replication() error = %v, want %v",
					err,
					test.want,
				)
			}
			assertContentClientClosed(t, harness.client)
		})
	}
}

func TestClientReplicationRejectsMalformedEncodedAndOversizedResponses(
	t *testing.T,
) {
	tests := []struct {
		name   string
		body   []byte
		header http.Header
		also   error
	}{
		{
			name: "malformed batch",
			body: []byte(`{"invalid":true}`),
			also: replication.ErrInvalidBatch,
		},
		{
			name: "content encoding",
			body: []byte(`{"invalid":true}`),
			header: http.Header{
				"Content-Encoding": {"gzip"},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newContentTLSFixture(t)
			service := newContentTestService(t, fixture.serverDevice)
			sessionBody, err := service.session.canonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			handler := http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				switch request.URL.Path {
				case SessionPath:
					writeScriptedResponse(
						writer,
						http.StatusOK,
						contentJSONMediaType,
						sessionBody,
						nil,
					)
				case ReplicationPath:
					writeScriptedResponse(
						writer,
						http.StatusOK,
						contentJSONMediaType,
						test.body,
						test.header,
					)
				default:
					http.NotFound(writer, request)
				}
			})
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
			_, err = harness.client.Replication(
				context.Background(),
				0,
			)
			if !errors.Is(err, ErrResponseProtocol) ||
				test.also != nil && !errors.Is(err, test.also) {
				t.Fatalf(
					"Replication() error = %v, want %v and %v",
					err,
					ErrResponseProtocol,
					test.also,
				)
			}
		})
	}

	oversized := int64(replication.MaxBatchExpandedBytes) + 1
	response := &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(strings.NewReader("x")),
		ContentLength: oversized,
		Header: http.Header{
			"Content-Type":   {contentJSONMediaType},
			"Content-Length": {strconv.FormatInt(oversized, 10)},
		},
	}
	if _, _, err := validateResponseEnvelope(
		response,
		int64(replication.MaxBatchExpandedBytes),
	); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf(
			"validateResponseEnvelope(oversized) error = %v",
			err,
		)
	}
}

func contentReplicationBatch(
	t testing.TB,
	privateKey ed25519.PrivateKey,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	paddingBytes int,
	mutate func(*replication.BatchInput),
) replication.Batch {
	t.Helper()
	serverDeviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	var startResult chain.Digest
	endResult := startResult
	resultCount := 1
	if paddingBytes > 0 {
		const paddingPerResult = 512 << 10
		resultCount = (paddingBytes + paddingPerResult - 1) /
			paddingPerResult
	}
	results := make([][]byte, 0, resultCount)
	remaining := paddingBytes
	for index := range resultCount {
		proposal := []byte(
			`{"event_id":"01890f47-3e72-7000-8000-000000000751"}`,
		)
		if paddingBytes > 0 {
			chunk := min(remaining, 512<<10)
			proposal, err = json.Marshal(struct {
				Index   int    `json:"index"`
				Padding string `json:"padding"`
			}{
				Index:   index,
				Padding: strings.Repeat("x", chunk),
			})
			if err != nil {
				t.Fatal(err)
			}
			remaining -= chunk
		}
		result := chain.Result{
			ResultIndex:    uint64(index + 1),
			Proposal:       proposal,
			Outcome:        []byte(`{"code":"task_not_ready","status":"rejected"}`),
			ProposalDigest: chain.Digest(sha256.Sum256(proposal)),
		}
		var encodedResult []byte
		endResult, encodedResult, err = chain.AppendResult(
			endResult,
			result,
		)
		if err != nil {
			t.Fatalf("chain.AppendResult() error = %v", err)
		}
		results = append(results, encodedResult)
	}
	input := replication.BatchInput{
		FromResultIndex:          1,
		ToResultIndex:            uint64(resultCount),
		StartResultHash:          startResult,
		EndResultHash:            endResult,
		Results:                  results,
		SessionID:                sessionID,
		WorkspaceID:              workspaceID,
		RecoveryGeneration:       recoveryGeneration,
		ServerDeviceID:           serverDeviceID,
		ServerAppliedResultIndex: uint64(resultCount),
		ServerAuthorityVersion:   1,
	}
	if mutate != nil {
		mutate(&input)
	}
	unsigned, err := replication.NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("replication.NewUnsignedBatch() error = %v", err)
	}
	batch, err := replication.SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("replication.SignBatch() error = %v", err)
	}
	return batch
}
