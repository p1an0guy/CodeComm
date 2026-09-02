package contenthttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEventWatermarkCanonicalRoundTrip(t *testing.T) {
	watermark, err := NewEventWatermark(EventWatermarkInput{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 7,
		ServerDeviceID:     testPeerDeviceID,
		ResultIndex:        45,
		ChainIndex:         42,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := watermark.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"chain_index":42,"recovery_generation":7,` +
		`"result_index":45,"schema_version":1,` +
		`"server_device_id":"cc12222222222222222222222222222222222222222222222222222222222222222",` +
		`"session_id":"01890f47-3e72-7000-8000-000000000701",` +
		`"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(encoded) != want {
		t.Fatalf("canonical watermark = %s", encoded)
	}
	decoded, err := decodeEventWatermark(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !sameEventWatermarkLineage(watermark, decoded) ||
		decoded.ResultIndex() != 45 ||
		decoded.ChainIndex() != 42 {
		t.Fatalf("decoded watermark = %+v", decoded)
	}
}

func TestServerEventStreamSendsCurrentCoalescedCutAndKeepalive(
	t *testing.T,
) {
	harness := startContentHarness(
		t,
		ActiveHandlersMax,
		func(server *Server) {
			server.eventStreamKeepalive = 20 * time.Millisecond
		},
	)
	request, err := http.NewRequest(
		http.MethodGet,
		"https://codecomm.invalid"+EventsStreamPath,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", eventStreamMediaType)
	request.Header.Set("Accept-Encoding", "identity")
	response, err := harness.client.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err := validateEventStreamResponse(response); err != nil {
		t.Fatalf("stream response: %v headers=%v", err, response.Header)
	}
	reader := bufio.NewReaderSize(response.Body, eventStreamMaxLine)
	initialBytes, err := readEventStreamFrame(reader, func() {})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := decodeEventWatermark(initialBytes)
	if err != nil {
		t.Fatal(err)
	}
	if initial.ResultIndex() != 0 || initial.ChainIndex() != 0 {
		t.Fatalf("initial watermark = %+v", initial)
	}

	first, err := NewEventWatermark(EventWatermarkInput{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ServerDeviceID:     harness.fixture.serverDevice,
		ResultIndex:        1,
		ChainIndex:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	latest, err := NewEventWatermark(EventWatermarkInput{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ServerDeviceID:     harness.fixture.serverDevice,
		ResultIndex:        3,
		ChainIndex:         2,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.service.mu.Lock()
	harness.service.watermark = first
	harness.service.watermarkChanges <- struct{}{}
	harness.service.watermark = latest
	harness.service.mu.Unlock()

	changedBytes, err := readEventStreamFrame(reader, func() {})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := decodeEventWatermark(changedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if changed.ResultIndex() != 3 || changed.ChainIndex() != 2 {
		t.Fatalf("coalesced watermark = %+v", changed)
	}
	frame, err := readEventStreamFrame(reader, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if frame != nil {
		t.Fatalf("keepalive carried data %q", frame)
	}
}

func TestClientEventStreamMultiplexesReplicationAndCancelsCleanly(
	t *testing.T,
) {
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
	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatal(err)
	}

	streamContext, cancelStream := context.WithCancel(context.Background())
	received := make(chan EventWatermark, 1)
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- harness.client.WatchEventWatermarks(
			streamContext,
			func(watermark EventWatermark) error {
				select {
				case received <- watermark:
				default:
				}
				return nil
			},
		)
	}()
	select {
	case watermark := <-received:
		if watermark.ResultIndex() != 0 {
			t.Fatalf("initial result index = %d", watermark.ResultIndex())
		}
	case <-time.After(contentTestTimeout):
		t.Fatal("event stream did not deliver its initial watermark")
	}
	if _, err := harness.client.Replication(
		context.Background(),
		0,
	); err != nil {
		t.Fatalf("concurrent Replication(): %v", err)
	}
	cancelStream()
	select {
	case err := <-streamDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WatchEventWatermarks() error = %v", err)
		}
	case <-time.After(contentTestTimeout):
		t.Fatal("event stream ignored cancellation")
	}
	if _, err := harness.client.Peers(context.Background()); err != nil {
		t.Fatalf("Peers() after stream cancellation: %v", err)
	}
}

func TestClientEventStreamRejectsMalformedAndStalledStreams(t *testing.T) {
	tests := []struct {
		name       string
		streamBody string
		stall      bool
		want       error
	}{
		{
			name:       "unknown event",
			streamBody: "event: result\ndata: {}\n\n",
			want:       ErrResponseProtocol,
		},
		{
			name:       "noncanonical data",
			streamBody: "event: watermark\ndata: {\"schema_version\":1}\n\n",
			want:       ErrResponseProtocol,
		},
		{
			name:       "oversized line",
			streamBody: strings.Repeat("x", eventStreamMaxLine+1) + "\n",
			want:       ErrResponseTooLarge,
		},
		{
			name:  "no progress",
			stall: true,
			want:  ErrConnectionUnavailable,
		},
	}
	for _, test := range tests {
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
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set(
					"Content-Type",
					eventStreamMediaType,
				)
				writer.Header().Set(
					"X-Content-Type-Options",
					"nosniff",
				)
				writer.WriteHeader(http.StatusOK)
				_ = http.NewResponseController(writer).Flush()
				if test.stall {
					<-request.Context().Done()
					return
				}
				_, _ = io.WriteString(writer, test.streamBody)
				_ = http.NewResponseController(writer).Flush()
				<-request.Context().Done()
			})
			harness := mustOpenScriptedContentClient(t, fixture, handler)
			defer harness.stop(t)
			if _, err := harness.client.Session(
				context.Background(),
			); err != nil {
				t.Fatal(err)
			}
			err = harness.client.watchEventWatermarks(
				context.Background(),
				func(EventWatermark) error { return nil },
				30*time.Millisecond,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"watchEventWatermarks() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func TestClientEventStreamRequiresMonotonicWatermarks(t *testing.T) {
	tests := []struct {
		name         string
		streamBody   func(testing.TB, contentTLSFixture) string
		wantReceived int
	}{
		{
			name: "keepalive before initial watermark",
			streamBody: func(
				_ testing.TB,
				_ contentTLSFixture,
			) string {
				return eventStreamKeepalive
			},
		},
		{
			name: "duplicate cut",
			streamBody: func(
				t testing.TB,
				fixture contentTLSFixture,
			) string {
				first := eventStreamTestWatermark(
					fixture,
					5,
					4,
				)
				second := eventStreamTestWatermark(
					fixture,
					6,
					5,
				)
				return mustEventStreamFrame(t, first) +
					mustEventStreamFrame(t, second) +
					mustEventStreamFrame(t, second)
			},
			wantReceived: 2,
		},
		{
			name: "unchanged result cut",
			streamBody: func(
				t testing.TB,
				fixture contentTLSFixture,
			) string {
				first := eventStreamTestWatermark(
					fixture,
					5,
					4,
				)
				second := eventStreamTestWatermark(
					fixture,
					5,
					5,
				)
				return mustEventStreamFrame(t, first) +
					mustEventStreamFrame(t, second)
			},
			wantReceived: 1,
		},
		{
			name: "result regression",
			streamBody: func(
				t testing.TB,
				fixture contentTLSFixture,
			) string {
				first := eventStreamTestWatermark(
					fixture,
					5,
					4,
				)
				second := eventStreamTestWatermark(
					fixture,
					4,
					4,
				)
				return mustEventStreamFrame(t, first) +
					mustEventStreamFrame(t, second)
			},
			wantReceived: 1,
		},
		{
			name: "chain regression",
			streamBody: func(
				t testing.TB,
				fixture contentTLSFixture,
			) string {
				first := eventStreamTestWatermark(
					fixture,
					5,
					4,
				)
				second := eventStreamTestWatermark(
					fixture,
					6,
					3,
				)
				return mustEventStreamFrame(t, first) +
					mustEventStreamFrame(t, second)
			},
			wantReceived: 1,
		},
		{
			name: "lineage change",
			streamBody: func(
				t testing.TB,
				fixture contentTLSFixture,
			) string {
				first := eventStreamTestWatermark(
					fixture,
					5,
					4,
				)
				second := eventStreamTestWatermark(
					fixture,
					6,
					5,
				)
				second.WorkspaceID = contentClientOtherWorkspace
				return mustEventStreamFrame(t, first) +
					mustEventStreamFrame(t, second)
			},
			wantReceived: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newContentTLSFixture(t)
			service := newContentTestService(t, fixture.serverDevice)
			sessionBody, err := service.session.canonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			streamBody := test.streamBody(t, fixture)
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
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set(
					"Content-Type",
					eventStreamMediaType,
				)
				writer.Header().Set(
					"X-Content-Type-Options",
					"nosniff",
				)
				writer.WriteHeader(http.StatusOK)
				controller := http.NewResponseController(writer)
				_ = controller.Flush()
				_, _ = io.WriteString(writer, streamBody)
				_ = controller.Flush()
				<-request.Context().Done()
			})
			harness := mustOpenScriptedContentClient(t, fixture, handler)
			defer harness.stop(t)
			if _, err := harness.client.Session(
				context.Background(),
			); err != nil {
				t.Fatal(err)
			}
			received := make([]EventWatermark, 0, test.wantReceived)
			err = harness.client.watchEventWatermarks(
				context.Background(),
				func(watermark EventWatermark) error {
					received = append(received, watermark)
					return nil
				},
				time.Second,
			)
			if !errors.Is(err, ErrResponseProtocol) {
				t.Fatalf(
					"watchEventWatermarks() error = %v, want %v",
					err,
					ErrResponseProtocol,
				)
			}
			if len(received) != test.wantReceived {
				t.Fatalf(
					"received %d watermarks, want %d",
					len(received),
					test.wantReceived,
				)
			}
		})
	}
}

func TestEventStreamWritesUseScopedWriteDeadlines(t *testing.T) {
	writer := newEventStreamTestResponseWriter()
	controller := http.NewResponseController(writer)
	watermark, err := NewEventWatermark(
		eventStreamTestWatermark(
			contentTLSFixture{serverDevice: testPeerDeviceID},
			5,
			4,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err = writeEventWatermarkFrame(
		writer,
		controller,
		time.Second,
		watermark,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeEventWatermarkFrame(
		writer,
		controller,
		time.Second,
		watermark,
	); err != nil {
		t.Fatal(err)
	}
	if err := writeEventStreamPayload(
		writer,
		controller,
		time.Second,
		[]byte(eventStreamKeepalive),
	); err != nil {
		t.Fatal(err)
	}

	wantOperations := []string{
		"arm", "write", "flush", "clear",
		"arm", "write", "flush", "clear",
		"arm", "write", "flush", "clear",
	}
	if strings.Join(writer.operations, ",") !=
		strings.Join(wantOperations, ",") {
		t.Fatalf("write operations = %v, want %v", writer.operations, wantOperations)
	}
	if len(writer.deadlines) != 6 {
		t.Fatalf("deadline calls = %d, want 6", len(writer.deadlines))
	}
	for index, deadline := range writer.deadlines {
		if index%2 == 0 && deadline.IsZero() {
			t.Fatalf("deadline %d was not armed", index)
		}
		if index%2 == 1 && !deadline.IsZero() {
			t.Fatalf("deadline %d was not cleared: %v", index, deadline)
		}
	}
}

func TestEventStreamWriteDeadlineClearsAfterFailure(t *testing.T) {
	writeFailure := errors.New("write failure")
	flushFailure := errors.New("flush failure")
	clearFailure := errors.New("clear failure")
	tests := []struct {
		name           string
		configure      func(*eventStreamTestResponseWriter)
		want           error
		wantOperations string
	}{
		{
			name: "write",
			configure: func(writer *eventStreamTestResponseWriter) {
				writer.writeErr = writeFailure
			},
			want:           writeFailure,
			wantOperations: "arm,write,clear",
		},
		{
			name: "flush",
			configure: func(writer *eventStreamTestResponseWriter) {
				writer.flushErr = flushFailure
			},
			want:           flushFailure,
			wantOperations: "arm,write,flush,clear",
		},
		{
			name: "clear",
			configure: func(writer *eventStreamTestResponseWriter) {
				writer.clearErr = clearFailure
			},
			want:           clearFailure,
			wantOperations: "arm,write,flush,clear",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := newEventStreamTestResponseWriter()
			test.configure(writer)
			err := writeEventStreamPayload(
				writer,
				http.NewResponseController(writer),
				time.Second,
				[]byte("frame"),
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("writeEventStreamPayload() error = %v, want %v", err, test.want)
			}
			if operations := strings.Join(
				writer.operations,
				",",
			); operations != test.wantOperations {
				t.Fatalf(
					"write operations = %s, want %s",
					operations,
					test.wantOperations,
				)
			}
			if len(writer.deadlines) != 2 ||
				writer.deadlines[0].IsZero() ||
				!writer.deadlines[1].IsZero() {
				t.Fatalf("deadline calls = %v", writer.deadlines)
			}
		})
	}
}

func TestReadEventStreamFrameRejectsAmbiguousGrammar(t *testing.T) {
	for _, input := range []string{
		"event: watermark\r\ndata: {}\r\n\r\n",
		"event: watermark\ndata: {}\n",
		":keepalive\n\n",
		"event: watermark\ndata:\n\n",
		"event: watermark\ndata: {}\nextra: x\n\n",
	} {
		reader := bufio.NewReaderSize(
			bytes.NewBufferString(input),
			eventStreamMaxLine,
		)
		if _, err := readEventStreamFrame(
			reader,
			func() {},
		); err == nil {
			t.Fatalf("readEventStreamFrame(%q) succeeded", input)
		}
	}
}

func eventStreamTestWatermark(
	fixture contentTLSFixture,
	resultIndex uint64,
	chainIndex uint64,
) EventWatermarkInput {
	return EventWatermarkInput{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ServerDeviceID:     fixture.serverDevice,
		ResultIndex:        resultIndex,
		ChainIndex:         chainIndex,
	}
}

func mustEventStreamFrame(
	t testing.TB,
	input EventWatermarkInput,
) string {
	t.Helper()
	watermark, err := NewEventWatermark(input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := watermark.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return eventStreamEventPrefix + string(body) + "\n\n"
}

type eventStreamTestResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	operations []string
	deadlines  []time.Time
	writeErr   error
	flushErr   error
	clearErr   error
}

func newEventStreamTestResponseWriter() *eventStreamTestResponseWriter {
	return &eventStreamTestResponseWriter{header: make(http.Header)}
}

func (writer *eventStreamTestResponseWriter) Header() http.Header {
	return writer.header
}

func (*eventStreamTestResponseWriter) WriteHeader(int) {}

func (writer *eventStreamTestResponseWriter) Write(
	payload []byte,
) (int, error) {
	writer.operations = append(writer.operations, "write")
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	return writer.body.Write(payload)
}

func (writer *eventStreamTestResponseWriter) FlushError() error {
	writer.operations = append(writer.operations, "flush")
	return writer.flushErr
}

func (writer *eventStreamTestResponseWriter) SetWriteDeadline(
	deadline time.Time,
) error {
	writer.deadlines = append(writer.deadlines, deadline)
	if deadline.IsZero() {
		writer.operations = append(writer.operations, "clear")
		return writer.clearErr
	}
	writer.operations = append(writer.operations, "arm")
	return nil
}
