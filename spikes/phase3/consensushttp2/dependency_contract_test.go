package consensushttp2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const (
	probeChildEnvironment = "CODECOMM_HTTP2_PROBE_CHILD"
	probeProtocol         = "codecomm-raft"
	probePath             = "/v1/consensus/raft"
	probeTimeout          = 10 * time.Second
)

func TestExtendedConnectDependencyContract(t *testing.T) {
	switch mode := os.Getenv(probeChildEnvironment); mode {
	case "disabled":
		proveExtendedConnectDisabled(t)
		return
	case "enabled":
		proveExtendedConnectEnabled(t)
		return
	case "":
	default:
		t.Fatalf("unknown child mode %q", mode)
	}

	runDependencyProbe(t, "disabled", false)
	runDependencyProbe(t, "enabled", true)
}

func runDependencyProbe(t *testing.T, mode string, enabled bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestExtendedConnectDependencyContract$",
		"-test.count=1",
	)
	command.Env = probeEnvironment(os.Environ(), mode, enabled)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s dependency probe timed out: %v", mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf(
			"%s dependency probe failed: %v\n%s",
			mode,
			err,
			output,
		)
	}
}

func probeEnvironment(base []string, mode string, enabled bool) []string {
	result := make([]string, 0, len(base)+2)
	var godebug []string
	for _, entry := range base {
		switch {
		case strings.HasPrefix(entry, probeChildEnvironment+"="):
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
	result = append(
		result,
		"GODEBUG="+strings.Join(godebug, ","),
		probeChildEnvironment+"="+mode,
	)
	return result
}

func proveExtendedConnectDisabled(t *testing.T) {
	var handlerCalls atomic.Uint64
	probe := newProbeConnection(t, http.HandlerFunc(func(
		http.ResponseWriter,
		*http.Request,
	) {
		handlerCalls.Add(1)
	}))

	request, err := newProbeRequest(
		context.Background(),
		http.NoBody,
		"disabled",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.client.RoundTrip(request)
	if err == nil ||
		!strings.Contains(err.Error(), "extended connect not supported") {
		t.Fatalf(
			"RoundTrip() without startup opt-in error = %v, want unsupported",
			err,
		)
	}
	if calls := handlerCalls.Load(); calls != 0 {
		t.Fatalf("disabled extended CONNECT reached handler %d times", calls)
	}
	assertFirstSettingsExtendedConnect(t, probe.serverWrites(), false)
}

func proveExtendedConnectEnabled(t *testing.T) {
	handlerErrors := make(chan error, 8)
	halfClosed := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	siblingDone := make(chan struct{}, 1)
	probe := newProbeConnection(t, http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if err := validateProbeRequest(request); err != nil {
			handlerErrors <- err
			http.Error(writer, "invalid probe", http.StatusBadRequest)
			return
		}
		controller := http.NewResponseController(writer)
		if err := controller.EnableFullDuplex(); err != nil {
			handlerErrors <- fmt.Errorf("enable full duplex: %w", err)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			handlerErrors <- fmt.Errorf("flush response headers: %w", err)
			return
		}

		switch request.Header.Get("X-Probe-Case") {
		case "duplex":
			runDuplexHandler(
				writer,
				controller,
				request,
				halfClosed,
				handlerErrors,
			)
		case "cancel":
			<-request.Context().Done()
			select {
			case canceled <- struct{}{}:
			default:
			}
		case "sibling":
			runSiblingHandler(
				writer,
				controller,
				request,
				siblingDone,
				handlerErrors,
			)
		default:
			handlerErrors <- errors.New("unknown probe case")
		}
	}))

	proveFullDuplexAndHalfClose(t, probe.client, halfClosed)
	proveCancellationPreservesSibling(
		t,
		probe.client,
		canceled,
		siblingDone,
	)
	assertNoHandlerErrors(t, handlerErrors)
	assertFirstSettingsExtendedConnect(t, probe.serverWrites(), true)
}

func runDuplexHandler(
	writer http.ResponseWriter,
	controller *http.ResponseController,
	request *http.Request,
	halfClosed chan<- struct{},
	handlerErrors chan<- error,
) {
	if _, err := writer.Write([]byte("ready")); err != nil {
		handlerErrors <- fmt.Errorf("write ready: %w", err)
		return
	}
	if err := controller.Flush(); err != nil {
		handlerErrors <- fmt.Errorf("flush ready: %w", err)
		return
	}
	payload := make([]byte, len("ping"))
	if _, err := io.ReadFull(request.Body, payload); err != nil {
		handlerErrors <- fmt.Errorf("read request payload: %w", err)
		return
	}
	if _, err := writer.Write(append([]byte("echo:"), payload...)); err != nil {
		handlerErrors <- fmt.Errorf("write echo: %w", err)
		return
	}
	if err := controller.Flush(); err != nil {
		handlerErrors <- fmt.Errorf("flush echo: %w", err)
		return
	}
	trailing, err := io.ReadAll(request.Body)
	if err != nil || len(trailing) != 0 {
		handlerErrors <- fmt.Errorf(
			"read request half-close: trailing=%q err=%v",
			trailing,
			err,
		)
		return
	}
	select {
	case halfClosed <- struct{}{}:
	default:
	}
	if _, err := writer.Write([]byte("after-eof")); err != nil {
		handlerErrors <- fmt.Errorf("write after request EOF: %w", err)
	}
}

func runSiblingHandler(
	writer http.ResponseWriter,
	controller *http.ResponseController,
	request *http.Request,
	done chan<- struct{},
	handlerErrors chan<- error,
) {
	defer func() {
		select {
		case done <- struct{}{}:
		default:
		}
	}()
	payload := make([]byte, len("alive"))
	if _, err := io.ReadFull(request.Body, payload); err != nil {
		handlerErrors <- fmt.Errorf("read sibling payload: %w", err)
		return
	}
	if _, err := writer.Write(append([]byte("echo:"), payload...)); err != nil {
		handlerErrors <- fmt.Errorf("write sibling echo: %w", err)
		return
	}
	if err := controller.Flush(); err != nil {
		handlerErrors <- fmt.Errorf("flush sibling echo: %w", err)
		return
	}
	_, _ = io.Copy(io.Discard, request.Body)
}

func proveFullDuplexAndHalfClose(
	t *testing.T,
	client *http2.ClientConn,
	halfClosed <-chan struct{},
) {
	t.Helper()
	requestReader, requestWriter := io.Pipe()
	request, err := newProbeRequest(
		testContext(t),
		requestReader,
		"duplex",
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.RoundTrip(request)
	if err != nil {
		t.Fatalf("RoundTrip(duplex): %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("duplex response status = %s", response.Status)
	}
	assertReadExactly(t, response.Body, "ready")
	if _, err := requestWriter.Write([]byte("ping")); err != nil {
		t.Fatalf("write duplex request: %v", err)
	}
	assertReadExactly(t, response.Body, "echo:ping")
	if err := requestWriter.Close(); err != nil {
		t.Fatalf("half-close duplex request: %v", err)
	}
	awaitSignal(t, halfClosed, "server request EOF")
	assertReadExactly(t, response.Body, "after-eof")
	buffer := make([]byte, 1)
	if count, err := response.Body.Read(buffer); count != 0 ||
		!errors.Is(err, io.EOF) {
		t.Fatalf(
			"duplex response tail = (%d, %v), want (0, EOF)",
			count,
			err,
		)
	}
}

func proveCancellationPreservesSibling(
	t *testing.T,
	client *http2.ClientConn,
	canceled <-chan struct{},
	siblingDone <-chan struct{},
) {
	t.Helper()
	cancelContext, cancelRequest := context.WithCancel(testContext(t))
	cancelReader, cancelWriter := io.Pipe()
	cancelProbe, err := newProbeRequest(
		cancelContext,
		cancelReader,
		"cancel",
	)
	if err != nil {
		t.Fatal(err)
	}
	cancelResponse, err := client.RoundTrip(cancelProbe)
	if err != nil {
		t.Fatalf("RoundTrip(cancel): %v", err)
	}
	defer cancelResponse.Body.Close()

	siblingReader, siblingWriter := io.Pipe()
	siblingProbe, err := newProbeRequest(
		testContext(t),
		siblingReader,
		"sibling",
	)
	if err != nil {
		t.Fatal(err)
	}
	siblingResponse, err := client.RoundTrip(siblingProbe)
	if err != nil {
		t.Fatalf("RoundTrip(sibling): %v", err)
	}
	defer siblingResponse.Body.Close()

	cancelRequest()
	_ = cancelWriter.CloseWithError(context.Canceled)
	awaitSignal(t, canceled, "canceled stream handler")

	if _, err := siblingWriter.Write([]byte("alive")); err != nil {
		t.Fatalf("write sibling after cancellation: %v", err)
	}
	assertReadExactly(t, siblingResponse.Body, "echo:alive")
	if err := siblingWriter.Close(); err != nil {
		t.Fatalf("half-close sibling request: %v", err)
	}
	awaitSignal(t, siblingDone, "sibling stream completion")
	buffer := make([]byte, 1)
	if count, err := siblingResponse.Body.Read(buffer); count != 0 ||
		!errors.Is(err, io.EOF) {
		t.Fatalf(
			"sibling response tail = (%d, %v), want (0, EOF)",
			count,
			err,
		)
	}
}

func newProbeRequest(
	ctx context.Context,
	body io.Reader,
	probeCase string,
) (*http.Request, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodConnect,
		"https://peer.invalid"+probePath,
		body,
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set(":protocol", probeProtocol)
	request.Header.Set("X-Probe-Case", probeCase)
	return request, nil
}

func validateProbeRequest(request *http.Request) error {
	if request == nil ||
		request.Method != http.MethodConnect ||
		request.URL == nil ||
		request.URL.Path != probePath ||
		request.URL.RawQuery != "" ||
		request.Header.Get(":protocol") != probeProtocol {
		return errors.New("extended CONNECT pseudoheaders changed")
	}
	return nil
}

type probeConnection struct {
	client   *http2.ClientConn
	recorder *recordingConn
}

func newProbeConnection(
	t *testing.T,
	handler http.Handler,
) *probeConnection {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	recorder := &recordingConn{Conn: serverConnection}
	serverDone := make(chan struct{})
	server := &http2.Server{
		MaxConcurrentStreams: 32,
		MaxReadFrameSize:     16 << 10,
	}
	go func() {
		defer close(serverDone)
		server.ServeConn(recorder, &http2.ServeConnOpts{
			Context: context.Background(),
			Handler: handler,
		})
	}()
	transport := &http2.Transport{AllowHTTP: true}
	client, err := transport.NewClientConn(clientConnection)
	if err != nil {
		_ = clientConnection.Close()
		<-serverDone
		t.Fatalf("NewClientConn(): %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = clientConnection.Close()
		select {
		case <-serverDone:
		case <-time.After(probeTimeout):
			t.Error("HTTP/2 probe server did not stop")
		}
	})
	return &probeConnection{client: client, recorder: recorder}
}

func (probe *probeConnection) serverWrites() []byte {
	if probe == nil || probe.recorder == nil {
		return nil
	}
	return probe.recorder.snapshot()
}

type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes bytes.Buffer
}

func (connection *recordingConn) Write(payload []byte) (int, error) {
	count, err := connection.Conn.Write(payload)
	connection.mu.Lock()
	_, _ = connection.writes.Write(payload[:count])
	connection.mu.Unlock()
	return count, err
}

func (connection *recordingConn) snapshot() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return bytes.Clone(connection.writes.Bytes())
}

func assertFirstSettingsExtendedConnect(
	t *testing.T,
	serverBytes []byte,
	want bool,
) {
	t.Helper()
	framer := http2.NewFramer(io.Discard, bytes.NewReader(serverBytes))
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatalf("read first server frame: %v", err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok || settings.IsAck() {
		t.Fatalf("first server frame = %T, want non-ACK SETTINGS", frame)
	}
	var (
		found bool
		value uint32
	)
	if err := settings.ForeachSetting(func(setting http2.Setting) error {
		if setting.ID == http2.SettingEnableConnectProtocol {
			found = true
			value = setting.Val
		}
		return nil
	}); err != nil {
		t.Fatalf("read first server SETTINGS: %v", err)
	}
	if found != want || found && value != 1 {
		t.Fatalf(
			"first SETTINGS extended CONNECT = (found=%t value=%d), want %t",
			found,
			value,
			want,
		)
	}
}

func assertReadExactly(t *testing.T, reader io.Reader, want string) {
	t.Helper()
	buffer := make([]byte, len(want))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(buffer) != want {
		t.Fatalf("read payload = %q, want %q", buffer, want)
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(probeTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func assertNoHandlerErrors(t *testing.T, handlerErrors <-chan error) {
	t.Helper()
	select {
	case err := <-handlerErrors:
		t.Fatalf("HTTP/2 probe handler: %v", err)
	default:
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	t.Cleanup(cancel)
	return ctx
}
