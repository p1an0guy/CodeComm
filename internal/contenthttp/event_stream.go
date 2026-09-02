package contenthttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	EventsStreamPath       = EventsPath + "/stream"
	eventStreamMediaType   = "text/event-stream"
	eventStreamName        = "watermark"
	eventStreamMaxLine     = 4 << 10
	eventStreamMaxData     = 2 << 10
	eventStreamKeepalive   = ": keepalive\n\n"
	eventStreamEventPrefix = "event: " + eventStreamName + "\ndata: "
)

var errEventStreamNoProgress = errors.New(
	"content HTTP: event stream made no progress",
)

// EventWatermark is an immutable, non-authoritative notification of the
// serving peer's latest durable result and accepted-event positions.
type EventWatermark struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	serverDeviceID     domain.DeviceID
	resultIndex        uint64
	chainIndex         uint64
	valid              bool
}

// EventWatermarkInput contains values copied into an EventWatermark.
type EventWatermarkInput struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	ServerDeviceID     domain.DeviceID
	ResultIndex        uint64
	ChainIndex         uint64
}

// NewEventWatermark validates and copies a durable notification cut.
func NewEventWatermark(input EventWatermarkInput) (EventWatermark, error) {
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!input.ServerDeviceID.Valid() ||
		!domain.ValidUnsignedInteger(input.ResultIndex) ||
		!domain.ValidUnsignedInteger(input.ChainIndex) ||
		input.ChainIndex > input.ResultIndex {
		return EventWatermark{}, ErrInvalidResponse
	}
	return EventWatermark{
		sessionID:          input.SessionID,
		workspaceID:        input.WorkspaceID,
		recoveryGeneration: input.RecoveryGeneration,
		serverDeviceID:     input.ServerDeviceID,
		resultIndex:        input.ResultIndex,
		chainIndex:         input.ChainIndex,
		valid:              true,
	}, nil
}

func (watermark EventWatermark) SessionID() domain.UUIDv7 {
	return watermark.sessionID
}

func (watermark EventWatermark) WorkspaceID() domain.UUIDv4 {
	return watermark.workspaceID
}

func (watermark EventWatermark) RecoveryGeneration() uint64 {
	return watermark.recoveryGeneration
}

func (watermark EventWatermark) ServerDeviceID() domain.DeviceID {
	return watermark.serverDeviceID
}

func (watermark EventWatermark) ResultIndex() uint64 {
	return watermark.resultIndex
}

func (watermark EventWatermark) ChainIndex() uint64 {
	return watermark.chainIndex
}

type eventWatermarkWire struct {
	ChainIndex         uint64 `json:"chain_index"`
	RecoveryGeneration uint64 `json:"recovery_generation"`
	ResultIndex        uint64 `json:"result_index"`
	SchemaVersion      uint64 `json:"schema_version"`
	ServerDeviceID     string `json:"server_device_id"`
	SessionID          string `json:"session_id"`
	WorkspaceID        string `json:"workspace_id"`
}

func (watermark EventWatermark) canonicalBytes() ([]byte, error) {
	if !watermark.valid {
		return nil, ErrInvalidResponse
	}
	return marshalCanonical(eventWatermarkWire{
		ChainIndex:         watermark.chainIndex,
		RecoveryGeneration: watermark.recoveryGeneration,
		ResultIndex:        watermark.resultIndex,
		SchemaVersion:      SchemaVersion,
		ServerDeviceID:     string(watermark.serverDeviceID),
		SessionID:          string(watermark.sessionID),
		WorkspaceID:        string(watermark.workspaceID),
	})
}

func decodeEventWatermark(input []byte) (EventWatermark, error) {
	if len(input) == 0 ||
		len(input) > eventStreamMaxData ||
		!canonicalResponse(input) {
		return EventWatermark{}, ErrResponseProtocol
	}
	var wire eventWatermarkWire
	if err := json.Unmarshal(input, &wire); err != nil ||
		wire.SchemaVersion != SchemaVersion {
		return EventWatermark{}, ErrResponseProtocol
	}
	watermark, err := NewEventWatermark(EventWatermarkInput{
		SessionID:          domain.UUIDv7(wire.SessionID),
		WorkspaceID:        domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration: wire.RecoveryGeneration,
		ServerDeviceID:     domain.DeviceID(wire.ServerDeviceID),
		ResultIndex:        wire.ResultIndex,
		ChainIndex:         wire.ChainIndex,
	})
	if err != nil {
		return EventWatermark{}, ErrResponseProtocol
	}
	canonical, err := watermark.canonicalBytes()
	if err != nil || !bytes.Equal(canonical, input) {
		return EventWatermark{}, ErrResponseProtocol
	}
	return watermark, nil
}

func (handler *connectionHandler) serveEventStream(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeProblem(writer, http.StatusMethodNotAllowed, problemMethod)
		return
	}
	if !validBodylessRequest(request) {
		writeProblem(writer, http.StatusBadRequest, problemRequestBody)
		return
	}
	if !validNegotiationFor(request.Header, eventStreamMediaType) {
		writeProblem(writer, http.StatusNotAcceptable, problemNegotiation)
		return
	}

	changes, err := handler.server.eventStreams.EventWatermarkChanges(
		request.Context(),
	)
	if err != nil || changes == nil {
		writeServiceProblem(writer, err)
		return
	}
	current, err := handler.server.eventStreams.EventWatermark(
		request.Context(),
	)
	if err != nil ||
		current.SessionID() != handler.peer.SessionID {
		writeServiceProblem(writer, err)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", eventStreamMediaType)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(writer)
	if err := writeEventWatermarkFrame(
		writer,
		controller,
		handler.server.streamNoProgress,
		current,
	); err != nil {
		return
	}

	keepalive := time.NewTicker(handler.server.eventStreamKeepalive)
	defer keepalive.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case _, open := <-changes:
			if !open {
				return
			}
			next, err := handler.server.eventStreams.EventWatermark(
				request.Context(),
			)
			if err != nil ||
				!sameEventWatermarkLineage(current, next) ||
				next.ResultIndex() < current.ResultIndex() ||
				next.ChainIndex() < current.ChainIndex() {
				return
			}
			if next.ResultIndex() == current.ResultIndex() &&
				next.ChainIndex() == current.ChainIndex() {
				continue
			}
			if err := writeEventWatermarkFrame(
				writer,
				controller,
				handler.server.streamNoProgress,
				next,
			); err != nil {
				return
			}
			current = next
		case <-keepalive.C:
			if err := writeEventStreamPayload(
				writer,
				controller,
				handler.server.streamNoProgress,
				[]byte(eventStreamKeepalive),
			); err != nil {
				return
			}
		}
	}
}

func writeEventWatermarkFrame(
	writer io.Writer,
	controller *http.ResponseController,
	noProgress time.Duration,
	watermark EventWatermark,
) error {
	body, err := watermark.canonicalBytes()
	if err != nil || len(body) > eventStreamMaxData {
		return ErrInvalidResponse
	}
	frame := make([]byte, 0, len(eventStreamEventPrefix)+len(body)+2)
	frame = append(frame, eventStreamEventPrefix...)
	frame = append(frame, body...)
	frame = append(frame, '\n', '\n')
	return writeEventStreamPayload(
		writer,
		controller,
		noProgress,
		frame,
	)
}

func writeEventStreamPayload(
	writer io.Writer,
	controller *http.ResponseController,
	noProgress time.Duration,
	payload []byte,
) (resultErr error) {
	if writer == nil ||
		controller == nil ||
		noProgress <= 0 ||
		len(payload) == 0 {
		return ErrInvalidResponse
	}
	if err := controller.SetWriteDeadline(
		time.Now().Add(noProgress),
	); err != nil {
		return err
	}
	defer func() {
		if clearErr := controller.SetWriteDeadline(time.Time{}); clearErr != nil {
			if resultErr == nil {
				resultErr = clearErr
				return
			}
			resultErr = errors.Join(resultErr, clearErr)
		}
	}()
	written, err := writer.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return controller.Flush()
}

func sameEventWatermarkLineage(
	left EventWatermark,
	right EventWatermark,
) bool {
	return left.valid &&
		right.valid &&
		left.SessionID() == right.SessionID() &&
		left.WorkspaceID() == right.WorkspaceID() &&
		left.RecoveryGeneration() == right.RecoveryGeneration() &&
		left.ServerDeviceID() == right.ServerDeviceID()
}

// WatchEventWatermarks blocks while receiving current-watermark notifications.
// The callback must return promptly; SSE is only a wake hint and carries no
// authoritative replication data.
func (client *Client) WatchEventWatermarks(
	ctx context.Context,
	receive func(EventWatermark) error,
) error {
	return client.watchEventWatermarks(
		ctx,
		receive,
		StreamNoProgress,
	)
}

func (client *Client) watchEventWatermarks(
	ctx context.Context,
	receive func(EventWatermark) error,
	noProgress time.Duration,
) error {
	if client == nil || ctx == nil || receive == nil {
		return ErrInvalidClient
	}
	if noProgress <= 0 {
		return ErrInvalidClient
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.acquireEventStream(ctx); err != nil {
		return err
	}
	defer client.releaseEventStream()

	connection, expected, err := client.eventStreamConnection()
	if err != nil {
		return err
	}
	progressContext, watchdog := newStreamProgressContext(
		ctx,
		noProgress,
	)
	defer watchdog.stop()
	request, err := http.NewRequestWithContext(
		progressContext,
		http.MethodGet,
		"https://"+contentPeerAuthority+EventsStreamPath,
		nil,
	)
	if err != nil {
		return ErrInvalidClient
	}
	request.Header.Set("Accept", eventStreamMediaType)
	request.Header.Set("Accept-Encoding", "identity")

	response, err := connection.http2.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return client.eventStreamFailure(
			ctx,
			progressContext,
			classifyRoundTripError(err),
		)
	}
	if err := validateClientResponseTLS(response, connection); err != nil {
		_ = response.Body.Close()
		client.invalidate()
		return err
	}
	if response.StatusCode >= http.StatusBadRequest {
		return client.readEventStreamProblem(
			ctx,
			progressContext,
			watchdog,
			response,
		)
	}
	if err := validateEventStreamResponse(response); err != nil {
		_ = response.Body.Close()
		client.invalidate()
		return err
	}
	defer response.Body.Close()
	watchdog.reset()
	reader := bufio.NewReaderSize(response.Body, eventStreamMaxLine)
	var current EventWatermark
	haveWatermark := false
	for {
		frame, err := readEventStreamFrame(reader, watchdog.reset)
		if err != nil {
			return client.eventStreamFailure(
				ctx,
				progressContext,
				err,
			)
		}
		if frame == nil {
			if !haveWatermark {
				client.invalidate()
				return ErrResponseProtocol
			}
			continue
		}
		watermark, err := decodeEventWatermark(frame)
		if err != nil ||
			watermark.SessionID() != expected.sessionID ||
			watermark.WorkspaceID() != expected.workspaceID ||
			watermark.RecoveryGeneration() !=
				expected.recoveryGeneration ||
			watermark.ServerDeviceID() !=
				connection.peerBinding.DeviceID {
			client.invalidate()
			return ErrResponseProtocol
		}
		if haveWatermark &&
			(!sameEventWatermarkLineage(current, watermark) ||
				watermark.ResultIndex() <= current.ResultIndex() ||
				watermark.ChainIndex() < current.ChainIndex()) {
			client.invalidate()
			return ErrResponseProtocol
		}
		current = watermark
		haveWatermark = true
		if err := receive(watermark); err != nil {
			return err
		}
	}
}

type eventStreamExpectedLineage struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
}

func (client *Client) eventStreamConnection() (
	clientConnection,
	eventStreamExpectedLineage,
	error,
) {
	connection, err := client.connection()
	if err != nil {
		return clientConnection{}, eventStreamExpectedLineage{}, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed ||
		client.role != contentConnectionControl ||
		!client.lineageSet ||
		!client.sessionBound {
		return clientConnection{}, eventStreamExpectedLineage{},
			ErrLineageMismatch
	}
	return connection, eventStreamExpectedLineage{
		sessionID:          client.peerBinding.SessionID,
		workspaceID:        client.workspaceID,
		recoveryGeneration: client.recoveryGeneration,
	}, nil
}

func validateEventStreamResponse(response *http.Response) error {
	if response == nil ||
		response.Body == nil ||
		response.StatusCode != http.StatusOK ||
		response.Uncompressed ||
		response.ContentLength != -1 ||
		len(response.TransferEncoding) != 0 ||
		len(response.Trailer) != 0 ||
		!boundedResponseHeader(response.Header) ||
		!exactMediaType(response.Header, eventStreamMediaType) ||
		len(response.Header.Values("Content-Length")) != 0 ||
		len(response.Header.Values("Content-Encoding")) != 0 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return ErrResponseProtocol
	}
	return nil
}

func readEventStreamFrame(
	reader *bufio.Reader,
	progress func(),
) ([]byte, error) {
	first, err := readEventStreamLine(reader, progress)
	if err != nil {
		return nil, err
	}
	switch first {
	case ": keepalive\n":
		empty, err := readEventStreamLine(reader, progress)
		if err != nil || empty != "\n" {
			return nil, ErrResponseProtocol
		}
		return nil, nil
	case "event: " + eventStreamName + "\n":
	default:
		return nil, ErrResponseProtocol
	}
	data, err := readEventStreamLine(reader, progress)
	if err != nil ||
		!bytes.HasPrefix([]byte(data), []byte("data: ")) ||
		len(data) <= len("data: \n") ||
		data[len(data)-1] != '\n' {
		return nil, ErrResponseProtocol
	}
	empty, err := readEventStreamLine(reader, progress)
	if err != nil || empty != "\n" {
		return nil, ErrResponseProtocol
	}
	body := []byte(data[len("data: ") : len(data)-1])
	if len(body) > eventStreamMaxData {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func readEventStreamLine(
	reader *bufio.Reader,
	progress func(),
) (string, error) {
	if reader == nil || progress == nil {
		return "", ErrResponseProtocol
	}
	line, err := reader.ReadSlice('\n')
	if len(line) > 0 {
		progress()
	}
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", ErrResponseTooLarge
		}
		if errors.Is(err, io.EOF) {
			return "", ErrConnectionUnavailable
		}
		return "", err
	}
	if len(line) > eventStreamMaxLine ||
		len(line) == 0 ||
		bytes.IndexByte(line, '\r') >= 0 {
		return "", ErrResponseProtocol
	}
	return string(line), nil
}

func (client *Client) readEventStreamProblem(
	ctx context.Context,
	progressContext context.Context,
	watchdog *streamProgressWatchdog,
	response *http.Response,
) error {
	limit, problem, err := validateResponseEnvelope(
		response,
		ResponseMaxBytes,
	)
	if err != nil || !problem {
		_ = response.Body.Close()
		client.invalidate()
		if err != nil {
			return err
		}
		return ErrResponseProtocol
	}
	body, err := readClientResponseWithProgress(
		progressContext,
		response,
		limit,
		watchdog.reset,
	)
	if err != nil {
		return client.eventStreamFailure(ctx, progressContext, err)
	}
	remote, err := decodeRemoteProblem(body, response.StatusCode)
	if err != nil {
		client.invalidate()
		return err
	}
	return remote
}

func (client *Client) eventStreamFailure(
	parent context.Context,
	progressContext context.Context,
	err error,
) error {
	switch {
	case parent.Err() != nil:
		return parent.Err()
	case errors.Is(context.Cause(progressContext), errEventStreamNoProgress):
		client.invalidate()
		return fmt.Errorf(
			"%w: event stream no progress",
			ErrConnectionUnavailable,
		)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		client.invalidate()
		if errors.Is(err, ErrResponseProtocol) ||
			errors.Is(err, ErrResponseTooLarge) {
			return err
		}
		return fmt.Errorf("%w: event stream", ErrConnectionUnavailable)
	}
}

type streamProgressWatchdog struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel context.CancelCauseFunc
	closed bool
	delay  time.Duration
}

func newStreamProgressContext(
	parent context.Context,
	delay time.Duration,
) (context.Context, *streamProgressWatchdog) {
	ctx, cancel := context.WithCancelCause(parent)
	watchdog := &streamProgressWatchdog{
		cancel: cancel,
		delay:  delay,
	}
	watchdog.timer = time.AfterFunc(delay, func() {
		cancel(errEventStreamNoProgress)
	})
	return ctx, watchdog
}

func (watchdog *streamProgressWatchdog) reset() {
	if watchdog == nil {
		return
	}
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	if !watchdog.closed {
		watchdog.timer.Reset(watchdog.delay)
	}
}

func (watchdog *streamProgressWatchdog) stop() {
	if watchdog == nil {
		return
	}
	watchdog.mu.Lock()
	if !watchdog.closed {
		watchdog.closed = true
		watchdog.timer.Stop()
		watchdog.cancel(nil)
	}
	watchdog.mu.Unlock()
}
