package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type consensusConnectionHandler struct {
	layer *ConsensusStreamLayer
	peer  AuthenticatedPeer
}

func (handler *consensusConnectionHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler == nil || handler.layer == nil || request == nil {
		writeConsensusStatus(writer, http.StatusInternalServerError)
		return
	}
	select {
	case handler.layer.handlers <- struct{}{}:
		defer func() { <-handler.layer.handlers }()
	default:
		writeConsensusStatus(writer, http.StatusServiceUnavailable)
		return
	}
	if !validConsensusRequestTransport(request, handler.peer) {
		writeConsensusStatus(writer, http.StatusBadRequest)
		return
	}
	if err := ReauthorizeAuthenticatedPeer(request.Context()); err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrPeerAuthorizationDenied) {
			status = http.StatusForbidden
		}
		writeConsensusStatus(writer, status)
		return
	}
	if request.Method != http.MethodConnect {
		if !validConsensusControlRequest(request) {
			writeConsensusStatus(writer, http.StatusNotFound)
			return
		}
		handler.layer.controlHandler.ServeHTTP(writer, request)
		return
	}
	handler.serveRaft(writer, request)
}

func (handler *consensusConnectionHandler) serveRaft(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !validConsensusStreamRequest(request, handler.peer) {
		writeConsensusStatus(writer, http.StatusBadRequest)
		return
	}
	if err := handler.layer.authorize(handler.peer.DeviceID); err != nil {
		writeConsensusStatus(writer, http.StatusForbidden)
		return
	}

	controller := http.NewResponseController(writer)
	if err := controller.EnableFullDuplex(); err != nil {
		writeConsensusStatus(writer, http.StatusInternalServerError)
		return
	}
	streamContext, streamCancel := context.WithCancel(request.Context())
	resources := &consensusInboundResources{
		cancel: streamCancel,
		body:   request.Body,
	}
	var connection *consensusStreamConn
	connection, resources.bridges = newConsensusStreamConn(
		handler.layer.localDeviceID,
		handler.peer.DeviceID,
		resources.close,
	)
	if !handler.layer.register(connection) {
		_ = connection.Close()
		writeConsensusStatus(writer, http.StatusServiceUnavailable)
		return
	}
	connection.addCloseHook(func() {
		handler.layer.unregister(connection)
	})
	if err := ReauthorizeAuthenticatedPeer(request.Context()); err != nil {
		_ = connection.Close()
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrPeerAuthorizationDenied) {
			status = http.StatusForbidden
		}
		writeConsensusStatus(writer, status)
		return
	}
	if err := handler.layer.authorize(handler.peer.DeviceID); err != nil {
		_ = connection.Close()
		writeConsensusStatus(writer, http.StatusForbidden)
		return
	}
	select {
	case handler.layer.accept <- connection:
	case <-streamContext.Done():
		_ = connection.Close()
		return
	case <-handler.layer.ctx.Done():
		_ = connection.Close()
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		_ = connection.Close()
		return
	}

	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-request.Context().Done():
			_ = connection.Close()
		case <-connection.done:
		}
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		copyInboundRequest(request.Body, resources.bridges.read)
	}()
	copyInboundResponse(
		connection,
		resources.bridges.write,
		&flushingResponseWriter{
			writer:     writer,
			controller: controller,
		},
	)
	_ = connection.Close()
	<-inputDone
	<-watcherDone
}

func validConsensusStreamRequest(
	request *http.Request,
	peer AuthenticatedPeer,
) bool {
	if !validConsensusRequestTransport(request, peer) {
		return false
	}
	return request.Method == http.MethodConnect &&
		request.Host == ConsensusRaftAuthority &&
		request.URL != nil &&
		request.URL.Path == ConsensusRaftPath &&
		request.URL.RawPath == "" &&
		request.URL.RawQuery == "" &&
		request.URL.Fragment == "" &&
		request.URL.RawFragment == "" &&
		!request.URL.ForceQuery &&
		request.Body != nil &&
		len(request.Header.Values(":protocol")) == 1 &&
		request.Header.Values(":protocol")[0] == ConsensusRaftProtocol
}

func validConsensusRequestTransport(
	request *http.Request,
	peer AuthenticatedPeer,
) bool {
	if request == nil ||
		request.ProtoMajor != 2 ||
		request.Host != ConsensusRaftAuthority ||
		peer.Plane != PlaneConsensus ||
		!peer.DeviceID.Valid() {
		return false
	}
	state := request.TLS
	return state != nil &&
		state.HandshakeComplete &&
		state.Version == tls.VersionTLS13 &&
		!state.DidResume &&
		state.NegotiatedProtocol == ALPNConsensus &&
		len(state.PeerCertificates) == 1
}

func validConsensusControlRequest(request *http.Request) bool {
	if request == nil ||
		request.URL == nil ||
		request.URL.RawPath != "" ||
		request.URL.RawQuery != "" ||
		request.URL.Fragment != "" ||
		request.URL.RawFragment != "" ||
		len(request.Header.Values(":protocol")) != 0 ||
		request.URL.ForceQuery {
		return false
	}
	switch {
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/consensus/status":
		return true
	case request.Method == http.MethodPost &&
		request.URL.Path == "/v1/consensus/prove":
		return true
	case request.Method == http.MethodPost &&
		request.URL.Path == "/v1/credentials/renew":
		return true
	case request.Method == http.MethodPost &&
		request.URL.Path == "/v1/credentials/endorse":
		return true
	default:
		return false
	}
}

func writeConsensusStatus(writer http.ResponseWriter, status int) {
	if writer == nil {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", "0")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
}

func copyInboundRequest(source io.ReadCloser, destination net.Conn) {
	_, _ = io.CopyBuffer(
		destination,
		source,
		make([]byte, consensusCopyBufferSize),
	)
	_ = destination.Close()
}

func copyInboundResponse(
	connection *consensusStreamConn,
	source net.Conn,
	destination io.Writer,
) {
	_, err := io.CopyBuffer(
		destination,
		source,
		make([]byte, consensusCopyBufferSize),
	)
	_ = source.Close()
	if err != nil {
		_ = connection.Close()
	}
}

type flushingResponseWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func (writer *flushingResponseWriter) Write(buffer []byte) (int, error) {
	count, err := writer.writer.Write(buffer)
	if err != nil {
		return count, err
	}
	if flushErr := writer.controller.Flush(); flushErr != nil {
		return count, flushErr
	}
	return count, nil
}

type consensusInboundResources struct {
	once sync.Once

	cancel  context.CancelFunc
	body    io.ReadCloser
	bridges consensusStreamBridges
}

type consensusHeaderGuard struct {
	connection net.Conn
	timeout    time.Duration
	expired    atomic.Bool

	mu               sync.Mutex
	timer            *time.Timer
	timerGeneration  uint64
	stopped          bool
	prefaceRemaining int
	frameHeader      [9]byte
	frameHeaderBytes int
	payloadRemaining uint32
	frameType        http2.FrameType
	frameFlags       http2.Flags
	headerBlockOpen  bool
	headerBlockSeen  bool
}

func newConsensusHeaderGuard(
	connection net.Conn,
	timeout time.Duration,
) *consensusHeaderGuard {
	guard := &consensusHeaderGuard{
		connection:       connection,
		timeout:          timeout,
		prefaceRemaining: len(http2.ClientPreface),
	}
	if connection == nil || timeout <= 0 {
		guard.expired.Store(true)
		guard.stopped = true
		return guard
	}
	guard.armLocked()
	return guard
}

func (guard *consensusHeaderGuard) observe(data []byte) {
	if guard == nil || len(data) == 0 {
		return
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.stopped {
		return
	}
	for len(data) > 0 {
		if guard.prefaceRemaining > 0 {
			count := guard.prefaceRemaining
			if count > len(data) {
				count = len(data)
			}
			guard.prefaceRemaining -= count
			data = data[count:]
			continue
		}
		if guard.payloadRemaining > 0 {
			count := uint32(len(data))
			if count > guard.payloadRemaining {
				count = guard.payloadRemaining
			}
			guard.payloadRemaining -= count
			data = data[count:]
			if guard.payloadRemaining == 0 {
				guard.finishFrameLocked()
			}
			continue
		}

		if guard.frameHeaderBytes == 0 && guard.timer == nil {
			guard.armLocked()
		}
		count := len(guard.frameHeader) - guard.frameHeaderBytes
		if count > len(data) {
			count = len(data)
		}
		copy(
			guard.frameHeader[guard.frameHeaderBytes:],
			data[:count],
		)
		guard.frameHeaderBytes += count
		data = data[count:]
		if guard.frameHeaderBytes != len(guard.frameHeader) {
			continue
		}
		guard.frameHeaderBytes = 0
		guard.payloadRemaining =
			uint32(guard.frameHeader[0])<<16 |
				uint32(guard.frameHeader[1])<<8 |
				uint32(guard.frameHeader[2])
		guard.frameType = http2.FrameType(guard.frameHeader[3])
		guard.frameFlags = http2.Flags(guard.frameHeader[4])
		if guard.frameType == http2.FrameHeaders &&
			!guard.headerBlockOpen {
			guard.headerBlockOpen = true
		} else if !guard.headerBlockOpen && guard.headerBlockSeen {
			guard.disarmLocked()
		}
		if guard.payloadRemaining == 0 {
			guard.finishFrameLocked()
		}
	}
}

func (guard *consensusHeaderGuard) stop() {
	if guard == nil {
		return
	}
	guard.mu.Lock()
	if !guard.stopped {
		guard.stopped = true
		guard.disarmLocked()
	}
	guard.mu.Unlock()
}

func (guard *consensusHeaderGuard) timedOut() bool {
	return guard != nil && guard.expired.Load()
}

func (guard *consensusHeaderGuard) finishFrameLocked() {
	if !guard.headerBlockOpen {
		return
	}
	endHeaders := false
	switch guard.frameType {
	case http2.FrameHeaders:
		endHeaders = guard.frameFlags.Has(http2.FlagHeadersEndHeaders)
	case http2.FrameContinuation:
		endHeaders = guard.frameFlags.Has(
			http2.FlagContinuationEndHeaders,
		)
	}
	if endHeaders {
		guard.headerBlockOpen = false
		guard.headerBlockSeen = true
		guard.disarmLocked()
	}
}

func (guard *consensusHeaderGuard) armLocked() {
	guard.timerGeneration++
	generation := guard.timerGeneration
	if guard.timer != nil {
		guard.timer.Stop()
	}
	guard.timer = time.AfterFunc(guard.timeout, func() {
		guard.expire(generation)
	})
}

func (guard *consensusHeaderGuard) disarmLocked() {
	guard.timerGeneration++
	if guard.timer != nil {
		guard.timer.Stop()
		guard.timer = nil
	}
}

func (guard *consensusHeaderGuard) expire(generation uint64) {
	guard.mu.Lock()
	if guard.stopped || guard.timerGeneration != generation {
		guard.mu.Unlock()
		return
	}
	guard.stopped = true
	guard.expired.Store(true)
	connection := guard.connection
	guard.mu.Unlock()
	_ = closeConsensusConnectionImmediately(connection)
}

// consensusHeaderTrackingConn observes only HTTP/2 frame envelopes to enforce
// request-header timeouts. The maintained HTTP/2 stack still parses and
// validates every byte.
type consensusHeaderTrackingConn struct {
	*tls.Conn
	guard *consensusHeaderGuard
}

func (connection *consensusHeaderTrackingConn) Read(
	buffer []byte,
) (int, error) {
	count, err := connection.Conn.Read(buffer)
	if count > 0 {
		connection.guard.observe(buffer[:count])
	}
	return count, err
}

func (resources *consensusInboundResources) close() {
	if resources == nil {
		return
	}
	resources.once.Do(func() {
		if resources.cancel != nil {
			resources.cancel()
		}
		if resources.body != nil {
			_ = resources.body.Close()
		}
		_ = resources.bridges.read.Close()
		_ = resources.bridges.write.Close()
	})
}
