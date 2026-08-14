package pairinghttp

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	http2FrameHeaderSize       = 9
	http2FrameTypeHeaders      = 0x1
	http2FrameTypeContinuation = 0x9
	http2FlagEndHeaders        = 0x4
)

// http2DeadlineConn supplements x/net/http2's first-request-only socket
// deadline. It observes frame envelopes only to maintain time bounds; the
// HTTP/2 implementation remains solely responsible for protocol validation.
type http2DeadlineConn struct {
	*tls.Conn

	mu              sync.Mutex
	headerTimeout   time.Duration
	idleTimeout     time.Duration
	frameNoProgress time.Duration
	readDeadline    time.Time
	state           http2DeadlineState
}

type http2DeadlineState struct {
	prefaceRemaining int
	frameHeader      [http2FrameHeaderSize]byte
	frameHeaderUsed  int
	frameRemaining   uint32
	frameType        byte
	frameFlags       byte
	headerBlock      bool
	phaseDeadline    time.Time
}

func newHTTP2DeadlineConn(
	connection *tls.Conn,
	headerTimeout time.Duration,
	idleTimeout time.Duration,
	frameNoProgress time.Duration,
) (*http2DeadlineConn, error) {
	if connection == nil ||
		headerTimeout <= 0 ||
		idleTimeout <= 0 ||
		frameNoProgress <= 0 {
		return nil, ErrInvalidConnection
	}
	now := time.Now()
	result := &http2DeadlineConn{
		Conn:            connection,
		headerTimeout:   headerTimeout,
		idleTimeout:     idleTimeout,
		frameNoProgress: frameNoProgress,
		state: http2DeadlineState{
			prefaceRemaining: len(http2.ClientPreface),
			phaseDeadline:    now.Add(headerTimeout),
		},
	}
	if err := result.applyReadDeadlineLocked(now); err != nil {
		return nil, errors.Join(ErrInvalidConnection, err)
	}
	return result, nil
}

func (connection *http2DeadlineConn) Read(buffer []byte) (int, error) {
	if connection == nil || connection.Conn == nil {
		return 0, ErrInvalidConnection
	}
	connection.mu.Lock()
	deadlineErr := connection.applyReadDeadlineLocked(time.Now())
	connection.mu.Unlock()
	if deadlineErr != nil {
		return 0, deadlineErr
	}

	count, readErr := connection.Conn.Read(buffer)
	if count == 0 {
		return count, readErr
	}
	now := time.Now()
	connection.mu.Lock()
	connection.state.observe(
		buffer[:count],
		now,
		connection.headerTimeout,
		connection.frameNoProgress,
	)
	deadlineErr = connection.applyReadDeadlineLocked(now)
	connection.mu.Unlock()
	if readErr == nil && deadlineErr != nil {
		readErr = deadlineErr
	}
	return count, readErr
}

func (connection *http2DeadlineConn) SetDeadline(deadline time.Time) error {
	if connection == nil || connection.Conn == nil {
		return ErrInvalidConnection
	}
	readErr := connection.SetReadDeadline(deadline)
	writeErr := connection.Conn.SetWriteDeadline(deadline)
	return errors.Join(readErr, writeErr)
}

func (connection *http2DeadlineConn) SetReadDeadline(
	deadline time.Time,
) error {
	if connection == nil || connection.Conn == nil {
		return ErrInvalidConnection
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.readDeadline = deadline
	return connection.applyReadDeadlineLocked(time.Now())
}

func (connection *http2DeadlineConn) applyReadDeadlineLocked(
	now time.Time,
) error {
	transportDeadline := connection.state.phaseDeadline
	if transportDeadline.IsZero() {
		transportDeadline = now.Add(connection.idleTimeout)
	}
	deadline := transportDeadline
	if !connection.readDeadline.IsZero() &&
		connection.readDeadline.Before(deadline) {
		deadline = connection.readDeadline
	}
	return connection.Conn.SetReadDeadline(deadline)
}

func (state *http2DeadlineState) observe(
	data []byte,
	now time.Time,
	headerTimeout time.Duration,
	frameNoProgress time.Duration,
) {
	for len(data) > 0 {
		if state.prefaceRemaining > 0 {
			used := min(len(data), state.prefaceRemaining)
			state.prefaceRemaining -= used
			data = data[used:]
			if state.prefaceRemaining == 0 {
				state.phaseDeadline = time.Time{}
			}
			continue
		}
		if state.frameHeaderUsed < http2FrameHeaderSize {
			if state.frameHeaderUsed == 0 &&
				state.phaseDeadline.IsZero() {
				state.phaseDeadline = now.Add(headerTimeout)
			}
			used := min(
				len(data),
				http2FrameHeaderSize-state.frameHeaderUsed,
			)
			copy(
				state.frameHeader[state.frameHeaderUsed:],
				data[:used],
			)
			state.frameHeaderUsed += used
			data = data[used:]
			if state.frameHeaderUsed < http2FrameHeaderSize {
				continue
			}
			state.frameRemaining =
				uint32(state.frameHeader[0])<<16 |
					uint32(state.frameHeader[1])<<8 |
					uint32(state.frameHeader[2])
			state.frameType = state.frameHeader[3]
			state.frameFlags = state.frameHeader[4]
			if !state.headerBlock &&
				state.frameType != http2FrameTypeHeaders &&
				state.frameType != http2FrameTypeContinuation {
				state.phaseDeadline = now.Add(frameNoProgress)
			}
			if state.frameRemaining == 0 {
				state.finishFrame()
			}
			continue
		}

		used := min(len(data), int(state.frameRemaining))
		state.frameRemaining -= uint32(used)
		data = data[used:]
		if used > 0 &&
			!state.headerBlock &&
			state.frameType != http2FrameTypeHeaders &&
			state.frameType != http2FrameTypeContinuation {
			state.phaseDeadline = now.Add(frameNoProgress)
		}
		if state.frameRemaining == 0 {
			state.finishFrame()
		}
	}
}

func (state *http2DeadlineState) finishFrame() {
	switch {
	case state.frameType == http2FrameTypeHeaders:
		state.headerBlock =
			state.frameFlags&http2FlagEndHeaders == 0
		if !state.headerBlock {
			state.phaseDeadline = time.Time{}
		}
	case state.frameType == http2FrameTypeContinuation &&
		state.headerBlock:
		state.headerBlock =
			state.frameFlags&http2FlagEndHeaders == 0
		if !state.headerBlock {
			state.phaseDeadline = time.Time{}
		}
	case state.headerBlock:
		// The HTTP/2 library will reject an interleaved header block. Keep
		// the original header deadline until it does.
	default:
		state.phaseDeadline = time.Time{}
	}
	state.frameHeader = [http2FrameHeaderSize]byte{}
	state.frameHeaderUsed = 0
	state.frameRemaining = 0
	state.frameType = 0
	state.frameFlags = 0
}

var _ net.Conn = (*http2DeadlineConn)(nil)
