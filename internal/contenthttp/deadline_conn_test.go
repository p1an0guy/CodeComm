package contenthttp

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestDeadlineStateBoundsPrefaceHeadersAndFrameProgress(t *testing.T) {
	t.Parallel()

	headerTimeout := 10 * time.Second
	noProgress := 30 * time.Second
	now := time.Unix(1_700_000_000, 0)
	state := deadlineState{
		prefaceRemaining: len(http2.ClientPreface),
		phaseDeadline:    now.Add(headerTimeout),
	}
	state.observe(
		[]byte(http2.ClientPreface[:8]), now.Add(time.Second),
		headerTimeout, noProgress,
	)
	if got := state.phaseDeadline; !got.Equal(now.Add(headerTimeout)) {
		t.Fatalf("partial-preface deadline = %s", got)
	}
	state.observe(
		[]byte(http2.ClientPreface[8:]), now.Add(2*time.Second),
		headerTimeout, noProgress,
	)
	if !state.phaseDeadline.IsZero() || state.prefaceRemaining != 0 {
		t.Fatalf("completed preface state = %+v", state)
	}

	dataHeader := testHTTP2FrameHeader(3, 0, 0)
	frameStart := now.Add(3 * time.Second)
	state.observe(dataHeader[:4], frameStart, headerTimeout, noProgress)
	if got := state.phaseDeadline; !got.Equal(frameStart.Add(headerTimeout)) {
		t.Fatalf("partial-frame-header deadline = %s", got)
	}
	state.observe(dataHeader[4:], frameStart, headerTimeout, noProgress)
	if got := state.phaseDeadline; !got.Equal(frameStart.Add(noProgress)) {
		t.Fatalf("data-frame deadline = %s", got)
	}
	progress := now.Add(4 * time.Second)
	state.observe([]byte{1}, progress, headerTimeout, noProgress)
	if got := state.phaseDeadline; !got.Equal(progress.Add(noProgress)) {
		t.Fatalf("data progress deadline = %s", got)
	}
	state.observe([]byte{2, 3}, now.Add(5*time.Second), headerTimeout, noProgress)
	if !state.phaseDeadline.IsZero() {
		t.Fatalf("completed data frame deadline = %s", state.phaseDeadline)
	}

	headers := testHTTP2FrameHeader(1, http2FrameTypeHeaders, 0)
	headerStart := now.Add(6 * time.Second)
	state.observe(headers, headerStart, headerTimeout, noProgress)
	state.observe([]byte{1}, now.Add(7*time.Second), headerTimeout, noProgress)
	if !state.headerBlock ||
		!state.phaseDeadline.Equal(headerStart.Add(headerTimeout)) {
		t.Fatalf("open header block state = %+v", state)
	}
	continuation := testHTTP2FrameHeader(
		1, http2FrameTypeContinuation, http2FlagEndHeaders,
	)
	state.observe(continuation, now.Add(8*time.Second), headerTimeout, noProgress)
	state.observe([]byte{2}, now.Add(9*time.Second), headerTimeout, noProgress)
	if state.headerBlock || !state.phaseDeadline.IsZero() {
		t.Fatalf("closed header block state = %+v", state)
	}
}

func TestDeadlineConnAppliesHeaderIdleAndCallerBounds(t *testing.T) {
	t.Parallel()

	raw := &recordingDeadlineConn{}
	connection := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	before := time.Now()
	bounded, err := newDeadlineConn(
		connection,
		RequestHeaderTimeout,
		ConnectionIdle,
		StreamNoProgress,
	)
	if err != nil {
		t.Fatal(err)
	}
	initial := raw.readDeadline()
	if initial.Before(before.Add(RequestHeaderTimeout-time.Second)) ||
		initial.After(time.Now().Add(RequestHeaderTimeout+time.Second)) {
		t.Fatalf("initial header deadline = %s", initial)
	}

	bounded.mu.Lock()
	bounded.state.phaseDeadline = time.Time{}
	bounded.mu.Unlock()
	before = time.Now()
	if err := bounded.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	idle := raw.readDeadline()
	if idle.Before(before.Add(ConnectionIdle-time.Second)) ||
		idle.After(time.Now().Add(ConnectionIdle+time.Second)) {
		t.Fatalf("idle deadline = %s", idle)
	}

	caller := time.Now().Add(time.Second)
	if err := bounded.SetReadDeadline(caller); err != nil {
		t.Fatal(err)
	}
	if got := raw.readDeadline(); !got.Equal(caller) {
		t.Fatalf("caller deadline = %s, want %s", got, caller)
	}
	if _, err := newDeadlineConn(nil, time.Second, time.Second, time.Second); !errors.Is(err, ErrInvalidConnection) {
		t.Fatalf("nil deadline connection error = %v", err)
	}
	if _, err := newDeadlineConn(connection, 0, time.Second, time.Second); !errors.Is(err, ErrInvalidConnection) {
		t.Fatalf("zero deadline error = %v", err)
	}
}

func testHTTP2FrameHeader(length uint32, frameType byte, flags byte) []byte {
	return []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		frameType, flags,
		0, 0, 0, 1,
	}
}

type recordingDeadlineConn struct {
	mu       sync.Mutex
	deadline time.Time
}

func (*recordingDeadlineConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (*recordingDeadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (*recordingDeadlineConn) Close() error                { return nil }
func (*recordingDeadlineConn) LocalAddr() net.Addr         { return testAddr("local") }
func (*recordingDeadlineConn) RemoteAddr() net.Addr        { return testAddr("remote") }
func (connection *recordingDeadlineConn) SetDeadline(value time.Time) error {
	if err := connection.SetReadDeadline(value); err != nil {
		return err
	}
	return connection.SetWriteDeadline(value)
}
func (connection *recordingDeadlineConn) SetReadDeadline(value time.Time) error {
	connection.mu.Lock()
	connection.deadline = value
	connection.mu.Unlock()
	return nil
}
func (*recordingDeadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (connection *recordingDeadlineConn) readDeadline() time.Time {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.deadline
}
