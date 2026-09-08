package faultnet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDirectedDropBlocksEstablishedAndFutureConnections(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)

	firstLocal, firstPeer := net.Pipe()
	t.Cleanup(func() { _ = firstPeer.Close() })
	first, err := controller.Wrap(firstLocal, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(existing): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(Drop): %v", err)
	}

	secondLocal, secondPeer := net.Pipe()
	t.Cleanup(func() { _ = secondPeer.Close() })
	second, err := controller.Wrap(secondLocal, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(future): %v", err)
	}

	firstPayload := []byte("existing-connection")
	secondPayload := []byte("future-connection")
	firstRead := faultnetReadExactly(firstPeer, len(firstPayload))
	secondRead := faultnetReadExactly(secondPeer, len(secondPayload))
	firstWrite := faultnetWrite(first, firstPayload)
	secondWrite := faultnetWrite(second, secondPayload)
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		2,
	); err != nil {
		t.Fatalf("WaitForHits(2): %v", err)
	}
	faultnetAssertPending(t, firstWrite)
	faultnetAssertPending(t, secondWrite)
	faultnetAssertPending(t, firstRead)
	faultnetAssertPending(t, secondRead)

	reversePayload := []byte("reverse-remains-usable")
	reverseWrite := faultnetWrite(firstPeer, reversePayload)
	reverseRead := faultnetReadExactly(first, len(reversePayload))
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, reverseWrite),
		len(reversePayload),
	)
	reverseResult := faultnetReceive(t, reverseRead)
	if reverseResult.err != nil ||
		!bytes.Equal(reverseResult.data, reversePayload) {
		t.Fatalf(
			"reverse Read() = (%q, %v)",
			reverseResult.data,
			reverseResult.err,
		)
	}

	before, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(before remove): %v", err)
	}
	if before.ActiveConnections != 2 ||
		before.ConnectionsHit != 2 ||
		before.Hits != 2 ||
		before.AffectedBytes !=
			uint64(len(firstPayload)+len(secondPayload)) {
		t.Fatalf("drop snapshot before removal = %+v", before)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Drop): %v", err)
	}

	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, firstWrite),
		len(firstPayload),
	)
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, secondWrite),
		len(secondPayload),
	)
	for name, result := range map[string]faultnetIOResult{
		"existing": faultnetReceive(t, firstRead),
		"future":   faultnetReceive(t, secondRead),
	} {
		var want []byte
		if name == "existing" {
			want = firstPayload
		} else {
			want = secondPayload
		}
		if result.err != nil || !bytes.Equal(result.data, want) {
			t.Fatalf("%s Read() = (%q, %v)", name, result.data, result.err)
		}
	}
}

func TestDropHonorsDeadlineChangesWhileBlocked(t *testing.T) {
	for _, test := range []struct {
		name string
		link Link
		run  func(net.Conn) <-chan faultnetIOResult
		set  func(net.Conn, time.Time) error
	}{
		{
			name: "write",
			link: faultnetTestLink(1, 2),
			run: func(connection net.Conn) <-chan faultnetIOResult {
				return faultnetWrite(connection, []byte("blocked"))
			},
			set: func(connection net.Conn, deadline time.Time) error {
				return connection.SetWriteDeadline(deadline)
			},
		},
		{
			name: "read",
			link: faultnetTestLink(2, 1),
			run: func(connection net.Conn) <-chan faultnetIOResult {
				return faultnetReadExactly(connection, 1)
			},
			set: func(connection net.Conn, deadline time.Time) error {
				return connection.SetReadDeadline(deadline)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := newFaultnetTestController(t, time.Second)
			local, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			connection, err := controller.Wrap(
				local,
				faultnetTestDeviceID(1),
				faultnetTestDeviceID(2),
			)
			if err != nil {
				t.Fatalf("Wrap(): %v", err)
			}
			handle, err := controller.Install(test.link, Rule{Kind: Drop})
			if err != nil {
				t.Fatalf("Install(Drop): %v", err)
			}
			result := test.run(connection)
			if err := controller.WaitForHits(
				faultnetTestContext(t),
				handle,
				1,
			); err != nil {
				t.Fatalf("WaitForHits(): %v", err)
			}
			faultnetAssertPending(t, result)
			if err := test.set(
				connection,
				time.Now().Add(20*time.Millisecond),
			); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			faultnetAssertDeadline(t, faultnetReceive(t, result))
			if err := controller.Remove(handle); err != nil {
				t.Fatalf("Remove(Drop): %v", err)
			}
		})
	}
}

func TestDelayHonorsBoundAndDeadlineBeforeUnderlyingIO(t *testing.T) {
	controller := newFaultnetTestController(t, 200*time.Millisecond)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetRecordingConn()
	connection, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(
		link,
		Rule{Kind: Delay, Delay: 100 * time.Millisecond},
	)
	if err != nil {
		t.Fatalf("Install(Delay): %v", err)
	}
	if err := connection.SetWriteDeadline(
		time.Now().Add(20 * time.Millisecond),
	); err != nil {
		t.Fatalf("SetWriteDeadline(): %v", err)
	}

	result := faultnetWrite(connection, []byte("must-not-reach-raw"))
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	faultnetAssertDeadline(t, faultnetReceive(t, result))
	select {
	case payload := <-raw.writes:
		t.Fatalf("delayed write reached raw connection: %q", payload)
	default:
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Delay): %v", err)
	}
}

func TestDelayForwardsOnceAfterItsBound(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetRecordingConn()
	connection, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(
		link,
		Rule{Kind: Delay, Delay: time.Millisecond},
	)
	if err != nil {
		t.Fatalf("Install(Delay): %v", err)
	}
	payload := []byte("one delayed write")
	result := faultnetWrite(connection, payload)
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	if got := faultnetReceive(t, raw.writes); !bytes.Equal(got, payload) {
		t.Fatalf("raw Write() payload = %q, want %q", got, payload)
	}
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, result),
		len(payload),
	)
	select {
	case extra := <-raw.writes:
		t.Fatalf("delay duplicated underlying write: %q", extra)
	default:
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Delay): %v", err)
	}
}

func TestDuplicateWriteForwardsOriginalAndOneReplay(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	connection, err := controller.Wrap(local, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Duplicate})
	if err != nil {
		t.Fatalf("Install(Duplicate): %v", err)
	}
	payload := []byte("duplicate-write")
	readResult := faultnetReadExactly(peer, len(payload)*2)
	writeResult := faultnetWrite(connection, payload)
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, writeResult),
		len(payload),
	)
	read := faultnetReceive(t, readResult)
	if read.err != nil ||
		!bytes.Equal(read.data, append(bytes.Clone(payload), payload...)) {
		t.Fatalf("duplicated bytes = (%q, %v)", read.data, read.err)
	}

	before, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(before remove): %v", err)
	}
	if before.Hits != 1 ||
		before.ConnectionsHit != 1 ||
		before.AffectedBytes != uint64(len(payload)) {
		t.Fatalf("duplicate snapshot before remove = %+v", before)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Duplicate): %v", err)
	}
	after, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(after remove): %v", err)
	}
	if after.ActiveConnections != 0 || after.ClosedConnections != 1 {
		t.Fatalf("duplicate snapshot after remove = %+v", after)
	}
}

func TestDuplicateReadReturnsOneBoundedReplay(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(2, 1)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	connection, err := controller.Wrap(
		local,
		faultnetTestDeviceID(1),
		faultnetTestDeviceID(2),
	)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	faultnetSetDeadlines(t, connection, peer)
	handle, err := controller.Install(link, Rule{Kind: Duplicate})
	if err != nil {
		t.Fatalf("Install(Duplicate): %v", err)
	}

	payload := bytes.Repeat([]byte{0x5a}, ReadChunkMax+1)
	writeResult := faultnetWrite(peer, payload)
	buffer := make([]byte, len(payload))
	firstCount, firstErr := connection.Read(buffer)
	if firstErr != nil || firstCount != ReadChunkMax {
		t.Fatalf("first Read() = (%d, %v)", firstCount, firstErr)
	}
	if !bytes.Equal(buffer[:firstCount], payload[:ReadChunkMax]) {
		t.Fatal("first Read() changed payload")
	}

	replay := make([]byte, ReadChunkMax)
	replayCount, replayErr := io.ReadFull(connection, replay)
	if replayErr != nil || replayCount != ReadChunkMax ||
		!bytes.Equal(replay, payload[:ReadChunkMax]) {
		t.Fatalf("bounded replay = (%d, %v)", replayCount, replayErr)
	}

	tail := make([]byte, 1)
	tailCount, tailErr := connection.Read(tail)
	if tailErr != nil || tailCount != 1 || tail[0] != payload[ReadChunkMax] {
		t.Fatalf("tail Read() = (%x, %v)", tail[:tailCount], tailErr)
	}
	tailReplay := make([]byte, 1)
	tailReplayCount, tailReplayErr := connection.Read(tailReplay)
	if tailReplayErr != nil ||
		tailReplayCount != 1 ||
		!bytes.Equal(tailReplay, tail) {
		t.Fatalf(
			"tail replay = (%x, %v)",
			tailReplay[:tailReplayCount],
			tailReplayErr,
		)
	}
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, writeResult),
		len(payload),
	)
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		2,
	); err != nil {
		t.Fatalf("WaitForHits(2): %v", err)
	}
	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.Hits != 2 ||
		snapshot.AffectedBytes != uint64(len(payload)) {
		t.Fatalf("duplicate read snapshot = %+v", snapshot)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Duplicate): %v", err)
	}
}

func TestTruncateWriteUsesExactPerConnectionBudget(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)

	firstLocal, firstPeer := net.Pipe()
	t.Cleanup(func() { _ = firstPeer.Close() })
	first, err := controller.Wrap(firstLocal, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(existing): %v", err)
	}
	faultnetSetDeadlines(t, first, firstPeer)
	handle, err := controller.Install(
		link,
		Rule{Kind: Truncate, TruncateAfter: 5},
	)
	if err != nil {
		t.Fatalf("Install(Truncate): %v", err)
	}
	secondLocal, secondPeer := net.Pipe()
	t.Cleanup(func() { _ = secondPeer.Close() })
	second, err := controller.Wrap(secondLocal, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(future): %v", err)
	}
	faultnetSetDeadlines(t, second, secondPeer)

	firstRead := faultnetReadAll(firstPeer)
	initialCount, initialErr := first.Write([]byte("ab"))
	if initialErr != nil || initialCount != 2 {
		t.Fatalf("first initial Write() = (%d, %v)", initialCount, initialErr)
	}
	finalCount, finalErr := first.Write([]byte("cdefgh"))
	if finalCount != 3 || !errors.Is(finalErr, io.ErrUnexpectedEOF) {
		t.Fatalf("first final Write() = (%d, %v)", finalCount, finalErr)
	}

	secondRead := faultnetReadAll(secondPeer)
	secondCount, secondErr := second.Write([]byte("12345678"))
	if secondCount != 5 || !errors.Is(secondErr, io.ErrUnexpectedEOF) {
		t.Fatalf("second Write() = (%d, %v)", secondCount, secondErr)
	}
	for name, result := range map[string]faultnetIOResult{
		"existing": faultnetReceive(t, firstRead),
		"future":   faultnetReceive(t, secondRead),
	} {
		want := []byte("abcde")
		if name == "future" {
			want = []byte("12345")
		}
		if result.err != nil || !bytes.Equal(result.data, want) {
			t.Fatalf("%s truncated bytes = (%q, %v)", name, result.data, result.err)
		}
	}

	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		3,
	); err != nil {
		t.Fatalf("WaitForHits(3): %v", err)
	}
	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.ActiveConnections != 0 ||
		snapshot.ConnectionsHit != 2 ||
		snapshot.Hits != 3 ||
		snapshot.AffectedBytes != 10 ||
		snapshot.ClosedConnections != 2 {
		t.Fatalf("truncate snapshot = %+v", snapshot)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Truncate): %v", err)
	}
}

func TestTruncateReadReturnsExactPrefixAndCloses(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(2, 1)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	connection, err := controller.Wrap(
		local,
		faultnetTestDeviceID(1),
		faultnetTestDeviceID(2),
	)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	faultnetSetDeadlines(t, connection, peer)
	handle, err := controller.Install(
		link,
		Rule{Kind: Truncate, TruncateAfter: 5},
	)
	if err != nil {
		t.Fatalf("Install(Truncate): %v", err)
	}

	writeResult := faultnetWrite(peer, []byte("abcdefgh"))
	buffer := make([]byte, 8)
	count, readErr := connection.Read(buffer)
	if count != 5 ||
		!errors.Is(readErr, io.ErrUnexpectedEOF) ||
		!bytes.Equal(buffer[:count], []byte("abcde")) {
		t.Fatalf("Read() = (%q, %v)", buffer[:count], readErr)
	}
	peerWrite := faultnetReceive(t, writeResult)
	if peerWrite.count > 5 || peerWrite.err == nil {
		t.Fatalf("peer Write() = (%d, %v)", peerWrite.count, peerWrite.err)
	}
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.AffectedBytes != 5 ||
		snapshot.ClosedConnections != 1 ||
		snapshot.ActiveConnections != 0 {
		t.Fatalf("truncate read snapshot = %+v", snapshot)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Truncate): %v", err)
	}
}

func TestZeroByteTruncateClosesWithoutUnderlyingIO(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetRecordingConn()
	connection, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Truncate})
	if err != nil {
		t.Fatalf("Install(Truncate zero): %v", err)
	}
	count, writeErr := connection.Write([]byte("not-forwarded"))
	if count != 0 || !errors.Is(writeErr, io.ErrUnexpectedEOF) {
		t.Fatalf("Write() = (%d, %v)", count, writeErr)
	}
	select {
	case payload := <-raw.writes:
		t.Fatalf("zero truncate reached raw connection: %q", payload)
	default:
	}
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Truncate): %v", err)
	}
}

func faultnetWrite(
	connection net.Conn,
	payload []byte,
) <-chan faultnetIOResult {
	result := make(chan faultnetIOResult, 1)
	go func() {
		count, err := connection.Write(payload)
		result <- faultnetIOResult{count: count, err: err}
	}()
	return result
}

func faultnetReadExactly(
	connection net.Conn,
	size int,
) <-chan faultnetIOResult {
	result := make(chan faultnetIOResult, 1)
	go func() {
		buffer := make([]byte, size)
		count, err := io.ReadFull(connection, buffer)
		result <- faultnetIOResult{
			count: count,
			data:  buffer[:count],
			err:   err,
		}
	}()
	return result
}

func faultnetReadAll(connection net.Conn) <-chan faultnetIOResult {
	result := make(chan faultnetIOResult, 1)
	go func() {
		data, err := io.ReadAll(connection)
		result <- faultnetIOResult{
			count: len(data),
			data:  data,
			err:   err,
		}
	}()
	return result
}

func assertFaultnetSuccessfulWrite(
	t *testing.T,
	result faultnetIOResult,
	want int,
) {
	t.Helper()
	if result.count != want || result.err != nil {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", result.count, result.err, want)
	}
}

func faultnetSetDeadlines(t *testing.T, connections ...net.Conn) {
	t.Helper()
	deadline := time.Now().Add(faultnetTestTimeout)
	for _, connection := range connections {
		if err := connection.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline(): %v", err)
		}
	}
}

type faultnetRecordingConn struct {
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFaultnetRecordingConn() *faultnetRecordingConn {
	return &faultnetRecordingConn{
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
}

func (connection *faultnetRecordingConn) Read([]byte) (int, error) {
	<-connection.closed
	return 0, net.ErrClosed
}

func (connection *faultnetRecordingConn) Write(buffer []byte) (int, error) {
	select {
	case <-connection.closed:
		return 0, net.ErrClosed
	default:
	}
	connection.writes <- bytes.Clone(buffer)
	return len(buffer), nil
}

func (connection *faultnetRecordingConn) Close() error {
	connection.once.Do(func() {
		close(connection.closed)
	})
	return nil
}

func (*faultnetRecordingConn) LocalAddr() net.Addr {
	return faultnetTestAddr("local")
}

func (*faultnetRecordingConn) RemoteAddr() net.Addr {
	return faultnetTestAddr("remote")
}

func (*faultnetRecordingConn) SetDeadline(time.Time) error {
	return nil
}

func (*faultnetRecordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*faultnetRecordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type faultnetTestAddr string

func (faultnetTestAddr) Network() string { return "faultnet-test" }
func (address faultnetTestAddr) String() string {
	return string(address)
}

var _ net.Conn = (*faultnetRecordingConn)(nil)
