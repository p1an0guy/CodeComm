package faultnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const faultnetTestTimeout = 5 * time.Second

func TestControllerValidatesBoundsLinksAndRules(t *testing.T) {
	if controller, err := NewController(0); controller != nil ||
		!errors.Is(err, ErrInvalidController) {
		t.Fatalf("NewController(0) = (%v, %v)", controller, err)
	}
	if controller, err := NewController(DelayHardMax + time.Nanosecond); controller != nil ||
		!errors.Is(err, ErrInvalidController) {
		t.Fatalf("NewController(over hard max) = (%v, %v)", controller, err)
	}

	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	invalidRules := []Rule{
		{},
		{Kind: Kind(255)},
		{Kind: Drop, Delay: time.Nanosecond},
		{Kind: Drop, TruncateAfter: 1},
		{Kind: Delay},
		{Kind: Delay, Delay: time.Second + time.Nanosecond},
		{Kind: Delay, Delay: time.Millisecond, TruncateAfter: 1},
		{Kind: Duplicate, Delay: time.Nanosecond},
		{Kind: Duplicate, TruncateAfter: 1},
		{Kind: Truncate, Delay: time.Nanosecond},
		{Kind: Truncate, TruncateAfter: TruncateBytesMax + 1},
	}
	for _, rule := range invalidRules {
		if handle, err := controller.Install(link, rule); handle != (Handle{}) ||
			!errors.Is(err, ErrInvalidRule) {
			t.Fatalf("Install(%+v) = (%+v, %v)", rule, handle, err)
		}
	}

	invalidLinks := []Link{
		{},
		{From: faultnetTestDeviceID(1), To: faultnetTestDeviceID(1)},
		{From: "invalid", To: faultnetTestDeviceID(2)},
		{From: faultnetTestDeviceID(1), To: "invalid"},
	}
	for _, invalid := range invalidLinks {
		if handle, err := controller.Install(
			invalid,
			Rule{Kind: Drop},
		); handle != (Handle{}) || !errors.Is(err, ErrInvalidLink) {
			t.Fatalf("Install(invalid link %+v) = (%+v, %v)", invalid, handle, err)
		}
	}

	handle, err := controller.Install(
		link,
		Rule{Kind: Delay, Delay: time.Second},
	)
	if err != nil {
		t.Fatalf("Install(valid delay): %v", err)
	}
	if _, err := controller.Install(
		link,
		Rule{Kind: Drop},
	); !errors.Is(err, ErrRuleActive) {
		t.Fatalf("Install(active link) error = %v", err)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(valid delay): %v", err)
	}

	for _, rule := range []Rule{
		{Kind: Drop},
		{Kind: Delay, Delay: time.Nanosecond},
		{Kind: Duplicate},
		{Kind: Truncate},
		{Kind: Truncate, TruncateAfter: TruncateBytesMax},
	} {
		handle, installErr := controller.Install(link, rule)
		if installErr != nil {
			t.Fatalf("Install(valid %+v): %v", rule, installErr)
		}
		if removeErr := controller.Remove(handle); removeErr != nil {
			t.Fatalf("Remove(valid %+v): %v", rule, removeErr)
		}
	}
}

func TestControllerBoundsActiveRulesAndConnections(t *testing.T) {
	t.Run("active rules", func(t *testing.T) {
		controller := newFaultnetTestController(t, time.Second)
		handles := make([]Handle, 0, ActiveRulesMax)
		for index := 0; index < ActiveRulesMax; index++ {
			handle, err := controller.Install(
				faultnetTestLink(1, index+2),
				Rule{Kind: Drop},
			)
			if err != nil {
				t.Fatalf("Install(rule %d): %v", index, err)
			}
			handles = append(handles, handle)
		}
		if _, err := controller.Install(
			faultnetTestLink(1, ActiveRulesMax+2),
			Rule{Kind: Drop},
		); !errors.Is(err, ErrRuleCapacity) {
			t.Fatalf("Install(over capacity) error = %v", err)
		}
		for _, handle := range handles {
			if err := controller.Remove(handle); err != nil {
				t.Fatalf("Remove(capacity handle): %v", err)
			}
		}
	})

	t.Run("tracked connections", func(t *testing.T) {
		controller := newFaultnetTestController(t, time.Second)
		wrapped := make([]net.Conn, 0, TrackedConnectionsMax)
		peers := make([]net.Conn, 0, TrackedConnectionsMax)
		defer func() {
			for _, connection := range wrapped {
				_ = connection.Close()
			}
			for _, peer := range peers {
				_ = peer.Close()
			}
		}()

		for index := 0; index < TrackedConnectionsMax; index++ {
			local, peer := net.Pipe()
			connection, err := controller.Wrap(
				local,
				faultnetTestDeviceID(1),
				faultnetTestDeviceID(2),
			)
			if err != nil {
				_ = local.Close()
				_ = peer.Close()
				t.Fatalf("Wrap(connection %d): %v", index, err)
			}
			wrapped = append(wrapped, connection)
			peers = append(peers, peer)
		}

		extra, extraPeer := net.Pipe()
		defer extra.Close()
		defer extraPeer.Close()
		if connection, err := controller.Wrap(
			extra,
			faultnetTestDeviceID(1),
			faultnetTestDeviceID(2),
		); connection != nil || !errors.Is(err, ErrConnectionCapacity) {
			t.Fatalf("Wrap(over capacity) = (%v, %v)", connection, err)
		}
	})
}

func TestControllerHandlesAreGenerationAndControllerSafe(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)

	first, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(first): %v", err)
	}
	if err := controller.Remove(first); err != nil {
		t.Fatalf("Remove(first): %v", err)
	}
	if err := controller.Remove(first); err != nil {
		t.Fatalf("Remove(first duplicate): %v", err)
	}
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		first,
		1,
	); !errors.Is(err, ErrRuleInactive) {
		t.Fatalf("WaitForHits(removed) error = %v", err)
	}

	second, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(second): %v", err)
	}
	if second.generation <= first.generation {
		t.Fatalf(
			"replacement generation = %d, want after %d",
			second.generation,
			first.generation,
		)
	}
	if err := controller.Remove(first); !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("Remove(stale first) error = %v", err)
	}
	if _, err := controller.Install(
		link,
		Rule{Kind: Drop},
	); !errors.Is(err, ErrRuleActive) {
		t.Fatalf("stale removal cleared replacement: %v", err)
	}

	waitContext, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if err := controller.WaitForHits(
		waitContext,
		second,
		1,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForHits(canceled) error = %v", err)
	}

	other := newFaultnetTestController(t, time.Second)
	if _, err := other.Snapshot(second); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("Snapshot(foreign handle) error = %v", err)
	}
	if err := controller.Remove(second); err != nil {
		t.Fatalf("Remove(second): %v", err)
	}
}

func TestRuleConnectionBookkeepingIsBoundedAcrossReconnects(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	handle, err := controller.Install(link, Rule{Kind: Duplicate})
	if err != nil {
		t.Fatalf("Install(Duplicate): %v", err)
	}

	const reconnects = TrackedConnectionsMax * 2
	for index := 0; index < reconnects; index++ {
		raw := newFaultnetRecordingConn()
		wrapped, err := controller.Wrap(raw, link.From, link.To)
		if err != nil {
			t.Fatalf("Wrap(%d): %v", index, err)
		}
		if count, err := wrapped.Write([]byte("x")); count != 1 || err != nil {
			t.Fatalf("Write(%d) = (%d, %v)", index, count, err)
		}
		if err := wrapped.Close(); err != nil {
			t.Fatalf("Close(%d): %v", index, err)
		}
	}

	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.ActiveConnections != 0 ||
		snapshot.ConnectionsHit != reconnects ||
		snapshot.ClosedConnections != reconnects {
		t.Fatalf("reconnect snapshot = %+v", snapshot)
	}
	handle.state.mu.Lock()
	active := len(handle.state.connections)
	touched := len(handle.state.touched)
	handle.state.mu.Unlock()
	if active != 0 || touched != 0 {
		t.Fatalf(
			"retained connection state = (active %d, touched %d)",
			active,
			touched,
		)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Duplicate): %v", err)
	}
}

func TestRemoveBlocksReplacementUntilDestructiveCleanupFinishes(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetBlockingCloseConn()
	t.Cleanup(raw.release)
	wrapped, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Duplicate})
	if err != nil {
		t.Fatalf("Install(Duplicate): %v", err)
	}
	if count, err := wrapped.Write([]byte("touch")); count != 5 || err != nil {
		t.Fatalf("Write() = (%d, %v)", count, err)
	}

	removed := make(chan error, 1)
	go func() {
		removed <- controller.Remove(handle)
	}()
	faultnetReceive(t, raw.closeStarted)
	if _, err := controller.Install(
		link,
		Rule{Kind: Drop},
	); !errors.Is(err, ErrRuleActive) {
		t.Fatalf("Install(during cleanup) error = %v", err)
	}
	raw.release()
	if err := faultnetReceive(t, removed); err != nil {
		t.Fatalf("Remove(Duplicate): %v", err)
	}

	replacement, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(after cleanup): %v", err)
	}
	if err := controller.Remove(replacement); err != nil {
		t.Fatalf("Remove(replacement): %v", err)
	}
}

func TestRemoveCancelsDelayedOperationBeforeReplacement(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetRecordingConn()
	wrapped, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(
		link,
		Rule{Kind: Delay, Delay: 500 * time.Millisecond},
	)
	if err != nil {
		t.Fatalf("Install(Delay): %v", err)
	}
	write := faultnetWrite(wrapped, []byte("delayed"))
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Delay): %v", err)
	}
	result := faultnetReceive(t, write)
	if result.count != 0 || !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("delayed Write() = (%d, %v)", result.count, result.err)
	}

	replacement, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(after canceled delay): %v", err)
	}
	if err := controller.Remove(replacement); err != nil {
		t.Fatalf("Remove(replacement): %v", err)
	}
}

func TestRemoveCancelsDelayBlockedInUnderlyingIO(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	raw := newFaultnetWriteEnteredConn(local)
	wrapped, err := controller.Wrap(raw, link.From, link.To)
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
	write := faultnetWrite(wrapped, []byte("blocked"))
	faultnetReceive(t, raw.writeEntered)

	removed := make(chan error, 1)
	go func() {
		removed <- controller.Remove(handle)
	}()
	if err := faultnetReceive(t, removed); err != nil {
		t.Fatalf("Remove(Delay): %v", err)
	}
	result := faultnetReceive(t, write)
	if result.count != 0 || !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("blocked delayed Write() = (%d, %v)", result.count, result.err)
	}

	replacement, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(after blocked delay): %v", err)
	}
	if err := controller.Remove(replacement); err != nil {
		t.Fatalf("Remove(replacement): %v", err)
	}
}

func TestSnapshotActiveConnectionsAreGenerationExact(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	raw := newFaultnetRecordingConn()
	wrapped, err := controller.Wrap(raw, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	first, err := controller.Install(
		link,
		Rule{Kind: Delay, Delay: time.Nanosecond},
	)
	if err != nil {
		t.Fatalf("Install(first): %v", err)
	}
	if count, err := wrapped.Write([]byte("first")); count != 5 || err != nil {
		t.Fatalf("Write(first) = (%d, %v)", count, err)
	}
	if err := controller.Remove(first); err != nil {
		t.Fatalf("Remove(first): %v", err)
	}

	second, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(second): %v", err)
	}
	write := faultnetWrite(wrapped, []byte("second"))
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		second,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(second): %v", err)
	}
	firstSnapshot, err := controller.Snapshot(first)
	if err != nil {
		t.Fatalf("Snapshot(first): %v", err)
	}
	secondSnapshot, err := controller.Snapshot(second)
	if err != nil {
		t.Fatalf("Snapshot(second): %v", err)
	}
	if firstSnapshot.ActiveConnections != 0 ||
		secondSnapshot.ActiveConnections != 1 {
		t.Fatalf(
			"generation snapshots = (first %+v, second %+v)",
			firstSnapshot,
			secondSnapshot,
		)
	}
	if err := controller.Remove(second); err != nil {
		t.Fatalf("Remove(second): %v", err)
	}
	assertFaultnetSuccessfulWrite(
		t,
		faultnetReceive(t, write),
		len("second"),
	)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
}

func TestControllerCloseIsConcurrentAndUnblocksOperations(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	wrapped, err := controller.Wrap(local, link.From, link.To)
	if err != nil {
		t.Fatalf("Wrap(): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(Drop): %v", err)
	}

	const operations = 16
	results := make(chan faultnetIOResult, operations)
	for index := 0; index < operations; index++ {
		go func() {
			count, writeErr := wrapped.Write([]byte("blocked"))
			results <- faultnetIOResult{count: count, err: writeErr}
		}()
	}
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}

	const closers = 16
	closeResults := make(chan error, closers)
	for index := 0; index < closers; index++ {
		go func() {
			closeResults <- controller.Close()
		}()
	}
	for index := 0; index < closers; index++ {
		if closeErr := faultnetReceive(t, closeResults); closeErr != nil {
			t.Fatalf("concurrent Close() error = %v", closeErr)
		}
	}
	for index := 0; index < operations; index++ {
		result := faultnetReceive(t, results)
		if result.count != 0 ||
			!errors.Is(result.err, ErrControllerClosed) {
			t.Fatalf("blocked Write() = (%d, %v)", result.count, result.err)
		}
	}

	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.ActiveConnections != 0 || snapshot.Hits != 1 {
		t.Fatalf("post-close snapshot = %+v", snapshot)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(after controller close): %v", err)
	}
	if _, err := controller.Install(
		link,
		Rule{Kind: Drop},
	); !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("Install(after close) error = %v", err)
	}
}

func TestFaultConnectionContextCancellationOwnsLifetime(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	link := faultnetTestLink(1, 2)
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	connectionContext, cancelConnection := context.WithCancel(
		context.Background(),
	)
	wrapped, err := controller.WrapContext(
		connectionContext,
		local,
		link.From,
		link.To,
	)
	if err != nil {
		t.Fatalf("WrapContext(): %v", err)
	}
	handle, err := controller.Install(link, Rule{Kind: Drop})
	if err != nil {
		t.Fatalf("Install(Drop): %v", err)
	}

	result := make(chan faultnetIOResult, 1)
	go func() {
		count, writeErr := wrapped.Write([]byte("blocked"))
		result <- faultnetIOResult{count: count, err: writeErr}
	}()
	if err := controller.WaitForHits(
		faultnetTestContext(t),
		handle,
		1,
	); err != nil {
		t.Fatalf("WaitForHits(): %v", err)
	}
	cancelConnection()
	writeResult := faultnetReceive(t, result)
	if writeResult.count != 0 ||
		!errors.Is(writeResult.err, context.Canceled) {
		t.Fatalf(
			"Write(after context cancel) = (%d, %v)",
			writeResult.count,
			writeResult.err,
		)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close(after context cancel): %v", err)
	}
	snapshot, err := controller.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if snapshot.ActiveConnections != 0 {
		t.Fatalf("active connections after cancellation = %d", snapshot.ActiveConnections)
	}
	if err := controller.Remove(handle); err != nil {
		t.Fatalf("Remove(Drop): %v", err)
	}
}

func TestWaitForHitsHonorsContextDeadline(t *testing.T) {
	controller := newFaultnetTestController(t, time.Second)
	handle, err := controller.Install(
		faultnetTestLink(1, 2),
		Rule{Kind: Drop},
	)
	if err != nil {
		t.Fatalf("Install(Drop): %v", err)
	}
	ctx, cancel := context.WithDeadline(
		context.Background(),
		time.Now().Add(20*time.Millisecond),
	)
	defer cancel()
	if err := controller.WaitForHits(
		ctx,
		handle,
		1,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForHits(deadline) error = %v", err)
	}
}

type faultnetIOResult struct {
	count int
	data  []byte
	err   error
}

type faultnetBlockingCloseConn struct {
	*faultnetRecordingConn
	closeStarted chan struct{}
	releaseClose chan struct{}
	releaseOnce  sync.Once
}

type faultnetWriteEnteredConn struct {
	net.Conn
	writeEntered chan struct{}
	once         sync.Once
}

func newFaultnetWriteEnteredConn(connection net.Conn) *faultnetWriteEnteredConn {
	return &faultnetWriteEnteredConn{
		Conn:         connection,
		writeEntered: make(chan struct{}),
	}
}

func (connection *faultnetWriteEnteredConn) Write(buffer []byte) (int, error) {
	connection.once.Do(func() {
		close(connection.writeEntered)
	})
	return connection.Conn.Write(buffer)
}

func newFaultnetBlockingCloseConn() *faultnetBlockingCloseConn {
	return &faultnetBlockingCloseConn{
		faultnetRecordingConn: newFaultnetRecordingConn(),
		closeStarted:          make(chan struct{}),
		releaseClose:          make(chan struct{}),
	}
}

func (connection *faultnetBlockingCloseConn) Close() error {
	close(connection.closeStarted)
	<-connection.releaseClose
	return connection.faultnetRecordingConn.Close()
}

func (connection *faultnetBlockingCloseConn) release() {
	connection.releaseOnce.Do(func() {
		close(connection.releaseClose)
	})
}

func newFaultnetTestController(
	t *testing.T,
	maxDelay time.Duration,
) *Controller {
	t.Helper()
	controller, err := NewController(maxDelay)
	if err != nil {
		t.Fatalf("NewController(): %v", err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Errorf("Controller.Close(): %v", err)
		}
	})
	return controller
}

func faultnetTestDeviceID(value int) domain.DeviceID {
	return domain.DeviceID(fmt.Sprintf("cc1%064x", value))
}

func faultnetTestLink(from, to int) Link {
	return Link{
		From: faultnetTestDeviceID(from),
		To:   faultnetTestDeviceID(to),
	}
}

func faultnetTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), faultnetTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

func faultnetReceive[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	timer := time.NewTimer(faultnetTestTimeout)
	defer timer.Stop()
	select {
	case value := <-values:
		return value
	case <-timer.C:
		t.Fatal("timed out waiting for synchronized test result")
		var zero T
		return zero
	}
}

func faultnetAssertPending[T any](t *testing.T, values <-chan T) {
	t.Helper()
	select {
	case value := <-values:
		t.Fatalf("operation completed before release: %+v", value)
	default:
	}
}

func faultnetAssertDeadline(t *testing.T, result faultnetIOResult) {
	t.Helper()
	if result.count != 0 ||
		!errors.Is(result.err, os.ErrDeadlineExceeded) {
		t.Fatalf("operation = (%d, %v), want deadline", result.count, result.err)
	}
}
