package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDaemonPeerListenerSetRebindsAndRecoversFromNoAddress(
	t *testing.T,
) {
	firstEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	secondEndpoint := netip.MustParseAddrPort("192.0.2.11:47831")
	thirdEndpoint := netip.MustParseAddrPort("192.0.2.12:47831")
	opened := make(map[netip.AddrPort][]*daemonPeerListenerStub)
	listen := func(
		_ context.Context,
		endpoint netip.AddrPort,
	) (net.Listener, error) {
		listener := newDaemonPeerListenerStub(endpoint)
		opened[endpoint] = append(opened[endpoint], listener)
		return listener, nil
	}
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{firstEndpoint},
		listen,
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	update, err := listeners.Replace(
		t.Context(),
		[]netip.AddrPort{secondEndpoint},
	)
	if err != nil {
		t.Fatalf("Replace(second): %v", err)
	}
	if !update.Changed ||
		!sameDaemonListeners(update.Previous, []netip.AddrPort{firstEndpoint}) ||
		!sameDaemonListeners(update.Current, []netip.AddrPort{secondEndpoint}) {
		t.Fatalf("second update = %+v", update)
	}
	assertDaemonPeerListenerClosed(t, opened[firstEndpoint][0])

	update, err = listeners.Replace(t.Context(), nil)
	if err != nil || !update.Changed || len(listeners.Current()) != 0 {
		t.Fatalf("Replace(empty) = (%+v, %v)", update, err)
	}
	assertDaemonPeerListenerClosed(t, opened[secondEndpoint][0])

	update, err = listeners.Replace(
		t.Context(),
		[]netip.AddrPort{thirdEndpoint},
	)
	if err != nil || !update.Changed ||
		!sameDaemonListeners(
			listeners.Current(),
			[]netip.AddrPort{thirdEndpoint},
		) {
		t.Fatalf("Replace(third) = (%+v, %v)", update, err)
	}
}

func TestDaemonPeerListenerSetBindFailureRetiresStaleGeneration(t *testing.T) {
	firstEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	secondEndpoint := netip.MustParseAddrPort("192.0.2.11:47831")
	thirdEndpoint := netip.MustParseAddrPort("192.0.2.12:47831")
	bindFailure := errors.New("bind failed")
	var first *daemonPeerListenerStub
	var partial *daemonPeerListenerStub
	listen := func(
		_ context.Context,
		endpoint netip.AddrPort,
	) (net.Listener, error) {
		switch endpoint {
		case firstEndpoint:
			first = newDaemonPeerListenerStub(endpoint)
			return first, nil
		case secondEndpoint:
			partial = newDaemonPeerListenerStub(endpoint)
			return partial, nil
		case thirdEndpoint:
			return nil, bindFailure
		default:
			return nil, errors.New("unexpected endpoint")
		}
	}
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{firstEndpoint},
		listen,
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	update, err := listeners.Replace(
		t.Context(),
		[]netip.AddrPort{secondEndpoint, thirdEndpoint},
	)
	if err != nil || !errors.Is(update.TransitionErr, bindFailure) {
		t.Fatalf(
			"Replace() = (%+v, %v), want transition error %v",
			update,
			err,
			bindFailure,
		)
	}
	if len(listeners.Current()) != 0 || !update.Changed {
		t.Fatalf("current endpoints after failure = %v", listeners.Current())
	}
	assertDaemonPeerListenerClosed(t, first)
	assertDaemonPeerListenerClosed(t, partial)
}

func TestDaemonPeerListenerSetPartialChangeRetiresBeforeRetainedRebind(
	t *testing.T,
) {
	firstEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	retainedEndpoint := netip.MustParseAddrPort("192.0.2.11:47831")
	replacementEndpoint := netip.MustParseAddrPort("192.0.2.12:47831")
	opened := make(map[netip.AddrPort][]*daemonPeerListenerStub)
	listen := func(
		_ context.Context,
		endpoint netip.AddrPort,
	) (net.Listener, error) {
		existing := opened[endpoint]
		if len(existing) != 0 &&
			existing[len(existing)-1].closeCalls.Load() == 0 {
			return nil, errors.New("address already in use")
		}
		listener := newDaemonPeerListenerStub(endpoint)
		opened[endpoint] = append(existing, listener)
		return listener, nil
	}
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{firstEndpoint, retainedEndpoint},
		listen,
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	update, err := listeners.Replace(
		t.Context(),
		[]netip.AddrPort{retainedEndpoint, replacementEndpoint},
	)
	if err != nil || update.TransitionErr != nil || !update.Changed {
		t.Fatalf("Replace(partial) = (%+v, %v)", update, err)
	}
	if !sameDaemonListeners(
		listeners.Current(),
		[]netip.AddrPort{retainedEndpoint, replacementEndpoint},
	) {
		t.Fatalf("current endpoints = %v", listeners.Current())
	}
	assertDaemonPeerListenerClosed(t, opened[firstEndpoint][0])
	assertDaemonPeerListenerClosed(t, opened[retainedEndpoint][0])
	if len(opened[retainedEndpoint]) != 2 {
		t.Fatalf(
			"retained endpoint opens = %d, want 2",
			len(opened[retainedEndpoint]),
		)
	}
}

func TestDaemonPeerListenerSetForcedRebindRefreshesSameEndpoint(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	opened := make([]*daemonPeerListenerStub, 0, 2)
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{endpoint},
		func(
			context.Context,
			netip.AddrPort,
		) (net.Listener, error) {
			if len(opened) != 0 &&
				opened[len(opened)-1].closeCalls.Load() == 0 {
				return nil, errors.New("address already in use")
			}
			listener := newDaemonPeerListenerStub(endpoint)
			opened = append(opened, listener)
			return listener, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	update, err := listeners.Rebind(
		t.Context(),
		[]netip.AddrPort{endpoint},
		true,
	)
	if err != nil || update.TransitionErr != nil || !update.Changed {
		t.Fatalf("Rebind(force) = (%+v, %v)", update, err)
	}
	if len(opened) != 2 {
		t.Fatalf("listener opens = %d, want 2", len(opened))
	}
	assertDaemonPeerListenerClosed(t, opened[0])
}

func TestDaemonPeerListenerSetCloseIsIdempotent(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	delegate := newDaemonPeerListenerStub(endpoint)
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{endpoint},
		func(
			context.Context,
			netip.AddrPort,
		) (net.Listener, error) {
			return delegate, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	if err := listeners.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	if err := listeners.Close(); err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	assertDaemonPeerListenerClosed(t, delegate)
}

func TestDaemonPeerListenerSetCloseCancelsBlockedRebind(t *testing.T) {
	initialEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	reboundEndpoint := netip.MustParseAddrPort("192.0.2.11:47831")
	initial := newDaemonPeerListenerStub(initialEndpoint)
	bindStarted := make(chan struct{})
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{initialEndpoint},
		func(
			ctx context.Context,
			endpoint netip.AddrPort,
		) (net.Listener, error) {
			if endpoint == initialEndpoint {
				return initial, nil
			}
			close(bindStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}

	rebindDone := make(chan daemonPeerListenerUpdate, 1)
	go func() {
		update, _ := listeners.Replace(
			context.Background(),
			[]netip.AddrPort{reboundEndpoint},
		)
		rebindDone <- update
	}()
	select {
	case <-bindStarted:
	case <-time.After(time.Second):
		t.Fatal("rebind did not reach the blocked listener")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- listeners.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close(): %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not cancel the blocked rebind")
	}
	select {
	case update := <-rebindDone:
		if !errors.Is(update.TransitionErr, context.Canceled) {
			t.Fatalf("rebind update = %+v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("rebind did not return after cancellation")
	}
	assertDaemonPeerListenerClosed(t, initial)
}

func TestDaemonPeerListenerSetRecoversExhaustedGeneration(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	exhausted := newDaemonTerminalPeerListener(endpoint)
	replacement := newDaemonPeerListenerStub(endpoint)
	opens := 0
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{endpoint},
		func(
			context.Context,
			netip.AddrPort,
		) (net.Listener, error) {
			opens++
			if opens == 1 {
				return exhausted, nil
			}
			return replacement, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	acceptDone := make(chan error, 1)
	go func() {
		_, acceptErr := listeners.Accept()
		acceptDone <- acceptErr
	}()
	exhausted.fail()
	deadline := time.Now().Add(time.Second)
	for len(listeners.Current()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("exhausted listener remained available")
		}
		time.Sleep(time.Millisecond)
	}

	update, err := listeners.Replace(
		t.Context(),
		[]netip.AddrPort{endpoint},
	)
	if err != nil || update.TransitionErr != nil || !update.Changed {
		t.Fatalf("Replace(exhausted) = (%+v, %v)", update, err)
	}
	if opens != 2 ||
		!sameDaemonListeners(
			listeners.Current(),
			[]netip.AddrPort{endpoint},
		) {
		t.Fatalf(
			"recovered listener state = opens %d, current %v",
			opens,
			listeners.Current(),
		)
	}
	_ = listeners.Close()
	select {
	case err := <-acceptDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() after Close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() remained blocked after Close")
	}
}

func TestDaemonPeerListenerOrNilPreservesNil(t *testing.T) {
	if listener := daemonPeerListenerOrNil(nil); listener != nil {
		t.Fatalf("daemonPeerListenerOrNil(nil) = %#v", listener)
	}
}

type daemonPeerListenerStub struct {
	endpoint netip.AddrPort
	closed   chan struct{}
	close    sync.Once

	closeCalls atomic.Int32
}

func newDaemonPeerListenerStub(
	endpoint netip.AddrPort,
) *daemonPeerListenerStub {
	return &daemonPeerListenerStub{
		endpoint: endpoint,
		closed:   make(chan struct{}),
	}
}

func (listener *daemonPeerListenerStub) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *daemonPeerListenerStub) Close() error {
	listener.close.Do(func() {
		listener.closeCalls.Add(1)
		close(listener.closed)
	})
	return nil
}

func (listener *daemonPeerListenerStub) Addr() net.Addr {
	return daemonPeerListenerStubAddress(listener.endpoint.String())
}

type daemonPeerListenerStubAddress string

func (daemonPeerListenerStubAddress) Network() string { return "tcp" }
func (address daemonPeerListenerStubAddress) String() string {
	return string(address)
}

func assertDaemonPeerListenerClosed(
	t *testing.T,
	listener *daemonPeerListenerStub,
) {
	t.Helper()
	if listener == nil || listener.closeCalls.Load() != 1 {
		t.Fatalf("listener close calls = %v, want 1", listener)
	}
}

var _ net.Listener = (*daemonPeerListenerStub)(nil)

type daemonTerminalPeerListener struct {
	endpoint netip.AddrPort
	failures chan struct{}
	closed   chan struct{}
	failOnce sync.Once
	close    sync.Once
}

func newDaemonTerminalPeerListener(
	endpoint netip.AddrPort,
) *daemonTerminalPeerListener {
	return &daemonTerminalPeerListener{
		endpoint: endpoint,
		failures: make(chan struct{}),
		closed:   make(chan struct{}),
	}
}

func (listener *daemonTerminalPeerListener) Accept() (net.Conn, error) {
	select {
	case <-listener.failures:
		return nil, errors.New("terminal accept failure")
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *daemonTerminalPeerListener) Close() error {
	listener.close.Do(func() {
		close(listener.closed)
	})
	return nil
}

func (listener *daemonTerminalPeerListener) Addr() net.Addr {
	return daemonPeerListenerStubAddress(listener.endpoint.String())
}

func (listener *daemonTerminalPeerListener) fail() {
	listener.failOnce.Do(func() {
		close(listener.failures)
	})
}

var _ net.Listener = (*daemonTerminalPeerListener)(nil)
