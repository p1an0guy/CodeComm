package transport

import (
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const aggregateListenerTestTimeout = 5 * time.Second

func TestAggregateListenerAcceptsEveryBoundEndpoint(t *testing.T) {
	t.Parallel()

	first := newAggregateTCPListener(t)
	second := newAggregateTCPListener(t)
	owned := false
	defer func() {
		if !owned {
			_ = first.Close()
			_ = second.Close()
		}
	}()

	listener, err := NewAggregateListener(second, first)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}
	owned = true
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("Close() cleanup error = %v", err)
		}
	})

	endpoints := []string{first.Addr().String(), second.Addr().String()}
	sort.Strings(endpoints)
	wantAddress := strings.Join(endpoints, ",")
	if got := listener.Addr(); got.Network() != "tcp" ||
		got.String() != wantAddress {
		t.Fatalf(
			"Addr() = (%q, %q), want (%q, %q)",
			got.Network(),
			got.String(),
			"tcp",
			wantAddress,
		)
	}

	clients := make([]net.Conn, 0, len(endpoints))
	for index, endpoint := range []string{
		first.Addr().String(),
		second.Addr().String(),
	} {
		connection, dialErr := net.DialTimeout(
			"tcp4",
			endpoint,
			aggregateListenerTestTimeout,
		)
		if dialErr != nil {
			t.Fatalf("dial endpoint %d: %v", index, dialErr)
		}
		clients = append(clients, connection)
		t.Cleanup(func() { _ = connection.Close() })
		if _, writeErr := connection.Write([]byte{byte(index + 1)}); writeErr != nil {
			t.Fatalf("write endpoint %d marker: %v", index, writeErr)
		}
	}

	seen := make(map[byte]bool, len(clients))
	for range clients {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatalf("Accept() error = %v", acceptErr)
		}
		if deadlineErr := connection.SetReadDeadline(
			time.Now().Add(aggregateListenerTestTimeout),
		); deadlineErr != nil {
			_ = connection.Close()
			t.Fatalf("SetReadDeadline(): %v", deadlineErr)
		}
		var marker [1]byte
		_, readErr := io.ReadFull(connection, marker[:])
		_ = connection.Close()
		if readErr != nil {
			t.Fatalf("read accepted marker: %v", readErr)
		}
		seen[marker[0]] = true
	}
	if !seen[1] || !seen[2] || len(seen) != 2 {
		t.Fatalf("accepted endpoint markers = %v, want 1 and 2", seen)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := listener.Addr().String(); got != wantAddress {
		t.Fatalf("Addr() after Close = %q, want stable %q", got, wantAddress)
	}
}

func TestAggregateListenerValidationDoesNotTakeOwnership(t *testing.T) {
	t.Parallel()

	var typedNilListener *aggregateTestListener
	var typedNilAddress *aggregateTestAddress
	tests := []struct {
		name      string
		listeners func() ([]net.Listener, []*aggregateTestListener)
	}{
		{
			name: "empty",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				return nil, nil
			},
		},
		{
			name: "nil listener",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				valid := newAggregateTestListener("127.0.0.1:41001")
				return []net.Listener{valid, nil}, []*aggregateTestListener{valid}
			},
		},
		{
			name: "typed nil listener",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				valid := newAggregateTestListener("127.0.0.1:41002")
				return []net.Listener{
					valid,
					typedNilListener,
				}, []*aggregateTestListener{valid}
			},
		},
		{
			name: "nil address",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListenerWithAddress(nil)
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "typed nil address",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListenerWithAddress(typedNilAddress)
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "empty address",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListener("")
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "malformed address",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListener("not-an-endpoint")
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "zero port",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListener("127.0.0.1:0")
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "IPv4 wildcard",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListener("0.0.0.0:41003")
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "IPv6 wildcard",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListener("[::]:41004")
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "unsupported network",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				invalid := newAggregateTestListenerWithAddress(
					&aggregateTestAddress{
						network:  "udp",
						endpoint: "127.0.0.1:41005",
					},
				)
				return []net.Listener{invalid}, []*aggregateTestListener{invalid}
			},
		},
		{
			name: "duplicate address",
			listeners: func() ([]net.Listener, []*aggregateTestListener) {
				first := newAggregateTestListener("127.0.0.1:41006")
				second := newAggregateTestListener(
					"[::ffff:127.0.0.1]:41006",
				)
				return []net.Listener{
					first,
					second,
				}, []*aggregateTestListener{first, second}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			listeners, tracked := test.listeners()
			aggregate, err := NewAggregateListener(listeners...)
			if aggregate != nil {
				_ = aggregate.Close()
				t.Fatal("NewAggregateListener() returned a listener")
			}
			if !errors.Is(err, ErrInvalidAggregateListener) {
				t.Fatalf(
					"NewAggregateListener() error = %v, want %v",
					err,
					ErrInvalidAggregateListener,
				)
			}
			for index, listener := range tracked {
				if got := listener.closeCalls.Load(); got != 0 {
					t.Fatalf("listener %d close calls = %d, want 0", index, got)
				}
				if got := listener.acceptCalls.Load(); got != 0 {
					t.Fatalf("listener %d accept calls = %d, want 0", index, got)
				}
			}
		})
	}
}

func TestAggregateListenerCloseUnblocksConcurrentAcceptsAndIsIdempotent(
	t *testing.T,
) {
	t.Parallel()

	children := []*aggregateTestListener{
		newAggregateTestListener("127.0.0.1:42001"),
		newAggregateTestListener("127.0.0.1:42002"),
		newAggregateTestListener("127.0.0.1:42003"),
	}
	listeners := make([]net.Listener, len(children))
	for index, child := range children {
		listeners[index] = child
	}
	listener, err := NewAggregateListener(listeners...)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}
	for index, child := range children {
		awaitAggregateSignal(t, child.acceptStarted, "child accept start")
		if child.acceptCalls.Load() == 0 {
			t.Fatalf("listener %d did not enter Accept", index)
		}
	}

	const (
		acceptors = 32
		closers   = 16
	)
	start := make(chan struct{})
	acceptResults := make(chan aggregateAcceptResult, acceptors)
	closeResults := make(chan error, closers)
	for range acceptors {
		go func() {
			<-start
			connection, acceptErr := listener.Accept()
			acceptResults <- aggregateAcceptResult{
				connection: connection,
				err:        acceptErr,
			}
		}()
	}
	for range closers {
		go func() {
			<-start
			closeResults <- listener.Close()
		}()
	}
	close(start)

	for range acceptors {
		result := awaitAggregateValue(t, acceptResults, "concurrent Accept")
		if result.connection != nil || !errors.Is(result.err, net.ErrClosed) {
			if result.connection != nil {
				_ = result.connection.Close()
			}
			t.Fatalf(
				"Accept() = (%v, %v), want (nil, %v)",
				result.connection,
				result.err,
				net.ErrClosed,
			)
		}
	}
	for range closers {
		if closeErr := awaitAggregateValue(
			t,
			closeResults,
			"concurrent Close",
		); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	for index, child := range children {
		if got := child.closeCalls.Load(); got != 1 {
			t.Fatalf("listener %d close calls = %d, want 1", index, got)
		}
	}
}

func TestAggregateListenerCloseDiscardsPendingConnection(t *testing.T) {
	t.Parallel()

	child := newAggregateTestListener("127.0.0.1:43001")
	listener, err := NewAggregateListener(child)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	returned := make(chan struct{})
	child.outcomes <- aggregateTestOutcome{
		connection: server,
		returned:   returned,
	}
	awaitAggregateSignal(t, returned, "child accepted connection")

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	deadlineErr := client.SetReadDeadline(
		time.Now().Add(aggregateListenerTestTimeout),
	)
	if deadlineErr != nil &&
		!errors.Is(deadlineErr, net.ErrClosed) &&
		!errors.Is(deadlineErr, io.ErrClosedPipe) {
		t.Fatalf("SetReadDeadline(): %v", deadlineErr)
	}
	if deadlineErr == nil {
		var buffer [1]byte
		if _, err := client.Read(buffer[:]); err == nil {
			t.Fatal("pending accepted connection remained open")
		}
	}
	if got := child.closeCalls.Load(); got != 1 {
		t.Fatalf("child close calls = %d, want 1", got)
	}
}

func TestAggregateListenerContinuesAfterEndpointFailureAndTemporaryError(
	t *testing.T,
) {
	t.Parallel()

	failed := newAggregateTestListener("127.0.0.1:44001")
	survivor := newAggregateTestListener("127.0.0.1:44002")
	listener, err := NewAggregateListener(failed, survivor)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	failed.outcomes <- aggregateTestOutcome{
		err: errors.New("endpoint failed"),
	}
	temporary := aggregateTestTemporaryError{}
	survivor.outcomes <- aggregateTestOutcome{err: temporary}
	connection, err := listener.Accept()
	if connection != nil || !errors.As(err, &temporary) {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("Accept() temporary result = (%v, %v)", connection, err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	survivor.outcomes <- aggregateTestOutcome{connection: server}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() after endpoint failure error = %v", err)
	}
	if accepted != server {
		_ = accepted.Close()
		t.Fatalf("Accept() connection = %p, want %p", accepted, server)
	}
	_ = accepted.Close()
}

func TestAggregateListenerReportsAllEndpointsUnavailable(t *testing.T) {
	t.Parallel()

	firstError := errors.New("first endpoint failed")
	secondError := errors.New("second endpoint failed")
	first := newAggregateTestListener("127.0.0.1:45001")
	second := newAggregateTestListener("127.0.0.1:45002")
	listener, err := NewAggregateListener(first, second)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	first.outcomes <- aggregateTestOutcome{err: firstError}
	second.outcomes <- aggregateTestOutcome{err: secondError}

	connection, err := listener.Accept()
	if connection != nil {
		_ = connection.Close()
		t.Fatal("Accept() returned a connection")
	}
	for _, want := range []error{
		ErrAggregateListenerUnavailable,
		firstError,
		secondError,
	} {
		if !errors.Is(err, want) {
			t.Fatalf("Accept() error = %v, want errors.Is(%v)", err, want)
		}
	}
}

func TestAggregateListenerCloseReturnsStableJoinedErrors(t *testing.T) {
	t.Parallel()

	firstError := errors.New("close first")
	secondError := errors.New("close second")
	first := newAggregateTestListener("127.0.0.1:46001")
	first.closeErr = firstError
	second := newAggregateTestListener("127.0.0.1:46002")
	second.closeErr = secondError
	listener, err := NewAggregateListener(first, second)
	if err != nil {
		t.Fatalf("NewAggregateListener() error = %v", err)
	}

	for attempt := range 2 {
		err := listener.Close()
		if !errors.Is(err, firstError) || !errors.Is(err, secondError) {
			t.Fatalf("Close() attempt %d error = %v", attempt, err)
		}
	}
	if first.closeCalls.Load() != 1 || second.closeCalls.Load() != 1 {
		t.Fatalf(
			"child close calls = (%d, %d), want (1, 1)",
			first.closeCalls.Load(),
			second.closeCalls.Load(),
		)
	}
}

type aggregateTestAddress struct {
	network  string
	endpoint string
}

func (address *aggregateTestAddress) Network() string {
	return address.network
}

func (address *aggregateTestAddress) String() string {
	return address.endpoint
}

type aggregateTestOutcome struct {
	connection net.Conn
	err        error
	returned   chan struct{}
}

type aggregateTestListener struct {
	address net.Addr

	outcomes      chan aggregateTestOutcome
	closed        chan struct{}
	acceptStarted chan struct{}

	acceptStartOnce sync.Once
	closeOnce       sync.Once
	acceptCalls     atomic.Int32
	closeCalls      atomic.Int32
	closeErr        error
}

func newAggregateTestListener(endpoint string) *aggregateTestListener {
	return newAggregateTestListenerWithAddress(&aggregateTestAddress{
		network:  "tcp",
		endpoint: endpoint,
	})
}

func newAggregateTestListenerWithAddress(
	address net.Addr,
) *aggregateTestListener {
	return &aggregateTestListener{
		address:       address,
		outcomes:      make(chan aggregateTestOutcome, 4),
		closed:        make(chan struct{}),
		acceptStarted: make(chan struct{}),
	}
}

func (listener *aggregateTestListener) Accept() (net.Conn, error) {
	listener.acceptCalls.Add(1)
	listener.acceptStartOnce.Do(func() {
		close(listener.acceptStarted)
	})
	select {
	case outcome := <-listener.outcomes:
		if outcome.returned != nil {
			close(outcome.returned)
		}
		return outcome.connection, outcome.err
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *aggregateTestListener) Close() error {
	listener.closeCalls.Add(1)
	listener.closeOnce.Do(func() {
		close(listener.closed)
	})
	return listener.closeErr
}

func (listener *aggregateTestListener) Addr() net.Addr {
	return listener.address
}

type aggregateTestTemporaryError struct{}

func (aggregateTestTemporaryError) Error() string   { return "temporary" }
func (aggregateTestTemporaryError) Timeout() bool   { return false }
func (aggregateTestTemporaryError) Temporary() bool { return true }

func newAggregateTCPListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	return listener
}

func awaitAggregateSignal(
	t *testing.T,
	signal <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(aggregateListenerTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitAggregateValue[T any](
	t *testing.T,
	values <-chan T,
	description string,
) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(aggregateListenerTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}
