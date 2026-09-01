package transport

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const rebindableListenerTestTimeout = 5 * time.Second

func TestRebindableListenerReplacesGenerationAndPreservesConnection(
	t *testing.T,
) {
	t.Parallel()

	first := newRebindTestListener("127.0.0.1:47001")
	second := newRebindTestListener("127.0.0.1:47002")
	third := newRebindTestListener("127.0.0.1:47003")
	listener, err := NewRebindableListener(first)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	acceptResult := make(chan rebindAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		acceptResult <- rebindAcceptResult{
			connection: connection,
			err:        acceptErr,
		}
	}()

	if err := listener.Replace(second); err != nil {
		t.Fatalf("Replace(second) error = %v", err)
	}
	assertRebindListenerRetired(t, first, "first")
	assertRebindAddress(t, listener.Addr(), "127.0.0.1:47002")

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	second.outcomes <- rebindTestOutcome{connection: server}
	result := awaitRebindValue(t, acceptResult, "replacement Accept")
	if result.err != nil {
		t.Fatalf("Accept() error = %v", result.err)
	}
	if result.connection != server {
		_ = result.connection.Close()
		t.Fatalf(
			"Accept() connection = %p, want %p",
			result.connection,
			server,
		)
	}

	if err := listener.Replace(third); err != nil {
		t.Fatalf("Replace(third) error = %v", err)
	}
	assertRebindListenerRetired(t, second, "second")
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := client.Write([]byte{0x5a})
		writeResult <- writeErr
	}()
	if err := result.connection.SetReadDeadline(
		time.Now().Add(rebindableListenerTestTimeout),
	); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	var marker [1]byte
	if _, err := io.ReadFull(result.connection, marker[:]); err != nil {
		t.Fatalf("read accepted connection after replacement: %v", err)
	}
	if marker[0] != 0x5a {
		t.Fatalf("accepted marker = %#x, want %#x", marker[0], byte(0x5a))
	}
	if err := awaitRebindValue(
		t,
		writeResult,
		"accepted connection write",
	); err != nil {
		t.Fatalf("write accepted connection after replacement: %v", err)
	}
}

func TestRebindableListenerWaitsAcrossZeroListenerGeneration(t *testing.T) {
	t.Parallel()

	first := newRebindTestListener("127.0.0.1:47101")
	listener, err := NewRebindableListener(first)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	initialAddress := listener.Addr()
	if err := listener.Replace(); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	assertRebindListenerRetired(t, first, "first")
	assertRebindAddress(t, listener.Addr(), initialAddress.String())

	acceptResult := make(chan rebindAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		acceptResult <- rebindAcceptResult{
			connection: connection,
			err:        acceptErr,
		}
	}()

	second := newRebindTestListener("127.0.0.1:47102")
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	second.outcomes <- rebindTestOutcome{connection: server}
	if err := listener.Replace(second); err != nil {
		t.Fatalf("Replace(second) error = %v", err)
	}

	result := awaitRebindValue(t, acceptResult, "Accept after zero generation")
	if result.err != nil || result.connection != server {
		if result.connection != nil {
			_ = result.connection.Close()
		}
		t.Fatalf(
			"Accept() = (%v, %v), want (%p, nil)",
			result.connection,
			result.err,
			server,
		)
	}
	assertRebindAddress(t, listener.Addr(), "127.0.0.1:47102")
}

func TestRebindableListenerRecoversAfterGenerationExhaustion(t *testing.T) {
	t.Parallel()

	first := newRebindTestListener("127.0.0.1:47111")
	listener, err := NewRebindableListener(first)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	acceptResult := make(chan rebindAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		acceptResult <- rebindAcceptResult{
			connection: connection,
			err:        acceptErr,
		}
	}()
	first.outcomes <- rebindTestOutcome{
		err: errors.New("listener address vanished"),
	}
	awaitRebindListenerRetired(t, first, "exhausted first")

	second := newRebindTestListener("127.0.0.1:47112")
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	second.outcomes <- rebindTestOutcome{connection: server}
	if err := listener.Replace(second); err != nil {
		t.Fatalf("Replace(second) error = %v", err)
	}
	result := awaitRebindValue(
		t,
		acceptResult,
		"Accept after generation exhaustion",
	)
	if result.err != nil || result.connection != server {
		if result.connection != nil {
			_ = result.connection.Close()
		}
		t.Fatalf(
			"Accept() = (%v, %v), want (%p, nil)",
			result.connection,
			result.err,
			server,
		)
	}
}

func TestRebindableListenerInvalidReplacementRollsBackWithoutOwnership(
	t *testing.T,
) {
	t.Parallel()

	current := newRebindTestListener("127.0.0.1:47201")
	listener, err := NewRebindableListener(current)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	candidate := newRebindTestListener("127.0.0.1:47202")
	err = listener.Replace(candidate, nil)
	if !errors.Is(err, ErrInvalidAggregateListener) {
		t.Fatalf(
			"Replace(invalid) error = %v, want %v",
			err,
			ErrInvalidAggregateListener,
		)
	}
	if got := candidate.closeCalls.Load(); got != 0 {
		t.Fatalf("invalid candidate close calls = %d, want 0", got)
	}
	if got := candidate.acceptCalls.Load(); got != 0 {
		t.Fatalf("invalid candidate accept calls = %d, want 0", got)
	}
	if got := current.closeCalls.Load(); got != 0 {
		t.Fatalf("current close calls = %d, want 0", got)
	}
	assertRebindAddress(t, listener.Addr(), "127.0.0.1:47201")

	err = listener.Replace(listener)
	if !errors.Is(err, ErrInvalidAggregateListener) {
		t.Fatalf(
			"Replace(self) error = %v, want %v",
			err,
			ErrInvalidAggregateListener,
		)
	}
	if got := current.closeCalls.Load(); got != 0 {
		t.Fatalf("current close calls after self replacement = %d, want 0", got)
	}
	otherRebindable, otherErr := NewRebindableListener(candidate)
	if otherErr != nil {
		t.Fatalf("NewRebindableListener(candidate): %v", otherErr)
	}
	if err := listener.Replace(otherRebindable); !errors.Is(
		err,
		ErrInvalidAggregateListener,
	) {
		t.Fatalf(
			"Replace(rebindable) error = %v, want %v",
			err,
			ErrInvalidAggregateListener,
		)
	}
	if err := otherRebindable.Close(); err != nil {
		t.Fatalf("close other rebindable: %v", err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	current.outcomes <- rebindTestOutcome{connection: server}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() after invalid replacement error = %v", err)
	}
	if accepted != server {
		_ = accepted.Close()
		t.Fatalf("Accept() connection = %p, want %p", accepted, server)
	}
}

func TestRebindableListenerCloseUnblocksAcceptAndIsIdempotent(
	t *testing.T,
) {
	t.Parallel()

	closeFailure := errors.New("close failure")
	child := newRebindTestListener("127.0.0.1:47301")
	child.closeErr = closeFailure
	listener, err := NewRebindableListener(child)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}
	awaitRebindSignal(t, child.acceptStarted, "child Accept")

	const (
		acceptors = 32
		closers   = 16
	)
	start := make(chan struct{})
	acceptResults := make(chan rebindAcceptResult, acceptors)
	closeResults := make(chan error, closers)
	for range acceptors {
		go func() {
			<-start
			connection, acceptErr := listener.Accept()
			acceptResults <- rebindAcceptResult{
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
		result := awaitRebindValue(t, acceptResults, "blocked Accept")
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
		closeErr := awaitRebindValue(t, closeResults, "concurrent Close")
		if !errors.Is(closeErr, closeFailure) {
			t.Fatalf("Close() error = %v, want %v", closeErr, closeFailure)
		}
	}
	if err := listener.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("repeated Close() error = %v, want %v", err, closeFailure)
	}
	if got := child.closeCalls.Load(); got != 1 {
		t.Fatalf("child close calls = %d, want 1", got)
	}
	if got := child.activeAccepts.Load(); got != 0 {
		t.Fatalf("child active Accept calls = %d, want 0", got)
	}
	assertRebindAddress(t, listener.Addr(), "127.0.0.1:47301")

	candidate := newRebindTestListener("127.0.0.1:47302")
	if err := listener.Replace(candidate); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Replace() after Close error = %v, want %v", err, net.ErrClosed)
	}
	if candidate.closeCalls.Load() != 0 || candidate.acceptCalls.Load() != 0 {
		t.Fatal("Replace() after Close took ownership of candidate")
	}
}

func TestRebindableListenerRepeatedReplacementsRetireEveryWorker(
	t *testing.T,
) {
	t.Parallel()

	const replacements = 128
	children := make([]*rebindTestListener, 0, replacements+1)
	initial := newRebindTestListener("127.0.0.1:48001")
	children = append(children, initial)
	listener, err := NewRebindableListener(initial)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}

	for index := range replacements {
		next := newRebindTestListener(
			net.JoinHostPort(
				"127.0.0.1",
				strconv.Itoa(index+48002),
			),
		)
		children = append(children, next)
		if err := listener.Replace(next); err != nil {
			t.Fatalf("Replace(%d) error = %v", index, err)
		}
		assertRebindListenerRetired(t, children[index], "retired")
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for index, child := range children {
		if got := child.closeCalls.Load(); got != 1 {
			t.Fatalf("child %d close calls = %d, want 1", index, got)
		}
		if got := child.activeAccepts.Load(); got != 0 {
			t.Fatalf("child %d active Accept calls = %d, want 0", index, got)
		}
	}
}

func TestRebindableListenerConcurrentReplacementsAreSerialized(
	t *testing.T,
) {
	t.Parallel()

	initial := newRebindTestListener("127.0.0.1:47401")
	first := newRebindTestListener("127.0.0.1:47402")
	second := newRebindTestListener("127.0.0.1:47403")
	listener, err := NewRebindableListener(initial)
	if err != nil {
		t.Fatalf("NewRebindableListener() error = %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, replacement := range []*rebindTestListener{first, second} {
		go func() {
			<-start
			results <- listener.Replace(replacement)
		}()
	}
	close(start)
	for range 2 {
		if err := awaitRebindValue(t, results, "concurrent Replace"); err != nil {
			t.Fatalf("Replace() error = %v", err)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	for index, child := range []*rebindTestListener{initial, first, second} {
		if got := child.closeCalls.Load(); got != 1 {
			t.Fatalf("child %d close calls = %d, want 1", index, got)
		}
		if got := child.activeAccepts.Load(); got != 0 {
			t.Fatalf("child %d active Accept calls = %d, want 0", index, got)
		}
	}
}

func TestNewRebindableListenerRejectsInvalidInitialSetWithoutOwnership(
	t *testing.T,
) {
	t.Parallel()

	if listener, err := NewRebindableListener(); listener != nil ||
		!errors.Is(err, ErrInvalidAggregateListener) {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf(
			"NewRebindableListener() = (%v, %v), want (nil, %v)",
			listener,
			err,
			ErrInvalidAggregateListener,
		)
	}

	candidate := newRebindTestListener("127.0.0.1:47501")
	listener, err := NewRebindableListener(candidate, nil)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("NewRebindableListener(invalid) returned a listener")
	}
	if !errors.Is(err, ErrInvalidAggregateListener) {
		t.Fatalf(
			"NewRebindableListener(invalid) error = %v, want %v",
			err,
			ErrInvalidAggregateListener,
		)
	}
	if candidate.closeCalls.Load() != 0 || candidate.acceptCalls.Load() != 0 {
		t.Fatal("invalid construction took ownership of candidate")
	}
}

type rebindAcceptResult struct {
	connection net.Conn
	err        error
}

type rebindTestOutcome struct {
	connection net.Conn
	err        error
}

type rebindTestListener struct {
	address net.Addr

	outcomes      chan rebindTestOutcome
	closed        chan struct{}
	acceptStarted chan struct{}

	acceptStartOnce sync.Once
	closeOnce       sync.Once
	acceptCalls     atomic.Int32
	activeAccepts   atomic.Int32
	closeCalls      atomic.Int32
	closeErr        error
}

func newRebindTestListener(endpoint string) *rebindTestListener {
	return &rebindTestListener{
		address: rebindTestAddress{
			network:  "tcp",
			endpoint: endpoint,
		},
		outcomes:      make(chan rebindTestOutcome, 1),
		closed:        make(chan struct{}),
		acceptStarted: make(chan struct{}),
	}
}

func (listener *rebindTestListener) Accept() (net.Conn, error) {
	listener.acceptCalls.Add(1)
	listener.activeAccepts.Add(1)
	defer listener.activeAccepts.Add(-1)
	listener.acceptStartOnce.Do(func() {
		close(listener.acceptStarted)
	})
	select {
	case outcome := <-listener.outcomes:
		return outcome.connection, outcome.err
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *rebindTestListener) Close() error {
	listener.closeCalls.Add(1)
	listener.closeOnce.Do(func() {
		close(listener.closed)
	})
	return listener.closeErr
}

func (listener *rebindTestListener) Addr() net.Addr {
	return listener.address
}

type rebindTestAddress struct {
	network  string
	endpoint string
}

func (address rebindTestAddress) Network() string {
	return address.network
}

func (address rebindTestAddress) String() string {
	return address.endpoint
}

func assertRebindListenerRetired(
	t *testing.T,
	listener *rebindTestListener,
	description string,
) {
	t.Helper()
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("%s close calls = %d, want 1", description, got)
	}
	if got := listener.activeAccepts.Load(); got != 0 {
		t.Fatalf("%s active Accept calls = %d, want 0", description, got)
	}
}

func awaitRebindListenerRetired(
	t *testing.T,
	listener *rebindTestListener,
	description string,
) {
	t.Helper()
	deadline := time.Now().Add(rebindableListenerTestTimeout)
	for time.Now().Before(deadline) {
		if listener.closeCalls.Load() == 1 &&
			listener.activeAccepts.Load() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	assertRebindListenerRetired(t, listener, description)
}

func assertRebindAddress(t *testing.T, address net.Addr, endpoint string) {
	t.Helper()
	if address == nil {
		t.Fatal("Addr() returned nil")
	}
	if address.Network() != "tcp" || address.String() != endpoint {
		t.Fatalf(
			"Addr() = (%q, %q), want (%q, %q)",
			address.Network(),
			address.String(),
			"tcp",
			endpoint,
		)
	}
}

func awaitRebindSignal(
	t *testing.T,
	signal <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(rebindableListenerTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitRebindValue[T any](
	t *testing.T,
	values <-chan T,
	description string,
) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(rebindableListenerTestTimeout):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}
