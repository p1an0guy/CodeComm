package transport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
)

var (
	ErrInvalidAggregateListener = errors.New(
		"transport: invalid aggregate listener",
	)
	ErrAggregateListenerUnavailable = errors.New(
		"transport: all aggregate listener endpoints are unavailable",
	)
)

// AggregateListener presents multiple already-bound TCP listeners as one
// listener. It owns every supplied listener only after validation succeeds.
type AggregateListener struct {
	listeners []net.Listener
	address   aggregateListenerAddress

	accepted  chan aggregateAcceptResult
	closed    chan struct{}
	exhausted chan struct{}

	stateMu   sync.Mutex
	remaining int
	failures  []error
	work      sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

type aggregateAcceptResult struct {
	connection net.Conn
	err        error
}

type aggregateListenerAddress struct {
	description string
}

var _ net.Listener = (*AggregateListener)(nil)

// NewAggregateListener validates and takes ownership of one or more
// already-bound, literal-address TCP listeners.
func NewAggregateListener(
	listeners ...net.Listener,
) (*AggregateListener, error) {
	if len(listeners) == 0 {
		return nil, ErrInvalidAggregateListener
	}

	owned := append([]net.Listener(nil), listeners...)
	endpoints := make([]string, len(owned))
	seen := make(map[string]struct{}, len(owned))
	for index, listener := range owned {
		endpoint, err := aggregateListenerEndpoint(listener)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: listener %d: %v",
				ErrInvalidAggregateListener,
				index,
				err,
			)
		}
		if _, duplicate := seen[endpoint]; duplicate {
			return nil, fmt.Errorf(
				"%w: listener %d duplicates %s",
				ErrInvalidAggregateListener,
				index,
				endpoint,
			)
		}
		seen[endpoint] = struct{}{}
		endpoints[index] = endpoint
	}

	sort.Strings(endpoints)
	aggregate := &AggregateListener{
		listeners: owned,
		address: aggregateListenerAddress{
			description: strings.Join(endpoints, ","),
		},
		accepted:  make(chan aggregateAcceptResult),
		closed:    make(chan struct{}),
		exhausted: make(chan struct{}),
		remaining: len(owned),
	}
	aggregate.work.Add(len(owned))
	for _, listener := range owned {
		go aggregate.acceptFrom(listener)
	}
	return aggregate, nil
}

// Accept returns the next connection accepted by any owned listener.
func (listener *AggregateListener) Accept() (net.Conn, error) {
	if listener == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	default:
	}

	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	case result := <-listener.accepted:
		select {
		case <-listener.closed:
			if result.connection != nil {
				_ = result.connection.Close()
			}
			return nil, net.ErrClosed
		default:
		}
		return result.connection, result.err
	case <-listener.exhausted:
		select {
		case <-listener.closed:
			return nil, net.ErrClosed
		default:
			return nil, listener.unavailableError()
		}
	}
}

// Close closes every owned listener exactly once and waits for all accept
// workers to exit.
func (listener *AggregateListener) Close() error {
	if listener == nil {
		return net.ErrClosed
	}
	listener.closeOnce.Do(func() {
		close(listener.closed)
		closeErrors := make([]error, 0, len(listener.listeners))
		for _, owned := range listener.listeners {
			if err := owned.Close(); err != nil &&
				!errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		listener.work.Wait()
		listener.closeErr = errors.Join(closeErrors...)
	})
	return listener.closeErr
}

// Addr returns an immutable, canonical comma-separated description of every
// literal endpoint owned by the aggregate.
func (listener *AggregateListener) Addr() net.Addr {
	if listener == nil {
		return aggregateListenerAddress{}
	}
	return listener.address
}

func (listener *AggregateListener) acceptFrom(owned net.Listener) {
	defer listener.work.Done()

	var terminalError error
	defer func() {
		listener.workerStopped(terminalError)
	}()

	for {
		connection, err := owned.Accept()
		if err != nil {
			if connection != nil {
				_ = connection.Close()
			}
			if listener.isClosed() {
				return
			}
			if aggregateTemporaryNetworkError(err) {
				if !listener.publishAccept(aggregateAcceptResult{err: err}) {
					return
				}
				continue
			}
			terminalError = err
			return
		}
		if connection == nil {
			terminalError = errors.New(
				"transport: child listener returned a nil connection",
			)
			return
		}
		if !listener.publishAccept(aggregateAcceptResult{
			connection: connection,
		}) {
			_ = connection.Close()
			return
		}
	}
}

func (listener *AggregateListener) publishAccept(
	result aggregateAcceptResult,
) bool {
	select {
	case listener.accepted <- result:
		return true
	case <-listener.closed:
		return false
	}
}

func (listener *AggregateListener) workerStopped(err error) {
	listener.stateMu.Lock()
	if err != nil {
		listener.failures = append(listener.failures, err)
	}
	listener.remaining--
	if listener.remaining == 0 {
		close(listener.exhausted)
	}
	listener.stateMu.Unlock()
}

func (listener *AggregateListener) unavailableError() error {
	listener.stateMu.Lock()
	failures := append([]error(nil), listener.failures...)
	listener.stateMu.Unlock()

	errs := make([]error, 1, len(failures)+1)
	errs[0] = ErrAggregateListenerUnavailable
	errs = append(errs, failures...)
	return errors.Join(errs...)
}

func (listener *AggregateListener) isClosed() bool {
	select {
	case <-listener.closed:
		return true
	default:
		return false
	}
}

func (listener *AggregateListener) available() bool {
	if listener == nil || listener.isClosed() {
		return false
	}
	listener.stateMu.Lock()
	available := listener.remaining > 0
	listener.stateMu.Unlock()
	return available
}

func (aggregateListenerAddress) Network() string {
	return "tcp"
}

func (address aggregateListenerAddress) String() string {
	return address.description
}

func aggregateListenerEndpoint(listener net.Listener) (string, error) {
	if aggregateNilInterface(listener) {
		return "", errors.New("listener is nil")
	}
	address := listener.Addr()
	if aggregateNilInterface(address) {
		return "", errors.New("listener address is nil")
	}

	network := address.Network()
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return "", fmt.Errorf("unsupported address network %q", network)
	}
	rawEndpoint := address.String()
	if rawEndpoint == "" || rawEndpoint != strings.TrimSpace(rawEndpoint) {
		return "", errors.New("listener address is empty or malformed")
	}
	endpoint, err := netip.ParseAddrPort(rawEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse listener address: %w", err)
	}
	boundAddress := endpoint.Addr()
	canonicalAddress := boundAddress.Unmap()
	if !boundAddress.IsValid() ||
		canonicalAddress.IsUnspecified() ||
		endpoint.Port() == 0 {
		return "", errors.New(
			"listener address must be a bound, non-wildcard endpoint",
		)
	}
	switch network {
	case "tcp4":
		if !boundAddress.Is4() {
			return "", errors.New("tcp4 listener has a non-IPv4 address")
		}
	case "tcp6":
		if !boundAddress.Is6() || boundAddress.Is4In6() {
			return "", errors.New("tcp6 listener has a non-IPv6 address")
		}
	}
	return netip.AddrPortFrom(canonicalAddress, endpoint.Port()).String(), nil
}

func aggregateTemporaryNetworkError(err error) bool {
	var temporary interface {
		Temporary() bool
	}
	return errors.As(err, &temporary) && temporary.Temporary()
}

func aggregateNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
