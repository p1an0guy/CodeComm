package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// RebindableListener presents replaceable generations of already-bound TCP
// listeners as one long-lived listener. A successful construction or Replace
// transfers ownership of the supplied listeners.
type RebindableListener struct {
	operationMu sync.Mutex

	stateMu  sync.Mutex
	current  *AggregateListener
	changed  chan struct{}
	address  aggregateListenerAddress
	closed   bool
	closeErr error
}

var _ net.Listener = (*RebindableListener)(nil)

// NewRebindableListener validates and takes ownership of one or more
// already-bound, literal-address TCP listeners.
func NewRebindableListener(
	initial ...net.Listener,
) (*RebindableListener, error) {
	aggregate, err := NewAggregateListener(initial...)
	if err != nil {
		return nil, err
	}
	return &RebindableListener{
		current: aggregate,
		changed: make(chan struct{}),
		address: aggregate.address,
	}, nil
}

// Accept returns the next connection from the current listener generation.
// Replacing a generation is transparent to blocked Accept calls. If the
// current generation is replaced with no listeners, Accept waits until a
// later replacement or Close.
func (listener *RebindableListener) Accept() (net.Conn, error) {
	if listener == nil {
		return nil, net.ErrClosed
	}

	for {
		listener.stateMu.Lock()
		if listener.closed {
			listener.stateMu.Unlock()
			return nil, net.ErrClosed
		}
		current := listener.current
		changed := listener.changed
		listener.stateMu.Unlock()

		if current == nil {
			<-changed
			continue
		}

		connection, err := current.Accept()
		if err == nil {
			return connection, nil
		}

		listener.stateMu.Lock()
		closed := listener.closed
		replaced := listener.current != current
		exhausted := errors.Is(err, ErrAggregateListenerUnavailable)
		if !closed && !replaced && exhausted {
			listener.current = nil
		}
		listener.stateMu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if replaced {
			continue
		}
		if exhausted {
			_ = current.Close()
			continue
		}
		return nil, err
	}
}

// Replace atomically installs a validated listener generation. Passing no
// listeners leaves the RebindableListener active with no bound endpoints;
// Accept then waits for a later replacement.
//
// Validation failure leaves the current generation untouched and does not
// transfer ownership of any supplied listener. Once installation succeeds,
// Replace closes the retired generation and waits for its workers to stop.
// An error from that close is returned after the new generation is installed.
func (listener *RebindableListener) Replace(
	next ...net.Listener,
) error {
	if listener == nil {
		return net.ErrClosed
	}

	listener.operationMu.Lock()
	defer listener.operationMu.Unlock()

	listener.stateMu.Lock()
	if listener.closed {
		listener.stateMu.Unlock()
		return net.ErrClosed
	}
	listener.stateMu.Unlock()

	for index, candidate := range next {
		if _, ok := candidate.(*RebindableListener); ok {
			return fmt.Errorf(
				"%w: listener %d is itself replaceable",
				ErrInvalidAggregateListener,
				index,
			)
		}
	}

	var replacement *AggregateListener
	if len(next) > 0 {
		var err error
		replacement, err = NewAggregateListener(next...)
		if err != nil {
			return err
		}
	}

	listener.stateMu.Lock()
	retired := listener.current
	listener.current = replacement
	if replacement != nil {
		listener.address = replacement.address
	}
	close(listener.changed)
	listener.changed = make(chan struct{})
	listener.stateMu.Unlock()

	if retired == nil {
		return nil
	}
	return retired.Close()
}

// Close prevents future replacement, closes the current listener generation,
// and waits for its workers to stop. Connections already returned by Accept
// are not closed. Concurrent and repeated calls return the same result.
func (listener *RebindableListener) Close() error {
	if listener == nil {
		return net.ErrClosed
	}

	listener.operationMu.Lock()
	defer listener.operationMu.Unlock()

	listener.stateMu.Lock()
	if listener.closed {
		err := listener.closeErr
		listener.stateMu.Unlock()
		return err
	}
	listener.closed = true
	retired := listener.current
	listener.current = nil
	close(listener.changed)
	listener.stateMu.Unlock()

	var err error
	if retired != nil {
		err = retired.Close()
	}

	listener.stateMu.Lock()
	listener.closeErr = err
	listener.stateMu.Unlock()
	return err
}

// Available reports whether the current generation still has at least one
// accepting child listener. It becomes false during zero-listener intervals,
// terminal child exhaustion, and shutdown.
func (listener *RebindableListener) Available() bool {
	if listener == nil {
		return false
	}
	listener.stateMu.Lock()
	current := listener.current
	closed := listener.closed
	listener.stateMu.Unlock()
	return !closed && current != nil && current.available()
}

// Addr returns the current generation's canonical endpoint description.
// During a zero-listener interval and after Close, it retains the most recent
// nonempty address so callers always receive a valid immutable net.Addr.
func (listener *RebindableListener) Addr() net.Addr {
	if listener == nil {
		return aggregateListenerAddress{}
	}
	listener.stateMu.Lock()
	address := listener.address
	listener.stateMu.Unlock()
	return address
}
