package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"

	"github.com/ijonahch/codecomm/internal/transport"
)

// daemonPeerListenerSet keeps one stable listener identity while replacing the
// concrete interface-bound listeners beneath it.
type daemonPeerListenerSet struct {
	operationMu sync.Mutex
	mu          sync.Mutex

	listener         *transport.RebindableListener
	listen           func(context.Context, netip.AddrPort) (net.Listener, error)
	endpoints        []netip.AddrPort
	activeBindCancel context.CancelFunc
	closed           bool
	closeOnce        sync.Once
	closeErr         error
}

type daemonPeerListenerUpdate struct {
	Previous      []netip.AddrPort
	Current       []netip.AddrPort
	Changed       bool
	TransitionErr error
}

var _ net.Listener = (*daemonPeerListenerSet)(nil)

func openDaemonPeerListeners(
	ctx context.Context,
	endpoints []netip.AddrPort,
	listen func(context.Context, netip.AddrPort) (net.Listener, error),
) (*daemonPeerListenerSet, error) {
	normalized, err := normalizeDaemonPeerListenerEndpoints(endpoints)
	if ctx == nil || listen == nil || err != nil || len(normalized) == 0 {
		return nil, errDaemonMeshConstruction
	}
	listeners, err := bindDaemonPeerListeners(ctx, normalized, listen)
	if err != nil {
		return nil, err
	}
	rebindable, err := transport.NewRebindableListener(listeners...)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"%w: aggregate peer listeners: %v",
				errDaemonMeshConstruction,
				err,
			),
			closeDaemonPeerListeners(listeners),
		)
	}
	return &daemonPeerListenerSet{
		listener:  rebindable,
		listen:    listen,
		endpoints: normalized,
	}, nil
}

func (listeners *daemonPeerListenerSet) Accept() (net.Conn, error) {
	if listeners == nil || listeners.listener == nil {
		return nil, net.ErrClosed
	}
	return listeners.listener.Accept()
}

func (listeners *daemonPeerListenerSet) Close() error {
	if listeners == nil {
		return net.ErrClosed
	}
	listeners.closeOnce.Do(func() {
		listeners.mu.Lock()
		listeners.closed = true
		listeners.endpoints = nil
		cancel := listeners.activeBindCancel
		listeners.mu.Unlock()
		if cancel != nil {
			cancel()
		}

		listeners.operationMu.Lock()
		err := listeners.listener.Close()
		listeners.operationMu.Unlock()

		listeners.mu.Lock()
		listeners.closeErr = err
		listeners.mu.Unlock()
	})
	listeners.mu.Lock()
	err := listeners.closeErr
	listeners.mu.Unlock()
	return err
}

func daemonPeerListenerOrNil(
	listeners *daemonPeerListenerSet,
) net.Listener {
	if listeners == nil {
		return nil
	}
	return listeners
}

func (listeners *daemonPeerListenerSet) Addr() net.Addr {
	if listeners == nil || listeners.listener == nil {
		return daemonPeerListenerAddress{}
	}
	return listeners.listener.Addr()
}

func (listeners *daemonPeerListenerSet) Current() []netip.AddrPort {
	if listeners == nil {
		return nil
	}
	listeners.mu.Lock()
	defer listeners.mu.Unlock()
	if listeners.closed || !listeners.listener.Available() {
		return nil
	}
	return slices.Clone(listeners.endpoints)
}

// Replace binds every candidate before atomically installing the generation.
// A bind or validation error leaves the prior generation untouched.
func (listeners *daemonPeerListenerSet) Replace(
	ctx context.Context,
	endpoints []netip.AddrPort,
) (daemonPeerListenerUpdate, error) {
	return listeners.rebind(ctx, endpoints, false)
}

func (listeners *daemonPeerListenerSet) Rebind(
	ctx context.Context,
	endpoints []netip.AddrPort,
	force bool,
) (daemonPeerListenerUpdate, error) {
	return listeners.rebind(ctx, endpoints, force)
}

func (listeners *daemonPeerListenerSet) rebind(
	ctx context.Context,
	endpoints []netip.AddrPort,
	force bool,
) (daemonPeerListenerUpdate, error) {
	if listeners == nil || listeners.listener == nil || ctx == nil {
		return daemonPeerListenerUpdate{}, errDaemonMeshConstruction
	}
	normalized, err := normalizeDaemonPeerListenerEndpoints(endpoints)
	if err != nil {
		return daemonPeerListenerUpdate{}, err
	}

	listeners.operationMu.Lock()
	defer listeners.operationMu.Unlock()

	listeners.mu.Lock()
	if listeners.closed {
		listeners.mu.Unlock()
		return daemonPeerListenerUpdate{}, net.ErrClosed
	}
	previous := slices.Clone(listeners.endpoints)
	available := listeners.listener.Available()
	if slices.Equal(previous, normalized) && !force && available {
		listeners.mu.Unlock()
		return daemonPeerListenerUpdate{
			Previous: previous,
			Current:  slices.Clone(previous),
		}, nil
	}
	force = force || !available
	bindContext, cancelBind := context.WithCancel(ctx)
	listeners.activeBindCancel = cancelBind
	listeners.mu.Unlock()
	defer func() {
		cancelBind()
		listeners.mu.Lock()
		listeners.activeBindCancel = nil
		listeners.mu.Unlock()
	}()

	// A generation containing a retained endpoint cannot be bound while the
	// old socket still owns that endpoint. Complete swaps remain
	// make-before-break; partial or forced refreshes retire first.
	retiredFirst := force ||
		daemonPeerListenerSetsOverlap(previous, normalized)
	var transitionErr error
	if retiredFirst {
		transitionErr = listeners.listener.Replace()
		listeners.mu.Lock()
		listeners.endpoints = nil
		listeners.mu.Unlock()
	}

	var bound []net.Listener
	if len(normalized) != 0 {
		bound, err = bindDaemonPeerListeners(
			bindContext,
			normalized,
			listeners.listen,
		)
		if err != nil {
			if !retiredFirst {
				transitionErr = errors.Join(
					transitionErr,
					listeners.listener.Replace(),
				)
				listeners.mu.Lock()
				listeners.endpoints = nil
				listeners.mu.Unlock()
			}
			return daemonPeerListenerUpdate{
				Previous:      previous,
				Current:       nil,
				Changed:       len(previous) != 0 || force,
				TransitionErr: errors.Join(transitionErr, err),
			}, nil
		}
	}
	if err := bindContext.Err(); err != nil {
		closeErr := closeDaemonPeerListeners(bound)
		if !retiredFirst {
			transitionErr = errors.Join(
				transitionErr,
				listeners.listener.Replace(),
			)
			listeners.mu.Lock()
			listeners.endpoints = nil
			listeners.mu.Unlock()
		}
		return daemonPeerListenerUpdate{
			Previous:      previous,
			Current:       nil,
			Changed:       len(previous) != 0 || force,
			TransitionErr: errors.Join(transitionErr, err, closeErr),
		}, nil
	}

	replaceErr := listeners.listener.Replace(bound...)
	if errors.Is(replaceErr, transport.ErrInvalidAggregateListener) {
		closeErr := closeDaemonPeerListeners(bound)
		current := previous
		if retiredFirst {
			current = nil
		}
		listeners.mu.Lock()
		listeners.endpoints = slices.Clone(current)
		listeners.mu.Unlock()
		return daemonPeerListenerUpdate{
			Previous: previous,
			Current:  slices.Clone(current),
			Changed:  !slices.Equal(previous, current) || force,
			TransitionErr: errors.Join(
				transitionErr,
				fmt.Errorf(
					"%w: replace peer listeners: %v",
					errDaemonMeshConstruction,
					replaceErr,
				),
				closeErr,
			),
		}, nil
	}

	// RebindableListener installs a validated generation before returning a
	// retired-generation close error, so the endpoint snapshot advances too.
	listeners.mu.Lock()
	listeners.endpoints = slices.Clone(normalized)
	listeners.mu.Unlock()
	return daemonPeerListenerUpdate{
		Previous:      previous,
		Current:       slices.Clone(normalized),
		Changed:       !slices.Equal(previous, normalized) || force,
		TransitionErr: errors.Join(transitionErr, replaceErr),
	}, nil
}

func daemonPeerListenerSetsOverlap(
	left []netip.AddrPort,
	right []netip.AddrPort,
) bool {
	rightSet := make(map[netip.AddrPort]struct{}, len(right))
	for _, endpoint := range right {
		rightSet[endpoint] = struct{}{}
	}
	for _, endpoint := range left {
		if _, exists := rightSet[endpoint]; exists {
			return true
		}
	}
	return false
}

func bindDaemonPeerListeners(
	ctx context.Context,
	endpoints []netip.AddrPort,
	listen func(context.Context, netip.AddrPort) (net.Listener, error),
) ([]net.Listener, error) {
	if ctx == nil || len(endpoints) == 0 || listen == nil {
		return nil, errDaemonMeshConstruction
	}
	listeners := make([]net.Listener, 0, len(endpoints))
	for _, endpoint := range endpoints {
		listener, err := listen(ctx, endpoint)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf(
					"%w: listen on %s: %w",
					errDaemonMeshConstruction,
					endpoint,
					err,
				),
				closeDaemonPeerListeners(listeners),
			)
		}
		if !daemonPeerListenerMatches(listener, endpoint) {
			if listener != nil {
				listeners = append(listeners, listener)
			}
			return nil, errors.Join(
				fmt.Errorf(
					"%w: listener did not bind requested endpoint %s",
					errDaemonMeshConstruction,
					endpoint,
				),
				closeDaemonPeerListeners(listeners),
			)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func closeDaemonPeerListeners(listeners []net.Listener) error {
	errs := make([]error, 0, len(listeners))
	for _, listener := range listeners {
		if listener != nil {
			errs = append(errs, listener.Close())
		}
	}
	return errors.Join(errs...)
}

func normalizeDaemonPeerListenerEndpoints(
	endpoints []netip.AddrPort,
) ([]netip.AddrPort, error) {
	if len(endpoints) > transport.MaxSelectedConsensusAddresses {
		return nil, errDaemonMeshConstruction
	}
	result := slices.Clone(endpoints)
	sort.Slice(result, func(left, right int) bool {
		return result[left].Compare(result[right]) < 0
	})
	var port uint16
	for index, endpoint := range result {
		if !endpoint.IsValid() ||
			endpoint.Port() == 0 ||
			!validDaemonSelectedAddress(endpoint.Addr()) {
			return nil, errDaemonMeshConstruction
		}
		if port == 0 {
			port = endpoint.Port()
		}
		if endpoint.Port() != port ||
			index > 0 && result[index-1] == endpoint {
			return nil, errDaemonMeshConstruction
		}
	}
	return result, nil
}

func daemonPeerListenerMatches(
	listener net.Listener,
	expected netip.AddrPort,
) bool {
	if listener == nil || listener.Addr() == nil {
		return false
	}
	switch listener.(type) {
	case *transport.RebindableListener:
		return false
	}
	actual, err := netip.ParseAddrPort(listener.Addr().String())
	return err == nil && actual == expected
}

type daemonPeerListenerAddress struct{}

func (daemonPeerListenerAddress) Network() string { return "tcp" }
func (daemonPeerListenerAddress) String() string  { return "" }
