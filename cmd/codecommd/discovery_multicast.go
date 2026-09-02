package main

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/ijonahch/codecomm/internal/discovery"
)

// daemonRecoveringMulticast keeps discovery optional at the process boundary:
// unavailable multicast must not disable manual routes, pairing, or content.
// The discovery runtime periodically calls Refresh, which reopens a failed
// delegate while the discovery service continues to own this stable wrapper.
type daemonRecoveringMulticast struct {
	refreshMu sync.Mutex
	mu        sync.RWMutex

	port    uint16
	opener  daemonMulticastOpener
	current daemonDiscoveryMulticast
	joins   []discovery.InterfaceJoin
	lastErr error
	closed  bool

	triggers chan struct{}
	updates  chan struct{}
	done     chan struct{}
	close    sync.Once
}

func newDaemonRecoveringMulticast(
	port uint16,
	selected []discovery.MulticastInterfaceSelection,
	opener daemonMulticastOpener,
) (*daemonRecoveringMulticast, discovery.MulticastReport, error) {
	if port == 0 || opener == nil {
		return nil, discovery.MulticastReport{}, errDaemonDiscoveryConstruction
	}
	value := &daemonRecoveringMulticast{
		port:     port,
		opener:   opener,
		triggers: make(chan struct{}, 1),
		updates:  make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	value.signalAdvertisement()
	if len(selected) == 0 {
		value.recordError(discovery.ErrNoMulticastJoin)
		return value, discovery.MulticastReport{}, nil
	}
	report, _ := value.openLocked(selected)
	return value, report, nil
}

func (multicast *daemonRecoveringMulticast) AdvertisementTriggers() <-chan struct{} {
	if multicast == nil {
		return nil
	}
	return multicast.triggers
}

func (multicast *daemonRecoveringMulticast) TriggerAdvertisement() error {
	if multicast == nil {
		return discovery.ErrMulticastClosed
	}
	multicast.mu.RLock()
	closed := multicast.closed
	multicast.mu.RUnlock()
	if closed {
		return discovery.ErrMulticastClosed
	}
	multicast.signalAdvertisement()
	return nil
}

func (multicast *daemonRecoveringMulticast) Send(payload []byte) error {
	if multicast == nil {
		return discovery.ErrMulticastClosed
	}
	delegate, closed := multicast.delegate()
	if closed {
		return discovery.ErrMulticastClosed
	}
	if delegate == nil {
		return nil
	}
	err := delegate.Send(payload)
	if errors.Is(err, discovery.ErrMulticastClosed) {
		multicast.retire(delegate, err)
		return nil
	}
	if err != nil {
		multicast.recordError(err)
	}
	return err
}

func (multicast *daemonRecoveringMulticast) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	if multicast == nil || ctx == nil {
		return discovery.ReceivedDatagram{}, errDaemonDiscoveryConstruction
	}
	for {
		delegate, closed := multicast.delegate()
		if closed {
			return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
		}
		if delegate == nil {
			select {
			case <-ctx.Done():
				return discovery.ReceivedDatagram{}, ctx.Err()
			case <-multicast.done:
				return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
			case <-multicast.updates:
				continue
			}
		}
		datagram, err := delegate.ReceiveDatagram(ctx)
		if err == nil {
			return datagram, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return discovery.ReceivedDatagram{}, ctxErr
		}
		if ignorableDaemonMulticastReceiveError(err) {
			return discovery.ReceivedDatagram{}, err
		}
		multicast.retire(delegate, err)
	}
}

func (multicast *daemonRecoveringMulticast) RefreshSelected(
	selected []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	if multicast == nil {
		return discovery.MulticastReport{}, discovery.ErrMulticastClosed
	}
	multicast.refreshMu.Lock()
	defer multicast.refreshMu.Unlock()

	delegate, closed := multicast.delegate()
	if closed {
		return discovery.MulticastReport{}, discovery.ErrMulticastClosed
	}
	if len(selected) == 0 {
		if delegate != nil {
			multicast.retire(delegate, discovery.ErrNoMulticastJoin)
		} else {
			multicast.recordError(discovery.ErrNoMulticastJoin)
		}
		return discovery.MulticastReport{}, discovery.ErrNoMulticastJoin
	}
	if delegate == nil {
		return multicast.openLocked(selected)
	}

	report, err := delegate.RefreshSelected(selected)
	if err != nil {
		multicast.recordError(err)
		if errors.Is(err, discovery.ErrMulticastClosed) ||
			errors.Is(err, discovery.ErrMulticastRefresh) ||
			errors.Is(err, discovery.ErrNoMulticastJoin) {
			multicast.retire(delegate, err)
			reopened, reopenErr := multicast.openLocked(selected)
			if reopenErr == nil {
				return reopened, nil
			}
			return reopened, errors.Join(err, reopenErr)
		}
		return report, err
	}

	multicast.mu.Lock()
	changed := !slices.Equal(multicast.joins, report.Joins)
	multicast.joins = slices.Clone(report.Joins)
	multicast.lastErr = nil
	multicast.mu.Unlock()
	if changed {
		multicast.signalAdvertisement()
	}
	return report, nil
}

func (multicast *daemonRecoveringMulticast) LastError() error {
	if multicast == nil {
		return errDaemonDiscoveryConstruction
	}
	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	return multicast.lastErr
}

func (multicast *daemonRecoveringMulticast) Close() error {
	if multicast == nil {
		return nil
	}
	var result error
	multicast.close.Do(func() {
		multicast.refreshMu.Lock()
		multicast.mu.Lock()
		multicast.closed = true
		delegate := multicast.current
		multicast.current = nil
		multicast.joins = nil
		close(multicast.done)
		multicast.mu.Unlock()
		if delegate != nil {
			result = delegate.Close()
		}
		multicast.refreshMu.Unlock()
	})
	return result
}

func (multicast *daemonRecoveringMulticast) openLocked(
	selected []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	delegate, report, err := multicast.opener(multicast.port, selected)
	if err == nil && (delegate == nil || len(report.Joins) == 0) {
		err = errDaemonDiscoveryConstruction
	}
	if err != nil {
		if delegate != nil {
			err = errors.Join(err, delegate.Close())
		}
		multicast.recordError(err)
		return report, err
	}

	multicast.mu.Lock()
	if multicast.closed {
		multicast.mu.Unlock()
		return report, errors.Join(
			discovery.ErrMulticastClosed,
			delegate.Close(),
		)
	}
	previous := multicast.current
	changed := previous == nil ||
		!slices.Equal(multicast.joins, report.Joins)
	multicast.current = delegate
	multicast.joins = slices.Clone(report.Joins)
	multicast.lastErr = nil
	multicast.mu.Unlock()
	if previous != nil && previous != delegate {
		_ = previous.Close()
	}
	multicast.signalUpdate()
	if changed {
		multicast.signalAdvertisement()
	}
	return report, nil
}

func (multicast *daemonRecoveringMulticast) delegate() (
	daemonDiscoveryMulticast,
	bool,
) {
	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	return multicast.current, multicast.closed
}

func (multicast *daemonRecoveringMulticast) retire(
	delegate daemonDiscoveryMulticast,
	cause error,
) {
	multicast.mu.Lock()
	if multicast.current != delegate {
		multicast.mu.Unlock()
		return
	}
	multicast.current = nil
	multicast.joins = nil
	if !multicast.closed {
		multicast.lastErr = cause
	}
	multicast.mu.Unlock()
	_ = delegate.Close()
	multicast.signalUpdate()
}

func (multicast *daemonRecoveringMulticast) recordError(err error) {
	if err == nil {
		return
	}
	multicast.mu.Lock()
	if !multicast.closed {
		multicast.lastErr = err
	}
	multicast.mu.Unlock()
}

func (multicast *daemonRecoveringMulticast) signalAdvertisement() {
	select {
	case multicast.triggers <- struct{}{}:
	default:
	}
}

func (multicast *daemonRecoveringMulticast) signalUpdate() {
	select {
	case multicast.updates <- struct{}{}:
	default:
	}
}

func ignorableDaemonMulticastReceiveError(err error) bool {
	return errors.Is(err, discovery.ErrMulticastSource) ||
		errors.Is(err, discovery.ErrMulticastInterface) ||
		errors.Is(err, discovery.ErrMulticastDatagramSize)
}

var _ daemonDiscoveryMulticast = (*daemonRecoveringMulticast)(nil)
