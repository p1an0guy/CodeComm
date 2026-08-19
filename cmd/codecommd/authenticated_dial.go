package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/transport"
)

var errDaemonAuthenticatedDialObserver = errors.New(
	"codecommd: authenticated dial observer unavailable",
)

type daemonAuthenticatedEndpointState interface {
	UpsertAuthenticatedEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
		domain.Timestamp,
	) error
}

type daemonConnectivityNotifier interface {
	NotifyConnectivityChange()
}

type daemonAuthenticatedDialRelay struct {
	mu       sync.RWMutex
	observer transport.ConsensusAuthenticatedDialObserver
	notifier daemonConnectivityNotifier
}

func (relay *daemonAuthenticatedDialRelay) observe(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) error {
	if relay == nil || ctx == nil {
		return errDaemonAuthenticatedDialObserver
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	relay.mu.RLock()
	observer := relay.observer
	relay.mu.RUnlock()
	if observer == nil {
		return errDaemonAuthenticatedDialObserver
	}
	return observer(ctx, deviceID, endpoint)
}

func (relay *daemonAuthenticatedDialRelay) set(
	observer transport.ConsensusAuthenticatedDialObserver,
	notifier daemonConnectivityNotifier,
) error {
	if relay == nil || observer == nil || notifier == nil {
		return errDaemonAuthenticatedDialObserver
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.observer != nil || relay.notifier != nil {
		return errDaemonAuthenticatedDialObserver
	}
	relay.observer = observer
	relay.notifier = notifier
	return nil
}

func (relay *daemonAuthenticatedDialRelay) NotifyConnectivityChange() {
	if relay == nil {
		return
	}
	relay.mu.RLock()
	notifier := relay.notifier
	relay.mu.RUnlock()
	if notifier != nil {
		notifier.NotifyConnectivityChange()
	}
}

func newDaemonAuthenticatedEndpointObserver(
	state daemonAuthenticatedEndpointState,
	now func() time.Time,
	connectivity daemonConnectivityNotifier,
) transport.ConsensusAuthenticatedDialObserver {
	return func(
		ctx context.Context,
		deviceID domain.DeviceID,
		endpoint netip.AddrPort,
	) error {
		if state == nil || now == nil || connectivity == nil || ctx == nil {
			return errDaemonAuthenticatedDialObserver
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		observedAt := domain.Timestamp(
			now().UTC().Format(time.RFC3339Nano),
		)
		if !observedAt.Valid() {
			return errDaemonAuthenticatedDialObserver
		}
		if err := state.UpsertAuthenticatedEndpoint(
			ctx,
			deviceID,
			endpoint,
			observedAt,
		); err != nil {
			return fmt.Errorf(
				"%w: persist endpoint: %w",
				errDaemonAuthenticatedDialObserver,
				err,
			)
		}
		connectivity.NotifyConnectivityChange()
		return nil
	}
}

func newDaemonAuthenticatedPeerObserver(
	connectivity daemonConnectivityNotifier,
) transport.AuthenticatedPeerObserver {
	return func(peer transport.AuthenticatedPeer) {
		if connectivity == nil || peer.Plane != transport.PlaneConsensus {
			return
		}
		connectivity.NotifyConnectivityChange()
	}
}
