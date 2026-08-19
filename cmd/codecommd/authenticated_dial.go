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

type daemonAuthenticatedDialRelay struct {
	mu       sync.RWMutex
	observer transport.ConsensusAuthenticatedDialObserver
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
) error {
	if relay == nil || observer == nil {
		return errDaemonAuthenticatedDialObserver
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.observer != nil {
		return errDaemonAuthenticatedDialObserver
	}
	relay.observer = observer
	return nil
}

func newDaemonAuthenticatedEndpointObserver(
	state daemonAuthenticatedEndpointState,
	now func() time.Time,
) transport.ConsensusAuthenticatedDialObserver {
	return func(
		ctx context.Context,
		deviceID domain.DeviceID,
		endpoint netip.AddrPort,
	) error {
		if state == nil || now == nil || ctx == nil {
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
		return nil
	}
}
