package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestDaemonAuthenticatedDialRelayFailsClosedUntilConfigured(t *testing.T) {
	relay := &daemonAuthenticatedDialRelay{}
	deviceID := daemonEndpointRouteTestDeviceID('6')
	endpoint := netip.MustParseAddrPort("192.0.2.60:47831")
	if err := relay.observe(
		context.Background(),
		deviceID,
		endpoint,
	); !errors.Is(err, errDaemonAuthenticatedDialObserver) {
		t.Fatalf("unconfigured observe error = %v", err)
	}

	state := &daemonAuthenticatedEndpointStateStub{}
	now := time.Date(2026, 8, 19, 12, 0, 0, 123, time.UTC)
	observer := newDaemonAuthenticatedEndpointObserver(
		state,
		func() time.Time { return now },
	)
	if err := relay.set(observer); err != nil {
		t.Fatalf("set(): %v", err)
	}
	if err := relay.set(observer); !errors.Is(
		err,
		errDaemonAuthenticatedDialObserver,
	) {
		t.Fatalf("second set error = %v", err)
	}
	if err := relay.observe(
		context.Background(),
		deviceID,
		endpoint,
	); err != nil {
		t.Fatalf("observe(): %v", err)
	}
	if state.deviceID != deviceID ||
		state.endpoint != endpoint ||
		state.observedAt != domain.Timestamp(now.Format(time.RFC3339Nano)) {
		t.Fatalf(
			"persisted observation = (%s, %s, %s)",
			state.deviceID,
			state.endpoint,
			state.observedAt,
		)
	}
}

func TestDaemonAuthenticatedEndpointObserverPropagatesFailureAndCancellation(
	t *testing.T,
) {
	persistErr := errors.New("endpoint store unavailable")
	state := &daemonAuthenticatedEndpointStateStub{err: persistErr}
	observer := newDaemonAuthenticatedEndpointObserver(state, time.Now)
	if err := observer(
		context.Background(),
		daemonEndpointRouteTestDeviceID('7'),
		netip.MustParseAddrPort("192.0.2.70:47831"),
	); !errors.Is(err, errDaemonAuthenticatedDialObserver) ||
		!errors.Is(err, persistErr) {
		t.Fatalf("persistence error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := state.calls
	if err := observer(
		ctx,
		daemonEndpointRouteTestDeviceID('7'),
		netip.MustParseAddrPort("192.0.2.70:47831"),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observer error = %v", err)
	}
	if state.calls != before {
		t.Fatal("canceled observer reached endpoint storage")
	}
}

type daemonAuthenticatedEndpointStateStub struct {
	deviceID   domain.DeviceID
	endpoint   netip.AddrPort
	observedAt domain.Timestamp
	calls      int
	err        error
}

func (state *daemonAuthenticatedEndpointStateStub) UpsertAuthenticatedEndpoint(
	_ context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	observedAt domain.Timestamp,
) error {
	state.calls++
	state.deviceID = deviceID
	state.endpoint = endpoint
	state.observedAt = observedAt
	return state.err
}
