package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/transport"
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
	connectivity := &daemonConnectivityNotifierStub{
		notify: func() {
			if state.calls != 1 {
				t.Fatal("connectivity notification preceded endpoint persistence")
			}
		},
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 123, time.UTC)
	observer := newDaemonAuthenticatedEndpointObserver(
		state,
		func() time.Time { return now },
		connectivity,
	)
	if err := relay.set(observer, connectivity); err != nil {
		t.Fatalf("set(): %v", err)
	}
	if err := relay.set(observer, connectivity); !errors.Is(
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
	if connectivity.calls != 1 {
		t.Fatalf("connectivity notifications = %d, want 1", connectivity.calls)
	}
}

func TestDaemonAuthenticatedEndpointObserverPropagatesFailureAndCancellation(
	t *testing.T,
) {
	persistErr := errors.New("endpoint store unavailable")
	state := &daemonAuthenticatedEndpointStateStub{err: persistErr}
	connectivity := &daemonConnectivityNotifierStub{}
	observer := newDaemonAuthenticatedEndpointObserver(
		state,
		time.Now,
		connectivity,
	)
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
	if connectivity.calls != 0 {
		t.Fatalf(
			"failed observations emitted %d connectivity notifications",
			connectivity.calls,
		)
	}
}

func TestDaemonAuthenticatedPeerObserverFiltersNonConsensusPlanes(
	t *testing.T,
) {
	connectivity := &daemonConnectivityNotifierStub{}
	observer := newDaemonAuthenticatedPeerObserver(connectivity)
	for _, plane := range []transport.Plane{
		transport.PlanePairing,
		transport.PlaneContent,
	} {
		observer(transport.AuthenticatedPeer{Plane: plane})
	}
	if connectivity.calls != 0 {
		t.Fatalf(
			"non-consensus notifications = %d, want 0",
			connectivity.calls,
		)
	}
	observer(transport.AuthenticatedPeer{Plane: transport.PlaneConsensus})
	if connectivity.calls != 1 {
		t.Fatalf("consensus notifications = %d, want 1", connectivity.calls)
	}
}

type daemonAuthenticatedEndpointStateStub struct {
	deviceID   domain.DeviceID
	endpoint   netip.AddrPort
	observedAt domain.Timestamp
	calls      int
	err        error
}

type daemonConnectivityNotifierStub struct {
	calls  int
	notify func()
}

func (notifier *daemonConnectivityNotifierStub) NotifyConnectivityChange() {
	notifier.calls++
	if notifier.notify != nil {
		notifier.notify()
	}
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
