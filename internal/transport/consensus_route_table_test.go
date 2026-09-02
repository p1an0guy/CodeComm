package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	routeTablePeerA = domain.DeviceID(
		"cc10000000000000000000000000000000000000000000000000000000000000001",
	)
	routeTablePeerB = domain.DeviceID(
		"cc10000000000000000000000000000000000000000000000000000000000000002",
	)
)

func TestConsensusRouteTableResolvesAndBindsSelectedSource(t *testing.T) {
	t.Parallel()

	local := netip.MustParseAddr("192.0.2.10")
	remote := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		[]ConsensusRoute{{
			PeerDeviceID:         routeTablePeerA,
			RemoteEndpoint:       remote,
			SelectedLocalAddress: local,
		}},
		func() time.Time {
			return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}

	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != remote {
		t.Fatalf("ResolveConsensusEndpoints() = (%v, %v)", endpoints, err)
	}
	dialer, network, address, err := table.dialConfiguration(
		context.Background(),
		remote,
	)
	if err != nil ||
		network != "tcp4" ||
		address != remote.String() {
		t.Fatalf(
			"dialConfiguration() = (%#v, %q, %q, %v)",
			dialer,
			network,
			address,
			err,
		)
	}
	tcp, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok || tcp.AddrPort().Addr() != local || tcp.Port != 0 {
		t.Fatalf("selected local address = %#v, want %s:0", dialer.LocalAddr, local)
	}
}

func TestConsensusRouteTablePrioritizesAuthorityAndExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	firstLocal := netip.MustParseAddr("192.0.2.10")
	secondLocal := netip.MustParseAddr("192.0.2.11")
	remote := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{firstLocal, secondLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteDiscovery,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       remote,
				SelectedLocalAddress: secondLocal,
			},
			ExpiresAt: now.Add(30 * time.Second),
		}},
	); err != nil {
		t.Fatalf("Replace(discovery) error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       remote,
				SelectedLocalAddress: firstLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace(signed) error = %v", err)
	}
	dialer, _, _, err := table.dialConfiguration(context.Background(), remote)
	if err != nil {
		t.Fatalf("dialConfiguration() error = %v", err)
	}
	if got := dialer.LocalAddr.(*net.TCPAddr).AddrPort().Addr(); got != firstLocal {
		t.Fatalf("effective source = %s, want signed source %s", got, firstLocal)
	}

	now = now.Add(time.Hour)
	if removed := table.Expire(); removed != 2 {
		t.Fatalf("Expire() removed %d routes, want 2", removed)
	}
	if _, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf("ResolveConsensusEndpoints(expired) error = %v", err)
	}
}

func TestConsensusRouteTableQuarantinesAmbiguousEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	firstLocal := netip.MustParseAddr("192.0.2.10")
	secondLocal := netip.MustParseAddr("192.0.2.11")
	shared := netip.MustParseAddrPort("192.0.2.20:47831")
	firstRemote := netip.MustParseAddrPort("192.0.2.21:47831")
	secondRemote := netip.MustParseAddrPort("192.0.2.22:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{firstLocal, secondLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       shared,
					SelectedLocalAddress: firstLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       firstRemote,
					SelectedLocalAddress: firstLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatalf("Replace(first peer) error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerB,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerB,
					RemoteEndpoint:       shared,
					SelectedLocalAddress: secondLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerB,
					RemoteEndpoint:       secondRemote,
					SelectedLocalAddress: secondLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatalf("Replace(colliding peer) error = %v", err)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != firstRemote {
		t.Fatalf("first peer routes after collision = (%v, %v)", endpoints, err)
	}
	endpoints, err = table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerB,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != secondRemote {
		t.Fatalf("second peer routes after collision = (%v, %v)", endpoints, err)
	}
	if _, _, _, err := table.dialConfiguration(
		context.Background(),
		shared,
	); !errors.Is(err, ErrConsensusRouteAmbiguous) {
		t.Fatalf("shared endpoint dial error = %v", err)
	}
}

func TestConsensusRouteTableReplacementIsAtomicAndPurgeKeepsManual(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddr("192.0.2.10")
	manual := netip.MustParseAddrPort("192.0.2.20:47831")
	learned := netip.MustParseAddrPort("192.0.2.21:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		[]ConsensusRoute{{
			PeerDeviceID:         routeTablePeerA,
			RemoteEndpoint:       manual,
			SelectedLocalAddress: local,
		}},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteAuthenticated,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       learned,
				SelectedLocalAddress: local,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace(authenticated) error = %v", err)
	}
	invalid := netip.MustParseAddr("192.0.2.99")
	err = table.Replace(
		routeTablePeerA,
		ConsensusRouteAuthenticated,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       learned,
				SelectedLocalAddress: invalid,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	)
	if !errors.Is(err, ErrInvalidConsensusRouteTable) {
		t.Fatalf("Replace(unselected source) error = %v", err)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 2 {
		t.Fatalf("routes after rejected replace = (%v, %v)", endpoints, err)
	}

	table.PurgePeer(routeTablePeerA, false)
	endpoints, err = table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != manual {
		t.Fatalf("routes after learned purge = (%v, %v)", endpoints, err)
	}
	table.PurgePeer(routeTablePeerA, true)
	if _, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf("routes after full purge error = %v", err)
	}
}

func TestConsensusRouteTableRejectsSourceLifetimeAndCapacityOverflow(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddr("192.0.2.10")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	tooLong := ExpiringConsensusRoute{
		ConsensusRoute: ConsensusRoute{
			PeerDeviceID: routeTablePeerA,
			RemoteEndpoint: netip.MustParseAddrPort(
				"192.0.2.20:47831",
			),
			SelectedLocalAddress: local,
		},
		ExpiresAt: now.Add(ConsensusDiscoveryRouteLifetimeMax + time.Second),
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteDiscovery,
		[]ExpiringConsensusRoute{tooLong},
	); !errors.Is(err, ErrInvalidConsensusRouteTable) {
		t.Fatalf("Replace(overlong discovery) error = %v", err)
	}

	routes := make(
		[]ExpiringConsensusRoute,
		ConsensusStaticRoutesPerPeerMax+1,
	)
	for index := range routes {
		routes[index] = ExpiringConsensusRoute{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID: routeTablePeerA,
				RemoteEndpoint: netip.AddrPortFrom(
					netip.MustParseAddr("192.0.2.20"),
					uint16(10_000+index),
				),
				SelectedLocalAddress: local,
			},
			ExpiresAt: now.Add(time.Hour),
		}
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		routes,
	); !errors.Is(err, ErrConsensusRouteCapacity) {
		t.Fatalf("Replace(over capacity) error = %v", err)
	}
}

func TestConsensusRouteTableSelectedAddressRefreshRollsBack(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	manualLocal := netip.MustParseAddr("192.0.2.10")
	learnedLocal := netip.MustParseAddr("192.0.2.11")
	manualEndpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	learnedEndpoint := netip.MustParseAddrPort("192.0.2.21:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{manualLocal, learnedLocal},
		[]ConsensusRoute{{
			PeerDeviceID:         routeTablePeerA,
			RemoteEndpoint:       manualEndpoint,
			SelectedLocalAddress: manualLocal,
		}},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       learnedEndpoint,
				SelectedLocalAddress: learnedLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace(signed) error = %v", err)
	}

	tooMany := make([]netip.Addr, MaxSelectedConsensusAddresses+1)
	for index := range tooMany {
		tooMany[index] = netip.AddrFrom4(
			[4]byte{198, 51, 100, byte(index + 1)},
		)
	}
	invalidSets := [][]netip.Addr{
		{manualLocal, manualLocal},
		{netip.MustParseAddr("127.0.0.1")},
		tooMany,
	}
	for _, selected := range invalidSets {
		if err := table.ReplaceSelectedAddresses(selected); !errors.Is(
			err,
			ErrInvalidConsensusRouteTable,
		) {
			t.Fatalf("ReplaceSelectedAddresses(%v) error = %v", selected, err)
		}
	}
	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{learnedLocal},
	); err != nil {
		t.Fatalf("ReplaceSelectedAddresses(drop stale manual) error = %v", err)
	}

	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil ||
		len(endpoints) != 1 ||
		endpoints[0] != learnedEndpoint {
		t.Fatalf("routes after selected refresh = (%v, %v)", endpoints, err)
	}
}

func TestConsensusRouteTableSelectedAddressRefreshPrunesLearnedRoutes(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	retainedLocal := netip.MustParseAddr("192.0.2.10")
	removedLocal := netip.MustParseAddr("192.0.2.11")
	retainedEndpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	removedEndpoint := netip.MustParseAddrPort("192.0.2.21:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{retainedLocal, removedLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	for _, candidate := range []struct {
		source ConsensusRouteSource
		route  ExpiringConsensusRoute
	}{
		{
			source: ConsensusRouteSigned,
			route: ExpiringConsensusRoute{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       retainedEndpoint,
					SelectedLocalAddress: retainedLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
		},
		{
			source: ConsensusRouteAuthenticated,
			route: ExpiringConsensusRoute{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       removedEndpoint,
					SelectedLocalAddress: removedLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
		},
	} {
		if err := table.Replace(
			routeTablePeerA,
			candidate.source,
			[]ExpiringConsensusRoute{candidate.route},
		); err != nil {
			t.Fatalf(
				"Replace(%s) error = %v",
				candidate.route.RemoteEndpoint,
				err,
			)
		}
	}

	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{retainedLocal},
	); err != nil {
		t.Fatalf("ReplaceSelectedAddresses() error = %v", err)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil ||
		len(endpoints) != 1 ||
		endpoints[0] != retainedEndpoint {
		t.Fatalf("routes after refresh = (%v, %v)", endpoints, err)
	}
	if _, _, _, err := table.dialConfiguration(
		context.Background(),
		removedEndpoint,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf("dialConfiguration(pruned route) error = %v", err)
	}
}

func TestConsensusRouteTableSelectedAddressRefreshAcceptsNewAddress(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	oldLocal := netip.MustParseAddr("192.0.2.10")
	newLocal := netip.MustParseAddr("192.0.2.11")
	remote := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{oldLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}

	selected := []netip.Addr{newLocal}
	if err := table.ReplaceSelectedAddresses(selected); err != nil {
		t.Fatalf("ReplaceSelectedAddresses() error = %v", err)
	}
	selected[0] = oldLocal
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteAuthenticated,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       remote,
				SelectedLocalAddress: newLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace(new selected address) error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerB,
		ConsensusRouteAuthenticated,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID: routeTablePeerB,
				RemoteEndpoint: netip.MustParseAddrPort(
					"192.0.2.21:47831",
				),
				SelectedLocalAddress: oldLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); !errors.Is(err, ErrInvalidConsensusRouteTable) {
		t.Fatalf("Replace(removed selected address) error = %v", err)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != remote {
		t.Fatalf("new-address route = (%v, %v)", endpoints, err)
	}
}

func TestConsensusRouteTableConcurrentResolveAndSelectedAddressRefresh(
	t *testing.T,
) {
	t.Parallel()

	manualLocal := netip.MustParseAddr("192.0.2.10")
	firstExtra := netip.MustParseAddr("192.0.2.11")
	secondExtra := netip.MustParseAddr("192.0.2.12")
	remote := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{manualLocal, firstExtra},
		[]ConsensusRoute{{
			PeerDeviceID:         routeTablePeerA,
			RemoteEndpoint:       remote,
			SelectedLocalAddress: manualLocal,
		}},
		func() time.Time {
			return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}

	const iterations = 1_000
	errs := make(chan error, 9)
	var workers sync.WaitGroup
	workers.Add(9)
	for reader := 0; reader < 8; reader++ {
		go func() {
			defer workers.Done()
			for range iterations {
				endpoints, err := table.ResolveConsensusEndpoints(
					context.Background(),
					routeTablePeerA,
				)
				if err != nil ||
					len(endpoints) != 1 ||
					endpoints[0] != remote {
					errs <- fmt.Errorf(
						"ResolveConsensusEndpoints() = (%v, %v)",
						endpoints,
						err,
					)
					return
				}
			}
		}()
	}
	go func() {
		defer workers.Done()
		for iteration := range iterations {
			extra := firstExtra
			if iteration%2 != 0 {
				extra = secondExtra
			}
			if err := table.ReplaceSelectedAddresses(
				[]netip.Addr{manualLocal, extra},
			); err != nil {
				errs <- fmt.Errorf(
					"ReplaceSelectedAddresses() error = %w",
					err,
				)
				return
			}
		}
	}()
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestConsensusRouteTableSelectedAddressRefreshClosesTrackedConnections(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	retainedLocal := netip.MustParseAddr("192.0.2.10")
	removedLocal := netip.MustParseAddr("192.0.2.11")
	retainedEndpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	removedEndpoint := netip.MustParseAddrPort("192.0.2.21:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{retainedLocal, removedLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       retainedEndpoint,
					SelectedLocalAddress: retainedLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
			{
				ConsensusRoute: ConsensusRoute{
					PeerDeviceID:         routeTablePeerA,
					RemoteEndpoint:       removedEndpoint,
					SelectedLocalAddress: removedLocal,
				},
				ExpiresAt: now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	peers := make(map[string]net.Conn)
	table.dialContext = func(
		_ context.Context,
		_ *net.Dialer,
		_ string,
		address string,
	) (net.Conn, error) {
		connection, peer := net.Pipe()
		peers[address] = peer
		return connection, nil
	}
	retained, err := table.DialConsensusEndpoint(
		context.Background(),
		retainedEndpoint,
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint(retained) error = %v", err)
	}
	removed, err := table.DialConsensusEndpoint(
		context.Background(),
		removedEndpoint,
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint(removed) error = %v", err)
	}
	t.Cleanup(func() {
		_ = retained.Close()
		_ = removed.Close()
		for _, peer := range peers {
			_ = peer.Close()
		}
	})

	retainedTracked := retained.(*consensusRouteTableConn)
	removedTracked := removed.(*consensusRouteTableConn)
	table.mu.Lock()
	retainedAddress, retainedRegistered := table.connections[retainedTracked]
	removedAddress, removedRegistered := table.connections[removedTracked]
	table.mu.Unlock()
	if !retainedRegistered || retainedAddress != retainedLocal {
		t.Fatalf(
			"retained connection registration = (%s, %t), want (%s, true)",
			retainedAddress,
			retainedRegistered,
			retainedLocal,
		)
	}
	if !removedRegistered || removedAddress != removedLocal {
		t.Fatalf(
			"removed connection registration = (%s, %t), want (%s, true)",
			removedAddress,
			removedRegistered,
			removedLocal,
		)
	}

	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{retainedLocal, retainedLocal},
	); !errors.Is(err, ErrInvalidConsensusRouteTable) {
		t.Fatalf("ReplaceSelectedAddresses(invalid) error = %v", err)
	}
	if got := consensusRouteTableConnectionCount(table); got != 2 {
		t.Fatalf("tracked connections after rejected refresh = %d, want 2", got)
	}

	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{retainedLocal},
	); err != nil {
		t.Fatalf("ReplaceSelectedAddresses() error = %v", err)
	}
	assertConsensusRoutePeerClosed(
		t,
		peers[removedEndpoint.String()],
	)
	table.mu.Lock()
	_, retainedRegistered = table.connections[retainedTracked]
	_, removedRegistered = table.connections[removedTracked]
	table.mu.Unlock()
	if !retainedRegistered || removedRegistered {
		t.Fatalf(
			"registrations after refresh = (retained %t, removed %t)",
			retainedRegistered,
			removedRegistered,
		)
	}

	if err := retained.Close(); err != nil {
		t.Fatalf("retained.Close() error = %v", err)
	}
	if got := consensusRouteTableConnectionCount(table); got != 0 {
		t.Fatalf("tracked connections after Close = %d, want 0", got)
	}
	assertConsensusRoutePeerClosed(
		t,
		peers[retainedEndpoint.String()],
	)
}

func TestConsensusRouteTableRebindClosesConnectionAndRetainsRoute(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddr("192.0.2.10")
	endpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       endpoint,
				SelectedLocalAddress: local,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	var peer net.Conn
	table.dialContext = func(
		context.Context,
		*net.Dialer,
		string,
		string,
	) (net.Conn, error) {
		connection, remote := net.Pipe()
		peer = remote
		return connection, nil
	}
	connection, err := table.DialConsensusEndpoint(
		context.Background(),
		endpoint,
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint() error = %v", err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})

	if err := table.RebindSelectedAddresses(
		[]netip.Addr{local},
		[]netip.Addr{local},
	); err != nil {
		t.Fatalf("RebindSelectedAddresses() error = %v", err)
	}
	assertConsensusRoutePeerClosed(t, peer)
	if got := consensusRouteTableConnectionCount(table); got != 0 {
		t.Fatalf("tracked connections after rebind = %d, want 0", got)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != endpoint {
		t.Fatalf("route after rebind = (%v, %v)", endpoints, err)
	}
}

func TestConsensusRouteTableInvalidRebindIsAtomic(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddr("192.0.2.10")
	unselected := netip.MustParseAddr("192.0.2.11")
	endpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       endpoint,
				SelectedLocalAddress: local,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	var peer net.Conn
	table.dialContext = func(
		context.Context,
		*net.Dialer,
		string,
		string,
	) (net.Conn, error) {
		connection, remote := net.Pipe()
		peer = remote
		return connection, nil
	}
	connection, err := table.DialConsensusEndpoint(
		context.Background(),
		endpoint,
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint() error = %v", err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})

	for _, input := range []struct {
		selected []netip.Addr
		rebound  []netip.Addr
	}{
		{
			selected: []netip.Addr{local},
			rebound:  []netip.Addr{unselected},
		},
		{
			selected: []netip.Addr{local, unselected},
			rebound:  []netip.Addr{unselected},
		},
	} {
		if err := table.RebindSelectedAddresses(
			input.selected,
			input.rebound,
		); !errors.Is(err, ErrInvalidConsensusRouteTable) {
			t.Fatalf(
				"RebindSelectedAddresses(%v, %v) error = %v",
				input.selected,
				input.rebound,
				err,
			)
		}
	}
	if got := consensusRouteTableConnectionCount(table); got != 1 {
		t.Fatalf("tracked connections after rejected rebind = %d, want 1", got)
	}
	endpoints, err := table.ResolveConsensusEndpoints(
		context.Background(),
		routeTablePeerA,
	)
	if err != nil || len(endpoints) != 1 || endpoints[0] != endpoint {
		t.Fatalf("route after rejected rebind = (%v, %v)", endpoints, err)
	}

	if err := table.RebindSelectedAddresses(
		[]netip.Addr{local},
		[]netip.Addr{local},
	); err != nil {
		t.Fatalf("valid RebindSelectedAddresses() error = %v", err)
	}
	assertConsensusRoutePeerClosed(t, peer)
}

func TestConsensusRouteTableDialReturnsPostDialContextCancellation(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddr("192.0.2.10")
	endpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{local},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       endpoint,
				SelectedLocalAddress: local,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var peer net.Conn
	table.dialContext = func(
		context.Context,
		*net.Dialer,
		string,
		string,
	) (net.Conn, error) {
		connection, remote := net.Pipe()
		peer = remote
		cancel()
		return connection, nil
	}
	connection, err := table.DialConsensusEndpoint(ctx, endpoint)
	if connection != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"DialConsensusEndpoint() = (%v, %v), want (nil, canceled)",
			connection,
			err,
		)
	}
	t.Cleanup(func() { _ = peer.Close() })
	assertConsensusRoutePeerClosed(t, peer)
	if got := consensusRouteTableConnectionCount(table); got != 0 {
		t.Fatalf("tracked connections after canceled dial = %d, want 0", got)
	}
}

func TestConsensusRouteTableDialFailsClosedAcrossAddressReplacement(
	t *testing.T,
) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	originalLocal := netip.MustParseAddr("192.0.2.10")
	replacementLocal := netip.MustParseAddr("192.0.2.11")
	endpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{originalLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       endpoint,
				SelectedLocalAddress: originalLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseDial)
		})
	}
	defer release()
	peerResult := make(chan net.Conn, 1)
	table.dialContext = func(
		_ context.Context,
		_ *net.Dialer,
		_ string,
		_ string,
	) (net.Conn, error) {
		close(dialStarted)
		<-releaseDial
		connection, peer := net.Pipe()
		peerResult <- peer
		return connection, nil
	}
	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		connection, dialErr := table.DialConsensusEndpoint(
			context.Background(),
			endpoint,
		)
		result <- dialResult{connection: connection, err: dialErr}
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("DialConsensusEndpoint() did not reach dial")
	}
	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{replacementLocal},
	); err != nil {
		t.Fatalf("ReplaceSelectedAddresses(replacement) error = %v", err)
	}
	if err := table.ReplaceSelectedAddresses(
		[]netip.Addr{originalLocal},
	); err != nil {
		t.Fatalf("ReplaceSelectedAddresses(re-add) error = %v", err)
	}
	release()

	var dial dialResult
	select {
	case dial = <-result:
	case <-time.After(time.Second):
		t.Fatal("DialConsensusEndpoint() did not return")
	}
	if dial.connection != nil ||
		!errors.Is(dial.err, ErrConsensusEndpointUnavailable) {
		t.Fatalf(
			"DialConsensusEndpoint() = (%v, %v), want (nil, unavailable)",
			dial.connection,
			dial.err,
		)
	}
	peer := <-peerResult
	defer peer.Close()
	assertConsensusRoutePeerClosed(t, peer)
	if got := consensusRouteTableConnectionCount(table); got != 0 {
		t.Fatalf("tracked connections after stale dial = %d, want 0", got)
	}
}

func TestConsensusRouteTableRefreshClosesOutsideTableLock(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	originalLocal := netip.MustParseAddr("192.0.2.10")
	replacementLocal := netip.MustParseAddr("192.0.2.11")
	endpoint := netip.MustParseAddrPort("192.0.2.20:47831")
	table, err := newConsensusRouteTable(
		[]netip.Addr{originalLocal},
		nil,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newConsensusRouteTable() error = %v", err)
	}
	if err := table.Replace(
		routeTablePeerA,
		ConsensusRouteSigned,
		[]ExpiringConsensusRoute{{
			ConsensusRoute: ConsensusRoute{
				PeerDeviceID:         routeTablePeerA,
				RemoteEndpoint:       endpoint,
				SelectedLocalAddress: originalLocal,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseClose)
		})
	}
	defer release()
	var peer net.Conn
	table.dialContext = func(
		_ context.Context,
		_ *net.Dialer,
		_ string,
		_ string,
	) (net.Conn, error) {
		connection, remote := net.Pipe()
		peer = remote
		return &blockingConsensusRouteCloseConn{
			Conn:    connection,
			started: closeStarted,
			release: releaseClose,
		}, nil
	}
	connection, err := table.DialConsensusEndpoint(
		context.Background(),
		endpoint,
	)
	if err != nil {
		t.Fatalf("DialConsensusEndpoint() error = %v", err)
	}
	t.Cleanup(func() {
		release()
		_ = connection.Close()
		_ = peer.Close()
	})

	replaceResult := make(chan error, 1)
	go func() {
		replaceResult <- table.ReplaceSelectedAddresses(
			[]netip.Addr{replacementLocal},
		)
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("ReplaceSelectedAddresses() did not close the connection")
	}

	resolveResult := make(chan error, 1)
	go func() {
		_, resolveErr := table.ResolveConsensusEndpoints(
			context.Background(),
			routeTablePeerA,
		)
		resolveResult <- resolveErr
	}()
	select {
	case resolveErr := <-resolveResult:
		if !errors.Is(resolveErr, ErrConsensusEndpointUnavailable) {
			t.Fatalf(
				"ResolveConsensusEndpoints() during Close error = %v",
				resolveErr,
			)
		}
	case <-time.After(time.Second):
		t.Fatal("route table lock remained held while closing a connection")
	}

	release()
	select {
	case replaceErr := <-replaceResult:
		if replaceErr != nil {
			t.Fatalf("ReplaceSelectedAddresses() error = %v", replaceErr)
		}
	case <-time.After(time.Second):
		t.Fatal("ReplaceSelectedAddresses() did not return after Close")
	}
	assertConsensusRoutePeerClosed(t, peer)
}

type blockingConsensusRouteCloseConn struct {
	net.Conn

	started     chan struct{}
	release     <-chan struct{}
	startedOnce sync.Once
}

func (connection *blockingConsensusRouteCloseConn) Close() error {
	connection.startedOnce.Do(func() {
		close(connection.started)
	})
	<-connection.release
	return connection.Conn.Close()
}

func consensusRouteTableConnectionCount(table *ConsensusRouteTable) int {
	table.mu.Lock()
	defer table.mu.Unlock()
	return len(table.connections)
}

func assertConsensusRoutePeerClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(
		time.Now().Add(time.Second),
	); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	var buffer [1]byte
	if _, err := connection.Read(buffer[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() after peer Close error = %v, want EOF", err)
	}
}
