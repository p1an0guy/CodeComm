package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestStaticConsensusRoutesResolveAndDefensivelyCopy(t *testing.T) {
	firstPeer := consensusRouteTestDeviceID('1')
	secondPeer := consensusRouteTestDeviceID('2')
	firstEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	secondEndpoint := netip.MustParseAddrPort("198.51.100.20:47831")
	ipv6Endpoint := netip.MustParseAddrPort("[2001:db8::20]:47831")
	input := []ConsensusRoute{
		{
			PeerDeviceID:         firstPeer,
			RemoteEndpoint:       firstEndpoint,
			SelectedLocalAddress: netip.MustParseAddr("10.0.0.10"),
		},
		{
			PeerDeviceID:         firstPeer,
			RemoteEndpoint:       secondEndpoint,
			SelectedLocalAddress: netip.MustParseAddr("10.0.0.10"),
		},
		{
			PeerDeviceID:         secondPeer,
			RemoteEndpoint:       ipv6Endpoint,
			SelectedLocalAddress: netip.MustParseAddr("fd00::10"),
		},
	}
	routes, err := NewStaticConsensusRoutes(input)
	if err != nil {
		t.Fatalf("NewStaticConsensusRoutes() error = %v", err)
	}
	input[0].RemoteEndpoint = netip.MustParseAddrPort("203.0.113.1:1")

	resolved, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		firstPeer,
	)
	if err != nil {
		t.Fatalf("ResolveConsensusEndpoints() error = %v", err)
	}
	want := []netip.AddrPort{firstEndpoint, secondEndpoint}
	if !equalConsensusRouteEndpoints(resolved, want) {
		t.Fatalf("resolved endpoints = %v, want %v", resolved, want)
	}
	resolved[0] = netip.MustParseAddrPort("203.0.113.2:2")
	again, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		firstPeer,
	)
	if err != nil {
		t.Fatalf("ResolveConsensusEndpoints(second call) error = %v", err)
	}
	if !equalConsensusRouteEndpoints(again, want) {
		t.Fatalf("resolved endpoints after caller mutation = %v, want %v", again, want)
	}

	ipv6, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		secondPeer,
	)
	if err != nil {
		t.Fatalf("ResolveConsensusEndpoints(IPv6) error = %v", err)
	}
	if !equalConsensusRouteEndpoints(
		ipv6,
		[]netip.AddrPort{ipv6Endpoint},
	) {
		t.Fatalf("resolved IPv6 endpoints = %v", ipv6)
	}
}

func TestStaticConsensusRoutesFailClosedForUnknownPeerAndEndpoint(
	t *testing.T,
) {
	route := validConsensusRouteForTest()
	routes, err := NewStaticConsensusRoutes([]ConsensusRoute{route})
	if err != nil {
		t.Fatalf("NewStaticConsensusRoutes() error = %v", err)
	}

	if _, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		consensusRouteTestDeviceID('f'),
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf(
			"ResolveConsensusEndpoints(unknown) error = %v, want %v",
			err,
			ErrConsensusEndpointUnavailable,
		)
	}
	if connection, err := routes.DialConsensusEndpoint(
		context.Background(),
		netip.MustParseAddrPort("192.0.2.99:47831"),
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf(
			"DialConsensusEndpoint(unknown) error = %v, want %v",
			err,
			ErrConsensusEndpointUnavailable,
		)
	}

	var nilRoutes *StaticConsensusRoutes
	if _, err := nilRoutes.ResolveConsensusEndpoints(
		context.Background(),
		route.PeerDeviceID,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf("nil resolver error = %v", err)
	}
	if connection, err := nilRoutes.DialConsensusEndpoint(
		context.Background(),
		route.RemoteEndpoint,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("nil dialer error = %v", err)
	}
}

func TestStaticConsensusRoutesMayBeEmptyAndRemainFailClosed(t *testing.T) {
	routes, err := NewStaticConsensusRoutes(nil)
	if err != nil {
		t.Fatalf("NewStaticConsensusRoutes(nil) error = %v", err)
	}
	peer := consensusRouteTestDeviceID('1')
	if _, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		peer,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		t.Fatalf("empty resolver error = %v", err)
	}
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	if connection, err := routes.DialConsensusEndpoint(
		context.Background(),
		endpoint,
	); !errors.Is(err, ErrConsensusEndpointUnavailable) {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("empty dialer error = %v", err)
	}
}

func TestStaticConsensusRoutesDialConfigurationUsesSelectedSource(
	t *testing.T,
) {
	tests := []struct {
		name    string
		route   ConsensusRoute
		network string
	}{
		{
			name:    "IPv4",
			route:   validConsensusRouteForTest(),
			network: "tcp4",
		},
		{
			name: "IPv6",
			route: ConsensusRoute{
				PeerDeviceID: consensusRouteTestDeviceID('2'),
				RemoteEndpoint: netip.MustParseAddrPort(
					"[2001:db8::20]:47831",
				),
				SelectedLocalAddress: netip.MustParseAddr("fd00::20"),
			},
			network: "tcp6",
		},
		{
			name: "IPv6 link-local",
			route: ConsensusRoute{
				PeerDeviceID: consensusRouteTestDeviceID('3'),
				RemoteEndpoint: netip.MustParseAddrPort(
					"[fe80::20%7]:47831",
				),
				SelectedLocalAddress: netip.MustParseAddr("fe80::10%7"),
			},
			network: "tcp6",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			routes, err := NewStaticConsensusRoutes(
				[]ConsensusRoute{test.route},
			)
			if err != nil {
				t.Fatalf("NewStaticConsensusRoutes() error = %v", err)
			}
			dialer, network, address, err := routes.dialConfiguration(
				context.Background(),
				test.route.RemoteEndpoint,
			)
			if err != nil {
				t.Fatalf("dialConfiguration() error = %v", err)
			}
			if network != test.network {
				t.Fatalf("network = %q, want %q", network, test.network)
			}
			if address != test.route.RemoteEndpoint.String() {
				t.Fatalf(
					"address = %q, want %q",
					address,
					test.route.RemoteEndpoint,
				)
			}
			local, ok := dialer.LocalAddr.(*net.TCPAddr)
			if !ok {
				t.Fatalf("LocalAddr type = %T, want *net.TCPAddr", dialer.LocalAddr)
			}
			wantLocal := netip.AddrPortFrom(
				test.route.SelectedLocalAddress,
				0,
			)
			if got := local.AddrPort(); got != wantLocal {
				t.Fatalf("LocalAddr = %s, want %s", got, wantLocal)
			}
		})
	}
}

func TestStaticConsensusRoutesHonorCancellation(t *testing.T) {
	route := validConsensusRouteForTest()
	routes, err := NewStaticConsensusRoutes([]ConsensusRoute{route})
	if err != nil {
		t.Fatalf("NewStaticConsensusRoutes() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := routes.ResolveConsensusEndpoints(
		ctx,
		route.PeerDeviceID,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveConsensusEndpoints(canceled) error = %v", err)
	}
	if connection, err := routes.DialConsensusEndpoint(
		ctx,
		route.RemoteEndpoint,
	); !errors.Is(err, context.Canceled) {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("DialConsensusEndpoint(canceled) error = %v", err)
	}
}

func TestNewStaticConsensusRoutesRejectsInvalidRoutes(t *testing.T) {
	valid := validConsensusRouteForTest()
	ipv6 := ConsensusRoute{
		PeerDeviceID: consensusRouteTestDeviceID('1'),
		RemoteEndpoint: netip.MustParseAddrPort(
			"[2001:db8::20]:47831",
		),
		SelectedLocalAddress: netip.MustParseAddr("fd00::20"),
	}
	tests := []struct {
		name   string
		routes []ConsensusRoute
		target error
	}{
		{
			name: "invalid peer",
			routes: []ConsensusRoute{
				withConsensusRoutePeer(valid, "bad"),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "invalid remote endpoint",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(valid, netip.AddrPort{}),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "zero remote port",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.AddrPortFrom(
						netip.MustParseAddr("192.0.2.20"),
						0,
					),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote loopback",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.MustParseAddrPort("127.0.0.1:47831"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote unspecified",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.MustParseAddrPort("0.0.0.0:47831"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote multicast",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.MustParseAddrPort("224.0.0.1:47831"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote broadcast",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.MustParseAddrPort("255.255.255.255:47831"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote IPv4-mapped IPv6",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					ipv6,
					netip.MustParseAddrPort(
						"[::ffff:192.0.2.20]:47831",
					),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote link-local without zone",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					ipv6,
					netip.MustParseAddrPort("[fe80::20]:47831"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "remote global address with zone",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					ipv6,
					netip.AddrPortFrom(
						netip.MustParseAddr("2001:db8::20").WithZone("7"),
						47831,
					),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "invalid local address",
			routes: []ConsensusRoute{
				withConsensusRouteLocal(valid, netip.Addr{}),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "local loopback",
			routes: []ConsensusRoute{
				withConsensusRouteLocal(
					valid,
					netip.MustParseAddr("127.0.0.1"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "local multicast",
			routes: []ConsensusRoute{
				withConsensusRouteLocal(
					valid,
					netip.MustParseAddr("224.0.0.1"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "address family mismatch",
			routes: []ConsensusRoute{
				withConsensusRouteLocal(
					valid,
					netip.MustParseAddr("fd00::10"),
				),
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "link-local zone mismatch",
			routes: []ConsensusRoute{
				{
					PeerDeviceID: consensusRouteTestDeviceID('1'),
					RemoteEndpoint: netip.MustParseAddrPort(
						"[fe80::20%7]:47831",
					),
					SelectedLocalAddress: netip.MustParseAddr(
						"fe80::10%8",
					),
				},
			},
			target: ErrInvalidConsensusRoutes,
		},
		{
			name: "peer order",
			routes: []ConsensusRoute{
				withConsensusRoutePeer(
					valid,
					consensusRouteTestDeviceID('2'),
				),
				valid,
			},
			target: ErrConsensusRouteOrder,
		},
		{
			name: "endpoint order",
			routes: []ConsensusRoute{
				withConsensusRouteRemote(
					valid,
					netip.MustParseAddrPort("198.51.100.20:47831"),
				),
				valid,
			},
			target: ErrConsensusRouteOrder,
		},
		{
			name:   "exact duplicate",
			routes: []ConsensusRoute{valid, valid},
			target: ErrDuplicateConsensusRoute,
		},
		{
			name: "endpoint reused by another peer",
			routes: []ConsensusRoute{
				valid,
				withConsensusRoutePeer(
					valid,
					consensusRouteTestDeviceID('2'),
				),
			},
			target: ErrDuplicateConsensusRoute,
		},
		{
			name:   "too many routes for peer",
			routes: consensusRoutesForPeer(ConsensusStaticRoutesPerPeerMax + 1),
			target: ErrInvalidConsensusRoutes,
		},
		{
			name:   "too many routes",
			routes: consensusRouteCount(ConsensusStaticRoutesMax + 1),
			target: ErrInvalidConsensusRoutes,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			routes, err := NewStaticConsensusRoutes(test.routes)
			if routes != nil {
				t.Fatal("NewStaticConsensusRoutes() returned routes on error")
			}
			if !errors.Is(err, test.target) {
				t.Fatalf(
					"NewStaticConsensusRoutes() error = %v, want %v",
					err,
					test.target,
				)
			}
		})
	}
}

func TestNewStaticConsensusRoutesAcceptsCanonicalBounds(t *testing.T) {
	routes, err := NewStaticConsensusRoutes(
		consensusRouteCount(ConsensusStaticRoutesMax),
	)
	if err != nil {
		t.Fatalf("NewStaticConsensusRoutes(maximum) error = %v", err)
	}
	for peer := 1; peer <= 8; peer++ {
		endpoints, err := routes.ResolveConsensusEndpoints(
			context.Background(),
			consensusRouteTestDeviceID(byte('0'+peer)),
		)
		if err != nil {
			t.Fatalf("ResolveConsensusEndpoints(peer %d) error = %v", peer, err)
		}
		if len(endpoints) != ConsensusStaticRoutesPerPeerMax {
			t.Fatalf(
				"peer %d endpoint count = %d, want %d",
				peer,
				len(endpoints),
				ConsensusStaticRoutesPerPeerMax,
			)
		}
	}
}

func validConsensusRouteForTest() ConsensusRoute {
	return ConsensusRoute{
		PeerDeviceID:         consensusRouteTestDeviceID('1'),
		RemoteEndpoint:       netip.MustParseAddrPort("192.0.2.20:47831"),
		SelectedLocalAddress: netip.MustParseAddr("10.0.0.10"),
	}
}

func consensusRouteTestDeviceID(fill byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(fill), 64))
}

func withConsensusRoutePeer(
	route ConsensusRoute,
	deviceID domain.DeviceID,
) ConsensusRoute {
	route.PeerDeviceID = deviceID
	return route
}

func withConsensusRouteRemote(
	route ConsensusRoute,
	endpoint netip.AddrPort,
) ConsensusRoute {
	route.RemoteEndpoint = endpoint
	return route
}

func withConsensusRouteLocal(
	route ConsensusRoute,
	address netip.Addr,
) ConsensusRoute {
	route.SelectedLocalAddress = address
	return route
}

func consensusRoutesForPeer(count int) []ConsensusRoute {
	routes := make([]ConsensusRoute, count)
	for index := range routes {
		routes[index] = ConsensusRoute{
			PeerDeviceID: consensusRouteTestDeviceID('1'),
			RemoteEndpoint: netip.AddrPortFrom(
				netip.MustParseAddr("192.0.2.20"),
				uint16(40000+index),
			),
			SelectedLocalAddress: netip.MustParseAddr("10.0.0.10"),
		}
	}
	return routes
}

func consensusRouteCount(count int) []ConsensusRoute {
	routes := make([]ConsensusRoute, 0, count)
	for peer := 1; len(routes) < count; peer++ {
		deviceID := consensusRouteTestDeviceID(byte('0' + peer))
		for endpoint := 0; endpoint < ConsensusStaticRoutesPerPeerMax &&
			len(routes) < count; endpoint++ {
			routes = append(routes, ConsensusRoute{
				PeerDeviceID: deviceID,
				RemoteEndpoint: netip.AddrPortFrom(
					netip.AddrFrom4(
						[4]byte{192, 0, byte(peer), 20},
					),
					uint16(40000+endpoint),
				),
				SelectedLocalAddress: netip.AddrFrom4(
					[4]byte{10, 0, byte(peer), 10},
				),
			})
		}
	}
	return routes
}

func equalConsensusRouteEndpoints(
	left []netip.AddrPort,
	right []netip.AddrPort,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
