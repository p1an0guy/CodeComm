package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	ConsensusStaticRoutesPerPeerMax = 16
	ConsensusStaticRoutesMax        = 128
)

var (
	ErrInvalidConsensusRoutes = errors.New(
		"transport: invalid static consensus routes",
	)
	ErrConsensusRouteOrder = errors.New(
		"transport: static consensus routes are not in canonical order",
	)
	ErrDuplicateConsensusRoute = errors.New(
		"transport: duplicate static consensus route",
	)
)

// ConsensusRoute binds one peer endpoint to the selected local source address
// that the operating system must use for the connection.
type ConsensusRoute struct {
	PeerDeviceID         domain.DeviceID
	RemoteEndpoint       netip.AddrPort
	SelectedLocalAddress netip.Addr
}

// StaticConsensusRoutes is an immutable resolver and selected-source dialer
// for explicitly configured peer routes.
type StaticConsensusRoutes struct {
	endpointsByPeer  map[domain.DeviceID][]netip.AddrPort
	routesByEndpoint map[netip.AddrPort]netip.Addr
}

var (
	_ ConsensusEndpointResolver = (*StaticConsensusRoutes)(nil)
	_ ConsensusEndpointDialer   = (*StaticConsensusRoutes)(nil)
)

// NewStaticConsensusRoutes validates and snapshots routes ordered by peer ID,
// then remote address family, address bytes, IPv6 zone, and port.
func NewStaticConsensusRoutes(
	routes []ConsensusRoute,
) (*StaticConsensusRoutes, error) {
	if len(routes) > ConsensusStaticRoutesMax {
		return nil, ErrInvalidConsensusRoutes
	}

	table := &StaticConsensusRoutes{
		endpointsByPeer: make(
			map[domain.DeviceID][]netip.AddrPort,
		),
		routesByEndpoint: make(
			map[netip.AddrPort]netip.Addr,
			len(routes),
		),
	}
	for index, route := range routes {
		if err := validateConsensusRoute(route); err != nil {
			return nil, fmt.Errorf(
				"%w at index %d: %v",
				ErrInvalidConsensusRoutes,
				index,
				err,
			)
		}
		if index > 0 {
			order := compareConsensusRoutes(routes[index-1], route)
			switch {
			case order == 0:
				return nil, fmt.Errorf(
					"%w at index %d",
					ErrDuplicateConsensusRoute,
					index,
				)
			case order > 0:
				return nil, fmt.Errorf(
					"%w at index %d",
					ErrConsensusRouteOrder,
					index,
				)
			}
		}
		if _, duplicate := table.routesByEndpoint[route.RemoteEndpoint]; duplicate {
			return nil, fmt.Errorf(
				"%w: endpoint %s",
				ErrDuplicateConsensusRoute,
				route.RemoteEndpoint,
			)
		}

		endpoints := table.endpointsByPeer[route.PeerDeviceID]
		if len(endpoints) == ConsensusStaticRoutesPerPeerMax {
			return nil, fmt.Errorf(
				"%w: peer %s exceeds %d routes",
				ErrInvalidConsensusRoutes,
				route.PeerDeviceID,
				ConsensusStaticRoutesPerPeerMax,
			)
		}
		table.endpointsByPeer[route.PeerDeviceID] = append(
			endpoints,
			route.RemoteEndpoint,
		)
		table.routesByEndpoint[route.RemoteEndpoint] =
			route.SelectedLocalAddress
	}
	return table, nil
}

// ResolveConsensusEndpoints returns a defensive copy of one configured peer's
// canonical endpoint list.
func (routes *StaticConsensusRoutes) ResolveConsensusEndpoints(
	ctx context.Context,
	deviceID domain.DeviceID,
) ([]netip.AddrPort, error) {
	if routes == nil || ctx == nil || !deviceID.Valid() {
		return nil, ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoints, exists := routes.endpointsByPeer[deviceID]
	if !exists || len(endpoints) == 0 {
		return nil, ErrConsensusEndpointUnavailable
	}
	return append([]netip.AddrPort(nil), endpoints...), nil
}

// DialConsensusEndpoint dials only an exact configured endpoint and binds the
// socket to that route's selected local source address.
func (routes *StaticConsensusRoutes) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	dialer, network, address, err := routes.dialConfiguration(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, address)
}

func (routes *StaticConsensusRoutes) dialConfiguration(
	ctx context.Context,
	endpoint netip.AddrPort,
) (*net.Dialer, string, string, error) {
	if routes == nil || ctx == nil {
		return nil, "", "", ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, "", "", err
	}
	localAddress, exists := routes.routesByEndpoint[endpoint]
	if !exists {
		return nil, "", "", ErrConsensusEndpointUnavailable
	}
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	localEndpoint := netip.AddrPortFrom(localAddress, 0)
	return &net.Dialer{
		LocalAddr: net.TCPAddrFromAddrPort(localEndpoint),
	}, network, endpoint.String(), nil
}

func validateConsensusRoute(route ConsensusRoute) error {
	if !route.PeerDeviceID.Valid() {
		return errors.New("invalid peer device ID")
	}
	if !validStaticConsensusEndpoint(route.RemoteEndpoint) {
		return errors.New("invalid remote endpoint")
	}
	if !validSelectedSourceAddress(route.SelectedLocalAddress) {
		return errors.New("invalid selected local address")
	}
	remoteAddress := route.RemoteEndpoint.Addr()
	localAddress := route.SelectedLocalAddress
	if remoteAddress.Is4() != localAddress.Is4() {
		return errors.New("remote and local address families differ")
	}
	if remoteAddress.Is6() &&
		(remoteAddress.IsLinkLocalUnicast() ||
			localAddress.IsLinkLocalUnicast()) &&
		(remoteAddress.Zone() == "" ||
			remoteAddress.Zone() != localAddress.Zone()) {
		return errors.New("IPv6 link-local route zones differ")
	}
	return nil
}

func validStaticConsensusEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() &&
		endpoint.Port() != 0 &&
		validStaticConsensusAddress(endpoint.Addr())
}

func validSelectedSourceAddress(address netip.Addr) bool {
	return validStaticConsensusAddress(address)
}

func validStaticConsensusAddress(address netip.Addr) bool {
	if !address.IsValid() ||
		address.Is4In6() ||
		address.IsLoopback() ||
		address.IsUnspecified() ||
		address.IsMulticast() ||
		!(address.IsGlobalUnicast() || address.IsLinkLocalUnicast()) {
		return false
	}
	if address.Is4() {
		return address.Zone() == "" &&
			address.As4() != [4]byte{255, 255, 255, 255}
	}
	if address.IsLinkLocalUnicast() {
		return address.Zone() != ""
	}
	return address.Zone() == ""
}

func compareConsensusRoutes(left, right ConsensusRoute) int {
	if left.PeerDeviceID < right.PeerDeviceID {
		return -1
	}
	if left.PeerDeviceID > right.PeerDeviceID {
		return 1
	}
	return compareConsensusRouteEndpoints(
		left.RemoteEndpoint,
		right.RemoteEndpoint,
	)
}

func compareConsensusRouteEndpoints(left, right netip.AddrPort) int {
	leftAddress := left.Addr()
	rightAddress := right.Addr()
	if leftAddress.Is4() != rightAddress.Is4() {
		if leftAddress.Is4() {
			return -1
		}
		return 1
	}
	if order := bytes.Compare(
		leftAddress.AsSlice(),
		rightAddress.AsSlice(),
	); order != 0 {
		return order
	}
	if leftAddress.Zone() < rightAddress.Zone() {
		return -1
	}
	if leftAddress.Zone() > rightAddress.Zone() {
		return 1
	}
	if left.Port() < right.Port() {
		return -1
	}
	if left.Port() > right.Port() {
		return 1
	}
	return 0
}
