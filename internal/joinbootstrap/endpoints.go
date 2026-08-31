package joinbootstrap

import (
	"bytes"
	"context"
	"net"
	"net/netip"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/transport"
)

type pinnedEndpoints struct {
	peer      domain.DeviceID
	endpoints []netip.AddrPort
	allowed   map[netip.AddrPort]struct{}
	dial      func(context.Context, string, string) (net.Conn, error)
}

func newPinnedEndpoints(
	peer domain.DeviceID,
	endpoints []netip.AddrPort,
	dial func(context.Context, string, string) (net.Conn, error),
) (*pinnedEndpoints, error) {
	if !peer.Valid() ||
		len(endpoints) == 0 ||
		len(endpoints) > pairing.MaxInviteEndpoints {
		return nil, ErrInvalidOptions
	}
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	result := &pinnedEndpoints{
		peer:      peer,
		endpoints: append([]netip.AddrPort(nil), endpoints...),
		allowed:   make(map[netip.AddrPort]struct{}, len(endpoints)),
		dial:      dial,
	}
	for index, endpoint := range result.endpoints {
		if !validJoinEndpoint(endpoint) {
			return nil, ErrInvalidOptions
		}
		if _, duplicate := result.allowed[endpoint]; duplicate {
			return nil, ErrInvalidOptions
		}
		if index > 0 &&
			compareJoinEndpoints(result.endpoints[index-1], endpoint) >= 0 {
			return nil, ErrInvalidOptions
		}
		result.allowed[endpoint] = struct{}{}
	}
	return result, nil
}

func (routes *pinnedEndpoints) ResolveConsensusEndpoints(
	ctx context.Context,
	peer domain.DeviceID,
) ([]netip.AddrPort, error) {
	if routes == nil || ctx == nil || peer != routes.peer {
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]netip.AddrPort(nil), routes.endpoints...), nil
}

func (routes *pinnedEndpoints) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	if routes == nil || ctx == nil {
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, allowed := routes.allowed[endpoint]; !allowed {
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	return routes.dial(ctx, network, endpoint.String())
}

func (routes *pinnedEndpoints) DialPairingEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	return routes.DialConsensusEndpoint(ctx, endpoint)
}

func validJoinEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return endpoint.IsValid() &&
		endpoint.Port() != 0 &&
		address.IsValid() &&
		!address.Is4In6() &&
		!address.IsLoopback() &&
		!address.IsUnspecified() &&
		!address.IsMulticast() &&
		address.Zone() == "" &&
		!(address.Is6() && address.IsLinkLocalUnicast()) &&
		(!address.Is4() ||
			address.As4() != [4]byte{255, 255, 255, 255})
}

func compareJoinEndpoints(left, right netip.AddrPort) int {
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
	switch {
	case left.Port() < right.Port():
		return -1
	case left.Port() > right.Port():
		return 1
	default:
		return 0
	}
}

var (
	_ transport.ConsensusEndpointResolver = (*pinnedEndpoints)(nil)
	_ transport.ConsensusEndpointDialer   = (*pinnedEndpoints)(nil)
)
