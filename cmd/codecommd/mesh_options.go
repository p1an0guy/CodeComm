package main

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/transport"
)

type daemonStringList []string

func (values *daemonStringList) String() string {
	return strings.Join(*values, ",")
}

func (values *daemonStringList) Set(value string) error {
	if value == "" {
		return errInvalidDaemonOptions
	}
	*values = append(*values, value)
	return nil
}

type daemonPeerRoute struct {
	deviceID domain.DeviceID
	remote   netip.AddrPort
	local    netip.Addr
}

func parseDaemonMeshOptions(
	listenerValues []string,
	routeValues []string,
) ([]netip.AddrPort, []daemonPeerRoute, error) {
	if len(listenerValues) == 0 {
		if len(routeValues) != 0 {
			return nil, nil, fmt.Errorf(
				"%w: peer routes require at least one peer listener",
				errInvalidDaemonOptions,
			)
		}
		return nil, nil, nil
	}
	listeners := make([]netip.AddrPort, len(listenerValues))
	for index, value := range listenerValues {
		address, err := netip.ParseAddrPort(value)
		if err != nil || !validDaemonSelectedAddress(address.Addr()) ||
			address.Port() == 0 {
			return nil, nil, fmt.Errorf(
				"%w: invalid selected peer listener %q",
				errInvalidDaemonOptions,
				value,
			)
		}
		listeners[index] = address
	}
	sort.Slice(listeners, func(left, right int) bool {
		return listeners[left].Compare(listeners[right]) < 0
	})
	for index := 1; index < len(listeners); index++ {
		if listeners[index-1] == listeners[index] {
			return nil, nil, fmt.Errorf(
				"%w: duplicate peer listener",
				errInvalidDaemonOptions,
			)
		}
	}
	selectedAddresses := make(map[netip.Addr]struct{}, len(listeners))
	for _, listener := range listeners {
		selectedAddresses[listener.Addr()] = struct{}{}
	}

	routes := make([]daemonPeerRoute, len(routeValues))
	for index, value := range routeValues {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return nil, nil, fmt.Errorf(
				"%w: peer route must be device,remote,local",
				errInvalidDaemonOptions,
			)
		}
		deviceID := domain.DeviceID(parts[0])
		remote, remoteErr := netip.ParseAddrPort(parts[1])
		local, localErr := netip.ParseAddr(parts[2])
		if !deviceID.Valid() ||
			remoteErr != nil ||
			localErr != nil ||
			remote.Port() == 0 ||
			!validDaemonSelectedAddress(remote.Addr()) ||
			!validDaemonSelectedAddress(local) ||
			remote.Addr().Is4() != local.Is4() {
			return nil, nil, fmt.Errorf(
				"%w: invalid peer route %q",
				errInvalidDaemonOptions,
				value,
			)
		}
		if _, selected := selectedAddresses[local]; !selected {
			return nil, nil, fmt.Errorf(
				"%w: peer route local address is not selected",
				errInvalidDaemonOptions,
			)
		}
		routes[index] = daemonPeerRoute{
			deviceID: deviceID,
			remote:   remote,
			local:    local,
		}
	}
	sort.Slice(routes, func(left, right int) bool {
		if routes[left].deviceID != routes[right].deviceID {
			return routes[left].deviceID < routes[right].deviceID
		}
		return routes[left].remote.Compare(routes[right].remote) < 0
	})
	for index := 1; index < len(routes); index++ {
		if routes[index-1].deviceID == routes[index].deviceID &&
			routes[index-1].remote == routes[index].remote {
			return nil, nil, fmt.Errorf(
				"%w: duplicate peer route",
				errInvalidDaemonOptions,
			)
		}
	}
	transportRoutes := make([]transport.ConsensusRoute, len(routes))
	for index, route := range routes {
		transportRoutes[index] = transport.ConsensusRoute{
			PeerDeviceID:         route.deviceID,
			RemoteEndpoint:       route.remote,
			SelectedLocalAddress: route.local,
		}
	}
	if _, err := transport.NewStaticConsensusRoutes(
		transportRoutes,
	); err != nil {
		return nil, nil, fmt.Errorf(
			"%w: peer routes: %v",
			errInvalidDaemonOptions,
			err,
		)
	}
	return listeners, routes, nil
}

func validDaemonSelectedAddress(address netip.Addr) bool {
	if !address.IsValid() ||
		address.IsUnspecified() ||
		address.IsLoopback() ||
		address.IsMulticast() ||
		address.Is4In6() {
		return false
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		return address.Zone() != ""
	}
	if address.Zone() != "" {
		return false
	}
	return address.IsGlobalUnicast() || address.IsLinkLocalUnicast()
}

func validateDaemonMeshOptions(options daemonOptions) error {
	listenerValues := make([]string, len(options.peerListeners))
	for index, listener := range options.peerListeners {
		listenerValues[index] = listener.String()
	}
	routeValues := make([]string, len(options.peerRoutes))
	for index, route := range options.peerRoutes {
		routeValues[index] = strings.Join([]string{
			string(route.deviceID),
			route.remote.String(),
			route.local.String(),
		}, ",")
	}
	listeners, routes, err := parseDaemonMeshOptions(
		listenerValues,
		routeValues,
	)
	if err != nil {
		return err
	}
	if !sameDaemonListeners(listeners, options.peerListeners) ||
		!sameDaemonRoutes(routes, options.peerRoutes) {
		return errors.New("codecommd: noncanonical mesh options")
	}
	return nil
}

func sameDaemonListeners(left, right []netip.AddrPort) bool {
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

func sameDaemonRoutes(left, right []daemonPeerRoute) bool {
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
