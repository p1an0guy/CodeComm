package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

var errDaemonEndpointRouteReconciliation = errors.New(
	"codecommd: endpoint route reconciliation failed",
)

type daemonEndpointRouteState interface {
	StatusSnapshot(
		context.Context,
		domain.DeviceID,
		int,
	) (coordstatus.DurableSnapshot, error)
	ExpireStalePeerEndpoints(context.Context, domain.Timestamp) (int, error)
	ListPeerEndpointCandidates(
		context.Context,
		domain.DeviceID,
		domain.Timestamp,
	) ([]store.PeerEndpointRecord, error)
	PurgePeerLearnedEndpoints(context.Context, domain.DeviceID) error
}

type daemonEndpointRouteReconciler struct {
	mu sync.Mutex

	localDeviceID domain.DeviceID
	state         daemonEndpointRouteState
	routes        *transport.ConsensusRouteTable
	staticManual  map[domain.DeviceID][]daemonConfiguredManualRoute
	bindings      map[daemonDiscoverySelector]netip.Addr
	now           func() time.Time
}

type daemonConfiguredManualRoute struct {
	remote          netip.AddrPort
	local           netip.Addr
	selector        daemonDiscoverySelector
	followsSelector bool
}

func newDaemonEndpointRouteReconciler(
	localDeviceID domain.DeviceID,
	state daemonEndpointRouteState,
	routes *transport.ConsensusRouteTable,
	configured []daemonPeerRoute,
	bindings map[daemonDiscoverySelector]netip.Addr,
) (*daemonEndpointRouteReconciler, error) {
	if !localDeviceID.Valid() || state == nil || routes == nil {
		return nil, errDaemonEndpointRouteReconciliation
	}
	if !validDaemonDiscoveryBindings(bindings) {
		return nil, errDaemonEndpointRouteReconciliation
	}
	manual := make(
		map[domain.DeviceID][]daemonConfiguredManualRoute,
	)
	for _, value := range configured {
		if !value.deviceID.Valid() ||
			!value.remote.IsValid() ||
			!value.local.IsValid() ||
			value.deviceID == localDeviceID {
			return nil, errDaemonEndpointRouteReconciliation
		}
		route := daemonConfiguredManualRoute{
			remote: value.remote,
			local:  value.local,
		}
		if bindings != nil {
			var matches int
			for selector, address := range bindings {
				if address == value.local {
					route.selector = selector
					matches++
				}
			}
			if matches != 1 {
				return nil, errDaemonEndpointRouteReconciliation
			}
			route.followsSelector = true
		}
		manual[value.deviceID] = append(manual[value.deviceID], route)
	}
	return &daemonEndpointRouteReconciler{
		localDeviceID: localDeviceID,
		state:         state,
		routes:        routes,
		staticManual:  manual,
		bindings:      cloneDaemonDiscoveryBindings(bindings),
		now:           time.Now,
	}, nil
}

func (reconciler *daemonEndpointRouteReconciler) replaceSelectedBindings(
	bindings map[daemonDiscoverySelector]netip.Addr,
) error {
	if reconciler == nil || !validDaemonDiscoveryBindings(bindings) {
		return errDaemonEndpointRouteReconciliation
	}
	reconciler.mu.Lock()
	reconciler.bindings = cloneDaemonDiscoveryBindings(bindings)
	reconciler.mu.Unlock()
	return nil
}

func (reconciler *daemonEndpointRouteReconciler) reconcile(
	ctx context.Context,
	selected []netip.Addr,
	includeDiscovery bool,
) error {
	if reconciler == nil ||
		reconciler.state == nil ||
		reconciler.routes == nil ||
		reconciler.now == nil ||
		ctx == nil {
		return errDaemonEndpointRouteReconciliation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	now := reconciler.now().UTC()
	if now.IsZero() {
		return errDaemonEndpointRouteReconciliation
	}
	nowValue := domain.Timestamp(now.Format(time.RFC3339Nano))
	if !nowValue.Valid() {
		return errDaemonEndpointRouteReconciliation
	}
	if _, err := reconciler.state.ExpireStalePeerEndpoints(
		ctx,
		nowValue,
	); err != nil {
		return fmt.Errorf(
			"%w: expire candidates: %w",
			errDaemonEndpointRouteReconciliation,
			err,
		)
	}
	snapshot, err := reconciler.state.StatusSnapshot(
		ctx,
		reconciler.localDeviceID,
		1,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: read membership: %w",
			errDaemonEndpointRouteReconciliation,
			err,
		)
	}
	if snapshot.MembersTruncated ||
		snapshot.MemberTotal != uint64(len(snapshot.Members)) {
		return fmt.Errorf(
			"%w: incomplete membership snapshot",
			errDaemonEndpointRouteReconciliation,
		)
	}

	for _, member := range snapshot.Members {
		if member.ID == reconciler.localDeviceID {
			reconciler.routes.PurgePeer(member.ID, false)
			continue
		}
		if member.Status != device.StatusActive {
			if err := reconciler.state.PurgePeerLearnedEndpoints(
				ctx,
				member.ID,
			); err != nil {
				return fmt.Errorf(
					"%w: purge peer %s: %w",
					errDaemonEndpointRouteReconciliation,
					member.ID,
					err,
				)
			}
			reconciler.routes.PurgePeer(member.ID, false)
			manual := daemonConfiguredManualRoutes(
				member.ID,
				reconciler.staticManual[member.ID],
				selected,
				reconciler.bindings,
			)
			if err := reconciler.routes.Replace(
				member.ID,
				transport.ConsensusRouteManual,
				manual,
			); err != nil {
				return fmt.Errorf(
					"%w: remap peer %s manual routes: %w",
					errDaemonEndpointRouteReconciliation,
					member.ID,
					err,
				)
			}
			continue
		}
		candidates, err := reconciler.state.ListPeerEndpointCandidates(
			ctx,
			member.ID,
			nowValue,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: list peer %s: %w",
				errDaemonEndpointRouteReconciliation,
				member.ID,
				err,
			)
		}
		grouped, err := daemonEndpointRoutes(
			member.ID,
			candidates,
			selected,
			now,
		)
		if err != nil {
			return err
		}
		manual, err := mergeDaemonManualRoutes(
			grouped[transport.ConsensusRouteManual],
			daemonConfiguredManualRoutes(
				member.ID,
				reconciler.staticManual[member.ID],
				selected,
				reconciler.bindings,
			),
		)
		if err != nil {
			return err
		}
		grouped[transport.ConsensusRouteManual] = manual
		for _, source := range []transport.ConsensusRouteSource{
			transport.ConsensusRouteManual,
			transport.ConsensusRouteSigned,
			transport.ConsensusRouteAuthenticated,
			transport.ConsensusRouteDiscovery,
		} {
			if source == transport.ConsensusRouteDiscovery &&
				!includeDiscovery {
				continue
			}
			if err := reconciler.routes.Replace(
				member.ID,
				source,
				grouped[source],
			); err != nil {
				return fmt.Errorf(
					"%w: install peer %s source %d: %w",
					errDaemonEndpointRouteReconciliation,
					member.ID,
					source,
					err,
				)
			}
		}
	}
	reconciler.routes.Expire()
	return nil
}

func daemonConfiguredManualRoutes(
	deviceID domain.DeviceID,
	configured []daemonConfiguredManualRoute,
	selected []netip.Addr,
	bindings map[daemonDiscoverySelector]netip.Addr,
) []transport.ExpiringConsensusRoute {
	result := make(
		[]transport.ExpiringConsensusRoute,
		0,
		len(configured),
	)
	for _, configuredRoute := range configured {
		local := configuredRoute.local
		if configuredRoute.followsSelector {
			var exists bool
			local, exists = bindings[configuredRoute.selector]
			if !exists {
				continue
			}
		}
		if !slices.Contains(selected, local) ||
			local.Is4() != configuredRoute.remote.Addr().Is4() {
			continue
		}
		result = append(result, transport.ExpiringConsensusRoute{
			ConsensusRoute: transport.ConsensusRoute{
				PeerDeviceID:         deviceID,
				RemoteEndpoint:       configuredRoute.remote,
				SelectedLocalAddress: local,
			},
		})
	}
	return result
}

func validDaemonDiscoveryBindings(
	bindings map[daemonDiscoverySelector]netip.Addr,
) bool {
	seen := make(map[netip.Addr]struct{}, len(bindings))
	for selector, address := range bindings {
		if selector.interfaceName == "" ||
			selector.family != discovery.AddressFamilyIPv4 &&
				selector.family != discovery.AddressFamilyIPv6 ||
			!validDaemonSelectedAddress(address) ||
			address.Is4() !=
				(selector.family == discovery.AddressFamilyIPv4) ||
			address.IsLinkLocalUnicast() != selector.linkLocal {
			return false
		}
		if _, duplicate := seen[address]; duplicate {
			return false
		}
		seen[address] = struct{}{}
	}
	return true
}

func daemonEndpointRoutes(
	deviceID domain.DeviceID,
	records []store.PeerEndpointRecord,
	selected []netip.Addr,
	now time.Time,
) (map[transport.ConsensusRouteSource][]transport.ExpiringConsensusRoute, error) {
	result := make(
		map[transport.ConsensusRouteSource][]transport.ExpiringConsensusRoute,
		4,
	)
	for _, record := range records {
		if record.DeviceID != deviceID || record.Validate() != nil {
			return nil, errDaemonEndpointRouteReconciliation
		}
		source, ok := daemonConsensusRouteSource(record.SourceKind)
		if !ok {
			return nil, errDaemonEndpointRouteReconciliation
		}
		local, ok := unambiguousDaemonRouteSource(
			record.Endpoint,
			selected,
		)
		if !ok {
			continue
		}
		var expiresAt time.Time
		if source != transport.ConsensusRouteManual {
			var err error
			expiresAt, err = record.ExpiresAt.Time()
			if err != nil || !expiresAt.After(now) {
				continue
			}
		}
		result[source] = append(
			result[source],
			transport.ExpiringConsensusRoute{
				ConsensusRoute: transport.ConsensusRoute{
					PeerDeviceID:         deviceID,
					RemoteEndpoint:       record.Endpoint,
					SelectedLocalAddress: local,
				},
				ExpiresAt: expiresAt,
			},
		)
	}
	for source := range result {
		slices.SortFunc(
			result[source],
			func(left, right transport.ExpiringConsensusRoute) int {
				return left.RemoteEndpoint.Compare(right.RemoteEndpoint)
			},
		)
	}
	return result, nil
}

func daemonConsensusRouteSource(
	source store.PeerEndpointSourceKind,
) (transport.ConsensusRouteSource, bool) {
	switch source {
	case store.PeerEndpointMemberSigned:
		return transport.ConsensusRouteSigned, true
	case store.PeerEndpointRawDiscovery:
		return transport.ConsensusRouteDiscovery, true
	case store.PeerEndpointAuthenticatedGuess:
		return transport.ConsensusRouteAuthenticated, true
	case store.PeerEndpointManual:
		return transport.ConsensusRouteManual, true
	default:
		return 0, false
	}
}

func unambiguousDaemonRouteSource(
	endpoint netip.AddrPort,
	selected []netip.Addr,
) (netip.Addr, bool) {
	if !endpoint.IsValid() {
		return netip.Addr{}, false
	}
	remote := endpoint.Addr()
	var result netip.Addr
	for _, candidate := range selected {
		if candidate.Is4() != remote.Is4() {
			continue
		}
		if remote.Is6() &&
			(remote.IsLinkLocalUnicast() || candidate.IsLinkLocalUnicast()) &&
			(remote.Zone() == "" || remote.Zone() != candidate.Zone()) {
			continue
		}
		if result.IsValid() && result != candidate {
			return netip.Addr{}, false
		}
		result = candidate
	}
	return result, result.IsValid()
}

func mergeDaemonManualRoutes(
	left []transport.ExpiringConsensusRoute,
	right []transport.ExpiringConsensusRoute,
) ([]transport.ExpiringConsensusRoute, error) {
	result := append(
		append([]transport.ExpiringConsensusRoute(nil), left...),
		right...,
	)
	slices.SortFunc(
		result,
		func(left, right transport.ExpiringConsensusRoute) int {
			return left.RemoteEndpoint.Compare(right.RemoteEndpoint)
		},
	)
	compacted := result[:0]
	for _, route := range result {
		if len(compacted) != 0 &&
			compacted[len(compacted)-1].RemoteEndpoint == route.RemoteEndpoint {
			if compacted[len(compacted)-1].SelectedLocalAddress !=
				route.SelectedLocalAddress {
				return nil, fmt.Errorf(
					"%w: manual endpoint has conflicting sources",
					errDaemonEndpointRouteReconciliation,
				)
			}
			continue
		}
		compacted = append(compacted, route)
	}
	return compacted, nil
}
