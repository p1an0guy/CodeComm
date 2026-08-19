package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	ConsensusDiscoveryRouteLifetimeMax = 60 * time.Second
	ConsensusGuessedRouteLifetimeMax   = 7 * 24 * time.Hour
)

var (
	ErrInvalidConsensusRouteTable = errors.New(
		"transport: invalid consensus route table",
	)
	ErrConsensusRouteCapacity = errors.New(
		"transport: consensus route table capacity reached",
	)
	ErrConsensusRouteAmbiguous = errors.New(
		"transport: consensus route endpoint is ambiguous",
	)
)

// ConsensusRouteSource identifies the bounded authority for one dial target.
type ConsensusRouteSource uint8

const (
	ConsensusRouteManual ConsensusRouteSource = iota + 1
	ConsensusRouteSigned
	ConsensusRouteAuthenticated
	ConsensusRouteDiscovery
)

func (source ConsensusRouteSource) valid() bool {
	return source >= ConsensusRouteManual &&
		source <= ConsensusRouteDiscovery
}

// ExpiringConsensusRoute is one selected-source route retained from a single
// endpoint authority. Manual routes have a zero expiry; every other source
// must expire.
type ExpiringConsensusRoute struct {
	ConsensusRoute
	ExpiresAt time.Time
}

// ConsensusRouteTable merges explicit and learned routes while preserving the
// selected local source address required for every dial.
type ConsensusRouteTable struct {
	now func() time.Time

	mu       sync.Mutex
	selected map[netip.Addr]struct{}
	routes   map[consensusRouteTableKey]consensusRouteTableEntry
}

type consensusRouteTableKey struct {
	peer     domain.DeviceID
	source   ConsensusRouteSource
	endpoint netip.AddrPort
}

type consensusRouteTableEntry struct {
	local     netip.Addr
	expiresAt time.Time
}

type effectiveConsensusRoute struct {
	peer     domain.DeviceID
	source   ConsensusRouteSource
	endpoint netip.AddrPort
	local    netip.Addr
}

var (
	_ ConsensusEndpointResolver = (*ConsensusRouteTable)(nil)
	_ ConsensusEndpointDialer   = (*ConsensusRouteTable)(nil)
)

// NewConsensusRouteTable validates the selected local addresses and installs
// the initial manual routes atomically.
func NewConsensusRouteTable(
	selectedLocalAddresses []netip.Addr,
	manualRoutes []ConsensusRoute,
) (*ConsensusRouteTable, error) {
	return newConsensusRouteTable(
		selectedLocalAddresses,
		manualRoutes,
		time.Now,
	)
}

func newConsensusRouteTable(
	selectedLocalAddresses []netip.Addr,
	manualRoutes []ConsensusRoute,
	now func() time.Time,
) (*ConsensusRouteTable, error) {
	if now == nil ||
		(len(selectedLocalAddresses) == 0 && len(manualRoutes) != 0) {
		return nil, ErrInvalidConsensusRouteTable
	}
	selected, err := normalizeSelectedConsensusAddresses(
		selectedLocalAddresses,
	)
	if err != nil {
		return nil, err
	}
	table := &ConsensusRouteTable{
		now:      now,
		selected: selected,
		routes: make(
			map[consensusRouteTableKey]consensusRouteTableEntry,
			len(manualRoutes),
		),
	}
	expiring := make([]ExpiringConsensusRoute, len(manualRoutes))
	for index, route := range manualRoutes {
		expiring[index] = ExpiringConsensusRoute{
			ConsensusRoute: route,
		}
	}
	if err := table.replaceLocked(
		"",
		ConsensusRouteManual,
		expiring,
		true,
	); err != nil {
		return nil, err
	}
	return table, nil
}

// ReplaceSelectedAddresses atomically installs the complete selected-source
// set. Learned routes tied to removed addresses are discarded. Manual routes
// prevent removal of their selected source.
func (table *ConsensusRouteTable) ReplaceSelectedAddresses(
	selectedLocalAddresses []netip.Addr,
) error {
	if table == nil {
		return ErrInvalidConsensusRouteTable
	}
	selected, err := normalizeSelectedConsensusAddresses(
		selectedLocalAddresses,
	)
	if err != nil {
		return err
	}

	table.mu.Lock()
	defer table.mu.Unlock()
	for key, entry := range table.routes {
		if key.source != ConsensusRouteManual {
			continue
		}
		if _, retained := selected[entry.local]; !retained {
			return fmt.Errorf(
				"%w: selected addresses exclude a manual route",
				ErrInvalidConsensusRouteTable,
			)
		}
	}

	table.selected = selected
	for key, entry := range table.routes {
		if key.source == ConsensusRouteManual {
			continue
		}
		if _, retained := selected[entry.local]; !retained {
			delete(table.routes, key)
		}
	}
	return nil
}

// Replace atomically replaces one peer/source route set. Empty learned sets
// are valid and remove that source. Endpoint collisions across peers are
// retained but excluded from resolution until the ambiguity disappears.
// Manual routes may be replaced only with a concrete peer ID.
func (table *ConsensusRouteTable) Replace(
	peer domain.DeviceID,
	source ConsensusRouteSource,
	routes []ExpiringConsensusRoute,
) error {
	if table == nil || !peer.Valid() || !source.valid() {
		return ErrInvalidConsensusRouteTable
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	return table.replaceLocked(peer, source, routes, false)
}

// PurgePeer removes learned authority for one peer. Manual configuration is
// retained unless includeManual is explicitly requested.
func (table *ConsensusRouteTable) PurgePeer(
	peer domain.DeviceID,
	includeManual bool,
) {
	if table == nil || !peer.Valid() {
		return
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	for key := range table.routes {
		if key.peer == peer &&
			(includeManual || key.source != ConsensusRouteManual) {
			delete(table.routes, key)
		}
	}
}

// Expire removes stale learned routes and returns the number removed.
func (table *ConsensusRouteTable) Expire() int {
	if table == nil {
		return 0
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	return table.expireLocked(table.now())
}

// ResolveConsensusEndpoints returns the unambiguous effective endpoints for
// one peer, ordered by source authority and canonical endpoint bytes.
func (table *ConsensusRouteTable) ResolveConsensusEndpoints(
	ctx context.Context,
	peer domain.DeviceID,
) ([]netip.AddrPort, error) {
	if table == nil || ctx == nil || !peer.Valid() {
		return nil, ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	table.expireLocked(table.now())
	effective, ambiguous := table.effectiveLocked()
	result := make([]netip.AddrPort, 0)
	for _, route := range effective {
		if route.peer == peer {
			if _, blocked := ambiguous[route.endpoint]; !blocked {
				result = append(result, route.endpoint)
			}
		}
	}
	if len(result) == 0 {
		return nil, ErrConsensusEndpointUnavailable
	}
	return result, nil
}

// DialConsensusEndpoint binds the socket to the selected source associated
// with one currently effective, globally unambiguous endpoint.
func (table *ConsensusRouteTable) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	dialer, network, address, err := table.dialConfiguration(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, address)
}

func (table *ConsensusRouteTable) dialConfiguration(
	ctx context.Context,
	endpoint netip.AddrPort,
) (*net.Dialer, string, string, error) {
	if table == nil || ctx == nil || !endpoint.IsValid() {
		return nil, "", "", ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, "", "", err
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	table.expireLocked(table.now())
	effective, ambiguous := table.effectiveLocked()
	if _, blocked := ambiguous[endpoint]; blocked {
		return nil, "", "", ErrConsensusRouteAmbiguous
	}
	var local netip.Addr
	for _, route := range effective {
		if route.endpoint != endpoint {
			continue
		}
		if local.IsValid() && local != route.local {
			return nil, "", "", ErrConsensusRouteAmbiguous
		}
		local = route.local
	}
	if !local.IsValid() {
		return nil, "", "", ErrConsensusEndpointUnavailable
	}
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	return &net.Dialer{
		LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
	}, network, endpoint.String(), nil
}

func (table *ConsensusRouteTable) replaceLocked(
	peer domain.DeviceID,
	source ConsensusRouteSource,
	routes []ExpiringConsensusRoute,
	initialManual bool,
) error {
	now := table.now()
	if now.IsZero() || !source.valid() {
		return ErrInvalidConsensusRouteTable
	}
	normalized := make(
		map[consensusRouteTableKey]consensusRouteTableEntry,
		len(routes),
	)
	for index, route := range routes {
		routePeer := route.PeerDeviceID
		if !initialManual && routePeer != peer {
			return fmt.Errorf(
				"%w: route %d names another peer",
				ErrInvalidConsensusRouteTable,
				index,
			)
		}
		if initialManual && !routePeer.Valid() {
			return ErrInvalidConsensusRouteTable
		}
		if err := validateConsensusRoute(route.ConsensusRoute); err != nil {
			return fmt.Errorf(
				"%w: route %d: %v",
				ErrInvalidConsensusRouteTable,
				index,
				err,
			)
		}
		if _, selected := table.selected[route.SelectedLocalAddress]; !selected {
			return fmt.Errorf(
				"%w: route %d leaves an unselected address",
				ErrInvalidConsensusRouteTable,
				index,
			)
		}
		if err := validateConsensusRouteExpiry(
			source,
			route.ExpiresAt,
			now,
		); err != nil {
			return fmt.Errorf(
				"%w: route %d: %v",
				ErrInvalidConsensusRouteTable,
				index,
				err,
			)
		}
		key := consensusRouteTableKey{
			peer:     routePeer,
			source:   source,
			endpoint: route.RemoteEndpoint,
		}
		if _, duplicate := normalized[key]; duplicate {
			return fmt.Errorf(
				"%w: duplicate route %d",
				ErrInvalidConsensusRouteTable,
				index,
			)
		}
		normalized[key] = consensusRouteTableEntry{
			local:     route.SelectedLocalAddress,
			expiresAt: route.ExpiresAt,
		}
	}

	candidateCount := len(table.routes)
	perPeer := make(map[domain.DeviceID]int)
	for key := range table.routes {
		if initialManual ||
			key.peer != peer ||
			key.source != source {
			perPeer[key.peer]++
			continue
		}
		candidateCount--
	}
	candidateCount += len(normalized)
	for key := range normalized {
		perPeer[key.peer]++
	}
	if candidateCount > ConsensusStaticRoutesMax {
		return ErrConsensusRouteCapacity
	}
	for _, count := range perPeer {
		if count > ConsensusStaticRoutesPerPeerMax {
			return ErrConsensusRouteCapacity
		}
	}
	if !initialManual {
		for key := range table.routes {
			if key.peer == peer && key.source == source {
				delete(table.routes, key)
			}
		}
	}
	for key, entry := range normalized {
		table.routes[key] = entry
	}
	return nil
}

func (table *ConsensusRouteTable) expireLocked(now time.Time) int {
	if now.IsZero() {
		return 0
	}
	removed := 0
	for key, entry := range table.routes {
		if key.source != ConsensusRouteManual &&
			!entry.expiresAt.After(now) {
			delete(table.routes, key)
			removed++
		}
	}
	return removed
}

func (table *ConsensusRouteTable) effectiveLocked() (
	[]effectiveConsensusRoute,
	map[netip.AddrPort]struct{},
) {
	byPeerEndpoint := make(
		map[[2]string]effectiveConsensusRoute,
		len(table.routes),
	)
	for key, entry := range table.routes {
		mapKey := [2]string{
			string(key.peer),
			key.endpoint.String(),
		}
		current, exists := byPeerEndpoint[mapKey]
		if exists && current.source < key.source {
			continue
		}
		byPeerEndpoint[mapKey] = effectiveConsensusRoute{
			peer: key.peer, source: key.source,
			endpoint: key.endpoint, local: entry.local,
		}
	}
	result := make(
		[]effectiveConsensusRoute,
		0,
		len(byPeerEndpoint),
	)
	owner := make(map[netip.AddrPort]effectiveConsensusRoute)
	ambiguous := make(map[netip.AddrPort]struct{})
	for _, route := range byPeerEndpoint {
		if prior, exists := owner[route.endpoint]; exists &&
			(prior.peer != route.peer || prior.local != route.local) {
			ambiguous[route.endpoint] = struct{}{}
		} else {
			owner[route.endpoint] = route
		}
		result = append(result, route)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].peer != result[right].peer {
			return result[left].peer < result[right].peer
		}
		if result[left].source != result[right].source {
			return result[left].source < result[right].source
		}
		return compareConsensusRouteEndpoints(
			result[left].endpoint,
			result[right].endpoint,
		) < 0
	})
	return result, ambiguous
}

func validateConsensusRouteExpiry(
	source ConsensusRouteSource,
	expiresAt time.Time,
	now time.Time,
) error {
	if source == ConsensusRouteManual {
		if !expiresAt.IsZero() {
			return errors.New("manual route expires")
		}
		return nil
	}
	if expiresAt.IsZero() || !expiresAt.After(now) {
		return errors.New("learned route is expired")
	}
	maximum := ConsensusGuessedRouteLifetimeMax
	if source == ConsensusRouteDiscovery {
		maximum = ConsensusDiscoveryRouteLifetimeMax
	}
	if expiresAt.Sub(now) > maximum {
		return errors.New("learned route lifetime exceeds its source bound")
	}
	return nil
}

func normalizeSelectedConsensusAddresses(
	addresses []netip.Addr,
) (map[netip.Addr]struct{}, error) {
	if len(addresses) > MaxSelectedConsensusAddresses {
		return nil, ErrInvalidConsensusRouteTable
	}
	selected := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !validSelectedSourceAddress(address) {
			return nil, ErrInvalidConsensusRouteTable
		}
		if _, duplicate := selected[address]; duplicate {
			return nil, ErrInvalidConsensusRouteTable
		}
		selected[address] = struct{}{}
	}
	return selected, nil
}

// MaxSelectedConsensusAddresses bounds one daemon's selected source set.
const MaxSelectedConsensusAddresses = 32
