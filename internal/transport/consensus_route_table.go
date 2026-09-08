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

	dialContext ConsensusRouteDialContext

	mu          sync.Mutex
	selected    map[netip.Addr]*consensusAddressSelection
	routes      map[consensusRouteTableKey]consensusRouteTableEntry
	connections map[*consensusRouteTableConn]netip.Addr
}

// ConsensusRouteDialContext opens one socket using the route table's fully
// configured dialer. Implementations must preserve its selected local address.
type ConsensusRouteDialContext func(
	context.Context,
	*net.Dialer,
	string,
	string,
) (net.Conn, error)

// One token represents an uninterrupted interval in which an address remains
// selected. Retained addresses preserve their token across replacements.
type consensusAddressSelection byte

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

type consensusRouteDialPlan struct {
	dialer    *net.Dialer
	network   string
	address   string
	local     netip.Addr
	selection *consensusAddressSelection
}

type consensusRouteTableConn struct {
	net.Conn

	table          *ConsensusRouteTable
	unregisterOnce sync.Once
}

var (
	_ ConsensusEndpointResolver = (*ConsensusRouteTable)(nil)
	_ ConsensusEndpointDialer   = (*ConsensusRouteTable)(nil)
	_ net.Conn                  = (*consensusRouteTableConn)(nil)
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

// NewConsensusRouteTableWithDialContext is NewConsensusRouteTable with an
// injected socket opener for deterministic network fault harnesses.
func NewConsensusRouteTableWithDialContext(
	selectedLocalAddresses []netip.Addr,
	manualRoutes []ConsensusRoute,
	dialContext ConsensusRouteDialContext,
) (*ConsensusRouteTable, error) {
	if dialContext == nil {
		return nil, ErrInvalidConsensusRouteTable
	}
	table, err := newConsensusRouteTable(
		selectedLocalAddresses,
		manualRoutes,
		time.Now,
	)
	if err != nil {
		return nil, err
	}
	table.dialContext = func(
		ctx context.Context,
		dialer *net.Dialer,
		network string,
		address string,
	) (net.Conn, error) {
		connection, dialErr := dialContext(
			ctx,
			dialer,
			network,
			address,
		)
		if dialErr != nil || connection == nil {
			return connection, dialErr
		}
		expected, expectedValid := consensusRouteNetAddress(
			dialer.LocalAddr,
		)
		actual, actualValid := consensusRouteNetAddress(
			connection.LocalAddr(),
		)
		if !expectedValid || !actualValid || actual != expected {
			_ = connection.Close()
			return nil, ErrConsensusEndpointUnavailable
		}
		return connection, nil
	}
	return table, nil
}

func consensusRouteNetAddress(address net.Addr) (netip.Addr, bool) {
	if address == nil {
		return netip.Addr{}, false
	}
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil {
		return netip.Addr{}, false
	}
	value, valid := netip.AddrFromSlice(tcpAddress.IP)
	if !valid {
		return netip.Addr{}, false
	}
	value = value.Unmap()
	if value.Is6() && value.IsLinkLocalUnicast() {
		value = value.WithZone(tcpAddress.Zone)
	}
	return value, value.IsValid()
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
		now: now,
		dialContext: func(
			ctx context.Context,
			dialer *net.Dialer,
			network string,
			address string,
		) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		selected: selected,
		routes: make(
			map[consensusRouteTableKey]consensusRouteTableEntry,
			len(manualRoutes),
		),
		connections: make(map[*consensusRouteTableConn]netip.Addr),
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
// set. Routes and active outbound connections tied to removed addresses are
// discarded; durable manual configuration is owned above this table and may
// be remapped onto a newly selected source.
func (table *ConsensusRouteTable) ReplaceSelectedAddresses(
	selectedLocalAddresses []netip.Addr,
) error {
	return table.replaceSelectedAddresses(selectedLocalAddresses, nil)
}

// RebindSelectedAddresses replaces the selected-source set and rotates the
// generation of retained addresses whose OS interface binding changed. Active
// connections on removed or rebound addresses are closed outside the table
// lock; routes on a rebound address remain eligible for a fresh dial.
func (table *ConsensusRouteTable) RebindSelectedAddresses(
	selectedLocalAddresses []netip.Addr,
	reboundLocalAddresses []netip.Addr,
) error {
	return table.replaceSelectedAddresses(
		selectedLocalAddresses,
		reboundLocalAddresses,
	)
}

func (table *ConsensusRouteTable) replaceSelectedAddresses(
	selectedLocalAddresses []netip.Addr,
	reboundLocalAddresses []netip.Addr,
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
	rebound, err := normalizeSelectedConsensusAddresses(
		reboundLocalAddresses,
	)
	if err != nil {
		return err
	}
	for address := range rebound {
		if _, retained := selected[address]; !retained {
			return ErrInvalidConsensusRouteTable
		}
	}

	table.mu.Lock()
	for address := range rebound {
		if _, previouslySelected := table.selected[address]; !previouslySelected {
			table.mu.Unlock()
			return ErrInvalidConsensusRouteTable
		}
	}
	for address := range selected {
		_, mustRebind := rebound[address]
		if retained, exists := table.selected[address]; exists && !mustRebind {
			selected[address] = retained
		}
	}

	table.selected = selected
	for key, entry := range table.routes {
		if _, retained := selected[entry.local]; !retained {
			delete(table.routes, key)
		}
	}
	stale := make([]*consensusRouteTableConn, 0)
	for connection, local := range table.connections {
		_, retained := selected[local]
		_, reboundAddress := rebound[local]
		if retained && !reboundAddress {
			continue
		}
		delete(table.connections, connection)
		stale = append(stale, connection)
	}
	table.mu.Unlock()

	for _, connection := range stale {
		_ = connection.Close()
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
	plan, err := table.prepareDial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	connection, err := table.dialContext(
		ctx,
		plan.dialer,
		plan.network,
		plan.address,
	)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, err
	}
	if connection == nil {
		return nil, ErrConsensusEndpointUnavailable
	}
	tracked := &consensusRouteTableConn{
		Conn:  connection,
		table: table,
	}

	table.mu.Lock()
	table.expireLocked(table.now())
	currentLocal, routeErr := table.effectiveLocalLocked(endpoint)
	contextErr := ctx.Err()
	if contextErr != nil ||
		table.selected[plan.local] != plan.selection ||
		routeErr != nil ||
		currentLocal != plan.local {
		table.mu.Unlock()
		_ = connection.Close()
		if contextErr != nil {
			return nil, contextErr
		}
		return nil, ErrConsensusEndpointUnavailable
	}
	table.connections[tracked] = plan.local
	table.mu.Unlock()
	return tracked, nil
}

func (table *ConsensusRouteTable) dialConfiguration(
	ctx context.Context,
	endpoint netip.AddrPort,
) (*net.Dialer, string, string, error) {
	plan, err := table.prepareDial(ctx, endpoint)
	if err != nil {
		return nil, "", "", err
	}
	return plan.dialer, plan.network, plan.address, nil
}

func (table *ConsensusRouteTable) prepareDial(
	ctx context.Context,
	endpoint netip.AddrPort,
) (consensusRouteDialPlan, error) {
	if table == nil || ctx == nil || !endpoint.IsValid() {
		return consensusRouteDialPlan{}, ErrConsensusEndpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return consensusRouteDialPlan{}, err
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	table.expireLocked(table.now())
	local, err := table.effectiveLocalLocked(endpoint)
	if err != nil {
		return consensusRouteDialPlan{}, err
	}
	selection := table.selected[local]
	if selection == nil {
		return consensusRouteDialPlan{}, ErrConsensusEndpointUnavailable
	}
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	return consensusRouteDialPlan{
		dialer: &net.Dialer{
			LocalAddr: net.TCPAddrFromAddrPort(
				netip.AddrPortFrom(local, 0),
			),
		},
		network:   network,
		address:   endpoint.String(),
		local:     local,
		selection: selection,
	}, nil
}

func (table *ConsensusRouteTable) effectiveLocalLocked(
	endpoint netip.AddrPort,
) (netip.Addr, error) {
	effective, ambiguous := table.effectiveLocked()
	if _, blocked := ambiguous[endpoint]; blocked {
		return netip.Addr{}, ErrConsensusRouteAmbiguous
	}
	var local netip.Addr
	for _, route := range effective {
		if route.endpoint != endpoint {
			continue
		}
		if local.IsValid() && local != route.local {
			return netip.Addr{}, ErrConsensusRouteAmbiguous
		}
		local = route.local
	}
	if !local.IsValid() {
		return netip.Addr{}, ErrConsensusEndpointUnavailable
	}
	return local, nil
}

func (table *ConsensusRouteTable) unregisterConnection(
	connection *consensusRouteTableConn,
) {
	table.mu.Lock()
	delete(table.connections, connection)
	table.mu.Unlock()
}

func (connection *consensusRouteTableConn) Close() error {
	connection.unregisterOnce.Do(func() {
		connection.table.unregisterConnection(connection)
	})
	return connection.Conn.Close()
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
) (map[netip.Addr]*consensusAddressSelection, error) {
	if len(addresses) > MaxSelectedConsensusAddresses {
		return nil, ErrInvalidConsensusRouteTable
	}
	selected := make(
		map[netip.Addr]*consensusAddressSelection,
		len(addresses),
	)
	for _, address := range addresses {
		if !validSelectedSourceAddress(address) {
			return nil, ErrInvalidConsensusRouteTable
		}
		if _, duplicate := selected[address]; duplicate {
			return nil, ErrInvalidConsensusRouteTable
		}
		selected[address] = new(consensusAddressSelection)
	}
	return selected, nil
}

// MaxSelectedConsensusAddresses bounds one daemon's selected source set.
const MaxSelectedConsensusAddresses = 32
