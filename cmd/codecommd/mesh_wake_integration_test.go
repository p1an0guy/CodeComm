package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/joinbootstrap"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

func TestDaemonProductionWakeAddressChangeComposition(t *testing.T) {
	if os.Getenv(daemonMeshIntegrationChildMarker) != "1" {
		runDaemonMeshIntegrationChild(
			t,
			"^TestDaemonProductionWakeAddressChangeComposition$",
		)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonProductionWakeAddressChangeComposition(t)
}

func runDaemonProductionWakeAddressChangeComposition(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	credentialBase := time.Now().UTC().
		Truncate(time.Second).
		Add(-3 * time.Minute)
	credentialClock := newDaemonMeshIntegrationCredentialClock(
		credentialBase.Add(-28 * time.Minute),
	)
	network := newDaemonMeshVirtualNetwork()
	nodes, interfaces := newDaemonMeshVirtualIntegrationNodes(
		t,
		root,
		network,
		credentialClock.Now,
	)
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, nodes...)
		_ = network.Close()
		for _, node := range nodes {
			clear(node.privateKey)
		}
	})

	initial := daemonMeshIntegrationInitialState(t, nodes, device.Device{})
	bootstrap := daemonMeshIntegrationBootstrap(nodes)
	for _, node := range nodes {
		initializeDaemonMeshIntegrationStore(t, node.statePath, initial)
		seedDaemonMeshIntegrationRaft(
			t,
			node.consensusDir,
			node.deviceID,
			bootstrap,
		)
		node.start(t, nodes)
	}
	voterIDs := daemonMeshIntegrationDeviceIDs(nodes)
	statuses := waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 1)

	leaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	sleeper := daemonMeshIntegrationFollower(t, nodes, leaderID)
	sleeperIndex := sleeper.indexIn(nodes)
	stable := make([]*daemonMeshIntegrationNode, 0, 2)
	for _, node := range nodes {
		if node != sleeper {
			stable = append(stable, node)
		}
	}
	if len(stable) != 2 {
		t.Fatal("wake-address mesh has no stable majority")
	}
	preSleep := openReadyDaemonMeshPeersClient(
		t,
		sleeper,
		stable[0],
		credentialClock.Now,
	)
	oldEndpoint := sleeper.currentPeerEndpoint()
	newEndpoint := netip.AddrPortFrom(
		netip.MustParseAddr("192.0.2.240"),
		oldEndpoint.Port(),
	)
	if oldEndpoint == newEndpoint {
		t.Fatal("wake-address fixture did not change address")
	}

	interfaces[sleeperIndex].set(netip.Addr{}, 0, false)
	network.DropAddress(oldEndpoint.Addr())
	waitForDaemonMeshVirtualCondition(
		t,
		"sleeping listener withdrawal",
		func() bool {
			return !network.Listening(oldEndpoint)
		},
	)
	if _, err := preSleep.roundTrip(stable[0]); err == nil {
		_ = preSleep.Close()
		t.Fatal("suspended device retained established content access")
	}
	if err := preSleep.Close(); err != nil {
		t.Fatalf("close suspended content client: %v", err)
	}
	if _, err := readDaemonMeshIntegrationStatus(
		sleeper.localEndpoint,
	); err != nil {
		t.Fatalf("suspended device lost local reads: %v", err)
	}

	credentialClock.Set(credentialBase.Add(3 * time.Minute))
	waitForDaemonMeshContentCredentialEpoch(t, stable, 2)
	if epoch, err := daemonMeshContentCredentialEpoch(sleeper); err == nil {
		t.Fatalf("suspended device exposed expired epoch %d", epoch)
	}

	interfaces[sleeperIndex].set(newEndpoint.Addr(), 101, true)
	waitForDaemonMeshVirtualCondition(
		t,
		"successor listener bind",
		func() bool {
			return network.Listening(newEndpoint) &&
				!network.Listening(oldEndpoint) &&
				sleeper.listenerBinds.Load() >= 2
		},
	)
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs) &&
				daemonMeshIntegrationMutationConverged(statuses)
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 2)

	response := waitForDaemonMeshWakeEndpointRelay(
		t,
		sleeper,
		stable[0],
		credentialClock.Now,
		sleeper,
		newEndpoint,
	)
	assertDaemonMeshWakeEndpointSet(
		t,
		response,
		sleeper,
		newEndpoint,
	)
	statuses = exerciseDaemonFollowerProposalForwarding(t, nodes)
	chainIndex := statuses[0].Session.EventChainIndex
	resultIndex := statuses[0].Session.ResultIndex
	stopDaemonMeshIntegrationNodes(t, nodes...)

	for _, node := range nodes {
		current := node.currentPeerEndpoint()
		node.peerEndpoint = current
		node.listener = network.Listen(t, current)
		node.start(t, nodes)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTaskConverged(
					statuses,
					daemonTestTaskID,
				) &&
				statuses[0].Session.EventChainIndex >= chainIndex &&
				statuses[0].Session.ResultIndex >= resultIndex
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 2)
	stopDaemonMeshIntegrationNodes(t, nodes...)
	assertDaemonMeshWakeDurable(
		t,
		nodes,
		chainIndex,
		resultIndex,
	)
}

func waitForDaemonMeshWakeEndpointRelay(
	t *testing.T,
	source *daemonMeshIntegrationNode,
	target *daemonMeshIntegrationNode,
	now func() time.Time,
	node *daemonMeshIntegrationNode,
	endpoint netip.AddrPort,
) daemonMeshPeersResponse {
	t.Helper()
	if node == nil || !endpoint.IsValid() {
		t.Fatal("invalid post-wake endpoint relay wait")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := dialDaemonMeshPeersClient(source, target, now)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		response, requestErr := client.roundTrip(target)
		closeErr := client.Close()
		err = errors.Join(requestErr, closeErr)
		if err == nil {
			encoded, present := daemonMeshOptionalMemberEndpointSet(
				t,
				response,
				node.deviceID,
			)
			if present {
				canonical, decodeErr := codec.DecodeBase64URL(encoded)
				parsed, parseErr := discovery.ParseEndpointSet(canonical)
				if decodeErr == nil && parseErr == nil {
					value := parsed.EndpointSet()
					if len(value.Endpoints) == 1 &&
						value.Endpoints[0].IP == endpoint.Addr() &&
						value.Endpoints[0].Port == endpoint.Port() {
						return response
					}
				}
				lastErr = errors.Join(decodeErr, parseErr)
				if lastErr == nil {
					lastErr = errors.New(
						"stale endpoint set is still relayed",
					)
				}
			} else {
				lastErr = errors.New(
					"successor endpoint set is not relayed yet",
				)
			}
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("post-wake endpoint relay did not converge: %v", lastErr)
	return daemonMeshPeersResponse{}
}

func assertDaemonMeshWakeEndpointSet(
	t *testing.T,
	response daemonMeshPeersResponse,
	node *daemonMeshIntegrationNode,
	endpoint netip.AddrPort,
) {
	t.Helper()
	if node == nil {
		t.Fatal("post-wake endpoint node is nil")
	}
	encoded := daemonMeshMemberEndpointSet(
		t,
		response,
		node.deviceID,
		true,
	)
	value, err := codec.DecodeBase64URL(encoded)
	if err != nil {
		t.Fatalf("decode post-wake endpoint set: %v", err)
	}
	verified := validateDaemonMeshEndpointSet(t, node, value)
	endpoints := verified.EndpointSet().Endpoints
	if len(endpoints) != 1 ||
		endpoints[0].IP != endpoint.Addr() ||
		endpoints[0].Port != endpoint.Port() {
		t.Fatalf(
			"post-wake endpoint set = %v, want [%s]",
			endpoints,
			endpoint,
		)
	}
}

func assertDaemonMeshWakeDurable(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	minChainIndex, minResultIndex uint64,
) {
	t.Helper()
	var baseline *store.StateView
	for _, node := range nodes {
		database, err := store.Open(
			context.Background(),
			store.Options{Path: node.statePath},
		)
		if err != nil {
			t.Fatalf("reopen wake-address store %s: %v", node.deviceID, err)
		}
		view, viewErr := database.View(context.Background())
		verifyErr := database.VerifyCommitmentHistory(context.Background())
		closeErr := database.Close()
		if viewErr != nil {
			t.Fatalf("wake-address view %s: %v", node.deviceID, viewErr)
		}
		if verifyErr != nil {
			t.Fatalf(
				"verify wake-address commitments %s: %v",
				node.deviceID,
				verifyErr,
			)
		}
		if closeErr != nil {
			t.Fatalf("close wake-address store %s: %v", node.deviceID, closeErr)
		}
		if view.Heads.ChainIndex < minChainIndex ||
			view.Heads.ResultIndex < minResultIndex {
			t.Fatalf(
				"wake-address durable heads %s = %+v",
				node.deviceID,
				view.Heads,
			)
		}
		if baseline == nil {
			cloned := view
			baseline = &cloned
			continue
		}
		if view.Heads != baseline.Heads ||
			view.ProjectionStateDigest != baseline.ProjectionStateDigest ||
			!reflect.DeepEqual(view.ProjectionRows, baseline.ProjectionRows) {
			t.Fatalf("wake-address durable state diverged on %s", node.deviceID)
		}
	}
}

func newDaemonMeshVirtualIntegrationNodes(
	t *testing.T,
	root string,
	network *daemonMeshVirtualNetwork,
	credentialNow func() time.Time,
) ([]*daemonMeshIntegrationNode, []*daemonMeshVirtualInterface) {
	t.Helper()
	if root == "" || network == nil || credentialNow == nil {
		t.Fatal("invalid virtual mesh fixture")
	}
	const port = 47831
	nodes := make([]*daemonMeshIntegrationNode, 3)
	interfacesByNode := make(map[*daemonMeshIntegrationNode]*daemonMeshVirtualInterface)
	for index := range nodes {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{byte(0xe1 + index)}, ed25519.SeedSize),
		)
		deviceID, err := device.DeriveID(
			privateKey.Public().(ed25519.PublicKey),
		)
		if err != nil {
			clear(privateKey)
			t.Fatalf("derive virtual device ID %d: %v", index, err)
		}
		address := netip.MustParseAddr(
			fmt.Sprintf("192.0.2.%d", 20+index*20),
		)
		endpoint := netip.AddrPortFrom(address, port)
		networkInterface := newDaemonMeshVirtualInterface(
			fmt.Sprintf("mesh%d", index),
			index+1,
			endpoint,
		)
		node := &daemonMeshIntegrationNode{
			deviceID:         deviceID,
			privateKey:       privateKey,
			daemonVersion:    joinbootstrap.CurrentDaemonVersion,
			maxApplyLevel:    joinbootstrap.CurrentMaxApplyLevel,
			statePath:        filepath.Join(root, fmt.Sprintf("node-%d", index), "state.db"),
			consensusDir:     filepath.Join(root, fmt.Sprintf("node-%d", index), "consensus"),
			localEndpoint:    daemonTestEndpoint(t),
			peerEndpoint:     endpoint,
			credentials:      newDaemonTestCredentialStore(),
			meshCapture:      &daemonMeshIntegrationFactoryCapture{},
			credentialNow:    credentialNow,
			listener:         network.Listen(t, endpoint),
			routeDialContext: network.DialContext,
			listenPeer:       network.ListenContext,
			listInterfaces:   networkInterface.Interfaces,
			interfaceAddrs:   networkInterface.Addrs,
			openMulticast:    network.MulticastOpener(networkInterface),
			peerEndpointNow:  networkInterface.Endpoint,
		}
		nodes[index] = node
		interfacesByNode[node] = networkInterface
	}
	sort.Slice(nodes, func(left, right int) bool {
		return nodes[left].deviceID < nodes[right].deviceID
	})
	interfaces := make([]*daemonMeshVirtualInterface, len(nodes))
	for index, node := range nodes {
		interfaces[index] = interfacesByNode[node]
	}
	return nodes, interfaces
}

func waitForDaemonMeshVirtualCondition(
	t *testing.T,
	description string,
	condition func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

type daemonMeshVirtualNetwork struct {
	mu          sync.Mutex
	listeners   map[netip.AddrPort]*daemonMeshVirtualListener
	connections map[*daemonMeshVirtualConnection]struct{}
	multicasts  map[*daemonMeshVirtualMulticast]struct{}
	nextPort    atomic.Uint32
	closed      bool
}

type daemonMeshVirtualListener struct {
	network  *daemonMeshVirtualNetwork
	endpoint netip.AddrPort
	incoming chan net.Conn
	done     chan struct{}

	mu       sync.Mutex
	closed   bool
	close    sync.Once
	closeErr error
}

type daemonMeshVirtualConnection struct {
	network *daemonMeshVirtualNetwork
	first   net.Conn
	second  net.Conn
	local   netip.Addr
	remote  netip.Addr

	close sync.Once
	err   error
}

type daemonMeshVirtualConn struct {
	net.Conn
	owner  *daemonMeshVirtualConnection
	local  net.Addr
	remote net.Addr
}

type daemonMeshVirtualMulticast struct {
	network *daemonMeshVirtualNetwork
	iface   *daemonMeshVirtualInterface
	inbound chan discovery.ReceivedDatagram
	trigger chan struct{}
	done    chan struct{}

	mu       sync.RWMutex
	report   discovery.MulticastReport
	closed   bool
	close    sync.Once
	closeErr error
}

func newDaemonMeshVirtualNetwork() *daemonMeshVirtualNetwork {
	return &daemonMeshVirtualNetwork{
		listeners: make(
			map[netip.AddrPort]*daemonMeshVirtualListener,
		),
		connections: make(
			map[*daemonMeshVirtualConnection]struct{},
		),
		multicasts: make(
			map[*daemonMeshVirtualMulticast]struct{},
		),
	}
}

func (network *daemonMeshVirtualNetwork) MulticastOpener(
	networkInterface *daemonMeshVirtualInterface,
) daemonMulticastOpener {
	return func(
		port uint16,
		selected []discovery.MulticastInterfaceSelection,
	) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
		if network == nil || networkInterface == nil {
			return nil, discovery.MulticastReport{},
				errDaemonMeshContentHarness
		}
		report, err := daemonMeshIntegrationMulticastReport(port, selected)
		if err != nil ||
			!networkInterface.matchesReport(report) {
			return nil, report,
				errors.Join(errDaemonMeshContentHarness, err)
		}
		multicast := &daemonMeshVirtualMulticast{
			network: network,
			iface:   networkInterface,
			inbound: make(chan discovery.ReceivedDatagram, 128),
			trigger: make(chan struct{}, 1),
			done:    make(chan struct{}),
			report:  report,
		}
		multicast.trigger <- struct{}{}
		network.mu.Lock()
		defer network.mu.Unlock()
		if network.closed {
			return nil, report, net.ErrClosed
		}
		network.multicasts[multicast] = struct{}{}
		return multicast, report, nil
	}
}

func (network *daemonMeshVirtualNetwork) Listen(
	t *testing.T,
	endpoint netip.AddrPort,
) net.Listener {
	t.Helper()
	listener, err := network.ListenContext(t.Context(), endpoint)
	if err != nil {
		t.Fatalf("listen on virtual endpoint %s: %v", endpoint, err)
	}
	return listener
}

func (network *daemonMeshVirtualNetwork) ListenContext(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Listener, error) {
	if network == nil || ctx == nil || ctx.Err() != nil ||
		!endpoint.IsValid() || !validDaemonSelectedAddress(endpoint.Addr()) {
		return nil, errDaemonMeshContentHarness
	}
	listener := &daemonMeshVirtualListener{
		network:  network,
		endpoint: endpoint,
		incoming: make(chan net.Conn, 128),
		done:     make(chan struct{}),
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.closed {
		return nil, net.ErrClosed
	}
	if _, exists := network.listeners[endpoint]; exists {
		return nil, fmt.Errorf("virtual endpoint %s is in use", endpoint)
	}
	network.listeners[endpoint] = listener
	return listener, nil
}

func (network *daemonMeshVirtualNetwork) DialContext(
	ctx context.Context,
	dialer *net.Dialer,
	networkName string,
	address string,
) (net.Conn, error) {
	if network == nil || ctx == nil || dialer == nil ||
		(networkName != "tcp4" && networkName != "tcp6") {
		return nil, errDaemonMeshContentHarness
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	remote, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	localTCP, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok || localTCP == nil {
		return nil, errDaemonMeshContentHarness
	}
	local, valid := netip.AddrFromSlice(localTCP.IP)
	if !valid {
		return nil, errDaemonMeshContentHarness
	}
	local = local.Unmap()
	if localTCP.Zone != "" {
		local = local.WithZone(localTCP.Zone)
	}
	if !validDaemonSelectedAddress(local) ||
		local.Is4() != remote.Addr().Is4() {
		return nil, errDaemonMeshContentHarness
	}

	network.mu.Lock()
	if network.closed {
		network.mu.Unlock()
		return nil, net.ErrClosed
	}
	listener := network.listeners[remote]
	if listener == nil {
		network.mu.Unlock()
		return nil, fmt.Errorf("virtual endpoint %s: %w", remote, net.ErrClosed)
	}
	port := uint16(network.nextPort.Add(1)%50000 + 10000)
	clientRaw, serverRaw := net.Pipe()
	pair := &daemonMeshVirtualConnection{
		network: network,
		first:   clientRaw,
		second:  serverRaw,
		local:   local,
		remote:  remote.Addr(),
	}
	network.connections[pair] = struct{}{}
	network.mu.Unlock()

	localEndpoint := netip.AddrPortFrom(local, port)
	client := &daemonMeshVirtualConn{
		Conn:   clientRaw,
		owner:  pair,
		local:  daemonMeshVirtualTCPAddress(localEndpoint),
		remote: daemonMeshVirtualTCPAddress(remote),
	}
	server := &daemonMeshVirtualConn{
		Conn:   serverRaw,
		owner:  pair,
		local:  daemonMeshVirtualTCPAddress(remote),
		remote: daemonMeshVirtualTCPAddress(localEndpoint),
	}
	if !listener.enqueue(server) {
		_ = pair.Close()
		return nil, fmt.Errorf("virtual endpoint %s: %w", remote, net.ErrClosed)
	}
	return client, nil
}

func (network *daemonMeshVirtualNetwork) Listening(
	endpoint netip.AddrPort,
) bool {
	if network == nil {
		return false
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	_, exists := network.listeners[endpoint]
	return exists
}

func (network *daemonMeshVirtualNetwork) DropAddress(address netip.Addr) {
	if network == nil || !address.IsValid() {
		return
	}
	network.mu.Lock()
	connections := make([]*daemonMeshVirtualConnection, 0)
	for connection := range network.connections {
		if connection.local == address || connection.remote == address {
			connections = append(connections, connection)
		}
	}
	network.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (network *daemonMeshVirtualNetwork) Close() error {
	if network == nil {
		return nil
	}
	network.mu.Lock()
	if network.closed {
		network.mu.Unlock()
		return nil
	}
	network.closed = true
	listeners := make([]*daemonMeshVirtualListener, 0, len(network.listeners))
	for _, listener := range network.listeners {
		listeners = append(listeners, listener)
	}
	connections := make(
		[]*daemonMeshVirtualConnection,
		0,
		len(network.connections),
	)
	for connection := range network.connections {
		connections = append(connections, connection)
	}
	multicasts := make(
		[]*daemonMeshVirtualMulticast,
		0,
		len(network.multicasts),
	)
	for multicast := range network.multicasts {
		multicasts = append(multicasts, multicast)
	}
	network.mu.Unlock()
	var result error
	for _, listener := range listeners {
		result = errors.Join(result, listener.Close())
	}
	for _, connection := range connections {
		result = errors.Join(result, connection.Close())
	}
	for _, multicast := range multicasts {
		result = errors.Join(result, multicast.Close())
	}
	return result
}

func (listener *daemonMeshVirtualListener) Accept() (net.Conn, error) {
	if listener == nil {
		return nil, net.ErrClosed
	}
	select {
	case connection := <-listener.incoming:
		return connection, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *daemonMeshVirtualListener) Close() error {
	if listener == nil {
		return nil
	}
	listener.close.Do(func() {
		listener.mu.Lock()
		listener.closed = true
		close(listener.done)
		listener.mu.Unlock()

		listener.network.mu.Lock()
		if listener.network.listeners[listener.endpoint] == listener {
			delete(listener.network.listeners, listener.endpoint)
		}
		listener.network.mu.Unlock()
		for {
			select {
			case connection := <-listener.incoming:
				listener.closeErr = errors.Join(
					listener.closeErr,
					connection.Close(),
				)
			default:
				return
			}
		}
	})
	return listener.closeErr
}

func (listener *daemonMeshVirtualListener) Addr() net.Addr {
	if listener == nil {
		return &net.TCPAddr{}
	}
	return daemonMeshVirtualTCPAddress(listener.endpoint)
}

func (listener *daemonMeshVirtualListener) enqueue(connection net.Conn) bool {
	if listener == nil || connection == nil {
		return false
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.closed {
		return false
	}
	select {
	case listener.incoming <- connection:
		return true
	default:
		return false
	}
}

func (connection *daemonMeshVirtualConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.close.Do(func() {
		connection.err = errors.Join(
			connection.first.Close(),
			connection.second.Close(),
		)
		connection.network.mu.Lock()
		delete(connection.network.connections, connection)
		connection.network.mu.Unlock()
	})
	return connection.err
}

func (connection *daemonMeshVirtualConn) Close() error {
	if connection == nil || connection.owner == nil {
		return nil
	}
	return connection.owner.Close()
}

func (connection *daemonMeshVirtualConn) LocalAddr() net.Addr {
	return connection.local
}

func (connection *daemonMeshVirtualConn) RemoteAddr() net.Addr {
	return connection.remote
}

func daemonMeshVirtualTCPAddress(endpoint netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(endpoint.Addr().AsSlice()),
		Port: int(endpoint.Port()),
		Zone: endpoint.Addr().Zone(),
	}
}

func (multicast *daemonMeshVirtualMulticast) AdvertisementTriggers() <-chan struct{} {
	if multicast == nil {
		return nil
	}
	return multicast.trigger
}

func (multicast *daemonMeshVirtualMulticast) Send(payload []byte) error {
	if multicast == nil ||
		len(payload) == 0 ||
		len(payload) > discovery.MaxDatagramBytes {
		return discovery.ErrMulticastDatagramSize
	}
	source, _, available := multicast.iface.snapshot()
	if !available {
		return nil
	}
	multicast.mu.RLock()
	closed := multicast.closed
	multicast.mu.RUnlock()
	if closed {
		return discovery.ErrMulticastClosed
	}

	multicast.network.mu.Lock()
	recipients := make(
		[]*daemonMeshVirtualMulticast,
		0,
		len(multicast.network.multicasts),
	)
	for recipient := range multicast.network.multicasts {
		if recipient != multicast {
			recipients = append(recipients, recipient)
		}
	}
	multicast.network.mu.Unlock()
	for _, recipient := range recipients {
		recipient.deliver(source.Addr(), payload)
	}
	return nil
}

func (multicast *daemonMeshVirtualMulticast) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	if multicast == nil || ctx == nil {
		return discovery.ReceivedDatagram{}, errDaemonMeshContentHarness
	}
	select {
	case datagram := <-multicast.inbound:
		return datagram, nil
	case <-multicast.done:
		return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
	case <-ctx.Done():
		return discovery.ReceivedDatagram{}, ctx.Err()
	}
}

func (multicast *daemonMeshVirtualMulticast) RefreshSelected(
	selected []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	if multicast == nil {
		return discovery.MulticastReport{}, discovery.ErrMulticastClosed
	}
	report, err := daemonMeshIntegrationMulticastReport(
		discovery.DefaultMulticastPort,
		selected,
	)
	if err != nil || !multicast.iface.matchesReport(report) {
		return report, errors.Join(errDaemonMeshContentHarness, err)
	}
	multicast.mu.Lock()
	defer multicast.mu.Unlock()
	if multicast.closed {
		return report, discovery.ErrMulticastClosed
	}
	multicast.report = report
	return report, nil
}

func (multicast *daemonMeshVirtualMulticast) Close() error {
	if multicast == nil {
		return nil
	}
	multicast.close.Do(func() {
		multicast.mu.Lock()
		multicast.closed = true
		close(multicast.done)
		multicast.mu.Unlock()
		multicast.network.mu.Lock()
		delete(multicast.network.multicasts, multicast)
		multicast.network.mu.Unlock()
	})
	return multicast.closeErr
}

func (multicast *daemonMeshVirtualMulticast) deliver(
	source netip.Addr,
	payload []byte,
) {
	if multicast == nil || !source.IsValid() {
		return
	}
	endpoint, interfaceIndex, available := multicast.iface.snapshot()
	if !available || endpoint.Addr().Is4() != source.Is4() {
		return
	}
	family := discovery.AddressFamilyIPv6
	if source.Is4() {
		family = discovery.AddressFamilyIPv4
	}
	multicast.mu.RLock()
	closed := multicast.closed
	joined := false
	for _, join := range multicast.report.Joins {
		if join.InterfaceIndex == interfaceIndex &&
			join.Family == family {
			joined = true
			break
		}
	}
	if !closed && joined {
		select {
		case multicast.inbound <- discovery.ReceivedDatagram{
			Payload:        bytes.Clone(payload),
			Source:         netip.AddrPortFrom(source, discovery.DefaultMulticastPort),
			Family:         family,
			InterfaceIndex: interfaceIndex,
		}:
		default:
		}
	}
	multicast.mu.RUnlock()
}

type daemonMeshVirtualInterface struct {
	mu        sync.RWMutex
	name      string
	index     int
	endpoint  netip.AddrPort
	available bool
}

func newDaemonMeshVirtualInterface(
	name string,
	index int,
	endpoint netip.AddrPort,
) *daemonMeshVirtualInterface {
	return &daemonMeshVirtualInterface{
		name:      name,
		index:     index,
		endpoint:  endpoint,
		available: true,
	}
}

func (networkInterface *daemonMeshVirtualInterface) set(
	address netip.Addr,
	index int,
	available bool,
) {
	networkInterface.mu.Lock()
	defer networkInterface.mu.Unlock()
	networkInterface.available = available
	if available {
		networkInterface.index = index
		networkInterface.endpoint = netip.AddrPortFrom(
			address,
			networkInterface.endpoint.Port(),
		)
	}
}

func (networkInterface *daemonMeshVirtualInterface) Endpoint() netip.AddrPort {
	networkInterface.mu.RLock()
	defer networkInterface.mu.RUnlock()
	if !networkInterface.available {
		return netip.AddrPort{}
	}
	return networkInterface.endpoint
}

func (networkInterface *daemonMeshVirtualInterface) snapshot() (
	netip.AddrPort,
	int,
	bool,
) {
	networkInterface.mu.RLock()
	defer networkInterface.mu.RUnlock()
	return networkInterface.endpoint,
		networkInterface.index,
		networkInterface.available
}

func (networkInterface *daemonMeshVirtualInterface) matchesReport(
	report discovery.MulticastReport,
) bool {
	endpoint, index, available := networkInterface.snapshot()
	if !available || !endpoint.IsValid() || len(report.Joins) != 1 {
		return false
	}
	family := discovery.AddressFamilyIPv6
	if endpoint.Addr().Is4() {
		family = discovery.AddressFamilyIPv4
	}
	join := report.Joins[0]
	return join.InterfaceIndex == index &&
		join.InterfaceName == networkInterface.name &&
		join.Family == family
}

func (networkInterface *daemonMeshVirtualInterface) Interfaces() (
	[]net.Interface,
	error,
) {
	networkInterface.mu.RLock()
	defer networkInterface.mu.RUnlock()
	if !networkInterface.available {
		return nil, nil
	}
	return []net.Interface{{
		Index: networkInterface.index,
		Name:  networkInterface.name,
		Flags: net.FlagUp | net.FlagMulticast,
	}}, nil
}

func (networkInterface *daemonMeshVirtualInterface) Addrs(
	iface *net.Interface,
) ([]net.Addr, error) {
	networkInterface.mu.RLock()
	defer networkInterface.mu.RUnlock()
	if !networkInterface.available ||
		iface == nil ||
		iface.Name != networkInterface.name ||
		iface.Index != networkInterface.index {
		return nil, nil
	}
	address := networkInterface.endpoint.Addr()
	bits := 64
	if address.Is4() {
		bits = 32
	}
	return []net.Addr{&net.IPNet{
		IP:   net.IP(address.AsSlice()),
		Mask: net.CIDRMask(24, bits),
	}}, nil
}
