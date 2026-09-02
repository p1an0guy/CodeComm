package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/endpointservice"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestResolveDaemonDiscoverySelectionBindsListenerAddresses(
	t *testing.T,
) {
	interfaces := []net.Interface{
		{
			Index: 7,
			Name:  "en7",
			Flags: net.FlagUp | net.FlagMulticast,
		},
		{
			Index: 3,
			Name:  "en3",
			Flags: net.FlagUp | net.FlagMulticast,
		},
	}
	addresses := map[int][]net.Addr{
		3: {
			daemonDiscoveryIPNet("192.0.2.10/24"),
		},
		7: {
			daemonDiscoveryIPNet("fe80::10/64"),
			daemonDiscoveryIPNet("2001:db8::10/64"),
		},
	}
	selection, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:47831"),
			netip.MustParseAddrPort("[fe80::10%en7]:47831"),
			netip.MustParseAddrPort("[2001:db8::10]:47831"),
		},
		interfaces,
		func(iface *net.Interface) ([]net.Addr, error) {
			return addresses[iface.Index], nil
		},
	)
	if err != nil {
		t.Fatalf("resolveDaemonDiscoverySelection(): %v", err)
	}
	if got := []int{
		selection.interfaces[0].Index,
		selection.interfaces[1].Index,
	}; !reflect.DeepEqual(got, []int{3, 7}) {
		t.Fatalf("selected interface indexes = %v", got)
	}
	want := map[daemonDiscoveryAddressKey]netip.Addr{
		{
			interfaceIndex: 3,
			family:         discovery.AddressFamilyIPv4,
		}: netip.MustParseAddr("192.0.2.10"),
		{
			interfaceIndex: 7,
			family:         discovery.AddressFamilyIPv6,
		}: netip.MustParseAddr("2001:db8::10"),
		{
			interfaceIndex: 7,
			family:         discovery.AddressFamilyIPv6,
			linkLocal:      true,
		}: netip.MustParseAddr("fe80::10%en7"),
	}
	if !reflect.DeepEqual(selection.addresses, want) {
		t.Fatalf(
			"selected addresses = %#v, want %#v",
			selection.addresses,
			want,
		)
	}
	wantSelected := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("fe80::10%en7"),
	}
	if !reflect.DeepEqual(selection.selected, wantSelected) {
		t.Fatalf(
			"route addresses = %v, want %v",
			selection.selected,
			wantSelected,
		)
	}
	multicast := daemonDiscoveryMulticastSelections(selection)
	if len(multicast) != 2 ||
		multicast[0].Interface.Index != 3 ||
		!reflect.DeepEqual(
			multicast[0].Families,
			[]discovery.AddressFamily{discovery.AddressFamilyIPv4},
		) ||
		multicast[1].Interface.Index != 7 ||
		!reflect.DeepEqual(
			multicast[1].Families,
			[]discovery.AddressFamily{discovery.AddressFamilyIPv6},
		) {
		t.Fatalf("multicast selections = %+v", multicast)
	}
}

func TestRefreshDaemonDiscoverySelectionFollowsInterfaceIdentity(
	t *testing.T,
) {
	initialInterface := net.Interface{
		Index: 3,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	initial, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:47831"),
		},
		[]net.Interface{initialInterface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve initial selection: %v", err)
	}
	selectors := daemonDiscoverySelectors(initial)
	reindexed := net.Interface{
		Index: 9,
		Name:  initialInterface.Name,
		Flags: net.FlagUp | net.FlagMulticast,
	}
	refreshed, err := refreshDaemonDiscoverySelection(
		selectors,
		initial.bindings,
		47831,
		[]net.Interface{reindexed},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.12/24"),
				daemonDiscoveryIPNet("192.0.2.11/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("refresh changed address: %v", err)
	}
	wantEndpoint := netip.MustParseAddrPort("192.0.2.11:47831")
	if !sameDaemonListeners(
		refreshed.listeners,
		[]netip.AddrPort{wantEndpoint},
	) {
		t.Fatalf("refreshed listeners = %v, want %s", refreshed.listeners, wantEndpoint)
	}
	key := daemonDiscoveryAddressKey{
		interfaceIndex: reindexed.Index,
		family:         discovery.AddressFamilyIPv4,
	}
	if refreshed.addresses[key] != wantEndpoint.Addr() {
		t.Fatalf("refreshed address map = %v", refreshed.addresses)
	}
	noMulticast := refreshed
	noMulticast.interfaces = append(
		[]net.Interface(nil),
		refreshed.interfaces...,
	)
	noMulticast.interfaces[0].Flags &^= net.FlagMulticast
	if selected := daemonDiscoveryMulticastSelections(noMulticast); len(selected) != 0 {
		t.Fatalf("non-multicast interface selections = %+v", selected)
	}

	retained, err := refreshDaemonDiscoverySelection(
		selectors,
		refreshed.bindings,
		47831,
		[]net.Interface{reindexed},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
				daemonDiscoveryIPNet("192.0.2.11/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("refresh retained address: %v", err)
	}
	if !sameDaemonListeners(
		retained.listeners,
		[]netip.AddrPort{wantEndpoint},
	) {
		t.Fatalf("retained listeners = %v, want %s", retained.listeners, wantEndpoint)
	}

	missing, err := refreshDaemonDiscoverySelection(
		selectors,
		retained.bindings,
		47831,
		nil,
		func(*net.Interface) ([]net.Addr, error) {
			t.Fatal("address provider called for a missing interface")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("refresh missing interface: %v", err)
	}
	if len(missing.listeners) != 0 ||
		len(missing.selected) != 0 ||
		len(missing.addresses) != 0 ||
		len(missing.interfaces) != 0 {
		t.Fatalf("missing-interface selection = %+v", missing)
	}

	noEligibleAddress, err := refreshDaemonDiscoverySelection(
		selectors,
		retained.bindings,
		47831,
		[]net.Interface{reindexed},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("2001:db8::10/64"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("refresh without eligible address: %v", err)
	}
	if len(noEligibleAddress.interfaces) != 0 {
		t.Fatalf(
			"interfaces without a bound listener = %v",
			noEligibleAddress.interfaces,
		)
	}
}

func TestRefreshDaemonDiscoverySelectionPreservesMultipleAddressSlots(
	t *testing.T,
) {
	iface := net.Interface{
		Index: 3,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	initial, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:47831"),
			netip.MustParseAddrPort("192.0.2.11:47831"),
		},
		[]net.Interface{iface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
				daemonDiscoveryIPNet("192.0.2.11/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve initial selection: %v", err)
	}
	selectors := daemonDiscoverySelectors(initial)
	if len(selectors) != 2 ||
		selectors[0].ordinal != 0 ||
		selectors[1].ordinal != 1 {
		t.Fatalf("selectors = %+v", selectors)
	}

	refreshed, err := refreshDaemonDiscoverySelection(
		selectors,
		initial.bindings,
		47831,
		[]net.Interface{iface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.11/24"),
				daemonDiscoveryIPNet("192.0.2.12/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("refresh multiple addresses: %v", err)
	}
	wantListeners := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.11:47831"),
		netip.MustParseAddrPort("192.0.2.12:47831"),
	}
	if !sameDaemonListeners(refreshed.listeners, wantListeners) {
		t.Fatalf(
			"refreshed listeners = %v, want %v",
			refreshed.listeners,
			wantListeners,
		)
	}
	if refreshed.bindings[selectors[1]] !=
		netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("retained slot bindings = %v", refreshed.bindings)
	}
	key := daemonDiscoveryAddressKey{
		interfaceIndex: iface.Index,
		family:         discovery.AddressFamilyIPv4,
	}
	if refreshed.addresses[key] != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("primary route address = %v", refreshed.addresses)
	}
}

func TestResolveDaemonDiscoverySelectionFailsClosed(
	t *testing.T,
) {
	up := net.Interface{
		Index: 3,
		Name:  "en3",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	tests := []struct {
		name       string
		listeners  []netip.AddrPort
		interfaces []net.Interface
		addresses  map[int][]net.Addr
	}{
		{
			name: "different listener ports",
			listeners: []netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.10:47831"),
				netip.MustParseAddrPort("192.0.2.11:47832"),
			},
			interfaces: []net.Interface{up},
			addresses: map[int][]net.Addr{
				3: {
					daemonDiscoveryIPNet("192.0.2.10/24"),
					daemonDiscoveryIPNet("192.0.2.11/24"),
				},
			},
		},
		{
			name: "address absent",
			listeners: []netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.10:47831"),
			},
			interfaces: []net.Interface{up},
			addresses: map[int][]net.Addr{
				3: {daemonDiscoveryIPNet("192.0.2.11/24")},
			},
		},
		{
			name: "address ambiguous",
			listeners: []netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.10:47831"),
			},
			interfaces: []net.Interface{
				up,
				{
					Index: 4,
					Name:  "en4",
					Flags: net.FlagUp | net.FlagMulticast,
				},
			},
			addresses: map[int][]net.Addr{
				3: {daemonDiscoveryIPNet("192.0.2.10/24")},
				4: {daemonDiscoveryIPNet("192.0.2.10/24")},
			},
		},
		{
			name: "zone mismatch",
			listeners: []netip.AddrPort{
				netip.MustParseAddrPort("[fe80::10%en9]:47831"),
			},
			interfaces: []net.Interface{up},
			addresses: map[int][]net.Addr{
				3: {daemonDiscoveryIPNet("fe80::10/64")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveDaemonDiscoverySelection(
				test.listeners,
				test.interfaces,
				func(iface *net.Interface) ([]net.Addr, error) {
					return test.addresses[iface.Index], nil
				},
			)
			if !errors.Is(err, errDaemonDiscoveryConstruction) {
				t.Fatalf(
					"resolveDaemonDiscoverySelection() error = %v",
					err,
				)
			}
		})
	}
}

func TestDaemonDiscoveryAddressBookReplacesAtomically(t *testing.T) {
	book := &daemonDiscoveryAddressBook{}
	firstKey := daemonDiscoveryAddressKey{
		interfaceIndex: 3,
		family:         discovery.AddressFamilyIPv4,
	}
	first := netip.MustParseAddr("192.0.2.10")
	book.replace(
		map[daemonDiscoveryAddressKey]netip.Addr{firstKey: first},
		[]netip.Addr{first},
	)
	if got, found := book.lookup(
		firstKey.interfaceIndex,
		firstKey.family,
		netip.MustParseAddrPort("192.0.2.20:47831"),
	); !found || got != first {
		t.Fatalf("first lookup = (%s, %t)", got, found)
	}

	secondKey := daemonDiscoveryAddressKey{
		interfaceIndex: 7,
		family:         discovery.AddressFamilyIPv6,
	}
	second := netip.MustParseAddr("2001:db8::10")
	book.replace(
		map[daemonDiscoveryAddressKey]netip.Addr{secondKey: second},
		[]netip.Addr{second},
	)
	if _, found := book.lookup(
		firstKey.interfaceIndex,
		firstKey.family,
		netip.MustParseAddrPort("192.0.2.20:47831"),
	); found {
		t.Fatal("replaced address book retained old key")
	}
	if got, found := book.lookup(
		secondKey.interfaceIndex,
		secondKey.family,
		netip.MustParseAddrPort("[2001:db8::20]:47831"),
	); !found || got != second {
		t.Fatalf("second lookup = (%s, %t)", got, found)
	}
	selected := book.selected()
	selected[0] = first
	if got := book.selected(); len(got) != 1 || got[0] != second {
		t.Fatalf("selected address snapshot was aliased: %v", got)
	}
}

func TestDaemonDiscoverySelectionChangeNotifiesCredentialRecovery(
	t *testing.T,
) {
	first := netip.MustParseAddr("192.0.2.10")
	second := netip.MustParseAddr("192.0.2.11")
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{first},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	localID := daemonEndpointRouteTestDeviceID('5')
	peerID := daemonEndpointRouteTestDeviceID('6')
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		&daemonEndpointRouteStateStub{
			snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		},
		routes,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	firstKey := daemonDiscoveryAddressKey{
		interfaceIndex: 3,
		family:         discovery.AddressFamilyIPv4,
	}
	book := &daemonDiscoveryAddressBook{}
	book.replace(
		map[daemonDiscoveryAddressKey]netip.Addr{firstKey: first},
		[]netip.Addr{first},
	)
	connectivity := &daemonConnectivityNotifierStub{}
	runtime := &daemonDiscoveryRuntime{
		routes:       routes,
		addresses:    book,
		reconciler:   reconciler,
		connectivity: connectivity,
	}
	firstSelection := daemonDiscoverySelection{
		addresses: map[daemonDiscoveryAddressKey]netip.Addr{
			firstKey: first,
		},
		selected: []netip.Addr{first},
	}
	changed, err := runtime.replaceSelectedAddresses(
		t.Context(),
		firstSelection,
	)
	if err != nil || changed {
		t.Fatalf("replace unchanged selection = (%t, %v)", changed, err)
	}
	if connectivity.calls != 0 {
		t.Fatalf(
			"unchanged selection notifications = %d",
			connectivity.calls,
		)
	}

	secondKey := firstKey
	secondKey.interfaceIndex = 7
	interfaceChanged := daemonDiscoverySelection{
		addresses: map[daemonDiscoveryAddressKey]netip.Addr{
			secondKey: first,
		},
		selected: []netip.Addr{first},
	}
	changed, err = runtime.replaceSelectedAddresses(
		t.Context(),
		interfaceChanged,
	)
	if err != nil || !changed {
		t.Fatalf("replace changed interface = (%t, %v)", changed, err)
	}
	if connectivity.calls != 1 {
		t.Fatalf(
			"interface-change notifications = %d, want 1",
			connectivity.calls,
		)
	}
	addressChanged := daemonDiscoverySelection{
		addresses: map[daemonDiscoveryAddressKey]netip.Addr{
			secondKey: second,
		},
		selected: []netip.Addr{second},
	}
	changed, err = runtime.replaceSelectedAddresses(
		t.Context(),
		addressChanged,
	)
	if err != nil || !changed {
		t.Fatalf("replace changed address = (%t, %v)", changed, err)
	}
	if connectivity.calls != 2 {
		t.Fatalf(
			"address-change notifications = %d, want 2",
			connectivity.calls,
		)
	}
}

func TestDaemonDiscoveryManualEndpointChangeReconcilesRoutesImmediately(
	t *testing.T,
) {
	now := time.Date(2026, 9, 1, 12, 34, 56, 0, time.UTC)
	localID := daemonEndpointRouteTestDeviceID('7')
	peerID := daemonEndpointRouteTestDeviceID('8')
	localAddress := netip.MustParseAddr("192.0.2.10")
	manualAddress := netip.MustParseAddrPort("192.0.2.80:47831")
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{localAddress},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	state := &daemonEndpointRouteStateStub{
		snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		candidates: map[domain.DeviceID][]store.PeerEndpointRecord{
			peerID: {{
				DeviceID:   peerID,
				SourceKind: store.PeerEndpointManual,
				Endpoint:   manualAddress,
				ObservedAt: daemonEndpointRouteTimestamp(now),
			}},
		},
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		state,
		routes,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	reconciler.now = func() time.Time { return now }
	book := &daemonDiscoveryAddressBook{}
	book.replace(nil, []netip.Addr{localAddress})
	connectivity := &daemonConnectivityNotifierStub{}
	runtime := &daemonDiscoveryRuntime{
		reconciler:   reconciler,
		addresses:    book,
		connectivity: connectivity,
	}
	if err := runtime.reconcileManualEndpoints(t.Context()); err != nil {
		t.Fatalf("reconcile add: %v", err)
	}
	endpoints, err := routes.ResolveConsensusEndpoints(t.Context(), peerID)
	if err != nil ||
		len(endpoints) != 1 ||
		endpoints[0] != manualAddress ||
		connectivity.calls != 1 {
		t.Fatalf(
			"manual add routes = (%v, %v), notifications %d",
			endpoints,
			err,
			connectivity.calls,
		)
	}

	state.candidates[peerID] = nil
	if err := runtime.reconcileManualEndpoints(t.Context()); err != nil {
		t.Fatalf("reconcile remove: %v", err)
	}
	endpoints, err = routes.ResolveConsensusEndpoints(t.Context(), peerID)
	if err == nil || len(endpoints) != 0 || connectivity.calls != 2 {
		t.Fatalf(
			"manual removal routes = (%v, %v), notifications %d",
			endpoints,
			err,
			connectivity.calls,
		)
	}
}

func TestDaemonDiscoveryRefreshRebindsAndWithdrawsOnInterfaceLoss(
	t *testing.T,
) {
	initialAddress := netip.MustParseAddr("192.0.2.10")
	reboundAddress := netip.MustParseAddr("192.0.2.11")
	const port = 47831
	initialEndpoint := netip.AddrPortFrom(initialAddress, port)
	reboundEndpoint := netip.AddrPortFrom(reboundAddress, port)
	iface := net.Interface{
		Index: 3,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	initialSelection, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{initialEndpoint},
		[]net.Interface{iface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve initial selection: %v", err)
	}

	opened := make(map[netip.AddrPort][]*daemonPeerListenerStub)
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{initialEndpoint},
		func(
			_ context.Context,
			endpoint netip.AddrPort,
		) (net.Listener, error) {
			listener := newDaemonPeerListenerStub(endpoint)
			opened[endpoint] = append(opened[endpoint], listener)
			return listener, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	localID := daemonEndpointRouteTestDeviceID('a')
	peerID := daemonEndpointRouteTestDeviceID('b')
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{initialAddress},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	routeState := &daemonEndpointRouteStateStub{
		snapshot: daemonEndpointRouteSnapshot(localID, peerID),
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		routeState,
		routes,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	reconciler.now = func() time.Time {
		return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	}
	book := &daemonDiscoveryAddressBook{}
	book.replace(initialSelection.addresses, initialSelection.selected)
	publicationFailure := errors.New("publication unavailable")
	publisher := &daemonEndpointPublisherStub{
		refreshErrors: []error{publicationFailure},
	}
	multicast := &daemonDiscoveryMulticastStub{}
	connectivity := &daemonConnectivityNotifierStub{}
	currentInterfaces := []net.Interface{iface}
	currentAddresses := []net.Addr{
		daemonDiscoveryIPNet("192.0.2.11/24"),
	}
	const interval = 20 * time.Second
	runtime := &daemonDiscoveryRuntime{
		publisher:    publisher,
		reconciler:   reconciler,
		multicast:    multicast,
		addresses:    book,
		routes:       routes,
		listeners:    listeners,
		selectors:    daemonDiscoverySelectors(initialSelection),
		bindings:     cloneDaemonDiscoveryBindings(initialSelection.bindings),
		listenerPort: port,
		localState:   daemonDiscoveryPolicyStub(interval),
		listInterfaces: func() ([]net.Interface, error) {
			return append([]net.Interface(nil), currentInterfaces...), nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return append([]net.Addr(nil), currentAddresses...), nil
		},
		connectivity: connectivity,
	}
	runtime.advertisementInterval.Store(int64(interval))

	changed, err := runtime.refresh(t.Context())
	if !errors.Is(err, publicationFailure) || !changed {
		t.Fatalf("refresh(rebind) = (%t, %v)", changed, err)
	}
	if !sameDaemonListeners(
		listeners.Current(),
		[]netip.AddrPort{reboundEndpoint},
	) {
		t.Fatalf("rebound listeners = %v", listeners.Current())
	}
	assertDaemonPeerListenerClosed(t, opened[initialEndpoint][0])
	if publisher.withdrawals != 2 ||
		len(publisher.refreshes) != 1 ||
		!sameDaemonListeners(
			publisher.refreshes[0].SelectedListeners,
			[]netip.AddrPort{reboundEndpoint},
		) {
		t.Fatalf(
			"publisher after rebind = refreshes %+v, withdrawals %d",
			publisher.refreshes,
			publisher.withdrawals,
		)
	}
	if selected := book.selected(); !reflect.DeepEqual(
		selected,
		[]netip.Addr{reboundAddress},
	) {
		t.Fatalf("selected addresses after rebind = %v", selected)
	}
	if connectivity.calls != 1 {
		t.Fatalf("connectivity notifications = %d, want 1", connectivity.calls)
	}
	if multicast.triggers != 1 {
		t.Fatalf("advertisement triggers = %d, want 1", multicast.triggers)
	}

	changed, err = runtime.refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("refresh(publication retry) = (%t, %v)", changed, err)
	}
	if runtime.publicationDirty {
		t.Fatal("successful publication retry remained dirty")
	}
	if publisher.withdrawals != 2 ||
		len(publisher.refreshes) != 2 ||
		!sameDaemonListeners(
			publisher.refreshes[1].SelectedListeners,
			[]netip.AddrPort{reboundEndpoint},
		) {
		t.Fatalf(
			"publisher after retry = refreshes %+v, withdrawals %d",
			publisher.refreshes,
			publisher.withdrawals,
		)
	}
	if multicast.triggers != 2 {
		t.Fatalf(
			"advertisement triggers after recovery = %d, want 2",
			multicast.triggers,
		)
	}

	currentInterfaces = nil
	currentAddresses = nil
	changed, err = runtime.refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("refresh(interface loss) = (%t, %v)", changed, err)
	}
	if len(listeners.Current()) != 0 || len(book.selected()) != 0 {
		t.Fatalf(
			"interface-loss state = listeners %v, selected %v",
			listeners.Current(),
			book.selected(),
		)
	}
	if publisher.withdrawals != 3 {
		t.Fatalf("publisher withdrawals = %d, want 3", publisher.withdrawals)
	}
	if connectivity.calls != 2 {
		t.Fatalf("connectivity notifications = %d, want 2", connectivity.calls)
	}
	if len(multicast.refreshes) != 3 ||
		len(multicast.refreshes[2]) != 0 {
		t.Fatalf("multicast refreshes = %+v", multicast.refreshes)
	}
	if multicast.triggers != 3 {
		t.Fatalf("advertisement triggers = %d, want 3", multicast.triggers)
	}
}

func TestDaemonDiscoveryRefreshBindFailureWithdrawsUntilRecovery(
	t *testing.T,
) {
	initialAddress := netip.MustParseAddr("192.0.2.10")
	reboundAddress := netip.MustParseAddr("192.0.2.11")
	const port = 47831
	initialEndpoint := netip.AddrPortFrom(initialAddress, port)
	reboundEndpoint := netip.AddrPortFrom(reboundAddress, port)
	iface := net.Interface{
		Index: 3,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	initialSelection, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{initialEndpoint},
		[]net.Interface{iface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve initial selection: %v", err)
	}

	bindFailure := errors.New("replacement bind failed")
	initialListener := newDaemonPeerListenerStub(initialEndpoint)
	reboundListener := newDaemonPeerListenerStub(reboundEndpoint)
	reboundAttempts := 0
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{initialEndpoint},
		func(
			_ context.Context,
			endpoint netip.AddrPort,
		) (net.Listener, error) {
			if endpoint == initialEndpoint {
				return initialListener, nil
			}
			reboundAttempts++
			if reboundAttempts == 1 {
				return nil, bindFailure
			}
			return reboundListener, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	localID := daemonEndpointRouteTestDeviceID('e')
	peerID := daemonEndpointRouteTestDeviceID('f')
	routeTable, err := transport.NewConsensusRouteTable(
		[]netip.Addr{initialAddress},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		&daemonEndpointRouteStateStub{
			snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		},
		routeTable,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	routes := &daemonSelectedAddressRoutesStub{delegate: routeTable}
	book := &daemonDiscoveryAddressBook{}
	book.replace(initialSelection.addresses, initialSelection.selected)
	publisher := &daemonEndpointPublisherStub{}
	multicast := &daemonDiscoveryMulticastStub{}
	connectivity := &daemonConnectivityNotifierStub{}
	const interval = 20 * time.Second
	runtime := &daemonDiscoveryRuntime{
		publisher:    publisher,
		reconciler:   reconciler,
		multicast:    multicast,
		addresses:    book,
		routes:       routes,
		listeners:    listeners,
		selectors:    daemonDiscoverySelectors(initialSelection),
		bindings:     cloneDaemonDiscoveryBindings(initialSelection.bindings),
		listenerPort: port,
		localState:   daemonDiscoveryPolicyStub(interval),
		listInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{iface}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.11/24"),
			}, nil
		},
		connectivity: connectivity,
	}
	runtime.advertisementInterval.Store(int64(interval))

	changed, err := runtime.refresh(t.Context())
	if !changed || !errors.Is(err, bindFailure) {
		t.Fatalf("refresh(bind failure) = (%t, %v)", changed, err)
	}
	if len(listeners.Current()) != 0 ||
		len(book.selected()) != 0 ||
		len(publisher.refreshes) != 0 ||
		publisher.withdrawals != 1 {
		t.Fatalf(
			"failed-bind state = listeners %v, selected %v, refreshes %d, withdrawals %d",
			listeners.Current(),
			book.selected(),
			len(publisher.refreshes),
			publisher.withdrawals,
		)
	}
	if len(routes.calls) != 1 ||
		len(routes.calls[0].selected) != 0 ||
		len(multicast.refreshes) != 1 ||
		len(multicast.refreshes[0]) != 0 {
		t.Fatalf(
			"failed-bind network state = routes %+v, multicast %+v",
			routes.calls,
			multicast.refreshes,
		)
	}
	assertDaemonPeerListenerClosed(t, initialListener)

	changed, err = runtime.refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("refresh(bind recovery) = (%t, %v)", changed, err)
	}
	if !sameDaemonListeners(
		listeners.Current(),
		[]netip.AddrPort{reboundEndpoint},
	) ||
		!reflect.DeepEqual(book.selected(), []netip.Addr{reboundAddress}) ||
		len(publisher.refreshes) != 1 ||
		publisher.withdrawals != 2 {
		t.Fatalf(
			"recovered state = listeners %v, selected %v, refreshes %d, withdrawals %d",
			listeners.Current(),
			book.selected(),
			len(publisher.refreshes),
			publisher.withdrawals,
		)
	}
	if len(routes.calls) != 2 ||
		!reflect.DeepEqual(
			routes.calls[1].selected,
			[]netip.Addr{reboundAddress},
		) ||
		len(multicast.refreshes) != 2 ||
		len(multicast.refreshes[1]) != 1 ||
		multicast.triggers != 2 {
		t.Fatalf(
			"recovered network state = routes %+v, multicast %+v, triggers %d",
			routes.calls,
			multicast.refreshes,
			multicast.triggers,
		)
	}
}

func TestDaemonDiscoveryRefreshRebindsSameAddressAfterInterfaceReplacement(
	t *testing.T,
) {
	address := netip.MustParseAddr("192.0.2.10")
	const port = 47831
	endpoint := netip.AddrPortFrom(address, port)
	initialInterface := net.Interface{
		Index: 3,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	initialSelection, err := resolveDaemonDiscoverySelection(
		[]netip.AddrPort{endpoint},
		[]net.Interface{initialInterface},
		func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve initial selection: %v", err)
	}

	opened := make([]*daemonPeerListenerStub, 0, 2)
	listeners, err := openDaemonPeerListeners(
		t.Context(),
		[]netip.AddrPort{endpoint},
		func(
			context.Context,
			netip.AddrPort,
		) (net.Listener, error) {
			if len(opened) != 0 &&
				opened[len(opened)-1].closeCalls.Load() == 0 {
				return nil, errors.New("address already in use")
			}
			listener := newDaemonPeerListenerStub(endpoint)
			opened = append(opened, listener)
			return listener, nil
		},
	)
	if err != nil {
		t.Fatalf("openDaemonPeerListeners(): %v", err)
	}
	t.Cleanup(func() { _ = listeners.Close() })

	localID := daemonEndpointRouteTestDeviceID('c')
	peerID := daemonEndpointRouteTestDeviceID('d')
	routeTable, err := transport.NewConsensusRouteTable(
		[]netip.Addr{address},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		&daemonEndpointRouteStateStub{
			snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		},
		routeTable,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	routes := &daemonSelectedAddressRoutesStub{delegate: routeTable}
	book := &daemonDiscoveryAddressBook{}
	book.replace(initialSelection.addresses, initialSelection.selected)
	publisher := &daemonEndpointPublisherStub{}
	multicast := &daemonDiscoveryMulticastStub{}
	inbound := &daemonInboundAddressInvalidatorStub{}
	connectivity := &daemonConnectivityNotifierStub{}
	const interval = 20 * time.Second
	runtime := &daemonDiscoveryRuntime{
		publisher:    publisher,
		reconciler:   reconciler,
		multicast:    multicast,
		addresses:    book,
		routes:       routes,
		listeners:    listeners,
		selectors:    daemonDiscoverySelectors(initialSelection),
		bindings:     cloneDaemonDiscoveryBindings(initialSelection.bindings),
		listenerPort: port,
		localState:   daemonDiscoveryPolicyStub(interval),
		listInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{
				Index: 9,
				Name:  initialInterface.Name,
				Flags: initialInterface.Flags,
			}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				daemonDiscoveryIPNet("192.0.2.10/24"),
			}, nil
		},
		connectivity: connectivity,
		ingress:      inbound,
	}
	runtime.advertisementInterval.Store(int64(interval))
	routes.before = func() error {
		if publisher.withdrawals == 0 {
			return errors.New("routes changed before endpoint withdrawal")
		}
		return nil
	}

	changed, err := runtime.refresh(t.Context())
	if err != nil || !changed {
		t.Fatalf("refresh(interface replacement) = (%t, %v)", changed, err)
	}
	if len(opened) != 2 {
		t.Fatalf("listener opens = %d, want 2", len(opened))
	}
	assertDaemonPeerListenerClosed(t, opened[0])
	if calls := routes.calls; len(calls) != 1 ||
		!reflect.DeepEqual(calls[0].selected, []netip.Addr{address}) ||
		!reflect.DeepEqual(calls[0].rebound, []netip.Addr{address}) {
		t.Fatalf("route rebind calls = %+v", calls)
	}
	if !reflect.DeepEqual(
		inbound.calls,
		[][]netip.Addr{{address}},
	) {
		t.Fatalf("inbound invalidations = %v", inbound.calls)
	}
	if multicast.triggers != 1 {
		t.Fatalf("advertisement triggers = %d, want 1", multicast.triggers)
	}
	if len(publisher.refreshes) != 1 ||
		!sameDaemonListeners(
			publisher.refreshes[0].SelectedListeners,
			[]netip.AddrPort{endpoint},
		) {
		t.Fatalf("endpoint refreshes = %+v", publisher.refreshes)
	}
	if connectivity.calls != 1 {
		t.Fatalf("connectivity notifications = %d, want 1", connectivity.calls)
	}
}

func TestDaemonDiscoveryRuntimeShutdownIgnoresLateRefreshFailure(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &daemonDiscoveryRuntime{
		cancel: cancel,
	}
	runtime.fatalMu.Lock()
	runtime.closing = true
	runtime.closeOnce.Do(runtime.cancel)
	runtime.fatalMu.Unlock()
	runtime.failRouteRefresh(context.Canceled)
	runtime.failEndpointRefresh(context.Canceled)
	runtime.fatalMu.RLock()
	fatal := runtime.fatalErr
	runtime.fatalMu.RUnlock()
	if fatal != nil {
		t.Fatalf("late shutdown failure became fatal: %v", fatal)
	}
	if ctx.Err() == nil {
		t.Fatal("runtime cancellation was not applied")
	}
}

type daemonDiscoveryPolicyStub time.Duration

func (policy daemonDiscoveryPolicyStub) DiscoveryAdvertisementInterval(
	context.Context,
) (time.Duration, error) {
	return time.Duration(policy), nil
}

type daemonEndpointPublisherStub struct {
	refreshes     []endpointservice.RefreshInput
	refreshErrors []error
	withdrawals   int
}

func (publisher *daemonEndpointPublisherStub) Refresh(
	_ context.Context,
	input endpointservice.RefreshInput,
) error {
	input.SelectedListeners = append(
		[]netip.AddrPort(nil),
		input.SelectedListeners...,
	)
	publisher.refreshes = append(publisher.refreshes, input)
	if len(publisher.refreshErrors) != 0 {
		err := publisher.refreshErrors[0]
		publisher.refreshErrors = publisher.refreshErrors[1:]
		return err
	}
	return nil
}

func (publisher *daemonEndpointPublisherStub) Withdraw() error {
	publisher.withdrawals++
	return nil
}

func (*daemonEndpointPublisherStub) CurrentEndpointSet() ([]byte, bool) {
	return nil, false
}

func (*daemonEndpointPublisherStub) BeginClose() error { return nil }
func (*daemonEndpointPublisherStub) Wait() error       { return nil }
func (*daemonEndpointPublisherStub) Close() error      { return nil }

type daemonDiscoveryMulticastStub struct {
	refreshes [][]net.Interface
	triggers  int
}

func (*daemonDiscoveryMulticastStub) AdvertisementTriggers() <-chan struct{} {
	return nil
}

func (*daemonDiscoveryMulticastStub) Send([]byte) error { return nil }

func (multicast *daemonDiscoveryMulticastStub) TriggerAdvertisement() error {
	multicast.triggers++
	return nil
}

func (*daemonDiscoveryMulticastStub) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	<-ctx.Done()
	return discovery.ReceivedDatagram{}, ctx.Err()
}

func (multicast *daemonDiscoveryMulticastStub) RefreshSelected(
	selections []discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	interfaces := make([]net.Interface, len(selections))
	for index := range selections {
		interfaces[index] = selections[index].Interface
	}
	multicast.refreshes = append(
		multicast.refreshes,
		append([]net.Interface(nil), interfaces...),
	)
	return discovery.MulticastReport{}, nil
}

func (*daemonDiscoveryMulticastStub) Close() error { return nil }

type daemonSelectedAddressRouteCall struct {
	selected []netip.Addr
	rebound  []netip.Addr
}

type daemonSelectedAddressRoutesStub struct {
	delegate *transport.ConsensusRouteTable
	before   func() error
	calls    []daemonSelectedAddressRouteCall
}

func (routes *daemonSelectedAddressRoutesStub) RebindSelectedAddresses(
	selected []netip.Addr,
	rebound []netip.Addr,
) error {
	if routes.before != nil {
		if err := routes.before(); err != nil {
			return err
		}
	}
	routes.calls = append(routes.calls, daemonSelectedAddressRouteCall{
		selected: append([]netip.Addr(nil), selected...),
		rebound:  append([]netip.Addr(nil), rebound...),
	})
	return routes.delegate.RebindSelectedAddresses(selected, rebound)
}

type daemonInboundAddressInvalidatorStub struct {
	calls [][]netip.Addr
}

func (invalidator *daemonInboundAddressInvalidatorStub) CloseConnectionsBoundTo(
	addresses []netip.Addr,
) (transport.LocalAddressCloseResult, error) {
	invalidator.calls = append(
		invalidator.calls,
		append([]netip.Addr(nil), addresses...),
	)
	return transport.LocalAddressCloseResult{
		Checked: 1,
		Closed:  1,
	}, nil
}

func daemonDiscoveryIPNet(value string) *net.IPNet {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	network.IP = ip
	return network
}
