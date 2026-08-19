package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/discovery"
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
		connectivity: connectivity,
	}
	firstSelection := daemonDiscoverySelection{
		addresses: map[daemonDiscoveryAddressKey]netip.Addr{
			firstKey: first,
		},
		selected: []netip.Addr{first},
	}
	if err := runtime.replaceSelectedAddresses(firstSelection); err != nil {
		t.Fatalf("replace unchanged selection: %v", err)
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
	if err := runtime.replaceSelectedAddresses(interfaceChanged); err != nil {
		t.Fatalf("replace changed interface: %v", err)
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
	if err := runtime.replaceSelectedAddresses(addressChanged); err != nil {
		t.Fatalf("replace changed address: %v", err)
	}
	if connectivity.calls != 2 {
		t.Fatalf(
			"address-change notifications = %d, want 2",
			connectivity.calls,
		)
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

func daemonDiscoveryIPNet(value string) *net.IPNet {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	network.IP = ip
	return network
}
