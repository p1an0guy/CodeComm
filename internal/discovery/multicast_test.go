package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestOpenMulticastValidatesSelectedInterfaces(t *testing.T) {
	t.Parallel()

	valid := testInterface(1, "ethernet0")
	tooMany := make([]net.Interface, MaxSelectedInterfaces+1)
	for index := range tooMany {
		tooMany[index] = testInterface(index+1, fmt.Sprintf("if%d", index+1))
	}

	tests := []struct {
		name       string
		port       uint16
		interfaces []net.Interface
	}{
		{name: "reserved port", port: MinMulticastPort - 1, interfaces: []net.Interface{valid}},
		{name: "empty", port: DefaultMulticastPort},
		{name: "too many", port: DefaultMulticastPort, interfaces: tooMany},
		{
			name:       "missing index",
			port:       DefaultMulticastPort,
			interfaces: []net.Interface{{Name: "ethernet0", Flags: net.FlagUp | net.FlagMulticast}},
		},
		{
			name:       "down",
			port:       DefaultMulticastPort,
			interfaces: []net.Interface{{Index: 1, Name: "ethernet0", Flags: net.FlagMulticast}},
		},
		{
			name:       "no multicast",
			port:       DefaultMulticastPort,
			interfaces: []net.Interface{{Index: 1, Name: "ethernet0", Flags: net.FlagUp}},
		},
		{
			name: "loopback",
			port: DefaultMulticastPort,
			interfaces: []net.Interface{{
				Index: 1,
				Name:  "loopback0",
				Flags: net.FlagUp | net.FlagMulticast | net.FlagLoopback,
			}},
		},
		{
			name: "duplicate index",
			port: DefaultMulticastPort,
			interfaces: []net.Interface{
				valid,
				testInterface(1, "ethernet1"),
			},
		},
		{
			name: "duplicate name",
			port: DefaultMulticastPort,
			interfaces: []net.Interface{
				valid,
				testInterface(2, "ethernet0"),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			network := newFakeMulticastNetwork(map[int][]net.Addr{
				1: testAddresses("192.0.2.1"),
			})
			value, _, err := openMulticast(
				test.port,
				test.interfaces,
				network.dependencies(),
			)
			if value != nil {
				t.Fatal("openMulticast() returned a value for invalid configuration")
			}
			if !errors.Is(err, ErrInvalidMulticastConfig) {
				t.Fatalf("openMulticast() error = %v, want ErrInvalidMulticastConfig", err)
			}
			if got := network.openCount(); got != 0 {
				t.Fatalf("socket open count = %d, want 0", got)
			}
		})
	}
}

func TestOpenMulticastAcceptsConfigurationBoundaries(t *testing.T) {
	t.Parallel()

	interfaces := make([]net.Interface, MaxSelectedInterfaces)
	addresses := make(map[int][]net.Addr, MaxSelectedInterfaces)
	for index := range interfaces {
		iface := testInterface(index+1, fmt.Sprintf("if%d", index+1))
		interfaces[index] = iface
		addresses[iface.Index] = testAddresses(fmt.Sprintf(
			"192.0.2.%d",
			index+1,
		))
	}
	network := newFakeMulticastNetwork(addresses)
	multicast, report, err := openMulticast(
		MinMulticastPort,
		interfaces,
		network.dependencies(),
	)
	if err != nil {
		t.Fatalf("openMulticast(boundaries) error = %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	if len(report.Joins) != MaxSelectedInterfaces {
		t.Fatalf(
			"join count = %d, want %d",
			len(report.Joins),
			MaxSelectedInterfaces,
		)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("boundary configuration failures = %#v", report.Failures)
	}
}

func TestOpenMulticastConfiguresJoinsAndSendsPerInterface(t *testing.T) {
	t.Parallel()

	first := testInterface(7, "ethernet0")
	second := testInterface(11, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.7", "fe80::7"),
		second.Index: testAddresses("198.51.100.11"),
	})
	multicast, report, err := openMulticast(
		49123,
		[]net.Interface{first, second},
		network.dependencies(),
	)
	if err != nil {
		t.Fatalf("openMulticast() error = %v", err)
	}
	t.Cleanup(func() {
		if err := multicast.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	wantJoins := []InterfaceJoin{
		{InterfaceIndex: 7, InterfaceName: "ethernet0", Family: AddressFamilyIPv4},
		{InterfaceIndex: 7, InterfaceName: "ethernet0", Family: AddressFamilyIPv6},
		{InterfaceIndex: 11, InterfaceName: "vpn0", Family: AddressFamilyIPv4},
	}
	if !equalJoins(report.Joins, wantJoins) {
		t.Fatalf("report joins = %#v, want %#v", report.Joins, wantJoins)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("report failures = %#v, want none", report.Failures)
	}
	select {
	case <-multicast.AdvertisementTriggers():
	default:
		t.Fatal("startup did not trigger immediate advertisement")
	}

	ipv4Socket := network.socket(AddressFamilyIPv4)
	ipv6Socket := network.socket(AddressFamilyIPv6)
	assertSocketConfiguration(t, ipv4Socket, multicastHopLimit, true)
	assertSocketConfiguration(t, ipv6Socket, multicastHopLimit, true)
	assertFakeJoins(t, ipv4Socket, map[int]netip.Addr{
		first.Index:  netip.MustParseAddr(DefaultIPv4Group),
		second.Index: netip.MustParseAddr(DefaultIPv4Group),
	})
	assertFakeJoins(t, ipv6Socket, map[int]netip.Addr{
		first.Index: netip.MustParseAddr(DefaultIPv6Group),
	})

	payload := []byte(`{"magic":"codecomm"}`)
	if err := multicast.Send(payload); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	assertFakeWrites(t, ipv4Socket, []fakeWrite{
		{
			interfaceIndex: first.Index,
			destination: netip.MustParseAddrPort(
				"239.192.71.31:49123",
			),
			payload: payload,
		},
		{
			interfaceIndex: second.Index,
			destination: netip.MustParseAddrPort(
				"239.192.71.31:49123",
			),
			payload: payload,
		},
	})
	assertFakeWrites(t, ipv6Socket, []fakeWrite{
		{
			interfaceIndex: first.Index,
			destination: netip.MustParseAddrPort(
				"[ff12::c0de:c031]:49123",
			),
			payload: payload,
		},
	})

	if err := multicast.Send(make([]byte, MaxDatagramBytes+1)); !errors.Is(
		err,
		ErrMulticastDatagramSize,
	) {
		t.Fatalf("oversize Send() error = %v, want ErrMulticastDatagramSize", err)
	}
}

func TestOpenMulticastAllowsPartialFamilyFailure(t *testing.T) {
	t.Parallel()

	iface := testInterface(3, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.3", "2001:db8::3"),
	})
	network.openErrors[AddressFamilyIPv6] = errors.New("IPv6 unavailable")

	multicast, report, err := openMulticast(
		DefaultMulticastPort,
		[]net.Interface{iface},
		network.dependencies(),
	)
	if err != nil {
		t.Fatalf("openMulticast() error = %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	if len(report.Joins) != 1 ||
		report.Joins[0].Family != AddressFamilyIPv4 {
		t.Fatalf("report joins = %#v, want one IPv4 join", report.Joins)
	}
	if len(report.Failures) != 1 ||
		report.Failures[0].Family != AddressFamilyIPv6 ||
		report.Failures[0].InterfaceIndex != iface.Index {
		t.Fatalf("report failures = %#v, want one per-interface IPv6 failure", report.Failures)
	}
}

func TestOpenMulticastTriesNextInterfaceAfterOpenFailure(t *testing.T) {
	t.Parallel()

	first := testInterface(1, "ethernet0")
	second := testInterface(2, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.1"),
		second.Index: testAddresses("198.51.100.2"),
	})
	network.openInterfaceErrors[joinKey{
		family:         AddressFamilyIPv4,
		interfaceIndex: first.Index,
	}] = errors.New("interface unavailable")

	multicast, report, err := openMulticast(
		DefaultMulticastPort,
		[]net.Interface{first, second},
		network.dependencies(),
	)
	if err != nil {
		t.Fatalf("openMulticast() error = %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	if len(report.Joins) != 2 {
		t.Fatalf("report joins = %#v, want both interfaces after fallback", report.Joins)
	}
	if len(report.Failures) != 1 ||
		report.Failures[0].InterfaceIndex != first.Index {
		t.Fatalf("report failures = %#v, want failed first open attempt", report.Failures)
	}
}

func TestOpenMulticastFailsWhenNoFamilyWorks(t *testing.T) {
	t.Parallel()

	iface := testInterface(3, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.3", "2001:db8::3"),
	})
	network.openErrors[AddressFamilyIPv4] = errors.New("IPv4 unavailable")
	network.openErrors[AddressFamilyIPv6] = errors.New("IPv6 unavailable")

	multicast, report, err := openMulticast(
		DefaultMulticastPort,
		[]net.Interface{iface},
		network.dependencies(),
	)
	if multicast != nil {
		t.Fatal("openMulticast() returned a value when no family worked")
	}
	if !errors.Is(err, ErrNoMulticastJoin) {
		t.Fatalf("openMulticast() error = %v, want ErrNoMulticastJoin", err)
	}
	if len(report.Failures) != 2 {
		t.Fatalf("report failure count = %d, want 2", len(report.Failures))
	}
}

func TestMulticastReceiveBoundsAndIPv6Zone(t *testing.T) {
	t.Parallel()

	iface := testInterface(7, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.7", "fe80::7"),
	})
	multicast := mustOpenFakeMulticast(t, network, iface)
	ipv4Socket := network.socket(AddressFamilyIPv4)
	ipv6Socket := network.socket(AddressFamilyIPv6)

	exact := bytes.Repeat([]byte{0x5a}, MaxDatagramBytes)
	ipv4Socket.inject(fakeRead{
		payload:        exact,
		source:         &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 60400},
		interfaceIndex: iface.Index,
	})
	datagram, err := multicast.ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatalf("ReceiveDatagram(exact limit) error = %v", err)
	}
	if !bytes.Equal(datagram.Payload, exact) ||
		datagram.Source != netip.MustParseAddrPort("192.0.2.9:60400") ||
		datagram.Family != AddressFamilyIPv4 ||
		datagram.InterfaceIndex != iface.Index {
		t.Fatalf("ReceiveDatagram(exact limit) = %+v", datagram)
	}
	ipv4Socket.inject(fakeRead{
		payload:        bytes.Repeat([]byte{0x6b}, MaxDatagramBytes+1),
		source:         &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 60400},
		interfaceIndex: iface.Index,
	})

	ipv6Socket.inject(fakeRead{
		payload: []byte("link-local"),
		source: &net.UDPAddr{
			IP:   net.ParseIP("fe80::1234"),
			Port: 60401,
		},
		interfaceIndex: iface.Index,
	})
	payload, source, err := multicast.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive(link-local control index) error = %v", err)
	}
	if string(payload) != "link-local" ||
		source != netip.MustParseAddrPort("[fe80::1234%ethernet0]:60401") {
		t.Fatalf("Receive(link-local control index) = %q from %s", payload, source)
	}

	ipv6Socket.inject(fakeRead{
		payload: []byte("windows-zone"),
		source: &net.UDPAddr{
			IP:   net.ParseIP("fe80::5678"),
			Port: 60402,
			Zone: strconvItoa(iface.Index),
		},
	})
	payload, source, err = multicast.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive(link-local source zone) error = %v", err)
	}
	if string(payload) != "windows-zone" ||
		source != netip.MustParseAddrPort("[fe80::5678%ethernet0]:60402") {
		t.Fatalf("Receive(link-local source zone) = %q from %s", payload, source)
	}

	ipv6Socket.inject(fakeRead{
		payload: []byte("global"),
		source: &net.UDPAddr{
			IP:   net.ParseIP("2001:db8::9"),
			Port: 60403,
			Zone: "untrusted",
		},
		interfaceIndex: iface.Index,
	})
	_, source, err = multicast.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive(global IPv6) error = %v", err)
	}
	if source != netip.MustParseAddrPort("[2001:db8::9]:60403") {
		t.Fatalf("Receive(global IPv6) source = %s, want zone stripped", source)
	}
}

func TestMulticastReaderDropsTruncationAndFailsClosedOnReadError(t *testing.T) {
	t.Parallel()

	iface := testInterface(17, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.17"),
	})
	multicast := mustOpenFakeMulticast(t, network, iface)
	socket := network.socket(AddressFamilyIPv4)

	socket.inject(fakeRead{err: syscall.EMSGSIZE})
	socket.inject(fakeRead{
		payload:        []byte("after-truncation"),
		source:         &net.UDPAddr{IP: net.ParseIP("192.0.2.18"), Port: 60400},
		interfaceIndex: iface.Index,
	})
	payload, _, err := multicast.Receive(context.Background())
	if err != nil || string(payload) != "after-truncation" {
		t.Fatalf("Receive(after truncation) = (%q, %v)", payload, err)
	}

	readFailure := errors.New("permanent receive failure")
	socket.inject(fakeRead{err: readFailure})
	select {
	case <-multicast.Done():
	case <-time.After(time.Second):
		t.Fatal("permanent read failure did not fail multicast closed")
	}
	if err := multicast.Close(); !errors.Is(err, readFailure) {
		t.Fatalf("Close() error = %v, want %v", err, readFailure)
	}
}

func TestMulticastReceiveCancellationAndClose(t *testing.T) {
	t.Parallel()

	iface := testInterface(5, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.5"),
	})
	multicast := mustOpenFakeMulticast(t, network, iface)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := multicast.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive(canceled) error = %v, want context.Canceled", err)
	}

	result := make(chan error, 1)
	go func() {
		_, _, err := multicast.Receive(context.Background())
		result <- err
	}()
	if err := multicast.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrMulticastClosed) {
			t.Fatalf("blocked Receive() error = %v, want ErrMulticastClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not unblock Receive()")
	}
	if err := multicast.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := network.socket(AddressFamilyIPv4).closeCount.Load(); got != 1 {
		t.Fatalf("socket Close() count = %d, want 1", got)
	}
	if got := network.socket(AddressFamilyIPv4).activeReads.Load(); got != 0 {
		t.Fatalf("active socket reads after Close = %d, want 0", got)
	}
}

func TestMulticastReceiveRejectsQueuedDatagramAfterClose(t *testing.T) {
	t.Parallel()

	iface := testInterface(5, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.5"),
	})
	multicast := mustOpenFakeMulticast(t, network, iface)
	multicast.inbound <- inboundDatagram{
		payload: []byte("queued-before-close"),
		source:  netip.MustParseAddrPort("192.0.2.9:60000"),
		family:  AddressFamilyIPv4,
	}

	if err := multicast.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	payload, source, err := multicast.Receive(context.Background())
	if !errors.Is(err, ErrMulticastClosed) {
		t.Fatalf("Receive() error = %v, want ErrMulticastClosed", err)
	}
	if payload != nil || source.IsValid() {
		t.Fatalf("Receive() returned closed payload/source: %q, %s", payload, source)
	}
}

func TestMulticastRefreshReplacesJoinsAndTriggersAdvertisement(t *testing.T) {
	t.Parallel()

	first := testInterface(1, "ethernet0")
	second := testInterface(2, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.1"),
		second.Index: testAddresses("198.51.100.2", "fe80::2"),
	})
	multicast := mustOpenFakeMulticast(t, network, first)
	<-multicast.AdvertisementTriggers()

	report, err := multicast.Refresh([]net.Interface{second})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	want := []InterfaceJoin{
		{InterfaceIndex: 2, InterfaceName: "vpn0", Family: AddressFamilyIPv4},
		{InterfaceIndex: 2, InterfaceName: "vpn0", Family: AddressFamilyIPv6},
	}
	if !equalJoins(report.Joins, want) {
		t.Fatalf("Refresh() joins = %#v, want %#v", report.Joins, want)
	}
	select {
	case <-multicast.AdvertisementTriggers():
	default:
		t.Fatal("successful Refresh() did not trigger immediate advertisement")
	}

	ipv4Socket := network.socket(AddressFamilyIPv4)
	assertFakeJoins(t, ipv4Socket, map[int]netip.Addr{
		second.Index: netip.MustParseAddr(DefaultIPv4Group),
	})
	if network.openCountFor(AddressFamilyIPv4) != 1 ||
		network.openCountFor(AddressFamilyIPv6) != 1 {
		t.Fatalf(
			"socket open counts = IPv4 %d, IPv6 %d; want one each",
			network.openCountFor(AddressFamilyIPv4),
			network.openCountFor(AddressFamilyIPv6),
		)
	}

	ipv4Socket.inject(fakeRead{
		payload:        []byte("stale"),
		source:         &net.UDPAddr{IP: net.ParseIP("192.0.2.8"), Port: 60000},
		interfaceIndex: first.Index,
	})
	ipv4Socket.inject(fakeRead{
		payload:        []byte("active"),
		source:         &net.UDPAddr{IP: net.ParseIP("198.51.100.8"), Port: 60001},
		interfaceIndex: second.Index,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload, _, err := multicast.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive(after refresh) error = %v", err)
	}
	if string(payload) != "active" {
		t.Fatalf("Receive(after refresh) payload = %q, want active", payload)
	}
}

func TestMulticastRefreshUnchangedDoesNotTriggerAdvertisement(t *testing.T) {
	t.Parallel()

	iface := testInterface(1, "ethernet0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		iface.Index: testAddresses("192.0.2.1"),
	})
	multicast := mustOpenFakeMulticast(t, network, iface)
	<-multicast.AdvertisementTriggers()

	report, err := multicast.Refresh([]net.Interface{iface})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	want := []InterfaceJoin{{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         AddressFamilyIPv4,
	}}
	if !equalJoins(report.Joins, want) {
		t.Fatalf("Refresh() joins = %#v, want %#v", report.Joins, want)
	}
	select {
	case <-multicast.AdvertisementTriggers():
		t.Fatal("unchanged Refresh() triggered an advertisement")
	default:
	}
}

func TestMulticastRefreshRollsBackFailedRemoval(t *testing.T) {
	t.Parallel()

	first := testInterface(1, "ethernet0")
	second := testInterface(2, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.1"),
		second.Index: testAddresses("198.51.100.2"),
	})
	multicast := mustOpenFakeMulticast(t, network, first)
	<-multicast.AdvertisementTriggers()
	ipv4Socket := network.socket(AddressFamilyIPv4)
	ipv4Socket.setLeaveError(first.Index, errors.New("leave failed"))

	report, err := multicast.Refresh([]net.Interface{second})
	if !errors.Is(err, ErrMulticastRefresh) {
		t.Fatalf("Refresh() error = %v, want ErrMulticastRefresh", err)
	}
	want := []InterfaceJoin{{
		InterfaceIndex: first.Index,
		InterfaceName:  first.Name,
		Family:         AddressFamilyIPv4,
	}}
	if !equalJoins(report.Joins, want) {
		t.Fatalf("failed Refresh() joins = %#v, want prior %#v", report.Joins, want)
	}
	assertFakeJoins(t, ipv4Socket, map[int]netip.Addr{
		first.Index: netip.MustParseAddr(DefaultIPv4Group),
	})
	select {
	case <-multicast.AdvertisementTriggers():
		t.Fatal("failed Refresh() triggered advertisement")
	default:
	}
}

func TestMulticastRefreshAllJoinsFailKeepsPriorSet(t *testing.T) {
	t.Parallel()

	first := testInterface(1, "ethernet0")
	second := testInterface(2, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.1"),
		second.Index: testAddresses("198.51.100.2"),
	})
	multicast := mustOpenFakeMulticast(t, network, first)
	ipv4Socket := network.socket(AddressFamilyIPv4)
	ipv4Socket.setJoinError(second.Index, errors.New("join failed"))

	report, err := multicast.Refresh([]net.Interface{second})
	if !errors.Is(err, ErrNoMulticastJoin) {
		t.Fatalf("Refresh() error = %v, want ErrNoMulticastJoin", err)
	}
	if len(report.Joins) != 1 ||
		report.Joins[0].InterfaceIndex != first.Index {
		t.Fatalf("failed Refresh() joins = %#v, want prior interface", report.Joins)
	}
	assertFakeJoins(t, ipv4Socket, map[int]netip.Addr{
		first.Index: netip.MustParseAddr(DefaultIPv4Group),
	})
}

func TestMulticastConcurrentSendReceiveRefreshAndClose(t *testing.T) {
	first := testInterface(1, "ethernet0")
	second := testInterface(2, "vpn0")
	network := newFakeMulticastNetwork(map[int][]net.Addr{
		first.Index:  testAddresses("192.0.2.1"),
		second.Index: testAddresses("198.51.100.2"),
	})
	multicast := mustOpenFakeMulticast(t, network, first)
	ipv4Socket := network.socket(AddressFamilyIPv4)

	var group sync.WaitGroup
	group.Add(3)
	go func() {
		defer group.Done()
		for index := 0; index < 100; index++ {
			_ = multicast.Send([]byte("advertisement"))
		}
	}()
	go func() {
		defer group.Done()
		for index := 0; index < 50; index++ {
			selected := []net.Interface{first}
			if index%2 != 0 {
				selected = []net.Interface{second}
			}
			_, _ = multicast.Refresh(selected)
		}
	}()
	go func() {
		defer group.Done()
		for index := 0; index < 100; index++ {
			ipv4Socket.inject(fakeRead{
				payload: []byte("inbound"),
				source: &net.UDPAddr{
					IP:   net.ParseIP("192.0.2.99"),
					Port: 60000,
				},
			})
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Millisecond,
			)
			_, _, _ = multicast.Receive(ctx)
			cancel()
		}
	}()
	group.Wait()
	if err := multicast.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := ipv4Socket.activeReads.Load(); got != 0 {
		t.Fatalf("active socket reads after race test = %d, want 0", got)
	}
}

func TestMulticastNativeIntegration(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces() error = %v", err)
	}
	var selected *net.Interface
	for index := range interfaces {
		iface := interfaces[index]
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagMulticast == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addressErr := iface.Addrs()
		if addressErr != nil || len(availableFamilies(addresses)) == 0 {
			continue
		}
		selected = &iface
		break
	}
	if selected == nil {
		nativeMulticastUnavailable(t, "no eligible non-loopback multicast interface")
	}

	port, err := availableUDPPort()
	if err != nil {
		nativeMulticastUnavailable(t, "reserve UDP port: %v", err)
	}
	multicast, _, err := OpenMulticast(port, []net.Interface{*selected})
	if err != nil {
		nativeMulticastUnavailable(t, "open: %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	second, _, err := OpenMulticast(port, []net.Interface{*selected})
	if err != nil {
		t.Fatalf("second same-port OpenMulticast() error = %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	payload := []byte(fmt.Sprintf(
		"codecomm-native-multicast-%d",
		time.Now().UnixNano(),
	))
	if err := multicast.Send(payload); err != nil {
		nativeMulticastUnavailable(t, "send: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		received, _, receiveErr := second.Receive(ctx)
		if receiveErr != nil {
			if errors.Is(receiveErr, context.DeadlineExceeded) {
				nativeMulticastUnavailable(t, "receive: %v", receiveErr)
			}
			t.Fatalf("Receive(native) error = %v", receiveErr)
		}
		if bytes.Equal(received, payload) {
			return
		}
	}
}

func nativeMulticastUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	message := fmt.Sprintf(format, args...)
	if os.Getenv("CODECOMM_REQUIRE_NATIVE_MULTICAST") == "1" {
		t.Fatalf("native multicast required: %s", message)
	}
	t.Skipf("native multicast unavailable: %s", message)
}

func availableUDPPort() (uint16, error) {
	listener, err := net.ListenUDP(
		"udp4",
		&net.UDPAddr{IP: net.IPv4zero},
	)
	if err != nil {
		return 0, err
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	if port < MinMulticastPort || port > 65535 {
		return 0, fmt.Errorf("reserved invalid UDP port %d", port)
	}
	return uint16(port), nil
}

func mustOpenFakeMulticast(
	t *testing.T,
	network *fakeMulticastNetwork,
	interfaces ...net.Interface,
) *MulticastIO {
	t.Helper()
	multicast, report, err := openMulticast(
		DefaultMulticastPort,
		interfaces,
		network.dependencies(),
	)
	if err != nil {
		t.Fatalf("openMulticast() error = %v; report = %#v", err, report)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	return multicast
}

func testInterface(index int, name string) net.Interface {
	return net.Interface{
		Index: index,
		Name:  name,
		Flags: net.FlagUp | net.FlagMulticast,
	}
}

func testAddresses(addresses ...string) []net.Addr {
	result := make([]net.Addr, 0, len(addresses))
	for _, text := range addresses {
		address := netip.MustParseAddr(text)
		bits := 128
		if address.Is4() {
			bits = 32
		}
		result = append(result, &net.IPNet{
			IP:   net.IP(address.AsSlice()),
			Mask: net.CIDRMask(bits, bits),
		})
	}
	return result
}

func equalJoins(left, right []InterfaceJoin) bool {
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

func strconvItoa(value int) string {
	return fmt.Sprintf("%d", value)
}

type fakeMulticastNetwork struct {
	mu sync.Mutex

	addresses           map[int][]net.Addr
	addressErr          map[int]error
	openErrors          map[AddressFamily]error
	openInterfaceErrors map[joinKey]error
	sockets             map[AddressFamily][]*fakeMulticastSocket
}

func newFakeMulticastNetwork(
	addresses map[int][]net.Addr,
) *fakeMulticastNetwork {
	return &fakeMulticastNetwork{
		addresses:           addresses,
		addressErr:          make(map[int]error),
		openErrors:          make(map[AddressFamily]error),
		openInterfaceErrors: make(map[joinKey]error),
		sockets:             make(map[AddressFamily][]*fakeMulticastSocket),
	}
}

func (network *fakeMulticastNetwork) dependencies() multicastDependencies {
	return multicastDependencies{
		open: func(
			family AddressFamily,
			port uint16,
			iface *net.Interface,
			group netip.Addr,
		) (multicastSocket, error) {
			network.mu.Lock()
			defer network.mu.Unlock()
			if err := network.openErrors[family]; err != nil {
				return nil, err
			}
			if err := network.openInterfaceErrors[joinKey{
				family:         family,
				interfaceIndex: iface.Index,
			}]; err != nil {
				return nil, err
			}
			socket := newFakeMulticastSocket(family, port)
			socket.joins[iface.Index] = group
			network.sockets[family] = append(
				network.sockets[family],
				socket,
			)
			return socket, nil
		},
		addrs: func(iface *net.Interface) ([]net.Addr, error) {
			network.mu.Lock()
			defer network.mu.Unlock()
			if err := network.addressErr[iface.Index]; err != nil {
				return nil, err
			}
			return append([]net.Addr(nil), network.addresses[iface.Index]...), nil
		},
	}
}

func (network *fakeMulticastNetwork) socket(
	family AddressFamily,
) *fakeMulticastSocket {
	network.mu.Lock()
	defer network.mu.Unlock()
	sockets := network.sockets[family]
	if len(sockets) == 0 {
		return nil
	}
	return sockets[len(sockets)-1]
}

func (network *fakeMulticastNetwork) openCount() int {
	network.mu.Lock()
	defer network.mu.Unlock()
	count := 0
	for _, sockets := range network.sockets {
		count += len(sockets)
	}
	return count
}

func (network *fakeMulticastNetwork) openCountFor(
	family AddressFamily,
) int {
	network.mu.Lock()
	defer network.mu.Unlock()
	return len(network.sockets[family])
}

type fakeWrite struct {
	interfaceIndex int
	destination    netip.AddrPort
	payload        []byte
}

type fakeRead struct {
	payload        []byte
	source         net.Addr
	interfaceIndex int
	err            error
}

type fakeMulticastSocket struct {
	family AddressFamily
	port   uint16

	mu             sync.Mutex
	hopLimits      []int
	loopback       bool
	receiveEnabled bool
	joins          map[int]netip.Addr
	joinErrors     map[int]error
	leaveErrors    map[int]error
	writes         []fakeWrite
	writeErrors    map[int]error

	reads       chan fakeRead
	closed      chan struct{}
	closeOnce   sync.Once
	closeCount  atomic.Int32
	activeReads atomic.Int32
}

func newFakeMulticastSocket(
	family AddressFamily,
	port uint16,
) *fakeMulticastSocket {
	return &fakeMulticastSocket{
		family:      family,
		port:        port,
		joins:       make(map[int]netip.Addr),
		joinErrors:  make(map[int]error),
		leaveErrors: make(map[int]error),
		writeErrors: make(map[int]error),
		reads:       make(chan fakeRead, 256),
		closed:      make(chan struct{}),
	}
}

func (socket *fakeMulticastSocket) SetMulticastHopLimit(value int) error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.hopLimits = append(socket.hopLimits, value)
	return nil
}

func (socket *fakeMulticastSocket) SetMulticastLoopback(enabled bool) error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.loopback = enabled
	return nil
}

func (socket *fakeMulticastSocket) EnableReceiveInterface() error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.receiveEnabled = true
	return nil
}

func (socket *fakeMulticastSocket) JoinGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if err := socket.joinErrors[iface.Index]; err != nil {
		return err
	}
	socket.joins[iface.Index] = group
	return nil
}

func (socket *fakeMulticastSocket) LeaveGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if err := socket.leaveErrors[iface.Index]; err != nil {
		return err
	}
	if joinedGroup, exists := socket.joins[iface.Index]; exists &&
		joinedGroup == group {
		delete(socket.joins, iface.Index)
	}
	return nil
}

func (socket *fakeMulticastSocket) ReadFrom(
	buffer []byte,
) (int, net.Addr, int, error) {
	socket.activeReads.Add(1)
	defer socket.activeReads.Add(-1)
	select {
	case read := <-socket.reads:
		if read.err != nil {
			return 0, nil, 0, read.err
		}
		copy(buffer, read.payload)
		return len(read.payload), read.source, read.interfaceIndex, nil
	case <-socket.closed:
		return 0, nil, 0, net.ErrClosed
	}
}

func (socket *fakeMulticastSocket) WriteTo(
	payload []byte,
	iface *net.Interface,
	destination netip.AddrPort,
) (int, error) {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if err := socket.writeErrors[iface.Index]; err != nil {
		return 0, err
	}
	socket.writes = append(socket.writes, fakeWrite{
		interfaceIndex: iface.Index,
		destination:    destination,
		payload:        append([]byte(nil), payload...),
	})
	return len(payload), nil
}

func (socket *fakeMulticastSocket) Close() error {
	socket.closeCount.Add(1)
	socket.closeOnce.Do(func() {
		close(socket.closed)
	})
	return nil
}

func (socket *fakeMulticastSocket) inject(read fakeRead) {
	select {
	case socket.reads <- read:
	case <-socket.closed:
	}
}

func (socket *fakeMulticastSocket) setJoinError(
	interfaceIndex int,
	err error,
) {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.joinErrors[interfaceIndex] = err
}

func (socket *fakeMulticastSocket) setLeaveError(
	interfaceIndex int,
	err error,
) {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.leaveErrors[interfaceIndex] = err
}

func assertSocketConfiguration(
	t *testing.T,
	socket *fakeMulticastSocket,
	hopLimit int,
	receiveEnabled bool,
) {
	t.Helper()
	if socket == nil {
		t.Fatal("socket is nil")
	}
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if len(socket.hopLimits) != 1 ||
		socket.hopLimits[0] != hopLimit {
		t.Fatalf("hop-limit calls = %#v, want [%d]", socket.hopLimits, hopLimit)
	}
	if !socket.loopback {
		t.Fatal("multicast loopback is disabled, want enabled for local sessions")
	}
	if socket.receiveEnabled != receiveEnabled {
		t.Fatalf(
			"receive-interface enabled = %t, want %t",
			socket.receiveEnabled,
			receiveEnabled,
		)
	}
}

func assertFakeJoins(
	t *testing.T,
	socket *fakeMulticastSocket,
	want map[int]netip.Addr,
) {
	t.Helper()
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if len(socket.joins) != len(want) {
		t.Fatalf("active joins = %#v, want %#v", socket.joins, want)
	}
	for interfaceIndex, group := range want {
		if socket.joins[interfaceIndex] != group {
			t.Fatalf(
				"join[%d] = %s, want %s",
				interfaceIndex,
				socket.joins[interfaceIndex],
				group,
			)
		}
	}
}

func assertFakeWrites(
	t *testing.T,
	socket *fakeMulticastSocket,
	want []fakeWrite,
) {
	t.Helper()
	socket.mu.Lock()
	defer socket.mu.Unlock()
	if len(socket.writes) != len(want) {
		t.Fatalf("writes = %#v, want %#v", socket.writes, want)
	}
	for index := range want {
		got := socket.writes[index]
		if got.interfaceIndex != want[index].interfaceIndex ||
			got.destination != want[index].destination ||
			!bytes.Equal(got.payload, want[index].payload) {
			t.Fatalf("write[%d] = %#v, want %#v", index, got, want[index])
		}
	}
}
