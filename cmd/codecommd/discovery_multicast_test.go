package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
)

func TestDaemonRecoveringMulticastOpensAfterStartupFailure(t *testing.T) {
	unavailable := errors.New("multicast unavailable")
	iface := net.Interface{
		Index: 7,
		Name:  "en7",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	report := discovery.MulticastReport{Joins: []discovery.InterfaceJoin{{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         discovery.AddressFamilyIPv4,
	}}}
	delegate := newDaemonRecoveringMulticastTestDelegate(report)
	attempts := 0
	multicast, _, err := newDaemonRecoveringMulticast(
		discovery.DefaultMulticastPort,
		daemonRecoveringMulticastTestSelection(iface),
		func(
			uint16,
			[]discovery.MulticastInterfaceSelection,
		) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
			attempts++
			if attempts == 1 {
				return nil, discovery.MulticastReport{}, unavailable
			}
			return delegate, report, nil
		},
	)
	if err != nil {
		t.Fatalf("newDaemonRecoveringMulticast(): %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	if !errors.Is(multicast.LastError(), unavailable) {
		t.Fatalf("startup error = %v, want %v", multicast.LastError(), unavailable)
	}
	select {
	case <-multicast.AdvertisementTriggers():
	default:
		t.Fatal("degraded startup omitted immediate advertisement trigger")
	}
	if err := multicast.Send([]byte("offline")); err != nil {
		t.Fatalf("degraded Send() error = %v", err)
	}

	got, err := multicast.RefreshSelected(
		daemonRecoveringMulticastTestSelection(iface),
	)
	if err != nil {
		t.Fatalf("Refresh(recover) error = %v", err)
	}
	if !sameDaemonMulticastReports(got, report) ||
		multicast.LastError() != nil ||
		attempts != 2 {
		t.Fatalf(
			"recovery = (report=%+v, error=%v, attempts=%d)",
			got,
			multicast.LastError(),
			attempts,
		)
	}
	select {
	case <-multicast.AdvertisementTriggers():
	default:
		t.Fatal("recovery did not trigger immediate advertisement")
	}

	payload := []byte("online")
	if err := multicast.Send(payload); err != nil {
		t.Fatalf("Send(online) error = %v", err)
	}
	if got := delegate.lastPayload(); string(got) != string(payload) {
		t.Fatalf("delegate payload = %q, want %q", got, payload)
	}

	if _, err := multicast.RefreshSelected(
		daemonRecoveringMulticastTestSelection(iface),
	); err != nil {
		t.Fatalf("Refresh(unchanged) error = %v", err)
	}
	select {
	case <-multicast.AdvertisementTriggers():
		t.Fatal("unchanged refresh triggered an advertisement")
	default:
	}
}

func TestDaemonRecoveringMulticastMasksReceiveFailureAndReopens(
	t *testing.T,
) {
	iface := net.Interface{
		Index: 11,
		Name:  "vpn0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	report := discovery.MulticastReport{Joins: []discovery.InterfaceJoin{{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         discovery.AddressFamilyIPv4,
	}}}
	first := newDaemonRecoveringMulticastTestDelegate(report)
	second := newDaemonRecoveringMulticastTestDelegate(report)
	delegates := []*daemonRecoveringMulticastTestDelegate{first, second}
	attempts := 0
	multicast, _, err := newDaemonRecoveringMulticast(
		discovery.DefaultMulticastPort,
		daemonRecoveringMulticastTestSelection(iface),
		func(
			uint16,
			[]discovery.MulticastInterfaceSelection,
		) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
			value := delegates[attempts]
			attempts++
			return value, report, nil
		},
	)
	if err != nil {
		t.Fatalf("newDaemonRecoveringMulticast(): %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	<-multicast.AdvertisementTriggers()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan discovery.ReceivedDatagram, 1)
	resultErr := make(chan error, 1)
	go func() {
		datagram, receiveErr := multicast.ReceiveDatagram(ctx)
		if receiveErr != nil {
			resultErr <- receiveErr
			return
		}
		result <- datagram
	}()
	readFailure := errors.New("socket read failed")
	first.deliver(daemonRecoveringMulticastTestResult{err: readFailure})
	deadline := time.Now().Add(time.Second)
	for !errors.Is(multicast.LastError(), readFailure) {
		if time.Now().After(deadline) {
			t.Fatalf("receive failure was not retained: %v", multicast.LastError())
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := multicast.RefreshSelected(
		daemonRecoveringMulticastTestSelection(iface),
	); err != nil {
		t.Fatalf("Refresh(reopen) error = %v", err)
	}
	want := discovery.ReceivedDatagram{
		Payload:        []byte("recovered"),
		Source:         netip.MustParseAddrPort("192.0.2.9:47831"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: iface.Index,
	}
	second.deliver(daemonRecoveringMulticastTestResult{datagram: want})
	select {
	case got := <-result:
		if string(got.Payload) != string(want.Payload) ||
			got.Source != want.Source ||
			got.Family != want.Family ||
			got.InterfaceIndex != want.InterfaceIndex {
			t.Fatalf("ReceiveDatagram() = %+v, want %+v", got, want)
		}
	case err := <-resultErr:
		t.Fatalf("ReceiveDatagram() error = %v", err)
	case <-ctx.Done():
		t.Fatal("ReceiveDatagram() did not resume after reopen")
	}
}

func TestDaemonRecoveringMulticastRetiresOnInterfaceLossAndReopens(
	t *testing.T,
) {
	iface := net.Interface{
		Index: 13,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	report := discovery.MulticastReport{Joins: []discovery.InterfaceJoin{{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         discovery.AddressFamilyIPv4,
	}}}
	first := newDaemonRecoveringMulticastTestDelegate(report)
	second := newDaemonRecoveringMulticastTestDelegate(report)
	delegates := []*daemonRecoveringMulticastTestDelegate{first, second}
	attempts := 0
	multicast, _, err := newDaemonRecoveringMulticast(
		discovery.DefaultMulticastPort,
		daemonRecoveringMulticastTestSelection(iface),
		func(
			uint16,
			[]discovery.MulticastInterfaceSelection,
		) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
			delegate := delegates[attempts]
			attempts++
			return delegate, report, nil
		},
	)
	if err != nil {
		t.Fatalf("newDaemonRecoveringMulticast(): %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })
	<-multicast.AdvertisementTriggers()

	if _, err := multicast.RefreshSelected(nil); !errors.Is(
		err,
		discovery.ErrNoMulticastJoin,
	) {
		t.Fatalf("Refresh(no interfaces) error = %v", err)
	}
	select {
	case <-first.done:
	default:
		t.Fatal("interface loss did not retire the active multicast delegate")
	}
	if !errors.Is(multicast.LastError(), discovery.ErrNoMulticastJoin) {
		t.Fatalf("interface-loss status = %v", multicast.LastError())
	}
	if err := multicast.Send([]byte("offline")); err != nil {
		t.Fatalf("Send(offline): %v", err)
	}

	if got, err := multicast.RefreshSelected(
		daemonRecoveringMulticastTestSelection(iface),
	); err != nil || !sameDaemonMulticastReports(got, report) {
		t.Fatalf("Refresh(reopen) = (%+v, %v)", got, err)
	}
	if attempts != 2 || multicast.LastError() != nil {
		t.Fatalf(
			"reopen state = attempts %d, error %v",
			attempts,
			multicast.LastError(),
		)
	}
}

func TestDaemonRecoveringMulticastRetiresStaleJoinsWhenMigrationFails(
	t *testing.T,
) {
	iface := net.Interface{
		Index: 17,
		Name:  "ethernet0",
		Flags: net.FlagUp | net.FlagMulticast,
	}
	report := discovery.MulticastReport{Joins: []discovery.InterfaceJoin{{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         discovery.AddressFamilyIPv4,
	}}}
	first := newDaemonRecoveringMulticastTestDelegate(report)
	first.refreshErr = discovery.ErrNoMulticastJoin
	reopenFailure := errors.New("replacement join unavailable")
	attempts := 0
	multicast, _, err := newDaemonRecoveringMulticast(
		discovery.DefaultMulticastPort,
		daemonRecoveringMulticastTestSelection(iface),
		func(
			uint16,
			[]discovery.MulticastInterfaceSelection,
		) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
			attempts++
			if attempts == 1 {
				return first, report, nil
			}
			return nil, discovery.MulticastReport{}, reopenFailure
		},
	)
	if err != nil {
		t.Fatalf("newDaemonRecoveringMulticast(): %v", err)
	}
	t.Cleanup(func() { _ = multicast.Close() })

	if _, err := multicast.RefreshSelected(
		daemonRecoveringMulticastTestSelection(iface),
	); !errors.Is(err, discovery.ErrNoMulticastJoin) ||
		!errors.Is(err, reopenFailure) {
		t.Fatalf("RefreshSelected(migration failure) error = %v", err)
	}
	select {
	case <-first.done:
	default:
		t.Fatal("failed migration retained stale multicast joins")
	}
	if err := multicast.Send([]byte("offline")); err != nil {
		t.Fatalf("degraded Send() error = %v", err)
	}
}

func daemonRecoveringMulticastTestSelection(
	iface net.Interface,
) []discovery.MulticastInterfaceSelection {
	return []discovery.MulticastInterfaceSelection{{
		Interface: iface,
		Families:  []discovery.AddressFamily{discovery.AddressFamilyIPv4},
	}}
}

type daemonRecoveringMulticastTestResult struct {
	datagram discovery.ReceivedDatagram
	err      error
}

type daemonRecoveringMulticastTestDelegate struct {
	report     discovery.MulticastReport
	refreshErr error
	triggers   chan struct{}
	results    chan daemonRecoveringMulticastTestResult
	done       chan struct{}
	close      sync.Once

	mu      sync.Mutex
	payload []byte
}

func newDaemonRecoveringMulticastTestDelegate(
	report discovery.MulticastReport,
) *daemonRecoveringMulticastTestDelegate {
	return &daemonRecoveringMulticastTestDelegate{
		report:   report,
		triggers: make(chan struct{}, 1),
		results:  make(chan daemonRecoveringMulticastTestResult, 1),
		done:     make(chan struct{}),
	}
}

func (delegate *daemonRecoveringMulticastTestDelegate) AdvertisementTriggers() <-chan struct{} {
	return delegate.triggers
}

func (delegate *daemonRecoveringMulticastTestDelegate) Send(payload []byte) error {
	select {
	case <-delegate.done:
		return discovery.ErrMulticastClosed
	default:
	}
	delegate.mu.Lock()
	delegate.payload = append(delegate.payload[:0], payload...)
	delegate.mu.Unlock()
	return nil
}

func (delegate *daemonRecoveringMulticastTestDelegate) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	select {
	case <-ctx.Done():
		return discovery.ReceivedDatagram{}, ctx.Err()
	case <-delegate.done:
		return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
	case result := <-delegate.results:
		return result.datagram, result.err
	}
}

func (delegate *daemonRecoveringMulticastTestDelegate) RefreshSelected(
	[]discovery.MulticastInterfaceSelection,
) (discovery.MulticastReport, error) {
	select {
	case <-delegate.done:
		return discovery.MulticastReport{}, discovery.ErrMulticastClosed
	default:
		return delegate.report, delegate.refreshErr
	}
}

func (delegate *daemonRecoveringMulticastTestDelegate) Close() error {
	delegate.close.Do(func() {
		close(delegate.done)
	})
	return nil
}

func (delegate *daemonRecoveringMulticastTestDelegate) deliver(
	result daemonRecoveringMulticastTestResult,
) {
	delegate.results <- result
}

func (delegate *daemonRecoveringMulticastTestDelegate) lastPayload() []byte {
	delegate.mu.Lock()
	defer delegate.mu.Unlock()
	return append([]byte(nil), delegate.payload...)
}

func sameDaemonMulticastReports(
	left discovery.MulticastReport,
	right discovery.MulticastReport,
) bool {
	if len(left.Joins) != len(right.Joins) ||
		len(left.Failures) != len(right.Failures) {
		return false
	}
	for index := range left.Joins {
		if left.Joins[index] != right.Joins[index] {
			return false
		}
	}
	return true
}
