package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestDaemonPairingEndpointsRejectsMixedPorts(t *testing.T) {
	_, err := daemonPairingEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:47831"),
		netip.MustParseAddrPort("[2001:db8::10]:47832"),
	})
	if !errors.Is(err, errDaemonPairingConstruction) {
		t.Fatalf(
			"daemonPairingEndpoints() error = %v, want %v",
			err,
			errDaemonPairingConstruction,
		)
	}
}

func TestDaemonPairingEndpointsEnforcesAdvertisedEndpointCap(t *testing.T) {
	listeners := make([]netip.AddrPort, pairing.MaxInviteEndpoints+1)
	for index := range listeners {
		listeners[index] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}),
			47831,
		)
	}
	if _, err := daemonPairingEndpoints(listeners); !errors.Is(
		err,
		errDaemonPairingConstruction,
	) {
		t.Fatalf(
			"daemonPairingEndpoints() error = %v, want %v",
			err,
			errDaemonPairingConstruction,
		)
	}
}

func TestDaemonPairingEndpointsFiltersIPv6LinkLocalBeforeCap(t *testing.T) {
	listeners := make([]netip.AddrPort, 0, pairing.MaxInviteEndpoints+1)
	for index := range pairing.MaxInviteEndpoints {
		listeners = append(listeners, netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}),
			47831,
		))
	}
	listeners = append(
		listeners,
		netip.MustParseAddrPort("[fe80::1%en0]:47831"),
	)
	endpoints, err := daemonPairingEndpoints(listeners)
	if err != nil {
		t.Fatalf("daemonPairingEndpoints() error = %v", err)
	}
	if len(endpoints) != pairing.MaxInviteEndpoints {
		t.Fatalf(
			"daemonPairingEndpoints() returned %d endpoints, want %d",
			len(endpoints),
			pairing.MaxInviteEndpoints,
		)
	}
	for _, endpoint := range endpoints {
		if endpoint.IP.Is6() && endpoint.IP.IsLinkLocalUnicast() {
			t.Fatalf("link-local endpoint was advertised: %+v", endpoint)
		}
	}
}

func TestDaemonPairingEndpointsIgnoresLinkLocalPort(t *testing.T) {
	endpoints, err := daemonPairingEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("[fe80::1%en0]:47832"),
		netip.MustParseAddrPort("192.0.2.10:47831"),
	})
	if err != nil {
		t.Fatalf("daemonPairingEndpoints() error = %v", err)
	}
	if len(endpoints) != 1 ||
		endpoints[0].IP.String() != "192.0.2.10" ||
		endpoints[0].Port != 47831 {
		t.Fatalf("endpoints = %+v", endpoints)
	}
}

func TestDaemonPairingEndpointsCanonicalizesListenerOrder(t *testing.T) {
	endpoints, err := daemonPairingEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::10]:47831"),
		netip.MustParseAddrPort("192.0.2.20:47831"),
		netip.MustParseAddrPort("192.0.2.10:47831"),
	})
	if err != nil {
		t.Fatalf("daemonPairingEndpoints() error = %v", err)
	}
	want := []string{
		"192.0.2.10:47831",
		"192.0.2.20:47831",
		"[2001:db8::10]:47831",
	}
	if len(endpoints) != len(want) {
		t.Fatalf("endpoint count = %d, want %d", len(endpoints), len(want))
	}
	for index := range want {
		if got := netip.AddrPortFrom(
			endpoints[index].IP,
			endpoints[index].Port,
		).String(); got != want[index] {
			t.Fatalf("endpoint %d = %s, want %s", index, got, want[index])
		}
	}
}

func TestDaemonPairingEndpointsRejectsDuplicates(t *testing.T) {
	_, err := daemonPairingEndpoints([]netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:47831"),
		netip.MustParseAddrPort("192.0.2.10:47831"),
	})
	if !errors.Is(err, errDaemonPairingConstruction) {
		t.Fatalf(
			"daemonPairingEndpoints() error = %v, want %v",
			err,
			errDaemonPairingConstruction,
		)
	}
}

func TestDaemonRebootstrapFinalizerClassifiesStateErrors(t *testing.T) {
	retryable := errors.New("state temporarily unavailable")
	tests := []struct {
		name       string
		stateErr   error
		want       error
		unexpected []error
	}{
		{name: "success"},
		{
			name:     "eligibility rejected",
			stateErr: store.ErrPairingEligibility,
			want:     pairingservice.ErrFinalizationRejected,
			unexpected: []error{
				pairingservice.ErrFinalizationIntegrity,
			},
		},
		{
			name:     "pairing row integrity",
			stateErr: store.ErrPairingStateIntegrity,
			want:     pairingservice.ErrFinalizationIntegrity,
			unexpected: []error{
				pairingservice.ErrFinalizationRejected,
			},
		},
		{
			name:     "projection integrity",
			stateErr: store.ErrLocalStateIntegrity,
			want:     pairingservice.ErrFinalizationIntegrity,
		},
		{
			name:     "store integrity",
			stateErr: store.ErrIntegrityCheck,
			want:     pairingservice.ErrFinalizationIntegrity,
		},
		{
			name:     "sqlite corruption",
			stateErr: store.ErrCorrupt,
			want:     pairingservice.ErrFinalizationIntegrity,
		},
		{
			name:     "availability retry",
			stateErr: retryable,
			want:     retryable,
			unexpected: []error{
				pairingservice.ErrFinalizationRejected,
				pairingservice.ErrFinalizationIntegrity,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &daemonRebootstrapStateStub{err: test.stateErr}
			finalizer := daemonRebootstrapFinalizer{state: state}
			err := finalizer.FinalizeRebootstrap(
				context.Background(),
				pairingservice.AttemptDetails{},
			)
			if test.want == nil && err != nil ||
				test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf(
					"FinalizeRebootstrap() error = %v, want %v",
					err,
					test.want,
				)
			}
			for _, unexpected := range test.unexpected {
				if errors.Is(err, unexpected) {
					t.Fatalf(
						"FinalizeRebootstrap() error = %v, unexpectedly matches %v",
						err,
						unexpected,
					)
				}
			}
			if state.calls != 1 {
				t.Fatalf("state calls = %d, want 1", state.calls)
			}
		})
	}
}

type daemonRebootstrapStateStub struct {
	err   error
	calls int
}

func (state *daemonRebootstrapStateStub) RevalidateRebootstrapEligibility(
	context.Context,
	store.PairingInviteRecord,
	pairing.RequestCore,
) error {
	state.calls++
	return state.err
}
