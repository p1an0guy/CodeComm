package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestDaemonEndpointRouteReconcilerRestoresAndPurgesRoutes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	localID := daemonEndpointRouteTestDeviceID('1')
	activeID := daemonEndpointRouteTestDeviceID('2')
	revokedID := daemonEndpointRouteTestDeviceID('3')
	localAddress := netip.MustParseAddr("192.0.2.10")
	staticActive := netip.MustParseAddrPort("192.0.2.20:47831")
	staticRevoked := netip.MustParseAddrPort("192.0.2.30:47831")
	learnedRevoked := netip.MustParseAddrPort("192.0.2.31:47831")

	configured := []daemonPeerRoute{
		{deviceID: activeID, remote: staticActive, local: localAddress},
		{deviceID: revokedID, remote: staticRevoked, local: localAddress},
	}
	initial := make([]transport.ConsensusRoute, len(configured))
	for index, value := range configured {
		initial[index] = transport.ConsensusRoute{
			PeerDeviceID:         value.deviceID,
			RemoteEndpoint:       value.remote,
			SelectedLocalAddress: value.local,
		}
	}
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{localAddress},
		initial,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	if err := routes.Replace(
		revokedID,
		transport.ConsensusRouteAuthenticated,
		[]transport.ExpiringConsensusRoute{{
			ConsensusRoute: transport.ConsensusRoute{
				PeerDeviceID:         revokedID,
				RemoteEndpoint:       learnedRevoked,
				SelectedLocalAddress: localAddress,
			},
			ExpiresAt: now.Add(time.Hour),
		}},
	); err != nil {
		t.Fatalf("seed revoked learned route: %v", err)
	}

	state := &daemonEndpointRouteStateStub{
		snapshot: daemonEndpointRouteSnapshot(
			localID,
			activeID,
			revokedID,
		),
		candidates: map[domain.DeviceID][]store.PeerEndpointRecord{
			activeID: daemonEndpointRouteRecords(activeID, now),
		},
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		state,
		routes,
		configured,
		nil,
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	reconciler.now = func() time.Time { return now }
	if err := reconciler.reconcile(
		context.Background(),
		[]netip.Addr{localAddress},
		true,
	); err != nil {
		t.Fatalf("reconcile(): %v", err)
	}

	activeEndpoints, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		activeID,
	)
	if err != nil || len(activeEndpoints) != 5 {
		t.Fatalf("active routes = (%v, %v), want five", activeEndpoints, err)
	}
	if !slices.Contains(activeEndpoints, staticActive) {
		t.Fatalf("active routes omit configured manual endpoint: %v", activeEndpoints)
	}
	revokedEndpoints, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		revokedID,
	)
	if err != nil ||
		len(revokedEndpoints) != 1 ||
		revokedEndpoints[0] != staticRevoked {
		t.Fatalf("revoked routes = (%v, %v), want retained manual", revokedEndpoints, err)
	}
	if !slices.Equal(state.purged, []domain.DeviceID{revokedID}) {
		t.Fatalf("purged peers = %v, want %s", state.purged, revokedID)
	}
}

func TestDaemonEndpointRouteReconcilerPreservesLiveDiscoveryOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	localID := daemonEndpointRouteTestDeviceID('4')
	peerID := daemonEndpointRouteTestDeviceID('5')
	firstLocal := netip.MustParseAddr("192.0.2.10")
	secondLocal := netip.MustParseAddr("192.0.2.11")
	remote := netip.MustParseAddrPort("192.0.2.40:47831")
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{firstLocal, secondLocal},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	if err := routes.Replace(
		peerID,
		transport.ConsensusRouteDiscovery,
		[]transport.ExpiringConsensusRoute{{
			ConsensusRoute: transport.ConsensusRoute{
				PeerDeviceID:         peerID,
				RemoteEndpoint:       remote,
				SelectedLocalAddress: firstLocal,
			},
			ExpiresAt: now.Add(30 * time.Second),
		}},
	); err != nil {
		t.Fatalf("seed discovery route: %v", err)
	}
	state := &daemonEndpointRouteStateStub{
		snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		candidates: map[domain.DeviceID][]store.PeerEndpointRecord{
			peerID: {{
				DeviceID:   peerID,
				SourceKind: store.PeerEndpointRawDiscovery,
				Endpoint:   remote,
				ObservedAt: daemonEndpointRouteTimestamp(now),
				ExpiresAt: daemonEndpointRouteTimestamp(
					now.Add(30 * time.Second),
				),
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
	selected := []netip.Addr{firstLocal, secondLocal}
	if err := reconciler.reconcile(
		context.Background(),
		selected,
		false,
	); err != nil {
		t.Fatalf("maintenance reconcile(): %v", err)
	}
	if endpoints, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		peerID,
	); err != nil || len(endpoints) != 1 || endpoints[0] != remote {
		t.Fatalf("live discovery route = (%v, %v)", endpoints, err)
	}

	if err := reconciler.reconcile(
		context.Background(),
		selected,
		true,
	); err != nil {
		t.Fatalf("startup reconcile(): %v", err)
	}
	if _, err := routes.ResolveConsensusEndpoints(
		context.Background(),
		peerID,
	); !errors.Is(err, transport.ErrConsensusEndpointUnavailable) {
		t.Fatalf("ambiguous restored discovery route error = %v", err)
	}
}

func TestDaemonEndpointRouteReconcilerRemapsConfiguredManualSource(
	t *testing.T,
) {
	now := time.Now().UTC().Truncate(time.Second)
	localID := daemonEndpointRouteTestDeviceID('c')
	peerID := daemonEndpointRouteTestDeviceID('d')
	original := netip.MustParseAddr("192.0.2.10")
	replacement := netip.MustParseAddr("192.0.2.11")
	unrelated := netip.MustParseAddr("192.0.2.12")
	remote := netip.MustParseAddrPort("192.0.2.20:47831")
	selector := daemonDiscoverySelector{
		interfaceName: "ethernet0",
		family:        discovery.AddressFamilyIPv4,
	}
	configured := []daemonPeerRoute{{
		deviceID: peerID,
		remote:   remote,
		local:    original,
	}}
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{original},
		[]transport.ConsensusRoute{{
			PeerDeviceID:         peerID,
			RemoteEndpoint:       remote,
			SelectedLocalAddress: original,
		}},
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	reconciler, err := newDaemonEndpointRouteReconciler(
		localID,
		&daemonEndpointRouteStateStub{
			snapshot: daemonEndpointRouteSnapshot(localID, peerID),
		},
		routes,
		configured,
		map[daemonDiscoverySelector]netip.Addr{
			selector: original,
		},
	)
	if err != nil {
		t.Fatalf("newDaemonEndpointRouteReconciler(): %v", err)
	}
	reconciler.now = func() time.Time { return now }

	if err := routes.ReplaceSelectedAddresses(
		[]netip.Addr{original, replacement, unrelated},
	); err != nil {
		t.Fatalf("install transition addresses: %v", err)
	}
	if err := reconciler.replaceSelectedBindings(
		map[daemonDiscoverySelector]netip.Addr{
			selector: replacement,
		},
	); err != nil {
		t.Fatalf("replace selected bindings: %v", err)
	}
	if err := reconciler.reconcile(
		t.Context(),
		[]netip.Addr{replacement, unrelated},
		false,
	); err != nil {
		t.Fatalf("reconcile replacement: %v", err)
	}
	if err := routes.ReplaceSelectedAddresses(
		[]netip.Addr{replacement, unrelated},
	); err != nil {
		t.Fatalf("retire original address: %v", err)
	}
	endpoints, err := routes.ResolveConsensusEndpoints(t.Context(), peerID)
	if err != nil || len(endpoints) != 1 || endpoints[0] != remote {
		t.Fatalf("remapped endpoints = (%v, %v)", endpoints, err)
	}
}

func TestDaemonEndpointRouteReconcilerQuarantinesPeerCollision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	localID := daemonEndpointRouteTestDeviceID('6')
	firstPeerID := daemonEndpointRouteTestDeviceID('7')
	secondPeerID := daemonEndpointRouteTestDeviceID('8')
	localAddress := netip.MustParseAddr("192.0.2.10")
	shared := netip.MustParseAddrPort("192.0.2.40:47831")
	routes, err := transport.NewConsensusRouteTable(
		[]netip.Addr{localAddress},
		nil,
	)
	if err != nil {
		t.Fatalf("NewConsensusRouteTable(): %v", err)
	}
	members := []coordstatus.MemberSummary{
		{
			ID: localID, Role: device.RoleOwner,
			Status: device.StatusActive, EntityVersion: 1,
		},
		{
			ID: firstPeerID, Role: device.RoleEditor,
			Status: device.StatusActive, EntityVersion: 1,
		},
		{
			ID: secondPeerID, Role: device.RoleEditor,
			Status: device.StatusActive, EntityVersion: 1,
		},
	}
	expiry := daemonEndpointRouteTimestamp(now.Add(7 * 24 * time.Hour))
	observed := daemonEndpointRouteTimestamp(now)
	state := &daemonEndpointRouteStateStub{
		snapshot: coordstatus.DurableSnapshot{
			Members:     members,
			MemberTotal: uint64(len(members)),
		},
		candidates: map[domain.DeviceID][]store.PeerEndpointRecord{
			firstPeerID: {
				{
					DeviceID:   firstPeerID,
					SourceKind: store.PeerEndpointMemberSigned,
					Endpoint:   shared, ObservedAt: observed,
					ExpiresAt: expiry,
				},
			},
			secondPeerID: {
				{
					DeviceID:   secondPeerID,
					SourceKind: store.PeerEndpointMemberSigned,
					Endpoint:   shared, ObservedAt: observed,
					ExpiresAt: expiry,
				},
			},
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
	if err := reconciler.reconcile(
		context.Background(),
		[]netip.Addr{localAddress},
		true,
	); err != nil {
		t.Fatalf("reconcile(colliding signed endpoints): %v", err)
	}
	for _, peerID := range []domain.DeviceID{firstPeerID, secondPeerID} {
		if _, err := routes.ResolveConsensusEndpoints(
			context.Background(),
			peerID,
		); !errors.Is(err, transport.ErrConsensusEndpointUnavailable) {
			t.Fatalf("ResolveConsensusEndpoints(%s) error = %v", peerID, err)
		}
	}
}

func TestUnambiguousDaemonRouteSource(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		selected []string
		want     string
		ok       bool
	}{
		{
			name:     "single ipv4",
			endpoint: "192.0.2.20:47831",
			selected: []string{"192.0.2.10", "2001:db8::10"},
			want:     "192.0.2.10",
			ok:       true,
		},
		{
			name:     "ambiguous ipv4",
			endpoint: "192.0.2.20:47831",
			selected: []string{"192.0.2.10", "192.0.2.11"},
		},
		{
			name:     "matching link local zone",
			endpoint: "[fe80::20%en7]:47831",
			selected: []string{"fe80::10%en3", "fe80::11%en7"},
			want:     "fe80::11%en7",
			ok:       true,
		},
		{
			name:     "missing link local zone",
			endpoint: "[fe80::20]:47831",
			selected: []string{"fe80::11%en7"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected := make([]netip.Addr, len(test.selected))
			for index, value := range test.selected {
				selected[index] = netip.MustParseAddr(value)
			}
			got, ok := unambiguousDaemonRouteSource(
				netip.MustParseAddrPort(test.endpoint),
				selected,
			)
			if ok != test.ok || ok && got.String() != test.want {
				t.Fatalf("source = (%s, %t), want (%s, %t)", got, ok, test.want, test.ok)
			}
		})
	}
}

type daemonEndpointRouteStateStub struct {
	snapshot   coordstatus.DurableSnapshot
	candidates map[domain.DeviceID][]store.PeerEndpointRecord
	purged     []domain.DeviceID
}

func (state *daemonEndpointRouteStateStub) StatusSnapshot(
	context.Context,
	domain.DeviceID,
	int,
) (coordstatus.DurableSnapshot, error) {
	return state.snapshot, nil
}

func (*daemonEndpointRouteStateStub) ExpireStalePeerEndpoints(
	context.Context,
	domain.Timestamp,
) (int, error) {
	return 0, nil
}

func (state *daemonEndpointRouteStateStub) ListPeerEndpointCandidates(
	_ context.Context,
	deviceID domain.DeviceID,
	_ domain.Timestamp,
) ([]store.PeerEndpointRecord, error) {
	return append([]store.PeerEndpointRecord(nil), state.candidates[deviceID]...), nil
}

func (state *daemonEndpointRouteStateStub) PurgePeerLearnedEndpoints(
	_ context.Context,
	deviceID domain.DeviceID,
) error {
	state.purged = append(state.purged, deviceID)
	return nil
}

func daemonEndpointRouteSnapshot(
	localID domain.DeviceID,
	peers ...domain.DeviceID,
) coordstatus.DurableSnapshot {
	members := []coordstatus.MemberSummary{{
		ID: localID, Role: device.RoleOwner,
		Status: device.StatusActive, EntityVersion: 1,
	}}
	for index, peerID := range peers {
		status := device.StatusActive
		if index == len(peers)-1 && len(peers) > 1 {
			status = device.StatusRevoked
		}
		members = append(members, coordstatus.MemberSummary{
			ID: peerID, Role: device.RoleEditor,
			Status: status, EntityVersion: 1,
		})
	}
	return coordstatus.DurableSnapshot{
		Members:     members,
		MemberTotal: uint64(len(members)),
	}
}

func daemonEndpointRouteRecords(
	deviceID domain.DeviceID,
	now time.Time,
) []store.PeerEndpointRecord {
	observed := daemonEndpointRouteTimestamp(now)
	guessExpiry := daemonEndpointRouteTimestamp(now.Add(7 * 24 * time.Hour))
	return []store.PeerEndpointRecord{
		{
			DeviceID: deviceID, SourceKind: store.PeerEndpointMemberSigned,
			Endpoint:   netip.MustParseAddrPort("192.0.2.21:47831"),
			ObservedAt: observed, ExpiresAt: guessExpiry,
		},
		{
			DeviceID: deviceID, SourceKind: store.PeerEndpointRawDiscovery,
			Endpoint:   netip.MustParseAddrPort("192.0.2.22:47831"),
			ObservedAt: observed,
			ExpiresAt:  daemonEndpointRouteTimestamp(now.Add(time.Minute)),
		},
		{
			DeviceID: deviceID, SourceKind: store.PeerEndpointAuthenticatedGuess,
			Endpoint:   netip.MustParseAddrPort("192.0.2.23:47831"),
			ObservedAt: observed, ExpiresAt: guessExpiry,
		},
		{
			DeviceID: deviceID, SourceKind: store.PeerEndpointManual,
			Endpoint:   netip.MustParseAddrPort("192.0.2.24:47831"),
			ObservedAt: observed,
		},
	}
}

func daemonEndpointRouteTimestamp(value time.Time) domain.Timestamp {
	return domain.Timestamp(value.UTC().Format(time.RFC3339Nano))
}

func daemonEndpointRouteTestDeviceID(fill byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(fill), 64))
}
