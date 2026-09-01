package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestListManualEndpointsReturnsDeterministicSourceIsolatedCopies(
	t *testing.T,
) {
	fixture := newPeerEndpointFixture(t, 2)
	state := fixture.store.LocalState()
	now := peerEndpointTimestamp(peerEndpointTestNow)

	lowID, highID := fixture.members[0].ID, fixture.members[1].ID
	if lowID > highID {
		lowID, highID = highID, lowID
	}
	lowTwo := netip.MustParseAddrPort("192.0.2.2:47831")
	lowTen := netip.MustParseAddrPort("192.0.2.10:47831")
	highIPv6 := netip.MustParseAddrPort("[2001:db8::1]:47831")
	for _, value := range []struct {
		deviceID domain.DeviceID
		endpoint netip.AddrPort
	}{
		{highID, highIPv6},
		{lowID, lowTen},
		{lowID, lowTwo},
	} {
		if err := state.UpsertManualEndpoint(
			context.Background(),
			value.deviceID,
			value.endpoint,
			now,
		); err != nil {
			t.Fatalf(
				"UpsertManualEndpoint(%s, %s): %v",
				value.deviceID,
				value.endpoint,
				err,
			)
		}
	}
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		lowID,
		lowTwo,
		now,
	); err != nil {
		t.Fatalf("UpsertAuthenticatedEndpoint(): %v", err)
	}

	want := []PeerEndpointRecord{
		{
			DeviceID:   lowID,
			SourceKind: PeerEndpointManual,
			Endpoint:   lowTwo,
			ObservedAt: now,
		},
		{
			DeviceID:   lowID,
			SourceKind: PeerEndpointManual,
			Endpoint:   lowTen,
			ObservedAt: now,
		},
		{
			DeviceID:   highID,
			SourceKind: PeerEndpointManual,
			Endpoint:   highIPv6,
			ObservedAt: now,
		},
	}
	got, err := state.ListManualEndpoints(context.Background())
	if err != nil {
		t.Fatalf("ListManualEndpoints(): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListManualEndpoints() = %#v, want %#v", got, want)
	}

	got[0] = PeerEndpointRecord{}
	again, err := state.ListManualEndpoints(context.Background())
	if err != nil {
		t.Fatalf("ListManualEndpoints(second): %v", err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("second list = %#v, want independent %#v", again, want)
	}
}

func TestRemoveManualEndpointIsExactSourceIsolatedAndIdempotent(
	t *testing.T,
) {
	fixture := newPeerEndpointFixture(t, 2)
	state := fixture.store.LocalState()
	now := peerEndpointTimestamp(peerEndpointTestNow)
	firstID := fixture.members[0].ID
	secondID := fixture.members[1].ID
	target := netip.MustParseAddrPort("198.51.100.7:47831")
	other := netip.MustParseAddrPort("198.51.100.8:47831")
	missing := netip.MustParseAddrPort("198.51.100.9:47831")

	for _, value := range []struct {
		deviceID domain.DeviceID
		endpoint netip.AddrPort
	}{
		{firstID, target},
		{firstID, other},
		{secondID, target},
	} {
		if err := state.UpsertManualEndpoint(
			context.Background(),
			value.deviceID,
			value.endpoint,
			now,
		); err != nil {
			t.Fatalf("UpsertManualEndpoint(): %v", err)
		}
	}
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		firstID,
		target,
		now,
	); err != nil {
		t.Fatalf("UpsertAuthenticatedEndpoint(): %v", err)
	}

	removed, err := state.RemoveManualEndpoint(
		context.Background(),
		firstID,
		missing,
	)
	if err != nil || removed {
		t.Fatalf("remove miss = (%t, %v), want (false, nil)", removed, err)
	}
	removed, err = state.RemoveManualEndpoint(
		context.Background(),
		firstID,
		target,
	)
	if err != nil || !removed {
		t.Fatalf("remove target = (%t, %v), want (true, nil)", removed, err)
	}
	removed, err = state.RemoveManualEndpoint(
		context.Background(),
		firstID,
		target,
	)
	if err != nil || removed {
		t.Fatalf("repeat remove = (%t, %v), want (false, nil)", removed, err)
	}

	firstRows := peerEndpointRows(t, fixture.store, firstID)
	if peerEndpointHas(firstRows, PeerEndpointManual, target) {
		t.Fatal("removed manual endpoint remains")
	}
	if !peerEndpointHas(firstRows, PeerEndpointManual, other) {
		t.Fatal("different manual endpoint was removed")
	}
	if !peerEndpointHas(firstRows, PeerEndpointAuthenticatedGuess, target) {
		t.Fatal("same-address authenticated source was removed")
	}
	secondRows := peerEndpointRows(t, fixture.store, secondID)
	if !peerEndpointHas(secondRows, PeerEndpointManual, target) {
		t.Fatal("same-address endpoint for another device was removed")
	}
}

func TestManualEndpointManagementRejectsInvalidArgumentsAndContexts(
	t *testing.T,
) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	deviceID := fixture.members[0].ID
	valid := netip.MustParseAddrPort("192.0.2.1:47831")

	if _, err := state.ListManualEndpoints(nil); !errors.Is(
		err,
		ErrInvalidLocalState,
	) {
		t.Fatalf("ListManualEndpoints(nil) error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := state.ListManualEndpoints(cancelled); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("ListManualEndpoints(cancelled) error = %v", err)
	}

	for _, test := range []struct {
		name     string
		deviceID domain.DeviceID
		endpoint netip.AddrPort
	}{
		{
			name:     "invalid device",
			deviceID: "cc1invalid",
			endpoint: valid,
		},
		{
			name:     "missing endpoint",
			deviceID: deviceID,
		},
		{
			name:     "unsafe endpoint",
			deviceID: deviceID,
			endpoint: netip.MustParseAddrPort("127.0.0.1:47831"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := state.RemoveManualEndpoint(
				context.Background(),
				test.deviceID,
				test.endpoint,
			); !errors.Is(err, ErrInvalidPeerEndpoint) {
				t.Fatalf("error = %v, want ErrInvalidPeerEndpoint", err)
			}
		})
	}

	if _, err := state.RemoveManualEndpoint(
		nil,
		deviceID,
		valid,
	); !errors.Is(err, ErrInvalidLocalState) {
		t.Fatalf("RemoveManualEndpoint(nil) error = %v", err)
	}
	if _, err := state.RemoveManualEndpoint(
		cancelled,
		deviceID,
		valid,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("RemoveManualEndpoint(cancelled) error = %v", err)
	}
}

func TestManualEndpointManagementFailsClosedOnCorruption(t *testing.T) {
	t.Run("malformed row blocks list", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		seedMalformedManualEndpoint(
			t,
			fixture.store.LocalState(),
			fixture.members[0].ID,
		)
		if _, err := fixture.store.LocalState().ListManualEndpoints(
			context.Background(),
		); !errors.Is(err, ErrPeerEndpointIntegrity) {
			t.Fatalf("list error = %v, want ErrPeerEndpointIntegrity", err)
		}
	})

	t.Run("over-cap rows block list", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		state := fixture.store.LocalState()
		if err := state.withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				for index := 1; index <= ManualEndpointsPerMemberMax+1; index++ {
					if err := execute(
						conn,
						`INSERT INTO peer_endpoints(
						    device_id, source_kind, transport, host, port,
						    observed_at
						) VALUES (?1, 'manual', 'tcp', ?2, 47831, ?3);`,
						string(fixture.members[0].ID),
						fmt.Sprintf("192.0.2.%d", index),
						string(peerEndpointTimestamp(peerEndpointTestNow)),
					); err != nil {
						return err
					}
				}
				return nil
			},
		); err != nil {
			t.Fatalf("seed over-cap rows: %v", err)
		}
		if _, err := state.ListManualEndpoints(
			context.Background(),
		); !errors.Is(err, ErrPeerEndpointCapacity) {
			t.Fatalf("list error = %v, want ErrPeerEndpointCapacity", err)
		}
	})

	t.Run("malformed unrelated row blocks removal", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		state := fixture.store.LocalState()
		target := netip.MustParseAddrPort("203.0.113.1:47831")
		if err := state.UpsertManualEndpoint(
			context.Background(),
			fixture.members[0].ID,
			target,
			peerEndpointTimestamp(peerEndpointTestNow),
		); err != nil {
			t.Fatalf("UpsertManualEndpoint(): %v", err)
		}
		seedMalformedManualEndpoint(
			t,
			state,
			peerEndpointDeviceID(t, 99),
		)

		removed, err := state.RemoveManualEndpoint(
			context.Background(),
			fixture.members[0].ID,
			target,
		)
		if !errors.Is(err, ErrPeerEndpointIntegrity) || removed {
			t.Fatalf(
				"remove from corrupt table = (%t, %v), want integrity error",
				removed,
				err,
			)
		}
		rows := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
		if !peerEndpointHas(rows, PeerEndpointManual, target) {
			t.Fatal("failed-closed removal deleted the target")
		}
	})
}

func seedMalformedManualEndpoint(
	t *testing.T,
	state LocalState,
	deviceID domain.DeviceID,
) {
	t.Helper()
	if err := state.withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO peer_endpoints(
				    device_id, source_kind, transport, host, port, observed_at
				) VALUES (?1, 'manual', 'tcp', 'peer.example', 47831, ?2);`,
				string(deviceID),
				string(peerEndpointTimestamp(peerEndpointTestNow)),
			)
		},
	); err != nil {
		t.Fatalf("seed malformed manual endpoint: %v", err)
	}
}
