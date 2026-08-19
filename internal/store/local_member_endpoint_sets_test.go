package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"zombiezen.com/go/sqlite"
)

func TestListMemberSignedEndpointSetsReturnsSortedExactCurrentSets(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 3)
	state := fixture.store.LocalState()
	now := peerEndpointTimestamp(peerEndpointTestNow)
	expected := make(map[domain.DeviceID][]byte, len(fixture.members))

	for _, memberIndex := range []int{2, 0, 1} {
		endpoint := netip.MustParseAddrPort(fmt.Sprintf(
			"192.0.2.%d:47831",
			memberIndex+1,
		))
		encoded := peerEndpointSignedSet(
			t,
			fixture,
			memberIndex,
			uint64(memberIndex+1),
			peerEndpointTestNow,
			peerEndpointTestNow.Add(160*time.Second),
			[]netip.AddrPort{endpoint},
		)
		if _, err := state.ReplaceMemberSignedEndpointSet(
			context.Background(),
			encoded,
			now,
		); err != nil {
			t.Fatalf("store member %d endpoint set: %v", memberIndex, err)
		}
		expected[fixture.members[memberIndex].ID] = bytes.Clone(encoded)
	}

	replacement := peerEndpointSignedSet(
		t,
		fixture,
		1,
		100,
		peerEndpointTestNow.Add(time.Second),
		peerEndpointTestNow.Add(161*time.Second),
		[]netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.8:443"),
		},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		replacement,
		peerEndpointTimestamp(peerEndpointTestNow.Add(time.Second)),
	); err != nil {
		t.Fatalf("replace member endpoint set: %v", err)
	}
	expected[fixture.members[1].ID] = bytes.Clone(replacement)

	if _, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		now,
	); err != nil {
		t.Fatalf("store own sequence: %v", err)
	}
	if err := state.UpsertRawDiscoveryEndpoint(
		context.Background(),
		fixture.members[0].ID,
		netip.MustParseAddrPort("192.0.2.20:47831"),
		now,
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(time.Minute)),
		),
	); err != nil {
		t.Fatalf("store raw discovery endpoint: %v", err)
	}
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		fixture.members[0].ID,
		netip.MustParseAddrPort("192.0.2.21:47831"),
		now,
	); err != nil {
		t.Fatalf("store authenticated endpoint: %v", err)
	}
	if err := state.UpsertManualEndpoint(
		context.Background(),
		fixture.members[0].ID,
		netip.MustParseAddrPort("192.0.2.22:47831"),
		now,
	); err != nil {
		t.Fatalf("store manual endpoint: %v", err)
	}

	got, err := state.ListMemberSignedEndpointSets(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow.Add(time.Second)),
	)
	if err != nil {
		t.Fatalf("ListMemberSignedEndpointSets(): %v", err)
	}
	if len(got) != len(expected) {
		t.Fatalf("endpoint sets = %d, want %d", len(got), len(expected))
	}
	for index, endpointSet := range got {
		if index > 0 && got[index-1].DeviceID >= endpointSet.DeviceID {
			t.Fatalf("endpoint sets are not canonically sorted: %#v", got)
		}
		want, exists := expected[endpointSet.DeviceID]
		if !exists {
			t.Fatalf("unexpected member endpoint set: %s", endpointSet.DeviceID)
		}
		if !bytes.Equal(endpointSet.EndpointSetJSON, want) {
			t.Fatalf(
				"endpoint set for %s changed bytes:\n got %s\nwant %s",
				endpointSet.DeviceID,
				endpointSet.EndpointSetJSON,
				want,
			)
		}
	}
}

func TestListMemberSignedEndpointSetsExpiresRelayObjectButNotGuess(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	encoded := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.4:47831"),
		},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		encoded,
		peerEndpointTimestamp(peerEndpointTestNow),
	); err != nil {
		t.Fatalf("store endpoint set: %v", err)
	}

	got, err := state.ListMemberSignedEndpointSets(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow.Add(161*time.Second)),
	)
	if err != nil {
		t.Fatalf("ListMemberSignedEndpointSets(): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expired endpoint sets = %#v, want none", got)
	}

	rows := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	if len(rows) != 1 ||
		rows[0].record.SourceKind != PeerEndpointMemberSigned ||
		rows[0].record.EndpointSequence != 0 ||
		len(rows[0].record.EndpointSetJSON) != 0 {
		t.Fatalf("expired relay object was not stripped: %#v", rows)
	}
	if rows[0].record.ExpiresAt != peerEndpointTimestamp(
		peerEndpointTestNow.Add(peerEndpointGuessTTL),
	) {
		t.Fatalf(
			"retained guess expiry = %q",
			rows[0].record.ExpiresAt,
		)
	}
}

func TestListMemberSignedEndpointSetsExcludesInactiveMembers(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 3)
	state := fixture.store.LocalState()
	now := peerEndpointTimestamp(peerEndpointTestNow)
	var activeSet []byte
	for memberIndex := range fixture.members {
		encoded := peerEndpointSignedSet(
			t,
			fixture,
			memberIndex,
			1,
			peerEndpointTestNow,
			peerEndpointTestNow.Add(160*time.Second),
			[]netip.AddrPort{
				netip.MustParseAddrPort(fmt.Sprintf(
					"192.0.2.%d:47831",
					memberIndex+1,
				)),
			},
		)
		if _, err := state.ReplaceMemberSignedEndpointSet(
			context.Background(),
			encoded,
			now,
		); err != nil {
			t.Fatalf("store member %d endpoint set: %v", memberIndex, err)
		}
		if memberIndex == 0 {
			activeSet = bytes.Clone(encoded)
		}
	}
	if err := state.withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			if err := execute(
				conn,
				`UPDATE devices
				    SET status = ?2, entity_version = entity_version + 1
				  WHERE device_id = ?1;`,
				string(fixture.members[1].ID),
				string(device.StatusRevoked),
			); err != nil {
				return err
			}
			return execute(
				conn,
				`UPDATE devices
				    SET status = ?2, entity_version = entity_version + 1
				  WHERE device_id = ?1;`,
				string(fixture.members[2].ID),
				string(device.StatusRequiresReadmission),
			)
		},
	); err != nil {
		t.Fatalf("mark members inactive: %v", err)
	}

	got, err := state.ListMemberSignedEndpointSets(
		context.Background(),
		now,
	)
	if err != nil {
		t.Fatalf("ListMemberSignedEndpointSets(): %v", err)
	}
	if len(got) != 1 ||
		got[0].DeviceID != fixture.members[0].ID ||
		!bytes.Equal(got[0].EndpointSetJSON, activeSet) {
		t.Fatalf("active endpoint sets = %#v", got)
	}
}

func TestListMemberSignedEndpointSetsFailsClosedOnCorruption(t *testing.T) {
	t.Run("incomplete signed group", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		state := fixture.store.LocalState()
		encoded := peerEndpointSignedSet(
			t,
			fixture,
			0,
			1,
			peerEndpointTestNow,
			peerEndpointTestNow.Add(160*time.Second),
			[]netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.4:47831"),
				netip.MustParseAddrPort("192.0.2.5:47831"),
			},
		)
		if _, err := state.ReplaceMemberSignedEndpointSet(
			context.Background(),
			encoded,
			peerEndpointTimestamp(peerEndpointTestNow),
		); err != nil {
			t.Fatalf("store endpoint set: %v", err)
		}
		if err := state.withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`DELETE FROM peer_endpoints
					  WHERE device_id = ?1
					    AND source_kind = 'member_signed'
					    AND host = '192.0.2.5';`,
					string(fixture.members[0].ID),
				)
			},
		); err != nil {
			t.Fatalf("corrupt endpoint group: %v", err)
		}

		if _, err := state.ListMemberSignedEndpointSets(
			context.Background(),
			peerEndpointTimestamp(peerEndpointTestNow),
		); !errors.Is(err, ErrPeerEndpointIntegrity) {
			t.Fatalf("corrupt group error = %v, want integrity failure", err)
		}
	})

	t.Run("invalid member signature", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 2)
		state := fixture.store.LocalState()
		endpoint := netip.MustParseAddrPort("192.0.2.4:47831")
		valid := peerEndpointSignedSet(
			t,
			fixture,
			0,
			1,
			peerEndpointTestNow,
			peerEndpointTestNow.Add(160*time.Second),
			[]netip.AddrPort{endpoint},
		)
		if _, err := state.ReplaceMemberSignedEndpointSet(
			context.Background(),
			valid,
			peerEndpointTimestamp(peerEndpointTestNow),
		); err != nil {
			t.Fatalf("store endpoint set: %v", err)
		}
		wrongSigner := peerEndpointSignWire(
			t,
			peerEndpointSetWireForFixture(
				fixture,
				0,
				1,
				peerEndpointTestNow,
				peerEndpointTestNow.Add(160*time.Second),
				[]peerEndpointWire{{
					IP:   endpoint.Addr().String(),
					Port: endpoint.Port(),
				}},
			),
			fixture.privateKeys[1],
		)
		if err := state.withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`UPDATE peer_endpoints
					    SET endpoint_set_json = ?2
					  WHERE device_id = ?1
					    AND source_kind = 'member_signed';`,
					string(fixture.members[0].ID),
					string(wrongSigner),
				)
			},
		); err != nil {
			t.Fatalf("corrupt member signature: %v", err)
		}

		if _, err := state.ListMemberSignedEndpointSets(
			context.Background(),
			peerEndpointTimestamp(peerEndpointTestNow),
		); !errors.Is(err, ErrPeerEndpointIntegrity) {
			t.Fatalf("signature error = %v, want integrity failure", err)
		}
	})

	t.Run("endpoint cap", func(t *testing.T) {
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
			t.Fatalf("seed over-cap endpoints: %v", err)
		}

		if _, err := state.ListMemberSignedEndpointSets(
			context.Background(),
			peerEndpointTimestamp(peerEndpointTestNow),
		); !errors.Is(err, ErrPeerEndpointCapacity) {
			t.Fatalf("over-cap error = %v, want capacity failure", err)
		}
	})
}

func TestListMemberSignedEndpointSetsReturnsDefensiveCopies(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	encoded := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.4:47831"),
		},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		encoded,
		peerEndpointTimestamp(peerEndpointTestNow),
	); err != nil {
		t.Fatalf("store endpoint set: %v", err)
	}

	first, err := state.ListMemberSignedEndpointSets(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow),
	)
	if err != nil {
		t.Fatalf("first list: %v", err)
	}
	if len(first) != 1 || len(first[0].EndpointSetJSON) == 0 {
		t.Fatalf("first list = %#v", first)
	}
	first[0].EndpointSetJSON[0] ^= 0xff
	first[0].EndpointSetJSON = append(first[0].EndpointSetJSON, 'x')

	second, err := state.ListMemberSignedEndpointSets(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow),
	)
	if err != nil {
		t.Fatalf("second list: %v", err)
	}
	if len(second) != 1 ||
		!bytes.Equal(second[0].EndpointSetJSON, encoded) {
		t.Fatalf("second list aliases caller-owned bytes: %#v", second)
	}
}

func TestListMemberSignedEndpointSetsRejectsInvalidNow(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	if _, err := fixture.store.LocalState().ListMemberSignedEndpointSets(
		context.Background(),
		domain.Timestamp("not-a-timestamp"),
	); !errors.Is(err, ErrInvalidPeerEndpoint) {
		t.Fatalf("invalid now error = %v, want invalid endpoint", err)
	}
}
