package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"zombiezen.com/go/sqlite"
)

var peerEndpointTestNow = time.Date(
	2026,
	time.August,
	18,
	12,
	0,
	0,
	0,
	time.UTC,
)

type peerEndpointFixture struct {
	store       *Store
	members     []device.Device
	privateKeys []ed25519.PrivateKey
}

func TestPeerEndpointSourceKindsAreClosed(t *testing.T) {
	t.Parallel()

	want := []PeerEndpointSourceKind{
		PeerEndpointOwnSigned,
		PeerEndpointMemberSigned,
		PeerEndpointRawDiscovery,
		PeerEndpointAuthenticatedGuess,
		PeerEndpointManual,
	}
	got := PeerEndpointSourceKinds()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PeerEndpointSourceKinds() = %v, want %v", got, want)
	}
	got[0] = "changed"
	if next := PeerEndpointSourceKinds(); !reflect.DeepEqual(next, want) {
		t.Fatalf("PeerEndpointSourceKinds() returned aliased storage: %v", next)
	}
	for _, kind := range want {
		if !kind.Valid() {
			t.Errorf("%q.Valid() = false", kind)
		}
	}
	if PeerEndpointSourceKind("").Valid() ||
		PeerEndpointSourceKind("network_guess").Valid() {
		t.Fatal("unknown endpoint source is valid")
	}
}

func TestAllocateOwnEndpointSequenceIsDurableAtomicAndLocalOnly(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	beforeDigest, beforeAccumulator := peerEndpointCommitments(t, fixture.store)
	now := peerEndpointTimestamp(peerEndpointTestNow)

	first, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		now,
	)
	if err != nil {
		t.Fatalf("AllocateOwnEndpointSequence(first): %v", err)
	}
	if want := uint64(peerEndpointTestNow.UnixMilli()); first != want {
		t.Fatalf("first sequence = %d, want %d", first, want)
	}
	second, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		now,
	)
	if err != nil {
		t.Fatalf("AllocateOwnEndpointSequence(second): %v", err)
	}
	if second != first+1 {
		t.Fatalf("second sequence = %d, want %d", second, first+1)
	}
	earlier := peerEndpointTimestamp(peerEndpointTestNow.Add(-time.Hour))
	third, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		earlier,
	)
	if err != nil {
		t.Fatalf("AllocateOwnEndpointSequence(earlier clock): %v", err)
	}
	if third != second+1 {
		t.Fatalf("third sequence = %d, want %d", third, second+1)
	}

	rows := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	if len(rows) != 1 {
		t.Fatalf("own rows = %d, want 1", len(rows))
	}
	wantRecord := PeerEndpointRecord{
		DeviceID:         fixture.members[0].ID,
		SourceKind:       PeerEndpointOwnSigned,
		Endpoint:         ownEndpointSequence(),
		EndpointSequence: third,
		ObservedAt:       earlier,
	}
	if !reflect.DeepEqual(rows[0].record, wantRecord) {
		t.Fatalf("own row = %#v, want %#v", rows[0].record, wantRecord)
	}

	afterDigest, afterAccumulator := peerEndpointCommitments(t, fixture.store)
	if beforeDigest != afterDigest || beforeAccumulator != afterAccumulator {
		t.Fatal("own endpoint sequence changed projection commitments")
	}

	path := fixture.store.Path()
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened := openTestStore(t, path, nil)
	fourth, err := reopened.LocalState().AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		earlier,
	)
	if err != nil {
		t.Fatalf("AllocateOwnEndpointSequence(reopened): %v", err)
	}
	if fourth != third+1 {
		t.Fatalf("reopened sequence = %d, want %d", fourth, third+1)
	}
}

func TestAllocateOwnEndpointSequenceSerializesConcurrentCallers(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	now := peerEndpointTimestamp(peerEndpointTestNow)

	const callers = 24
	results := make([]uint64, callers)
	errs := make([]error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range callers {
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = state.AllocateOwnEndpointSequence(
				context.Background(),
				fixture.members[0].ID,
				now,
			)
		}(index)
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", index, err)
		}
	}
	sort.Slice(results, func(left, right int) bool {
		return results[left] < results[right]
	})
	first := uint64(peerEndpointTestNow.UnixMilli())
	for index, sequence := range results {
		if want := first + uint64(index); sequence != want {
			t.Fatalf("sequence[%d] = %d, want %d", index, sequence, want)
		}
	}
}

func TestAllocateOwnEndpointSequenceRejectsInvalidState(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	tests := []struct {
		name     string
		deviceID domain.DeviceID
		now      domain.Timestamp
	}{
		{
			name:     "invalid device",
			deviceID: "cc1bad",
			now:      peerEndpointTimestamp(peerEndpointTestNow),
		},
		{
			name:     "unknown device",
			deviceID: peerEndpointDeviceID(t, 99),
			now:      peerEndpointTimestamp(peerEndpointTestNow),
		},
		{
			name:     "invalid time",
			deviceID: fixture.members[0].ID,
			now:      "2026-08-18 12:00:00Z",
		},
		{
			name:     "before Unix epoch",
			deviceID: fixture.members[0].ID,
			now:      "1969-12-31T23:59:59Z",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := state.AllocateOwnEndpointSequence(
				context.Background(),
				test.deviceID,
				test.now,
			); !errors.Is(err, ErrInvalidPeerEndpoint) {
				t.Fatalf("error = %v, want ErrInvalidPeerEndpoint", err)
			}
		})
	}

	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`INSERT INTO peer_endpoints(
			    device_id, source_kind, endpoint_sequence, transport, host,
			    port, observed_at
			) VALUES (?1, 'own_signed', ?2, 'tcp', ?3, ?4, ?5);`,
			string(fixture.members[0].ID),
			uint64(domain.MaxSafeInteger),
			ownEndpointSequenceHost,
			uint64(ownEndpointSequencePort),
			string(peerEndpointTimestamp(peerEndpointTestNow)),
		)
	}); err != nil {
		t.Fatalf("seed exhausted sequence: %v", err)
	}
	if _, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		fixture.members[0].ID,
		peerEndpointTimestamp(peerEndpointTestNow),
	); !errors.Is(err, ErrPeerEndpointSequenceRollback) {
		t.Fatalf("exhausted sequence error = %v, want rollback", err)
	}
}

func TestReplaceMemberSignedEndpointSetPreservesExactObjectAndSequence(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	beforeDigest, beforeAccumulator := peerEndpointCommitments(t, fixture.store)
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.4:47831"),
		netip.MustParseAddrPort("[2001:db8::1]:47831"),
	}
	encoded := peerEndpointSignedSet(
		t,
		fixture,
		0,
		100,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		endpoints,
	)
	observedAt := peerEndpointTimestamp(peerEndpointTestNow)

	update, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		encoded,
		observedAt,
	)
	if err != nil {
		t.Fatalf("ReplaceMemberSignedEndpointSet(first): %v", err)
	}
	if update != MemberEndpointSetStored {
		t.Fatalf("first update = %d, want stored", update)
	}
	rows := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	if len(rows) != len(endpoints) {
		t.Fatalf("signed rows = %d, want %d", len(rows), len(endpoints))
	}
	wantExpiry := peerEndpointTimestamp(
		peerEndpointTestNow.Add(peerEndpointGuessTTL),
	)
	for index, row := range rows {
		record := row.record
		if record.SourceKind != PeerEndpointMemberSigned ||
			record.Endpoint != endpoints[index] ||
			record.EndpointSequence != 100 ||
			!bytes.Equal(record.EndpointSetJSON, encoded) ||
			record.ObservedAt != observedAt ||
			record.ExpiresAt != wantExpiry {
			t.Fatalf("signed row[%d] = %#v", index, record)
		}
	}

	laterObserved := peerEndpointTimestamp(peerEndpointTestNow.Add(time.Second))
	update, err = state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		encoded,
		laterObserved,
	)
	if err != nil {
		t.Fatalf("ReplaceMemberSignedEndpointSet(idempotent): %v", err)
	}
	if update != MemberEndpointSetIdempotent {
		t.Fatalf("idempotent update = %d, want idempotent", update)
	}
	rows = peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	for _, row := range rows {
		if !bytes.Equal(row.record.EndpointSetJSON, encoded) ||
			row.record.ObservedAt != laterObserved ||
			row.record.ExpiresAt != peerEndpointTimestamp(
				peerEndpointTestNow.Add(time.Second+peerEndpointGuessTTL),
			) {
			t.Fatalf("idempotent refresh changed exact set incorrectly: %#v", row.record)
		}
	}

	replacementEndpoints := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.8:443"),
	}
	replacement := peerEndpointSignedSet(
		t,
		fixture,
		0,
		101,
		peerEndpointTestNow.Add(2*time.Second),
		peerEndpointTestNow.Add(162*time.Second),
		replacementEndpoints,
	)
	update, err = state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		replacement,
		peerEndpointTimestamp(peerEndpointTestNow.Add(2*time.Second)),
	)
	if err != nil {
		t.Fatalf("ReplaceMemberSignedEndpointSet(replacement): %v", err)
	}
	if update != MemberEndpointSetReplaced {
		t.Fatalf("replacement update = %d, want replaced", update)
	}
	rows = peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	if len(rows) != 1 ||
		rows[0].record.Endpoint != replacementEndpoints[0] ||
		rows[0].record.EndpointSequence != 101 ||
		!bytes.Equal(rows[0].record.EndpointSetJSON, replacement) {
		t.Fatalf("replacement rows = %#v", rows)
	}

	afterDigest, afterAccumulator := peerEndpointCommitments(t, fixture.store)
	if beforeDigest != afterDigest || beforeAccumulator != afterAccumulator {
		t.Fatal("signed endpoint replacement changed projection commitments")
	}
}

func TestReplaceMemberSignedEndpointSetRejectsRollbackAndConflictAtomically(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	first := peerEndpointSignedSet(
		t,
		fixture,
		0,
		100,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.4:47831")},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		first,
		peerEndpointTimestamp(peerEndpointTestNow),
	); err != nil {
		t.Fatalf("store first set: %v", err)
	}
	before := peerEndpointRows(t, fixture.store, fixture.members[0].ID)

	conflict := peerEndpointSignedSet(
		t,
		fixture,
		0,
		100,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.5:47831")},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		conflict,
		peerEndpointTimestamp(peerEndpointTestNow),
	); !errors.Is(err, ErrPeerEndpointSequenceConflict) {
		t.Fatalf("conflict error = %v, want sequence conflict", err)
	}
	rollback := peerEndpointSignedSet(
		t,
		fixture,
		0,
		99,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.6:47831")},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		rollback,
		peerEndpointTimestamp(peerEndpointTestNow),
	); !errors.Is(err, ErrPeerEndpointSequenceRollback) {
		t.Fatalf("rollback error = %v, want sequence rollback", err)
	}
	after := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected replacement changed rows:\nbefore %#v\nafter  %#v", before, after)
	}
}

func TestExpiredMemberSetDropsHighWaterButRetainsBoundedGuesses(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	endpoint := netip.MustParseAddrPort("192.0.2.4:47831")
	first := peerEndpointSignedSet(
		t,
		fixture,
		0,
		100,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{endpoint},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		first,
		peerEndpointTimestamp(peerEndpointTestNow),
	); err != nil {
		t.Fatalf("store first set: %v", err)
	}

	afterSetExpiry := peerEndpointTestNow.Add(161 * time.Second)
	affected, err := state.ExpireStalePeerEndpoints(
		context.Background(),
		peerEndpointTimestamp(afterSetExpiry),
	)
	if err != nil {
		t.Fatalf("ExpireStalePeerEndpoints(set): %v", err)
	}
	if affected != 1 {
		t.Fatalf("affected after set expiry = %d, want 1", affected)
	}
	candidates, err := state.ListPeerEndpointCandidates(
		context.Background(),
		fixture.members[0].ID,
		peerEndpointTimestamp(afterSetExpiry),
	)
	if err != nil {
		t.Fatalf("ListPeerEndpointCandidates(stale guess): %v", err)
	}
	if len(candidates) != 1 ||
		candidates[0].Endpoint != endpoint ||
		candidates[0].EndpointSequence != 0 ||
		len(candidates[0].EndpointSetJSON) != 0 {
		t.Fatalf("stale candidates = %#v", candidates)
	}

	lower := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		afterSetExpiry,
		afterSetExpiry.Add(160*time.Second),
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.5:47831")},
	)
	update, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		lower,
		peerEndpointTimestamp(afterSetExpiry),
	)
	if err != nil {
		t.Fatalf("ReplaceMemberSignedEndpointSet(after expiry): %v", err)
	}
	if update != MemberEndpointSetStored {
		t.Fatalf("post-expiry update = %d, want stored", update)
	}

	affected, err = state.ExpireStalePeerEndpoints(
		context.Background(),
		peerEndpointTimestamp(
			afterSetExpiry.Add(peerEndpointGuessTTL+time.Second),
		),
	)
	if err != nil {
		t.Fatalf("ExpireStalePeerEndpoints(guess): %v", err)
	}
	if affected == 0 {
		t.Fatal("seven-day signed guess did not expire")
	}
}

func TestReplaceMemberSignedEndpointSetRejectsMalformedUnsafeAndWrongLineage(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	validWire := peerEndpointSetWireForFixture(
		fixture,
		0,
		100,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]peerEndpointWire{{IP: "192.0.2.4", Port: 47831}},
	)
	valid := peerEndpointSignWire(t, validWire, fixture.privateKeys[0])

	tests := []struct {
		name  string
		input func() []byte
	}{
		{
			name: "noncanonical whitespace",
			input: func() []byte {
				return append(bytes.Clone(valid), '\n')
			},
		},
		{
			name: "unknown member",
			input: func() []byte {
				return peerEndpointSignMembers(
					t,
					validWire,
					fixture.privateKeys[0],
					map[string]json.RawMessage{"unknown": json.RawMessage(`true`)},
				)
			},
		},
		{
			name: "wrong session",
			input: func() []byte {
				wire := validWire
				wire.SessionID = "01890f47-3e72-7000-8000-000000000099"
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "bad signature",
			input: func() []byte {
				wire := validWire
				wire.Signature = codec.EncodeBase64URL(bytes.Repeat([]byte{1}, 64))
				return peerEndpointCanonicalJSON(t, wire)
			},
		},
		{
			name: "hostname",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{
					{IP: "peer.example", Port: 47831},
				}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "loopback",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{{IP: "127.0.0.1", Port: 47831}}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "unspecified",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{{IP: "::", Port: 47831}}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "multicast",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{{IP: "ff02::1", Port: 47831}}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "mapped",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{
					{IP: "::ffff:192.0.2.1", Port: 47831},
				}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "link local",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{{IP: "fe80::1", Port: 47831}}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "zone",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{
					{IP: "2001:db8::1%eth0", Port: 47831},
				}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "noncanonical address",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{
					{IP: "2001:DB8::1", Port: 47831},
				}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "descending endpoints",
			input: func() []byte {
				wire := validWire
				wire.Endpoints = []peerEndpointWire{
					{IP: "192.0.2.5", Port: 47831},
					{IP: "192.0.2.4", Port: 47831},
				}
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "expired",
			input: func() []byte {
				wire := validWire
				wire.ExpiresAt = peerEndpointWholeSecond(
					peerEndpointTestNow,
				)
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "TTL over committed bound",
			input: func() []byte {
				wire := validWire
				wire.ExpiresAt = peerEndpointWholeSecond(
					peerEndpointTestNow.Add(161 * time.Second),
				)
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
		{
			name: "future issuance",
			input: func() []byte {
				wire := validWire
				wire.IssuedAt = peerEndpointWholeSecond(
					peerEndpointTestNow.Add(peerEndpointClockSkew + time.Second),
				)
				wire.ExpiresAt = peerEndpointWholeSecond(
					peerEndpointTestNow.Add(peerEndpointClockSkew + 2*time.Second),
				)
				return peerEndpointSignWire(t, wire, fixture.privateKeys[0])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := state.ReplaceMemberSignedEndpointSet(
				context.Background(),
				test.input(),
				peerEndpointTimestamp(peerEndpointTestNow),
			); !errors.Is(err, ErrInvalidPeerEndpointSet) &&
				!errors.Is(err, ErrInvalidPeerEndpoint) {
				t.Fatalf("error = %v, want invalid endpoint/set", err)
			}
			if rows := peerEndpointRows(
				t,
				fixture.store,
				fixture.members[0].ID,
			); len(rows) != 0 {
				t.Fatalf("rejected set persisted %d rows", len(rows))
			}
		})
	}
}

func TestPeerEndpointCandidateSourceRulesOrderingExpiryAndPurge(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	memberID := fixture.members[0].ID
	now := peerEndpointTimestamp(peerEndpointTestNow)
	signedEndpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	signed := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{signedEndpoint},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		signed,
		now,
	); err != nil {
		t.Fatalf("signed set: %v", err)
	}
	if err := state.UpsertRawDiscoveryEndpoint(
		context.Background(),
		memberID,
		netip.MustParseAddrPort("[fe80::1%en0]:47831"),
		now,
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(60*time.Second)),
		),
	); err != nil {
		t.Fatalf("raw endpoint: %v", err)
	}
	if err := state.UpsertRawDiscoveryEndpoint(
		context.Background(),
		memberID,
		signedEndpoint,
		now,
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(60*time.Second)),
		),
	); err != nil {
		t.Fatalf("duplicate raw endpoint: %v", err)
	}
	authEndpoint := netip.MustParseAddrPort("198.51.100.2:443")
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		memberID,
		authEndpoint,
		now,
	); err != nil {
		t.Fatalf("authenticated endpoint: %v", err)
	}
	manualEndpoint := netip.MustParseAddrPort("203.0.113.8:80")
	if err := state.UpsertManualEndpoint(
		context.Background(),
		memberID,
		manualEndpoint,
		now,
	); err != nil {
		t.Fatalf("manual endpoint: %v", err)
	}

	candidates, err := state.ListPeerEndpointCandidates(
		context.Background(),
		memberID,
		now,
	)
	if err != nil {
		t.Fatalf("ListPeerEndpointCandidates(): %v", err)
	}
	want := []struct {
		source   PeerEndpointSourceKind
		endpoint netip.AddrPort
	}{
		{PeerEndpointMemberSigned, signedEndpoint},
		{
			PeerEndpointRawDiscovery,
			netip.MustParseAddrPort("[fe80::1%en0]:47831"),
		},
		{PeerEndpointAuthenticatedGuess, authEndpoint},
		{PeerEndpointManual, manualEndpoint},
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidates = %#v, want %d", candidates, len(want))
	}
	for index, expected := range want {
		if candidates[index].SourceKind != expected.source ||
			candidates[index].Endpoint != expected.endpoint {
			t.Fatalf(
				"candidate[%d] = (%s, %s), want (%s, %s)",
				index,
				candidates[index].SourceKind,
				candidates[index].Endpoint,
				expected.source,
				expected.endpoint,
			)
		}
	}
	candidates[0].EndpointSetJSON[0] = '['
	again, err := state.ListPeerEndpointCandidates(
		context.Background(),
		memberID,
		now,
	)
	if err != nil || again[0].EndpointSetJSON[0] != '{' {
		t.Fatalf("candidate JSON was aliased: %#v, %v", again, err)
	}

	affected, err := state.ExpireStalePeerEndpoints(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow.Add(61*time.Second)),
	)
	if err != nil {
		t.Fatalf("ExpireStalePeerEndpoints(raw): %v", err)
	}
	if affected != 2 {
		t.Fatalf("raw expiry affected = %d, want 2", affected)
	}
	afterRaw, err := state.ListPeerEndpointCandidates(
		context.Background(),
		memberID,
		peerEndpointTimestamp(peerEndpointTestNow.Add(61*time.Second)),
	)
	if err != nil {
		t.Fatalf("list after raw expiry: %v", err)
	}
	if len(afterRaw) != 3 {
		t.Fatalf("after raw expiry = %#v", afterRaw)
	}

	afterGuessTTL := peerEndpointTimestamp(
		peerEndpointTestNow.Add(peerEndpointGuessTTL + time.Second),
	)
	if _, err := state.ExpireStalePeerEndpoints(
		context.Background(),
		afterGuessTTL,
	); err != nil {
		t.Fatalf("ExpireStalePeerEndpoints(guesses): %v", err)
	}
	remaining, err := state.ListPeerEndpointCandidates(
		context.Background(),
		memberID,
		afterGuessTTL,
	)
	if err != nil {
		t.Fatalf("list after guess expiry: %v", err)
	}
	if len(remaining) != 1 ||
		remaining[0].SourceKind != PeerEndpointManual {
		t.Fatalf("remaining candidates = %#v, want manual only", remaining)
	}

	if _, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		memberID,
		afterGuessTTL,
	); err != nil {
		t.Fatalf("allocate own sequence: %v", err)
	}
	if err := state.PurgePeerEndpoints(
		context.Background(),
		memberID,
	); err != nil {
		t.Fatalf("PurgePeerEndpoints(): %v", err)
	}
	rows := peerEndpointRows(t, fixture.store, memberID)
	if len(rows) != 1 ||
		rows[0].record.SourceKind != PeerEndpointOwnSigned {
		t.Fatalf("rows after purge = %#v, want own counter only", rows)
	}
}

func TestPeerEndpointCandidatesRejectUnsafeAddressesZonesAndTimes(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	memberID := fixture.members[0].ID
	now := peerEndpointTimestamp(peerEndpointTestNow)
	expiry := domain.WholeSecondTimestamp(
		peerEndpointWholeSecond(peerEndpointTestNow.Add(time.Minute)),
	)
	unsafe := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:47831"),
		netip.MustParseAddrPort("0.0.0.0:47831"),
		netip.MustParseAddrPort("224.0.0.1:47831"),
		netip.MustParseAddrPort("[::1]:47831"),
		netip.MustParseAddrPort("[::]:47831"),
		netip.MustParseAddrPort("[ff02::1]:47831"),
		netip.MustParseAddrPort("[::ffff:192.0.2.1]:47831"),
		netip.MustParseAddrPort("[2001:db8::1%en0]:47831"),
		netip.MustParseAddrPort("[fe80::1]:47831"),
		netip.MustParseAddrPort("[fe80::1%bad zone]:47831"),
	}
	for _, endpoint := range unsafe {
		if err := state.UpsertRawDiscoveryEndpoint(
			context.Background(),
			memberID,
			endpoint,
			now,
			expiry,
		); !errors.Is(err, ErrInvalidPeerEndpoint) {
			t.Errorf("raw %s error = %v, want invalid endpoint", endpoint, err)
		}
		if err := state.UpsertManualEndpoint(
			context.Background(),
			memberID,
			endpoint,
			now,
		); !errors.Is(err, ErrInvalidPeerEndpoint) {
			t.Errorf("manual %s error = %v, want invalid endpoint", endpoint, err)
		}
	}

	valid := netip.MustParseAddrPort("192.0.2.1:47831")
	timeTests := []struct {
		name      string
		observed  domain.Timestamp
		expiresAt domain.WholeSecondTimestamp
	}{
		{
			name:      "invalid observed",
			observed:  "bad",
			expiresAt: expiry,
		},
		{
			name:     "missing expiry",
			observed: now,
		},
		{
			name:      "expired",
			observed:  now,
			expiresAt: domain.WholeSecondTimestamp(now),
		},
		{
			name:     "over sixty seconds",
			observed: now,
			expiresAt: domain.WholeSecondTimestamp(
				peerEndpointWholeSecond(
					peerEndpointTestNow.Add(61 * time.Second),
				),
			),
		},
		{
			name:     "fractional expiry",
			observed: now,
			expiresAt: domain.WholeSecondTimestamp(
				"2026-08-18T12:00:00.1Z",
			),
		},
	}
	for _, test := range timeTests {
		t.Run(test.name, func(t *testing.T) {
			if err := state.UpsertRawDiscoveryEndpoint(
				context.Background(),
				memberID,
				valid,
				test.observed,
				test.expiresAt,
			); !errors.Is(err, ErrInvalidPeerEndpoint) {
				t.Fatalf("error = %v, want invalid endpoint", err)
			}
		})
	}
	if rows := peerEndpointRows(t, fixture.store, memberID); len(rows) != 0 {
		t.Fatalf("invalid candidates persisted %d rows", len(rows))
	}
}

func TestManualEndpointCapsRefuseWithoutReplacement(t *testing.T) {
	t.Run("per member", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		state := fixture.store.LocalState()
		now := peerEndpointTimestamp(peerEndpointTestNow)
		for index := 1; index <= ManualEndpointsPerMemberMax; index++ {
			if err := state.UpsertManualEndpoint(
				context.Background(),
				fixture.members[0].ID,
				netip.MustParseAddrPort(
					fmt.Sprintf("192.0.2.%d:47831", index),
				),
				now,
			); err != nil {
				t.Fatalf("manual endpoint %d: %v", index, err)
			}
		}
		before := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
		if err := state.UpsertManualEndpoint(
			context.Background(),
			fixture.members[0].ID,
			netip.MustParseAddrPort("192.0.2.200:47831"),
			now,
		); !errors.Is(err, ErrPeerEndpointCapacity) {
			t.Fatalf("seventeenth endpoint error = %v, want capacity", err)
		}
		after := peerEndpointRows(t, fixture.store, fixture.members[0].ID)
		if !reflect.DeepEqual(after, before) {
			t.Fatal("capacity rejection replaced a manual endpoint")
		}
	})

	t.Run("per session", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		state := fixture.store.LocalState()
		now := peerEndpointTimestamp(peerEndpointTestNow)
		for deviceIndex := 1; deviceIndex <= 8; deviceIndex++ {
			deviceID := peerEndpointDeviceID(t, byte(100+deviceIndex))
			for endpointIndex := 1; endpointIndex <= 16; endpointIndex++ {
				endpoint := netip.MustParseAddrPort(fmt.Sprintf(
					"10.%d.0.%d:47831",
					deviceIndex,
					endpointIndex,
				))
				if err := state.UpsertManualEndpoint(
					context.Background(),
					deviceID,
					endpoint,
					now,
				); err != nil {
					t.Fatalf(
						"manual device %d endpoint %d: %v",
						deviceIndex,
						endpointIndex,
						err,
					)
				}
			}
		}
		if err := state.UpsertManualEndpoint(
			context.Background(),
			peerEndpointDeviceID(t, 109),
			netip.MustParseAddrPort("10.9.0.1:47831"),
			now,
		); !errors.Is(err, ErrPeerEndpointCapacity) {
			t.Fatalf("129th endpoint error = %v, want capacity", err)
		}
		if got := peerEndpointRowCount(t, fixture.store, "manual"); got != 128 {
			t.Fatalf("manual row count = %d, want 128", got)
		}
	})
}

func TestNonmanualEndpointCapsEvictOldestButProtectCurrentSignedSet(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	memberID := fixture.members[0].ID
	for index := 1; index <= PeerEndpointHintsPerMemberMax; index++ {
		if err := state.UpsertAuthenticatedEndpoint(
			context.Background(),
			memberID,
			netip.MustParseAddrPort(
				fmt.Sprintf("198.51.100.%d:47831", index),
			),
			peerEndpointTimestamp(
				peerEndpointTestNow.Add(time.Duration(index)*time.Second),
			),
		); err != nil {
			t.Fatalf("authenticated endpoint %d: %v", index, err)
		}
	}
	newest := netip.MustParseAddrPort("203.0.113.1:47831")
	if err := state.UpsertRawDiscoveryEndpoint(
		context.Background(),
		memberID,
		newest,
		peerEndpointTimestamp(peerEndpointTestNow.Add(time.Minute)),
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(2*time.Minute)),
		),
	); err != nil {
		t.Fatalf("raw endpoint at capacity: %v", err)
	}
	rows := peerEndpointRows(t, fixture.store, memberID)
	if len(rows) != PeerEndpointHintsPerMemberMax {
		t.Fatalf("nonmanual rows = %d, want %d", len(rows), PeerEndpointHintsPerMemberMax)
	}
	if peerEndpointHas(
		rows,
		PeerEndpointAuthenticatedGuess,
		netip.MustParseAddrPort("198.51.100.1:47831"),
	) {
		t.Fatal("oldest authenticated guess was not evicted")
	}
	if !peerEndpointHas(rows, PeerEndpointRawDiscovery, newest) {
		t.Fatal("new raw candidate was not retained")
	}

	signedEndpoints := make([]netip.AddrPort, PeerEndpointHintsPerMemberMax)
	for index := range signedEndpoints {
		signedEndpoints[index] = netip.MustParseAddrPort(fmt.Sprintf(
			"10.0.0.%d:47831",
			index+1,
		))
	}
	signed := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		peerEndpointTestNow.Add(3*time.Minute),
		peerEndpointTestNow.Add(3*time.Minute+160*time.Second),
		signedEndpoints,
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		signed,
		peerEndpointTimestamp(peerEndpointTestNow.Add(3*time.Minute)),
	); err != nil {
		t.Fatalf("replace with full signed set: %v", err)
	}
	rows = peerEndpointRows(t, fixture.store, memberID)
	if len(rows) != PeerEndpointHintsPerMemberMax {
		t.Fatalf("rows after signed set = %d, want %d", len(rows), PeerEndpointHintsPerMemberMax)
	}
	for _, row := range rows {
		if row.record.SourceKind != PeerEndpointMemberSigned {
			t.Fatalf("lower-authority row survived full signed set: %#v", row.record)
		}
	}

	before := peerEndpointRows(t, fixture.store, memberID)
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		memberID,
		netip.MustParseAddrPort("203.0.113.200:47831"),
		peerEndpointTimestamp(peerEndpointTestNow.Add(4*time.Minute)),
	); !errors.Is(err, ErrPeerEndpointCapacity) {
		t.Fatalf("guess beside full signed set error = %v, want capacity", err)
	}
	after := peerEndpointRows(t, fixture.store, memberID)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("capacity failure changed protected signed set")
	}
}

func TestListPeerEndpointCandidatesFailsClosedOnCorruptOrOverCapRows(t *testing.T) {
	t.Run("hostname", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		if err := fixture.store.LocalState().withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`INSERT INTO peer_endpoints(
					    device_id, source_kind, transport, host, port, observed_at
					) VALUES (?1, 'manual', 'tcp', 'peer.example', 47831, ?2);`,
					string(fixture.members[0].ID),
					string(peerEndpointTimestamp(peerEndpointTestNow)),
				)
			},
		); err != nil {
			t.Fatalf("seed hostname row: %v", err)
		}
		if _, err := fixture.store.LocalState().ListPeerEndpointCandidates(
			context.Background(),
			fixture.members[0].ID,
			peerEndpointTimestamp(peerEndpointTestNow),
		); !errors.Is(err, ErrPeerEndpointIntegrity) {
			t.Fatalf("hostname row error = %v, want integrity failure", err)
		}
	})

	t.Run("manual over cap", func(t *testing.T) {
		fixture := newPeerEndpointFixture(t, 1)
		if err := fixture.store.LocalState().withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				for index := 1; index <= ManualEndpointsPerMemberMax+1; index++ {
					if err := execute(
						conn,
						`INSERT INTO peer_endpoints(
						    device_id, source_kind, transport, host, port, observed_at
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
		if _, err := fixture.store.LocalState().ListPeerEndpointCandidates(
			context.Background(),
			fixture.members[0].ID,
			peerEndpointTimestamp(peerEndpointTestNow),
		); !errors.Is(err, ErrPeerEndpointCapacity) {
			t.Fatalf("over-cap list error = %v, want capacity", err)
		}
	})
}

func TestAllPeerEndpointWritesLeaveProjectionCommitmentsUnchanged(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	beforeDigest, beforeAccumulator := peerEndpointCommitments(t, fixture.store)
	now := peerEndpointTimestamp(peerEndpointTestNow)
	memberID := fixture.members[0].ID

	if _, err := state.AllocateOwnEndpointSequence(
		context.Background(),
		memberID,
		now,
	); err != nil {
		t.Fatalf("allocate sequence: %v", err)
	}
	signed := peerEndpointSignedSet(
		t,
		fixture,
		0,
		1,
		peerEndpointTestNow,
		peerEndpointTestNow.Add(160*time.Second),
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.4:47831")},
	)
	if _, err := state.ReplaceMemberSignedEndpointSet(
		context.Background(),
		signed,
		now,
	); err != nil {
		t.Fatalf("replace signed set: %v", err)
	}
	if err := state.UpsertRawDiscoveryEndpoint(
		context.Background(),
		memberID,
		netip.MustParseAddrPort("192.0.2.5:47831"),
		now,
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(time.Minute)),
		),
	); err != nil {
		t.Fatalf("raw endpoint: %v", err)
	}
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		memberID,
		netip.MustParseAddrPort("192.0.2.6:47831"),
		now,
	); err != nil {
		t.Fatalf("authenticated endpoint: %v", err)
	}
	if err := state.UpsertManualEndpoint(
		context.Background(),
		memberID,
		netip.MustParseAddrPort("192.0.2.7:47831"),
		now,
	); err != nil {
		t.Fatalf("manual endpoint: %v", err)
	}
	if _, err := state.ExpireStalePeerEndpoints(
		context.Background(),
		peerEndpointTimestamp(peerEndpointTestNow.Add(161*time.Second)),
	); err != nil {
		t.Fatalf("expire endpoints: %v", err)
	}
	if err := state.PurgePeerEndpoints(
		context.Background(),
		memberID,
	); err != nil {
		t.Fatalf("purge endpoints: %v", err)
	}

	afterDigest, afterAccumulator := peerEndpointCommitments(t, fixture.store)
	if beforeDigest != afterDigest {
		t.Fatalf("projection digest changed: %x -> %x", beforeDigest, afterDigest)
	}
	if beforeAccumulator != afterAccumulator {
		t.Fatalf(
			"projection accumulator changed: %x -> %x",
			beforeAccumulator,
			afterAccumulator,
		)
	}
}

func newPeerEndpointFixture(
	t *testing.T,
	memberCount int,
) peerEndpointFixture {
	t.Helper()
	if memberCount < 1 || memberCount > int(policy.MaxMemberDevices) {
		t.Fatalf("member count = %d", memberCount)
	}
	fixture := peerEndpointFixture{
		store: openTestStore(
			t,
			filepath.Join(t.TempDir(), "session", "state.db"),
			nil,
		),
		members:     make([]device.Device, memberCount),
		privateKeys: make([]ed25519.PrivateKey, memberCount),
	}
	for index := range memberCount {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		deviceID, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatalf("derive member %d ID: %v", index, err)
		}
		fixture.privateKeys[index] = privateKey
		fixture.members[index] = device.Device{
			ID:                deviceID,
			Role:              device.RoleOwner,
			IdentityPublicKey: bytes.Clone(publicKey),
			DaemonVersion:     "1.0.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		}
		if err := fixture.members[index].Validate(); err != nil {
			t.Fatalf("member %d: %v", index, err)
		}
	}
	const genesis = `{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000002","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	_, err := fixture.store.Initialize(context.Background(), InitialState{
		SessionID:   domain.UUIDv7(testSessionID),
		WorkspaceID: testWorkspaceID,
		GenesisJSON: []byte(genesis),
		Projections: ProjectionWrites{
			Devices: fixture.members,
			SessionPolicy: []policy.Policy{{
				SessionID:     domain.UUIDv7(testSessionID),
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	})
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	return fixture
}

func peerEndpointSignedSet(
	t *testing.T,
	fixture peerEndpointFixture,
	memberIndex int,
	sequence uint64,
	issuedAt time.Time,
	expiresAt time.Time,
	endpoints []netip.AddrPort,
) []byte {
	t.Helper()
	wireEndpoints := make([]peerEndpointWire, len(endpoints))
	for index, endpoint := range endpoints {
		wireEndpoints[index] = peerEndpointWire{
			IP:   endpoint.Addr().String(),
			Port: endpoint.Port(),
		}
	}
	wire := peerEndpointSetWireForFixture(
		fixture,
		memberIndex,
		sequence,
		issuedAt,
		expiresAt,
		wireEndpoints,
	)
	return peerEndpointSignWire(
		t,
		wire,
		fixture.privateKeys[memberIndex],
	)
}

func peerEndpointSetWireForFixture(
	fixture peerEndpointFixture,
	memberIndex int,
	sequence uint64,
	issuedAt time.Time,
	expiresAt time.Time,
	endpoints []peerEndpointWire,
) peerEndpointSetWire {
	return peerEndpointSetWire{
		SchemaVersion:      peerEndpointSetSchemaVersion,
		SessionID:          testSessionID,
		WorkspaceID:        string(testWorkspaceID),
		RecoveryGeneration: 0,
		DeviceID:           string(fixture.members[memberIndex].ID),
		EndpointSequence:   sequence,
		IssuedAt:           peerEndpointWholeSecond(issuedAt),
		ExpiresAt:          peerEndpointWholeSecond(expiresAt),
		Endpoints:          endpoints,
	}
}

func peerEndpointSignWire(
	t *testing.T,
	wire peerEndpointSetWire,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	unsignedObject := peerEndpointCanonicalJSON(t, wire)
	unsigned, _, err := codec.RemoveCanonicalObjectMember(
		unsignedObject,
		"signature",
	)
	if err != nil {
		t.Fatalf("remove empty signature: %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEndpointHints,
		unsigned,
	)
	if err != nil {
		t.Fatalf("sign endpoint set: %v", err)
	}
	wire.Signature = codec.EncodeBase64URL(signature)
	return peerEndpointCanonicalJSON(t, wire)
}

func peerEndpointSignMembers(
	t *testing.T,
	wire peerEndpointSetWire,
	privateKey ed25519.PrivateKey,
	extra map[string]json.RawMessage,
) []byte {
	t.Helper()
	base := peerEndpointCanonicalJSON(t, wire)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(base, &members); err != nil {
		t.Fatalf("decode endpoint members: %v", err)
	}
	for name, value := range extra {
		members[name] = value
	}
	delete(members, "signature")
	unsignedRaw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("marshal unsigned members: %v", err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(unsignedRaw)
	if err != nil {
		t.Fatalf("canonicalize unsigned members: %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEndpointHints,
		unsigned,
	)
	if err != nil {
		t.Fatalf("sign members: %v", err)
	}
	members["signature"] = json.RawMessage(
		fmt.Sprintf("%q", codec.EncodeBase64URL(signature)),
	)
	completeRaw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("marshal complete members: %v", err)
	}
	complete, err := codec.CanonicalizeSignedObject(completeRaw)
	if err != nil {
		t.Fatalf("canonicalize complete members: %v", err)
	}
	return complete
}

func peerEndpointCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal canonical input: %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("canonicalize input: %v", err)
	}
	return canonical
}

func peerEndpointRows(
	t *testing.T,
	store *Store,
	deviceID domain.DeviceID,
) []storedPeerEndpoint {
	t.Helper()
	var rows []storedPeerEndpoint
	err := store.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var err error
			rows, err = readPeerEndpointRowsForDevice(conn, deviceID)
			return err
		},
	)
	if err != nil {
		t.Fatalf("read peer endpoint rows: %v", err)
	}
	return rows
}

func peerEndpointRowCount(
	t *testing.T,
	store *Store,
	sourceKind PeerEndpointSourceKind,
) int64 {
	t.Helper()
	var count int64
	err := store.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOneArgs(
				conn,
				"SELECT count(*) FROM peer_endpoints WHERE source_kind = ?1;",
				[]any{string(sourceKind)},
				func(stmt *sqlite.Stmt) {
					count = stmt.ColumnInt64(0)
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("count peer endpoint rows: %v", err)
	}
	return count
}

func peerEndpointCommitments(
	t *testing.T,
	store *Store,
) (Digest, Digest) {
	t.Helper()
	stateDigest, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}
	var accumulator Digest
	err = store.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOne(
				conn,
				`SELECT projection_accumulator
				   FROM consensus_state
				  WHERE singleton = 1;`,
				func(stmt *sqlite.Stmt) {
					copy(accumulator[:], columnBytes(stmt, 0))
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("read projection accumulator: %v", err)
	}
	return stateDigest, accumulator
}

func peerEndpointHas(
	rows []storedPeerEndpoint,
	source PeerEndpointSourceKind,
	endpoint netip.AddrPort,
) bool {
	for _, row := range rows {
		if row.record.SourceKind == source &&
			row.record.Endpoint == endpoint {
			return true
		}
	}
	return false
}

func peerEndpointTimestamp(value time.Time) domain.Timestamp {
	return domain.Timestamp(value.UTC().Format(time.RFC3339Nano))
}

func peerEndpointWholeSecond(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05Z")
}

func peerEndpointDeviceID(t *testing.T, seedByte byte) domain.DeviceID {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seedByte}, ed25519.SeedSize),
	)
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("derive device ID: %v", err)
	}
	return deviceID
}
