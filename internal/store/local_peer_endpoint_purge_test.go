package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestPurgePeerLearnedEndpointsPreservesManualConfiguration(t *testing.T) {
	fixture := newPeerEndpointFixture(t, 1)
	state := fixture.store.LocalState()
	deviceID := fixture.members[0].ID
	now := peerEndpointTimestamp(peerEndpointTestNow)
	manual := netip.MustParseAddrPort("192.0.2.8:47831")

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
		deviceID,
		netip.MustParseAddrPort("192.0.2.5:47831"),
		now,
		domain.WholeSecondTimestamp(
			peerEndpointWholeSecond(peerEndpointTestNow.Add(time.Minute)),
		),
	); err != nil {
		t.Fatalf("upsert raw endpoint: %v", err)
	}
	if err := state.UpsertAuthenticatedEndpoint(
		context.Background(),
		deviceID,
		netip.MustParseAddrPort("192.0.2.6:47831"),
		now,
	); err != nil {
		t.Fatalf("upsert authenticated endpoint: %v", err)
	}
	if err := state.UpsertManualEndpoint(
		context.Background(),
		deviceID,
		manual,
		now,
	); err != nil {
		t.Fatalf("upsert manual endpoint: %v", err)
	}

	if err := state.PurgePeerLearnedEndpoints(
		context.Background(),
		deviceID,
	); err != nil {
		t.Fatalf("PurgePeerLearnedEndpoints(): %v", err)
	}
	candidates, err := state.ListPeerEndpointCandidates(
		context.Background(),
		deviceID,
		now,
	)
	if err != nil {
		t.Fatalf("ListPeerEndpointCandidates(): %v", err)
	}
	if len(candidates) != 1 ||
		candidates[0].SourceKind != PeerEndpointManual ||
		candidates[0].Endpoint != manual {
		t.Fatalf("remaining candidates = %#v, want manual only", candidates)
	}
	if err := state.PurgePeerLearnedEndpoints(
		context.Background(),
		deviceID,
	); err != nil {
		t.Fatalf("idempotent purge: %v", err)
	}
	if err := state.PurgePeerLearnedEndpoints(
		context.Background(),
		"invalid",
	); !errors.Is(err, ErrInvalidPeerEndpoint) {
		t.Fatalf("invalid peer purge error = %v", err)
	}
}
