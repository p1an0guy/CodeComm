package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

const daemonContentTestAdvertisementInterval = 20 * time.Second

type daemonContentStateStub struct {
	snapshot     coordstatus.DurableSnapshot
	snapshotErr  error
	endpointSets []store.MemberSignedEndpointSet
	endpointsErr error
	now          domain.Timestamp
}

func (state *daemonContentStateStub) StatusSnapshot(
	context.Context,
	domain.DeviceID,
	int,
) (coordstatus.DurableSnapshot, error) {
	if state.snapshotErr != nil {
		return coordstatus.DurableSnapshot{}, state.snapshotErr
	}
	return state.snapshot, nil
}

func (state *daemonContentStateStub) ListMemberSignedEndpointSets(
	_ context.Context,
	now domain.Timestamp,
) ([]store.MemberSignedEndpointSet, error) {
	state.now = now
	if state.endpointsErr != nil {
		return nil, state.endpointsErr
	}
	result := make([]store.MemberSignedEndpointSet, len(state.endpointSets))
	for index, value := range state.endpointSets {
		result[index] = store.MemberSignedEndpointSet{
			DeviceID:        value.DeviceID,
			EndpointSetJSON: bytes.Clone(value.EndpointSetJSON),
		}
	}
	return result, nil
}

type daemonEndpointSetSourceStub struct {
	value []byte
	found bool
}

type daemonEventProposalConsensusStub struct {
	lookup store.CommandResultLookup
	err    error

	calls     int
	sender    domain.DeviceID
	canonical []byte
	hop       contenthttp.ProposalHop
}

func (stub *daemonEventProposalConsensusStub) apply(
	sender domain.DeviceID,
	canonical []byte,
	hop contenthttp.ProposalHop,
) (store.CommandResultLookup, error) {
	stub.calls++
	stub.sender = sender
	stub.canonical = bytes.Clone(canonical)
	stub.hop = hop
	return stub.lookup, stub.err
}

func (stub *daemonEventProposalConsensusStub) ApplyPeerProposal(
	_ context.Context,
	sender domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return stub.apply(sender, canonical, contenthttp.ProposalHopInitial)
}

func (stub *daemonEventProposalConsensusStub) ApplyForwardedProposal(
	_ context.Context,
	sender domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return stub.apply(sender, canonical, contenthttp.ProposalHopForwarded)
}

func (source *daemonEndpointSetSourceStub) CurrentEndpointSet() (
	[]byte,
	time.Duration,
	bool,
) {
	return bytes.Clone(source.value),
		daemonContentTestAdvertisementInterval,
		source.found
}

func TestDaemonContentServiceReturnsAppliedSessionAndExactEndpointSets(
	t *testing.T,
) {
	snapshot := daemonContentTestSnapshot(t)
	remoteID := daemonContentTestDeviceID(t, 0xc7)
	snapshot.Members = append(
		snapshot.Members,
		coordstatus.MemberSummary{
			ID: remoteID, Role: device.RoleEditor,
			Status: device.StatusActive, EntityVersion: 1,
		},
	)
	sort.Slice(snapshot.Members, func(left, right int) bool {
		return snapshot.Members[left].ID < snapshot.Members[right].ID
	})
	snapshot.MemberTotal = uint64(len(snapshot.Members))

	testNow := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	localSet := daemonContentTestEndpointSet(t, snapshot, testNow)
	remoteSet := []byte(`{"remote":2}`)
	state := &daemonContentStateStub{
		snapshot: snapshot,
		endpointSets: []store.MemberSignedEndpointSet{{
			DeviceID: remoteID, EndpointSetJSON: remoteSet,
		}},
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		state,
		&daemonEndpointSetSourceStub{value: localSet, found: true},
		&daemonEventProposalConsensusStub{},
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}

	session, err := service.Session(context.Background())
	if err != nil {
		t.Fatalf("Session(): %v", err)
	}
	if session.SessionID() != snapshot.SessionID ||
		session.WorkspaceID() != snapshot.WorkspaceID ||
		session.RecoveryGeneration() != snapshot.RecoveryGeneration ||
		session.ServerDeviceID() != snapshot.Member.ID ||
		session.DaemonVersion() != snapshot.Member.DaemonVersion ||
		session.MaxApplyLevel() != snapshot.Member.MaxApplyLevel ||
		len(session.RequiredCapabilities()) != 0 {
		t.Fatalf("session response = %#v", session)
	}

	peers, err := service.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers(): %v", err)
	}
	if !state.now.Valid() {
		t.Fatalf("endpoint read time = %q", state.now)
	}
	members := peers.Members()
	if len(members) != 2 ||
		members[0].DeviceID() >= members[1].DeviceID() {
		t.Fatalf("members = %#v", members)
	}
	endpoints := make(map[domain.DeviceID][]byte, len(members))
	for _, member := range members {
		endpoints[member.DeviceID()] = member.EndpointSet()
	}
	if !bytes.Equal(endpoints[snapshot.Member.ID], localSet) ||
		!bytes.Equal(endpoints[remoteID], remoteSet) {
		t.Fatalf("relayed endpoint sets = %#v", endpoints)
	}
	localSet[0] ^= 0xff
	remoteSet[0] ^= 0xff
	if bytes.Equal(
		daemonContentMember(t, peers, snapshot.Member.ID).EndpointSet(),
		localSet,
	) || bytes.Equal(
		daemonContentMember(t, peers, remoteID).EndpointSet(),
		remoteSet,
	) {
		t.Fatal("response retained caller-owned endpoint-set storage")
	}
}

func TestDaemonContentServiceSuppressesInactiveEndpointSet(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	remoteID := daemonContentTestDeviceID(t, 0xc8)
	snapshot.Members = append(
		snapshot.Members,
		coordstatus.MemberSummary{
			ID: remoteID, Role: device.RoleEditor,
			Status: device.StatusRevoked, EntityVersion: 2,
		},
	)
	sort.Slice(snapshot.Members, func(left, right int) bool {
		return snapshot.Members[left].ID < snapshot.Members[right].ID
	})
	snapshot.MemberTotal = uint64(len(snapshot.Members))
	testNow := time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC)
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{
			snapshot: snapshot,
			endpointSets: []store.MemberSignedEndpointSet{{
				DeviceID:        remoteID,
				EndpointSetJSON: []byte(`{"stale":1}`),
			}},
		},
		&daemonEndpointSetSourceStub{
			value: daemonContentTestEndpointSet(t, snapshot, testNow),
			found: true,
		},
		&daemonEventProposalConsensusStub{},
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	peers, err := service.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers(): %v", err)
	}
	if endpointSet := daemonContentMember(
		t,
		peers,
		remoteID,
	).EndpointSet(); endpointSet != nil {
		t.Fatalf("revoked member endpoint set = %q", endpointSet)
	}
}

func TestDaemonContentServiceProposesBoundCommittedResult(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("event fixture identity mismatch")
	}
	signed := daemonTestTaskEvent(t, privateKey, deviceID)
	proposals := &daemonEventProposalConsensusStub{
		lookup: daemonContentTestCommandLookup(t, signed, snapshot),
	}
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{snapshot: snapshot},
		&daemonEndpointSetSourceStub{},
		proposals,
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	sender := daemonContentTestDeviceID(t, 0xd8)
	result, err := service.ProposeEvent(
		context.Background(),
		sender,
		signed.CanonicalBytes(),
		contenthttp.ProposalHopInitial,
	)
	if err != nil {
		t.Fatalf("ProposeEvent(): %v", err)
	}
	if proposals.calls != 1 ||
		proposals.sender != sender ||
		!bytes.Equal(proposals.canonical, signed.CanonicalBytes()) ||
		proposals.hop != contenthttp.ProposalHopInitial ||
		!bytes.Equal(result.Proposal(), signed.CanonicalBytes()) ||
		result.Outcome().Status != store.OutcomeAccepted {
		t.Fatalf(
			"proposal call/result = (%d, %s, %q, %+v)",
			proposals.calls,
			proposals.sender,
			proposals.canonical,
			result.Outcome(),
		)
	}
	if _, err := service.ProposeEvent(
		context.Background(),
		sender,
		signed.CanonicalBytes(),
		contenthttp.ProposalHopForwarded,
	); err != nil {
		t.Fatalf("ProposeEvent(forwarded): %v", err)
	}
	if proposals.calls != 2 ||
		proposals.hop != contenthttp.ProposalHopForwarded {
		t.Fatalf(
			"forwarded proposal call = (%d, %d)",
			proposals.calls,
			proposals.hop,
		)
	}

	for _, test := range []struct {
		name   string
		mutate func(*store.CommandResultLookup)
	}{
		{
			name: "session",
			mutate: func(lookup *store.CommandResultLookup) {
				lookup.SessionID =
					"01890f47-3e72-7000-8000-000000000799"
			},
		},
		{
			name: "generation",
			mutate: func(lookup *store.CommandResultLookup) {
				lookup.RecoveryGeneration++
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookup := daemonContentTestCommandLookup(
				t,
				signed,
				snapshot,
			)
			test.mutate(&lookup)
			proposals := &daemonEventProposalConsensusStub{
				lookup: lookup,
			}
			service.proposals = proposals
			if _, err := service.ProposeEvent(
				context.Background(),
				sender,
				signed.CanonicalBytes(),
				contenthttp.ProposalHopInitial,
			); !errors.Is(err, errDaemonContentConstruction) {
				t.Fatalf("ProposeEvent() error = %v", err)
			}
		})
	}
}

func TestDaemonContentServiceMapsProposalErrors(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	sentinel := errors.New("unexpected proposal failure")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "invalid",
			err:  consensus.ErrInvalidPeerProposal,
			want: contenthttp.ErrInvalidEventProposal,
		},
		{
			name: "idempotency conflict",
			err:  store.ErrIdempotencyConflict,
			want: contenthttp.ErrEventIdempotencyConflict,
		},
		{
			name: "rate limited",
			err:  consensus.ErrProposalIngressRateLimited,
			want: contenthttp.ErrEventProposalRateLimited,
		},
		{
			name: "canceled",
			err:  context.Canceled,
			want: context.Canceled,
		},
		{
			name: "not leader",
			err:  raft.ErrNotLeader,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "leadership lost",
			err:  raft.ErrLeadershipLost,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "forwarding unavailable",
			err:  consensus.ErrProposalForwardingUnavailable,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "node closed",
			err:  consensus.ErrNodeClosed,
			want: contenthttp.ErrEventProposalUnavailable,
		},
		{
			name: "unexpected",
			err:  sentinel,
			want: errDaemonContentConstruction,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := newDaemonContentService(
				snapshot.SessionID,
				snapshot.WorkspaceID,
				snapshot.RecoveryGeneration,
				snapshot.Member.ID,
				&daemonContentStateStub{snapshot: snapshot},
				&daemonEndpointSetSourceStub{},
				&daemonEventProposalConsensusStub{err: test.err},
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			if _, err := service.ProposeEvent(
				context.Background(),
				daemonContentTestDeviceID(t, 0xd9),
				[]byte(`{}`),
				contenthttp.ProposalHopInitial,
			); !errors.Is(err, test.want) {
				t.Fatalf("ProposeEvent() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDaemonContentServiceFailsClosed(t *testing.T) {
	sentinel := errors.New("state unavailable")
	valid := daemonContentTestSnapshot(t)
	tests := []struct {
		name       string
		snapshot   coordstatus.DurableSnapshot
		stateErr   error
		sets       []store.MemberSignedEndpointSet
		setErr     error
		localSet   []byte
		localFound bool
	}{
		{
			name: "snapshot unavailable", snapshot: valid,
			stateErr: sentinel, localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "truncated roster",
			snapshot: func() coordstatus.DurableSnapshot {
				value := valid
				value.MembersTruncated = true
				value.MemberTotal++
				return value
			}(),
			localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "endpoint state unavailable", snapshot: valid,
			setErr: sentinel, localSet: []byte(`{}`), localFound: true,
		},
		{
			name: "local endpoint set unavailable", snapshot: valid,
		},
		{
			name: "noncanonical local endpoint set", snapshot: valid,
			localSet: []byte(`{"b":1,"a":2}`), localFound: true,
		},
		{
			name: "unsorted relayed endpoint sets", snapshot: valid,
			sets: []store.MemberSignedEndpointSet{
				{
					DeviceID:        daemonContentTestDeviceID(t, 0xd2),
					EndpointSetJSON: []byte(`{}`),
				},
				{
					DeviceID:        daemonContentTestDeviceID(t, 0xd1),
					EndpointSetJSON: []byte(`{}`),
				},
			},
			localSet: []byte(`{}`), localFound: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := newDaemonContentService(
				test.snapshot.SessionID,
				test.snapshot.WorkspaceID,
				test.snapshot.RecoveryGeneration,
				test.snapshot.Member.ID,
				&daemonContentStateStub{
					snapshot: test.snapshot, snapshotErr: test.stateErr,
					endpointSets: test.sets, endpointsErr: test.setErr,
				},
				&daemonEndpointSetSourceStub{
					value: test.localSet, found: test.localFound,
				},
				&daemonEventProposalConsensusStub{},
				time.Now,
			)
			if err != nil {
				t.Fatalf("newDaemonContentService(): %v", err)
			}
			if _, err := service.Peers(context.Background()); !errors.Is(
				err,
				errDaemonContentConstruction,
			) {
				t.Fatalf("Peers() error = %v", err)
			}
		})
	}
}

func daemonContentTestCommandLookup(
	t *testing.T,
	signed event.SignedEvent,
	snapshot coordstatus.DurableSnapshot,
) store.CommandResultLookup {
	t.Helper()
	canonical := signed.CanonicalBytes()
	proposalDigest := sha256.Sum256(canonical)
	chainHash := store.Digest(sha256.Sum256([]byte("daemon-content-chain")))
	chainIndex := uint64(1)
	return store.CommandResultLookup{
		EventID:            signed.Proposal().EventID,
		SessionID:          snapshot.SessionID,
		RecoveryGeneration: snapshot.RecoveryGeneration,
		CanonicalProposal:  canonical,
		ProposalDigest:     proposalDigest,
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		Tuple: store.CommandResultTuple{
			ResultIndex: 1,
			ChainIndex:  &chainIndex,
			ChainHash:   &chainHash,
		},
	}
}

func daemonContentTestSnapshot(t *testing.T) coordstatus.DurableSnapshot {
	t.Helper()
	initial, _, deviceID := daemonTestInitialState(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("secure content test directory: %v", err)
	}
	database, err := store.Open(
		context.Background(),
		store.Options{Path: filepath.Join(directory, "state.db")},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close content test store: %v", err)
		}
	})
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	snapshot, err := database.LocalState().StatusSnapshot(
		context.Background(),
		deviceID,
		1,
	)
	if err != nil {
		t.Fatalf("StatusSnapshot(): %v", err)
	}
	return snapshot
}

func daemonContentTestEndpointSet(
	t *testing.T,
	snapshot coordstatus.DurableSnapshot,
	now time.Time,
) []byte {
	t.Helper()
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("content endpoint fixture identity mismatch")
	}
	address := netip.MustParseAddr("192.0.2.31")
	signer, err := discovery.NewEndpointSigner(
		daemonContentTestAdvertisementInterval,
		47831,
		[]netip.Addr{address},
	)
	if err != nil {
		t.Fatalf("discovery.NewEndpointSigner(): %v", err)
	}
	now = now.UTC().Truncate(time.Second)
	encoded, err := signer.Sign(
		discovery.EndpointSet{
			SessionID:          snapshot.SessionID,
			WorkspaceID:        snapshot.WorkspaceID,
			RecoveryGeneration: snapshot.RecoveryGeneration,
			DeviceID:           snapshot.Member.ID,
			EndpointSequence:   uint64(now.UnixMilli()),
			IssuedAt: domain.WholeSecondTimestamp(
				now.Format(time.RFC3339),
			),
			ExpiresAt: domain.WholeSecondTimestamp(
				now.Add(
					discovery.EndpointHintTTLIntervals *
						daemonContentTestAdvertisementInterval,
				).Format(time.RFC3339),
			),
			Endpoints: []discovery.Endpoint{{IP: address, Port: 47831}},
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("EndpointSigner.Sign(): %v", err)
	}
	return encoded
}

func daemonContentTestDeviceID(t *testing.T, seed byte) domain.DeviceID {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	defer clear(privateKey)
	value, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	return value
}

func daemonContentMember(
	t *testing.T,
	response contenthttp.PeersResponse,
	deviceID domain.DeviceID,
) contenthttp.PeerMember {
	t.Helper()
	for _, member := range response.Members() {
		if member.DeviceID() == deviceID {
			return member
		}
	}
	t.Fatalf("member %s not found", deviceID)
	return contenthttp.PeerMember{}
}
