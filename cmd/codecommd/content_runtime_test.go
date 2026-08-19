package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
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
		snapshot.Member.ID,
		state,
		&daemonEndpointSetSourceStub{value: localSet, found: true},
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
				test.snapshot.Member.ID,
				&daemonContentStateStub{
					snapshot: test.snapshot, snapshotErr: test.stateErr,
					endpointSets: test.sets, endpointsErr: test.setErr,
				},
				&daemonEndpointSetSourceStub{
					value: test.localSet, found: test.localFound,
				},
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
