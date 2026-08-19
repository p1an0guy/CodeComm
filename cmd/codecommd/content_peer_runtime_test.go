package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

type daemonContentPeerStateStub struct {
	mu            sync.Mutex
	snapshot      coordstatus.DurableSnapshot
	authenticated error
}

func (state *daemonContentPeerStateStub) StatusSnapshot(
	context.Context,
	domain.DeviceID,
	int,
) (coordstatus.DurableSnapshot, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	result := state.snapshot
	result.Members = slices.Clone(state.snapshot.Members)
	return result, nil
}

func (*daemonContentPeerStateStub) ReplaceMemberSignedEndpointSet(
	context.Context,
	[]byte,
	domain.Timestamp,
) (store.MemberEndpointSetUpdate, error) {
	return store.MemberEndpointSetStored, nil
}

func (state *daemonContentPeerStateStub) UpsertAuthenticatedEndpoint(
	context.Context,
	domain.DeviceID,
	netip.AddrPort,
	domain.Timestamp,
) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.authenticated
}

func (state *daemonContentPeerStateStub) revoke(deviceID domain.DeviceID) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for index := range state.snapshot.Members {
		if state.snapshot.Members[index].ID == deviceID {
			state.snapshot.Members[index].Status = device.StatusRevoked
			state.snapshot.Members[index].EntityVersion++
		}
	}
}

type daemonContentPeerAdmissionStub struct {
	snapshot *peerauth.Snapshot
}

func (stub daemonContentPeerAdmissionStub) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	if stub.snapshot != nil {
		return stub.snapshot, nil
	}
	return nil, errors.New("admission unavailable in route-only test")
}

type daemonContentPeerRoutesStub struct{}

func (daemonContentPeerRoutesStub) ResolveConsensusEndpoints(
	context.Context,
	domain.DeviceID,
) ([]netip.AddrPort, error) {
	return nil, transport.ErrConsensusEndpointUnavailable
}

func (daemonContentPeerRoutesStub) DialConsensusEndpoint(
	context.Context,
	netip.AddrPort,
) (net.Conn, error) {
	return nil, transport.ErrConsensusEndpointUnavailable
}

type daemonContentPeerResolvedRoutesStub struct {
	dialed bool
}

func (*daemonContentPeerResolvedRoutesStub) ResolveConsensusEndpoints(
	context.Context,
	domain.DeviceID,
) ([]netip.AddrPort, error) {
	return []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:47831"),
	}, nil
}

func (routes *daemonContentPeerResolvedRoutesStub) DialConsensusEndpoint(
	context.Context,
	netip.AddrPort,
) (net.Conn, error) {
	routes.dialed = true
	return nil, transport.ErrConsensusEndpointUnavailable
}

func TestDaemonContentPeerRuntimeTracksAppliedActiveMembership(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	remoteID := daemonContentTestDeviceID(t, 0xe1)
	snapshot.Members = append(snapshot.Members, coordstatus.MemberSummary{
		ID: remoteID, Role: device.RoleEditor,
		Status: device.StatusActive, EntityVersion: 1,
	})
	slices.SortFunc(snapshot.Members, func(
		left, right coordstatus.MemberSummary,
	) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	snapshot.MemberTotal = uint64(len(snapshot.Members))
	state := &daemonContentPeerStateStub{snapshot: snapshot}
	runtime, err := newDaemonContentPeerRuntime(
		context.Background(),
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		state,
		daemonContentPeerAdmissionStub{},
		func() (tls.Certificate, error) {
			return tls.Certificate{}, transport.ErrContentCertificateUnavailable
		},
		daemonContentPeerRoutesStub{},
	)
	if err != nil {
		t.Fatalf("newDaemonContentPeerRuntime(): %v", err)
	}
	t.Cleanup(func() {
		_ = runtime.BeginClose()
		_ = runtime.Wait()
	})

	runtime.workersMu.Lock()
	worker := runtime.workers[remoteID]
	workerCount := len(runtime.workers)
	runtime.workersMu.Unlock()
	if worker == nil || workerCount != 1 {
		t.Fatalf("active workers = %d, remote worker = %p", workerCount, worker)
	}

	state.revoke(remoteID)
	if err := runtime.reconcileWorkers(context.Background()); err != nil {
		t.Fatalf("reconcileWorkers(revoked): %v", err)
	}
	runtime.workersMu.Lock()
	workerCount = len(runtime.workers)
	runtime.workersMu.Unlock()
	if workerCount != 0 {
		t.Fatalf("workers after revocation = %d, want 0", workerCount)
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("revoked peer worker retained its connection lifecycle")
	}
}

func TestDaemonContentPeerRuntimeRejectsMalformedLocalCertificate(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	routes := &daemonContentPeerResolvedRoutesStub{}
	runtime := &daemonContentPeerRuntime{
		sessionID:     snapshot.SessionID,
		workspaceID:   snapshot.WorkspaceID,
		generation:    snapshot.RecoveryGeneration,
		localDeviceID: snapshot.Member.ID,
		certificate: func() (tls.Certificate, error) {
			return tls.Certificate{}, nil
		},
		routes: routes,
	}
	remoteID := daemonContentTestDeviceID(t, 0xe2)
	if _, err := runtime.dialPeer(
		context.Background(),
		remoteID,
	); !errors.Is(err, errDaemonContentPeerConstruction) {
		t.Fatalf("dialPeer(malformed certificate) error = %v", err)
	}
	if routes.dialed {
		t.Fatal("malformed local certificate reached the network dialer")
	}
	if runtime.localCredentialAdvanced(1) {
		t.Fatal("malformed local certificate advanced the credential epoch")
	}
}

func TestDaemonContentPeerRuntimeDetectsActiveRemoteSuccessor(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	local := daemonContentPeerTestMember(t, 0xa1)
	remote := daemonContentPeerTestMember(t, 0xa2)
	first := daemonContentPeerTestAuthorization(
		t,
		now.Add(-28*time.Minute),
		remote,
		0xb1,
		1,
		10,
	)
	second := daemonContentPeerTestAuthorization(
		t,
		now.Add(-time.Minute),
		remote,
		0xb2,
		2,
		20,
	)
	snapshot, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:          daemonTestSessionID,
		RecoveryGeneration: 0,
		AppliedChainIndex:  second.AuthorizationChainIndex,
		Devices: map[domain.DeviceID]device.Device{
			local.ID:  local,
			remote.ID: remote,
		},
		AuditCounters: map[domain.DeviceID]auditcounter.Counter{
			local.ID: {
				DeviceID: local.ID,
			},
			remote.ID: {
				DeviceID:        remote.ID,
				CredentialEpoch: 2,
			},
		},
		CredentialAuthorizations: map[credentialauthorization.Key]credentialauthorization.Authorization{
			first.PrimaryKey():  first,
			second.PrimaryKey(): second,
		},
	})
	if err != nil {
		t.Fatalf("NewSnapshot(): %v", err)
	}
	runtime := &daemonContentPeerRuntime{
		sessionID:     daemonTestSessionID,
		localDeviceID: local.ID,
		admission: daemonContentPeerAdmissionStub{
			snapshot: snapshot,
		},
		now: func() time.Time { return now },
	}
	if !runtime.remoteCredentialAdvanced(remote.ID, 1) {
		t.Fatal("active remote successor did not request make-before-break")
	}
	if runtime.remoteCredentialAdvanced(remote.ID, 2) {
		t.Fatal("current remote epoch requested a redundant replacement")
	}
}

func TestDaemonContentPeerRuntimeRejectsInconsistentMembership(t *testing.T) {
	snapshot := daemonContentTestSnapshot(t)
	snapshot.MembersTruncated = true
	snapshot.MemberTotal++
	_, err := newDaemonContentPeerRuntime(
		context.Background(),
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentPeerStateStub{snapshot: snapshot},
		daemonContentPeerAdmissionStub{},
		func() (tls.Certificate, error) { return tls.Certificate{}, nil },
		daemonContentPeerRoutesStub{},
	)
	if !errors.Is(err, errDaemonContentPeerConstruction) {
		t.Fatalf("newDaemonContentPeerRuntime() error = %v", err)
	}
}

func TestDaemonContentPeerRuntimeShutdownDoesNotRecordCancellationFatal(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &daemonContentPeerRuntime{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if err := runtime.BeginClose(); err != nil {
		t.Fatalf("BeginClose(): %v", err)
	}
	runtime.fail(context.Canceled)
	if err := runtime.FatalError(); err != nil {
		t.Fatalf("FatalError() after shutdown cancellation = %v", err)
	}
}

func TestDaemonContentPeerRuntimeClassifiesEndpointPersistenceFailures(
	t *testing.T,
) {
	t.Parallel()

	snapshot := daemonContentTestSnapshot(t)
	state := &daemonContentPeerStateStub{snapshot: snapshot}
	runtime := &daemonContentPeerRuntime{
		localDeviceID: snapshot.Member.ID,
		state:         state,
		now: func() time.Time {
			return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
		},
	}
	peerID := daemonContentTestDeviceID(t, 0xe3)
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")

	state.authenticated = store.ErrPeerEndpointCapacity
	if err := runtime.recordAuthenticatedEndpoint(
		t.Context(),
		peerID,
		endpoint,
	); err != nil {
		t.Fatalf("capacity refusal = %v", err)
	}

	state.authenticated = store.ErrPeerEndpointIntegrity
	if err := runtime.recordAuthenticatedEndpoint(
		t.Context(),
		peerID,
		endpoint,
	); !errors.Is(err, errDaemonContentPeerState) ||
		!errors.Is(err, store.ErrPeerEndpointIntegrity) {
		t.Fatalf("integrity failure = %v", err)
	}

	for _, err := range []error{
		store.ErrInvalidPeerEndpointSet,
		store.ErrPeerEndpointSequenceConflict,
		store.ErrPeerEndpointCapacity,
	} {
		if !contentPeerSetRefusal(err) {
			t.Fatalf("peer refusal %v was classified as local state", err)
		}
	}
	if contentPeerSetRefusal(store.ErrPeerEndpointIntegrity) {
		t.Fatal("local integrity failure was classified as peer refusal")
	}
}

func TestDaemonContentPeerRetryDelayIsBounded(t *testing.T) {
	for _, backoff := range []time.Duration{
		daemonContentPeerRetryInitial,
		time.Second,
		daemonContentPeerRetryMaximum,
	} {
		for range 100 {
			delay := daemonContentPeerRetryDelay(backoff)
			if delay < backoff*3/4 || delay > backoff*5/4 {
				t.Fatalf("retry delay for %s = %s", backoff, delay)
			}
		}
	}
	if delay := daemonContentPeerRetryDelay(0); delay != 0 {
		t.Fatalf("zero retry delay = %s", delay)
	}
}

func daemonContentPeerTestMember(
	t testing.TB,
	fill byte,
) device.Device {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{fill}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(publicKey),
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func daemonContentPeerTestAuthorization(
	t testing.TB,
	notBefore time.Time,
	member device.Device,
	keyFill byte,
	epoch uint64,
	chainIndex uint64,
) credentialauthorization.Authorization {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{keyFill}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	timestamp := domain.WholeSecondTimestamp(
		notBefore.UTC().Truncate(time.Second).Format(time.RFC3339),
	)
	authorization := credentialauthorization.Authorization{
		SessionID:                daemonTestSessionID,
		DeviceID:                 member.ID,
		Epoch:                    epoch,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 timestamp,
		NotBefore:                timestamp,
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: member.ID,
		}},
		AuthorizationChainIndex: chainIndex,
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	authorization.KeyDigest = sha256.Sum256(publicKey)
	if err := authorization.Validate(); err != nil {
		t.Fatal(err)
	}
	return authorization
}
