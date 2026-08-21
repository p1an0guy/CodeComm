package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
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

type daemonContentPeerReplicationStub struct {
	forgotten chan domain.DeviceID
}

func (*daemonContentPeerReplicationStub) Sync(
	context.Context,
	domain.DeviceID,
	daemonReplicationClient,
) error {
	return nil
}

func (stub *daemonContentPeerReplicationStub) ForgetPeer(
	peerID domain.DeviceID,
) {
	stub.forgotten <- peerID
}

type daemonConsensusStatusRequesterStub struct {
	mu       sync.Mutex
	response transport.ConsensusControlResponse
	err      error
	targets  []domain.DeviceID
}

func (stub *daemonConsensusStatusRequesterStub) RequestConsensusStatus(
	_ context.Context,
	target domain.DeviceID,
) (transport.ConsensusControlResponse, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.targets = append(stub.targets, target)
	return stub.response, stub.err
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

func TestDaemonContentPeerWorkerForgetsReplicationPeerOnExit(t *testing.T) {
	replicationRuntime := &daemonContentPeerReplicationStub{
		forgotten: make(chan domain.DeviceID, 1),
	}
	runtime := &daemonContentPeerRuntime{
		replication: replicationRuntime,
	}
	peerID := daemonContentTestDeviceID(t, 0xe0)
	worker := &daemonContentPeerWorker{
		deviceID: peerID,
		done:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runtime.runWorker(ctx, worker)

	select {
	case got := <-replicationRuntime.forgotten:
		if got != peerID {
			t.Fatalf("forgotten peer = %s, want %s", got, peerID)
		}
	default:
		t.Fatal("worker exit retained replication freshness")
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("worker exit did not close done")
	}
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
		time.Now,
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
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        daemonTestSessionID,
			VoterDeviceIDs:   []domain.DeviceID{local.ID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
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
		credentialNow: func() time.Time { return now },
	}
	if !runtime.remoteCredentialAdvanced(remote.ID, 1) {
		t.Fatal("active remote successor did not request make-before-break")
	}
	if runtime.remoteCredentialAdvanced(remote.ID, 2) {
		t.Fatal("current remote epoch requested a redundant replacement")
	}
}

func TestDaemonContentPeerBootstrapInstallsAuthorityVerifiedLaterEpoch(
	t *testing.T,
) {
	now := time.Now().UTC().Truncate(time.Second)
	local := daemonContentPeerTestMember(t, 0xc1)
	peerIdentity := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xc2}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(peerIdentity) })
	peerID, err := device.DeriveID(
		peerIdentity.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(peer): %v", err)
	}
	peer := device.Device{
		ID:                peerID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(peerIdentity.Public().(ed25519.PublicKey)),
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	firstEpochKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xd1}, ed25519.SeedSize),
	)
	secondEpochKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xd2}, ed25519.SeedSize),
	)
	thirdEpochKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xd3}, ed25519.SeedSize),
	)
	t.Cleanup(func() {
		clear(firstEpochKey)
		clear(secondEpochKey)
		clear(thirdEpochKey)
	})
	first := daemonContentPeerSignedAuthorization(
		t,
		peer,
		peerIdentity,
		firstEpochKey,
		nil,
		now.Add(-58*time.Minute),
		now.Add(-58*time.Minute),
		1,
	)
	second := daemonContentPeerSignedAuthorization(
		t,
		peer,
		peerIdentity,
		secondEpochKey,
		&first,
		now.Add(-31*time.Minute),
		now.Add(-30*time.Minute),
		2,
	)
	third := daemonContentPeerSignedAuthorization(
		t,
		peer,
		peerIdentity,
		thirdEpochKey,
		&second,
		now.Add(-2*time.Minute),
		now.Add(-2*time.Minute),
		3,
	)
	snapshot, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:          daemonTestSessionID,
		RecoveryGeneration: 0,
		AppliedChainIndex:  1,
		Devices: map[domain.DeviceID]device.Device{
			local.ID: local,
			peer.ID:  peer,
		},
		AuditCounters: map[domain.DeviceID]auditcounter.Counter{
			local.ID: {DeviceID: local.ID},
			peer.ID: {
				DeviceID:        peer.ID,
				CredentialEpoch: 1,
			},
		},
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        daemonTestSessionID,
			VoterDeviceIDs:   []domain.DeviceID{peer.ID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		CredentialAuthorizations: map[credentialauthorization.Key]credentialauthorization.Authorization{
			first.PrimaryKey(): first,
		},
	})
	if err != nil {
		t.Fatalf("peerauth.NewSnapshot(): %v", err)
	}
	outbound, err := peerauth.NewVerifiersWithProvisional(
		func() (*peerauth.Snapshot, error) { return snapshot, nil },
		func() time.Time { return now },
		peerauth.NewProvisionalAuthorizations(),
	)
	if err != nil {
		t.Fatalf("NewVerifiersWithProvisional(outbound): %v", err)
	}
	ingress, err := peerauth.NewVerifiers(
		func() (*peerauth.Snapshot, error) { return snapshot, nil },
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewVerifiers(ingress): %v", err)
	}
	certificate, _, err := transport.IssueContentCertificate(
		third,
		thirdEpochKey,
	)
	if err != nil {
		t.Fatalf("IssueContentCertificate(): %v", err)
	}
	t.Cleanup(func() { clearDaemonTLSCertificate(&certificate) })
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil {
		t.Fatalf("ParseContentCertificate(): %v", err)
	}
	if _, err := ingress.VerifyContentPeer(parsed); !errors.Is(
		err,
		peerauth.ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(before bootstrap) error = %v", err)
	}

	requester := &daemonConsensusStatusRequesterStub{
		response: daemonContentPeerConsensusStatusResponse(
			t,
			peer.ID,
			third,
			0,
		),
	}
	runtime := &daemonContentPeerRuntime{
		sessionID:     daemonTestSessionID,
		generation:    0,
		localDeviceID: local.ID,
		admission: daemonContentPeerAdmissionStub{
			snapshot: snapshot,
		},
		verifiers:     outbound,
		credentialNow: func() time.Time { return now },
		status:        requester,
	}
	if err := runtime.bootstrapPeerAuthorization(
		t.Context(),
		peer.ID,
	); err != nil {
		t.Fatalf("bootstrapPeerAuthorization(): %v", err)
	}
	requester.mu.Lock()
	targets := slices.Clone(requester.targets)
	requester.mu.Unlock()
	if !slices.Equal(targets, []domain.DeviceID{peer.ID}) {
		t.Fatalf("status targets = %v, want [%s]", targets, peer.ID)
	}
	if _, err := outbound.VerifyExpectedContentPeer(
		peer.ID,
		parsed,
	); err != nil {
		t.Fatalf("VerifyExpectedContentPeer(after bootstrap): %v", err)
	}
	if _, err := ingress.VerifyContentPeer(parsed); !errors.Is(
		err,
		peerauth.ErrPeerNotAdmitted,
	) {
		t.Fatalf("VerifyContentPeer(after outbound bootstrap) error = %v", err)
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
		time.Now,
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

func TestNormalizeDaemonProposalForwardingError(t *testing.T) {
	sentinel := errors.New("invalid peer response")
	tests := []struct {
		name  string
		input error
		want  error
	}{
		{
			name:  "canceled",
			input: context.Canceled,
			want:  context.Canceled,
		},
		{
			name:  "connection closed",
			input: contenthttp.ErrClientClosed,
			want:  consensus.ErrProposalForwardingUnavailable,
		},
		{
			name: "connection unavailable",
			input: errors.Join(
				contenthttp.ErrConnectionUnavailable,
				errors.New("GOAWAY"),
			),
			want: consensus.ErrProposalForwardingUnavailable,
		},
		{
			name: "idempotency conflict",
			input: &contenthttp.RemoteError{
				Code: "idempotency_conflict",
			},
			want: store.ErrIdempotencyConflict,
		},
		{
			name: "leader ingress rate",
			input: &contenthttp.RemoteError{
				Code:      "leader_ingress_rate_limited",
				Retryable: true,
			},
			want: consensus.ErrProposalIngressRateLimited,
		},
		{
			name: "receiver proposal rate",
			input: &contenthttp.RemoteError{
				Code:      "proposal_rate_limited",
				Retryable: true,
			},
			want: consensus.ErrProposalForwardingUnavailable,
		},
		{
			name: "connection draining",
			input: &contenthttp.RemoteError{
				Code:      "connection_draining",
				Retryable: true,
			},
			want: consensus.ErrProposalForwardingUnavailable,
		},
		{
			name:  "protocol failure",
			input: sentinel,
			want:  sentinel,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeDaemonProposalForwardingError(test.input)
			if !errors.Is(got, test.want) {
				t.Fatalf(
					"normalizeDaemonProposalForwardingError() = %v, want %v",
					got,
					test.want,
				)
			}
		})
	}
	if err := normalizeDaemonProposalForwardingError(nil); err != nil {
		t.Fatalf("nil error normalized to %v", err)
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

func daemonContentPeerSignedAuthorization(
	t testing.TB,
	member device.Device,
	identityPrivateKey ed25519.PrivateKey,
	epochPrivateKey ed25519.PrivateKey,
	previous *credentialauthorization.Authorization,
	issuedAt time.Time,
	notBefore time.Time,
	chainIndex uint64,
) credentialauthorization.Authorization {
	t.Helper()
	epoch := uint64(1)
	if previous != nil {
		epoch = previous.Epoch + 1
	}
	binding, err := credential.SignBinding(
		daemonTestSessionID,
		member.ID,
		epoch,
		epochPrivateKey.Public().(ed25519.PublicKey),
		identityPrivateKey,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(): %v", err)
	}
	authorization := credentialauthorization.Authorization{
		SessionID:      binding.SessionID,
		DeviceID:       binding.DeviceID,
		Epoch:          binding.Epoch,
		EpochPublicKey: binding.EpochPublicKey,
		KeyDigest:      binding.KeyDigest,
		Role:           credentialauthorization.Role(member.Role),
		IssuedAt: domain.WholeSecondTimestamp(
			issuedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		),
		NotBefore: domain.WholeSecondTimestamp(
			notBefore.UTC().Truncate(time.Second).Format(time.RFC3339),
		),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: member.ID,
		}},
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: chainIndex,
	}
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		authorization,
	)
	if err != nil {
		t.Fatalf("CanonicalEndorsementPreimage(): %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		identityPrivateKey,
		codec.SignatureCredentialTimeEndorsement,
		preimage,
	)
	if err != nil {
		t.Fatalf("SignEd25519(endorsement): %v", err)
	}
	copy(authorization.ClockEndorsements[0].Signature[:], signature)
	clear(signature)
	if err := authorization.Validate(); err != nil {
		t.Fatalf("Authorization.Validate(): %v", err)
	}
	if err := credentialauthorization.ValidateTransition(
		previous,
		authorization,
	); err != nil {
		t.Fatalf("ValidateTransition(): %v", err)
	}
	return authorization
}

func daemonContentPeerConsensusStatusResponse(
	t testing.TB,
	serverDeviceID domain.DeviceID,
	authorization credentialauthorization.Authorization,
	recoveryGeneration uint64,
) transport.ConsensusControlResponse {
	t.Helper()
	endorsements := make(
		[]map[string]any,
		len(authorization.ClockEndorsements),
	)
	for index, endorsement := range authorization.ClockEndorsements {
		endorsements[index] = map[string]any{
			"device_id": string(endorsement.DeviceID),
			"signature": codec.EncodeBase64URL(
				endorsement.Signature[:],
			),
		}
	}
	encoded, err := json.Marshal(map[string]any{
		"schema_version":              uint64(1),
		"session_id":                  string(daemonTestSessionID),
		"recovery_generation":         recoveryGeneration,
		"server_device_id":            string(serverDeviceID),
		"local_term":                  uint64(1),
		"leader_device_id":            string(serverDeviceID),
		"quorum_required":             uint64(1),
		"last_raft_applied_log_index": uint64(1),
		"content_credential_authorization": map[string]any{
			"schema_version":              uint64(1),
			"session_id":                  string(authorization.SessionID),
			"device_id":                   string(authorization.DeviceID),
			"epoch":                       authorization.Epoch,
			"epoch_public_key":            codec.EncodeBase64URL(authorization.EpochPublicKey[:]),
			"key_digest":                  codec.EncodeBase64URL(authorization.KeyDigest[:]),
			"role":                        string(authorization.Role),
			"issued_at":                   string(authorization.IssuedAt),
			"not_before":                  string(authorization.NotBefore),
			"validity_seconds":            authorization.ValiditySeconds,
			"authority_voter_set_version": authorization.AuthorityVoterSetVersion,
			"clock_endorsements":          endorsements,
			"binding_signature": codec.EncodeBase64URL(
				authorization.BindingSignature[:],
			),
			"authorization_chain_index": authorization.AuthorizationChainIndex,
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal(consensus status): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(consensus status): %v", err)
	}
	return transport.ConsensusControlResponse{
		StatusCode: 200,
		MediaType:  "application/json",
		Body:       canonical,
	}
}
