package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestNodeConfigurationReadinessProviderBindsConnectionGeneration(
	t *testing.T,
) {
	fixture := newConfigurationReadinessProviderFixture(t)
	candidate, err := fixture.gate.collect(
		t.Context(),
		fixture.requirement,
	)
	if err != nil {
		t.Fatalf("collect(): %v", err)
	}
	if !sameDeviceIDs(
		candidate.candidate.ReachableDeviceIDs,
		fixture.deviceIDs,
	) {
		t.Fatalf(
			"reachable devices = %v, want %v",
			candidate.candidate.ReachableDeviceIDs,
			fixture.deviceIDs,
		)
	}
	token, err := decodeConfigurationReadinessToken(
		candidate.candidate.Token,
	)
	if err != nil {
		t.Fatalf("decodeConfigurationReadinessToken(): %v", err)
	}
	localIndex := sort.Search(
		len(token.reachability),
		func(index int) bool {
			return token.reachability[index].DeviceID >=
				fixture.localDeviceID
		},
	)
	if localIndex == 0 ||
		localIndex >= len(token.reachability) ||
		token.reachability[localIndex].DeviceID != fixture.localDeviceID ||
		token.reachability[localIndex].Generation != 0 {
		t.Fatalf(
			"local reachability token = %#v at index %d",
			token.reachability,
			localIndex,
		)
	}
	if err := fixture.gate.verifyCurrent(
		fixture.requirement,
		candidate,
	); err != nil {
		t.Fatalf("verifyCurrent(): %v", err)
	}
	probesBefore := fixture.reachability.probeCount()

	remoteID := fixture.deviceIDs[0]
	fixture.reachability.replace(remoteID)
	if err := fixture.gate.verifyCurrent(
		fixture.requirement,
		candidate,
	); !errors.Is(err, ErrConfigurationReadinessChanged) {
		t.Fatalf("verifyCurrent(replaced connection) error = %v", err)
	}
	if probesAfter := fixture.reachability.probeCount(); probesAfter != probesBefore {
		t.Fatalf(
			"freshness verification performed I/O: probes %d -> %d",
			probesBefore,
			probesAfter,
		)
	}
}

func TestNodeConfigurationReadinessProviderInvalidatesCredentialChanges(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*configurationReadinessProviderFixture)
	}{
		{
			name: "expiry",
			mutate: func(fixture *configurationReadinessProviderFixture) {
				fixture.now = fixture.notBefore.Add(
					time.Duration(
						credentialauthorization.ValiditySeconds,
					) * time.Second,
				)
			},
		},
		{
			name: "replacement",
			mutate: func(fixture *configurationReadinessProviderFixture) {
				fixture.epochs[fixture.deviceIDs[0]] = 2
				fixture.rebuildAdmission(t)
			},
		},
		{
			name: "revocation",
			mutate: func(fixture *configurationReadinessProviderFixture) {
				fixture.statuses[fixture.deviceIDs[0]] =
					device.StatusRevoked
				fixture.rebuildAdmission(t)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newConfigurationReadinessProviderFixture(t)
			candidate, err := fixture.gate.collect(
				t.Context(),
				fixture.requirement,
			)
			if err != nil {
				t.Fatalf("collect(): %v", err)
			}
			test.mutate(fixture)
			if err := fixture.gate.verifyCurrent(
				fixture.requirement,
				candidate,
			); !errors.Is(err, ErrConfigurationReadinessChanged) {
				t.Fatalf("verifyCurrent() error = %v", err)
			}
		})
	}
}

func TestNodeConfigurationReadinessProviderUsesOverlapPredecessor(
	t *testing.T,
) {
	fixture := newConfigurationReadinessProviderFixture(t)
	fixture.now = fixture.notBefore.Add(27 * time.Minute)
	verified, err := fixture.gate.collect(t.Context(), fixture.requirement)
	if err != nil {
		t.Fatalf("collect(predecessor): %v", err)
	}

	subject := fixture.deviceIDs[0]
	fixture.epochs[subject] = 2
	fixture.authorizationTimes[2] = configurationAuthorizationTimes{
		issuedAt:  fixture.notBefore.Add(25 * time.Minute),
		notBefore: fixture.notBefore.Add(28 * time.Minute),
	}
	fixture.rebuildAdmission(t)
	if err := fixture.gate.verifyCurrent(
		fixture.requirement,
		verified,
	); err != nil {
		t.Fatalf("verifyCurrent(overlap predecessor): %v", err)
	}
	token, err := decodeConfigurationReadinessToken(
		verified.candidate.Token,
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentialEpochForDevice(token.credentials, subject) != 1 {
		t.Fatalf(
			"overlap credential epoch = %d, want 1",
			credentialEpochForDevice(token.credentials, subject),
		)
	}

	fixture.now = fixture.notBefore.Add(28 * time.Minute)
	if err := fixture.gate.verifyCurrent(
		fixture.requirement,
		verified,
	); !errors.Is(err, ErrConfigurationReadinessChanged) {
		t.Fatalf("verifyCurrent(successor activation) error = %v", err)
	}
	fresh, err := fixture.gate.collect(t.Context(), fixture.requirement)
	if err != nil {
		t.Fatalf("collect(successor): %v", err)
	}
	freshToken, err := decodeConfigurationReadinessToken(
		fresh.candidate.Token,
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentialEpochForDevice(freshToken.credentials, subject) != 2 {
		t.Fatalf(
			"active credential epoch = %d, want 2",
			credentialEpochForDevice(freshToken.credentials, subject),
		)
	}
}

func TestNodeConfigurationReadinessProviderFailsClosed(t *testing.T) {
	fixture := newConfigurationReadinessProviderFixture(t)
	fixture.admissionErr = errors.New("admission unavailable")
	if _, err := fixture.gate.collect(
		t.Context(),
		fixture.requirement,
	); !errors.Is(err, fixture.admissionErr) {
		t.Fatalf("collect(admission unavailable) error = %v", err)
	}

	fixture = newConfigurationReadinessProviderFixture(t)
	fixture.localReachable = false
	if _, err := fixture.gate.collect(
		t.Context(),
		fixture.requirement,
	); !errors.Is(err, ErrConfigurationQuorumUnavailable) {
		t.Fatalf("collect(local unavailable) error = %v", err)
	}
}

type configurationAuthorizationTimes struct {
	issuedAt  time.Time
	notBefore time.Time
}

type configurationReadinessProviderFixture struct {
	gate               *configurationReadinessGate
	provider           *nodeConfigurationReadinessProvider
	reachability       *configurationReadinessReachability
	requirement        ConfigurationReadinessRequirement
	deviceIDs          []domain.DeviceID
	localDeviceID      domain.DeviceID
	identityKeys       map[domain.DeviceID]ed25519.PrivateKey
	epochs             map[domain.DeviceID]uint64
	statuses           map[domain.DeviceID]device.Status
	admission          *peerauth.Snapshot
	admissionErr       error
	localReachable     bool
	now                time.Time
	notBefore          time.Time
	authorizationTimes map[uint64]configurationAuthorizationTimes
	appliedChainIndex  uint64
}

func newConfigurationReadinessProviderFixture(
	t *testing.T,
) *configurationReadinessProviderFixture {
	t.Helper()
	identityKeys := make(map[domain.DeviceID]ed25519.PrivateKey, 3)
	deviceIDs := make([]domain.DeviceID, 0, 3)
	for _, value := range []byte{0x81, 0x82, 0x83} {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{value}, ed25519.SeedSize),
		)
		deviceID, err := device.DeriveID(
			privateKey.Public().(ed25519.PublicKey),
		)
		if err != nil {
			t.Fatalf("device.DeriveID(): %v", err)
		}
		identityKeys[deviceID] = privateKey
		deviceIDs = append(deviceIDs, deviceID)
	}
	sort.Slice(deviceIDs, func(left, right int) bool {
		return deviceIDs[left] < deviceIDs[right]
	})
	localDeviceID := deviceIDs[1]
	notBefore := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture := &configurationReadinessProviderFixture{
		reachability: newConfigurationReadinessReachability(
			deviceIDs,
			localDeviceID,
		),
		deviceIDs:      deviceIDs,
		localDeviceID:  localDeviceID,
		identityKeys:   identityKeys,
		epochs:         make(map[domain.DeviceID]uint64, 3),
		statuses:       make(map[domain.DeviceID]device.Status, 3),
		localReachable: true,
		now:            notBefore.Add(5 * time.Minute),
		notBefore:      notBefore,
		authorizationTimes: map[uint64]configurationAuthorizationTimes{
			1: {
				issuedAt:  notBefore,
				notBefore: notBefore,
			},
		},
		appliedChainIndex: 1,
	}
	for _, id := range deviceIDs {
		fixture.epochs[id] = 1
		fixture.statuses[id] = device.StatusActive
	}
	fixture.rebuildAdmission(t)
	fixture.requirement = ConfigurationReadinessRequirement{
		SessionID:                nodeTestSessionID,
		RecoveryGeneration:       0,
		TargetVoterSetVersion:    1,
		TargetVoterDeviceIDs:     append([]domain.DeviceID(nil), deviceIDs...),
		ConfigurationIndex:       1,
		LiveVoterDeviceIDs:       append([]domain.DeviceID(nil), deviceIDs...),
		LiveNonvoterDeviceIDs:    []domain.DeviceID{},
		ActiveDeviceIDs:          append([]domain.DeviceID(nil), deviceIDs...),
		PostChangeVoterDeviceIDs: append([]domain.DeviceID(nil), deviceIDs...),
		RequiredPostChangeQuorum: 2,
		Operation:                ConfigurationObserve,
		SubjectDeviceID:          localDeviceID,
	}
	fixture.provider = &nodeConfigurationReadinessProvider{
		admissionSnapshot: func() (*peerauth.Snapshot, error) {
			return fixture.admission, fixture.admissionErr
		},
		localDeviceID: localDeviceID,
		localReachable: func() bool {
			return fixture.localReachable
		},
		reachability: fixture.reachability,
		now: func() time.Time {
			return fixture.now
		},
	}
	fixture.gate = newConfigurationReadinessGate(fixture.provider)
	t.Cleanup(func() {
		for _, key := range identityKeys {
			clear(key)
		}
	})
	return fixture
}

func (fixture *configurationReadinessProviderFixture) rebuildAdmission(
	t *testing.T,
) {
	t.Helper()
	devices := make(map[domain.DeviceID]device.Device, len(fixture.deviceIDs))
	counters := make(
		map[domain.DeviceID]auditcounter.Counter,
		len(fixture.deviceIDs),
	)
	authorizations := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		len(fixture.deviceIDs)*2,
	)
	var maxEpoch uint64
	for _, id := range fixture.deviceIDs {
		privateKey := fixture.identityKeys[id]
		devices[id] = device.Device{
			ID:   id,
			Role: device.RoleOwner,
			IdentityPublicKey: bytes.Clone(
				privateKey.Public().(ed25519.PublicKey),
			),
			DaemonVersion: "0.1.0",
			MaxApplyLevel: 1,
			Status:        fixture.statuses[id],
			EntityVersion: 1,
		}
		epoch := fixture.epochs[id]
		counters[id] = auditcounter.Counter{
			DeviceID:        id,
			CredentialEpoch: epoch,
		}
		if epoch > maxEpoch {
			maxEpoch = epoch
		}
		for value := uint64(1); value <= epoch; value++ {
			authorization := fixture.authorization(id, value)
			authorizations[authorization.PrimaryKey()] = authorization
		}
	}
	fixture.appliedChainIndex = maxEpoch
	snapshot, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:                nodeTestSessionID,
		RecoveryGeneration:       0,
		AppliedChainIndex:        fixture.appliedChainIndex,
		Devices:                  devices,
		AuditCounters:            counters,
		CredentialAuthorizations: authorizations,
	})
	if err != nil {
		t.Fatalf("peerauth.NewSnapshot(): %v", err)
	}
	fixture.admission = snapshot
}

func (fixture *configurationReadinessProviderFixture) authorization(
	id domain.DeviceID,
	epoch uint64,
) credentialauthorization.Authorization {
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat(
			[]byte{byte(0x90 + epoch)},
			ed25519.SeedSize,
		),
	)
	publicKey := epochPrivate.Public().(ed25519.PublicKey)
	times, exists := fixture.authorizationTimes[epoch]
	if !exists {
		times = configurationAuthorizationTimes{
			issuedAt:  fixture.notBefore,
			notBefore: fixture.notBefore,
		}
	}
	authorization := credentialauthorization.Authorization{
		SessionID: nodeTestSessionID,
		DeviceID:  id,
		Epoch:     epoch,
		Role:      credentialauthorization.RoleOwner,
		IssuedAt: domain.WholeSecondTimestamp(
			times.issuedAt.Format(time.RFC3339),
		),
		NotBefore: domain.WholeSecondTimestamp(
			times.notBefore.Format(time.RFC3339),
		),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: fixture.localDeviceID,
		}},
		AuthorizationChainIndex: epoch,
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	authorization.KeyDigest = sha256.Sum256(publicKey)
	clear(epochPrivate)
	return authorization
}

func credentialEpochForDevice(
	tokens []configurationCredentialToken,
	deviceID domain.DeviceID,
) uint64 {
	for _, token := range tokens {
		if token.deviceID == deviceID {
			return token.epoch
		}
	}
	return 0
}

type configurationReadinessReachability struct {
	mu          sync.Mutex
	generations map[domain.DeviceID]uint64
	probes      int
}

func newConfigurationReadinessReachability(
	deviceIDs []domain.DeviceID,
	local domain.DeviceID,
) *configurationReadinessReachability {
	generations := make(map[domain.DeviceID]uint64, len(deviceIDs)-1)
	for _, id := range deviceIDs {
		if id != local {
			generations[id] = 1
		}
	}
	return &configurationReadinessReachability{
		generations: generations,
	}
}

func (reachability *configurationReadinessReachability) ProbeConsensusPeer(
	ctx context.Context,
	id domain.DeviceID,
) (transport.ConsensusPeerReachabilityToken, error) {
	if err := ctx.Err(); err != nil {
		return transport.ConsensusPeerReachabilityToken{}, err
	}
	reachability.mu.Lock()
	defer reachability.mu.Unlock()
	reachability.probes++
	generation, exists := reachability.generations[id]
	if !exists {
		return transport.ConsensusPeerReachabilityToken{},
			transport.ErrConsensusPeerUnreachable
	}
	return transport.ConsensusPeerReachabilityToken{
		DeviceID:   id,
		Generation: generation,
	}, nil
}

func (reachability *configurationReadinessReachability) VerifyConsensusPeerReachability(
	token transport.ConsensusPeerReachabilityToken,
) error {
	reachability.mu.Lock()
	defer reachability.mu.Unlock()
	if reachability.generations[token.DeviceID] != token.Generation {
		return transport.ErrConsensusReachabilityTokenStale
	}
	return nil
}

func (reachability *configurationReadinessReachability) replace(
	id domain.DeviceID,
) {
	reachability.mu.Lock()
	reachability.generations[id]++
	reachability.mu.Unlock()
}

func (reachability *configurationReadinessReachability) probeCount() int {
	reachability.mu.Lock()
	defer reachability.mu.Unlock()
	return reachability.probes
}

var _ consensusPeerReachability = (*configurationReadinessReachability)(nil)
