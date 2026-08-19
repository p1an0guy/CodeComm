package credentialservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	serviceTestSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-0123456789ab",
	)
	serviceTestNowText = "2026-08-18T12:00:00Z"
)

type testSecretStore struct {
	mu      sync.Mutex
	values  map[string][]byte
	creates int
}

func newTestSecretStore() *testSecretStore {
	return &testSecretStore{values: make(map[string][]byte)}
}

func (store *testSecretStore) Get(
	ctx context.Context,
	reference credentialstore.Reference,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[reference.String()]
	if !exists {
		return nil, credentialstore.ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (store *testSecretStore) Create(
	ctx context.Context,
	reference credentialstore.Reference,
	value []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.values[reference.String()]; exists {
		return credentialstore.ErrAlreadyExists
	}
	store.values[reference.String()] = bytes.Clone(value)
	store.creates++
	return nil
}

func (store *testSecretStore) Delete(
	ctx context.Context,
	reference credentialstore.Reference,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	value := store.values[reference.String()]
	if value == nil {
		store.mu.Unlock()
		return credentialstore.ErrNotFound
	}
	clear(value)
	delete(store.values, reference.String())
	store.mu.Unlock()
	return nil
}

func (store *testSecretStore) has(reference credentialstore.Reference) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.values[reference.String()]
	return exists
}

type testConsensus struct {
	mu       sync.Mutex
	snapshot *peerauth.Snapshot
	renew    func(credential.Binding) (
		credentialauthorization.Authorization,
		error,
	)
	calls []credential.Binding
}

func (consensus *testConsensus) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	consensus.mu.Lock()
	defer consensus.mu.Unlock()
	return consensus.snapshot, nil
}

func (consensus *testConsensus) RenewCredential(
	ctx context.Context,
	binding credential.Binding,
) (credentialauthorization.Authorization, error) {
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	consensus.mu.Lock()
	consensus.calls = append(consensus.calls, binding)
	renew := consensus.renew
	consensus.mu.Unlock()
	if renew == nil {
		return credentialauthorization.Authorization{},
			errors.New("renew unavailable")
	}
	return renew(binding)
}

func (consensus *testConsensus) advance(
	t *testing.T,
	authorization credentialauthorization.Authorization,
) {
	t.Helper()
	consensus.mu.Lock()
	defer consensus.mu.Unlock()
	next, err := consensus.snapshot.Advance(peerauth.Changes{
		AdvancesEventChain: true,
		AuditCounters: []auditcounter.Counter{{
			DeviceID:        authorization.DeviceID,
			CredentialEpoch: authorization.Epoch,
		}},
		CredentialAuthorizations: []credentialauthorization.Authorization{
			authorization,
		},
	})
	if err != nil {
		t.Fatalf("Advance(): %v", err)
	}
	consensus.snapshot = next
}

type serviceFixture struct {
	service         *Service
	secrets         *testSecretStore
	consensus       *testConsensus
	identityPrivate ed25519.PrivateKey
	deviceID        domain.DeviceID
	now             time.Time
	generated       int
}

func TestInitialCredentialPersistsBeforeAuthorizationAndInstalls(
	t *testing.T,
) {
	fixture := newServiceFixture(t, nil)
	epochReference := serviceEpochReference(t, fixture.deviceID, 1)
	fixture.consensus.renew = func(
		binding credential.Binding,
	) (credentialauthorization.Authorization, error) {
		if !fixture.secrets.has(epochReference) {
			t.Fatal("renewal ran before candidate key persistence")
		}
		authorization := fixture.authorization(binding, fixture.now, 1)
		fixture.consensus.advance(t, authorization)
		return authorization, nil
	}

	next, transient, fatal := fixture.service.reconcile(t.Context())
	if !next.IsZero() || transient != nil || fatal != nil {
		t.Fatalf(
			"first reconcile = (%s, %v, %v)",
			next,
			transient,
			fatal,
		)
	}
	if fixture.generated != 1 || fixture.secrets.creates != 1 {
		t.Fatalf(
			"key generation/create = %d/%d, want 1/1",
			fixture.generated,
			fixture.secrets.creates,
		)
	}
	_, transient, fatal = fixture.service.reconcile(t.Context())
	if transient != nil || fatal != nil {
		t.Fatalf("second reconcile = (%v, %v)", transient, fatal)
	}
	certificate, err := fixture.service.ContentCertificate()
	if err != nil {
		t.Fatalf("ContentCertificate(): %v", err)
	}
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil ||
		parsed.Binding.DeviceID != fixture.deviceID ||
		parsed.Binding.Epoch != 1 ||
		parsed.Binding.AuthorizationChainIndex != 1 {
		t.Fatalf("installed certificate = (%#v, %v)", parsed, err)
	}
}

func TestTransientRenewalReusesPersistedCandidate(t *testing.T) {
	fixture := newServiceFixture(t, nil)
	transientFailure := errors.New("quorum unavailable")
	fixture.consensus.renew = func(
		credential.Binding,
	) (credentialauthorization.Authorization, error) {
		return credentialauthorization.Authorization{}, transientFailure
	}

	for attempt := 0; attempt < 2; attempt++ {
		_, transient, fatal := fixture.service.reconcile(t.Context())
		if !errors.Is(transient, transientFailure) || fatal != nil {
			t.Fatalf(
				"reconcile %d = (%v, %v)",
				attempt,
				transient,
				fatal,
			)
		}
	}
	if fixture.generated != 1 ||
		fixture.secrets.creates != 1 ||
		len(fixture.consensus.calls) != 2 ||
		fixture.consensus.calls[0] != fixture.consensus.calls[1] {
		t.Fatalf(
			"candidate reuse = generated %d, creates %d, calls %#v",
			fixture.generated,
			fixture.secrets.creates,
			fixture.consensus.calls,
		)
	}
}

func TestRenewalWaitsForFloorThenAllowsNextDayRecovery(t *testing.T) {
	initialPrivate := servicePrivateKey(0x61)
	fixture := newServiceFixture(t, initialPrivate)
	initialBinding := serviceBinding(
		t,
		fixture,
		1,
		initialPrivate.Public().(ed25519.PublicKey),
	)
	initial := fixture.authorization(initialBinding, fixture.now, 1)
	fixture.consensus.advance(t, initial)

	renewalAt := fixture.now.Add(
		time.Duration(
			credentialauthorization.ValiditySeconds-
				credentialauthorization.RenewalLeadSeconds,
		) * time.Second,
	)
	next, transient, fatal := fixture.service.reconcile(t.Context())
	if !next.Equal(renewalAt) || transient != nil || fatal != nil ||
		len(fixture.consensus.calls) != 0 {
		t.Fatalf(
			"early reconcile = (%s, %v, %v, calls=%d)",
			next,
			transient,
			fatal,
			len(fixture.consensus.calls),
		)
	}

	fixture.now = fixture.now.Add(24 * time.Hour)
	fixture.consensus.renew = func(
		binding credential.Binding,
	) (credentialauthorization.Authorization, error) {
		authorization := fixture.authorization(binding, fixture.now, 2)
		fixture.consensus.advance(t, authorization)
		return authorization, nil
	}
	_, transient, fatal = fixture.service.reconcile(t.Context())
	if transient != nil || fatal != nil ||
		len(fixture.consensus.calls) != 1 ||
		fixture.consensus.calls[0].Epoch != 2 {
		t.Fatalf(
			"late reconcile = (%v, %v, calls=%#v)",
			transient,
			fatal,
			fixture.consensus.calls,
		)
	}
	_, transient, fatal = fixture.service.reconcile(t.Context())
	if transient != nil || fatal != nil {
		t.Fatalf("late install reconcile = (%v, %v)", transient, fatal)
	}
	certificate, err := fixture.service.ContentCertificate()
	if err != nil {
		t.Fatalf("ContentCertificate(late): %v", err)
	}
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil || parsed.Binding.Epoch != 2 {
		t.Fatalf("late certificate = (%#v, %v)", parsed, err)
	}
}

func TestCertificateProviderSwitchesAtSuccessorActivation(t *testing.T) {
	firstPrivate := servicePrivateKey(0x68)
	fixture := newServiceFixture(t, firstPrivate)
	firstBinding := serviceBinding(
		t,
		fixture,
		1,
		firstPrivate.Public().(ed25519.PublicKey),
	)
	first := fixture.authorization(firstBinding, fixture.now, 1)
	fixture.consensus.advance(t, first)

	secondPrivate := servicePrivateKey(0x69)
	secondReference := serviceEpochReference(t, fixture.deviceID, 2)
	if err := fixture.secrets.Create(
		t.Context(),
		secondReference,
		secondPrivate,
	); err != nil {
		t.Fatal(err)
	}
	secondBinding := serviceBinding(
		t,
		fixture,
		2,
		secondPrivate.Public().(ed25519.PublicKey),
	)
	second := fixture.authorization(
		secondBinding,
		fixture.now.Add(25*time.Minute),
		2,
	)
	second.NotBefore = wholeSecond(fixture.now.Add(28 * time.Minute))
	fixture.consensus.advance(t, second)

	fixture.now = fixture.now.Add(27 * time.Minute)
	_, transient, fatal := fixture.service.reconcile(t.Context())
	if transient != nil || fatal != nil {
		t.Fatalf("overlap reconcile = (%v, %v)", transient, fatal)
	}
	assertServiceCertificateEpoch(t, fixture.service, 1)

	fixture.now = fixture.now.Add(time.Minute)
	assertServiceCertificateEpoch(t, fixture.service, 2)
	clear(secondPrivate)
}

func TestDiscoveryAdvertisementUsesLatestRetainedKeyAfterExpiry(
	t *testing.T,
) {
	epochPrivate := servicePrivateKey(0x6f)
	fixture := newServiceFixture(t, epochPrivate)
	binding := serviceBinding(
		t,
		fixture,
		1,
		epochPrivate.Public().(ed25519.PublicKey),
	)
	fixture.consensus.advance(
		t,
		fixture.authorization(binding, fixture.now, 1),
	)
	if _, transient, fatal := fixture.service.reconcile(t.Context()); transient != nil ||
		fatal != nil {
		t.Fatalf("reconcile = (%v, %v)", transient, fatal)
	}
	fixture.now = fixture.now.Add(24 * time.Hour)
	encoded, err := fixture.service.DiscoveryAdvertisement(47831)
	if err != nil {
		t.Fatalf("DiscoveryAdvertisement(): %v", err)
	}
	unverified, err := discovery.ParseAdvertisement(
		encoded,
		serviceTestSessionID,
	)
	if err != nil {
		t.Fatalf("ParseAdvertisement(): %v", err)
	}
	if err := unverified.ValidateTime(fixture.now); err != nil {
		t.Fatalf("ValidateTime(): %v", err)
	}
	verified, err := unverified.Verify(
		epochPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil ||
		verified.Advertisement().CredentialEpoch != 1 {
		t.Fatalf("Verify() = (%#v, %v)", verified, err)
	}
}

func TestMissingOrMismatchedEpochKeyFailsClosed(t *testing.T) {
	initialPrivate := servicePrivateKey(0x71)
	fixture := newServiceFixture(t, nil)
	binding := serviceBinding(
		t,
		fixture,
		1,
		initialPrivate.Public().(ed25519.PublicKey),
	)
	fixture.consensus.advance(
		t,
		fixture.authorization(binding, fixture.now, 1),
	)

	_, transient, fatal := fixture.service.reconcile(t.Context())
	if transient != nil || fatal != nil {
		t.Fatalf("missing-key reconcile = (%v, %v)", transient, fatal)
	}
	if _, err := fixture.service.ContentCertificate(); !errors.Is(
		err,
		transport.ErrContentCertificateUnavailable,
	) {
		t.Fatalf("missing-key provider error = %v", err)
	}

	reference := serviceEpochReference(t, fixture.deviceID, 1)
	wrong := servicePrivateKey(0x72)
	if err := fixture.secrets.Create(t.Context(), reference, wrong); err != nil {
		t.Fatal(err)
	}
	_, _, fatal = fixture.service.reconcile(t.Context())
	if !errors.Is(fatal, ErrCredentialIntegrity) {
		t.Fatalf("mismatched-key fatal = %v", fatal)
	}
}

func TestRevocationErasesRetainedAndCandidateKeys(t *testing.T) {
	currentPrivate := servicePrivateKey(0x73)
	fixture := newServiceFixture(t, currentPrivate)
	binding := serviceBinding(
		t,
		fixture,
		1,
		currentPrivate.Public().(ed25519.PublicKey),
	)
	fixture.consensus.advance(
		t,
		fixture.authorization(binding, fixture.now, 1),
	)
	if _, transient, fatal := fixture.service.reconcile(t.Context()); transient != nil ||
		fatal != nil {
		t.Fatalf("active reconcile = (%v, %v)", transient, fatal)
	}
	assertServiceCertificateEpoch(t, fixture.service, 1)

	candidateReference := serviceEpochReference(t, fixture.deviceID, 2)
	candidatePrivate := servicePrivateKey(0x74)
	if err := fixture.secrets.Create(
		t.Context(),
		candidateReference,
		candidatePrivate,
	); err != nil {
		t.Fatal(err)
	}
	clear(candidatePrivate)

	member, found := fixture.consensus.snapshot.Member(fixture.deviceID)
	if !found {
		t.Fatal("local member absent")
	}
	member.Status = device.StatusRevoked
	member.EntityVersion++
	fixture.consensus.mu.Lock()
	next, err := fixture.consensus.snapshot.Advance(peerauth.Changes{
		AdvancesEventChain: true,
		Devices:            []device.Device{member},
	})
	if err == nil {
		fixture.consensus.snapshot = next
	}
	fixture.consensus.mu.Unlock()
	if err != nil {
		t.Fatalf("revoke snapshot: %v", err)
	}

	callsBefore := len(fixture.consensus.calls)
	if _, transient, fatal := fixture.service.reconcile(t.Context()); transient != nil ||
		fatal != nil {
		t.Fatalf("revoked reconcile = (%v, %v)", transient, fatal)
	}
	if _, transient, fatal := fixture.service.reconcile(t.Context()); transient != nil ||
		fatal != nil {
		t.Fatalf("repeated revoked reconcile = (%v, %v)", transient, fatal)
	}
	for _, epoch := range []uint64{1, 2} {
		if fixture.secrets.has(
			serviceEpochReference(t, fixture.deviceID, epoch),
		) {
			t.Fatalf("revoked epoch %d key remains", epoch)
		}
	}
	if len(fixture.consensus.calls) != callsBefore {
		t.Fatal("revoked service attempted credential renewal")
	}
	if _, err := fixture.service.ContentCertificate(); !errors.Is(
		err,
		transport.ErrContentCertificateUnavailable,
	) {
		t.Fatalf("revoked certificate provider error = %v", err)
	}
	if _, err := fixture.service.DiscoveryAdvertisement(47831); !errors.Is(
		err,
		discovery.ErrInvalidAdvertisement,
	) {
		t.Fatalf("revoked discovery advertisement error = %v", err)
	}
}

func newServiceFixture(
	t *testing.T,
	initialEpochKey ed25519.PrivateKey,
) *serviceFixture {
	t.Helper()
	now, err := time.Parse(time.RFC3339, serviceTestNowText)
	if err != nil {
		t.Fatal(err)
	}
	identityPrivate := servicePrivateKey(0x41)
	deviceID, err := device.DeriveID(
		identityPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:         serviceTestSessionID,
		AppliedChainIndex: 0,
		Devices: map[domain.DeviceID]device.Device{
			deviceID: {
				ID:   deviceID,
				Role: device.RoleOwner,
				IdentityPublicKey: bytes.Clone(
					identityPrivate.Public().(ed25519.PublicKey),
				),
				DaemonVersion: "0.1.0",
				MaxApplyLevel: 1,
				Status:        device.StatusActive,
				EntityVersion: 1,
			},
		},
		AuditCounters: map[domain.DeviceID]auditcounter.Counter{
			deviceID: {DeviceID: deviceID},
		},
		CredentialAuthorizations: map[credentialauthorization.Key]credentialauthorization.Authorization{},
	})
	if err != nil {
		t.Fatal(err)
	}
	secrets := newTestSecretStore()
	if initialEpochKey != nil {
		reference := serviceEpochReference(t, deviceID, 1)
		if err := secrets.Create(
			t.Context(),
			reference,
			initialEpochKey,
		); err != nil {
			t.Fatal(err)
		}
	}
	consensus := &testConsensus{snapshot: snapshot}
	fixture := &serviceFixture{
		secrets:         secrets,
		consensus:       consensus,
		identityPrivate: identityPrivate,
		deviceID:        deviceID,
		now:             now,
	}
	service, err := newService(serviceOptions{
		Options: Options{
			SessionID: serviceTestSessionID,
			DeviceID:  deviceID,
			Secrets:   secrets,
			Consensus: consensus,
			Sign: func(
				ctx context.Context,
				epoch uint64,
				publicKey ed25519.PublicKey,
			) (credential.Binding, error) {
				if err := ctx.Err(); err != nil {
					return credential.Binding{}, err
				}
				return credential.SignBinding(
					serviceTestSessionID,
					deviceID,
					epoch,
					publicKey,
					identityPrivate,
				)
			},
		},
		now: func() time.Time {
			return fixture.now
		},
		generateKey: func() (ed25519.PrivateKey, error) {
			fixture.generated++
			return servicePrivateKey(
				byte(0x50 + fixture.generated),
			), nil
		},
		retryInitial: time.Millisecond,
		retryMaximum: 10 * time.Millisecond,
		pollInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	t.Cleanup(func() {
		_ = service.Close()
		clear(identityPrivate)
		clear(initialEpochKey)
	})
	return fixture
}

func (fixture *serviceFixture) authorization(
	binding credential.Binding,
	at time.Time,
	chainIndex uint64,
) credentialauthorization.Authorization {
	endorser := fixture.deviceID
	return credentialauthorization.Authorization{
		SessionID:                binding.SessionID,
		DeviceID:                 binding.DeviceID,
		Epoch:                    binding.Epoch,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 wholeSecond(at),
		NotBefore:                wholeSecond(at),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: endorser,
		}},
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: chainIndex,
	}
}

func serviceBinding(
	t *testing.T,
	fixture *serviceFixture,
	epoch uint64,
	publicKey ed25519.PublicKey,
) credential.Binding {
	t.Helper()
	binding, err := credential.SignBinding(
		serviceTestSessionID,
		fixture.deviceID,
		epoch,
		publicKey,
		fixture.identityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func serviceEpochReference(
	t *testing.T,
	deviceID domain.DeviceID,
	epoch uint64,
) credentialstore.Reference {
	t.Helper()
	reference, err := credentialstore.EpochReference(
		serviceTestSessionID,
		deviceID,
		epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func servicePrivateKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
}

func wholeSecond(value time.Time) domain.WholeSecondTimestamp {
	return domain.WholeSecondTimestamp(
		value.UTC().Truncate(time.Second).Format(time.RFC3339),
	)
}

func assertServiceCertificateEpoch(
	t *testing.T,
	service *Service,
	want uint64,
) {
	t.Helper()
	certificate, err := service.ContentCertificate()
	if err != nil {
		t.Fatalf("ContentCertificate(): %v", err)
	}
	defer clearTLSCertificate(&certificate)
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil || parsed.Binding.Epoch != want {
		t.Fatalf(
			"certificate epoch = (%d, %v), want %d",
			parsed.Binding.Epoch,
			err,
			want,
		)
	}
}

var (
	_ SecretStore = (*testSecretStore)(nil)
	_ Consensus   = (*testConsensus)(nil)
)
