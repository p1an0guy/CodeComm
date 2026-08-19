package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

type credentialAuthorizationTestOrigin struct {
	deviceID domain.DeviceID
	bootID   domain.UUIDv7

	mu             sync.Mutex
	authorizations []credentialauthorization.Authorization
	outcome        store.CommandOutcome
}

func (origin *credentialAuthorizationTestOrigin) DeviceID() domain.DeviceID {
	return origin.deviceID
}

func (origin *credentialAuthorizationTestOrigin) BootID() domain.UUIDv7 {
	return origin.bootID
}

func (origin *credentialAuthorizationTestOrigin) RunExclusive(
	ctx context.Context,
	operation func(CheckpointReservation) error,
) error {
	if ctx == nil || operation == nil {
		return ErrCheckpointOriginUnavailable
	}
	return errors.New("credential authorization test origin does not reserve checkpoints")
}

func (origin *credentialAuthorizationTestOrigin) SubmitCredentialAuthorization(
	ctx context.Context,
	authorization credentialauthorization.Authorization,
) (store.CommandOutcome, error) {
	if ctx == nil {
		return store.CommandOutcome{},
			ErrCredentialAuthorizationOriginUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.CommandOutcome{}, err
	}
	origin.mu.Lock()
	defer origin.mu.Unlock()
	origin.authorizations = append(
		origin.authorizations,
		authorization.Clone(),
	)
	return origin.outcome, nil
}

func (origin *credentialAuthorizationTestOrigin) submitted() []credentialauthorization.Authorization {
	origin.mu.Lock()
	defer origin.mu.Unlock()
	result := make(
		[]credentialauthorization.Authorization,
		len(origin.authorizations),
	)
	for index, authorization := range origin.authorizations {
		result[index] = authorization.Clone()
	}
	return result
}

type credentialAuthorizationTestTransport struct {
	RaftTransport
	request func(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error)
}

func (testTransport *credentialAuthorizationTestTransport) RequestConsensusProof(
	context.Context,
	domain.DeviceID,
	[]byte,
) (transport.ConsensusControlResponse, error) {
	return transport.ConsensusControlResponse{},
		ErrCheckpointProofUnavailable
}

func (testTransport *credentialAuthorizationTestTransport) RequestCredentialEndorsement(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	if testTransport == nil || testTransport.request == nil {
		return transport.ConsensusControlResponse{},
			ErrCredentialEndorsementUnavailable
	}
	return testTransport.request(ctx, deviceID, body)
}

type credentialAuthorizationFixture struct {
	node      *SingleNode
	origin    *credentialAuthorizationTestOrigin
	binding   credential.Binding
	localID   domain.DeviceID
	localKey  ed25519.PrivateKey
	private   map[domain.DeviceID]ed25519.PrivateKey
	remoteIDs []domain.DeviceID
	request   func(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error)
}

func TestAuthorizeCredentialCollectsThreeVoterMajorityConcurrently(
	t *testing.T,
) {
	fixture := openCredentialAuthorizationFixture(t)
	started := make(chan domain.DeviceID, len(fixture.remoteIDs))
	release := make(chan struct{})
	fixture.request = func(
		ctx context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		started <- deviceID
		select {
		case <-ctx.Done():
			return transport.ConsensusControlResponse{}, ctx.Err()
		case <-release:
			return credentialAuthorizationResponse(
				t,
				fixture.private[deviceID],
				deviceID,
				body,
			)
		}
	}

	type result struct {
		authorization credentialauthorization.Authorization
		outcome       store.CommandOutcome
		err           error
	}
	done := make(chan result, 1)
	go func() {
		authorization, outcome, err := fixture.node.AuthorizeCredential(
			testContext(t),
			fixture.binding,
		)
		done <- result{
			authorization: authorization,
			outcome:       outcome,
			err:           err,
		}
	}()
	for range fixture.remoteIDs {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("credential endorsements were not requested concurrently")
		}
	}
	close(release)
	got := <-done
	if got.err != nil {
		t.Fatalf("AuthorizeCredential(): %v", got.err)
	}
	if got.outcome.Status != store.OutcomeAccepted ||
		got.outcome.Code != string(reducer.CodeAccepted) ||
		len(got.authorization.ClockEndorsements) < 2 {
		t.Fatalf(
			"AuthorizeCredential() = (%#v, %#v)",
			got.authorization,
			got.outcome,
		)
	}
	for index := 1; index < len(got.authorization.ClockEndorsements); index++ {
		if got.authorization.ClockEndorsements[index-1].DeviceID >=
			got.authorization.ClockEndorsements[index].DeviceID {
			t.Fatalf(
				"endorsements are not sorted: %#v",
				got.authorization.ClockEndorsements,
			)
		}
	}
	if submitted := fixture.origin.submitted(); len(submitted) != 1 ||
		submitted[0].Epoch != fixture.binding.Epoch ||
		submitted[0].AuthorizationChainIndex != 0 {
		t.Fatalf("submitted authorizations = %#v", submitted)
	}
}

func TestAuthorizeCredentialNeverSubmitsWithMinority(t *testing.T) {
	fixture := openCredentialAuthorizationFixture(t)
	fixture.request = func(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error) {
		return transport.ConsensusControlResponse{},
			errors.New("peer unavailable")
	}

	_, _, err := fixture.node.AuthorizeCredential(
		testContext(t),
		fixture.binding,
	)
	if !errors.Is(err, ErrCredentialAuthorizationUnavailable) {
		t.Fatalf("AuthorizeCredential() error = %v", err)
	}
	if submitted := fixture.origin.submitted(); len(submitted) != 0 {
		t.Fatalf("minority submitted %#v", submitted)
	}
}

func TestAuthorizeCredentialRefusesNonleader(t *testing.T) {
	fixture := openCredentialAuthorizationFixture(t)
	var requests atomic.Int32
	fixture.request = func(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error) {
		requests.Add(1)
		return transport.ConsensusControlResponse{}, nil
	}
	fixture.node.readLeadershipEpoch = func() (raftLeadershipEpoch, error) {
		return raftLeadershipEpoch{}, raft.ErrNotLeader
	}

	_, _, err := fixture.node.AuthorizeCredential(
		testContext(t),
		fixture.binding,
	)
	if !errors.Is(err, raft.ErrNotLeader) {
		t.Fatalf("AuthorizeCredential() error = %v", err)
	}
	if requests.Load() != 0 || len(fixture.origin.submitted()) != 0 {
		t.Fatal("nonleader collected or submitted an authorization")
	}
}

func TestAuthorizeCredentialRejectsChangedStateCut(t *testing.T) {
	fixture := openCredentialAuthorizationFixture(t)
	changed := make(chan error, 1)
	var once sync.Once
	fixture.request = func(
		ctx context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		once.Do(func() {
			signed := nodeTestTaskEvent(
				t,
				fixture.localKey,
				fixture.localID,
				nodeTestBootID1,
				nodeTestEventID1,
				nodeTestTaskID1,
				nodeTestTimestamp1,
				1,
				"change credential cut",
			)
			_, err := fixture.node.Apply(ctx, signed)
			changed <- err
		})
		return credentialAuthorizationResponse(
			t,
			fixture.private[deviceID],
			deviceID,
			body,
		)
	}

	_, _, err := fixture.node.AuthorizeCredential(
		testContext(t),
		fixture.binding,
	)
	if applyErr := <-changed; applyErr != nil {
		t.Fatalf("Apply(cut change): %v", applyErr)
	}
	if !errors.Is(err, ErrCredentialAuthorizationUnavailable) {
		t.Fatalf("AuthorizeCredential() error = %v", err)
	}
	if submitted := fixture.origin.submitted(); len(submitted) != 0 {
		t.Fatalf("changed cut submitted %#v", submitted)
	}
}

func TestCredentialAuthorizationSuccessorTiming(t *testing.T) {
	t.Parallel()

	prior := credentialauthorization.Authorization{
		NotBefore:       "2026-08-18T12:00:00Z",
		ValiditySeconds: credentialauthorization.ValiditySeconds,
	}
	cut := credentialAuthorizationCut{
		subject:  device.Device{Role: device.RoleEditor},
		previous: &prior,
		state: decodedState{
			CredentialAuthority: credentialauthority.Authority{
				VoterSetVersion: 3,
			},
		},
	}
	binding := credential.Binding{
		SessionID: nodeTestSessionID,
		DeviceID:  checkpointProofDeviceID('8'),
		Epoch:     2,
	}
	for name, test := range map[string]struct {
		issuedAt      domain.WholeSecondTimestamp
		wantNotBefore domain.WholeSecondTimestamp
		wantErr       error
	}{
		"early renewal": {
			issuedAt: "2026-08-18T12:24:59Z",
			wantErr:  ErrCredentialRenewalTooEarly,
		},
		"renewal overlap": {
			issuedAt:      "2026-08-18T12:25:00Z",
			wantNotBefore: "2026-08-18T12:28:00Z",
		},
		"late renewal": {
			issuedAt:      "2026-08-19T09:00:00Z",
			wantNotBefore: "2026-08-19T09:00:00Z",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			authorization, err := buildCredentialAuthorization(
				binding,
				cut,
				test.issuedAt,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("buildCredentialAuthorization() error = %v", err)
			}
			if err == nil &&
				authorization.NotBefore != test.wantNotBefore {
				t.Fatalf(
					"not_before = %s, want %s",
					authorization.NotBefore,
					test.wantNotBefore,
				)
			}
		})
	}
}

func TestCredentialAuthorizationSemanticCutIgnoresRejectedResultBookkeeping(
	t *testing.T,
) {
	t.Parallel()

	left := credentialAuthorizationCut{
		leadership:        raftLeadershipEpoch{term: 4},
		sessionID:         nodeTestSessionID,
		workspaceID:       nodeTestWorkspaceID,
		recovery:          2,
		admissionRevision: 7,
		subject: device.Device{
			ID:                checkpointProofDeviceID('7'),
			Role:              device.RoleEditor,
			IdentityPublicKey: bytes.Repeat([]byte{7}, ed25519.PublicKeySize),
			Status:            device.StatusActive,
			EntityVersion:     3,
		},
		authorityIDs: []domain.DeviceID{checkpointProofDeviceID('6')},
		authorityKeys: map[domain.DeviceID]ed25519.PublicKey{
			checkpointProofDeviceID('6'): bytes.Repeat(
				[]byte{6},
				ed25519.PublicKeySize,
			),
		},
	}
	right := left
	right.heads.ResultIndex = 8
	right.projectionDigest[0] = 1
	right.admissionRevision++
	if sameCredentialAuthorizationCut(left, right) {
		t.Fatal("strict cut ignored result bookkeeping")
	}
	if !sameCredentialAuthorizationSemanticCut(left, right) {
		t.Fatal("semantic cut depended on rejected-command bookkeeping")
	}
}

func openCredentialAuthorizationFixture(
	t *testing.T,
) *credentialAuthorizationFixture {
	t.Helper()
	initial, localPrivate, localID := nodeTestInitialState(t)
	privateKeys := map[domain.DeviceID]ed25519.PrivateKey{
		localID: localPrivate,
	}
	devices := append([]device.Device(nil), initial.Projections.Devices...)
	counters := append(
		[]auditcounter.Counter(nil),
		initial.Projections.AuditCounters...,
	)
	for seed := byte(0xd1); seed <= 0xd2; seed++ {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{seed}, ed25519.SeedSize),
		)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		deviceID, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[deviceID] = privateKey
		devices = append(devices, device.Device{
			ID:                deviceID,
			Role:              device.RoleEditor,
			IdentityPublicKey: bytes.Clone(publicKey),
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		})
		counters = append(counters, auditcounter.Counter{
			DeviceID: deviceID,
		})
	}
	authorityIDs := make([]domain.DeviceID, 0, len(privateKeys))
	for deviceID := range privateKeys {
		authorityIDs = append(authorityIDs, deviceID)
	}
	sort.Slice(authorityIDs, func(left, right int) bool {
		return authorityIDs[left] < authorityIDs[right]
	})
	target, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{localID},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	initial.Projections.Devices = devices
	initial.Projections.AuditCounters = counters
	initial.Projections.VoterSet = []voterset.Set{target}
	initial.Projections.CredentialAuthority =
		[]store.CredentialAuthorityRow{{
			SessionID:        nodeTestSessionID,
			VoterDeviceIDs:   authorityIDs,
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}}

	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xe1}, ed25519.SeedSize),
	)
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		localID,
		1,
		epochPrivate.Public().(ed25519.PublicKey),
		localPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	origin := &credentialAuthorizationTestOrigin{
		deviceID: localID,
		bootID:   nodeTestBootID1,
		outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   string(reducer.CodeAccepted),
		},
	}
	checkpointSigner := CheckpointSignerAdapter{
		SignerDeviceID: localID,
		Sign: func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := ctx.Err(); err != nil {
				return store.Signature{}, err
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				localPrivate,
			)
			return store.Signature(signature), err
		},
	}
	credentialSigner := credentialAuthorizationSigner(
		t,
		localID,
		localPrivate,
	)
	root := t.TempDir()
	_, inMemory := raft.NewInmemTransport(raft.ServerAddress(localID))
	fixture := &credentialAuthorizationFixture{
		origin:    origin,
		binding:   binding,
		localID:   localID,
		localKey:  localPrivate,
		private:   privateKeys,
		remoteIDs: make([]domain.DeviceID, 0, 2),
	}
	for _, deviceID := range authorityIDs {
		if deviceID != localID {
			fixture.remoteIDs = append(fixture.remoteIDs, deviceID)
		}
	}
	wrapper := &credentialAuthorizationTestTransport{
		RaftTransport: inMemory,
		request: func(
			ctx context.Context,
			deviceID domain.DeviceID,
			body []byte,
		) (transport.ConsensusControlResponse, error) {
			return fixture.request(ctx, deviceID, body)
		},
	}
	node, err := openNode(context.Background(), nodeOpenOptions{
		ServerID:     localID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		BootstrapConfiguration: raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(localID),
			Address:  raft.ServerAddress(localID),
		}}},
		CheckpointSigner:            checkpointSigner,
		CredentialEndorsementSigner: credentialSigner,
		CheckpointOrigin:            origin,
		DisableVoterReconciliation:  true,
		Clock:                       nodeTestClock(),
		RaftConfig:                  nodeTestRaftConfig(),
		TransportFactory: func(ConsensusTransportGate) (
			RaftTransport,
			error,
		) {
			return wrapper, nil
		},
	})
	if err != nil {
		t.Fatalf("openNode(): %v", err)
	}
	fixture.node = node
	node.credentialEndorsementNow = func() time.Time {
		return time.Date(
			2026,
			time.August,
			18,
			12,
			0,
			0,
			0,
			time.UTC,
		)
	}
	t.Cleanup(func() {
		_ = node.Close()
		for _, privateKey := range privateKeys {
			clear(privateKey)
		}
		clear(epochPrivate)
	})
	if err := node.WaitForLeader(testContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
	if node.credentialAuthorizationOrigin != origin {
		t.Fatal("credential authorization origin was not wired from checkpoint origin")
	}
	return fixture
}

func credentialAuthorizationSigner(
	t *testing.T,
	deviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) CredentialEndorsementSigner {
	t.Helper()
	return CredentialEndorsementSignerAdapter{
		SignerDeviceID: deviceID,
		Sign: func(
			ctx context.Context,
			preimage []byte,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			raw, err := codecommcrypto.SignEd25519(
				privateKey,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
			)
			var signature [ed25519.SignatureSize]byte
			copy(signature[:], raw)
			return signature, err
		},
	}
}

func credentialAuthorizationResponse(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	t.Helper()
	request, err := decodeCredentialEndorsementRequest(body)
	if err != nil {
		return transport.ConsensusControlResponse{}, err
	}
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		request.authorization,
	)
	if err != nil {
		return transport.ConsensusControlResponse{}, err
	}
	raw, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureCredentialTimeEndorsement,
		preimage,
	)
	if err != nil {
		return transport.ConsensusControlResponse{}, err
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], raw)
	encoded, err := encodeCredentialEndorsementResponse(
		request,
		deviceID,
		signature,
	)
	if err != nil {
		return transport.ConsensusControlResponse{}, err
	}
	return transport.ConsensusControlResponse{
		StatusCode: 200,
		MediaType:  "application/json",
		Body:       encoded,
	}, nil
}

var (
	_ CheckpointOrigin               = (*credentialAuthorizationTestOrigin)(nil)
	_ CredentialAuthorizationOrigin  = (*credentialAuthorizationTestOrigin)(nil)
	_ credentialEndorsementRequester = (*credentialAuthorizationTestTransport)(nil)
	_ consensusProofRequester        = (*credentialAuthorizationTestTransport)(nil)
)
