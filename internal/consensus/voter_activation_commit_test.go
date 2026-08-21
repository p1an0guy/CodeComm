package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

type voterActivationCommitOrigin struct {
	*checkpointCommitOrigin

	node *SingleNode

	mu       sync.Mutex
	payloads []voteractivation.ActivationPayload
}

func (origin *voterActivationCommitOrigin) SubmitVoterSetActivation(
	ctx context.Context,
	payload voteractivation.ActivationPayload,
) (store.CommandOutcome, error) {
	if origin == nil ||
		origin.checkpointCommitOrigin == nil ||
		origin.node == nil ||
		ctx == nil {
		return store.CommandOutcome{},
			ErrVoterActivationOriginUnavailable
	}
	if err := ctx.Err(); err != nil {
		return store.CommandOutcome{}, err
	}
	encoded, err := voteractivation.EncodeActivationPayload(payload)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	select {
	case origin.exclusive <- struct{}{}:
		defer func() { <-origin.exclusive }()
	case <-ctx.Done():
		return store.CommandOutcome{}, ctx.Err()
	}
	authority, err := event.NewLocalAuthority(
		origin.deviceID,
		origin.bootID,
	)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		return store.CommandOutcome{}, err
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindMembershipVoterSetActivated,
			EntityID: event.StringEntityID(string(nodeTestSessionID)),
			Actions:  []event.Action{},
			Payload:  encoded,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        checkpointCommitRetryEventID,
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      nodeTestTimestamp1,
			OriginSequence: origin.nextSequence,
		},
	)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	signed, err := event.Sign(proposal, origin.private)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	origin.nextSequence++
	result, err := origin.node.Apply(ctx, signed)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	origin.mu.Lock()
	origin.payloads = append(origin.payloads, payload)
	origin.mu.Unlock()
	return result.Outcome, nil
}

func TestReconcileVoterSetActivatesExactTargetThroughDurableOrigin(
	t *testing.T,
) {
	node, origin := openVoterActivationCommitNode(t)

	if err := node.ReconcileVoterSet(testContext(t)); err != nil {
		t.Fatalf("ReconcileVoterSet(): %v", err)
	}
	if err := node.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(): %v", err)
	}
	view, err := node.state.View(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeStateView(view)
	if err != nil {
		t.Fatal(err)
	}
	if state.CredentialAuthority.VoterSetVersion != 2 ||
		!credentialAuthorityMatchesTarget(state) ||
		state.CredentialAuthority.ActivationCheckpointEventID !=
			checkpointCommitEventID {
		t.Fatalf(
			"activated authority = %#v",
			state.CredentialAuthority,
		)
	}
	origin.mu.Lock()
	payloads := append(
		[]voteractivation.ActivationPayload(nil),
		origin.payloads...,
	)
	origin.mu.Unlock()
	if len(payloads) != 1 {
		t.Fatalf("activation submissions = %d, want 1", len(payloads))
	}
	input := payloads[0].UnsignedHandoff().Input()
	if input.TargetVoterSetVersion != 2 ||
		input.ExpectedAuthorityVoterSetVersion != 1 ||
		len(input.VoterSet) != 1 ||
		input.VoterSet[0] != origin.deviceID ||
		len(input.ActivationProofs) != 1 ||
		input.ActivationProofs[0].VoterDeviceID() != origin.deviceID {
		t.Fatalf("activation payload = %#v", input)
	}

	if err := node.ReconcileVoterSet(testContext(t)); err != nil {
		t.Fatalf("stable ReconcileVoterSet(): %v", err)
	}
	origin.mu.Lock()
	submissions := len(origin.payloads)
	origin.mu.Unlock()
	if submissions != 1 {
		t.Fatalf("stable reconciliation resubmitted activation %d times", submissions)
	}
}

func TestReconcileVoterSetPreflightsBeforeTopologyMutation(t *testing.T) {
	fixture := openConfigurationChangeFixture(t, true)
	before := raftConfiguration(t, fixture.node)

	err := fixture.node.ReconcileVoterSet(testContext(t))
	if !errors.Is(err, ErrVoterReconciliationUnavailable) {
		t.Fatalf("ReconcileVoterSet() error = %v", err)
	}
	after := raftConfiguration(t, fixture.node)
	if after.Index != before.Index ||
		!sameRaftConfiguration(after.Configuration, before.Configuration) {
		t.Fatal("failed reconciliation preflight changed topology")
	}
}

func TestReconcileVoterSetReusesActivationAttemptAfterHandoffFailure(
	t *testing.T,
) {
	node, origin := openVoterActivationCommitNode(t)
	baseSigner := node.voterActivationSigner
	handoffAttempts := 0
	proofAttempts := 0
	node.voterActivationSigner = VoterActivationSignerAdapter{
		SignerDeviceID: origin.deviceID,
		SignProof: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			proofAttempts++
			return baseSigner.SignVoterActivationProof(ctx, unsigned)
		},
		SignHandoff: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			handoffAttempts++
			if handoffAttempts == 1 {
				return [ed25519.SignatureSize]byte{},
					errConsensusVoterActivationSignerUnavailable
			}
			return baseSigner.SignVoterAuthorityHandoff(ctx, unsigned)
		},
	}

	err := node.ReconcileVoterSet(testContext(t))
	if !errors.Is(err, ErrVoterReconciliationStalled) ||
		!errors.Is(err, errConsensusVoterActivationSignerUnavailable) {
		t.Fatalf("first ReconcileVoterSet() error = %v", err)
	}
	if node.voterActivationAttempt == nil ||
		len(node.voterActivationAttempt.proofs) != 1 {
		t.Fatal("failed handoff discarded the activation attempt")
	}
	if origin.nextSequence != 2 {
		t.Fatalf(
			"origin sequence after failed handoff = %d, want 2",
			origin.nextSequence,
		)
	}

	if err := node.ReconcileVoterSet(testContext(t)); err != nil {
		t.Fatalf("second ReconcileVoterSet(): %v", err)
	}
	if proofAttempts != 1 {
		t.Fatalf("target proof attempts = %d, want 1", proofAttempts)
	}
	if handoffAttempts != 2 {
		t.Fatalf("handoff attempts = %d, want 2", handoffAttempts)
	}
	if origin.nextSequence != 3 {
		t.Fatalf(
			"origin sequence after activation = %d, want 3",
			origin.nextSequence,
		)
	}
}

func TestAuthorityHandoffFallsBackAfterBlackholedSigner(t *testing.T) {
	fixture := newVoterActivationProtocolFixture(t)
	privateKeys := make(map[domain.DeviceID]ed25519.PrivateKey, 3)
	publicKeys := make(map[domain.DeviceID]ed25519.PublicKey, 3)
	devices := make(map[domain.DeviceID]device.Device, 3)
	counters := make(map[domain.DeviceID]auditcounter.Counter, 3)
	signerIDs := make([]domain.DeviceID, 0, 3)
	for _, seed := range []byte{0x51, 0x52, 0x53} {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{seed}, ed25519.SeedSize),
		)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		deviceID, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[deviceID] = privateKey
		publicKeys[deviceID] = bytes.Clone(publicKey)
		devices[deviceID] = device.Device{
			ID:                deviceID,
			Role:              device.RoleOwner,
			IdentityPublicKey: bytes.Clone(publicKey),
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		}
		counters[deviceID] = auditcounter.Counter{DeviceID: deviceID}
		signerIDs = append(signerIDs, deviceID)
	}
	sort.Slice(signerIDs, func(left, right int) bool {
		return signerIDs[left] < signerIDs[right]
	})
	t.Cleanup(func() {
		for _, privateKey := range privateKeys {
			clear(privateKey)
		}
		for _, publicKey := range publicKeys {
			clear(publicKey)
		}
	})
	admission, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:          nodeTestSessionID,
		RecoveryGeneration: 0,
		AppliedChainIndex:  0,
		Devices:            devices,
		AuditCounters:      counters,
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        nodeTestSessionID,
			VoterDeviceIDs:   append([]domain.DeviceID(nil), signerIDs...),
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		CredentialAuthorizations: map[credentialauthorization.Key]credentialauthorization.Authorization{},
	})
	if err != nil {
		t.Fatalf("peerauth.NewSnapshot(): %v", err)
	}
	target, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{fixture.targetDeviceID},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	state := decodedState{
		Admission: admission,
		VoterSet:  target,
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        nodeTestSessionID,
			VoterDeviceIDs:   append([]domain.DeviceID(nil), signerIDs...),
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		recoveryGeneration: 0,
		workspaceID:        nodeTestWorkspaceID,
		identityPublicKeys: publicKeys,
	}
	leadership := raftLeadershipEpoch{term: 3}
	var attempts []domain.DeviceID
	node := &SingleNode{
		serverID: raft.ServerID(checkpointProofDeviceID('9')),
		readLeadershipEpoch: func() (raftLeadershipEpoch, error) {
			return leadership, nil
		},
	}
	node.checkpointRequester = checkpointProofRequesterFunc(func(
		ctx context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		attempts = append(attempts, deviceID)
		if deviceID == signerIDs[0] {
			<-ctx.Done()
			return transport.ConsensusControlResponse{}, ctx.Err()
		}
		request, err := decodeAuthorityHandoffRequest(body)
		if err != nil {
			return transport.ConsensusControlResponse{}, err
		}
		payload, err := voteractivation.SignAuthorityHandoff(
			request.unsigned,
			privateKeys[deviceID],
		)
		if err != nil {
			return transport.ConsensusControlResponse{}, err
		}
		expectation, err := newAuthorityHandoffExpectation(
			deviceID,
			request.unsigned,
			publicKeys[deviceID],
		)
		if err != nil {
			return transport.ConsensusControlResponse{}, err
		}
		encoded, err := encodeAuthorityHandoffResponse(
			payload,
			expectation,
		)
		if err != nil {
			return transport.ConsensusControlResponse{}, err
		}
		return transport.ConsensusControlResponse{
			StatusCode: 200,
			MediaType:  "application/json",
			Body:       encoded,
		}, nil
	})

	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
	defer cancel()
	payload, err := node.collectAuthorityHandoff(
		ctx,
		leadership,
		state,
		[]voteractivation.Proof{fixture.proof},
		fixture.unsignedProof.Input().CheckpointEventID,
	)
	if err != nil {
		t.Fatalf("collectAuthorityHandoff(): %v", err)
	}
	if len(attempts) != 2 ||
		attempts[0] != signerIDs[0] ||
		attempts[1] != signerIDs[1] ||
		payload.UnsignedHandoff().Input().PriorAuthoritySigner !=
			signerIDs[1] {
		t.Fatalf(
			"handoff attempts = %v, signer = %q",
			attempts,
			payload.UnsignedHandoff().Input().PriorAuthoritySigner,
		)
	}
}

func TestAutomaticVoterReconciliationActivatesAndStopsWithNode(
	t *testing.T,
) {
	node, _ := openVoterActivationCommitNode(t)
	node.startVoterReconciliation()
	if node.voterReconcileDone == nil {
		t.Fatal("complete node did not start voter reconciliation")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		view, err := node.state.View(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeStateView(view)
		if err != nil {
			t.Fatal(err)
		}
		if credentialAuthorityMatchesTarget(state) {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("automatic voter reconciliation did not activate target")
		case <-ticker.C:
		}
	}
	done := node.voterReconcileDone
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("voter reconciliation goroutine leaked after Close")
	}
}

func TestAutomaticVoterReconciliationReportsMissingCapabilities(
	t *testing.T,
) {
	fixture := openConfigurationChangeFixture(t, true)
	fixture.node.startVoterReconciliation()
	if fixture.node.voterReconcileDone == nil {
		t.Fatal("incomplete node did not start voter reconciliation")
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, err := fixture.node.Status(t.Context())
		if err != nil {
			t.Fatalf("Status(): %v", err)
		}
		if snapshot.Runtime.ReconciliationBlocker ==
			coordstatus.ReconciliationBlockerCapabilityDisabled {
			if snapshot.Runtime.ConfigurationReconciled ||
				snapshot.Runtime.ReconciliationState !=
					coordstatus.ReconciliationPending ||
				snapshot.Runtime.ReconciliationStep !=
					coordstatus.ReconciliationStepObserve {
				t.Fatalf(
					"missing-capability status = %#v",
					snapshot.Runtime,
				)
			}
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf(
				"missing capabilities were not reported: %#v",
				snapshot.Runtime,
			)
		case <-ticker.C:
		}
	}
}

func openVoterActivationCommitNode(
	t *testing.T,
) (*SingleNode, *voterActivationCommitOrigin) {
	t.Helper()
	return openVoterActivationCommitNodeWithInitial(t, nil)
}

func openVoterActivationCommitNodeWithInitial(
	t *testing.T,
	mutate func(*store.InitialState),
) (*SingleNode, *voterActivationCommitOrigin) {
	t.Helper()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	if mutate != nil {
		mutate(&initial)
	}
	target, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{deviceID},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	initial.Projections.VoterSet = []voterset.Set{target}

	baseOrigin := &checkpointCommitOrigin{
		deviceID:     deviceID,
		bootID:       nodeTestBootID1,
		private:      bytes.Clone(privateKey),
		eventID:      checkpointCommitEventID,
		createdAt:    nodeTestTimestamp1,
		exclusive:    make(chan struct{}, 1),
		nextSequence: 1,
	}
	origin := &voterActivationCommitOrigin{
		checkpointCommitOrigin: baseOrigin,
	}
	checkpointSigner := CheckpointSignerAdapter{
		SignerDeviceID: deviceID,
		Sign: func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := ctx.Err(); err != nil {
				return store.Signature{}, err
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				privateKey,
			)
			return store.Signature(signature), err
		},
	}
	activationSigner := VoterActivationSignerAdapter{
		SignerDeviceID: deviceID,
		SignProof: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			proof, err := voteractivation.SignProof(
				unsigned,
				privateKey,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return proof.VoterSignature(), nil
		},
		SignHandoff: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			payload, err := voteractivation.SignAuthorityHandoff(
				unsigned,
				privateKey,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return payload.HandoffSignature(), nil
		},
	}
	collector := &configurationCoverageCollector{
		privateKeys: map[domain.DeviceID]ed25519.PrivateKey{
			deviceID: privateKey,
		},
	}
	root := t.TempDir()
	_, raftTransport := raft.NewInmemTransport(
		raft.ServerAddress(deviceID),
	)
	node, err := openNode(context.Background(), nodeOpenOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		BootstrapConfiguration: raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(deviceID),
			Address:  raft.ServerAddress(deviceID),
		}}},
		CanonicalCoverage:          collector,
		ConfigurationReadiness:     configurationReadinessProvider{},
		DisableVoterReconciliation: true,
		CheckpointSigner:           checkpointSigner,
		VoterActivationSigner:      activationSigner,
		Clock:                      nodeTestClock(),
		RaftConfig:                 nodeTestRaftConfig(),
		TransportFactory: func(ConsensusTransportGate) (
			RaftTransport,
			error,
		) {
			return raftTransport, nil
		},
	})
	if err != nil {
		t.Fatalf("OpenNode(): %v", err)
	}
	origin.node = node
	node.checkpointOrigin = origin
	node.voterActivationOrigin = origin
	node.checkpointRequester = checkpointProofRequesterFunc(func(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error) {
		return transport.ConsensusControlResponse{},
			ErrVoterActivationProofUnavailable
	})
	t.Cleanup(func() {
		_ = node.Close()
		clear(privateKey)
		clear(baseOrigin.private)
	})
	if err := node.WaitForLeader(testContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
	return node, origin
}

var _ VoterActivationOrigin = (*voterActivationCommitOrigin)(nil)
