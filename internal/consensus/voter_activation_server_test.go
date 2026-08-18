package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

type voterActivationServerFixture struct {
	node          *SingleNode
	privateKey    ed25519.PrivateKey
	deviceID      domain.DeviceID
	peer          transport.AuthenticatedPeer
	authority     stagingProofAuthority
	checkpoint    store.AppliedCheckpointLookup
	unsignedProof voteractivation.UnsignedProof
	proofCalls    int
	handoffCalls  int
	mutateProof   func(context.Context) error
	invalidProof  bool
}

func TestVoterActivationServerSignsVerifiedTargetAndHandoff(t *testing.T) {
	fixture := openVoterActivationServerFixture(t)

	proof, expectation, err := fixture.node.proveTargetActivation(
		t.Context(),
		fixture.peer,
		targetActivationRequest{
			targetDeviceID: fixture.deviceID,
			unsigned:       fixture.unsignedProof,
		},
		fixture.authority,
	)
	if err != nil ||
		fixture.proofCalls != 1 ||
		voteractivation.VerifyProof(
			proof,
			fixture.privateKey.Public().(ed25519.PublicKey),
		) != nil ||
		!bytes.Equal(
			expectation.unsigned.CanonicalBytes(),
			fixture.unsignedProof.CanonicalBytes(),
		) {
		t.Fatalf(
			"proveTargetActivation() = (%#v, %#v, %v), calls=%d",
			proof,
			expectation,
			err,
			fixture.proofCalls,
		)
	}
	unsignedHandoff, err := voteractivation.NewUnsignedAuthorityHandoff(
		voteractivation.AuthorityHandoffInput{
			SessionID:                        nodeTestSessionID,
			WorkspaceID:                      nodeTestWorkspaceID,
			RecoveryGeneration:               0,
			TargetVoterSetVersion:            2,
			ExpectedAuthorityVoterSetVersion: 1,
			VoterSet:                         []domain.DeviceID{fixture.deviceID},
			ActivationCheckpointEventID: fixture.checkpoint.
				Record.CheckpointEventID,
			ActivationProofs:     []voteractivation.Proof{proof},
			PriorAuthoritySigner: fixture.deviceID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, handoffExpectation, err := fixture.node.proveAuthorityHandoff(
		t.Context(),
		fixture.peer,
		authorityHandoffRequest{
			signerDeviceID: fixture.deviceID,
			unsigned:       unsignedHandoff,
		},
		fixture.authority,
	)
	if err != nil ||
		fixture.handoffCalls != 1 ||
		voteractivation.VerifyAuthorityHandoff(
			payload,
			fixture.privateKey.Public().(ed25519.PublicKey),
		) != nil ||
		!bytes.Equal(
			handoffExpectation.unsigned.CanonicalBytes(),
			unsignedHandoff.CanonicalBytes(),
		) {
		t.Fatalf(
			"proveAuthorityHandoff() = (%#v, %#v, %v), calls=%d",
			payload,
			handoffExpectation,
			err,
			fixture.handoffCalls,
		)
	}
}

func TestVoterActivationServerFailsClosedBeforeAndAfterSigning(
	t *testing.T,
) {
	t.Run("stale exact configuration", func(t *testing.T) {
		fixture := openVoterActivationServerFixture(t)
		input := fixture.unsignedProof.Input()
		input.LiveConfigurationIndex++
		stale, err := voteractivation.NewUnsignedProof(input)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = fixture.node.proveTargetActivation(
			t.Context(),
			fixture.peer,
			targetActivationRequest{
				targetDeviceID: fixture.deviceID,
				unsigned:       stale,
			},
			fixture.authority,
		)
		if !errors.Is(err, errConsensusProofStale) ||
			fixture.proofCalls != 0 {
			t.Fatalf("stale proof = (calls=%d, %v)", fixture.proofCalls, err)
		}
	})

	t.Run("invalid signer output", func(t *testing.T) {
		fixture := openVoterActivationServerFixture(t)
		fixture.invalidProof = true
		_, _, err := fixture.node.proveTargetActivation(
			t.Context(),
			fixture.peer,
			targetActivationRequest{
				targetDeviceID: fixture.deviceID,
				unsigned:       fixture.unsignedProof,
			},
			fixture.authority,
		)
		if !errors.Is(err, errConsensusVoterActivationSignerInvalid) {
			t.Fatalf("invalid signer output error = %v", err)
		}
	})

	t.Run("state changes while signing", func(t *testing.T) {
		fixture := openVoterActivationServerFixture(t)
		fixture.mutateProof = func(ctx context.Context) error {
			taskEvent := nodeTestTaskEvent(
				t,
				fixture.privateKey,
				fixture.deviceID,
				nodeTestBootID1,
				domain.UUIDv7(
					"018f47de-89ab-7def-8123-7323456789ab",
				),
				domain.UUIDv7(
					"018f47de-89ab-7def-8123-7423456789ab",
				),
				nodeTestTimestamp1,
				2,
				"change activation cut",
			)
			result, err := fixture.node.Apply(ctx, taskEvent)
			if err != nil {
				return err
			}
			if result.Outcome.Status != store.OutcomeAccepted {
				return errors.New("mutation was rejected")
			}
			return nil
		}
		_, _, err := fixture.node.proveTargetActivation(
			t.Context(),
			fixture.peer,
			targetActivationRequest{
				targetDeviceID: fixture.deviceID,
				unsigned:       fixture.unsignedProof,
			},
			fixture.authority,
		)
		if !errors.Is(err, ErrConsensusAuthorizationUnavailable) {
			t.Fatalf("changed signing cut error = %v", err)
		}
	})

	t.Run("requester is not current leader", func(t *testing.T) {
		fixture := openVoterActivationServerFixture(t)
		wrongPeer := fixture.peer
		wrongPeer.DeviceID = checkpointProofDeviceID('9')
		_, _, err := fixture.node.proveTargetActivation(
			t.Context(),
			wrongPeer,
			targetActivationRequest{
				targetDeviceID: fixture.deviceID,
				unsigned:       fixture.unsignedProof,
			},
			fixture.authority,
		)
		if !errors.Is(err, errConsensusProofDenied) ||
			fixture.proofCalls != 0 {
			t.Fatalf("unauthorized proof = (calls=%d, %v)", fixture.proofCalls, err)
		}
	})
}

func openVoterActivationServerFixture(
	t *testing.T,
) *voterActivationServerFixture {
	t.Helper()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	target, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{deviceID},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	initial.Projections.VoterSet = []voterset.Set{target}

	fixture := &voterActivationServerFixture{
		privateKey: bytes.Clone(privateKey),
		deviceID:   deviceID,
	}
	origin := &checkpointCommitOrigin{
		deviceID:     deviceID,
		bootID:       nodeTestBootID1,
		private:      bytes.Clone(privateKey),
		eventID:      checkpointCommitEventID,
		createdAt:    nodeTestTimestamp1,
		exclusive:    make(chan struct{}, 1),
		nextSequence: 1,
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
			signature, err := event.SignCheckpoint(checkpoint, privateKey)
			return store.Signature(signature), err
		},
	}
	activationSigner := VoterActivationSignerAdapter{
		SignerDeviceID: deviceID,
		SignProof: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			fixture.proofCalls++
			if fixture.mutateProof != nil {
				mutate := fixture.mutateProof
				fixture.mutateProof = nil
				if err := mutate(ctx); err != nil {
					return [ed25519.SignatureSize]byte{}, err
				}
			}
			if fixture.invalidProof {
				return [ed25519.SignatureSize]byte{}, nil
			}
			proof, err := voteractivation.SignProof(unsigned, privateKey)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return proof.VoterSignature(), nil
		},
		SignHandoff: func(
			_ context.Context,
			unsigned voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			fixture.handoffCalls++
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
	root := t.TempDir()
	node, err := OpenSingleNode(
		context.Background(),
		SingleNodeOptions{
			ServerID:              deviceID,
			StatePath:             filepath.Join(root, "state", "state.db"),
			ConsensusDir:          filepath.Join(root, "consensus"),
			OriginBootID:          nodeTestBootID1,
			InitialState:          &initial,
			CheckpointSigner:      checkpointSigner,
			VoterActivationSigner: activationSigner,
			CheckpointOrigin:      origin,
			Clock:                 nodeTestClock(),
			RaftConfig:            nodeTestRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	fixture.node = node
	t.Cleanup(func() {
		_ = node.Close()
		clear(fixture.privateKey)
		clear(origin.private)
	})
	waitForNodeLeader(t, node)
	checkpoint, err := node.ForceCheckpoint(testContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	fixture.checkpoint = checkpoint
	configuration := node.fsm.committedConfiguration()
	if configuration == nil {
		t.Fatal("missing committed configuration")
	}
	checkpointValue, err := event.DecodeCheckpoint(
		checkpoint.Record.CheckpointJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.unsignedProof, err = voteractivation.NewUnsignedProof(
		voteractivation.ProofInput{
			SessionID:                       nodeTestSessionID,
			WorkspaceID:                     nodeTestWorkspaceID,
			RecoveryGeneration:              0,
			TargetVoterSetVersion:           2,
			CurrentAuthorityVoterSetVersion: 1,
			VoterSet:                        []domain.DeviceID{deviceID},
			VoterDeviceID:                   deviceID,
			LiveConfigurationIndex:          configuration.Index,
			CheckpointEventID: checkpoint.Record.
				CheckpointEventID,
			Checkpoint: checkpointValue,
			CheckpointSignature: [ed25519.SignatureSize]byte(
				checkpoint.Record.AuthoritySignature,
			),
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedProof(): %v", err)
	}
	fixture.peer = transport.AuthenticatedPeer{
		Plane:              transport.PlaneConsensus,
		SessionID:          nodeTestSessionID,
		DeviceID:           deviceID,
		RecoveryGeneration: 0,
	}
	fixture.authority, err = node.consensusProofRequesterAuthority(
		fixture.peer,
	)
	if err != nil {
		t.Fatalf("consensusProofRequesterAuthority(): %v", err)
	}
	return fixture
}
