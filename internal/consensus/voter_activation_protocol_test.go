package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

type voterActivationProtocolFixture struct {
	targetPrivate    ed25519.PrivateKey
	targetPublic     ed25519.PublicKey
	targetDeviceID   domain.DeviceID
	authorityPrivate ed25519.PrivateKey
	authorityPublic  ed25519.PublicKey
	authorityID      domain.DeviceID
	unsignedProof    voteractivation.UnsignedProof
	proof            voteractivation.Proof
	unsignedHandoff  voteractivation.UnsignedAuthorityHandoff
	payload          voteractivation.ActivationPayload
}

func TestVoterActivationProtocolRoundTripsClosedCanonicalMessages(
	t *testing.T,
) {
	t.Parallel()

	fixture := newVoterActivationProtocolFixture(t)
	targetExpectation, err := newTargetActivationExpectation(
		fixture.targetDeviceID,
		fixture.unsignedProof,
		fixture.targetPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	targetRequest, err := encodeTargetActivationRequest(targetExpectation)
	if err != nil {
		t.Fatalf("encodeTargetActivationRequest(): %v", err)
	}
	if mode, err := decodeConsensusProofMode(targetRequest); err != nil ||
		mode != consensusProofModeTargetActivation {
		t.Fatalf("decode target mode = (%q, %v)", mode, err)
	}
	decodedTarget, err := decodeTargetActivationRequest(targetRequest)
	if err != nil ||
		decodedTarget.targetDeviceID != fixture.targetDeviceID ||
		!bytes.Equal(
			decodedTarget.unsigned.CanonicalBytes(),
			fixture.unsignedProof.CanonicalBytes(),
		) {
		t.Fatalf("decode target request = (%#v, %v)", decodedTarget, err)
	}
	targetResponse, err := encodeTargetActivationResponse(
		fixture.proof,
		targetExpectation,
	)
	if err != nil {
		t.Fatalf("encodeTargetActivationResponse(): %v", err)
	}
	if _, err := decodeTargetActivationResponse(
		targetResponse,
		targetExpectation,
	); err != nil {
		t.Fatalf("decodeTargetActivationResponse(): %v", err)
	}

	handoffExpectation, err := newAuthorityHandoffExpectation(
		fixture.authorityID,
		fixture.unsignedHandoff,
		fixture.authorityPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	handoffRequest, err := encodeAuthorityHandoffRequest(handoffExpectation)
	if err != nil {
		t.Fatalf("encodeAuthorityHandoffRequest(): %v", err)
	}
	if mode, err := decodeConsensusProofMode(handoffRequest); err != nil ||
		mode != consensusProofModeAuthorityHandoff {
		t.Fatalf("decode handoff mode = (%q, %v)", mode, err)
	}
	decodedHandoff, err := decodeAuthorityHandoffRequest(handoffRequest)
	if err != nil ||
		decodedHandoff.signerDeviceID != fixture.authorityID ||
		!bytes.Equal(
			decodedHandoff.unsigned.CanonicalBytes(),
			fixture.unsignedHandoff.CanonicalBytes(),
		) {
		t.Fatalf("decode handoff request = (%#v, %v)", decodedHandoff, err)
	}
	handoffResponse, err := encodeAuthorityHandoffResponse(
		fixture.payload,
		handoffExpectation,
	)
	if err != nil {
		t.Fatalf("encodeAuthorityHandoffResponse(): %v", err)
	}
	if _, err := decodeAuthorityHandoffResponse(
		handoffResponse,
		handoffExpectation,
	); err != nil {
		t.Fatalf("decodeAuthorityHandoffResponse(): %v", err)
	}

	var targetMembers map[string]json.RawMessage
	if err := json.Unmarshal(targetRequest, &targetMembers); err != nil {
		t.Fatal(err)
	}
	targetMembers["future"] = json.RawMessage(`true`)
	unknown, err := json.Marshal(targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err = codec.CanonicalizeSignedObject(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTargetActivationRequest(unknown); !errors.Is(
		err,
		ErrInvalidVoterActivationProof,
	) {
		t.Fatalf("unknown target request field error = %v", err)
	}
	noncanonical := append([]byte(" "), handoffRequest...)
	if _, err := decodeAuthorityHandoffRequest(noncanonical); !errors.Is(
		err,
		ErrInvalidVoterActivationProof,
	) {
		t.Fatalf("noncanonical handoff request error = %v", err)
	}
}

func TestVoterActivationResponsesRequireExactRequestedSignedObjects(
	t *testing.T,
) {
	t.Parallel()

	fixture := newVoterActivationProtocolFixture(t)
	targetExpectation, err := newTargetActivationExpectation(
		fixture.targetDeviceID,
		fixture.unsignedProof,
		fixture.targetPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	targetResponse, err := encodeTargetActivationResponse(
		fixture.proof,
		targetExpectation,
	)
	if err != nil {
		t.Fatal(err)
	}
	var targetWire targetActivationResponseWire
	if err := json.Unmarshal(targetResponse, &targetWire); err != nil {
		t.Fatal(err)
	}
	tamperedProof, err := voteractivation.NewProof(
		fixture.unsignedProof,
		[ed25519.SignatureSize]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	targetWire.Proof = tamperedProof.CanonicalBytes()
	tamperedTarget, err := marshalCanonicalConsensusProof(targetWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTargetActivationResponse(
		tamperedTarget,
		targetExpectation,
	); !errors.Is(err, ErrVoterActivationProofMismatch) {
		t.Fatalf("tampered target response error = %v", err)
	}

	handoffExpectation, err := newAuthorityHandoffExpectation(
		fixture.authorityID,
		fixture.unsignedHandoff,
		fixture.authorityPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	handoffResponse, err := encodeAuthorityHandoffResponse(
		fixture.payload,
		handoffExpectation,
	)
	if err != nil {
		t.Fatal(err)
	}
	var handoffWire authorityHandoffResponseWire
	if err := json.Unmarshal(handoffResponse, &handoffWire); err != nil {
		t.Fatal(err)
	}
	tamperedPayload, err := voteractivation.NewActivationPayload(
		fixture.unsignedHandoff,
		[ed25519.SignatureSize]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	handoffWire.ActivationPayload, err =
		voteractivation.EncodeActivationPayload(tamperedPayload)
	if err != nil {
		t.Fatal(err)
	}
	tamperedHandoff, err := marshalCanonicalConsensusProof(handoffWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAuthorityHandoffResponse(
		tamperedHandoff,
		handoffExpectation,
	); !errors.Is(err, ErrVoterActivationProofMismatch) {
		t.Fatalf("tampered handoff response error = %v", err)
	}
}

func TestVoterActivationRequesterVerifiesSuccessAndClassifiesProblems(
	t *testing.T,
) {
	t.Parallel()

	fixture := newVoterActivationProtocolFixture(t)
	expectation, err := newTargetActivationExpectation(
		fixture.targetDeviceID,
		fixture.unsignedProof,
		fixture.targetPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := encodeTargetActivationResponse(
		fixture.proof,
		expectation,
	)
	if err != nil {
		t.Fatal(err)
	}
	requester := checkpointProofRequesterFunc(func(
		_ context.Context,
		target domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		if target != fixture.targetDeviceID {
			t.Fatalf("target = %q", target)
		}
		if _, err := decodeTargetActivationRequest(body); err != nil {
			t.Fatalf("request body: %v", err)
		}
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       responseBody,
		}, nil
	})
	if _, err := requestTargetActivationProof(
		t.Context(),
		requester,
		expectation,
	); err != nil {
		t.Fatalf("requestTargetActivationProof(): %v", err)
	}

	for _, test := range []struct {
		name      string
		status    int
		code      string
		title     string
		retryable bool
		want      error
	}{
		{
			name:      "retryable",
			status:    http.StatusServiceUnavailable,
			code:      "proof_unavailable",
			title:     "Proof service unavailable",
			retryable: true,
			want:      ErrVoterActivationProofUnavailable,
		},
		{
			name:   "terminal",
			status: http.StatusConflict,
			code:   "checkpoint_mismatch",
			title:  "Checkpoint mismatch",
			want:   ErrVoterActivationProofRejected,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			problem, err := json.Marshal(consensusProofProblem{
				Type:          "urn:codecomm:problem:" + test.code,
				Title:         test.title,
				Status:        test.status,
				Code:          test.code,
				CorrelationID: "018f47de-89ab-7def-8123-0123456789ab",
				Retryable:     test.retryable,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = requestTargetActivationProof(
				t.Context(),
				checkpointProofRequesterFunc(func(
					context.Context,
					domain.DeviceID,
					[]byte,
				) (transport.ConsensusControlResponse, error) {
					return transport.ConsensusControlResponse{
						StatusCode: test.status,
						MediaType:  "application/problem+json",
						Body:       problem,
					}, nil
				}),
				expectation,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("request error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVoterActivationSignerAdapterBindsDeviceAndContext(t *testing.T) {
	t.Parallel()

	fixture := newVoterActivationProtocolFixture(t)
	called := false
	adapter := VoterActivationSignerAdapter{
		SignerDeviceID: fixture.targetDeviceID,
		SignProof: func(
			context.Context,
			voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			called = true
			return fixture.proof.VoterSignature(), nil
		},
		SignHandoff: func(
			context.Context,
			voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			return [ed25519.SignatureSize]byte{}, nil
		},
	}
	if _, err := adapter.SignVoterActivationProof(
		t.Context(),
		fixture.unsignedProof,
	); err != nil || !called {
		t.Fatalf("SignVoterActivationProof() = (called=%t, %v)", called, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	called = false
	if _, err := adapter.SignVoterActivationProof(
		canceled,
		fixture.unsignedProof,
	); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled signer = (called=%t, %v)", called, err)
	}

	wrong := adapter
	wrong.SignerDeviceID = fixture.authorityID
	if _, err := wrong.SignVoterActivationProof(
		t.Context(),
		fixture.unsignedProof,
	); !errors.Is(err, ErrInvalidVoterActivationSigner) {
		t.Fatalf("wrong-device proof signer error = %v", err)
	}
	if _, err := adapter.SignVoterAuthorityHandoff(
		t.Context(),
		fixture.unsignedHandoff,
	); !errors.Is(err, ErrInvalidVoterActivationSigner) {
		t.Fatalf("wrong-device handoff signer error = %v", err)
	}
}

func newVoterActivationProtocolFixture(
	t *testing.T,
) voterActivationProtocolFixture {
	t.Helper()
	targetPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x41}, ed25519.SeedSize),
	)
	authorityPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x42}, ed25519.SeedSize),
	)
	targetPublic := targetPrivate.Public().(ed25519.PublicKey)
	authorityPublic := authorityPrivate.Public().(ed25519.PublicKey)
	targetDeviceID, err := device.DeriveID(targetPublic)
	if err != nil {
		t.Fatal(err)
	}
	authorityID, err := device.DeriveID(authorityPublic)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := domain.Checkpoint{
		SessionID:                nodeTestSessionID,
		WorkspaceID:              nodeTestWorkspaceID,
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           authorityID,
		Term:                     3,
		CoveredAppliedLogIndex:   8,
		CoveredChainIndex:        4,
		CoveredChainHash:         [32]byte{0x51},
		CoveredResultIndex:       5,
		CoveredResultHash:        [32]byte{0x61},
		ProjectionAccumulator:    [32]byte{0x71},
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	checkpointJSON, err := event.EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointSignatureBytes, err := codecommcrypto.SignEd25519(
		authorityPrivate,
		codec.SignatureCheckpoint,
		checkpointJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	var checkpointSignature [ed25519.SignatureSize]byte
	copy(checkpointSignature[:], checkpointSignatureBytes)
	unsignedProof, err := voteractivation.NewUnsignedProof(
		voteractivation.ProofInput{
			SessionID:                       nodeTestSessionID,
			WorkspaceID:                     nodeTestWorkspaceID,
			RecoveryGeneration:              0,
			TargetVoterSetVersion:           2,
			CurrentAuthorityVoterSetVersion: 1,
			VoterSet:                        []domain.DeviceID{targetDeviceID},
			VoterDeviceID:                   targetDeviceID,
			LiveConfigurationIndex:          7,
			CheckpointEventID: domain.UUIDv7(
				"018f47de-89ab-7def-8123-7123456789ab",
			),
			Checkpoint:          checkpoint,
			CheckpointSignature: checkpointSignature,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := voteractivation.SignProof(unsignedProof, targetPrivate)
	if err != nil {
		t.Fatal(err)
	}
	unsignedHandoff, err := voteractivation.NewUnsignedAuthorityHandoff(
		voteractivation.AuthorityHandoffInput{
			SessionID:                        nodeTestSessionID,
			WorkspaceID:                      nodeTestWorkspaceID,
			RecoveryGeneration:               0,
			TargetVoterSetVersion:            2,
			ExpectedAuthorityVoterSetVersion: 1,
			VoterSet:                         []domain.DeviceID{targetDeviceID},
			ActivationCheckpointEventID: domain.UUIDv7(
				"018f47de-89ab-7def-8123-7123456789ab",
			),
			ActivationProofs:     []voteractivation.Proof{proof},
			PriorAuthoritySigner: authorityID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := voteractivation.SignAuthorityHandoff(
		unsignedHandoff,
		authorityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return voterActivationProtocolFixture{
		targetPrivate:    targetPrivate,
		targetPublic:     targetPublic,
		targetDeviceID:   targetDeviceID,
		authorityPrivate: authorityPrivate,
		authorityPublic:  authorityPublic,
		authorityID:      authorityID,
		unsignedProof:    unsignedProof,
		proof:            proof,
		unsignedHandoff:  unsignedHandoff,
		payload:          payload,
	}
}
