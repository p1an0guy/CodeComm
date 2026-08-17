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
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestCheckpointSignRequestRoundTripsExactTuple(t *testing.T) {
	t.Parallel()

	expectation, _ := checkpointSigningTestExpectation(t)
	encoded, err := encodeCheckpointSignRequest(expectation)
	if err != nil {
		t.Fatalf("encodeCheckpointSignRequest(): %v", err)
	}
	mode, err := decodeConsensusProofMode(encoded)
	if err != nil || mode != consensusProofModeCheckpointSign {
		t.Fatalf("decodeConsensusProofMode() = (%q, %v)", mode, err)
	}
	request, err := decodeCheckpointSignRequest(encoded)
	if err != nil {
		t.Fatalf("decodeCheckpointSignRequest(): %v", err)
	}
	if request.checkpoint != expectation.checkpoint ||
		!bytes.Equal(
			request.checkpointJSON,
			expectation.checkpointJSON,
		) {
		t.Fatalf("decoded request = %#v", request)
	}

	var wire checkpointSignRequestWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.SignerDeviceID = string(checkpointProofDeviceID('9'))
	mismatched, err := marshalCanonicalConsensusProof(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCheckpointSignRequest(mismatched); !errors.Is(
		err,
		ErrInvalidCheckpointProof,
	) {
		t.Fatalf("mismatched signer error = %v", err)
	}

	var unknown map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["mode"] = json.RawMessage(`"future_mode"`)
	future, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	future, err = codec.CanonicalizeSignedObject(future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeConsensusProofMode(future); !errors.Is(
		err,
		ErrInvalidCheckpointProof,
	) {
		t.Fatalf("unknown mode error = %v", err)
	}
}

func TestCheckpointSignResponseRequiresValidExpectedSignature(
	t *testing.T,
) {
	t.Parallel()

	expectation, privateKey := checkpointSigningTestExpectation(t)
	signature := checkpointSigningTestSignature(
		t,
		privateKey,
		expectation.checkpointJSON,
	)
	proof := checkpointSignatureProof{expectation: expectation}
	copy(proof.signature[:], signature)
	encoded, err := encodeCheckpointSignResponse(proof)
	if err != nil {
		t.Fatalf("encodeCheckpointSignResponse(): %v", err)
	}
	decoded, err := decodeCheckpointSignResponse(encoded, expectation)
	if err != nil || decoded.signature != proof.signature {
		t.Fatalf(
			"decodeCheckpointSignResponse() = (%#v, %v)",
			decoded,
			err,
		)
	}

	var wire checkpointSignResponseWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.CheckpointSignature = codec.EncodeBase64URL(
		make([]byte, ed25519.SignatureSize),
	)
	tampered, err := marshalCanonicalConsensusProof(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCheckpointSignResponse(
		tampered,
		expectation,
	); !errors.Is(err, ErrCheckpointProofMismatch) {
		t.Fatalf("tampered response error = %v", err)
	}
}

func TestRequestCheckpointSignatureClassifiesResponses(t *testing.T) {
	t.Parallel()

	expectation, privateKey := checkpointSigningTestExpectation(t)
	signature := checkpointSigningTestSignature(
		t,
		privateKey,
		expectation.checkpointJSON,
	)
	proof := checkpointSignatureProof{expectation: expectation}
	copy(proof.signature[:], signature)
	responseBody, err := encodeCheckpointSignResponse(proof)
	if err != nil {
		t.Fatal(err)
	}
	requester := checkpointProofRequesterFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		if deviceID != expectation.checkpoint.SignerDeviceID {
			t.Fatalf("request target = %q", deviceID)
		}
		if request, err := decodeCheckpointSignRequest(body); err != nil ||
			request.checkpoint != expectation.checkpoint {
			t.Fatalf("request = (%#v, %v)", request, err)
		}
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       responseBody,
		}, nil
	})
	actual, err := requestCheckpointSignature(
		t.Context(),
		requester,
		expectation,
	)
	if err != nil || actual.signature != proof.signature {
		t.Fatalf(
			"requestCheckpointSignature() = (%#v, %v)",
			actual,
			err,
		)
	}

	problem, err := json.Marshal(consensusProofProblem{
		Type:          "urn:codecomm:problem:checkpoint_not_applied",
		Title:         "Checkpoint not applied",
		Status:        http.StatusConflict,
		Code:          "checkpoint_not_applied",
		CorrelationID: "018f47de-89ab-7def-8123-0123456789ab",
		Retryable:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestCheckpointSignature(
		t.Context(),
		checkpointProofRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusConflict,
				MediaType:  "application/problem+json",
				Body:       problem,
			}, nil
		}),
		expectation,
	)
	if !errors.Is(err, ErrCheckpointProofUnavailable) {
		t.Fatalf("retryable response error = %v", err)
	}
}

func TestCheckpointSignerAdapterBindsNodeAndCheckpointDevice(
	t *testing.T,
) {
	t.Parallel()

	expectation, _ := checkpointSigningTestExpectation(t)
	called := false
	adapter := CheckpointSignerAdapter{
		SignerDeviceID: expectation.checkpoint.SignerDeviceID,
		Sign: func(
			context.Context,
			domain.Checkpoint,
		) (store.Signature, error) {
			called = true
			return store.Signature{}, nil
		},
	}
	otherDeviceID := checkpointProofDeviceID('9')
	if err := validateCheckpointSigner(
		otherDeviceID,
		adapter,
	); !errors.Is(err, ErrInvalidNodeOptions) {
		t.Fatalf("mismatched node signer error = %v", err)
	}
	checkpoint := expectation.checkpoint
	checkpoint.SignerDeviceID = otherDeviceID
	if _, err := adapter.SignCheckpoint(
		t.Context(),
		checkpoint,
	); !errors.Is(err, ErrInvalidCheckpointSigner) {
		t.Fatalf("mismatched checkpoint signer error = %v", err)
	}
	if called {
		t.Fatal("adapter invoked signer for mismatched checkpoint")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adapter.SignCheckpoint(
		ctx,
		expectation.checkpoint,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signer error = %v", err)
	}
	if called {
		t.Fatal("adapter invoked signer after cancellation")
	}
}

func checkpointSigningTestExpectation(
	t *testing.T,
) (checkpointSigningExpectation, ed25519.PrivateKey) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x42}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := domain.Checkpoint{
		SessionID: domain.UUIDv7(
			"018f47de-89ab-7def-8123-0123456789ab",
		),
		WorkspaceID: domain.UUIDv4(
			"550e8400-e29b-41d4-a716-446655440000",
		),
		RecoveryGeneration:       2,
		AuthorityVoterSetVersion: 3,
		SignerDeviceID:           deviceID,
		Term:                     4,
		CoveredAppliedLogIndex:   5,
		CoveredChainIndex:        6,
		CoveredChainHash:         [32]byte{0x51},
		CoveredResultIndex:       7,
		CoveredResultHash:        [32]byte{0x61},
		ProjectionAccumulator:    [32]byte{0x71},
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	expectation, err := newCheckpointSigningExpectation(
		checkpoint,
		publicKey,
	)
	if err != nil {
		t.Fatalf("newCheckpointSigningExpectation(): %v", err)
	}
	return expectation, privateKey
}

func checkpointSigningTestSignature(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	checkpoint []byte,
) []byte {
	t.Helper()
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureCheckpoint,
		checkpoint,
	)
	if err != nil {
		t.Fatalf("SignEd25519(): %v", err)
	}
	return signature
}
