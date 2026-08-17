package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const consensusProofModeCheckpointSign = "checkpoint_sign"

var (
	ErrInvalidCheckpointSigner = errors.New(
		"consensus: invalid checkpoint signer",
	)
	errCheckpointSignerNotApplied = errors.New(
		"consensus: checkpoint signer has not applied the requested cut",
	)
)

// CheckpointSigner is an opaque device-identity signing capability. Consensus
// validates the signed object and signature before using the result. An
// implementation must return when the supplied context is canceled.
type CheckpointSigner interface {
	DeviceID() domain.DeviceID
	SignCheckpoint(
		context.Context,
		domain.Checkpoint,
	) (store.Signature, error)
}

// CheckpointSignerAdapter adapts a device-bound function to CheckpointSigner.
type CheckpointSignerAdapter struct {
	SignerDeviceID domain.DeviceID
	Sign           func(
		context.Context,
		domain.Checkpoint,
	) (store.Signature, error)
}

func (adapter CheckpointSignerAdapter) DeviceID() domain.DeviceID {
	return adapter.SignerDeviceID
}

func (adapter CheckpointSignerAdapter) SignCheckpoint(
	ctx context.Context,
	checkpoint domain.Checkpoint,
) (store.Signature, error) {
	if ctx == nil ||
		!adapter.SignerDeviceID.Valid() ||
		adapter.Sign == nil ||
		checkpoint.SignerDeviceID != adapter.SignerDeviceID {
		return store.Signature{}, ErrInvalidCheckpointSigner
	}
	if err := ctx.Err(); err != nil {
		return store.Signature{}, err
	}
	return adapter.Sign(ctx, checkpoint)
}

type checkpointSignRequestWire struct {
	SchemaVersion  uint64          `json:"schema_version"`
	Mode           string          `json:"mode"`
	SignerDeviceID string          `json:"signer_device_id"`
	Checkpoint     json.RawMessage `json:"checkpoint"`
}

type checkpointSignResponseWire struct {
	SchemaVersion       uint64          `json:"schema_version"`
	Mode                string          `json:"mode"`
	SignerDeviceID      string          `json:"signer_device_id"`
	Checkpoint          json.RawMessage `json:"checkpoint"`
	CheckpointSignature string          `json:"checkpoint_signature"`
}

type checkpointSigningExpectation struct {
	checkpoint      domain.Checkpoint
	checkpointJSON  []byte
	signerPublicKey ed25519.PublicKey
}

func newCheckpointSigningExpectation(
	checkpoint domain.Checkpoint,
	signerPublicKey ed25519.PublicKey,
) (checkpointSigningExpectation, error) {
	encoded, err := event.EncodeCheckpoint(checkpoint)
	if err != nil ||
		len(signerPublicKey) != ed25519.PublicKeySize {
		return checkpointSigningExpectation{},
			ErrInvalidCheckpointProof
	}
	signerDeviceID, err := device.DeriveID(signerPublicKey)
	if err != nil || signerDeviceID != checkpoint.SignerDeviceID {
		return checkpointSigningExpectation{},
			ErrInvalidCheckpointProof
	}
	return checkpointSigningExpectation{
		checkpoint:      checkpoint,
		checkpointJSON:  encoded,
		signerPublicKey: bytes.Clone(signerPublicKey),
	}, nil
}

func (expectation checkpointSigningExpectation) validate() error {
	expected, err := newCheckpointSigningExpectation(
		expectation.checkpoint,
		expectation.signerPublicKey,
	)
	if err != nil ||
		!bytes.Equal(expected.checkpointJSON, expectation.checkpointJSON) {
		return ErrInvalidCheckpointProof
	}
	return nil
}

type checkpointSignRequest struct {
	checkpoint     domain.Checkpoint
	checkpointJSON []byte
}

type checkpointSignatureProof struct {
	expectation checkpointSigningExpectation
	signature   store.Signature
}

func requestCheckpointSignature(
	ctx context.Context,
	requester consensusProofRequester,
	expectation checkpointSigningExpectation,
) (checkpointSignatureProof, error) {
	if ctx == nil || requester == nil ||
		expectation.validate() != nil {
		return checkpointSignatureProof{},
			ErrInvalidCheckpointProof
	}
	encoded, err := encodeCheckpointSignRequest(expectation)
	if err != nil {
		return checkpointSignatureProof{}, err
	}
	response, err := requester.RequestConsensusProof(
		ctx,
		expectation.checkpoint.SignerDeviceID,
		encoded,
	)
	if err != nil {
		return checkpointSignatureProof{}, fmt.Errorf(
			"%w: %w",
			ErrCheckpointProofUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return checkpointSignatureProof{},
				ErrInvalidCheckpointProof
		}
		problem, err := decodeConsensusProofProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return checkpointSignatureProof{}, err
		}
		classification := ErrCheckpointProofRejected
		if problem.Retryable {
			classification = ErrCheckpointProofUnavailable
		}
		if problem.Code == "checkpoint_not_applied" {
			return checkpointSignatureProof{}, fmt.Errorf(
				"%w: %w: remote code %s, HTTP status %d",
				classification,
				errCheckpointSignerNotApplied,
				problem.Code,
				response.StatusCode,
			)
		}
		return checkpointSignatureProof{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return checkpointSignatureProof{},
			ErrInvalidCheckpointProof
	}
	return decodeCheckpointSignResponse(response.Body, expectation)
}

func encodeCheckpointSignRequest(
	expectation checkpointSigningExpectation,
) ([]byte, error) {
	if expectation.validate() != nil {
		return nil, ErrInvalidCheckpointProof
	}
	return marshalCanonicalConsensusProof(checkpointSignRequestWire{
		SchemaVersion:  consensusProofSchemaVersion,
		Mode:           consensusProofModeCheckpointSign,
		SignerDeviceID: string(expectation.checkpoint.SignerDeviceID),
		Checkpoint:     expectation.checkpointJSON,
	})
}

func decodeCheckpointSignRequest(
	encoded []byte,
) (checkpointSignRequest, error) {
	var wire checkpointSignRequestWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return checkpointSignRequest{}, err
	}
	checkpointJSON, err := canonicalCheckpointJSON(wire.Checkpoint)
	if err != nil {
		return checkpointSignRequest{}, err
	}
	checkpoint, err := event.DecodeCheckpoint(checkpointJSON)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeCheckpointSign ||
		err != nil ||
		domain.DeviceID(wire.SignerDeviceID) !=
			checkpoint.SignerDeviceID {
		return checkpointSignRequest{},
			ErrInvalidCheckpointProof
	}
	return checkpointSignRequest{
		checkpoint:     checkpoint,
		checkpointJSON: checkpointJSON,
	}, nil
}

func encodeCheckpointSignResponse(
	proof checkpointSignatureProof,
) ([]byte, error) {
	if proof.expectation.validate() != nil ||
		codecommcrypto.VerifyEd25519(
			proof.expectation.signerPublicKey,
			codec.SignatureCheckpoint,
			proof.expectation.checkpointJSON,
			proof.signature[:],
		) != nil {
		return nil, ErrInvalidCheckpointProof
	}
	return marshalCanonicalConsensusProof(checkpointSignResponseWire{
		SchemaVersion: consensusProofSchemaVersion,
		Mode:          consensusProofModeCheckpointSign,
		SignerDeviceID: string(
			proof.expectation.checkpoint.SignerDeviceID,
		),
		Checkpoint: proof.expectation.checkpointJSON,
		CheckpointSignature: codec.EncodeBase64URL(
			proof.signature[:],
		),
	})
}

func decodeCheckpointSignResponse(
	encoded []byte,
	expected checkpointSigningExpectation,
) (checkpointSignatureProof, error) {
	if expected.validate() != nil {
		return checkpointSignatureProof{},
			ErrInvalidCheckpointProof
	}
	var wire checkpointSignResponseWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return checkpointSignatureProof{}, err
	}
	checkpointJSON, checkpointErr := canonicalCheckpointJSON(
		wire.Checkpoint,
	)
	signature, signatureErr := codec.DecodeBase64URLExact(
		wire.CheckpointSignature,
		ed25519.SignatureSize,
	)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeCheckpointSign ||
		domain.DeviceID(wire.SignerDeviceID) !=
			expected.checkpoint.SignerDeviceID ||
		checkpointErr != nil ||
		signatureErr != nil ||
		!bytes.Equal(checkpointJSON, expected.checkpointJSON) ||
		codecommcrypto.VerifyEd25519(
			expected.signerPublicKey,
			codec.SignatureCheckpoint,
			expected.checkpointJSON,
			signature,
		) != nil {
		return checkpointSignatureProof{},
			ErrCheckpointProofMismatch
	}
	proof := checkpointSignatureProof{expectation: expected}
	copy(proof.signature[:], signature)
	return proof, nil
}

var _ CheckpointSigner = CheckpointSignerAdapter{}
