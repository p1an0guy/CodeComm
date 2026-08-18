package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

const (
	consensusProofModeTargetActivation = "target_activation"
	consensusProofModeAuthorityHandoff = "authority_handoff"
)

var (
	ErrInvalidVoterActivationSigner = errors.New(
		"consensus: invalid voter activation signer",
	)
	ErrInvalidVoterActivationProof = errors.New(
		"consensus: invalid voter activation proof",
	)
	ErrVoterActivationProofUnavailable = errors.New(
		"consensus: voter activation proof unavailable",
	)
	ErrVoterActivationProofRejected = errors.New(
		"consensus: voter activation proof request rejected",
	)
	ErrVoterActivationProofMismatch = errors.New(
		"consensus: voter activation proof differs from requested cut",
	)
)

// VoterActivationSigner is an opaque device-identity signing capability. Its
// two methods expose only the frozen voter-activation signature preimages.
// Implementations must return when the supplied context is canceled.
type VoterActivationSigner interface {
	DeviceID() domain.DeviceID
	SignVoterActivationProof(
		context.Context,
		voteractivation.UnsignedProof,
	) ([ed25519.SignatureSize]byte, error)
	SignVoterAuthorityHandoff(
		context.Context,
		voteractivation.UnsignedAuthorityHandoff,
	) ([ed25519.SignatureSize]byte, error)
}

// VoterActivationSignerAdapter binds focused signing functions to one device.
type VoterActivationSignerAdapter struct {
	SignerDeviceID domain.DeviceID
	SignProof      func(
		context.Context,
		voteractivation.UnsignedProof,
	) ([ed25519.SignatureSize]byte, error)
	SignHandoff func(
		context.Context,
		voteractivation.UnsignedAuthorityHandoff,
	) ([ed25519.SignatureSize]byte, error)
}

func (adapter VoterActivationSignerAdapter) DeviceID() domain.DeviceID {
	return adapter.SignerDeviceID
}

func (adapter VoterActivationSignerAdapter) SignVoterActivationProof(
	ctx context.Context,
	unsigned voteractivation.UnsignedProof,
) ([ed25519.SignatureSize]byte, error) {
	if ctx == nil ||
		!adapter.SignerDeviceID.Valid() ||
		adapter.SignProof == nil {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidVoterActivationSigner
	}
	if err := ctx.Err(); err != nil {
		return [ed25519.SignatureSize]byte{}, err
	}
	parsed, err := voteractivation.ParseUnsignedProof(
		unsigned.CanonicalBytes(),
	)
	if err != nil ||
		parsed.Input().VoterDeviceID != adapter.SignerDeviceID {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidVoterActivationSigner
	}
	return adapter.SignProof(ctx, parsed)
}

func (adapter VoterActivationSignerAdapter) SignVoterAuthorityHandoff(
	ctx context.Context,
	unsigned voteractivation.UnsignedAuthorityHandoff,
) ([ed25519.SignatureSize]byte, error) {
	if ctx == nil ||
		!adapter.SignerDeviceID.Valid() ||
		adapter.SignHandoff == nil {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidVoterActivationSigner
	}
	if err := ctx.Err(); err != nil {
		return [ed25519.SignatureSize]byte{}, err
	}
	parsed, err := voteractivation.ParseUnsignedAuthorityHandoff(
		unsigned.CanonicalBytes(),
	)
	if err != nil ||
		parsed.Input().PriorAuthoritySigner != adapter.SignerDeviceID {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidVoterActivationSigner
	}
	return adapter.SignHandoff(ctx, parsed)
}

type targetActivationRequestWire struct {
	SchemaVersion  uint64          `json:"schema_version"`
	Mode           string          `json:"mode"`
	TargetDeviceID string          `json:"target_device_id"`
	UnsignedProof  json.RawMessage `json:"unsigned_proof"`
}

type targetActivationResponseWire struct {
	SchemaVersion  uint64          `json:"schema_version"`
	Mode           string          `json:"mode"`
	TargetDeviceID string          `json:"target_device_id"`
	Proof          json.RawMessage `json:"proof"`
}

type authorityHandoffRequestWire struct {
	SchemaVersion   uint64          `json:"schema_version"`
	Mode            string          `json:"mode"`
	SignerDeviceID  string          `json:"signer_device_id"`
	UnsignedHandoff json.RawMessage `json:"unsigned_handoff"`
}

type authorityHandoffResponseWire struct {
	SchemaVersion     uint64          `json:"schema_version"`
	Mode              string          `json:"mode"`
	SignerDeviceID    string          `json:"signer_device_id"`
	ActivationPayload json.RawMessage `json:"activation_payload"`
}

type targetActivationExpectation struct {
	targetDeviceID  domain.DeviceID
	unsigned        voteractivation.UnsignedProof
	targetPublicKey ed25519.PublicKey
}

func newTargetActivationExpectation(
	targetDeviceID domain.DeviceID,
	unsigned voteractivation.UnsignedProof,
	targetPublicKey ed25519.PublicKey,
) (targetActivationExpectation, error) {
	parsed, err := voteractivation.ParseUnsignedProof(unsigned.CanonicalBytes())
	if err != nil ||
		!targetDeviceID.Valid() ||
		parsed.Input().VoterDeviceID != targetDeviceID ||
		validateActivationPublicKey(targetDeviceID, targetPublicKey) != nil {
		return targetActivationExpectation{}, ErrInvalidVoterActivationProof
	}
	return targetActivationExpectation{
		targetDeviceID:  targetDeviceID,
		unsigned:        parsed,
		targetPublicKey: bytes.Clone(targetPublicKey),
	}, nil
}

func (expectation targetActivationExpectation) validate() error {
	expected, err := newTargetActivationExpectation(
		expectation.targetDeviceID,
		expectation.unsigned,
		expectation.targetPublicKey,
	)
	if err != nil ||
		!bytes.Equal(
			expected.unsigned.CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) {
		return ErrInvalidVoterActivationProof
	}
	return nil
}

type targetActivationRequest struct {
	targetDeviceID domain.DeviceID
	unsigned       voteractivation.UnsignedProof
}

type authorityHandoffExpectation struct {
	signerDeviceID  domain.DeviceID
	unsigned        voteractivation.UnsignedAuthorityHandoff
	signerPublicKey ed25519.PublicKey
}

func newAuthorityHandoffExpectation(
	signerDeviceID domain.DeviceID,
	unsigned voteractivation.UnsignedAuthorityHandoff,
	signerPublicKey ed25519.PublicKey,
) (authorityHandoffExpectation, error) {
	parsed, err := voteractivation.ParseUnsignedAuthorityHandoff(
		unsigned.CanonicalBytes(),
	)
	if err != nil ||
		!signerDeviceID.Valid() ||
		parsed.Input().PriorAuthoritySigner != signerDeviceID ||
		validateActivationPublicKey(signerDeviceID, signerPublicKey) != nil {
		return authorityHandoffExpectation{}, ErrInvalidVoterActivationProof
	}
	return authorityHandoffExpectation{
		signerDeviceID:  signerDeviceID,
		unsigned:        parsed,
		signerPublicKey: bytes.Clone(signerPublicKey),
	}, nil
}

func (expectation authorityHandoffExpectation) validate() error {
	expected, err := newAuthorityHandoffExpectation(
		expectation.signerDeviceID,
		expectation.unsigned,
		expectation.signerPublicKey,
	)
	if err != nil ||
		!bytes.Equal(
			expected.unsigned.CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) {
		return ErrInvalidVoterActivationProof
	}
	return nil
}

type authorityHandoffRequest struct {
	signerDeviceID domain.DeviceID
	unsigned       voteractivation.UnsignedAuthorityHandoff
}

func requestTargetActivationProof(
	ctx context.Context,
	requester consensusProofRequester,
	expectation targetActivationExpectation,
) (voteractivation.Proof, error) {
	if ctx == nil || requester == nil || expectation.validate() != nil {
		return voteractivation.Proof{}, ErrInvalidVoterActivationProof
	}
	encoded, err := encodeTargetActivationRequest(expectation)
	if err != nil {
		return voteractivation.Proof{}, err
	}
	response, err := requester.RequestConsensusProof(
		ctx,
		expectation.targetDeviceID,
		encoded,
	)
	if err != nil {
		return voteractivation.Proof{}, fmt.Errorf(
			"%w: %w",
			ErrVoterActivationProofUnavailable,
			err,
		)
	}
	if err := classifyVoterActivationResponse(response); err != nil {
		return voteractivation.Proof{}, err
	}
	return decodeTargetActivationResponse(response.Body, expectation)
}

func requestAuthorityHandoff(
	ctx context.Context,
	requester consensusProofRequester,
	expectation authorityHandoffExpectation,
) (voteractivation.ActivationPayload, error) {
	if ctx == nil || requester == nil || expectation.validate() != nil {
		return voteractivation.ActivationPayload{},
			ErrInvalidVoterActivationProof
	}
	encoded, err := encodeAuthorityHandoffRequest(expectation)
	if err != nil {
		return voteractivation.ActivationPayload{}, err
	}
	response, err := requester.RequestConsensusProof(
		ctx,
		expectation.signerDeviceID,
		encoded,
	)
	if err != nil {
		return voteractivation.ActivationPayload{}, fmt.Errorf(
			"%w: %w",
			ErrVoterActivationProofUnavailable,
			err,
		)
	}
	if err := classifyVoterActivationResponse(response); err != nil {
		return voteractivation.ActivationPayload{}, err
	}
	return decodeAuthorityHandoffResponse(response.Body, expectation)
}

func encodeTargetActivationRequest(
	expectation targetActivationExpectation,
) ([]byte, error) {
	if expectation.validate() != nil {
		return nil, ErrInvalidVoterActivationProof
	}
	return marshalCanonicalConsensusProof(targetActivationRequestWire{
		SchemaVersion:  consensusProofSchemaVersion,
		Mode:           consensusProofModeTargetActivation,
		TargetDeviceID: string(expectation.targetDeviceID),
		UnsignedProof:  expectation.unsigned.CanonicalBytes(),
	})
}

func decodeTargetActivationRequest(
	encoded []byte,
) (targetActivationRequest, error) {
	var wire targetActivationRequestWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return targetActivationRequest{}, ErrInvalidVoterActivationProof
	}
	unsigned, err := voteractivation.ParseUnsignedProof(wire.UnsignedProof)
	targetDeviceID := domain.DeviceID(wire.TargetDeviceID)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeTargetActivation ||
		err != nil ||
		!targetDeviceID.Valid() ||
		unsigned.Input().VoterDeviceID != targetDeviceID {
		return targetActivationRequest{}, ErrInvalidVoterActivationProof
	}
	return targetActivationRequest{
		targetDeviceID: targetDeviceID,
		unsigned:       unsigned,
	}, nil
}

func encodeTargetActivationResponse(
	proof voteractivation.Proof,
	expectation targetActivationExpectation,
) ([]byte, error) {
	if expectation.validate() != nil ||
		voteractivation.VerifyProof(proof, expectation.targetPublicKey) != nil ||
		!bytes.Equal(
			proof.Unsigned().CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) {
		return nil, ErrInvalidVoterActivationProof
	}
	return marshalCanonicalConsensusProof(targetActivationResponseWire{
		SchemaVersion:  consensusProofSchemaVersion,
		Mode:           consensusProofModeTargetActivation,
		TargetDeviceID: string(expectation.targetDeviceID),
		Proof:          proof.CanonicalBytes(),
	})
}

func decodeTargetActivationResponse(
	encoded []byte,
	expectation targetActivationExpectation,
) (voteractivation.Proof, error) {
	if expectation.validate() != nil {
		return voteractivation.Proof{}, ErrInvalidVoterActivationProof
	}
	var wire targetActivationResponseWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return voteractivation.Proof{}, err
	}
	proof, err := voteractivation.ParseProof(wire.Proof)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeTargetActivation ||
		domain.DeviceID(wire.TargetDeviceID) != expectation.targetDeviceID ||
		err != nil ||
		!bytes.Equal(
			proof.Unsigned().CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) ||
		voteractivation.VerifyProof(proof, expectation.targetPublicKey) != nil {
		return voteractivation.Proof{}, ErrVoterActivationProofMismatch
	}
	return proof, nil
}

func encodeAuthorityHandoffRequest(
	expectation authorityHandoffExpectation,
) ([]byte, error) {
	if expectation.validate() != nil {
		return nil, ErrInvalidVoterActivationProof
	}
	return marshalCanonicalConsensusProof(authorityHandoffRequestWire{
		SchemaVersion:   consensusProofSchemaVersion,
		Mode:            consensusProofModeAuthorityHandoff,
		SignerDeviceID:  string(expectation.signerDeviceID),
		UnsignedHandoff: expectation.unsigned.CanonicalBytes(),
	})
}

func decodeAuthorityHandoffRequest(
	encoded []byte,
) (authorityHandoffRequest, error) {
	var wire authorityHandoffRequestWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return authorityHandoffRequest{}, ErrInvalidVoterActivationProof
	}
	unsigned, err := voteractivation.ParseUnsignedAuthorityHandoff(
		wire.UnsignedHandoff,
	)
	signerDeviceID := domain.DeviceID(wire.SignerDeviceID)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeAuthorityHandoff ||
		err != nil ||
		!signerDeviceID.Valid() ||
		unsigned.Input().PriorAuthoritySigner != signerDeviceID {
		return authorityHandoffRequest{}, ErrInvalidVoterActivationProof
	}
	return authorityHandoffRequest{
		signerDeviceID: signerDeviceID,
		unsigned:       unsigned,
	}, nil
}

func encodeAuthorityHandoffResponse(
	payload voteractivation.ActivationPayload,
	expectation authorityHandoffExpectation,
) ([]byte, error) {
	if expectation.validate() != nil ||
		voteractivation.VerifyAuthorityHandoff(
			payload,
			expectation.signerPublicKey,
		) != nil ||
		!bytes.Equal(
			payload.UnsignedHandoff().CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) {
		return nil, ErrInvalidVoterActivationProof
	}
	encodedPayload, err := voteractivation.EncodeActivationPayload(payload)
	if err != nil {
		return nil, ErrInvalidVoterActivationProof
	}
	return marshalCanonicalConsensusProof(authorityHandoffResponseWire{
		SchemaVersion:     consensusProofSchemaVersion,
		Mode:              consensusProofModeAuthorityHandoff,
		SignerDeviceID:    string(expectation.signerDeviceID),
		ActivationPayload: encodedPayload,
	})
}

func decodeAuthorityHandoffResponse(
	encoded []byte,
	expectation authorityHandoffExpectation,
) (voteractivation.ActivationPayload, error) {
	if expectation.validate() != nil {
		return voteractivation.ActivationPayload{},
			ErrInvalidVoterActivationProof
	}
	var wire authorityHandoffResponseWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return voteractivation.ActivationPayload{}, err
	}
	payload, err := voteractivation.DecodeActivationPayload(
		wire.ActivationPayload,
	)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeAuthorityHandoff ||
		domain.DeviceID(wire.SignerDeviceID) != expectation.signerDeviceID ||
		err != nil ||
		!bytes.Equal(
			payload.UnsignedHandoff().CanonicalBytes(),
			expectation.unsigned.CanonicalBytes(),
		) ||
		voteractivation.VerifyAuthorityHandoff(
			payload,
			expectation.signerPublicKey,
		) != nil {
		return voteractivation.ActivationPayload{},
			ErrVoterActivationProofMismatch
	}
	return payload, nil
}

func classifyVoterActivationResponse(
	response transport.ConsensusControlResponse,
) error {
	if response.StatusCode == http.StatusOK {
		if response.MediaType != "application/json" {
			return ErrInvalidVoterActivationProof
		}
		return nil
	}
	if response.MediaType != "application/problem+json" {
		return ErrInvalidVoterActivationProof
	}
	problem, err := decodeConsensusProofProblem(
		response.Body,
		response.StatusCode,
	)
	if err != nil {
		return err
	}
	classification := ErrVoterActivationProofRejected
	if problem.Retryable {
		classification = ErrVoterActivationProofUnavailable
	}
	return fmt.Errorf(
		"%w: remote code %s, HTTP status %d",
		classification,
		problem.Code,
		response.StatusCode,
	)
}

func validateActivationPublicKey(
	deviceID domain.DeviceID,
	publicKey ed25519.PublicKey,
) error {
	if !deviceID.Valid() || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidVoterActivationProof
	}
	derived, err := device.DeriveID(publicKey)
	if err != nil || derived != deviceID {
		return ErrInvalidVoterActivationProof
	}
	return nil
}

func normalizedVoterActivationSigner(
	signer VoterActivationSigner,
) VoterActivationSigner {
	if signer == nil {
		return nil
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	return signer
}

func validateVoterActivationSigner(
	deviceID domain.DeviceID,
	signer VoterActivationSigner,
) error {
	signer = normalizedVoterActivationSigner(signer)
	if signer != nil && signer.DeviceID() != deviceID {
		return fmt.Errorf(
			"%w: signer belongs to another device",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

var _ VoterActivationSigner = VoterActivationSignerAdapter{}
