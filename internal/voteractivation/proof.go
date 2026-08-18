// Package voteractivation implements the closed V1 voter-activation proof and
// prior-authority handoff wire formats.
package voteractivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

var (
	ErrInvalidProof       = errors.New("voteractivation: invalid voter proof")
	ErrInvalidHandoff     = errors.New("voteractivation: invalid authority handoff")
	ErrInvalidPayload     = errors.New("voteractivation: invalid activation payload")
	ErrNoncanonicalJSON   = errors.New("voteractivation: noncanonical JSON")
	ErrInvalidFieldSet    = errors.New("voteractivation: invalid JSON field set")
	ErrSignerMismatch     = errors.New("voteractivation: signer key does not match device")
	ErrSignatureInvalid   = errors.New("voteractivation: signature verification failed")
	ErrProofContext       = errors.New("voteractivation: inconsistent proof context")
	ErrProofOrder         = errors.New("voteractivation: invalid proof order")
	ErrCheckpointMismatch = errors.New("voteractivation: inconsistent proof checkpoint")
)

var (
	unsignedProofFields = fieldSet(
		"session_id",
		"workspace_id",
		"recovery_generation",
		"target_voter_set_version",
		"current_authority_voter_set_version",
		"voter_set",
		"voter_device_id",
		"live_configuration_index",
		"checkpoint_event_id",
		"checkpoint",
		"checkpoint_signature",
	)
	completeProofFields = withField(unsignedProofFields, "voter_signature")
)

type unsignedProofWire struct {
	SessionID                       string          `json:"session_id"`
	WorkspaceID                     string          `json:"workspace_id"`
	RecoveryGeneration              uint64          `json:"recovery_generation"`
	TargetVoterSetVersion           uint64          `json:"target_voter_set_version"`
	CurrentAuthorityVoterSetVersion uint64          `json:"current_authority_voter_set_version"`
	VoterSet                        []string        `json:"voter_set"`
	VoterDeviceID                   string          `json:"voter_device_id"`
	LiveConfigurationIndex          uint64          `json:"live_configuration_index"`
	CheckpointEventID               string          `json:"checkpoint_event_id"`
	Checkpoint                      json.RawMessage `json:"checkpoint"`
	CheckpointSignature             string          `json:"checkpoint_signature"`
}

type completeProofWire struct {
	SessionID                       string          `json:"session_id"`
	WorkspaceID                     string          `json:"workspace_id"`
	RecoveryGeneration              uint64          `json:"recovery_generation"`
	TargetVoterSetVersion           uint64          `json:"target_voter_set_version"`
	CurrentAuthorityVoterSetVersion uint64          `json:"current_authority_voter_set_version"`
	VoterSet                        []string        `json:"voter_set"`
	VoterDeviceID                   string          `json:"voter_device_id"`
	LiveConfigurationIndex          uint64          `json:"live_configuration_index"`
	CheckpointEventID               string          `json:"checkpoint_event_id"`
	Checkpoint                      json.RawMessage `json:"checkpoint"`
	CheckpointSignature             string          `json:"checkpoint_signature"`
	VoterSignature                  string          `json:"voter_signature"`
}

// ProofInput contains the typed fields covered by a target voter's signature.
// NewUnsignedProof validates and copies all caller-owned data.
type ProofInput struct {
	SessionID                       domain.UUIDv7
	WorkspaceID                     domain.UUIDv4
	RecoveryGeneration              uint64
	TargetVoterSetVersion           uint64
	CurrentAuthorityVoterSetVersion uint64
	VoterSet                        []domain.DeviceID
	VoterDeviceID                   domain.DeviceID
	LiveConfigurationIndex          uint64
	CheckpointEventID               domain.UUIDv7
	Checkpoint                      domain.Checkpoint
	CheckpointSignature             [ed25519.SignatureSize]byte
}

// UnsignedProof is an immutable, validated voter-activation signature
// preimage.
type UnsignedProof struct {
	input          ProofInput
	checkpointJSON []byte
	canonical      []byte
}

// Proof is an immutable complete voter-signed activation proof.
type Proof struct {
	unsigned  UnsignedProof
	signature [ed25519.SignatureSize]byte
	canonical []byte
}

// NewUnsignedProof validates input and builds the exact canonical signature
// preimage.
func NewUnsignedProof(input ProofInput) (UnsignedProof, error) {
	input.VoterSet = cloneDeviceIDs(input.VoterSet)
	checkpointJSON, err := validateProofInput(input)
	if err != nil {
		return UnsignedProof{}, err
	}
	wire := proofWire(input, checkpointJSON)
	canonical, err := marshalCanonical(wire)
	if err != nil {
		return UnsignedProof{}, fmt.Errorf("%w: encode: %v", ErrInvalidProof, err)
	}
	return UnsignedProof{
		input:          input,
		checkpointJSON: bytes.Clone(checkpointJSON),
		canonical:      canonical,
	}, nil
}

// ParseUnsignedProof accepts only the exact canonical closed unsigned object.
func ParseUnsignedProof(encoded []byte) (UnsignedProof, error) {
	var wire unsignedProofWire
	if err := decodeClosedCanonical(encoded, unsignedProofFields, &wire); err != nil {
		return UnsignedProof{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	input, err := proofInputFromWire(wire)
	if err != nil {
		return UnsignedProof{}, err
	}
	proof, err := NewUnsignedProof(input)
	if err != nil {
		return UnsignedProof{}, err
	}
	if !bytes.Equal(proof.canonical, encoded) {
		return UnsignedProof{}, fmt.Errorf("%w: proof does not round trip", ErrInvalidProof)
	}
	return proof, nil
}

// NewProof attaches a fixed-size signature to a validated unsigned proof.
func NewProof(
	unsigned UnsignedProof,
	signature [ed25519.SignatureSize]byte,
) (Proof, error) {
	if err := unsigned.validate(); err != nil {
		return Proof{}, err
	}
	wire := completeWire(unsigned, signature)
	canonical, err := marshalCanonical(wire)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: encode complete proof: %v", ErrInvalidProof, err)
	}
	return Proof{
		unsigned:  unsigned.clone(),
		signature: signature,
		canonical: canonical,
	}, nil
}

// ParseProof accepts only the exact canonical closed complete proof object.
func ParseProof(encoded []byte) (Proof, error) {
	var wire completeProofWire
	if err := decodeClosedCanonical(encoded, completeProofFields, &wire); err != nil {
		return Proof{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	unsignedWire := unsignedProofWire{
		SessionID:                       wire.SessionID,
		WorkspaceID:                     wire.WorkspaceID,
		RecoveryGeneration:              wire.RecoveryGeneration,
		TargetVoterSetVersion:           wire.TargetVoterSetVersion,
		CurrentAuthorityVoterSetVersion: wire.CurrentAuthorityVoterSetVersion,
		VoterSet:                        append([]string(nil), wire.VoterSet...),
		VoterDeviceID:                   wire.VoterDeviceID,
		LiveConfigurationIndex:          wire.LiveConfigurationIndex,
		CheckpointEventID:               wire.CheckpointEventID,
		Checkpoint:                      bytes.Clone(wire.Checkpoint),
		CheckpointSignature:             wire.CheckpointSignature,
	}
	unsignedBytes, err := marshalCanonical(unsignedWire)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: rebuild unsigned proof", ErrInvalidProof)
	}
	unsigned, err := ParseUnsignedProof(unsignedBytes)
	if err != nil {
		return Proof{}, err
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.VoterSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: invalid voter signature", ErrInvalidProof)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	proof, err := NewProof(unsigned, signature)
	if err != nil {
		return Proof{}, err
	}
	if !bytes.Equal(proof.canonical, encoded) {
		return Proof{}, fmt.Errorf("%w: complete proof does not round trip", ErrInvalidProof)
	}
	return proof, nil
}

// SignProof signs only a validated voter-activation proof and requires the
// private key to belong to its named voter.
func SignProof(unsigned UnsignedProof, privateKey []byte) (Proof, error) {
	if err := unsigned.validate(); err != nil {
		return Proof{}, err
	}
	if err := requireSigner(privateKey, unsigned.input.VoterDeviceID); err != nil {
		return Proof{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	signatureBytes, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureVoterActivationProof,
		unsigned.canonical,
	)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: sign: %v", ErrInvalidProof, err)
	}
	defer clear(signatureBytes)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return NewProof(unsigned, signature)
}

// VerifyProof verifies the named voter's labeled signature and rejects a
// public key that derives to another device.
func VerifyProof(proof Proof, publicKey []byte) error {
	if err := proof.validate(); err != nil {
		return err
	}
	if err := requirePublicSigner(publicKey, proof.unsigned.input.VoterDeviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureVoterActivationProof,
		proof.unsigned.canonical,
		proof.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// CanonicalBytes returns an independent copy of the signature preimage.
func (proof UnsignedProof) CanonicalBytes() []byte {
	return bytes.Clone(proof.canonical)
}

// Input returns an independent typed copy of the proof fields.
func (proof UnsignedProof) Input() ProofInput {
	result := proof.input
	result.VoterSet = cloneDeviceIDs(proof.input.VoterSet)
	return result
}

// CanonicalBytes returns an independent copy of the complete proof object.
func (proof Proof) CanonicalBytes() []byte {
	return bytes.Clone(proof.canonical)
}

// Unsigned returns an independent copy of the signature preimage.
func (proof Proof) Unsigned() UnsignedProof {
	return proof.unsigned.clone()
}

// VoterSignature returns the complete voter signature by value.
func (proof Proof) VoterSignature() [ed25519.SignatureSize]byte {
	return proof.signature
}

// VoterDeviceID returns the proof's named target voter.
func (proof Proof) VoterDeviceID() domain.DeviceID {
	return proof.unsigned.input.VoterDeviceID
}

func (proof UnsignedProof) validate() error {
	expected, err := NewUnsignedProof(proof.Input())
	if err != nil ||
		!bytes.Equal(expected.checkpointJSON, proof.checkpointJSON) ||
		!bytes.Equal(expected.canonical, proof.canonical) {
		return fmt.Errorf("%w: invalid unsigned value", ErrInvalidProof)
	}
	return nil
}

func (proof Proof) validate() error {
	if err := proof.unsigned.validate(); err != nil {
		return err
	}
	expected, err := NewProof(proof.unsigned, proof.signature)
	if err != nil || !bytes.Equal(expected.canonical, proof.canonical) {
		return fmt.Errorf("%w: invalid complete value", ErrInvalidProof)
	}
	return nil
}

func (proof UnsignedProof) clone() UnsignedProof {
	return UnsignedProof{
		input:          proof.Input(),
		checkpointJSON: bytes.Clone(proof.checkpointJSON),
		canonical:      bytes.Clone(proof.canonical),
	}
}

func (proof Proof) clone() Proof {
	return Proof{
		unsigned:  proof.unsigned.clone(),
		signature: proof.signature,
		canonical: bytes.Clone(proof.canonical),
	}
}

func validateProofInput(input ProofInput) ([]byte, error) {
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.VoterDeviceID.Valid() ||
		!input.CheckpointEventID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		input.TargetVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(input.TargetVoterSetVersion) ||
		input.CurrentAuthorityVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(input.CurrentAuthorityVoterSetVersion) ||
		input.TargetVoterSetVersion <=
			input.CurrentAuthorityVoterSetVersion ||
		input.LiveConfigurationIndex < 1 ||
		!domain.ValidUnsignedInteger(input.LiveConfigurationIndex) {
		return nil, fmt.Errorf("%w: invalid identity or number", ErrInvalidProof)
	}
	target, err := voterset.New(
		input.SessionID,
		input.VoterSet,
		input.TargetVoterSetVersion,
	)
	if err != nil || !target.Contains(input.VoterDeviceID) {
		return nil, fmt.Errorf("%w: invalid voter target", ErrInvalidProof)
	}
	checkpoint := input.Checkpoint
	if err := checkpoint.Validate(); err != nil ||
		checkpoint.SessionID != input.SessionID ||
		checkpoint.WorkspaceID != input.WorkspaceID ||
		checkpoint.RecoveryGeneration != input.RecoveryGeneration ||
		checkpoint.AuthorityVoterSetVersion !=
			input.CurrentAuthorityVoterSetVersion ||
		checkpoint.CoveredAppliedLogIndex < input.LiveConfigurationIndex {
		return nil, fmt.Errorf("%w: checkpoint context or coverage", ErrProofContext)
	}
	checkpointJSON, err := event.EncodeCheckpoint(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: encode checkpoint: %v", ErrInvalidProof, err)
	}
	return checkpointJSON, nil
}

func proofWire(input ProofInput, checkpointJSON []byte) unsignedProofWire {
	return unsignedProofWire{
		SessionID:                       string(input.SessionID),
		WorkspaceID:                     string(input.WorkspaceID),
		RecoveryGeneration:              input.RecoveryGeneration,
		TargetVoterSetVersion:           input.TargetVoterSetVersion,
		CurrentAuthorityVoterSetVersion: input.CurrentAuthorityVoterSetVersion,
		VoterSet:                        deviceIDStrings(input.VoterSet),
		VoterDeviceID:                   string(input.VoterDeviceID),
		LiveConfigurationIndex:          input.LiveConfigurationIndex,
		CheckpointEventID:               string(input.CheckpointEventID),
		Checkpoint:                      bytes.Clone(checkpointJSON),
		CheckpointSignature: codec.EncodeBase64URL(
			input.CheckpointSignature[:],
		),
	}
}

func completeWire(
	unsigned UnsignedProof,
	signature [ed25519.SignatureSize]byte,
) completeProofWire {
	wire := proofWire(unsigned.input, unsigned.checkpointJSON)
	return completeProofWire{
		SessionID:                       wire.SessionID,
		WorkspaceID:                     wire.WorkspaceID,
		RecoveryGeneration:              wire.RecoveryGeneration,
		TargetVoterSetVersion:           wire.TargetVoterSetVersion,
		CurrentAuthorityVoterSetVersion: wire.CurrentAuthorityVoterSetVersion,
		VoterSet:                        wire.VoterSet,
		VoterDeviceID:                   wire.VoterDeviceID,
		LiveConfigurationIndex:          wire.LiveConfigurationIndex,
		CheckpointEventID:               wire.CheckpointEventID,
		Checkpoint:                      wire.Checkpoint,
		CheckpointSignature:             wire.CheckpointSignature,
		VoterSignature:                  codec.EncodeBase64URL(signature[:]),
	}
}

func proofInputFromWire(wire unsignedProofWire) (ProofInput, error) {
	checkpoint, err := event.DecodeCheckpoint(wire.Checkpoint)
	if err != nil {
		return ProofInput{}, fmt.Errorf("%w: invalid checkpoint", ErrInvalidProof)
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.CheckpointSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return ProofInput{}, fmt.Errorf("%w: invalid checkpoint signature", ErrInvalidProof)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return ProofInput{
		SessionID:                       domain.UUIDv7(wire.SessionID),
		WorkspaceID:                     domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:              wire.RecoveryGeneration,
		TargetVoterSetVersion:           wire.TargetVoterSetVersion,
		CurrentAuthorityVoterSetVersion: wire.CurrentAuthorityVoterSetVersion,
		VoterSet:                        parseDeviceIDs(wire.VoterSet),
		VoterDeviceID:                   domain.DeviceID(wire.VoterDeviceID),
		LiveConfigurationIndex:          wire.LiveConfigurationIndex,
		CheckpointEventID:               domain.UUIDv7(wire.CheckpointEventID),
		Checkpoint:                      checkpoint,
		CheckpointSignature:             signature,
	}, nil
}
