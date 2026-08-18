package voteractivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

var (
	unsignedHandoffFields = fieldSet(
		"session_id",
		"workspace_id",
		"recovery_generation",
		"target_voter_set_version",
		"expected_authority_voter_set_version",
		"voter_set",
		"activation_checkpoint_event_id",
		"activation_proofs",
		"prior_authority_signer",
	)
	activationPayloadFields = fieldSet(
		"target_voter_set_version",
		"expected_authority_voter_set_version",
		"voter_set",
		"activation_checkpoint_event_id",
		"activation_proofs",
		"prior_authority_signer",
		"prior_authority_handoff",
	)
)

type unsignedHandoffWire struct {
	SessionID                        string            `json:"session_id"`
	WorkspaceID                      string            `json:"workspace_id"`
	RecoveryGeneration               uint64            `json:"recovery_generation"`
	TargetVoterSetVersion            uint64            `json:"target_voter_set_version"`
	ExpectedAuthorityVoterSetVersion uint64            `json:"expected_authority_voter_set_version"`
	VoterSet                         []string          `json:"voter_set"`
	ActivationCheckpointEventID      string            `json:"activation_checkpoint_event_id"`
	ActivationProofs                 []json.RawMessage `json:"activation_proofs"`
	PriorAuthoritySigner             string            `json:"prior_authority_signer"`
}

type activationPayloadWire struct {
	TargetVoterSetVersion            uint64            `json:"target_voter_set_version"`
	ExpectedAuthorityVoterSetVersion uint64            `json:"expected_authority_voter_set_version"`
	VoterSet                         []string          `json:"voter_set"`
	ActivationCheckpointEventID      string            `json:"activation_checkpoint_event_id"`
	ActivationProofs                 []json.RawMessage `json:"activation_proofs"`
	PriorAuthoritySigner             string            `json:"prior_authority_signer"`
	PriorAuthorityHandoff            string            `json:"prior_authority_handoff"`
}

// AuthorityHandoffInput contains the fields covered by the prior authority's
// handoff signature. NewUnsignedAuthorityHandoff validates and copies all
// caller-owned data.
type AuthorityHandoffInput struct {
	SessionID                        domain.UUIDv7
	WorkspaceID                      domain.UUIDv4
	RecoveryGeneration               uint64
	TargetVoterSetVersion            uint64
	ExpectedAuthorityVoterSetVersion uint64
	VoterSet                         []domain.DeviceID
	ActivationCheckpointEventID      domain.UUIDv7
	ActivationProofs                 []Proof
	PriorAuthoritySigner             domain.DeviceID
}

// UnsignedAuthorityHandoff is an immutable, validated prior-authority
// signature preimage.
type UnsignedAuthorityHandoff struct {
	input     AuthorityHandoffInput
	canonical []byte
}

// ActivationPayload is the immutable complete
// membership.voter_set_activated payload.
type ActivationPayload struct {
	handoff   UnsignedAuthorityHandoff
	signature [ed25519.SignatureSize]byte
	canonical []byte
}

// NewUnsignedAuthorityHandoff validates the complete ordered target proof set
// and builds the exact canonical handoff signature preimage.
func NewUnsignedAuthorityHandoff(
	input AuthorityHandoffInput,
) (UnsignedAuthorityHandoff, error) {
	input = cloneHandoffInput(input)
	if err := validateHandoffInput(input); err != nil {
		return UnsignedAuthorityHandoff{}, err
	}
	canonical, err := marshalCanonical(handoffWire(input))
	if err != nil {
		return UnsignedAuthorityHandoff{},
			fmt.Errorf("%w: encode: %v", ErrInvalidHandoff, err)
	}
	return UnsignedAuthorityHandoff{
		input:     input,
		canonical: canonical,
	}, nil
}

// ParseUnsignedAuthorityHandoff accepts only the exact canonical closed
// handoff preimage.
func ParseUnsignedAuthorityHandoff(
	encoded []byte,
) (UnsignedAuthorityHandoff, error) {
	var wire unsignedHandoffWire
	if err := decodeClosedCanonical(
		encoded,
		unsignedHandoffFields,
		&wire,
	); err != nil {
		return UnsignedAuthorityHandoff{},
			fmt.Errorf("%w: %w", ErrInvalidHandoff, err)
	}
	input, err := handoffInputFromWire(wire)
	if err != nil {
		return UnsignedAuthorityHandoff{}, err
	}
	handoff, err := NewUnsignedAuthorityHandoff(input)
	if err != nil {
		return UnsignedAuthorityHandoff{}, err
	}
	if !bytes.Equal(handoff.canonical, encoded) {
		return UnsignedAuthorityHandoff{},
			fmt.Errorf("%w: handoff does not round trip", ErrInvalidHandoff)
	}
	return handoff, nil
}

// NewActivationPayload attaches a fixed-size prior-authority signature to a
// validated handoff.
func NewActivationPayload(
	handoff UnsignedAuthorityHandoff,
	signature [ed25519.SignatureSize]byte,
) (ActivationPayload, error) {
	if err := handoff.validate(); err != nil {
		return ActivationPayload{}, err
	}
	canonical, err := marshalCanonical(payloadWire(handoff, signature))
	if err != nil {
		return ActivationPayload{},
			fmt.Errorf("%w: encode: %v", ErrInvalidPayload, err)
	}
	return ActivationPayload{
		handoff:   handoff.clone(),
		signature: signature,
		canonical: canonical,
	}, nil
}

// SignAuthorityHandoff signs only a validated authority-handoff preimage and
// requires the private key to belong to its named prior-authority signer.
func SignAuthorityHandoff(
	handoff UnsignedAuthorityHandoff,
	privateKey []byte,
) (ActivationPayload, error) {
	if err := handoff.validate(); err != nil {
		return ActivationPayload{}, err
	}
	if err := requireSigner(
		privateKey,
		handoff.input.PriorAuthoritySigner,
	); err != nil {
		return ActivationPayload{}, fmt.Errorf("%w: %w", ErrInvalidHandoff, err)
	}
	signatureBytes, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureVoterAuthorityHandoff,
		handoff.canonical,
	)
	if err != nil {
		return ActivationPayload{},
			fmt.Errorf("%w: sign: %v", ErrInvalidHandoff, err)
	}
	defer clear(signatureBytes)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return NewActivationPayload(handoff, signature)
}

// VerifyAuthorityHandoff verifies the named prior-authority signer's labeled
// signature and rejects a public key that derives to another device.
func VerifyAuthorityHandoff(
	payload ActivationPayload,
	publicKey []byte,
) error {
	if err := payload.validate(); err != nil {
		return err
	}
	if err := requirePublicSigner(
		publicKey,
		payload.handoff.input.PriorAuthoritySigner,
	); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureVoterAuthorityHandoff,
		payload.handoff.canonical,
		payload.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// EncodeActivationPayload returns an independent copy of the exact canonical
// event payload.
func EncodeActivationPayload(payload ActivationPayload) ([]byte, error) {
	if err := payload.validate(); err != nil {
		return nil, err
	}
	return bytes.Clone(payload.canonical), nil
}

// DecodeActivationPayload accepts only the exact canonical closed event
// payload.
func DecodeActivationPayload(encoded []byte) (ActivationPayload, error) {
	var wire activationPayloadWire
	if err := decodeClosedCanonical(
		encoded,
		activationPayloadFields,
		&wire,
	); err != nil {
		return ActivationPayload{},
			fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	handoffWireValue := unsignedHandoffWire{
		TargetVoterSetVersion:            wire.TargetVoterSetVersion,
		ExpectedAuthorityVoterSetVersion: wire.ExpectedAuthorityVoterSetVersion,
		VoterSet:                         append([]string(nil), wire.VoterSet...),
		ActivationCheckpointEventID:      wire.ActivationCheckpointEventID,
		ActivationProofs:                 cloneRawMessages(wire.ActivationProofs),
		PriorAuthoritySigner:             wire.PriorAuthoritySigner,
	}
	if len(wire.ActivationProofs) == 0 {
		return ActivationPayload{},
			fmt.Errorf("%w: empty proof set", ErrInvalidPayload)
	}
	first, err := ParseProof(wire.ActivationProofs[0])
	if err != nil {
		return ActivationPayload{}, err
	}
	firstInput := first.unsigned.input
	handoffWireValue.SessionID = string(firstInput.SessionID)
	handoffWireValue.WorkspaceID = string(firstInput.WorkspaceID)
	handoffWireValue.RecoveryGeneration = firstInput.RecoveryGeneration
	handoffBytes, err := marshalCanonical(handoffWireValue)
	if err != nil {
		return ActivationPayload{},
			fmt.Errorf("%w: rebuild handoff", ErrInvalidPayload)
	}
	handoff, err := ParseUnsignedAuthorityHandoff(handoffBytes)
	if err != nil {
		return ActivationPayload{}, err
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.PriorAuthorityHandoff,
		ed25519.SignatureSize,
	)
	if err != nil {
		return ActivationPayload{},
			fmt.Errorf("%w: invalid handoff signature", ErrInvalidPayload)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	payload, err := NewActivationPayload(handoff, signature)
	if err != nil {
		return ActivationPayload{}, err
	}
	if !bytes.Equal(payload.canonical, encoded) {
		return ActivationPayload{},
			fmt.Errorf("%w: payload does not round trip", ErrInvalidPayload)
	}
	return payload, nil
}

// CanonicalBytes returns an independent copy of the handoff signature
// preimage.
func (handoff UnsignedAuthorityHandoff) CanonicalBytes() []byte {
	return bytes.Clone(handoff.canonical)
}

// Input returns an independent typed copy of the handoff fields and proofs.
func (handoff UnsignedAuthorityHandoff) Input() AuthorityHandoffInput {
	return cloneHandoffInput(handoff.input)
}

// CanonicalBytes returns an independent copy of the complete event payload.
func (payload ActivationPayload) CanonicalBytes() []byte {
	return bytes.Clone(payload.canonical)
}

// UnsignedHandoff returns an independent copy of the handoff preimage.
func (payload ActivationPayload) UnsignedHandoff() UnsignedAuthorityHandoff {
	return payload.handoff.clone()
}

// HandoffSignature returns the complete prior-authority signature by value.
func (payload ActivationPayload) HandoffSignature() [ed25519.SignatureSize]byte {
	return payload.signature
}

func (handoff UnsignedAuthorityHandoff) validate() error {
	expected, err := NewUnsignedAuthorityHandoff(handoff.Input())
	if err != nil || !bytes.Equal(expected.canonical, handoff.canonical) {
		return fmt.Errorf("%w: invalid unsigned value", ErrInvalidHandoff)
	}
	return nil
}

func (handoff UnsignedAuthorityHandoff) clone() UnsignedAuthorityHandoff {
	return UnsignedAuthorityHandoff{
		input:     handoff.Input(),
		canonical: bytes.Clone(handoff.canonical),
	}
}

func (payload ActivationPayload) validate() error {
	if err := payload.handoff.validate(); err != nil {
		return err
	}
	expected, err := NewActivationPayload(payload.handoff, payload.signature)
	if err != nil || !bytes.Equal(expected.canonical, payload.canonical) {
		return fmt.Errorf("%w: invalid complete value", ErrInvalidPayload)
	}
	return nil
}

func validateHandoffInput(input AuthorityHandoffInput) error {
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.ActivationCheckpointEventID.Valid() ||
		!input.PriorAuthoritySigner.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		input.TargetVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(input.TargetVoterSetVersion) ||
		input.ExpectedAuthorityVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(input.ExpectedAuthorityVoterSetVersion) ||
		input.TargetVoterSetVersion <=
			input.ExpectedAuthorityVoterSetVersion {
		return fmt.Errorf("%w: invalid identity or version", ErrInvalidHandoff)
	}
	target, err := voterset.New(
		input.SessionID,
		input.VoterSet,
		input.TargetVoterSetVersion,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid voter target", ErrInvalidHandoff)
	}
	if len(input.ActivationProofs) != len(input.VoterSet) {
		return fmt.Errorf("%w: proof count", ErrProofOrder)
	}

	var common ProofInput
	for index, proof := range input.ActivationProofs {
		if err := proof.validate(); err != nil {
			return err
		}
		proofInput := proof.unsigned.input
		if proofInput.VoterDeviceID != input.VoterSet[index] ||
			!target.Contains(proofInput.VoterDeviceID) {
			return fmt.Errorf("%w: proof %d", ErrProofOrder, index)
		}
		if proofInput.SessionID != input.SessionID ||
			proofInput.WorkspaceID != input.WorkspaceID ||
			proofInput.RecoveryGeneration != input.RecoveryGeneration ||
			proofInput.TargetVoterSetVersion !=
				input.TargetVoterSetVersion ||
			proofInput.CurrentAuthorityVoterSetVersion !=
				input.ExpectedAuthorityVoterSetVersion ||
			!sameDeviceIDs(proofInput.VoterSet, input.VoterSet) ||
			proofInput.CheckpointEventID !=
				input.ActivationCheckpointEventID {
			return fmt.Errorf("%w: proof %d", ErrProofContext, index)
		}
		if index == 0 {
			common = proofInput
			continue
		}
		if proofInput.LiveConfigurationIndex !=
			common.LiveConfigurationIndex ||
			!bytes.Equal(
				proof.unsigned.checkpointJSON,
				input.ActivationProofs[0].unsigned.checkpointJSON,
			) ||
			proofInput.CheckpointSignature !=
				common.CheckpointSignature {
			return fmt.Errorf("%w: proof %d", ErrCheckpointMismatch, index)
		}
	}
	return nil
}

func handoffWire(input AuthorityHandoffInput) unsignedHandoffWire {
	proofs := make([]json.RawMessage, len(input.ActivationProofs))
	for index, proof := range input.ActivationProofs {
		proofs[index] = proof.CanonicalBytes()
	}
	return unsignedHandoffWire{
		SessionID:                        string(input.SessionID),
		WorkspaceID:                      string(input.WorkspaceID),
		RecoveryGeneration:               input.RecoveryGeneration,
		TargetVoterSetVersion:            input.TargetVoterSetVersion,
		ExpectedAuthorityVoterSetVersion: input.ExpectedAuthorityVoterSetVersion,
		VoterSet:                         deviceIDStrings(input.VoterSet),
		ActivationCheckpointEventID: string(
			input.ActivationCheckpointEventID,
		),
		ActivationProofs:     proofs,
		PriorAuthoritySigner: string(input.PriorAuthoritySigner),
	}
}

func payloadWire(
	handoff UnsignedAuthorityHandoff,
	signature [ed25519.SignatureSize]byte,
) activationPayloadWire {
	wire := handoffWire(handoff.input)
	return activationPayloadWire{
		TargetVoterSetVersion:            wire.TargetVoterSetVersion,
		ExpectedAuthorityVoterSetVersion: wire.ExpectedAuthorityVoterSetVersion,
		VoterSet:                         wire.VoterSet,
		ActivationCheckpointEventID:      wire.ActivationCheckpointEventID,
		ActivationProofs:                 wire.ActivationProofs,
		PriorAuthoritySigner:             wire.PriorAuthoritySigner,
		PriorAuthorityHandoff: codec.EncodeBase64URL(
			signature[:],
		),
	}
}

func handoffInputFromWire(
	wire unsignedHandoffWire,
) (AuthorityHandoffInput, error) {
	proofs := make([]Proof, len(wire.ActivationProofs))
	for index, encoded := range wire.ActivationProofs {
		proof, err := ParseProof(encoded)
		if err != nil {
			return AuthorityHandoffInput{},
				fmt.Errorf("%w: proof %d: %w", ErrInvalidHandoff, index, err)
		}
		proofs[index] = proof
	}
	return AuthorityHandoffInput{
		SessionID:                        domain.UUIDv7(wire.SessionID),
		WorkspaceID:                      domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:               wire.RecoveryGeneration,
		TargetVoterSetVersion:            wire.TargetVoterSetVersion,
		ExpectedAuthorityVoterSetVersion: wire.ExpectedAuthorityVoterSetVersion,
		VoterSet:                         parseDeviceIDs(wire.VoterSet),
		ActivationCheckpointEventID: domain.UUIDv7(
			wire.ActivationCheckpointEventID,
		),
		ActivationProofs:     proofs,
		PriorAuthoritySigner: domain.DeviceID(wire.PriorAuthoritySigner),
	}, nil
}

func cloneHandoffInput(input AuthorityHandoffInput) AuthorityHandoffInput {
	result := input
	result.VoterSet = cloneDeviceIDs(input.VoterSet)
	result.ActivationProofs = make([]Proof, len(input.ActivationProofs))
	for index, proof := range input.ActivationProofs {
		result.ActivationProofs[index] = proof.clone()
	}
	return result
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	result := make([]json.RawMessage, len(values))
	for index, value := range values {
		result[index] = bytes.Clone(value)
	}
	return result
}

func sameDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
