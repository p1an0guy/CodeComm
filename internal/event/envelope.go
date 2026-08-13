package event

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	SchemaVersion        = 1
	MaxApplyLevel        = domain.MaxApplyLevel
	MaxEventBytes        = 256 << 10
	MaxLocalCommandBytes = 1 << 20
)

var (
	ErrInvalidEnvelope       = errors.New("event: invalid envelope")
	ErrInvalidKind           = errors.New("event: unknown V1 kind")
	ErrActorNotAllowed       = errors.New("event: actor is not allowed for kind")
	ErrExpectedEntityVersion = errors.New("event: invalid expected entity version")
	ErrAgentStartBinding     = errors.New("event: invalid agent-session start binding")
	ErrInvalidPayload        = errors.New("event: payload must be a JSON object")
	ErrEventTooLarge         = errors.New("event: event exceeds maximum size")
	ErrOriginKeyMismatch     = errors.New("event: origin device ID does not match signing key")
	ErrSessionBinding        = errors.New("event: proposal does not match session binding")
	ErrNoncanonicalEvent     = errors.New("event: signed event is not canonical JSON")
	ErrUnknownField          = errors.New("event: unknown field")
	ErrMissingField          = errors.New("event: missing required field")
	ErrClientSuppliedOrigin  = errors.New("event: local command must not supply origin")
)

// Command is the non-authority-bearing mutation body accepted from local IPC.
// Schema, apply level, IDs, time, capture level, origin, and signature are
// supplied by the daemon.
type Command struct {
	Kind                  Kind
	EntityID              EntityID
	ExpectedEntityVersion *uint64
	RationaleSummary      string
	Actions               []Action
	Payload               json.RawMessage
	Redaction             Redaction
}

// BuildContext contains daemon-owned values reserved for one local command.
type BuildContext struct {
	EventID        domain.UUIDv7
	SessionID      domain.UUIDv7
	WorkspaceID    domain.UUIDv4
	CreatedAt      domain.Timestamp
	OriginSequence uint64
}

// Proposal is the complete origin-signature preimage.
type Proposal struct {
	SchemaVersion         uint64
	MinApplyLevel         uint64
	EventID               domain.UUIDv7
	SessionID             domain.UUIDv7
	WorkspaceID           domain.UUIDv4
	Origin                Origin
	CreatedAt             domain.Timestamp
	Kind                  Kind
	EntityID              EntityID
	ExpectedEntityVersion *uint64
	RationaleSummary      string
	CaptureLevel          CaptureLevel
	Actions               []Action
	Payload               json.RawMessage
	Redaction             Redaction
}

// BuildProposal constructs a proposal from a local command and authenticated
// IPC binding. No caller-controlled identity field is accepted.
func BuildProposal(command Command, binding Binding, context BuildContext) (Proposal, error) {
	if !context.EventID.Valid() ||
		!context.SessionID.Valid() ||
		!context.WorkspaceID.Valid() ||
		!context.CreatedAt.Valid() {
		return Proposal{}, ErrInvalidEnvelope
	}
	origin, err := binding.Origin(context.OriginSequence)
	if err != nil {
		return Proposal{}, err
	}
	spec, ok := LookupKind(command.Kind)
	if !ok {
		return Proposal{}, fmt.Errorf("%w: %q", ErrInvalidKind, command.Kind)
	}
	payload, err := canonicalPayload(command.Payload)
	if err != nil {
		return Proposal{}, err
	}

	proposal := Proposal{
		SchemaVersion:         SchemaVersion,
		MinApplyLevel:         spec.MinApplyLevel(),
		EventID:               context.EventID,
		SessionID:             context.SessionID,
		WorkspaceID:           context.WorkspaceID,
		Origin:                origin,
		CreatedAt:             context.CreatedAt,
		Kind:                  command.Kind,
		EntityID:              command.EntityID,
		ExpectedEntityVersion: cloneUint64Pointer(command.ExpectedEntityVersion),
		RationaleSummary:      command.RationaleSummary,
		CaptureLevel:          captureLevelForActor(origin.ActorType()),
		Actions:               cloneActions(command.Actions),
		Payload:               payload,
		Redaction:             cloneRedaction(command.Redaction),
	}
	if err := proposal.ValidateForEmission(); err != nil {
		return Proposal{}, err
	}

	// Check the final signed-envelope size, not merely the signature preimage.
	complete, _, err := encodeProposal(proposal, make([]byte, codecommcrypto.Ed25519SignatureSize))
	if err != nil {
		return Proposal{}, err
	}
	if len(complete) > MaxEventBytes {
		return Proposal{}, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrEventTooLarge,
			len(complete),
			MaxEventBytes,
		)
	}
	return proposal, nil
}

// ValidateEnvelope checks context-free envelope syntax and bounds. It does not
// apply role, sequence-continuity, state, or kind-specific domain decisions.
func (proposal Proposal) ValidateEnvelope() error {
	if proposal.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema_version %d", ErrInvalidEnvelope, proposal.SchemaVersion)
	}
	if proposal.MinApplyLevel < 1 || proposal.MinApplyLevel > MaxApplyLevel {
		return fmt.Errorf("%w: min_apply_level %d", ErrInvalidEnvelope, proposal.MinApplyLevel)
	}
	if !proposal.EventID.Valid() ||
		!proposal.SessionID.Valid() ||
		!proposal.WorkspaceID.Valid() ||
		!proposal.CreatedAt.Valid() ||
		!validKindText(proposal.Kind) ||
		!proposal.EntityID.validGeneralForm() {
		return ErrInvalidEnvelope
	}
	if spec, ok := LookupKind(proposal.Kind); ok &&
		proposal.MinApplyLevel != spec.MinApplyLevel() {
		return fmt.Errorf(
			"%w: min_apply_level %d, want %d for %q",
			ErrInvalidEnvelope,
			proposal.MinApplyLevel,
			spec.MinApplyLevel(),
			proposal.Kind,
		)
	}
	if err := proposal.Origin.validate(); err != nil {
		return err
	}
	if proposal.ExpectedEntityVersion != nil &&
		(*proposal.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*proposal.ExpectedEntityVersion)) {
		return fmt.Errorf(
			"%w: %d",
			ErrExpectedEntityVersion,
			*proposal.ExpectedEntityVersion,
		)
	}
	if !validText(proposal.RationaleSummary, 0, MaxRationaleSummaryBytes, true) {
		return fmt.Errorf("%w: rationale_summary", ErrInvalidEnvelope)
	}
	if proposal.CaptureLevel != captureLevelForActor(proposal.Origin.ActorType()) {
		return fmt.Errorf("%w: capture_level %q", ErrInvalidEnvelope, proposal.CaptureLevel)
	}
	if proposal.Actions == nil || len(proposal.Actions) > MaxActions {
		return fmt.Errorf("%w: actions count %d", ErrInvalidEnvelope, len(proposal.Actions))
	}
	for index, action := range proposal.Actions {
		if err := action.Validate(); err != nil {
			return fmt.Errorf("event: actions[%d]: %w", index, err)
		}
	}
	if err := validatePayload(proposal.Payload); err != nil {
		return err
	}
	if err := proposal.Redaction.Validate(); err != nil {
		return err
	}
	return nil
}

// ValidateKindContract checks the immutable V1 actor, CAS, entity-ID, and
// special agent-start rules. Reducers can call this only after consuming a
// structurally valid next origin sequence.
func (proposal Proposal) ValidateKindContract() error {
	spec, ok := LookupKind(proposal.Kind)
	if !ok {
		return fmt.Errorf("%w: %q", ErrInvalidKind, proposal.Kind)
	}
	if !spec.AllowsActor(proposal.Origin.ActorType()) {
		return fmt.Errorf(
			"%w: %q for %q",
			ErrActorNotAllowed,
			proposal.Origin.ActorType(),
			proposal.Kind,
		)
	}
	switch spec.CASPolicy() {
	case CASRequired:
		if proposal.ExpectedEntityVersion == nil {
			return fmt.Errorf("%w: required for %q", ErrExpectedEntityVersion, proposal.Kind)
		}
	case CASForbidden, CASPayload:
		if proposal.ExpectedEntityVersion != nil {
			return fmt.Errorf("%w: prohibited for %q", ErrExpectedEntityVersion, proposal.Kind)
		}
	case CASConditional:
		// The reducer decides whether this instance is an initial admission or
		// readmission and therefore whether the token is required.
	default:
		return fmt.Errorf("%w: CAS policy for %q", ErrInvalidEnvelope, proposal.Kind)
	}
	if !proposal.EntityID.validFor(spec.EntityIDType()) {
		return fmt.Errorf(
			"%w: %q requires %q",
			ErrInvalidEntityID,
			proposal.Kind,
			spec.EntityIDType(),
		)
	}
	if proposal.Kind == KindAgentSessionStarted {
		entityID, _ := proposal.EntityID.Value()
		if proposal.Origin.ActorType() != ActorAgent ||
			entityID != string(proposal.Origin.AgentSessionID()) ||
			proposal.Origin.Sequence() != 1 {
			return ErrAgentStartBinding
		}
	}
	if proposal.Kind == KindActivityRecorded &&
		proposal.RationaleSummary == "" &&
		len(proposal.Actions) == 0 {
		return fmt.Errorf("%w: activity.recorded is empty", ErrInvalidEnvelope)
	}
	return nil
}

// ValidateForEmission checks both structural and immutable kind contracts.
func (proposal Proposal) ValidateForEmission() error {
	if err := proposal.ValidateEnvelope(); err != nil {
		return err
	}
	return proposal.ValidateKindContract()
}

// VerificationContext binds a received proposal to its authenticated session
// and enrolled device identity key.
type VerificationContext struct {
	SessionID         domain.UUIDv7
	WorkspaceID       domain.UUIDv4
	IdentityPublicKey []byte
}

// SignedEvent retains the exact canonical bytes replicated through Raft.
type SignedEvent struct {
	proposal    Proposal
	signature   []byte
	signedBytes []byte
	canonical   []byte
}

// Proposal returns a deep copy of the decoded proposal.
func (event SignedEvent) Proposal() Proposal {
	return cloneProposal(event.proposal)
}

// OriginSignature returns an independent signature copy.
func (event SignedEvent) OriginSignature() []byte {
	return bytes.Clone(event.signature)
}

// SignedBytes returns JCS(proposal minus origin_signature).
func (event SignedEvent) SignedBytes() []byte {
	return bytes.Clone(event.signedBytes)
}

// CanonicalBytes returns the exact canonical signed proposal replicated by
// the leader.
func (event SignedEvent) CanonicalBytes() []byte {
	return bytes.Clone(event.canonical)
}

// Sign validates and signs a locally constructed proposal with its bound
// device identity key.
func Sign(proposal Proposal, privateKey []byte) (SignedEvent, error) {
	proposal = cloneProposal(proposal)
	payload, err := canonicalPayload(proposal.Payload)
	if err != nil {
		return SignedEvent{}, err
	}
	proposal.Payload = payload
	if err := proposal.ValidateForEmission(); err != nil {
		return SignedEvent{}, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return SignedEvent{}, err
	}
	deviceID, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil {
		return SignedEvent{}, err
	}
	if deviceID != string(proposal.Origin.DeviceID()) {
		return SignedEvent{}, ErrOriginKeyMismatch
	}

	_, signedBytes, err := encodeProposal(
		proposal,
		make([]byte, codecommcrypto.Ed25519SignatureSize),
	)
	if err != nil {
		return SignedEvent{}, err
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureEventOrigin,
		signedBytes,
	)
	if err != nil {
		return SignedEvent{}, err
	}
	canonical, finalSignedBytes, err := encodeProposal(proposal, signature)
	if err != nil {
		return SignedEvent{}, err
	}
	if !bytes.Equal(finalSignedBytes, signedBytes) {
		return SignedEvent{}, errors.New("event: signature changed its own preimage")
	}
	if len(canonical) > MaxEventBytes {
		return SignedEvent{}, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrEventTooLarge,
			len(canonical),
			MaxEventBytes,
		)
	}
	return newSignedEvent(proposal, signature, signedBytes, canonical), nil
}

func validatePayload(payload json.RawMessage) error {
	_, err := canonicalPayload(payload)
	return err
}

func canonicalPayload(payload json.RawMessage) (json.RawMessage, error) {
	if len(payload) > MaxEventBytes {
		return nil, fmt.Errorf(
			"%w: payload got %d bytes, event limit %d",
			ErrEventTooLarge,
			len(payload),
			MaxEventBytes,
		)
	}
	if payload == nil {
		return nil, ErrInvalidPayload
	}
	canonical, err := codec.CanonicalizeSignedObject(payload)
	if err != nil || len(canonical) < 2 || canonical[0] != '{' {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	return json.RawMessage(canonical), nil
}

func validKindText(kind Kind) bool {
	text := string(kind)
	if len(text) < 1 || len(text) > 128 || !utf8.ValidString(text) {
		return false
	}
	for index := range len(text) {
		char := text[index]
		if char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' && index > 0 ||
			(char == '.' || char == '_') && index > 0 {
			continue
		}
		return false
	}
	return text[len(text)-1] != '.' && text[len(text)-1] != '_'
}

func cloneProposal(proposal Proposal) Proposal {
	proposal.ExpectedEntityVersion = cloneUint64Pointer(proposal.ExpectedEntityVersion)
	proposal.Actions = cloneActions(proposal.Actions)
	proposal.Payload = bytes.Clone(proposal.Payload)
	proposal.Redaction = cloneRedaction(proposal.Redaction)
	return proposal
}

func cloneActions(actions []Action) []Action {
	if actions == nil {
		return nil
	}
	result := make([]Action, len(actions))
	for index, action := range actions {
		result[index] = action
		if action.TaskID != nil {
			value := *action.TaskID
			result[index].TaskID = &value
		}
		if action.ArtifactDigest != nil {
			value := *action.ArtifactDigest
			result[index].ArtifactDigest = &value
		}
		if action.StartedAt != nil {
			value := *action.StartedAt
			result[index].StartedAt = &value
		}
		result[index].DurationMS = cloneUint64Pointer(action.DurationMS)
	}
	return result
}

func cloneRedaction(redaction Redaction) Redaction {
	result := Redaction{Policy: redaction.Policy}
	if redaction.FieldsRemoved != nil {
		result.FieldsRemoved = append([]RedactionField{}, redaction.FieldsRemoved...)
	}
	return result
}

func cloneUint64Pointer(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func newSignedEvent(
	proposal Proposal,
	signature []byte,
	signedBytes []byte,
	canonical []byte,
) SignedEvent {
	return SignedEvent{
		proposal:    cloneProposal(proposal),
		signature:   bytes.Clone(signature),
		signedBytes: bytes.Clone(signedBytes),
		canonical:   bytes.Clone(canonical),
	}
}
