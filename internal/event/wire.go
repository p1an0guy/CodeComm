package event

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

type originWire struct {
	DeviceID       string  `json:"device_id"`
	ActorType      string  `json:"actor_type"`
	AgentProfileID *string `json:"agent_profile_id"`
	AgentSessionID *string `json:"agent_session_id"`
	OriginBootID   *string `json:"origin_boot_id"`
	OriginSequence uint64  `json:"origin_sequence"`
}

type actionWire struct {
	Type           string  `json:"type"`
	Target         string  `json:"target"`
	Summary        string  `json:"summary"`
	Status         string  `json:"status"`
	TaskID         *string `json:"task_id,omitempty"`
	ArtifactDigest *string `json:"artifact_digest,omitempty"`
	StartedAt      *string `json:"started_at,omitempty"`
	DurationMS     *uint64 `json:"duration_ms,omitempty"`
}

type redactionWire struct {
	Policy        string   `json:"policy"`
	FieldsRemoved []string `json:"fields_removed"`
}

type proposalWire struct {
	SchemaVersion         uint64          `json:"schema_version"`
	MinApplyLevel         uint64          `json:"min_apply_level"`
	EventID               string          `json:"event_id"`
	SessionID             string          `json:"session_id"`
	WorkspaceID           string          `json:"workspace_id"`
	Origin                originWire      `json:"origin"`
	CreatedAt             string          `json:"created_at"`
	Kind                  string          `json:"kind"`
	EntityID              EntityID        `json:"entity_id"`
	ExpectedEntityVersion *uint64         `json:"expected_entity_version,omitempty"`
	RationaleSummary      string          `json:"rationale_summary"`
	CaptureLevel          string          `json:"capture_level"`
	Actions               []actionWire    `json:"actions"`
	Payload               json.RawMessage `json:"payload"`
	Redaction             redactionWire   `json:"redaction"`
	OriginSignature       *string         `json:"origin_signature,omitempty"`
}

type commandWire struct {
	Kind                  string          `json:"kind"`
	EntityID              EntityID        `json:"entity_id"`
	ExpectedEntityVersion *uint64         `json:"expected_entity_version,omitempty"`
	RationaleSummary      string          `json:"rationale_summary"`
	Actions               []actionWire    `json:"actions"`
	Payload               json.RawMessage `json:"payload"`
	Redaction             redactionWire   `json:"redaction"`
}

var (
	proposalRequiredFields = fieldSet(
		"schema_version",
		"min_apply_level",
		"event_id",
		"session_id",
		"workspace_id",
		"origin",
		"created_at",
		"kind",
		"entity_id",
		"rationale_summary",
		"capture_level",
		"actions",
		"payload",
		"redaction",
		"origin_signature",
	)
	proposalOptionalFields = fieldSet("expected_entity_version")
	commandRequiredFields  = fieldSet(
		"kind",
		"entity_id",
		"rationale_summary",
		"actions",
		"payload",
		"redaction",
	)
	commandOptionalFields = fieldSet("expected_entity_version")
	originRequiredFields  = fieldSet(
		"device_id",
		"actor_type",
		"agent_profile_id",
		"agent_session_id",
		"origin_boot_id",
		"origin_sequence",
	)
	actionRequiredFields = fieldSet("type", "target", "summary", "status")
	actionOptionalFields = fieldSet(
		"task_id",
		"artifact_digest",
		"started_at",
		"duration_ms",
	)
	redactionRequiredFields = fieldSet("policy", "fields_removed")
)

// DecodeLocalCommand parses the strict authority-free local IPC schema.
// Supplying origin is always a dedicated schema error, even when it is null.
func DecodeLocalCommand(input []byte) (Command, error) {
	if len(input) > MaxLocalCommandBytes {
		return Command{}, fmt.Errorf(
			"%w: local body got %d bytes, limit %d",
			ErrEventTooLarge,
			len(input),
			MaxLocalCommandBytes,
		)
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	members, err := objectMembers(canonical)
	if err != nil {
		return Command{}, err
	}
	if _, supplied := members["origin"]; supplied {
		return Command{}, ErrClientSuppliedOrigin
	}
	if err := validateMemberSet(members, commandRequiredFields, commandOptionalFields); err != nil {
		return Command{}, err
	}
	if raw, present := members["expected_entity_version"]; present && bytes.Equal(raw, []byte("null")) {
		return Command{}, ErrExpectedEntityVersion
	}
	if err := rejectNullMembers(members, fieldSet("entity_id")); err != nil {
		return Command{}, err
	}
	if err := validateActivityWireMembers(members["actions"], members["redaction"]); err != nil {
		return Command{}, err
	}

	var wire commandWire
	if err := decodeStrict(canonical, &wire); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	actions, err := actionsFromWire(wire.Actions)
	if err != nil {
		return Command{}, err
	}
	command := Command{
		Kind:                  Kind(wire.Kind),
		EntityID:              wire.EntityID,
		ExpectedEntityVersion: cloneUint64Pointer(wire.ExpectedEntityVersion),
		RationaleSummary:      wire.RationaleSummary,
		Actions:               actions,
		Payload:               bytes.Clone(wire.Payload),
		Redaction:             redactionFromWire(wire.Redaction),
	}
	if err := validateCommandEnvelope(command); err != nil {
		return Command{}, err
	}
	return command, nil
}

// ParseAndVerify validates a canonical network proposal, verifies its exact
// unknown-field-preserving signature preimage, then applies the closed typed
// envelope schema. Domain outcomes remain reducer work.
func ParseAndVerify(input []byte, context VerificationContext) (SignedEvent, error) {
	if len(input) > MaxEventBytes {
		return SignedEvent{}, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrEventTooLarge,
			len(input),
			MaxEventBytes,
		)
	}
	if !context.SessionID.Valid() || !context.WorkspaceID.Valid() {
		return SignedEvent{}, ErrSessionBinding
	}

	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return SignedEvent{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	if !bytes.Equal(input, canonical) {
		return SignedEvent{}, ErrNoncanonicalEvent
	}
	signedBytes, encodedSignature, err := codec.RemoveCanonicalObjectMember(
		canonical,
		"origin_signature",
	)
	if err != nil {
		if errors.Is(err, codec.ErrObjectMemberAbsent) {
			return SignedEvent{}, fmt.Errorf(
				"%w: origin_signature",
				ErrMissingField,
			)
		}
		return SignedEvent{}, fmt.Errorf(
			"%w: origin_signature: %v",
			ErrInvalidEnvelope,
			err,
		)
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil {
		return SignedEvent{}, fmt.Errorf("%w: origin_signature", ErrInvalidEnvelope)
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		codecommcrypto.Ed25519SignatureSize,
	)
	if err != nil {
		return SignedEvent{}, err
	}

	prevalidated, err := decodeProposalLenient(canonical)
	if err != nil {
		return SignedEvent{}, err
	}
	if err := prevalidated.ValidateEnvelope(); err != nil {
		return SignedEvent{}, err
	}
	derivedDeviceID, err := codec.DeriveDeviceID(ed25519.PublicKey(context.IdentityPublicKey))
	if err != nil {
		return SignedEvent{}, err
	}
	if derivedDeviceID != string(prevalidated.Origin.DeviceID()) {
		return SignedEvent{}, ErrOriginKeyMismatch
	}
	if err := codecommcrypto.VerifyEd25519(
		context.IdentityPublicKey,
		codec.SignatureEventOrigin,
		signedBytes,
		signature,
	); err != nil {
		return SignedEvent{}, err
	}

	proposal, err := decodeProposal(canonical)
	if err != nil {
		return SignedEvent{}, err
	}
	if err := proposal.ValidateEnvelope(); err != nil {
		return SignedEvent{}, err
	}
	if proposal.SessionID != context.SessionID ||
		proposal.WorkspaceID != context.WorkspaceID {
		return SignedEvent{}, ErrSessionBinding
	}
	return newSignedEvent(proposal, signature, signedBytes, canonical), nil
}

func encodeProposal(proposal Proposal, signature []byte) ([]byte, []byte, error) {
	wire := proposalToWire(proposal)
	unsignedJSON, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("event: marshal signature preimage: %w", err)
	}
	signedBytes, err := codec.CanonicalizeSignedObject(unsignedJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("event: canonicalize signature preimage: %w", err)
	}

	signatureText := codec.EncodeBase64URL(signature)
	wire.OriginSignature = &signatureText
	completeJSON, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("event: marshal signed proposal: %w", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(completeJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("event: canonicalize signed proposal: %w", err)
	}
	return canonical, signedBytes, nil
}

func proposalToWire(proposal Proposal) proposalWire {
	return proposalWire{
		SchemaVersion:         proposal.SchemaVersion,
		MinApplyLevel:         proposal.MinApplyLevel,
		EventID:               string(proposal.EventID),
		SessionID:             string(proposal.SessionID),
		WorkspaceID:           string(proposal.WorkspaceID),
		Origin:                originToWire(proposal.Origin),
		CreatedAt:             string(proposal.CreatedAt),
		Kind:                  string(proposal.Kind),
		EntityID:              proposal.EntityID,
		ExpectedEntityVersion: cloneUint64Pointer(proposal.ExpectedEntityVersion),
		RationaleSummary:      proposal.RationaleSummary,
		CaptureLevel:          string(proposal.CaptureLevel),
		Actions:               actionsToWire(proposal.Actions),
		Payload:               bytes.Clone(proposal.Payload),
		Redaction:             redactionToWire(proposal.Redaction),
	}
}

func originToWire(origin Origin) originWire {
	wire := originWire{
		DeviceID:       string(origin.DeviceID()),
		ActorType:      string(origin.ActorType()),
		OriginSequence: origin.Sequence(),
	}
	if profile, present := origin.AgentProfileID(); present {
		wire.AgentProfileID = stringPointer(profile)
	}
	if origin.AgentSessionID() != "" {
		wire.AgentSessionID = stringPointer(string(origin.AgentSessionID()))
	}
	if origin.OriginBootID() != "" {
		wire.OriginBootID = stringPointer(string(origin.OriginBootID()))
	}
	return wire
}

func actionsToWire(actions []Action) []actionWire {
	if actions == nil {
		return nil
	}
	result := make([]actionWire, len(actions))
	for index, action := range actions {
		result[index] = actionWire{
			Type:       string(action.Type),
			Target:     action.Target,
			Summary:    action.Summary,
			Status:     string(action.Status),
			DurationMS: cloneUint64Pointer(action.DurationMS),
		}
		if action.TaskID != nil {
			result[index].TaskID = stringPointer(string(*action.TaskID))
		}
		if action.ArtifactDigest != nil {
			result[index].ArtifactDigest = stringPointer(
				codec.EncodeBase64URL(action.ArtifactDigest[:]),
			)
		}
		if action.StartedAt != nil {
			result[index].StartedAt = stringPointer(string(*action.StartedAt))
		}
	}
	return result
}

func redactionToWire(redaction Redaction) redactionWire {
	fields := make([]string, len(redaction.FieldsRemoved))
	for index, field := range redaction.FieldsRemoved {
		fields[index] = string(field)
	}
	return redactionWire{
		Policy:        string(redaction.Policy),
		FieldsRemoved: fields,
	}
}

func decodeProposal(canonical []byte) (Proposal, error) {
	members, err := objectMembers(canonical)
	if err != nil {
		return Proposal{}, err
	}
	if err := validateMemberSet(members, proposalRequiredFields, proposalOptionalFields); err != nil {
		return Proposal{}, err
	}
	if raw, present := members["expected_entity_version"]; present && bytes.Equal(raw, []byte("null")) {
		return Proposal{}, ErrExpectedEntityVersion
	}
	if err := rejectNullMembers(members, fieldSet("entity_id")); err != nil {
		return Proposal{}, err
	}
	if err := validateOriginWireMembers(members["origin"], true); err != nil {
		return Proposal{}, fmt.Errorf("event: origin: %w", err)
	}
	if err := validateActivityWireMembers(members["actions"], members["redaction"]); err != nil {
		return Proposal{}, err
	}

	var wire proposalWire
	if err := decodeStrict(canonical, &wire); err != nil {
		return Proposal{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	return proposalFromWire(wire)
}

// decodeProposalLenient validates all known required fields and their bounds
// before signature work while deliberately ignoring unknown members. The
// strict decoder runs only after verification, so an extension is never
// stripped from the signature preimage.
func decodeProposalLenient(canonical []byte) (Proposal, error) {
	members, err := objectMembers(canonical)
	if err != nil {
		return Proposal{}, err
	}
	if err := validateRequiredMembers(members, proposalRequiredFields); err != nil {
		return Proposal{}, err
	}
	if raw, present := members["expected_entity_version"]; present && bytes.Equal(raw, []byte("null")) {
		return Proposal{}, ErrExpectedEntityVersion
	}
	if err := rejectNullMembers(members, fieldSet("entity_id")); err != nil {
		return Proposal{}, err
	}
	if err := validateOriginWireMembers(members["origin"], false); err != nil {
		return Proposal{}, fmt.Errorf("event: origin: %w", err)
	}
	if err := validateActivityWireShape(members["actions"], members["redaction"]); err != nil {
		return Proposal{}, err
	}

	var wire proposalWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return Proposal{}, fmt.Errorf("%w: %w", ErrInvalidEnvelope, err)
	}
	return proposalFromWire(wire)
}

func proposalFromWire(wire proposalWire) (Proposal, error) {
	origin, err := originFromWire(wire.Origin)
	if err != nil {
		return Proposal{}, err
	}
	actions, err := actionsFromWire(wire.Actions)
	if err != nil {
		return Proposal{}, err
	}
	return Proposal{
		SchemaVersion:         wire.SchemaVersion,
		MinApplyLevel:         wire.MinApplyLevel,
		EventID:               domain.UUIDv7(wire.EventID),
		SessionID:             domain.UUIDv7(wire.SessionID),
		WorkspaceID:           domain.UUIDv4(wire.WorkspaceID),
		Origin:                origin,
		CreatedAt:             domain.Timestamp(wire.CreatedAt),
		Kind:                  Kind(wire.Kind),
		EntityID:              wire.EntityID,
		ExpectedEntityVersion: cloneUint64Pointer(wire.ExpectedEntityVersion),
		RationaleSummary:      wire.RationaleSummary,
		CaptureLevel:          CaptureLevel(wire.CaptureLevel),
		Actions:               actions,
		Payload:               bytes.Clone(wire.Payload),
		Redaction:             redactionFromWire(wire.Redaction),
	}, nil
}

func originFromWire(wire originWire) (Origin, error) {
	origin := Origin{
		deviceID:  domain.DeviceID(wire.DeviceID),
		actorType: ActorType(wire.ActorType),
		sequence:  wire.OriginSequence,
	}
	if wire.AgentProfileID != nil {
		origin.agentProfileID = *wire.AgentProfileID
		origin.profilePresent = true
	}
	if wire.AgentSessionID != nil {
		origin.agentSessionID = domain.UUIDv7(*wire.AgentSessionID)
	}
	if wire.OriginBootID != nil {
		origin.originBootID = domain.UUIDv7(*wire.OriginBootID)
	}
	if err := origin.validate(); err != nil {
		return Origin{}, err
	}
	return origin, nil
}

func actionsFromWire(wires []actionWire) ([]Action, error) {
	if wires == nil {
		return nil, nil
	}
	actions := make([]Action, len(wires))
	for index, wire := range wires {
		action := Action{
			Type:       ActionType(wire.Type),
			Target:     wire.Target,
			Summary:    wire.Summary,
			Status:     ActionStatus(wire.Status),
			DurationMS: cloneUint64Pointer(wire.DurationMS),
		}
		if wire.TaskID != nil {
			value := domain.UUIDv7(*wire.TaskID)
			action.TaskID = &value
		}
		if wire.ArtifactDigest != nil {
			value, err := codec.DecodeBase64URLExact(
				*wire.ArtifactDigest,
				codecommcrypto.SHA256Size,
			)
			if err != nil {
				return nil, fmt.Errorf("event: actions[%d].artifact_digest: %w", index, err)
			}
			var digest SHA256Digest
			copy(digest[:], value)
			action.ArtifactDigest = &digest
		}
		if wire.StartedAt != nil {
			value := domain.Timestamp(*wire.StartedAt)
			action.StartedAt = &value
		}
		if err := action.Validate(); err != nil {
			return nil, fmt.Errorf("event: actions[%d]: %w", index, err)
		}
		actions[index] = action
	}
	return actions, nil
}

func redactionFromWire(wire redactionWire) Redaction {
	fields := make([]RedactionField, len(wire.FieldsRemoved))
	for index, field := range wire.FieldsRemoved {
		fields[index] = RedactionField(field)
	}
	return Redaction{
		Policy:        RedactionPolicy(wire.Policy),
		FieldsRemoved: fields,
	}
}

func validateCommandEnvelope(command Command) error {
	if _, ok := LookupKind(command.Kind); !ok {
		return fmt.Errorf("%w: %q", ErrInvalidKind, command.Kind)
	}
	if !command.EntityID.validGeneralForm() {
		return ErrInvalidEntityID
	}
	if command.ExpectedEntityVersion != nil &&
		(*command.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*command.ExpectedEntityVersion)) {
		return ErrExpectedEntityVersion
	}
	if !validText(command.RationaleSummary, 0, MaxRationaleSummaryBytes, true) {
		return fmt.Errorf("%w: rationale_summary", ErrInvalidEnvelope)
	}
	if command.Actions == nil || len(command.Actions) > MaxActions {
		return fmt.Errorf("%w: actions count %d", ErrInvalidEnvelope, len(command.Actions))
	}
	for index, action := range command.Actions {
		if err := action.Validate(); err != nil {
			return fmt.Errorf("event: actions[%d]: %w", index, err)
		}
	}
	if err := validatePayload(command.Payload); err != nil {
		return err
	}
	return command.Redaction.Validate()
}

func validateActivityWireMembers(actionsRaw, redactionRaw json.RawMessage) error {
	if err := validateActivityWireShape(actionsRaw, redactionRaw); err != nil {
		return err
	}
	var actionValues []json.RawMessage
	_ = json.Unmarshal(actionsRaw, &actionValues)
	for index, raw := range actionValues {
		if err := validateMemberObject(raw, actionRequiredFields, actionOptionalFields); err != nil {
			return fmt.Errorf("event: actions[%d]: %w", index, err)
		}
		members, _ := objectMembers(raw)
		for _, optional := range []string{
			"task_id",
			"artifact_digest",
			"started_at",
			"duration_ms",
		} {
			if value, present := members[optional]; present && bytes.Equal(value, []byte("null")) {
				return fmt.Errorf("%w: actions[%d].%s", ErrInvalidEnvelope, index, optional)
			}
		}
	}
	if err := validateMemberObject(redactionRaw, redactionRequiredFields, nil); err != nil {
		return fmt.Errorf("event: redaction: %w", err)
	}
	return nil
}

func validateActivityWireShape(actionsRaw, redactionRaw json.RawMessage) error {
	var actionValues []json.RawMessage
	if err := json.Unmarshal(actionsRaw, &actionValues); err != nil || actionValues == nil {
		return fmt.Errorf("%w: actions", ErrInvalidEnvelope)
	}
	if len(actionValues) > MaxActions {
		return fmt.Errorf("%w: actions count %d", ErrInvalidEnvelope, len(actionValues))
	}
	for index, raw := range actionValues {
		if err := validateRequiredMemberObject(raw, actionRequiredFields); err != nil {
			return fmt.Errorf("event: actions[%d]: %w", index, err)
		}
		members, _ := objectMembers(raw)
		if err := rejectNullMembers(members, nil); err != nil {
			return fmt.Errorf("event: actions[%d]: %w", index, err)
		}
		for _, optional := range []string{
			"task_id",
			"artifact_digest",
			"started_at",
			"duration_ms",
		} {
			if value, present := members[optional]; present && bytes.Equal(value, []byte("null")) {
				return fmt.Errorf("%w: actions[%d].%s", ErrInvalidEnvelope, index, optional)
			}
		}
	}
	if err := validateRequiredMemberObject(redactionRaw, redactionRequiredFields); err != nil {
		return fmt.Errorf("event: redaction: %w", err)
	}
	redactionMembers, _ := objectMembers(redactionRaw)
	if err := rejectNullMembers(redactionMembers, nil); err != nil {
		return fmt.Errorf("event: redaction: %w", err)
	}
	return nil
}

func validateOriginWireMembers(input json.RawMessage, strict bool) error {
	members, err := objectMembers(input)
	if err != nil {
		return err
	}
	if strict {
		if err := validateMemberSet(members, originRequiredFields, nil); err != nil {
			return err
		}
	} else if err := validateRequiredMembers(members, originRequiredFields); err != nil {
		return err
	}
	return rejectNullMembers(
		members,
		fieldSet("agent_profile_id", "agent_session_id", "origin_boot_id"),
	)
}

func fieldSet(fields ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result
}

func objectMembers(input []byte) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(input, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: expected object", ErrInvalidEnvelope)
	}
	return members, nil
}

func validateMemberObject(
	input []byte,
	required map[string]struct{},
	optional map[string]struct{},
) error {
	members, err := objectMembers(input)
	if err != nil {
		return err
	}
	return validateMemberSet(members, required, optional)
}

func validateRequiredMemberObject(input []byte, required map[string]struct{}) error {
	members, err := objectMembers(input)
	if err != nil {
		return err
	}
	return validateRequiredMembers(members, required)
}

func validateRequiredMembers(
	members map[string]json.RawMessage,
	required map[string]struct{},
) error {
	for field := range required {
		if _, ok := members[field]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingField, field)
		}
	}
	return nil
}

func rejectNullMembers(
	members map[string]json.RawMessage,
	nullable map[string]struct{},
) error {
	for field, value := range members {
		if !bytes.Equal(value, []byte("null")) {
			continue
		}
		if _, allowed := nullable[field]; allowed {
			continue
		}
		return fmt.Errorf("%w: %s must not be null", ErrInvalidEnvelope, field)
	}
	return nil
}

func validateMemberSet(
	members map[string]json.RawMessage,
	required map[string]struct{},
	optional map[string]struct{},
) error {
	for field := range members {
		if _, ok := required[field]; ok {
			continue
		}
		if _, ok := optional[field]; ok {
			continue
		}
		return fmt.Errorf("%w: %s", ErrUnknownField, field)
	}
	for field := range required {
		if _, ok := members[field]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingField, field)
		}
	}
	return nil
}

func decodeStrict(input []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return codec.ErrTrailingData
		}
		return err
	}
	return nil
}

func stringPointer(value string) *string {
	return &value
}
