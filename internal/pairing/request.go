package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var (
	ErrInvalidRequest      = errors.New("pairing: invalid request")
	ErrRequestTooLarge     = errors.New("pairing: request exceeds message limit")
	ErrRequestNoncanonical = errors.New("pairing: request is not canonical")
	ErrRequestSchema       = errors.New("pairing: unsupported request schema")
	ErrRequestUnknownField = errors.New("pairing: unknown request field")
	ErrRequestCore         = errors.New("pairing: invalid request core")
	ErrRequestInvite       = errors.New("pairing: request does not match invite")
	ErrInviteProof         = errors.New("pairing: invite proof failed")
)

// RequestCore is the exact operator-approved joiner identity and initial key.
type RequestCore struct {
	AttemptID               domain.UUIDv7
	JoinerDeviceID          domain.DeviceID
	JoinerIdentityPublicKey [ed25519.PublicKeySize]byte
	DaemonVersion           string
	MaxApplyLevel           uint64
	InitialEpochBinding     credential.Binding
}

// CanonicalRequestCore retains immutable JCS bytes for transcript binding.
type CanonicalRequestCore struct {
	value     RequestCore
	canonical []byte
}

type epochBindingWire struct {
	Epoch            uint64 `json:"epoch"`
	EpochPublicKey   string `json:"epoch_public_key"`
	KeyDigest        string `json:"key_digest"`
	BindingSignature string `json:"binding_signature"`
}

type requestCoreWire struct {
	SchemaVersion           uint64           `json:"schema_version"`
	AttemptID               string           `json:"attempt_id"`
	JoinerDeviceID          string           `json:"joiner_device_id"`
	JoinerIdentityPublicKey string           `json:"joiner_identity_public_key"`
	DaemonVersion           string           `json:"daemon_version"`
	MaxApplyLevel           uint64           `json:"max_apply_level"`
	InitialEpochBinding     epochBindingWire `json:"initial_epoch_binding"`
}

type requestWire struct {
	SchemaVersion uint64          `json:"schema_version"`
	InviteID      string          `json:"invite_id"`
	InviteDigest  string          `json:"invite_digest"`
	RequestCore   json.RawMessage `json:"request_core"`
	Proof         string          `json:"proof"`
}

// Request is a canonical exporter-bound pairing request. It contains no invite secret.
type Request struct {
	inviteID     domain.UUIDv7
	inviteDigest [sha256.Size]byte
	coreRaw      []byte
	proof        [ProofSize]byte
	canonical    []byte
}

// VerifiedRequest is authenticated by the invite and current TLS connection.
type VerifiedRequest struct {
	request        Request
	core           CanonicalRequestCore
	transcriptHash [sha256.Size]byte
}

// VerificationContext is the non-secret issuer state needed to bind a
// request to one persisted invite.
type VerificationContext struct {
	inviteID                 domain.UUIDv7
	sessionID                domain.UUIDv7
	inviteDigest             [sha256.Size]byte
	inviterIdentityPublicKey [ed25519.PublicKeySize]byte
	subjectDeviceID          *domain.DeviceID
	initialCredentialEpoch   uint64
}

// ProofAttempt is a structurally valid, exporter-bound request whose HMAC has
// not yet been accepted. Its transcript fields remain available when proof
// verification fails so the issuer can durably charge the attempt.
type ProofAttempt struct {
	request        Request
	core           CanonicalRequestCore
	transcriptHash [sha256.Size]byte
}

// NewVerificationContext reconstructs the non-secret portion of an invite
// from issuer-local durable state.
func NewVerificationContext(
	inviteID domain.UUIDv7,
	sessionID domain.UUIDv7,
	inviteDigest [sha256.Size]byte,
	inviterIdentityPublicKey []byte,
	subjectDeviceID *domain.DeviceID,
	initialCredentialEpoch uint64,
) (VerificationContext, error) {
	if !inviteID.Valid() || !sessionID.Valid() ||
		len(inviterIdentityPublicKey) != ed25519.PublicKeySize ||
		initialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(initialCredentialEpoch) ||
		subjectDeviceID != nil && !subjectDeviceID.Valid() {
		return VerificationContext{}, ErrRequestInvite
	}
	result := VerificationContext{
		inviteID: inviteID, sessionID: sessionID, inviteDigest: inviteDigest,
		initialCredentialEpoch: initialCredentialEpoch,
	}
	copy(result.inviterIdentityPublicKey[:], inviterIdentityPublicKey)
	if subjectDeviceID != nil {
		subject := *subjectDeviceID
		result.subjectDeviceID = &subject
	}
	return result, nil
}

// VerificationContext returns the persisted, non-secret verification fields
// represented by this signed invite.
func (invite SignedInvite) VerificationContext() (VerificationContext, error) {
	if err := invite.Validate(); err != nil {
		return VerificationContext{}, err
	}
	value := invite.Invite()
	defer clear(value.Secret[:])
	return NewVerificationContext(
		value.InviteID,
		value.SessionID,
		invite.Digest(),
		value.InviterIdentityPublicKey[:],
		value.SubjectDeviceID,
		value.InitialCredentialEpoch,
	)
}

// NewRequestCore validates and canonicalizes all joiner-approved fields.
func NewRequestCore(value RequestCore) (CanonicalRequestCore, error) {
	if err := validateRequestCore(value); err != nil {
		return CanonicalRequestCore{}, err
	}
	wire := requestCoreToWire(value)
	raw, err := json.Marshal(wire)
	if err != nil {
		return CanonicalRequestCore{}, fmt.Errorf("%w: encode: %v", ErrRequestCore, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return CanonicalRequestCore{}, fmt.Errorf("%w: canonicalize: %v", ErrRequestCore, err)
	}
	return CanonicalRequestCore{value: value, canonical: bytes.Clone(canonical)}, nil
}

// ParseRequestCore validates exact canonical bytes for one invite session.
func ParseRequestCore(
	input []byte,
	sessionID domain.UUIDv7,
) (CanonicalRequestCore, error) {
	return parseRequestCore(input, sessionID)
}

// Value returns an independent value copy.
func (core CanonicalRequestCore) Value() RequestCore { return core.value }

// CanonicalBytes returns a private copy of the transcript-bound core.
func (core CanonicalRequestCore) CanonicalBytes() []byte { return bytes.Clone(core.canonical) }

// BuildRequest proves possession of an invite without transmitting its secret.
func BuildRequest(
	invite SignedInvite,
	core CanonicalRequestCore,
	exporter []byte,
) (Request, error) {
	inviteValue := invite.Invite()
	defer clear(inviteValue.Secret[:])
	if len(invite.canonical) == 0 || len(core.canonical) == 0 ||
		core.value.InitialEpochBinding.SessionID != inviteValue.SessionID ||
		core.value.InitialEpochBinding.Epoch != inviteValue.InitialCredentialEpoch ||
		inviteValue.SubjectDeviceID != nil && *inviteValue.SubjectDeviceID != core.value.JoinerDeviceID {
		return Request{}, ErrRequestInvite
	}
	transcriptHash, err := buildTranscriptHash(
		exporter,
		inviteValue.InviterIdentityPublicKey[:],
		core.value.JoinerIdentityPublicKey[:],
		invite.digest,
		core.canonical,
	)
	if err != nil {
		return Request{}, err
	}
	request := Request{
		inviteID: inviteValue.InviteID, inviteDigest: invite.digest,
		coreRaw: bytes.Clone(core.canonical), proof: inviteProof(inviteValue.Secret, transcriptHash),
	}
	canonical, err := encodeRequest(request)
	if err != nil {
		return Request{}, err
	}
	request.canonical = canonical
	return request, nil
}

// ParseRequest performs bounded canonical and closed-schema decoding before proof work.
func ParseRequest(input []byte) (Request, error) {
	if len(input) == 0 {
		return Request{}, ErrInvalidRequest
	}
	if len(input) > MaxPairingMessageBytes {
		return Request{}, ErrRequestTooLarge
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if !bytes.Equal(input, canonical) {
		return Request{}, ErrRequestNoncanonical
	}
	if err := validateClosedObject(canonical, []string{
		"schema_version", "invite_id", "invite_digest", "request_core", "proof",
	}); err != nil {
		return Request{}, err
	}
	var wire requestWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return Request{}, fmt.Errorf("%w: decode: %v", ErrInvalidRequest, err)
	}
	if wire.SchemaVersion != SchemaVersion {
		return Request{}, ErrRequestSchema
	}
	inviteID := domain.UUIDv7(wire.InviteID)
	inviteDigest, digestErr := codec.DecodeBase64URLExact(wire.InviteDigest, sha256.Size)
	proof, proofErr := codec.DecodeBase64URLExact(wire.Proof, ProofSize)
	if !inviteID.Valid() || digestErr != nil || proofErr != nil || len(wire.RequestCore) == 0 {
		return Request{}, ErrInvalidRequest
	}
	request := Request{inviteID: inviteID, coreRaw: bytes.Clone(wire.RequestCore), canonical: bytes.Clone(canonical)}
	copy(request.inviteDigest[:], inviteDigest)
	copy(request.proof[:], proof)
	return request, nil
}

// Verify authenticates the request against an exact invite and TLS exporter.
func (request Request) Verify(invite SignedInvite, exporter []byte) (VerifiedRequest, error) {
	inviteValue := invite.Invite()
	defer clear(inviteValue.Secret[:])
	verificationContext, err := invite.VerificationContext()
	if err != nil {
		return VerifiedRequest{}, err
	}
	attempt, err := request.PrepareVerification(verificationContext, exporter)
	if err != nil {
		return VerifiedRequest{}, err
	}
	return attempt.VerifyProof(inviteValue.Secret)
}

// PrepareVerification validates every non-secret request field and binds it
// to the current TLS exporter. A returned attempt is safe to persist as a
// failed-proof observation if VerifyProof returns ErrInviteProof.
func (request Request) PrepareVerification(
	context VerificationContext,
	exporter []byte,
) (ProofAttempt, error) {
	if request.inviteID != context.inviteID ||
		request.inviteDigest != context.inviteDigest {
		return ProofAttempt{}, ErrRequestInvite
	}
	core, err := parseRequestCore(request.coreRaw, context.sessionID)
	if err != nil {
		return ProofAttempt{}, err
	}
	if core.value.InitialEpochBinding.Epoch != context.initialCredentialEpoch ||
		context.subjectDeviceID != nil &&
			*context.subjectDeviceID != core.value.JoinerDeviceID {
		return ProofAttempt{}, ErrRequestInvite
	}
	transcriptHash, err := buildTranscriptHash(
		exporter,
		context.inviterIdentityPublicKey[:],
		core.value.JoinerIdentityPublicKey[:],
		context.inviteDigest,
		core.canonical,
	)
	if err != nil {
		return ProofAttempt{}, err
	}
	return ProofAttempt{
		request: request.clone(), core: core, transcriptHash: transcriptHash,
	}, nil
}

// VerifyProof performs the constant-time one-use-secret check.
func (attempt ProofAttempt) VerifyProof(
	secret [InviteSecretSize]byte,
) (VerifiedRequest, error) {
	defer clear(secret[:])
	if len(attempt.request.canonical) == 0 || len(attempt.core.canonical) == 0 {
		return VerifiedRequest{}, ErrInvalidRequest
	}
	if !proofEqual(
		attempt.request.proof,
		inviteProof(secret, attempt.transcriptHash),
	) {
		return VerifiedRequest{}, ErrInviteProof
	}
	return VerifiedRequest{
		request:        attempt.request.clone(),
		core:           attempt.core.clone(),
		transcriptHash: attempt.transcriptHash,
	}, nil
}

// InviteID returns the local one-use invite lookup key.
func (request Request) InviteID() domain.UUIDv7 { return request.inviteID }

// CanonicalBytes returns a private copy of the complete request.
func (request Request) CanonicalBytes() []byte { return bytes.Clone(request.canonical) }

// Digest returns SHA-256 over the complete canonical request.
func (request Request) Digest() [sha256.Size]byte { return sha256.Sum256(request.canonical) }

// Core returns the exact authenticated request core.
func (request VerifiedRequest) Core() CanonicalRequestCore { return request.core.clone() }

// TranscriptHash returns the exporter-bound transcript commitment.
func (request VerifiedRequest) TranscriptHash() [sha256.Size]byte { return request.transcriptHash }

// InviteID returns the consumed invite identifier.
func (request VerifiedRequest) InviteID() domain.UUIDv7 { return request.request.inviteID }

// InviteDigest returns the complete signed invite commitment.
func (request VerifiedRequest) InviteDigest() [sha256.Size]byte {
	return request.request.inviteDigest
}

// RequestDigest returns SHA-256 over the complete canonical request.
func (request VerifiedRequest) RequestDigest() [sha256.Size]byte {
	return request.request.Digest()
}

// SAS returns the normative five-group authentication string.
func (request VerifiedRequest) SAS() string { return renderSAS(request.transcriptHash) }

// Core returns the exact structurally valid request core, even when the proof
// is later rejected.
func (attempt ProofAttempt) Core() CanonicalRequestCore { return attempt.core.clone() }

// TranscriptHash returns the exporter-bound transcript commitment.
func (attempt ProofAttempt) TranscriptHash() [sha256.Size]byte {
	return attempt.transcriptHash
}

// InviteID returns the invite named by this attempt.
func (attempt ProofAttempt) InviteID() domain.UUIDv7 { return attempt.request.inviteID }

// InviteDigest returns the complete signed invite commitment.
func (attempt ProofAttempt) InviteDigest() [sha256.Size]byte {
	return attempt.request.inviteDigest
}

// RequestDigest returns SHA-256 over the complete canonical request.
func (attempt ProofAttempt) RequestDigest() [sha256.Size]byte {
	return attempt.request.Digest()
}

func encodeRequest(request Request) ([]byte, error) {
	raw, err := json.Marshal(requestWire{
		SchemaVersion: SchemaVersion,
		InviteID:      string(request.inviteID),
		InviteDigest:  codec.EncodeBase64URL(request.inviteDigest[:]),
		RequestCore:   json.RawMessage(request.coreRaw),
		Proof:         codec.EncodeBase64URL(request.proof[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidRequest, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidRequest, err)
	}
	if len(canonical) > MaxPairingMessageBytes {
		return nil, ErrRequestTooLarge
	}
	return bytes.Clone(canonical), nil
}

func parseRequestCore(input []byte, sessionID domain.UUIDv7) (CanonicalRequestCore, error) {
	if len(input) == 0 || len(input) > MaxPairingMessageBytes || !sessionID.Valid() {
		return CanonicalRequestCore{}, ErrRequestCore
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(input, canonical) {
		return CanonicalRequestCore{}, ErrRequestCore
	}
	coreFields := []string{
		"schema_version", "attempt_id", "joiner_device_id",
		"joiner_identity_public_key", "daemon_version", "max_apply_level",
		"initial_epoch_binding",
	}
	if err := validateClosedObject(canonical, coreFields); err != nil {
		return CanonicalRequestCore{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return CanonicalRequestCore{}, ErrRequestCore
	}
	if err := validateClosedObject(members["initial_epoch_binding"], []string{
		"epoch", "epoch_public_key", "key_digest", "binding_signature",
	}); err != nil {
		return CanonicalRequestCore{}, err
	}
	var wire requestCoreWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return CanonicalRequestCore{}, ErrRequestCore
	}
	if wire.SchemaVersion != SchemaVersion {
		return CanonicalRequestCore{}, ErrRequestSchema
	}
	identityKey, keyErr := codec.DecodeBase64URLExact(
		wire.JoinerIdentityPublicKey, ed25519.PublicKeySize,
	)
	epochKey, epochKeyErr := codec.DecodeBase64URLExact(
		wire.InitialEpochBinding.EpochPublicKey, ed25519.PublicKeySize,
	)
	digest, digestErr := codec.DecodeBase64URLExact(
		wire.InitialEpochBinding.KeyDigest, sha256.Size,
	)
	signature, signatureErr := codec.DecodeBase64URLExact(
		wire.InitialEpochBinding.BindingSignature, ed25519.SignatureSize,
	)
	if keyErr != nil || epochKeyErr != nil || digestErr != nil || signatureErr != nil {
		return CanonicalRequestCore{}, ErrRequestCore
	}
	value := RequestCore{
		AttemptID:      domain.UUIDv7(wire.AttemptID),
		JoinerDeviceID: domain.DeviceID(wire.JoinerDeviceID),
		DaemonVersion:  wire.DaemonVersion, MaxApplyLevel: wire.MaxApplyLevel,
		InitialEpochBinding: credential.Binding{
			SessionID: sessionID, DeviceID: domain.DeviceID(wire.JoinerDeviceID),
			Epoch: wire.InitialEpochBinding.Epoch,
		},
	}
	copy(value.JoinerIdentityPublicKey[:], identityKey)
	copy(value.InitialEpochBinding.EpochPublicKey[:], epochKey)
	copy(value.InitialEpochBinding.KeyDigest[:], digest)
	copy(value.InitialEpochBinding.Signature[:], signature)
	if err := validateRequestCore(value); err != nil {
		return CanonicalRequestCore{}, err
	}
	return CanonicalRequestCore{value: value, canonical: bytes.Clone(canonical)}, nil
}

func validateRequestCore(value RequestCore) error {
	if !value.AttemptID.Valid() || !value.JoinerDeviceID.Valid() ||
		!device.ValidDaemonVersion(value.DaemonVersion) ||
		value.MaxApplyLevel < 1 || value.MaxApplyLevel > domain.MaxApplyLevel ||
		value.InitialEpochBinding.DeviceID != value.JoinerDeviceID {
		return ErrRequestCore
	}
	derivedID, err := device.DeriveID(value.JoinerIdentityPublicKey[:])
	if err != nil || derivedID != value.JoinerDeviceID {
		return ErrRequestCore
	}
	if err := value.InitialEpochBinding.Validate(value.JoinerIdentityPublicKey[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrRequestCore, err)
	}
	return nil
}

func requestCoreToWire(value RequestCore) requestCoreWire {
	return requestCoreWire{
		SchemaVersion: SchemaVersion, AttemptID: string(value.AttemptID),
		JoinerDeviceID:          string(value.JoinerDeviceID),
		JoinerIdentityPublicKey: codec.EncodeBase64URL(value.JoinerIdentityPublicKey[:]),
		DaemonVersion:           value.DaemonVersion, MaxApplyLevel: value.MaxApplyLevel,
		InitialEpochBinding: epochBindingWire{
			Epoch:            value.InitialEpochBinding.Epoch,
			EpochPublicKey:   codec.EncodeBase64URL(value.InitialEpochBinding.EpochPublicKey[:]),
			KeyDigest:        codec.EncodeBase64URL(value.InitialEpochBinding.KeyDigest[:]),
			BindingSignature: codec.EncodeBase64URL(value.InitialEpochBinding.Signature[:]),
		},
	}
}

func validateClosedObject(input []byte, fields []string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(input, &members); err != nil {
		return ErrInvalidRequest
	}
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	for field := range members {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("%w: %s", ErrRequestUnknownField, field)
		}
	}
	if len(members) != len(fields) {
		return ErrInvalidRequest
	}
	return nil
}

func (request Request) clone() Request {
	request.coreRaw = bytes.Clone(request.coreRaw)
	request.canonical = bytes.Clone(request.canonical)
	return request
}

func (core CanonicalRequestCore) clone() CanonicalRequestCore {
	core.canonical = bytes.Clone(core.canonical)
	return core
}
