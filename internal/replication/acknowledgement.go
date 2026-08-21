package replication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	AcknowledgementObjectKind = "replication_acknowledgement"
	MaxAcknowledgementBytes   = 4 << 10

	acknowledgementSignatureTextBytes = 86
)

var (
	ErrInvalidAcknowledgement = errors.New(
		"replication: invalid acknowledgement",
	)
	ErrAcknowledgementTooLarge = errors.New(
		"replication: acknowledgement exceeds size limit",
	)
	ErrNoncanonicalAcknowledgement = errors.New(
		"replication: acknowledgement is not canonical",
	)
)

// AcknowledgementInput is the complete variable tuple covered by an
// equal-cursor acknowledgement signature. The fixed object kind is also part
// of the signature preimage.
type AcknowledgementInput struct {
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	ServerDeviceID           domain.DeviceID
	ServerAuthorityVersion   uint64
	ResultIndex              uint64
	ResultHash               chain.Digest
	ChainIndex               uint64
	ChainHash                chain.Digest
	ProjectionAccumulator    chain.Digest
	ProjectionStateDigest    chain.Digest
	ServerAppliedResultIndex uint64
}

// AcknowledgementMetadata contains every signed field except the signature.
type AcknowledgementMetadata struct {
	ObjectKind               string
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	ServerDeviceID           domain.DeviceID
	ServerAuthorityVersion   uint64
	ResultIndex              uint64
	ResultHash               chain.Digest
	ChainIndex               uint64
	ChainHash                chain.Digest
	ProjectionAccumulator    chain.Digest
	ProjectionStateDigest    chain.Digest
	ServerAppliedResultIndex uint64
}

// UnsignedAcknowledgement is an immutable, validated acknowledgement
// signature preimage.
type UnsignedAcknowledgement struct {
	input     AcknowledgementInput
	canonical []byte
	valid     bool
}

// Acknowledgement is an immutable identity-signed equal-cursor
// acknowledgement.
type Acknowledgement struct {
	unsigned  UnsignedAcknowledgement
	signature [ed25519.SignatureSize]byte
	valid     bool
}

type acknowledgementWire struct {
	AcknowledgementSignature string
	ChainHash                string
	ChainIndex               uint64
	ObjectKind               string
	ProjectionAccumulator    string
	ProjectionStateDigest    string
	RecoveryGeneration       uint64
	ResultHash               string
	ResultIndex              uint64
	ServerAppliedResultIndex uint64
	ServerAuthorityVersion   uint64
	ServerDeviceID           string
	SessionID                string
	WorkspaceID              string
}

// NewUnsignedAcknowledgement validates and copies the complete signed tuple.
func NewUnsignedAcknowledgement(
	input AcknowledgementInput,
) (UnsignedAcknowledgement, error) {
	if err := validateAcknowledgementInput(input); err != nil {
		return UnsignedAcknowledgement{}, err
	}
	canonical := encodeUnsignedAcknowledgement(input)
	if completeAcknowledgementSize(len(canonical)) > MaxAcknowledgementBytes {
		return UnsignedAcknowledgement{}, ErrAcknowledgementTooLarge
	}
	return UnsignedAcknowledgement{
		input:     input,
		canonical: canonical,
		valid:     true,
	}, nil
}

// NewAcknowledgement attaches a fixed-size signature to a validated
// acknowledgement preimage.
func NewAcknowledgement(
	unsigned UnsignedAcknowledgement,
	signature [ed25519.SignatureSize]byte,
) (Acknowledgement, error) {
	if err := unsigned.validate(); err != nil {
		return Acknowledgement{}, err
	}
	if completeAcknowledgementSize(len(unsigned.canonical)) >
		MaxAcknowledgementBytes {
		return Acknowledgement{}, ErrAcknowledgementTooLarge
	}
	return Acknowledgement{
		unsigned:  unsigned.clone(),
		signature: signature,
		valid:     true,
	}, nil
}

// SignAcknowledgement signs a validated acknowledgement with its named server
// identity.
func SignAcknowledgement(
	unsigned UnsignedAcknowledgement,
	privateKey []byte,
) (Acknowledgement, error) {
	if err := unsigned.validate(); err != nil {
		return Acknowledgement{}, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return Acknowledgement{}, fmt.Errorf("%w: %v", ErrSignerMismatch, err)
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil || derived != unsigned.input.ServerDeviceID {
		return Acknowledgement{}, ErrSignerMismatch
	}
	signatureBytes, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureBatch,
		unsigned.canonical,
	)
	if err != nil {
		return Acknowledgement{}, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	defer clear(signatureBytes)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return NewAcknowledgement(unsigned, signature)
}

// ParseAcknowledgement accepts only the exact canonical closed V1
// acknowledgement object. Authority membership is checked by the caller.
func ParseAcknowledgement(encoded []byte) (Acknowledgement, error) {
	if len(encoded) == 0 {
		return Acknowledgement{}, ErrInvalidAcknowledgement
	}
	if len(encoded) > MaxAcknowledgementBytes {
		return Acknowledgement{}, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrAcknowledgementTooLarge,
			len(encoded),
			MaxAcknowledgementBytes,
		)
	}
	wire, err := decodeAcknowledgementWire(encoded)
	if err != nil {
		return Acknowledgement{}, err
	}
	input, err := acknowledgementInputFromWire(wire)
	if err != nil {
		return Acknowledgement{}, err
	}
	unsigned, err := NewUnsignedAcknowledgement(input)
	if err != nil {
		return Acknowledgement{}, err
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.AcknowledgementSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return Acknowledgement{}, fmt.Errorf(
			"%w: acknowledgement signature: %v",
			ErrInvalidAcknowledgement,
			err,
		)
	}
	defer clear(signatureBytes)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	acknowledgement, err := NewAcknowledgement(unsigned, signature)
	if err != nil {
		return Acknowledgement{}, err
	}
	if !matchesCompleteAcknowledgement(
		encoded,
		unsigned.canonical,
		signature,
	) {
		return Acknowledgement{}, ErrNoncanonicalAcknowledgement
	}
	return acknowledgement, nil
}

// VerifyAcknowledgement verifies the named server's identity signature.
// Authority at the acknowledged cursor is established separately.
func VerifyAcknowledgement(
	acknowledgement Acknowledgement,
	publicKey []byte,
) error {
	if err := acknowledgement.validate(); err != nil {
		return err
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil ||
		derived != acknowledgement.unsigned.input.ServerDeviceID {
		return ErrSignerMismatch
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureBatch,
		acknowledgement.unsigned.canonical,
		acknowledgement.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// Input returns every variable signed field by value.
func (acknowledgement UnsignedAcknowledgement) Input() AcknowledgementInput {
	if acknowledgement.validate() != nil {
		return AcknowledgementInput{}
	}
	return acknowledgement.input
}

// Metadata returns every signed field except the signature.
func (
	acknowledgement UnsignedAcknowledgement,
) Metadata() AcknowledgementMetadata {
	if acknowledgement.validate() != nil {
		return AcknowledgementMetadata{}
	}
	input := acknowledgement.input
	return AcknowledgementMetadata{
		ObjectKind:               AcknowledgementObjectKind,
		SessionID:                input.SessionID,
		WorkspaceID:              input.WorkspaceID,
		RecoveryGeneration:       input.RecoveryGeneration,
		ServerDeviceID:           input.ServerDeviceID,
		ServerAuthorityVersion:   input.ServerAuthorityVersion,
		ResultIndex:              input.ResultIndex,
		ResultHash:               input.ResultHash,
		ChainIndex:               input.ChainIndex,
		ChainHash:                input.ChainHash,
		ProjectionAccumulator:    input.ProjectionAccumulator,
		ProjectionStateDigest:    input.ProjectionStateDigest,
		ServerAppliedResultIndex: input.ServerAppliedResultIndex,
	}
}

// CanonicalBytes returns an independent copy of the signature preimage.
func (
	acknowledgement UnsignedAcknowledgement,
) CanonicalBytes() []byte {
	if acknowledgement.validate() != nil {
		return nil
	}
	return bytes.Clone(acknowledgement.canonical)
}

// Unsigned returns an independent copy of the acknowledgement preimage.
func (
	acknowledgement Acknowledgement,
) Unsigned() UnsignedAcknowledgement {
	if acknowledgement.validate() != nil {
		return UnsignedAcknowledgement{}
	}
	return acknowledgement.unsigned.clone()
}

// CanonicalBytes returns an independent copy of the complete signed object.
func (acknowledgement Acknowledgement) CanonicalBytes() []byte {
	if acknowledgement.validate() != nil {
		return nil
	}
	return encodeCompleteAcknowledgement(
		acknowledgement.unsigned.canonical,
		acknowledgement.signature,
	)
}

// MatchesUnsigned reports whether the signed acknowledgement contains the
// exact validated preimage.
func (
	acknowledgement Acknowledgement,
) MatchesUnsigned(unsigned UnsignedAcknowledgement) bool {
	return acknowledgement.validate() == nil &&
		unsigned.validate() == nil &&
		bytes.Equal(
			acknowledgement.unsigned.canonical,
			unsigned.canonical,
		)
}

// Signature returns the complete identity signature by value.
func (
	acknowledgement Acknowledgement,
) Signature() [ed25519.SignatureSize]byte {
	return acknowledgement.signature
}

// AttestationID deterministically identifies the complete signed
// acknowledgement.
func (acknowledgement Acknowledgement) AttestationID() string {
	if acknowledgement.validate() != nil {
		return ""
	}
	digest := sha256.Sum256(acknowledgement.CanonicalBytes())
	return "acknowledgement:" + codec.EncodeBase64URL(digest[:])
}

func (acknowledgement UnsignedAcknowledgement) validate() error {
	if !acknowledgement.valid ||
		len(acknowledgement.canonical) == 0 ||
		completeAcknowledgementSize(len(acknowledgement.canonical)) >
			MaxAcknowledgementBytes {
		return fmt.Errorf(
			"%w: invalid unsigned value",
			ErrInvalidAcknowledgement,
		)
	}
	if err := validateAcknowledgementInput(acknowledgement.input); err != nil {
		return err
	}
	if !bytes.Equal(
		acknowledgement.canonical,
		encodeUnsignedAcknowledgement(acknowledgement.input),
	) {
		return fmt.Errorf(
			"%w: invalid unsigned encoding",
			ErrInvalidAcknowledgement,
		)
	}
	return nil
}

func (acknowledgement Acknowledgement) validate() error {
	if !acknowledgement.valid {
		return fmt.Errorf(
			"%w: invalid complete value",
			ErrInvalidAcknowledgement,
		)
	}
	return acknowledgement.unsigned.validate()
}

func (acknowledgement UnsignedAcknowledgement) clone() UnsignedAcknowledgement {
	return UnsignedAcknowledgement{
		input:     acknowledgement.input,
		canonical: bytes.Clone(acknowledgement.canonical),
		valid:     acknowledgement.valid,
	}
}

func validateAcknowledgementInput(input AcknowledgementInput) error {
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.ServerDeviceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!domain.ValidUnsignedInteger(input.ResultIndex) ||
		!domain.ValidUnsignedInteger(input.ChainIndex) ||
		input.ChainIndex > input.ResultIndex ||
		input.ServerAuthorityVersion < 1 ||
		!domain.ValidUnsignedInteger(input.ServerAuthorityVersion) ||
		input.ServerAppliedResultIndex != input.ResultIndex ||
		!domain.ValidUnsignedInteger(input.ServerAppliedResultIndex) {
		return ErrInvalidAcknowledgement
	}
	return nil
}

func decodeAcknowledgementWire(
	encoded []byte,
) (acknowledgementWire, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return acknowledgementWire{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidAcknowledgement,
			err,
		)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return acknowledgementWire{}, fmt.Errorf(
			"%w: acknowledgement must be an object",
			ErrInvalidAcknowledgement,
		)
	}

	var wire acknowledgementWire
	seen := make(map[string]struct{}, 14)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return acknowledgementWire{}, fmt.Errorf(
				"%w: decode field name: %v",
				ErrInvalidAcknowledgement,
				err,
			)
		}
		name, ok := token.(string)
		if !ok {
			return acknowledgementWire{}, fmt.Errorf(
				"%w: field name is not a string",
				ErrInvalidAcknowledgement,
			)
		}
		if _, duplicate := seen[name]; duplicate {
			return acknowledgementWire{}, fmt.Errorf(
				"%w: duplicate field %q",
				ErrInvalidAcknowledgement,
				name,
			)
		}
		seen[name] = struct{}{}

		switch name {
		case "acknowledgement_signature":
			err = decodeAcknowledgementField(
				decoder,
				&wire.AcknowledgementSignature,
			)
		case "chain_hash":
			err = decodeAcknowledgementField(decoder, &wire.ChainHash)
		case "chain_index":
			err = decodeAcknowledgementField(decoder, &wire.ChainIndex)
		case "object_kind":
			err = decodeAcknowledgementField(decoder, &wire.ObjectKind)
		case "projection_accumulator":
			err = decodeAcknowledgementField(
				decoder,
				&wire.ProjectionAccumulator,
			)
		case "projection_state_digest":
			err = decodeAcknowledgementField(
				decoder,
				&wire.ProjectionStateDigest,
			)
		case "recovery_generation":
			err = decodeAcknowledgementField(
				decoder,
				&wire.RecoveryGeneration,
			)
		case "result_hash":
			err = decodeAcknowledgementField(decoder, &wire.ResultHash)
		case "result_index":
			err = decodeAcknowledgementField(decoder, &wire.ResultIndex)
		case "server_applied_result_index":
			err = decodeAcknowledgementField(
				decoder,
				&wire.ServerAppliedResultIndex,
			)
		case "server_authority_version":
			err = decodeAcknowledgementField(
				decoder,
				&wire.ServerAuthorityVersion,
			)
		case "server_device_id":
			err = decodeAcknowledgementField(
				decoder,
				&wire.ServerDeviceID,
			)
		case "session_id":
			err = decodeAcknowledgementField(decoder, &wire.SessionID)
		case "workspace_id":
			err = decodeAcknowledgementField(decoder, &wire.WorkspaceID)
		default:
			return acknowledgementWire{}, fmt.Errorf(
				"%w: unknown field %q",
				ErrInvalidAcknowledgement,
				name,
			)
		}
		if err != nil {
			return acknowledgementWire{}, fmt.Errorf(
				"%w: field %s: %v",
				ErrInvalidAcknowledgement,
				name,
				err,
			)
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return acknowledgementWire{}, fmt.Errorf(
			"%w: close object: %v",
			ErrInvalidAcknowledgement,
			err,
		)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return acknowledgementWire{}, fmt.Errorf(
			"%w: invalid object terminator",
			ErrInvalidAcknowledgement,
		)
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("unexpected token %v", token)
		}
		return acknowledgementWire{}, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidAcknowledgement,
			err,
		)
	}
	if len(seen) != 14 {
		return acknowledgementWire{}, fmt.Errorf(
			"%w: got %d fields, want 14",
			ErrInvalidAcknowledgement,
			len(seen),
		)
	}
	return wire, nil
}

func decodeAcknowledgementField(
	decoder *json.Decoder,
	destination any,
) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if bytes.Equal(raw, []byte("null")) {
		return errors.New("must not be null")
	}
	return json.Unmarshal(raw, destination)
}

func acknowledgementInputFromWire(
	wire acknowledgementWire,
) (AcknowledgementInput, error) {
	if wire.ObjectKind != AcknowledgementObjectKind {
		return AcknowledgementInput{}, fmt.Errorf(
			"%w: object_kind %q",
			ErrInvalidAcknowledgement,
			wire.ObjectKind,
		)
	}
	resultHash, err := decodeAcknowledgementDigest(
		"result_hash",
		wire.ResultHash,
	)
	if err != nil {
		return AcknowledgementInput{}, err
	}
	chainHash, err := decodeAcknowledgementDigest(
		"chain_hash",
		wire.ChainHash,
	)
	if err != nil {
		return AcknowledgementInput{}, err
	}
	accumulator, err := decodeAcknowledgementDigest(
		"projection_accumulator",
		wire.ProjectionAccumulator,
	)
	if err != nil {
		return AcknowledgementInput{}, err
	}
	stateDigest, err := decodeAcknowledgementDigest(
		"projection_state_digest",
		wire.ProjectionStateDigest,
	)
	if err != nil {
		return AcknowledgementInput{}, err
	}
	return AcknowledgementInput{
		SessionID:                domain.UUIDv7(wire.SessionID),
		WorkspaceID:              domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:       wire.RecoveryGeneration,
		ServerDeviceID:           domain.DeviceID(wire.ServerDeviceID),
		ServerAuthorityVersion:   wire.ServerAuthorityVersion,
		ResultIndex:              wire.ResultIndex,
		ResultHash:               resultHash,
		ChainIndex:               wire.ChainIndex,
		ChainHash:                chainHash,
		ProjectionAccumulator:    accumulator,
		ProjectionStateDigest:    stateDigest,
		ServerAppliedResultIndex: wire.ServerAppliedResultIndex,
	}, nil
}

func decodeAcknowledgementDigest(
	name string,
	text string,
) (chain.Digest, error) {
	decoded, err := codec.DecodeBase64URLExact(text, len(chain.Digest{}))
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: %s: %v",
			ErrInvalidAcknowledgement,
			name,
			err,
		)
	}
	var digest chain.Digest
	copy(digest[:], decoded)
	return digest, nil
}

func encodeUnsignedAcknowledgement(input AcknowledgementInput) []byte {
	encoded := make([]byte, 0, 768)
	encoded = append(encoded, `{"chain_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.ChainHash[:]))
	encoded = append(encoded, `,"chain_index":`...)
	encoded = strconv.AppendUint(encoded, input.ChainIndex, 10)
	encoded = append(encoded, `,"object_kind":`...)
	encoded = appendQuoted(encoded, AcknowledgementObjectKind)
	encoded = append(encoded, `,"projection_accumulator":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.ProjectionAccumulator[:]),
	)
	encoded = append(encoded, `,"projection_state_digest":`...)
	encoded = appendQuoted(
		encoded,
		codec.EncodeBase64URL(input.ProjectionStateDigest[:]),
	)
	encoded = append(encoded, `,"recovery_generation":`...)
	encoded = strconv.AppendUint(encoded, input.RecoveryGeneration, 10)
	encoded = append(encoded, `,"result_hash":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(input.ResultHash[:]))
	encoded = append(encoded, `,"result_index":`...)
	encoded = strconv.AppendUint(encoded, input.ResultIndex, 10)
	encoded = append(encoded, `,"server_applied_result_index":`...)
	encoded = strconv.AppendUint(
		encoded,
		input.ServerAppliedResultIndex,
		10,
	)
	encoded = append(encoded, `,"server_authority_version":`...)
	encoded = strconv.AppendUint(encoded, input.ServerAuthorityVersion, 10)
	encoded = append(encoded, `,"server_device_id":`...)
	encoded = appendQuoted(encoded, string(input.ServerDeviceID))
	encoded = append(encoded, `,"session_id":`...)
	encoded = appendQuoted(encoded, string(input.SessionID))
	encoded = append(encoded, `,"workspace_id":`...)
	encoded = appendQuoted(encoded, string(input.WorkspaceID))
	return append(encoded, '}')
}

func encodeCompleteAcknowledgement(
	unsigned []byte,
	signature [ed25519.SignatureSize]byte,
) []byte {
	prefix := completeAcknowledgementPrefix(signature)
	encoded := make(
		[]byte,
		0,
		completeAcknowledgementSize(len(unsigned)),
	)
	encoded = append(encoded, prefix...)
	encoded = append(encoded, unsigned[1:]...)
	return encoded
}

func completeAcknowledgementPrefix(
	signature [ed25519.SignatureSize]byte,
) []byte {
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, `{"acknowledgement_signature":`...)
	encoded = appendQuoted(encoded, codec.EncodeBase64URL(signature[:]))
	return append(encoded, ',')
}

func completeAcknowledgementSize(unsignedBytes int) int {
	if unsignedBytes < 1 {
		return 0
	}
	return unsignedBytes - 1 +
		len(`{"acknowledgement_signature":`) +
		3 +
		acknowledgementSignatureTextBytes
}

func matchesCompleteAcknowledgement(
	complete []byte,
	unsigned []byte,
	signature [ed25519.SignatureSize]byte,
) bool {
	prefix := completeAcknowledgementPrefix(signature)
	return len(complete) == len(prefix)+len(unsigned)-1 &&
		bytes.Equal(complete[:len(prefix)], prefix) &&
		bytes.Equal(complete[len(prefix):], unsigned[1:])
}
