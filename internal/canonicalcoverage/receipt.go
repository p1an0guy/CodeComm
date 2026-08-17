// Package canonicalcoverage proves that the current canonical Git object is
// durably held by a majority of the committed voter target.
package canonicalcoverage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const MaxReceiptBytes = 4 << 10

var (
	ErrInvalidSubject   = errors.New("canonical coverage: invalid subject")
	ErrInvalidReceipt   = errors.New("canonical coverage: invalid receipt")
	ErrReceiptTooLarge  = errors.New("canonical coverage: receipt exceeds size limit")
	ErrReceiptCanonical = errors.New("canonical coverage: receipt is not canonical")
	ErrReceiptSchema    = errors.New("canonical coverage: receipt has an invalid schema")
	ErrReceiptIdentity  = errors.New("canonical coverage: receipt identity mismatch")
	ErrReceiptSignature = errors.New("canonical coverage: receipt signature invalid")
)

// Subject is the exact replicated tuple covered by one receipt.
type Subject struct {
	SessionID           domain.UUIDv7
	WorkspaceID         domain.UUIDv4
	VoterSetVersion     uint64
	CanonicalRefVersion uint64
	CommitOID           domain.GitOID
}

// Validate checks the complete signed tuple.
func (subject Subject) Validate() error {
	if !subject.SessionID.Valid() ||
		!subject.WorkspaceID.Valid() ||
		subject.VoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(subject.VoterSetVersion) ||
		subject.CanonicalRefVersion < 1 ||
		!domain.ValidUnsignedInteger(subject.CanonicalRefVersion) ||
		!subject.CommitOID.Valid() {
		return ErrInvalidSubject
	}
	return nil
}

// Receipt is an identity-signed durable-possession statement. Its fields and
// exact wire bytes are immutable after signing or parsing.
type Receipt struct {
	subject       Subject
	voterDeviceID domain.DeviceID
	signature     [ed25519.SignatureSize]byte
	signedBytes   []byte
	canonical     []byte
}

type unsignedReceiptWire struct {
	CanonicalRefVersion uint64 `json:"canonical_ref_version"`
	CommitOID           string `json:"commit_oid"`
	SessionID           string `json:"session_id"`
	VoterDeviceID       string `json:"voter_device_id"`
	VoterSetVersion     uint64 `json:"voter_set_version"`
	WorkspaceID         string `json:"workspace_id"`
}

type receiptWire struct {
	CanonicalRefVersion uint64 `json:"canonical_ref_version"`
	CommitOID           string `json:"commit_oid"`
	SessionID           string `json:"session_id"`
	Signature           string `json:"signature"`
	VoterDeviceID       string `json:"voter_device_id"`
	VoterSetVersion     uint64 `json:"voter_set_version"`
	WorkspaceID         string `json:"workspace_id"`
}

// ParseReceipt validates bounded canonical structure and the known field
// shapes while retaining unknown fields in the exact signature preimage.
// Verify authenticates those bytes before enforcing the closed V1 schema.
func ParseReceipt(input []byte) (Receipt, error) {
	if len(input) == 0 {
		return Receipt{}, ErrInvalidReceipt
	}
	if len(input) > MaxReceiptBytes {
		return Receipt{}, ErrReceiptTooLarge
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if !bytes.Equal(canonical, input) {
		return Receipt{}, ErrReceiptCanonical
	}
	signedBytes, encodedSignature, err := codec.RemoveCanonicalObjectMember(
		canonical,
		"signature",
	)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: signature: %v", ErrInvalidReceipt, err)
	}
	var wire receiptWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return Receipt{}, fmt.Errorf("%w: decode: %v", ErrInvalidReceipt, err)
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil {
		return Receipt{}, fmt.Errorf("%w: signature", ErrInvalidReceipt)
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: signature: %v", ErrInvalidReceipt, err)
	}
	subject := Subject{
		SessionID:           domain.UUIDv7(wire.SessionID),
		WorkspaceID:         domain.UUIDv4(wire.WorkspaceID),
		VoterSetVersion:     wire.VoterSetVersion,
		CanonicalRefVersion: wire.CanonicalRefVersion,
		CommitOID:           domain.GitOID(wire.CommitOID),
	}
	voterDeviceID := domain.DeviceID(wire.VoterDeviceID)
	if err := subject.Validate(); err != nil || !voterDeviceID.Valid() {
		return Receipt{}, ErrInvalidReceipt
	}

	receipt := Receipt{
		subject:       subject,
		voterDeviceID: voterDeviceID,
		signedBytes:   bytes.Clone(signedBytes),
		canonical:     bytes.Clone(canonical),
	}
	copy(receipt.signature[:], signature)
	return receipt, nil
}

// Subject returns the exact signed coverage tuple.
func (receipt Receipt) Subject() Subject { return receipt.subject }

// VoterDeviceID returns the identity that issued this receipt.
func (receipt Receipt) VoterDeviceID() domain.DeviceID {
	return receipt.voterDeviceID
}

// SignedBytes returns JCS over the six fields covered by the signature.
func (receipt Receipt) SignedBytes() []byte {
	return bytes.Clone(receipt.signedBytes)
}

// CanonicalBytes returns the complete signed canonical receipt.
func (receipt Receipt) CanonicalBytes() []byte {
	return bytes.Clone(receipt.canonical)
}

// Verify validates the retained wire object and its signature against the
// exact enrolled identity key.
func (receipt Receipt) Verify(identityPublicKey []byte) error {
	if len(receipt.canonical) == 0 {
		return ErrInvalidReceipt
	}
	parsed, err := ParseReceipt(receipt.canonical)
	if err != nil ||
		parsed.subject != receipt.subject ||
		parsed.voterDeviceID != receipt.voterDeviceID ||
		parsed.signature != receipt.signature ||
		!bytes.Equal(parsed.signedBytes, receipt.signedBytes) {
		return ErrInvalidReceipt
	}
	derivedID, err := device.DeriveID(ed25519.PublicKey(identityPublicKey))
	if err != nil || derivedID != receipt.voterDeviceID {
		return ErrReceiptIdentity
	}
	if err := codecommcrypto.VerifyEd25519(
		identityPublicKey,
		codec.SignatureGitCanonicalCoverage,
		receipt.signedBytes,
		receipt.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptSignature, err)
	}
	if err := validateReceiptSchema(receipt.canonical); err != nil {
		return err
	}
	expected, err := encodeUnsignedReceipt(
		receipt.subject,
		receipt.voterDeviceID,
	)
	if err != nil || !bytes.Equal(expected, receipt.signedBytes) {
		return ErrReceiptCanonical
	}
	return nil
}

func newReceipt(
	subject Subject,
	voterDeviceID domain.DeviceID,
	signature []byte,
) (Receipt, error) {
	if err := subject.Validate(); err != nil ||
		!voterDeviceID.Valid() ||
		len(signature) != ed25519.SignatureSize {
		return Receipt{}, ErrInvalidReceipt
	}
	signedBytes, err := encodeUnsignedReceipt(subject, voterDeviceID)
	if err != nil {
		return Receipt{}, err
	}
	raw, err := json.Marshal(receiptWire{
		CanonicalRefVersion: subject.CanonicalRefVersion,
		CommitOID:           string(subject.CommitOID),
		SessionID:           string(subject.SessionID),
		Signature:           codec.EncodeBase64URL(signature),
		VoterDeviceID:       string(voterDeviceID),
		VoterSetVersion:     subject.VoterSetVersion,
		WorkspaceID:         string(subject.WorkspaceID),
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: encode: %v", ErrInvalidReceipt, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: canonicalize: %v", ErrInvalidReceipt, err)
	}
	if len(canonical) > MaxReceiptBytes {
		return Receipt{}, ErrReceiptTooLarge
	}
	receipt := Receipt{
		subject:       subject,
		voterDeviceID: voterDeviceID,
		signedBytes:   bytes.Clone(signedBytes),
		canonical:     bytes.Clone(canonical),
	}
	copy(receipt.signature[:], signature)
	return receipt, nil
}

func encodeUnsignedReceipt(
	subject Subject,
	voterDeviceID domain.DeviceID,
) ([]byte, error) {
	if err := subject.Validate(); err != nil || !voterDeviceID.Valid() {
		return nil, ErrInvalidReceipt
	}
	raw, err := json.Marshal(unsignedReceiptWire{
		CanonicalRefVersion: subject.CanonicalRefVersion,
		CommitOID:           string(subject.CommitOID),
		SessionID:           string(subject.SessionID),
		VoterDeviceID:       string(voterDeviceID),
		VoterSetVersion:     subject.VoterSetVersion,
		WorkspaceID:         string(subject.WorkspaceID),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode preimage: %v", ErrInvalidReceipt, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: canonicalize preimage: %v",
			ErrInvalidReceipt,
			err,
		)
	}
	return canonical, nil
}

func validateReceiptSchema(input []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(input, &members); err != nil {
		return ErrInvalidReceipt
	}
	for _, field := range [...]string{
		"canonical_ref_version",
		"commit_oid",
		"session_id",
		"signature",
		"voter_device_id",
		"voter_set_version",
		"workspace_id",
	} {
		if _, exists := members[field]; !exists {
			return fmt.Errorf("%w: missing %s", ErrReceiptSchema, field)
		}
		delete(members, field)
	}
	if len(members) != 0 {
		return ErrReceiptSchema
	}
	return nil
}
