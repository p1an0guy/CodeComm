package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidPairingMessage      = errors.New("pairing: invalid response or confirmation")
	ErrPairingMessageTooLarge     = errors.New("pairing: response or confirmation exceeds message limit")
	ErrPairingMessageSchema       = errors.New("pairing: unsupported response or confirmation schema")
	ErrPairingMessageStatus       = errors.New("pairing: invalid confirmation status")
	ErrPairingMessageUnknownField = errors.New("pairing: unknown response or confirmation field")
)

// ConfirmationStatus is the closed operator-confirmation state sent to a joiner.
type ConfirmationStatus string

const (
	StatusAwaitingSAS     ConfirmationStatus = "awaiting_sas"
	StatusAwaitingInviter ConfirmationStatus = "awaiting_inviter"
	StatusFinalizing      ConfirmationStatus = "finalizing"
	StatusConfirmed       ConfirmationStatus = "confirmed"
	StatusDeclined        ConfirmationStatus = "declined"
	StatusExpired         ConfirmationStatus = "expired"
	StatusRevoked         ConfirmationStatus = "revoked"
)

func (status ConfirmationStatus) validAcknowledgment() bool {
	return status == StatusAwaitingSAS
}

func (status ConfirmationStatus) validConfirmation() bool {
	switch status {
	case StatusAwaitingInviter, StatusFinalizing, StatusConfirmed,
		StatusDeclined, StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// RequestAcknowledgment confirms durable invite consumption before the inviter
// displays the SAS. It contains no SAS; the joiner derives that locally.
type RequestAcknowledgment struct {
	AttemptID     domain.UUIDv7
	RequestDigest [sha256.Size]byte
	InviteDigest  [sha256.Size]byte
	Status        ConfirmationStatus
	canonical     []byte
}

// Confirmation is the joiner's one irreversible SAS decision.
type Confirmation struct {
	AttemptID     domain.UUIDv7
	RequestDigest [sha256.Size]byte
	Confirmed     bool
	canonical     []byte
}

// ConfirmationResult reports the inviter-side state after a decision or poll.
type ConfirmationResult struct {
	AttemptID     domain.UUIDv7
	RequestDigest [sha256.Size]byte
	Status        ConfirmationStatus
	canonical     []byte
}

type requestAcknowledgmentWire struct {
	SchemaVersion uint64 `json:"schema_version"`
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	InviteDigest  string `json:"invite_digest"`
	Status        string `json:"status"`
}

type confirmationWire struct {
	SchemaVersion uint64 `json:"schema_version"`
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	Confirmed     bool   `json:"confirmed"`
}

type confirmationResultWire struct {
	SchemaVersion uint64 `json:"schema_version"`
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	Status        string `json:"status"`
}

// NewRequestAcknowledgment creates the exact response for a verified request.
func NewRequestAcknowledgment(verified VerifiedRequest) (RequestAcknowledgment, error) {
	return NewRequestAcknowledgmentValues(
		verified.Core().Value().AttemptID,
		verified.RequestDigest(),
		verified.InviteDigest(),
	)
}

// NewRequestAcknowledgmentValues reconstructs an acknowledgment for an exact
// durable same-connection retry after successful invite consumption.
func NewRequestAcknowledgmentValues(
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	inviteDigest [sha256.Size]byte,
) (RequestAcknowledgment, error) {
	if !attemptID.Valid() {
		return RequestAcknowledgment{}, ErrInvalidPairingMessage
	}
	value := RequestAcknowledgment{
		AttemptID: attemptID, RequestDigest: requestDigest, InviteDigest: inviteDigest,
		Status: StatusAwaitingSAS,
	}
	encoded, err := encodePairingObject(requestAcknowledgmentWire{
		SchemaVersion: SchemaVersion,
		AttemptID:     string(value.AttemptID),
		RequestDigest: codec.EncodeBase64URL(value.RequestDigest[:]),
		InviteDigest:  codec.EncodeBase64URL(value.InviteDigest[:]),
		Status:        string(value.Status),
	})
	if err != nil {
		return RequestAcknowledgment{}, err
	}
	value.canonical = encoded
	return value, nil
}

// ParseRequestAcknowledgment validates one exact canonical response.
func ParseRequestAcknowledgment(input []byte) (RequestAcknowledgment, error) {
	canonical, err := parsePairingObject(input, []string{
		"schema_version", "attempt_id", "request_digest", "invite_digest", "status",
	})
	if err != nil {
		return RequestAcknowledgment{}, err
	}
	var wire requestAcknowledgmentWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return RequestAcknowledgment{}, ErrInvalidPairingMessage
	}
	requestDigest, requestErr := pairingDigest(wire.RequestDigest)
	inviteDigest, inviteErr := pairingDigest(wire.InviteDigest)
	value := RequestAcknowledgment{
		AttemptID: domain.UUIDv7(wire.AttemptID), RequestDigest: requestDigest,
		InviteDigest: inviteDigest, Status: ConfirmationStatus(wire.Status),
		canonical: bytes.Clone(canonical),
	}
	if wire.SchemaVersion != SchemaVersion {
		return RequestAcknowledgment{}, ErrPairingMessageSchema
	}
	if !value.AttemptID.Valid() || requestErr != nil || inviteErr != nil {
		return RequestAcknowledgment{}, ErrInvalidPairingMessage
	}
	if !value.Status.validAcknowledgment() {
		return RequestAcknowledgment{}, ErrPairingMessageStatus
	}
	return value, nil
}

// NewConfirmation creates the exact remote SAS decision body.
func NewConfirmation(
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	confirmed bool,
) (Confirmation, error) {
	if !attemptID.Valid() {
		return Confirmation{}, ErrInvalidPairingMessage
	}
	value := Confirmation{AttemptID: attemptID, RequestDigest: requestDigest, Confirmed: confirmed}
	encoded, err := encodePairingObject(confirmationWire{
		SchemaVersion: SchemaVersion, AttemptID: string(attemptID),
		RequestDigest: codec.EncodeBase64URL(requestDigest[:]), Confirmed: confirmed,
	})
	if err != nil {
		return Confirmation{}, err
	}
	value.canonical = encoded
	return value, nil
}

// ParseConfirmation validates one exact canonical remote SAS decision.
func ParseConfirmation(input []byte) (Confirmation, error) {
	canonical, err := parsePairingObject(input, []string{
		"schema_version", "attempt_id", "request_digest", "confirmed",
	})
	if err != nil {
		return Confirmation{}, err
	}
	var wire confirmationWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return Confirmation{}, ErrInvalidPairingMessage
	}
	digest, digestErr := pairingDigest(wire.RequestDigest)
	value := Confirmation{
		AttemptID: domain.UUIDv7(wire.AttemptID), RequestDigest: digest,
		Confirmed: wire.Confirmed, canonical: bytes.Clone(canonical),
	}
	if wire.SchemaVersion != SchemaVersion {
		return Confirmation{}, ErrPairingMessageSchema
	}
	if !value.AttemptID.Valid() || digestErr != nil {
		return Confirmation{}, ErrInvalidPairingMessage
	}
	return value, nil
}

// NewConfirmationResult creates an exact confirmation status response.
func NewConfirmationResult(
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	status ConfirmationStatus,
) (ConfirmationResult, error) {
	if !attemptID.Valid() || !status.validConfirmation() {
		return ConfirmationResult{}, ErrInvalidPairingMessage
	}
	value := ConfirmationResult{
		AttemptID: attemptID, RequestDigest: requestDigest, Status: status,
	}
	encoded, err := encodePairingObject(confirmationResultWire{
		SchemaVersion: SchemaVersion, AttemptID: string(attemptID),
		RequestDigest: codec.EncodeBase64URL(requestDigest[:]), Status: string(status),
	})
	if err != nil {
		return ConfirmationResult{}, err
	}
	value.canonical = encoded
	return value, nil
}

// ParseConfirmationResult validates one exact canonical confirmation response.
func ParseConfirmationResult(input []byte) (ConfirmationResult, error) {
	canonical, err := parsePairingObject(input, []string{
		"schema_version", "attempt_id", "request_digest", "status",
	})
	if err != nil {
		return ConfirmationResult{}, err
	}
	var wire confirmationResultWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return ConfirmationResult{}, ErrInvalidPairingMessage
	}
	digest, digestErr := pairingDigest(wire.RequestDigest)
	value := ConfirmationResult{
		AttemptID: domain.UUIDv7(wire.AttemptID), RequestDigest: digest,
		Status: ConfirmationStatus(wire.Status), canonical: bytes.Clone(canonical),
	}
	if wire.SchemaVersion != SchemaVersion {
		return ConfirmationResult{}, ErrPairingMessageSchema
	}
	if !value.AttemptID.Valid() || digestErr != nil {
		return ConfirmationResult{}, ErrInvalidPairingMessage
	}
	if !value.Status.validConfirmation() {
		return ConfirmationResult{}, ErrPairingMessageStatus
	}
	return value, nil
}

func (value RequestAcknowledgment) CanonicalBytes() []byte { return bytes.Clone(value.canonical) }
func (value Confirmation) CanonicalBytes() []byte          { return bytes.Clone(value.canonical) }
func (value ConfirmationResult) CanonicalBytes() []byte    { return bytes.Clone(value.canonical) }

func encodePairingObject(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidPairingMessage, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidPairingMessage, err)
	}
	if len(canonical) > MaxPairingMessageBytes {
		return nil, ErrPairingMessageTooLarge
	}
	return bytes.Clone(canonical), nil
}

func parsePairingObject(input []byte, fields []string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInvalidPairingMessage
	}
	if len(input) > MaxPairingMessageBytes {
		return nil, ErrPairingMessageTooLarge
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return nil, ErrInvalidPairingMessage
	}
	if err := validatePairingObject(canonical, fields); err != nil {
		return nil, err
	}
	return canonical, nil
}

func validatePairingObject(input []byte, fields []string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(input, &members); err != nil {
		return ErrInvalidPairingMessage
	}
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	for field := range members {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("%w: %s", ErrPairingMessageUnknownField, field)
		}
	}
	if len(members) != len(fields) {
		return ErrInvalidPairingMessage
	}
	return nil
}

func pairingDigest(encoded string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := codec.DecodeBase64URLExact(encoded, sha256.Size)
	if err != nil {
		return result, err
	}
	copy(result[:], decoded)
	return result, nil
}
