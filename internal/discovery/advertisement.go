// Package discovery implements bounded, authenticated LAN endpoint discovery.
package discovery

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	ProtocolVersion        uint64 = 1
	MaxDatagramBytes              = 1200
	AdvertisementNonceSize        = 16
	MaxAdvertisementFuture        = 60 * time.Second

	DefaultMulticastPort = 47831
	DefaultIPv4Group     = "239.192.71.31"
	DefaultIPv6Group     = "ff12::c0de:c031"
)

var (
	ErrInvalidAdvertisement  = errors.New("discovery: invalid advertisement")
	ErrAdvertisementTooLarge = errors.New("discovery: advertisement exceeds 1200 bytes")
	ErrNoncanonicalMessage   = errors.New("discovery: message is not canonical")
	ErrProtocolMismatch      = errors.New("discovery: protocol mismatch")
	ErrSessionMismatch       = errors.New("discovery: session mismatch")
	ErrAdvertisementExpired  = errors.New("discovery: advertisement expired")
	ErrAdvertisementFuture   = errors.New("discovery: advertisement expires too far in the future")
	ErrAdvertisingKey        = errors.New("discovery: advertising key does not match its digest")
	ErrUnknownField          = errors.New("discovery: unknown field")
)

// Advertisement is the authenticated content of one multicast datagram.
// Its source address remains only an unverified dial hint.
type Advertisement struct {
	SessionID            domain.UUIDv7
	HTTPSPort            uint16
	CredentialEpoch      uint64
	AdvertisingKeyDigest [sha256.Size]byte
	AdvertisementNonce   [AdvertisementNonceSize]byte
	ExpiresAt            domain.Timestamp
}

type advertisementWire struct {
	Magic                string `json:"magic"`
	Protocol             uint64 `json:"protocol"`
	SessionID            string `json:"session_id"`
	HTTPSPort            uint16 `json:"https_port"`
	CredentialEpoch      uint64 `json:"credential_epoch"`
	AdvertisingKeyDigest string `json:"advertising_key_digest"`
	AdvertisementNonce   string `json:"advertisement_nonce"`
	ExpiresAt            string `json:"expires_at"`
	Signature            string `json:"signature,omitempty"`
}

type advertisementRoutingWire struct {
	Magic     string `json:"magic"`
	Protocol  uint64 `json:"protocol"`
	SessionID string `json:"session_id"`
}

var advertisementFields = map[string]struct{}{
	"magic":                  {},
	"protocol":               {},
	"session_id":             {},
	"https_port":             {},
	"credential_epoch":       {},
	"advertising_key_digest": {},
	"advertisement_nonce":    {},
	"expires_at":             {},
	"signature":              {},
}

// preflightAdvertisementRouting avoids allocating source state for a
// well-formed sibling-session datagram. Malformed input deliberately proceeds
// to the per-source limiter before strict canonical parsing.
func preflightAdvertisementRouting(
	input []byte,
	expectedSessionID domain.UUIDv7,
) error {
	var routing advertisementRoutingWire
	if err := json.Unmarshal(input, &routing); err != nil {
		return nil
	}
	if routing.Magic != "codecomm" ||
		routing.Protocol != ProtocolVersion {
		return ErrProtocolMismatch
	}
	if routing.SessionID != string(expectedSessionID) {
		return ErrSessionMismatch
	}
	return nil
}

// UnverifiedAdvertisement has passed bounded canonical decoding and the cheap
// protocol/session/field-shape checks, but grants no network authority.
type UnverifiedAdvertisement struct {
	advertisement Advertisement
	canonical     []byte
	unsigned      []byte
	signature     [ed25519.SignatureSize]byte
}

// VerifiedAdvertisement is signed by the exact committed epoch key supplied
// by the caller. It still grants only a short-lived endpoint hint.
type VerifiedAdvertisement struct {
	advertisement Advertisement
	canonical     []byte
}

// NewAdvertisement creates a fresh advertisement nonce from OS entropy.
func NewAdvertisement(
	sessionID domain.UUIDv7,
	httpsPort uint16,
	credentialEpoch uint64,
	advertisingKeyDigest [sha256.Size]byte,
	expiresAt domain.Timestamp,
) (Advertisement, error) {
	return newAdvertisement(
		sessionID,
		httpsPort,
		credentialEpoch,
		advertisingKeyDigest,
		expiresAt,
		cryptorand.Reader,
	)
}

func newAdvertisement(
	sessionID domain.UUIDv7,
	httpsPort uint16,
	credentialEpoch uint64,
	advertisingKeyDigest [sha256.Size]byte,
	expiresAt domain.Timestamp,
	entropy io.Reader,
) (Advertisement, error) {
	value := Advertisement{
		SessionID:            sessionID,
		HTTPSPort:            httpsPort,
		CredentialEpoch:      credentialEpoch,
		AdvertisingKeyDigest: advertisingKeyDigest,
		ExpiresAt:            expiresAt,
	}
	if entropy == nil {
		return Advertisement{}, codecommcrypto.ErrEntropy
	}
	if _, err := io.ReadFull(entropy, value.AdvertisementNonce[:]); err != nil {
		return Advertisement{}, fmt.Errorf("%w: %w", codecommcrypto.ErrEntropy, err)
	}
	if err := value.validate(); err != nil {
		return Advertisement{}, err
	}
	return value, nil
}

// SignAdvertisement returns the exact canonical multicast datagram.
func SignAdvertisement(
	value Advertisement,
	privateKey []byte,
) ([]byte, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(publicKey) != value.AdvertisingKeyDigest {
		return nil, ErrAdvertisingKey
	}

	wire := advertisementToWire(value)
	rawUnsigned, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: encode unsigned message: %v", ErrInvalidAdvertisement, err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(rawUnsigned)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize unsigned message: %v", ErrInvalidAdvertisement, err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureDiscovery,
		unsigned,
	)
	if err != nil {
		return nil, err
	}
	wire.Signature = codec.EncodeBase64URL(signature)
	rawComplete, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: encode signed message: %v", ErrInvalidAdvertisement, err)
	}
	complete, err := codec.CanonicalizeSignedObject(rawComplete)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize signed message: %v", ErrInvalidAdvertisement, err)
	}
	if len(complete) > MaxDatagramBytes {
		return nil, ErrAdvertisementTooLarge
	}
	return complete, nil
}

// ParseAdvertisement performs bounded canonical decoding and all cheap checks
// that precede signature verification. A sibling session returns
// ErrSessionMismatch so callers can ignore it without allocating source state.
func ParseAdvertisement(
	input []byte,
	expectedSessionID domain.UUIDv7,
) (UnverifiedAdvertisement, error) {
	if len(input) == 0 {
		return UnverifiedAdvertisement{}, ErrInvalidAdvertisement
	}
	if len(input) > MaxDatagramBytes {
		return UnverifiedAdvertisement{}, ErrAdvertisementTooLarge
	}
	if !expectedSessionID.Valid() {
		return UnverifiedAdvertisement{}, ErrSessionMismatch
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return UnverifiedAdvertisement{}, fmt.Errorf("%w: %w", ErrInvalidAdvertisement, err)
	}
	if !bytes.Equal(input, canonical) {
		return UnverifiedAdvertisement{}, ErrNoncanonicalMessage
	}
	unsigned, encodedSignature, err := codec.RemoveCanonicalObjectMember(
		canonical,
		"signature",
	)
	if err != nil {
		return UnverifiedAdvertisement{}, fmt.Errorf("%w: %w", ErrInvalidAdvertisement, err)
	}

	var wire advertisementWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return UnverifiedAdvertisement{}, fmt.Errorf("%w: decode message: %v", ErrInvalidAdvertisement, err)
	}
	if wire.Magic != "codecomm" || wire.Protocol != ProtocolVersion {
		return UnverifiedAdvertisement{}, ErrProtocolMismatch
	}
	if wire.SessionID != string(expectedSessionID) {
		return UnverifiedAdvertisement{}, ErrSessionMismatch
	}
	value, err := advertisementFromWire(wire)
	if err != nil {
		return UnverifiedAdvertisement{}, err
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil {
		return UnverifiedAdvertisement{}, fmt.Errorf("%w: signature", ErrInvalidAdvertisement)
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil {
		return UnverifiedAdvertisement{}, fmt.Errorf("%w: signature: %v", ErrInvalidAdvertisement, err)
	}
	result := UnverifiedAdvertisement{
		advertisement: value,
		canonical:     bytes.Clone(canonical),
		unsigned:      unsigned,
	}
	copy(result.signature[:], signature)
	return result, nil
}

// ValidateTime applies the receiver-local liveness window. It is never a
// reducer input or replicated authority.
func (value UnverifiedAdvertisement) ValidateTime(now time.Time) error {
	expiresAt, err := value.advertisement.ExpiresAt.Time()
	if err != nil {
		return ErrInvalidAdvertisement
	}
	now = now.UTC()
	if !expiresAt.After(now) {
		return ErrAdvertisementExpired
	}
	if expiresAt.After(now.Add(MaxAdvertisementFuture)) {
		return ErrAdvertisementFuture
	}
	return nil
}

// Verify authenticates the exact unknown-field-preserving preimage, then
// enforces the closed V1 schema.
func (value UnverifiedAdvertisement) Verify(
	epochPublicKey ed25519.PublicKey,
) (VerifiedAdvertisement, error) {
	if len(epochPublicKey) != ed25519.PublicKeySize ||
		sha256.Sum256(epochPublicKey) != value.advertisement.AdvertisingKeyDigest {
		return VerifiedAdvertisement{}, ErrAdvertisingKey
	}
	if err := codecommcrypto.VerifyEd25519(
		epochPublicKey,
		codec.SignatureDiscovery,
		value.unsigned,
		value.signature[:],
	); err != nil {
		return VerifiedAdvertisement{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(value.canonical, &members); err != nil {
		return VerifiedAdvertisement{}, fmt.Errorf("%w: decode fields", ErrInvalidAdvertisement)
	}
	for field := range members {
		if _, exists := advertisementFields[field]; !exists {
			return VerifiedAdvertisement{}, fmt.Errorf("%w: %s", ErrUnknownField, field)
		}
	}
	if len(members) != len(advertisementFields) {
		return VerifiedAdvertisement{}, ErrInvalidAdvertisement
	}
	return VerifiedAdvertisement{
		advertisement: value.advertisement,
		canonical:     bytes.Clone(value.canonical),
	}, nil
}

// Advertisement returns an independent copy of the decoded, untrusted fields.
func (value UnverifiedAdvertisement) Advertisement() Advertisement {
	return value.advertisement
}

// Advertisement returns an independent copy of the authenticated fields.
func (value VerifiedAdvertisement) Advertisement() Advertisement {
	return value.advertisement
}

// CanonicalBytes returns an independent copy suitable for fixtures or audit.
func (value VerifiedAdvertisement) CanonicalBytes() []byte {
	return bytes.Clone(value.canonical)
}

func (value Advertisement) validate() error {
	if !value.SessionID.Valid() ||
		value.HTTPSPort == 0 ||
		value.CredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(value.CredentialEpoch) ||
		!value.ExpiresAt.Valid() {
		return ErrInvalidAdvertisement
	}
	return nil
}

func advertisementToWire(value Advertisement) advertisementWire {
	return advertisementWire{
		Magic:                "codecomm",
		Protocol:             ProtocolVersion,
		SessionID:            string(value.SessionID),
		HTTPSPort:            value.HTTPSPort,
		CredentialEpoch:      value.CredentialEpoch,
		AdvertisingKeyDigest: codec.EncodeBase64URL(value.AdvertisingKeyDigest[:]),
		AdvertisementNonce:   codec.EncodeBase64URL(value.AdvertisementNonce[:]),
		ExpiresAt:            string(value.ExpiresAt),
	}
}

func advertisementFromWire(
	wire advertisementWire,
) (Advertisement, error) {
	sessionID := domain.UUIDv7(wire.SessionID)
	keyDigest, err := codec.DecodeBase64URLExact(
		wire.AdvertisingKeyDigest,
		sha256.Size,
	)
	if err != nil {
		return Advertisement{}, fmt.Errorf("%w: advertising key digest: %v", ErrInvalidAdvertisement, err)
	}
	nonce, err := codec.DecodeBase64URLExact(
		wire.AdvertisementNonce,
		AdvertisementNonceSize,
	)
	if err != nil {
		return Advertisement{}, fmt.Errorf("%w: nonce: %v", ErrInvalidAdvertisement, err)
	}
	value := Advertisement{
		SessionID:       sessionID,
		HTTPSPort:       wire.HTTPSPort,
		CredentialEpoch: wire.CredentialEpoch,
		ExpiresAt:       domain.Timestamp(wire.ExpiresAt),
	}
	copy(value.AdvertisingKeyDigest[:], keyDigest)
	copy(value.AdvertisementNonce[:], nonce)
	if err := value.validate(); err != nil {
		return Advertisement{}, err
	}
	return value, nil
}
