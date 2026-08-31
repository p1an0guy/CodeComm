// Package pairing implements one-use signed invites and exporter-bound SAS
// confirmation. It grants no membership authority by itself.
package pairing

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	SchemaVersion          uint64 = 1
	ProtocolVersion        uint64 = 1
	InviteCodePrefix              = "ccinvite1_"
	InviteSecretSize              = 16
	InviteTTL                     = 15 * time.Minute
	MaxPairingMessageBytes        = 64 << 10
	MaxInviteEndpoints            = 16
)

var (
	ErrInvalidInvite       = errors.New("pairing: invalid invite")
	ErrInviteTooLarge      = errors.New("pairing: invite exceeds message limit")
	ErrInviteCode          = errors.New("pairing: invalid invite code")
	ErrInviteSchema        = errors.New("pairing: unsupported invite schema")
	ErrInviteIdentity      = errors.New("pairing: invite identity mismatch")
	ErrInviteTime          = errors.New("pairing: invalid invite lifetime")
	ErrInviteMode          = errors.New("pairing: invalid invite mode")
	ErrInviteEndpoint      = errors.New("pairing: invalid invite endpoint")
	ErrInviteEndpointOrder = errors.New("pairing: invite endpoints are not sorted and unique")
	ErrInviteUnknownField  = errors.New("pairing: unknown invite field")
)

// Mode identifies the only three V1 pairing workflows.
type Mode string

const (
	ModeNew         Mode = "new"
	ModeRebootstrap Mode = "rebootstrap"
	ModeReadmission Mode = "readmission"
)

func (mode Mode) Valid() bool {
	return mode == ModeNew || mode == ModeRebootstrap || mode == ModeReadmission
}

// GenerateInviteSecret returns a fresh one-use secret from OS entropy.
func GenerateInviteSecret() ([InviteSecretSize]byte, error) {
	return generateInviteSecret(cryptorand.Reader)
}

func generateInviteSecret(entropy io.Reader) ([InviteSecretSize]byte, error) {
	var secret [InviteSecretSize]byte
	if entropy == nil {
		return secret, codecommcrypto.ErrEntropy
	}
	if _, err := io.ReadFull(entropy, secret[:]); err != nil {
		clear(secret[:])
		return secret, fmt.Errorf("%w: %w", codecommcrypto.ErrEntropy, err)
	}
	return secret, nil
}

// Endpoint is one inviter-owned literal listener address.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

// Invite is the exact signed V1 trust bundle. Secret must be cleared by the
// caller after native-store persistence or proof construction.
type Invite struct {
	InviteID                 domain.UUIDv7
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	CreatedAt                domain.WholeSecondTimestamp
	ExpiresAt                domain.WholeSecondTimestamp
	Secret                   [InviteSecretSize]byte
	InviterDeviceID          domain.DeviceID
	InviterIdentityPublicKey [ed25519.PublicKeySize]byte
	SignedGenesisDigest      [sha256.Size]byte
	Mode                     Mode
	SubjectDeviceID          *domain.DeviceID
	ExpectedEntityVersion    *uint64
	Role                     device.Role
	InitialCredentialEpoch   uint64
	Endpoints                []Endpoint
}

// SignedInvite retains exact canonical bytes and their complete-object digest.
type SignedInvite struct {
	value     Invite
	canonical []byte
	digest    [sha256.Size]byte
}

type inviteEndpointWire struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type inviteWire struct {
	SchemaVersion            uint64               `json:"schema_version"`
	Protocol                 uint64               `json:"protocol"`
	InviteID                 string               `json:"invite_id"`
	SessionID                string               `json:"session_id"`
	WorkspaceID              string               `json:"workspace_id"`
	RecoveryGeneration       uint64               `json:"recovery_generation"`
	CreatedAt                string               `json:"created_at"`
	ExpiresAt                string               `json:"expires_at"`
	Secret                   string               `json:"secret"`
	InviterDeviceID          string               `json:"inviter_device_id"`
	InviterIdentityPublicKey string               `json:"inviter_identity_public_key"`
	SignedGenesisDigest      string               `json:"signed_genesis_digest"`
	Mode                     string               `json:"mode"`
	SubjectDeviceID          *string              `json:"subject_device_id"`
	ExpectedEntityVersion    *uint64              `json:"expected_entity_version"`
	Role                     string               `json:"role"`
	InitialCredentialEpoch   uint64               `json:"initial_credential_epoch"`
	Endpoints                []inviteEndpointWire `json:"endpoints"`
	Signature                string               `json:"signature,omitempty"`
}

// SignInvite validates and identity-signs the exact invite.
func SignInvite(value Invite, identityPrivateKey []byte) (SignedInvite, error) {
	if err := value.validate(); err != nil {
		return SignedInvite{}, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivateKey)
	if err != nil {
		return SignedInvite{}, err
	}
	if !bytes.Equal(publicKey, value.InviterIdentityPublicKey[:]) {
		return SignedInvite{}, ErrInviteIdentity
	}

	wire := inviteToWire(value)
	raw, err := json.Marshal(wire)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: encode: %v", ErrInvalidInvite, err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: canonicalize: %v", ErrInvalidInvite, err)
	}
	signature, err := codecommcrypto.SignEd25519(
		identityPrivateKey,
		codec.SignatureInvite,
		unsigned,
	)
	if err != nil {
		return SignedInvite{}, err
	}
	wire.Signature = codec.EncodeBase64URL(signature)
	raw, err = json.Marshal(wire)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: encode signed: %v", ErrInvalidInvite, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: canonicalize signed: %v", ErrInvalidInvite, err)
	}
	if len(InviteCodePrefix)+len(codec.EncodeBase64URL(canonical)) > MaxPairingMessageBytes {
		return SignedInvite{}, ErrInviteTooLarge
	}
	return newSignedInvite(value, canonical), nil
}

// ParseInviteCode verifies an exact prefixed, unpadded-base64url invite.
func ParseInviteCode(code string) (SignedInvite, error) {
	return ParseInviteCodeBytes([]byte(code))
}

// ParseInviteCodeBytes verifies an exact prefixed, unpadded-base64url invite
// without creating an immutable secret-bearing string.
func ParseInviteCodeBytes(code []byte) (SignedInvite, error) {
	prefix := []byte(InviteCodePrefix)
	if len(code) > MaxPairingMessageBytes ||
		!bytes.HasPrefix(code, prefix) {
		return SignedInvite{}, ErrInviteCode
	}
	encoded := code[len(prefix):]
	canonical := make(
		[]byte,
		base64.RawURLEncoding.DecodedLen(len(encoded)),
	)
	count, err := base64.RawURLEncoding.Strict().Decode(
		canonical,
		encoded,
	)
	if err != nil {
		clear(canonical)
		return SignedInvite{}, fmt.Errorf("%w: %v", ErrInviteCode, err)
	}
	canonical = canonical[:count]
	defer clear(canonical)
	if len(canonical) == 0 || len(canonical) > MaxPairingMessageBytes {
		return SignedInvite{}, ErrInviteCode
	}
	reencoded := make([]byte, 0, len(code))
	reencoded = append(reencoded, prefix...)
	reencoded = base64.RawURLEncoding.AppendEncode(reencoded, canonical)
	defer clear(reencoded)
	if !bytes.Equal(reencoded, code) {
		return SignedInvite{}, ErrInviteCode
	}
	return parseSignedInvite(canonical)
}

func parseSignedInvite(canonical []byte) (SignedInvite, error) {
	parsed, err := codec.CanonicalizeSignedObject(canonical)
	if err != nil || !bytes.Equal(parsed, canonical) {
		return SignedInvite{}, fmt.Errorf("%w: canonical form", ErrInvalidInvite)
	}
	unsigned, signatureJSON, err := codec.RemoveCanonicalObjectMember(canonical, "signature")
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: signature: %v", ErrInvalidInvite, err)
	}
	var wire inviteWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return SignedInvite{}, fmt.Errorf("%w: decode: %v", ErrInvalidInvite, err)
	}
	publicKey, err := codec.DecodeBase64URLExact(wire.InviterIdentityPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: inviter key", ErrInvalidInvite)
	}
	var signatureText string
	if err := json.Unmarshal(signatureJSON, &signatureText); err != nil {
		return SignedInvite{}, fmt.Errorf("%w: signature", ErrInvalidInvite)
	}
	signature, err := codec.DecodeBase64URLExact(signatureText, ed25519.SignatureSize)
	if err != nil {
		return SignedInvite{}, fmt.Errorf("%w: signature", ErrInvalidInvite)
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureInvite,
		unsigned,
		signature,
	); err != nil {
		return SignedInvite{}, err
	}
	if err := validateClosedInviteSchema(canonical); err != nil {
		return SignedInvite{}, err
	}
	value, err := inviteFromWire(wire)
	if err != nil {
		return SignedInvite{}, err
	}
	return newSignedInvite(value, canonical), nil
}

// Invite returns an independent decoded copy.
func (value SignedInvite) Invite() Invite { return value.value.clone() }

// CanonicalBytes returns an independent copy of the complete signed object.
func (value SignedInvite) CanonicalBytes() []byte { return bytes.Clone(value.canonical) }

// Code returns the exact shareable invite representation.
func (value SignedInvite) Code() string {
	if len(value.canonical) == 0 {
		return ""
	}
	return InviteCodePrefix + codec.EncodeBase64URL(value.canonical)
}

// Digest returns SHA-256 over the complete signed canonical invite.
func (value SignedInvite) Digest() [sha256.Size]byte { return value.digest }

// Clear zeroes the retained invite secret and canonical representation.
func (value *SignedInvite) Clear() {
	if value == nil {
		return
	}
	clear(value.value.Secret[:])
	clear(value.canonical)
	*value = SignedInvite{}
}

// Validate re-verifies the retained canonical invite without materializing its share code.
func (value SignedInvite) Validate() error {
	if len(value.canonical) == 0 || sha256.Sum256(value.canonical) != value.digest {
		return ErrInvalidInvite
	}
	parsed, err := parseSignedInvite(value.canonical)
	defer clear(parsed.value.Secret[:])
	if err != nil || parsed.digest != value.digest {
		return ErrInvalidInvite
	}
	return nil
}

// ValidateTime applies the issuer-local one-use invite lifetime.
func (value SignedInvite) ValidateTime(now time.Time) error {
	createdAt, _ := value.value.CreatedAt.Time()
	expiresAt, _ := value.value.ExpiresAt.Time()
	now = now.UTC()
	if now.Before(createdAt) || !expiresAt.After(now) {
		return ErrInviteTime
	}
	return nil
}

func newSignedInvite(value Invite, canonical []byte) SignedInvite {
	return SignedInvite{
		value:     value.clone(),
		canonical: bytes.Clone(canonical),
		digest:    sha256.Sum256(canonical),
	}
}

func (value Invite) validate() error {
	if !value.InviteID.Valid() || !value.SessionID.Valid() || !value.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(value.RecoveryGeneration) || !value.CreatedAt.Valid() ||
		!value.ExpiresAt.Valid() || !value.InviterDeviceID.Valid() || !value.Role.Valid() ||
		value.InitialCredentialEpoch < 1 || !domain.ValidUnsignedInteger(value.InitialCredentialEpoch) {
		return ErrInvalidInvite
	}
	derivedID, err := device.DeriveID(value.InviterIdentityPublicKey[:])
	if err != nil || derivedID != value.InviterDeviceID {
		return ErrInviteIdentity
	}
	createdAt, _ := value.CreatedAt.Time()
	expiresAt, _ := value.ExpiresAt.Time()
	if expiresAt.Sub(createdAt) != InviteTTL {
		return ErrInviteTime
	}
	if !value.Mode.Valid() {
		return ErrInviteMode
	}
	switch value.Mode {
	case ModeNew:
		if value.SubjectDeviceID != nil || value.ExpectedEntityVersion != nil || value.InitialCredentialEpoch != 1 {
			return ErrInviteMode
		}
	case ModeRebootstrap:
		if value.SubjectDeviceID == nil || !value.SubjectDeviceID.Valid() || value.ExpectedEntityVersion != nil {
			return ErrInviteMode
		}
	case ModeReadmission:
		if value.SubjectDeviceID == nil || !value.SubjectDeviceID.Valid() ||
			value.ExpectedEntityVersion == nil || *value.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*value.ExpectedEntityVersion) || value.InitialCredentialEpoch != 1 {
			return ErrInviteMode
		}
	}
	if len(value.Endpoints) < 1 || len(value.Endpoints) > MaxInviteEndpoints {
		return ErrInviteEndpoint
	}
	listenerPort := value.Endpoints[0].Port
	for index, endpoint := range value.Endpoints {
		if err := endpoint.validate(); err != nil || endpoint.Port != listenerPort {
			return ErrInviteEndpoint
		}
		if index > 0 && compareEndpoints(value.Endpoints[index-1], endpoint) >= 0 {
			return ErrInviteEndpointOrder
		}
	}
	return nil
}

func (endpoint Endpoint) validate() error {
	address := endpoint.IP
	if !address.IsValid() || address.Zone() != "" || endpoint.Port == 0 ||
		address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() ||
		address.Is4In6() || address.Is6() && address.IsLinkLocalUnicast() ||
		address.Is4() && address.As4() == [4]byte{255, 255, 255, 255} {
		return ErrInviteEndpoint
	}
	return nil
}

func compareEndpoints(left, right Endpoint) int {
	if left.IP.Is4() != right.IP.Is4() {
		if left.IP.Is4() {
			return -1
		}
		return 1
	}
	order := bytes.Compare(left.IP.AsSlice(), right.IP.AsSlice())
	if order != 0 {
		return order
	}
	if left.Port < right.Port {
		return -1
	}
	if left.Port > right.Port {
		return 1
	}
	return 0
}

func inviteToWire(value Invite) inviteWire {
	endpoints := make([]inviteEndpointWire, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		endpoints[index] = inviteEndpointWire{IP: endpoint.IP.String(), Port: endpoint.Port}
	}
	var subject *string
	if value.SubjectDeviceID != nil {
		text := string(*value.SubjectDeviceID)
		subject = &text
	}
	return inviteWire{
		SchemaVersion: SchemaVersion, Protocol: ProtocolVersion,
		InviteID: string(value.InviteID), SessionID: string(value.SessionID),
		WorkspaceID: string(value.WorkspaceID), RecoveryGeneration: value.RecoveryGeneration,
		CreatedAt: string(value.CreatedAt), ExpiresAt: string(value.ExpiresAt),
		Secret: codec.EncodeBase64URL(value.Secret[:]), InviterDeviceID: string(value.InviterDeviceID),
		InviterIdentityPublicKey: codec.EncodeBase64URL(value.InviterIdentityPublicKey[:]),
		SignedGenesisDigest:      codec.EncodeBase64URL(value.SignedGenesisDigest[:]),
		Mode:                     string(value.Mode), SubjectDeviceID: subject,
		ExpectedEntityVersion: cloneUint64Pointer(value.ExpectedEntityVersion),
		Role:                  string(value.Role), InitialCredentialEpoch: value.InitialCredentialEpoch,
		Endpoints: endpoints,
	}
}

func inviteFromWire(wire inviteWire) (Invite, error) {
	if wire.SchemaVersion != SchemaVersion || wire.Protocol != ProtocolVersion {
		return Invite{}, ErrInviteSchema
	}
	secret, err := codec.DecodeBase64URLExact(wire.Secret, InviteSecretSize)
	if err != nil {
		return Invite{}, ErrInvalidInvite
	}
	identityKey, err := codec.DecodeBase64URLExact(wire.InviterIdentityPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return Invite{}, ErrInvalidInvite
	}
	genesisDigest, err := codec.DecodeBase64URLExact(wire.SignedGenesisDigest, sha256.Size)
	if err != nil {
		return Invite{}, ErrInvalidInvite
	}
	value := Invite{
		InviteID: domain.UUIDv7(wire.InviteID), SessionID: domain.UUIDv7(wire.SessionID),
		WorkspaceID: domain.UUIDv4(wire.WorkspaceID), RecoveryGeneration: wire.RecoveryGeneration,
		CreatedAt: domain.WholeSecondTimestamp(wire.CreatedAt),
		ExpiresAt: domain.WholeSecondTimestamp(wire.ExpiresAt), Mode: Mode(wire.Mode),
		ExpectedEntityVersion: cloneUint64Pointer(wire.ExpectedEntityVersion),
		Role:                  device.Role(wire.Role), InitialCredentialEpoch: wire.InitialCredentialEpoch,
	}
	copy(value.Secret[:], secret)
	copy(value.InviterIdentityPublicKey[:], identityKey)
	copy(value.SignedGenesisDigest[:], genesisDigest)
	value.InviterDeviceID = domain.DeviceID(wire.InviterDeviceID)
	if wire.SubjectDeviceID != nil {
		subject := domain.DeviceID(*wire.SubjectDeviceID)
		value.SubjectDeviceID = &subject
	}
	if len(wire.Endpoints) > MaxInviteEndpoints {
		return Invite{}, ErrInviteEndpoint
	}
	value.Endpoints = make([]Endpoint, len(wire.Endpoints))
	for index, endpoint := range wire.Endpoints {
		address, err := netip.ParseAddr(endpoint.IP)
		if err != nil || address.String() != endpoint.IP {
			return Invite{}, ErrInviteEndpoint
		}
		value.Endpoints[index] = Endpoint{IP: address, Port: endpoint.Port}
	}
	if err := value.validate(); err != nil {
		return Invite{}, err
	}
	return value, nil
}

func validateClosedInviteSchema(canonical []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return ErrInvalidInvite
	}
	fields := map[string]struct{}{
		"schema_version": {}, "protocol": {}, "invite_id": {}, "session_id": {},
		"workspace_id": {}, "recovery_generation": {}, "created_at": {}, "expires_at": {},
		"secret": {}, "inviter_device_id": {}, "inviter_identity_public_key": {},
		"signed_genesis_digest": {}, "mode": {}, "subject_device_id": {},
		"expected_entity_version": {}, "role": {}, "initial_credential_epoch": {},
		"endpoints": {}, "signature": {},
	}
	for field := range members {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("%w: %s", ErrInviteUnknownField, field)
		}
	}
	if len(members) != len(fields) {
		return ErrInvalidInvite
	}
	var endpoints []map[string]json.RawMessage
	if err := json.Unmarshal(members["endpoints"], &endpoints); err != nil {
		return ErrInvalidInvite
	}
	for _, endpoint := range endpoints {
		if len(endpoint) != 2 || endpoint["ip"] == nil || endpoint["port"] == nil {
			return ErrInvalidInvite
		}
	}
	return nil
}

func (value Invite) clone() Invite {
	value.Endpoints = append([]Endpoint(nil), value.Endpoints...)
	value.ExpectedEntityVersion = cloneUint64Pointer(value.ExpectedEntityVersion)
	if value.SubjectDeviceID != nil {
		subject := *value.SubjectDeviceID
		value.SubjectDeviceID = &subject
	}
	return value
}

func cloneUint64Pointer(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
