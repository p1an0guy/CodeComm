package discovery

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

const (
	EndpointSetSchemaVersion uint64 = 1
	MaxEndpointSetBytes             = 16 << 10
	MaxEndpointsPerSet              = 16
	EndpointHintTTLIntervals        = 8
	EndpointSetClockSkew            = 120 * time.Second
)

var (
	ErrInvalidEndpointSet            = errors.New("discovery: invalid signed endpoint set")
	ErrEndpointSetTooLarge           = errors.New("discovery: signed endpoint set exceeds 16 KiB")
	ErrEndpointSetSchema             = errors.New("discovery: unsupported endpoint-set schema")
	ErrEndpointSequence              = errors.New("discovery: invalid endpoint sequence")
	ErrEndpointSetTime               = errors.New("discovery: invalid endpoint-set time window")
	ErrEndpointSetExpired            = errors.New("discovery: endpoint set expired")
	ErrEndpointSetFuture             = errors.New("discovery: endpoint-set time exceeds the local acceptance window")
	ErrInvalidEndpoint               = errors.New("discovery: invalid endpoint")
	ErrEndpointOrder                 = errors.New("discovery: endpoints are not in canonical order")
	ErrDuplicateEndpoint             = errors.New("discovery: duplicate endpoint")
	ErrEndpointSetIdentity           = errors.New("discovery: endpoint-set identity mismatch")
	ErrEndpointSetLineage            = errors.New("discovery: endpoint-set lineage mismatch")
	ErrEndpointSetMember             = errors.New("discovery: endpoint-set signer is not an active member")
	ErrEndpointAdvertisementInterval = errors.New("discovery: invalid endpoint advertisement interval")
	ErrEndpointSigner                = errors.New("discovery: invalid endpoint signer configuration")
	ErrEndpointNotSelected           = errors.New("discovery: endpoint is not a selected listener address")
)

// Endpoint is one canonical literal IP address and listener port.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

// EndpointSet is the signed source-owned endpoint set for one active member.
type EndpointSet struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	DeviceID           domain.DeviceID
	EndpointSequence   uint64
	IssuedAt           domain.WholeSecondTimestamp
	ExpiresAt          domain.WholeSecondTimestamp
	Endpoints          []Endpoint
}

type endpointWire struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type endpointSetWire struct {
	SchemaVersion      uint64         `json:"schema_version"`
	SessionID          string         `json:"session_id"`
	WorkspaceID        string         `json:"workspace_id"`
	RecoveryGeneration uint64         `json:"recovery_generation"`
	DeviceID           string         `json:"device_id"`
	EndpointSequence   uint64         `json:"endpoint_sequence"`
	IssuedAt           string         `json:"issued_at"`
	ExpiresAt          string         `json:"expires_at"`
	Endpoints          []endpointWire `json:"endpoints"`
	Signature          string         `json:"signature,omitempty"`
}

// EndpointSetExpectation supplies the applied lineage, active member, and
// receiver-local liveness inputs used to validate an endpoint set.
type EndpointSetExpectation struct {
	SessionID             domain.UUIDv7
	WorkspaceID           domain.UUIDv4
	RecoveryGeneration    uint64
	Member                device.Device
	AdvertisementInterval time.Duration
	Now                   time.Time
}

// UnverifiedEndpointSet has passed bounded canonical decoding but grants no
// routing authority.
type UnverifiedEndpointSet struct {
	value     EndpointSet
	canonical []byte
	unsigned  []byte
	signature [ed25519.SignatureSize]byte
}

// VerifiedEndpointSet is signed by the expected active member and is valid
// for the supplied lineage and receiver-local time window.
type VerifiedEndpointSet struct {
	value     EndpointSet
	canonical []byte
}

// EndpointSigner is the only exported endpoint publication path. It binds
// every advertised address to the daemon's selected interfaces and listener.
type EndpointSigner struct {
	advertisementInterval time.Duration
	listenerPort          uint16
	selectedAddresses     map[netip.Addr]struct{}
}

// NewEndpointSigner snapshots the selected, non-link-local interface
// addresses for one active listener.
func NewEndpointSigner(
	advertisementInterval time.Duration,
	listenerPort uint16,
	selectedAddresses []netip.Addr,
) (*EndpointSigner, error) {
	if err := validateEndpointAdvertisementInterval(
		advertisementInterval,
	); err != nil {
		return nil, err
	}
	if listenerPort == 0 ||
		len(selectedAddresses) < 1 ||
		len(selectedAddresses) > MaxEndpointsPerSet {
		return nil, ErrEndpointSigner
	}
	selected := make(map[netip.Addr]struct{}, len(selectedAddresses))
	for _, address := range selectedAddresses {
		if err := (Endpoint{IP: address, Port: listenerPort}).validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEndpointSigner, err)
		}
		if _, duplicate := selected[address]; duplicate {
			return nil, ErrEndpointSigner
		}
		selected[address] = struct{}{}
	}
	return &EndpointSigner{
		advertisementInterval: advertisementInterval,
		listenerPort:          listenerPort,
		selectedAddresses:     selected,
	}, nil
}

// Sign returns the exact canonical identity-signed endpoint set after
// checking every endpoint against the selected listener snapshot.
func (signer *EndpointSigner) Sign(
	value EndpointSet,
	identityPrivateKey []byte,
) ([]byte, error) {
	if signer == nil || len(signer.selectedAddresses) == 0 {
		return nil, ErrEndpointSigner
	}
	for _, endpoint := range value.Endpoints {
		if endpoint.Port != signer.listenerPort {
			return nil, ErrEndpointNotSelected
		}
		if _, selected := signer.selectedAddresses[endpoint.IP]; !selected {
			return nil, ErrEndpointNotSelected
		}
	}
	return signEndpointSet(
		value,
		identityPrivateKey,
		signer.advertisementInterval,
	)
}

// signEndpointSet is the fixture-level primitive beneath EndpointSigner.
func signEndpointSet(
	value EndpointSet,
	identityPrivateKey []byte,
	advertisementInterval time.Duration,
) ([]byte, error) {
	if err := value.validate(advertisementInterval); err != nil {
		return nil, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		identityPrivateKey,
	)
	if err != nil {
		return nil, err
	}
	deviceID, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil {
		return nil, err
	}
	if domain.DeviceID(deviceID) != value.DeviceID {
		return nil, ErrEndpointSetIdentity
	}

	wire := endpointSetToWire(value)
	rawUnsigned, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: encode unsigned object: %v", ErrInvalidEndpointSet, err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(rawUnsigned)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize unsigned object: %v", ErrInvalidEndpointSet, err)
	}
	signature, err := codecommcrypto.SignEd25519(
		identityPrivateKey,
		codec.SignatureEndpointHints,
		unsigned,
	)
	if err != nil {
		return nil, err
	}
	wire.Signature = codec.EncodeBase64URL(signature)
	rawComplete, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: encode signed object: %v", ErrInvalidEndpointSet, err)
	}
	complete, err := codec.CanonicalizeSignedObject(rawComplete)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize signed object: %v", ErrInvalidEndpointSet, err)
	}
	if len(complete) > MaxEndpointSetBytes {
		return nil, ErrEndpointSetTooLarge
	}
	return complete, nil
}

// ParseEndpointSet performs bounded canonical decoding while retaining the
// exact signature preimage. Closed-schema enforcement is intentionally
// deferred until after identity verification.
func ParseEndpointSet(input []byte) (UnverifiedEndpointSet, error) {
	if len(input) == 0 {
		return UnverifiedEndpointSet{}, ErrInvalidEndpointSet
	}
	if len(input) > MaxEndpointSetBytes {
		return UnverifiedEndpointSet{}, ErrEndpointSetTooLarge
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return UnverifiedEndpointSet{}, fmt.Errorf("%w: %w", ErrInvalidEndpointSet, err)
	}
	if !bytes.Equal(input, canonical) {
		return UnverifiedEndpointSet{}, ErrNoncanonicalMessage
	}
	unsigned, encodedSignature, err := codec.RemoveCanonicalObjectMember(
		canonical,
		"signature",
	)
	if err != nil {
		return UnverifiedEndpointSet{}, fmt.Errorf("%w: %w", ErrInvalidEndpointSet, err)
	}

	var wire endpointSetWire
	if err := json.Unmarshal(canonical, &wire); err != nil {
		return UnverifiedEndpointSet{}, fmt.Errorf("%w: decode object: %v", ErrInvalidEndpointSet, err)
	}
	value, err := endpointSetFromWire(wire)
	if err != nil {
		return UnverifiedEndpointSet{}, err
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil {
		return UnverifiedEndpointSet{}, fmt.Errorf("%w: signature", ErrInvalidEndpointSet)
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil {
		return UnverifiedEndpointSet{}, fmt.Errorf("%w: signature: %v", ErrInvalidEndpointSet, err)
	}

	result := UnverifiedEndpointSet{
		value:     value,
		canonical: bytes.Clone(canonical),
		unsigned:  unsigned,
	}
	copy(result.signature[:], signature)
	return result, nil
}

// ValidateEndpointSet parses and verifies one signed endpoint set.
func ValidateEndpointSet(
	input []byte,
	expected EndpointSetExpectation,
) (VerifiedEndpointSet, error) {
	unverified, err := ParseEndpointSet(input)
	if err != nil {
		return VerifiedEndpointSet{}, err
	}
	return unverified.Verify(expected)
}

// Verify authenticates the exact received object before enforcing its closed
// schema, then validates lineage, membership, endpoints, and local liveness.
func (value UnverifiedEndpointSet) Verify(
	expected EndpointSetExpectation,
) (VerifiedEndpointSet, error) {
	if err := expected.validate(); err != nil {
		return VerifiedEndpointSet{}, err
	}
	if err := codecommcrypto.VerifyEd25519(
		expected.Member.IdentityPublicKey,
		codec.SignatureEndpointHints,
		value.unsigned,
		value.signature[:],
	); err != nil {
		return VerifiedEndpointSet{}, err
	}
	if err := validateClosedEndpointSetSchema(value.canonical); err != nil {
		return VerifiedEndpointSet{}, err
	}
	if err := value.value.validate(expected.AdvertisementInterval); err != nil {
		return VerifiedEndpointSet{}, err
	}
	if value.value.SessionID != expected.SessionID ||
		value.value.WorkspaceID != expected.WorkspaceID ||
		value.value.RecoveryGeneration != expected.RecoveryGeneration {
		return VerifiedEndpointSet{}, ErrEndpointSetLineage
	}
	if value.value.DeviceID != expected.Member.ID {
		return VerifiedEndpointSet{}, ErrEndpointSetIdentity
	}
	if err := value.value.validateLocalTime(
		expected.Now,
		expected.AdvertisementInterval,
	); err != nil {
		return VerifiedEndpointSet{}, err
	}
	return VerifiedEndpointSet{
		value:     value.value.clone(),
		canonical: bytes.Clone(value.canonical),
	}, nil
}

// EndpointSet returns an independent copy of the decoded value.
func (value UnverifiedEndpointSet) EndpointSet() EndpointSet {
	return value.value.clone()
}

// EndpointSet returns an independent copy of the authenticated value.
func (value VerifiedEndpointSet) EndpointSet() EndpointSet {
	return value.value.clone()
}

// CanonicalBytes returns an independent copy of the exact signed JCS object.
func (value VerifiedEndpointSet) CanonicalBytes() []byte {
	return bytes.Clone(value.canonical)
}

// OpaqueRelay returns the exact signed JCS object as unpadded base64url.
func (value VerifiedEndpointSet) OpaqueRelay() string {
	return codec.EncodeBase64URL(value.canonical)
}

// NextEndpointSequence returns max(previous+1, current Unix milliseconds).
func NextEndpointSequence(previous uint64, now time.Time) (uint64, error) {
	if previous >= domain.MaxSafeInteger {
		return 0, fmt.Errorf(
			"%w: previous value %d cannot advance",
			ErrEndpointSequence,
			previous,
		)
	}
	next := previous + 1
	epoch := time.Unix(0, 0)
	firstOutOfRange := time.UnixMilli(int64(domain.MaxSafeInteger) + 1)
	if !now.Before(firstOutOfRange) {
		return 0, fmt.Errorf(
			"%w: Unix milliseconds exceed %d",
			ErrEndpointSequence,
			domain.MaxSafeInteger,
		)
	}
	if !now.Before(epoch) {
		milliseconds := uint64(now.UnixMilli())
		if milliseconds > next {
			next = milliseconds
		}
	}
	if next < 1 || !domain.ValidUnsignedInteger(next) {
		return 0, ErrEndpointSequence
	}
	return next, nil
}

func (expected EndpointSetExpectation) validate() error {
	if !expected.SessionID.Valid() ||
		!expected.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(expected.RecoveryGeneration) {
		return ErrEndpointSetLineage
	}
	if err := expected.Member.Validate(); err != nil ||
		expected.Member.Status != device.StatusActive {
		return ErrEndpointSetMember
	}
	if expected.Now.IsZero() {
		return ErrEndpointSetTime
	}
	return validateEndpointAdvertisementInterval(
		expected.AdvertisementInterval,
	)
}

func (value EndpointSet) validate(
	advertisementInterval time.Duration,
) error {
	if err := value.validateShape(); err != nil {
		return err
	}
	if err := validateEndpointAdvertisementInterval(
		advertisementInterval,
	); err != nil {
		return err
	}
	issuedAt, _ := value.IssuedAt.Time()
	expiresAt, _ := value.ExpiresAt.Time()
	if expiresAt.Sub(issuedAt) > EndpointHintTTLIntervals*advertisementInterval {
		return ErrEndpointSetTime
	}
	return nil
}

func (value EndpointSet) validateShape() error {
	if !value.SessionID.Valid() ||
		!value.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(value.RecoveryGeneration) ||
		!value.DeviceID.Valid() {
		return ErrInvalidEndpointSet
	}
	if value.EndpointSequence < 1 ||
		!domain.ValidUnsignedInteger(value.EndpointSequence) {
		return ErrEndpointSequence
	}
	if !value.IssuedAt.Valid() || !value.ExpiresAt.Valid() {
		return ErrEndpointSetTime
	}
	issuedAt, _ := value.IssuedAt.Time()
	expiresAt, _ := value.ExpiresAt.Time()
	if !expiresAt.After(issuedAt) {
		return ErrEndpointSetTime
	}
	if len(value.Endpoints) < 1 || len(value.Endpoints) > MaxEndpointsPerSet {
		return ErrInvalidEndpointSet
	}
	for index, endpoint := range value.Endpoints {
		if err := endpoint.validate(); err != nil {
			return fmt.Errorf(
				"%w at index %d: %w",
				ErrInvalidEndpointSet,
				index,
				err,
			)
		}
		if index == 0 {
			continue
		}
		order := compareEndpoints(value.Endpoints[index-1], endpoint)
		if order == 0 {
			return fmt.Errorf("%w at index %d", ErrDuplicateEndpoint, index)
		}
		if order > 0 {
			return fmt.Errorf("%w at index %d", ErrEndpointOrder, index)
		}
	}
	return nil
}

func (value EndpointSet) validateLocalTime(
	now time.Time,
	advertisementInterval time.Duration,
) error {
	issuedAt, _ := value.IssuedAt.Time()
	expiresAt, _ := value.ExpiresAt.Time()
	now = now.UTC()
	if issuedAt.After(now.Add(EndpointSetClockSkew)) {
		return ErrEndpointSetFuture
	}
	if !expiresAt.After(now) {
		return ErrEndpointSetExpired
	}
	latestExpiry := now.Add(
		EndpointHintTTLIntervals*advertisementInterval +
			EndpointSetClockSkew,
	)
	if expiresAt.After(latestExpiry) {
		return ErrEndpointSetFuture
	}
	return nil
}

func validateEndpointAdvertisementInterval(interval time.Duration) error {
	minimum := time.Duration(policy.MinAdvertisementIntervalSeconds) *
		time.Second
	maximum := time.Duration(policy.MaxAdvertisementIntervalSeconds) *
		time.Second
	if interval < minimum ||
		interval > maximum ||
		interval%time.Second != 0 {
		return ErrEndpointAdvertisementInterval
	}
	return nil
}

func (endpoint Endpoint) validate() error {
	address := endpoint.IP
	if !address.IsValid() ||
		address.Zone() != "" ||
		endpoint.Port == 0 ||
		address.IsLoopback() ||
		address.IsUnspecified() ||
		address.IsMulticast() ||
		address.Is4In6() ||
		address.Is6() && address.IsLinkLocalUnicast() ||
		isIPv4Broadcast(address) {
		return ErrInvalidEndpoint
	}
	return nil
}

func isIPv4Broadcast(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	return address.As4() == [4]byte{255, 255, 255, 255}
}

func compareEndpoints(left, right Endpoint) int {
	switch {
	case left.IP.Is4() && right.IP.Is6():
		return -1
	case left.IP.Is6() && right.IP.Is4():
		return 1
	}
	var addressOrder int
	if left.IP.Is4() {
		leftBytes := left.IP.As4()
		rightBytes := right.IP.As4()
		addressOrder = bytes.Compare(leftBytes[:], rightBytes[:])
	} else {
		leftBytes := left.IP.As16()
		rightBytes := right.IP.As16()
		addressOrder = bytes.Compare(leftBytes[:], rightBytes[:])
	}
	if addressOrder != 0 {
		return addressOrder
	}
	switch {
	case left.Port < right.Port:
		return -1
	case left.Port > right.Port:
		return 1
	default:
		return 0
	}
}

func endpointSetToWire(value EndpointSet) endpointSetWire {
	endpoints := make([]endpointWire, len(value.Endpoints))
	for index, endpoint := range value.Endpoints {
		endpoints[index] = endpointWire{
			IP:   endpoint.IP.String(),
			Port: endpoint.Port,
		}
	}
	return endpointSetWire{
		SchemaVersion:      EndpointSetSchemaVersion,
		SessionID:          string(value.SessionID),
		WorkspaceID:        string(value.WorkspaceID),
		RecoveryGeneration: value.RecoveryGeneration,
		DeviceID:           string(value.DeviceID),
		EndpointSequence:   value.EndpointSequence,
		IssuedAt:           string(value.IssuedAt),
		ExpiresAt:          string(value.ExpiresAt),
		Endpoints:          endpoints,
	}
}

func endpointSetFromWire(wire endpointSetWire) (EndpointSet, error) {
	if wire.SchemaVersion != EndpointSetSchemaVersion {
		return EndpointSet{}, ErrEndpointSetSchema
	}
	if len(wire.Endpoints) < 1 || len(wire.Endpoints) > MaxEndpointsPerSet {
		return EndpointSet{}, ErrInvalidEndpointSet
	}
	endpoints := make([]Endpoint, len(wire.Endpoints))
	for index, wireEndpoint := range wire.Endpoints {
		address, err := netip.ParseAddr(wireEndpoint.IP)
		if err != nil ||
			address.Zone() != "" ||
			address.String() != wireEndpoint.IP {
			return EndpointSet{}, fmt.Errorf(
				"%w: noncanonical IP at index %d",
				ErrInvalidEndpoint,
				index,
			)
		}
		endpoints[index] = Endpoint{
			IP:   address,
			Port: wireEndpoint.Port,
		}
	}
	value := EndpointSet{
		SessionID:          domain.UUIDv7(wire.SessionID),
		WorkspaceID:        domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration: wire.RecoveryGeneration,
		DeviceID:           domain.DeviceID(wire.DeviceID),
		EndpointSequence:   wire.EndpointSequence,
		IssuedAt:           domain.WholeSecondTimestamp(wire.IssuedAt),
		ExpiresAt:          domain.WholeSecondTimestamp(wire.ExpiresAt),
		Endpoints:          endpoints,
	}
	if err := value.validateShape(); err != nil {
		return EndpointSet{}, err
	}
	return value, nil
}

func validateClosedEndpointSetSchema(canonical []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return fmt.Errorf("%w: decode fields", ErrInvalidEndpointSet)
	}
	for field := range members {
		if !isEndpointSetField(field) {
			return fmt.Errorf("%w: %s", ErrUnknownField, field)
		}
	}
	if len(members) != 10 {
		return ErrInvalidEndpointSet
	}

	var endpoints []map[string]json.RawMessage
	if err := json.Unmarshal(members["endpoints"], &endpoints); err != nil {
		return fmt.Errorf("%w: decode endpoint fields", ErrInvalidEndpointSet)
	}
	for index, endpoint := range endpoints {
		for field := range endpoint {
			if field != "ip" && field != "port" {
				return fmt.Errorf(
					"%w: endpoints[%d].%s",
					ErrUnknownField,
					index,
					field,
				)
			}
		}
		if len(endpoint) != 2 {
			return fmt.Errorf(
				"%w: endpoint %d fields",
				ErrInvalidEndpointSet,
				index,
			)
		}
	}
	return nil
}

func isEndpointSetField(field string) bool {
	switch field {
	case "schema_version",
		"session_id",
		"workspace_id",
		"recovery_generation",
		"device_id",
		"endpoint_sequence",
		"issued_at",
		"expires_at",
		"endpoints",
		"signature":
		return true
	default:
		return false
	}
}

func (value EndpointSet) clone() EndpointSet {
	value.Endpoints = append([]Endpoint(nil), value.Endpoints...)
	return value
}
