package transport

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const certificateBindingFormatVersion = 1

const ContentClockSkew = 120 * time.Second

var (
	ErrInvalidCertificateInput = errors.New("transport: invalid certificate input")
	ErrCertificateProfile      = errors.New("transport: invalid certificate profile")
	ErrCertificateBinding      = errors.New("transport: invalid certificate binding")
	ErrCertificateNotCurrent   = errors.New("transport: content certificate is not current")
)

var (
	identityNotBefore = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	identityNotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// IdentityBinding is the exact long-lived consensus/pairing certificate
// commitment. DeviceID is derived from the certificate public key digest.
type IdentityBinding struct {
	SessionID          domain.UUIDv7
	RecoveryGeneration uint64
	DeviceID           domain.DeviceID
}

// ContentBinding is the exact short-lived content certificate commitment.
type ContentBinding struct {
	SessionID               domain.UUIDv7
	DeviceID                domain.DeviceID
	Epoch                   uint64
	AuthorizationChainIndex uint64
}

// IdentityCertificate is a strictly parsed identity certificate.
type IdentityCertificate struct {
	Binding   IdentityBinding
	PublicKey ed25519.PublicKey
	Leaf      *x509.Certificate
}

// ContentCertificate is a strictly parsed content certificate.
type ContentCertificate struct {
	Binding   ContentBinding
	PublicKey ed25519.PublicKey
	KeyDigest [sha256.Size]byte
	NotBefore time.Time
	NotAfter  time.Time
	Leaf      *x509.Certificate
}

// VerifyLineage checks the pre-membership portion of an identity certificate.
func (certificate IdentityCertificate) VerifyLineage(
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
) error {
	if certificate.Leaf == nil || !sessionID.Valid() ||
		!domain.ValidUnsignedInteger(recoveryGeneration) ||
		certificate.Binding.SessionID != sessionID ||
		certificate.Binding.RecoveryGeneration != recoveryGeneration {
		return ErrCertificateBinding
	}
	return nil
}

// VerifyIdentity pins an identity certificate to one enrolled member key.
func (certificate IdentityCertificate) VerifyIdentity(
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	deviceID domain.DeviceID,
	identityPublicKey []byte,
) error {
	if err := certificate.VerifyLineage(sessionID, recoveryGeneration); err != nil {
		return err
	}
	if !deviceID.Valid() || len(identityPublicKey) != ed25519.PublicKeySize ||
		certificate.Binding.DeviceID != deviceID ||
		!bytes.Equal(certificate.PublicKey, identityPublicKey) {
		return ErrCertificateBinding
	}
	return nil
}

// VerifyAuthorization pins a content certificate to one committed epoch and
// applies the asymmetric local-time admission window.
func (certificate ContentCertificate) VerifyAuthorization(
	authorization credentialauthorization.Authorization,
	now time.Time,
) error {
	if certificate.Leaf == nil || now.IsZero() {
		return ErrCertificateBinding
	}
	if err := authorization.Validate(); err != nil {
		return ErrCertificateBinding
	}
	want := ContentBinding{
		SessionID: authorization.SessionID, DeviceID: authorization.DeviceID,
		Epoch:                   authorization.Epoch,
		AuthorizationChainIndex: authorization.AuthorizationChainIndex,
	}
	notBefore, _ := authorization.NotBefore.Time()
	notAfter := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	if certificate.Binding != want ||
		!bytes.Equal(certificate.PublicKey, authorization.EpochPublicKey[:]) ||
		certificate.KeyDigest != authorization.KeyDigest ||
		!certificate.NotBefore.Equal(notBefore) ||
		!certificate.NotAfter.Equal(notAfter) {
		return ErrCertificateBinding
	}
	now = now.UTC()
	if now.Add(ContentClockSkew).Before(notBefore) || !now.Before(notAfter) {
		return ErrCertificateNotCurrent
	}
	return nil
}

// CloseAfter returns the monotonic lifetime a content connection may retain
// after admission. Callers must arm a close timer with this duration; capping
// at one credential lifetime prevents a backward wall-clock step from extending
// access after the handshake.
func (certificate ContentCertificate) CloseAfter(now time.Time) (time.Duration, error) {
	if certificate.Leaf == nil || now.IsZero() ||
		certificate.NotAfter.Sub(certificate.NotBefore) !=
			time.Duration(credentialauthorization.ValiditySeconds)*time.Second {
		return 0, ErrCertificateBinding
	}
	now = now.UTC()
	if now.Add(ContentClockSkew).Before(certificate.NotBefore) ||
		!now.Before(certificate.NotAfter) {
		return 0, ErrCertificateNotCurrent
	}
	remaining := certificate.NotAfter.Sub(now)
	maximum := time.Duration(credentialauthorization.ValiditySeconds) * time.Second
	if remaining > maximum {
		remaining = maximum
	}
	return remaining, nil
}

type identityBindingDER struct {
	FormatVersion      int
	SessionID          []byte
	RecoveryGeneration *big.Int
	DeviceKeyDigest    []byte
}

type contentBindingDER struct {
	FormatVersion           int
	SessionID               []byte
	DeviceKeyDigest         []byte
	Epoch                   *big.Int
	AuthorizationChainIndex *big.Int
}

// IssueIdentityCertificate creates the fixed self-signed identity profile.
func IssueIdentityCertificate(
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	identityPrivateKey []byte,
) (tls.Certificate, IdentityBinding, error) {
	return issueIdentityCertificate(
		sessionID,
		recoveryGeneration,
		identityPrivateKey,
		cryptorand.Reader,
	)
}

func issueIdentityCertificate(
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	identityPrivateKey []byte,
	entropy io.Reader,
) (tls.Certificate, IdentityBinding, error) {
	if !sessionID.Valid() ||
		!domain.ValidUnsignedInteger(recoveryGeneration) ||
		entropy == nil {
		return tls.Certificate{}, IdentityBinding{}, ErrInvalidCertificateInput
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivateKey)
	if err != nil {
		return tls.Certificate{}, IdentityBinding{}, fmt.Errorf("%w: %v", ErrInvalidCertificateInput, err)
	}
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		return tls.Certificate{}, IdentityBinding{}, fmt.Errorf("%w: %v", ErrInvalidCertificateInput, err)
	}
	binding := IdentityBinding{
		SessionID: sessionID, RecoveryGeneration: recoveryGeneration, DeviceID: deviceID,
	}
	extensionValue, err := marshalIdentityBinding(binding)
	if err != nil {
		return tls.Certificate{}, IdentityBinding{}, err
	}
	serial, err := certificateSerial(entropy)
	if err != nil {
		return tls.Certificate{}, IdentityBinding{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    identityNotBefore,
		NotAfter:     identityNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		ExtraExtensions: []pkix.Extension{{
			Id: identityBindingOID(), Critical: true, Value: extensionValue,
		}},
	}
	return createIdentityTLSCertificate(template, publicKey, identityPrivateKey, entropy, binding)
}

// IssueContentCertificate creates the fixed self-signed epoch-key profile for
// one committed credential authorization.
func IssueContentCertificate(
	authorization credentialauthorization.Authorization,
	epochPrivateKey []byte,
) (tls.Certificate, ContentBinding, error) {
	return issueContentCertificate(authorization, epochPrivateKey, cryptorand.Reader)
}

func issueContentCertificate(
	authorization credentialauthorization.Authorization,
	epochPrivateKey []byte,
	entropy io.Reader,
) (tls.Certificate, ContentBinding, error) {
	if entropy == nil {
		return tls.Certificate{}, ContentBinding{}, ErrInvalidCertificateInput
	}
	if err := authorization.Validate(); err != nil {
		return tls.Certificate{}, ContentBinding{}, fmt.Errorf("%w: %v", ErrInvalidCertificateInput, err)
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(epochPrivateKey)
	if err != nil || !bytes.Equal(publicKey, authorization.EpochPublicKey[:]) {
		return tls.Certificate{}, ContentBinding{}, ErrInvalidCertificateInput
	}
	binding := ContentBinding{
		SessionID: authorization.SessionID, DeviceID: authorization.DeviceID,
		Epoch:                   authorization.Epoch,
		AuthorizationChainIndex: authorization.AuthorizationChainIndex,
	}
	extensionValue, err := marshalContentBinding(binding)
	if err != nil {
		return tls.Certificate{}, ContentBinding{}, err
	}
	serial, err := certificateSerial(entropy)
	if err != nil {
		return tls.Certificate{}, ContentBinding{}, err
	}
	notBefore, _ := authorization.NotBefore.Time()
	notAfter := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	principal := contentPrincipal(binding.SessionID, binding.DeviceID)
	uri, err := url.Parse(principal)
	if err != nil || uri.String() != principal {
		return tls.Certificate{}, ContentBinding{}, ErrInvalidCertificateInput
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: principal},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		URIs: []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{{
			Id: contentBindingOID(), Critical: true, Value: extensionValue,
		}},
	}
	return createContentTLSCertificate(template, publicKey, epochPrivateKey, entropy, binding)
}

// ParseIdentityCertificate rejects every profile or DER variation outside the
// fixed identity certificate contract.
func ParseIdentityCertificate(rawDER []byte) (IdentityCertificate, error) {
	leaf, publicKey, err := parseBaseCertificate(rawDER, identityBindingOID(), false)
	if err != nil {
		return IdentityCertificate{}, err
	}
	if !leaf.NotBefore.Equal(identityNotBefore) ||
		!leaf.NotAfter.Equal(identityNotAfter) ||
		!bytes.Equal(leaf.RawSubject, emptyNameDER()) ||
		!bytes.Equal(leaf.RawIssuer, emptyNameDER()) ||
		len(leaf.URIs) != 0 || len(leaf.DNSNames) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return IdentityCertificate{}, ErrCertificateProfile
	}
	extension, ok := exactExtension(leaf, identityBindingOID())
	if !ok {
		return IdentityCertificate{}, ErrCertificateProfile
	}
	binding, err := unmarshalIdentityBinding(extension.Value)
	if err != nil {
		return IdentityCertificate{}, err
	}
	derivedID, err := device.DeriveID(publicKey)
	if err != nil || derivedID != binding.DeviceID {
		return IdentityCertificate{}, ErrCertificateBinding
	}
	return IdentityCertificate{
		Binding: binding, PublicKey: bytes.Clone(publicKey), Leaf: leaf,
	}, nil
}

// ParseContentCertificate rejects every profile or DER variation outside the
// fixed content certificate contract.
func ParseContentCertificate(rawDER []byte) (ContentCertificate, error) {
	leaf, publicKey, err := parseBaseCertificate(rawDER, contentBindingOID(), true)
	if err != nil {
		return ContentCertificate{}, err
	}
	extension, ok := exactExtension(leaf, contentBindingOID())
	if !ok {
		return ContentCertificate{}, ErrCertificateProfile
	}
	binding, err := unmarshalContentBinding(extension.Value)
	if err != nil {
		return ContentCertificate{}, err
	}
	principal := contentPrincipal(binding.SessionID, binding.DeviceID)
	expectedName := pkix.Name{CommonName: principal}
	expectedSubject, err := asn1.Marshal(expectedName.ToRDNSequence())
	if err != nil || !bytes.Equal(leaf.RawSubject, expectedSubject) ||
		!bytes.Equal(leaf.RawIssuer, expectedSubject) ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != principal ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || leaf.NotBefore.Nanosecond() != 0 ||
		leaf.NotAfter.Nanosecond() != 0 ||
		leaf.NotAfter.Sub(leaf.NotBefore) !=
			time.Duration(credentialauthorization.ValiditySeconds)*time.Second {
		return ContentCertificate{}, ErrCertificateProfile
	}
	return ContentCertificate{
		Binding: binding, PublicKey: bytes.Clone(publicKey),
		KeyDigest: sha256.Sum256(publicKey),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Leaf: leaf,
	}, nil
}

func createIdentityTLSCertificate(
	template *x509.Certificate,
	publicKey ed25519.PublicKey,
	privateKey []byte,
	entropy io.Reader,
	want IdentityBinding,
) (tls.Certificate, IdentityBinding, error) {
	der, err := x509.CreateCertificate(
		entropy, template, template, publicKey, ed25519.PrivateKey(privateKey),
	)
	if err != nil {
		return tls.Certificate{}, IdentityBinding{}, fmt.Errorf("%w: create: %v", ErrInvalidCertificateInput, err)
	}
	parsed, err := ParseIdentityCertificate(der)
	if err != nil || parsed.Binding != want {
		return tls.Certificate{}, IdentityBinding{}, fmt.Errorf("%w: self-check: %v", ErrCertificateProfile, err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{bytes.Clone(der)},
		PrivateKey:  ed25519.PrivateKey(bytes.Clone(privateKey)),
		Leaf:        parsed.Leaf,
	}
	return certificate, want, nil
}

func createContentTLSCertificate(
	template *x509.Certificate,
	publicKey ed25519.PublicKey,
	privateKey []byte,
	entropy io.Reader,
	want ContentBinding,
) (tls.Certificate, ContentBinding, error) {
	der, err := x509.CreateCertificate(
		entropy, template, template, publicKey, ed25519.PrivateKey(privateKey),
	)
	if err != nil {
		return tls.Certificate{}, ContentBinding{}, fmt.Errorf("%w: create: %v", ErrInvalidCertificateInput, err)
	}
	parsed, err := ParseContentCertificate(der)
	if err != nil || parsed.Binding != want {
		return tls.Certificate{}, ContentBinding{}, fmt.Errorf("%w: self-check: %v", ErrCertificateProfile, err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{bytes.Clone(der)},
		PrivateKey:  ed25519.PrivateKey(bytes.Clone(privateKey)),
		Leaf:        parsed.Leaf,
	}
	return certificate, want, nil
}

func parseBaseCertificate(
	rawDER []byte,
	customOID asn1.ObjectIdentifier,
	wantSAN bool,
) (*x509.Certificate, ed25519.PublicKey, error) {
	if len(rawDER) == 0 {
		return nil, nil, ErrCertificateProfile
	}
	leaf, err := x509.ParseCertificate(rawDER)
	if err != nil || !bytes.Equal(leaf.Raw, rawDER) {
		return nil, nil, ErrCertificateProfile
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	expectedExtensionCount := 3
	if wantSAN {
		expectedExtensionCount++
	}
	if !ok || len(publicKey) != ed25519.PublicKeySize ||
		leaf.Version != 3 || leaf.PublicKeyAlgorithm != x509.Ed25519 ||
		leaf.SignatureAlgorithm != x509.PureEd25519 ||
		leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 ||
		leaf.SerialNumber.BitLen() > 127 ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!exactExtendedKeyUsage(leaf.ExtKeyUsage) ||
		len(leaf.UnknownExtKeyUsage) != 0 || leaf.IsCA ||
		leaf.BasicConstraintsValid ||
		len(leaf.Extensions) != expectedExtensionCount ||
		!exactProfileExtensions(leaf.Extensions, customOID, wantSAN) ||
		!exactUnhandledCriticalExtension(leaf.UnhandledCriticalExtensions, customOID) ||
		!bytes.Equal(leaf.RawSubject, leaf.RawIssuer) ||
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		return nil, nil, ErrCertificateProfile
	}
	return leaf, bytes.Clone(publicKey), nil
}

func exactUnhandledCriticalExtension(
	values []asn1.ObjectIdentifier,
	customOID asn1.ObjectIdentifier,
) bool {
	return len(values) == 1 && values[0].Equal(customOID)
}

func marshalIdentityBinding(binding IdentityBinding) ([]byte, error) {
	if !binding.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(binding.RecoveryGeneration) ||
		!binding.DeviceID.Valid() {
		return nil, ErrCertificateBinding
	}
	sessionBytes, err := uuidBytes(binding.SessionID)
	if err != nil {
		return nil, err
	}
	digest, err := deviceDigest(binding.DeviceID)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(identityBindingDER{
		FormatVersion:      certificateBindingFormatVersion,
		SessionID:          sessionBytes,
		RecoveryGeneration: new(big.Int).SetUint64(binding.RecoveryGeneration),
		DeviceKeyDigest:    digest[:],
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode identity DER: %v", ErrCertificateBinding, err)
	}
	return encoded, nil
}

func unmarshalIdentityBinding(encoded []byte) (IdentityBinding, error) {
	var wire identityBindingDER
	rest, err := asn1.Unmarshal(encoded, &wire)
	if err != nil || len(rest) != 0 ||
		wire.FormatVersion != certificateBindingFormatVersion ||
		len(wire.SessionID) != 16 || wire.RecoveryGeneration == nil ||
		wire.RecoveryGeneration.Sign() < 0 || !wire.RecoveryGeneration.IsUint64() ||
		len(wire.DeviceKeyDigest) != sha256.Size {
		return IdentityBinding{}, ErrCertificateBinding
	}
	generation := wire.RecoveryGeneration.Uint64()
	if !domain.ValidUnsignedInteger(generation) {
		return IdentityBinding{}, ErrCertificateBinding
	}
	sessionID, err := sessionIDFromBytes(wire.SessionID)
	if err != nil {
		return IdentityBinding{}, err
	}
	return IdentityBinding{
		SessionID: sessionID, RecoveryGeneration: generation,
		DeviceID: deviceIDFromDigest(wire.DeviceKeyDigest),
	}, nil
}

func marshalContentBinding(binding ContentBinding) ([]byte, error) {
	if !binding.SessionID.Valid() || !binding.DeviceID.Valid() ||
		binding.Epoch < 1 || !domain.ValidUnsignedInteger(binding.Epoch) ||
		binding.AuthorizationChainIndex < 1 ||
		!domain.ValidUnsignedInteger(binding.AuthorizationChainIndex) {
		return nil, ErrCertificateBinding
	}
	sessionBytes, err := uuidBytes(binding.SessionID)
	if err != nil {
		return nil, err
	}
	digest, err := deviceDigest(binding.DeviceID)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(contentBindingDER{
		FormatVersion: certificateBindingFormatVersion,
		SessionID:     sessionBytes, DeviceKeyDigest: digest[:],
		Epoch:                   new(big.Int).SetUint64(binding.Epoch),
		AuthorizationChainIndex: new(big.Int).SetUint64(binding.AuthorizationChainIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode content DER: %v", ErrCertificateBinding, err)
	}
	return encoded, nil
}

func unmarshalContentBinding(encoded []byte) (ContentBinding, error) {
	var wire contentBindingDER
	rest, err := asn1.Unmarshal(encoded, &wire)
	if err != nil || len(rest) != 0 ||
		wire.FormatVersion != certificateBindingFormatVersion ||
		len(wire.SessionID) != 16 || len(wire.DeviceKeyDigest) != sha256.Size ||
		wire.Epoch == nil || wire.Epoch.Sign() <= 0 || !wire.Epoch.IsUint64() ||
		wire.AuthorizationChainIndex == nil ||
		wire.AuthorizationChainIndex.Sign() <= 0 ||
		!wire.AuthorizationChainIndex.IsUint64() {
		return ContentBinding{}, ErrCertificateBinding
	}
	epoch := wire.Epoch.Uint64()
	chainIndex := wire.AuthorizationChainIndex.Uint64()
	if !domain.ValidUnsignedInteger(epoch) || !domain.ValidUnsignedInteger(chainIndex) {
		return ContentBinding{}, ErrCertificateBinding
	}
	sessionID, err := sessionIDFromBytes(wire.SessionID)
	if err != nil {
		return ContentBinding{}, err
	}
	return ContentBinding{
		SessionID: sessionID, DeviceID: deviceIDFromDigest(wire.DeviceKeyDigest),
		Epoch: epoch, AuthorizationChainIndex: chainIndex,
	}, nil
}

func certificateSerial(entropy io.Reader) (*big.Int, error) {
	if entropy == nil {
		return nil, ErrInvalidCertificateInput
	}
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	serial, err := cryptorand.Int(entropy, maximum)
	if err != nil {
		return nil, fmt.Errorf("%w: serial entropy: %v", ErrInvalidCertificateInput, err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func exactExtendedKeyUsage(values []x509.ExtKeyUsage) bool {
	return len(values) == 2 &&
		values[0] == x509.ExtKeyUsageClientAuth &&
		values[1] == x509.ExtKeyUsageServerAuth
}

func exactProfileExtensions(
	extensions []pkix.Extension,
	customOID asn1.ObjectIdentifier,
	wantSAN bool,
) bool {
	wanted := map[string]bool{
		"2.5.29.15":        false,
		"2.5.29.37":        false,
		customOID.String(): false,
	}
	if wantSAN {
		wanted["2.5.29.17"] = false
	}
	for _, extension := range extensions {
		name := extension.Id.String()
		seen, ok := wanted[name]
		if !ok || seen {
			return false
		}
		if name == customOID.String() && !extension.Critical ||
			name == "2.5.29.15" && !extension.Critical ||
			(name == "2.5.29.37" || name == "2.5.29.17") && extension.Critical {
			return false
		}
		wanted[name] = true
	}
	for _, seen := range wanted {
		if !seen {
			return false
		}
	}
	return true
}

func exactExtension(
	certificate *x509.Certificate,
	oid asn1.ObjectIdentifier,
) (pkix.Extension, bool) {
	var result pkix.Extension
	found := false
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			if found {
				return pkix.Extension{}, false
			}
			result = extension
			found = true
		}
	}
	return result, found && result.Critical
}

func uuidBytes(sessionID domain.UUIDv7) ([]byte, error) {
	parsed, err := uuid.Parse(string(sessionID))
	if err != nil {
		return nil, ErrCertificateBinding
	}
	return bytes.Clone(parsed[:]), nil
}

func sessionIDFromBytes(value []byte) (domain.UUIDv7, error) {
	parsed, err := uuid.FromBytes(value)
	if err != nil {
		return "", ErrCertificateBinding
	}
	sessionID := domain.UUIDv7(parsed.String())
	if !sessionID.Valid() {
		return "", ErrCertificateBinding
	}
	return sessionID, nil
}

func deviceDigest(deviceID domain.DeviceID) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !deviceID.Valid() {
		return result, ErrCertificateBinding
	}
	decoded, err := hex.DecodeString(string(deviceID)[3:])
	if err != nil || len(decoded) != sha256.Size {
		return result, ErrCertificateBinding
	}
	copy(result[:], decoded)
	return result, nil
}

func deviceIDFromDigest(digest []byte) domain.DeviceID {
	return domain.DeviceID("cc1" + hex.EncodeToString(digest))
}

func contentPrincipal(sessionID domain.UUIDv7, deviceID domain.DeviceID) string {
	return "codecomm:" + string(sessionID) + "/" + string(deviceID)
}

func emptyNameDER() []byte { return []byte{0x30, 0x00} }

func identityBindingOID() asn1.ObjectIdentifier {
	// Go X.509 caps OID arcs at 31 bits. Encode the UUID as eight uint16
	// children below the nil-UUID compatibility root instead of one 128-bit
	// 2.25 arc that crypto/tls cannot parse.
	return asn1.ObjectIdentifier{
		2, 25, 0, 0x6767, 0xfe03, 0xa5ff, 0x42df,
		0x81ef, 0x2425, 0x7c26, 0xf570,
	}
}

func contentBindingOID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{
		2, 25, 0, 0xc175, 0xcdf1, 0x313f, 0x4f06,
		0xa098, 0xa6b8, 0x39b3, 0x066e,
	}
}
