package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const certificateTestSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000401")

func TestIdentityCertificateClosedProfile(t *testing.T) {
	t.Parallel()

	privateKey := certificatePrivateKey(1)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	wantDeviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	certificate, binding, err := issueIdentityCertificate(
		certificateTestSessionID,
		7,
		privateKey,
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	)
	if err != nil {
		t.Fatalf("issueIdentityCertificate() error = %v", err)
	}
	wantBinding := IdentityBinding{
		SessionID: certificateTestSessionID, RecoveryGeneration: 7, DeviceID: wantDeviceID,
	}
	if binding != wantBinding || len(certificate.Certificate) != 1 || certificate.Leaf == nil {
		t.Fatalf("issued identity certificate = (%+v, chains=%d, leaf=%v)", binding, len(certificate.Certificate), certificate.Leaf != nil)
	}
	parsed, err := ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseIdentityCertificate() error = %v", err)
	}
	if parsed.Binding != wantBinding || !bytes.Equal(parsed.PublicKey, publicKey) {
		t.Fatalf("parsed identity certificate = %+v", parsed)
	}
	if parsed.Leaf.SerialNumber.Sign() <= 0 || parsed.Leaf.SerialNumber.BitLen() > 127 {
		t.Fatalf("serial = %v", parsed.Leaf.SerialNumber)
	}
	if _, err := ParseContentCertificate(certificate.Certificate[0]); !errors.Is(err, ErrCertificateProfile) {
		t.Fatalf("ParseContentCertificate(identity) error = %v, want %v", err, ErrCertificateProfile)
	}

	extension, ok := exactExtension(parsed.Leaf, identityBindingOID())
	if !ok {
		t.Fatal("identity extension missing")
	}
	const wantExtension = "303a020101041001890f473e7270008000000000000401020107042034750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e"
	if got := hex.EncodeToString(extension.Value); got != wantExtension {
		t.Fatalf("identity binding DER = %s, want %s", got, wantExtension)
	}

	tampered := bytes.Clone(certificate.Certificate[0])
	tampered[len(tampered)-1] ^= 1
	if _, err := ParseIdentityCertificate(tampered); !errors.Is(err, ErrCertificateProfile) {
		t.Fatalf("tampered signature error = %v, want %v", err, ErrCertificateProfile)
	}
}

func TestContentCertificateClosedProfile(t *testing.T) {
	t.Parallel()

	authorization, epochPrivateKey := certificateAuthorization(t)
	certificate, binding, err := issueContentCertificate(
		authorization,
		epochPrivateKey,
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)),
	)
	if err != nil {
		t.Fatalf("issueContentCertificate() error = %v", err)
	}
	wantBinding := ContentBinding{
		SessionID: authorization.SessionID, DeviceID: authorization.DeviceID,
		Epoch:                   authorization.Epoch,
		AuthorizationChainIndex: authorization.AuthorizationChainIndex,
	}
	if binding != wantBinding || len(certificate.Certificate) != 1 || certificate.Leaf == nil {
		t.Fatalf("issued content certificate = (%+v, chains=%d, leaf=%v)", binding, len(certificate.Certificate), certificate.Leaf != nil)
	}
	parsed, err := ParseContentCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseContentCertificate() error = %v", err)
	}
	publicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	if parsed.Binding != wantBinding || !bytes.Equal(parsed.PublicKey, publicKey) ||
		parsed.KeyDigest != authorization.KeyDigest {
		t.Fatalf("parsed content certificate = %+v", parsed)
	}
	notBefore, _ := authorization.NotBefore.Time()
	if !parsed.NotBefore.Equal(notBefore) ||
		!parsed.NotAfter.Equal(notBefore.Add(30*time.Minute)) {
		t.Fatalf("content validity = %s..%s", parsed.NotBefore, parsed.NotAfter)
	}
	if err := parsed.VerifyAuthorization(authorization, notBefore); err != nil {
		t.Fatalf("VerifyAuthorization() error = %v", err)
	}
	if err := parsed.VerifyAuthorization(
		authorization,
		notBefore.Add(-ContentClockSkew),
	); err != nil {
		t.Fatalf("VerifyAuthorization(skew boundary) error = %v", err)
	}
	if err := parsed.VerifyAuthorization(
		authorization,
		notBefore.Add(-ContentClockSkew-time.Second),
	); !errors.Is(err, ErrCertificateNotCurrent) {
		t.Fatalf("VerifyAuthorization(before skew) error = %v, want %v", err, ErrCertificateNotCurrent)
	}
	if err := parsed.VerifyAuthorization(authorization, parsed.NotAfter); !errors.Is(err, ErrCertificateNotCurrent) {
		t.Fatalf("VerifyAuthorization(at expiry) error = %v, want %v", err, ErrCertificateNotCurrent)
	}
	if closeAfter, err := parsed.CloseAfter(notBefore.Add(-ContentClockSkew)); err != nil || closeAfter != 30*time.Minute {
		t.Fatalf("CloseAfter(skew boundary) = (%s, %v), want (30m, nil)", closeAfter, err)
	}
	if closeAfter, err := parsed.CloseAfter(parsed.NotAfter.Add(-time.Second)); err != nil || closeAfter != time.Second {
		t.Fatalf("CloseAfter(near expiry) = (%s, %v), want (1s, nil)", closeAfter, err)
	}
	if _, err := parsed.CloseAfter(parsed.NotAfter); !errors.Is(err, ErrCertificateNotCurrent) {
		t.Fatalf("CloseAfter(at expiry) error = %v, want %v", err, ErrCertificateNotCurrent)
	}
	if _, err := ParseIdentityCertificate(certificate.Certificate[0]); !errors.Is(err, ErrCertificateProfile) {
		t.Fatalf("ParseIdentityCertificate(content) error = %v, want %v", err, ErrCertificateProfile)
	}
	extension, ok := exactExtension(parsed.Leaf, contentBindingOID())
	if !ok {
		t.Fatal("content extension missing")
	}
	const wantExtension = "303d020101041001890f473e72700080000000000004010420fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff55226388902010202012a"
	if got := hex.EncodeToString(extension.Value); got != wantExtension {
		t.Fatalf("content binding DER = %s, want %s", got, wantExtension)
	}

	wrongKey := certificatePrivateKey(9)
	if _, _, err := IssueContentCertificate(authorization, wrongKey); !errors.Is(err, ErrInvalidCertificateInput) {
		t.Fatalf("IssueContentCertificate(wrong key) error = %v, want %v", err, ErrInvalidCertificateInput)
	}
}

func TestIdentityCertificateVerificationPinsLineageAndKey(t *testing.T) {
	t.Parallel()

	privateKey := certificatePrivateKey(3)
	certificate, binding, err := issueIdentityCertificate(
		certificateTestSessionID, 4, privateKey,
		bytes.NewReader(bytes.Repeat([]byte{0x52}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyIdentity(
		binding.SessionID, binding.RecoveryGeneration, binding.DeviceID,
		privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("VerifyIdentity() error = %v", err)
	}
	for _, test := range []struct {
		name       string
		sessionID  domain.UUIDv7
		generation uint64
		deviceID   domain.DeviceID
		publicKey  []byte
	}{
		{name: "session", sessionID: "01890f47-3e72-7000-8000-000000000402", generation: 4, deviceID: binding.DeviceID, publicKey: parsed.PublicKey},
		{name: "generation", sessionID: binding.SessionID, generation: 5, deviceID: binding.DeviceID, publicKey: parsed.PublicKey},
		{name: "device", sessionID: binding.SessionID, generation: 4, publicKey: parsed.PublicKey},
		{name: "key", sessionID: binding.SessionID, generation: 4, deviceID: binding.DeviceID, publicKey: certificatePrivateKey(4).Public().(ed25519.PublicKey)},
	} {
		if err := parsed.VerifyIdentity(
			test.sessionID, test.generation, test.deviceID, test.publicKey,
		); !errors.Is(err, ErrCertificateBinding) {
			t.Errorf("VerifyIdentity(%s) error = %v, want %v", test.name, err, ErrCertificateBinding)
		}
	}
}

func TestCertificateProfilesRejectMutations(t *testing.T) {
	t.Parallel()

	identityKey := certificatePrivateKey(1)
	identityCertificate, _, err := issueIdentityCertificate(
		certificateTestSessionID, 0, identityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x31}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	identityExtension, ok := exactExtension(identityCertificate.Leaf, identityBindingOID())
	if !ok {
		t.Fatal("identity extension missing")
	}

	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "key usage", mutate: func(value *x509.Certificate) { value.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{name: "validity", mutate: func(value *x509.Certificate) { value.NotAfter = value.NotAfter.Add(-time.Second) }},
		{name: "subject", mutate: func(value *x509.Certificate) { value.Subject = pkix.Name{CommonName: "unexpected"} }},
		{name: "noncritical binding", mutate: func(value *x509.Certificate) { value.ExtraExtensions[0].Critical = false }},
		{name: "unknown extension", mutate: func(value *x509.Certificate) {
			value.ExtraExtensions = append(value.ExtraExtensions, pkix.Extension{
				Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00},
			})
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			template := identityCertificateTemplate(identityCertificate.Leaf, identityExtension)
			test.mutate(template)
			der := createTestCertificate(t, template, identityKey)
			if _, err := ParseIdentityCertificate(der); !errors.Is(err, ErrCertificateProfile) {
				t.Fatalf("ParseIdentityCertificate() error = %v, want %v", err, ErrCertificateProfile)
			}
		})
	}
}

func TestCertificateBindingDERIsClosed(t *testing.T) {
	t.Parallel()

	identityKey := certificatePrivateKey(2)
	deviceID, _ := device.DeriveID(identityKey.Public().(ed25519.PublicKey))
	identity := IdentityBinding{
		SessionID: certificateTestSessionID, RecoveryGeneration: domain.MaxSafeInteger,
		DeviceID: deviceID,
	}
	encodedIdentity, err := marshalIdentityBinding(identity)
	if err != nil {
		t.Fatalf("marshalIdentityBinding() error = %v", err)
	}
	decodedIdentity, err := unmarshalIdentityBinding(encodedIdentity)
	if err != nil || decodedIdentity != identity {
		t.Fatalf("unmarshalIdentityBinding() = (%+v, %v)", decodedIdentity, err)
	}
	if _, err := unmarshalIdentityBinding(append(bytes.Clone(encodedIdentity), 0)); !errors.Is(err, ErrCertificateBinding) {
		t.Fatalf("identity trailing DER error = %v, want %v", err, ErrCertificateBinding)
	}

	content := ContentBinding{
		SessionID: certificateTestSessionID, DeviceID: deviceID, Epoch: 1,
		AuthorizationChainIndex: domain.MaxSafeInteger,
	}
	encodedContent, err := marshalContentBinding(content)
	if err != nil {
		t.Fatalf("marshalContentBinding() error = %v", err)
	}
	decodedContent, err := unmarshalContentBinding(encodedContent)
	if err != nil || decodedContent != content {
		t.Fatalf("unmarshalContentBinding() = (%+v, %v)", decodedContent, err)
	}
	if _, err := unmarshalContentBinding(append(bytes.Clone(encodedContent), 0)); !errors.Is(err, ErrCertificateBinding) {
		t.Fatalf("content trailing DER error = %v, want %v", err, ErrCertificateBinding)
	}
}

func TestCertificateOIDEncodingIsStableAndPortable(t *testing.T) {
	t.Parallel()

	const identity = "2.25.0.26471.65027.42495.17119.33263.9253.31782.62832"
	const content = "2.25.0.49525.52721.12607.20230.41112.42680.14771.1646"
	if got := identityBindingOID().String(); got != identity {
		t.Fatalf("identity OID = %q, want %q", got, identity)
	}
	if got := contentBindingOID().String(); got != content {
		t.Fatalf("content OID = %q, want %q", got, content)
	}
	for _, oid := range []asn1.ObjectIdentifier{identityBindingOID(), contentBindingOID()} {
		encoded, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatalf("asn1.Marshal(%s) error = %v", oid, err)
		}
		var decoded asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(encoded, &decoded); err != nil || len(rest) != 0 || !decoded.Equal(oid) {
			t.Fatalf("OID round trip = (%s, %x, %v)", decoded, rest, err)
		}
	}
}

func certificateAuthorization(
	t testing.TB,
) (credentialauthorization.Authorization, ed25519.PrivateKey) {
	t.Helper()
	identityKey := certificatePrivateKey(7)
	epochPrivateKey := certificatePrivateKey(8)
	return certificateAuthorizationForKeys(t, identityKey, epochPrivateKey, 2, 42), epochPrivateKey
}

func certificateAuthorizationForKeys(
	t testing.TB,
	identityKey ed25519.PrivateKey,
	epochPrivateKey ed25519.PrivateKey,
	epoch uint64,
	chainIndex uint64,
) credentialauthorization.Authorization {
	t.Helper()
	deviceID, err := device.DeriveID(identityKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	epochPublicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID: certificateTestSessionID, DeviceID: deviceID, Epoch: epoch,
		Role:     credentialauthorization.RoleOwner,
		IssuedAt: "2026-08-13T12:00:00Z", NotBefore: "2026-08-13T12:00:00Z",
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements:        []credentialauthorization.ClockEndorsement{{DeviceID: deviceID}},
		AuthorizationChainIndex:  chainIndex,
	}
	copy(authorization.EpochPublicKey[:], epochPublicKey)
	authorization.KeyDigest = sha256.Sum256(epochPublicKey)
	if err := authorization.Validate(); err != nil {
		t.Fatalf("Authorization.Validate() error = %v", err)
	}
	return authorization
}

func identityCertificateTemplate(
	leaf *x509.Certificate,
	extension pkix.Extension,
) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      leaf.Subject, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		KeyUsage: leaf.KeyUsage, ExtKeyUsage: append([]x509.ExtKeyUsage(nil), leaf.ExtKeyUsage...),
		ExtraExtensions: []pkix.Extension{{
			Id:       append(asn1.ObjectIdentifier(nil), extension.Id...),
			Critical: extension.Critical, Value: bytes.Clone(extension.Value),
		}},
	}
}

func createTestCertificate(
	t testing.TB,
	template *x509.Certificate,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(
		bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)),
		template, template, privateKey.Public(), privateKey,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return der
}

func certificatePrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}
