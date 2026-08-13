package discovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const testSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")

func TestAdvertisementSignParseVerify(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	keyDigest := sha256.Sum256(publicKey)
	value, err := newAdvertisement(
		testSessionID,
		47831,
		42,
		keyDigest,
		"2026-08-13T12:00:40Z",
		bytes.NewReader(bytes.Repeat([]byte{0xa5}, AdvertisementNonceSize)),
	)
	if err != nil {
		t.Fatalf("newAdvertisement() error = %v", err)
	}
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	if len(encoded) > MaxDatagramBytes {
		t.Fatalf("encoded length = %d, limit %d", len(encoded), MaxDatagramBytes)
	}

	unverified, err := ParseAdvertisement(encoded, testSessionID)
	if err != nil {
		t.Fatalf("ParseAdvertisement() error = %v", err)
	}
	if err := unverified.ValidateTime(
		time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("ValidateTime() error = %v", err)
	}
	verified, err := unverified.Verify(publicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Advertisement() != value {
		t.Fatalf("verified advertisement = %#v, want %#v", verified.Advertisement(), value)
	}
	if !bytes.Equal(verified.CanonicalBytes(), encoded) {
		t.Fatalf("CanonicalBytes() = %s, want %s", verified.CanonicalBytes(), encoded)
	}
}

func TestAdvertisementGoldenVector(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	value, err := newAdvertisement(
		testSessionID,
		47831,
		42,
		sha256.Sum256(publicKey),
		"2026-08-13T12:00:40Z",
		bytes.NewReader(bytes.Repeat([]byte{0xa5}, AdvertisementNonceSize)),
	)
	if err != nil {
		t.Fatalf("newAdvertisement() error = %v", err)
	}
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	const want = `{"advertisement_nonce":"paWlpaWlpaWlpaWlpaWlpQ","advertising_key_digest":"NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4","credential_epoch":42,"expires_at":"2026-08-13T12:00:40Z","https_port":47831,"magic":"codecomm","protocol":1,"session_id":"01890f47-3e72-7000-8000-000000000001","signature":"PFfx8tNQ3bmzs9_TP73Rvp5ilsxP40st2bsUVq4qyAlq-PuxsPxPibqeU94-3dJJ6VX8UARE1Z1Ye-CPWzxfDg"}`
	if string(encoded) != want {
		t.Fatalf("golden advertisement = %s\nwant = %s", encoded, want)
	}
}

func TestAdvertisementTimeWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		expires domain.Timestamp
		want    error
	}{
		{name: "one nanosecond future", expires: "2026-08-13T12:00:00.000000001Z"},
		{name: "exact future limit", expires: "2026-08-13T12:01:00Z"},
		{name: "equal now", expires: "2026-08-13T12:00:00Z", want: ErrAdvertisementExpired},
		{name: "past", expires: "2026-08-13T11:59:59Z", want: ErrAdvertisementExpired},
		{name: "past future limit", expires: "2026-08-13T12:01:00.000000001Z", want: ErrAdvertisementFuture},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := UnverifiedAdvertisement{
				advertisement: Advertisement{ExpiresAt: test.expires},
			}
			if err := value.ValidateTime(now); !errors.Is(err, test.want) {
				t.Fatalf("ValidateTime() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAdvertisementAccessorsCannotMutateVerifiedFields(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	original := validAdvertisement(t, publicKey)
	encoded, err := SignAdvertisement(original, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	unverified, err := ParseAdvertisement(encoded, testSessionID)
	if err != nil {
		t.Fatalf("ParseAdvertisement() error = %v", err)
	}
	decoded := unverified.Advertisement()
	decoded.HTTPSPort++
	decoded.CredentialEpoch++
	decoded.ExpiresAt = "2099-01-01T00:00:00Z"

	verified, err := unverified.Verify(publicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := verified.Advertisement(); got != original {
		t.Fatalf("verified advertisement = %#v, want %#v", got, original)
	}
}

func TestAdvertisementRejectsSiblingBeforeVerification(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	value := validAdvertisement(t, publicKey)
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	otherSession := domain.UUIDv7("01890f47-3e72-7000-8000-000000000002")
	if _, err := ParseAdvertisement(encoded, otherSession); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("ParseAdvertisement() error = %v, want %v", err, ErrSessionMismatch)
	}
}

func TestAdvertisementUnknownFieldVerifiedBeforeClosedSchemaRejection(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	value := validAdvertisement(t, publicKey)
	wire := advertisementToWire(value)
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	members["future_capability"] = json.RawMessage(`1`)
	delete(members, "signature")
	unsignedRaw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(unsigned) error = %v", err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(unsignedRaw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(unsigned) error = %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureDiscovery,
		unsigned,
	)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	members["signature"], _ = json.Marshal(codec.EncodeBase64URL(signature))
	completeRaw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(complete) error = %v", err)
	}
	complete, err := codec.CanonicalizeSignedObject(completeRaw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(complete) error = %v", err)
	}

	unverified, err := ParseAdvertisement(complete, testSessionID)
	if err != nil {
		t.Fatalf("ParseAdvertisement() rejected signed unknown field early: %v", err)
	}
	if _, err := unverified.Verify(publicKey); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrUnknownField)
	}

	complete[len(complete)-2] ^= 1
	if parsed, err := ParseAdvertisement(complete, testSessionID); err == nil {
		if _, err := parsed.Verify(publicKey); errors.Is(err, ErrUnknownField) {
			t.Fatal("tampered signature reached closed-schema rejection")
		}
	}
}

func TestAdvertisementRejectsWrongKeyAndDigest(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	otherPublicKey, _ := advertisementKey(t, 2)
	value := validAdvertisement(t, publicKey)
	encoded, err := SignAdvertisement(value, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	unverified, err := ParseAdvertisement(encoded, testSessionID)
	if err != nil {
		t.Fatalf("ParseAdvertisement() error = %v", err)
	}
	if _, err := unverified.Verify(otherPublicKey); !errors.Is(err, ErrAdvertisingKey) {
		t.Fatalf("Verify(wrong key) error = %v, want %v", err, ErrAdvertisingKey)
	}

	value.AdvertisingKeyDigest[0] ^= 1
	if _, err := SignAdvertisement(value, privateKey); !errors.Is(err, ErrAdvertisingKey) {
		t.Fatalf("SignAdvertisement(wrong digest) error = %v, want %v", err, ErrAdvertisingKey)
	}
}

func TestAdvertisementBoundsAndCanonicalForm(t *testing.T) {
	t.Parallel()

	publicKey, privateKey := advertisementKey(t, 1)
	encoded, err := SignAdvertisement(validAdvertisement(t, publicKey), privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement() error = %v", err)
	}
	if _, err := ParseAdvertisement(append(encoded, '\n'), testSessionID); !errors.Is(err, ErrNoncanonicalMessage) {
		t.Fatalf("ParseAdvertisement(noncanonical) error = %v, want %v", err, ErrNoncanonicalMessage)
	}
	if _, err := ParseAdvertisement(
		[]byte(strings.Repeat("x", MaxDatagramBytes+1)),
		testSessionID,
	); !errors.Is(err, ErrAdvertisementTooLarge) {
		t.Fatalf("ParseAdvertisement(oversized) error = %v, want %v", err, ErrAdvertisementTooLarge)
	}
}

func validAdvertisement(
	t *testing.T,
	publicKey ed25519.PublicKey,
) Advertisement {
	t.Helper()
	value, err := newAdvertisement(
		testSessionID,
		47831,
		1,
		sha256.Sum256(publicKey),
		"2026-08-13T12:00:40Z",
		bytes.NewReader(bytes.Repeat([]byte{1}, AdvertisementNonceSize)),
	)
	if err != nil {
		t.Fatalf("newAdvertisement() error = %v", err)
	}
	return value
}

func advertisementKey(
	t *testing.T,
	fill byte,
) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...), append(ed25519.PrivateKey(nil), privateKey...)
}
