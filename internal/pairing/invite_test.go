package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	testInviteID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000101")
	testSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000102")
	testWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
)

func TestInviteSignParseRoundTrip(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	if !strings.HasPrefix(signed.Code(), InviteCodePrefix) || strings.Contains(signed.Code(), "=") {
		t.Fatalf("Code() = %q, want prefixed unpadded base64url", signed.Code())
	}
	if signed.Digest() != sha256.Sum256(signed.CanonicalBytes()) {
		t.Fatal("Digest() does not cover the complete signed canonical invite")
	}

	parsed, err := ParseInviteCode(signed.Code())
	if err != nil {
		t.Fatalf("ParseInviteCode() error = %v", err)
	}
	if !reflect.DeepEqual(parsed.Invite(), value) {
		t.Fatalf("parsed invite = %#v, want %#v", parsed.Invite(), value)
	}
	if !bytes.Equal(parsed.CanonicalBytes(), signed.CanonicalBytes()) || parsed.Digest() != signed.Digest() {
		t.Fatal("parsed invite did not retain exact signed bytes and digest")
	}

	decoded := parsed.Invite()
	decoded.Endpoints[0].Port++
	decoded.Secret[0] ^= 0xff
	canonical := parsed.CanonicalBytes()
	canonical[0] ^= 0xff
	if !reflect.DeepEqual(parsed.Invite(), value) || bytes.Equal(parsed.CanonicalBytes(), canonical) {
		t.Fatal("SignedInvite accessors expose mutable internal state")
	}
}

func TestSignedInviteClearZeroesOwnedSecretAndCanonicalBytes(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := signed.value.Secret[:]
	canonical := signed.canonical
	if len(canonical) == 0 {
		t.Fatal("fixture has no canonical invite")
	}
	signed.Clear()
	if signed.Code() != "" ||
		signed.Validate() == nil ||
		!allZero(secret) ||
		!allZero(canonical) {
		t.Fatal("Clear retained usable or nonzero invite material")
	}
	signed.Clear()
	(*SignedInvite)(nil).Clear()
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func TestInviteGoldenVector(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	const wantCanonical = `{"created_at":"2026-08-13T12:00:00Z","endpoints":[{"ip":"10.0.0.5","port":47831},{"ip":"fd00::5","port":47831}],"expected_entity_version":null,"expires_at":"2026-08-13T12:15:00Z","initial_credential_epoch":1,"invite_id":"01890f47-3e72-7000-8000-000000000101","inviter_device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","inviter_identity_public_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","mode":"new","protocol":1,"recovery_generation":0,"role":"editor","schema_version":1,"secret":"AAECAwQFBgcICQoLDA0ODw","session_id":"01890f47-3e72-7000-8000-000000000102","signature":"5XPviyN1Xm5-p6mgPSC3s9on_eOcA3DnIk__OOvLMhlGRvztWgZ2P8VdK8lEF9eyaAphHHTjPtwxtUQOEgVRAA","signed_genesis_digest":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8","subject_device_id":null,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(signed.CanonicalBytes()) != wantCanonical {
		t.Fatalf("golden invite = %s", signed.CanonicalBytes())
	}
}

func TestGenerateInviteSecret(t *testing.T) {
	t.Parallel()

	want := bytes.Repeat([]byte{0xa5}, InviteSecretSize)
	got, err := generateInviteSecret(bytes.NewReader(want))
	if err != nil {
		t.Fatalf("generateInviteSecret() error = %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("generateInviteSecret() = %x, want %x", got, want)
	}
	if _, err := generateInviteSecret(nil); !errors.Is(err, codecommcrypto.ErrEntropy) {
		t.Fatalf("generateInviteSecret(nil) error = %v, want %v", err, codecommcrypto.ErrEntropy)
	}
	if got, err := generateInviteSecret(bytes.NewReader([]byte{1})); !errors.Is(err, codecommcrypto.ErrEntropy) || got != [InviteSecretSize]byte{} {
		t.Fatalf("short entropy = (%x, %v), want zero and %v", got, err, codecommcrypto.ErrEntropy)
	}
}

func TestInviteModeContracts(t *testing.T) {
	t.Parallel()

	base, subjectID, privateKey := validInvite(t)
	version := uint64(7)
	tests := []struct {
		name   string
		mutate func(*Invite)
		want   error
	}{
		{name: "new"},
		{name: "new subject", mutate: func(value *Invite) { value.SubjectDeviceID = &subjectID }, want: ErrInviteMode},
		{name: "new epoch", mutate: func(value *Invite) { value.InitialCredentialEpoch = 2 }, want: ErrInviteMode},
		{name: "rebootstrap", mutate: func(value *Invite) {
			value.Mode = ModeRebootstrap
			value.SubjectDeviceID = &subjectID
			value.InitialCredentialEpoch = 8
		}},
		{name: "rebootstrap version", mutate: func(value *Invite) {
			value.Mode = ModeRebootstrap
			value.SubjectDeviceID = &subjectID
			value.ExpectedEntityVersion = &version
		}, want: ErrInviteMode},
		{name: "readmission", mutate: func(value *Invite) {
			value.Mode = ModeReadmission
			value.SubjectDeviceID = &subjectID
			value.ExpectedEntityVersion = &version
		}},
		{name: "readmission no version", mutate: func(value *Invite) { value.Mode = ModeReadmission; value.SubjectDeviceID = &subjectID }, want: ErrInviteMode},
		{name: "readmission later epoch", mutate: func(value *Invite) {
			value.Mode = ModeReadmission
			value.SubjectDeviceID = &subjectID
			value.ExpectedEntityVersion = &version
			value.InitialCredentialEpoch = 2
		}, want: ErrInviteMode},
		{name: "unknown", mutate: func(value *Invite) { value.Mode = "future" }, want: ErrInviteMode},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base.clone()
			if test.mutate != nil {
				test.mutate(&value)
			}
			_, err := SignInvite(value, privateKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("SignInvite() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestInviteEndpointContracts(t *testing.T) {
	t.Parallel()

	base, _, privateKey := validInvite(t)
	tests := []struct {
		name      string
		endpoints []Endpoint
		want      error
	}{
		{name: "empty", want: ErrInviteEndpoint},
		{name: "loopback", endpoints: []Endpoint{{IP: netip.MustParseAddr("127.0.0.1"), Port: 47831}}, want: ErrInviteEndpoint},
		{name: "unspecified", endpoints: []Endpoint{{IP: netip.IPv4Unspecified(), Port: 47831}}, want: ErrInviteEndpoint},
		{name: "multicast", endpoints: []Endpoint{{IP: netip.MustParseAddr("239.1.2.3"), Port: 47831}}, want: ErrInviteEndpoint},
		{name: "link local", endpoints: []Endpoint{{IP: netip.MustParseAddr("fe80::1"), Port: 47831}}, want: ErrInviteEndpoint},
		{name: "zone", endpoints: []Endpoint{{IP: netip.MustParseAddr("fe80::1%en0"), Port: 47831}}, want: ErrInviteEndpoint},
		{name: "zero port", endpoints: []Endpoint{{IP: netip.MustParseAddr("10.0.0.1")}}, want: ErrInviteEndpoint},
		{name: "mixed ports", endpoints: []Endpoint{{IP: netip.MustParseAddr("10.0.0.1"), Port: 1}, {IP: netip.MustParseAddr("10.0.0.2"), Port: 2}}, want: ErrInviteEndpoint},
		{name: "duplicate", endpoints: []Endpoint{{IP: netip.MustParseAddr("10.0.0.1"), Port: 47831}, {IP: netip.MustParseAddr("10.0.0.1"), Port: 47831}}, want: ErrInviteEndpointOrder},
		{name: "unsorted", endpoints: []Endpoint{{IP: netip.MustParseAddr("10.0.0.2"), Port: 47831}, {IP: netip.MustParseAddr("10.0.0.1"), Port: 47831}}, want: ErrInviteEndpointOrder},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base.clone()
			value.Endpoints = test.endpoints
			_, err := SignInvite(value, privateKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("SignInvite() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestInviteTimeAndIdentityContracts(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	created, _ := value.CreatedAt.Time()
	expires, _ := value.ExpiresAt.Time()
	for _, test := range []struct {
		name string
		now  time.Time
		want error
	}{
		{name: "creation", now: created},
		{name: "last instant", now: expires.Add(-time.Nanosecond)},
		{name: "before creation", now: created.Add(-time.Nanosecond), want: ErrInviteTime},
		{name: "expiry", now: expires, want: ErrInviteTime},
	} {
		if err := signed.ValidateTime(test.now); !errors.Is(err, test.want) {
			t.Errorf("ValidateTime(%s) error = %v, want %v", test.name, err, test.want)
		}
	}

	invalidLifetime := value
	invalidLifetime.ExpiresAt = "2026-08-13T12:14:59Z"
	if _, err := SignInvite(invalidLifetime, privateKey); !errors.Is(err, ErrInviteTime) {
		t.Fatalf("SignInvite(short lifetime) error = %v, want %v", err, ErrInviteTime)
	}
	otherPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	if _, err := SignInvite(value, otherPrivateKey); !errors.Is(err, ErrInviteIdentity) {
		t.Fatalf("SignInvite(wrong identity) error = %v, want %v", err, ErrInviteIdentity)
	}
}

func TestInviteClosedSchemaAndSignatureOrdering(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	wire := inviteToWire(value)
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	members["future_capability"] = json.RawMessage(`1`)
	code := signInviteMembers(t, members, privateKey)
	if _, err := ParseInviteCode(code); !errors.Is(err, ErrInviteUnknownField) {
		t.Fatalf("ParseInviteCode(unknown field) error = %v, want %v", err, ErrInviteUnknownField)
	}

	canonical, err := codec.DecodeBase64URL(strings.TrimPrefix(code, InviteCodePrefix))
	if err != nil {
		t.Fatalf("DecodeBase64URL() error = %v", err)
	}
	canonical[len(canonical)-2] ^= 1
	tampered := InviteCodePrefix + codec.EncodeBase64URL(canonical)
	if _, err := ParseInviteCode(tampered); err == nil || errors.Is(err, ErrInviteUnknownField) {
		t.Fatalf("tampered unknown-field invite error = %v, want signature failure first", err)
	}
}

func TestInviteRejectsMalformedCodes(t *testing.T) {
	t.Parallel()

	value, _, privateKey := validInvite(t)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	tests := []string{
		"",
		"ccinvite2_abc",
		InviteCodePrefix,
		signed.Code() + "=",
		InviteCodePrefix + strings.Repeat("a", MaxPairingMessageBytes),
	}
	for _, input := range tests {
		if _, err := ParseInviteCode(input); err == nil {
			t.Errorf("ParseInviteCode(%q) succeeded", input)
		}
	}
}

func FuzzParseInviteCode(f *testing.F) {
	value, _, privateKey := validInvite(f)
	signed, err := SignInvite(value, privateKey)
	if err != nil {
		f.Fatalf("SignInvite() error = %v", err)
	}
	f.Add(signed.Code())
	f.Add("")
	f.Add(InviteCodePrefix + "e30")
	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := ParseInviteCode(input)
		if err != nil {
			return
		}
		if parsed.Code() != input {
			t.Fatalf("successful parse did not round-trip: %q != %q", parsed.Code(), input)
		}
	})
}

func validInvite(t testing.TB) (Invite, domain.DeviceID, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	value := Invite{
		InviteID:               testInviteID,
		SessionID:              testSessionID,
		WorkspaceID:            testWorkspaceID,
		RecoveryGeneration:     0,
		CreatedAt:              "2026-08-13T12:00:00Z",
		ExpiresAt:              "2026-08-13T12:15:00Z",
		InviterDeviceID:        deviceID,
		Mode:                   ModeNew,
		Role:                   device.RoleEditor,
		InitialCredentialEpoch: 1,
		Endpoints: []Endpoint{
			{IP: netip.MustParseAddr("10.0.0.5"), Port: 47831},
			{IP: netip.MustParseAddr("fd00::5"), Port: 47831},
		},
	}
	for index := range value.Secret {
		value.Secret[index] = byte(index)
	}
	copy(value.InviterIdentityPublicKey[:], publicKey)
	for index := range value.SignedGenesisDigest {
		value.SignedGenesisDigest[index] = byte(0x80 + index)
	}
	return value, deviceID, privateKey
}

func signInviteMembers(
	t testing.TB,
	members map[string]json.RawMessage,
	privateKey ed25519.PrivateKey,
) string {
	t.Helper()
	delete(members, "signature")
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	unsigned, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject() error = %v", err)
	}
	signature, err := codecommcrypto.SignEd25519(privateKey, codec.SignatureInvite, unsigned)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	members["signature"], _ = json.Marshal(codec.EncodeBase64URL(signature))
	raw, err = json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject() error = %v", err)
	}
	return InviteCodePrefix + codec.EncodeBase64URL(canonical)
}
