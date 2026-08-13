package credential

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const bindingSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000201")

func TestBindingSignValidateAndGoldenPreimage(t *testing.T) {
	t.Parallel()

	identityPrivateKey := bindingPrivateKey(1)
	identityPublicKey := identityPrivateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(identityPublicKey)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	epochPublicKey := bindingPrivateKey(2).Public().(ed25519.PublicKey)
	binding, err := SignBinding(
		bindingSessionID,
		deviceID,
		7,
		epochPublicKey,
		identityPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignBinding() error = %v", err)
	}
	if err := binding.Validate(identityPublicKey); err != nil {
		t.Fatalf("Binding.Validate() error = %v", err)
	}
	if binding.KeyDigest != sha256.Sum256(epochPublicKey) {
		t.Fatal("binding key digest does not cover the epoch public key")
	}
	preimage, err := binding.CanonicalPreimage()
	if err != nil {
		t.Fatalf("CanonicalPreimage() error = %v", err)
	}
	const want = `{"device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","epoch":7,"epoch_public_key":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q","session_id":"01890f47-3e72-7000-8000-000000000201"}`
	if string(preimage) != want {
		t.Fatalf("CanonicalPreimage() = %s, want %s", preimage, want)
	}
	const wantSignature = "2e2872592f804ffb45caff909e09713de0957df0c10d355a9e4c56fafeaf65021476cd3906e435e97bb90e77979ac0bff487bafff70b8ab0617a303ba8a2ca09"
	if got := bytesToHex(binding.Signature[:]); got != wantSignature {
		t.Fatalf("signature = %s, want %s", got, wantSignature)
	}
}

func TestBindingRejectsMutations(t *testing.T) {
	t.Parallel()

	identityPrivateKey := bindingPrivateKey(1)
	identityPublicKey := identityPrivateKey.Public().(ed25519.PublicKey)
	deviceID, _ := device.DeriveID(identityPublicKey)
	binding, err := SignBinding(
		bindingSessionID,
		deviceID,
		1,
		bindingPrivateKey(2).Public().(ed25519.PublicKey),
		identityPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignBinding() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Binding)
		key    []byte
		want   error
	}{
		{name: "digest", mutate: func(value *Binding) { value.KeyDigest[0] ^= 1 }, key: identityPublicKey, want: ErrBindingKeyDigest},
		{name: "signature", mutate: func(value *Binding) { value.Signature[0] ^= 1 }, key: identityPublicKey, want: ErrBindingSignature},
		{name: "session", mutate: func(value *Binding) { value.SessionID = "01890f47-3e72-7000-8000-000000000202" }, key: identityPublicKey, want: ErrBindingSignature},
		{name: "epoch", mutate: func(value *Binding) { value.Epoch++ }, key: identityPublicKey, want: ErrBindingSignature},
		{name: "identity", key: bindingPrivateKey(3).Public().(ed25519.PublicKey), want: ErrBindingIdentity},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := binding
			if test.mutate != nil {
				test.mutate(&value)
			}
			if err := value.Validate(test.key); !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignBindingRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	identityPrivateKey := bindingPrivateKey(1)
	deviceID, _ := device.DeriveID(identityPrivateKey.Public().(ed25519.PublicKey))
	epochPublicKey := bindingPrivateKey(2).Public().(ed25519.PublicKey)
	for _, test := range []struct {
		name      string
		sessionID domain.UUIDv7
		deviceID  domain.DeviceID
		epoch     uint64
		key       []byte
		want      error
	}{
		{name: "session", deviceID: deviceID, epoch: 1, key: epochPublicKey, want: ErrInvalidBinding},
		{name: "device", sessionID: bindingSessionID, epoch: 1, key: epochPublicKey, want: ErrInvalidBinding},
		{name: "epoch", sessionID: bindingSessionID, deviceID: deviceID, key: epochPublicKey, want: ErrInvalidBinding},
		{name: "key", sessionID: bindingSessionID, deviceID: deviceID, epoch: 1, key: epochPublicKey[:31], want: ErrInvalidBinding},
	} {
		if _, err := SignBinding(test.sessionID, test.deviceID, test.epoch, test.key, identityPrivateKey); !errors.Is(err, test.want) {
			t.Errorf("SignBinding(%s) error = %v, want %v", test.name, err, test.want)
		}
	}
}

func bindingPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func bytesToHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, octet := range value {
		result[index*2] = alphabet[octet>>4]
		result[index*2+1] = alphabet[octet&0x0f]
	}
	return string(result)
}
