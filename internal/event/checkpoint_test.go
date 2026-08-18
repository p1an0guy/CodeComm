package event

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

func TestCheckpointCodecRoundTripsExactCanonicalObject(t *testing.T) {
	t.Parallel()

	checkpoint := checkpointCodecFixture()
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatalf("EncodeCheckpoint(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatalf("checkpoint is not canonical: %v", err)
	}
	decoded, err := DecodeCheckpoint(encoded)
	if err != nil {
		t.Fatalf("DecodeCheckpoint(): %v", err)
	}
	if decoded != checkpoint {
		t.Fatalf("decoded checkpoint = %#v", decoded)
	}
	encoded[0] ^= 0xff
	if decoded != checkpoint {
		t.Fatal("decoded checkpoint aliases input bytes")
	}
}

func TestCheckpointCodecRejectsShapeAndEncodingChanges(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeCheckpoint(checkpointCodecFixture())
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &baseline); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(map[string]json.RawMessage){
		"missing zero-valued field": func(value map[string]json.RawMessage) {
			delete(value, "recovery_generation")
		},
		"unknown field": func(value map[string]json.RawMessage) {
			value["unknown"] = json.RawMessage(`true`)
		},
		"null field": func(value map[string]json.RawMessage) {
			value["covered_chain_index"] = json.RawMessage(`null`)
		},
		"padded digest": func(value map[string]json.RawMessage) {
			value["covered_chain_hash"] = json.RawMessage(
				`"` + codec.EncodeBase64URL(make([]byte, 32)) + `="`,
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := make(map[string]json.RawMessage, len(baseline))
			for field, raw := range baseline {
				value[field] = bytes.Clone(raw)
			}
			mutate(value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			mutated, err = codec.CanonicalizeSignedObject(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeCheckpoint(mutated); !errors.Is(
				err,
				ErrInvalidCheckpoint,
			) {
				t.Fatalf("DecodeCheckpoint() error = %v", err)
			}
		})
	}
	if _, err := DecodeCheckpoint(
		append(bytes.Clone(encoded), ' '),
	); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("noncanonical checkpoint error = %v", err)
	}
}

func TestEncodeCheckpointPayloadAddsSignatureOutsidePreimage(t *testing.T) {
	t.Parallel()

	checkpoint := checkpointCodecFixture()
	signature := [ed25519.SignatureSize]byte{0x91}
	unsigned, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeCheckpointPayload(checkpoint, signature)
	if err != nil {
		t.Fatalf("EncodeCheckpointPayload(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(payload)
	if err != nil || !bytes.Equal(canonical, payload) {
		t.Fatalf("payload is not canonical: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	encodedSignature, exists := object["authority_signature"]
	if !exists {
		t.Fatal("payload has no authority_signature")
	}
	delete(object, "authority_signature")
	withoutSignature, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	withoutSignature, err = codec.CanonicalizeSignedObject(
		withoutSignature,
	)
	if err != nil || !bytes.Equal(withoutSignature, unsigned) {
		t.Fatalf("payload changed unsigned checkpoint: %v", err)
	}
	var signatureText string
	if err := json.Unmarshal(encodedSignature, &signatureText); err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil || !bytes.Equal(decoded, signature[:]) {
		t.Fatalf("payload signature = %x, %v", decoded, err)
	}
}

func TestDecodeCheckpointPayloadRequiresExactCanonicalRoundTrip(
	t *testing.T,
) {
	t.Parallel()

	checkpoint := checkpointCodecFixture()
	signature := [ed25519.SignatureSize]byte{0x91, 0x72}
	payload, err := EncodeCheckpointPayload(checkpoint, signature)
	if err != nil {
		t.Fatal(err)
	}
	decodedCheckpoint, decodedSignature, err :=
		DecodeCheckpointPayload(payload)
	if err != nil {
		t.Fatalf("DecodeCheckpointPayload(): %v", err)
	}
	if decodedCheckpoint != checkpoint ||
		decodedSignature != signature {
		t.Fatalf(
			"decoded payload = (%#v, %x)",
			decodedCheckpoint,
			decodedSignature,
		)
	}
	for _, malformed := range [][]byte{
		append(bytes.Clone(payload), ' '),
		checkpointPayloadMutation(t, payload, func(
			object map[string]json.RawMessage,
		) {
			object["unexpected"] = json.RawMessage("true")
		}),
		checkpointPayloadMutation(t, payload, func(
			object map[string]json.RawMessage,
		) {
			var text string
			if err := json.Unmarshal(
				object["authority_signature"],
				&text,
			); err != nil {
				t.Fatal(err)
			}
			object["authority_signature"], err = json.Marshal(
				text + "=",
			)
			if err != nil {
				t.Fatal(err)
			}
		}),
	} {
		if _, _, err := DecodeCheckpointPayload(
			malformed,
		); !errors.Is(err, ErrInvalidCheckpoint) {
			t.Fatalf("malformed payload error = %v", err)
		}
	}
}

func checkpointPayloadMutation(
	t *testing.T,
	payload []byte,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestSignCheckpointBindsNamedDeviceAndLabel(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x72}, ed25519.SeedSize),
	)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := codec.DeriveDeviceID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := checkpointCodecFixture()
	checkpoint.SignerDeviceID = domain.DeviceID(deviceID)
	signature, err := SignCheckpoint(checkpoint, privateKey)
	if err != nil {
		t.Fatalf("SignCheckpoint(): %v", err)
	}
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	input, err := codec.BuildSignedInput(
		codec.SignatureCheckpoint,
		encoded,
	)
	if err != nil ||
		!ed25519.Verify(publicKey, input, signature[:]) {
		t.Fatalf("checkpoint signature did not verify: %v", err)
	}
	checkpoint.SignerDeviceID = checkpointProofDeviceIDForEventTest()
	if _, err := SignCheckpoint(
		checkpoint,
		privateKey,
	); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("mismatched signer error = %v", err)
	}
}

func checkpointCodecFixture() domain.Checkpoint {
	return domain.Checkpoint{
		SessionID: domain.UUIDv7(
			"018f47de-89ab-7def-8123-0123456789ab",
		),
		WorkspaceID: domain.UUIDv4(
			"550e8400-e29b-41d4-a716-446655440000",
		),
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID: domain.DeviceID(
			"cc1" + strings.Repeat("1", 64),
		),
		Term:                    2,
		CoveredAppliedLogIndex:  3,
		CoveredChainIndex:       0,
		CoveredChainHash:        [32]byte{0x41},
		CoveredResultIndex:      1,
		CoveredResultHash:       [32]byte{0x51},
		ProjectionAccumulator:   [32]byte{0x61},
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
}

func checkpointProofDeviceIDForEventTest() domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat("9", 64))
}
