package reducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestCheckpointProofGoldenVector(t *testing.T) {
	t.Parallel()

	const (
		wantUnsigned  = `{"authority_voter_set_version":1,"covered_applied_log_index":9,"covered_chain_hash":"MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE","covered_chain_index":5,"covered_result_hash":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI","covered_result_index":6,"digest_version":1,"projection_accumulator":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM","projection_schema_version":1,"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000001","signer_device_id":"cc134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e","term":3,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
		wantSignature = "iLI75zCN827KCfCpIR6WiA3PIuW2sOjpabd0qiNJkFIk9SfmFYQMmeV9v8VVy0TMjYCNMeKc4nCXqk2_DV18Bw"
	)
	fixture := newReducerFixture(t)
	payload, unsigned := signedCheckpointProofPayload(
		t,
		fixture,
		fixture.ownerDevice,
		nil,
	)
	directive, ok := decodeCheckpointProof(fixture.state, payload)
	if !ok {
		t.Fatal("decodeCheckpointProof() rejected golden proof")
	}

	if got := string(unsigned); got != wantUnsigned {
		t.Fatalf("unsigned checkpoint = %q, want %q", got, wantUnsigned)
	}
	if got := codec.EncodeBase64URL(directive.AuthoritySignature[:]); got != wantSignature {
		t.Fatalf("authority signature = %q, want %q", got, wantSignature)
	}
	if !bytes.Equal(directive.CanonicalUnsignedJSON, unsigned) {
		t.Fatalf(
			"retained unsigned checkpoint = %q, want %q",
			directive.CanonicalUnsignedJSON,
			unsigned,
		)
	}
	if directive.Checkpoint.SessionID != fixture.state.sessionID ||
		directive.Checkpoint.WorkspaceID != fixture.state.workspaceID ||
		directive.Checkpoint.RecoveryGeneration !=
			fixture.state.recoveryGeneration ||
		directive.Checkpoint.AuthorityVoterSetVersion !=
			fixture.state.credentialAuthority.VoterSetVersion ||
		directive.Checkpoint.SignerDeviceID != fixture.ownerDevice ||
		directive.Checkpoint.DigestVersion != 1 ||
		directive.Checkpoint.ProjectionSchemaVersion != 1 {
		t.Fatalf("retained checkpoint = %#v", directive.Checkpoint)
	}

	for index := range payload {
		payload[index] = 0
	}
	if !bytes.Equal(directive.CanonicalUnsignedJSON, unsigned) {
		t.Fatal("retained unsigned checkpoint aliases payload storage")
	}
}

func TestCheckpointProofRejectsInvalidShapeAndAuthority(t *testing.T) {
	t.Parallel()

	otherSessionID := "01890f47-3e72-7000-8000-000000000099"
	otherWorkspaceID := "650e8400-e29b-41d4-a716-446655440000"
	shortDigest := codec.EncodeBase64URL(bytes.Repeat([]byte{0x41}, 31))
	longDigest := codec.EncodeBase64URL(bytes.Repeat([]byte{0x41}, 33))

	tests := []struct {
		name    string
		prepare func(*reducerFixture)
		signer  func(reducerFixture) domain.DeviceID
		mutate  func(map[string]any)
		payload func(*testing.T, reducerFixture, json.RawMessage) json.RawMessage
	}{
		{
			name: "session binding",
			mutate: func(object map[string]any) {
				object["session_id"] = otherSessionID
			},
		},
		{
			name: "workspace binding",
			mutate: func(object map[string]any) {
				object["workspace_id"] = otherWorkspaceID
			},
		},
		{
			name: "recovery generation binding",
			mutate: func(object map[string]any) {
				object["recovery_generation"] = float64(1)
			},
		},
		{
			name: "digest version immutable",
			mutate: func(object map[string]any) {
				object["digest_version"] = float64(2)
			},
		},
		{
			name: "projection schema immutable",
			mutate: func(object map[string]any) {
				object["projection_schema_version"] = float64(2)
			},
		},
		{
			name: "authority version exact",
			mutate: func(object map[string]any) {
				object["authority_voter_set_version"] = float64(2)
			},
		},
		{
			name: "signer outside exact authority",
			signer: func(fixture reducerFixture) domain.DeviceID {
				return fixture.editorDevice
			},
		},
		{
			name: "inactive authority signer",
			prepare: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.ownerDevice]
				member.Status = device.StatusRequiresReadmission
				fixture.state.devices[fixture.ownerDevice] = member
			},
		},
		{
			name: "short chain hash",
			mutate: func(object map[string]any) {
				object["covered_chain_hash"] = shortDigest
			},
		},
		{
			name: "long result hash",
			mutate: func(object map[string]any) {
				object["covered_result_hash"] = longDigest
			},
		},
		{
			name: "short projection accumulator",
			mutate: func(object map[string]any) {
				object["projection_accumulator"] = shortDigest
			},
		},
		{
			name: "padded hash",
			mutate: func(object map[string]any) {
				object["covered_chain_hash"] =
					codec.EncodeBase64URL(bytes.Repeat([]byte{0x41}, 32)) + "="
			},
		},
		{
			name: "covered chain exceeds result",
			mutate: func(object map[string]any) {
				object["covered_chain_index"] = float64(7)
				object["covered_result_index"] = float64(6)
			},
		},
		{
			name: "missing field",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					delete(object, "term")
				})
			},
		},
		{
			name: "unknown field",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					object["extra"] = true
				})
			},
		},
		{
			name: "null field",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					object["authority_signature"] = nil
				})
			},
		},
		{
			name: "short signature",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					object["authority_signature"] = codec.EncodeBase64URL(
						bytes.Repeat([]byte{0x51}, ed25519.SignatureSize-1),
					)
				})
			},
		},
		{
			name: "padded signature",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					signature := object["authority_signature"].(string)
					object["authority_signature"] = signature + "="
				})
			},
		},
		{
			name: "invalid signature",
			payload: func(
				t *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return mutateCheckpointProofPayload(t, payload, func(object map[string]any) {
					object["authority_signature"] = codec.EncodeBase64URL(
						make([]byte, ed25519.SignatureSize),
					)
				})
			},
		},
		{
			name: "noncanonical payload",
			payload: func(
				_ *testing.T,
				_ reducerFixture,
				payload json.RawMessage,
			) json.RawMessage {
				return append(append(json.RawMessage(nil), payload...), '\n')
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			if test.prepare != nil {
				test.prepare(&fixture)
			}
			signerID := fixture.ownerDevice
			if test.signer != nil {
				signerID = test.signer(fixture)
			}
			payload, _ := signedCheckpointProofPayload(
				t,
				fixture,
				signerID,
				test.mutate,
			)
			if test.payload != nil {
				payload = test.payload(t, fixture, payload)
			}
			if directive, ok := decodeCheckpointProof(fixture.state, payload); ok {
				t.Fatalf("decodeCheckpointProof() accepted %#v", directive)
			}
		})
	}
}

func signedCheckpointProofPayload(
	t *testing.T,
	fixture reducerFixture,
	signerID domain.DeviceID,
	mutate func(map[string]any),
) (json.RawMessage, json.RawMessage) {
	t.Helper()

	encoded, err := json.Marshal(activationCheckpoint(t, fixture))
	if err != nil {
		t.Fatalf("json.Marshal() checkpoint error = %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("json.Unmarshal() checkpoint error = %v", err)
	}
	object["signer_device_id"] = string(signerID)
	if mutate != nil {
		mutate(object)
	}
	unsigned := mustCanonicalJSON(t, object)

	privateKey, exists := fixture.privateKeys[signerID]
	if !exists {
		t.Fatalf("no private key for checkpoint signer %q", signerID)
	}
	signature := signLabeled(
		t,
		privateKey,
		codec.SignatureCheckpoint,
		unsigned,
	)
	object["authority_signature"] = codec.EncodeBase64URL(signature)
	return mustCanonicalJSON(t, object), unsigned
}

func mutateCheckpointProofPayload(
	t *testing.T,
	payload json.RawMessage,
	mutate func(map[string]any),
) json.RawMessage {
	t.Helper()

	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("json.Unmarshal() payload error = %v", err)
	}
	mutate(object)
	return mustCanonicalJSON(t, object)
}
