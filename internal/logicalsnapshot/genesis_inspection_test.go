package logicalsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
)

func TestInspectGenesisPayloadInitial(t *testing.T) {
	t.Parallel()

	transform := genesisInspectionDigest(0x31)
	genesis := canonicalSemanticJSON(t, map[string]any{
		"creator_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x41}, ed25519.SignatureSize),
		),
		"recovery_generation": uint64(0),
		"session_id":          string(semanticSession0),
		"workspace_id":        string(semanticWorkspaceID),
	})
	genesisDigest, err := chain.GenesisDigest(genesis)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(): %v", err)
	}
	encoded := mustEncodeGenesisPayload(t, GenesisPayload{
		GenesisJSON:             genesis,
		BoundaryTransformDigest: transform,
	})
	payload, err := DecodeGenesisPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeGenesisPayload(): %v", err)
	}

	got, err := InspectGenesisPayload(payload)
	if err != nil {
		t.Fatalf("InspectGenesisPayload(): %v", err)
	}
	want := GenesisMetadata{
		SessionID:               semanticSession0,
		WorkspaceID:             semanticWorkspaceID,
		RecoveryGeneration:      0,
		GenesisDigest:           genesisDigest,
		BoundaryTransformDigest: transform,
	}
	if got != want {
		t.Fatalf("InspectGenesisPayload() = %#v, want %#v", got, want)
	}
}

func TestInspectGenesisPayloadSuccessor(t *testing.T) {
	t.Parallel()

	predecessorGenesis := genesisInspectionDigest(0x11)
	predecessorChainHash := genesisInspectionDigest(0x12)
	predecessorResultHash := genesisInspectionDigest(0x13)
	predecessorAccumulator := genesisInspectionDigest(0x14)
	transform := genesisInspectionDigest(0x15)
	genesis := canonicalSemanticJSON(t, map[string]any{
		"digest_version": uint64(7),
		"post_transform_state_digest": codec.EncodeBase64URL(
			transform[:],
		),
		"predecessor_chain_hash": codec.EncodeBase64URL(
			predecessorChainHash[:],
		),
		"predecessor_chain_index": uint64(23),
		"predecessor_genesis_digest": codec.EncodeBase64URL(
			predecessorGenesis[:],
		),
		"predecessor_projection_accumulator": codec.EncodeBase64URL(
			predecessorAccumulator[:],
		),
		"predecessor_result_hash": codec.EncodeBase64URL(
			predecessorResultHash[:],
		),
		"predecessor_result_index":  uint64(29),
		"projection_schema_version": uint64(9),
		"quorum_recovery_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x51}, ed25519.SignatureSize),
		),
		"recovering_identity_signature": codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x52}, ed25519.SignatureSize),
		),
		"recovery_generation": uint64(1),
		"session_id":          string(semanticSession1),
		"workspace_id":        string(semanticWorkspaceID),
	})
	genesisDigest, err := chain.GenesisDigest(genesis)
	if err != nil {
		t.Fatalf("chain.GenesisDigest(): %v", err)
	}
	encoded := mustEncodeGenesisPayload(t, GenesisPayload{
		GenesisJSON: genesis,
		RecoveryAuthorizationJSON: canonicalSemanticJSON(
			t,
			map[string]any{"kind": "test-recovery"},
		),
		BoundaryTransformDigest: transform,
	})
	payload, err := DecodeGenesisPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeGenesisPayload(): %v", err)
	}

	got, err := InspectGenesisPayload(payload)
	if err != nil {
		t.Fatalf("InspectGenesisPayload(): %v", err)
	}
	want := GenesisMetadata{
		SessionID:                        semanticSession1,
		WorkspaceID:                      semanticWorkspaceID,
		RecoveryGeneration:               1,
		GenesisDigest:                    genesisDigest,
		HasPredecessor:                   true,
		PredecessorGenesisDigest:         predecessorGenesis,
		PredecessorChainIndex:            23,
		PredecessorChainHash:             predecessorChainHash,
		PredecessorResultIndex:           29,
		PredecessorResultHash:            predecessorResultHash,
		PredecessorProjectionAccumulator: predecessorAccumulator,
		BoundaryTransformDigest:          transform,
		DigestVersion:                    7,
		ProjectionSchemaVersion:          9,
	}
	if got != want {
		t.Fatalf("InspectGenesisPayload() = %#v, want %#v", got, want)
	}

	copied := got
	copied.GenesisDigest[0] ^= 0xff
	copied.PredecessorProjectionAccumulator[0] ^= 0xff
	payload.GenesisJSON[0] = '!'
	if got != want {
		t.Fatal("GenesisMetadata aliases its input or a copied value")
	}
}

func TestInspectGenesisPayloadValidatesDecodedPayload(t *testing.T) {
	t.Parallel()

	fixture := newSemanticFixture(t, true, nil)
	valid, err := DecodeGenesisPayload(fixture.records[1].Payload)
	if err != nil {
		t.Fatalf("DecodeGenesisPayload(): %v", err)
	}
	noncanonicalGenesis := valid
	noncanonicalGenesis.GenesisJSON = append(
		[]byte(" "),
		noncanonicalGenesis.GenesisJSON...,
	)
	mismatchedTransform := valid
	mismatchedTransform.BoundaryTransformDigest[0] ^= 0xff
	missingAuthorization := valid
	missingAuthorization.RecoveryAuthorizationJSON = nil

	for _, test := range []struct {
		name    string
		payload GenesisPayload
	}{
		{
			name:    "noncanonical genesis",
			payload: noncanonicalGenesis,
		},
		{
			name:    "successor transform mismatch",
			payload: mismatchedTransform,
		},
		{
			name:    "missing recovery authorization",
			payload: missingAuthorization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := InspectGenesisPayload(test.payload)
			if !errors.Is(err, ErrInvalidGenesisPayload) {
				t.Fatalf(
					"InspectGenesisPayload() error = %v, want %v",
					err,
					ErrInvalidGenesisPayload,
				)
			}
		})
	}
}

func genesisInspectionDigest(value byte) (digest chain.Digest) {
	for index := range digest {
		digest[index] = value
	}
	return digest
}
