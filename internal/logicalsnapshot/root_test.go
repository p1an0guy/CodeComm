package logicalsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestRootRoundTripAndSignatureBinding(t *testing.T) {
	t.Parallel()

	input, privateKey, publicKey := testRootInput(t)
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	encoded := root.CanonicalBytes()
	parsed, err := ParseRoot(encoded)
	if err != nil {
		t.Fatalf("ParseRoot(): %v", err)
	}
	if parsed.Unsigned().Input() != input {
		t.Fatalf(
			"parsed input = %#v, want %#v",
			parsed.Unsigned().Input(),
			input,
		)
	}
	if !bytes.Equal(parsed.CanonicalBytes(), encoded) {
		t.Fatal("parsed root encoding differs")
	}
	if err := VerifyRoot(parsed, publicKey); err != nil {
		t.Fatalf("VerifyRoot(): %v", err)
	}

	wrongPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(wrong): %v", err)
	}
	if err := VerifyRoot(parsed, wrongPublic); !errors.Is(err, ErrRootSigner) {
		t.Fatalf("VerifyRoot(wrong signer) = %v, want ErrRootSigner", err)
	}

	signature := parsed.Signature()
	signature[0] ^= 0xff
	tampered, err := NewRoot(parsed.Unsigned(), signature)
	if err != nil {
		t.Fatalf("NewRoot(tampered signature): %v", err)
	}
	if err := VerifyRoot(tampered, publicKey); !errors.Is(
		err,
		ErrRootSignature,
	) {
		t.Fatalf(
			"VerifyRoot(tampered signature) = %v, want ErrRootSignature",
			err,
		)
	}

	wrongLabel, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureBatch,
		unsigned.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("SignEd25519(wrong label): %v", err)
	}
	var wrongLabelSignature [ed25519.SignatureSize]byte
	copy(wrongLabelSignature[:], wrongLabel)
	wrongLabelRoot, err := NewRoot(unsigned, wrongLabelSignature)
	if err != nil {
		t.Fatalf("NewRoot(wrong label): %v", err)
	}
	if err := VerifyRoot(wrongLabelRoot, publicKey); !errors.Is(
		err,
		ErrRootSignature,
	) {
		t.Fatalf(
			"VerifyRoot(wrong label) = %v, want ErrRootSignature",
			err,
		)
	}
}

func TestRootRejectsNoncanonicalUnknownAndInvalidFields(t *testing.T) {
	t.Parallel()

	input, privateKey, _ := testRootInput(t)
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	encoded := root.CanonicalBytes()

	if _, err := ParseRoot(append([]byte(" "), encoded...)); !errors.Is(
		err,
		ErrInvalidRoot,
	) {
		t.Fatalf("ParseRoot(noncanonical) = %v, want ErrInvalidRoot", err)
	}
	if _, err := ParseRoot(make([]byte, MaxRootBytes+1)); !errors.Is(
		err,
		ErrRootTooLarge,
	) {
		t.Fatalf("ParseRoot(oversized) = %v, want ErrRootTooLarge", err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("json.Unmarshal(root): %v", err)
	}
	members["unknown"] = json.RawMessage("true")
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(unknown root): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(unknown root): %v", err)
	}
	if _, err := ParseRoot(canonical); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("ParseRoot(unknown) = %v, want ErrInvalidRoot", err)
	}

	tests := map[string]func(*RootInput){
		"artifact": func(value *RootInput) { value.ArtifactID = "../snapshot" },
		"session":  func(value *RootInput) { value.SessionID = "" },
		"recovery generation": func(value *RootInput) {
			value.RecoveryGeneration = MaxRecoveryGeneration + 1
		},
		"result": func(value *RootInput) { value.ResultIndex = 0 },
		"chain": func(value *RootInput) {
			value.ChainIndex = value.ResultIndex + 1
		},
		"authority": func(value *RootInput) { value.AuthorityVersion = 0 },
		"encoding":  func(value *RootInput) { value.ContentEncoding = "br" },
		"records":   func(value *RootInput) { value.RecordCount = 0 },
		"more records than expanded bytes": func(value *RootInput) {
			value.RecordCount = value.ExpandedBytes + 1
		},
		"more results than records": func(value *RootInput) {
			value.ResultIndex = value.RecordCount + 1
		},
		"more events than records": func(value *RootInput) {
			value.ChainIndex = value.RecordCount + 1
			value.ResultIndex = value.ChainIndex
		},
		"record quota": func(value *RootInput) {
			value.RecordCount = MaxArtifactRecordCount + 1
			value.ExpandedBytes = MaxArtifactExpandedBytes
		},
		"expanded quota": func(value *RootInput) {
			value.ExpandedBytes = MaxArtifactExpandedBytes + 1
		},
		"compressed quota": func(value *RootInput) {
			value.CompressedBytes = MaxArtifactCompressedBytes + 1
		},
		"pages": func(value *RootInput) { value.DescriptorPageCount = 0 },
		"page quota": func(value *RootInput) {
			value.DescriptorPageCount = MaxDescriptorPageCount + 1
			value.ChunkCount = value.DescriptorPageCount
		},
		"chunks": func(value *RootInput) { value.ChunkCount = 0 },
		"chunk quota": func(value *RootInput) {
			value.ChunkCount = MaxArtifactChunkCount + 1
			value.DescriptorPageCount = MaxDescriptorPageCount + 1
			value.CompressedBytes = MaxArtifactCompressedBytes
			value.ExpandedBytes = MaxArtifactExpandedBytes
		},
		"more chunks than bytes": func(value *RootInput) {
			value.ChunkCount = value.CompressedBytes + 1
			value.DescriptorPageCount = 1
		},
		"identity totals differ": func(value *RootInput) {
			value.ContentEncoding = EncodingIdentity
		},
		"page count does not cover chunks": func(value *RootInput) {
			value.DescriptorPageCount = 2
		},
		"more chunks than records": func(value *RootInput) {
			value.ChunkCount = value.RecordCount + 1
		},
		"compressed total exceeds chunk capacity": func(value *RootInput) {
			value.ChunkCount = 1
			value.CompressedBytes = MaxChunkCompressedBytes + 1
		},
		"expanded total exceeds chunk capacity": func(value *RootInput) {
			value.ChunkCount = 1
			value.ExpandedBytes = MaxChunkExpandedBytes + 1
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := input
			mutate(&candidate)
			if _, err := NewUnsignedRoot(candidate); !errors.Is(
				err,
				ErrInvalidRoot,
			) {
				t.Fatalf(
					"NewUnsignedRoot(%s) = %v, want ErrInvalidRoot",
					name,
					err,
				)
			}
		})
	}
	for name, mutate := range map[string]func(*RootInput){
		"digest": func(value *RootInput) {
			value.DigestVersion = SupportedDigestVersion + 1
		},
		"projection": func(value *RootInput) {
			value.ProjectionSchemaVersion =
				SupportedProjectionSchemaVersion + 1
		},
	} {
		name, mutate := name, mutate
		t.Run("unsupported_"+name, func(t *testing.T) {
			t.Parallel()
			candidate := input
			mutate(&candidate)
			if _, err := NewUnsignedRoot(candidate); !errors.Is(
				err,
				ErrUnsupportedVersion,
			) {
				t.Fatalf(
					"NewUnsignedRoot(unsupported %s) = %v, want ErrUnsupportedVersion",
					name,
					err,
				)
			}
		})
	}
}

func TestRootOwnsCanonicalMemory(t *testing.T) {
	t.Parallel()

	input, _, _ := testRootInput(t)
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	first := unsigned.CanonicalBytes()
	first[0] ^= 0xff
	second := unsigned.CanonicalBytes()
	if bytes.Equal(first, second) || second[0] != '{' {
		t.Fatal("UnsignedRoot.CanonicalBytes() aliases internal memory")
	}
}

func testRootInput(
	t *testing.T,
) (RootInput, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("logicalsnapshot-root-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	return RootInput{
		ArtifactID:              "snapshot-01890f47",
		SessionID:               "01890f47-3e72-7000-8000-000000000001",
		WorkspaceID:             "550e8400-e29b-41d4-a716-446655440000",
		RecoveryGeneration:      0,
		CheckpointEventID:       "01890f47-3e72-7000-8000-000000000002",
		ChainIndex:              7,
		ChainHash:               sha256.Sum256([]byte("chain")),
		ResultIndex:             9,
		ResultHash:              sha256.Sum256([]byte("result")),
		ProjectionAccumulator:   sha256.Sum256([]byte("accumulator")),
		ProjectionStateDigest:   sha256.Sum256([]byte("state")),
		AuthorityVersion:        3,
		SignerDeviceID:          deviceID,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		ContentEncoding:         EncodingGZIP,
		ExpandedBytes:           2048,
		CompressedBytes:         1024,
		RecordCount:             12,
		DescriptorPageCount:     1,
		ChunkCount:              2,
		ArtifactDigest:          sha256.Sum256([]byte("artifact")),
		FinalDescriptorPageHash: sha256.Sum256([]byte("page")),
	}, privateKey, publicKey
}
