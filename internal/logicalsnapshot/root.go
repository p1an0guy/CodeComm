// Package logicalsnapshot implements the bounded, signed logical-snapshot
// wire format. It deliberately has no SQLite or Raft dependencies.
package logicalsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	RootSchemaVersion                = 1
	SupportedDigestVersion           = 1
	SupportedProjectionSchemaVersion = 1
	MaxRootBytes                     = 64 << 10
)

var (
	ErrInvalidRoot        = errors.New("logicalsnapshot: invalid signed root")
	ErrRootTooLarge       = errors.New("logicalsnapshot: signed root exceeds size limit")
	ErrRootSigner         = errors.New("logicalsnapshot: root signer mismatch")
	ErrRootSignature      = errors.New("logicalsnapshot: invalid root signature")
	ErrUnsupportedCodec   = errors.New("logicalsnapshot: unsupported content encoding")
	ErrUnsupportedVersion = errors.New(
		"logicalsnapshot: unsupported projection commitment version",
	)
)

// ContentEncoding names the exact encoding used for every transmitted chunk.
type ContentEncoding string

const (
	EncodingIdentity ContentEncoding = "identity"
	EncodingGZIP     ContentEncoding = "gzip"
	EncodingZSTD     ContentEncoding = "zstd"
)

func (encoding ContentEncoding) valid() bool {
	switch encoding {
	case EncodingIdentity, EncodingGZIP, EncodingZSTD:
		return true
	default:
		return false
	}
}

// RootInput is the complete logical-snapshot signature preimage.
type RootInput struct {
	ArtifactID              string
	SessionID               domain.UUIDv7
	WorkspaceID             domain.UUIDv4
	RecoveryGeneration      uint64
	CheckpointEventID       domain.UUIDv7
	ChainIndex              uint64
	ChainHash               chain.Digest
	ResultIndex             uint64
	ResultHash              chain.Digest
	ProjectionAccumulator   chain.Digest
	ProjectionStateDigest   chain.Digest
	AuthorityVersion        uint64
	SignerDeviceID          domain.DeviceID
	DigestVersion           uint64
	ProjectionSchemaVersion uint64
	ContentEncoding         ContentEncoding
	ExpandedBytes           uint64
	CompressedBytes         uint64
	RecordCount             uint64
	DescriptorPageCount     uint64
	ChunkCount              uint64
	ArtifactDigest          chain.Digest
	FinalDescriptorPageHash chain.Digest
}

// UnsignedRoot is an immutable validated snapshot-root preimage.
type UnsignedRoot struct {
	input     RootInput
	canonical []byte
	valid     bool
}

// Root is an immutable identity-signed logical-snapshot root.
type Root struct {
	unsigned  UnsignedRoot
	signature [ed25519.SignatureSize]byte
	valid     bool
}

type rootFieldsWire struct {
	ArtifactDigest          string `json:"artifact_digest"`
	ArtifactID              string `json:"artifact_id"`
	AuthorityVersion        uint64 `json:"authority_voter_set_version"`
	ChainHash               string `json:"chain_hash"`
	ChainIndex              uint64 `json:"chain_index"`
	CheckpointEventID       string `json:"checkpoint_event_id"`
	ChunkCount              uint64 `json:"chunk_count"`
	CompressedBytes         uint64 `json:"compressed_bytes"`
	ContentEncoding         string `json:"content_encoding"`
	DescriptorPageCount     uint64 `json:"descriptor_page_count"`
	DigestVersion           uint64 `json:"digest_version"`
	ExpandedBytes           uint64 `json:"expanded_bytes"`
	FinalDescriptorPageHash string `json:"final_descriptor_page_hash"`
	ProjectionAccumulator   string `json:"projection_accumulator"`
	ProjectionSchemaVersion uint64 `json:"projection_schema_version"`
	ProjectionStateDigest   string `json:"projection_state_digest"`
	RecordCount             uint64 `json:"record_count"`
	RecoveryGeneration      uint64 `json:"recovery_generation"`
	ResultHash              string `json:"result_hash"`
	ResultIndex             uint64 `json:"result_index"`
	SchemaVersion           uint64 `json:"schema_version"`
	SessionID               string `json:"session_id"`
	SignerDeviceID          string `json:"signer_device_id"`
	WorkspaceID             string `json:"workspace_id"`
}

type completeRootWire struct {
	rootFieldsWire
	SnapshotSignature string `json:"snapshot_signature"`
}

// NewUnsignedRoot validates and copies a complete snapshot-root preimage.
func NewUnsignedRoot(input RootInput) (UnsignedRoot, error) {
	if err := validateRootInput(input); err != nil {
		return UnsignedRoot{}, err
	}
	raw, err := json.Marshal(rootWireFromInput(input))
	if err != nil {
		return UnsignedRoot{}, fmt.Errorf("%w: encode: %v", ErrInvalidRoot, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return UnsignedRoot{}, fmt.Errorf("%w: canonicalize: %v", ErrInvalidRoot, err)
	}
	if len(canonical) > MaxRootBytes {
		return UnsignedRoot{}, ErrRootTooLarge
	}
	return UnsignedRoot{
		input:     input,
		canonical: canonical,
		valid:     true,
	}, nil
}

// NewRoot attaches a fixed-size signature to a validated root preimage.
func NewRoot(
	unsigned UnsignedRoot,
	signature [ed25519.SignatureSize]byte,
) (Root, error) {
	if err := unsigned.validate(); err != nil {
		return Root{}, err
	}
	root := Root{
		unsigned:  unsigned,
		signature: signature,
		valid:     true,
	}
	if len(root.CanonicalBytes()) > MaxRootBytes {
		return Root{}, ErrRootTooLarge
	}
	return root, nil
}

// SignRoot signs a validated root with its named server identity.
func SignRoot(unsigned UnsignedRoot, privateKey []byte) (Root, error) {
	if err := unsigned.validate(); err != nil {
		return Root{}, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return Root{}, fmt.Errorf("%w: %v", ErrRootSigner, err)
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil || derived != unsigned.input.SignerDeviceID {
		return Root{}, ErrRootSigner
	}
	raw, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureSnapshot,
		unsigned.canonical,
	)
	if err != nil {
		return Root{}, fmt.Errorf("%w: %v", ErrRootSignature, err)
	}
	defer clear(raw)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], raw)
	return NewRoot(unsigned, signature)
}

// ParseRoot accepts only the exact canonical closed V1 root object.
func ParseRoot(encoded []byte) (Root, error) {
	if len(encoded) == 0 {
		return Root{}, ErrInvalidRoot
	}
	if len(encoded) > MaxRootBytes {
		return Root{}, ErrRootTooLarge
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Root{}, fmt.Errorf("%w: noncanonical object", ErrInvalidRoot)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire completeRootWire
	if err := decoder.Decode(&wire); err != nil {
		return Root{}, fmt.Errorf("%w: decode: %v", ErrInvalidRoot, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Root{}, ErrInvalidRoot
	}
	input, err := rootInputFromWire(wire.rootFieldsWire)
	if err != nil {
		return Root{}, err
	}
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		return Root{}, err
	}
	signatureBytes, err := codec.DecodeBase64URLExact(
		wire.SnapshotSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return Root{}, fmt.Errorf("%w: signature: %v", ErrInvalidRoot, err)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	root, err := NewRoot(unsigned, signature)
	if err != nil {
		return Root{}, err
	}
	if !bytes.Equal(root.CanonicalBytes(), encoded) {
		return Root{}, fmt.Errorf("%w: encoding differs", ErrInvalidRoot)
	}
	return root, nil
}

// VerifyRoot verifies the named signer's identity signature.
func VerifyRoot(root Root, publicKey []byte) error {
	if err := root.validate(); err != nil {
		return err
	}
	derived, err := device.DeriveID(ed25519.PublicKey(publicKey))
	if err != nil || derived != root.unsigned.input.SignerDeviceID {
		return ErrRootSigner
	}
	if err := codecommcrypto.VerifyEd25519(
		publicKey,
		codec.SignatureSnapshot,
		root.unsigned.canonical,
		root.signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrRootSignature, err)
	}
	return nil
}

// Input returns the signed fields by value.
func (unsigned UnsignedRoot) Input() RootInput {
	if !unsigned.valid {
		return RootInput{}
	}
	return unsigned.input
}

// CanonicalBytes returns an independent copy of the signature preimage.
func (unsigned UnsignedRoot) CanonicalBytes() []byte {
	if !unsigned.valid {
		return nil
	}
	return bytes.Clone(unsigned.canonical)
}

// Unsigned returns the validated signature preimage.
func (root Root) Unsigned() UnsignedRoot {
	return root.unsigned
}

// Signature returns the complete signature by value.
func (root Root) Signature() [ed25519.SignatureSize]byte {
	return root.signature
}

// CanonicalBytes returns an independent copy of the complete signed root.
func (root Root) CanonicalBytes() []byte {
	if root.validate() != nil {
		return nil
	}
	wire := completeRootWire{
		rootFieldsWire:    rootWireFromInput(root.unsigned.input),
		SnapshotSignature: codec.EncodeBase64URL(root.signature[:]),
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil
	}
	return canonical
}

func (unsigned UnsignedRoot) validate() error {
	if !unsigned.valid ||
		len(unsigned.canonical) == 0 ||
		len(unsigned.canonical) > MaxRootBytes {
		return ErrInvalidRoot
	}
	return validateRootInput(unsigned.input)
}

func (root Root) validate() error {
	if !root.valid {
		return ErrInvalidRoot
	}
	return root.unsigned.validate()
}

func validateRootInput(input RootInput) error {
	if input.DigestVersion != SupportedDigestVersion ||
		input.ProjectionSchemaVersion !=
			SupportedProjectionSchemaVersion {
		return ErrUnsupportedVersion
	}
	if !validArtifactID(input.ArtifactID) ||
		!input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.CheckpointEventID.Valid() ||
		!input.SignerDeviceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!domain.ValidUnsignedInteger(input.ChainIndex) ||
		input.ResultIndex < 1 ||
		!domain.ValidUnsignedInteger(input.ResultIndex) ||
		input.ChainIndex > input.ResultIndex ||
		input.AuthorityVersion < 1 ||
		!domain.ValidUnsignedInteger(input.AuthorityVersion) ||
		!input.ContentEncoding.valid() ||
		input.ExpandedBytes < 1 ||
		!domain.ValidUnsignedInteger(input.ExpandedBytes) ||
		input.CompressedBytes < 1 ||
		!domain.ValidUnsignedInteger(input.CompressedBytes) ||
		input.RecordCount < 1 ||
		!domain.ValidUnsignedInteger(input.RecordCount) ||
		input.DescriptorPageCount < 1 ||
		!domain.ValidUnsignedInteger(input.DescriptorPageCount) ||
		input.ChunkCount < 1 ||
		!domain.ValidUnsignedInteger(input.ChunkCount) {
		return ErrInvalidRoot
	}
	return nil
}

func validArtifactID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == ':',
			character == '-':
		default:
			return false
		}
	}
	return true
}

func rootWireFromInput(input RootInput) rootFieldsWire {
	return rootFieldsWire{
		ArtifactDigest:          codec.EncodeBase64URL(input.ArtifactDigest[:]),
		ArtifactID:              input.ArtifactID,
		AuthorityVersion:        input.AuthorityVersion,
		ChainHash:               codec.EncodeBase64URL(input.ChainHash[:]),
		ChainIndex:              input.ChainIndex,
		CheckpointEventID:       string(input.CheckpointEventID),
		ChunkCount:              input.ChunkCount,
		CompressedBytes:         input.CompressedBytes,
		ContentEncoding:         string(input.ContentEncoding),
		DescriptorPageCount:     input.DescriptorPageCount,
		DigestVersion:           input.DigestVersion,
		ExpandedBytes:           input.ExpandedBytes,
		FinalDescriptorPageHash: codec.EncodeBase64URL(input.FinalDescriptorPageHash[:]),
		ProjectionAccumulator:   codec.EncodeBase64URL(input.ProjectionAccumulator[:]),
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
		ProjectionStateDigest:   codec.EncodeBase64URL(input.ProjectionStateDigest[:]),
		RecordCount:             input.RecordCount,
		RecoveryGeneration:      input.RecoveryGeneration,
		ResultHash:              codec.EncodeBase64URL(input.ResultHash[:]),
		ResultIndex:             input.ResultIndex,
		SchemaVersion:           RootSchemaVersion,
		SessionID:               string(input.SessionID),
		SignerDeviceID:          string(input.SignerDeviceID),
		WorkspaceID:             string(input.WorkspaceID),
	}
}

func rootInputFromWire(wire rootFieldsWire) (RootInput, error) {
	if wire.SchemaVersion != RootSchemaVersion {
		return RootInput{}, ErrInvalidRoot
	}
	var input RootInput
	input.ArtifactID = wire.ArtifactID
	input.SessionID = domain.UUIDv7(wire.SessionID)
	input.WorkspaceID = domain.UUIDv4(wire.WorkspaceID)
	input.RecoveryGeneration = wire.RecoveryGeneration
	input.CheckpointEventID = domain.UUIDv7(wire.CheckpointEventID)
	input.ChainIndex = wire.ChainIndex
	input.ResultIndex = wire.ResultIndex
	input.AuthorityVersion = wire.AuthorityVersion
	input.SignerDeviceID = domain.DeviceID(wire.SignerDeviceID)
	input.DigestVersion = wire.DigestVersion
	input.ProjectionSchemaVersion = wire.ProjectionSchemaVersion
	input.ContentEncoding = ContentEncoding(wire.ContentEncoding)
	input.ExpandedBytes = wire.ExpandedBytes
	input.CompressedBytes = wire.CompressedBytes
	input.RecordCount = wire.RecordCount
	input.DescriptorPageCount = wire.DescriptorPageCount
	input.ChunkCount = wire.ChunkCount
	for _, target := range []struct {
		encoded string
		digest  *chain.Digest
	}{
		{wire.ChainHash, &input.ChainHash},
		{wire.ResultHash, &input.ResultHash},
		{wire.ProjectionAccumulator, &input.ProjectionAccumulator},
		{wire.ProjectionStateDigest, &input.ProjectionStateDigest},
		{wire.ArtifactDigest, &input.ArtifactDigest},
		{wire.FinalDescriptorPageHash, &input.FinalDescriptorPageHash},
	} {
		decoded, err := codec.DecodeBase64URLExact(
			target.encoded,
			len(chain.Digest{}),
		)
		if err != nil {
			return RootInput{}, fmt.Errorf("%w: digest: %v", ErrInvalidRoot, err)
		}
		copy(target.digest[:], decoded)
	}
	if err := validateRootInput(input); err != nil {
		return RootInput{}, err
	}
	return input, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
