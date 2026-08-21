package logicalsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxDescriptorPageBytes  = 4 << 20
	MaxChunkCompressedBytes = 4 << 20
	MaxChunkExpandedBytes   = 64 << 20
	MaxDescriptorsPerPage   = 16_384
)

var (
	ErrInvalidDescriptor      = errors.New("logicalsnapshot: invalid chunk descriptor")
	ErrInvalidDescriptorPage  = errors.New("logicalsnapshot: invalid descriptor page")
	ErrDescriptorPageTooLarge = errors.New(
		"logicalsnapshot: descriptor page exceeds size limit",
	)
	ErrDescriptorSequence = errors.New(
		"logicalsnapshot: descriptor pages do not match signed root",
	)
)

// ChunkDescriptor binds one exact transmitted chunk.
type ChunkDescriptor struct {
	ChunkIndex       uint64
	CompressedLength uint64
	ExpandedLength   uint64
	SHA256           chain.Digest
}

// DescriptorPageInput is one page in the descriptor hash chain.
type DescriptorPageInput struct {
	ArtifactID       string
	PageIndex        uint64
	PreviousPageHash chain.Digest
	Descriptors      []ChunkDescriptor
}

// DescriptorPage is an immutable canonical descriptor page and its computed
// chain hash.
type DescriptorPage struct {
	input     DescriptorPageInput
	canonical []byte
	hash      chain.Digest
	valid     bool
}

type descriptorWire struct {
	ChunkIndex       uint64 `json:"chunk_index"`
	CompressedLength uint64 `json:"compressed_length"`
	ExpandedLength   uint64 `json:"expanded_length"`
	SHA256           string `json:"sha256"`
}

type descriptorPageWire struct {
	ArtifactID       string           `json:"artifact_id"`
	Descriptors      []descriptorWire `json:"descriptors"`
	PageIndex        uint64           `json:"page_index"`
	PreviousPageHash string           `json:"previous_page_hash"`
}

// NewDescriptorPage validates and copies one descriptor page.
func NewDescriptorPage(input DescriptorPageInput) (DescriptorPage, error) {
	if err := validateDescriptorPageInput(input); err != nil {
		return DescriptorPage{}, err
	}
	wire := descriptorPageWire{
		ArtifactID:       input.ArtifactID,
		Descriptors:      descriptorsToWire(input.Descriptors),
		PageIndex:        input.PageIndex,
		PreviousPageHash: codec.EncodeBase64URL(input.PreviousPageHash[:]),
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return DescriptorPage{}, fmt.Errorf(
			"%w: encode: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	canonical, err := canonicalPageObject(raw)
	if err != nil {
		return DescriptorPage{}, fmt.Errorf(
			"%w: canonicalize: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	if len(canonical) > MaxDescriptorPageBytes {
		return DescriptorPage{}, ErrDescriptorPageTooLarge
	}
	hash, err := descriptorPageHash(input)
	if err != nil {
		return DescriptorPage{}, err
	}
	input.Descriptors = cloneDescriptors(input.Descriptors)
	return DescriptorPage{
		input:     input,
		canonical: canonical,
		hash:      hash,
		valid:     true,
	}, nil
}

// ParseDescriptorPage accepts only the exact canonical closed page object.
func ParseDescriptorPage(encoded []byte) (DescriptorPage, error) {
	if len(encoded) == 0 {
		return DescriptorPage{}, ErrInvalidDescriptorPage
	}
	if len(encoded) > MaxDescriptorPageBytes {
		return DescriptorPage{}, ErrDescriptorPageTooLarge
	}
	canonical, err := canonicalPageObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return DescriptorPage{}, fmt.Errorf(
			"%w: noncanonical object",
			ErrInvalidDescriptorPage,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire descriptorPageWire
	if err := decoder.Decode(&wire); err != nil {
		return DescriptorPage{}, fmt.Errorf(
			"%w: decode: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return DescriptorPage{}, ErrInvalidDescriptorPage
	}
	previous, err := decodePageDigest(wire.PreviousPageHash)
	if err != nil {
		return DescriptorPage{}, err
	}
	descriptors := make([]ChunkDescriptor, len(wire.Descriptors))
	for index, descriptor := range wire.Descriptors {
		digest, err := decodePageDigest(descriptor.SHA256)
		if err != nil {
			return DescriptorPage{}, err
		}
		descriptors[index] = ChunkDescriptor{
			ChunkIndex:       descriptor.ChunkIndex,
			CompressedLength: descriptor.CompressedLength,
			ExpandedLength:   descriptor.ExpandedLength,
			SHA256:           digest,
		}
	}
	page, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:       wire.ArtifactID,
		PageIndex:        wire.PageIndex,
		PreviousPageHash: previous,
		Descriptors:      descriptors,
	})
	if err != nil {
		return DescriptorPage{}, err
	}
	if !bytes.Equal(page.canonical, encoded) {
		return DescriptorPage{}, ErrInvalidDescriptorPage
	}
	return page, nil
}

// Input returns an independent copy of the page fields.
func (page DescriptorPage) Input() DescriptorPageInput {
	if !page.valid {
		return DescriptorPageInput{}
	}
	result := page.input
	result.Descriptors = cloneDescriptors(page.input.Descriptors)
	return result
}

// CanonicalBytes returns an independent copy of the encoded page.
func (page DescriptorPage) CanonicalBytes() []byte {
	if !page.valid {
		return nil
	}
	return bytes.Clone(page.canonical)
}

// Hash returns this page's descriptor-chain hash.
func (page DescriptorPage) Hash() chain.Digest {
	return page.hash
}

// ValidateDescriptorPages cross-checks a complete ordered page sequence
// against every descriptor commitment in the signed root.
func ValidateDescriptorPages(root Root, pages []DescriptorPage) error {
	if err := root.validate(); err != nil {
		return err
	}
	input := root.unsigned.input
	if uint64(len(pages)) != input.DescriptorPageCount {
		return ErrDescriptorSequence
	}
	var (
		previous        chain.Digest
		nextChunk       uint64
		compressedTotal uint64
		expandedTotal   uint64
	)
	for pageIndex, page := range pages {
		if !page.valid {
			return ErrDescriptorSequence
		}
		pageInput := page.input
		if pageInput.ArtifactID != input.ArtifactID ||
			pageInput.PageIndex != uint64(pageIndex) ||
			pageInput.PreviousPageHash != previous {
			return ErrDescriptorSequence
		}
		for _, descriptor := range pageInput.Descriptors {
			if descriptor.ChunkIndex != nextChunk ||
				compressedTotal > domain.MaxSafeInteger-descriptor.CompressedLength ||
				expandedTotal > domain.MaxSafeInteger-descriptor.ExpandedLength {
				return ErrDescriptorSequence
			}
			nextChunk++
			compressedTotal += descriptor.CompressedLength
			expandedTotal += descriptor.ExpandedLength
		}
		previous = page.hash
	}
	if nextChunk != input.ChunkCount ||
		compressedTotal != input.CompressedBytes ||
		expandedTotal != input.ExpandedBytes ||
		previous != input.FinalDescriptorPageHash {
		return ErrDescriptorSequence
	}
	return nil
}

func validateDescriptorPageInput(input DescriptorPageInput) error {
	if !validArtifactID(input.ArtifactID) ||
		!domain.ValidUnsignedInteger(input.PageIndex) ||
		len(input.Descriptors) < 1 ||
		len(input.Descriptors) > MaxDescriptorsPerPage ||
		input.PageIndex == 0 && input.PreviousPageHash != (chain.Digest{}) {
		return ErrInvalidDescriptorPage
	}
	for index, descriptor := range input.Descriptors {
		if descriptor.CompressedLength < 1 ||
			descriptor.CompressedLength > MaxChunkCompressedBytes ||
			descriptor.ExpandedLength < 1 ||
			descriptor.ExpandedLength > MaxChunkExpandedBytes ||
			!domain.ValidUnsignedInteger(descriptor.ChunkIndex) ||
			index > 0 &&
				descriptor.ChunkIndex != input.Descriptors[index-1].ChunkIndex+1 {
			return ErrInvalidDescriptor
		}
	}
	return nil
}

func descriptorPageHash(input DescriptorPageInput) (chain.Digest, error) {
	descriptorRaw, err := json.Marshal(descriptorsToWire(input.Descriptors))
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: encode descriptors: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	canonical, err := codec.Canonicalize(descriptorRaw)
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: canonicalize descriptors: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("codecomm/v1/snapshot-page-chain"))
	_, _ = hash.Write([]byte{0})
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], uint64(len(input.ArtifactID)))
	_, _ = hash.Write(framed[:])
	_, _ = hash.Write([]byte(input.ArtifactID))
	binary.BigEndian.PutUint64(framed[:], input.PageIndex)
	_, _ = hash.Write(framed[:])
	_, _ = hash.Write(input.PreviousPageHash[:])
	_, _ = hash.Write(canonical)
	var result chain.Digest
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func descriptorsToWire(values []ChunkDescriptor) []descriptorWire {
	result := make([]descriptorWire, len(values))
	for index, value := range values {
		result[index] = descriptorWire{
			ChunkIndex:       value.ChunkIndex,
			CompressedLength: value.CompressedLength,
			ExpandedLength:   value.ExpandedLength,
			SHA256:           codec.EncodeBase64URL(value.SHA256[:]),
		}
	}
	return result
}

func cloneDescriptors(values []ChunkDescriptor) []ChunkDescriptor {
	result := make([]ChunkDescriptor, len(values))
	copy(result, values)
	return result
}

func decodePageDigest(encoded string) (chain.Digest, error) {
	value, err := codec.DecodeBase64URLExact(encoded, len(chain.Digest{}))
	if err != nil {
		return chain.Digest{}, fmt.Errorf(
			"%w: digest: %v",
			ErrInvalidDescriptorPage,
			err,
		)
	}
	var result chain.Digest
	copy(result[:], value)
	return result, nil
}

func canonicalPageObject(value []byte) ([]byte, error) {
	canonical, err := codec.Canonicalize(value)
	if err != nil {
		return nil, err
	}
	if len(canonical) < 2 ||
		canonical[0] != '{' ||
		canonical[len(canonical)-1] != '}' {
		return nil, ErrInvalidDescriptorPage
	}
	return canonical, nil
}
