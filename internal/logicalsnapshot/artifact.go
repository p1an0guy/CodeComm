package logicalsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidArtifactBuilder = errors.New(
		"logicalsnapshot: invalid artifact builder",
	)
	ErrArtifactFinished = errors.New(
		"logicalsnapshot: artifact builder is already finished",
	)
	ErrEmptyArtifact = errors.New(
		"logicalsnapshot: artifact contains no records",
	)
	ErrArtifactTooLarge = errors.New(
		"logicalsnapshot: artifact exceeds protocol integer limits",
	)
)

// ArtifactChunkSink consumes one complete, bounded chunk. It must consume the
// content through EOF before returning success. The reader is valid only for
// the duration of the call.
type ArtifactChunkSink func(
	context.Context,
	ChunkDescriptor,
	io.Reader,
) error

// ArtifactSummary contains the root fields derived from an expanded artifact.
// Descriptors are delivered incrementally to ArtifactChunkSink and are not
// retained by ArtifactBuilder.
type ArtifactSummary struct {
	ContentEncoding ContentEncoding
	ArtifactDigest  chain.Digest
	ExpandedBytes   uint64
	CompressedBytes uint64
	RecordCount     uint64
	ChunkCount      uint64
}

// ArtifactBuilder incrementally frames records and emits greedy identity
// chunks. It retains only the current bounded chunk and fixed-size summary
// state. ArtifactBuilder is not safe for concurrent use.
type ArtifactBuilder struct {
	ctx      context.Context
	encoding ContentEncoding
	sink     ArtifactChunkSink

	chunk        bytes.Buffer
	artifactHash hash.Hash

	expandedBytes   uint64
	compressedBytes uint64
	recordCount     uint64
	chunkCount      uint64

	failed   error
	finished bool
	summary  ArtifactSummary
}

// NewArtifactBuilder constructs a streaming artifact builder. V1 initially
// supports identity encoding only.
func NewArtifactBuilder(
	ctx context.Context,
	encoding ContentEncoding,
	sink ArtifactChunkSink,
) (*ArtifactBuilder, error) {
	if ctx == nil || sink == nil {
		return nil, ErrInvalidArtifactBuilder
	}
	if encoding != EncodingIdentity {
		return nil, ErrUnsupportedCodec
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ArtifactBuilder{
		ctx:          ctx,
		encoding:     encoding,
		sink:         sink,
		artifactHash: sha256.New(),
	}, nil
}

// Consume appends one already semantically validated record. WriteRecord still
// enforces the closed type namespace, payload bounds, and canonical framing.
func (builder *ArtifactBuilder) Consume(record Record) error {
	if builder == nil {
		return ErrInvalidArtifactBuilder
	}
	if builder.failed != nil {
		return builder.failed
	}
	if builder.finished {
		return ErrArtifactFinished
	}
	if err := builder.ctx.Err(); err != nil {
		return builder.fail(err)
	}

	framed, err := frameArtifactRecord(record)
	if err != nil {
		return builder.fail(err)
	}
	framedLength := uint64(len(framed))
	if framedLength > identityChunkLimit() {
		return builder.fail(fmt.Errorf(
			"%w: framed record is %d bytes",
			ErrRecordTooLarge,
			framedLength,
		))
	}
	if builder.recordCount >= domain.MaxSafeInteger ||
		builder.expandedBytes > domain.MaxSafeInteger-framedLength {
		return builder.fail(ErrArtifactTooLarge)
	}
	if err := builder.ctx.Err(); err != nil {
		return builder.fail(err)
	}

	if builder.chunk.Len() != 0 &&
		uint64(builder.chunk.Len()) > identityChunkLimit()-framedLength {
		if err := builder.flushChunk(); err != nil {
			return builder.fail(err)
		}
	}
	if err := writeAll(&builder.chunk, framed); err != nil {
		return builder.fail(fmt.Errorf(
			"logicalsnapshot: buffer artifact record: %w",
			err,
		))
	}
	if err := writeAll(builder.artifactHash, framed); err != nil {
		return builder.fail(fmt.Errorf(
			"logicalsnapshot: hash artifact record: %w",
			err,
		))
	}
	builder.expandedBytes += framedLength
	builder.recordCount++
	if err := builder.ctx.Err(); err != nil {
		return builder.fail(err)
	}
	return nil
}

// Finish emits the final nonempty chunk and returns the complete summary.
// Repeated successful calls return the same value without invoking the sink.
func (builder *ArtifactBuilder) Finish() (ArtifactSummary, error) {
	if builder == nil {
		return ArtifactSummary{}, ErrInvalidArtifactBuilder
	}
	if builder.failed != nil {
		return ArtifactSummary{}, builder.failed
	}
	if builder.finished {
		return builder.summary, nil
	}
	if err := builder.ctx.Err(); err != nil {
		return ArtifactSummary{}, builder.fail(err)
	}
	if builder.recordCount == 0 {
		return ArtifactSummary{}, builder.fail(ErrEmptyArtifact)
	}
	if err := builder.flushChunk(); err != nil {
		return ArtifactSummary{}, builder.fail(err)
	}

	var artifactDigest chain.Digest
	copy(artifactDigest[:], builder.artifactHash.Sum(nil))
	builder.summary = ArtifactSummary{
		ContentEncoding: builder.encoding,
		ArtifactDigest:  artifactDigest,
		ExpandedBytes:   builder.expandedBytes,
		CompressedBytes: builder.compressedBytes,
		RecordCount:     builder.recordCount,
		ChunkCount:      builder.chunkCount,
	}
	builder.finished = true
	return builder.summary, nil
}

func (builder *ArtifactBuilder) flushChunk() error {
	if builder.chunk.Len() == 0 {
		return nil
	}
	if err := builder.ctx.Err(); err != nil {
		return err
	}
	chunkLength := uint64(builder.chunk.Len())
	if chunkLength > MaxChunkCompressedBytes ||
		chunkLength > MaxChunkExpandedBytes {
		return ErrRecordTooLarge
	}
	if builder.chunkCount >= domain.MaxSafeInteger ||
		builder.compressedBytes > domain.MaxSafeInteger-chunkLength {
		return ErrArtifactTooLarge
	}

	content := bytes.Clone(builder.chunk.Bytes())
	digest := sha256.Sum256(content)
	descriptor := ChunkDescriptor{
		ChunkIndex:       builder.chunkCount,
		CompressedLength: chunkLength,
		ExpandedLength:   chunkLength,
		SHA256:           digest,
	}
	reader := bytes.NewReader(content)
	if err := builder.sink(builder.ctx, descriptor, reader); err != nil {
		return fmt.Errorf(
			"logicalsnapshot: write artifact chunk %d: %w",
			descriptor.ChunkIndex,
			err,
		)
	}
	if reader.Len() != 0 {
		return fmt.Errorf(
			"logicalsnapshot: write artifact chunk %d: %w",
			descriptor.ChunkIndex,
			io.ErrShortWrite,
		)
	}
	if err := builder.ctx.Err(); err != nil {
		return err
	}

	builder.compressedBytes += chunkLength
	builder.chunkCount++
	builder.chunk.Reset()
	return nil
}

func (builder *ArtifactBuilder) fail(err error) error {
	if builder.failed == nil {
		builder.failed = err
	}
	return builder.failed
}

func frameArtifactRecord(record Record) ([]byte, error) {
	var framed bytes.Buffer
	if record.Type.valid() &&
		len(record.Payload) <= MaxRecordPayloadBytes {
		framed.Grow(10 + len(record.Type) + len(record.Payload))
	}
	written, err := WriteRecord(&framed, record.Type, record.Payload)
	if err != nil {
		return nil, err
	}
	if written != uint64(framed.Len()) {
		return nil, io.ErrShortWrite
	}
	return bytes.Clone(framed.Bytes()), nil
}

func identityChunkLimit() uint64 {
	if MaxChunkCompressedBytes < MaxChunkExpandedBytes {
		return MaxChunkCompressedBytes
	}
	return MaxChunkExpandedBytes
}
