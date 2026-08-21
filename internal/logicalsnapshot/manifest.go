package logicalsnapshot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidManifestBuilder = errors.New(
		"logicalsnapshot: invalid manifest builder",
	)
	ErrManifestFinished = errors.New(
		"logicalsnapshot: manifest builder is already finished",
	)
	ErrEmptyManifest = errors.New(
		"logicalsnapshot: manifest contains no descriptors",
	)
	ErrManifestTooLarge = errors.New(
		"logicalsnapshot: manifest exceeds protocol integer limits",
	)
)

// DescriptorPageSink consumes one complete canonical descriptor page. It must
// consume content through EOF before returning success. The reader is valid
// only for the duration of the call.
type DescriptorPageSink func(
	context.Context,
	DescriptorPage,
	io.Reader,
) error

// ManifestSummary contains the signed-root fields derived from a descriptor
// page chain.
type ManifestSummary struct {
	DescriptorPageCount     uint64
	FinalDescriptorPageHash chain.Digest
}

// ManifestBuilder incrementally groups contiguous chunk descriptors into
// bounded, hash-chained pages. It retains at most MaxDescriptorsPerPage
// descriptors and is not safe for concurrent use.
type ManifestBuilder struct {
	ctx        context.Context
	artifactID string
	sink       DescriptorPageSink

	descriptors      []ChunkDescriptor
	descriptorCount  uint64
	pageCount        uint64
	previousPageHash chain.Digest

	failed   error
	finished bool
	summary  ManifestSummary
}

// NewManifestBuilder constructs a streaming descriptor-page builder.
func NewManifestBuilder(
	ctx context.Context,
	artifactID string,
	sink DescriptorPageSink,
) (*ManifestBuilder, error) {
	if ctx == nil || sink == nil || !validArtifactID(artifactID) {
		return nil, ErrInvalidManifestBuilder
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ManifestBuilder{
		ctx:         ctx,
		artifactID:  artifactID,
		sink:        sink,
		descriptors: make([]ChunkDescriptor, 0, MaxDescriptorsPerPage),
	}, nil
}

// Consume appends the next contiguous chunk descriptor. A full page is
// emitted immediately.
func (builder *ManifestBuilder) Consume(descriptor ChunkDescriptor) error {
	if builder == nil {
		return ErrInvalidManifestBuilder
	}
	if builder.failed != nil {
		return builder.failed
	}
	if builder.finished {
		return ErrManifestFinished
	}
	if err := builder.ctx.Err(); err != nil {
		return builder.fail(err)
	}
	if err := validateManifestDescriptor(descriptor); err != nil {
		return builder.fail(err)
	}
	if builder.descriptorCount >= domain.MaxSafeInteger {
		return builder.fail(ErrManifestTooLarge)
	}
	if descriptor.ChunkIndex != builder.descriptorCount {
		return builder.fail(ErrDescriptorSequence)
	}

	builder.descriptors = append(builder.descriptors, descriptor)
	builder.descriptorCount++
	if len(builder.descriptors) == MaxDescriptorsPerPage {
		if err := builder.flushPage(); err != nil {
			return builder.fail(err)
		}
	}
	if err := builder.ctx.Err(); err != nil {
		return builder.fail(err)
	}
	return nil
}

// Finish emits the final nonempty page and returns the complete page-chain
// summary. Repeated successful calls return the same value without invoking
// the sink.
func (builder *ManifestBuilder) Finish() (ManifestSummary, error) {
	if builder == nil {
		return ManifestSummary{}, ErrInvalidManifestBuilder
	}
	if builder.failed != nil {
		return ManifestSummary{}, builder.failed
	}
	if builder.finished {
		return builder.summary, nil
	}
	if err := builder.ctx.Err(); err != nil {
		return ManifestSummary{}, builder.fail(err)
	}
	if builder.descriptorCount == 0 {
		return ManifestSummary{}, builder.fail(ErrEmptyManifest)
	}
	if err := builder.flushPage(); err != nil {
		return ManifestSummary{}, builder.fail(err)
	}

	builder.summary = ManifestSummary{
		DescriptorPageCount:     builder.pageCount,
		FinalDescriptorPageHash: builder.previousPageHash,
	}
	builder.finished = true
	return builder.summary, nil
}

func (builder *ManifestBuilder) flushPage() error {
	if len(builder.descriptors) == 0 {
		return nil
	}
	if err := builder.ctx.Err(); err != nil {
		return err
	}
	if builder.pageCount >= domain.MaxSafeInteger {
		return ErrManifestTooLarge
	}

	page, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:       builder.artifactID,
		PageIndex:        builder.pageCount,
		PreviousPageHash: builder.previousPageHash,
		Descriptors:      builder.descriptors,
	})
	if err != nil {
		return err
	}
	content := page.CanonicalBytes()
	reader := bytes.NewReader(content)
	if err := builder.sink(builder.ctx, page, reader); err != nil {
		return fmt.Errorf(
			"logicalsnapshot: write descriptor page %d: %w",
			builder.pageCount,
			err,
		)
	}
	if reader.Len() != 0 {
		return fmt.Errorf(
			"logicalsnapshot: write descriptor page %d: %w",
			builder.pageCount,
			io.ErrShortWrite,
		)
	}
	if err := builder.ctx.Err(); err != nil {
		return err
	}

	builder.previousPageHash = page.Hash()
	builder.pageCount++
	clear(builder.descriptors)
	builder.descriptors = builder.descriptors[:0]
	return nil
}

func (builder *ManifestBuilder) fail(err error) error {
	if builder.failed == nil {
		builder.failed = err
	}
	return builder.failed
}

func validateManifestDescriptor(descriptor ChunkDescriptor) error {
	if !domain.ValidUnsignedInteger(descriptor.ChunkIndex) ||
		descriptor.CompressedLength < 1 ||
		descriptor.CompressedLength > MaxChunkCompressedBytes ||
		descriptor.ExpandedLength < 1 ||
		descriptor.ExpandedLength > MaxChunkExpandedBytes {
		return ErrInvalidDescriptor
	}
	return nil
}
