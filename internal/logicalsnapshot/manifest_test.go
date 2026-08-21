package logicalsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
)

func TestManifestBuilderSinglePageRoundTripAndFinishIdempotence(t *testing.T) {
	t.Parallel()

	descriptors := []ChunkDescriptor{
		manifestDescriptor(0),
		manifestDescriptor(1),
		manifestDescriptor(2),
	}
	var (
		pages   []DescriptorPage
		encoded [][]byte
	)
	builder := mustManifestBuilder(t, "artifact-1", func(
		_ context.Context,
		page DescriptorPage,
		content io.Reader,
	) error {
		raw, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		pages = append(pages, page)
		encoded = append(encoded, raw)
		return nil
	})
	for _, descriptor := range descriptors {
		if err := builder.Consume(descriptor); err != nil {
			t.Fatalf("Consume(%d): %v", descriptor.ChunkIndex, err)
		}
	}

	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if len(pages) != 1 || len(encoded) != 1 {
		t.Fatalf("sink calls = (%d pages, %d encodings), want 1 each", len(pages), len(encoded))
	}
	if summary != (ManifestSummary{
		DescriptorPageCount:     1,
		FinalDescriptorPageHash: pages[0].Hash(),
	}) {
		t.Fatalf("summary = %#v", summary)
	}
	input := pages[0].Input()
	if input.ArtifactID != "artifact-1" ||
		input.PageIndex != 0 ||
		input.PreviousPageHash != (chain.Digest{}) ||
		!equalManifestDescriptors(input.Descriptors, descriptors) {
		t.Fatalf("page input = %#v", input)
	}
	parsed, err := ParseDescriptorPage(encoded[0])
	if err != nil {
		t.Fatalf("ParseDescriptorPage(): %v", err)
	}
	if parsed.Hash() != pages[0].Hash() ||
		!bytes.Equal(parsed.CanonicalBytes(), encoded[0]) {
		t.Fatal("parsed page differs from emitted page")
	}

	input.Descriptors[0] = ChunkDescriptor{}
	if pages[0].Input().Descriptors[0] != descriptors[0] {
		t.Fatal("Input returned a descriptor slice aliased to the page")
	}
	encoded[0][0] ^= 0xff
	if pages[0].CanonicalBytes()[0] == encoded[0][0] {
		t.Fatal("sink content was aliased to the page encoding")
	}

	again, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(second): %v", err)
	}
	if again != summary || len(pages) != 1 {
		t.Fatalf("Finish(second) = %#v with %d sink calls", again, len(pages))
	}
	if err := builder.Consume(manifestDescriptor(3)); !errors.Is(
		err,
		ErrManifestFinished,
	) {
		t.Fatalf("Consume(after Finish) = %v, want ErrManifestFinished", err)
	}
}

func TestManifestBuilderMultiplePagesAndHashChain(t *testing.T) {
	t.Parallel()

	const descriptorCount = MaxDescriptorsPerPage + 3
	pages := make([]DescriptorPage, 0, 2)
	encodings := make([][]byte, 0, 2)
	builder := mustManifestBuilder(t, "multi-page", func(
		_ context.Context,
		page DescriptorPage,
		content io.Reader,
	) error {
		raw, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		pages = append(pages, page)
		encodings = append(encodings, raw)
		return nil
	})
	for index := 0; index < descriptorCount; index++ {
		if err := builder.Consume(manifestDescriptor(uint64(index))); err != nil {
			t.Fatalf("Consume(%d): %v", index, err)
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if len(pages) != 2 || summary.DescriptorPageCount != 2 {
		t.Fatalf("page count = (%d, %d), want 2", len(pages), summary.DescriptorPageCount)
	}

	var previous chain.Digest
	nextChunk := uint64(0)
	for index, page := range pages {
		input := page.Input()
		if input.PageIndex != uint64(index) ||
			input.PreviousPageHash != previous ||
			len(input.Descriptors) == 0 ||
			len(input.Descriptors) > MaxDescriptorsPerPage {
			t.Fatalf("page %d input = %#v", index, input)
		}
		for _, descriptor := range input.Descriptors {
			if descriptor.ChunkIndex != nextChunk {
				t.Fatalf("chunk index = %d, want %d", descriptor.ChunkIndex, nextChunk)
			}
			nextChunk++
		}
		parsed, err := ParseDescriptorPage(encodings[index])
		if err != nil {
			t.Fatalf("ParseDescriptorPage(%d): %v", index, err)
		}
		if parsed.Hash() != page.Hash() {
			t.Fatalf("parsed page %d hash differs", index)
		}
		previous = page.Hash()
	}
	if nextChunk != descriptorCount {
		t.Fatalf("descriptor count = %d, want %d", nextChunk, descriptorCount)
	}
	if summary.FinalDescriptorPageHash != previous {
		t.Fatal("summary has the wrong final page hash")
	}
}

func TestManifestBuilderExactPageBoundaryDoesNotEmitEmptyPage(t *testing.T) {
	t.Parallel()

	sinkCalls := 0
	builder := mustManifestBuilder(t, "exact-boundary", func(
		_ context.Context,
		page DescriptorPage,
		content io.Reader,
	) error {
		sinkCalls++
		if len(page.Input().Descriptors) != MaxDescriptorsPerPage {
			t.Fatalf("descriptor count = %d", len(page.Input().Descriptors))
		}
		_, err := io.Copy(io.Discard, content)
		return err
	})
	for index := 0; index < MaxDescriptorsPerPage; index++ {
		if err := builder.Consume(manifestDescriptor(uint64(index))); err != nil {
			t.Fatalf("Consume(%d): %v", index, err)
		}
	}
	if sinkCalls != 1 {
		t.Fatalf("sink calls before Finish = %d, want 1", sinkCalls)
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if sinkCalls != 1 || summary.DescriptorPageCount != 1 {
		t.Fatalf("Finish emitted empty page: calls=%d summary=%#v", sinkCalls, summary)
	}
}

func TestManifestBuilderRejectsInvalidConstructionAndEmptyManifest(t *testing.T) {
	t.Parallel()

	validSink := func(
		_ context.Context,
		_ DescriptorPage,
		content io.Reader,
	) error {
		_, err := io.Copy(io.Discard, content)
		return err
	}
	var nilContext context.Context
	for name, create := range map[string]func() (*ManifestBuilder, error){
		"nil context": func() (*ManifestBuilder, error) {
			return NewManifestBuilder(nilContext, "artifact", validSink)
		},
		"nil sink": func() (*ManifestBuilder, error) {
			return NewManifestBuilder(context.Background(), "artifact", nil)
		},
		"invalid artifact": func() (*ManifestBuilder, error) {
			return NewManifestBuilder(context.Background(), "../artifact", validSink)
		},
	} {
		name, create := name, create
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := create(); !errors.Is(err, ErrInvalidManifestBuilder) {
				t.Fatalf("NewManifestBuilder() = %v, want ErrInvalidManifestBuilder", err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewManifestBuilder(ctx, "artifact", validSink); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("NewManifestBuilder(canceled) = %v, want context.Canceled", err)
	}

	sinkCalls := 0
	empty := mustManifestBuilder(t, "empty", func(
		_ context.Context,
		_ DescriptorPage,
		_ io.Reader,
	) error {
		sinkCalls++
		return nil
	})
	if summary, err := empty.Finish(); !errors.Is(
		err,
		ErrEmptyManifest,
	) || summary != (ManifestSummary{}) {
		t.Fatalf("Finish(empty) = (%#v, %v), want zero/ErrEmptyManifest", summary, err)
	}
	if sinkCalls != 0 {
		t.Fatalf("empty manifest emitted %d pages", sinkCalls)
	}

	var nilBuilder *ManifestBuilder
	if err := nilBuilder.Consume(manifestDescriptor(0)); !errors.Is(
		err,
		ErrInvalidManifestBuilder,
	) {
		t.Fatalf("nil Consume() = %v", err)
	}
	if summary, err := nilBuilder.Finish(); !errors.Is(
		err,
		ErrInvalidManifestBuilder,
	) || summary != (ManifestSummary{}) {
		t.Fatalf("nil Finish() = (%#v, %v)", summary, err)
	}
}

func TestManifestBuilderRejectsMalformedDescriptorsAndSequence(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		descriptors []ChunkDescriptor
		want        error
	}{
		"first index": {
			descriptors: []ChunkDescriptor{manifestDescriptor(1)},
			want:        ErrDescriptorSequence,
		},
		"gap": {
			descriptors: []ChunkDescriptor{
				manifestDescriptor(0),
				manifestDescriptor(2),
			},
			want: ErrDescriptorSequence,
		},
		"duplicate": {
			descriptors: []ChunkDescriptor{
				manifestDescriptor(0),
				manifestDescriptor(0),
			},
			want: ErrDescriptorSequence,
		},
		"zero compressed": {
			descriptors: []ChunkDescriptor{func() ChunkDescriptor {
				value := manifestDescriptor(0)
				value.CompressedLength = 0
				return value
			}()},
			want: ErrInvalidDescriptor,
		},
		"large compressed": {
			descriptors: []ChunkDescriptor{func() ChunkDescriptor {
				value := manifestDescriptor(0)
				value.CompressedLength = MaxChunkCompressedBytes + 1
				return value
			}()},
			want: ErrInvalidDescriptor,
		},
		"zero expanded": {
			descriptors: []ChunkDescriptor{func() ChunkDescriptor {
				value := manifestDescriptor(0)
				value.ExpandedLength = 0
				return value
			}()},
			want: ErrInvalidDescriptor,
		},
		"large expanded": {
			descriptors: []ChunkDescriptor{func() ChunkDescriptor {
				value := manifestDescriptor(0)
				value.ExpandedLength = MaxChunkExpandedBytes + 1
				return value
			}()},
			want: ErrInvalidDescriptor,
		},
		"large index": {
			descriptors: []ChunkDescriptor{func() ChunkDescriptor {
				value := manifestDescriptor(0)
				value.ChunkIndex = domain.MaxSafeInteger + 1
				return value
			}()},
			want: ErrInvalidDescriptor,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sinkCalls := 0
			builder := mustManifestBuilder(t, "invalid", func(
				_ context.Context,
				_ DescriptorPage,
				_ io.Reader,
			) error {
				sinkCalls++
				return nil
			})
			var got error
			for _, descriptor := range test.descriptors {
				got = builder.Consume(descriptor)
				if got != nil {
					break
				}
			}
			if !errors.Is(got, test.want) {
				t.Fatalf("Consume() = %v, want %v", got, test.want)
			}
			if again := builder.Consume(manifestDescriptor(99)); again != got {
				t.Fatalf("latched Consume() error = %v, want identical %v", again, got)
			}
			if summary, again := builder.Finish(); again != got ||
				summary != (ManifestSummary{}) {
				t.Fatalf("Finish() = (%#v, %v), want zero/identical %v", summary, again, got)
			}
			if sinkCalls != 0 {
				t.Fatalf("invalid descriptors emitted %d pages", sinkCalls)
			}
		})
	}

	builder := mustManifestBuilder(t, "too-large", func(
		_ context.Context,
		_ DescriptorPage,
		_ io.Reader,
	) error {
		return nil
	})
	builder.descriptorCount = domain.MaxSafeInteger
	if err := builder.Consume(manifestDescriptor(domain.MaxSafeInteger)); !errors.Is(
		err,
		ErrManifestTooLarge,
	) {
		t.Fatalf("Consume(over limit) = %v, want ErrManifestTooLarge", err)
	}
}

func TestManifestBuilderCancellation(t *testing.T) {
	t.Parallel()

	t.Run("before consume", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		builder, err := NewManifestBuilder(ctx, "cancel-before", func(
			_ context.Context,
			_ DescriptorPage,
			content io.Reader,
		) error {
			_, err := io.Copy(io.Discard, content)
			return err
		})
		if err != nil {
			t.Fatalf("NewManifestBuilder(): %v", err)
		}
		cancel()
		got := builder.Consume(manifestDescriptor(0))
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("Consume() = %v, want context.Canceled", got)
		}
		if summary, again := builder.Finish(); again != got ||
			summary != (ManifestSummary{}) {
			t.Fatalf("Finish() = (%#v, %v), want zero/identical %v", summary, again, got)
		}
	})

	t.Run("during sink", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		sinkCalls := 0
		builder, err := NewManifestBuilder(ctx, "cancel-sink", func(
			gotContext context.Context,
			_ DescriptorPage,
			content io.Reader,
		) error {
			sinkCalls++
			if gotContext != ctx {
				return errors.New("sink received a different context")
			}
			if _, err := io.Copy(io.Discard, content); err != nil {
				return err
			}
			cancel()
			return nil
		})
		if err != nil {
			t.Fatalf("NewManifestBuilder(): %v", err)
		}
		if err := builder.Consume(manifestDescriptor(0)); err != nil {
			t.Fatalf("Consume(): %v", err)
		}
		if summary, err := builder.Finish(); !errors.Is(
			err,
			context.Canceled,
		) || summary != (ManifestSummary{}) {
			t.Fatalf("Finish() = (%#v, %v), want zero/context.Canceled", summary, err)
		}
		if sinkCalls != 1 {
			t.Fatalf("sink calls = %d, want 1", sinkCalls)
		}
	})
}

func TestManifestBuilderPropagatesAndLatchesSinkFailures(t *testing.T) {
	t.Parallel()

	sinkFailure := errors.New("page sink failed")
	tests := []struct {
		name string
		sink DescriptorPageSink
		want error
	}{
		{
			name: "error",
			sink: func(
				_ context.Context,
				_ DescriptorPage,
				_ io.Reader,
			) error {
				return sinkFailure
			},
			want: sinkFailure,
		},
		{
			name: "short",
			sink: func(
				_ context.Context,
				_ DescriptorPage,
				content io.Reader,
			) error {
				var one [1]byte
				_, err := content.Read(one[:])
				return err
			},
			want: io.ErrShortWrite,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			builder := mustManifestBuilder(t, "sink-failure", test.sink)
			if err := builder.Consume(manifestDescriptor(0)); err != nil {
				t.Fatalf("Consume(): %v", err)
			}
			summary, got := builder.Finish()
			if !errors.Is(got, test.want) || summary != (ManifestSummary{}) {
				t.Fatalf("Finish() = (%#v, %v), want zero/%v", summary, got, test.want)
			}
			if again, err := builder.Finish(); err != got ||
				again != (ManifestSummary{}) {
				t.Fatalf("Finish(second) = (%#v, %v), want zero/identical %v", again, err, got)
			}
		})
	}
}

func TestManifestBuilderLargeStreamingDescriptorCount(t *testing.T) {
	t.Parallel()

	const descriptorCount = 4*MaxDescriptorsPerPage + 137
	var (
		pageCount        uint64
		nextChunk        uint64
		previousPageHash chain.Digest
	)
	builder := mustManifestBuilder(t, "large-stream", func(
		_ context.Context,
		page DescriptorPage,
		content io.Reader,
	) error {
		input := page.Input()
		if input.PageIndex != pageCount ||
			input.PreviousPageHash != previousPageHash ||
			len(input.Descriptors) == 0 ||
			len(input.Descriptors) > MaxDescriptorsPerPage {
			return errors.New("invalid streamed page")
		}
		for _, descriptor := range input.Descriptors {
			if descriptor.ChunkIndex != nextChunk {
				return errors.New("noncontiguous streamed descriptor")
			}
			nextChunk++
		}
		if _, err := io.Copy(io.Discard, content); err != nil {
			return err
		}
		pageCount++
		previousPageHash = page.Hash()
		return nil
	})
	for index := uint64(0); index < descriptorCount; index++ {
		if err := builder.Consume(manifestDescriptor(index)); err != nil {
			t.Fatalf("Consume(%d): %v", index, err)
		}
		if len(builder.descriptors) > MaxDescriptorsPerPage {
			t.Fatalf("retained %d descriptors", len(builder.descriptors))
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if nextChunk != descriptorCount ||
		pageCount != 5 ||
		summary.DescriptorPageCount != pageCount ||
		summary.FinalDescriptorPageHash != previousPageHash {
		t.Fatalf(
			"stream result = chunks %d, pages %d, summary %#v",
			nextChunk,
			pageCount,
			summary,
		)
	}
	if cap(builder.descriptors) > MaxDescriptorsPerPage {
		t.Fatalf("descriptor capacity = %d, want <= %d", cap(builder.descriptors), MaxDescriptorsPerPage)
	}
}

func mustManifestBuilder(
	t *testing.T,
	artifactID string,
	sink DescriptorPageSink,
) *ManifestBuilder {
	t.Helper()
	builder, err := NewManifestBuilder(context.Background(), artifactID, sink)
	if err != nil {
		t.Fatalf("NewManifestBuilder(): %v", err)
	}
	return builder
}

func manifestDescriptor(index uint64) ChunkDescriptor {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], index)
	return ChunkDescriptor{
		ChunkIndex:       index,
		CompressedLength: index%MaxChunkCompressedBytes + 1,
		ExpandedLength:   index%MaxChunkExpandedBytes + 1,
		SHA256:           sha256.Sum256(encoded[:]),
	}
}

func equalManifestDescriptors(left, right []ChunkDescriptor) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
