package logicalsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
)

func TestArtifactBuilderIdentityDigestCountsAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{
		[]byte(`{"generation":0}`),
		[]byte(`{"accepted":true,"index":1}`),
		[]byte(`{"checkpoint":true}`),
	}
	records := []Record{
		{Type: RecordGenesis, Payload: payloads[0]},
		{Type: RecordResult, Payload: payloads[1]},
		{Type: RecordCheckpoint, Payload: payloads[2]},
	}
	var expected bytes.Buffer
	for _, record := range records {
		if _, err := WriteRecord(
			&expected,
			record.Type,
			record.Payload,
		); err != nil {
			t.Fatalf("WriteRecord(): %v", err)
		}
	}
	expectedBytes := bytes.Clone(expected.Bytes())

	var (
		descriptors []ChunkDescriptor
		chunks      [][]byte
	)
	sink := func(
		_ context.Context,
		descriptor ChunkDescriptor,
		content io.Reader,
	) error {
		chunk, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		descriptors = append(descriptors, descriptor)
		chunks = append(chunks, chunk)
		return nil
	}
	builder, err := NewArtifactBuilder(
		context.Background(),
		EncodingIdentity,
		sink,
	)
	if err != nil {
		t.Fatalf("NewArtifactBuilder(): %v", err)
	}
	for _, record := range records {
		if err := builder.Consume(record); err != nil {
			t.Fatalf("Consume(%s): %v", record.Type, err)
		}
	}
	for _, payload := range payloads {
		clear(payload)
	}

	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if len(descriptors) != 1 || len(chunks) != 1 {
		t.Fatalf(
			"sink calls = descriptors %d, chunks %d, want 1 each",
			len(descriptors),
			len(chunks),
		)
	}
	if !bytes.Equal(chunks[0], expectedBytes) {
		t.Fatal("emitted chunk changed with caller-owned record payloads")
	}
	wantDigest := sha256.Sum256(expectedBytes)
	if summary != (ArtifactSummary{
		ContentEncoding: EncodingIdentity,
		ArtifactDigest:  wantDigest,
		ExpandedBytes:   uint64(len(expectedBytes)),
		CompressedBytes: uint64(len(expectedBytes)),
		RecordCount:     uint64(len(records)),
		ChunkCount:      1,
	}) {
		t.Fatalf("summary = %#v", summary)
	}
	if descriptors[0] != (ChunkDescriptor{
		ChunkIndex:       0,
		CompressedLength: uint64(len(expectedBytes)),
		ExpandedLength:   uint64(len(expectedBytes)),
		SHA256:           wantDigest,
	}) {
		t.Fatalf("descriptor = %#v", descriptors[0])
	}

	again, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(second): %v", err)
	}
	if again != summary {
		t.Fatalf("Finish(second) = %#v, want %#v", again, summary)
	}
	if len(chunks) != 1 {
		t.Fatalf("idempotent Finish emitted %d chunks, want 1", len(chunks))
	}
	if err := builder.Consume(Record{
		Type:    RecordEvent,
		Payload: []byte(`{"late":true}`),
	}); !errors.Is(err, ErrArtifactFinished) {
		t.Fatalf("Consume(after Finish) = %v, want ErrArtifactFinished", err)
	}
}

func TestArtifactBuilderGreedyIdentityChunkBoundaries(t *testing.T) {
	t.Parallel()

	const framingBytes = 10 + len(RecordEvent)
	firstPayloadLength := MaxRecordPayloadBytes
	secondPayloadLength := int(MaxChunkCompressedBytes) -
		(firstPayloadLength + framingBytes) -
		framingBytes
	if secondPayloadLength < 8 {
		t.Fatal("test constants cannot construct an exact-boundary record")
	}
	records := []Record{
		{
			Type:    RecordEvent,
			Payload: artifactPayloadOfLength(t, firstPayloadLength),
		},
		{
			Type:    RecordEvent,
			Payload: artifactPayloadOfLength(t, secondPayloadLength),
		},
		{
			Type:    RecordEvent,
			Payload: []byte(`{"v":""}`),
		},
	}
	var (
		descriptors []ChunkDescriptor
		chunks      [][]byte
	)
	builder := mustArtifactBuilder(t, func(
		_ context.Context,
		descriptor ChunkDescriptor,
		content io.Reader,
	) error {
		chunk, err := io.ReadAll(content)
		if err != nil {
			return err
		}
		descriptors = append(descriptors, descriptor)
		chunks = append(chunks, chunk)
		return nil
	})
	for _, record := range records {
		if err := builder.Consume(record); err != nil {
			t.Fatalf("Consume(): %v", err)
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}

	if len(chunks) != 2 {
		t.Fatalf("chunk count = %d, want 2", len(chunks))
	}
	if len(chunks[0]) != MaxChunkCompressedBytes {
		t.Fatalf(
			"first chunk length = %d, want %d",
			len(chunks[0]),
			MaxChunkCompressedBytes,
		)
	}
	if len(chunks[1]) != framingBytes+len(records[2].Payload) {
		t.Fatalf(
			"second chunk length = %d, want %d",
			len(chunks[1]),
			framingBytes+len(records[2].Payload),
		)
	}
	for index, chunk := range chunks {
		if len(chunk) == 0 ||
			len(chunk) > MaxChunkCompressedBytes ||
			len(chunk) > MaxChunkExpandedBytes {
			t.Fatalf("chunk %d has invalid length %d", index, len(chunk))
		}
		if descriptors[index].ChunkIndex != uint64(index) ||
			descriptors[index].CompressedLength != uint64(len(chunk)) ||
			descriptors[index].ExpandedLength != uint64(len(chunk)) ||
			descriptors[index].SHA256 != sha256.Sum256(chunk) {
			t.Fatalf(
				"descriptor %d = %#v for %d bytes",
				index,
				descriptors[index],
				len(chunk),
			)
		}
	}
	if got := countArtifactRecords(t, chunks[0]); got != 2 {
		t.Fatalf("first chunk record count = %d, want 2", got)
	}
	if got := countArtifactRecords(t, chunks[1]); got != 1 {
		t.Fatalf("second chunk record count = %d, want 1", got)
	}
	if summary.ChunkCount != 2 || summary.RecordCount != 3 ||
		summary.ExpandedBytes !=
			uint64(len(chunks[0])+len(chunks[1])) ||
		summary.CompressedBytes != summary.ExpandedBytes {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestArtifactBuilderRejectsConstructionAndRecordErrors(t *testing.T) {
	t.Parallel()

	validSink := func(
		_ context.Context,
		_ ChunkDescriptor,
		content io.Reader,
	) error {
		_, err := io.Copy(io.Discard, content)
		return err
	}
	var nilContext context.Context
	if _, err := NewArtifactBuilder(
		nilContext,
		EncodingIdentity,
		validSink,
	); !errors.Is(err, ErrInvalidArtifactBuilder) {
		t.Fatalf("NewArtifactBuilder(nil context) = %v", err)
	}
	if _, err := NewArtifactBuilder(
		context.Background(),
		EncodingIdentity,
		nil,
	); !errors.Is(err, ErrInvalidArtifactBuilder) {
		t.Fatalf("NewArtifactBuilder(nil sink) = %v", err)
	}
	for _, encoding := range []ContentEncoding{
		EncodingGZIP,
		EncodingZSTD,
		"br",
	} {
		if _, err := NewArtifactBuilder(
			context.Background(),
			encoding,
			validSink,
		); !errors.Is(err, ErrUnsupportedCodec) {
			t.Errorf(
				"NewArtifactBuilder(%q) = %v, want ErrUnsupportedCodec",
				encoding,
				err,
			)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewArtifactBuilder(
		ctx,
		EncodingIdentity,
		validSink,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewArtifactBuilder(canceled) = %v", err)
	}

	sinkCalls := 0
	builder := mustArtifactBuilder(t, func(
		_ context.Context,
		_ ChunkDescriptor,
		content io.Reader,
	) error {
		sinkCalls++
		_, err := io.Copy(io.Discard, content)
		return err
	})
	tooLarge := Record{
		Type: RecordEvent,
		Payload: artifactPayloadOfLength(
			t,
			MaxRecordPayloadBytes+1,
		),
	}
	if err := builder.Consume(tooLarge); !errors.Is(
		err,
		ErrRecordTooLarge,
	) {
		t.Fatalf("Consume(oversized) = %v, want ErrRecordTooLarge", err)
	}
	if summary, err := builder.Finish(); !errors.Is(
		err,
		ErrRecordTooLarge,
	) || summary != (ArtifactSummary{}) {
		t.Fatalf(
			"Finish(after oversized) = (%#v, %v), want zero/ErrRecordTooLarge",
			summary,
			err,
		)
	}
	if sinkCalls != 0 {
		t.Fatalf("oversized record emitted %d chunks", sinkCalls)
	}

	emptyCalls := 0
	empty := mustArtifactBuilder(t, func(
		_ context.Context,
		_ ChunkDescriptor,
		_ io.Reader,
	) error {
		emptyCalls++
		return nil
	})
	if summary, err := empty.Finish(); !errors.Is(
		err,
		ErrEmptyArtifact,
	) || summary != (ArtifactSummary{}) {
		t.Fatalf(
			"Finish(empty) = (%#v, %v), want zero/ErrEmptyArtifact",
			summary,
			err,
		)
	}
	if emptyCalls != 0 {
		t.Fatalf("empty artifact emitted %d chunks", emptyCalls)
	}
}

func TestArtifactBuilderCancellation(t *testing.T) {
	t.Parallel()

	t.Run("before consume", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		builder, err := NewArtifactBuilder(
			ctx,
			EncodingIdentity,
			func(
				_ context.Context,
				_ ChunkDescriptor,
				content io.Reader,
			) error {
				_, err := io.Copy(io.Discard, content)
				return err
			},
		)
		if err != nil {
			t.Fatalf("NewArtifactBuilder(): %v", err)
		}
		cancel()
		if err := builder.Consume(Record{
			Type:    RecordEvent,
			Payload: []byte(`{"v":1}`),
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("Consume(canceled) = %v, want context.Canceled", err)
		}
		if summary, err := builder.Finish(); !errors.Is(
			err,
			context.Canceled,
		) || summary != (ArtifactSummary{}) {
			t.Fatalf(
				"Finish(canceled) = (%#v, %v), want zero/context.Canceled",
				summary,
				err,
			)
		}
	})

	t.Run("during sink", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		sinkCalls := 0
		builder, err := NewArtifactBuilder(
			ctx,
			EncodingIdentity,
			func(
				gotContext context.Context,
				_ ChunkDescriptor,
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
			},
		)
		if err != nil {
			t.Fatalf("NewArtifactBuilder(): %v", err)
		}
		if err := builder.Consume(Record{
			Type:    RecordEvent,
			Payload: []byte(`{"v":1}`),
		}); err != nil {
			t.Fatalf("Consume(): %v", err)
		}
		if summary, err := builder.Finish(); !errors.Is(
			err,
			context.Canceled,
		) || summary != (ArtifactSummary{}) {
			t.Fatalf(
				"Finish(canceled sink) = (%#v, %v), want zero/context.Canceled",
				summary,
				err,
			)
		}
		if sinkCalls != 1 {
			t.Fatalf("sink calls = %d, want 1", sinkCalls)
		}
	})
}

func TestArtifactBuilderPropagatesWriterAndSinkFailures(t *testing.T) {
	t.Parallel()

	writerFailure := errors.New("destination write failed")
	sinkFailure := errors.New("chunk sink failed")
	tests := []struct {
		name string
		sink ArtifactChunkSink
		want error
	}{
		{
			name: "writer error",
			sink: func(
				_ context.Context,
				_ ChunkDescriptor,
				content io.Reader,
			) error {
				_, err := io.Copy(
					artifactFailWriter{err: writerFailure},
					content,
				)
				return err
			},
			want: writerFailure,
		},
		{
			name: "short writer",
			sink: func(
				_ context.Context,
				_ ChunkDescriptor,
				content io.Reader,
			) error {
				_, err := io.Copy(artifactShortWriter{}, content)
				return err
			},
			want: io.ErrShortWrite,
		},
		{
			name: "short sink",
			sink: func(
				_ context.Context,
				_ ChunkDescriptor,
				content io.Reader,
			) error {
				var one [1]byte
				_, err := content.Read(one[:])
				return err
			},
			want: io.ErrShortWrite,
		},
		{
			name: "sink error",
			sink: func(
				_ context.Context,
				_ ChunkDescriptor,
				_ io.Reader,
			) error {
				return sinkFailure
			},
			want: sinkFailure,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			builder := mustArtifactBuilder(t, test.sink)
			if err := builder.Consume(Record{
				Type:    RecordEvent,
				Payload: []byte(`{"v":1}`),
			}); err != nil {
				t.Fatalf("Consume(): %v", err)
			}
			summary, err := builder.Finish()
			if !errors.Is(err, test.want) {
				t.Fatalf("Finish() error = %v, want %v", err, test.want)
			}
			if summary != (ArtifactSummary{}) {
				t.Fatalf(
					"Finish() summary = %#v, want no partial summary",
					summary,
				)
			}
			if again, againErr := builder.Finish(); !errors.Is(
				againErr,
				test.want,
			) || again != (ArtifactSummary{}) {
				t.Fatalf(
					"Finish(second) = (%#v, %v), want zero/%v",
					again,
					againErr,
					test.want,
				)
			}
		})
	}
}

func TestArtifactBuilderLargeStreamingHistory(t *testing.T) {
	t.Parallel()

	const (
		recordCount  = 6_000
		payloadBytes = 4 << 10
	)
	payload := artifactPayloadOfLength(t, payloadBytes)
	var (
		sinkChunkCount uint64
		sinkBytes      uint64
		maxChunkBytes  uint64
	)
	builder := mustArtifactBuilder(t, func(
		_ context.Context,
		descriptor ChunkDescriptor,
		content io.Reader,
	) error {
		if descriptor.ChunkIndex != sinkChunkCount {
			return errors.New("noncontiguous descriptor")
		}
		if descriptor.CompressedLength == 0 ||
			descriptor.CompressedLength > MaxChunkCompressedBytes ||
			descriptor.ExpandedLength != descriptor.CompressedLength {
			return errors.New("invalid identity descriptor length")
		}
		hash := sha256.New()
		written, err := io.Copy(hash, content)
		if err != nil {
			return err
		}
		if uint64(written) != descriptor.CompressedLength {
			return io.ErrShortWrite
		}
		var digest chain.Digest
		copy(digest[:], hash.Sum(nil))
		if digest != descriptor.SHA256 {
			return errors.New("chunk digest mismatch")
		}
		sinkChunkCount++
		sinkBytes += uint64(written)
		if uint64(written) > maxChunkBytes {
			maxChunkBytes = uint64(written)
		}
		return nil
	})
	for index := 0; index < recordCount; index++ {
		if err := builder.Consume(Record{
			Type:    RecordProjection,
			Payload: payload,
		}); err != nil {
			t.Fatalf("Consume(%d): %v", index, err)
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	wantRecordBytes := uint64(
		10 + len(RecordProjection) + len(payload),
	)
	wantBytes := uint64(recordCount) * wantRecordBytes
	if summary.RecordCount != recordCount ||
		summary.ExpandedBytes != wantBytes ||
		summary.CompressedBytes != wantBytes ||
		summary.ChunkCount != sinkChunkCount ||
		sinkBytes != wantBytes {
		t.Fatalf(
			"summary = %#v, sink chunks/bytes = %d/%d, want records/bytes = %d/%d",
			summary,
			sinkChunkCount,
			sinkBytes,
			recordCount,
			wantBytes,
		)
	}
	if sinkChunkCount < 5 {
		t.Fatalf("sink chunk count = %d, want at least 5", sinkChunkCount)
	}
	if maxChunkBytes > MaxChunkCompressedBytes {
		t.Fatalf(
			"largest chunk = %d, limit %d",
			maxChunkBytes,
			MaxChunkCompressedBytes,
		)
	}
}

func TestArtifactBuilderCarriesLargeMutationContinuationStream(
	t *testing.T,
) {
	t.Parallel()

	fixture := newSemanticFixture(t, false, nil)
	existing, err := DecodeResultPayload(fixture.records[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload, encodedMutations, err := NewResultPayload(
		existing.Result,
		largeSemanticLeaseMutations(256),
	)
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{{
		Type:    RecordResult,
		Payload: mustEncodeResultPayload(t, payload),
	}}
	for offset := 0; offset < len(encodedMutations); {
		end := min(offset+MaxMutationChunkBytes, len(encodedMutations))
		records = append(records, Record{
			Type: RecordMutation,
			Payload: mustEncodeMutationChunkPayload(
				t,
				MutationChunkPayload{
					ResultIndex: payload.Result.ResultIndex,
					ChunkIndex: uint64(
						offset / MaxMutationChunkBytes,
					),
					Data: encodedMutations[offset:end],
				},
			),
		})
		offset = end
	}

	var artifact bytes.Buffer
	builder := mustArtifactBuilder(t, func(
		_ context.Context,
		descriptor ChunkDescriptor,
		content io.Reader,
	) error {
		if descriptor.CompressedLength > MaxChunkCompressedBytes ||
			descriptor.ExpandedLength > MaxChunkExpandedBytes {
			return ErrRecordTooLarge
		}
		_, err := io.Copy(&artifact, content)
		return err
	})
	for _, record := range records {
		if err := builder.Consume(record); err != nil {
			t.Fatalf("Consume(%s): %v", record.Type, err)
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if summary.RecordCount != uint64(len(records)) ||
		summary.ChunkCount < 2 ||
		summary.ExpandedBytes != uint64(artifact.Len()) ||
		summary.ArtifactDigest != sha256.Sum256(artifact.Bytes()) {
		t.Fatalf("summary = %#v for %d records", summary, len(records))
	}

	reader := NewRecordReader(bytes.NewReader(artifact.Bytes()))
	var reconstructed []byte
	for index := range records {
		record, err := reader.Next()
		if err != nil {
			t.Fatalf("Next(%d): %v", index, err)
		}
		if index == 0 {
			if record.Type != RecordResult {
				t.Fatalf("record 0 type = %s", record.Type)
			}
			continue
		}
		if record.Type != RecordMutation {
			t.Fatalf("record %d type = %s", index, record.Type)
		}
		chunk, err := DecodeMutationChunkPayload(record.Payload)
		if err != nil {
			t.Fatalf("DecodeMutationChunkPayload(%d): %v", index, err)
		}
		reconstructed = append(reconstructed, chunk.Data...)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next(after records) = %v, want EOF", err)
	}
	if !bytes.Equal(reconstructed, encodedMutations) {
		t.Fatal("artifact changed the exact mutation encoding")
	}
}

func mustArtifactBuilder(
	t *testing.T,
	sink ArtifactChunkSink,
) *ArtifactBuilder {
	t.Helper()
	builder, err := NewArtifactBuilder(
		context.Background(),
		EncodingIdentity,
		sink,
	)
	if err != nil {
		t.Fatalf("NewArtifactBuilder(): %v", err)
	}
	return builder
}

func artifactPayloadOfLength(t *testing.T, length int) []byte {
	t.Helper()
	const prefix = `{"v":"`
	const suffix = `"}`
	if length < len(prefix)+len(suffix) {
		t.Fatalf("payload length %d is below object minimum", length)
	}
	return []byte(
		prefix +
			strings.Repeat(
				"a",
				length-len(prefix)-len(suffix),
			) +
			suffix,
	)
}

func countArtifactRecords(t *testing.T, encoded []byte) int {
	t.Helper()
	reader := NewRecordReader(bytes.NewReader(encoded))
	count := 0
	for {
		_, err := reader.Next()
		switch {
		case errors.Is(err, io.EOF):
			return count
		case err != nil:
			t.Fatalf("Next(record %d): %v", count, err)
		default:
			count++
		}
	}
}

type artifactFailWriter struct {
	err error
}

func (writer artifactFailWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

type artifactShortWriter struct{}

func (artifactShortWriter) Write([]byte) (int, error) {
	return 0, nil
}
