package logicalsnapshot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"testing"
)

type artifactReplayFixture struct {
	root      Root
	publicKey ed25519.PublicKey
	pages     [][]byte
	chunks    [][]byte
	records   []Record
}

func TestReplayArtifactVerifiesCompleteQuarantinedStream(t *testing.T) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	var staged []Record
	summary, err := ReplayArtifact(
		context.Background(),
		fixture.root,
		replayOptions(
			t,
			fixture,
			func(_ context.Context, record Record) error {
				staged = append(staged, cloneReplayTestRecord(record))
				return nil
			},
		),
	)
	if err != nil {
		t.Fatalf("ReplayArtifact(): %v", err)
	}
	input := fixture.root.Unsigned().Input()
	if summary.ExpandedBytes != input.ExpandedBytes ||
		summary.RecordCount != input.RecordCount ||
		summary.ArtifactDigest != input.ArtifactDigest {
		t.Fatalf("summary = %#v, want root totals", summary)
	}
	if len(staged) != len(fixture.records) {
		t.Fatalf(
			"staged records = %d, want %d",
			len(staged),
			len(fixture.records),
		)
	}
	for index := range staged {
		if staged[index].Type != fixture.records[index].Type ||
			!bytes.Equal(
				staged[index].Payload,
				fixture.records[index].Payload,
			) {
			t.Fatalf("staged record %d differs", index)
		}
	}
}

func TestReplayArtifactSeparatesIntegrityAndOperationalFailures(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*artifactReplayFixture, *ArtifactReplayOptions)
		want      error
		integrity bool
	}{
		{
			name: "wrong root key",
			mutate: func(
				_ *artifactReplayFixture,
				options *ArtifactReplayOptions,
			) {
				privateKey := ed25519.NewKeyFromSeed(
					bytes.Repeat([]byte{0x7f}, ed25519.SeedSize),
				)
				options.SignerPublicKey = privateKey.Public().(ed25519.PublicKey)
			},
			want:      ErrArtifactReplayIntegrity,
			integrity: true,
		},
		{
			name: "noncanonical page",
			mutate: func(
				fixture *artifactReplayFixture,
				_ *ArtifactReplayOptions,
			) {
				fixture.pages[0] = append(
					[]byte(" "),
					fixture.pages[0]...,
				)
			},
			want:      ErrArtifactReplayIntegrity,
			integrity: true,
		},
		{
			name: "changed chunk",
			mutate: func(
				fixture *artifactReplayFixture,
				_ *ArtifactReplayOptions,
			) {
				fixture.chunks[0][len(fixture.chunks[0])-1] ^= 0x01
			},
			want:      ErrArtifactReplayIntegrity,
			integrity: true,
		},
		{
			name: "truncated chunk",
			mutate: func(
				fixture *artifactReplayFixture,
				_ *ArtifactReplayOptions,
			) {
				fixture.chunks[0] = fixture.chunks[0][:len(fixture.chunks[0])-1]
			},
			want:      ErrArtifactReplayIntegrity,
			integrity: true,
		},
		{
			name: "page source",
			mutate: func(
				_ *artifactReplayFixture,
				options *ArtifactReplayOptions,
			) {
				options.OpenPage = func(
					context.Context,
					uint64,
				) (io.ReadCloser, error) {
					return nil, errReplayTestPageSource
				}
			},
			want: errReplayTestPageSource,
		},
		{
			name: "chunk source",
			mutate: func(
				_ *artifactReplayFixture,
				options *ArtifactReplayOptions,
			) {
				options.OpenChunk = func(
					context.Context,
					uint64,
				) (io.ReadCloser, error) {
					return nil, errReplayTestChunkSource
				}
			},
			want: errReplayTestChunkSource,
		},
		{
			name: "record sink",
			mutate: func(
				_ *artifactReplayFixture,
				options *ArtifactReplayOptions,
			) {
				options.RecordSink = func(
					context.Context,
					Record,
				) error {
					return errReplayTestRecordSink
				}
			},
			want: errReplayTestRecordSink,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newArtifactReplayFixture(t)
			options := replayOptions(
				t,
				fixture,
				func(context.Context, Record) error { return nil },
			)
			test.mutate(&fixture, &options)
			summary, err := ReplayArtifact(
				context.Background(),
				fixture.root,
				options,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"ReplayArtifact() = (%#v, %v), want %v",
					summary,
					err,
					test.want,
				)
			}
			if summary != (ArtifactReplaySummary{}) {
				t.Fatalf("failed replay returned summary %#v", summary)
			}
			if errors.Is(err, ErrArtifactReplayIntegrity) !=
				test.integrity {
				t.Fatalf(
					"integrity classification = %t, want %t: %v",
					errors.Is(err, ErrArtifactReplayIntegrity),
					test.integrity,
					err,
				)
			}
		})
	}
}

func TestReplayArtifactRejectsUnsupportedCodecBeforeSources(
	t *testing.T,
) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	input := fixture.root.Unsigned().Input()
	input.ContentEncoding = EncodingGZIP
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	semantic := newSemanticFixture(t, false, semanticProjectionRows())
	root, err := SignRoot(unsigned, semantic.privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}

	options := replayOptions(
		t,
		fixture,
		func(context.Context, Record) error { return nil },
	)
	pageCalls := 0
	options.OpenPage = func(
		context.Context,
		uint64,
	) (io.ReadCloser, error) {
		pageCalls++
		return nil, errors.New("unexpected page source")
	}
	if summary, err := ReplayArtifact(
		context.Background(),
		root,
		options,
	); !errors.Is(err, ErrUnsupportedCodec) ||
		summary != (ArtifactReplaySummary{}) {
		t.Fatalf(
			"ReplayArtifact(gzip) = (%#v, %v), want ErrUnsupportedCodec",
			summary,
			err,
		)
	}
	if pageCalls != 0 {
		t.Fatalf("unsupported codec opened %d pages", pageCalls)
	}
}

func TestReplayArtifactObservesCancellation(t *testing.T) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	options := replayOptions(
		t,
		fixture,
		func(context.Context, Record) error {
			cancel()
			return nil
		},
	)
	summary, err := ReplayArtifact(ctx, fixture.root, options)
	if !errors.Is(err, context.Canceled) ||
		summary != (ArtifactReplaySummary{}) {
		t.Fatalf(
			"ReplayArtifact(canceled) = (%#v, %v), want context.Canceled",
			summary,
			err,
		)
	}
}

func TestReplayArtifactRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	options := replayOptions(
		t,
		fixture,
		func(context.Context, Record) error { return nil },
	)
	options.RecordSink = nil
	if summary, err := ReplayArtifact(
		context.Background(),
		fixture.root,
		options,
	); !errors.Is(err, ErrInvalidArtifactReplay) ||
		summary != (ArtifactReplaySummary{}) {
		t.Fatalf(
			"ReplayArtifact(invalid) = (%#v, %v)",
			summary,
			err,
		)
	}
}

var (
	errReplayTestPageSource  = errors.New("page source failed")
	errReplayTestChunkSource = errors.New("chunk source failed")
	errReplayTestRecordSink  = errors.New("record sink failed")
)

func newArtifactReplayFixture(t *testing.T) artifactReplayFixture {
	t.Helper()

	semantic := newSemanticFixture(t, false, semanticProjectionRows())
	var (
		descriptors []ChunkDescriptor
		chunks      [][]byte
	)
	artifact, err := NewArtifactBuilder(
		context.Background(),
		EncodingIdentity,
		func(
			_ context.Context,
			descriptor ChunkDescriptor,
			content io.Reader,
		) error {
			raw, err := io.ReadAll(content)
			if err != nil {
				return err
			}
			descriptors = append(descriptors, descriptor)
			chunks = append(chunks, bytes.Clone(raw))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewArtifactBuilder(): %v", err)
	}
	for _, record := range semantic.records {
		if err := artifact.Consume(record); err != nil {
			t.Fatalf("artifact.Consume(): %v", err)
		}
	}
	artifactSummary, err := artifact.Finish()
	if err != nil {
		t.Fatalf("artifact.Finish(): %v", err)
	}

	var pages [][]byte
	manifest, err := NewManifestBuilder(
		context.Background(),
		semantic.root.Unsigned().Input().ArtifactID,
		func(
			_ context.Context,
			_ DescriptorPage,
			content io.Reader,
		) error {
			raw, err := io.ReadAll(content)
			if err != nil {
				return err
			}
			pages = append(pages, bytes.Clone(raw))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewManifestBuilder(): %v", err)
	}
	for _, descriptor := range descriptors {
		if err := manifest.Consume(descriptor); err != nil {
			t.Fatalf("manifest.Consume(): %v", err)
		}
	}
	manifestSummary, err := manifest.Finish()
	if err != nil {
		t.Fatalf("manifest.Finish(): %v", err)
	}

	input := semantic.root.Unsigned().Input()
	input.ContentEncoding = artifactSummary.ContentEncoding
	input.ExpandedBytes = artifactSummary.ExpandedBytes
	input.CompressedBytes = artifactSummary.CompressedBytes
	input.RecordCount = artifactSummary.RecordCount
	input.ChunkCount = artifactSummary.ChunkCount
	input.ArtifactDigest = artifactSummary.ArtifactDigest
	input.DescriptorPageCount = manifestSummary.DescriptorPageCount
	input.FinalDescriptorPageHash =
		manifestSummary.FinalDescriptorPageHash
	unsigned, err := NewUnsignedRoot(input)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, semantic.privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	publicKey := semantic.privateKey.Public().(ed25519.PublicKey)
	return artifactReplayFixture{
		root:      root,
		publicKey: bytes.Clone(publicKey),
		pages:     cloneReplayTestBytes(pages),
		chunks:    cloneReplayTestBytes(chunks),
		records:   cloneReplayTestRecords(semantic.records),
	}
}

func replayOptions(
	t *testing.T,
	fixture artifactReplayFixture,
	sink ArtifactRecordSink,
) ArtifactReplayOptions {
	t.Helper()

	scratch, err := os.CreateTemp(t.TempDir(), "artifact-replay-*")
	if err != nil {
		t.Fatalf("os.CreateTemp(): %v", err)
	}
	t.Cleanup(func() {
		if err := scratch.Close(); err != nil {
			t.Errorf("scratch.Close(): %v", err)
		}
	})
	return ArtifactReplayOptions{
		SignerPublicKey: bytes.Clone(fixture.publicKey),
		SequenceScratch: scratch,
		OpenPage: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.pages)) {
				return nil, io.EOF
			}
			return io.NopCloser(
				bytes.NewReader(bytes.Clone(fixture.pages[index])),
			), nil
		},
		OpenChunk: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.chunks)) {
				return nil, io.EOF
			}
			return io.NopCloser(
				bytes.NewReader(bytes.Clone(fixture.chunks[index])),
			), nil
		},
		RecordSink: sink,
	}
}

func cloneReplayTestBytes(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func cloneReplayTestRecord(record Record) Record {
	return Record{
		Type:    record.Type,
		Payload: bytes.Clone(record.Payload),
	}
}

func cloneReplayTestRecords(records []Record) []Record {
	result := make([]Record, len(records))
	for index := range records {
		result[index] = cloneReplayTestRecord(records[index])
	}
	return result
}
