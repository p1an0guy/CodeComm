package logicalsnapshot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ijonahch/codecomm/internal/chain"
)

var (
	ErrInvalidArtifactReplay = errors.New(
		"logicalsnapshot: invalid artifact replay",
	)
	ErrArtifactReplayIntegrity = errors.New(
		"logicalsnapshot: artifact replay integrity failure",
	)
)

// DescriptorPageSource opens one canonical descriptor page by zero-based
// index. The caller closes every non-nil reader.
type DescriptorPageSource func(
	context.Context,
	uint64,
) (io.ReadCloser, error)

// ArtifactChunkSource opens one transmitted chunk by zero-based index. The
// caller closes every non-nil reader.
type ArtifactChunkSource func(
	context.Context,
	uint64,
) (io.ReadCloser, error)

// ArtifactRecordSink consumes one structurally verified record
// synchronously. It should write only to quarantined staging state: authority
// and reducer verification are intentionally performed by the import layer.
type ArtifactRecordSink func(context.Context, Record) error

// ArtifactReplayOptions binds caller-owned sources, file-backed sequence
// scratch, and the expected root-signing identity.
type ArtifactReplayOptions struct {
	SignerPublicKey []byte
	SequenceScratch VerificationScratch
	OpenPage        DescriptorPageSource
	OpenChunk       ArtifactChunkSource
	RecordSink      ArtifactRecordSink
}

// ArtifactReplaySummary contains independently measured expanded-stream
// totals. It is returned only after every signed commitment has matched.
type ArtifactReplaySummary struct {
	ExpandedBytes  uint64
	RecordCount    uint64
	ArtifactDigest chain.Digest
}

// ReplayArtifact verifies a signed root, its complete descriptor chain, every
// transmitted chunk, and the expanded semantic record sequence. V1 emits and
// accepts identity-encoded artifacts; other named codecs fail closed until
// bounded streaming decoders are implemented.
func ReplayArtifact(
	ctx context.Context,
	root Root,
	options ArtifactReplayOptions,
) (ArtifactReplaySummary, error) {
	if ctx == nil ||
		len(options.SignerPublicKey) != ed25519.PublicKeySize ||
		options.SequenceScratch == nil ||
		options.OpenPage == nil ||
		options.OpenChunk == nil ||
		options.RecordSink == nil {
		return ArtifactReplaySummary{}, ErrInvalidArtifactReplay
	}
	if err := ctx.Err(); err != nil {
		return ArtifactReplaySummary{}, err
	}
	if err := VerifyRoot(root, options.SignerPublicKey); err != nil {
		return ArtifactReplaySummary{}, replayIntegrity(
			"verify signed root",
			err,
		)
	}
	return verifyArtifactTransport(
		ctx,
		root,
		artifactTransportVerificationOptions{
			SequenceScratch: options.SequenceScratch,
			OpenPage:        options.OpenPage,
			OpenChunk:       options.OpenChunk,
			RecordSink:      options.RecordSink,
		},
	)
}

type artifactTransportVerificationOptions struct {
	SequenceScratch VerificationScratch
	OpenPage        DescriptorPageSource
	OpenChunk       ArtifactChunkSource
	RecordSink      ArtifactRecordSink
	ExpandedSink    io.Writer
}

func verifyArtifactTransport(
	ctx context.Context,
	root Root,
	options artifactTransportVerificationOptions,
) (ArtifactReplaySummary, error) {
	if ctx == nil ||
		options.SequenceScratch == nil ||
		options.OpenPage == nil ||
		options.OpenChunk == nil {
		return ArtifactReplaySummary{}, ErrInvalidArtifactReplay
	}
	if err := ctx.Err(); err != nil {
		return ArtifactReplaySummary{}, err
	}
	if err := root.validate(); err != nil {
		return ArtifactReplaySummary{}, err
	}
	input := root.Unsigned().Input()
	if input.ContentEncoding != EncodingIdentity {
		return ArtifactReplaySummary{}, ErrUnsupportedCodec
	}

	sequence, err := NewSequenceValidator(
		root,
		options.SequenceScratch,
	)
	if err != nil {
		return ArtifactReplaySummary{}, replayIntegrity(
			"construct sequence validator",
			err,
		)
	}
	artifactHash := sha256.New()
	var expandedBytes uint64
	var recordCount uint64

	manifest, err := NewManifestValidator(
		root,
		func(descriptor ChunkDescriptor) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			content, err := readReplaySource(
				ctx,
				fmt.Sprintf("chunk %d", descriptor.ChunkIndex),
				descriptor.CompressedLength,
				func() (io.ReadCloser, error) {
					return options.OpenChunk(
						ctx,
						descriptor.ChunkIndex,
					)
				},
			)
			if err != nil {
				return err
			}
			if uint64(len(content)) != descriptor.CompressedLength ||
				descriptor.ExpandedLength !=
					descriptor.CompressedLength ||
				sha256.Sum256(content) != descriptor.SHA256 {
				return replayIntegrity(
					fmt.Sprintf(
						"chunk %d differs from descriptor",
						descriptor.ChunkIndex,
					),
					nil,
				)
			}
			if options.ExpandedSink != nil {
				if err := writeAll(options.ExpandedSink, content); err != nil {
					return fmt.Errorf(
						"logicalsnapshot: write expanded chunk %d: %w",
						descriptor.ChunkIndex,
						err,
					)
				}
			}
			if _, err := artifactHash.Write(content); err != nil {
				return fmt.Errorf(
					"logicalsnapshot: hash chunk %d: %w",
					descriptor.ChunkIndex,
					err,
				)
			}

			reader := NewRecordReader(bytes.NewReader(content))
			for {
				record, err := reader.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return replayIntegrity(
						fmt.Sprintf(
							"decode chunk %d record %d",
							descriptor.ChunkIndex,
							recordCount,
						),
						err,
					)
				}
				if recordCount >= input.RecordCount {
					return replayIntegrity(
						"record count exceeds signed root",
						nil,
					)
				}
				if err := sequence.Consume(record); err != nil {
					return replayIntegrity(
						fmt.Sprintf(
							"validate record %d",
							recordCount,
						),
						err,
					)
				}
				if options.RecordSink != nil {
					if err := options.RecordSink(ctx, record); err != nil {
						return fmt.Errorf(
							"logicalsnapshot: stage record %d: %w",
							recordCount,
							err,
						)
					}
				}
				recordCount++
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			expandedBytes += uint64(len(content))
			return nil
		},
	)
	if err != nil {
		return ArtifactReplaySummary{}, err
	}

	for pageIndex := uint64(0); pageIndex < input.DescriptorPageCount; pageIndex++ {
		if err := ctx.Err(); err != nil {
			return ArtifactReplaySummary{}, err
		}
		encoded, err := readReplaySource(
			ctx,
			fmt.Sprintf("descriptor page %d", pageIndex),
			MaxDescriptorPageBytes,
			func() (io.ReadCloser, error) {
				return options.OpenPage(ctx, pageIndex)
			},
		)
		if err != nil {
			return ArtifactReplaySummary{}, err
		}
		page, err := ParseDescriptorPage(encoded)
		if err != nil {
			return ArtifactReplaySummary{}, replayIntegrity(
				fmt.Sprintf(
					"parse descriptor page %d",
					pageIndex,
				),
				err,
			)
		}
		if err := manifest.Consume(page); err != nil {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return ArtifactReplaySummary{}, err
			}
			if errors.Is(err, ErrDescriptorSequence) ||
				errors.Is(err, ErrInvalidDescriptor) {
				return ArtifactReplaySummary{}, replayIntegrity(
					fmt.Sprintf(
						"validate descriptor page %d",
						pageIndex,
					),
					err,
				)
			}
			return ArtifactReplaySummary{}, err
		}
	}
	if err := manifest.Finish(); err != nil {
		return ArtifactReplaySummary{}, replayIntegrity(
			"finish descriptor manifest",
			err,
		)
	}
	if expandedBytes != input.ExpandedBytes ||
		recordCount != input.RecordCount {
		return ArtifactReplaySummary{}, replayIntegrity(
			"expanded byte or record count differs from signed root",
			nil,
		)
	}
	if err := sequence.Finish(); err != nil {
		return ArtifactReplaySummary{}, replayIntegrity(
			"finish semantic sequence",
			err,
		)
	}
	var artifactDigest chain.Digest
	copy(artifactDigest[:], artifactHash.Sum(nil))
	if artifactDigest != input.ArtifactDigest {
		return ArtifactReplaySummary{}, replayIntegrity(
			"expanded artifact digest differs from signed root",
			nil,
		)
	}
	if err := ctx.Err(); err != nil {
		return ArtifactReplaySummary{}, err
	}
	return ArtifactReplaySummary{
		ExpandedBytes:  expandedBytes,
		RecordCount:    recordCount,
		ArtifactDigest: artifactDigest,
	}, nil
}

func readReplaySource(
	ctx context.Context,
	name string,
	maxBytes uint64,
	open func() (io.ReadCloser, error),
) (_ []byte, err error) {
	if maxBytes == 0 || maxBytes > uint64(^uint(0)>>1) {
		return nil, ErrInvalidArtifactReplay
	}
	reader, err := open()
	if err != nil {
		return nil, fmt.Errorf(
			"logicalsnapshot: open %s: %w",
			name,
			err,
		)
	}
	if reader == nil {
		return nil, fmt.Errorf(
			"logicalsnapshot: open %s: nil reader",
			name,
		)
	}
	var (
		closeOnce sync.Once
		closeErr  error
	)
	closeReader := func() {
		closeOnce.Do(func() {
			closeErr = reader.Close()
		})
	}
	stopCancelClose := context.AfterFunc(ctx, closeReader)
	defer func() {
		stopCancelClose()
		closeReader()
		if err == nil && closeErr != nil {
			err = fmt.Errorf(
				"logicalsnapshot: close %s: %w",
				name,
				closeErr,
			)
		}
	}()
	limited := &io.LimitedReader{
		R: reader,
		N: int64(maxBytes) + 1,
	}
	content, err := io.ReadAll(limited)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf(
			"logicalsnapshot: read %s: %w",
			name,
			err,
		)
	}
	if uint64(len(content)) > maxBytes {
		return nil, replayIntegrity(
			fmt.Sprintf("%s exceeds its bound", name),
			nil,
		)
	}
	return content, nil
}

func replayIntegrity(detail string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrArtifactReplayIntegrity, detail)
	}
	return fmt.Errorf(
		"%w: %s: %w",
		ErrArtifactReplayIntegrity,
		detail,
		cause,
	)
}
