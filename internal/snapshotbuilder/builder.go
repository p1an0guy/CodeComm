// Package snapshotbuilder composes a verified store record stream into one
// bounded logical-snapshot artifact and signs its root only after replaying
// the exact expanded bytes.
package snapshotbuilder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidOptions = errors.New(
		"snapshotbuilder: invalid options",
	)
	ErrArtifactScratch = errors.New(
		"snapshotbuilder: expanded artifact scratch failure",
	)
	ErrArtifactReplay = errors.New(
		"snapshotbuilder: expanded artifact replay failure",
	)
	ErrSourceCut = errors.New(
		"snapshotbuilder: record source returned a mismatched cut",
	)
	ErrRootSigner = errors.New(
		"snapshotbuilder: invalid root signer result",
	)
)

// Scratch is caller-owned bounded temporary storage. ArtifactScratch and
// SequenceScratch must be distinct.
type Scratch interface {
	io.Reader
	io.Writer
	io.Seeker
}

// RecordSource provides one stable, integrity-verified checkpoint stream.
type RecordSource interface {
	ExportLogicalSnapshotRecords(
		context.Context,
		store.LogicalSnapshotExportOptions,
		store.LogicalSnapshotRecordSink,
	) (store.LogicalSnapshotCut, error)
}

// RootSigner signs one fully validated snapshot-root preimage.
type RootSigner func(
	context.Context,
	logicalsnapshot.UnsignedRoot,
) (logicalsnapshot.Root, error)

// Options binds artifact storage, checkpoint selection, and root identity.
type Options struct {
	ArtifactID        string
	CheckpointEventID domain.UUIDv7
	SignerDeviceID    domain.DeviceID
	SignerPublicKey   ed25519.PublicKey

	ArtifactScratch Scratch
	SequenceScratch Scratch
	ChunkSink       logicalsnapshot.ArtifactChunkSink
	PageSink        logicalsnapshot.DescriptorPageSink
	SignRoot        RootSigner
}

// Snapshot contains the signed root and the exact independently derived
// artifact/page summaries. Chunks and pages remain owned by caller sinks.
type Snapshot struct {
	Root     logicalsnapshot.Root
	Cut      store.LogicalSnapshotCut
	Artifact logicalsnapshot.ArtifactSummary
	Manifest logicalsnapshot.ManifestSummary
}

// Build streams, replays, and signs one identity-encoded snapshot. Failed
// builds may leave unreferenced quarantined chunks/pages; no signed root is
// returned for them.
func Build(
	ctx context.Context,
	source RecordSource,
	options Options,
) (Snapshot, error) {
	if err := validateOptions(ctx, source, options); err != nil {
		return Snapshot{}, err
	}
	signerPublicKey := bytes.Clone(options.SignerPublicKey)
	if err := resetArtifactScratch(options.ArtifactScratch); err != nil {
		return Snapshot{}, fmt.Errorf(
			"%w: reset for write: %v",
			ErrArtifactScratch,
			err,
		)
	}

	manifest, err := logicalsnapshot.NewManifestBuilder(
		ctx,
		options.ArtifactID,
		options.PageSink,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: manifest: %v", ErrInvalidOptions, err)
	}
	var scratchBytes uint64
	artifact, err := logicalsnapshot.NewArtifactBuilder(
		ctx,
		logicalsnapshot.EncodingIdentity,
		func(
			sinkContext context.Context,
			descriptor logicalsnapshot.ChunkDescriptor,
			content io.Reader,
		) error {
			chunk, err := readArtifactChunk(content)
			if err != nil {
				return err
			}
			if uint64(len(chunk)) != descriptor.ExpandedLength ||
				descriptor.ExpandedLength !=
					descriptor.CompressedLength ||
				sha256.Sum256(chunk) != descriptor.SHA256 {
				return fmt.Errorf(
					"%w: chunk %d differs from descriptor",
					ErrArtifactScratch,
					descriptor.ChunkIndex,
				)
			}
			if scratchBytes >
				domain.MaxSafeInteger-descriptor.ExpandedLength {
				return fmt.Errorf(
					"%w: expanded byte count exceeds exact range",
					ErrArtifactScratch,
				)
			}
			if err := writeAll(options.ArtifactScratch, chunk); err != nil {
				return fmt.Errorf(
					"%w: write chunk %d: %v",
					ErrArtifactScratch,
					descriptor.ChunkIndex,
					err,
				)
			}
			scratchBytes += descriptor.ExpandedLength

			reader := bytes.NewReader(chunk)
			if err := options.ChunkSink(
				sinkContext,
				descriptor,
				reader,
			); err != nil {
				return fmt.Errorf(
					"snapshotbuilder: persist chunk %d: %w",
					descriptor.ChunkIndex,
					err,
				)
			}
			if reader.Len() != 0 {
				return fmt.Errorf(
					"snapshotbuilder: persist chunk %d: %w",
					descriptor.ChunkIndex,
					io.ErrShortWrite,
				)
			}
			if err := manifest.Consume(descriptor); err != nil {
				return fmt.Errorf(
					"snapshotbuilder: append chunk %d descriptor: %w",
					descriptor.ChunkIndex,
					err,
				)
			}
			return sinkContext.Err()
		},
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: artifact: %v", ErrInvalidOptions, err)
	}

	cut, err := source.ExportLogicalSnapshotRecords(
		ctx,
		store.LogicalSnapshotExportOptions{
			CheckpointEventID: options.CheckpointEventID,
			SignerDeviceID:    options.SignerDeviceID,
		},
		func(
			_ context.Context,
			record logicalsnapshot.Record,
		) error {
			return artifact.Consume(record)
		},
	)
	if err != nil {
		return Snapshot{}, err
	}
	if cut.CheckpointEventID != options.CheckpointEventID ||
		cut.SignerDeviceID != options.SignerDeviceID {
		return Snapshot{}, ErrSourceCut
	}
	artifactSummary, err := artifact.Finish()
	if err != nil {
		return Snapshot{}, err
	}
	manifestSummary, err := manifest.Finish()
	if err != nil {
		return Snapshot{}, err
	}
	if artifactSummary.RecordCount != cut.RecordCount ||
		artifactSummary.ExpandedBytes != scratchBytes {
		return Snapshot{}, fmt.Errorf(
			"%w: store, artifact, and scratch counts differ",
			ErrArtifactScratch,
		)
	}

	unsigned, err := logicalsnapshot.NewUnsignedRoot(
		logicalsnapshot.RootInput{
			ArtifactID:              options.ArtifactID,
			SessionID:               cut.SessionID,
			WorkspaceID:             cut.WorkspaceID,
			RecoveryGeneration:      cut.RecoveryGeneration,
			CheckpointEventID:       cut.CheckpointEventID,
			ChainIndex:              cut.ChainIndex,
			ChainHash:               chain.Digest(cut.ChainHash),
			ResultIndex:             cut.ResultIndex,
			ResultHash:              chain.Digest(cut.ResultHash),
			ProjectionAccumulator:   chain.Digest(cut.ProjectionAccumulator),
			ProjectionStateDigest:   chain.Digest(cut.ProjectionStateDigest),
			AuthorityVersion:        cut.AuthorityVersion,
			SignerDeviceID:          cut.SignerDeviceID,
			DigestVersion:           cut.DigestVersion,
			ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
			ContentEncoding:         artifactSummary.ContentEncoding,
			ExpandedBytes:           artifactSummary.ExpandedBytes,
			CompressedBytes:         artifactSummary.CompressedBytes,
			RecordCount:             artifactSummary.RecordCount,
			DescriptorPageCount:     manifestSummary.DescriptorPageCount,
			ChunkCount:              artifactSummary.ChunkCount,
			ArtifactDigest:          artifactSummary.ArtifactDigest,
			FinalDescriptorPageHash: manifestSummary.FinalDescriptorPageHash,
		},
	)
	if err != nil {
		return Snapshot{}, err
	}
	if err := replayArtifact(
		unsigned,
		options.ArtifactScratch,
		options.SequenceScratch,
	); err != nil {
		return Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}

	root, err := options.SignRoot(ctx, unsigned)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrRootSigner, err)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !bytes.Equal(
		root.Unsigned().CanonicalBytes(),
		unsigned.CanonicalBytes(),
	) {
		return Snapshot{}, fmt.Errorf(
			"%w: signer changed root preimage",
			ErrRootSigner,
		)
	}
	if err := logicalsnapshot.VerifyRoot(
		root,
		signerPublicKey,
	); err != nil {
		return Snapshot{}, fmt.Errorf(
			"%w: verify signature: %v",
			ErrRootSigner,
			err,
		)
	}
	return Snapshot{
		Root:     root,
		Cut:      cut,
		Artifact: artifactSummary,
		Manifest: manifestSummary,
	}, nil
}

func validateOptions(
	ctx context.Context,
	source RecordSource,
	options Options,
) error {
	if ctx == nil ||
		isNilInterface(source) ||
		!options.CheckpointEventID.Valid() ||
		!options.SignerDeviceID.Valid() ||
		len(options.SignerPublicKey) != ed25519.PublicKeySize ||
		isNilInterface(options.ArtifactScratch) ||
		isNilInterface(options.SequenceScratch) ||
		options.ChunkSink == nil ||
		options.PageSink == nil ||
		options.SignRoot == nil ||
		sameScratch(options.ArtifactScratch, options.SequenceScratch) {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	signerID, err := device.DeriveID(options.SignerPublicKey)
	if err != nil || signerID != options.SignerDeviceID {
		return fmt.Errorf(
			"%w: signer public key differs from device ID",
			ErrInvalidOptions,
		)
	}
	return nil
}

func readArtifactChunk(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: nil chunk reader", ErrArtifactScratch)
	}
	limited := &io.LimitedReader{
		R: reader,
		N: int64(logicalsnapshot.MaxChunkCompressedBytes) + 1,
	}
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: read chunk: %v", ErrArtifactScratch, err)
	}
	if len(content) == 0 ||
		len(content) > logicalsnapshot.MaxChunkCompressedBytes {
		return nil, fmt.Errorf(
			"%w: chunk exceeds expanded bound",
			ErrArtifactScratch,
		)
	}
	return content, nil
}

func replayArtifact(
	unsigned logicalsnapshot.UnsignedRoot,
	artifactScratch Scratch,
	sequenceScratch Scratch,
) error {
	input := unsigned.Input()
	if _, err := artifactScratch.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf(
			"%w: seek expanded artifact: %v",
			ErrArtifactReplay,
			err,
		)
	}
	provisional, err := logicalsnapshot.NewRoot(
		unsigned,
		[ed25519.SignatureSize]byte{},
	)
	if err != nil {
		return fmt.Errorf("%w: provisional root: %v", ErrArtifactReplay, err)
	}
	validator, err := logicalsnapshot.NewSequenceValidator(
		provisional,
		sequenceScratch,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: construct sequence validator: %v",
			ErrArtifactReplay,
			err,
		)
	}

	limited := &io.LimitedReader{
		R: artifactScratch,
		N: int64(input.ExpandedBytes),
	}
	hasher := sha256.New()
	reader := logicalsnapshot.NewRecordReader(io.TeeReader(limited, hasher))
	var recordCount uint64
	for {
		record, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf(
				"%w: decode record %d: %v",
				ErrArtifactReplay,
				recordCount,
				err,
			)
		}
		if err := validator.Consume(record); err != nil {
			return fmt.Errorf(
				"%w: validate record %d: %v",
				ErrArtifactReplay,
				recordCount,
				err,
			)
		}
		recordCount++
	}
	if limited.N != 0 ||
		recordCount != input.RecordCount {
		return fmt.Errorf(
			"%w: expanded byte or record count differs",
			ErrArtifactReplay,
		)
	}
	var trailing [1]byte
	trailingBytes, trailingErr := artifactScratch.Read(trailing[:])
	if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) {
		return fmt.Errorf(
			"%w: expanded scratch has trailing bytes",
			ErrArtifactReplay,
		)
	}
	var digest chain.Digest
	copy(digest[:], hasher.Sum(nil))
	if digest != input.ArtifactDigest {
		return fmt.Errorf(
			"%w: expanded artifact digest differs",
			ErrArtifactReplay,
		)
	}
	if err := validator.Finish(); err != nil {
		return fmt.Errorf(
			"%w: finish semantic sequence: %v",
			ErrArtifactReplay,
			err,
		)
	}
	return nil
}

func resetArtifactScratch(scratch Scratch) error {
	if truncater, ok := scratch.(interface {
		Truncate(int64) error
	}); ok {
		if err := truncater.Truncate(0); err != nil {
			return err
		}
	}
	_, err := scratch.Seek(0, io.SeekStart)
	return err
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written < 1 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func sameScratch(left, right Scratch) bool {
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if !leftValue.IsValid() || !rightValue.IsValid() ||
		leftValue.Type() != rightValue.Type() {
		return sameScratchFile(left, right)
	}
	switch leftValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		if leftValue.Pointer() == rightValue.Pointer() {
			return true
		}
		return sameScratchFile(left, right)
	default:
		if leftValue.Type().Comparable() &&
			leftValue.Interface() == rightValue.Interface() {
			return true
		}
		return sameScratchFile(left, right)
	}
}

func sameScratchFile(left, right Scratch) bool {
	leftFile, leftOK := left.(interface {
		Stat() (os.FileInfo, error)
	})
	rightFile, rightOK := right.(interface {
		Stat() (os.FileInfo, error)
	})
	if !leftOK || !rightOK {
		return false
	}
	leftInfo, leftErr := leftFile.Stat()
	rightInfo, rightErr := rightFile.Stat()
	return leftErr == nil &&
		rightErr == nil &&
		os.SameFile(leftInfo, rightInfo)
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
