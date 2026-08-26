package logicalsnapshot

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/ijonahch/codecomm/internal/chain"
)

var ErrExpandedArtifactIntegrity = errors.New(
	"logicalsnapshot: expanded artifact integrity failure",
)

// ExpandedArtifact is caller-owned, truncatable storage for the exact
// expanded record stream reconstructed from verified transmitted chunks.
type ExpandedArtifact interface {
	io.Reader
	io.Writer
	io.Seeker
	Truncate(int64) error
}

// VerificationScratch is caller-owned, truncatable file-backed scratch used
// by the structural sequence validator.
type VerificationScratch interface {
	io.Reader
	io.Writer
	io.Seeker
	Truncate(int64) error
}

// ArtifactVerificationOptions binds the complete transport artifact to
// distinct caller-owned expanded and sequence quarantine storage.
type ArtifactVerificationOptions struct {
	ExpandedArtifact ExpandedArtifact
	SequenceScratch  VerificationScratch
	OpenPage         DescriptorPageSource
	OpenChunk        ArtifactChunkSource
}

// VerifiedExpandedArtifact is an opaque proof that one exact root was matched
// against its descriptor chain, chunks, and expanded semantic record stream.
// Root-signature authorization is intentionally checked against replayed
// membership by the import layer. The zero value is invalid.
type VerifiedExpandedArtifact struct {
	rootDigest     chain.Digest
	artifactDigest chain.Digest
	expandedBytes  uint64
	recordCount    uint64
	valid          bool
}

// VerifyExpandedArtifact verifies one already-expanded record stream against
// the signed root. It is used by transports, such as Raft snapshots, that
// authenticate and digest one contiguous expanded payload instead of carrying
// the descriptor-page/chunk representation.
func VerifyExpandedArtifact(
	ctx context.Context,
	root Root,
	expanded ExpandedArtifact,
	sequenceScratch VerificationScratch,
) (VerifiedExpandedArtifact, error) {
	if ctx == nil ||
		isNilArtifactScratch(expanded) ||
		isNilArtifactScratch(sequenceScratch) ||
		sameArtifactScratch(expanded, sequenceScratch) {
		return VerifiedExpandedArtifact{}, ErrInvalidArtifactReplay
	}
	if err := ctx.Err(); err != nil {
		return VerifiedExpandedArtifact{}, err
	}
	if err := root.validate(); err != nil {
		return VerifiedExpandedArtifact{}, err
	}
	if err := resetArtifactVerificationScratch(sequenceScratch); err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: reset sequence scratch: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}
	if _, err := expanded.Seek(0, io.SeekStart); err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: rewind expanded artifact: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}

	input := root.Unsigned().Input()
	limited := &io.LimitedReader{
		R: expanded,
		N: int64(input.ExpandedBytes),
	}
	hasher := sha256.New()
	records := NewRecordReader(io.TeeReader(limited, hasher))
	sequence, err := NewSequenceValidator(root, sequenceScratch)
	if err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: construct sequence validator: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}
	var recordCount uint64
	for {
		if err := ctx.Err(); err != nil {
			return VerifiedExpandedArtifact{}, err
		}
		record, err := records.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return VerifiedExpandedArtifact{}, fmt.Errorf(
				"%w: decode record %d: %v",
				ErrExpandedArtifactIntegrity,
				recordCount,
				err,
			)
		}
		if recordCount >= input.RecordCount {
			return VerifiedExpandedArtifact{}, fmt.Errorf(
				"%w: record count exceeds signed root",
				ErrExpandedArtifactIntegrity,
			)
		}
		if err := sequence.Consume(record); err != nil {
			return VerifiedExpandedArtifact{}, fmt.Errorf(
				"%w: validate record %d: %v",
				ErrExpandedArtifactIntegrity,
				recordCount,
				err,
			)
		}
		recordCount++
	}
	if err := sequence.Finish(); err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: finish record sequence: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}
	var trailing [1]byte
	trailingBytes, trailingErr := expanded.Read(trailing[:])
	var artifactDigest chain.Digest
	copy(artifactDigest[:], hasher.Sum(nil))
	if limited.N != 0 ||
		recordCount != input.RecordCount ||
		artifactDigest != input.ArtifactDigest ||
		trailingBytes != 0 ||
		!errors.Is(trailingErr, io.EOF) {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: expanded stream differs from signed root",
			ErrExpandedArtifactIntegrity,
		)
	}
	return VerifiedExpandedArtifact{
		rootDigest:     sha256.Sum256(root.CanonicalBytes()),
		artifactDigest: artifactDigest,
		expandedBytes:  input.ExpandedBytes,
		recordCount:    recordCount,
		valid:          true,
	}, nil
}

// VerifyAndExpandArtifact verifies every descriptor page and transmitted
// chunk, reconstructs the exact expanded stream in quarantine, and returns a
// root-bound proof only after all structural commitments match. Root signer
// authorization remains deferred until replayed membership is available.
func VerifyAndExpandArtifact(
	ctx context.Context,
	root Root,
	options ArtifactVerificationOptions,
) (VerifiedExpandedArtifact, error) {
	if ctx == nil ||
		isNilArtifactScratch(options.ExpandedArtifact) ||
		isNilArtifactScratch(options.SequenceScratch) ||
		options.OpenPage == nil ||
		options.OpenChunk == nil ||
		sameArtifactScratch(
			options.ExpandedArtifact,
			options.SequenceScratch,
		) {
		return VerifiedExpandedArtifact{}, ErrInvalidArtifactReplay
	}
	if err := ctx.Err(); err != nil {
		return VerifiedExpandedArtifact{}, err
	}
	if err := root.validate(); err != nil {
		return VerifiedExpandedArtifact{}, err
	}
	if err := resetArtifactVerificationScratch(
		options.ExpandedArtifact,
	); err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: reset expanded artifact: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}
	if err := resetArtifactVerificationScratch(
		options.SequenceScratch,
	); err != nil {
		return VerifiedExpandedArtifact{}, fmt.Errorf(
			"%w: reset sequence scratch: %v",
			ErrExpandedArtifactIntegrity,
			err,
		)
	}
	summary, err := verifyArtifactTransport(
		ctx,
		root,
		artifactTransportVerificationOptions{
			SequenceScratch: options.SequenceScratch,
			OpenPage:        options.OpenPage,
			OpenChunk:       options.OpenChunk,
			ExpandedSink:    options.ExpandedArtifact,
		},
	)
	if err != nil {
		if errors.Is(err, ErrArtifactReplayIntegrity) {
			return VerifiedExpandedArtifact{}, fmt.Errorf(
				"%w: %w",
				ErrExpandedArtifactIntegrity,
				err,
			)
		}
		return VerifiedExpandedArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedExpandedArtifact{}, err
	}
	return VerifiedExpandedArtifact{
		rootDigest:     sha256.Sum256(root.CanonicalBytes()),
		artifactDigest: summary.ArtifactDigest,
		expandedBytes:  summary.ExpandedBytes,
		recordCount:    summary.RecordCount,
		valid:          true,
	}, nil
}

// MatchesRoot reports whether this proof was minted for the exact canonical
// signed root and its expanded-stream commitments.
func (verified VerifiedExpandedArtifact) MatchesRoot(root Root) bool {
	if !verified.valid || root.validate() != nil {
		return false
	}
	input := root.Unsigned().Input()
	return verified.rootDigest == sha256.Sum256(root.CanonicalBytes()) &&
		verified.artifactDigest == input.ArtifactDigest &&
		verified.expandedBytes == input.ExpandedBytes &&
		verified.recordCount == input.RecordCount
}

func resetArtifactVerificationScratch(
	scratch VerificationScratch,
) error {
	if err := scratch.Truncate(0); err != nil {
		return err
	}
	_, err := scratch.Seek(0, io.SeekStart)
	return err
}

func isNilArtifactScratch(value any) bool {
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

func sameArtifactScratch(
	left VerificationScratch,
	right VerificationScratch,
) bool {
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.IsValid() &&
		rightValue.IsValid() &&
		leftValue.Type() == rightValue.Type() {
		switch leftValue.Kind() {
		case reflect.Chan, reflect.Func, reflect.Map,
			reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
			if leftValue.Pointer() == rightValue.Pointer() {
				return true
			}
		default:
			if leftValue.Type().Comparable() &&
				leftValue.Interface() == rightValue.Interface() {
				return true
			}
		}
	}
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
