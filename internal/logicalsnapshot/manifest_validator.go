package logicalsnapshot

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrInvalidManifestValidator = errors.New(
		"logicalsnapshot: invalid manifest validator",
	)
	ErrManifestValidationFinished = errors.New(
		"logicalsnapshot: manifest validation is already finished",
	)
)

// ManifestDescriptorSink consumes one descriptor after its containing page
// has been validated against the signed root. The sink is called in chunk
// order and may perform bounded chunk retrieval synchronously.
type ManifestDescriptorSink func(ChunkDescriptor) error

// ManifestValidator incrementally verifies a descriptor-page chain against a
// signed root. It retains only fixed-size counters and one bounded page.
// ManifestValidator is not safe for concurrent use.
type ManifestValidator struct {
	root RootInput
	sink ManifestDescriptorSink

	previousPageHash chain.Digest
	nextPage         uint64
	nextChunk        uint64
	compressedBytes  uint64
	expandedBytes    uint64

	failed   error
	finished bool
}

// NewManifestValidator constructs a streaming descriptor-page validator.
func NewManifestValidator(
	root Root,
	sink ManifestDescriptorSink,
) (*ManifestValidator, error) {
	if err := root.validate(); err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, ErrInvalidManifestValidator
	}
	return &ManifestValidator{
		root: root.Unsigned().Input(),
		sink: sink,
	}, nil
}

// Consume validates one canonical descriptor page and synchronously emits its
// descriptors. Any failure is latched.
func (validator *ManifestValidator) Consume(page DescriptorPage) error {
	if validator == nil || validator.sink == nil {
		return ErrInvalidManifestValidator
	}
	if validator.failed != nil {
		return validator.failed
	}
	if validator.finished {
		return ErrManifestValidationFinished
	}
	if !page.valid || validator.nextPage >= validator.root.DescriptorPageCount {
		return validator.fail(ErrDescriptorSequence)
	}

	input := page.Input()
	if input.ArtifactID != validator.root.ArtifactID ||
		input.PageIndex != validator.nextPage ||
		input.PreviousPageHash != validator.previousPageHash ||
		validator.nextPage+1 < validator.root.DescriptorPageCount &&
			len(input.Descriptors) != MaxDescriptorsPerPage {
		return validator.fail(ErrDescriptorSequence)
	}

	nextChunk := validator.nextChunk
	compressedBytes := validator.compressedBytes
	expandedBytes := validator.expandedBytes
	for _, descriptor := range input.Descriptors {
		if descriptor.ChunkIndex != nextChunk ||
			compressedBytes >
				domain.MaxSafeInteger-descriptor.CompressedLength ||
			expandedBytes >
				domain.MaxSafeInteger-descriptor.ExpandedLength {
			return validator.fail(ErrDescriptorSequence)
		}
		nextChunk++
		compressedBytes += descriptor.CompressedLength
		expandedBytes += descriptor.ExpandedLength
		if nextChunk > validator.root.ChunkCount ||
			compressedBytes > validator.root.CompressedBytes ||
			expandedBytes > validator.root.ExpandedBytes {
			return validator.fail(ErrDescriptorSequence)
		}
	}

	for _, descriptor := range input.Descriptors {
		if err := validator.sink(descriptor); err != nil {
			return validator.fail(err)
		}
	}
	validator.nextChunk = nextChunk
	validator.compressedBytes = compressedBytes
	validator.expandedBytes = expandedBytes
	validator.previousPageHash = page.Hash()
	validator.nextPage++
	return nil
}

// Finish succeeds only when every page, descriptor, byte total, and terminal
// page hash exactly matches the signed root.
func (validator *ManifestValidator) Finish() error {
	if validator == nil || validator.sink == nil {
		return ErrInvalidManifestValidator
	}
	if validator.failed != nil {
		return validator.failed
	}
	if validator.finished {
		return nil
	}
	if validator.nextPage != validator.root.DescriptorPageCount ||
		validator.nextChunk != validator.root.ChunkCount ||
		validator.compressedBytes != validator.root.CompressedBytes ||
		validator.expandedBytes != validator.root.ExpandedBytes ||
		validator.previousPageHash !=
			validator.root.FinalDescriptorPageHash {
		return validator.fail(ErrDescriptorSequence)
	}
	validator.finished = true
	return nil
}

func (validator *ManifestValidator) fail(err error) error {
	if validator.failed == nil {
		if err == nil {
			err = fmt.Errorf(
				"%w: nil failure",
				ErrInvalidManifestValidator,
			)
		}
		validator.failed = err
	}
	return validator.failed
}
