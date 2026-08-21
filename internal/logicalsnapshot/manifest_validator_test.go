package logicalsnapshot

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
)

func TestManifestValidatorStreamsCompleteSignedSequence(t *testing.T) {
	t.Parallel()

	rootInput, privateKey, _ := testRootInput(t)
	descriptors := []ChunkDescriptor{
		manifestDescriptor(0),
		manifestDescriptor(1),
	}
	first, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:  rootInput.ArtifactID,
		PageIndex:   0,
		Descriptors: descriptors,
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(): %v", err)
	}
	rootInput.DescriptorPageCount = 1
	rootInput.ChunkCount = 2
	rootInput.CompressedBytes =
		descriptors[0].CompressedLength +
			descriptors[1].CompressedLength
	rootInput.ExpandedBytes =
		descriptors[0].ExpandedLength +
			descriptors[1].ExpandedLength
	rootInput.FinalDescriptorPageHash = first.Hash()
	unsigned, err := NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}

	var got []ChunkDescriptor
	validator, err := NewManifestValidator(
		root,
		func(descriptor ChunkDescriptor) error {
			got = append(got, descriptor)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewManifestValidator(): %v", err)
	}
	if err := validator.Consume(first); err != nil {
		t.Fatalf("Consume(): %v", err)
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(): %v", err)
	}
	if len(got) != len(descriptors) {
		t.Fatalf("descriptor calls = %d, want %d", len(got), len(descriptors))
	}
	for index := range descriptors {
		if got[index] != descriptors[index] {
			t.Fatalf(
				"descriptor %d = %#v, want %#v",
				index,
				got[index],
				descriptors[index],
			)
		}
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(second): %v", err)
	}
	if err := validator.Consume(first); !errors.Is(
		err,
		ErrManifestValidationFinished,
	) {
		t.Fatalf(
			"Consume(after finish) = %v, want ErrManifestValidationFinished",
			err,
		)
	}
}

func TestManifestValidatorRejectsShortInteriorPageBeforeSink(
	t *testing.T,
) {
	t.Parallel()

	rootInput, privateKey, _ := testRootInput(t)
	firstDescriptor := ChunkDescriptor{
		ChunkIndex:       0,
		CompressedLength: 1,
		ExpandedLength:   1,
		SHA256:           chain.Digest{1},
	}
	secondDescriptor := ChunkDescriptor{
		ChunkIndex:       1,
		CompressedLength: 1,
		ExpandedLength:   1,
		SHA256:           chain.Digest{2},
	}
	first, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:  rootInput.ArtifactID,
		PageIndex:   0,
		Descriptors: []ChunkDescriptor{firstDescriptor},
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(first): %v", err)
	}
	second, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:       rootInput.ArtifactID,
		PageIndex:        1,
		PreviousPageHash: first.Hash(),
		Descriptors:      []ChunkDescriptor{secondDescriptor},
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(second): %v", err)
	}
	rootInput.DescriptorPageCount = 2
	rootInput.ChunkCount = 2
	rootInput.CompressedBytes = 2
	rootInput.ExpandedBytes = 2
	rootInput.FinalDescriptorPageHash = second.Hash()
	unsigned, err := NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}

	sinkCalls := 0
	validator, err := NewManifestValidator(
		root,
		func(ChunkDescriptor) error {
			sinkCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewManifestValidator(): %v", err)
	}
	got := validator.Consume(first)
	if !errors.Is(got, ErrDescriptorSequence) {
		t.Fatalf("Consume(short interior) = %v, want ErrDescriptorSequence", got)
	}
	if sinkCalls != 0 {
		t.Fatalf("invalid page emitted %d descriptors", sinkCalls)
	}
	if again := validator.Consume(second); again != got {
		t.Fatalf("latched error = %v, want identical %v", again, got)
	}
	if again := validator.Finish(); again != got {
		t.Fatalf("Finish() = %v, want identical %v", again, got)
	}
}

func TestManifestValidatorLatchesSinkFailureWithoutAdvancing(
	t *testing.T,
) {
	t.Parallel()

	rootInput, privateKey, _ := testRootInput(t)
	descriptor := manifestDescriptor(0)
	page, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:  rootInput.ArtifactID,
		Descriptors: []ChunkDescriptor{descriptor},
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(): %v", err)
	}
	rootInput.DescriptorPageCount = 1
	rootInput.ChunkCount = 1
	rootInput.CompressedBytes = descriptor.CompressedLength
	rootInput.ExpandedBytes = descriptor.ExpandedLength
	rootInput.FinalDescriptorPageHash = page.Hash()
	unsigned, err := NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}

	sinkFailure := errors.New("chunk quarantine unavailable")
	validator, err := NewManifestValidator(
		root,
		func(ChunkDescriptor) error {
			return sinkFailure
		},
	)
	if err != nil {
		t.Fatalf("NewManifestValidator(): %v", err)
	}
	got := validator.Consume(page)
	if !errors.Is(got, sinkFailure) {
		t.Fatalf("Consume() = %v, want sink failure", got)
	}
	if validator.nextPage != 0 ||
		validator.nextChunk != 0 ||
		validator.previousPageHash != (chain.Digest{}) {
		t.Fatalf("failed sink advanced validator: %#v", validator)
	}
	if again := validator.Finish(); again != got {
		t.Fatalf("Finish() = %v, want identical %v", again, got)
	}
}

func TestManifestValidatorRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()

	rootInput, privateKey, _ := testRootInput(t)
	unsigned, err := NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	if _, err := NewManifestValidator(root, nil); !errors.Is(
		err,
		ErrInvalidManifestValidator,
	) {
		t.Fatalf("NewManifestValidator(nil sink) = %v", err)
	}
	var validator *ManifestValidator
	if err := validator.Finish(); !errors.Is(
		err,
		ErrInvalidManifestValidator,
	) {
		t.Fatalf("nil Finish() = %v", err)
	}

	invalid := root
	invalid.valid = false
	if _, err := NewManifestValidator(
		invalid,
		func(ChunkDescriptor) error { return nil },
	); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("NewManifestValidator(invalid root) = %v", err)
	}

	if bytes.Equal(root.CanonicalBytes(), nil) {
		t.Fatal("test root unexpectedly invalid")
	}
}
