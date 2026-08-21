package logicalsnapshot

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
)

func TestDescriptorPageRoundTripAndSequence(t *testing.T) {
	t.Parallel()

	descriptors := []ChunkDescriptor{
		{
			ChunkIndex:       0,
			CompressedLength: 31,
			ExpandedLength:   41,
			SHA256:           sha256.Sum256([]byte("chunk-0")),
		},
		{
			ChunkIndex:       1,
			CompressedLength: 37,
			ExpandedLength:   43,
			SHA256:           sha256.Sum256([]byte("chunk-1")),
		},
	}
	first, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:  "artifact",
		PageIndex:   0,
		Descriptors: descriptors[:1],
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(first): %v", err)
	}
	second, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID:       "artifact",
		PageIndex:        1,
		PreviousPageHash: first.Hash(),
		Descriptors:      descriptors[1:],
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(second): %v", err)
	}
	parsed, err := ParseDescriptorPage(second.CanonicalBytes())
	if err != nil {
		t.Fatalf("ParseDescriptorPage(): %v", err)
	}
	if parsed.Hash() != second.Hash() ||
		parsed.Input().Descriptors[0] != descriptors[1] {
		t.Fatalf("parsed page = %#v, want %#v", parsed.Input(), second.Input())
	}

	rootInput, privateKey, _ := testRootInput(t)
	rootInput.ArtifactID = "artifact"
	rootInput.ContentEncoding = EncodingIdentity
	rootInput.CompressedBytes = 68
	rootInput.ExpandedBytes = 84
	rootInput.ChunkCount = 2
	rootInput.DescriptorPageCount = 2
	rootInput.FinalDescriptorPageHash = second.Hash()
	unsigned, err := NewUnsignedRoot(rootInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	if err := ValidateDescriptorPages(
		root,
		[]DescriptorPage{first, second},
	); err != nil {
		t.Fatalf("ValidateDescriptorPages(): %v", err)
	}

	for name, pages := range map[string][]DescriptorPage{
		"missing":   {first},
		"reordered": {second, first},
		"duplicate": {first, first},
	} {
		if err := ValidateDescriptorPages(root, pages); !errors.Is(
			err,
			ErrDescriptorSequence,
		) {
			t.Errorf(
				"ValidateDescriptorPages(%s) = %v, want ErrDescriptorSequence",
				name,
				err,
			)
		}
	}
}

func TestDescriptorPageHashGoldenAndTamper(t *testing.T) {
	t.Parallel()

	page, err := NewDescriptorPage(DescriptorPageInput{
		ArtifactID: "artifact-1",
		PageIndex:  0,
		Descriptors: []ChunkDescriptor{{
			ChunkIndex:       0,
			CompressedLength: 17,
			ExpandedLength:   29,
			SHA256:           sha256.Sum256([]byte("payload")),
		}},
	})
	if err != nil {
		t.Fatalf("NewDescriptorPage(): %v", err)
	}
	const wantHash = "EiSUPGGo49-uXPzdnOI8gxXwljkHq6_em9BYnX7LYmI"
	pageHash := page.Hash()
	if got := codec.EncodeBase64URL(pageHash[:]); got != wantHash {
		t.Fatalf("page hash = %q, want %q", got, wantHash)
	}

	encoded := page.CanonicalBytes()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("json.Unmarshal(page): %v", err)
	}
	members["unknown"] = json.RawMessage("true")
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("json.Marshal(page): %v", err)
	}
	canonical, err := codec.Canonicalize(raw)
	if err != nil {
		t.Fatalf("Canonicalize(page): %v", err)
	}
	if _, err := ParseDescriptorPage(canonical); !errors.Is(
		err,
		ErrInvalidDescriptorPage,
	) {
		t.Fatalf(
			"ParseDescriptorPage(unknown) = %v, want ErrInvalidDescriptorPage",
			err,
		)
	}
	if _, err := ParseDescriptorPage(
		append([]byte(" "), encoded...),
	); !errors.Is(err, ErrInvalidDescriptorPage) {
		t.Fatalf(
			"ParseDescriptorPage(noncanonical) = %v, want ErrInvalidDescriptorPage",
			err,
		)
	}
}

func TestDescriptorPageRejectsInvalidBounds(t *testing.T) {
	t.Parallel()

	base := DescriptorPageInput{
		ArtifactID: "artifact",
		PageIndex:  0,
		Descriptors: []ChunkDescriptor{{
			ChunkIndex:       0,
			CompressedLength: 1,
			ExpandedLength:   1,
			SHA256:           chain.Digest{1},
		}},
	}
	tests := map[string]func(*DescriptorPageInput){
		"artifact": func(value *DescriptorPageInput) {
			value.ArtifactID = "../artifact"
		},
		"empty": func(value *DescriptorPageInput) {
			value.Descriptors = nil
		},
		"zero compressed": func(value *DescriptorPageInput) {
			value.Descriptors[0].CompressedLength = 0
		},
		"large compressed": func(value *DescriptorPageInput) {
			value.Descriptors[0].CompressedLength =
				MaxChunkCompressedBytes + 1
		},
		"large expanded": func(value *DescriptorPageInput) {
			value.Descriptors[0].ExpandedLength =
				MaxChunkExpandedBytes + 1
		},
		"gap": func(value *DescriptorPageInput) {
			value.Descriptors = append(value.Descriptors, ChunkDescriptor{
				ChunkIndex:       2,
				CompressedLength: 1,
				ExpandedLength:   1,
			})
		},
		"page zero predecessor": func(value *DescriptorPageInput) {
			value.PreviousPageHash[0] = 1
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			candidate.Descriptors = cloneDescriptors(base.Descriptors)
			mutate(&candidate)
			if _, err := NewDescriptorPage(candidate); err == nil {
				t.Fatalf("NewDescriptorPage(%s) succeeded", name)
			}
		})
	}
}
