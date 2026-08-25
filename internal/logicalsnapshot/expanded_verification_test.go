package logicalsnapshot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestVerifyAndExpandArtifactMintsCompleteTransportProof(t *testing.T) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	expanded := expandedVerificationScratch(t)
	if _, err := expanded.Write([]byte("stale expanded bytes")); err != nil {
		t.Fatalf("seed expanded scratch: %v", err)
	}
	verified, err := VerifyAndExpandArtifact(
		context.Background(),
		fixture.root,
		artifactVerificationOptions(
			t,
			fixture,
			expanded,
		),
	)
	if err != nil {
		t.Fatalf("VerifyAndExpandArtifact(): %v", err)
	}
	if !verified.MatchesRoot(fixture.root) {
		t.Fatal("verified expanded artifact does not match its root")
	}
	if _, err := expanded.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind expanded scratch: %v", err)
	}
	got, err := io.ReadAll(expanded)
	if err != nil {
		t.Fatalf("read expanded scratch: %v", err)
	}
	if want := bytes.Join(fixture.chunks, nil); !bytes.Equal(got, want) {
		t.Fatal("expanded scratch differs from verified transmitted chunks")
	}
	if (VerifiedExpandedArtifact{}).MatchesRoot(fixture.root) {
		t.Fatal("zero expanded-artifact proof matched a root")
	}

	otherSignature := fixture.root.Signature()
	otherSignature[0] ^= 0xff
	other, err := NewRoot(fixture.root.Unsigned(), otherSignature)
	if err != nil {
		t.Fatalf("NewRoot(other): %v", err)
	}
	if verified.MatchesRoot(other) {
		t.Fatal("expanded-artifact proof matched another signed root")
	}
}

func TestVerifyAndExpandArtifactRejectsIncompleteTransportProof(
	t *testing.T,
) {
	t.Parallel()

	for name, mutate := range map[string]func(*artifactReplayFixture){
		"descriptor page mutation": func(fixture *artifactReplayFixture) {
			fixture.pages[0][len(fixture.pages[0])/2] ^= 0x01
		},
		"chunk mutation": func(fixture *artifactReplayFixture) {
			fixture.chunks[0][len(fixture.chunks[0])/2] ^= 0x01
		},
		"chunk truncation": func(fixture *artifactReplayFixture) {
			fixture.chunks[0] =
				fixture.chunks[0][:len(fixture.chunks[0])-1]
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newArtifactReplayFixture(t)
			mutate(&fixture)
			verified, err := VerifyAndExpandArtifact(
				context.Background(),
				fixture.root,
				artifactVerificationOptions(
					t,
					fixture,
					expandedVerificationScratch(t),
				),
			)
			if !errors.Is(err, ErrExpandedArtifactIntegrity) ||
				verified != (VerifiedExpandedArtifact{}) {
				t.Fatalf(
					"VerifyAndExpandArtifact(%s) = (%#v, %v)",
					name,
					verified,
					err,
				)
			}
		})
	}
}

func TestVerifyAndExpandArtifactRejectsAliasedScratch(t *testing.T) {
	t.Parallel()

	fixture := newArtifactReplayFixture(t)
	scratch := expandedVerificationScratch(t)
	options := artifactVerificationOptions(t, fixture, scratch)
	options.SequenceScratch = scratch
	if verified, err := VerifyAndExpandArtifact(
		context.Background(),
		fixture.root,
		options,
	); !errors.Is(err, ErrInvalidArtifactReplay) ||
		verified != (VerifiedExpandedArtifact{}) {
		t.Fatalf(
			"VerifyAndExpandArtifact(alias) = (%#v, %v)",
			verified,
			err,
		)
	}
}

func artifactVerificationOptions(
	t *testing.T,
	fixture artifactReplayFixture,
	expanded ExpandedArtifact,
) ArtifactVerificationOptions {
	t.Helper()
	return ArtifactVerificationOptions{
		ExpandedArtifact: expanded,
		SequenceScratch:  expandedVerificationScratch(t),
		OpenPage: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.pages)) {
				return nil, io.EOF
			}
			return io.NopCloser(bytes.NewReader(
				bytes.Clone(fixture.pages[index]),
			)), nil
		},
		OpenChunk: func(
			_ context.Context,
			index uint64,
		) (io.ReadCloser, error) {
			if index >= uint64(len(fixture.chunks)) {
				return nil, io.EOF
			}
			return io.NopCloser(bytes.NewReader(
				bytes.Clone(fixture.chunks[index]),
			)), nil
		},
	}
}

func expandedVerificationScratch(t *testing.T) *os.File {
	t.Helper()
	scratch, err := os.CreateTemp(t.TempDir(), "expanded-verification-*")
	if err != nil {
		t.Fatalf("os.CreateTemp(): %v", err)
	}
	t.Cleanup(func() {
		if err := scratch.Close(); err != nil {
			t.Errorf("scratch.Close(): %v", err)
		}
	})
	return scratch
}
