package codec

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestSignatureLabelsAreClosedAndStable(t *testing.T) {
	t.Parallel()

	want := []SignatureLabel{
		SignatureGenesis,
		SignatureDiscovery,
		SignatureEndpointHints,
		SignatureInvite,
		SignatureCredentialBinding,
		SignatureCredentialTimeEndorsement,
		SignatureVoterActivationProof,
		SignatureVoterAuthorityHandoff,
		SignatureEventOrigin,
		SignatureCheckpoint,
		SignatureBatch,
		SignatureSnapshot,
		SignatureGitRefAdvertisement,
		SignatureGitStageReceipt,
		SignatureGitCanonicalCoverage,
		SignatureOwnerRecovery,
		SignatureQuorumRecovery,
	}
	if got := SignatureLabels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SignatureLabels() = %q, want %q", got, want)
	}
	for _, label := range want {
		if !label.Valid() {
			t.Errorf("%q.Valid() = false", label)
		}
	}
	for _, label := range []SignatureLabel{
		"",
		"codecomm/v1/chain",
		"codecomm/v1/invite-proof",
		"codecomm/v2/event-origin",
		"codecomm/v1/event-origin\x00suffix",
	} {
		if label.Valid() {
			t.Errorf("%q.Valid() = true", label)
		}
	}

	got := SignatureLabels()
	got[0] = "changed"
	if SignatureLabels()[0] != SignatureGenesis {
		t.Fatal("SignatureLabels() did not return a defensive copy")
	}
}

func TestBuildSignedInputUsesExactDomainSeparator(t *testing.T) {
	t.Parallel()

	signedBytes := []byte(`{"a":1}`)
	got, err := BuildSignedInput(SignatureEventOrigin, signedBytes)
	if err != nil {
		t.Fatalf("BuildSignedInput() error = %v", err)
	}
	want := []byte("codecomm/v1/event-origin\x00{\"a\":1}")
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildSignedInput() = %q, want %q", got, want)
	}

	signedBytes[0] = '['
	if !bytes.Equal(got, want) {
		t.Fatal("BuildSignedInput() result aliases signed bytes")
	}
}

func TestBuildSignedInputRejectsNonSignatureLabels(t *testing.T) {
	t.Parallel()

	for _, label := range []SignatureLabel{
		"",
		"codecomm/v1/chain",
		"codecomm/v1/invite-proof",
		"codecomm/v2/event-origin",
	} {
		if _, err := BuildSignedInput(label, nil); !errors.Is(err, ErrInvalidSignatureLabel) {
			t.Errorf(
				"BuildSignedInput(%q) error = %v, want ErrInvalidSignatureLabel",
				label,
				err,
			)
		}
	}
}

func TestBuildSignedInputEnforcesSignedObjectBound(t *testing.T) {
	t.Parallel()

	atLimit := make([]byte, maxSignedObjectJSONBytes)
	if _, err := BuildSignedInput(SignatureEventOrigin, atLimit); err != nil {
		t.Fatalf("BuildSignedInput(at limit) error = %v", err)
	}
	if _, err := BuildSignedInput(
		SignatureEventOrigin,
		make([]byte, maxSignedObjectJSONBytes+1),
	); !errors.Is(err, ErrSignedInputTooLarge) {
		t.Fatalf("BuildSignedInput(over limit) error = %v, want ErrSignedInputTooLarge", err)
	}
}
