package transport

import (
	"errors"
	"testing"
	"time"
)

func TestContentAdmissionRecorderPreservesVerifierLifetime(t *testing.T) {
	certificate := contentAdmissionTestCertificate(t, 0x91, 0x92, 1)
	const authorized = 250 * time.Millisecond
	recorder, err := NewContentAdmissionRecorder(func(
		got ContentCertificate,
	) (ContentPeerAdmission, error) {
		if got.Binding != certificate.Binding {
			return ContentPeerAdmission{}, ErrTLSAdmission
		}
		return ContentPeerAdmission{CloseAfter: authorized}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Verify(certificate); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	remaining, err := recorder.Consume(certificate)
	if err != nil || remaining <= 0 || remaining >= authorized {
		t.Fatalf("Consume() = (%s, %v), want (0, %s)", remaining, err, authorized)
	}
	if _, err := recorder.Consume(certificate); !errors.Is(
		err,
		ErrContentAdmissionUnavailable,
	) {
		t.Fatalf("Consume(second) error = %v", err)
	}
}

func TestContentAdmissionRecorderRejectsMismatchedCertificate(t *testing.T) {
	first := contentAdmissionTestCertificate(t, 0x93, 0x94, 1)
	second := contentAdmissionTestCertificate(t, 0x95, 0x96, 1)
	recorder, err := NewContentAdmissionRecorder(admitTestContentPeer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Verify(first); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
	if _, err := recorder.Consume(second); !errors.Is(
		err,
		ErrContentAdmissionUnavailable,
	) {
		t.Fatalf("Consume(mismatched) error = %v", err)
	}
	if _, err := recorder.Consume(first); !errors.Is(
		err,
		ErrContentAdmissionUnavailable,
	) {
		t.Fatalf("Consume(after mismatch) error = %v", err)
	}
}

func contentAdmissionTestCertificate(
	t testing.TB,
	identityFill byte,
	epochFill byte,
	epoch uint64,
) ContentCertificate {
	t.Helper()
	identityKey := certificatePrivateKey(identityFill)
	epochKey := certificatePrivateKey(epochFill)
	authorization := certificateAuthorizationForKeys(
		t,
		identityKey,
		epochKey,
		epoch,
		epoch,
	)
	certificate, _, err := IssueContentCertificate(
		authorization,
		epochKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseContentCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
