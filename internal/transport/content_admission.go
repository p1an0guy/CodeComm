package transport

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

var ErrContentAdmissionUnavailable = errors.New(
	"transport: content peer admission unavailable",
)

// ContentAdmissionRecorder preserves the exact monotonic lifetime returned by
// a content verifier during one TLS handshake. Create one recorder per
// connection attempt and configure TLS with its Verify method.
type ContentAdmissionRecorder struct {
	verify ContentPeerVerifier

	mu         sync.Mutex
	digest     [sha256.Size]byte
	admission  ContentPeerAdmission
	verifiedAt time.Time
	ready      bool
}

func NewContentAdmissionRecorder(
	verify ContentPeerVerifier,
) (*ContentAdmissionRecorder, error) {
	if verify == nil {
		return nil, ErrInvalidTLSOptions
	}
	return &ContentAdmissionRecorder{verify: verify}, nil
}

// Verify delegates admission policy and records its exact successful result.
func (recorder *ContentAdmissionRecorder) Verify(
	certificate ContentCertificate,
) (ContentPeerAdmission, error) {
	if recorder == nil || recorder.verify == nil ||
		certificate.Leaf == nil || len(certificate.Leaf.Raw) == 0 {
		return ContentPeerAdmission{}, ErrContentAdmissionUnavailable
	}
	verifiedAt := time.Now()
	if verifiedAt.IsZero() {
		return ContentPeerAdmission{}, ErrContentAdmissionUnavailable
	}
	admission, err := recorder.verify(certificate)
	if err != nil {
		return ContentPeerAdmission{}, err
	}
	if !admission.validFor(certificate) {
		return ContentPeerAdmission{}, ErrTLSAdmission
	}
	recorder.mu.Lock()
	recorder.digest = sha256.Sum256(certificate.Leaf.Raw)
	recorder.admission = admission
	recorder.verifiedAt = verifiedAt
	recorder.ready = true
	recorder.mu.Unlock()
	return admission, nil
}

// Consume returns the unelapsed portion of the recorded verifier lifetime.
// The record is one-shot and must match the authenticated certificate exactly.
func (recorder *ContentAdmissionRecorder) Consume(
	certificate ContentCertificate,
) (time.Duration, error) {
	if recorder == nil ||
		certificate.Leaf == nil ||
		len(certificate.Leaf.Raw) == 0 {
		return 0, ErrContentAdmissionUnavailable
	}
	digest := sha256.Sum256(certificate.Leaf.Raw)
	recorder.mu.Lock()
	ready := recorder.ready
	matched := recorder.digest == digest
	admission := recorder.admission
	verifiedAt := recorder.verifiedAt
	recorder.digest = [sha256.Size]byte{}
	recorder.admission = ContentPeerAdmission{}
	recorder.verifiedAt = time.Time{}
	recorder.ready = false
	recorder.mu.Unlock()

	if !ready || !matched {
		return 0, ErrContentAdmissionUnavailable
	}
	remaining := admission.CloseAfter - time.Since(verifiedAt)
	if remaining <= 0 {
		return 0, ErrContentAdmissionUnavailable
	}
	return remaining, nil
}
