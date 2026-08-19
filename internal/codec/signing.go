package codec

import (
	"errors"
	"fmt"
)

const maxBatchSignedInputBytes = 64 << 20

// SignatureLabel is one exact V1 Ed25519 domain-separation label. Digest and
// HMAC labels are deliberately excluded because their preimages differ.
type SignatureLabel string

const (
	SignatureGenesis                   SignatureLabel = "codecomm/v1/genesis"
	SignatureDiscovery                 SignatureLabel = "codecomm/v1/discovery"
	SignatureEndpointHints             SignatureLabel = "codecomm/v1/endpoint-hints"
	SignatureInvite                    SignatureLabel = "codecomm/v1/invite"
	SignatureCredentialBinding         SignatureLabel = "codecomm/v1/credential-binding"
	SignatureCredentialTimeEndorsement SignatureLabel = "codecomm/v1/credential-time-endorsement"
	SignatureVoterActivationProof      SignatureLabel = "codecomm/v1/voter-activation-proof"
	SignatureVoterAuthorityHandoff     SignatureLabel = "codecomm/v1/voter-authority-handoff"
	SignatureEventOrigin               SignatureLabel = "codecomm/v1/event-origin"
	SignatureCheckpoint                SignatureLabel = "codecomm/v1/checkpoint"
	SignatureBatch                     SignatureLabel = "codecomm/v1/batch"
	SignatureSnapshot                  SignatureLabel = "codecomm/v1/snapshot"
	SignatureGitRefAdvertisement       SignatureLabel = "codecomm/v1/git-ref-advertisement"
	SignatureGitStageReceipt           SignatureLabel = "codecomm/v1/git-stage-receipt"
	SignatureGitCanonicalCoverage      SignatureLabel = "codecomm/v1/git-canonical-coverage"
	SignatureOwnerRecovery             SignatureLabel = "codecomm/v1/owner-recovery"
	SignatureQuorumRecovery            SignatureLabel = "codecomm/v1/quorum-recovery"
)

var signatureLabels = [...]SignatureLabel{
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

var (
	ErrInvalidSignatureLabel = errors.New("codec: invalid V1 signature label")
	ErrSignedInputTooLarge   = errors.New("codec: signed input exceeds the signed-object limit")
)

// Valid reports whether label is a closed V1 Ed25519 label.
func (label SignatureLabel) Valid() bool {
	switch label {
	case SignatureGenesis,
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
		SignatureQuorumRecovery:
		return true
	default:
		return false
	}
}

// SignatureLabels returns the closed V1 label set in stable order.
func SignatureLabels() []SignatureLabel {
	result := make([]SignatureLabel, len(signatureLabels))
	copy(result, signatureLabels[:])
	return result
}

// BuildSignedInput returns label || 0x00 || signedBytes for Ed25519.
func BuildSignedInput(label SignatureLabel, signedBytes []byte) ([]byte, error) {
	if !label.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSignatureLabel, label)
	}
	limit := maxSignedObjectJSONBytes
	if label == SignatureBatch {
		limit = maxBatchSignedInputBytes
	}
	if len(signedBytes) > limit {
		return nil, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			ErrSignedInputTooLarge,
			len(signedBytes),
			limit,
		)
	}
	result := make([]byte, 0, len(label)+1+len(signedBytes))
	result = append(result, label...)
	result = append(result, 0)
	result = append(result, signedBytes...)
	return result, nil
}
