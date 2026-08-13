package publication

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxStagingReceipts = 5

// Signature is an exact Ed25519 signature. Cryptographic verification belongs
// to the receipt verifier, not this pure shape validator.
type Signature [ed25519.SignatureSize]byte

// StagingReceipt is one voter's signed durable-import attestation.
type StagingReceipt struct {
	SessionID                 domain.UUIDv7
	WorkspaceID               domain.UUIDv4
	VoterSetVersion           uint64
	PublicationMetadataDigest SHA256Digest
	VoterDeviceID             domain.DeviceID
	StagedResultIndex         uint64
	Signature                 Signature
}

var (
	ErrInvalidStagingReceipts        = errors.New("publication: invalid staging receipts")
	ErrInvalidReceiptSessionID       = errors.New("publication: invalid receipt session ID")
	ErrInvalidReceiptWorkspaceID     = errors.New("publication: invalid receipt workspace ID")
	ErrInvalidReceiptVoterDeviceID   = errors.New("publication: invalid receipt voter device ID")
	ErrInvalidReceiptVoterSetVersion = errors.New("publication: invalid receipt voter-set version")
	ErrInvalidReceiptResultIndex     = errors.New("publication: invalid receipt staged result index")
	ErrInconsistentReceiptContext    = errors.New("publication: inconsistent staging-receipt context")
)

// Validate checks the receipt fields whose validity is independent of signed
// metadata, membership, current replicated state, and cryptography.
func (receipt StagingReceipt) Validate() error {
	if !receipt.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidReceiptSessionID, receipt.SessionID)
	}
	if !receipt.WorkspaceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidReceiptWorkspaceID, receipt.WorkspaceID)
	}
	if !receipt.VoterDeviceID.Valid() {
		return fmt.Errorf(
			"%w: %q",
			ErrInvalidReceiptVoterDeviceID,
			receipt.VoterDeviceID,
		)
	}
	if receipt.VoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(receipt.VoterSetVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidReceiptVoterSetVersion,
			domain.MaxSafeInteger,
		)
	}
	if !domain.ValidUnsignedInteger(receipt.StagedResultIndex) {
		return fmt.Errorf(
			"%w: must be in 0..%d",
			ErrInvalidReceiptResultIndex,
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// ValidateStagingReceipts validates a bounded, voter-sorted receipt set for
// one session, workspace, publication digest, and voter-set version. Majority,
// target membership, freshness, signatures, and metadata-digest equality to
// the publication are reducer/verifier concerns.
func ValidateStagingReceipts(receipts []StagingReceipt) error {
	if len(receipts) > MaxStagingReceipts {
		return fmt.Errorf(
			"%w: got %d entries, limit %d",
			ErrInvalidStagingReceipts,
			len(receipts),
			MaxStagingReceipts,
		)
	}
	for index, receipt := range receipts {
		if err := receipt.Validate(); err != nil {
			return fmt.Errorf("receipt %d: %w", index, err)
		}
		if index == 0 {
			continue
		}
		previous := receipts[index-1]
		if previous.VoterDeviceID >= receipt.VoterDeviceID {
			return fmt.Errorf(
				"%w: voter IDs must be sorted and unique",
				ErrInvalidStagingReceipts,
			)
		}
		if receipt.SessionID != receipts[0].SessionID ||
			receipt.WorkspaceID != receipts[0].WorkspaceID ||
			receipt.PublicationMetadataDigest != receipts[0].PublicationMetadataDigest ||
			receipt.VoterSetVersion != receipts[0].VoterSetVersion {
			return fmt.Errorf("%w: receipt %d", ErrInconsistentReceiptContext, index)
		}
	}
	return nil
}
