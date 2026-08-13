// Package controlfile defines replicated control-file review proposals.
package controlfile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxContentBytes uint64 = 1 << 20
	MaxDiffBytes           = 64 << 10
)

// Operation identifies the proposed filesystem operation.
type Operation string

const (
	OperationUpsert Operation = "upsert"
	OperationDelete Operation = "delete"
)

// Valid reports whether operation is in the closed V1 namespace.
func (operation Operation) Valid() bool {
	return operation == OperationUpsert || operation == OperationDelete
}

// SHA256Digest is an exact content digest.
type SHA256Digest [sha256.Size]byte

// Proposal is one replicated, append-only review input.
type Proposal struct {
	ProposalEventID    domain.UUIDv7
	SessionID          domain.UUIDv7
	Path               domain.RepositoryPath
	Operation          Operation
	ContentDigest      *SHA256Digest
	ContentSize        uint64
	Diff               string
	ProposedByDeviceID domain.DeviceID
	ChainIndex         uint64
}

var (
	ErrInvalidIdentity  = errors.New("control file: invalid proposal identity")
	ErrInvalidPath      = errors.New("control file: invalid path")
	ErrInvalidOperation = errors.New(
		"control file: invalid operation",
	)
	ErrInvalidContent = errors.New("control file: invalid content metadata")
	ErrInvalidDiff    = errors.New("control file: invalid diff")
)

// Validate checks context-free proposal invariants.
func (proposal Proposal) Validate() error {
	if !proposal.ProposalEventID.Valid() ||
		!proposal.SessionID.Valid() ||
		!proposal.ProposedByDeviceID.Valid() {
		return ErrInvalidIdentity
	}
	if proposal.ChainIndex < 1 ||
		!domain.ValidUnsignedInteger(proposal.ChainIndex) {
		return ErrInvalidIdentity
	}
	if !proposal.Path.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidPath, proposal.Path)
	}
	if !proposal.Operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, proposal.Operation)
	}
	if !domain.ValidUnsignedInteger(proposal.ContentSize) ||
		proposal.ContentSize > MaxContentBytes {
		return fmt.Errorf(
			"%w: content size must be in 0..%d",
			ErrInvalidContent,
			MaxContentBytes,
		)
	}
	switch proposal.Operation {
	case OperationUpsert:
		if proposal.ContentDigest == nil {
			return fmt.Errorf("%w: upsert requires a digest", ErrInvalidContent)
		}
	case OperationDelete:
		if proposal.ContentDigest != nil || proposal.ContentSize != 0 {
			return fmt.Errorf(
				"%w: delete requires a null digest and zero size",
				ErrInvalidContent,
			)
		}
	}
	if !utf8.ValidString(proposal.Diff) || len(proposal.Diff) > MaxDiffBytes {
		return fmt.Errorf(
			"%w: must be valid UTF-8 and at most %d bytes",
			ErrInvalidDiff,
			MaxDiffBytes,
		)
	}
	return nil
}

// Clone returns a proposal that does not alias digest storage.
func (proposal Proposal) Clone() Proposal {
	result := proposal
	if proposal.ContentDigest != nil {
		digest := *proposal.ContentDigest
		result.ContentDigest = &digest
	}
	return result
}
