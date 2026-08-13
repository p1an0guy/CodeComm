package domain

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrInvalidCheckpointIdentity = errors.New("domain: invalid checkpoint identity")
	ErrInvalidCheckpointNumber   = errors.New("domain: invalid checkpoint number")
)

// Checkpoint is the unsigned portable checkpoint tuple signed by one member
// of the activated credential authority.
type Checkpoint struct {
	SessionID                UUIDv7
	WorkspaceID              UUIDv4
	RecoveryGeneration       uint64
	AuthorityVoterSetVersion uint64
	SignerDeviceID           DeviceID
	Term                     uint64
	CoveredAppliedLogIndex   uint64
	CoveredChainIndex        uint64
	CoveredChainHash         [sha256.Size]byte
	CoveredResultIndex       uint64
	CoveredResultHash        [sha256.Size]byte
	ProjectionAccumulator    [sha256.Size]byte
	DigestVersion            uint64
	ProjectionSchemaVersion  uint64
}

// Validate verifies the tuple's context-free persisted invariants.
func (checkpoint Checkpoint) Validate() error {
	if !checkpoint.SessionID.Valid() ||
		!checkpoint.WorkspaceID.Valid() ||
		!checkpoint.SignerDeviceID.Valid() {
		return ErrInvalidCheckpointIdentity
	}
	numbers := [...]struct {
		name     string
		value    uint64
		positive bool
	}{
		{name: "recovery_generation", value: checkpoint.RecoveryGeneration},
		{
			name:     "authority_voter_set_version",
			value:    checkpoint.AuthorityVoterSetVersion,
			positive: true,
		},
		{name: "term", value: checkpoint.Term, positive: true},
		{
			name:     "covered_applied_log_index",
			value:    checkpoint.CoveredAppliedLogIndex,
			positive: true,
		},
		{name: "covered_chain_index", value: checkpoint.CoveredChainIndex},
		{name: "covered_result_index", value: checkpoint.CoveredResultIndex},
		{
			name:     "digest_version",
			value:    checkpoint.DigestVersion,
			positive: true,
		},
		{
			name:     "projection_schema_version",
			value:    checkpoint.ProjectionSchemaVersion,
			positive: true,
		},
	}
	for _, number := range numbers {
		if !ValidUnsignedInteger(number.value) ||
			number.positive && number.value == 0 {
			return fmt.Errorf(
				"%w: %s=%d",
				ErrInvalidCheckpointNumber,
				number.name,
				number.value,
			)
		}
	}
	if checkpoint.CoveredChainIndex > checkpoint.CoveredResultIndex {
		return fmt.Errorf(
			"%w: covered_chain_index=%d exceeds covered_result_index=%d",
			ErrInvalidCheckpointNumber,
			checkpoint.CoveredChainIndex,
			checkpoint.CoveredResultIndex,
		)
	}
	return nil
}
