// Package credentialauthority defines the activated voter authority used to
// validate credential, checkpoint, and replication attestations.
package credentialauthority

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxVoters = 5

var (
	ErrInvalidSessionID            = errors.New("credential authority: invalid session ID")
	ErrInvalidVoterCount           = errors.New("credential authority: invalid voter count")
	ErrInvalidVoterDeviceID        = errors.New("credential authority: invalid voter device ID")
	ErrVotersNotSortedUnique       = errors.New("credential authority: voters are not sorted and unique")
	ErrInvalidVoterSetVersion      = errors.New("credential authority: invalid voter-set version")
	ErrInvalidActivationSource     = errors.New("credential authority: invalid activation source")
	ErrInvalidActivationVersion    = errors.New("credential authority: invalid activation version")
	ErrInvalidProofVoter           = errors.New("credential authority: invalid activation-proof voter")
	ErrProofOrder                  = errors.New("credential authority: activation proofs are out of voter order")
	ErrInvalidProofObject          = errors.New("credential authority: invalid activation-proof object")
	ErrGenesisHandoffFields        = errors.New("credential authority: genesis prohibits handoff fields")
	ErrHandoffCheckpoint           = errors.New("credential authority: handoff requires a checkpoint")
	ErrHandoffProofCount           = errors.New("credential authority: handoff proof count does not match voters")
	ErrHandoffPriorAuthority       = errors.New("credential authority: handoff requires prior-authority evidence")
	ErrInvalidOperation            = errors.New("credential authority: invalid transition operation")
	ErrInvalidTransition           = errors.New("credential authority: invalid transition")
	ErrSessionChanged              = errors.New("credential authority: session changed outside recovery")
	ErrAuthorityVersionNotAdvanced = errors.New("credential authority: authority version did not advance")
	ErrActivationSourceNotHandoff  = errors.New("credential authority: activation destination is not a handoff")
	ErrPriorSignerNotAuthority     = errors.New("credential authority: prior signer is not in the prior authority")
	ErrInvalidRecoveryAuthority    = errors.New("credential authority: invalid recovery authority")
)

// ActivationSource identifies how an authority became active in its recovery
// generation.
type ActivationSource string

const (
	ActivationGenesis ActivationSource = "genesis"
	ActivationHandoff ActivationSource = "handoff"
)

// Valid reports whether source is a closed V1 activation source.
func (source ActivationSource) Valid() bool {
	return source == ActivationGenesis || source == ActivationHandoff
}

// ActivationProof binds exact canonical signed proof bytes to their voter.
// Codec-level canonicality and signature checks remain reducer/store boundary
// responsibilities; this package validates the projection's pure shape.
type ActivationProof struct {
	VoterDeviceID domain.DeviceID
	CanonicalJSON json.RawMessage
}

// Authority is the most recent voter target activated by a proven handoff.
type Authority struct {
	SessionID                   domain.UUIDv7
	VoterDeviceIDs              []domain.DeviceID
	VoterSetVersion             uint64
	ActivationSource            ActivationSource
	ActivationCheckpointEventID domain.UUIDv7
	ActivationProofs            []ActivationProof
	PriorAuthoritySigner        domain.DeviceID
	PriorAuthorityHandoff       *[ed25519.SignatureSize]byte
}

// Validate checks pure persisted-form invariants.
func (authority Authority) Validate() error {
	if !authority.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, authority.SessionID)
	}
	if err := validateVoters(authority.VoterDeviceIDs); err != nil {
		return err
	}
	if authority.VoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(authority.VoterSetVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidVoterSetVersion,
			domain.MaxSafeInteger,
		)
	}
	if !authority.ActivationSource.Valid() {
		return fmt.Errorf(
			"%w: %q",
			ErrInvalidActivationSource,
			authority.ActivationSource,
		)
	}
	for index, proof := range authority.ActivationProofs {
		if !proof.VoterDeviceID.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidProofVoter, index)
		}
		if index >= len(authority.VoterDeviceIDs) ||
			proof.VoterDeviceID != authority.VoterDeviceIDs[index] {
			return fmt.Errorf("%w: entry %d", ErrProofOrder, index)
		}
		if !validJSONObject(proof.CanonicalJSON) {
			return fmt.Errorf("%w: entry %d", ErrInvalidProofObject, index)
		}
	}

	switch authority.ActivationSource {
	case ActivationGenesis:
		if authority.VoterSetVersion != 1 {
			return fmt.Errorf(
				"%w: genesis requires version 1",
				ErrInvalidActivationVersion,
			)
		}
		if authority.ActivationCheckpointEventID != "" ||
			len(authority.ActivationProofs) != 0 ||
			authority.PriorAuthoritySigner != "" ||
			authority.PriorAuthorityHandoff != nil {
			return ErrGenesisHandoffFields
		}
	case ActivationHandoff:
		if authority.VoterSetVersion == 1 {
			return fmt.Errorf(
				"%w: handoff requires version greater than 1",
				ErrInvalidActivationVersion,
			)
		}
		if !authority.ActivationCheckpointEventID.Valid() {
			return ErrHandoffCheckpoint
		}
		if len(authority.ActivationProofs) != len(authority.VoterDeviceIDs) {
			return fmt.Errorf(
				"%w: got %d proofs for %d voters",
				ErrHandoffProofCount,
				len(authority.ActivationProofs),
				len(authority.VoterDeviceIDs),
			)
		}
		if !authority.PriorAuthoritySigner.Valid() ||
			authority.PriorAuthorityHandoff == nil {
			return ErrHandoffPriorAuthority
		}
	default:
		return fmt.Errorf(
			"%w: %q",
			ErrInvalidActivationSource,
			authority.ActivationSource,
		)
	}
	return nil
}

// Clone returns a deep copy suitable for retaining in reducer state.
func (authority Authority) Clone() Authority {
	result := authority
	result.VoterDeviceIDs = append(
		[]domain.DeviceID(nil),
		authority.VoterDeviceIDs...,
	)
	result.ActivationProofs = make(
		[]ActivationProof,
		len(authority.ActivationProofs),
	)
	for index, proof := range authority.ActivationProofs {
		result.ActivationProofs[index] = ActivationProof{
			VoterDeviceID: proof.VoterDeviceID,
			CanonicalJSON: append(json.RawMessage(nil), proof.CanonicalJSON...),
		}
	}
	if authority.PriorAuthorityHandoff != nil {
		signature := *authority.PriorAuthorityHandoff
		result.PriorAuthorityHandoff = &signature
	}
	return result
}

// VoterIDs returns a copy of the sorted authority members.
func (authority Authority) VoterIDs() []domain.DeviceID {
	return append([]domain.DeviceID(nil), authority.VoterDeviceIDs...)
}

// Contains reports whether deviceID belongs to a valid authority.
func (authority Authority) Contains(deviceID domain.DeviceID) bool {
	if !deviceID.Valid() || authority.Validate() != nil {
		return false
	}
	for _, candidate := range authority.VoterDeviceIDs {
		if candidate == deviceID {
			return true
		}
	}
	return false
}

// Operation identifies an authority mutation.
type Operation string

const (
	OperationActivate      Operation = "membership.voter_set_activated"
	OperationRecoveryReset Operation = "recovery.credential_authority"
)

// Valid reports whether operation is a closed authority operation.
func (operation Operation) Valid() bool {
	return operation == OperationActivate ||
		operation == OperationRecoveryReset
}

// ValidateTransition checks a complete authority mutation. Target equality,
// expected versions, membership status, and cryptographic proofs remain
// reducer concerns.
func ValidateTransition(operation Operation, before, after Authority) error {
	if !operation.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	if err := before.Validate(); err != nil {
		return fmt.Errorf("%w: invalid source: %w", ErrInvalidTransition, err)
	}
	if err := after.Validate(); err != nil {
		return fmt.Errorf("%w: invalid destination: %w", ErrInvalidTransition, err)
	}

	switch operation {
	case OperationActivate:
		if after.SessionID != before.SessionID {
			return fmt.Errorf(
				"%w: %q -> %q",
				ErrSessionChanged,
				before.SessionID,
				after.SessionID,
			)
		}
		if after.ActivationSource != ActivationHandoff {
			return ErrActivationSourceNotHandoff
		}
		if after.VoterSetVersion <= before.VoterSetVersion {
			return fmt.Errorf(
				"%w: %d -> %d",
				ErrAuthorityVersionNotAdvanced,
				before.VoterSetVersion,
				after.VoterSetVersion,
			)
		}
		if !before.Contains(after.PriorAuthoritySigner) {
			return fmt.Errorf(
				"%w: %q",
				ErrPriorSignerNotAuthority,
				after.PriorAuthoritySigner,
			)
		}
	case OperationRecoveryReset:
		if after.SessionID == before.SessionID ||
			after.VoterSetVersion != 1 ||
			after.ActivationSource != ActivationGenesis ||
			len(after.VoterDeviceIDs) != 1 {
			return ErrInvalidRecoveryAuthority
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidOperation, operation)
	}
	return nil
}

func validateVoters(ids []domain.DeviceID) error {
	if len(ids) != 1 && len(ids) != 3 && len(ids) != MaxVoters {
		return fmt.Errorf(
			"%w: got %d, want 1, 3, or %d",
			ErrInvalidVoterCount,
			len(ids),
			MaxVoters,
		)
	}
	var previous domain.DeviceID
	for index, id := range ids {
		if !id.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidVoterDeviceID, index)
		}
		if index > 0 && previous >= id {
			return fmt.Errorf(
				"%w: entries %d and %d",
				ErrVotersNotSortedUnique,
				index-1,
				index,
			)
		}
		previous = id
	}
	return nil
}

func validJSONObject(input []byte) bool {
	if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(input, &object) == nil && object != nil
}
