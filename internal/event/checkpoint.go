package event

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

var ErrInvalidCheckpoint = errors.New("event: invalid checkpoint")

var checkpointRequiredFields = map[string]struct{}{
	"session_id":                  {},
	"workspace_id":                {},
	"recovery_generation":         {},
	"authority_voter_set_version": {},
	"signer_device_id":            {},
	"term":                        {},
	"covered_applied_log_index":   {},
	"covered_chain_index":         {},
	"covered_chain_hash":          {},
	"covered_result_index":        {},
	"covered_result_hash":         {},
	"projection_accumulator":      {},
	"digest_version":              {},
	"projection_schema_version":   {},
}

type checkpointWire struct {
	SessionID                string `json:"session_id"`
	WorkspaceID              string `json:"workspace_id"`
	RecoveryGeneration       uint64 `json:"recovery_generation"`
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	SignerDeviceID           string `json:"signer_device_id"`
	Term                     uint64 `json:"term"`
	CoveredAppliedLogIndex   uint64 `json:"covered_applied_log_index"`
	CoveredChainIndex        uint64 `json:"covered_chain_index"`
	CoveredChainHash         string `json:"covered_chain_hash"`
	CoveredResultIndex       uint64 `json:"covered_result_index"`
	CoveredResultHash        string `json:"covered_result_hash"`
	ProjectionAccumulator    string `json:"projection_accumulator"`
	DigestVersion            uint64 `json:"digest_version"`
	ProjectionSchemaVersion  uint64 `json:"projection_schema_version"`
}

// EncodeCheckpoint returns the exact canonical unsigned checkpoint object.
func EncodeCheckpoint(checkpoint domain.Checkpoint) ([]byte, error) {
	if err := checkpoint.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	encoded, err := json.Marshal(checkpointWire{
		SessionID:                string(checkpoint.SessionID),
		WorkspaceID:              string(checkpoint.WorkspaceID),
		RecoveryGeneration:       checkpoint.RecoveryGeneration,
		AuthorityVoterSetVersion: checkpoint.AuthorityVoterSetVersion,
		SignerDeviceID:           string(checkpoint.SignerDeviceID),
		Term:                     checkpoint.Term,
		CoveredAppliedLogIndex:   checkpoint.CoveredAppliedLogIndex,
		CoveredChainIndex:        checkpoint.CoveredChainIndex,
		CoveredChainHash: codec.EncodeBase64URL(
			checkpoint.CoveredChainHash[:],
		),
		CoveredResultIndex: checkpoint.CoveredResultIndex,
		CoveredResultHash: codec.EncodeBase64URL(
			checkpoint.CoveredResultHash[:],
		),
		ProjectionAccumulator: codec.EncodeBase64URL(
			checkpoint.ProjectionAccumulator[:],
		),
		DigestVersion:           checkpoint.DigestVersion,
		ProjectionSchemaVersion: checkpoint.ProjectionSchemaVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode JSON", ErrInvalidCheckpoint)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: canonicalize JSON: %v",
			ErrInvalidCheckpoint,
			err,
		)
	}
	return canonical, nil
}

// DecodeCheckpoint accepts only the exact canonical unsigned checkpoint
// object and returns values backed by no caller-owned memory.
func DecodeCheckpoint(encoded []byte) (domain.Checkpoint, error) {
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: noncanonical JSON",
			ErrInvalidCheckpoint,
		)
	}
	var members map[string]json.RawMessage
	if err := decodeStrict(encoded, &members); err != nil ||
		validateMemberSet(
			members,
			checkpointRequiredFields,
			map[string]struct{}{},
		) != nil ||
		rejectNullMembers(members, map[string]struct{}{}) != nil {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: invalid field set",
			ErrInvalidCheckpoint,
		)
	}

	var wire checkpointWire
	if err := decodeStrict(encoded, &wire); err != nil {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: decode JSON",
			ErrInvalidCheckpoint,
		)
	}
	chainHash, chainErr := codec.DecodeBase64URLExact(
		wire.CoveredChainHash,
		len(domain.Checkpoint{}.CoveredChainHash),
	)
	resultHash, resultErr := codec.DecodeBase64URLExact(
		wire.CoveredResultHash,
		len(domain.Checkpoint{}.CoveredResultHash),
	)
	accumulator, accumulatorErr := codec.DecodeBase64URLExact(
		wire.ProjectionAccumulator,
		len(domain.Checkpoint{}.ProjectionAccumulator),
	)
	if chainErr != nil || resultErr != nil || accumulatorErr != nil {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: invalid digest encoding",
			ErrInvalidCheckpoint,
		)
	}
	checkpoint := domain.Checkpoint{
		SessionID:                domain.UUIDv7(wire.SessionID),
		WorkspaceID:              domain.UUIDv4(wire.WorkspaceID),
		RecoveryGeneration:       wire.RecoveryGeneration,
		AuthorityVoterSetVersion: wire.AuthorityVoterSetVersion,
		SignerDeviceID:           domain.DeviceID(wire.SignerDeviceID),
		Term:                     wire.Term,
		CoveredAppliedLogIndex:   wire.CoveredAppliedLogIndex,
		CoveredChainIndex:        wire.CoveredChainIndex,
		CoveredResultIndex:       wire.CoveredResultIndex,
		DigestVersion:            wire.DigestVersion,
		ProjectionSchemaVersion:  wire.ProjectionSchemaVersion,
	}
	copy(checkpoint.CoveredChainHash[:], chainHash)
	copy(checkpoint.CoveredResultHash[:], resultHash)
	copy(checkpoint.ProjectionAccumulator[:], accumulator)
	if err := checkpoint.Validate(); err != nil {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: %v",
			ErrInvalidCheckpoint,
			err,
		)
	}
	reencoded, err := EncodeCheckpoint(checkpoint)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return domain.Checkpoint{}, fmt.Errorf(
			"%w: typed fields do not round trip",
			ErrInvalidCheckpoint,
		)
	}
	return checkpoint, nil
}

// SignCheckpoint signs only the canonical checkpoint tuple and requires the
// private key to belong to the tuple's named signer.
func SignCheckpoint(
	checkpoint domain.Checkpoint,
	privateKey []byte,
) ([ed25519.SignatureSize]byte, error) {
	var result [ed25519.SignatureSize]byte
	encoded, err := EncodeCheckpoint(checkpoint)
	if err != nil {
		return result, err
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		privateKey,
	)
	if err != nil {
		return result, fmt.Errorf(
			"%w: invalid signer key",
			ErrInvalidCheckpoint,
		)
	}
	deviceID, err := codec.DeriveDeviceID(publicKey)
	if err != nil ||
		domain.DeviceID(deviceID) != checkpoint.SignerDeviceID {
		return result, fmt.Errorf(
			"%w: signer key does not match signer_device_id",
			ErrInvalidCheckpoint,
		)
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureCheckpoint,
		encoded,
	)
	if err != nil {
		return result, fmt.Errorf(
			"%w: sign tuple: %v",
			ErrInvalidCheckpoint,
			err,
		)
	}
	copy(result[:], signature)
	clear(signature)
	return result, nil
}
