package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
)

const maxEncodedResultBytes = 4 << 20

type commandResultWire struct {
	ChainHash      *string         `json:"chain_hash"`
	ChainIndex     *uint64         `json:"chain_index"`
	Outcome        json.RawMessage `json:"outcome"`
	Proposal       json.RawMessage `json:"proposal"`
	ProposalDigest string          `json:"proposal_digest"`
	ResultIndex    uint64          `json:"result_index"`
}

// DecodeResult parses an exact EncodeResult result. It rejects unknown,
// missing, duplicate, or otherwise noncanonical members.
func DecodeResult(encoded []byte) (Result, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedResultBytes {
		return Result{}, fmt.Errorf(
			"%w: encoded size %d outside 1..%d",
			ErrInvalidResult,
			len(encoded),
			maxEncodedResultBytes,
		)
	}
	type decodeWire struct {
		ChainHash      json.RawMessage `json:"chain_hash"`
		ChainIndex     json.RawMessage `json:"chain_index"`
		Outcome        json.RawMessage `json:"outcome"`
		Proposal       json.RawMessage `json:"proposal"`
		ProposalDigest json.RawMessage `json:"proposal_digest"`
		ResultIndex    json.RawMessage `json:"result_index"`
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire decodeWire
	if err := decoder.Decode(&wire); err != nil {
		return Result{}, fmt.Errorf("%w: decode: %v", ErrInvalidResult, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Result{}, fmt.Errorf(
				"%w: trailing JSON value",
				ErrInvalidResult,
			)
		}
		return Result{}, fmt.Errorf(
			"%w: trailing JSON: %v",
			ErrInvalidResult,
			err,
		)
	}

	for _, member := range []struct {
		name  string
		value json.RawMessage
	}{
		{name: "chain_hash", value: wire.ChainHash},
		{name: "chain_index", value: wire.ChainIndex},
		{name: "outcome", value: wire.Outcome},
		{name: "proposal", value: wire.Proposal},
		{name: "proposal_digest", value: wire.ProposalDigest},
		{name: "result_index", value: wire.ResultIndex},
	} {
		if member.value == nil {
			return Result{}, fmt.Errorf(
				"%w: missing member %s",
				ErrInvalidResult,
				member.name,
			)
		}
	}

	chainIndex, err := decodeNullableResultIndex(wire.ChainIndex)
	if err != nil {
		return Result{}, err
	}
	chainHash, err := decodeNullableResultDigest(
		"chain_hash",
		wire.ChainHash,
	)
	if err != nil {
		return Result{}, err
	}
	proposalDigest, err := decodeRequiredResultDigest(
		"proposal_digest",
		wire.ProposalDigest,
	)
	if err != nil {
		return Result{}, err
	}
	var resultIndex uint64
	if err := json.Unmarshal(wire.ResultIndex, &resultIndex); err != nil {
		return Result{}, fmt.Errorf(
			"%w: result_index must be an exact integer: %v",
			ErrInvalidResult,
			err,
		)
	}

	result := Result{
		ResultIndex:    resultIndex,
		Proposal:       bytes.Clone(wire.Proposal),
		Outcome:        bytes.Clone(wire.Outcome),
		ProposalDigest: proposalDigest,
		ChainIndex:     chainIndex,
		ChainHash:      chainHash,
	}
	canonical, err := EncodeResult(result)
	if err != nil {
		return Result{}, fmt.Errorf("%w: decoded value: %w", ErrInvalidResult, err)
	}
	if !bytes.Equal(canonical, encoded) {
		return Result{}, fmt.Errorf(
			"%w: encoding is not canonical",
			ErrInvalidResult,
		)
	}
	return result, nil
}

func decodeNullableResultIndex(encoded json.RawMessage) (*uint64, error) {
	var value *uint64
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf(
			"%w: chain_index must be null or an exact integer: %v",
			ErrInvalidResult,
			err,
		)
	}
	return value, nil
}

func decodeNullableResultDigest(
	name string,
	encoded json.RawMessage,
) (*Digest, error) {
	var text *string
	if err := json.Unmarshal(encoded, &text); err != nil {
		return nil, fmt.Errorf(
			"%w: %s must be null or a base64url string: %v",
			ErrInvalidResult,
			name,
			err,
		)
	}
	if text == nil {
		return nil, nil
	}
	value, err := codec.DecodeBase64URLExact(*text, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s: %w",
			ErrInvalidResult,
			name,
			err,
		)
	}
	var digest Digest
	copy(digest[:], value)
	return &digest, nil
}

func decodeRequiredResultDigest(
	name string,
	encoded json.RawMessage,
) (Digest, error) {
	value, err := decodeNullableResultDigest(name, encoded)
	if err != nil {
		return Digest{}, err
	}
	if value == nil {
		return Digest{}, fmt.Errorf(
			"%w: %s must not be null",
			ErrInvalidResult,
			name,
		)
	}
	return *value, nil
}

// EncodeResult returns the exact closed six-field command-result JCS object.
func EncodeResult(result Result) ([]byte, error) {
	if result.ResultIndex == 0 || result.ResultIndex > maxSafeInteger {
		return nil, fmt.Errorf(
			"%w: result index %d",
			ErrInvalidIndex,
			result.ResultIndex,
		)
	}
	if err := validateCanonicalObject("proposal", result.Proposal); err != nil {
		return nil, err
	}
	if err := validateCanonicalObject("outcome", result.Outcome); err != nil {
		return nil, err
	}
	outcomeStatus, err := decodeOutcomeStatus(result.Outcome)
	if err != nil {
		return nil, err
	}
	proposalDigest := sha256.Sum256(result.Proposal)
	if proposalDigest != result.ProposalDigest {
		return nil, ErrProposalDigest
	}

	if (result.ChainIndex == nil) != (result.ChainHash == nil) {
		return nil, fmt.Errorf(
			"%w: accepted chain index and hash must both be null or non-null",
			ErrInvalidResult,
		)
	}
	if result.ChainIndex != nil &&
		(*result.ChainIndex == 0 ||
			*result.ChainIndex > maxSafeInteger ||
			*result.ChainIndex > result.ResultIndex) {
		return nil, fmt.Errorf(
			"%w: accepted chain index %d at result %d",
			ErrInvalidIndex,
			*result.ChainIndex,
			result.ResultIndex,
		)
	}
	accepted := result.ChainIndex != nil
	if accepted != (outcomeStatus == "accepted") {
		return nil, fmt.Errorf(
			"%w: outcome status %q disagrees with chain tuple",
			ErrInvalidResult,
			outcomeStatus,
		)
	}

	var chainHash *string
	if result.ChainHash != nil {
		encoded := codec.EncodeBase64URL(result.ChainHash[:])
		chainHash = &encoded
	}
	encoded, err := json.Marshal(commandResultWire{
		ChainHash:      chainHash,
		ChainIndex:     result.ChainIndex,
		Outcome:        json.RawMessage(result.Outcome),
		Proposal:       json.RawMessage(result.Proposal),
		ProposalDigest: codec.EncodeBase64URL(result.ProposalDigest[:]),
		ResultIndex:    result.ResultIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("chain: encode command result: %w", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		return nil, fmt.Errorf("chain: canonicalize command result: %w", err)
	}
	return canonical, nil
}

func decodeOutcomeStatus(outcome []byte) (string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(outcome, &members); err != nil {
		return "", fmt.Errorf("%w: decode outcome", ErrInvalidResult)
	}

	var status string
	if err := json.Unmarshal(members["status"], &status); err != nil ||
		(status != "accepted" && status != "rejected") {
		return "", fmt.Errorf("%w: outcome status", ErrInvalidResult)
	}
	var code string
	if err := json.Unmarshal(members["code"], &code); err != nil || code == "" {
		return "", fmt.Errorf("%w: outcome code", ErrInvalidResult)
	}
	return status, nil
}

// AppendResult encodes result and extends the result chain with those exact
// bytes.
func AppendResult(previous Digest, result Result) (Digest, []byte, error) {
	encoded, err := EncodeResult(result)
	if err != nil {
		return Digest{}, nil, err
	}
	return digestDomain(resultChainLabel, previous[:], encoded), encoded, nil
}
