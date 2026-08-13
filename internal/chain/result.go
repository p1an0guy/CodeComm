package chain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
)

type commandResultWire struct {
	ChainHash      *string         `json:"chain_hash"`
	ChainIndex     *uint64         `json:"chain_index"`
	Outcome        json.RawMessage `json:"outcome"`
	Proposal       json.RawMessage `json:"proposal"`
	ProposalDigest string          `json:"proposal_digest"`
	ResultIndex    uint64          `json:"result_index"`
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
