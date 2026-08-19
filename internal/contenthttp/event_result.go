package contenthttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

// EventResult is the exact six-member command-result object committed by the
// leader. Storage-only result-chain links are deliberately excluded.
type EventResult struct {
	proposal       []byte
	proposalDigest store.Digest
	outcome        store.CommandOutcome
	resultIndex    uint64
	chainIndex     *uint64
	chainHash      *store.Digest
	valid          bool
}

// NewEventResult validates and copies one integrity-checked store lookup bound
// to the caller's current session generation.
func NewEventResult(
	lookup store.CommandResultLookup,
	expectedSessionID domain.UUIDv7,
	expectedRecoveryGeneration uint64,
) (EventResult, error) {
	if !expectedSessionID.Valid() ||
		!domain.ValidUnsignedInteger(expectedRecoveryGeneration) ||
		lookup.SessionID != expectedSessionID ||
		lookup.RecoveryGeneration != expectedRecoveryGeneration {
		return EventResult{}, ErrInvalidResponse
	}
	if lookup.EventID.Valid() {
		proposal, err := event.InspectUnverifiedProposal(
			lookup.CanonicalProposal,
		)
		if err != nil ||
			proposal.EventID != lookup.EventID ||
			proposal.SessionID != expectedSessionID {
			return EventResult{}, ErrInvalidResponse
		}
	} else {
		return EventResult{}, ErrInvalidResponse
	}
	digest := sha256.Sum256(lookup.CanonicalProposal)
	if digest != lookup.ProposalDigest ||
		lookup.Tuple.ResultIndex < 1 ||
		!domain.ValidUnsignedInteger(lookup.Tuple.ResultIndex) ||
		!validEventOutcome(lookup.Outcome) {
		return EventResult{}, ErrInvalidResponse
	}

	var chainIndex *uint64
	var chainHash *store.Digest
	switch lookup.Outcome.Status {
	case store.OutcomeAccepted:
		if lookup.Tuple.ChainIndex == nil ||
			lookup.Tuple.ChainHash == nil ||
			*lookup.Tuple.ChainIndex < 1 ||
			*lookup.Tuple.ChainIndex > lookup.Tuple.ResultIndex ||
			!domain.ValidUnsignedInteger(*lookup.Tuple.ChainIndex) {
			return EventResult{}, ErrInvalidResponse
		}
		index := *lookup.Tuple.ChainIndex
		hash := *lookup.Tuple.ChainHash
		chainIndex = &index
		chainHash = &hash
	case store.OutcomeRejected:
		if lookup.Tuple.ChainIndex != nil || lookup.Tuple.ChainHash != nil {
			return EventResult{}, ErrInvalidResponse
		}
	default:
		return EventResult{}, ErrInvalidResponse
	}
	return EventResult{
		proposal:       bytes.Clone(lookup.CanonicalProposal),
		proposalDigest: lookup.ProposalDigest,
		outcome: store.CommandOutcome{
			Status: lookup.Outcome.Status,
			Code:   lookup.Outcome.Code,
			JSON:   bytes.Clone(lookup.Outcome.JSON),
		},
		resultIndex: lookup.Tuple.ResultIndex,
		chainIndex:  chainIndex,
		chainHash:   chainHash,
		valid:       true,
	}, nil
}

// Proposal returns an independent copy of the exact signed proposal.
func (result EventResult) Proposal() []byte {
	return bytes.Clone(result.proposal)
}

// Outcome returns an independent copy of the committed canonical outcome.
func (result EventResult) Outcome() store.CommandOutcome {
	return store.CommandOutcome{
		Status: result.outcome.Status,
		Code:   result.outcome.Code,
		JSON:   bytes.Clone(result.outcome.JSON),
	}
}

// ResultIndex returns the dense first-seen command position.
func (result EventResult) ResultIndex() uint64 {
	return result.resultIndex
}

// ChainPosition returns the accepted-event position. Rejections return false.
func (result EventResult) ChainPosition() (
	uint64,
	store.Digest,
	bool,
) {
	if result.chainIndex == nil || result.chainHash == nil {
		return 0, store.Digest{}, false
	}
	return *result.chainIndex, *result.chainHash, true
}

type eventResultWire struct {
	ChainHash      *string         `json:"chain_hash"`
	ChainIndex     *uint64         `json:"chain_index"`
	Outcome        json.RawMessage `json:"outcome"`
	Proposal       json.RawMessage `json:"proposal"`
	ProposalDigest string          `json:"proposal_digest"`
	ResultIndex    uint64          `json:"result_index"`
}

func (result EventResult) canonicalBytes() ([]byte, error) {
	if !result.valid || !validEventOutcome(result.outcome) {
		return nil, ErrInvalidResponse
	}
	var chainHash *string
	if result.chainHash != nil {
		encoded := codec.EncodeBase64URL(result.chainHash[:])
		chainHash = &encoded
	}
	return marshalCanonical(eventResultWire{
		ChainHash:      chainHash,
		ChainIndex:     cloneEventResultIndex(result.chainIndex),
		Outcome:        bytes.Clone(result.outcome.JSON),
		Proposal:       bytes.Clone(result.proposal),
		ProposalDigest: codec.EncodeBase64URL(result.proposalDigest[:]),
		ResultIndex:    result.resultIndex,
	})
}

func decodeEventResult(
	body []byte,
	expectedProposal []byte,
	expectedSessionID domain.UUIDv7,
	expectedRecoveryGeneration uint64,
) (EventResult, error) {
	if !canonicalResponse(body) ||
		len(expectedProposal) == 0 ||
		!expectedSessionID.Valid() ||
		!domain.ValidUnsignedInteger(expectedRecoveryGeneration) {
		return EventResult{}, ErrResponseProtocol
	}
	var wire eventResultWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return EventResult{}, ErrResponseProtocol
	}
	proposal, err := event.InspectUnverifiedProposal(wire.Proposal)
	if err != nil ||
		proposal.SessionID != expectedSessionID ||
		!bytes.Equal(wire.Proposal, expectedProposal) {
		return EventResult{}, ErrResponseProtocol
	}
	proposalDigest, digestErr := codec.DecodeBase64URLExact(
		wire.ProposalDigest,
		sha256.Size,
	)
	if digestErr != nil {
		return EventResult{}, ErrResponseProtocol
	}
	var digest store.Digest
	copy(digest[:], proposalDigest)
	outcome, err := decodeEventOutcome(wire.Outcome)
	if err != nil {
		return EventResult{}, ErrResponseProtocol
	}
	lookup := store.CommandResultLookup{
		EventID:            proposal.EventID,
		SessionID:          expectedSessionID,
		RecoveryGeneration: expectedRecoveryGeneration,
		CanonicalProposal:  bytes.Clone(wire.Proposal),
		ProposalDigest:     digest,
		Outcome:            outcome,
		Tuple: store.CommandResultTuple{
			ResultIndex: wire.ResultIndex,
			ChainIndex:  cloneEventResultIndex(wire.ChainIndex),
		},
	}
	if wire.ChainHash != nil {
		decoded, decodeErr := codec.DecodeBase64URLExact(
			*wire.ChainHash,
			sha256.Size,
		)
		if decodeErr != nil {
			return EventResult{}, ErrResponseProtocol
		}
		hash := store.Digest{}
		copy(hash[:], decoded)
		lookup.Tuple.ChainHash = &hash
	}
	result, err := NewEventResult(
		lookup,
		expectedSessionID,
		expectedRecoveryGeneration,
	)
	if err != nil {
		return EventResult{}, ErrResponseProtocol
	}
	canonical, err := result.canonicalBytes()
	if err != nil || !bytes.Equal(canonical, body) {
		return EventResult{}, ErrResponseProtocol
	}
	return result, nil
}

func decodeEventOutcome(input []byte) (store.CommandOutcome, error) {
	if len(input) == 0 {
		return store.CommandOutcome{}, ErrInvalidResponse
	}
	var fields struct {
		Status string `json:"status"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(input, &fields); err != nil {
		return store.CommandOutcome{}, ErrInvalidResponse
	}
	outcome := store.CommandOutcome{
		Status: store.OutcomeStatus(fields.Status),
		Code:   fields.Code,
		JSON:   bytes.Clone(input),
	}
	if !validEventOutcome(outcome) {
		return store.CommandOutcome{}, ErrInvalidResponse
	}
	return outcome, nil
}

func validEventOutcome(outcome store.CommandOutcome) bool {
	if outcome.Status != store.OutcomeAccepted &&
		outcome.Status != store.OutcomeRejected {
		return false
	}
	if !validEventOutcomeCode(outcome.Code) ||
		len(outcome.JSON) == 0 ||
		len(outcome.JSON) > ResponseMaxBytes {
		return false
	}
	canonical, err := codec.CanonicalizeSignedObject(outcome.JSON)
	if err != nil || !bytes.Equal(canonical, outcome.JSON) {
		return false
	}
	var fields struct {
		Status string `json:"status"`
		Code   string `json:"code"`
	}
	return json.Unmarshal(outcome.JSON, &fields) == nil &&
		fields.Status == string(outcome.Status) &&
		fields.Code == outcome.Code
}

func validEventOutcomeCode(value string) bool {
	if len(value) < 1 || len(value) > 64 || !utf8.ValidString(value) {
		return false
	}
	for index := range len(value) {
		char := value[index]
		if char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' ||
			char == '_' {
			continue
		}
		return false
	}
	return true
}

func cloneEventResultIndex(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
