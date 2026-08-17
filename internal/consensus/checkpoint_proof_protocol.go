package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	consensusProofSchemaVersion    uint64 = 1
	consensusProofModeStagingApply        = "staging_apply"
	consensusProofPath                    = "/v1/consensus/prove"
)

var (
	ErrInvalidCheckpointProof = errors.New(
		"consensus: invalid checkpoint proof",
	)
	ErrCheckpointProofUnavailable = errors.New(
		"consensus: checkpoint proof unavailable",
	)
	ErrCheckpointProofRejected = errors.New(
		"consensus: checkpoint proof request rejected",
	)
	ErrCheckpointProofMismatch = errors.New(
		"consensus: checkpoint proof differs from requested checkpoint",
	)
)

type stagingApplyRequestWire struct {
	SchemaVersion       uint64          `json:"schema_version"`
	Mode                string          `json:"mode"`
	TargetDeviceID      string          `json:"target_device_id"`
	CheckpointEventID   string          `json:"checkpoint_event_id"`
	Checkpoint          json.RawMessage `json:"checkpoint"`
	CheckpointSignature string          `json:"checkpoint_signature"`
}

type stagingApplyResponseWire struct {
	SchemaVersion               uint64          `json:"schema_version"`
	Mode                        string          `json:"mode"`
	TargetDeviceID              string          `json:"target_device_id"`
	CheckpointEventID           string          `json:"checkpoint_event_id"`
	Checkpoint                  json.RawMessage `json:"checkpoint"`
	CheckpointSignature         string          `json:"checkpoint_signature"`
	AppliedLogIndex             uint64          `json:"applied_log_index"`
	StoredProjectionAccumulator string          `json:"stored_projection_accumulator"`
}

type stagingCheckpointExpectation struct {
	targetDeviceID domain.DeviceID
	record         store.CheckpointRecord
}

func (expectation stagingCheckpointExpectation) validate() error {
	if !expectation.targetDeviceID.Valid() ||
		expectation.record.Validate() != nil ||
		expectation.record.CoveredAppliedLogIndex >= domain.MaxSafeInteger {
		return ErrInvalidCheckpointProof
	}
	return nil
}

type stagingApplyRequest struct {
	targetDeviceID      domain.DeviceID
	checkpointEventID   domain.UUIDv7
	checkpointJSON      []byte
	checkpointSignature store.Signature
}

type stagingApplyProof struct {
	expectation     stagingCheckpointExpectation
	appliedLogIndex uint64
}

type consensusProofRequester interface {
	RequestConsensusProof(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error)
}

func requestStagingApplyProof(
	ctx context.Context,
	requester consensusProofRequester,
	expectation stagingCheckpointExpectation,
) (stagingApplyProof, error) {
	if ctx == nil || requester == nil ||
		expectation.validate() != nil {
		return stagingApplyProof{}, ErrInvalidCheckpointProof
	}
	encoded, err := encodeStagingApplyRequest(expectation)
	if err != nil {
		return stagingApplyProof{}, err
	}
	response, err := requester.RequestConsensusProof(
		ctx,
		expectation.targetDeviceID,
		encoded,
	)
	if err != nil {
		return stagingApplyProof{}, fmt.Errorf(
			"%w: %w",
			ErrCheckpointProofUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return stagingApplyProof{}, ErrInvalidCheckpointProof
		}
		problem, err := decodeConsensusProofProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return stagingApplyProof{}, err
		}
		classification := ErrCheckpointProofRejected
		if problem.Retryable {
			classification = ErrCheckpointProofUnavailable
		}
		return stagingApplyProof{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return stagingApplyProof{}, ErrInvalidCheckpointProof
	}
	proof, err := decodeStagingApplyResponse(
		response.Body,
		expectation,
	)
	if err != nil {
		return stagingApplyProof{}, err
	}
	return proof, nil
}

func encodeStagingApplyRequest(
	expectation stagingCheckpointExpectation,
) ([]byte, error) {
	if expectation.validate() != nil {
		return nil, ErrInvalidCheckpointProof
	}
	return marshalCanonicalConsensusProof(stagingApplyRequestWire{
		SchemaVersion:     consensusProofSchemaVersion,
		Mode:              consensusProofModeStagingApply,
		TargetDeviceID:    string(expectation.targetDeviceID),
		CheckpointEventID: string(expectation.record.CheckpointEventID),
		Checkpoint:        expectation.record.CheckpointJSON,
		CheckpointSignature: codec.EncodeBase64URL(
			expectation.record.AuthoritySignature[:],
		),
	})
}

func decodeStagingApplyRequest(
	encoded []byte,
) (stagingApplyRequest, error) {
	var wire stagingApplyRequestWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return stagingApplyRequest{}, err
	}
	signature, err := codec.DecodeBase64URLExact(
		wire.CheckpointSignature,
		ed25519.SignatureSize,
	)
	targetDeviceID := domain.DeviceID(wire.TargetDeviceID)
	checkpointEventID := domain.UUIDv7(wire.CheckpointEventID)
	checkpointJSON, checkpointErr := canonicalCheckpointJSON(
		wire.Checkpoint,
	)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeStagingApply ||
		!targetDeviceID.Valid() ||
		!checkpointEventID.Valid() ||
		err != nil ||
		checkpointErr != nil {
		return stagingApplyRequest{}, ErrInvalidCheckpointProof
	}
	request := stagingApplyRequest{
		targetDeviceID:    targetDeviceID,
		checkpointEventID: checkpointEventID,
		checkpointJSON:    checkpointJSON,
	}
	copy(request.checkpointSignature[:], signature)
	return request, nil
}

func encodeStagingApplyResponse(
	proof stagingApplyProof,
) ([]byte, error) {
	if proof.expectation.validate() != nil ||
		proof.appliedLogIndex !=
			proof.expectation.record.CoveredAppliedLogIndex+1 {
		return nil, ErrInvalidCheckpointProof
	}
	return marshalCanonicalConsensusProof(stagingApplyResponseWire{
		SchemaVersion:     consensusProofSchemaVersion,
		Mode:              consensusProofModeStagingApply,
		TargetDeviceID:    string(proof.expectation.targetDeviceID),
		CheckpointEventID: string(proof.expectation.record.CheckpointEventID),
		Checkpoint:        proof.expectation.record.CheckpointJSON,
		CheckpointSignature: codec.EncodeBase64URL(
			proof.expectation.record.AuthoritySignature[:],
		),
		AppliedLogIndex: proof.appliedLogIndex,
		StoredProjectionAccumulator: codec.EncodeBase64URL(
			proof.expectation.record.ProjectionAccumulator[:],
		),
	})
}

func decodeStagingApplyResponse(
	encoded []byte,
	expected stagingCheckpointExpectation,
) (stagingApplyProof, error) {
	if expected.validate() != nil {
		return stagingApplyProof{}, ErrInvalidCheckpointProof
	}
	var wire stagingApplyResponseWire
	if err := decodeCanonicalConsensusProof(encoded, &wire); err != nil {
		return stagingApplyProof{}, err
	}
	signature, signatureErr := codec.DecodeBase64URLExact(
		wire.CheckpointSignature,
		ed25519.SignatureSize,
	)
	accumulator, accumulatorErr := codec.DecodeBase64URLExact(
		wire.StoredProjectionAccumulator,
		len(expected.record.ProjectionAccumulator),
	)
	checkpointJSON, checkpointErr := canonicalCheckpointJSON(
		wire.Checkpoint,
	)
	if wire.SchemaVersion != consensusProofSchemaVersion ||
		wire.Mode != consensusProofModeStagingApply ||
		domain.DeviceID(wire.TargetDeviceID) != expected.targetDeviceID ||
		domain.UUIDv7(wire.CheckpointEventID) !=
			expected.record.CheckpointEventID ||
		wire.AppliedLogIndex !=
			expected.record.CoveredAppliedLogIndex+1 ||
		signatureErr != nil ||
		accumulatorErr != nil ||
		checkpointErr != nil ||
		!bytes.Equal(checkpointJSON, expected.record.CheckpointJSON) ||
		!bytes.Equal(signature, expected.record.AuthoritySignature[:]) ||
		!bytes.Equal(
			accumulator,
			expected.record.ProjectionAccumulator[:],
		) {
		return stagingApplyProof{}, ErrCheckpointProofMismatch
	}
	return stagingApplyProof{
		expectation:     expected,
		appliedLogIndex: wire.AppliedLogIndex,
	}, nil
}

func marshalCanonicalConsensusProof(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode JSON", ErrInvalidCheckpointProof)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return nil, fmt.Errorf(
			"%w: canonical JSON",
			ErrInvalidCheckpointProof,
		)
	}
	return canonical, nil
}

func decodeCanonicalConsensusProof(
	encoded []byte,
	destination any,
) error {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes ||
		destination == nil {
		return ErrInvalidCheckpointProof
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidCheckpointProof
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidCheckpointProof
	}
	if err := requireConsensusProofJSONEOF(decoder); err != nil {
		return ErrInvalidCheckpointProof
	}
	return nil
}

func canonicalCheckpointJSON(
	encoded json.RawMessage,
) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, ErrInvalidCheckpointProof
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrInvalidCheckpointProof
	}
	return bytes.Clone(canonical), nil
}

func requireConsensusProofJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrInvalidCheckpointProof
}

type consensusProofProblem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
	Retryable     bool   `json:"retryable"`
	Detail        string `json:"detail,omitempty"`
}

func decodeConsensusProofProblem(
	encoded []byte,
	status int,
) (consensusProofProblem, error) {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes {
		return consensusProofProblem{}, ErrInvalidCheckpointProof
	}
	if _, err := codec.Canonicalize(encoded); err != nil {
		return consensusProofProblem{}, ErrInvalidCheckpointProof
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return consensusProofProblem{}, ErrInvalidCheckpointProof
	}
	required := [...]string{
		"type",
		"title",
		"status",
		"code",
		"correlation_id",
		"retryable",
	}
	for _, field := range required {
		if _, exists := members[field]; !exists {
			return consensusProofProblem{}, ErrInvalidCheckpointProof
		}
	}
	if len(members) != len(required) {
		if _, hasDetail := members["detail"]; !hasDetail ||
			len(members) != len(required)+1 {
			return consensusProofProblem{}, ErrInvalidCheckpointProof
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var problem consensusProofProblem
	if err := decoder.Decode(&problem); err != nil ||
		requireConsensusProofJSONEOF(decoder) != nil ||
		status < http.StatusBadRequest ||
		status > 599 ||
		problem.Status != status ||
		problem.Type != "urn:codecomm:problem:"+problem.Code ||
		!validConsensusProofProblemSemantics(problem) ||
		!validConsensusProofText(problem.Title, 1, 128) ||
		!validConsensusProofText(problem.CorrelationID, 1, 128) ||
		!validConsensusProofText(problem.Detail, 0, 1024) {
		return consensusProofProblem{}, ErrInvalidCheckpointProof
	}
	return problem, nil
}

func validConsensusProofProblemSemantics(
	problem consensusProofProblem,
) bool {
	switch problem.Code {
	case "route_not_found":
		return problem.Status == http.StatusNotFound &&
			!problem.Retryable
	case "unsupported_media_type":
		return problem.Status == http.StatusUnsupportedMediaType &&
			!problem.Retryable
	case "body_too_large":
		return problem.Status == http.StatusRequestEntityTooLarge &&
			!problem.Retryable
	case "invalid_proof_request":
		return problem.Status == http.StatusBadRequest &&
			!problem.Retryable
	case "proof_forbidden":
		return problem.Status == http.StatusForbidden &&
			!problem.Retryable
	case "checkpoint_not_applied":
		return problem.Status == http.StatusConflict &&
			problem.Retryable
	case "checkpoint_stale", "checkpoint_mismatch":
		return problem.Status == http.StatusConflict &&
			!problem.Retryable
	case "proof_unavailable":
		return (problem.Status == http.StatusRequestTimeout ||
			problem.Status == http.StatusServiceUnavailable) &&
			problem.Retryable
	case "internal_error":
		return problem.Status == http.StatusInternalServerError &&
			problem.Retryable
	default:
		return false
	}
}

func validConsensusProofText(
	value string,
	minimum int,
	maximum int,
) bool {
	return len(value) >= minimum &&
		len(value) <= maximum &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}
