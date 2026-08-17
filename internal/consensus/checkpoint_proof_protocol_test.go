package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

type checkpointProofRequesterFunc func(
	context.Context,
	domain.DeviceID,
	[]byte,
) (transport.ConsensusControlResponse, error)

func (function checkpointProofRequesterFunc) RequestConsensusProof(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	return function(ctx, deviceID, body)
}

func TestStagingApplyRequestRoundTripsCanonicalCheckpoint(t *testing.T) {
	t.Parallel()

	expectation := checkpointProofTestExpectation(t)
	encoded, err := encodeStagingApplyRequest(expectation)
	if err != nil {
		t.Fatalf("encodeStagingApplyRequest(): %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatalf("request is not canonical: %v", err)
	}
	request, err := decodeStagingApplyRequest(encoded)
	if err != nil {
		t.Fatalf("decodeStagingApplyRequest(): %v", err)
	}
	if request.targetDeviceID != expectation.targetDeviceID ||
		request.checkpointEventID !=
			expectation.record.CheckpointEventID ||
		!bytes.Equal(
			request.checkpointJSON,
			expectation.record.CheckpointJSON,
		) ||
		request.checkpointSignature !=
			expectation.record.AuthoritySignature {
		t.Fatalf("decoded request = %#v", request)
	}

	if _, err := decodeStagingApplyRequest(
		append(bytes.Clone(encoded), ' '),
	); !errors.Is(err, ErrInvalidCheckpointProof) {
		t.Fatalf("noncanonical request error = %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = json.RawMessage(`true`)
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err = codec.CanonicalizeSignedObject(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStagingApplyRequest(
		unknown,
	); !errors.Is(err, ErrInvalidCheckpointProof) {
		t.Fatalf("unknown-field request error = %v", err)
	}
}

func TestStagingApplyResponseRequiresExactExpectedTuple(t *testing.T) {
	t.Parallel()

	expectation := checkpointProofTestExpectation(t)
	proof := stagingApplyProof{
		expectation: expectation,
		appliedLogIndex: expectation.record.
			CoveredAppliedLogIndex + 1,
	}
	encoded, err := encodeStagingApplyResponse(proof)
	if err != nil {
		t.Fatalf("encodeStagingApplyResponse(): %v", err)
	}
	decoded, err := decodeStagingApplyResponse(encoded, expectation)
	if err != nil {
		t.Fatalf("decodeStagingApplyResponse(): %v", err)
	}
	if decoded.appliedLogIndex != proof.appliedLogIndex {
		t.Fatalf("decoded applied index = %d", decoded.appliedLogIndex)
	}

	var baseline stagingApplyResponseWire
	if err := json.Unmarshal(encoded, &baseline); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*stagingApplyResponseWire){
		"schema": func(wire *stagingApplyResponseWire) {
			wire.SchemaVersion++
		},
		"mode": func(wire *stagingApplyResponseWire) {
			wire.Mode = "target_activation"
		},
		"target": func(wire *stagingApplyResponseWire) {
			wire.TargetDeviceID = string(checkpointProofDeviceID('9'))
		},
		"event": func(wire *stagingApplyResponseWire) {
			wire.CheckpointEventID =
				"018f47de-89ab-7def-8123-112345678999"
		},
		"checkpoint": func(wire *stagingApplyResponseWire) {
			wire.Checkpoint = json.RawMessage(`{"unexpected":true}`)
		},
		"signature": func(wire *stagingApplyResponseWire) {
			wire.CheckpointSignature = codec.EncodeBase64URL(
				make([]byte, ed25519.SignatureSize),
			)
		},
		"applied index": func(wire *stagingApplyResponseWire) {
			wire.AppliedLogIndex++
		},
		"accumulator": func(wire *stagingApplyResponseWire) {
			wire.StoredProjectionAccumulator = codec.EncodeBase64URL(
				make([]byte, len(store.Digest{})),
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			wire := baseline
			wire.Checkpoint = bytes.Clone(baseline.Checkpoint)
			mutate(&wire)
			mutated, err := marshalCanonicalConsensusProof(wire)
			if err != nil {
				t.Fatalf("marshal mutation: %v", err)
			}
			if _, err := decodeStagingApplyResponse(
				mutated,
				expectation,
			); !errors.Is(err, ErrCheckpointProofMismatch) {
				t.Fatalf("decode mutation error = %v", err)
			}
		})
	}
}

func TestRequestStagingApplyProofClassifiesRemoteResults(t *testing.T) {
	t.Parallel()

	expectation := checkpointProofTestExpectation(t)
	responseBody, err := encodeStagingApplyResponse(stagingApplyProof{
		expectation: expectation,
		appliedLogIndex: expectation.record.
			CoveredAppliedLogIndex + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var observedRequest []byte
	requester := checkpointProofRequesterFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		if deviceID != expectation.targetDeviceID {
			t.Fatalf("request target = %q", deviceID)
		}
		observedRequest = bytes.Clone(body)
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       responseBody,
		}, nil
	})
	proof, err := requestStagingApplyProof(
		t.Context(),
		requester,
		expectation,
	)
	if err != nil ||
		proof.appliedLogIndex !=
			expectation.record.CoveredAppliedLogIndex+1 ||
		len(observedRequest) == 0 {
		t.Fatalf("requestStagingApplyProof() = (%#v, %v)", proof, err)
	}

	remoteProblem, err := json.Marshal(consensusProofProblem{
		Type:          "urn:codecomm:problem:checkpoint_not_applied",
		Title:         "Checkpoint not applied",
		Status:        http.StatusConflict,
		Code:          "checkpoint_not_applied",
		CorrelationID: "018f47de-89ab-7def-8123-0123456789ab",
		Retryable:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestStagingApplyProof(
		t.Context(),
		checkpointProofRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusConflict,
				MediaType:  "application/problem+json",
				Body:       remoteProblem,
			}, nil
		}),
		expectation,
	)
	if !errors.Is(err, ErrCheckpointProofUnavailable) {
		t.Fatalf("remote problem error = %v", err)
	}

	terminalProblem, err := json.Marshal(consensusProofProblem{
		Type:          "urn:codecomm:problem:proof_forbidden",
		Title:         "Proof request forbidden",
		Status:        http.StatusForbidden,
		Code:          "proof_forbidden",
		CorrelationID: "018f47de-89ab-7def-8123-0123456789ab",
		Retryable:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestStagingApplyProof(
		t.Context(),
		checkpointProofRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusForbidden,
				MediaType:  "application/problem+json",
				Body:       terminalProblem,
			}, nil
		}),
		expectation,
	)
	if !errors.Is(err, ErrCheckpointProofRejected) ||
		errors.Is(err, ErrCheckpointProofUnavailable) {
		t.Fatalf("terminal remote problem error = %v", err)
	}
	duplicateCode := []byte(
		`{"type":"urn:codecomm:problem:proof_forbidden",` +
			`"title":"Proof request forbidden","status":403,` +
			`"code":"checkpoint_not_applied",` +
			`"code":"proof_forbidden","correlation_id":` +
			`"018f47de-89ab-7def-8123-0123456789ab",` +
			`"retryable":false}`,
	)
	if _, err := decodeConsensusProofProblem(
		duplicateCode,
		http.StatusForbidden,
	); !errors.Is(err, ErrInvalidCheckpointProof) {
		t.Fatalf("duplicate-key problem error = %v", err)
	}
	staleProblem, err := json.Marshal(consensusProofProblem{
		Type:          "urn:codecomm:problem:checkpoint_stale",
		Title:         "Checkpoint predates staging",
		Status:        http.StatusConflict,
		Code:          "checkpoint_stale",
		CorrelationID: "018f47de-89ab-7def-8123-0123456789ab",
		Retryable:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestStagingApplyProof(
		t.Context(),
		checkpointProofRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusConflict,
				MediaType:  "application/problem+json",
				Body:       staleProblem,
			}, nil
		}),
		expectation,
	)
	if !errors.Is(err, ErrCheckpointProofRejected) ||
		errors.Is(err, ErrCheckpointProofUnavailable) {
		t.Fatalf("stale remote problem error = %v", err)
	}

	transportFailure := errors.New("network failed")
	_, err = requestStagingApplyProof(
		t.Context(),
		checkpointProofRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{},
				transportFailure
		}),
		expectation,
	)
	if !errors.Is(err, ErrCheckpointProofUnavailable) ||
		!errors.Is(err, transportFailure) {
		t.Fatalf("transport failure error = %v", err)
	}
}

func checkpointProofTestExpectation(
	t *testing.T,
) stagingCheckpointExpectation {
	t.Helper()
	record := store.CheckpointRecord{
		CheckpointEventID: domain.UUIDv7(
			"018f47de-89ab-7def-8123-1123456789ab",
		),
		SessionID: domain.UUIDv7(
			"018f47de-89ab-7def-8123-0123456789ab",
		),
		WorkspaceID: domain.UUIDv4(
			"550e8400-e29b-41d4-a716-446655440000",
		),
		RecoveryGeneration:       2,
		AuthorityVoterSetVersion: 3,
		SignerDeviceID:           checkpointProofDeviceID('1'),
		Term:                     4,
		CoveredAppliedLogIndex:   5,
		CoveredChainIndex:        6,
		CoveredChainHash:         store.Digest{0x51},
		CoveredResultIndex:       7,
		CoveredResultHash:        store.Digest{0x61},
		ProjectionAccumulator:    store.Digest{0x71},
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
		AuthoritySignature:       store.Signature{0x81},
	}
	record.CheckpointJSON = checkpointProofTestCheckpointJSON(t, record)
	if err := record.Validate(); err != nil {
		t.Fatalf("checkpoint fixture: %v", err)
	}
	return stagingCheckpointExpectation{
		targetDeviceID: checkpointProofDeviceID('2'),
		record:         record,
	}
}

func checkpointProofTestCheckpointJSON(
	t *testing.T,
	record store.CheckpointRecord,
) []byte {
	t.Helper()
	wire := struct {
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
	}{
		SessionID:                string(record.SessionID),
		WorkspaceID:              string(record.WorkspaceID),
		RecoveryGeneration:       record.RecoveryGeneration,
		AuthorityVoterSetVersion: record.AuthorityVoterSetVersion,
		SignerDeviceID:           string(record.SignerDeviceID),
		Term:                     record.Term,
		CoveredAppliedLogIndex:   record.CoveredAppliedLogIndex,
		CoveredChainIndex:        record.CoveredChainIndex,
		CoveredChainHash: codec.EncodeBase64URL(
			record.CoveredChainHash[:],
		),
		CoveredResultIndex: record.CoveredResultIndex,
		CoveredResultHash: codec.EncodeBase64URL(
			record.CoveredResultHash[:],
		),
		ProjectionAccumulator: codec.EncodeBase64URL(
			record.ProjectionAccumulator[:],
		),
		DigestVersion:           record.DigestVersion,
		ProjectionSchemaVersion: record.ProjectionSchemaVersion,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func checkpointProofDeviceID(value byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(value), 64))
}
