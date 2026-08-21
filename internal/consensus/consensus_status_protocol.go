package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	consensusStatusPath                 = "/v1/consensus/status"
	consensusStatusSchemaVersion uint64 = 1
)

var (
	ErrInvalidConsensusStatus = errors.New(
		"consensus: invalid consensus status",
	)
	ErrConsensusStatusUnavailable = errors.New(
		"consensus: consensus status unavailable",
	)
	ErrConsensusStatusRejected = errors.New(
		"consensus: consensus status request rejected",
	)
	ErrConsensusStatusMismatch = errors.New(
		"consensus: consensus status response mismatch",
	)
)

type consensusStatusResponseWire struct {
	SchemaVersion                  uint64                        `json:"schema_version"`
	SessionID                      string                        `json:"session_id"`
	RecoveryGeneration             uint64                        `json:"recovery_generation"`
	ServerDeviceID                 string                        `json:"server_device_id"`
	LocalTerm                      uint64                        `json:"local_term"`
	LeaderDeviceID                 *string                       `json:"leader_device_id"`
	QuorumRequired                 uint64                        `json:"quorum_required"`
	LastRaftAppliedLogIndex        *uint64                       `json:"last_raft_applied_log_index"`
	ContentCredentialAuthorization credentialRenewalResponseWire `json:"content_credential_authorization"`
}

// ConsensusStatusResult is one peer-pinned identity-plane bootstrap cut.
// The caller still verifies the authorization's signatures and compares the
// returned lineage with its own applied state before provisional use.
type ConsensusStatusResult struct {
	SessionID                      domain.UUIDv7
	RecoveryGeneration             uint64
	ServerDeviceID                 domain.DeviceID
	LocalTerm                      uint64
	LeaderDeviceID                 *domain.DeviceID
	QuorumRequired                 uint64
	LastRaftAppliedLogIndex        *uint64
	ContentCredentialAuthorization credentialauthorization.Authorization
}

// ConsensusStatusRequester sends the bodyless identity-authenticated request.
type ConsensusStatusRequester interface {
	RequestConsensusStatus(
		context.Context,
		domain.DeviceID,
	) (transport.ConsensusControlResponse, error)
}

// RequestConsensusStatus fetches and strictly validates one peer's bounded
// late-wake bootstrap cut.
func RequestConsensusStatus(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
) (ConsensusStatusResult, error) {
	return requestConsensusStatusWithClock(
		ctx,
		requester,
		peerDeviceID,
		time.Now,
	)
}

func requestConsensusStatusAt(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
	now time.Time,
) (ConsensusStatusResult, error) {
	return requestConsensusStatusWithClock(
		ctx,
		requester,
		peerDeviceID,
		func() time.Time { return now },
	)
}

func requestConsensusStatusWithClock(
	ctx context.Context,
	requester ConsensusStatusRequester,
	peerDeviceID domain.DeviceID,
	now func() time.Time,
) (ConsensusStatusResult, error) {
	if ctx == nil ||
		requester == nil ||
		!peerDeviceID.Valid() ||
		now == nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	if err := ctx.Err(); err != nil {
		return ConsensusStatusResult{}, err
	}
	response, err := requester.RequestConsensusStatus(ctx, peerDeviceID)
	if err != nil {
		return ConsensusStatusResult{}, fmt.Errorf(
			"%w: %w",
			ErrConsensusStatusUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return ConsensusStatusResult{}, ErrInvalidConsensusStatus
		}
		problem, err := decodeConsensusStatusProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return ConsensusStatusResult{}, err
		}
		classification := ErrConsensusStatusRejected
		if problem.Retryable {
			classification = ErrConsensusStatusUnavailable
		}
		return ConsensusStatusResult{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	receivedAt := now()
	if receivedAt.IsZero() {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	return decodeConsensusStatusResponse(
		response.Body,
		peerDeviceID,
		receivedAt,
	)
}

func encodeConsensusStatusResponse(
	status ConsensusStatusResult,
	now time.Time,
) ([]byte, error) {
	return encodeConsensusStatusResponseForUse(status, now, true)
}

func encodeConsensusStatusResponseForUse(
	status ConsensusStatusResult,
	now time.Time,
	serverActive bool,
) ([]byte, error) {
	if err := validateConsensusStatusResult(
		status,
		status.ServerDeviceID,
		now,
		serverActive,
	); err != nil {
		return nil, err
	}
	authorization, err := credentialAuthorizationToWire(
		status.ContentCredentialAuthorization,
	)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	wire := consensusStatusResponseWire{
		SchemaVersion:                  consensusStatusSchemaVersion,
		SessionID:                      string(status.SessionID),
		RecoveryGeneration:             status.RecoveryGeneration,
		ServerDeviceID:                 string(status.ServerDeviceID),
		LocalTerm:                      status.LocalTerm,
		LeaderDeviceID:                 encodeOptionalDeviceID(status.LeaderDeviceID),
		QuorumRequired:                 status.QuorumRequired,
		LastRaftAppliedLogIndex:        cloneOptionalUint64(status.LastRaftAppliedLogIndex),
		ContentCredentialAuthorization: authorization,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrInvalidConsensusStatus
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return nil, ErrInvalidConsensusStatus
	}
	return bytes.Clone(canonical), nil
}

func decodeConsensusStatusResponse(
	encoded []byte,
	expectedServerDeviceID domain.DeviceID,
	now time.Time,
) (ConsensusStatusResult, error) {
	var wire consensusStatusResponseWire
	if err := decodeCanonicalConsensusStatus(encoded, &wire); err != nil {
		return ConsensusStatusResult{}, err
	}
	authorization, err := credentialAuthorizationFromWire(
		wire.ContentCredentialAuthorization,
	)
	if err != nil {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	status := ConsensusStatusResult{
		SessionID:                      domain.UUIDv7(wire.SessionID),
		RecoveryGeneration:             wire.RecoveryGeneration,
		ServerDeviceID:                 domain.DeviceID(wire.ServerDeviceID),
		LocalTerm:                      wire.LocalTerm,
		LeaderDeviceID:                 decodeOptionalDeviceID(wire.LeaderDeviceID),
		QuorumRequired:                 wire.QuorumRequired,
		LastRaftAppliedLogIndex:        cloneOptionalUint64(wire.LastRaftAppliedLogIndex),
		ContentCredentialAuthorization: authorization,
	}
	if err := validateConsensusStatusResult(
		status,
		expectedServerDeviceID,
		now,
		false,
	); err != nil {
		return ConsensusStatusResult{}, err
	}
	expected, err := encodeConsensusStatusResponseForUse(
		status,
		now,
		false,
	)
	if err != nil || !bytes.Equal(expected, encoded) {
		return ConsensusStatusResult{}, ErrInvalidConsensusStatus
	}
	return cloneConsensusStatusResult(status), nil
}

func validateConsensusStatusResult(
	status ConsensusStatusResult,
	expectedServerDeviceID domain.DeviceID,
	now time.Time,
	serverActive bool,
) error {
	maximumQuorum := uint64(policy.MaxMemberDevices/2 + 1)
	if !expectedServerDeviceID.Valid() ||
		!status.SessionID.Valid() ||
		!domain.ValidUnsignedInteger(status.RecoveryGeneration) ||
		status.ServerDeviceID != expectedServerDeviceID ||
		status.LocalTerm < 1 ||
		!domain.ValidUnsignedInteger(status.LocalTerm) ||
		status.QuorumRequired < 1 ||
		status.QuorumRequired > maximumQuorum ||
		status.LeaderDeviceID != nil &&
			!(*status.LeaderDeviceID).Valid() ||
		status.LastRaftAppliedLogIndex != nil &&
			(*status.LastRaftAppliedLogIndex < 1 ||
				!domain.ValidUnsignedInteger(
					*status.LastRaftAppliedLogIndex,
				)) {
		return ErrConsensusStatusMismatch
	}
	authorization := status.ContentCredentialAuthorization
	if authorization.Validate() != nil ||
		authorization.SessionID != status.SessionID ||
		authorization.DeviceID != status.ServerDeviceID ||
		!consensusStatusAuthorizationUsableAt(
			authorization,
			now,
			serverActive,
		) {
		return ErrConsensusStatusMismatch
	}
	return nil
}

func consensusStatusAuthorizationUsableAt(
	authorization credentialauthorization.Authorization,
	now time.Time,
	serverActive bool,
) bool {
	if serverActive {
		return authorization.ActiveAt(now)
	}
	if now.IsZero() || authorization.Validate() != nil {
		return false
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		return false
	}
	expiresAt := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	return !now.Add(credentialEndorsementClockSkew).Before(notBefore) &&
		now.Before(expiresAt)
}

func decodeCanonicalConsensusStatus(encoded []byte, destination any) error {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes ||
		destination == nil {
		return ErrInvalidConsensusStatus
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidConsensusStatus
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidConsensusStatus
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidConsensusStatus
	}
	return nil
}

func decodeConsensusStatusProblem(
	encoded []byte,
	status int,
) (consensusProofProblem, error) {
	var members map[string]json.RawMessage
	if err := decodeCanonicalConsensusStatus(encoded, &members); err != nil {
		return consensusProofProblem{}, err
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
			return consensusProofProblem{}, ErrInvalidConsensusStatus
		}
	}
	if len(members) != len(required) {
		if _, hasDetail := members["detail"]; !hasDetail ||
			len(members) != len(required)+1 {
			return consensusProofProblem{}, ErrInvalidConsensusStatus
		}
	}
	var problem consensusProofProblem
	if err := decodeCanonicalConsensusStatus(encoded, &problem); err != nil {
		return consensusProofProblem{}, err
	}
	if status < http.StatusBadRequest ||
		status > 599 ||
		problem.Status != status ||
		problem.Type != "urn:codecomm:problem:"+problem.Code ||
		!validConsensusProofText(problem.Title, 1, 128) ||
		!validConsensusProofText(problem.CorrelationID, 1, 128) ||
		!validConsensusProofText(problem.Detail, 0, 1024) ||
		!validConsensusStatusProblem(problem) {
		return consensusProofProblem{}, ErrInvalidConsensusStatus
	}
	return problem, nil
}

func validConsensusStatusProblem(problem consensusProofProblem) bool {
	switch problem.Code {
	case "route_not_found":
		return problem.Status == http.StatusNotFound && !problem.Retryable
	case "unsupported_media_type":
		return problem.Status == http.StatusUnsupportedMediaType &&
			!problem.Retryable
	case "invalid_consensus_status_request":
		return problem.Status == http.StatusBadRequest &&
			!problem.Retryable
	case "consensus_status_forbidden":
		return problem.Status == http.StatusForbidden &&
			!problem.Retryable
	case "consensus_status_unavailable":
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

func encodeOptionalDeviceID(value *domain.DeviceID) *string {
	if value == nil {
		return nil
	}
	encoded := string(*value)
	return &encoded
}

func decodeOptionalDeviceID(value *string) *domain.DeviceID {
	if value == nil {
		return nil
	}
	decoded := domain.DeviceID(*value)
	return &decoded
}

func cloneOptionalUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneConsensusStatusResult(
	status ConsensusStatusResult,
) ConsensusStatusResult {
	result := status
	if status.LeaderDeviceID != nil {
		leader := *status.LeaderDeviceID
		result.LeaderDeviceID = &leader
	}
	result.LastRaftAppliedLogIndex = cloneOptionalUint64(
		status.LastRaftAppliedLogIndex,
	)
	result.ContentCredentialAuthorization =
		status.ContentCredentialAuthorization.Clone()
	return result
}
