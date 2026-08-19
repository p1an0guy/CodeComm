package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	credentialRenewalPath                 = "/v1/credentials/renew"
	credentialRenewalSchemaVersion uint64 = 1
)

var (
	ErrInvalidCredentialRenewal = errors.New(
		"consensus: invalid credential renewal",
	)
	ErrCredentialRenewalUnavailable = errors.New(
		"consensus: credential renewal unavailable",
	)
	ErrCredentialRenewalRejected = errors.New(
		"consensus: credential renewal rejected",
	)
	ErrCredentialRenewalMismatch = errors.New(
		"consensus: credential renewal response mismatch",
	)
)

type credentialRenewalMode string

const (
	credentialRenewalModeSubmit  credentialRenewalMode = "submit"
	credentialRenewalModeForward credentialRenewalMode = "forward"
)

func (mode credentialRenewalMode) valid() bool {
	return mode == credentialRenewalModeSubmit ||
		mode == credentialRenewalModeForward
}

type credentialRenewalRequestWire struct {
	SchemaVersion    uint64 `json:"schema_version"`
	Mode             string `json:"mode"`
	SessionID        string `json:"session_id"`
	DeviceID         string `json:"device_id"`
	Epoch            uint64 `json:"epoch"`
	EpochPublicKey   string `json:"epoch_public_key"`
	KeyDigest        string `json:"key_digest"`
	BindingSignature string `json:"binding_signature"`
}

type credentialRenewalEndorsementWire struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

type credentialRenewalResponseWire struct {
	SchemaVersion            uint64                             `json:"schema_version"`
	SessionID                string                             `json:"session_id"`
	DeviceID                 string                             `json:"device_id"`
	Epoch                    uint64                             `json:"epoch"`
	EpochPublicKey           string                             `json:"epoch_public_key"`
	KeyDigest                string                             `json:"key_digest"`
	Role                     string                             `json:"role"`
	IssuedAt                 string                             `json:"issued_at"`
	NotBefore                string                             `json:"not_before"`
	ValiditySeconds          uint64                             `json:"validity_seconds"`
	AuthorityVoterSetVersion uint64                             `json:"authority_voter_set_version"`
	ClockEndorsements        []credentialRenewalEndorsementWire `json:"clock_endorsements"`
	BindingSignature         string                             `json:"binding_signature"`
	AuthorizationChainIndex  uint64                             `json:"authorization_chain_index"`
}

type credentialRenewalRequest struct {
	mode      credentialRenewalMode
	binding   credential.Binding
	canonical []byte
}

type credentialRenewalRequester interface {
	RequestCredentialRenewal(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error)
}

func newCredentialRenewalRequest(
	binding credential.Binding,
	mode credentialRenewalMode,
) (credentialRenewalRequest, error) {
	if !mode.valid() ||
		!validCredentialRenewalBindingShape(binding) {
		return credentialRenewalRequest{}, ErrInvalidCredentialRenewal
	}
	encoded, err := json.Marshal(credentialRenewalRequestWire{
		SchemaVersion:    credentialRenewalSchemaVersion,
		Mode:             string(mode),
		SessionID:        string(binding.SessionID),
		DeviceID:         string(binding.DeviceID),
		Epoch:            binding.Epoch,
		EpochPublicKey:   codec.EncodeBase64URL(binding.EpochPublicKey[:]),
		KeyDigest:        codec.EncodeBase64URL(binding.KeyDigest[:]),
		BindingSignature: codec.EncodeBase64URL(binding.Signature[:]),
	})
	if err != nil {
		return credentialRenewalRequest{}, ErrInvalidCredentialRenewal
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return credentialRenewalRequest{}, ErrInvalidCredentialRenewal
	}
	return credentialRenewalRequest{
		mode:      mode,
		binding:   binding,
		canonical: bytes.Clone(canonical),
	}, nil
}

func decodeCredentialRenewalRequest(
	encoded []byte,
) (credentialRenewalRequest, error) {
	var wire credentialRenewalRequestWire
	if err := decodeCanonicalCredentialRenewal(encoded, &wire); err != nil {
		return credentialRenewalRequest{}, err
	}
	publicKey, publicKeyErr := codec.DecodeBase64URLExact(
		wire.EpochPublicKey,
		ed25519.PublicKeySize,
	)
	keyDigest, digestErr := codec.DecodeBase64URLExact(
		wire.KeyDigest,
		sha256.Size,
	)
	signature, signatureErr := codec.DecodeBase64URLExact(
		wire.BindingSignature,
		ed25519.SignatureSize,
	)
	request := credentialRenewalRequest{
		mode: credentialRenewalMode(wire.Mode),
		binding: credential.Binding{
			SessionID: domain.UUIDv7(wire.SessionID),
			DeviceID:  domain.DeviceID(wire.DeviceID),
			Epoch:     wire.Epoch,
		},
	}
	if wire.SchemaVersion != credentialRenewalSchemaVersion ||
		publicKeyErr != nil ||
		digestErr != nil ||
		signatureErr != nil {
		return credentialRenewalRequest{}, ErrInvalidCredentialRenewal
	}
	copy(request.binding.EpochPublicKey[:], publicKey)
	copy(request.binding.KeyDigest[:], keyDigest)
	copy(request.binding.Signature[:], signature)
	expected, err := newCredentialRenewalRequest(
		request.binding,
		request.mode,
	)
	if err != nil || !bytes.Equal(expected.canonical, encoded) {
		return credentialRenewalRequest{}, ErrInvalidCredentialRenewal
	}
	return expected, nil
}

func encodeCredentialRenewalResponse(
	authorization credentialauthorization.Authorization,
) ([]byte, error) {
	if err := authorization.Validate(); err != nil ||
		authorization.AuthorizationChainIndex == 0 {
		return nil, ErrInvalidCredentialRenewal
	}
	endorsements := make(
		[]credentialRenewalEndorsementWire,
		len(authorization.ClockEndorsements),
	)
	for index, endorsement := range authorization.ClockEndorsements {
		endorsements[index] = credentialRenewalEndorsementWire{
			DeviceID: string(endorsement.DeviceID),
			Signature: codec.EncodeBase64URL(
				endorsement.Signature[:],
			),
		}
	}
	encoded, err := json.Marshal(credentialRenewalResponseWire{
		SchemaVersion: credentialRenewalSchemaVersion,
		SessionID:     string(authorization.SessionID),
		DeviceID:      string(authorization.DeviceID),
		Epoch:         authorization.Epoch,
		EpochPublicKey: codec.EncodeBase64URL(
			authorization.EpochPublicKey[:],
		),
		KeyDigest: codec.EncodeBase64URL(
			authorization.KeyDigest[:],
		),
		Role:                     string(authorization.Role),
		IssuedAt:                 string(authorization.IssuedAt),
		NotBefore:                string(authorization.NotBefore),
		ValiditySeconds:          authorization.ValiditySeconds,
		AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
		ClockEndorsements:        endorsements,
		BindingSignature: codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
		AuthorizationChainIndex: authorization.AuthorizationChainIndex,
	})
	if err != nil {
		return nil, ErrInvalidCredentialRenewal
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return nil, ErrInvalidCredentialRenewal
	}
	return bytes.Clone(canonical), nil
}

func decodeCredentialRenewalResponse(
	encoded []byte,
	request credentialRenewalRequest,
) (credentialauthorization.Authorization, error) {
	if len(request.canonical) == 0 {
		return credentialauthorization.Authorization{},
			ErrInvalidCredentialRenewal
	}
	var wire credentialRenewalResponseWire
	if err := decodeCanonicalCredentialRenewal(encoded, &wire); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	publicKey, publicKeyErr := codec.DecodeBase64URLExact(
		wire.EpochPublicKey,
		ed25519.PublicKeySize,
	)
	keyDigest, digestErr := codec.DecodeBase64URLExact(
		wire.KeyDigest,
		sha256.Size,
	)
	bindingSignature, bindingErr := codec.DecodeBase64URLExact(
		wire.BindingSignature,
		ed25519.SignatureSize,
	)
	authorization := credentialauthorization.Authorization{
		SessionID:                domain.UUIDv7(wire.SessionID),
		DeviceID:                 domain.DeviceID(wire.DeviceID),
		Epoch:                    wire.Epoch,
		Role:                     credentialauthorization.Role(wire.Role),
		IssuedAt:                 domain.WholeSecondTimestamp(wire.IssuedAt),
		NotBefore:                domain.WholeSecondTimestamp(wire.NotBefore),
		ValiditySeconds:          wire.ValiditySeconds,
		AuthorityVoterSetVersion: wire.AuthorityVoterSetVersion,
		ClockEndorsements: make(
			[]credentialauthorization.ClockEndorsement,
			len(wire.ClockEndorsements),
		),
		AuthorizationChainIndex: wire.AuthorizationChainIndex,
	}
	if wire.SchemaVersion != credentialRenewalSchemaVersion ||
		publicKeyErr != nil ||
		digestErr != nil ||
		bindingErr != nil ||
		len(wire.ClockEndorsements) < 1 ||
		len(wire.ClockEndorsements) >
			credentialauthorization.MaxEndorsements {
		return credentialauthorization.Authorization{},
			ErrInvalidCredentialRenewal
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	copy(authorization.KeyDigest[:], keyDigest)
	copy(authorization.BindingSignature[:], bindingSignature)
	for index, endorsement := range wire.ClockEndorsements {
		signature, err := codec.DecodeBase64URLExact(
			endorsement.Signature,
			ed25519.SignatureSize,
		)
		if err != nil {
			return credentialauthorization.Authorization{},
				ErrInvalidCredentialRenewal
		}
		authorization.ClockEndorsements[index].DeviceID =
			domain.DeviceID(endorsement.DeviceID)
		copy(
			authorization.ClockEndorsements[index].Signature[:],
			signature,
		)
	}
	if err := authorization.Validate(); err != nil ||
		!credentialAuthorizationMatchesBinding(
			authorization,
			request.binding,
		) {
		return credentialauthorization.Authorization{},
			ErrCredentialRenewalMismatch
	}
	expected, err := encodeCredentialRenewalResponse(authorization)
	if err != nil || !bytes.Equal(expected, encoded) {
		return credentialauthorization.Authorization{},
			ErrInvalidCredentialRenewal
	}
	return authorization.Clone(), nil
}

func requestCredentialRenewal(
	ctx context.Context,
	requester credentialRenewalRequester,
	leaderDeviceID domain.DeviceID,
	binding credential.Binding,
	mode credentialRenewalMode,
) (credentialauthorization.Authorization, error) {
	if ctx == nil ||
		requester == nil ||
		!leaderDeviceID.Valid() {
		return credentialauthorization.Authorization{},
			ErrInvalidCredentialRenewal
	}
	request, err := newCredentialRenewalRequest(binding, mode)
	if err != nil {
		return credentialauthorization.Authorization{}, err
	}
	response, err := requester.RequestCredentialRenewal(
		ctx,
		leaderDeviceID,
		request.canonical,
	)
	if err != nil {
		return credentialauthorization.Authorization{}, fmt.Errorf(
			"%w: %w",
			ErrCredentialRenewalUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return credentialauthorization.Authorization{},
				ErrInvalidCredentialRenewal
		}
		problem, err := decodeCredentialRenewalProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return credentialauthorization.Authorization{}, err
		}
		classification := ErrCredentialRenewalRejected
		if problem.Retryable {
			classification = ErrCredentialRenewalUnavailable
		}
		return credentialauthorization.Authorization{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return credentialauthorization.Authorization{},
			ErrInvalidCredentialRenewal
	}
	return decodeCredentialRenewalResponse(response.Body, request)
}

func validCredentialRenewalBindingShape(
	binding credential.Binding,
) bool {
	if !binding.SessionID.Valid() ||
		!binding.DeviceID.Valid() ||
		binding.Epoch < 1 ||
		!domain.ValidUnsignedInteger(binding.Epoch) ||
		sha256.Sum256(binding.EpochPublicKey[:]) != binding.KeyDigest {
		return false
	}
	_, err := binding.CanonicalPreimage()
	return err == nil
}

func credentialAuthorizationMatchesBinding(
	authorization credentialauthorization.Authorization,
	binding credential.Binding,
) bool {
	return authorization.SessionID == binding.SessionID &&
		authorization.DeviceID == binding.DeviceID &&
		authorization.Epoch == binding.Epoch &&
		authorization.EpochPublicKey == binding.EpochPublicKey &&
		authorization.KeyDigest == binding.KeyDigest &&
		authorization.BindingSignature == binding.Signature
}

func decodeCanonicalCredentialRenewal(
	encoded []byte,
	destination any,
) error {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes ||
		destination == nil {
		return ErrInvalidCredentialRenewal
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidCredentialRenewal
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidCredentialRenewal
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidCredentialRenewal
	}
	return nil
}

func decodeCredentialRenewalProblem(
	encoded []byte,
	status int,
) (consensusProofProblem, error) {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes {
		return consensusProofProblem{}, ErrInvalidCredentialRenewal
	}
	if _, err := codec.Canonicalize(encoded); err != nil {
		return consensusProofProblem{}, ErrInvalidCredentialRenewal
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return consensusProofProblem{}, ErrInvalidCredentialRenewal
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
			return consensusProofProblem{}, ErrInvalidCredentialRenewal
		}
	}
	if len(members) != len(required) {
		if _, hasDetail := members["detail"]; !hasDetail ||
			len(members) != len(required)+1 {
			return consensusProofProblem{}, ErrInvalidCredentialRenewal
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
		!validConsensusProofText(problem.Title, 1, 128) ||
		!validConsensusProofText(problem.CorrelationID, 1, 128) ||
		!validConsensusProofText(problem.Detail, 0, 1024) ||
		!validCredentialRenewalProblem(problem) {
		return consensusProofProblem{}, ErrInvalidCredentialRenewal
	}
	return problem, nil
}

func validCredentialRenewalProblem(problem consensusProofProblem) bool {
	switch problem.Code {
	case "invalid_credential_renewal":
		return problem.Status == http.StatusBadRequest &&
			!problem.Retryable
	case "credential_renewal_forbidden":
		return problem.Status == http.StatusForbidden &&
			!problem.Retryable
	case "credential_renewal_too_early":
		return problem.Status == http.StatusConflict &&
			problem.Retryable
	case "credential_renewal_rejected":
		return problem.Status == http.StatusConflict &&
			!problem.Retryable
	case "credential_renewal_unavailable":
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
