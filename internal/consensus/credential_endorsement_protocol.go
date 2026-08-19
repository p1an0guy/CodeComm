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
	"reflect"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	credentialEndorsementPath                 = "/v1/credentials/endorse"
	credentialEndorsementSchemaVersion uint64 = 1
)

var (
	ErrInvalidCredentialEndorsement = errors.New(
		"consensus: invalid credential endorsement",
	)
	ErrCredentialEndorsementUnavailable = errors.New(
		"consensus: credential endorsement unavailable",
	)
	ErrCredentialEndorsementRejected = errors.New(
		"consensus: credential endorsement rejected",
	)
	ErrCredentialEndorsementMismatch = errors.New(
		"consensus: credential endorsement mismatch",
	)
	ErrInvalidCredentialEndorsementSigner = errors.New(
		"consensus: invalid credential endorsement signer",
	)
)

// CredentialEndorsementSigner is a device-bound identity signing capability.
// Implementations must sign only the supplied frozen credential-time
// endorsement preimage and return when the context is canceled.
type CredentialEndorsementSigner interface {
	DeviceID() domain.DeviceID
	SignCredentialEndorsement(
		context.Context,
		credentialauthorization.Authorization,
	) ([ed25519.SignatureSize]byte, error)
}

// CredentialEndorsementSignerAdapter binds a focused signing function to one
// device while deriving the exact preimage inside consensus.
type CredentialEndorsementSignerAdapter struct {
	SignerDeviceID domain.DeviceID
	Sign           func(
		context.Context,
		[]byte,
	) ([ed25519.SignatureSize]byte, error)
}

func (adapter CredentialEndorsementSignerAdapter) DeviceID() domain.DeviceID {
	return adapter.SignerDeviceID
}

func (adapter CredentialEndorsementSignerAdapter) SignCredentialEndorsement(
	ctx context.Context,
	authorization credentialauthorization.Authorization,
) ([ed25519.SignatureSize]byte, error) {
	if ctx == nil ||
		!adapter.SignerDeviceID.Valid() ||
		adapter.Sign == nil {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidCredentialEndorsementSigner
	}
	if err := ctx.Err(); err != nil {
		return [ed25519.SignatureSize]byte{}, err
	}
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(authorization)
	if err != nil {
		return [ed25519.SignatureSize]byte{},
			ErrInvalidCredentialEndorsementSigner
	}
	return adapter.Sign(ctx, preimage)
}

type credentialEndorsementRequestWire struct {
	SchemaVersion            uint64 `json:"schema_version"`
	SessionID                string `json:"session_id"`
	SubjectDeviceID          string `json:"subject_device_id"`
	Epoch                    uint64 `json:"epoch"`
	EpochPublicKey           string `json:"epoch_public_key"`
	KeyDigest                string `json:"key_digest"`
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	IssuedAt                 string `json:"issued_at"`
}

type credentialEndorsementResponseWire struct {
	SchemaVersion    uint64 `json:"schema_version"`
	EndorserDeviceID string `json:"endorser_device_id"`
	RequestDigest    string `json:"request_digest"`
	Signature        string `json:"signature"`
}

type credentialEndorsementRequest struct {
	authorization credentialauthorization.Authorization
	canonical     []byte
	digest        [sha256.Size]byte
}

type credentialEndorsementProof struct {
	request          credentialEndorsementRequest
	endorserDeviceID domain.DeviceID
	signature        [ed25519.SignatureSize]byte
}

type credentialEndorsementRequester interface {
	RequestCredentialEndorsement(
		context.Context,
		domain.DeviceID,
		[]byte,
	) (transport.ConsensusControlResponse, error)
}

func newCredentialEndorsementRequest(
	authorization credentialauthorization.Authorization,
) (credentialEndorsementRequest, error) {
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(authorization)
	if err != nil {
		return credentialEndorsementRequest{},
			ErrInvalidCredentialEndorsement
	}
	_ = preimage
	encoded, err := json.Marshal(credentialEndorsementRequestWire{
		SchemaVersion:   credentialEndorsementSchemaVersion,
		SessionID:       string(authorization.SessionID),
		SubjectDeviceID: string(authorization.DeviceID),
		Epoch:           authorization.Epoch,
		EpochPublicKey: codec.EncodeBase64URL(
			authorization.EpochPublicKey[:],
		),
		KeyDigest:                codec.EncodeBase64URL(authorization.KeyDigest[:]),
		AuthorityVoterSetVersion: authorization.AuthorityVoterSetVersion,
		IssuedAt:                 string(authorization.IssuedAt),
	})
	if err != nil {
		return credentialEndorsementRequest{},
			ErrInvalidCredentialEndorsement
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return credentialEndorsementRequest{},
			ErrInvalidCredentialEndorsement
	}
	return credentialEndorsementRequest{
		authorization: authorization,
		canonical:     bytes.Clone(canonical),
		digest:        sha256.Sum256(canonical),
	}, nil
}

func decodeCredentialEndorsementRequest(
	encoded []byte,
) (credentialEndorsementRequest, error) {
	var wire credentialEndorsementRequestWire
	if err := decodeCanonicalCredentialMessage(encoded, &wire); err != nil {
		return credentialEndorsementRequest{}, err
	}
	publicKey, publicKeyErr := codec.DecodeBase64URLExact(
		wire.EpochPublicKey,
		ed25519.PublicKeySize,
	)
	publicDigest, digestErr := codec.DecodeBase64URLExact(
		wire.KeyDigest,
		sha256.Size,
	)
	authorization := credentialauthorization.Authorization{
		SessionID:                domain.UUIDv7(wire.SessionID),
		DeviceID:                 domain.DeviceID(wire.SubjectDeviceID),
		Epoch:                    wire.Epoch,
		AuthorityVoterSetVersion: wire.AuthorityVoterSetVersion,
		IssuedAt: domain.WholeSecondTimestamp(
			wire.IssuedAt,
		),
	}
	if wire.SchemaVersion != credentialEndorsementSchemaVersion ||
		publicKeyErr != nil ||
		digestErr != nil {
		return credentialEndorsementRequest{},
			ErrInvalidCredentialEndorsement
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	copy(authorization.KeyDigest[:], publicDigest)
	request, err := newCredentialEndorsementRequest(authorization)
	if err != nil || !bytes.Equal(request.canonical, encoded) {
		return credentialEndorsementRequest{},
			ErrInvalidCredentialEndorsement
	}
	return request, nil
}

func encodeCredentialEndorsementResponse(
	request credentialEndorsementRequest,
	endorserDeviceID domain.DeviceID,
	signature [ed25519.SignatureSize]byte,
) ([]byte, error) {
	if !endorserDeviceID.Valid() ||
		len(request.canonical) == 0 {
		return nil, ErrInvalidCredentialEndorsement
	}
	encoded, err := json.Marshal(credentialEndorsementResponseWire{
		SchemaVersion:    credentialEndorsementSchemaVersion,
		EndorserDeviceID: string(endorserDeviceID),
		RequestDigest:    codec.EncodeBase64URL(request.digest[:]),
		Signature:        codec.EncodeBase64URL(signature[:]),
	})
	if err != nil {
		return nil, ErrInvalidCredentialEndorsement
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil ||
		len(canonical) == 0 ||
		len(canonical) > transport.ConsensusControlBodyMaxBytes {
		return nil, ErrInvalidCredentialEndorsement
	}
	return bytes.Clone(canonical), nil
}

func decodeCredentialEndorsementResponse(
	encoded []byte,
	request credentialEndorsementRequest,
	endorserDeviceID domain.DeviceID,
	endorserPublicKey ed25519.PublicKey,
) (credentialEndorsementProof, error) {
	if !endorserDeviceID.Valid() ||
		len(endorserPublicKey) != ed25519.PublicKeySize {
		return credentialEndorsementProof{},
			ErrInvalidCredentialEndorsement
	}
	derived, err := device.DeriveID(endorserPublicKey)
	if err != nil || derived != endorserDeviceID {
		return credentialEndorsementProof{},
			ErrInvalidCredentialEndorsement
	}
	var wire credentialEndorsementResponseWire
	if err := decodeCanonicalCredentialMessage(encoded, &wire); err != nil {
		return credentialEndorsementProof{}, err
	}
	digest, digestErr := codec.DecodeBase64URLExact(
		wire.RequestDigest,
		sha256.Size,
	)
	signature, signatureErr := codec.DecodeBase64URLExact(
		wire.Signature,
		ed25519.SignatureSize,
	)
	preimage, preimageErr := credentialauthorization.
		CanonicalEndorsementPreimage(request.authorization)
	if wire.SchemaVersion != credentialEndorsementSchemaVersion ||
		domain.DeviceID(wire.EndorserDeviceID) != endorserDeviceID ||
		digestErr != nil ||
		!bytes.Equal(digest, request.digest[:]) ||
		signatureErr != nil ||
		preimageErr != nil ||
		codecommcrypto.VerifyEd25519(
			endorserPublicKey,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
			signature,
		) != nil {
		return credentialEndorsementProof{},
			ErrCredentialEndorsementMismatch
	}
	proof := credentialEndorsementProof{
		request:          request,
		endorserDeviceID: endorserDeviceID,
	}
	copy(proof.signature[:], signature)
	return proof, nil
}

func requestCredentialEndorsement(
	ctx context.Context,
	requester credentialEndorsementRequester,
	endorserDeviceID domain.DeviceID,
	endorserPublicKey ed25519.PublicKey,
	authorization credentialauthorization.Authorization,
) (credentialEndorsementProof, error) {
	if ctx == nil ||
		requester == nil ||
		!endorserDeviceID.Valid() ||
		len(endorserPublicKey) != ed25519.PublicKeySize {
		return credentialEndorsementProof{},
			ErrInvalidCredentialEndorsement
	}
	request, err := newCredentialEndorsementRequest(authorization)
	if err != nil {
		return credentialEndorsementProof{}, err
	}
	response, err := requester.RequestCredentialEndorsement(
		ctx,
		endorserDeviceID,
		request.canonical,
	)
	if err != nil {
		return credentialEndorsementProof{}, fmt.Errorf(
			"%w: %w",
			ErrCredentialEndorsementUnavailable,
			err,
		)
	}
	if response.StatusCode != http.StatusOK {
		if response.MediaType != "application/problem+json" {
			return credentialEndorsementProof{},
				ErrInvalidCredentialEndorsement
		}
		problem, err := decodeConsensusProofProblem(
			response.Body,
			response.StatusCode,
		)
		if err != nil {
			return credentialEndorsementProof{}, err
		}
		classification := ErrCredentialEndorsementRejected
		if problem.Retryable {
			classification = ErrCredentialEndorsementUnavailable
		}
		return credentialEndorsementProof{}, fmt.Errorf(
			"%w: remote code %s, HTTP status %d",
			classification,
			problem.Code,
			response.StatusCode,
		)
	}
	if response.MediaType != "application/json" {
		return credentialEndorsementProof{},
			ErrInvalidCredentialEndorsement
	}
	return decodeCredentialEndorsementResponse(
		response.Body,
		request,
		endorserDeviceID,
		endorserPublicKey,
	)
}

func decodeCanonicalCredentialMessage(
	encoded []byte,
	destination any,
) error {
	if len(encoded) == 0 ||
		len(encoded) > transport.ConsensusControlBodyMaxBytes ||
		destination == nil {
		return ErrInvalidCredentialEndorsement
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidCredentialEndorsement
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidCredentialEndorsement
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidCredentialEndorsement
	}
	return nil
}

func normalizedCredentialEndorsementSigner(
	signer CredentialEndorsementSigner,
) CredentialEndorsementSigner {
	if signer == nil {
		return nil
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	return signer
}

func validateCredentialEndorsementSigner(
	deviceID domain.DeviceID,
	signer CredentialEndorsementSigner,
) error {
	signer = normalizedCredentialEndorsementSigner(signer)
	if signer != nil && signer.DeviceID() != deviceID {
		return fmt.Errorf(
			"%w: credential signer belongs to another device",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

var _ CredentialEndorsementSigner = CredentialEndorsementSignerAdapter{}
