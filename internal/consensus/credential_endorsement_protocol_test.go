package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

type credentialEndorsementRequesterFunc func(
	context.Context,
	domain.DeviceID,
	[]byte,
) (transport.ConsensusControlResponse, error)

func (function credentialEndorsementRequesterFunc) RequestCredentialEndorsement(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	return function(ctx, deviceID, body)
}

func TestCredentialEndorsementProtocolIsCanonicalAndClosed(t *testing.T) {
	t.Parallel()

	authorization := credentialEndorsementTestAuthorization(t)
	request, err := newCredentialEndorsementRequest(authorization)
	if err != nil {
		t.Fatalf("newCredentialEndorsementRequest(): %v", err)
	}
	decoded, err := decodeCredentialEndorsementRequest(request.canonical)
	if err != nil {
		t.Fatalf("decodeCredentialEndorsementRequest(): %v", err)
	}
	if decoded.digest != request.digest ||
		decoded.authorization.SessionID != authorization.SessionID ||
		decoded.authorization.DeviceID != authorization.DeviceID ||
		decoded.authorization.Epoch != authorization.Epoch ||
		decoded.authorization.EpochPublicKey != authorization.EpochPublicKey ||
		decoded.authorization.KeyDigest != authorization.KeyDigest ||
		decoded.authorization.AuthorityVoterSetVersion !=
			authorization.AuthorityVoterSetVersion ||
		decoded.authorization.IssuedAt != authorization.IssuedAt {
		t.Fatalf("decoded request = %#v", decoded)
	}
	if _, err := decodeCredentialEndorsementRequest(
		append(bytes.Clone(request.canonical), ' '),
	); !errors.Is(err, ErrInvalidCredentialEndorsement) {
		t.Fatalf("noncanonical request error = %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(request.canonical, &members); err != nil {
		t.Fatal(err)
	}
	members["unknown"] = json.RawMessage(`true`)
	unknown, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err = codec.CanonicalizeSignedObject(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCredentialEndorsementRequest(
		unknown,
	); !errors.Is(err, ErrInvalidCredentialEndorsement) {
		t.Fatalf("unknown-field request error = %v", err)
	}
}

func TestCredentialEndorsementResponseBindsRequestSignerAndSignature(
	t *testing.T,
) {
	t.Parallel()

	authorization := credentialEndorsementTestAuthorization(t)
	request, err := newCredentialEndorsementRequest(authorization)
	if err != nil {
		t.Fatal(err)
	}
	endorserPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xb2}, ed25519.SeedSize),
	)
	endorserPublic := endorserPrivate.Public().(ed25519.PublicKey)
	endorserID, err := device.DeriveID(endorserPublic)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(authorization)
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := codecommcrypto.SignEd25519(
		endorserPrivate,
		codec.SignatureCredentialTimeEndorsement,
		preimage,
	)
	if err != nil {
		t.Fatal(err)
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], rawSignature)
	response, err := encodeCredentialEndorsementResponse(
		request,
		endorserID,
		signature,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := decodeCredentialEndorsementResponse(
		response,
		request,
		endorserID,
		endorserPublic,
	)
	if err != nil ||
		proof.endorserDeviceID != endorserID ||
		proof.signature != signature {
		t.Fatalf(
			"decodeCredentialEndorsementResponse() = (%#v, %v)",
			proof,
			err,
		)
	}

	var wire credentialEndorsementResponseWire
	if err := json.Unmarshal(response, &wire); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*credentialEndorsementResponseWire){
		"digest": func(value *credentialEndorsementResponseWire) {
			value.RequestDigest = codec.EncodeBase64URL(
				make([]byte, sha256.Size),
			)
		},
		"signer": func(value *credentialEndorsementResponseWire) {
			value.EndorserDeviceID = string(authorization.DeviceID)
		},
		"signature": func(value *credentialEndorsementResponseWire) {
			value.Signature = codec.EncodeBase64URL(
				make([]byte, ed25519.SignatureSize),
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := wire
			mutate(&mutated)
			encoded, err := json.Marshal(mutated)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err = codec.CanonicalizeSignedObject(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCredentialEndorsementResponse(
				encoded,
				request,
				endorserID,
				endorserPublic,
			); !errors.Is(err, ErrCredentialEndorsementMismatch) {
				t.Fatalf("mutation error = %v", err)
			}
		})
	}
}

func TestRequestCredentialEndorsementClassifiesRemoteResults(t *testing.T) {
	t.Parallel()

	authorization := credentialEndorsementTestAuthorization(t)
	endorserPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xb3}, ed25519.SeedSize),
	)
	endorserPublic := endorserPrivate.Public().(ed25519.PublicKey)
	endorserID, err := device.DeriveID(endorserPublic)
	if err != nil {
		t.Fatal(err)
	}
	requester := credentialEndorsementRequesterFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		if deviceID != endorserID {
			t.Fatalf("endorser = %s", deviceID)
		}
		request, err := decodeCredentialEndorsementRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		preimage, err := credentialauthorization.
			CanonicalEndorsementPreimage(request.authorization)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := codecommcrypto.SignEd25519(
			endorserPrivate,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
		)
		if err != nil {
			t.Fatal(err)
		}
		var signature [ed25519.SignatureSize]byte
		copy(signature[:], raw)
		response, err := encodeCredentialEndorsementResponse(
			request,
			endorserID,
			signature,
		)
		if err != nil {
			t.Fatal(err)
		}
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       response,
		}, nil
	})
	if _, err := requestCredentialEndorsement(
		t.Context(),
		requester,
		endorserID,
		endorserPublic,
		authorization,
	); err != nil {
		t.Fatalf("requestCredentialEndorsement(): %v", err)
	}

	problem := []byte(
		`{"type":"urn:codecomm:problem:credential_endorsement_unavailable","title":"Credential endorsement unavailable","status":503,"code":"credential_endorsement_unavailable","correlation_id":"unavailable","retryable":true}`,
	)
	_, err = requestCredentialEndorsement(
		t.Context(),
		credentialEndorsementRequesterFunc(func(
			context.Context,
			domain.DeviceID,
			[]byte,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusServiceUnavailable,
				MediaType:  "application/problem+json",
				Body:       problem,
			}, nil
		}),
		endorserID,
		endorserPublic,
		authorization,
	)
	if !errors.Is(err, ErrCredentialEndorsementUnavailable) {
		t.Fatalf("unavailable error = %v", err)
	}
}

func TestCredentialEndorsementSignerAdapterBindsCanonicalInput(
	t *testing.T,
) {
	t.Parallel()

	authorization := credentialEndorsementTestAuthorization(t)
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xb4}, ed25519.SeedSize),
	)
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	adapter := CredentialEndorsementSignerAdapter{
		SignerDeviceID: deviceID,
		Sign: func(
			ctx context.Context,
			preimage []byte,
		) ([ed25519.SignatureSize]byte, error) {
			raw, err := codecommcrypto.SignEd25519(
				privateKey,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
			)
			var result [ed25519.SignatureSize]byte
			copy(result[:], raw)
			return result, err
		},
	}
	signature, err := adapter.SignCredentialEndorsement(
		t.Context(),
		authorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := codecommcrypto.VerifyEd25519(
		privateKey.Public().(ed25519.PublicKey),
		codec.SignatureCredentialTimeEndorsement,
		preimage,
		signature[:],
	); err != nil {
		t.Fatalf("signature verification: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adapter.SignCredentialEndorsement(
		canceled,
		authorization,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signer error = %v", err)
	}
	otherID := authorization.DeviceID
	adapter.SignerDeviceID = otherID
	if err := validateCredentialEndorsementSigner(
		deviceID,
		adapter,
	); !errors.Is(err, ErrInvalidNodeOptions) {
		t.Fatalf("mismatched signer validation error = %v", err)
	}
}

func TestCredentialEndorsementClockSkewBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	node := &SingleNode{
		credentialEndorsementNow: func() time.Time {
			return now
		},
	}
	for _, offset := range []time.Duration{
		-credentialEndorsementClockSkew,
		0,
		credentialEndorsementClockSkew,
	} {
		issuedAt := domain.WholeSecondTimestamp(
			now.Add(offset).Format(time.RFC3339),
		)
		if err := node.requireCredentialEndorsementTime(
			issuedAt,
		); err != nil {
			t.Fatalf("boundary offset %s error = %v", offset, err)
		}
	}
	for _, offset := range []time.Duration{
		-credentialEndorsementClockSkew - time.Second,
		credentialEndorsementClockSkew + time.Second,
	} {
		issuedAt := domain.WholeSecondTimestamp(
			now.Add(offset).Format(time.RFC3339),
		)
		if err := node.requireCredentialEndorsementTime(
			issuedAt,
		); !errors.Is(err, errCredentialEndorsementClock) {
			t.Fatalf("outside offset %s error = %v", offset, err)
		}
	}
}

func credentialEndorsementTestAuthorization(
	t testing.TB,
) credentialauthorization.Authorization {
	t.Helper()
	subjectPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xb0}, ed25519.SeedSize),
	)
	subjectID, err := device.DeriveID(
		subjectPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xb1}, ed25519.SeedSize),
	)
	epochPublic := epochPrivate.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID:                nodeTestSessionID,
		DeviceID:                 subjectID,
		Epoch:                    2,
		KeyDigest:                sha256.Sum256(epochPublic),
		AuthorityVoterSetVersion: 3,
		IssuedAt: domain.WholeSecondTimestamp(
			"2026-08-18T12:00:00Z",
		),
	}
	copy(authorization.EpochPublicKey[:], epochPublic)
	return authorization
}
