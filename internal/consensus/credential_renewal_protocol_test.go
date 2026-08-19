package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

type credentialRenewalRequesterFunc func(
	context.Context,
	domain.DeviceID,
	[]byte,
) (transport.ConsensusControlResponse, error)

func (function credentialRenewalRequesterFunc) RequestCredentialRenewal(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	return function(ctx, deviceID, body)
}

func TestCredentialRenewalRequestIsCanonicalBoundedAndClosed(
	t *testing.T,
) {
	t.Parallel()

	binding := credentialRenewalTestBinding(t, 1)
	for _, mode := range []credentialRenewalMode{
		credentialRenewalModeSubmit,
		credentialRenewalModeForward,
	} {
		request, err := newCredentialRenewalRequest(binding, mode)
		if err != nil {
			t.Fatalf("newCredentialRenewalRequest(%s): %v", mode, err)
		}
		decoded, err := decodeCredentialRenewalRequest(request.canonical)
		if err != nil {
			t.Fatalf("decodeCredentialRenewalRequest(%s): %v", mode, err)
		}
		if decoded.mode != mode || decoded.binding != binding {
			t.Fatalf("decoded request = %#v", decoded)
		}
	}
	if _, err := newCredentialRenewalRequest(
		binding,
		credentialRenewalMode("redirect"),
	); !errors.Is(err, ErrInvalidCredentialRenewal) {
		t.Fatalf("open mode error = %v", err)
	}

	request, err := newCredentialRenewalRequest(
		binding,
		credentialRenewalModeSubmit,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCredentialRenewalRequest(
		append(bytes.Clone(request.canonical), ' '),
	); !errors.Is(err, ErrInvalidCredentialRenewal) {
		t.Fatalf("noncanonical request error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request.canonical, &fields); err != nil {
		t.Fatal(err)
	}
	fields["unknown"] = json.RawMessage(`true`)
	unknown, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err = codec.CanonicalizeSignedObject(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCredentialRenewalRequest(
		unknown,
	); !errors.Is(err, ErrInvalidCredentialRenewal) {
		t.Fatalf("unknown-field request error = %v", err)
	}
	if _, err := decodeCredentialRenewalRequest(
		make([]byte, transport.ConsensusControlBodyMaxBytes+1),
	); !errors.Is(err, ErrInvalidCredentialRenewal) {
		t.Fatalf("oversize request error = %v", err)
	}
}

func TestCredentialRenewalResponseCarriesExactCommittedAuthorization(
	t *testing.T,
) {
	t.Parallel()

	binding := credentialRenewalTestBinding(t, 2)
	request, err := newCredentialRenewalRequest(
		binding,
		credentialRenewalModeForward,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization := credentialRenewalTestAuthorization(t, binding)
	encoded, err := encodeCredentialRenewalResponse(authorization)
	if err != nil {
		t.Fatalf("encodeCredentialRenewalResponse(): %v", err)
	}
	decoded, err := decodeCredentialRenewalResponse(encoded, request)
	if err != nil {
		t.Fatalf("decodeCredentialRenewalResponse(): %v", err)
	}
	if !credentialRenewalAuthorizationsEqual(decoded, authorization) ||
		decoded.AuthorizationChainIndex == 0 {
		t.Fatalf("decoded authorization = %#v", decoded)
	}

	var baseline credentialRenewalResponseWire
	if err := json.Unmarshal(encoded, &baseline); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*credentialRenewalResponseWire){
		"zero chain index": func(wire *credentialRenewalResponseWire) {
			wire.AuthorizationChainIndex = 0
		},
		"different epoch key": func(wire *credentialRenewalResponseWire) {
			wire.EpochPublicKey = codec.EncodeBase64URL(
				make([]byte, ed25519.PublicKeySize),
			)
		},
		"different binding signature": func(wire *credentialRenewalResponseWire) {
			wire.BindingSignature = codec.EncodeBase64URL(
				make([]byte, ed25519.SignatureSize),
			)
		},
		"open endorsement field": func(wire *credentialRenewalResponseWire) {
			wire.ClockEndorsements[0].DeviceID = "not-a-device"
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := baseline
			mutated.ClockEndorsements = append(
				[]credentialRenewalEndorsementWire(nil),
				baseline.ClockEndorsements...,
			)
			mutate(&mutated)
			body, err := json.Marshal(mutated)
			if err != nil {
				t.Fatal(err)
			}
			body, err = codec.CanonicalizeSignedObject(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCredentialRenewalResponse(
				body,
				request,
			); err == nil {
				t.Fatal("mutated response was accepted")
			}
		})
	}
}

func TestRequestCredentialRenewalUsesOneClosedForwardRequest(
	t *testing.T,
) {
	t.Parallel()

	binding := credentialRenewalTestBinding(t, 1)
	authorization := credentialRenewalTestAuthorization(t, binding)
	responseBody, err := encodeCredentialRenewalResponse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	leaderID := credentialRenewalTestDeviceID(t, 0xa7)
	var calls int
	requester := credentialRenewalRequesterFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
		body []byte,
	) (transport.ConsensusControlResponse, error) {
		calls++
		if deviceID != leaderID {
			t.Fatalf("target = %s", deviceID)
		}
		request, err := decodeCredentialRenewalRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		if request.mode != credentialRenewalModeForward ||
			request.binding != binding {
			t.Fatalf("forward request = %#v", request)
		}
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       responseBody,
		}, nil
	})
	got, err := requestCredentialRenewal(
		t.Context(),
		requester,
		leaderID,
		binding,
		credentialRenewalModeForward,
	)
	if err != nil {
		t.Fatalf("requestCredentialRenewal(): %v", err)
	}
	if calls != 1 || !credentialRenewalAuthorizationsEqual(got, authorization) {
		t.Fatalf("result = (%#v, calls %d)", got, calls)
	}

	problem := []byte(
		`{"type":"urn:codecomm:problem:credential_renewal_unavailable",` +
			`"title":"Credential renewal unavailable","status":503,` +
			`"code":"credential_renewal_unavailable",` +
			`"correlation_id":"unavailable","retryable":true}`,
	)
	_, err = requestCredentialRenewal(
		t.Context(),
		credentialRenewalRequesterFunc(func(
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
		leaderID,
		binding,
		credentialRenewalModeForward,
	)
	if !errors.Is(err, ErrCredentialRenewalUnavailable) {
		t.Fatalf("unavailable response error = %v", err)
	}
}

func credentialRenewalTestBinding(
	t testing.TB,
	epoch uint64,
) credential.Binding {
	t.Helper()
	identityPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xa1}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(identityPrivate) })
	deviceID, err := device.DeriveID(
		identityPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{byte(0xb0 + epoch)}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(epochPrivate) })
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		deviceID,
		epoch,
		epochPrivate.Public().(ed25519.PublicKey),
		identityPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func credentialRenewalTestAuthorization(
	t testing.TB,
	binding credential.Binding,
) credentialauthorization.Authorization {
	t.Helper()
	first := credentialRenewalTestDeviceID(t, 0xa2)
	second := credentialRenewalTestDeviceID(t, 0xa3)
	if first > second {
		first, second = second, first
	}
	authorization := credentialauthorization.Authorization{
		SessionID:                binding.SessionID,
		DeviceID:                 binding.DeviceID,
		Epoch:                    binding.Epoch,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.RoleEditor,
		IssuedAt:                 "2026-08-18T12:00:00Z",
		NotBefore:                "2026-08-18T12:00:00Z",
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 3,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{
			{DeviceID: first, Signature: [ed25519.SignatureSize]byte{1}},
			{DeviceID: second, Signature: [ed25519.SignatureSize]byte{2}},
		},
		BindingSignature:        binding.Signature,
		AuthorizationChainIndex: 17,
	}
	if err := authorization.Validate(); err != nil {
		t.Fatalf("authorization fixture: %v", err)
	}
	return authorization
}

func credentialRenewalTestDeviceID(
	t testing.TB,
	seed byte,
) domain.DeviceID {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	defer clear(privateKey)
	deviceID, err := device.DeriveID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	return deviceID
}

func credentialRenewalAuthorizationsEqual(
	left credentialauthorization.Authorization,
	right credentialauthorization.Authorization,
) bool {
	leftJSON, leftErr := encodeCredentialRenewalResponse(left)
	rightJSON, rightErr := encodeCredentialRenewalResponse(right)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftJSON, rightJSON)
}

var _ credentialRenewalRequester = credentialRenewalRequesterFunc(nil)
