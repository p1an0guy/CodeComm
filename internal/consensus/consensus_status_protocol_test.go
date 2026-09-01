package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

type consensusStatusRequesterFunc func(
	context.Context,
	domain.DeviceID,
) (transport.ConsensusControlResponse, error)

func (function consensusStatusRequesterFunc) RequestConsensusStatus(
	ctx context.Context,
	deviceID domain.DeviceID,
) (transport.ConsensusControlResponse, error) {
	return function(ctx, deviceID)
}

func TestConsensusStatusResponseIsCanonicalBoundedAndClosed(
	t *testing.T,
) {
	t.Parallel()

	status, now := consensusStatusProtocolFixture(t)
	encoded, err := encodeConsensusStatusResponse(status, now)
	if err != nil {
		t.Fatalf("encodeConsensusStatusResponse(): %v", err)
	}
	decoded, err := decodeConsensusStatusResponse(
		encoded,
		status.ServerDeviceID,
		now,
	)
	if err != nil {
		t.Fatalf("decodeConsensusStatusResponse(): %v", err)
	}
	if decoded.SessionID != status.SessionID ||
		decoded.WorkspaceID != status.WorkspaceID ||
		decoded.RecoveryGeneration != status.RecoveryGeneration ||
		decoded.ServerDeviceID != status.ServerDeviceID ||
		decoded.LocalTerm != status.LocalTerm ||
		decoded.LeaderDeviceID == nil ||
		*decoded.LeaderDeviceID != *status.LeaderDeviceID ||
		len(decoded.LeaderEndpointSet) != 0 ||
		decoded.AdvertisementIntervalSeconds !=
			status.AdvertisementIntervalSeconds ||
		decoded.QuorumRequired != status.QuorumRequired ||
		decoded.LastRaftAppliedLogIndex == nil ||
		*decoded.LastRaftAppliedLogIndex !=
			*status.LastRaftAppliedLogIndex ||
		decoded.MembershipAppliedChainIndex !=
			status.MembershipAppliedChainIndex ||
		!sameConsensusStatusMember(
			decoded.RequesterMembership,
			status.RequesterMembership,
		) ||
		len(decoded.ActiveRoster) != len(status.ActiveRoster) ||
		decoded.RequesterCredentialAuthorization == nil ||
		!credentialRenewalAuthorizationsEqual(
			*decoded.RequesterCredentialAuthorization,
			*status.RequesterCredentialAuthorization,
		) ||
		decoded.CredentialAuthority.VoterSetVersion !=
			status.CredentialAuthority.VoterSetVersion ||
		!credentialRenewalAuthorizationsEqual(
			decoded.ContentCredentialAuthorization,
			status.ContentCredentialAuthorization,
		) ||
		decoded.GenerationZeroState.SessionID !=
			status.GenerationZeroState.SessionID ||
		decoded.GenerationZeroState.ProjectionStateDigest !=
			status.GenerationZeroState.ProjectionStateDigest ||
		!bytes.Equal(
			decoded.GenerationZeroState.GenesisJSON,
			status.GenerationZeroState.GenesisJSON,
		) ||
		len(decoded.GenerationZeroState.ProjectionRows) !=
			len(status.GenerationZeroState.ProjectionRows) {
		t.Fatalf("decoded status = %#v", decoded)
	}

	for name, body := range map[string][]byte{
		"noncanonical": append(bytes.Clone(encoded), ' '),
		"oversize": make(
			[]byte,
			transport.ConsensusControlBodyMaxBytes+1,
		),
		"unknown top-level field": consensusStatusUnknownField(
			t,
			encoded,
			false,
		),
		"unknown authorization field": consensusStatusUnknownField(
			t,
			encoded,
			true,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConsensusStatusResponse(
				body,
				status.ServerDeviceID,
				now,
			); !errors.Is(err, ErrInvalidConsensusStatus) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}

	status.LeaderDeviceID = nil
	status.LastRaftAppliedLogIndex = nil
	encoded, err = encodeConsensusStatusResponse(status, now)
	if err != nil {
		t.Fatalf("encode nullable status: %v", err)
	}
	decoded, err = decodeConsensusStatusResponse(
		encoded,
		status.ServerDeviceID,
		now,
	)
	if err != nil ||
		decoded.LeaderDeviceID != nil ||
		decoded.LastRaftAppliedLogIndex != nil {
		t.Fatalf("nullable status = (%#v, %v)", decoded, err)
	}
}

func TestConsensusStatusClientRejectsMismatchedOrUnusableMetadata(
	t *testing.T,
) {
	t.Parallel()

	status, now := consensusStatusProtocolFixture(t)
	encoded, err := encodeConsensusStatusResponse(status, now)
	if err != nil {
		t.Fatal(err)
	}
	otherDeviceID := credentialRenewalTestDeviceID(t, 0xd1)
	if _, err := decodeConsensusStatusResponse(
		encoded,
		otherDeviceID,
		now,
	); !errors.Is(err, ErrConsensusStatusMismatch) {
		t.Fatalf("wrong expected server error = %v", err)
	}
	if _, err := decodeConsensusStatusResponse(
		encoded,
		status.ServerDeviceID,
		now.Add(
			time.Duration(
				status.ContentCredentialAuthorization.ValiditySeconds,
			)*time.Second,
		),
	); !errors.Is(err, ErrConsensusStatusMismatch) {
		t.Fatalf("expired authorization error = %v", err)
	}
	unsafeGeneration := bytes.Replace(
		encoded,
		[]byte(`"recovery_generation":2`),
		[]byte(`"recovery_generation":9007199254740992`),
		1,
	)
	if bytes.Equal(unsafeGeneration, encoded) {
		t.Fatal("recovery-generation fixture did not mutate")
	}
	if _, err := decodeConsensusStatusResponse(
		unsafeGeneration,
		status.ServerDeviceID,
		now,
	); !errors.Is(err, ErrInvalidConsensusStatus) {
		t.Fatalf("unsafe recovery generation error = %v", err)
	}

	tests := map[string]func(*consensusStatusResponseWire){
		"malformed lineage": func(wire *consensusStatusResponseWire) {
			wire.SessionID = "not-a-session"
		},
		"wrong server device": func(wire *consensusStatusResponseWire) {
			wire.ServerDeviceID = string(otherDeviceID)
		},
		"zero term": func(wire *consensusStatusResponseWire) {
			wire.LocalTerm = 0
		},
		"malformed leader": func(wire *consensusStatusResponseWire) {
			value := "not-a-device"
			wire.LeaderDeviceID = &value
		},
		"invalid advertisement interval": func(
			wire *consensusStatusResponseWire,
		) {
			wire.AdvertisementIntervalSeconds = 0
		},
		"impossible quorum": func(wire *consensusStatusResponseWire) {
			wire.QuorumRequired = 6
		},
		"zero applied index": func(wire *consensusStatusResponseWire) {
			value := uint64(0)
			wire.LastRaftAppliedLogIndex = &value
		},
		"authorization subject mismatch": func(
			wire *consensusStatusResponseWire,
		) {
			wire.ContentCredentialAuthorization.DeviceID =
				string(otherDeviceID)
		},
		"requester membership identity mismatch": func(
			wire *consensusStatusResponseWire,
		) {
			wire.RequesterMembership.DeviceID = string(otherDeviceID)
		},
		"requester authorization epoch mismatch": func(
			wire *consensusStatusResponseWire,
		) {
			wire.RequesterMembership.CurrentCredentialEpoch++
		},
		"requester authorization beyond cut": func(
			wire *consensusStatusResponseWire,
		) {
			wire.MembershipAppliedChainIndex = 1
		},
		"empty active roster": func(
			wire *consensusStatusResponseWire,
		) {
			wire.ActiveRoster = nil
		},
		"authorization lineage mismatch": func(
			wire *consensusStatusResponseWire,
		) {
			wire.SessionID =
				"018f47de-89ab-7def-8123-1123456789ab"
		},
		"malformed authorization": func(
			wire *consensusStatusResponseWire,
		) {
			wire.ContentCredentialAuthorization.ValiditySeconds = 1
		},
		"bootstrap state digest": func(
			wire *consensusStatusResponseWire,
		) {
			wire.GenerationZeroState.ProjectionStateDigest =
				codec.EncodeBase64URL(make([]byte, 32))
		},
		"bootstrap workspace mismatch": func(
			wire *consensusStatusResponseWire,
		) {
			wire.GenerationZeroState.WorkspaceID =
				"550e8400-e29b-41d4-a716-446655440001"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			body := mutateConsensusStatusWire(t, encoded, mutate)
			if _, err := decodeConsensusStatusResponse(
				body,
				status.ServerDeviceID,
				now,
			); err == nil {
				t.Fatal("mutated status was accepted")
			}
		})
	}
}

func TestConsensusStatusAuthenticatesRemoteLeaderEndpointSet(
	t *testing.T,
) {
	t.Parallel()

	status, now := consensusStatusProtocolFixture(t)
	leaderPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xd0}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(leaderPrivate) })
	leaderID, err := device.DeriveID(
		leaderPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	status.LeaderDeviceID = &leaderID
	status.ActiveRoster = append(
		status.ActiveRoster,
		ConsensusStatusMember{
			Device: device.Device{
				ID:                leaderID,
				Role:              device.RoleOwner,
				IdentityPublicKey: bytes.Clone(leaderPrivate.Public().(ed25519.PublicKey)),
				DaemonVersion:     "0.1.0",
				MaxApplyLevel:     1,
				Status:            device.StatusActive,
				EntityVersion:     1,
			},
		},
	)
	sort.Slice(status.ActiveRoster, func(left, right int) bool {
		return status.ActiveRoster[left].Device.ID <
			status.ActiveRoster[right].Device.ID
	})
	address := netip.MustParseAddr("192.0.2.10")
	interval := time.Duration(
		status.AdvertisementIntervalSeconds,
	) * time.Second
	signer, err := discovery.NewEndpointSigner(
		interval,
		47831,
		[]netip.Addr{address},
	)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := now.UTC().Truncate(time.Second)
	status.LeaderEndpointSet, err = signer.Sign(
		discovery.EndpointSet{
			SessionID:          status.SessionID,
			WorkspaceID:        status.WorkspaceID,
			RecoveryGeneration: status.RecoveryGeneration,
			DeviceID:           leaderID,
			EndpointSequence:   1,
			IssuedAt: domain.WholeSecondTimestamp(
				issuedAt.Format(time.RFC3339),
			),
			ExpiresAt: domain.WholeSecondTimestamp(
				issuedAt.Add(
					discovery.EndpointHintTTLIntervals * interval,
				).Format(time.RFC3339),
			),
			Endpoints: []discovery.Endpoint{{
				IP: address, Port: 47831,
			}},
		},
		leaderPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeConsensusStatusResponse(status, now)
	if err != nil {
		t.Fatalf("encode remote leader status: %v", err)
	}
	decoded, err := decodeConsensusStatusResponse(
		encoded,
		status.ServerDeviceID,
		now,
	)
	if err != nil ||
		decoded.LeaderDeviceID == nil ||
		*decoded.LeaderDeviceID != leaderID ||
		!bytes.Equal(
			decoded.LeaderEndpointSet,
			status.LeaderEndpointSet,
		) {
		t.Fatalf("remote leader status = (%+v, %v)", decoded, err)
	}

	status.LeaderEndpointSet[len(status.LeaderEndpointSet)-1] ^= 1
	if _, err := encodeConsensusStatusResponse(
		status,
		now,
	); !errors.Is(err, ErrConsensusStatusMismatch) {
		t.Fatalf("tampered leader endpoint-set error = %v", err)
	}
}

func TestRequestConsensusStatusUsesOnePeerPinnedRequest(
	t *testing.T,
) {
	t.Parallel()

	status, now := consensusStatusProtocolFixture(t)
	body, err := encodeConsensusStatusResponse(status, now)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	requester := consensusStatusRequesterFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
	) (transport.ConsensusControlResponse, error) {
		calls++
		if deviceID != status.ServerDeviceID {
			t.Fatalf("request target = %s", deviceID)
		}
		return transport.ConsensusControlResponse{
			StatusCode: http.StatusOK,
			MediaType:  "application/json",
			Body:       body,
		}, nil
	})
	got, err := RequestConsensusStatusAt(
		t.Context(),
		requester,
		status.ServerDeviceID,
		now,
	)
	if err != nil {
		t.Fatalf("RequestConsensusStatusAt(): %v", err)
	}
	if calls != 1 || got.ServerDeviceID != status.ServerDeviceID {
		t.Fatalf("request result = (%#v, calls %d)", got, calls)
	}

	problem := canonicalConsensusStatusTestJSON(t, consensusProofProblem{
		Type:          "urn:codecomm:problem:consensus_status_unavailable",
		Title:         "Consensus status unavailable",
		Status:        http.StatusServiceUnavailable,
		Code:          "consensus_status_unavailable",
		CorrelationID: "unavailable",
		Retryable:     true,
	})
	_, err = RequestConsensusStatusAt(
		t.Context(),
		consensusStatusRequesterFunc(func(
			context.Context,
			domain.DeviceID,
		) (transport.ConsensusControlResponse, error) {
			return transport.ConsensusControlResponse{
				StatusCode: http.StatusServiceUnavailable,
				MediaType:  "application/problem+json",
				Body:       problem,
			}, nil
		}),
		status.ServerDeviceID,
		now,
	)
	if !errors.Is(err, ErrConsensusStatusUnavailable) {
		t.Fatalf("unavailable status error = %v", err)
	}
}

func consensusStatusProtocolFixture(
	t *testing.T,
) (ConsensusStatusResult, time.Time) {
	t.Helper()
	binding := credentialRenewalTestBinding(t, 1)
	authorization := credentialRenewalTestAuthorization(t, binding)
	authorization.AuthorityVoterSetVersion = 1
	now := time.Date(2026, 8, 18, 12, 1, 0, 0, time.UTC)
	leader := authorization.DeviceID
	applied := uint64(23)
	generationZero := consensusStatusBootstrapFixture(t)
	identityPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xa1}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(identityPrivate) })
	member := ConsensusStatusMember{
		Device: device.Device{
			ID:   authorization.DeviceID,
			Role: device.RoleEditor,
			IdentityPublicKey: bytes.Clone(
				identityPrivate.Public().(ed25519.PublicKey),
			),
			DaemonVersion: "0.1.0",
			MaxApplyLevel: 1,
			Status:        device.StatusActive,
			EntityVersion: 1,
		},
		CurrentCredentialEpoch: authorization.Epoch,
	}
	requesterAuthorization := authorization.Clone()
	return ConsensusStatusResult{
		SessionID:                        authorization.SessionID,
		WorkspaceID:                      nodeTestWorkspaceID,
		RecoveryGeneration:               2,
		ServerDeviceID:                   authorization.DeviceID,
		LocalTerm:                        7,
		LeaderDeviceID:                   &leader,
		AdvertisementIntervalSeconds:     policy.DefaultAdvertisementIntervalSeconds,
		QuorumRequired:                   2,
		LastRaftAppliedLogIndex:          &applied,
		MembershipAppliedChainIndex:      applied,
		RequesterMembership:              member,
		ActiveRoster:                     []ConsensusStatusMember{member},
		RequesterCredentialAuthorization: &requesterAuthorization,
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        authorization.SessionID,
			VoterDeviceIDs:   []domain.DeviceID{authorization.DeviceID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		ContentCredentialAuthorization: authorization,
		GenerationZeroState:            generationZero,
	}, now
}

func consensusStatusBootstrapFixture(t *testing.T) store.StateView {
	t.Helper()
	initial, _, _ := nodeTestInitialState(t)
	database, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(
				t.TempDir(),
				"consensus-status-bootstrap",
				"state.db",
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	view, err := database.VerifiedGenerationZeroView(
		context.Background(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func mutateConsensusStatusWire(
	t *testing.T,
	encoded []byte,
	mutate func(*consensusStatusResponseWire),
) []byte {
	t.Helper()
	var wire consensusStatusResponseWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	mutate(&wire)
	return canonicalConsensusStatusTestJSON(t, wire)
}

func consensusStatusUnknownField(
	t *testing.T,
	encoded []byte,
	nested bool,
) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if !nested {
		fields["unexpected"] = json.RawMessage(`true`)
		return canonicalConsensusStatusTestJSON(t, fields)
	}
	var authorization map[string]json.RawMessage
	if err := json.Unmarshal(
		fields["content_credential_authorization"],
		&authorization,
	); err != nil {
		t.Fatal(err)
	}
	authorization["unexpected"] = json.RawMessage(`true`)
	fields["content_credential_authorization"] =
		canonicalConsensusStatusTestJSON(t, authorization)
	return canonicalConsensusStatusTestJSON(t, fields)
}

func canonicalConsensusStatusTestJSON(
	t testing.TB,
	value any,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

var _ ConsensusStatusRequester = consensusStatusRequesterFunc(nil)
