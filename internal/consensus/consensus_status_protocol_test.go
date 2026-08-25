package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
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
		decoded.QuorumRequired != status.QuorumRequired ||
		decoded.LastRaftAppliedLogIndex == nil ||
		*decoded.LastRaftAppliedLogIndex !=
			*status.LastRaftAppliedLogIndex ||
		decoded.CredentialAuthority.VoterSetVersion !=
			status.CredentialAuthority.VoterSetVersion ||
		!credentialRenewalAuthorizationsEqual(
			decoded.ContentCredentialAuthorization,
			status.ContentCredentialAuthorization,
		) {
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
	got, err := requestConsensusStatusAt(
		t.Context(),
		requester,
		status.ServerDeviceID,
		now,
	)
	if err != nil {
		t.Fatalf("requestConsensusStatusAt(): %v", err)
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
	_, err = requestConsensusStatusAt(
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
	t testing.TB,
) (ConsensusStatusResult, time.Time) {
	t.Helper()
	binding := credentialRenewalTestBinding(t, 1)
	authorization := credentialRenewalTestAuthorization(t, binding)
	authorization.AuthorityVoterSetVersion = 1
	now := time.Date(2026, 8, 18, 12, 1, 0, 0, time.UTC)
	leader := credentialRenewalTestDeviceID(t, 0xd0)
	applied := uint64(23)
	return ConsensusStatusResult{
		SessionID:               authorization.SessionID,
		WorkspaceID:             nodeTestWorkspaceID,
		RecoveryGeneration:      2,
		ServerDeviceID:          authorization.DeviceID,
		LocalTerm:               7,
		LeaderDeviceID:          &leader,
		QuorumRequired:          2,
		LastRaftAppliedLogIndex: &applied,
		CredentialAuthority: credentialauthority.Authority{
			SessionID:        authorization.SessionID,
			VoterDeviceIDs:   []domain.DeviceID{authorization.DeviceID},
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		},
		ContentCredentialAuthorization: authorization,
	}, now
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
