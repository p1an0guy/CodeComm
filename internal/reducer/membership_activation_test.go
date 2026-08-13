package reducer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

const activationCheckpointEventID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000021",
)

const activationLiveConfigurationIndex uint64 = 9

func TestMembershipVoterSetActivatedVerifiesCompleteHandoff(t *testing.T) {
	t.Parallel()

	fixture, voterIDs := activationFixture(t)
	payload := activationPayload(t, fixture, voterIDs)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorDaemon,
		event.KindMembershipVoterSetActivated,
		string(testSessionID),
		0,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.CredentialAuthority) != 1 ||
		len(outcome.Changes.VoterSet) != 0 ||
		outcome.Audit != nil {
		t.Fatalf("activation outcome = %#v", outcome)
	}
	next := outcome.Changes.CredentialAuthority[0]
	if next.VoterSetVersion != 2 ||
		next.ActivationSource != credentialauthority.ActivationHandoff ||
		next.ActivationCheckpointEventID != activationCheckpointEventID ||
		len(next.ActivationProofs) != len(voterIDs) ||
		next.PriorAuthoritySigner != fixture.ownerDevice {
		t.Fatalf("activated authority = %#v", next)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	outcome.Changes.CredentialAuthority[0].ActivationProofs[0].
		CanonicalJSON[0] = '['
	if fixture.state.credentialAuthority.Validate() != nil ||
		!bytes.HasPrefix(
			fixture.state.credentialAuthority.ActivationProofs[0].CanonicalJSON,
			[]byte("{"),
		) {
		t.Fatal("applied credential authority aliases reducer output")
	}
}

func TestMembershipVoterSetActivatedRejectsInvalidProofsAndHandoff(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, *map[string]any)
		want   Code
	}{
		{
			name: "proof order",
			mutate: func(_ *testing.T, payload *map[string]any) {
				proofs := (*payload)["activation_proofs"].([]json.RawMessage)
				proofs[0], proofs[1] = proofs[1], proofs[0]
			},
			want: CodeInvalidVoterActivationProof,
		},
		{
			name: "voter signature",
			mutate: func(t *testing.T, payload *map[string]any) {
				mutateActivationProof(t, payload, 0, func(object map[string]any) {
					object["voter_signature"] = codec.EncodeBase64URL(
						make([]byte, ed25519.SignatureSize),
					)
				})
			},
			want: CodeInvalidVoterActivationProof,
		},
		{
			name: "checkpoint signature",
			mutate: func(t *testing.T, payload *map[string]any) {
				mutateActivationProof(t, payload, 0, func(object map[string]any) {
					object["checkpoint_signature"] = codec.EncodeBase64URL(
						make([]byte, ed25519.SignatureSize),
					)
				})
			},
			want: CodeInvalidVoterActivationProof,
		},
		{
			name: "handoff signature",
			mutate: func(_ *testing.T, payload *map[string]any) {
				(*payload)["prior_authority_handoff"] =
					codec.EncodeBase64URL(
						make([]byte, ed25519.SignatureSize),
					)
			},
			want: CodeInvalidCredentialAuthorityHandoff,
		},
		{
			name: "target version",
			mutate: func(_ *testing.T, payload *map[string]any) {
				(*payload)["target_voter_set_version"] = uint64(3)
			},
			want: CodeVoterSetVersionMismatch,
		},
		{
			name: "authority version",
			mutate: func(_ *testing.T, payload *map[string]any) {
				(*payload)["expected_authority_voter_set_version"] = uint64(2)
			},
			want: CodeCredentialAuthorityVersionMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture, voterIDs := activationFixture(t)
			payload := activationPayloadObject(t, fixture, voterIDs)
			test.mutate(t, &payload)
			signed := buildMembershipProposal(
				t,
				fixture,
				fixture.ownerDevice,
				event.ActorDaemon,
				event.KindMembershipVoterSetActivated,
				string(testSessionID),
				0,
				mustJSON(t, payload),
			)
			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			assertMembershipRejection(t, outcome, test.want)
		})
	}
}

func TestMembershipVoterSetActivatedRequiresPostPromotionCheckpoint(
	t *testing.T,
) {
	t.Parallel()

	fixture, voterIDs := activationFixture(t)
	payload := activationPayloadObjectAtIndexes(
		t,
		fixture,
		voterIDs,
		activationLiveConfigurationIndex,
		activationLiveConfigurationIndex-1,
	)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorDaemon,
		event.KindMembershipVoterSetActivated,
		string(testSessionID),
		0,
		mustJSON(t, payload),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	assertMembershipRejection(t, outcome, CodeInvalidVoterActivationProof)
}

func TestMembershipVoterSetActivatedRejectsAlreadyActiveTarget(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	payload := map[string]any{
		"target_voter_set_version":             uint64(1),
		"expected_authority_voter_set_version": uint64(1),
		"voter_set":                            []domain.DeviceID{fixture.ownerDevice},
		"activation_checkpoint_event_id":       activationCheckpointEventID,
		"activation_proofs":                    []json.RawMessage{},
		"prior_authority_signer":               fixture.ownerDevice,
		"prior_authority_handoff": codec.EncodeBase64URL(
			make([]byte, ed25519.SignatureSize),
		),
	}
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorDaemon,
		event.KindMembershipVoterSetActivated,
		string(testSessionID),
		0,
		mustJSON(t, payload),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	assertMembershipRejection(t, outcome, CodeVoterTargetAlreadyActivated)
}

func activationFixture(
	t *testing.T,
) (reducerFixture, []domain.DeviceID) {
	t.Helper()

	fixture := newReducerFixture(t)
	voterIDs := []domain.DeviceID{
		fixture.editorDevice,
		fixture.ownerDevice,
		fixture.targetDevice,
	}
	sortDeviceIDs(voterIDs)
	target, err := voterset.New(testSessionID, voterIDs, 2)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	fixture.state.voterSet = target
	return fixture, voterIDs
}

func activationPayload(
	t *testing.T,
	fixture reducerFixture,
	voterIDs []domain.DeviceID,
) string {
	t.Helper()
	return mustJSON(t, activationPayloadObject(t, fixture, voterIDs))
}

func activationPayloadObject(
	t *testing.T,
	fixture reducerFixture,
	voterIDs []domain.DeviceID,
) map[string]any {
	t.Helper()

	return activationPayloadObjectAtIndexes(
		t,
		fixture,
		voterIDs,
		activationLiveConfigurationIndex,
		activationLiveConfigurationIndex,
	)
}

func activationPayloadObjectAtIndexes(
	t *testing.T,
	fixture reducerFixture,
	voterIDs []domain.DeviceID,
	liveConfigurationIndex uint64,
	checkpointAppliedIndex uint64,
) map[string]any {
	t.Helper()

	checkpoint := activationCheckpoint(t, fixture)
	checkpoint.CoveredAppliedLogIndex = checkpointAppliedIndex
	checkpointBytes := mustCanonicalJSON(t, checkpoint)
	checkpointSignature := signLabeled(
		t,
		fixture.privateKeys[fixture.ownerDevice],
		codec.SignatureCheckpoint,
		checkpointBytes,
	)
	proofs := make([]json.RawMessage, len(voterIDs))
	for index, voterID := range voterIDs {
		unsigned := voterActivationProofUnsignedWire{
			SessionID:                       string(testSessionID),
			WorkspaceID:                     string(testWorkspaceID),
			RecoveryGeneration:              fixture.state.recoveryGeneration,
			TargetVoterSetVersion:           2,
			CurrentAuthorityVoterSetVersion: 1,
			VoterSet:                        deviceIDStrings(voterIDs),
			VoterDeviceID:                   string(voterID),
			LiveConfigurationIndex:          liveConfigurationIndex,
			CheckpointEventID:               string(activationCheckpointEventID),
			Checkpoint:                      checkpointBytes,
			CheckpointSignature: codec.EncodeBase64URL(
				checkpointSignature,
			),
		}
		unsignedBytes := mustCanonicalJSON(t, unsigned)
		voterSignature := signLabeled(
			t,
			fixture.privateKeys[voterID],
			codec.SignatureVoterActivationProof,
			unsignedBytes,
		)
		var complete map[string]any
		if err := json.Unmarshal(unsignedBytes, &complete); err != nil {
			t.Fatalf("json.Unmarshal(proof) error = %v", err)
		}
		complete["voter_signature"] = codec.EncodeBase64URL(voterSignature)
		proofs[index] = mustCanonicalJSON(t, complete)
	}

	handoff := authorityHandoffWire{
		SessionID:                        string(testSessionID),
		WorkspaceID:                      string(testWorkspaceID),
		RecoveryGeneration:               fixture.state.recoveryGeneration,
		TargetVoterSetVersion:            2,
		ExpectedAuthorityVoterSetVersion: 1,
		VoterSet:                         deviceIDStrings(voterIDs),
		ActivationCheckpointEventID:      string(activationCheckpointEventID),
		ActivationProofs:                 proofs,
		PriorAuthoritySigner:             string(fixture.ownerDevice),
	}
	handoffBytes := mustCanonicalJSON(t, handoff)
	handoffSignature := signLabeled(
		t,
		fixture.privateKeys[fixture.ownerDevice],
		codec.SignatureVoterAuthorityHandoff,
		handoffBytes,
	)
	return map[string]any{
		"target_voter_set_version":             uint64(2),
		"expected_authority_voter_set_version": uint64(1),
		"voter_set":                            voterIDs,
		"activation_checkpoint_event_id":       activationCheckpointEventID,
		"activation_proofs":                    proofs,
		"prior_authority_signer":               fixture.ownerDevice,
		"prior_authority_handoff": codec.EncodeBase64URL(
			handoffSignature,
		),
	}
}

func activationCheckpoint(
	t *testing.T,
	fixture reducerFixture,
) checkpointWire {
	t.Helper()

	digest := bytes.Repeat([]byte{0x31}, 32)
	return checkpointWire{
		SessionID:                string(testSessionID),
		WorkspaceID:              string(testWorkspaceID),
		RecoveryGeneration:       fixture.state.recoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           string(fixture.ownerDevice),
		Term:                     3,
		CoveredAppliedLogIndex:   activationLiveConfigurationIndex,
		CoveredChainIndex:        5,
		CoveredChainHash:         codec.EncodeBase64URL(digest),
		CoveredResultIndex:       6,
		CoveredResultHash: codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x32}, 32),
		),
		ProjectionAccumulator: codec.EncodeBase64URL(
			bytes.Repeat([]byte{0x33}, 32),
		),
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
}

func signLabeled(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	label codec.SignatureLabel,
	preimage []byte,
) []byte {
	t.Helper()
	signedInput, err := codec.BuildSignedInput(label, preimage)
	if err != nil {
		t.Fatalf("codec.BuildSignedInput() error = %v", err)
	}
	return ed25519.Sign(privateKey, signedInput)
}

func mustCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("codec.CanonicalizeSignedObject() error = %v", err)
	}
	return canonical
}

func mutateActivationProof(
	t *testing.T,
	payload *map[string]any,
	index int,
	mutate func(map[string]any),
) {
	t.Helper()
	proofs := (*payload)["activation_proofs"].([]json.RawMessage)
	var object map[string]any
	if err := json.Unmarshal(proofs[index], &object); err != nil {
		t.Fatalf("json.Unmarshal(proof) error = %v", err)
	}
	mutate(object)
	proofs[index] = mustCanonicalJSON(t, object)
}
