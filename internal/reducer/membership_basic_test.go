package reducer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestMembershipVersionReportedAppliesSelfReport(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.editorDevice,
		event.ActorDaemon,
		event.KindMembershipVersionReported,
		string(fixture.editorDevice),
		1,
		`{"daemon_version":"0.2.0","max_apply_level":2}`,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.Devices) != 1 ||
		outcome.Audit != nil {
		t.Fatalf("version-report outcome = %#v", outcome)
	}
	got := outcome.Changes.Devices[0]
	if got.ID != fixture.editorDevice ||
		got.DaemonVersion != "0.2.0" ||
		got.MaxApplyLevel != 2 ||
		got.EntityVersion != 2 {
		t.Fatalf("version-report device = %#v", got)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
}

func TestMembershipOutcomeDoesNotAliasCommittedDeviceKey(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.editorDevice,
		event.ActorDaemon,
		event.KindMembershipVersionReported,
		string(fixture.editorDevice),
		1,
		`{"daemon_version":"0.2.0","max_apply_level":2}`,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() || len(outcome.Changes.Devices) != 1 {
		t.Fatalf("version-report outcome = %#v", outcome)
	}
	committedKey := bytes.Clone(
		fixture.state.devices[fixture.editorDevice].IdentityPublicKey,
	)
	outcome.Changes.Devices[0].IdentityPublicKey[0] ^= 0xff
	if !bytes.Equal(
		fixture.state.devices[fixture.editorDevice].IdentityPublicKey,
		committedKey,
	) {
		t.Fatal("membership outcome aliases committed device public key")
	}
}

func TestMembershipDeviceAdmittedCreatesDeviceAndAuditCounter(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	member, identityPrivateKey := testDevice(t, 4, device.RoleEditor)
	payload := admissionPayload(t, member, identityPrivateKey)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorHuman,
		event.KindMembershipDeviceAdmitted,
		string(member.ID),
		0,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.Devices) != 1 ||
		len(outcome.Changes.AuditCounters) != 1 ||
		outcome.Audit == nil {
		t.Fatalf("admission outcome = %#v", outcome)
	}
	if got := outcome.Changes.AuditCounters[0]; got.DeviceID != member.ID ||
		got.CredentialEpoch != 0 ||
		got.AcceptedCount != 0 {
		t.Fatalf("admission audit counter = %#v", got)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	if fixture.state.devices[member.ID].Status != device.StatusActive {
		t.Fatal("admitted member is not active")
	}
}

func TestMembershipDeviceAdmittedReadmitsRetainedIdentity(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	current := fixture.state.devices[fixture.targetDevice]
	current.Status = device.StatusRequiresReadmission
	fixture.state.devices[fixture.targetDevice] = current
	payload := admissionPayload(
		t,
		current,
		fixture.privateKeys[fixture.targetDevice],
	)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorHuman,
		event.KindMembershipDeviceAdmitted,
		string(current.ID),
		current.EntityVersion,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.Devices) != 1 ||
		len(outcome.Changes.AuditCounters) != 0 {
		t.Fatalf("readmission outcome = %#v", outcome)
	}
	got := outcome.Changes.Devices[0]
	if got.Status != device.StatusActive ||
		got.EntityVersion != current.EntityVersion+1 {
		t.Fatalf("readmitted device = %#v", got)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
}

func TestMembershipDeviceAdmittedRejectsInvalidBindingAndMemberLimit(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*reducerFixture, *map[string]any)
		want   Code
	}{
		{
			name: "binding signature",
			mutate: func(_ *reducerFixture, payload *map[string]any) {
				binding := (*payload)["initial_epoch_binding"].(map[string]any)
				binding["binding_signature"] =
					codec.EncodeBase64URL(make([]byte, ed25519.SignatureSize))
			},
			want: CodeInvalidPayload,
		},
		{
			name: "member limit",
			mutate: func(fixture *reducerFixture, _ *map[string]any) {
				fixture.state.sessionPolicy.Values.MaxMemberDevices = 3
			},
			want: CodeMemberLimitReached,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			member, privateKey := testDevice(t, 4, device.RoleEditor)
			payload := admissionPayloadObject(t, member, privateKey)
			test.mutate(&fixture, &payload)
			signed := buildMembershipProposal(
				t,
				fixture,
				fixture.ownerDevice,
				event.ActorHuman,
				event.KindMembershipDeviceAdmitted,
				string(member.ID),
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

func TestMembershipDeviceAdmittedClassifiesExistingRowBeforeMemberLimit(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name            string
		prepare         func(*reducerFixture)
		expectedVersion uint64
		want            Code
	}{
		{
			name: "active duplicate",
			prepare: func(fixture *reducerFixture) {
				fixture.state.sessionPolicy.Values.MaxMemberDevices = 3
			},
			want: CodeEntityAlreadyExists,
		},
		{
			name: "stale readmission",
			prepare: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.targetDevice]
				member.Status = device.StatusRequiresReadmission
				fixture.state.devices[fixture.targetDevice] = member
				fixture.state.sessionPolicy.Values.MaxMemberDevices = 2
			},
			expectedVersion: 2,
			want:            CodeEntityVersionMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			test.prepare(&fixture)
			member := fixture.state.devices[fixture.targetDevice]
			signed := buildMembershipProposal(
				t,
				fixture,
				fixture.ownerDevice,
				event.ActorHuman,
				event.KindMembershipDeviceAdmitted,
				string(member.ID),
				test.expectedVersion,
				admissionPayload(
					t,
					member,
					fixture.privateKeys[member.ID],
				),
			)
			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			assertMembershipRejection(t, outcome, test.want)
		})
	}
}

func TestMembershipRoleChangedPreservesOwnerContinuity(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorHuman,
		event.KindMembershipRoleChanged,
		string(fixture.editorDevice),
		1,
		fmt.Sprintf(
			`{"device_id":%q,"role":"owner"}`,
			fixture.editorDevice,
		),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce(promote) error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.Devices) != 1 ||
		outcome.Audit == nil {
		t.Fatalf("role-change outcome = %#v", outcome)
	}
	if got := outcome.Changes.Devices[0]; got.Role != device.RoleOwner ||
		got.EntityVersion != 2 {
		t.Fatalf("promoted device = %#v", got)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply(promote) error = %v", err)
	}

	demote := buildMembershipProposal(
		t,
		fixture,
		fixture.editorDevice,
		event.ActorHuman,
		event.KindMembershipRoleChanged,
		string(fixture.ownerDevice),
		1,
		fmt.Sprintf(
			`{"device_id":%q,"role":"editor"}`,
			fixture.ownerDevice,
		),
	)
	outcome, err = Reduce(fixture.state, demote)
	if err != nil {
		t.Fatalf("Reduce(demote) error = %v", err)
	}
	if !outcome.Accepted() {
		t.Fatalf("demote outcome = %#v", outcome)
	}
}

func TestMembershipOwnerRecoveredRequiresExactRecoveryAuthorization(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	payload := ownerRecoveryPayload(
		t,
		fixture,
		fixture.editorDevice,
		1,
		fixture.recoveryPrivateKey,
	)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.editorDevice,
		event.ActorHuman,
		event.KindMembershipOwnerRecovered,
		string(fixture.editorDevice),
		1,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.Devices) != 1 ||
		outcome.Changes.Devices[0].Role != device.RoleOwner ||
		outcome.Audit == nil {
		t.Fatalf("owner-recovery outcome = %#v", outcome)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
}

func TestMembershipOwnerRecoveredRejectsWrongKeyAndTuple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload func(*testing.T, reducerFixture) string
		want    Code
	}{
		{
			name: "wrong key",
			payload: func(t *testing.T, fixture reducerFixture) string {
				wrongKey := ed25519.NewKeyFromSeed(
					make([]byte, ed25519.SeedSize),
				)
				return ownerRecoveryPayload(
					t,
					fixture,
					fixture.editorDevice,
					1,
					wrongKey,
				)
			},
			want: CodeInvalidRecoveryAuthorization,
		},
		{
			name: "wrong generation",
			payload: func(t *testing.T, fixture reducerFixture) string {
				payload := ownerRecoveryPayloadObject(
					t,
					fixture,
					fixture.editorDevice,
					1,
					fixture.recoveryPrivateKey,
				)
				authorization := payload["recovery_authorization"].(map[string]any)
				authorization["recovery_generation"] = uint64(1)
				return mustJSON(t, payload)
			},
			want: CodeInvalidRecoveryAuthorization,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			signed := buildMembershipProposal(
				t,
				fixture,
				fixture.editorDevice,
				event.ActorHuman,
				event.KindMembershipOwnerRecovered,
				string(fixture.editorDevice),
				1,
				test.payload(t, fixture),
			)
			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			assertMembershipRejection(t, outcome, test.want)
		})
	}
}

func TestMembershipRoleChangedRejectsLastOwnerDemotion(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorHuman,
		event.KindMembershipRoleChanged,
		string(fixture.ownerDevice),
		1,
		fmt.Sprintf(
			`{"device_id":%q,"role":"editor"}`,
			fixture.ownerDevice,
		),
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	assertMembershipRejection(t, outcome, CodeLastActiveOwner)
}

func TestMembershipVoterSetChangedAppliesFullTarget(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	ids := []domain.DeviceID{
		fixture.editorDevice,
		fixture.ownerDevice,
		fixture.targetDevice,
	}
	sortDeviceIDs(ids)
	payload := mustJSON(t, map[string]any{"voter_set": ids})
	signed := buildMembershipProposal(
		t,
		fixture,
		fixture.ownerDevice,
		event.ActorHuman,
		event.KindMembershipVoterSetChanged,
		string(testSessionID),
		1,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		len(outcome.Changes.VoterSet) != 1 ||
		outcome.Audit == nil {
		t.Fatalf("voter-set outcome = %#v", outcome)
	}
	next := outcome.Changes.VoterSet[0]
	if next.VoterSetVersion != 2 ||
		!sameDeviceIDs(next.VoterDeviceIDs(), ids) {
		t.Fatalf("voter target = %#v", next)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
}

func TestMembershipDeviceRevokedHandlesNonvoterAndTargetVoter(t *testing.T) {
	t.Parallel()

	t.Run("nonvoter", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		payload := revocationPayload(
			t,
			fixture.targetDevice,
			fixture.state.voterSet.VoterDeviceIDs(),
			fixture.state.voterSet.VoterSetVersion,
		)
		signed := buildMembershipProposal(
			t,
			fixture,
			fixture.ownerDevice,
			event.ActorHuman,
			event.KindMembershipDeviceRevoked,
			string(fixture.targetDevice),
			1,
			payload,
		)
		outcome, err := Reduce(fixture.state, signed)
		if err != nil {
			t.Fatalf("Reduce() error = %v", err)
		}
		if !outcome.Accepted() ||
			len(outcome.Changes.Devices) != 1 ||
			len(outcome.Changes.VoterSet) != 0 ||
			outcome.Changes.Devices[0].Status != device.StatusRevoked {
			t.Fatalf("nonvoter revocation = %#v", outcome)
		}
		if err := fixture.state.Apply(outcome.Changes); err != nil {
			t.Fatalf("State.Apply() error = %v", err)
		}
	})

	t.Run("target voter", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		ids := []domain.DeviceID{
			fixture.editorDevice,
			fixture.ownerDevice,
			fixture.targetDevice,
		}
		sortDeviceIDs(ids)
		target, err := voterset.New(testSessionID, ids, 1)
		if err != nil {
			t.Fatalf("voterset.New() error = %v", err)
		}
		fixture.state.voterSet = target
		fixture.state.credentialAuthority = credentialauthority.Authority{
			SessionID:        testSessionID,
			VoterDeviceIDs:   append([]domain.DeviceID(nil), ids...),
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}
		payload := revocationPayload(
			t,
			fixture.targetDevice,
			[]domain.DeviceID{fixture.ownerDevice},
			1,
		)
		signed := buildMembershipProposal(
			t,
			fixture,
			fixture.ownerDevice,
			event.ActorHuman,
			event.KindMembershipDeviceRevoked,
			string(fixture.targetDevice),
			1,
			payload,
		)
		outcome, err := Reduce(fixture.state, signed)
		if err != nil {
			t.Fatalf("Reduce() error = %v", err)
		}
		if !outcome.Accepted() ||
			len(outcome.Changes.VoterSet) != 1 ||
			outcome.Changes.VoterSet[0].VoterSetVersion != 2 {
			t.Fatalf("target-voter revocation = %#v", outcome)
		}
		if err := fixture.state.Apply(outcome.Changes); err != nil {
			t.Fatalf("State.Apply() error = %v", err)
		}
	})
}

func TestMembershipDeviceRevokedPreservesGovernanceAndAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*testing.T, *reducerFixture)
		subject func(reducerFixture) domain.DeviceID
		version func(reducerFixture) uint64
		target  func(reducerFixture) []domain.DeviceID
		want    Code
	}{
		{
			name: "last owner",
			subject: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			version: func(reducerFixture) uint64 { return 1 },
			target: func(fixture reducerFixture) []domain.DeviceID {
				return fixture.state.voterSet.VoterDeviceIDs()
			},
			want: CodeLastActiveOwner,
		},
		{
			name: "sole voter",
			prepare: func(_ *testing.T, fixture *reducerFixture) {
				editor := fixture.state.devices[fixture.editorDevice]
				editor.Role = device.RoleOwner
				fixture.state.devices[fixture.editorDevice] = editor
			},
			subject: func(fixture reducerFixture) domain.DeviceID {
				return fixture.ownerDevice
			},
			version: func(reducerFixture) uint64 { return 1 },
			target: func(fixture reducerFixture) []domain.DeviceID {
				return fixture.state.voterSet.VoterDeviceIDs()
			},
			want: CodeSoleVoterRevocation,
		},
		{
			name: "authority majority",
			prepare: func(t *testing.T, fixture *reducerFixture) {
				ids := []domain.DeviceID{
					fixture.editorDevice,
					fixture.ownerDevice,
					fixture.targetDevice,
				}
				sortDeviceIDs(ids)
				target, err := voterset.New(
					testSessionID,
					[]domain.DeviceID{fixture.ownerDevice},
					2,
				)
				if err != nil {
					t.Fatalf("voterset.New() error = %v", err)
				}
				fixture.state.voterSet = target
				fixture.state.credentialAuthority =
					credentialauthority.Authority{
						SessionID:        testSessionID,
						VoterDeviceIDs:   ids,
						VoterSetVersion:  1,
						ActivationSource: credentialauthority.ActivationGenesis,
					}
				inactive := fixture.state.devices[fixture.targetDevice]
				inactive.Status = device.StatusRequiresReadmission
				fixture.state.devices[fixture.targetDevice] = inactive
			},
			subject: func(fixture reducerFixture) domain.DeviceID {
				return fixture.editorDevice
			},
			version: func(fixture reducerFixture) uint64 {
				return fixture.state.voterSet.VoterSetVersion
			},
			target: func(fixture reducerFixture) []domain.DeviceID {
				return fixture.state.voterSet.VoterDeviceIDs()
			},
			want: CodeCredentialAuthorityQuorumLost,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			if test.prepare != nil {
				test.prepare(t, &fixture)
			}
			subject := test.subject(fixture)
			payload := revocationPayload(
				t,
				subject,
				test.target(fixture),
				test.version(fixture),
			)
			signed := buildMembershipProposal(
				t,
				fixture,
				fixture.ownerDevice,
				event.ActorHuman,
				event.KindMembershipDeviceRevoked,
				string(subject),
				fixture.state.devices[subject].EntityVersion,
				payload,
			)
			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			assertMembershipRejection(t, outcome, test.want)
		})
	}
}

func TestBasicMembershipReducersRejectDeterministically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    event.Kind
		actor   event.ActorType
		origin  func(reducerFixture) domain.DeviceID
		entity  func(reducerFixture) string
		version uint64
		payload func(reducerFixture) string
		mutate  func(*reducerFixture)
		want    Code
	}{
		{
			name:    "version report targets another member",
			kind:    event.KindMembershipVersionReported,
			actor:   event.ActorDaemon,
			origin:  editorOrigin,
			entity:  ownerEntity,
			version: 1,
			payload: func(reducerFixture) string {
				return `{"daemon_version":"0.2.0","max_apply_level":1}`
			},
			want: CodeMembershipSubjectMismatch,
		},
		{
			name:    "version report unchanged",
			kind:    event.KindMembershipVersionReported,
			actor:   event.ActorDaemon,
			origin:  editorOrigin,
			entity:  editorEntity,
			version: 1,
			payload: func(reducerFixture) string {
				return `{"daemon_version":"0.1.0","max_apply_level":1}`
			},
			want: CodeMembershipReportUnchanged,
		},
		{
			name:    "role payload subject mismatch",
			kind:    event.KindMembershipRoleChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  editorEntity,
			version: 1,
			payload: func(fixture reducerFixture) string {
				return fmt.Sprintf(
					`{"device_id":%q,"role":"owner"}`,
					fixture.targetDevice,
				)
			},
			want: CodeMembershipSubjectMismatch,
		},
		{
			name:    "role payload malformed subject",
			kind:    event.KindMembershipRoleChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  editorEntity,
			version: 1,
			payload: func(reducerFixture) string {
				return `{"device_id":"malformed","role":"owner"}`
			},
			want: CodeInvalidPayload,
		},
		{
			name:    "role unchanged",
			kind:    event.KindMembershipRoleChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  editorEntity,
			version: 1,
			payload: func(fixture reducerFixture) string {
				return fmt.Sprintf(
					`{"device_id":%q,"role":"editor"}`,
					fixture.editorDevice,
				)
			},
			want: CodeInvalidMembershipTransition,
		},
		{
			name:    "role stale version",
			kind:    event.KindMembershipRoleChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  editorEntity,
			version: 2,
			payload: func(fixture reducerFixture) string {
				return fmt.Sprintf(
					`{"device_id":%q,"role":"owner"}`,
					fixture.editorDevice,
				)
			},
			want: CodeEntityVersionMismatch,
		},
		{
			name:    "revocation payload malformed subject",
			kind:    event.KindMembershipDeviceRevoked,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  editorEntity,
			version: 1,
			payload: func(fixture reducerFixture) string {
				return mustJSON(t, map[string]any{
					"device_id":                  "malformed",
					"reason":                     "operator removal",
					"voter_set":                  fixture.state.voterSet.VoterDeviceIDs(),
					"expected_voter_set_version": fixture.state.voterSet.VoterSetVersion,
				})
			},
			want: CodeInvalidPayload,
		},
		{
			name:    "voter target unchanged",
			kind:    event.KindMembershipVoterSetChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  sessionEntity,
			version: 1,
			payload: func(fixture reducerFixture) string {
				return mustJSON(t, map[string]any{
					"voter_set": []domain.DeviceID{fixture.ownerDevice},
				})
			},
			want: CodeVoterTargetUnchanged,
		},
		{
			name:    "voter target contains inactive member",
			kind:    event.KindMembershipVoterSetChanged,
			actor:   event.ActorHuman,
			origin:  ownerOrigin,
			entity:  sessionEntity,
			version: 1,
			payload: func(fixture reducerFixture) string {
				ids := []domain.DeviceID{
					fixture.editorDevice,
					fixture.ownerDevice,
					fixture.targetDevice,
				}
				sortDeviceIDs(ids)
				return mustJSON(t, map[string]any{"voter_set": ids})
			},
			mutate: func(fixture *reducerFixture) {
				member := fixture.state.devices[fixture.targetDevice]
				member.Status = device.StatusRequiresReadmission
				fixture.state.devices[fixture.targetDevice] = member
			},
			want: CodeVoterTargetNotActive,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			if test.mutate != nil {
				test.mutate(&fixture)
			}
			signed := buildMembershipProposal(
				t,
				fixture,
				test.origin(fixture),
				test.actor,
				test.kind,
				test.entity(fixture),
				test.version,
				test.payload(fixture),
			)
			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			assertMembershipRejection(t, outcome, test.want)
		})
	}
}

func buildMembershipProposal(
	t *testing.T,
	fixture reducerFixture,
	originDeviceID domain.DeviceID,
	actor event.ActorType,
	kind event.Kind,
	entityID string,
	expectedVersion uint64,
	payload string,
) event.SignedEvent {
	t.Helper()

	authority, err := event.NewLocalAuthority(originDeviceID, testBootID)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority() error = %v", err)
	}
	var binding event.Binding
	switch actor {
	case event.ActorHuman:
		binding, err = authority.OperatorBinding()
	case event.ActorDaemon:
		binding, err = authority.DaemonBinding()
	default:
		t.Fatalf("unsupported membership actor %q", actor)
	}
	if err != nil {
		t.Fatalf("construct membership binding: %v", err)
	}
	command := event.Command{
		Kind:             kind,
		EntityID:         event.StringEntityID(entityID),
		RationaleSummary: "",
		Actions:          []event.Action{},
		Payload:          json.RawMessage(payload),
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}
	if expectedVersion != 0 {
		command.ExpectedEntityVersion = &expectedVersion
	}
	proposal, err := event.BuildProposal(command, binding, event.BuildContext{
		EventID:        testEventID,
		SessionID:      testSessionID,
		WorkspaceID:    testWorkspaceID,
		CreatedAt:      testTimestamp,
		OriginSequence: 2,
	})
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	privateKey, exists := fixture.privateKeys[originDeviceID]
	if !exists {
		t.Fatalf("missing private key for %q", originDeviceID)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}

func assertMembershipRejection(t *testing.T, outcome Outcome, want Code) {
	t.Helper()
	if outcome.Status != StatusRejected ||
		outcome.Code != want ||
		len(outcome.Changes.OriginScopes) != 1 ||
		len(outcome.Changes.Devices) != 0 ||
		len(outcome.Changes.VoterSet) != 0 ||
		len(outcome.Changes.CredentialAuthority) != 0 {
		t.Fatalf("membership rejection = %#v, want %q", outcome, want)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
}

func admissionPayload(
	t *testing.T,
	member device.Device,
	identityPrivateKey ed25519.PrivateKey,
) string {
	t.Helper()
	return mustJSON(t, admissionPayloadObject(t, member, identityPrivateKey))
}

func admissionPayloadObject(
	t *testing.T,
	member device.Device,
	identityPrivateKey ed25519.PrivateKey,
) map[string]any {
	t.Helper()

	epochPrivateKey := ed25519.NewKeyFromSeed(
		make([]byte, ed25519.SeedSize),
	)
	epochPublicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	publicKeyText := codec.EncodeBase64URL(epochPublicKey)
	preimageJSON, err := json.Marshal(credentialBindingPreimage{
		DeviceID:       string(member.ID),
		Epoch:          initialCredentialEpoch,
		EpochPublicKey: publicKeyText,
		SessionID:      string(testSessionID),
	})
	if err != nil {
		t.Fatalf("json.Marshal(binding preimage) error = %v", err)
	}
	preimage, err := codec.CanonicalizeSignedObject(preimageJSON)
	if err != nil {
		t.Fatalf("canonicalize binding preimage: %v", err)
	}
	signedInput, err := codec.BuildSignedInput(
		codec.SignatureCredentialBinding,
		preimage,
	)
	if err != nil {
		t.Fatalf("codec.BuildSignedInput() error = %v", err)
	}
	signature := ed25519.Sign(identityPrivateKey, signedInput)
	digest := sha256.Sum256(epochPublicKey)
	return map[string]any{
		"identity_public_key": codec.EncodeBase64URL(member.IdentityPublicKey),
		"role":                member.Role,
		"daemon_version":      member.DaemonVersion,
		"max_apply_level":     member.MaxApplyLevel,
		"initial_epoch_binding": map[string]any{
			"binding_signature": codec.EncodeBase64URL(signature),
			"epoch":             initialCredentialEpoch,
			"epoch_public_key":  publicKeyText,
			"key_digest":        codec.EncodeBase64URL(digest[:]),
		},
	}
}

func ownerRecoveryPayload(
	t *testing.T,
	fixture reducerFixture,
	subjectID domain.DeviceID,
	expectedVersion uint64,
	privateKey ed25519.PrivateKey,
) string {
	t.Helper()
	return mustJSON(
		t,
		ownerRecoveryPayloadObject(
			t,
			fixture,
			subjectID,
			expectedVersion,
			privateKey,
		),
	)
}

func ownerRecoveryPayloadObject(
	t *testing.T,
	fixture reducerFixture,
	subjectID domain.DeviceID,
	expectedVersion uint64,
	privateKey ed25519.PrivateKey,
) map[string]any {
	t.Helper()

	preimage := ownerRecoveryPreimage{
		EventID:               string(testEventID),
		ExpectedEntityVersion: expectedVersion,
		RecoveryGeneration:    fixture.state.recoveryGeneration,
		SessionID:             string(testSessionID),
		SubjectDeviceID:       string(subjectID),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		t.Fatalf("json.Marshal(owner recovery) error = %v", err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		t.Fatalf("canonicalize owner recovery: %v", err)
	}
	signedInput, err := codec.BuildSignedInput(
		codec.SignatureOwnerRecovery,
		canonical,
	)
	if err != nil {
		t.Fatalf("codec.BuildSignedInput() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, signedInput)
	return map[string]any{
		"recovery_authorization": map[string]any{
			"event_id":                preimage.EventID,
			"expected_entity_version": preimage.ExpectedEntityVersion,
			"recovery_generation":     preimage.RecoveryGeneration,
			"session_id":              preimage.SessionID,
			"signature":               codec.EncodeBase64URL(signature),
			"subject_device_id":       preimage.SubjectDeviceID,
		},
	}
}

func revocationPayload(
	t *testing.T,
	subjectID domain.DeviceID,
	target []domain.DeviceID,
	expectedVoterSetVersion uint64,
) string {
	t.Helper()
	return mustJSON(t, map[string]any{
		"device_id":                  subjectID,
		"reason":                     "device retired",
		"voter_set":                  target,
		"expected_voter_set_version": expectedVoterSetVersion,
	})
}

func sortDeviceIDs(ids []domain.DeviceID) {
	for index := 1; index < len(ids); index++ {
		for cursor := index; cursor > 0 && ids[cursor] < ids[cursor-1]; cursor-- {
			ids[cursor], ids[cursor-1] = ids[cursor-1], ids[cursor]
		}
	}
}

func ownerOrigin(fixture reducerFixture) domain.DeviceID {
	return fixture.ownerDevice
}

func editorOrigin(fixture reducerFixture) domain.DeviceID {
	return fixture.editorDevice
}

func ownerEntity(fixture reducerFixture) string {
	return string(fixture.ownerDevice)
}

func editorEntity(fixture reducerFixture) string {
	return string(fixture.editorDevice)
}

func sessionEntity(reducerFixture) string {
	return string(testSessionID)
}

func TestMembershipStateRejectsAtomicCorruption(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	before := snapshotFromState(fixture.state)
	next, err := voterset.New(
		testSessionID,
		[]domain.DeviceID{fixture.targetDevice},
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	inactive := fixture.state.devices[fixture.targetDevice]
	inactive.Status = device.StatusRequiresReadmission
	fixture.state.devices[fixture.targetDevice] = inactive
	err = fixture.state.Apply(Changes{VoterSet: []voterset.Set{next}})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid state", err)
	}
	after := snapshotFromState(fixture.state)
	if !before.VoterSet.SameTarget(after.VoterSet) ||
		before.VoterSet.VoterSetVersion != after.VoterSet.VoterSetVersion {
		t.Fatal("failed membership apply mutated voter target")
	}
}
