package reducer

import (
	"crypto/ed25519"
	"sort"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestCredentialAuthorizedRejectsClosedPayloadViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   Code
	}{
		{
			name: "unknown top-level field",
			mutate: func(payload map[string]any) {
				payload["extra"] = true
			},
			want: CodeUnknownPayloadField,
		},
		{
			name: "missing top-level field",
			mutate: func(payload map[string]any) {
				delete(payload, "issued_at")
			},
			want: CodeMissingPayloadField,
		},
		{
			name: "null top-level field",
			mutate: func(payload map[string]any) {
				payload["issued_at"] = nil
			},
			want: CodeInvalidPayload,
		},
		{
			name: "padded base64url",
			mutate: func(payload map[string]any) {
				payload["key_digest"] = payload["key_digest"].(string) + "="
			},
			want: CodeInvalidPayload,
		},
		{
			name: "unknown endorsement field",
			mutate: func(payload map[string]any) {
				endorsements := payload["clock_endorsements"].([]map[string]any)
				endorsements[0]["extra"] = true
			},
			want: CodeInvalidPayload,
		},
		{
			name: "missing endorsement field",
			mutate: func(payload map[string]any) {
				endorsements := payload["clock_endorsements"].([]map[string]any)
				delete(endorsements[0], "signature")
			},
			want: CodeInvalidPayload,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			options := defaultCredentialPayloadOptions(fixture)
			outcome := reduceCredentialPayload(
				t,
				fixture,
				options,
				test.mutate,
			)
			assertCredentialRejection(t, outcome, test.want)
		})
	}
}

func TestCredentialAuthorizedRejectionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(*testing.T, reducerFixture) Outcome
		want Code
	}{
		{
			name: "subject entity mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				payload, _ := credentialPayload(t, fixture, options)
				signed := buildCredentialProposal(
					t,
					fixture,
					fixture.ownerDevice,
					fixture.targetDevice,
					2,
					payload,
				)
				return mustReduceCredential(t, fixture, signed)
			},
			want: CodeCredentialSubjectMismatch,
		},
		{
			name: "subject not found",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				unknown, _ := testDevice(t, 0x45, device.RoleEditor)
				options := defaultCredentialPayloadOptions(fixture)
				payload, _ := credentialPayload(t, fixture, options)
				payload["subject_device_id"] = unknown.ID
				signed := buildCredentialProposal(
					t,
					fixture,
					fixture.ownerDevice,
					unknown.ID,
					2,
					payload,
				)
				return mustReduceCredential(t, fixture, signed)
			},
			want: CodeCredentialSubjectNotFound,
		},
		{
			name: "subject not active",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.subject = fixture.targetDevice
				options.role = device.RoleEditor
				payload, _ := credentialPayload(t, fixture, options)
				member := fixture.state.devices[fixture.targetDevice]
				member.Status = device.StatusRevoked
				fixture.state.devices[fixture.targetDevice] = member
				signed := buildCredentialProposal(
					t,
					fixture,
					fixture.ownerDevice,
					fixture.targetDevice,
					2,
					payload,
				)
				return mustReduceCredential(t, fixture, signed)
			},
			want: CodeCredentialSubjectNotActive,
		},
		{
			name: "epoch mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.epoch = 2
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialEpochMismatch,
		},
		{
			name: "epoch exhausted",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				counter := fixture.state.auditCounters[fixture.editorDevice]
				counter.CredentialEpoch = domain.MaxSafeInteger
				fixture.state.auditCounters[fixture.editorDevice] = counter
				options := defaultCredentialPayloadOptions(fixture)
				options.epoch = domain.MaxSafeInteger
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialEpochExhausted,
		},
		{
			name: "key digest mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				return reduceCredentialPayload(
					t,
					fixture,
					options,
					func(payload map[string]any) {
						payload["key_digest"] = codec.EncodeBase64URL(
							make([]byte, 32),
						)
					},
				)
			},
			want: CodeCredentialKeyDigestMismatch,
		},
		{
			name: "invalid binding signature",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				return reduceCredentialPayload(
					t,
					fixture,
					options,
					func(payload map[string]any) {
						payload["binding_signature"] = codec.EncodeBase64URL(
							make([]byte, ed25519.SignatureSize),
						)
					},
				)
			},
			want: CodeInvalidCredentialBinding,
		},
		{
			name: "key reused",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				payload, authorization := credentialPayload(t, fixture, options)
				fixture.state.credentialKeys[authorization.KeyDigest] =
					credentialauthorization.Key{
						SessionID: fixture.state.sessionID,
						DeviceID:  fixture.ownerDevice,
						Epoch:     1,
					}
				signed := buildCredentialProposal(
					t,
					fixture,
					fixture.ownerDevice,
					fixture.editorDevice,
					2,
					payload,
				)
				return mustReduceCredential(t, fixture, signed)
			},
			want: CodeCredentialKeyReused,
		},
		{
			name: "role mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.role = device.RoleOwner
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialRoleMismatch,
		},
		{
			name: "authority version mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.authorityVersion = 2
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialAuthorityVersionMismatch,
		},
		{
			name: "duplicate endorsement",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.endorsers = []domain.DeviceID{
					fixture.ownerDevice,
					fixture.ownerDevice,
				}
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeInvalidCredentialEndorsements,
		},
		{
			name: "non-authority endorsement",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.endorsers = []domain.DeviceID{fixture.editorDevice}
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeInvalidCredentialEndorsements,
		},
		{
			name: "invalid endorsement signature",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				return reduceCredentialPayload(
					t,
					fixture,
					options,
					func(payload map[string]any) {
						endorsements :=
							payload["clock_endorsements"].([]map[string]any)
						endorsements[0]["signature"] =
							codec.EncodeBase64URL(
								make([]byte, ed25519.SignatureSize),
							)
					},
				)
			},
			want: CodeInvalidCredentialEndorsements,
		},
		{
			name: "validity mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.validitySeconds = 1_799
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialValidityMismatch,
		},
		{
			name: "first not-before mismatch",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.notBefore = "2024-01-01T00:00:01Z"
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialNotBeforeMismatch,
		},
		{
			name: "not-before precedes issued-at",
			run: func(t *testing.T, fixture reducerFixture) Outcome {
				options := defaultCredentialPayloadOptions(fixture)
				options.notBefore = "2023-12-31T23:59:59Z"
				return reduceCredentialPayload(t, fixture, options, nil)
			},
			want: CodeCredentialNotBeforeMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			outcome := test.run(t, fixture)
			assertCredentialRejection(t, outcome, test.want)
		})
	}
}

func TestCredentialEndorsementMajoritiesUseValidTopology(t *testing.T) {
	t.Parallel()

	t.Run("three voter exact majority", func(t *testing.T) {
		t.Parallel()

		fixture := credentialVoterFixture(t, 3)
		options := defaultCredentialPayloadOptions(fixture)
		options.endorsers = fixture.state.credentialAuthority.VoterIDs()[:2]
		outcome := reduceCredentialPayload(t, fixture, options, nil)
		if !outcome.Accepted() {
			t.Fatalf("exact-majority outcome = %#v", outcome)
		}
	})

	t.Run("five voter under quorum", func(t *testing.T) {
		t.Parallel()

		fixture := credentialVoterFixture(t, 5)
		options := defaultCredentialPayloadOptions(fixture)
		options.endorsers = fixture.state.credentialAuthority.VoterIDs()[:2]
		outcome := reduceCredentialPayload(t, fixture, options, nil)
		assertCredentialRejection(
			t,
			outcome,
			CodeCredentialEndorsementQuorumNotMet,
		)
	})

	t.Run("revoked authority member with surviving majority", func(t *testing.T) {
		t.Parallel()

		fixture := credentialVoterFixture(t, 5)
		authorityIDs := fixture.state.credentialAuthority.VoterIDs()
		var revokedID domain.DeviceID
		for _, id := range authorityIDs {
			if id != fixture.ownerDevice &&
				id != fixture.editorDevice &&
				id != fixture.targetDevice {
				revokedID = id
				break
			}
		}
		if revokedID == "" {
			t.Fatal("fixture has no extra authority voter to revoke")
		}

		snapshot := snapshotFromState(fixture.state)
		revoked := snapshot.Devices[revokedID]
		revoked.Status = device.StatusRevoked
		revoked.EntityVersion++
		snapshot.Devices[revokedID] = revoked
		targetIDs := []domain.DeviceID{
			fixture.ownerDevice,
			fixture.editorDevice,
			fixture.targetDevice,
		}
		sort.Slice(targetIDs, func(left, right int) bool {
			return targetIDs[left] < targetIDs[right]
		})
		target, err := voterset.New(snapshot.SessionID, targetIDs, 2)
		if err != nil {
			t.Fatalf("voterset.New() error = %v", err)
		}
		snapshot.VoterSet = target
		state, err := NewState(snapshot)
		if err != nil {
			t.Fatalf("valid revoked-member snapshot: %v", err)
		}
		fixture.state = state

		activeEndorsers := make([]domain.DeviceID, 0, 4)
		for _, id := range authorityIDs {
			if id != revokedID {
				activeEndorsers = append(activeEndorsers, id)
			}
		}
		options := defaultCredentialPayloadOptions(fixture)
		options.endorsers = activeEndorsers[:3]
		outcome := reduceCredentialPayload(t, fixture, options, nil)
		if !outcome.Accepted() {
			t.Fatalf("surviving-majority outcome = %#v", outcome)
		}

		options.endorsers = []domain.DeviceID{
			activeEndorsers[0],
			activeEndorsers[1],
			revokedID,
		}
		sort.Slice(options.endorsers, func(left, right int) bool {
			return options.endorsers[left] < options.endorsers[right]
		})
		outcome = reduceCredentialPayload(t, fixture, options, nil)
		assertCredentialRejection(
			t,
			outcome,
			CodeInvalidCredentialEndorsements,
		)
	})
}

func credentialVoterFixture(
	t *testing.T,
	voterCount int,
) reducerFixture {
	t.Helper()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	voterIDs := []domain.DeviceID{
		fixture.ownerDevice,
		fixture.editorDevice,
		fixture.targetDevice,
	}
	for fill := byte(4); len(voterIDs) < voterCount; fill++ {
		member, privateKey := testDevice(t, fill, device.RoleEditor)
		snapshot.Devices[member.ID] = member
		snapshot.AuditCounters[member.ID] = auditcounter.Counter{
			DeviceID: member.ID,
		}
		fixture.privateKeys[member.ID] = privateKey
		voterIDs = append(voterIDs, member.ID)
	}
	sort.Slice(voterIDs, func(left, right int) bool {
		return voterIDs[left] < voterIDs[right]
	})
	target, err := voterset.New(snapshot.SessionID, voterIDs, 1)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	snapshot.VoterSet = target
	snapshot.CredentialAuthority = credentialauthority.Authority{
		SessionID:        snapshot.SessionID,
		VoterDeviceIDs:   voterIDs,
		VoterSetVersion:  1,
		ActivationSource: credentialauthority.ActivationGenesis,
	}
	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState(%d voters) error = %v", voterCount, err)
	}
	fixture.state = state
	return fixture
}

func TestCredentialAuthorizedRejectsSuccessorTimeViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		issuedAt  domain.WholeSecondTimestamp
		notBefore domain.WholeSecondTimestamp
		want      Code
	}{
		{
			name:      "before renewal lead",
			issuedAt:  "2024-01-01T00:24:59Z",
			notBefore: "2024-01-01T00:28:00Z",
			want:      CodeCredentialRenewalTooEarly,
		},
		{
			name:      "wrong overlap clamp",
			issuedAt:  "2024-01-01T00:25:00Z",
			notBefore: "2024-01-01T00:27:59Z",
			want:      CodeCredentialNotBeforeMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := fixtureWithFirstCredential(t)
			options := defaultCredentialPayloadOptions(fixture)
			options.keySeed = 0x62
			options.issuedAt = test.issuedAt
			options.notBefore = test.notBefore
			payload, _ := credentialPayload(t, fixture, options)
			signed := buildCredentialProposal(
				t,
				fixture,
				fixture.ownerDevice,
				fixture.editorDevice,
				3,
				payload,
			)
			outcome := mustReduceCredential(t, fixture, signed)
			assertCredentialRejection(t, outcome, test.want)
		})
	}
}

func TestCredentialAuthorizedRejectionPrecedence(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	options := defaultCredentialPayloadOptions(fixture)
	options.epoch = 2
	options.role = device.RoleOwner
	options.authorityVersion = 2
	outcome := reduceCredentialPayload(t, fixture, options, nil)
	assertCredentialRejection(t, outcome, CodeCredentialEpochMismatch)
}

func mustReduceCredential(
	t *testing.T,
	fixture reducerFixture,
	signed event.SignedEvent,
) Outcome {
	t.Helper()
	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	return outcome
}

func fixtureWithFirstCredential(t *testing.T) reducerFixture {
	t.Helper()
	fixture := newReducerFixture(t)
	options := defaultCredentialPayloadOptions(fixture)
	payload, _ := credentialPayload(t, fixture, options)
	signed := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		fixture.editorDevice,
		2,
		payload,
	)
	outcome := mustReduceCredential(t, fixture, signed)
	if !outcome.Accepted() {
		t.Fatalf("first credential outcome = %#v", outcome)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("apply first credential: %v", err)
	}
	return fixture
}
