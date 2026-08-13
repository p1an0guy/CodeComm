package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
)

func TestCredentialAuthorizedAppliesAuthorizationAndResetsAuditCounter(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	counter := fixture.state.auditCounters[fixture.editorDevice]
	counter.AcceptedCount = 7
	fixture.state.auditCounters[fixture.editorDevice] = counter
	options := defaultCredentialPayloadOptions(fixture)
	payload, expected := credentialPayload(t, fixture, options)
	signed := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		fixture.editorDevice,
		2,
		payload,
	)

	outcome, err := Reduce(fixture.state, signed)
	if err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}
	if !outcome.Accepted() ||
		!outcome.Changes.AdvancesEventChain ||
		len(outcome.Changes.CredentialAuthorizations) != 1 ||
		len(outcome.Changes.AuditCounters) != 1 {
		t.Fatalf("credential outcome = %#v", outcome)
	}
	got := outcome.Changes.CredentialAuthorizations[0]
	if got.PrimaryKey() != expected.PrimaryKey() ||
		got.AuthorizationChainIndex != 1 ||
		got.KeyDigest != expected.KeyDigest {
		t.Fatalf("credential authorization = %#v", got)
	}
	if gotCounter := outcome.Changes.AuditCounters[0]; gotCounter.DeviceID != fixture.editorDevice ||
		gotCounter.CredentialEpoch != 1 ||
		gotCounter.AcceptedCount != 0 {
		t.Fatalf("audit counter = %#v", gotCounter)
	}
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	if fixture.state.currentChainIndex != 1 ||
		fixture.state.auditCounters[fixture.editorDevice].CredentialEpoch != 1 {
		t.Fatalf("state did not advance atomically: %#v", fixture.state)
	}
	stored := fixture.state.credentialAuthorizations[got.PrimaryKey()]
	outcome.Changes.CredentialAuthorizations[0].ClockEndorsements[0].
		Signature[0] ^= 0xff
	if stored.ClockEndorsements[0].Signature !=
		expected.ClockEndorsements[0].Signature {
		t.Fatal("credential outcome aliases committed authorization")
	}
}

func TestCredentialAuthorizedSupportsOverlapAndLateRenewal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		issuedAt  string
		notBefore string
	}{
		{
			name:      "overlap clamp",
			issuedAt:  "2024-01-01T00:25:00Z",
			notBefore: "2024-01-01T00:28:00Z",
		},
		{
			name:      "late renewal",
			issuedAt:  "2024-01-02T08:00:00Z",
			notBefore: "2024-01-02T08:00:00Z",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			firstOptions := defaultCredentialPayloadOptions(fixture)
			firstPayload, _ := credentialPayload(t, fixture, firstOptions)
			first := buildCredentialProposal(
				t,
				fixture,
				fixture.ownerDevice,
				fixture.editorDevice,
				2,
				firstPayload,
			)
			firstOutcome, err := Reduce(fixture.state, first)
			if err != nil || !firstOutcome.Accepted() {
				t.Fatalf("first Reduce() = %#v, %v", firstOutcome, err)
			}
			if err := fixture.state.Apply(firstOutcome.Changes); err != nil {
				t.Fatalf("first Apply() error = %v", err)
			}

			nextOptions := defaultCredentialPayloadOptions(fixture)
			nextOptions.keySeed = 0x62
			nextOptions.issuedAt = domain.WholeSecondTimestamp(test.issuedAt)
			nextOptions.notBefore = domain.WholeSecondTimestamp(test.notBefore)
			nextPayload, _ := credentialPayload(t, fixture, nextOptions)
			next := buildCredentialProposal(
				t,
				fixture,
				fixture.ownerDevice,
				fixture.editorDevice,
				3,
				nextPayload,
			)
			nextOutcome, err := Reduce(fixture.state, next)
			if err != nil {
				t.Fatalf("successor Reduce() error = %v", err)
			}
			if !nextOutcome.Accepted() {
				t.Fatalf("successor outcome = %#v", nextOutcome)
			}
			if got := nextOutcome.Changes.CredentialAuthorizations[0]; got.Epoch != 2 || got.AuthorizationChainIndex != 2 {
				t.Fatalf("successor authorization = %#v", got)
			}
		})
	}
}

func TestCredentialAuthorizationChainPositionIgnoresRejectedResults(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	rejected := Changes{
		OriginScopes: []OriginScope{{
			OriginScopeKey: OriginScopeKey{
				DeviceID: fixture.ownerDevice,
				Kind:     ScopeBoot,
				ScopeID:  testBootID,
			},
			LastSequence: 2,
		}},
	}
	if err := fixture.state.Apply(rejected); err != nil {
		t.Fatalf("apply rejected result: %v", err)
	}
	if fixture.state.currentResultIndex != 2 ||
		fixture.state.currentChainIndex != 0 {
		t.Fatalf(
			"indices after rejection = result %d, chain %d",
			fixture.state.currentResultIndex,
			fixture.state.currentChainIndex,
		)
	}
	options := defaultCredentialPayloadOptions(fixture)
	payload, _ := credentialPayload(t, fixture, options)
	signed := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		fixture.editorDevice,
		3,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil || !outcome.Accepted() {
		t.Fatalf("Reduce() = %#v, %v", outcome, err)
	}
	if got := outcome.Changes.CredentialAuthorizations[0].
		AuthorizationChainIndex; got != 1 {
		t.Fatalf("authorization chain index = %d, want 1", got)
	}
}

func TestCredentialAuthorizationUsesPerDeviceEpochs(t *testing.T) {
	t.Parallel()

	fixture := fixtureWithFirstCredential(t)
	options := defaultCredentialPayloadOptions(fixture)
	options.subject = fixture.ownerDevice
	options.epoch = 1
	options.role = fixture.state.devices[fixture.ownerDevice].Role
	options.keySeed = 0x63
	payload, _ := credentialPayload(t, fixture, options)
	signed := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		fixture.ownerDevice,
		3,
		payload,
	)
	outcome, err := Reduce(fixture.state, signed)
	if err != nil || !outcome.Accepted() {
		t.Fatalf("owner authorization = %#v, %v", outcome, err)
	}
	got := outcome.Changes.AuditCounters[0]
	if got.DeviceID != fixture.ownerDevice || got.CredentialEpoch != 1 ||
		fixture.state.auditCounters[fixture.editorDevice].CredentialEpoch != 1 {
		t.Fatalf("owner audit counter = %#v", got)
	}
	if credentialauthorization.ValiditySeconds != 1_800 {
		t.Fatal("credential validity constant changed")
	}
}
