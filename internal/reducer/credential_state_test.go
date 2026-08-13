package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestCredentialApplyRejectsPartialOrTamperedChangesAtomically(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Changes)
	}{
		{
			name: "missing counter reset",
			mutate: func(changes *Changes) {
				changes.AuditCounters = nil
			},
		},
		{
			name: "counter not reset",
			mutate: func(changes *Changes) {
				changes.AuditCounters[0].AcceptedCount = 1
			},
		},
		{
			name: "wrong chain position",
			mutate: func(changes *Changes) {
				changes.CredentialAuthorizations[0].
					AuthorizationChainIndex++
			},
		},
		{
			name: "stale role",
			mutate: func(changes *Changes) {
				changes.CredentialAuthorizations[0].Role =
					credentialauthorization.RoleOwner
			},
		},
		{
			name: "invalid binding",
			mutate: func(changes *Changes) {
				changes.CredentialAuthorizations[0].
					BindingSignature[0] ^= 0xff
			},
		},
		{
			name: "invalid endorsement",
			mutate: func(changes *Changes) {
				changes.CredentialAuthorizations[0].
					ClockEndorsements[0].Signature[0] ^= 0xff
			},
		},
		{
			name: "mixed domain change",
			mutate: func(changes *Changes) {
				member := device.Device{}
				changes.Devices = []device.Device{member}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			outcome := validCredentialOutcome(t, fixture)
			test.mutate(&outcome.Changes)

			beforeResult := fixture.state.currentResultIndex
			beforeChain := fixture.state.currentChainIndex
			beforeCounter := fixture.state.auditCounters[fixture.editorDevice]
			beforeScope := fixture.state.originScopes[OriginScopeKey{
				DeviceID: fixture.ownerDevice,
				Kind:     ScopeBoot,
				ScopeID:  testBootID,
			}]
			if err := fixture.state.Apply(outcome.Changes); err == nil {
				t.Fatal("State.Apply() accepted tampered credential changes")
			}
			if fixture.state.currentResultIndex != beforeResult ||
				fixture.state.currentChainIndex != beforeChain ||
				fixture.state.auditCounters[fixture.editorDevice] !=
					beforeCounter ||
				fixture.state.originScopes[beforeScope.OriginScopeKey] !=
					beforeScope ||
				len(fixture.state.credentialAuthorizations) != 0 {
				t.Fatal("failed credential apply mutated state")
			}
		})
	}
}

func TestCredentialApplyRejectsCounterEpochAdvanceWithoutAuthorization(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	counter := fixture.state.auditCounters[fixture.editorDevice]
	counter.CredentialEpoch = 1
	if err := fixture.state.Apply(Changes{
		AuditCounters: []auditcounter.Counter{counter},
	}); err == nil {
		t.Fatal("State.Apply() accepted an unbacked credential-epoch advance")
	}
	if fixture.state.auditCounters[fixture.editorDevice].CredentialEpoch != 0 ||
		fixture.state.currentChainIndex != 0 {
		t.Fatal("unbacked epoch advance mutated state")
	}
}

func TestNewStateValidatesCredentialAuthorizationHistory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Snapshot, credentialauthorization.Key)
		valid  bool
	}{
		{name: "valid", valid: true},
		{
			name: "map key mismatch",
			mutate: func(snapshot *Snapshot, key credentialauthorization.Key) {
				value := snapshot.CredentialAuthorizations[key]
				delete(snapshot.CredentialAuthorizations, key)
				key.Epoch = 2
				snapshot.CredentialAuthorizations[key] = value
			},
		},
		{
			name: "counter mismatch",
			mutate: func(snapshot *Snapshot, key credentialauthorization.Key) {
				counter := snapshot.AuditCounters[key.DeviceID]
				counter.CredentialEpoch = 0
				snapshot.AuditCounters[key.DeviceID] = counter
			},
		},
		{
			name: "future chain position",
			mutate: func(snapshot *Snapshot, key credentialauthorization.Key) {
				value := snapshot.CredentialAuthorizations[key]
				value.AuthorizationChainIndex = 2
				snapshot.CredentialAuthorizations[key] = value
			},
		},
		{
			name: "invalid binding",
			mutate: func(snapshot *Snapshot, key credentialauthorization.Key) {
				value := snapshot.CredentialAuthorizations[key]
				value.BindingSignature[0] ^= 0xff
				snapshot.CredentialAuthorizations[key] = value
			},
		},
		{
			name: "invalid historical endorsement",
			mutate: func(snapshot *Snapshot, key credentialauthorization.Key) {
				value := snapshot.CredentialAuthorizations[key]
				value.ClockEndorsements[0].Signature[0] ^= 0xff
				snapshot.CredentialAuthorizations[key] = value
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			outcome := validCredentialOutcome(t, fixture)
			value := outcome.Changes.CredentialAuthorizations[0].Clone()
			key := value.PrimaryKey()
			snapshot := snapshotFromState(fixture.state)
			snapshot.CurrentChainIndex = 1
			snapshot.CredentialAuthorizations[key] = value
			snapshot.AuditCounters[value.DeviceID] =
				outcome.Changes.AuditCounters[0]
			if test.mutate != nil {
				test.mutate(&snapshot, key)
			}

			state, err := NewState(snapshot)
			if test.valid {
				if err != nil {
					t.Fatalf("NewState() error = %v", err)
				}
				stored := state.credentialAuthorizations[key]
				value.ClockEndorsements[0].Signature[0] ^= 0xff
				if stored.ClockEndorsements[0].Signature ==
					value.ClockEndorsements[0].Signature {
					t.Fatal("snapshot authorization was not deep-copied")
				}
				return
			}
			if err == nil {
				t.Fatal("NewState() accepted malformed credential history")
			}
		})
	}
}

func TestNewStateRetainsCredentialEpochsAcrossRecoverySessions(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	currentOutcome := validCredentialOutcome(t, fixture)
	current := currentOutcome.Changes.CredentialAuthorizations[0].Clone()
	current.AuthorizationChainIndex = 2

	predecessorFixture := fixture
	predecessorFixture.state.sessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000099",
	)
	predecessorFixture.state.currentChainIndex = 0
	predecessorOptions := defaultCredentialPayloadOptions(predecessorFixture)
	predecessorOptions.keySeed = 0x71
	_, predecessor := credentialPayload(
		t,
		predecessorFixture,
		predecessorOptions,
	)

	snapshot := snapshotFromState(fixture.state)
	snapshot.CurrentChainIndex = 2
	snapshot.CurrentResultIndex = 2
	snapshot.CredentialAuthorizations[predecessor.PrimaryKey()] =
		predecessor
	snapshot.CredentialAuthorizations[current.PrimaryKey()] = current
	snapshot.AuditCounters[current.DeviceID] =
		currentOutcome.Changes.AuditCounters[0]

	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	if len(state.credentialAuthorizations) != 2 {
		t.Fatalf(
			"retained credential count = %d, want 2",
			len(state.credentialAuthorizations),
		)
	}
	if _, exists := state.credentialAuthorizations[predecessor.PrimaryKey()]; !exists {
		t.Fatal("predecessor credential was not retained")
	}
	if _, exists := state.credentialAuthorizations[current.PrimaryKey()]; !exists {
		t.Fatal("current credential was not retained")
	}

	fixture.state = state
	successorOptions := defaultCredentialPayloadOptions(fixture)
	successorOptions.keySeed = 0x72
	successorOptions.issuedAt = "2024-01-01T00:25:00Z"
	successorOptions.notBefore = "2024-01-01T00:28:00Z"
	successorPayload, _ := credentialPayload(
		t,
		fixture,
		successorOptions,
	)
	successor := buildCredentialProposal(
		t,
		fixture,
		fixture.ownerDevice,
		fixture.editorDevice,
		2,
		successorPayload,
	)
	successorOutcome, err := Reduce(fixture.state, successor)
	if err != nil || !successorOutcome.Accepted() {
		t.Fatalf(
			"successor credential selected wrong session history: %#v, %v",
			successorOutcome,
			err,
		)
	}
}

func validCredentialOutcome(
	t *testing.T,
	fixture reducerFixture,
) Outcome {
	t.Helper()
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
		t.Fatalf("credential outcome = %#v", outcome)
	}
	return outcome
}
