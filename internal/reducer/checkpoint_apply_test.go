package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/event"
)

func TestValidateCheckpointAtApplyClassifiesStaleAndDivergentState(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	payload, _ := signedCheckpointProofPayload(
		t,
		fixture,
		fixture.ownerDevice,
		nil,
	)
	directive, ok := decodeCheckpointProof(fixture.state, payload)
	if !ok {
		t.Fatal("decodeCheckpointProof() rejected valid proof")
	}
	context := checkpointApplyContext(directive)
	if code, err := validateCheckpointAtApply(directive, context); code != "" ||
		err != nil {
		t.Fatalf("validateCheckpointAtApply() = (%q, %v)", code, err)
	}

	staleTests := []struct {
		name   string
		mutate func(*CheckpointApplyContext)
	}{
		{
			name: "term",
			mutate: func(value *CheckpointApplyContext) {
				value.Term++
			},
		},
		{
			name: "log position",
			mutate: func(value *CheckpointApplyContext) {
				value.LogIndex++
			},
		},
	}
	for _, test := range staleTests {
		test := test
		t.Run("stale "+test.name, func(t *testing.T) {
			t.Parallel()
			value := context
			test.mutate(&value)
			code, err := validateCheckpointAtApply(directive, value)
			if code != CodeStaleCheckpoint || err != nil {
				t.Fatalf(
					"validateCheckpointAtApply() = (%q, %v), want stale",
					code,
					err,
				)
			}
		})
	}

	divergenceTests := []struct {
		name   string
		mutate func(*CheckpointApplyContext)
	}{
		{
			name: "chain index",
			mutate: func(value *CheckpointApplyContext) {
				value.ChainIndex--
			},
		},
		{
			name: "chain hash",
			mutate: func(value *CheckpointApplyContext) {
				value.ChainHash[0] ^= 0xff
			},
		},
		{
			name: "result index",
			mutate: func(value *CheckpointApplyContext) {
				value.ResultIndex++
			},
		},
		{
			name: "result hash",
			mutate: func(value *CheckpointApplyContext) {
				value.ResultHash[0] ^= 0xff
			},
		},
		{
			name: "projection accumulator",
			mutate: func(value *CheckpointApplyContext) {
				value.ProjectionAccumulator[0] ^= 0xff
			},
		},
	}
	for _, test := range divergenceTests {
		test := test
		t.Run("divergent "+test.name, func(t *testing.T) {
			t.Parallel()
			value := context
			test.mutate(&value)
			code, err := validateCheckpointAtApply(directive, value)
			if code != "" ||
				!errors.Is(err, ErrCheckpointIntegrityMismatch) {
				t.Fatalf(
					"validateCheckpointAtApply() = (%q, %v), want integrity halt",
					code,
					err,
				)
			}
		})
	}
}

func TestValidateCheckpointAtApplyRejectsInvalidLocalContext(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	payload, _ := signedCheckpointProofPayload(
		t,
		fixture,
		fixture.ownerDevice,
		nil,
	)
	directive, ok := decodeCheckpointProof(fixture.state, payload)
	if !ok {
		t.Fatal("decodeCheckpointProof() rejected valid proof")
	}
	context := checkpointApplyContext(directive)
	context.LogIndex = 1

	code, err := validateCheckpointAtApply(directive, context)
	if code != "" || !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf(
			"validateCheckpointAtApply() = (%q, %v), want invalid state",
			code,
			err,
		)
	}
}

func TestCheckpointDispatchAppliesAndClassifiesStaleContext(t *testing.T) {
	t.Parallel()

	t.Run("accepted", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		payload, _ := signedCheckpointProofPayload(
			t,
			fixture,
			fixture.ownerDevice,
			nil,
		)
		directive, ok := decodeCheckpointProof(fixture.state, payload)
		if !ok {
			t.Fatal("decodeCheckpointProof() rejected valid proof")
		}
		applyContext := checkpointApplyContext(directive)
		fixture.state.currentChainIndex = applyContext.ChainIndex
		fixture.state.currentResultIndex = applyContext.ResultIndex
		signed := signedCheckpointEvent(t, fixture, payload)

		outcome, err := ReduceCheckpoint(
			fixture.state,
			signed,
			applyContext,
		)
		if err != nil {
			t.Fatalf("ReduceCheckpoint() error = %v", err)
		}
		if !outcome.Accepted() ||
			!outcome.Changes.AdvancesEventChain ||
			outcome.Checkpoint == nil ||
			outcome.RecordActivity {
			t.Fatalf("outcome = %#v", outcome)
		}
		if _, err := Reduce(fixture.state, signed); !errors.Is(
			err,
			ErrCheckpointApplyContextRequired,
		) {
			t.Fatalf("Reduce() error = %v, want checkpoint context", err)
		}
		if err := fixture.state.Apply(outcome.Changes); err != nil {
			t.Fatalf("State.Apply() error = %v", err)
		}
		if fixture.state.currentChainIndex != applyContext.ChainIndex+1 ||
			fixture.state.currentResultIndex != applyContext.ResultIndex+1 {
			t.Fatalf(
				"applied heads = (%d, %d)",
				fixture.state.currentChainIndex,
				fixture.state.currentResultIndex,
			)
		}
	})

	t.Run("stale", func(t *testing.T) {
		t.Parallel()

		fixture := newReducerFixture(t)
		payload, _ := signedCheckpointProofPayload(
			t,
			fixture,
			fixture.ownerDevice,
			nil,
		)
		directive, ok := decodeCheckpointProof(fixture.state, payload)
		if !ok {
			t.Fatal("decodeCheckpointProof() rejected valid proof")
		}
		applyContext := checkpointApplyContext(directive)
		fixture.state.currentChainIndex = applyContext.ChainIndex
		fixture.state.currentResultIndex = applyContext.ResultIndex
		applyContext.Term++
		signed := signedCheckpointEvent(t, fixture, payload)

		outcome, err := ReduceCheckpoint(
			fixture.state,
			signed,
			applyContext,
		)
		if err != nil {
			t.Fatalf("ReduceCheckpoint() error = %v", err)
		}
		if outcome.Accepted() ||
			outcome.Code != CodeStaleCheckpoint ||
			outcome.Checkpoint != nil ||
			outcome.Changes.AdvancesEventChain {
			t.Fatalf("outcome = %#v", outcome)
		}
		if err := fixture.state.Apply(outcome.Changes); err != nil {
			t.Fatalf("State.Apply() error = %v", err)
		}
		if fixture.state.currentChainIndex != directive.Checkpoint.CoveredChainIndex ||
			fixture.state.currentResultIndex !=
				directive.Checkpoint.CoveredResultIndex+1 {
			t.Fatalf(
				"applied heads = (%d, %d)",
				fixture.state.currentChainIndex,
				fixture.state.currentResultIndex,
			)
		}
	})
}

func TestCheckpointDispatchHaltsBeforePersistenceOnHeadDivergence(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	payload, _ := signedCheckpointProofPayload(
		t,
		fixture,
		fixture.ownerDevice,
		nil,
	)
	directive, ok := decodeCheckpointProof(fixture.state, payload)
	if !ok {
		t.Fatal("decodeCheckpointProof() rejected valid proof")
	}
	applyContext := checkpointApplyContext(directive)
	fixture.state.currentChainIndex = applyContext.ChainIndex
	fixture.state.currentResultIndex = applyContext.ResultIndex
	applyContext.ProjectionAccumulator[0] ^= 0xff
	signed := signedCheckpointEvent(t, fixture, payload)

	outcome, err := ReduceCheckpoint(fixture.state, signed, applyContext)
	if !errors.Is(err, ErrCheckpointIntegrityMismatch) {
		t.Fatalf("ReduceCheckpoint() error = %v, want integrity halt", err)
	}
	if outcome.Status != "" ||
		fixture.state.currentChainIndex != directive.Checkpoint.CoveredChainIndex ||
		fixture.state.currentResultIndex != directive.Checkpoint.CoveredResultIndex {
		t.Fatalf("checkpoint divergence changed state or returned outcome: %#v", outcome)
	}
}

func signedCheckpointEvent(
	t *testing.T,
	fixture reducerFixture,
	payload []byte,
) event.SignedEvent {
	t.Helper()

	authority, err := event.NewLocalAuthority(
		fixture.ownerDevice,
		testBootID,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority() error = %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding() error = %v", err)
	}
	proposal, err := event.BuildProposal(event.Command{
		Kind:     event.KindConsensusCheckpoint,
		EntityID: event.NullEntityID(),
		Actions:  []event.Action{},
		Payload:  payload,
		Redaction: event.Redaction{
			Policy:        event.RedactionDefault,
			FieldsRemoved: []event.RedactionField{},
		},
	}, binding, event.BuildContext{
		EventID:        domainEventID(170),
		SessionID:      fixture.state.sessionID,
		WorkspaceID:    fixture.state.workspaceID,
		CreatedAt:      testTimestamp,
		OriginSequence: 2,
	})
	if err != nil {
		t.Fatalf("event.BuildProposal() error = %v", err)
	}
	signed, err := event.Sign(
		proposal,
		fixture.privateKeys[fixture.ownerDevice],
	)
	if err != nil {
		t.Fatalf("event.Sign() error = %v", err)
	}
	return signed
}

func checkpointApplyContext(
	directive CheckpointDirective,
) CheckpointApplyContext {
	checkpoint := directive.Checkpoint
	return CheckpointApplyContext{
		Term:                    checkpoint.Term,
		LogIndex:                checkpoint.CoveredAppliedLogIndex + 1,
		ChainIndex:              checkpoint.CoveredChainIndex,
		ChainHash:               checkpoint.CoveredChainHash,
		ResultIndex:             checkpoint.CoveredResultIndex,
		ResultHash:              checkpoint.CoveredResultHash,
		ProjectionAccumulator:   checkpoint.ProjectionAccumulator,
		DigestVersion:           checkpoint.DigestVersion,
		ProjectionSchemaVersion: checkpoint.ProjectionSchemaVersion,
	}
}
