package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestConflictDetectionRejectsStaleCanonicalTip(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	value := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	fixture.state.canonicalRef.CommitOID = testReducerGitOID(50)
	fixture.state.canonicalRef.EntityVersion++
	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorDaemon,
		fixture.editorDevice,
		"",
		event.KindWorkspaceConflictDetected,
		string(value.ID),
		0,
		mustRawJSON(t, conflictDetectionPayload(value)),
		domainEventID(92),
		2,
	)

	assertRejectedCode(
		t,
		fixture.state,
		signed,
		CodeConflictCanonicalCommitMismatch,
	)
}

func TestConflictExactRedetectionIgnoresLaterTerminalAndCanonicalState(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	value := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	candidate.State = publication.StateWithdrawn
	candidate.TerminalSource = publication.TerminalSourceWithdraw
	candidate.EntityVersion++
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	fixture.state.mergeConflicts[value.ID] = value
	fixture.state.canonicalRef.CommitOID = testReducerGitOID(51)
	fixture.state.canonicalRef.EntityVersion++
	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorDaemon,
		fixture.editorDevice,
		"",
		event.KindWorkspaceConflictDetected,
		string(value.ID),
		0,
		mustRawJSON(t, conflictDetectionPayload(value)),
		domainEventID(93),
		2,
	)

	outcome := assertAccepted(t, fixture.state, signed)
	if len(outcome.Changes.MergeConflicts) != 0 {
		t.Fatalf("exact redetection rewrote conflict: %#v", outcome)
	}
}

func TestConflictMismatchesReturnDeterministicAlarms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(map[string]any)
		wantCode  Code
		wantClass AlarmClass
	}{
		{
			name: "immutable tuple",
			mutate: func(payload map[string]any) {
				payload["canonical_commit"] = testReducerGitOID(52)
			},
			wantCode:  CodeConflictImmutableTupleMismatch,
			wantClass: AlarmConflictIntegrity,
		},
		{
			name: "detector paths",
			mutate: func(payload map[string]any) {
				payload["paths"] = []string{"src/other.go"}
			},
			wantCode:  CodeConflictDetectorPathsMismatch,
			wantClass: AlarmConflictDetectorCompatibility,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			candidate := testProposedPublication(
				t,
				fixture,
				testPublicationID,
				testPublicationEventID,
				"",
			)
			value := testConflictForPublication(
				t,
				fixture,
				candidate,
				fixture.state.canonicalRef.CommitOID,
			)
			fixture.state.publications[candidate.Metadata.PublicationID] =
				candidate
			fixture.state.mergeConflicts[value.ID] = value
			payload := conflictDetectionPayload(value)
			test.mutate(payload)
			signed := buildRepositoryProposal(
				t,
				fixture,
				event.ActorDaemon,
				fixture.editorDevice,
				"",
				event.KindWorkspaceConflictDetected,
				string(value.ID),
				0,
				mustRawJSON(t, payload),
				domainEventID(94),
				2,
			)

			outcome, err := Reduce(fixture.state, signed)
			if err != nil {
				t.Fatalf("Reduce() error = %v", err)
			}
			if outcome.Code != test.wantCode ||
				outcome.Alarm == nil ||
				outcome.Alarm.Class != test.wantClass ||
				outcome.Alarm.Subject != "conflict:"+string(value.ID) {
				t.Fatalf("outcome = %#v", outcome)
			}
		})
	}
}

func TestConflictResolutionUsesAppliedPublicationAsHistoricalStagingProof(
	t *testing.T,
) {
	t.Parallel()

	fixture, conflictValue, resolution := resolvedConflictFixture(t)
	fixture.state.currentResultIndex =
		publicationReceiptWindow + resolution.StagingReceipts[0].StagedResultIndex + 1
	nextTarget, err := voterset.New(
		fixture.state.sessionID,
		[]domain.DeviceID{
			fixture.ownerDevice,
			fixture.editorDevice,
			fixture.targetDevice,
		},
		fixture.state.voterSet.VoterSetVersion+1,
	)
	if err != nil {
		t.Fatalf("voterset.New() error = %v", err)
	}
	fixture.state.voterSet = nextTarget
	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindWorkspaceConflictResolved,
		string(conflictValue.ID),
		conflictValue.EntityVersion,
		mustRawJSON(t, map[string]any{
			"resolution_publication_id": resolution.Metadata.PublicationID,
		}),
		domainEventID(95),
		2,
	)

	outcome := assertAccepted(t, fixture.state, signed)
	if got := outcome.Changes.MergeConflicts[0]; got.Status != conflict.StatusResolved {
		t.Fatalf("resolved conflict = %#v", got)
	}
}
