package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPublicationReducersAcceptLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("propose", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		addPublicationLease(t, &fixture)
		heldTask := taskForReducerState(fixture, task.StateInProgress, 2)
		fixture.state.tasks[testTaskID] = heldTask
		metadata := testPublicationMetadata(
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
			fixture.state.canonicalRef.CommitOID,
			testReducerGitOID(20),
			testReducerGitOID(21),
		)
		receipts := signedStagingReceipts(
			t,
			fixture,
			metadata,
			fixture.state.currentResultIndex,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			event.KindPublicationProposed,
			string(testPublicationID),
			0,
			publicationPayload(t, metadata, receipts),
			testPublicationEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		if len(outcome.Changes.Publications) != 1 ||
			len(outcome.Changes.CanonicalRefs) != 0 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("outcome = %#v", outcome)
		}
		got := outcome.Changes.Publications[0]
		if !got.Metadata.Equal(metadata) ||
			got.State != publication.StateProposed ||
			got.EntityVersion != 1 ||
			len(got.StagingReceipts) != 1 {
			t.Fatalf("proposed publication = %#v", got)
		}
	})

	t.Run("cross-device agent approves", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		addReviewerAgent(t, &fixture)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
		)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
		fixture.state.publications[testPublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.targetDevice,
			testReviewerAgentID,
			event.KindPublicationReviewed,
			string(testPublicationID),
			1,
			mustRawJSON(t, map[string]any{"verdict": "approve"}),
			testResolutionEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		got := outcome.Changes.Publications[0]
		if got.State != publication.StateApproved ||
			got.ReviewVerdict != publication.ReviewVerdictApprove ||
			got.ReviewerDeviceID != fixture.targetDevice ||
			got.ReviewerAgentSessionID != testReviewerAgentID ||
			got.ReviewActorType != publication.ReviewActorAgent ||
			got.EntityVersion != 2 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("approved publication = %#v, outcome = %#v", got, outcome)
		}
	})

	t.Run("same-device human approves", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		fixture.state.publications[testPublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindPublicationReviewed,
			string(testPublicationID),
			1,
			mustRawJSON(t, map[string]any{"verdict": "approve"}),
			testResolutionEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		got := outcome.Changes.Publications[0]
		if got.State != publication.StateApproved ||
			got.ReviewerDeviceID != fixture.editorDevice ||
			got.ReviewerAgentSessionID != "" ||
			got.ReviewActorType != publication.ReviewActorHuman {
			t.Fatalf("human-reviewed publication = %#v", got)
		}
	})

	t.Run("apply advances both CAS rows", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testApprovedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
		)
		fixture.state.tasks[testTaskID] = testTask(task.StateDone, 1)
		fixture.state.publications[testPublicationID] = current
		receipts := signedStagingReceipts(
			t,
			fixture,
			current.Metadata,
			fixture.state.currentResultIndex,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			event.KindPublicationApplied,
			string(testPublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{
				"expected_canonical_ref_version": fixture.state.canonicalRef.EntityVersion,
				"staging_receipts":               stagingReceiptPayloads(receipts),
			}),
			testResolutionEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		if len(outcome.Changes.Publications) != 1 ||
			len(outcome.Changes.CanonicalRefs) != 1 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("outcome = %#v", outcome)
		}
		got := outcome.Changes.Publications[0]
		ref := outcome.Changes.CanonicalRefs[0]
		if got.State != publication.StateApplied ||
			got.TerminalSource != publication.TerminalSourceApply ||
			!got.CanonicalLineageMember ||
			got.EntityVersion != current.EntityVersion+1 ||
			ref.CommitOID != current.Metadata.CommitOID ||
			ref.EntityVersion != fixture.state.canonicalRef.EntityVersion+1 {
			t.Fatalf("applied publication = %#v, ref = %#v", got, ref)
		}
	})

	t.Run("author withdraws with reason", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		current := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
		)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
		fixture.state.publications[testPublicationID] = current
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.editorDevice,
			testAgentSessionID,
			event.KindPublicationWithdrawn,
			string(testPublicationID),
			current.EntityVersion,
			mustRawJSON(t, map[string]any{"reason": "superseded"}),
			testResolutionEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		got := outcome.Changes.Publications[0]
		if got.State != publication.StateWithdrawn ||
			got.TerminalSource != publication.TerminalSourceWithdraw ||
			got.DecisionReason == nil ||
			*got.DecisionReason != "superseded" ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("withdrawn publication = %#v, outcome = %#v", got, outcome)
		}
	})
}
