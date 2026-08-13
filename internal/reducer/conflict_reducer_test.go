package reducer

import (
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestConflictReducersAcceptLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("detect", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
		candidate := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
		)
		fixture.state.publications[testPublicationID] = candidate
		value := testConflictForPublication(
			t,
			fixture,
			candidate,
			fixture.state.canonicalRef.CommitOID,
		)
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
			testResolutionEventID,
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		if len(outcome.Changes.MergeConflicts) != 1 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("outcome = %#v", outcome)
		}
		got := outcome.Changes.MergeConflicts[0]
		if got.ID != value.ID ||
			got.Status != conflict.StatusUnresolved ||
			got.EntityVersion != 1 {
			t.Fatalf("detected conflict = %#v", got)
		}
		if err := fixture.state.Apply(outcome.Changes); err != nil {
			t.Fatalf("State.Apply() error = %v", err)
		}
		if fixture.state.unresolvedConflictsByTask[testTaskID] != 1 {
			t.Fatalf(
				"unresolved task count = %d, want 1",
				fixture.state.unresolvedConflictsByTask[testTaskID],
			)
		}
	})

	t.Run("publication resolution", func(t *testing.T) {
		t.Parallel()
		fixture, conflictValue, resolution := resolvedConflictFixture(t)
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
			domainEventID(90),
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		got := outcome.Changes.MergeConflicts[0]
		if got.Status != conflict.StatusResolved ||
			got.ResolutionKind != conflict.ResolutionKindPublication ||
			got.ResolutionPublicationID != resolution.Metadata.PublicationID ||
			got.ResolvedByDeviceID != fixture.editorDevice ||
			got.EntityVersion != conflictValue.EntityVersion+1 ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("resolved conflict = %#v, outcome = %#v", got, outcome)
		}
	})

	t.Run("owner force resolution", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
		candidate := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			testTaskID,
		)
		conflictValue := testConflictForPublication(
			t,
			fixture,
			candidate,
			fixture.state.canonicalRef.CommitOID,
		)
		fixture.state.publications[candidate.Metadata.PublicationID] = candidate
		fixture.state.mergeConflicts[conflictValue.ID] = conflictValue
		fixture.state.unresolvedConflictsByTask[testTaskID] = 1
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.ownerDevice,
			"",
			event.KindWorkspaceConflictForceResolved,
			string(conflictValue.ID),
			conflictValue.EntityVersion,
			mustRawJSON(t, map[string]any{"reason": "artifact unavailable"}),
			domainEventID(91),
			2,
		)

		outcome := assertAccepted(t, fixture.state, signed)
		got := outcome.Changes.MergeConflicts[0]
		if got.Status != conflict.StatusResolved ||
			got.ResolutionKind != conflict.ResolutionKindForced ||
			got.ForceReason != "artifact unavailable" ||
			got.ResolvedByDeviceID != fixture.ownerDevice ||
			outcome.Audit == nil ||
			outcome.Audit.Class != AuditOperatorOverride ||
			outcome.ActivityTaskID != testTaskID {
			t.Fatalf("force-resolved conflict = %#v, outcome = %#v", got, outcome)
		}
	})
}

func TestResolvingOneOfTwoTaskConflictsKeepsTaskBlocked(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		testTaskID,
	)
	first := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	second := cloneConflict(first)
	second.MergeKind = conflict.MergeKindRebase
	second.ReplayCommitOID = testReducerGitOID(32)
	rederiveConflictID(t, fixture, &second)
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	fixture.state.mergeConflicts[first.ID] = first
	fixture.state.mergeConflicts[second.ID] = second
	fixture.state.unresolvedConflictsByTask[testTaskID] = 2

	signed := buildRepositoryProposal(
		t,
		fixture,
		event.ActorHuman,
		fixture.ownerDevice,
		"",
		event.KindWorkspaceConflictForceResolved,
		string(first.ID),
		first.EntityVersion,
		mustRawJSON(t, map[string]any{"reason": "operator selected replacement"}),
		domainEventID(122),
		2,
	)
	outcome := assertAccepted(t, fixture.state, signed)
	if err := fixture.state.Apply(outcome.Changes); err != nil {
		t.Fatalf("State.Apply() error = %v", err)
	}
	if got := fixture.state.unresolvedConflictsByTask[testTaskID]; got != 1 {
		t.Fatalf("unresolved task count = %d, want 1", got)
	}
	if got := fixture.state.mergeConflicts[second.ID]; got.Status != conflict.StatusUnresolved {
		t.Fatalf("second conflict status = %q, want unresolved", got.Status)
	}
}

func resolvedConflictFixture(
	t *testing.T,
) (reducerFixture, conflict.Conflict, publication.Publication) {
	t.Helper()
	fixture := newReducerFixture(t)
	fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		testTaskID,
	)
	conflictValue := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	metadata := testPublicationMetadata(
		fixture,
		testResolutionPublicationID,
		testResolutionEventID,
		testTaskID,
		fixture.state.canonicalRef.CommitOID,
		testReducerGitOID(30),
		testReducerGitOID(31),
		conflictValue.ID,
	)
	resolution := publication.Publication{
		Metadata: metadata,
		StagingReceipts: signedStagingReceipts(
			t,
			fixture,
			metadata,
			fixture.state.currentResultIndex,
		),
		State:                  publication.StateApplied,
		TerminalSource:         publication.TerminalSourceApply,
		CanonicalLineageMember: true,
		ReviewVerdict:          publication.ReviewVerdictApprove,
		ReviewerDeviceID:       fixture.ownerDevice,
		ReviewActorType:        publication.ReviewActorHuman,
		EntityVersion:          3,
	}
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	fixture.state.publications[resolution.Metadata.PublicationID] = resolution
	fixture.state.mergeConflicts[conflictValue.ID] = conflictValue
	fixture.state.unresolvedConflictsByTask[testTaskID] = 1
	fixture.state.canonicalRef.CommitOID = resolution.Metadata.CommitOID
	fixture.state.canonicalRef.EntityVersion++
	return fixture, conflictValue, resolution
}
