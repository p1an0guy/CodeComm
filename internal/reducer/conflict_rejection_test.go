package reducer

import (
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestConflictDetectionRejectionMatrix(t *testing.T) {
	t.Parallel()

	t.Run("conflict ID mismatch", func(t *testing.T) {
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
		value.ID = domain.ConflictID("ccf1" + strings.Repeat("f", 64))
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
			domainEventID(110),
			2,
		)

		outcome, err := Reduce(fixture.state, signed)
		if err != nil {
			t.Fatalf("Reduce() error = %v", err)
		}
		if outcome.Code != CodeConflictIDMismatch ||
			outcome.Alarm == nil ||
			outcome.Alarm.Class != AlarmConflictIntegrity {
			t.Fatalf("outcome = %#v", outcome)
		}
	})

	t.Run("publication absent", func(t *testing.T) {
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
			domainEventID(111),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictPublicationNotFound,
		)
	})

	t.Run("publication terminal", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		candidate := testProposedPublication(
			t,
			fixture,
			testPublicationID,
			testPublicationEventID,
			"",
		)
		candidate.State = publication.StateWithdrawn
		candidate.TerminalSource = publication.TerminalSourceWithdraw
		candidate.EntityVersion++
		fixture.state.publications[candidate.Metadata.PublicationID] = candidate
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
			domainEventID(112),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictPublicationTerminal,
		)
	})

	t.Run("candidate commit differs from publication", func(t *testing.T) {
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
		value.CandidateCommit = testReducerGitOID(70)
		rederiveConflictID(t, fixture, &value)
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
			domainEventID(113),
			2,
		)

		assertRejectedCode(t, fixture.state, signed, CodeInvalidPayload)
	})
}

func TestConflictResolutionRejectionMatrix(t *testing.T) {
	t.Parallel()

	t.Run("resolution publication absent", func(t *testing.T) {
		t.Parallel()
		fixture, value, _ := unresolvedConflictFixture(t)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindWorkspaceConflictResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{
				"resolution_publication_id": testResolutionPublicationID,
			}),
			domainEventID(114),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictResolutionNotFound,
		)
	})

	t.Run("resolution publication not applied", func(t *testing.T) {
		t.Parallel()
		fixture, value, _ := unresolvedConflictFixture(t)
		resolution := testProposedPublication(
			t,
			fixture,
			testResolutionPublicationID,
			testResolutionEventID,
			"",
		)
		fixture.state.publications[resolution.Metadata.PublicationID] =
			resolution
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindWorkspaceConflictResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{
				"resolution_publication_id": resolution.Metadata.PublicationID,
			}),
			domainEventID(115),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictResolutionNotApplied,
		)
	})

	t.Run("resolution declaration absent", func(t *testing.T) {
		t.Parallel()
		fixture, value, _ := unresolvedConflictFixture(t)
		resolution := testApprovedPublication(
			t,
			fixture,
			testResolutionPublicationID,
			testResolutionEventID,
			"",
		)
		resolution.State = publication.StateApplied
		resolution.TerminalSource = publication.TerminalSourceApply
		resolution.CanonicalLineageMember = true
		resolution.EntityVersion++
		fixture.state.publications[resolution.Metadata.PublicationID] =
			resolution
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindWorkspaceConflictResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{
				"resolution_publication_id": resolution.Metadata.PublicationID,
			}),
			domainEventID(116),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictResolutionNotDeclared,
		)
	})

	t.Run("agent did not author resolution", func(t *testing.T) {
		t.Parallel()
		fixture, value, resolution := resolvedConflictFixture(t)
		addReviewerAgent(t, &fixture)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorAgent,
			fixture.targetDevice,
			testReviewerAgentID,
			event.KindWorkspaceConflictResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{
				"resolution_publication_id": resolution.Metadata.PublicationID,
			}),
			domainEventID(117),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeConflictResolutionAuthorMismatch,
		)
	})

	t.Run("resolved conflict is terminal", func(t *testing.T) {
		t.Parallel()
		fixture, value, resolution := resolvedConflictFixture(t)
		value.Status = conflict.StatusResolved
		value.ResolutionKind = conflict.ResolutionKindPublication
		value.ResolutionPublicationID = resolution.Metadata.PublicationID
		value.ResolvedByDeviceID = fixture.editorDevice
		value.EntityVersion++
		fixture.state.mergeConflicts[value.ID] = value
		fixture.state.unresolvedConflictsByTask = make(
			map[domain.UUIDv7]uint64,
		)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.editorDevice,
			"",
			event.KindWorkspaceConflictResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{
				"resolution_publication_id": resolution.Metadata.PublicationID,
			}),
			domainEventID(118),
			2,
		)

		assertRejectedCode(
			t,
			fixture.state,
			signed,
			CodeInvalidConflictTransition,
		)
	})

	t.Run("force reason empty", func(t *testing.T) {
		t.Parallel()
		fixture, value, _ := unresolvedConflictFixture(t)
		signed := buildRepositoryProposal(
			t,
			fixture,
			event.ActorHuman,
			fixture.ownerDevice,
			"",
			event.KindWorkspaceConflictForceResolved,
			string(value.ID),
			value.EntityVersion,
			mustRawJSON(t, map[string]any{"reason": ""}),
			domainEventID(119),
			2,
		)

		assertRejectedCode(t, fixture.state, signed, CodeInvalidPayload)
	})
}

func unresolvedConflictFixture(
	t *testing.T,
) (reducerFixture, conflict.Conflict, publication.Publication) {
	t.Helper()
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
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	fixture.state.mergeConflicts[value.ID] = value
	return fixture, value, candidate
}
