package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestPublicationProposalRejectsSupersessionOutsideLineage(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	addPublicationLease(t, &fixture)
	fixture.state.tasks[testTaskID] = taskForReducerState(
		fixture,
		task.StateInProgress,
		1,
	)
	otherTask := testTask(task.StateDone, 1)
	otherTask.ID = testOtherTaskID
	fixture.state.tasks[testOtherTaskID] = otherTask
	previous := testProposedPublication(
		t,
		fixture,
		testResolutionPublicationID,
		testResolutionEventID,
		testOtherTaskID,
	)
	previous.State = publication.StateWithdrawn
	previous.TerminalSource = publication.TerminalSourceWithdraw
	previous.EntityVersion = 2
	fixture.state.publications[previous.Metadata.PublicationID] = previous

	metadata := testPublicationMetadata(
		fixture,
		testPublicationID,
		testPublicationEventID,
		testTaskID,
		fixture.state.canonicalRef.CommitOID,
		testReducerGitOID(40),
		testReducerGitOID(41),
	)
	metadata.SupersedesPublicationID = previous.Metadata.PublicationID
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
		string(metadata.PublicationID),
		0,
		publicationPayload(t, metadata, receipts),
		metadata.ProposalEventID,
		2,
	)

	assertRejectedCode(
		t,
		fixture.state,
		signed,
		CodePublicationSupersedesLineageMismatch,
	)
}

func TestNewStateRejectsCyclicPublicationSupersession(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	first := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	second := testProposedPublication(
		t,
		fixture,
		testResolutionPublicationID,
		testResolutionEventID,
		"",
	)
	first.State = publication.StateWithdrawn
	first.TerminalSource = publication.TerminalSourceWithdraw
	first.EntityVersion = 2
	second.State = publication.StateWithdrawn
	second.TerminalSource = publication.TerminalSourceWithdraw
	second.EntityVersion = 2
	first.Metadata.SupersedesPublicationID = second.Metadata.PublicationID
	second.Metadata.SupersedesPublicationID = first.Metadata.PublicationID
	first.StagingReceipts = signedStagingReceipts(
		t,
		fixture,
		first.Metadata,
		fixture.state.currentResultIndex,
	)
	second.StagingReceipts = signedStagingReceipts(
		t,
		fixture,
		second.Metadata,
		fixture.state.currentResultIndex,
	)
	snapshot := snapshotFromState(fixture.state)
	snapshot.Publications[first.Metadata.PublicationID] = first
	snapshot.Publications[second.Metadata.PublicationID] = second

	if _, err := NewState(snapshot); !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("NewState() error = %v, want invalid committed state", err)
	}
}
