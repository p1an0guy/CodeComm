package reducer

import (
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/publication"
)

func TestNewStateAcceptsPublicationBackedConflictResolution(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	conflictValue := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	resolutionMetadata := testPublicationMetadata(
		fixture,
		testResolutionPublicationID,
		testResolutionEventID,
		"",
		fixture.state.canonicalRef.CommitOID,
		testReducerGitOID(30),
		testReducerGitOID(31),
		conflictValue.ID,
	)
	resolution := publication.Publication{
		Metadata: resolutionMetadata,
		StagingReceipts: signedStagingReceipts(
			t,
			fixture,
			resolutionMetadata,
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
	conflictValue.Status = conflict.StatusResolved
	conflictValue.ResolutionKind = conflict.ResolutionKindPublication
	conflictValue.ResolutionPublicationID = resolution.Metadata.PublicationID
	conflictValue.ResolvedByDeviceID = fixture.editorDevice
	conflictValue.EntityVersion = 2

	snapshot := snapshotFromState(fixture.state)
	snapshot.CanonicalRef.CommitOID = resolution.Metadata.CommitOID
	snapshot.CanonicalRef.EntityVersion++
	snapshot.Publications[candidate.Metadata.PublicationID] = candidate
	snapshot.Publications[resolution.Metadata.PublicationID] = resolution
	snapshot.MergeConflicts[conflictValue.ID] = conflictValue

	if _, err := NewState(snapshot); err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
}

func TestNewStateRejectsConflictIDThatDoesNotMatchImmutableTuple(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	conflictValue := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	conflictValue.ID = domain.ConflictID("ccf1" + strings.Repeat("f", 64))

	snapshot := snapshotFromState(fixture.state)
	snapshot.Publications[candidate.Metadata.PublicationID] = candidate
	snapshot.MergeConflicts[conflictValue.ID] = conflictValue

	if _, err := NewState(snapshot); !errors.Is(
		err,
		ErrInvalidCommittedState,
	) {
		t.Fatalf("NewState() error = %v, want invalid committed state", err)
	}
}

func TestStateApplyRejectsDuplicatePublicationProposalEventAtomically(
	t *testing.T,
) {
	t.Parallel()

	fixture := newReducerFixture(t)
	existing := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	fixture.state.publications[existing.Metadata.PublicationID] = existing
	duplicate := testProposedPublication(
		t,
		fixture,
		testResolutionPublicationID,
		testResolutionEventID,
		"",
	)
	duplicate.Metadata.ProposalEventID = existing.Metadata.ProposalEventID
	duplicate.StagingReceipts = signedStagingReceipts(
		t,
		fixture,
		duplicate.Metadata,
		fixture.state.currentResultIndex,
	)
	beforeIndex := fixture.state.currentResultIndex

	err := fixture.state.Apply(Changes{
		Publications: []publication.Publication{duplicate},
	})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid committed state", err)
	}
	if fixture.state.currentResultIndex != beforeIndex {
		t.Fatalf(
			"failed apply advanced result index: got %d, want %d",
			fixture.state.currentResultIndex,
			beforeIndex,
		)
	}
	if _, exists := fixture.state.publications[duplicate.Metadata.PublicationID]; exists {
		t.Fatal("failed apply inserted duplicate-event publication")
	}
}

func TestStateApplyRejectsConflictRedetectionAsProjectionMutation(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	candidate := testProposedPublication(
		t,
		fixture,
		testPublicationID,
		testPublicationEventID,
		"",
	)
	conflictValue := testConflictForPublication(
		t,
		fixture,
		candidate,
		fixture.state.canonicalRef.CommitOID,
	)
	fixture.state.publications[candidate.Metadata.PublicationID] = candidate
	fixture.state.mergeConflicts[conflictValue.ID] = conflictValue
	beforeIndex := fixture.state.currentResultIndex

	err := fixture.state.Apply(Changes{
		MergeConflicts: []conflict.Conflict{cloneConflict(conflictValue)},
	})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("State.Apply() error = %v, want invalid committed state", err)
	}
	if fixture.state.currentResultIndex != beforeIndex {
		t.Fatalf(
			"failed apply advanced result index: got %d, want %d",
			fixture.state.currentResultIndex,
			beforeIndex,
		)
	}
}
