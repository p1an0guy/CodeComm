package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
)

func TestNewStateValidatesPlanAndMemoryReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, reducerFixture, *Snapshot)
	}{
		{
			name: "current plan has wrong session",
			mutate: func(
				_ *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanCurrent.SessionID = testPlanRevisionID
			},
		},
		{
			name: "current plan revision is missing",
			mutate: func(
				_ *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanCurrent.RevisionID = testPlanRevisionID
			},
		},
		{
			name: "unselected current plan advanced past version one",
			mutate: func(
				_ *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanCurrent.EntityVersion = 2
			},
		},
		{
			name: "plan task is missing",
			mutate: func(
				t *testing.T,
				fixture reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
					t,
					testPlanRevisionID,
					"",
					[]domain.UUIDv7{testTaskID},
					fixture.editorDevice,
				)
			},
		},
		{
			name: "plan predecessor is missing",
			mutate: func(
				t *testing.T,
				fixture reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
					t,
					testPlanRevisionID,
					testPriorPlanRevisionID,
					nil,
					fixture.editorDevice,
				)
			},
		},
		{
			name: "plan supersession cycle",
			mutate: func(
				t *testing.T,
				fixture reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
					t,
					testPlanRevisionID,
					testPriorPlanRevisionID,
					nil,
					fixture.editorDevice,
				)
				snapshot.PlanRevisions[testPriorPlanRevisionID] = mustPlanRevision(
					t,
					testPriorPlanRevisionID,
					testPlanRevisionID,
					nil,
					fixture.editorDevice,
				)
			},
		},
		{
			name: "memory task is missing",
			mutate: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeTask,
					testTaskID,
					"key",
					"",
					"",
				)
			},
		},
		{
			name: "memory predecessor is missing",
			mutate: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					testPriorMemoryID,
				)
			},
		},
		{
			name: "memory predecessor key differs",
			mutate: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
					t,
					testPriorMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					"",
				)
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeSession,
					"",
					"other",
					"",
					testPriorMemoryID,
				)
			},
		},
		{
			name: "memory predecessor has two successors",
			mutate: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
					t,
					testPriorMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					"",
				)
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"one",
					testPriorMemoryID,
				)
				snapshot.MemoryRecords[testMemorySuccessorID] = mustMemoryRecord(
					t,
					testMemorySuccessorID,
					memory.ScopeSession,
					"",
					"key",
					"two",
					testPriorMemoryID,
				)
			},
		},
		{
			name: "memory supersession cycle",
			mutate: func(
				t *testing.T,
				_ reducerFixture,
				snapshot *Snapshot,
			) {
				snapshot.MemoryRecords[testMemoryID] = mustMemoryRecord(
					t,
					testMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					testPriorMemoryID,
				)
				snapshot.MemoryRecords[testPriorMemoryID] = mustMemoryRecord(
					t,
					testPriorMemoryID,
					memory.ScopeSession,
					"",
					"key",
					"",
					testMemoryID,
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			test.mutate(t, fixture, &snapshot)
			if _, err := NewState(snapshot); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("NewState() error = %v", err)
			}
		})
	}
}

func TestStateApplyRejectsPlanMemoryChangesAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes func(*testing.T, reducerFixture) Changes
	}{
		{
			name: "plan references missing task",
			changes: func(t *testing.T, fixture reducerFixture) Changes {
				return Changes{
					PlanRevisions: []plan.Revision{mustPlanRevision(
						t,
						testPlanRevisionID,
						"",
						[]domain.UUIDv7{testTaskID},
						fixture.ownerDevice,
					)},
				}
			},
		},
		{
			name: "current plan references missing revision",
			changes: func(_ *testing.T, _ reducerFixture) Changes {
				return Changes{
					PlanCurrent: []plan.Current{{
						SessionID:     testSessionID,
						RevisionID:    testPlanRevisionID,
						EntityVersion: 2,
					}},
				}
			},
		},
		{
			name: "memory references missing predecessor",
			changes: func(t *testing.T, _ reducerFixture) Changes {
				return Changes{
					MemoryRecords: []memory.Record{mustMemoryRecord(
						t,
						testMemoryID,
						memory.ScopeSession,
						"",
						"key",
						"",
						testPriorMemoryID,
					)},
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			key := OriginScopeKey{
				DeviceID: fixture.ownerDevice,
				Kind:     ScopeBoot,
				ScopeID:  testBootID,
			}
			changes := test.changes(t, fixture)
			changes.OriginScopes = []OriginScope{{
				OriginScopeKey: key,
				LastSequence:   2,
			}}

			if err := fixture.state.Apply(changes); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("Apply() error = %v", err)
			}
			if fixture.state.originScopes[key].LastSequence != 1 ||
				len(fixture.state.planRevisions) != 0 ||
				fixture.state.planCurrent.RevisionID != "" ||
				fixture.state.planCurrent.EntityVersion != 1 ||
				len(fixture.state.memoryRecords) != 0 ||
				len(fixture.state.memorySuccessors) != 0 {
				t.Fatalf("invalid changes partially applied: %#v", fixture.state)
			}
		})
	}
}

func TestStateApplyRejectsImmutablePlanMemoryReplacement(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	revision := mustPlanRevision(
		t,
		testPlanRevisionID,
		"",
		nil,
		fixture.editorDevice,
	)
	record := mustMemoryRecord(
		t,
		testMemoryID,
		memory.ScopeSession,
		"",
		"key",
		"",
		"",
	)
	snapshot.PlanRevisions[revision.ID()] = revision
	snapshot.MemoryRecords[record.ID()] = record
	state := mustReducerState(t, snapshot)

	for _, changes := range []Changes{
		{PlanRevisions: []plan.Revision{revision}},
		{MemoryRecords: []memory.Record{record}},
	} {
		if err := state.Apply(changes); !errors.Is(
			err,
			ErrInvalidCommittedState,
		) {
			t.Fatalf("Apply() error = %v", err)
		}
	}
	if len(state.planRevisions) != 1 ||
		len(state.memoryRecords) != 1 {
		t.Fatalf("immutable rows changed: %#v", state)
	}
}

func TestStateApplyRejectsCorruptRetainedPlanReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		changes func(*testing.T, reducerFixture) Changes
	}{
		{
			name: "new revision predecessor",
			changes: func(t *testing.T, fixture reducerFixture) Changes {
				return Changes{
					PlanRevisions: []plan.Revision{mustPlanRevision(
						t,
						testPlanRevisionID,
						testPriorPlanRevisionID,
						nil,
						fixture.editorDevice,
					)},
				}
			},
		},
		{
			name: "current pointer target",
			changes: func(_ *testing.T, _ reducerFixture) Changes {
				return Changes{
					PlanCurrent: []plan.Current{{
						SessionID:     testSessionID,
						RevisionID:    testPriorPlanRevisionID,
						EntityVersion: 2,
					}},
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			snapshot.PlanRevisions[testPriorPlanRevisionID] = mustPlanRevision(
				t,
				testPriorPlanRevisionID,
				"",
				nil,
				fixture.editorDevice,
			)
			state := mustReducerState(t, snapshot)
			state.planRevisions[testPriorPlanRevisionID] = mustPlanRevision(
				t,
				testMemorySuccessorID,
				"",
				nil,
				fixture.editorDevice,
			)

			if err := state.Apply(test.changes(t, fixture)); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("Apply() error = %v", err)
			}
			if len(state.planRevisions) != 1 ||
				state.planCurrent.RevisionID != "" ||
				state.planCurrent.EntityVersion != 1 {
				t.Fatalf("invalid plan change was applied: %#v", state)
			}
		})
	}
}

func TestStateApplyRejectsMissingCurrentPlanRevision(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.PlanRevisions[testPriorPlanRevisionID] = mustPlanRevision(
		t,
		testPriorPlanRevisionID,
		"",
		nil,
		fixture.editorDevice,
	)
	snapshot.PlanRevisions[testPlanRevisionID] = mustPlanRevision(
		t,
		testPlanRevisionID,
		"",
		nil,
		fixture.editorDevice,
	)
	snapshot.PlanCurrent.RevisionID = testPriorPlanRevisionID
	state := mustReducerState(t, snapshot)
	delete(state.planRevisions, testPriorPlanRevisionID)

	err := state.Apply(Changes{
		PlanCurrent: []plan.Current{{
			SessionID:     testSessionID,
			RevisionID:    testPlanRevisionID,
			EntityVersion: 2,
		}},
	})
	if !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("Apply() error = %v", err)
	}
	if state.planCurrent.RevisionID != testPriorPlanRevisionID ||
		state.planCurrent.EntityVersion != 1 {
		t.Fatalf("invalid current-plan change was applied: %#v", state.planCurrent)
	}
}
