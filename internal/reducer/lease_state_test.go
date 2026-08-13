package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

func TestNewStateDerivesActiveLeaseIndexesAndLimits(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	snapshot.SessionPolicy.Values.AgentLeaseLimit = 1
	snapshot.SessionPolicy.Values.DeviceLeaseLimit = 1
	current := mustReducerLease(
		t,
		reducerLeaseID(1),
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		1,
		"docs/**",
	)
	snapshot.Leases[current.ID] = current

	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	if len(state.activeLeaseIDs) != 1 ||
		len(state.activeLeasesByAgent[testAgentSessionID]) != 1 ||
		len(state.activeLeasesByDevice[fixture.editorDevice]) != 1 {
		t.Fatalf("derived lease indexes = %#v", state)
	}
	fixture.state = state
	proposal := buildLeaseProposal(
		t,
		fixture,
		"agent",
		"lease.acquired",
		testLeaseID,
		0,
		`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
	)
	assertRejectedCode(t, state, proposal, CodeAgentLeaseLimitReached)
}

func TestNewStateRejectsOverlappingActiveLeases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		first  lease.Lease
		second lease.Lease
	}{
		{
			name: "path prefix and exact",
		},
		{
			name: "equal task",
		},
	}
	for index := range tests {
		fixture := newReducerFixture(t)
		switch tests[index].name {
		case "path prefix and exact":
			tests[index].first = mustReducerLease(
				t,
				reducerLeaseID(1),
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				1,
				"src/**",
			)
			tests[index].second = mustReducerLease(
				t,
				reducerLeaseID(2),
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				1,
				"src/main.go",
			)
		case "equal task":
			fixture.state.tasks[testTaskID] = taskForReducerState(
				fixture,
				task.StateInProgress,
				1,
			)
			tests[index].first = mustReducerLease(
				t,
				reducerLeaseID(1),
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopeTask,
				testTaskID,
				1,
			)
			tests[index].second = mustReducerLease(
				t,
				reducerLeaseID(2),
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopeTask,
				testTaskID,
				1,
			)
		}
		snapshot := snapshotFromState(fixture.state)
		snapshot.Leases[tests[index].first.ID] = tests[index].first
		snapshot.Leases[tests[index].second.ID] = tests[index].second
		if _, err := NewState(snapshot); !errors.Is(err, ErrInvalidCommittedState) {
			t.Fatalf("%s: NewState() error = %v", tests[index].name, err)
		}
	}
}

func TestNewStateValidatesLeaseReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*reducerFixture, *Snapshot, lease.Lease) lease.Lease
	}{
		{
			name: "map key mismatch",
			mutate: func(
				_ *reducerFixture,
				snapshot *Snapshot,
				value lease.Lease,
			) lease.Lease {
				snapshot.Leases[reducerLeaseID(2)] = value
				return lease.Lease{}
			},
		},
		{
			name: "missing holder session",
			mutate: func(
				_ *reducerFixture,
				_ *Snapshot,
				value lease.Lease,
			) lease.Lease {
				value.HolderAgentSessionID = reducerAgentID(9)
				return value
			},
		},
		{
			name: "holder binding mismatch",
			mutate: func(
				fixture *reducerFixture,
				snapshot *Snapshot,
				value lease.Lease,
			) lease.Lease {
				session := snapshot.AgentSessions[testAgentSessionID]
				session.DeviceID = fixture.targetDevice
				snapshot.AgentSessions[testAgentSessionID] = session
				return value
			},
		},
		{
			name: "missing associated task",
			mutate: func(
				_ *reducerFixture,
				_ *Snapshot,
				value lease.Lease,
			) lease.Lease {
				value.TaskID = testOtherTaskID
				return value
			},
		},
		{
			name: "active lease held by ended session",
			mutate: func(
				_ *reducerFixture,
				snapshot *Snapshot,
				value lease.Lease,
			) lease.Lease {
				session := snapshot.AgentSessions[testAgentSessionID]
				session.State = agentsession.StateEnded
				session.EndReason = agentsession.EndReasonClean
				session.EntityVersion++
				snapshot.AgentSessions[testAgentSessionID] = session
				return value
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			value := mustReducerLease(
				t,
				testLeaseID,
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				1,
				"src/**",
			)
			value = test.mutate(&fixture, &snapshot, value)
			if value.ID != "" {
				snapshot.Leases[value.ID] = value
			}
			if _, err := NewState(snapshot); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("NewState() error = %v", err)
			}
		})
	}
}

func TestNewStateAllowsReleasedLeaseHeldByEndedSession(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	session := snapshot.AgentSessions[testAgentSessionID]
	session.State = agentsession.StateEnded
	session.EndReason = agentsession.EndReasonClean
	session.EntityVersion++
	snapshot.AgentSessions[testAgentSessionID] = session
	value := mustReducerLease(
		t,
		testLeaseID,
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		1,
		"src/**",
	)
	value.Status = lease.StatusReleased
	value.ReleaseReason = lease.ReleaseSessionEnded
	value.EntityVersion = 2
	snapshot.Leases[value.ID] = value

	if _, err := NewState(snapshot); err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
}

func TestStateApplyRejectsInvalidLeaseChangesAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*testing.T, reducerFixture) lease.Lease
	}{
		{
			name: "immutable reservation changed",
			change: func(t *testing.T, fixture reducerFixture) lease.Lease {
				return mustReducerLease(
					t,
					testLeaseID,
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					5,
					"other/**",
				)
			},
		},
		{
			name: "intersects retained active lease",
			change: func(t *testing.T, fixture reducerFixture) lease.Lease {
				return mustReducerLease(
					t,
					reducerLeaseID(2),
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					1,
					"src/main.go",
				)
			},
		},
		{
			name: "skips entity version",
			change: func(t *testing.T, fixture reducerFixture) lease.Lease {
				return mustReducerLease(
					t,
					testLeaseID,
					fixture.editorDevice,
					testAgentSessionID,
					lease.ScopePath,
					"",
					6,
					"src/**",
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			current := mustReducerLease(
				t,
				testLeaseID,
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				4,
				"src/**",
			)
			addReducerLease(&fixture.state, current)
			change := test.change(t, fixture)

			if err := fixture.state.Apply(Changes{
				Leases: []lease.Lease{change},
			}); !errors.Is(err, ErrInvalidCommittedState) {
				t.Fatalf("Apply() error = %v", err)
			}
			if got := fixture.state.leases[testLeaseID]; got.EntityVersion != 4 ||
				len(fixture.state.activeLeaseIDs) != 1 {
				t.Fatalf("state mutated after rejected Apply: %#v", fixture.state)
			}
			if _, exists := fixture.state.leases[reducerLeaseID(2)]; exists {
				t.Fatal("rejected Apply inserted lease")
			}
		})
	}
}

func TestLeaseSnapshotDeepCopiesSourceMaps(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	value := mustReducerLease(
		t,
		testLeaseID,
		fixture.editorDevice,
		testAgentSessionID,
		lease.ScopePath,
		"",
		1,
		"src/**",
	)
	snapshot.Leases[value.ID] = value
	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	delete(snapshot.Leases, value.ID)

	if _, exists := state.leases[value.ID]; !exists ||
		len(state.activeLeaseIDs) != 1 {
		t.Fatalf("state aliases source lease map: %#v", state)
	}
}
