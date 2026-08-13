package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestNewStateValidatesAgentScopesAndActiveCap(t *testing.T) {
	t.Parallel()

	t.Run("orphan rejected-start scope at sequence one", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		snapshot := snapshotFromState(fixture.state)
		key := OriginScopeKey{
			DeviceID: fixture.editorDevice,
			Kind:     ScopeAgent,
			ScopeID:  testNewAgentSessionID,
		}
		snapshot.OriginScopes[key] = OriginScope{
			OriginScopeKey: key,
			LastSequence:   1,
		}
		if _, err := NewState(snapshot); err != nil {
			t.Fatalf("NewState() error = %v", err)
		}
	})

	t.Run("recovery-ended historical session may lack scope", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		snapshot := snapshotFromState(fixture.state)
		delete(snapshot.OriginScopes, OriginScopeKey{
			DeviceID: fixture.editorDevice,
			Kind:     ScopeAgent,
			ScopeID:  testAgentSessionID,
		})
		session := snapshot.AgentSessions[testAgentSessionID]
		session.State = agentsession.StateEnded
		session.EndReason = agentsession.EndReasonRecovery
		session.EntityVersion = 1
		snapshot.AgentSessions[testAgentSessionID] = session
		if _, err := NewState(snapshot); err != nil {
			t.Fatalf("NewState() error = %v", err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*Snapshot, reducerFixture)
	}{
		{
			name: "session missing scope",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				delete(snapshot.OriginScopes, OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				})
			},
		},
		{
			name: "orphan scope advanced",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				key := OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testNewAgentSessionID,
				}
				snapshot.OriginScopes[key] = OriginScope{
					OriginScopeKey: key,
					LastSequence:   2,
				}
			},
		},
		{
			name: "orphan scope references missing device",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				delete(snapshot.Devices, fixture.targetDevice)
				key := OriginScopeKey{
					DeviceID: fixture.targetDevice,
					Kind:     ScopeAgent,
					ScopeID:  testNewAgentSessionID,
				}
				snapshot.OriginScopes[key] = OriginScope{
					OriginScopeKey: key,
					LastSequence:   1,
				}
			},
		},
		{
			name: "agent scope ID reused across devices",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				key := OriginScopeKey{
					DeviceID: fixture.targetDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				}
				snapshot.OriginScopes[key] = OriginScope{
					OriginScopeKey: key,
					LastSequence:   1,
				}
			},
		},
		{
			name: "recovery-ended session rebound to another device",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				delete(snapshot.OriginScopes, OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				})
				session := snapshot.AgentSessions[testAgentSessionID]
				session.State = agentsession.StateEnded
				session.EndReason = agentsession.EndReasonRecovery
				snapshot.AgentSessions[testAgentSessionID] = session
				key := OriginScopeKey{
					DeviceID: fixture.targetDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				}
				snapshot.OriginScopes[key] = OriginScope{
					OriginScopeKey: key,
					LastSequence:   1,
				}
			},
		},
		{
			name: "recovery-ended session retains same-device scope",
			mutate: func(snapshot *Snapshot, _ reducerFixture) {
				session := snapshot.AgentSessions[testAgentSessionID]
				session.State = agentsession.StateEnded
				session.EndReason = agentsession.EndReasonRecovery
				snapshot.AgentSessions[testAgentSessionID] = session
			},
		},
		{
			name: "active session cap exceeded",
			mutate: func(snapshot *Snapshot, fixture reducerFixture) {
				snapshot.SessionPolicy.Values.MaxActiveAgentSessions = 1
				session := agentsession.Session{
					ID:            testNewAgentSessionID,
					DeviceID:      fixture.editorDevice,
					ClientKind:    agentsession.ClientKindClaude,
					State:         agentsession.StateIdle,
					WorkingRootID: testNewWorkingRootID,
					EntityVersion: 1,
				}
				snapshot.AgentSessions[session.ID] = session
				key := OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  session.ID,
				}
				snapshot.OriginScopes[key] = OriginScope{
					OriginScopeKey: key,
					LastSequence:   1,
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
			test.mutate(&snapshot, fixture)
			if _, err := NewState(snapshot); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("NewState() error = %v", err)
			}
		})
	}
}

func TestStateApplyRejectsNewOwnershipByEndingSessionAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, reducerFixture, *Changes)
	}{
		{
			name: "new task claim",
			mutate: func(
				_ *testing.T,
				fixture reducerFixture,
				changes *Changes,
			) {
				value := testTask(task.StateClaimed, 2)
				ownTask(&value, fixture.editorDevice)
				changes.Tasks = append(changes.Tasks, value)
			},
		},
		{
			name: "new active lease",
			mutate: func(
				t *testing.T,
				fixture reducerFixture,
				changes *Changes,
			) {
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
				changes.Leases = append(changes.Leases, value)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			fixture.state.tasks[testTaskID] = testTask(task.StateReady, 1)
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				nil,
				event.KindAgentSessionEnded,
				testAgentSessionID,
				1,
				`{"end_reason":"clean"}`,
				2,
			)
			outcome := assertAccepted(t, fixture.state, proposal)
			test.mutate(t, fixture, &outcome.Changes)

			if err := fixture.state.Apply(outcome.Changes); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("Apply() error = %v", err)
			}
			if fixture.state.agentSessions[testAgentSessionID].State !=
				agentsession.StateIdle ||
				fixture.state.tasks[testTaskID].State != task.StateReady ||
				fixture.state.originScopes[OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				}].LastSequence != 1 {
				t.Fatalf("state mutated after ownership rejection: %#v", fixture.state)
			}
			if _, exists := fixture.state.leases[testLeaseID]; exists {
				t.Fatal("rejected ownership inserted a lease")
			}
		})
	}
}

func TestStateApplyRejectsIncompleteSessionEndCascadeAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Changes)
	}{
		{
			name: "missing task",
			mutate: func(changes *Changes) {
				changes.Tasks = nil
			},
		},
		{
			name: "missing lease",
			mutate: func(changes *Changes) {
				changes.Leases = nil
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			claimed := taskForReducerState(
				fixture,
				task.StateInProgress,
				4,
			)
			fixture.state.tasks[claimed.ID] = claimed
			fixture.state.addClaim(claimed)
			activeLease := mustReducerLease(
				t,
				testLeaseID,
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				4,
				"src/**",
			)
			addReducerLease(&fixture.state, activeLease)
			proposal := buildAgentSessionProposal(
				t,
				fixture,
				event.ActorAgent,
				fixture.editorDevice,
				testAgentSessionID,
				nil,
				event.KindAgentSessionEnded,
				testAgentSessionID,
				1,
				`{"end_reason":"clean"}`,
				2,
			)
			outcome := assertAccepted(t, fixture.state, proposal)
			test.mutate(&outcome.Changes)

			if err := fixture.state.Apply(outcome.Changes); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("Apply() error = %v", err)
			}
			if fixture.state.agentSessions[testAgentSessionID].State !=
				agentsession.StateIdle ||
				fixture.state.tasks[testTaskID].State != task.StateInProgress ||
				fixture.state.leases[testLeaseID].Status != lease.StatusActive ||
				fixture.state.originScopes[OriginScopeKey{
					DeviceID: fixture.editorDevice,
					Kind:     ScopeAgent,
					ScopeID:  testAgentSessionID,
				}].LastSequence != 1 {
				t.Fatalf("state mutated after rejected cascade: %#v", fixture.state)
			}
		})
	}
}

func TestStateApplyRejectsAgentIdentityMutation(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	next := cloneAgentSession(
		fixture.state.agentSessions[testAgentSessionID],
	)
	next.ClientKind = agentsession.ClientKindClaude
	next.State = agentsession.StateWorking
	next.EntityVersion++

	if err := fixture.state.Apply(Changes{
		AgentSessions: []agentsession.Session{next},
	}); !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("Apply() error = %v", err)
	}
	if got := fixture.state.agentSessions[testAgentSessionID]; got.ClientKind !=
		agentsession.ClientKindCodex ||
		got.State != agentsession.StateIdle ||
		got.EntityVersion != 1 {
		t.Fatalf("state mutated after identity rejection: %#v", got)
	}
}

func TestStateApplyBurnsRejectedStartScopeWithoutSession(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	key := OriginScopeKey{
		DeviceID: fixture.editorDevice,
		Kind:     ScopeAgent,
		ScopeID:  testNewAgentSessionID,
	}
	if err := fixture.state.Apply(Changes{
		OriginScopes: []OriginScope{{
			OriginScopeKey: key,
			LastSequence:   1,
		}},
	}); err != nil {
		t.Fatalf("Apply(rejected start) error = %v", err)
	}
	if fixture.state.agentScopeDevices[testNewAgentSessionID] !=
		fixture.editorDevice {
		t.Fatalf("burned scope index = %#v", fixture.state.agentScopeDevices)
	}

	session := agentsession.Session{
		ID:            testNewAgentSessionID,
		DeviceID:      fixture.editorDevice,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateStarting,
		WorkingRootID: testNewWorkingRootID,
		EntityVersion: 1,
	}
	if err := fixture.state.Apply(Changes{
		AgentSessions: []agentsession.Session{session},
	}); !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("Apply(reused ID) error = %v", err)
	}
	if _, exists := fixture.state.agentSessions[testNewAgentSessionID]; exists {
		t.Fatal("burned agent-session ID was reused")
	}
}

func TestStateApplyRejectsOriginScopeForMissingDevice(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	delete(fixture.state.devices, fixture.targetDevice)
	key := OriginScopeKey{
		DeviceID: fixture.targetDevice,
		Kind:     ScopeAgent,
		ScopeID:  testNewAgentSessionID,
	}
	if err := fixture.state.Apply(Changes{
		OriginScopes: []OriginScope{{
			OriginScopeKey: key,
			LastSequence:   1,
		}},
	}); !errors.Is(err, ErrInvalidCommittedState) {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, exists := fixture.state.originScopes[key]; exists {
		t.Fatal("scope for missing device was inserted")
	}
}

func TestStateApplyRejectsRebindingRecoveryEndedSessionID(t *testing.T) {
	t.Parallel()

	for _, useOriginalDevice := range []bool{true, false} {
		useOriginalDevice := useOriginalDevice
		name := "different device"
		if useOriginalDevice {
			name = "original device"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			snapshot := snapshotFromState(fixture.state)
			delete(snapshot.OriginScopes, OriginScopeKey{
				DeviceID: fixture.editorDevice,
				Kind:     ScopeAgent,
				ScopeID:  testAgentSessionID,
			})
			session := snapshot.AgentSessions[testAgentSessionID]
			session.State = agentsession.StateEnded
			session.EndReason = agentsession.EndReasonRecovery
			snapshot.AgentSessions[testAgentSessionID] = session
			state, err := NewState(snapshot)
			if err != nil {
				t.Fatalf("NewState() error = %v", err)
			}

			deviceID := fixture.targetDevice
			if useOriginalDevice {
				deviceID = fixture.editorDevice
			}
			key := OriginScopeKey{
				DeviceID: deviceID,
				Kind:     ScopeAgent,
				ScopeID:  testAgentSessionID,
			}
			if err := state.Apply(Changes{
				OriginScopes: []OriginScope{{
					OriginScopeKey: key,
					LastSequence:   1,
				}},
			}); !errors.Is(err, ErrInvalidCommittedState) {
				t.Fatalf("Apply() error = %v", err)
			}
			if _, exists := state.originScopes[key]; exists {
				t.Fatal("rebound origin scope was inserted")
			}
			if _, exists := state.agentScopeDevices[testAgentSessionID]; exists {
				t.Fatal("rebound origin-scope index was inserted")
			}
		})
	}
}

func TestAgentSessionResumeAndReapCASHasOneWinner(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	session := fixture.state.agentSessions[testAgentSessionID]
	session.State = agentsession.StateDisconnected
	session.ResumeState = agentsession.StateWorking
	session.EntityVersion = 2
	fixture.state.agentSessions[testAgentSessionID] = session

	resume := buildAgentSessionProposal(
		t,
		fixture,
		event.ActorDaemon,
		fixture.editorDevice,
		"",
		nil,
		event.KindAgentSessionStateChanged,
		testAgentSessionID,
		2,
		`{"to_state":"working"}`,
		2,
	)
	resumed := assertAccepted(t, fixture.state, resume)
	if err := fixture.state.Apply(resumed.Changes); err != nil {
		t.Fatalf("Apply(resume) error = %v", err)
	}

	reap := buildAgentSessionProposal(
		t,
		fixture,
		event.ActorDaemon,
		fixture.editorDevice,
		"",
		nil,
		event.KindAgentSessionEnded,
		testAgentSessionID,
		2,
		`{"end_reason":"disconnect_timeout"}`,
		3,
	)
	assertRejectedCode(
		t,
		fixture.state,
		reap,
		CodeEntityVersionMismatch,
	)
}

func TestNewStateDeepCopiesAgentProfile(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	snapshot := snapshotFromState(fixture.state)
	session := snapshot.AgentSessions[testAgentSessionID]
	profile := "builder"
	session.AgentProfileID = &profile
	snapshot.AgentSessions[testAgentSessionID] = session
	state, err := NewState(snapshot)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	profile = "mutated"
	if got := state.agentSessions[testAgentSessionID].AgentProfileID; got == nil ||
		*got != "builder" {
		t.Fatalf("agent profile aliases snapshot: %#v", got)
	}
}
