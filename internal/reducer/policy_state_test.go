package reducer

import (
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

func TestNewStateRejectsPolicyUseAndCapabilityViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{
			name: "member cap below active rows",
			mutate: func(snapshot *Snapshot) {
				snapshot.SessionPolicy.Values.MaxMemberDevices = 2
			},
		},
		{
			name: "active device below cluster apply floor",
			mutate: func(snapshot *Snapshot) {
				snapshot.SessionPolicy.Values.ClusterMinApplyLevel = 2
			},
		},
		{
			name: "audit depth below retained counter",
			mutate: func(snapshot *Snapshot) {
				snapshot.SessionPolicy.Values.
					AuditDepthPerDevicePerEpoch =
					policy.MinAuditDepthPerDevicePerEpoch
				for id, counter := range snapshot.AuditCounters {
					counter.AcceptedCount =
						uint64(policy.MinAuditDepthPerDevicePerEpoch + 1)
					snapshot.AuditCounters[id] = counter
					break
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
			test.mutate(&snapshot)
			if _, err := NewState(snapshot); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("NewState() error = %v", err)
			}
		})
	}
}

func TestStateApplyRejectsInvalidPolicyChangesAtomically(t *testing.T) {
	t.Parallel()

	otherSessionID := domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000099",
	)
	tests := []struct {
		name    string
		changes func(State) []policy.Policy
	}{
		{
			name: "duplicate rows",
			changes: func(state State) []policy.Policy {
				next := state.sessionPolicy
				next.EntityVersion++
				return []policy.Policy{next, next}
			},
		},
		{
			name: "wrong session",
			changes: func(state State) []policy.Policy {
				next := state.sessionPolicy
				next.SessionID = otherSessionID
				next.EntityVersion++
				return []policy.Policy{next}
			},
		},
		{
			name: "version does not advance",
			changes: func(state State) []policy.Policy {
				return []policy.Policy{state.sessionPolicy}
			},
		},
		{
			name: "invalid values",
			changes: func(state State) []policy.Policy {
				next := state.sessionPolicy
				next.Values.CheckpointEvents = 99
				next.EntityVersion++
				return []policy.Policy{next}
			},
		},
		{
			name: "cap below current use",
			changes: func(state State) []policy.Policy {
				next := state.sessionPolicy
				next.Values.MaxMemberDevices = 2
				next.EntityVersion++
				return []policy.Policy{next}
			},
		},
		{
			name: "unsupported apply level",
			changes: func(state State) []policy.Policy {
				next := state.sessionPolicy
				next.Values.ClusterMinApplyLevel = 2
				next.EntityVersion++
				return []policy.Policy{next}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newReducerFixture(t)
			original := fixture.state.sessionPolicy
			key := OriginScopeKey{
				DeviceID: fixture.ownerDevice,
				Kind:     ScopeBoot,
				ScopeID:  testBootID,
			}
			changes := Changes{
				OriginScopes: []OriginScope{{
					OriginScopeKey: key,
					LastSequence:   2,
				}},
				SessionPolicy: test.changes(fixture.state),
			}
			if err := fixture.state.Apply(changes); !errors.Is(
				err,
				ErrInvalidCommittedState,
			) {
				t.Fatalf("Apply() error = %v", err)
			}
			if fixture.state.sessionPolicy != original ||
				fixture.state.originScopes[key].LastSequence != 1 {
				t.Fatalf("invalid policy changes partially applied: %#v", fixture.state)
			}
		})
	}
}
