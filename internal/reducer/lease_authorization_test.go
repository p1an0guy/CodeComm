package reducer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

func TestLeaseRenewAndReleaseAuthorization(t *testing.T) {
	t.Parallel()

	t.Run("foreign agent cannot renew", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		otherAgent := reducerAgentID(1)
		addReducerAgent(&fixture.state, otherAgent, fixture.editorDevice)
		addReducerLease(
			&fixture.state,
			mustReducerLease(
				t,
				testLeaseID,
				fixture.editorDevice,
				otherAgent,
				lease.ScopePath,
				"",
				4,
				"src/**",
			),
		)
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseRenewed,
			testLeaseID,
			4,
			`{"ttl_seconds":900}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeLeaseHolderRequired)
	})

	tests := []struct {
		name         string
		actor        event.ActorType
		originDevice func(reducerFixture) domain.DeviceID
		holderDevice func(reducerFixture) domain.DeviceID
		reason       lease.ReleaseReason
		want         Code
		accepted     bool
	}{
		{
			name:         "human cannot volunteer",
			actor:        event.ActorHuman,
			holderDevice: editorDevice,
			reason:       lease.ReleaseVoluntary,
			want:         CodeReleaseActorMismatch,
		},
		{
			name:         "agent cannot force",
			actor:        event.ActorAgent,
			holderDevice: editorDevice,
			reason:       lease.ReleaseForced,
			want:         CodeReleaseActorMismatch,
		},
		{
			name:         "agent cannot expire",
			actor:        event.ActorAgent,
			holderDevice: editorDevice,
			reason:       lease.ReleaseExpired,
			want:         CodeReleaseActorMismatch,
		},
		{
			name:         "human cannot expire",
			actor:        event.ActorHuman,
			holderDevice: editorDevice,
			reason:       lease.ReleaseExpired,
			want:         CodeReleaseActorMismatch,
		},
		{
			name:         "editor cannot force foreign device",
			actor:        event.ActorHuman,
			originDevice: editorDevice,
			holderDevice: targetDevice,
			reason:       lease.ReleaseForced,
			want:         CodeReleaseNotAuthorized,
		},
		{
			name:         "editor can force own device",
			actor:        event.ActorHuman,
			originDevice: editorDevice,
			holderDevice: editorDevice,
			reason:       lease.ReleaseForced,
			accepted:     true,
		},
		{
			name:         "owner can force foreign device",
			actor:        event.ActorHuman,
			originDevice: ownerDevice,
			holderDevice: targetDevice,
			reason:       lease.ReleaseForced,
			accepted:     true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			holderDeviceID := test.holderDevice(fixture)
			holderAgent := testAgentSessionID
			if holderDeviceID != fixture.editorDevice {
				holderAgent = reducerAgentID(2)
				addReducerAgent(&fixture.state, holderAgent, holderDeviceID)
			}
			addReducerLease(
				&fixture.state,
				mustReducerLease(
					t,
					testLeaseID,
					holderDeviceID,
					holderAgent,
					lease.ScopePath,
					"",
					4,
					"src/**",
				),
			)
			originDeviceID := domain.DeviceID("")
			if test.originDevice != nil {
				originDeviceID = test.originDevice(fixture)
			}
			proposal := buildLeaseProposalForOrigin(
				t,
				fixture,
				test.actor,
				originDeviceID,
				"",
				event.KindLeaseReleased,
				testLeaseID,
				4,
				`{"release_reason":"`+string(test.reason)+`"}`,
				2,
			)
			if test.accepted {
				outcome := assertAccepted(t, fixture.state, proposal)
				if outcome.Audit == nil ||
					outcome.Audit.Class != AuditOperatorOverride {
					t.Fatalf("forced-release audit = %#v", outcome.Audit)
				}
				return
			}
			assertRejectedCode(t, fixture.state, proposal, test.want)
		})
	}
}

func TestLeaseAcquisitionEnforcesAgentAndDeviceLimitsIndependently(t *testing.T) {
	t.Parallel()

	t.Run("agent limit", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.sessionPolicy.Values.AgentLeaseLimit = 1
		fixture.state.sessionPolicy.Values.DeviceLeaseLimit = 2
		addReducerLease(
			&fixture.state,
			mustReducerLease(
				t,
				reducerLeaseID(1),
				fixture.editorDevice,
				testAgentSessionID,
				lease.ScopePath,
				"",
				1,
				"docs/**",
			),
		)
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseAcquired,
			testLeaseID,
			0,
			`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeAgentLeaseLimitReached)
	})

	t.Run("device limit with agent capacity", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.sessionPolicy.Values.AgentLeaseLimit = 1
		fixture.state.sessionPolicy.Values.DeviceLeaseLimit = 2
		for index := 1; index <= 2; index++ {
			agentID := reducerAgentID(index)
			addReducerAgent(&fixture.state, agentID, fixture.editorDevice)
			addReducerLease(
				&fixture.state,
				mustReducerLease(
					t,
					reducerLeaseID(index),
					fixture.editorDevice,
					agentID,
					lease.ScopePath,
					"",
					1,
					fmt.Sprintf("area-%d/**", index),
				),
			)
		}
		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseAcquired,
			testLeaseID,
			0,
			`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
		)
		assertRejectedCode(t, fixture.state, proposal, CodeDeviceLeaseLimitReached)
	})

	t.Run("released rows do not count", func(t *testing.T) {
		t.Parallel()
		fixture := newReducerFixture(t)
		fixture.state.sessionPolicy.Values.AgentLeaseLimit = 1
		fixture.state.sessionPolicy.Values.DeviceLeaseLimit = 1
		released := mustReducerLease(
			t,
			reducerLeaseID(1),
			fixture.editorDevice,
			testAgentSessionID,
			lease.ScopePath,
			"",
			1,
			"src/**",
		)
		released.Status = lease.StatusReleased
		released.ReleaseReason = lease.ReleaseExpired
		released.EntityVersion = 2
		fixture.state.leases[released.ID] = released

		proposal := buildLeaseProposal(
			t,
			fixture,
			event.ActorAgent,
			event.KindLeaseAcquired,
			testLeaseID,
			0,
			`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
		)
		assertAccepted(t, fixture.state, proposal)
	})
}

func TestLeaseAcquisitionIntersectionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		existingScope    lease.Scope
		existingTask     domain.UUIDv7
		existingPatterns []string
		candidatePayload string
		wantConflict     bool
	}{
		{
			name:          "equal task",
			existingScope: lease.ScopeTask,
			existingTask:  testTaskID,
			candidatePayload: `{"scope":"task","task_id":"` +
				string(testTaskID) + `","ttl_seconds":900}`,
			wantConflict: true,
		},
		{
			name:          "different tasks",
			existingScope: lease.ScopeTask,
			existingTask:  testOtherTaskID,
			candidatePayload: `{"scope":"task","task_id":"` +
				string(testTaskID) + `","ttl_seconds":900}`,
		},
		{
			name:             "task and path are disjoint",
			existingScope:    lease.ScopeTask,
			existingTask:     testTaskID,
			candidatePayload: `{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
		},
		{
			name:             "exact equality",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"src/main.go"},
			candidatePayload: `{"path_globs":["src/main.go"],"scope":"path","ttl_seconds":900}`,
			wantConflict:     true,
		},
		{
			name:             "existing prefix contains exact",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"src/**"},
			candidatePayload: `{"path_globs":["src/main.go"],"scope":"path","ttl_seconds":900}`,
			wantConflict:     true,
		},
		{
			name:             "candidate prefix contains exact",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"src/main.go"},
			candidatePayload: `{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
			wantConflict:     true,
		},
		{
			name:             "nested prefixes",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"src/pkg/**"},
			candidatePayload: `{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
			wantConflict:     true,
		},
		{
			name:             "component boundary is disjoint",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"src/**"},
			candidatePayload: `{"path_globs":["src2/main.go"],"scope":"path","ttl_seconds":900}`,
		},
		{
			name:             "comparison is case sensitive",
			existingScope:    lease.ScopePath,
			existingPatterns: []string{"Src/**"},
			candidatePayload: `{"path_globs":["src/main.go"],"scope":"path","ttl_seconds":900}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			fixture.state.tasks[testTaskID] = taskForReducerState(
				fixture,
				task.StateInProgress,
				2,
			)
			other := testTask(task.StateDone, 1)
			other.ID = testOtherTaskID
			fixture.state.tasks[testOtherTaskID] = other
			addReducerLease(
				&fixture.state,
				mustReducerLease(
					t,
					reducerLeaseID(1),
					fixture.editorDevice,
					testAgentSessionID,
					test.existingScope,
					test.existingTask,
					1,
					test.existingPatterns...,
				),
			)
			proposal := buildLeaseProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindLeaseAcquired,
				testLeaseID,
				0,
				test.candidatePayload,
			)
			if test.wantConflict {
				assertRejectedCode(
					t,
					fixture.state,
					proposal,
					CodeLeaseScopeConflict,
				)
				return
			}
			assertAccepted(t, fixture.state, proposal)
		})
	}
}

func TestSequentialOverlappingLeaseRaceAndRelease(t *testing.T) {
	t.Parallel()

	fixture := newReducerFixture(t)
	firstProposal := buildLeaseProposalForOrigin(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindLeaseAcquired,
		reducerLeaseID(1),
		0,
		`{"path_globs":["src/**"],"scope":"path","ttl_seconds":900}`,
		2,
	)
	first := assertAccepted(t, fixture.state, firstProposal)
	if err := fixture.state.Apply(first.Changes); err != nil {
		t.Fatalf("Apply(first) error = %v", err)
	}

	secondProposal := buildLeaseProposalForOrigin(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindLeaseAcquired,
		reducerLeaseID(2),
		0,
		`{"path_globs":["src/main.go"],"scope":"path","ttl_seconds":900}`,
		3,
	)
	second, err := Reduce(fixture.state, secondProposal)
	if err != nil {
		t.Fatalf("Reduce(second) error = %v", err)
	}
	if second.Code != CodeLeaseScopeConflict {
		t.Fatalf("second outcome = %#v", second)
	}
	if err := fixture.state.Apply(second.Changes); err != nil {
		t.Fatalf("Apply(second rejection) error = %v", err)
	}

	releaseProposal := buildLeaseProposalForOrigin(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindLeaseReleased,
		reducerLeaseID(1),
		1,
		`{"release_reason":"voluntary"}`,
		4,
	)
	released := assertAccepted(t, fixture.state, releaseProposal)
	if err := fixture.state.Apply(released.Changes); err != nil {
		t.Fatalf("Apply(release) error = %v", err)
	}

	afterRelease := buildLeaseProposalForOrigin(
		t,
		fixture,
		event.ActorAgent,
		fixture.editorDevice,
		testAgentSessionID,
		event.KindLeaseAcquired,
		reducerLeaseID(2),
		0,
		`{"path_globs":["src/main.go"],"scope":"path","ttl_seconds":900}`,
		5,
	)
	assertAccepted(t, fixture.state, afterRelease)
}

func TestLeasePathPatternRawBoundaries(t *testing.T) {
	t.Parallel()

	for _, count := range []int{1, lease.MaxPathPatterns, lease.MaxPathPatterns + 1} {
		count := count
		t.Run(fmt.Sprintf("%d", count), func(t *testing.T) {
			t.Parallel()
			fixture := newReducerFixture(t)
			patterns := make([]string, count)
			for index := range patterns {
				patterns[index] = fmt.Sprintf("area-%02d/**", index)
			}
			proposal := buildLeaseProposal(
				t,
				fixture,
				event.ActorAgent,
				event.KindLeaseAcquired,
				testLeaseID,
				0,
				`{"path_globs":["`+strings.Join(patterns, `","`)+
					`"],"scope":"path","ttl_seconds":900}`,
			)
			if count <= lease.MaxPathPatterns {
				assertAccepted(t, fixture.state, proposal)
			} else {
				assertRejectedCode(t, fixture.state, proposal, CodeInvalidPayload)
			}
		})
	}
}

func editorDevice(fixture reducerFixture) domain.DeviceID {
	return fixture.editorDevice
}

func ownerDevice(fixture reducerFixture) domain.DeviceID {
	return fixture.ownerDevice
}

func targetDevice(fixture reducerFixture) domain.DeviceID {
	return fixture.targetDevice
}
