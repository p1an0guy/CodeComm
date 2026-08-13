package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

type controlledApplyClock struct {
	mu        sync.Mutex
	wall      time.Time
	monotonic time.Duration
}

func newControlledApplyClock() *controlledApplyClock {
	return &controlledApplyClock{
		wall: time.Date(2026, 8, 12, 14, 0, 0, 0, time.UTC),
	}
}

func (clock *controlledApplyClock) read() (domain.Timestamp, int64, error) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return domain.Timestamp(clock.wall.UTC().Format(time.RFC3339Nano)),
		clock.monotonic.Nanoseconds(),
		nil
}

func (clock *controlledApplyClock) advanceMonotonic(duration time.Duration) {
	clock.mu.Lock()
	clock.monotonic += duration
	clock.mu.Unlock()
}

func (clock *controlledApplyClock) jumpWall(duration time.Duration) {
	clock.mu.Lock()
	clock.wall = clock.wall.Add(duration)
	clock.mu.Unlock()
}

func TestLeaseExpiryUsesMonotonicTimeAndVersionedCAS(t *testing.T) {
	clock := newControlledApplyClock()
	harness := newAgentTestHarnessWithState(
		t,
		nil,
		nil,
		nil,
		clock.read,
	)
	harness.service.leasePollInterval = 2 * time.Millisecond
	if err := harness.service.Recover(testAgentContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	launched := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-8123456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-8223456789ab"),
		agentsession.ClientKindCodex,
	)
	leaseID := domain.UUIDv7("018f47de-89ab-7def-8123-8323456789ab")
	acquired := submitLeaseMutation(
		t,
		launched.client,
		event.KindLeaseAcquired,
		leaseID,
		nil,
	)
	if acquired.Status != store.OutcomeAccepted {
		t.Fatalf("lease acquisition = %#v", acquired)
	}
	first := waitForLeaseDeadline(t, harness, 1)
	if first.MonotonicDeadlineNS != int64(30*time.Second) {
		t.Fatalf(
			"first deadline = %d, want %d",
			first.MonotonicDeadlineNS,
			30*time.Second,
		)
	}

	for index := range 12 {
		outcome := submitBusyTask(t, launched.client, index)
		if outcome.Status != store.OutcomeAccepted {
			t.Fatalf("busy task %d = %#v", index, outcome)
		}
	}
	afterTraffic := waitForLeaseDeadline(t, harness, 1)
	if afterTraffic.MonotonicDeadlineNS != first.MonotonicDeadlineNS {
		t.Fatalf(
			"event volume moved deadline from %d to %d",
			first.MonotonicDeadlineNS,
			afterTraffic.MonotonicDeadlineNS,
		)
	}

	clock.jumpWall(48 * time.Hour)
	time.Sleep(5 * harness.service.leasePollInterval)
	assertLeaseProjection(t, harness, leaseID, "active", nil, 1)

	clock.advanceMonotonic(29 * time.Second)
	time.Sleep(5 * harness.service.leasePollInterval)
	assertLeaseProjection(t, harness, leaseID, "active", nil, 1)

	renewed := submitLeaseMutation(
		t,
		launched.client,
		event.KindLeaseRenewed,
		leaseID,
		versionPointer(1),
	)
	if renewed.Status != store.OutcomeAccepted {
		t.Fatalf("lease renewal = %#v", renewed)
	}
	second := waitForLeaseDeadline(t, harness, 2)
	if second.MonotonicDeadlineNS != int64(59*time.Second) {
		t.Fatalf(
			"renewed deadline = %d, want %d",
			second.MonotonicDeadlineNS,
			59*time.Second,
		)
	}

	clock.advanceMonotonic(time.Second)
	time.Sleep(5 * harness.service.leasePollInterval)
	assertLeaseProjection(t, harness, leaseID, "active", nil, 2)

	clock.advanceMonotonic(29 * time.Second)
	waitForLeaseProjection(t, harness, leaseID, "released", "expired", 3)

	staleRenewal := submitLeaseMutation(
		t,
		launched.client,
		event.KindLeaseRenewed,
		leaseID,
		versionPointer(2),
	)
	if staleRenewal.Status != store.OutcomeRejected {
		t.Fatalf("renewal after expiry = %#v", staleRenewal)
	}
}

func TestFollowerDoesNotOriginateLeaseExpiry(t *testing.T) {
	clock := newControlledApplyClock()
	harness := newAgentTestHarnessWithState(
		t,
		nil,
		nil,
		nil,
		clock.read,
	)
	harness.service.leasePollInterval = 2 * time.Millisecond
	if err := harness.service.Recover(testAgentContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	launched := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-8423456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-8523456789ab"),
		agentsession.ClientKindClaude,
	)
	leaseID := domain.UUIDv7("018f47de-89ab-7def-8123-8623456789ab")
	acquired := submitLeaseMutation(
		t,
		launched.client,
		event.KindLeaseAcquired,
		leaseID,
		nil,
	)
	if acquired.Status != store.OutcomeAccepted {
		t.Fatalf("lease acquisition = %#v", acquired)
	}
	waitForLeaseDeadline(t, harness, 1)

	harness.consensus.leader.Store(false)
	before := consensusIndex(harness.consensus)
	clock.advanceMonotonic(30 * time.Second)
	time.Sleep(5 * harness.service.leasePollInterval)
	if got := consensusIndex(harness.consensus); got != before {
		t.Fatalf("follower advanced consensus index from %d to %d", before, got)
	}
	assertLeaseProjection(t, harness, leaseID, "active", nil, 1)
	waitForLeaseDeadline(t, harness, 1)

	harness.consensus.leader.Store(true)
	waitForLeaseProjection(t, harness, leaseID, "released", "expired", 2)
}

func submitLeaseMutation(
	t *testing.T,
	client *boundClient,
	kind event.Kind,
	leaseID domain.UUIDv7,
	expectedVersion *uint64,
) store.CommandOutcome {
	t.Helper()
	payload := map[string]any{"ttl_seconds": int64(30)}
	if kind == event.KindLeaseAcquired {
		payload["scope"] = lease.ScopePath
		payload["path_globs"] = []string{"src/**"}
	}
	return submitAgentTestCommand(
		t,
		client,
		event.Command{
			Kind:                  kind,
			EntityID:              event.StringEntityID(string(leaseID)),
			ExpectedEntityVersion: expectedVersion,
			RationaleSummary:      "",
			Actions:               []event.Action{},
			Payload:               mustCanonicalTestObject(t, payload),
			Redaction:             defaultRedaction(),
		},
	)
}

func submitBusyTask(
	t *testing.T,
	client *boundClient,
	index int,
) store.CommandOutcome {
	t.Helper()
	id := mustTestUUIDv7(t)
	return submitAgentTestCommand(
		t,
		client,
		event.Command{
			Kind:             event.KindTaskCreated,
			EntityID:         event.StringEntityID(string(id)),
			RationaleSummary: "",
			Actions:          []event.Action{},
			Payload: mustCanonicalTestObject(t, map[string]any{
				"priority": task.PriorityNormal,
				"title":    fmt.Sprintf("busy event %02d", index),
			}),
			Redaction: defaultRedaction(),
		},
	)
}

func submitAgentTestCommand(
	t *testing.T,
	client *boundClient,
	command event.Command,
) store.CommandOutcome {
	t.Helper()
	requestID := mustTestUUIDv7(t)
	canonical := mustCanonicalTestObject(t, map[string]any{
		"kind":       command.Kind,
		"request_id": requestID,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, duplicate, err := client.submitCommand(ctx, localCommandRequest{
		Operation: string(command.Kind),
		RequestID: requestID,
		Command:   command,
		Canonical: canonical,
	})
	if err != nil {
		t.Fatalf("submit %s: %v", command.Kind, err)
	}
	if duplicate || result.Outcome == nil {
		t.Fatalf(
			"submit %s = duplicate %t, outcome %#v",
			command.Kind,
			duplicate,
			result.Outcome,
		)
	}
	return *result.Outcome
}

func waitForLeaseDeadline(
	t *testing.T,
	harness *agentTestHarness,
	version uint64,
) store.LeaseDeadlineRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, found, err := harness.local.NextLeaseDeadline(
			context.Background(),
			agentTestBootID,
		)
		if err == nil && found && record.EntityVersion == version {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lease deadline version %d did not appear", version)
	return store.LeaseDeadlineRecord{}
}

func waitForLeaseProjection(
	t *testing.T,
	harness *agentTestHarness,
	leaseID domain.UUIDv7,
	status, reason string,
	version uint64,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if leaseProjectionMatches(
			t,
			harness,
			leaseID,
			status,
			reason,
			version,
		) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	assertLeaseProjection(t, harness, leaseID, status, &reason, version)
}

func assertLeaseProjection(
	t *testing.T,
	harness *agentTestHarness,
	leaseID domain.UUIDv7,
	status string,
	reason *string,
	version uint64,
) {
	t.Helper()
	var expectedReason string
	if reason != nil {
		expectedReason = *reason
	}
	if !leaseProjectionMatches(
		t,
		harness,
		leaseID,
		status,
		expectedReason,
		version,
	) {
		t.Fatalf(
			"lease %s did not match status=%s reason=%q version=%d",
			leaseID,
			status,
			expectedReason,
			version,
		)
	}
}

func leaseProjectionMatches(
	t *testing.T,
	harness *agentTestHarness,
	leaseID domain.UUIDv7,
	status, reason string,
	version uint64,
) bool {
	t.Helper()
	view, err := harness.state.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	for _, row := range view.ProjectionRows {
		if row.Table != "leases" {
			continue
		}
		var value struct {
			LeaseID       string  `json:"lease_id"`
			Status        string  `json:"status"`
			ReleaseReason *string `json:"release_reason"`
			EntityVersion uint64  `json:"entity_version"`
		}
		if err := json.Unmarshal(row.Row, &value); err != nil {
			t.Fatalf("decode lease projection: %v", err)
		}
		if value.LeaseID != string(leaseID) {
			continue
		}
		gotReason := ""
		if value.ReleaseReason != nil {
			gotReason = *value.ReleaseReason
		}
		return value.Status == status &&
			gotReason == reason &&
			value.EntityVersion == version
	}
	return false
}

func mustCanonicalTestObject(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalObject(value)
	if err != nil {
		t.Fatalf("canonical object: %v", err)
	}
	return encoded
}

func mustTestUUIDv7(t *testing.T) domain.UUIDv7 {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("UUIDv7: %v", err)
	}
	result := domain.UUIDv7(value.String())
	if !result.Valid() {
		t.Fatalf("generated invalid UUIDv7 %q", result)
	}
	return result
}

func versionPointer(value uint64) *uint64 {
	return &value
}

func consensusIndex(runtime *fsmConsensus) uint64 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.index
}
