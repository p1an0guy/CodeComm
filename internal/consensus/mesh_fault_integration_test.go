package consensus

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/testharness/faultnet"
)

const secureMeshDirectedFaultChild = "directed-faults"

func TestSecureMeshDirectedFaultsHealAndReopen(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshDirectedFaultChild {
		runSecureMeshDirectedFaultsHealAndReopen(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshDirectedFaultsHealAndReopen$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshDirectedFaultChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("directed-fault mesh child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("directed-fault mesh child failed: %v\n%s", err, output)
	}
}

func runSecureMeshDirectedFaultsHealAndReopen(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	nodes := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, nodes)
	harness.waitForLeader(t, nodes)

	faults := []struct {
		name             string
		rule             faultnet.Rule
		closesConnection bool
	}{
		{name: "drop", rule: faultnet.Rule{Kind: faultnet.Drop}},
		{
			name:             "delay",
			closesConnection: true,
			rule: faultnet.Rule{
				Kind:  faultnet.Delay,
				Delay: 2 * time.Second,
			},
		},
		{
			name:             "duplicate",
			rule:             faultnet.Rule{Kind: faultnet.Duplicate},
			closesConnection: true,
		},
		{
			name: "truncate",
			rule: faultnet.Rule{
				Kind:          faultnet.Truncate,
				TruncateAfter: 128,
			},
			closesConnection: true,
		},
	}
	var finalTaskID domain.UUIDv7
	for index, test := range faults {
		leader := harness.waitForLeader(t, nodes)
		target := directedFaultTarget(t, nodes, leader)
		eventID := directedFaultUUID(0x100 + uint64(index))
		taskID := directedFaultUUID(0x200 + uint64(index))
		finalTaskID = taskID
		timestamp := domain.Timestamp(
			time.Date(
				2026,
				time.August,
				11,
				12,
				10,
				index,
				0,
				time.UTC,
			).Format(time.RFC3339),
		)
		signed := harness.taskEvent(
			t,
			leader,
			eventID,
			taskID,
			timestamp,
			"directed "+test.name+" recovery",
		)
		applyUnderDirectedFault(
			t,
			harness,
			leader,
			target,
			test.rule,
			test.closesConnection,
			signed,
			taskID,
		)
		harness.waitForTask(t, nodes, taskID)
		assertMeshViewsConverged(t, nodes)
	}

	for _, candidate := range nodes {
		harness.stopNode(t, candidate)
	}
	for _, candidate := range nodes {
		harness.startNode(t, candidate, false)
	}
	reopened := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, reopened)
	harness.waitForLeader(t, reopened)
	harness.waitForTask(t, reopened, finalTaskID)
	for _, candidate := range reopened {
		if err := candidate.node.state.VerifyCommitmentHistory(
			meshTestContext(t),
		); err != nil {
			t.Fatalf(
				"VerifyCommitmentHistory(reopened %s): %v",
				candidate.identity.deviceID,
				err,
			)
		}
	}
	assertMeshViewsConverged(t, reopened)
}

func applyUnderDirectedFault(
	t *testing.T,
	harness *secureMeshHarness,
	leader *secureMeshNode,
	target *secureMeshNode,
	rule faultnet.Rule,
	closesConnection bool,
	signed event.SignedEvent,
	taskID domain.UUIDv7,
) {
	t.Helper()
	link := faultnet.Link{
		From: leader.identity.deviceID,
		To:   target.identity.deviceID,
	}
	harness.topology.setPartition(target.identity.deviceID, true)
	partitioned := true
	defer func() {
		if partitioned {
			harness.topology.setPartition(target.identity.deviceID, false)
		}
	}()
	handle, err := harness.faults.Install(link, rule)
	if err != nil {
		t.Fatalf("Install(%+v): %v", rule, err)
	}
	removed := false
	defer func() {
		if !removed {
			_ = harness.faults.Remove(handle)
		}
	}()
	harness.topology.setPartition(target.identity.deviceID, false)
	partitioned = false

	if !leader.node.IsLeader() {
		t.Fatalf("one directed fault %+v displaced the healthy-quorum leader", rule)
	}
	result, err := leader.node.Apply(meshTestContext(t), signed)
	if err != nil {
		t.Fatalf("Apply under directed fault %+v: %v", rule, err)
	}
	if result.Duplicate ||
		result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply under directed fault %+v = %#v", rule, result)
	}
	targetView, err := target.node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("View(faulted target under %+v): %v", rule, err)
	}
	if viewContainsTask(targetView, taskID) {
		t.Fatalf("faulted target applied task %s before healing %+v", taskID, rule)
	}
	// Force Raft to establish another replication stream after the entry
	// committed. This prevents ordinary follower lag from satisfying the
	// assertion even if a fault implementation accidentally becomes a no-op.
	harness.topology.setPartition(target.identity.deviceID, true)
	partitioned = true
	before, err := harness.faults.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(disconnected, %+v): %v", rule, err)
	}
	if before.Hits == ^uint64(0) ||
		before.ConnectionsHit == ^uint64(0) {
		t.Fatalf("directed fault %+v saturated its counters", rule)
	}
	harness.topology.setPartition(target.identity.deviceID, false)
	partitioned = false
	hitContext, cancelHit := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelHit()
	if err := harness.faults.WaitForHits(
		hitContext,
		handle,
		before.Hits+1,
	); err != nil {
		t.Fatalf("WaitForHits(fresh connection, %+v): %v", rule, err)
	}
	reconnected, err := harness.faults.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(reconnected, %+v): %v", rule, err)
	}
	if reconnected.ConnectionsHit <= before.ConnectionsHit {
		t.Fatalf(
			"directed fault %+v hit no fresh connection: before=%+v after=%+v",
			rule,
			before,
			reconnected,
		)
	}

	blockedUntil := time.Now().Add(time.Second)
	for time.Now().Before(blockedUntil) {
		targetView, viewErr := target.node.View(meshTestContext(t))
		if viewErr != nil {
			t.Fatalf("View(faulted target under %+v): %v", rule, viewErr)
		}
		if viewContainsTask(targetView, taskID) {
			t.Fatalf(
				"faulted target applied task %s through active %+v",
				taskID,
				rule,
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !leader.node.IsLeader() {
		t.Fatalf("directed fault %+v displaced the healthy-quorum leader", rule)
	}
	if err := harness.faults.Remove(handle); err != nil {
		t.Fatalf("Remove(%+v): %v", rule, err)
	}
	removed = true
	after, err := harness.faults.Snapshot(handle)
	if err != nil {
		t.Fatalf("Snapshot(removed %+v): %v", rule, err)
	}
	if closesConnection && after.ClosedConnections == 0 {
		t.Fatalf("destructive fault %+v closed no connection: %+v", rule, after)
	}
}

func directedFaultTarget(
	t *testing.T,
	nodes []*secureMeshNode,
	leader *secureMeshNode,
) *secureMeshNode {
	t.Helper()
	for _, candidate := range nodes {
		if candidate != leader {
			return candidate
		}
	}
	t.Fatal("directed-fault mesh has no follower")
	return nil
}

func directedFaultUUID(sequence uint64) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"018f47de-89ab-7def-b123-%012x",
		sequence,
	))
}
