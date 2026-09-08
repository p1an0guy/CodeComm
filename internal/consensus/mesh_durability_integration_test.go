package consensus

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

const secureMeshRaftSQLiteDurabilityChild = "raft-sqlite-durability"

func TestSecureMeshRaftCommitSQLiteReplayDurability(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshRaftSQLiteDurabilityChild {
		runSecureMeshRaftCommitSQLiteReplayDurability(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshRaftCommitSQLiteReplayDurability$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshRaftSQLiteDurabilityChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("Raft/SQLite durability child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("Raft/SQLite durability child failed: %v\n%s", err, output)
	}
}

func runSecureMeshRaftCommitSQLiteReplayDurability(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	nodes := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, nodes)
	leader := harness.waitForLeader(t, nodes)
	for _, candidate := range nodes {
		if err := candidate.node.WaitForLeader(meshTestContext(t)); err != nil {
			t.Fatalf(
				"WaitForLeader(%s): %v",
				candidate.identity.deviceID,
				err,
			)
		}
	}
	assertMeshViewsConverged(t, nodes)
	target := secureMeshDurabilityFollower(t, nodes, leader)
	signed := harness.taskEvent(
		t,
		leader,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		"committed before SQLite apply",
	)
	injected := errors.New("injected pre-SQLite apply failure")

	// Hold the target before its next FSM apply. The other two voters can
	// commit while this follower's durable SQLite cut remains observable.
	target.node.fsm.applyMu.Lock()
	applyLocked := true
	defer func() {
		if applyLocked {
			target.node.fsm.applyMu.Unlock()
		}
	}()
	before, err := target.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("target View(before commit): %v", err)
	}
	if viewContainsTask(before, nodeTestTaskID1) {
		t.Fatal("target contained durability task before proposal")
	}

	type applyOutcome struct {
		result store.ApplyResult
		err    error
	}
	applyDone := make(chan applyOutcome, 1)
	applyContext := meshTestContext(t)
	go func() {
		result, applyErr := leader.node.Apply(applyContext, signed)
		applyDone <- applyOutcome{result: result, err: applyErr}
	}()
	var applied applyOutcome
	select {
	case applied = <-applyDone:
	case <-applyContext.Done():
		t.Fatalf("leader Apply(): %v", applyContext.Err())
	}
	if applied.err != nil ||
		applied.result.Duplicate ||
		applied.result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("leader Apply() = (%#v, %v)", applied.result, applied.err)
	}
	leaderView, err := leader.node.View(meshTestContext(t))
	if err != nil || leaderView.LastRaftAppliedLogIndex == nil {
		t.Fatalf("leader View(after commit) = (%#v, %v)", leaderView, err)
	}
	commandIndex := *leaderView.LastRaftAppliedLogIndex

	var committed raft.Log
	awaitMeshCondition(
		t,
		10*time.Second,
		"target durable committed Raft command",
		func() bool {
			if target.node.raft.CommitIndex() < commandIndex {
				return false
			}
			return target.node.stable.GetLog(commandIndex, &committed) == nil
		},
	)
	if committed.Index != commandIndex ||
		committed.Type != raft.LogCommand ||
		!bytes.Equal(committed.Data, signed.CanonicalBytes()) {
		t.Fatalf("target committed log = %#v, want exact command", committed)
	}
	blocked, err := target.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("target View(while FSM blocked): %v", err)
	}
	if !reflect.DeepEqual(blocked, before) {
		t.Fatal("target SQLite state advanced while FSM apply was blocked")
	}

	normalClock := target.node.fsm.clock
	clockCalls := 0
	target.node.fsm.clock = func() (domain.Timestamp, int64, error) {
		clockCalls++
		if clockCalls == 1 {
			return "", 0, injected
		}
		return normalClock()
	}
	target.node.fsm.applyMu.Unlock()
	applyLocked = false

	awaitMeshCondition(
		t,
		10*time.Second,
		"target fatal pre-SQLite apply failure",
		func() bool {
			return errors.Is(target.node.FatalError(), injected)
		},
	)
	failed, err := target.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("target View(after failed apply): %v", err)
	}
	if !reflect.DeepEqual(failed, before) {
		t.Fatal("failed FSM apply changed the target SQLite transaction")
	}
	if clockCalls != 1 {
		t.Fatalf("injected clock calls = %d, want 1", clockCalls)
	}

	harness.stopNode(t, target)
	harness.startNode(t, target, false)
	restarted := harness.runningNodes()
	harness.waitForCommittedConfiguration(t, restarted)
	harness.waitForLeader(t, restarted)
	harness.waitForTask(t, restarted, nodeTestTaskID1)

	replayed, err := target.node.state.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("target View(after replay): %v", err)
	}
	if replayed.LastRaftAppliedLogIndex == nil ||
		*replayed.LastRaftAppliedLogIndex < commandIndex {
		t.Fatalf(
			"target replay watermark = %v, want at least %d",
			replayed.LastRaftAppliedLogIndex,
			commandIndex,
		)
	}
	if err := target.node.state.VerifyRaftCommand(
		meshTestContext(t),
		committed.Term,
		commandIndex,
		signed,
	); err != nil {
		t.Fatalf("VerifyRaftCommand(replayed): %v", err)
	}
	for _, candidate := range restarted {
		if err := candidate.node.state.VerifyCommitmentHistory(
			meshTestContext(t),
		); err != nil {
			t.Fatalf(
				"VerifyCommitmentHistory(%s): %v",
				candidate.identity.deviceID,
				err,
			)
		}
	}
	assertMeshViewsConverged(t, restarted)
}

func secureMeshDurabilityFollower(
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
	t.Fatal("secure mesh has no durability follower")
	return nil
}
