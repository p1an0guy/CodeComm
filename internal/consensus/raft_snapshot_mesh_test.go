package consensus

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const secureMeshRaftSnapshotChild = "raft-snapshot"

func TestSecureMeshCompactedSnapshotCatchupAndPromotion(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshRaftSnapshotChild {
		runSecureMeshCompactedSnapshotCatchupAndPromotion(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshCompactedSnapshotCatchupAndPromotion$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshRaftSnapshotChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("Raft snapshot mesh child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("Raft snapshot mesh child failed: %v\n%s", err, output)
	}
}

func runSecureMeshCompactedSnapshotCatchupAndPromotion(t *testing.T) {
	harness := newSecureMeshHarnessWithOptions(t, secureMeshHarnessOptions{
		compactSnapshots: true,
	})
	defer harness.close(t)

	leader := harness.waitForLeader(t, harness.runningNodes())
	harness.waitForCommittedConfiguration(t, harness.runningNodes())
	target := raftSnapshotMeshFollower(t, harness, leader)
	harness.changeMeshSuffrage(t, leader, target, raft.Nonvoter)
	targetLastIndex, err := target.node.stable.LastIndex()
	if err != nil {
		t.Fatalf("target LastIndex before lag: %v", err)
	}
	harness.stopNode(t, target)

	prefix := harness.taskEvent(
		t,
		leader,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		"snapshot prefix",
	)
	if result, err := leader.node.Apply(meshTestContext(t), prefix); err != nil ||
		result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(snapshot prefix) = (%#v, %v)", result, err)
	}
	checkpointRecord := harness.checkpointRecord(t, leader)
	checkpoint := harness.checkpointEvent(t, leader, checkpointRecord)
	if result, err := leader.node.Apply(
		meshTestContext(t),
		checkpoint,
	); err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(snapshot checkpoint) = (%#v, %v)", result, err)
	}
	checkpointView, err := leader.node.View(meshTestContext(t))
	if err != nil || checkpointView.LastRaftAppliedLogIndex == nil {
		t.Fatalf("checkpoint View() = (%#v, %v)", checkpointView, err)
	}
	checkpointIndex := *checkpointView.LastRaftAppliedLogIndex
	if checkpointIndex <= targetLastIndex {
		t.Fatalf(
			"checkpoint index = %d, want after lagging target index %d",
			checkpointIndex,
			targetLastIndex,
		)
	}
	if err := leader.node.Snapshot(meshTestContext(t)); err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	var compacted raft.Log
	if err := leader.node.stable.GetLog(
		targetLastIndex+1,
		&compacted,
	); !errors.Is(err, raft.ErrLogNotFound) {
		t.Fatalf(
			"leader retained lagging target successor at %d: %v",
			targetLastIndex+1,
			err,
		)
	}

	harness.startNode(t, target, false)
	harness.waitForTask(t, harness.runningNodes(), nodeTestTaskID1)
	firstInstall := waitForRaftSnapshotInstall(t, target)
	if firstInstall.SourceServerID != leader.identity.deviceID ||
		firstInstall.BaselineCommandLogIndex == nil ||
		*firstInstall.BaselineCommandLogIndex != checkpointIndex ||
		firstInstall.SnapshotIndex < checkpointIndex {
		t.Fatalf("installed snapshot baseline = %#v", firstInstall)
	}
	assertMeshViewsConverged(t, harness.runningNodes())
	waitForSnapshotReplicationResume(
		t,
		leader,
		target,
		firstInstall.SnapshotIndex,
	)
	install := waitForRaftSnapshotInstall(t, target)
	firstInstall.SnapshotID = install.SnapshotID
	if !reflect.DeepEqual(firstInstall, install) {
		t.Fatalf(
			"snapshot retry changed semantic install metadata:\n got  %#v\n want %#v",
			install,
			firstInstall,
		)
	}

	leader = harness.waitForLeader(t, harness.runningNodes())
	tail := harness.taskEvent(
		t,
		leader,
		meshFinalEventID,
		meshFinalTaskID,
		meshFinalTimestamp,
		"post-snapshot tail",
	)
	if result, err := leader.node.Apply(meshTestContext(t), tail); err != nil ||
		result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(post-snapshot tail) = (%#v, %v)", result, err)
	}
	waitForSnapshotMeshTask(t, harness, meshFinalTaskID)
	assertMeshRaftCommandBinding(t, target, tail)

	harness.stopNode(t, target)
	harness.startNode(t, target, false)
	waitForSnapshotMeshTask(t, harness, meshFinalTaskID)
	reopenedInstall := waitForRaftSnapshotInstall(t, target)
	if !reflect.DeepEqual(reopenedInstall, install) {
		t.Fatalf(
			"snapshot install changed across restart:\n got  %#v\n want %#v",
			reopenedInstall,
			install,
		)
	}
	assertMeshRaftCommandBinding(t, target, tail)
	if err := target.node.state.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(after restart): %v", err)
	}

	leader = harness.waitForLeader(t, harness.runningNodes())
	harness.changeMeshSuffrage(t, leader, target, raft.Voter)
	assertMeshViewsConverged(t, harness.runningNodes())
}

func raftSnapshotMeshFollower(
	t *testing.T,
	harness *secureMeshHarness,
	leader *secureMeshNode,
) *secureMeshNode {
	t.Helper()
	for _, candidate := range harness.runningNodes() {
		if candidate != leader {
			return candidate
		}
	}
	t.Fatal("secure mesh has no snapshot catch-up target")
	return nil
}

func waitForRaftSnapshotInstall(
	t *testing.T,
	target *secureMeshNode,
) store.RaftSnapshotInstallRecord {
	t.Helper()
	var result store.RaftSnapshotInstallRecord
	awaitMeshCondition(
		t,
		20*time.Second,
		"durable Raft snapshot install",
		func() bool {
			var (
				found bool
				err   error
			)
			result, found, err = target.node.state.
				VerifiedRaftSnapshotInstall(context.Background())
			return err == nil && found
		},
	)
	return result
}

func waitForSnapshotReplicationResume(
	t *testing.T,
	leader *secureMeshNode,
	target *secureMeshNode,
	snapshotIndex uint64,
) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if target.node.raft.CommitIndex() >= snapshotIndex {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if target.node.raft.CommitIndex() < snapshotIndex {
		t.Fatalf(
			"target commit index = %d after snapshot %d; leader=%v target=%v",
			target.node.raft.CommitIndex(),
			snapshotIndex,
			leader.node.raft.Stats(),
			target.node.raft.Stats(),
		)
	}
	if err := leader.node.Barrier(meshTestContext(t)); err != nil {
		t.Fatalf("post-snapshot replication barrier: %v", err)
	}
	awaitMeshCondition(
		t,
		15*time.Second,
		"post-snapshot barrier replication",
		func() bool {
			return target.node.raft.AppliedIndex() > snapshotIndex
		},
	)
}

func waitForSnapshotMeshTask(
	t *testing.T,
	harness *secureMeshHarness,
	taskID domain.UUIDv7,
) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		ready := true
		for _, candidate := range harness.runningNodes() {
			view, err := candidate.node.View(context.Background())
			if err != nil || !viewContainsTask(view, taskID) {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	logSecureMeshDiagnostics(t, harness)
	t.Fatalf("timed out waiting for snapshot-mesh task %s", taskID)
}

func assertMeshRaftCommandBinding(
	t *testing.T,
	target *secureMeshNode,
	signed event.SignedEvent,
) {
	t.Helper()
	view, err := target.node.View(meshTestContext(t))
	if err != nil ||
		view.CurrentTerm == nil ||
		view.LastRaftAppliedLogIndex == nil {
		t.Fatalf("target command watermark = (%#v, %v)", view, err)
	}
	if err := target.node.state.VerifyRaftCommand(
		context.Background(),
		*view.CurrentTerm,
		*view.LastRaftAppliedLogIndex,
		signed,
	); err != nil {
		t.Fatalf("VerifyRaftCommand(post-snapshot tail): %v", err)
	}
}
