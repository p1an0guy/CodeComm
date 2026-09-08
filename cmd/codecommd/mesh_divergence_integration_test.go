package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func TestDaemonProductionMeshIntegrityProofs(t *testing.T) {
	if os.Getenv(daemonMeshIntegrationChildMarker) != "1" {
		runDaemonMeshIntegrationChild(
			t,
			"^TestDaemonProductionMeshIntegrityProofs$",
		)
		return
	}
	registerDaemonIntegrationChildResult(t)
	_, preflightListeners := reserveDaemonMeshIntegrationListeners(t, 1)
	if err := preflightListeners[0].Close(); err != nil {
		t.Fatalf("close mesh integrity preflight listener: %v", err)
	}

	t.Run("checkpoint divergence halts before persistence", func(t *testing.T) {
		nodes := newDaemonMeshIntegrityFixture(t)
		statuses := exerciseDaemonFollowerProposalForwarding(t, nodes)
		waitForDaemonMeshIntegrationStableHeads(t, nodes, 500*time.Millisecond)

		leaderID := domain.DeviceID(
			*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
				Consensus.LeaderDeviceID,
		)
		leader := daemonMeshIntegrationNodeByID(t, nodes, leaderID)
		follower := daemonMeshIntegrationFollower(t, nodes, leaderID)
		leaderNode := requireDaemonMeshConsensusNode(t, leader)
		followerNode := requireDaemonMeshConsensusNode(t, follower)

		before := daemonMeshNodeView(t, followerNode)
		if before.Heads.ResultIndex == 0 ||
			before.Heads.ChainIndex == 0 {
			t.Fatal("checkpoint-divergence fixture has empty heads")
		}
		corruptAccumulator := before.Heads.ProjectionAccumulator
		corruptAccumulator[0] ^= 0xff
		tamperDaemonMeshSQLite(
			t,
			follower.statePath,
			`UPDATE consensus_state
			    SET projection_accumulator = ?1
			  WHERE singleton = 1;`,
			corruptAccumulator[:],
		)
		corrupted := daemonMeshNodeView(t, followerNode)
		expected := before
		expected.Heads.ProjectionAccumulator = corruptAccumulator
		if !reflect.DeepEqual(corrupted, expected) {
			t.Fatalf(
				"post-corruption view changed beyond projection accumulator:\n got: %#v\nwant: %#v",
				corrupted,
				expected,
			)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			daemonMeshIntegrationTimeout,
		)
		checkpoint, err := leaderNode.ForceCheckpoint(ctx)
		cancel()
		if err != nil {
			t.Fatalf("ForceCheckpoint(): %v", err)
		}
		// The FSM cache retains its last verified cut; the store transaction
		// detects a live SQLite rewrite before persisting the checkpoint.
		requireDaemonMeshExpectedHalt(
			t,
			follower,
			consensus.ErrFSMHalted,
			store.ErrApplyConflict,
		)
		assertDaemonMeshCheckpointNotPersisted(
			t,
			follower.statePath,
			corrupted,
			checkpoint.Record.CheckpointEventID,
		)

		follower.listener = listenDaemonMeshIntegrationEndpoint(
			t,
			follower.peerEndpoint,
		)
		follower.start(t, nodes)
		requireDaemonMeshExpectedHalt(
			t,
			follower,
			consensus.ErrSnapshotAnchorCoverage,
		)
		assertDaemonMeshCheckpointNotPersisted(
			t,
			follower.statePath,
			corrupted,
			checkpoint.Record.CheckpointEventID,
		)
	})

	t.Run("covered row corruption halts snapshot", func(t *testing.T) {
		nodes := newDaemonMeshIntegrityFixture(t)
		statuses := exerciseDaemonFollowerProposalForwarding(t, nodes)
		leaderID := domain.DeviceID(
			*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
				Consensus.LeaderDeviceID,
		)
		leaderNode := requireDaemonMeshConsensusNode(
			t,
			daemonMeshIntegrationNodeByID(t, nodes, leaderID),
		)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			daemonMeshIntegrationTimeout,
		)
		checkpoint, err := leaderNode.ForceCheckpoint(ctx)
		cancel()
		if err != nil {
			t.Fatalf("ForceCheckpoint(): %v", err)
		}
		waitForDaemonMeshIntegrationCluster(
			t,
			nodes,
			func(statuses []ui.Snapshot) bool {
				for _, status := range statuses {
					if status.Session.EventChainIndex !=
						checkpoint.Record.CoveredChainIndex+1 ||
						status.Session.ResultIndex !=
							checkpoint.Record.CoveredResultIndex+1 ||
						status.Session.AppliedRaftIndex == nil ||
						*status.Session.AppliedRaftIndex <
							checkpoint.AppliedLogIndex {
						return false
					}
				}
				return true
			},
		)

		target := daemonMeshIntegrationFollower(t, nodes, leaderID)
		targetNode := requireDaemonMeshConsensusNode(t, target)
		tamperDaemonMeshSQLite(
			t,
			target.statePath,
			`UPDATE tasks
			    SET title = title || ?1
			  WHERE task_id = ?2;`,
			" corrupt",
			string(daemonTestTaskID),
		)

		_, localState, ready := target.meshCapture.snapshot()
		if !ready {
			t.Fatal("target local state is unavailable")
		}
		emitted := 0
		_, err = localState.ExportLogicalSnapshotRecords(
			context.Background(),
			store.LogicalSnapshotExportOptions{
				CheckpointEventID: checkpoint.Record.CheckpointEventID,
				SignerDeviceID:    target.deviceID,
			},
			func(context.Context, logicalsnapshot.Record) error {
				emitted++
				return nil
			},
		)
		if !errors.Is(err, store.ErrLogicalSnapshotIntegrity) ||
			!errors.Is(err, store.ErrCommandResultCorrupt) {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() error = %v, want logical-snapshot and command-result integrity errors",
				err,
			)
		}
		if emitted != 0 {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() emitted %d records before integrity failure",
				emitted,
			)
		}

		ctx, cancel = context.WithTimeout(
			context.Background(),
			daemonMeshIntegrationTimeout,
		)
		err = targetNode.Snapshot(ctx)
		cancel()
		if err == nil {
			t.Fatal("Snapshot() succeeded after covered-row corruption")
		}
		fatalErr := targetNode.FatalError()
		if !errors.Is(fatalErr, consensus.ErrFSMHalted) ||
			!errors.Is(fatalErr, store.ErrCommandResultCorrupt) {
			t.Fatalf(
				"FatalError() = %v, want FSM halt wrapping command-result corruption",
				fatalErr,
			)
		}
		requireDaemonMeshExpectedHalt(
			t,
			target,
			consensus.ErrFSMHalted,
			store.ErrCommandResultCorrupt,
		)
	})
}

func newDaemonMeshIntegrityFixture(
	t *testing.T,
) []*daemonMeshIntegrationNode {
	t.Helper()
	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 4)
	root := t.TempDir()
	credentialNow := func() time.Time { return time.Now().UTC() }
	nodes := newDaemonMeshIntegrationNodes(
		t,
		root,
		selectedAddress,
		listeners[:3],
		credentialNow,
	)
	retained := newDaemonMeshIntegrationRetainedNode(
		t,
		root,
		selectedAddress,
		listeners[3],
		credentialNow,
	)
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(
			t,
			append(nodes, retained)...,
		)
		for _, node := range nodes {
			clear(node.privateKey)
		}
		clear(retained.privateKey)
	})

	initial := daemonMeshIntegrationInitialState(
		t,
		nodes,
		daemonMeshIntegrationRetainedMember(t, retained),
	)
	bootstrap := daemonMeshIntegrationBootstrap(nodes)
	for _, node := range nodes {
		initializeDaemonMeshIntegrationStore(t, node.statePath, initial)
		seedDaemonMeshIntegrationRaft(
			t,
			node.consensusDir,
			node.deviceID,
			bootstrap,
		)
	}
	for _, node := range nodes {
		node.start(t, nodes)
	}
	voterIDs := daemonMeshIntegrationDeviceIDs(nodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	return nodes
}

func requireDaemonMeshConsensusNode(
	t *testing.T,
	node *daemonMeshIntegrationNode,
) *consensus.Node {
	t.Helper()
	consensusNode, ready := node.meshCapture.consensusNode()
	if !ready {
		t.Fatalf("consensus node %s is unavailable", node.deviceID)
	}
	return consensusNode
}

func daemonMeshNodeView(
	t *testing.T,
	node *consensus.Node,
) store.StateView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	view, err := node.View(ctx)
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	return view
}

func requireDaemonMeshExpectedHalt(
	t *testing.T,
	node *daemonMeshIntegrationNode,
	causes ...error,
) {
	t.Helper()
	select {
	case <-node.exited:
	case <-time.After(daemonMeshIntegrationTimeout):
		t.Fatalf("daemon %s did not exit after integrity halt", node.deviceID)
	}
	node.running = false
	if node.cancel != nil {
		node.cancel()
		node.cancel = nil
	}
	node.listener = nil
	if node.exitErr == nil {
		t.Fatalf("daemon %s exited without an error", node.deviceID)
	}
	for _, cause := range causes {
		if !errors.Is(node.exitErr, cause) {
			t.Fatalf(
				"runDaemon(%s) error = %v, want %v",
				node.deviceID,
				node.exitErr,
				cause,
			)
		}
	}
}

func assertDaemonMeshCheckpointNotPersisted(
	t *testing.T,
	path string,
	expected store.StateView,
	checkpointEventID domain.UUIDv7,
) {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("reopen halted store: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Errorf("close halted store: %v", err)
		}
	}()
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(halted store): %v", err)
	}
	if view.Heads != expected.Heads ||
		!reflect.DeepEqual(
			view.LastRaftAppliedLogIndex,
			expected.LastRaftAppliedLogIndex,
		) ||
		view.ProjectionStateDigest != expected.ProjectionStateDigest ||
		!reflect.DeepEqual(view.ProjectionRows, expected.ProjectionRows) {
		t.Fatalf(
			"halted store changed durable state:\n got: %#v\nwant: %#v",
			view,
			expected,
		)
	}
	if _, found, err := database.AppliedCheckpoint(
		context.Background(),
		checkpointEventID,
	); err != nil || found {
		t.Fatalf(
			"AppliedCheckpoint(halted) = (found=%t, err=%v), want absent",
			found,
			err,
		)
	}
	if _, found, err := database.LookupCommandResult(
		context.Background(),
		checkpointEventID,
	); err != nil || found {
		t.Fatalf(
			"LookupCommandResult(halted) = (found=%t, err=%v), want absent",
			found,
			err,
		)
	}
}

func tamperDaemonMeshSQLite(
	t *testing.T,
	path string,
	statement string,
	args ...any,
) {
	t.Helper()
	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite)
	if err != nil {
		t.Fatalf("sqlite.OpenConn(%s): %v", path, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close SQLite tamper connection: %v", err)
		}
	}()
	if err := sqlitex.Execute(
		conn,
		"PRAGMA busy_timeout = 5000;",
		nil,
	); err != nil {
		t.Fatalf("configure SQLite tamper connection: %v", err)
	}
	if err := sqlitex.Execute(
		conn,
		statement,
		&sqlitex.ExecOptions{Args: args},
	); err != nil {
		t.Fatalf("tamper SQLite: %v", err)
	}
	if changed := conn.Changes(); changed != 1 {
		t.Fatalf("tamper SQLite changed %d rows, want 1", changed)
	}
}
