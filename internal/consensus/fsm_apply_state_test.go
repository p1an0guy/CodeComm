package consensus

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/store"
)

func TestFSMApplyStateMatchesDurableAcceptedAndRejectedResults(
	t *testing.T,
) {
	root := t.TempDir()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	node, err := OpenSingleNode(context.Background(), SingleNodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		Clock:        nodeTestClock(),
		RaftConfig:   nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	waitForNodeLeader(t, node)

	first := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"cached accepted task",
	)
	result, err := node.Apply(testContext(t), first)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(accepted) = (%#v, %v)", result, err)
	}
	assertFSMApplyStateMatchesStore(t, node.fsm)

	reusedSequence := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		1,
		"cached rejected task",
	)
	result, err = node.Apply(testContext(t), reusedSequence)
	if err != nil || result.Outcome.Status != store.OutcomeRejected {
		t.Fatalf("Apply(rejected) = (%#v, %v)", result, err)
	}
	assertFSMApplyStateMatchesStore(t, node.fsm)
}

func assertFSMApplyStateMatchesStore(t *testing.T, fsm *FSM) {
	t.Helper()
	view, err := fsm.store.View(context.Background())
	if err != nil {
		t.Fatalf("Store.View(): %v", err)
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("decodeStateView(): %v", err)
	}

	fsm.applyMu.Lock()
	cached := fsm.applyState
	fsm.applyMu.Unlock()

	lastApplied := uint64(0)
	if view.LastRaftAppliedLogIndex != nil {
		lastApplied = *view.LastRaftAppliedLogIndex
	}
	cachedHeads := cached.heads
	cachedHeads.PreviousResultHash = store.Digest{}
	if cached.sessionID != view.SessionID ||
		cached.workspaceID != view.WorkspaceID ||
		cached.recoveryGeneration != view.RecoveryGeneration ||
		cachedHeads != view.Heads ||
		cached.lastRaftAppliedLogIndex != lastApplied ||
		cached.admissionRevision != view.AdmissionRevision ||
		!reflect.DeepEqual(cached.reducer, decoded.Reducer) ||
		!reflect.DeepEqual(cached.admission, decoded.Admission) ||
		!reflect.DeepEqual(
			cached.identityPublicKeys,
			decoded.identityPublicKeys,
		) {
		t.Fatalf(
			"FSM apply cache differs from durable state\ncache: %#v\nview: %#v",
			cached,
			view,
		)
	}
}
