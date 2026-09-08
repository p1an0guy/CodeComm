package consensus

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
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

func TestFSMHaltsAfterDurablyApplyingFloorAboveBinary(t *testing.T) {
	root := t.TempDir()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	level := event.MaxSupportedApplyLevel + 1
	initial.Projections.Devices[0].MaxApplyLevel = level
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

	values := policy.DefaultValues()
	values.ClusterMinApplyLevel = int64(level)
	expectedVersion := uint64(1)
	raise := nodeTestSignedEntityCommand(
		t,
		privateKey,
		deviceID,
		event.ActorHuman,
		event.KindPolicyChanged,
		string(nodeTestSessionID),
		&expectedVersion,
		map[string]any{
			"checkpoint_events":                values.CheckpointEvents,
			"checkpoint_interval_seconds":      values.CheckpointIntervalSeconds,
			"lease_min_ttl_seconds":            values.LeaseMinTTLSeconds,
			"lease_default_ttl_seconds":        values.LeaseDefaultTTLSeconds,
			"lease_max_ttl_seconds":            values.LeaseMaxTTLSeconds,
			"agent_claim_limit":                values.AgentClaimLimit,
			"agent_lease_limit":                values.AgentLeaseLimit,
			"device_claim_limit":               values.DeviceClaimLimit,
			"device_lease_limit":               values.DeviceLeaseLimit,
			"advertisement_interval_seconds":   values.AdvertisementIntervalSeconds,
			"audit_depth_per_device_per_epoch": values.AuditDepthPerDevicePerEpoch,
			"max_member_devices":               values.MaxMemberDevices,
			"max_active_agent_sessions":        values.MaxActiveAgentSessions,
			"cluster_min_apply_level":          values.ClusterMinApplyLevel,
		},
		nodeTestEventID1,
		1,
	)
	result, err := node.Apply(testContext(t), raise)
	if !errors.Is(err, reducer.ErrApplyLevelUnsupported) {
		t.Fatalf("Apply(floor raise) = (%#v, %v)", result, err)
	}
	if !errors.Is(node.FatalError(), reducer.ErrApplyLevelUnsupported) {
		t.Fatalf("FatalError() = %v", node.FatalError())
	}

	view, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("decodeStateView(): %v", err)
	}
	if !errors.Is(
		decoded.Reducer.ValidateBinaryApplyLevel(),
		reducer.ErrApplyLevelUnsupported,
	) ||
		view.Heads.ResultIndex != 1 ||
		view.LastRaftAppliedLogIndex == nil {
		t.Fatalf("floor-raising entry was not durable: %#v", view)
	}
	lookup, found, err := node.state.LookupCommandResult(
		testContext(t),
		nodeTestEventID1,
	)
	if err != nil || !found ||
		lookup.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"LookupCommandResult(floor raise) = (%#v, %t, %v)",
			lookup,
			found,
			err,
		)
	}
	lastIndex, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(before rejected command): %v", err)
	}
	next := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"must not enqueue after floor halt",
	)
	if _, err := node.Apply(testContext(t), next); !errors.Is(
		err,
		reducer.ErrApplyLevelUnsupported,
	) {
		t.Fatalf("Apply(after floor halt) error = %v", err)
	}
	afterIndex, err := node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(after rejected command): %v", err)
	}
	if afterIndex != lastIndex {
		t.Fatalf("halted node appended Raft log: %d -> %d", lastIndex, afterIndex)
	}
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
