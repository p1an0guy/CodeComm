package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

const (
	daemonSettledReplicationChildMarker = "CODECOMM_TEST_SETTLED_REPLICATION_CHILD"
	daemonSettledSnapshotChildMarker    = "CODECOMM_TEST_SETTLED_SNAPSHOT_CHILD"
	daemonTwoDeviceRecoveryEventID      = domain.UUIDv7(
		"018f47de-89ab-7def-8123-e123456789ab",
	)
	daemonTwoDeviceRecoveryTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-f123456789ab",
	)
)

var daemonSettledSnapshotProcessTimeout = daemonMeshTimeouts.snapshotChild

func TestDaemonSettledNonvoterReplicatesAcrossAuthorityHandoffsAndRestart(
	t *testing.T,
) {
	if os.Getenv(daemonSettledReplicationChildMarker) != "1" {
		runDaemonSettledReplicationChild(t)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonSettledReplicationIntegration(t)
}

func TestDaemonSettledAutomaticLogicalSnapshotFallbackPersistsAcrossRestart(
	t *testing.T,
) {
	if os.Getenv(daemonSettledSnapshotChildMarker) != "1" {
		runDaemonSettledSnapshotFallbackChild(t)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonSettledSnapshotFallbackIntegration(t)
}

func runDaemonSettledReplicationIntegration(t *testing.T) {
	t.Helper()
	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 4)
	root := t.TempDir()
	credentialClock := newDaemonMeshIntegrationCredentialClock(
		time.Now().UTC().Truncate(time.Second),
	)
	allNodes := newDaemonMeshIntegrationNodes(
		t,
		root,
		selectedAddress,
		listeners,
		credentialClock.Now,
	)
	voters := append(
		[]*daemonMeshIntegrationNode(nil),
		allNodes[:3]...,
	)
	settled := allNodes[3]
	coverage := &daemonSettledCoverageCollector{
		privateKeys: make(
			map[domain.DeviceID]ed25519.PrivateKey,
			len(voters),
		),
	}
	for _, voter := range voters {
		coverage.privateKeys[voter.deviceID] = voter.privateKey
		voter.coverage = coverage
	}
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, allNodes...)
		for _, node := range allNodes {
			clear(node.privateKey)
		}
	})

	settledMember := device.Device{
		ID:   settled.deviceID,
		Role: device.RoleOwner,
		IdentityPublicKey: bytes.Clone(
			settled.privateKey.Public().(ed25519.PublicKey),
		),
		DaemonVersion: "0.1.0",
		MaxApplyLevel: 1,
		Status:        device.StatusActive,
		EntityVersion: 1,
	}
	initial := daemonMeshIntegrationInitialState(
		t,
		voters,
		settledMember,
	)
	bootstrap := daemonMeshIntegrationBootstrap(voters)
	for _, voter := range voters {
		initializeDaemonMeshIntegrationStore(t, voter.statePath, initial)
		seedDaemonMeshIntegrationRaft(
			t,
			voter.consensusDir,
			voter.deviceID,
			bootstrap,
		)
	}
	initializeDaemonMeshIntegrationStore(t, settled.statePath, initial)
	enterDaemonSettledReplicationMode(
		t,
		settled.statePath,
		daemonMeshIntegrationDeviceIDs(voters),
	)

	for _, voter := range voters {
		voter.start(t, allNodes)
	}
	voterIDs := daemonMeshIntegrationDeviceIDs(voters)
	statuses := waitForDaemonMeshIntegrationCluster(
		t,
		voters,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	waitForDaemonMeshContentCredentials(t, voters)
	leaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	leader := daemonMeshIntegrationNodeByID(t, voters, leaderID)
	target := daemonMeshIntegrationFollower(t, voters, leaderID)
	targetNodes := []*daemonMeshIntegrationNode{target}
	targetIDs := daemonMeshIntegrationDeviceIDs(targetNodes)
	authorityTwoNodes := []*daemonMeshIntegrationNode{leader}
	authorityTwoIDs := daemonMeshIntegrationDeviceIDs(authorityTwoNodes)
	removedVoters := make([]*daemonMeshIntegrationNode, 0, 2)
	for _, voter := range voters {
		if voter != target {
			removedVoters = append(removedVoters, voter)
		}
	}

	settledCertificate := authorizeDaemonSettledCredential(
		t,
		voters,
		leader,
		settled,
		credentialClock.Now(),
		credentialauthorization.RoleOwner,
	)
	bootstrapResultIndex := bootstrapDaemonSettledReplica(
		t,
		selectedAddress,
		leader,
		settled,
		settledCertificate,
	)
	clearDaemonTLSCertificate(&settledCertificate)

	settled.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.ResultIndex == bootstrapResultIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	awaitDaemonSettledEventReplication(
		t,
		settled,
		bootstrapResultIndex,
	)
	authorityOneTaskID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-7123456789ab",
	)
	authorityOneEventID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-8123456789ab",
	)
	leaderNode, ready := leader.meshCapture.consensusNode()
	if !ready {
		t.Fatal("authority-v1 leader consensus node was not captured")
	}
	authorityOneContext, cancelAuthorityOne := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	authorityOneResult, err := leaderNode.Apply(
		authorityOneContext,
		daemonSettledTaskEvent(
			t,
			leader.privateKey,
			leader.deviceID,
			authorityOneEventID,
			authorityOneTaskID,
			"replicate through production under authority v1",
		),
	)
	cancelAuthorityOne()
	if err != nil ||
		authorityOneResult.Outcome.Status != store.OutcomeAccepted ||
		authorityOneResult.Outcome.Code != "accepted" {
		t.Fatalf(
			"authority-v1 task apply = (%+v, %v)",
			authorityOneResult,
			err,
		)
	}
	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		voters,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
				)
		},
	)
	authorityOneResultIndex := statuses[0].Session.ResultIndex
	authorityOneChainIndex := statuses[0].Session.EventChainIndex
	awaitDaemonSettledSSEConvergence(
		t,
		settled,
		authorityOneResultIndex,
		authorityOneChainIndex,
		voterIDs,
		authorityOneTaskID,
	)
	settled.stop(t)

	operator := dialDaemonMeshIntegrationOperator(t, leader.localEndpoint)
	changeContext, cancelChange := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	changeResult, err := operator.SetVoters(
		changeContext,
		ui.SetVotersRequest{
			ExpectedVoterSetVersion: 1,
			VoterDeviceIDs:          authorityTwoIDs,
		},
	)
	cancelChange()
	closeErr := operator.Close()
	if err != nil {
		t.Fatalf("SetVoters(): %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close set-voters client: %v", closeErr)
	}
	if changeResult.Status != store.OutcomeAccepted ||
		changeResult.Code != "accepted" ||
		changeResult.Duplicate {
		t.Fatalf("SetVoters() result = %+v", changeResult)
	}

	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		authorityTwoNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				authorityTwoIDs,
			) &&
				daemonMeshIntegrationTarget(statuses, 2, authorityTwoIDs)
		},
	)
	postHandoffLeaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	postHandoffLeader := daemonMeshIntegrationNodeByID(
		t,
		authorityTwoNodes,
		postHandoffLeaderID,
	)
	postHandoffNode, ready := postHandoffLeader.meshCapture.consensusNode()
	if !ready {
		t.Fatal("post-handoff leader consensus node was not captured")
	}
	taskContext, cancelTask := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	taskResult, err := postHandoffNode.Apply(
		taskContext,
		daemonTestTaskEvent(
			t,
			target.privateKey,
			target.deviceID,
		),
	)
	cancelTask()
	if err != nil ||
		taskResult.Outcome.Status != store.OutcomeAccepted ||
		taskResult.Outcome.Code != "accepted" {
		t.Fatalf("post-handoff task apply = (%+v, %v)", taskResult, err)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		authorityTwoNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				authorityTwoIDs,
			) &&
				daemonMeshIntegrationTarget(
					statuses,
					2,
					authorityTwoIDs,
				) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)

	operator = dialDaemonMeshIntegrationOperator(
		t,
		postHandoffLeader.localEndpoint,
	)
	changeContext, cancelChange = context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	changeResult, err = operator.SetVoters(
		changeContext,
		ui.SetVotersRequest{
			ExpectedVoterSetVersion: 2,
			VoterDeviceIDs:          targetIDs,
		},
	)
	cancelChange()
	closeErr = operator.Close()
	if err != nil {
		t.Fatalf("SetVoters(second handoff): %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close second set-voters client: %v", closeErr)
	}
	if changeResult.Status != store.OutcomeAccepted ||
		changeResult.Code != "accepted" ||
		changeResult.Duplicate {
		t.Fatalf("SetVoters(second handoff) result = %+v", changeResult)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, targetIDs) &&
				daemonMeshIntegrationTarget(statuses, 3, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	assertDaemonSettledRejectsPriorAuthoritySigner(
		t,
		target,
		settled,
		leader,
		authorityOneResultIndex,
		3,
	)

	stopDaemonMeshIntegrationNodes(t, removedVoters...)
	settled.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		settled.peerEndpoint,
	)
	settled.start(t, allNodes)
	twoDeviceStatuses := waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled, target},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 2 &&
				statuses[0].Session.ResultIndex ==
					statuses[1].Session.ResultIndex &&
				statuses[0].Session.EventChainIndex ==
					statuses[1].Session.EventChainIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 3, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	exerciseDaemonTwoDeviceDegradedRun(
		t,
		allNodes,
		target,
		settled,
		credentialClock,
		twoDeviceStatuses,
		targetIDs,
		authorityOneTaskID,
		3,
	)

	stopDaemonMeshIntegrationNodes(t, target, settled)
	assertDaemonSettledReplicationDurableState(
		t,
		target,
		settled,
		leader.deviceID,
		target.deviceID,
		authorityOneResultIndex,
		3,
	)
}

func awaitDaemonSettledEventReplication(
	t *testing.T,
	node *daemonMeshIntegrationNode,
	resultIndex uint64,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	for time.Now().Before(deadline) {
		if daemonSettledEventReplicationReached(node, resultIndex) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(
		"settled SSE replication did not reach result %d",
		resultIndex,
	)
}

func daemonSettledEventReplicationReached(
	node *daemonMeshIntegrationNode,
	resultIndex uint64,
) bool {
	if node == nil {
		return false
	}
	runtime := node.contentPeers.Load()
	if runtime == nil {
		return false
	}
	runtime.workersMu.Lock()
	workers := make([]*daemonContentPeerWorker, 0, len(runtime.workers))
	for _, worker := range runtime.workers {
		workers = append(workers, worker)
	}
	runtime.workersMu.Unlock()
	for _, worker := range workers {
		if worker.eventStreamReplicatedResult.Load() >= resultIndex {
			return true
		}
	}
	return false
}

func awaitDaemonSettledSSEConvergence(
	t *testing.T,
	node *daemonMeshIntegrationNode,
	resultIndex uint64,
	chainIndex uint64,
	voterIDs []domain.DeviceID,
	taskID domain.UUIDv7,
) {
	t.Helper()
	deadline := time.Now().Add(
		daemonContentPeerReplicationFallback / 2,
	)
	var (
		lastStatus ui.Snapshot
		lastErr    error
	)
	for time.Now().Before(deadline) {
		if !daemonSettledEventReplicationReached(node, resultIndex) {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		lastStatus, lastErr = readDaemonMeshIntegrationStatus(
			node.localEndpoint,
		)
		statuses := []ui.Snapshot{lastStatus}
		if lastErr == nil &&
			lastStatus.Session.ResultIndex == resultIndex &&
			lastStatus.Session.EventChainIndex == chainIndex &&
			lastStatus.Session.AppliedRaftIndex == nil &&
			daemonMeshIntegrationTarget(statuses, 1, voterIDs) &&
			daemonSettledTasksConverged(statuses, taskID) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(
		"settled SSE catch-up missed result %d before fallback: status=%s error=%v",
		resultIndex,
		daemonMeshIntegrationStatusSummary([]ui.Snapshot{lastStatus}),
		lastErr,
	)
}

func exerciseDaemonTwoDeviceDegradedRun(
	t *testing.T,
	allNodes []*daemonMeshIntegrationNode,
	voter, settled *daemonMeshIntegrationNode,
	clock *daemonMeshIntegrationCredentialClock,
	baseline []ui.Snapshot,
	voterIDs []domain.DeviceID,
	authorityOneTaskID domain.UUIDv7,
	authorityVersion uint64,
) {
	t.Helper()
	if len(allNodes) < 2 ||
		voter == nil ||
		settled == nil ||
		clock == nil ||
		len(baseline) != 2 ||
		len(voterIDs) != 1 ||
		voterIDs[0] != voter.deviceID ||
		authorityVersion < 1 {
		t.Fatal("invalid two-device degraded-run fixture")
	}
	var revoked *daemonMeshIntegrationNode
	for _, candidate := range allNodes {
		if candidate != voter && candidate != settled {
			revoked = candidate
			break
		}
	}
	if revoked == nil {
		t.Fatal("two-device degraded run has no removed nonvoter")
	}
	before, err := readDaemonMeshIntegrationStatus(settled.localEndpoint)
	if err != nil {
		t.Fatalf("read settled baseline: %v", err)
	}
	provider, _, ready := voter.meshCapture.snapshot()
	if !ready || provider == nil {
		t.Fatal("sole voter content credential provider is unavailable")
	}
	certificate, err := provider()
	if err != nil || len(certificate.Certificate) != 1 {
		clearDaemonTLSCertificate(&certificate)
		t.Fatalf("read sole voter content credential: %v", err)
	}
	parsed, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	clearDaemonTLSCertificate(&certificate)
	if err != nil || parsed.Binding.DeviceID != voter.deviceID {
		t.Fatalf("parse sole voter content credential: %v", err)
	}

	stopDaemonMeshIntegrationNodes(t, voter, settled)
	clock.Set(parsed.NotAfter.Add(time.Second))
	settled.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		settled.peerEndpoint,
	)
	settled.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			if len(statuses) != 1 {
				return false
			}
			status := statuses[0]
			return status.Consensus.State == "settled" &&
				status.Consensus.Role == "nonvoter" &&
				status.Consensus.StrongWrites == "waiting" &&
				status.Consensus.LeaderDeviceID == nil &&
				status.Session.AppliedRaftIndex == nil &&
				status.Session.EventChainIndex ==
					before.Session.EventChainIndex &&
				status.Session.ResultIndex ==
					before.Session.ResultIndex &&
				daemonMeshIntegrationTarget(
					statuses,
					authorityVersion,
					voterIDs,
				) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	waitForDaemonMeshContentCredentialUnavailable(t, settled)

	operator := dialDaemonMeshIntegrationOperator(t, settled.localEndpoint)
	proposalContext, cancelProposal := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	_, proposalErr := operator.RevokePeer(
		proposalContext,
		ui.RevokePeerRequest{
			DeviceID:                revoked.deviceID,
			ExpectedEntityVersion:   1,
			ExpectedVoterSetVersion: authorityVersion,
			VoterDeviceIDs:          voterIDs,
			Reason:                  "removed device retired during degraded run",
		},
	)
	cancelProposal()
	if closeErr := operator.Close(); closeErr != nil {
		t.Fatalf("close isolated settled operator: %v", closeErr)
	}
	if proposalErr == nil {
		t.Fatal("settled nonvoter committed while its sole voter was offline")
	}
	queued := waitForDaemonSettledOutboxCount(t, settled, 1)
	if queued[0].Kind != event.KindMembershipDeviceRevoked ||
		queued[0].OriginDeviceID != settled.deviceID {
		t.Fatalf("isolated settled outbox = %+v", queued[0])
	}
	isolated, err := readDaemonMeshIntegrationStatus(settled.localEndpoint)
	if err != nil {
		t.Fatalf("read isolated settled status: %v", err)
	}
	if isolated.Session.EventChainIndex != before.Session.EventChainIndex ||
		isolated.Session.ResultIndex != before.Session.ResultIndex ||
		isolated.Consensus.StrongWrites != "waiting" ||
		isolated.Consensus.LeaderDeviceID != nil {
		t.Fatalf("isolated settled status changed authority: %+v", isolated)
	}

	voter.listener = listenDaemonMeshIntegrationEndpoint(t, voter.peerEndpoint)
	voter.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{voter, settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 2 &&
				statuses[0].Consensus.State == "ready" &&
				statuses[0].Consensus.Role == "leader" &&
				statuses[0].Consensus.StrongWrites == "available" &&
				statuses[1].Consensus.State == "settled" &&
				statuses[1].Consensus.Role == "nonvoter" &&
				statuses[1].Consensus.StrongWrites == "waiting" &&
				daemonMeshIntegrationTarget(
					statuses,
					authorityVersion,
					voterIDs,
				) &&
				daemonMeshIntegrationMemberStatus(
					statuses,
					revoked.deviceID,
					device.StatusRevoked,
					2,
				) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	waitForDaemonMeshContentCredentialEpoch(
		t,
		[]*daemonMeshIntegrationNode{voter, settled},
		parsed.Binding.Epoch+1,
	)
	waitForDaemonSettledOutboxCount(t, settled, 0)
	_, settledState, ready := settled.meshCapture.snapshot()
	if !ready {
		t.Fatal("recovered settled local state is unavailable")
	}
	resolved, found, err := settledState.LookupRequest(
		context.Background(),
		queued[0].ClientInstanceID,
		queued[0].RequestID,
	)
	if err != nil ||
		!found ||
		resolved.State != store.LocalRequestResolved ||
		resolved.Outcome == nil ||
		resolved.Outcome.Status != store.OutcomeAccepted ||
		resolved.Outcome.Code != "accepted" {
		t.Fatalf("recovered queued command = (%+v, %t, %v)", resolved, found, err)
	}
	connection := openReadyDaemonMeshPeersClient(t, settled, voter, clock.Now)
	if err := connection.Close(); err != nil {
		t.Fatalf("close recovered two-device content client: %v", err)
	}

	recoveryEvent := daemonSettledTaskEventAtSequence(
		t,
		voter.privateKey,
		voter.deviceID,
		daemonTwoDeviceRecoveryEventID,
		daemonTwoDeviceRecoveryTaskID,
		"commit after sole voter returns",
		2,
	)
	applyContext, cancelApply := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	result, err := applyDaemonSettledEventWithLeaderRetry(
		applyContext,
		[]*daemonMeshIntegrationNode{voter},
		recoveryEvent,
	)
	cancelApply()
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != "accepted" {
		t.Fatalf("post-recovery task apply = (%+v, %v)", result, err)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{voter, settled},
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationTarget(
				statuses,
				authorityVersion,
				voterIDs,
			) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
					daemonTwoDeviceRecoveryTaskID,
				)
		},
	)
}

func waitForDaemonMeshContentCredentialUnavailable(
	t *testing.T,
	node *daemonMeshIntegrationNode,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	for time.Now().Before(deadline) {
		if _, err := daemonMeshContentCredentialEpoch(node); err != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("content credential remained available on %s", node.deviceID)
}

func waitForDaemonSettledOutboxCount(
	t *testing.T,
	node *daemonMeshIntegrationNode,
	want int,
) []store.OutboxRecord {
	t.Helper()
	if node == nil || want < 0 {
		t.Fatal("invalid settled outbox wait")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var (
		last    []store.OutboxRecord
		lastErr error
	)
	for time.Now().Before(deadline) {
		_, local, ready := node.meshCapture.snapshot()
		if ready {
			last, lastErr = local.OutboxRecords(context.Background())
			if lastErr == nil && len(last) == want {
				return last
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf(
		"settled outbox count on %s = %d, want %d: %v",
		node.deviceID,
		len(last),
		want,
		lastErr,
	)
	return nil
}

func runDaemonSettledSnapshotFallbackIntegration(t *testing.T) {
	t.Helper()
	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 5)
	root := t.TempDir()
	credentialClock := newDaemonMeshIntegrationCredentialClock(
		time.Now().UTC().Truncate(time.Second),
	)
	allNodes := newDaemonMeshIntegrationNodes(
		t,
		root,
		selectedAddress,
		listeners,
		credentialClock.Now,
	)
	voters := append(
		[]*daemonMeshIntegrationNode(nil),
		allNodes[:3]...,
	)
	target := allNodes[3]
	settled := allNodes[4]
	var targetCoverageCalls atomic.Uint64
	nonvoterStageReached := make(chan struct{})
	releasePromotion := make(chan struct{})
	promotionReleased := false
	defer func() {
		if !promotionReleased {
			close(releasePromotion)
		}
	}()
	raftParticipants := append(
		append(
			[]*daemonMeshIntegrationNode(nil),
			voters...,
		),
		target,
	)
	coverage := &daemonSettledCoverageCollector{
		privateKeys: make(
			map[domain.DeviceID]ed25519.PrivateKey,
			len(raftParticipants),
		),
		afterCollect: func(requirement canonicalcoverage.Requirement) {
			if requirement.VoterSet.VoterSetVersion != 2 ||
				targetCoverageCalls.Add(1) != 2 {
				return
			}
			close(nonvoterStageReached)
			<-releasePromotion
		},
	}
	for _, participant := range raftParticipants {
		coverage.privateKeys[participant.deviceID] = participant.privateKey
		participant.coverage = coverage
	}
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, allNodes...)
		for _, node := range allNodes {
			clear(node.privateKey)
		}
	})

	settledMember := device.Device{
		ID:   settled.deviceID,
		Role: device.RoleEditor,
		IdentityPublicKey: bytes.Clone(
			settled.privateKey.Public().(ed25519.PublicKey),
		),
		DaemonVersion: "0.1.0",
		MaxApplyLevel: 1,
		Status:        device.StatusActive,
		EntityVersion: 1,
	}
	targetMember := device.Device{
		ID:   target.deviceID,
		Role: device.RoleEditor,
		IdentityPublicKey: bytes.Clone(
			target.privateKey.Public().(ed25519.PublicKey),
		),
		DaemonVersion: "0.1.0",
		MaxApplyLevel: 1,
		Status:        device.StatusActive,
		EntityVersion: 1,
	}
	initial := daemonMeshIntegrationInitialState(
		t,
		voters,
		settledMember,
	)
	initial.Projections.Devices = append(
		initial.Projections.Devices,
		targetMember,
	)
	sort.Slice(initial.Projections.Devices, func(left, right int) bool {
		return initial.Projections.Devices[left].ID <
			initial.Projections.Devices[right].ID
	})
	initial.Projections.AuditCounters = append(
		initial.Projections.AuditCounters,
		auditcounter.Counter{DeviceID: target.deviceID},
	)
	sort.Slice(
		initial.Projections.AuditCounters,
		func(left, right int) bool {
			return initial.Projections.AuditCounters[left].DeviceID <
				initial.Projections.AuditCounters[right].DeviceID
		},
	)
	bootstrap := daemonMeshIntegrationBootstrap(voters)
	for _, participant := range raftParticipants {
		initializeDaemonMeshIntegrationStore(
			t,
			participant.statePath,
			initial,
		)
		seedDaemonMeshIntegrationRaft(
			t,
			participant.consensusDir,
			participant.deviceID,
			bootstrap,
		)
	}
	targetStore, err := store.Open(
		context.Background(),
		store.Options{Path: target.statePath},
	)
	if err != nil {
		t.Fatalf("open staging nonvoter state: %v", err)
	}
	storeDaemonTestConfiguration(
		t,
		targetStore,
		daemonMeshIntegrationDeviceIDs(voters),
		nil,
	)
	if err := targetStore.Close(); err != nil {
		t.Fatalf("close staging nonvoter state: %v", err)
	}
	initializeDaemonMeshIntegrationStore(t, settled.statePath, initial)
	enterDaemonSettledReplicationMode(
		t,
		settled.statePath,
		daemonMeshIntegrationDeviceIDs(voters),
	)

	for _, voter := range voters {
		voter.start(t, allNodes)
	}
	voterIDs := daemonMeshIntegrationDeviceIDs(voters)
	statuses := waitForDaemonMeshIntegrationCluster(
		t,
		voters,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	waitForDaemonMeshContentCredentials(t, voters)
	leaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	leader := daemonMeshIntegrationNodeByID(t, voters, leaderID)
	targetNodes := []*daemonMeshIntegrationNode{target}
	targetIDs := daemonMeshIntegrationDeviceIDs(targetNodes)
	removedVoters := append([]*daemonMeshIntegrationNode(nil), voters...)

	settledCertificate := authorizeDaemonSettledCredential(
		t,
		voters,
		leader,
		settled,
		credentialClock.Now(),
		credentialauthorization.RoleEditor,
	)
	defer clearDaemonTLSCertificate(&settledCertificate)
	bootstrapResultIndex := bootstrapDaemonSettledReplica(
		t,
		selectedAddress,
		leader,
		settled,
		settledCertificate,
	)

	settled.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.ResultIndex == bootstrapResultIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs)
		},
	)
	authorityOneTaskID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-7123456789ab",
	)
	authorityOneEventID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-8123456789ab",
	)
	if _, ready := leader.meshCapture.consensusNode(); !ready {
		t.Fatal("snapshot-fallback authority-v1 leader was not captured")
	}
	applyContext, cancelApply := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	authorityOneResult, err := applyDaemonSettledEventWithLeaderRetry(
		applyContext,
		voters,
		daemonSettledTaskEvent(
			t,
			leader.privateKey,
			leader.deviceID,
			authorityOneEventID,
			authorityOneTaskID,
			"anchor snapshot fallback cursor",
		),
	)
	cancelApply()
	if err != nil ||
		authorityOneResult.Outcome.Status != store.OutcomeAccepted ||
		authorityOneResult.Outcome.Code != "accepted" {
		t.Fatalf(
			"snapshot-fallback anchor apply = (%+v, %v)",
			authorityOneResult,
			err,
		)
	}
	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		voters,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
				)
		},
	)
	staleResultIndex := statuses[0].Session.ResultIndex
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.ResultIndex == staleResultIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
				)
		},
	)
	settled.stop(t)

	backlogContext, cancelBacklog := context.WithTimeout(
		context.Background(),
		2*daemonMeshIntegrationTimeout,
	)
	var backlogResultIndex uint64
	for index := 0; index < replication.MaxBatchResults; index++ {
		result, applyErr := applyDaemonSettledEventWithLeaderRetry(
			backlogContext,
			voters,
			daemonSettledTaskEventAtSequence(
				t,
				leader.privateKey,
				leader.deviceID,
				daemonSettledSnapshotFallbackEventID(t, index),
				authorityOneTaskID,
				"force bounded authority handoff",
				uint64(index)+2,
			),
		)
		if applyErr != nil ||
			result.Outcome.Status != store.OutcomeRejected ||
			result.Outcome.Code != "entity_already_exists" {
			cancelBacklog()
			t.Fatalf(
				"snapshot-fallback backlog apply %d = (%+v, %v)",
				index,
				result,
				applyErr,
			)
		}
		backlogResultIndex = result.Heads.ResultIndex
	}
	cancelBacklog()
	if backlogResultIndex < staleResultIndex+replication.MaxBatchResults {
		t.Fatalf(
			"snapshot-fallback backlog cursor = %d after %d, want at least %d",
			backlogResultIndex,
			staleResultIndex,
			staleResultIndex+replication.MaxBatchResults,
		)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		voters,
		func(statuses []ui.Snapshot) bool {
			if !daemonMeshIntegrationClusterReady(statuses, voterIDs) ||
				!daemonMeshIntegrationTarget(statuses, 1, voterIDs) {
				return false
			}
			for _, status := range statuses {
				if status.Session.ResultIndex < backlogResultIndex {
					return false
				}
			}
			return true
		},
	)
	target.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.LocalDeviceID ==
					string(target.deviceID) &&
				statuses[0].Consensus.VoterSetVersion == 1 &&
				statuses[0].Consensus.ActivatedVoterSetVersion == 1 &&
				sameDaemonMeshIntegrationIDs(
					statuses[0].Consensus.LiveVoterDeviceIDs,
					voterIDs,
				) &&
				len(statuses[0].Consensus.LiveNonvoterDeviceIDs) == 0
		},
	)

	operator := dialDaemonMeshIntegrationOperator(t, leader.localEndpoint)
	changeContext, cancelChange := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	changeResult, err := operator.SetVoters(
		changeContext,
		ui.SetVotersRequest{
			ExpectedVoterSetVersion: 1,
			VoterDeviceIDs:          targetIDs,
		},
	)
	cancelChange()
	closeErr := operator.Close()
	if err != nil {
		t.Fatalf("SetVoters(snapshot fallback): %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close snapshot-fallback set-voters client: %v", closeErr)
	}
	if changeResult.Status != store.OutcomeAccepted ||
		changeResult.Code != "accepted" ||
		changeResult.Duplicate {
		t.Fatalf(
			"SetVoters(snapshot fallback) result = %+v",
			changeResult,
		)
	}
	select {
	case <-nonvoterStageReached:
	case <-time.After(daemonMeshIntegrationTimeout):
		t.Fatal("target did not reach the proven nonvoter stage")
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		raftParticipants,
		func(statuses []ui.Snapshot) bool {
			if !daemonMeshIntegrationClusterReady(statuses, voterIDs) {
				return false
			}
			for _, status := range statuses {
				if status.Consensus.VoterSetVersion != 2 ||
					status.Consensus.ActivatedVoterSetVersion != 1 ||
					!sameDaemonMeshIntegrationIDs(
						status.Consensus.TargetVoterDeviceIDs,
						targetIDs,
					) ||
					!sameDaemonMeshIntegrationIDs(
						status.Consensus.ActivatedVoterDeviceIDs,
						voterIDs,
					) ||
					!sameDaemonMeshIntegrationIDs(
						status.Consensus.LiveNonvoterDeviceIDs,
						targetIDs,
					) {
					return false
				}
			}
			return true
		},
	)
	close(releasePromotion)
	promotionReleased = true

	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, targetIDs) &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs)
		},
	)
	activatedResultIndex := statuses[0].Session.ResultIndex
	if activatedResultIndex <= backlogResultIndex {
		t.Fatalf(
			"activated cursor = %d, backlog cursor = %d",
			activatedResultIndex,
			backlogResultIndex,
		)
	}
	stopDaemonMeshIntegrationNodes(t, removedVoters...)

	contentContext, cancelContent := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancelContent()
	contentConnection, err := dialDaemonMeshExternalContentClient(
		contentContext,
		settledCertificate,
		selectedAddress,
		target,
	)
	if err != nil {
		t.Fatalf("dial snapshot-fallback source: %v", err)
	}
	contentConnectionClosed := false
	defer func() {
		if !contentConnectionClosed {
			_ = contentConnection.Close()
		}
	}()
	if _, err := contentConnection.client.Session(contentContext); err != nil {
		t.Fatalf("bind snapshot-fallback source: %v", err)
	}
	if _, err := contentConnection.client.Replication(
		contentContext,
		staleResultIndex,
	); !errors.Is(err, contenthttp.ErrReplicationSnapshotRequired) {
		t.Fatalf(
			"replication after stale cursor error = %v, want snapshot_required",
			err,
		)
	}
	snapshotRoot := waitForDaemonSettledLogicalSnapshot(
		t,
		contentContext,
		contentConnection.client,
		target.deviceID,
		target.privateKey.Public().(ed25519.PublicKey),
		activatedResultIndex,
	)
	snapshotInput := snapshotRoot.Unsigned().Input()
	contentCloseErr := contentConnection.Close()
	contentConnectionClosed = true
	if contentCloseErr != nil {
		t.Fatalf(
			"close snapshot-fallback source: %v",
			contentCloseErr,
		)
	}
	cancelContent()
	if snapshotInput.ResultIndex <= staleResultIndex {
		t.Fatalf(
			"snapshot cursor = %d, stale cursor = %d",
			snapshotInput.ResultIndex,
			staleResultIndex,
		)
	}

	if _, ready := target.meshCapture.consensusNode(); !ready {
		t.Fatal("snapshot-fallback authority-v2 leader was not captured")
	}
	tailContext, cancelTail := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	tailResult, err := applyDaemonSettledEventWithLeaderRetry(
		tailContext,
		targetNodes,
		daemonTestTaskEvent(
			t,
			target.privateKey,
			target.deviceID,
		),
	)
	cancelTail()
	if err != nil ||
		tailResult.Outcome.Status != store.OutcomeAccepted ||
		tailResult.Outcome.Code != "accepted" ||
		tailResult.Heads.ResultIndex <= snapshotInput.ResultIndex {
		t.Fatalf(
			"post-snapshot tail apply = (%+v, %v), snapshot cursor %d",
			tailResult,
			err,
			snapshotInput.ResultIndex,
		)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, targetIDs) &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs) &&
				statuses[0].Session.ResultIndex >=
					tailResult.Heads.ResultIndex &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)

	settled.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		settled.peerEndpoint,
	)
	settled.start(t, allNodes)
	finalStatuses := waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{target, settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 2 &&
				statuses[0].Session.ResultIndex ==
					statuses[1].Session.ResultIndex &&
				statuses[0].Session.EventChainIndex ==
					statuses[1].Session.EventChainIndex &&
				statuses[1].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	finalResultIndex := finalStatuses[0].Session.ResultIndex
	finalChainIndex := finalStatuses[0].Session.EventChainIndex
	if finalResultIndex <= snapshotInput.ResultIndex {
		t.Fatalf(
			"settled cursor %d did not resume after snapshot %d",
			finalResultIndex,
			snapshotInput.ResultIndex,
		)
	}

	settled.stop(t)
	installedSnapshotRoot := readDaemonSettledSnapshotBaseline(
		t,
		settled.statePath,
	)
	installedSnapshotInput := installedSnapshotRoot.Unsigned().Input()
	if installedSnapshotInput.SessionID != snapshotInput.SessionID ||
		installedSnapshotInput.WorkspaceID != snapshotInput.WorkspaceID ||
		installedSnapshotInput.RecoveryGeneration !=
			snapshotInput.RecoveryGeneration ||
		installedSnapshotInput.SignerDeviceID != target.deviceID ||
		installedSnapshotInput.AuthorityVersion !=
			snapshotInput.AuthorityVersion ||
		installedSnapshotInput.ResultIndex < snapshotInput.ResultIndex ||
		installedSnapshotInput.ChainIndex < snapshotInput.ChainIndex {
		t.Fatalf(
			"installed snapshot cut is not the observed cut or a successor:\nobserved=%+v\ninstalled=%+v",
			snapshotInput,
			installedSnapshotInput,
		)
	}
	if err := logicalsnapshot.VerifyRoot(
		installedSnapshotRoot,
		target.privateKey.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("verify installed snapshot authority: %v", err)
	}
	settled.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		settled.peerEndpoint,
	)
	settled.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{target, settled},
		func(statuses []ui.Snapshot) bool {
			// The live authority may commit a scheduler result while the
			// settled replica is stopped for baseline inspection.
			return len(statuses) == 2 &&
				statuses[0].Session.ResultIndex >= finalResultIndex &&
				statuses[1].Session.ResultIndex ==
					statuses[0].Session.ResultIndex &&
				statuses[0].Session.EventChainIndex >= finalChainIndex &&
				statuses[1].Session.EventChainIndex ==
					statuses[0].Session.EventChainIndex &&
				statuses[1].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)

	stopDaemonMeshIntegrationNodes(t, settled, target)
	assertDaemonSettledSnapshotFallbackDurableState(
		t,
		target,
		settled,
		snapshotRoot,
		installedSnapshotRoot,
	)
}

func daemonSettledTaskEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	eventID, taskID domain.UUIDv7,
	title string,
) event.SignedEvent {
	t.Helper()
	return daemonSettledTaskEventAtSequence(
		t,
		privateKey,
		deviceID,
		eventID,
		taskID,
		title,
		1,
	)
}

func daemonSettledTaskEventAtSequence(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	eventID, taskID domain.UUIDv7,
	title string,
	originSequence uint64,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		deviceID,
		daemonTestSetupBootID,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding(): %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"priority": 2,
		"title":    title,
	})
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindTaskCreated,
			EntityID: event.StringEntityID(string(taskID)),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      daemonTestSessionID,
			WorkspaceID:    daemonTestWorkspaceID,
			CreatedAt:      daemonTestTimestamp,
			OriginSequence: originSequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func applyDaemonSettledEventWithLeaderRetry(
	ctx context.Context,
	nodes []*daemonMeshIntegrationNode,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	if ctx == nil || len(nodes) == 0 {
		return store.ApplyResult{}, errors.New(
			"invalid settled integration apply fixture",
		)
	}
	var lastErr error
	for ctx.Err() == nil {
		for _, candidate := range nodes {
			node, ready := candidate.meshCapture.consensusNode()
			if !ready || !node.IsLeader() {
				continue
			}
			result, err := node.Apply(ctx, signed)
			if err == nil {
				return result, nil
			}
			lastErr = err
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no Raft leader became available")
	}
	return store.ApplyResult{}, errors.Join(ctx.Err(), lastErr)
}

func daemonSettledSnapshotFallbackEventID(
	t *testing.T,
	index int,
) domain.UUIDv7 {
	t.Helper()
	eventID := domain.UUIDv7(fmt.Sprintf(
		"018f47de-89ab-7def-9234-%012x",
		index+1,
	))
	if index < 0 || !eventID.Valid() {
		t.Fatalf("invalid snapshot-fallback event ID at %d: %q", index, eventID)
	}
	return eventID
}

func waitForDaemonSettledLogicalSnapshot(
	t *testing.T,
	ctx context.Context,
	client *contenthttp.Client,
	signerDeviceID domain.DeviceID,
	signerPublicKey ed25519.PublicKey,
	minimumResultIndex uint64,
) logicalsnapshot.Root {
	t.Helper()
	if ctx == nil ||
		client == nil ||
		!signerDeviceID.Valid() ||
		len(signerPublicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid logical snapshot wait fixture")
	}
	var (
		lastInput logicalsnapshot.RootInput
		lastErr   error
	)
	for {
		root, err := client.LatestSnapshot(ctx)
		if err == nil {
			input := root.Unsigned().Input()
			lastInput = input
			if input.SessionID == daemonTestSessionID &&
				input.WorkspaceID == daemonTestWorkspaceID &&
				input.RecoveryGeneration == 0 &&
				input.SignerDeviceID == signerDeviceID &&
				input.AuthorityVersion == 2 &&
				input.ResultIndex >= minimumResultIndex &&
				input.DescriptorPageCount > 0 &&
				input.ChunkCount > 0 &&
				input.RecordCount > 0 {
				if err := logicalsnapshot.VerifyRoot(
					root,
					signerPublicKey,
				); err != nil {
					t.Fatalf(
						"verify published logical snapshot root: %v",
						err,
					)
				}
				return root
			}
			lastErr = errors.New("latest snapshot does not cover activation")
		} else if !errors.Is(err, contenthttp.ErrSnapshotUnavailable) {
			t.Fatalf("fetch latest logical snapshot: %v", err)
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			t.Fatalf(
				"logical snapshot publication timed out: %v; last root %+v; last error %v",
				ctx.Err(),
				lastInput,
				lastErr,
			)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func daemonSettledTasksConverged(
	statuses []ui.Snapshot,
	taskIDs ...domain.UUIDv7,
) bool {
	if len(statuses) == 0 || len(taskIDs) == 0 {
		return false
	}
	expected := make(map[string]struct{}, len(taskIDs))
	for _, taskID := range taskIDs {
		if !taskID.Valid() {
			return false
		}
		expected[string(taskID)] = struct{}{}
	}
	if len(expected) != len(taskIDs) {
		return false
	}
	for _, snapshot := range statuses {
		if snapshot.TaskTotal != uint64(len(expected)) ||
			snapshot.Truncated ||
			len(snapshot.Tasks) != len(expected) {
			return false
		}
		for _, task := range snapshot.Tasks {
			if _, found := expected[task.TaskID]; !found ||
				task.EntityVersion != 1 {
				return false
			}
		}
	}
	return daemonMeshIntegrationMutationConverged(statuses)
}

func enterDaemonSettledReplicationMode(
	t *testing.T,
	statePath string,
	voterIDs []domain.DeviceID,
) {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: statePath},
	)
	if err != nil {
		t.Fatalf("store.Open(settled setup): %v", err)
	}
	storeDaemonTestConfiguration(t, database, voterIDs, nil)
	_, enterErr := database.EnterSettledNonvoter(
		context.Background(),
		daemonMeshTimestamp(t, time.Now()),
	)
	closeErr := database.Close()
	if enterErr != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", enterErr)
	}
	if closeErr != nil {
		t.Fatalf("Close(settled setup): %v", closeErr)
	}
}

func authorizeDaemonSettledCredential(
	t *testing.T,
	voters []*daemonMeshIntegrationNode,
	leader, settled *daemonMeshIntegrationNode,
	now time.Time,
	expectedRole credentialauthorization.Role,
) tls.Certificate {
	t.Helper()
	return authorizeDaemonSettledCredentialWithSeed(
		t,
		voters,
		leader,
		settled,
		now,
		expectedRole,
		0xf1,
	)
}

func authorizeDaemonSettledCredentialWithSeed(
	t *testing.T,
	voters []*daemonMeshIntegrationNode,
	leader, settled *daemonMeshIntegrationNode,
	now time.Time,
	expectedRole credentialauthorization.Role,
	seedByte byte,
) tls.Certificate {
	t.Helper()
	if len(voters) == 0 ||
		leader == nil ||
		settled == nil ||
		now.IsZero() ||
		seedByte == 0 {
		t.Fatal("invalid settled credential fixture")
	}
	epochPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seedByte}, ed25519.SeedSize),
	)
	defer clear(epochPrivateKey)
	binding, err := credential.SignBinding(
		daemonTestSessionID,
		settled.deviceID,
		1,
		epochPrivateKey.Public().(ed25519.PublicKey),
		settled.privateKey,
	)
	if err != nil {
		t.Fatalf("SignBinding(settled): %v", err)
	}
	node, ready := leader.meshCapture.consensusNode()
	if !ready {
		t.Fatal("credential leader consensus node was not captured")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	var authorization credentialauthorization.Authorization
	for {
		authorization, err = node.RenewCredential(ctx, binding)
		if err == nil ||
			!errors.Is(
				err,
				consensus.ErrCredentialAuthorizationUnavailable,
			) {
			break
		}
		select {
		case <-ctx.Done():
			err = errors.Join(ctx.Err(), err)
		case <-time.After(25 * time.Millisecond):
			continue
		}
		break
	}
	cancel()
	if err != nil {
		t.Fatalf("RenewCredential(settled): %v", err)
	}
	if authorization.DeviceID != settled.deviceID ||
		authorization.Epoch != 1 ||
		authorization.Role != expectedRole ||
		authorization.AuthorityVoterSetVersion != 1 {
		t.Fatalf("settled credential authorization = %+v", authorization)
	}
	reference, err := credentialstore.EpochReference(
		daemonTestSessionID,
		settled.deviceID,
		1,
	)
	if err != nil {
		t.Fatalf("EpochReference(settled): %v", err)
	}
	if err := settled.credentials.Create(
		context.Background(),
		reference,
		epochPrivateKey,
	); err != nil {
		t.Fatalf("persist settled epoch key: %v", err)
	}
	waitForDaemonSettledCredential(t, voters, settled.deviceID, now)
	certificate, contentBinding, err :=
		transport.IssueContentCertificate(authorization, epochPrivateKey)
	if err != nil ||
		contentBinding.DeviceID != settled.deviceID ||
		contentBinding.Epoch != 1 {
		t.Fatalf(
			"IssueContentCertificate(settled) = (%+v, %v)",
			contentBinding,
			err,
		)
	}
	return certificate
}

func waitForDaemonSettledCredential(
	t *testing.T,
	voters []*daemonMeshIntegrationNode,
	settledID domain.DeviceID,
	now time.Time,
) {
	t.Helper()
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		readyCount := 0
		for _, voter := range voters {
			node, ready := voter.meshCapture.consensusNode()
			if !ready {
				lastErr = errors.New("voter consensus node unavailable")
				break
			}
			snapshot, err := node.PeerAdmissionSnapshot()
			if err != nil {
				lastErr = err
				break
			}
			if authorization, active :=
				snapshot.ActiveCredentialAuthorizationAt(
					settledID,
					now,
				); active &&
				authorization.AuthorityVoterSetVersion == 1 {
				readyCount++
			} else {
				lastErr = errors.New(
					"settled credential is not active",
				)
				break
			}
		}
		if readyCount == len(voters) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("settled credential did not become active: %v", lastErr)
}

func bootstrapDaemonSettledReplica(
	t *testing.T,
	selectedAddress netip.Addr,
	source, settled *daemonMeshIntegrationNode,
	certificate tls.Certificate,
) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	connection, err := dialDaemonMeshExternalContentClient(
		ctx,
		certificate,
		selectedAddress,
		source,
	)
	if err != nil {
		t.Fatalf("dial settled bootstrap source: %v", err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close settled bootstrap client: %v", err)
		}
	}()
	session, err := connection.client.Session(ctx)
	if err != nil ||
		session.SessionID() != daemonTestSessionID ||
		session.WorkspaceID() != daemonTestWorkspaceID ||
		session.ServerDeviceID() != source.deviceID {
		t.Fatalf("settled bootstrap session = (%+v, %v)", session, err)
	}
	replica, err := consensus.OpenSettledReplica(
		ctx,
		consensus.SettledReplicaOptions{
			StatePath:     settled.statePath,
			OriginBootID:  daemonTestVerifyBootID,
			LocalDeviceID: settled.deviceID,
			Clock:         consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(bootstrap): %v", err)
	}
	defer func() {
		if err := replica.Close(); err != nil {
			t.Errorf("close settled bootstrap replica: %v", err)
		}
	}()
	var resultIndex uint64
	for page := 0; page < daemonSettledReplicationPagesPerPass; page++ {
		batch, err := connection.client.Replication(ctx, resultIndex)
		if err != nil {
			t.Fatalf(
				"bootstrap replication after %d: %v",
				resultIndex,
				err,
			)
		}
		metadata := batch.Unsigned().Metadata()
		result, err := replica.ImportResultBatch(
			ctx,
			source.deviceID,
			batch,
		)
		if err != nil {
			t.Fatalf("ImportResultBatch(bootstrap): %v", err)
		}
		if result.Heads.ResultIndex <= resultIndex {
			t.Fatalf(
				"bootstrap result cursor did not advance: %d -> %d",
				resultIndex,
				result.Heads.ResultIndex,
			)
		}
		resultIndex = result.Heads.ResultIndex
		if resultIndex >= metadata.ServerAppliedResultIndex {
			progress, err := replica.ReplicationProgress(ctx)
			if err != nil {
				t.Fatalf("ReplicationProgress(bootstrap): %v", err)
			}
			if progress.Blocker != nil ||
				len(progress.Observations) != 1 ||
				progress.Observations[0].SignerDeviceID !=
					source.deviceID ||
				progress.Observations[0].AuthorityVersion != 1 {
				t.Fatalf("bootstrap progress = %+v", progress)
			}
			return resultIndex
		}
	}
	t.Fatal("settled bootstrap exceeded the bounded page count")
	return 0
}

func assertDaemonSettledReplicationDurableState(
	t *testing.T,
	source, settled *daemonMeshIntegrationNode,
	authorityOneSigner, terminalAuthoritySigner domain.DeviceID,
	offlineResultIndex, terminalAuthorityVersion uint64,
) {
	t.Helper()
	sourceStore, err := store.Open(
		context.Background(),
		store.Options{Path: source.statePath},
	)
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	defer func() { _ = sourceStore.Close() }()
	settledStore, err := store.Open(
		context.Background(),
		store.Options{Path: settled.statePath},
	)
	if err != nil {
		t.Fatalf("open settled store: %v", err)
	}
	defer func() { _ = settledStore.Close() }()

	sourceView, err := sourceStore.View(context.Background())
	if err != nil {
		t.Fatalf("source View(): %v", err)
	}
	settledView, err := settledStore.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("settled VerifiedSettledNonvoterView(): %v", err)
	}
	rowsEqual := reflect.DeepEqual(
		sourceView.ProjectionRows,
		settledView.ProjectionRows,
	)
	if sourceView.Heads != settledView.Heads ||
		sourceView.ProjectionStateDigest !=
			settledView.ProjectionStateDigest ||
		!rowsEqual {
		t.Fatalf(
			"settled durable logical state differs from authority source: heads=(%+v, %+v) digests=(%x, %x) rows_equal=%t",
			sourceView.Heads,
			settledView.Heads,
			sourceView.ProjectionStateDigest,
			settledView.ProjectionStateDigest,
			rowsEqual,
		)
	}
	if sourceView.LastRaftAppliedLogIndex == nil ||
		settledView.CurrentTerm != nil ||
		settledView.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"source/settled Raft provenance = (%v, %v, %v)",
			sourceView.LastRaftAppliedLogIndex,
			settledView.CurrentTerm,
			settledView.LastRaftAppliedLogIndex,
		)
	}
	if err := sourceStore.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(source): %v", err)
	}
	if err := settledStore.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(settled): %v", err)
	}
	mode, err := settledStore.ReplicaEvidenceMode(context.Background())
	if err != nil || mode != store.ReplicaEvidenceSettledNonvoter {
		t.Fatalf("settled evidence mode = (%q, %v)", mode, err)
	}
	progress, err := settledStore.SettledReplicationProgress(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("SettledReplicationProgress(): %v", err)
	}
	if progress.Blocker != nil || progress.Heads != settledView.Heads {
		t.Fatalf("settled progress = %+v", progress)
	}
	var sawAuthorityOne, sawTerminalAuthority bool
	for _, observation := range progress.Observations {
		switch {
		case observation.SignerDeviceID == authorityOneSigner &&
			observation.AuthorityVersion == 1:
			sawAuthorityOne = true
		case observation.SignerDeviceID == terminalAuthoritySigner &&
			observation.AuthorityVersion == terminalAuthorityVersion:
			sawTerminalAuthority = true
		case observation.AuthorityVersion > 1 &&
			observation.AuthorityVersion < terminalAuthorityVersion:
			t.Fatalf(
				"offline replica retained an intermediate-authority batch: %+v",
				observation,
			)
		}
	}
	if !sawAuthorityOne || !sawTerminalAuthority {
		t.Fatalf(
			"authority observations = %+v, want %s/v1 and %s/v%d",
			progress.Observations,
			authorityOneSigner,
			terminalAuthoritySigner,
			terminalAuthorityVersion,
		)
	}

	exported, found, err := settledStore.ExportResultRange(
		context.Background(),
		store.ResultRangeOptions{
			AfterResultIndex:          offlineResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: terminalAuthoritySigner,
		},
	)
	if err != nil || !found {
		t.Fatalf(
			"export multi-activation catch-up range = (found=%t, err=%v)",
			found,
			err,
		)
	}
	if exported.FromResultIndex != offlineResultIndex+1 ||
		exported.ToResultIndex != settledView.Heads.ResultIndex ||
		exported.Authority.VoterSetVersion != terminalAuthorityVersion ||
		!exported.Authority.Contains(terminalAuthoritySigner) {
		t.Fatalf("multi-activation catch-up range = %+v", exported)
	}
	activationCount := uint64(0)
	for index, encoded := range exported.Results {
		result, err := chain.DecodeResult(encoded)
		if err != nil {
			t.Fatalf("decode catch-up result %d: %v", index, err)
		}
		var proposal struct {
			Kind event.Kind `json:"kind"`
		}
		if err := json.Unmarshal(result.Proposal, &proposal); err != nil {
			t.Fatalf("decode catch-up proposal %d: %v", index, err)
		}
		if proposal.Kind == event.KindMembershipVoterSetActivated {
			activationCount++
		}
	}
	if activationCount != terminalAuthorityVersion-1 {
		t.Fatalf(
			"catch-up activation count = %d, want %d",
			activationCount,
			terminalAuthorityVersion-1,
		)
	}
	if _, err := os.Stat(settled.consensusDir); !os.IsNotExist(err) {
		t.Fatalf("settled runtime created Raft storage: %v", err)
	}
}

func assertDaemonSettledRejectsPriorAuthoritySigner(
	t *testing.T,
	source, settled, priorAuthority *daemonMeshIntegrationNode,
	afterResultIndex, terminalAuthorityVersion uint64,
) {
	t.Helper()
	if source == nil ||
		settled == nil ||
		priorAuthority == nil ||
		afterResultIndex == domain.MaxSafeInteger ||
		terminalAuthorityVersion < 2 {
		t.Fatal("invalid prior-authority rejection fixture")
	}
	sourceStore, err := store.Open(
		context.Background(),
		store.Options{Path: source.statePath},
	)
	if err != nil {
		t.Fatalf("open prior-authority rejection source: %v", err)
	}
	exported, found, exportErr := sourceStore.ExportResultRange(
		context.Background(),
		store.ResultRangeOptions{
			AfterResultIndex:          afterResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: source.deviceID,
		},
	)
	closeErr := sourceStore.Close()
	if exportErr != nil || !found || closeErr != nil {
		t.Fatalf(
			"export prior-authority rejection range = (found=%t, export_err=%v, close_err=%v)",
			found,
			exportErr,
			closeErr,
		)
	}
	if exported.Authority.VoterSetVersion != terminalAuthorityVersion ||
		exported.Authority.Contains(priorAuthority.deviceID) {
		t.Fatalf(
			"prior-authority rejection terminal authority = %+v",
			exported.Authority,
		)
	}
	unsigned, err := replication.NewUnsignedBatch(
		replication.BatchInput{
			FromResultIndex: exported.FromResultIndex,
			ToResultIndex:   exported.ToResultIndex,
			StartResultHash: chain.Digest(exported.StartResultHash),
			EndResultHash:   chain.Digest(exported.EndResultHash),
			StartChainIndex: exported.StartChainIndex,
			StartChainHash:  chain.Digest(exported.StartChainHash),
			EndChainIndex:   exported.EndChainIndex,
			EndChainHash:    chain.Digest(exported.EndChainHash),
			StartProjectionAccumulator: chain.Digest(
				exported.StartProjectionAccumulator,
			),
			EndProjectionAccumulator: chain.Digest(
				exported.EndProjectionAccumulator,
			),
			StartProjectionStateDigest: chain.Digest(
				exported.StartProjectionStateDigest,
			),
			EndProjectionStateDigest: chain.Digest(
				exported.EndProjectionStateDigest,
			),
			Results:                  exported.Results,
			SessionID:                exported.SessionID,
			WorkspaceID:              exported.WorkspaceID,
			RecoveryGeneration:       exported.RecoveryGeneration,
			ServerDeviceID:           priorAuthority.deviceID,
			ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
			ServerAuthorityVersion:   terminalAuthorityVersion,
		},
	)
	if err != nil {
		t.Fatalf("build prior-authority signed batch: %v", err)
	}
	batch, err := replication.SignBatch(unsigned, priorAuthority.privateKey)
	if err != nil {
		t.Fatalf("sign prior-authority batch: %v", err)
	}

	replica, err := consensus.OpenSettledReplica(
		context.Background(),
		consensus.SettledReplicaOptions{
			StatePath:     settled.statePath,
			OriginBootID:  daemonTestVerifyBootID,
			LocalDeviceID: settled.deviceID,
			Clock:         consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("open settled replica for prior-authority rejection: %v", err)
	}
	before, err := replica.View(context.Background())
	if err != nil {
		_ = replica.Close()
		t.Fatalf("read prior-authority rejection baseline: %v", err)
	}
	progressBefore, err := replica.ReplicationProgress(context.Background())
	if err != nil {
		_ = replica.Close()
		t.Fatalf("read prior-authority rejection progress: %v", err)
	}
	_, importErr := replica.ImportResultBatch(
		context.Background(),
		priorAuthority.deviceID,
		batch,
	)
	after, viewErr := replica.View(context.Background())
	progressAfter, progressErr := replica.ReplicationProgress(
		context.Background(),
	)
	fatalErr := replica.FatalError()
	closeErr = replica.Close()
	if !errors.Is(
		importErr,
		consensus.ErrReplicationSignerUnauthorized,
	) {
		t.Fatalf(
			"prior-authority ImportResultBatch() error = %v, want %v",
			importErr,
			consensus.ErrReplicationSignerUnauthorized,
		)
	}
	if viewErr != nil ||
		progressErr != nil ||
		fatalErr != nil ||
		closeErr != nil {
		t.Fatalf(
			"prior-authority rejection follow-up = (view=%v, progress=%v, fatal=%v, close=%v)",
			viewErr,
			progressErr,
			fatalErr,
			closeErr,
		)
	}
	if !reflect.DeepEqual(after, before) ||
		!reflect.DeepEqual(progressAfter, progressBefore) {
		t.Fatalf(
			"prior-authority rejection changed durable cursors:\nbefore=%+v\nafter=%+v\nprogress_before=%+v\nprogress_after=%+v",
			before,
			after,
			progressBefore,
			progressAfter,
		)
	}
}

func assertDaemonSettledSnapshotFallbackDurableState(
	t *testing.T,
	source, settled *daemonMeshIntegrationNode,
	observedSnapshotRoot, installedSnapshotRoot logicalsnapshot.Root,
) {
	t.Helper()
	observedSnapshotInput := observedSnapshotRoot.Unsigned().Input()
	sourceStore, err := store.Open(
		context.Background(),
		store.Options{Path: source.statePath},
	)
	if err != nil {
		t.Fatalf("open snapshot source store: %v", err)
	}
	defer func() { _ = sourceStore.Close() }()
	settledStore, err := store.Open(
		context.Background(),
		store.Options{Path: settled.statePath},
	)
	if err != nil {
		t.Fatalf("open snapshot-restored settled store: %v", err)
	}
	defer func() { _ = settledStore.Close() }()

	sourceView, err := sourceStore.View(context.Background())
	if err != nil {
		t.Fatalf("snapshot source View(): %v", err)
	}
	settledView, err := settledStore.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("snapshot-restored VerifiedSettledNonvoterView(): %v", err)
	}
	if sourceView.SessionID != settledView.SessionID ||
		sourceView.WorkspaceID != settledView.WorkspaceID ||
		sourceView.RecoveryGeneration != settledView.RecoveryGeneration ||
		!bytes.Equal(sourceView.GenesisJSON, settledView.GenesisJSON) ||
		sourceView.Heads != settledView.Heads ||
		sourceView.ProjectionStateDigest !=
			settledView.ProjectionStateDigest ||
		!reflect.DeepEqual(
			sourceView.ProjectionRows,
			settledView.ProjectionRows,
		) {
		t.Fatalf(
			"snapshot-restored durable state differs:\nsource=%+v\nsettled=%+v",
			sourceView,
			settledView,
		)
	}
	if sourceView.LastRaftAppliedLogIndex == nil ||
		settledView.CurrentTerm != nil ||
		settledView.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"snapshot source/settled Raft provenance = (%v, %v, %v)",
			sourceView.LastRaftAppliedLogIndex,
			settledView.CurrentTerm,
			settledView.LastRaftAppliedLogIndex,
		)
	}
	if settledView.Heads.ResultIndex <= observedSnapshotInput.ResultIndex {
		t.Fatalf(
			"settled result cursor %d did not include tail after snapshot %d",
			settledView.Heads.ResultIndex,
			observedSnapshotInput.ResultIndex,
		)
	}
	if err := sourceStore.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(snapshot source): %v", err)
	}
	if err := settledStore.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(snapshot-restored settled): %v", err)
	}
	storedRoot, hasSnapshot, err :=
		settledStore.VerifiedStandaloneLogicalSnapshotBaseline(
			context.Background(),
		)
	if err != nil ||
		!hasSnapshot ||
		!bytes.Equal(
			storedRoot.CanonicalBytes(),
			installedSnapshotRoot.CanonicalBytes(),
		) ||
		storedRoot.Signature() != installedSnapshotRoot.Signature() {
		t.Fatalf(
			"verified standalone snapshot baseline = (%x, %t, %v), want %x",
			storedRoot.CanonicalBytes(),
			hasSnapshot,
			err,
			installedSnapshotRoot.CanonicalBytes(),
		)
	}
	mode, err := settledStore.ReplicaEvidenceMode(context.Background())
	if err != nil || mode != store.ReplicaEvidenceSettledNonvoter {
		t.Fatalf("snapshot-restored evidence mode = (%q, %v)", mode, err)
	}
	progress, err := settledStore.SettledReplicationProgress(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("snapshot-restored SettledReplicationProgress(): %v", err)
	}
	if progress.Blocker != nil || progress.Heads != settledView.Heads {
		t.Fatalf("snapshot-restored settled progress = %+v", progress)
	}
	if _, err := os.Stat(settled.consensusDir); !os.IsNotExist(err) {
		t.Fatalf("snapshot-restored runtime created Raft storage: %v", err)
	}
}

func readDaemonSettledSnapshotBaseline(
	t *testing.T,
	statePath string,
) logicalsnapshot.Root {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: statePath},
	)
	if err != nil {
		t.Fatalf("open snapshot-restored settled store: %v", err)
	}
	root, found, baselineErr :=
		database.VerifiedStandaloneLogicalSnapshotBaseline(
			context.Background(),
		)
	closeErr := database.Close()
	if baselineErr != nil || !found || closeErr != nil {
		t.Fatalf(
			"read installed standalone snapshot baseline = (found=%t, baseline_err=%v, close_err=%v)",
			found,
			baselineErr,
			closeErr,
		)
	}
	return root
}

type daemonSettledCoverageCollector struct {
	privateKeys  map[domain.DeviceID]ed25519.PrivateKey
	afterCollect func(canonicalcoverage.Requirement)
}

func (collector *daemonSettledCoverageCollector) CollectCanonicalCoverage(
	ctx context.Context,
	requirement canonicalcoverage.Requirement,
) ([][]byte, error) {
	if collector == nil || ctx == nil {
		return nil, canonicalcoverage.ErrCollectorUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := requirement.VoterSet.VoterDeviceIDs()
	required := len(target)/2 + 1
	receipts := make([][]byte, 0, required)
	for _, deviceID := range target {
		privateKey, found := collector.privateKeys[deviceID]
		if !found {
			continue
		}
		receipt, err := signDaemonSettledCoverageReceipt(
			requirement,
			deviceID,
			privateKey,
		)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
		if len(receipts) == required {
			if collector.afterCollect != nil {
				collector.afterCollect(requirement)
			}
			return receipts, nil
		}
	}
	return receipts, nil
}

func signDaemonSettledCoverageReceipt(
	requirement canonicalcoverage.Requirement,
	voterDeviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) ([]byte, error) {
	subject, err := requirement.Subject()
	if err != nil {
		return nil, err
	}
	wire := map[string]any{
		"canonical_ref_version": subject.CanonicalRefVersion,
		"commit_oid":            subject.CommitOID,
		"session_id":            subject.SessionID,
		"voter_device_id":       voterDeviceID,
		"voter_set_version":     subject.VoterSetVersion,
		"workspace_id":          subject.WorkspaceID,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	signedBytes, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, err
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureGitCanonicalCoverage,
		signedBytes,
	)
	if err != nil {
		return nil, err
	}
	wire["signature"] = codec.EncodeBase64URL(signature)
	encoded, err = json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func runDaemonSettledReplicationChild(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationProcessTimeout,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestDaemonSettledNonvoterReplicatesAcrossAuthorityHandoffsAndRestart$",
		"-test.count=1",
		"-test.v",
		daemonMeshChildWatchdogArgument(
			daemonMeshIntegrationProcessTimeout,
		),
	)
	command.Env = append(
		daemonTestEnvironment(os.Environ()),
		daemonSettledReplicationChildMarker+"=1",
		daemonMeshIntegrationRequired+"=1",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"settled replication child timed out after %s: %v\n%s",
			daemonMeshIntegrationProcessTimeout,
			ctx.Err(),
			output,
		)
	}
	requireDaemonIntegrationChildResult(
		t,
		"settled replication",
		output,
		err,
	)
}

func runDaemonSettledSnapshotFallbackChild(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonSettledSnapshotProcessTimeout,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestDaemonSettledAutomaticLogicalSnapshotFallbackPersistsAcrossRestart$",
		"-test.count=1",
		"-test.v",
		daemonMeshChildWatchdogArgument(
			daemonSettledSnapshotProcessTimeout,
		),
	)
	command.Env = append(
		daemonTestEnvironment(os.Environ()),
		daemonSettledSnapshotChildMarker+"=1",
		daemonMeshIntegrationRequired+"=1",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"settled snapshot child timed out after %s: %v\n%s",
			daemonSettledSnapshotProcessTimeout,
			ctx.Err(),
			output,
		)
	}
	requireDaemonIntegrationChildResult(t, "settled snapshot", output, err)
}

var _ canonicalcoverage.ReceiptCollector = (*daemonSettledCoverageCollector)(nil)
