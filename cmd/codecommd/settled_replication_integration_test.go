package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

const daemonSettledReplicationChildMarker = "CODECOMM_TEST_SETTLED_REPLICATION_CHILD"

func TestDaemonSettledNonvoterReplicatesAcrossAuthorityHandoffAndRestart(
	t *testing.T,
) {
	if os.Getenv(daemonSettledReplicationChildMarker) != "1" {
		runDaemonSettledReplicationChild(t)
		return
	}
	runDaemonSettledReplicationIntegration(t)
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
		for _, node := range allNodes {
			node.cleanup(t)
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
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.ResultIndex ==
					authorityOneResultIndex &&
				statuses[0].Session.EventChainIndex ==
					authorityOneChainIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 1, voterIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
				)
		},
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
			VoterDeviceIDs:          targetIDs,
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
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, targetIDs) &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs)
		},
	)
	postHandoffLeaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	postHandoffLeader := daemonMeshIntegrationNodeByID(
		t,
		targetNodes,
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
			postHandoffLeader.privateKey,
			postHandoffLeader.deviceID,
		),
	)
	cancelTask()
	if err != nil ||
		taskResult.Outcome.Status != store.OutcomeAccepted ||
		taskResult.Outcome.Code != "accepted" {
		t.Fatalf("post-handoff task apply = (%+v, %v)", taskResult, err)
	}
	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		targetNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, targetIDs) &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)
	frozenResultIndex := statuses[0].Session.ResultIndex
	frozenChainIndex := statuses[0].Session.EventChainIndex

	for _, voter := range removedVoters {
		voter.stop(t)
	}
	settled.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		settled.peerEndpoint,
	)
	settled.start(t, allNodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{settled},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1 &&
				statuses[0].Session.ResultIndex == frozenResultIndex &&
				statuses[0].Session.EventChainIndex == frozenChainIndex &&
				statuses[0].Session.AppliedRaftIndex == nil &&
				daemonMeshIntegrationTarget(statuses, 2, targetIDs) &&
				daemonSettledTasksConverged(
					statuses,
					authorityOneTaskID,
					daemonTestTaskID,
				)
		},
	)

	settled.stop(t)
	target.stop(t)
	assertDaemonSettledReplicationDurableState(
		t,
		target,
		settled,
		leader.deviceID,
		target.deviceID,
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
			OriginSequence: 1,
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
) tls.Certificate {
	t.Helper()
	if len(voters) == 0 || leader == nil || settled == nil || now.IsZero() {
		t.Fatal("invalid settled credential fixture")
	}
	epochPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xf1}, ed25519.SeedSize),
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
	authorization, err := node.RenewCredential(ctx, binding)
	cancel()
	if err != nil {
		t.Fatalf("RenewCredential(settled): %v", err)
	}
	if authorization.DeviceID != settled.deviceID ||
		authorization.Epoch != 1 ||
		authorization.Role != credentialauthorization.RoleEditor ||
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
	authorityOneSigner, authorityTwoSigner domain.DeviceID,
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
	if sourceView.Heads != settledView.Heads ||
		sourceView.ProjectionStateDigest !=
			settledView.ProjectionStateDigest ||
		!reflect.DeepEqual(
			sourceView.ProjectionRows,
			settledView.ProjectionRows,
		) {
		t.Fatal("settled durable logical state differs from authority source")
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
	var sawAuthorityOne, sawAuthorityTwo bool
	for _, observation := range progress.Observations {
		switch {
		case observation.SignerDeviceID == authorityOneSigner &&
			observation.AuthorityVersion == 1:
			sawAuthorityOne = true
		case observation.SignerDeviceID == authorityTwoSigner &&
			observation.AuthorityVersion == 2:
			sawAuthorityTwo = true
		}
	}
	if !sawAuthorityOne || !sawAuthorityTwo {
		t.Fatalf(
			"authority observations = %+v, want %s/v1 and %s/v2",
			progress.Observations,
			authorityOneSigner,
			authorityTwoSigner,
		)
	}
	if _, err := os.Stat(settled.consensusDir); !os.IsNotExist(err) {
		t.Fatalf("settled runtime created Raft storage: %v", err)
	}
}

type daemonSettledCoverageCollector struct {
	privateKeys map[domain.DeviceID]ed25519.PrivateKey
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
		"-test.run=^TestDaemonSettledNonvoterReplicatesAcrossAuthorityHandoffAndRestart$",
		"-test.count=1",
		"-test.v",
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
	if err != nil {
		t.Fatalf("settled replication child failed: %v\n%s", err, output)
	}
}

var _ canonicalcoverage.ReceiptCollector = (*daemonSettledCoverageCollector)(nil)
