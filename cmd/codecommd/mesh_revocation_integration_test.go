package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

const daemonMeshRevocationCloseTarget = 5 * time.Second

type daemonMeshRevocationTransfer struct {
	control *daemonMeshPairedContentConnection
	bulk    *daemonMeshSnapshotBulkConnection
	gate    *daemonMeshVirtualWriteGate
	done    chan error
}

func TestDaemonProductionFullPlaneRevocationComposition(t *testing.T) {
	if os.Getenv(daemonMeshIntegrationChildMarker) != "1" {
		runDaemonMeshIntegrationChild(
			t,
			"^TestDaemonProductionFullPlaneRevocationComposition$",
		)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonProductionFullPlaneRevocationComposition(t)
}

func runDaemonProductionFullPlaneRevocationComposition(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	credentialBase := time.Now().UTC().Truncate(time.Second)
	credentialClock := newDaemonMeshIntegrationCredentialClock(credentialBase)
	network := newDaemonMeshVirtualNetwork()
	nodes, _ := newDaemonMeshVirtualIntegrationNodesCount(
		t,
		root,
		network,
		credentialClock.Now,
		5,
	)
	coverage := &daemonSettledCoverageCollector{
		privateKeys: make(
			map[domain.DeviceID]ed25519.PrivateKey,
			len(nodes),
		),
	}
	for _, node := range nodes {
		coverage.privateKeys[node.deviceID] = node.privateKey
		node.coverage = coverage
	}
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, nodes...)
		_ = network.Close()
		for _, node := range nodes {
			clear(node.privateKey)
		}
	})

	initial := daemonMeshIntegrationInitialState(t, nodes, device.Device{})
	bootstrap := daemonMeshIntegrationBootstrap(nodes)
	for _, node := range nodes {
		initializeDaemonMeshIntegrationStore(t, node.statePath, initial)
		seedDaemonMeshIntegrationRaft(
			t,
			node.consensusDir,
			node.deviceID,
			bootstrap,
		)
		node.start(t, nodes)
	}
	initialVoters := daemonMeshIntegrationDeviceIDs(nodes)
	statuses := waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				initialVoters,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				initialVoters,
			)
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 1)

	leaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	leader := daemonMeshIntegrationNodeByID(t, nodes, leaderID)
	followers := make([]*daemonMeshIntegrationNode, 0, len(nodes)-1)
	for _, node := range nodes {
		if node != leader {
			followers = append(followers, node)
		}
	}
	if len(followers) != 4 {
		t.Fatalf("revocation followers = %d, want 4", len(followers))
	}
	subject := leader
	stale := followers[0]
	finalNodes := []*daemonMeshIntegrationNode{
		stale,
		followers[1],
		followers[2],
	}
	sort.Slice(finalNodes, func(left, right int) bool {
		return finalNodes[left].deviceID < finalNodes[right].deviceID
	})
	finalVoters := daemonMeshIntegrationDeviceIDs(finalNodes)
	informed := make([]*daemonMeshIntegrationNode, 0, 3)
	var extra *daemonMeshIntegrationNode
	for _, node := range nodes {
		if node != stale && node != subject {
			informed = append(informed, node)
		}
		if node != subject && node != stale &&
			node != followers[1] && node != followers[2] {
			extra = node
		}
	}
	if extra == nil {
		t.Fatal("revocation mesh has no active non-target voter")
	}

	isolation := make(map[*daemonMeshIntegrationNode]*daemonMeshVirtualWriteGate)
	for _, source := range nodes {
		if source == stale {
			continue
		}
		gate, err := network.HoldWrites(
			source.currentPeerEndpoint().Addr(),
			stale.currentPeerEndpoint().Addr(),
		)
		if err != nil {
			t.Fatalf(
				"hold %s -> stale %s: %v",
				source.deviceID,
				stale.deviceID,
				err,
			)
		}
		isolation[source] = gate
	}
	defer func() {
		for _, gate := range isolation {
			gate.Release()
		}
	}()
	network.DropAddress(stale.currentPeerEndpoint().Addr())
	select {
	case <-isolation[leader].Entered():
	case <-time.After(daemonMeshIntegrationTimeout):
		t.Fatal("leader replication did not enter the stale-voter partition")
	}
	waitForDaemonMeshIntegrationStableHeads(
		t,
		[]*daemonMeshIntegrationNode{stale},
		250*time.Millisecond,
	)
	staleBefore, err := readDaemonMeshIntegrationStatus(stale.localEndpoint)
	if err != nil {
		t.Fatalf("read stale baseline: %v", err)
	}

	subjectProvider, _, ready := subject.meshCapture.snapshot()
	if !ready || subjectProvider == nil {
		t.Fatal("revocation subject content credential is unavailable")
	}
	subjectCertificate, err := subjectProvider()
	if err != nil {
		t.Fatalf("read revocation subject credential: %v", err)
	}
	defer clearDaemonTLSCertificate(&subjectCertificate)
	transferSource := followers[1]
	transferProvider, _, ready := transferSource.meshCapture.snapshot()
	if !ready || transferProvider == nil {
		t.Fatal("revocation transfer credential is unavailable")
	}
	transferCertificate, err := transferProvider()
	if err != nil {
		t.Fatalf("read revocation transfer credential: %v", err)
	}
	defer clearDaemonTLSCertificate(&transferCertificate)
	transfer := openDaemonMeshRevocationTransfer(
		t,
		network,
		transferSource,
		subject,
		transferCertificate,
	)
	defer transfer.close(t)
	if count := network.ConnectionCount(
		transferSource.currentPeerEndpoint().Addr(),
		subject.currentPeerEndpoint().Addr(),
	); count < 3 {
		t.Fatalf(
			"subject/leader established connections = %d, want consensus, control, and bulk",
			count,
		)
	}

	operator := dialDaemonMeshIntegrationOperator(t, subject.localEndpoint)
	mutationContext, cancelMutation := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	result, err := operator.RevokePeer(
		mutationContext,
		ui.RevokePeerRequest{
			DeviceID:                subject.deviceID,
			ExpectedEntityVersion:   1,
			ExpectedVoterSetVersion: 1,
			VoterDeviceIDs:          finalVoters,
			Reason:                  "production full-plane revocation proof",
		},
	)
	cancelMutation()
	closeErr := operator.Close()
	if err != nil {
		t.Fatalf("RevokePeer(): %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close revocation operator: %v", closeErr)
	}
	if result.Status != store.OutcomeAccepted ||
		result.Code != "accepted" ||
		result.Duplicate {
		t.Fatalf("RevokePeer() result = %#v", result)
	}
	closedBy := time.Now().Add(daemonMeshRevocationCloseTarget)

	waitForDaemonMeshIntegrationCluster(
		t,
		informed,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationMemberStatus(
				statuses,
				subject.deviceID,
				device.StatusRevoked,
				2,
			) && daemonMeshIntegrationCommittedTarget(
				statuses,
				2,
				finalVoters,
			) && daemonMeshIntegrationMutationConverged(statuses)
		},
	)
	awaitDaemonMeshRevocationTransferClosed(t, transfer, closedBy)
	awaitDaemonMeshRevokedControlClosed(t, transfer.control, closedBy)
	awaitDaemonMeshRevokedExit(t, subject, closedBy)
	awaitDaemonMeshAddressConnectionsClosed(
		t,
		network,
		subject.currentPeerEndpoint().Addr(),
		closedBy,
	)
	assertDaemonMeshRevokedEpochKeysErased(t, subject)

	assertDaemonMeshFreshContentDenied(
		t,
		network,
		subject,
		informed[0],
		subjectCertificate,
	)
	assertDaemonMeshFreshConsensusDenied(t, network, subject, informed[0])

	staleAfter := waitForDaemonMeshIntegrationCluster(
		t, []*daemonMeshIntegrationNode{stale},
		func([]ui.Snapshot) bool { return true },
	)[0]
	if staleAfter.Session.EventChainIndex !=
		staleBefore.Session.EventChainIndex ||
		staleAfter.Session.ResultIndex !=
			staleBefore.Session.ResultIndex ||
		!reflect.DeepEqual(
			staleAfter.Session.AppliedRaftIndex,
			staleBefore.Session.AppliedRaftIndex,
		) {
		t.Fatalf(
			"stale voter advanced across revocation:\n before=%+v\n after=%+v",
			staleBefore.Session,
			staleAfter.Session,
		)
	}
	staleNode, ready := stale.meshCapture.consensusNode()
	if !ready || staleNode.IsLeader() {
		t.Fatal("isolated stale voter became a leader")
	}

	isolation[subject].Release()
	staleClient, err := openDaemonMeshIdentityConsensusClient(
		network,
		subject,
		stale,
	)
	if err != nil {
		t.Fatalf("open stale identity client: %v", err)
	}
	statusContext, cancelStatus := context.WithTimeout(
		context.Background(),
		3*time.Second,
	)
	_, statusErr := staleClient.RequestConsensusStatus(
		statusContext,
		stale.deviceID,
	)
	cancelStatus()
	if statusErr != nil {
		_ = staleClient.Close()
		t.Fatalf(
			"stale voter refused still-applied identity control request: %v",
			statusErr,
		)
	}
	if staleNode.IsLeader() {
		_ = staleClient.Close()
		t.Fatal("stale voter became leader while admitting old identity")
	}
	if err := staleClient.Close(); err != nil {
		t.Fatalf("close stale admission probe: %v", err)
	}

	credentialClock.Set(credentialBase.Add(25*time.Minute + time.Second))
	nextEpochKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xf4}, ed25519.SeedSize),
	)
	binding, err := credential.SignBinding(
		daemonTestSessionID,
		subject.deviceID,
		2,
		nextEpochKey.Public().(ed25519.PublicKey),
		subject.privateKey,
	)
	clear(nextEpochKey)
	if err != nil {
		t.Fatalf("sign revoked renewal binding: %v", err)
	}
	renewContext, cancelRenew := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	_, renewErr := staleNode.RenewCredential(renewContext, binding)
	cancelRenew()
	if renewErr == nil {
		t.Fatal("stale minority renewed the revoked member")
	}
	assertDaemonMeshCredentialAbsent(
		t,
		append(informed, stale),
		subject.deviceID,
		2,
	)

	for _, gate := range isolation {
		gate.Release()
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		finalNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				finalVoters,
			) && daemonMeshIntegrationTarget(
				statuses,
				2,
				finalVoters,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				subject.deviceID,
				device.StatusRevoked,
				2,
			) && daemonMeshIntegrationMutationConverged(statuses)
		},
	)
	credentialClock.Set(
		credentialBase.Add(
			time.Duration(
				credentialauthorization.ValiditySeconds-
					credentialauthorization.OverlapSeconds,
			)*time.Second + time.Second,
		),
	)
	waitForDaemonMeshContentCredentialEpoch(t, finalNodes, 2)
	assertDaemonMeshCredentialAbsent(
		t,
		append(informed, stale),
		subject.deviceID,
		2,
	)
	statuses = exerciseDaemonFollowerProposalForwarding(t, finalNodes)
	finalChainIndex := statuses[0].Session.EventChainIndex
	finalResultIndex := statuses[0].Session.ResultIndex

	stopDaemonMeshIntegrationNodes(
		t,
		append(
			append([]*daemonMeshIntegrationNode(nil), finalNodes...),
			extra,
		)...,
	)
	for _, node := range finalNodes {
		node.listener = network.Listen(t, node.currentPeerEndpoint())
		node.start(t, finalNodes)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		finalNodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				finalVoters,
			) && daemonMeshIntegrationTarget(
				statuses,
				2,
				finalVoters,
			) && daemonMeshIntegrationTaskConverged(
				statuses,
				daemonTestTaskID,
			) && statuses[0].Session.EventChainIndex >= finalChainIndex &&
				statuses[0].Session.ResultIndex >= finalResultIndex
		},
	)
	stopDaemonMeshIntegrationNodes(t, finalNodes...)
	assertDaemonMeshRevocationDurable(
		t,
		nodes,
		finalNodes,
		finalChainIndex,
		finalResultIndex,
	)
}

func daemonMeshIntegrationCommittedTarget(
	statuses []ui.Snapshot,
	version uint64,
	target []domain.DeviceID,
) bool {
	for _, status := range statuses {
		if status.Consensus.VoterSetVersion != version ||
			!sameDaemonMeshIntegrationIDs(
				status.Consensus.TargetVoterDeviceIDs,
				target,
			) {
			return false
		}
	}
	return true
}

func openDaemonMeshRevocationTransfer(
	t *testing.T,
	network *daemonMeshVirtualNetwork,
	source, target *daemonMeshIntegrationNode,
	certificate tls.Certificate,
) *daemonMeshRevocationTransfer {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	control, err := dialDaemonMeshExternalContentClientWithDialContext(
		ctx,
		certificate,
		source.currentPeerEndpoint().Addr(),
		target,
		network.DialContext,
	)
	if err != nil {
		t.Fatalf("dial revocation control connection: %v", err)
	}
	session, err := control.client.Session(ctx)
	if err != nil ||
		session.SessionID() != daemonTestSessionID ||
		session.WorkspaceID() != daemonTestWorkspaceID ||
		session.ServerDeviceID() != target.deviceID {
		_ = control.Close()
		t.Fatalf("bind revocation control session = (%+v, %v)", session, err)
	}
	var rootErr error
	for ctx.Err() == nil {
		latest, latestErr := control.client.LatestSnapshot(ctx)
		if latestErr == nil {
			var raw net.Conn
			bulk, bulkErr := dialDaemonMeshExternalSnapshotBulkObserved(
				ctx,
				certificate,
				source.currentPeerEndpoint().Addr(),
				target,
				latest,
				network.DialContext,
				func(connection net.Conn) {
					raw = connection
				},
			)
			if bulkErr != nil {
				_ = control.Close()
				t.Fatalf("dial revocation snapshot bulk: %v", bulkErr)
			}
			if _, pageErr := bulk.client.SnapshotManifestPage(
				ctx,
				0,
			); pageErr != nil {
				_ = bulk.Close()
				_ = control.Close()
				t.Fatalf("warm revocation snapshot bulk: %v", pageErr)
			}
			gate, gateErr := network.HoldConnectionWrites(
				raw,
				target.currentPeerEndpoint().Addr(),
				source.currentPeerEndpoint().Addr(),
			)
			if gateErr != nil {
				_ = bulk.Close()
				_ = control.Close()
				t.Fatalf("hold snapshot response: %v", gateErr)
			}
			done := make(chan error, 1)
			go func() {
				_, chunkErr := bulk.client.SnapshotChunk(
					context.Background(),
					0,
				)
				done <- chunkErr
			}()
			select {
			case <-gate.Entered():
			case <-ctx.Done():
				gate.Release()
				_ = bulk.Close()
				_ = control.Close()
				t.Fatalf(
					"snapshot transfer did not enter gate: %v",
					ctx.Err(),
				)
			}
			select {
			case transferErr := <-done:
				gate.Release()
				_ = bulk.Close()
				_ = control.Close()
				t.Fatalf(
					"snapshot transfer completed before revocation: %v",
					transferErr,
				)
			default:
			}
			return &daemonMeshRevocationTransfer{
				control: control,
				bulk:    bulk,
				gate:    gate,
				done:    done,
			}
		}
		rootErr = latestErr
		if !errors.Is(latestErr, contenthttp.ErrSnapshotUnavailable) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = control.Close()
	t.Fatalf(
		"revocation snapshot root unavailable: %v",
		errors.Join(rootErr, ctx.Err()),
	)
	return nil
}

func (transfer *daemonMeshRevocationTransfer) close(t *testing.T) {
	t.Helper()
	if transfer == nil {
		return
	}
	if transfer.gate != nil {
		transfer.gate.Release()
	}
	if transfer.bulk != nil {
		if err := transfer.bulk.Close(); err != nil {
			t.Errorf("close revocation bulk: %v", err)
		}
		transfer.bulk = nil
	}
	if transfer.control != nil {
		if err := transfer.control.Close(); err != nil {
			t.Errorf("close revocation control: %v", err)
		}
		transfer.control = nil
	}
}

type daemonMeshIdentityConsensusEndpoint struct {
	deviceID domain.DeviceID
	endpoint netip.AddrPort
}

func (resolver daemonMeshIdentityConsensusEndpoint) ResolveConsensusEndpoints(
	ctx context.Context,
	deviceID domain.DeviceID,
) ([]netip.AddrPort, error) {
	if ctx == nil || ctx.Err() != nil ||
		deviceID != resolver.deviceID ||
		!resolver.endpoint.IsValid() {
		return nil, errDaemonMeshContentHarness
	}
	return []netip.AddrPort{resolver.endpoint}, nil
}

func openDaemonMeshIdentityConsensusClient(
	network *daemonMeshVirtualNetwork,
	source, target *daemonMeshIntegrationNode,
) (*transport.ConsensusBootstrapClient, error) {
	if network == nil || source == nil || target == nil {
		return nil, errDaemonMeshContentHarness
	}
	certificate, binding, err := transport.IssueIdentityCertificate(
		daemonTestSessionID,
		0,
		source.privateKey,
	)
	if err != nil {
		return nil, err
	}
	defer clearDaemonTLSCertificate(&certificate)
	if binding.DeviceID != source.deviceID {
		return nil, errDaemonMeshContentHarness
	}
	targetPublic := target.privateKey.Public().(ed25519.PublicKey)
	sourceEndpoint := source.currentPeerEndpoint()
	targetEndpoint := target.currentPeerEndpoint()
	client, err := transport.NewConsensusBootstrapClient(
		transport.ConsensusBootstrapClientOptions{
			LocalDeviceID:       source.deviceID,
			PeerDeviceID:        target.deviceID,
			IdentityCertificate: certificate,
			Endpoints: daemonMeshIdentityConsensusEndpoint{
				deviceID: target.deviceID,
				endpoint: targetEndpoint,
			},
			Dialer: transport.ConsensusEndpointDialerFunc(func(
				ctx context.Context,
				endpoint netip.AddrPort,
			) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout: 5 * time.Second,
					LocalAddr: &net.TCPAddr{
						IP: net.IP(
							sourceEndpoint.Addr().AsSlice(),
						),
					},
				}
				return network.DialContext(
					ctx,
					dialer,
					"tcp4",
					endpoint.String(),
				)
			}),
			VerifyExpectedPeer: func(
				deviceID domain.DeviceID,
				remote transport.IdentityCertificate,
			) error {
				if deviceID != target.deviceID {
					return errDaemonMeshContentHarness
				}
				return remote.VerifyIdentity(
					daemonTestSessionID,
					0,
					target.deviceID,
					targetPublic,
				)
			},
		},
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func awaitDaemonMeshAddressConnectionsClosed(
	t *testing.T,
	network *daemonMeshVirtualNetwork,
	address netip.Addr,
	deadline time.Time,
) {
	t.Helper()
	for time.Now().Before(deadline) {
		if network.ConnectionCountForAddress(address) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("revoked device retained established transport connections")
}

func awaitDaemonMeshRevocationTransferClosed(
	t *testing.T,
	transfer *daemonMeshRevocationTransfer,
	deadline time.Time,
) {
	t.Helper()
	delay := time.Until(deadline)
	if transfer == nil || delay <= 0 {
		t.Fatal("snapshot transfer closure exceeded the target")
	}
	select {
	case err := <-transfer.done:
		if err == nil {
			t.Fatal("revoked in-flight snapshot transfer completed")
		}
	case <-time.After(delay):
		t.Fatal("revoked in-flight snapshot transfer remained open")
	}
}

func awaitDaemonMeshRevokedControlClosed(
	t *testing.T,
	connection *daemonMeshPairedContentConnection,
	deadline time.Time,
) {
	t.Helper()
	if connection == nil || connection.client == nil {
		t.Fatal("revocation control connection is unavailable")
	}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		_, err := connection.client.Peers(ctx)
		cancel()
		if err != nil {
			return
		}
	}
	t.Fatal("revoked established content connection remained open")
}

func awaitDaemonMeshRevokedExit(
	t *testing.T,
	node *daemonMeshIntegrationNode,
	deadline time.Time,
) {
	t.Helper()
	delay := time.Until(deadline)
	if node == nil || delay <= 0 {
		t.Fatal("revoked daemon exit exceeded the target")
	}
	select {
	case <-node.exited:
	case <-time.After(delay):
		stage, ready := node.meshCapture.lifecycleState()
		t.Fatalf(
			"revoked daemon did not stop (stage=%q, ready=%t, fatal=%v, content=%s)",
			stage,
			ready,
			node.meshCapture.fatalError(),
			daemonMeshIntegrationContentDiagnostics(node),
		)
	}
	if node.exitErr == nil ||
		!strings.Contains(
			node.exitErr.Error(),
			"inconsistent applied membership",
		) {
		t.Fatalf("revoked daemon exit error = %v", node.exitErr)
	}
	if node.cancel != nil {
		node.cancel()
	}
	node.running = false
	node.cancel = nil
	node.listener = nil
}

func assertDaemonMeshRevokedEpochKeysErased(
	t *testing.T,
	node *daemonMeshIntegrationNode,
) {
	t.Helper()
	for _, epoch := range []uint64{1, 2} {
		reference, err := credentialstore.EpochReference(
			daemonTestSessionID,
			node.deviceID,
			epoch,
		)
		if err != nil {
			t.Fatalf("build epoch-%d reference: %v", epoch, err)
		}
		value, err := node.credentials.Get(t.Context(), reference)
		clear(value)
		if !errors.Is(err, credentialstore.ErrNotFound) {
			t.Fatalf("revoked epoch-%d key remained: %v", epoch, err)
		}
	}
}

func assertDaemonMeshFreshContentDenied(
	t *testing.T,
	network *daemonMeshVirtualNetwork,
	source, target *daemonMeshIntegrationNode,
	certificate tls.Certificate,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := dialDaemonMeshExternalContentClientWithDialContext(
		ctx,
		certificate,
		source.currentPeerEndpoint().Addr(),
		target,
		network.DialContext,
	)
	if err != nil {
		return
	}
	defer connection.Close()
	if _, requestErr := connection.client.Session(ctx); requestErr == nil {
		t.Fatal("revoked member completed fresh content access")
	}
}

func assertDaemonMeshFreshConsensusDenied(
	t *testing.T,
	network *daemonMeshVirtualNetwork,
	source, target *daemonMeshIntegrationNode,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := openDaemonMeshIdentityConsensusClient(
		network,
		source,
		target,
	)
	if err != nil {
		return
	}
	defer client.Close()
	if _, requestErr := client.RequestConsensusStatus(
		ctx,
		target.deviceID,
	); requestErr == nil {
		t.Fatal("revoked member completed fresh consensus control access")
	}
}

func assertDaemonMeshCredentialAbsent(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	deviceID domain.DeviceID,
	epoch uint64,
) {
	t.Helper()
	key := credentialauthorization.Key{
		SessionID: daemonTestSessionID,
		DeviceID:  deviceID,
		Epoch:     epoch,
	}
	for _, node := range nodes {
		consensusNode, ready := node.meshCapture.consensusNode()
		if !ready {
			t.Fatalf("consensus node %s is unavailable", node.deviceID)
		}
		admission, err := consensusNode.PeerAdmissionSnapshot()
		if err != nil {
			t.Fatalf("admission snapshot %s: %v", node.deviceID, err)
		}
		if _, found := admission.Authorization(key); found {
			t.Fatalf(
				"device %s authorized revoked credential epoch %d",
				node.deviceID,
				epoch,
			)
		}
	}
}

func assertDaemonMeshRevocationDurable(
	t *testing.T,
	allNodes, finalNodes []*daemonMeshIntegrationNode,
	minChainIndex, minResultIndex uint64,
) {
	t.Helper()
	var baseline *store.StateView
	for _, node := range allNodes {
		database, err := store.Open(
			context.Background(),
			store.Options{Path: node.statePath},
		)
		if err != nil {
			t.Fatalf("reopen revocation store %s: %v", node.deviceID, err)
		}
		view, viewErr := database.View(context.Background())
		verifyErr := database.VerifyCommitmentHistory(context.Background())
		closeErr := database.Close()
		if viewErr != nil || verifyErr != nil || closeErr != nil {
			t.Fatalf(
				"verify revocation store %s = (view=%v, history=%v, close=%v)",
				node.deviceID,
				viewErr,
				verifyErr,
				closeErr,
			)
		}
		isFinal := false
		for _, candidate := range finalNodes {
			if candidate == node {
				isFinal = true
				break
			}
		}
		if !isFinal {
			continue
		}
		if view.Heads.ChainIndex < minChainIndex ||
			view.Heads.ResultIndex < minResultIndex {
			t.Fatalf(
				"revocation survivor %s heads = %+v",
				node.deviceID,
				view.Heads,
			)
		}
		if baseline == nil {
			copy := view
			baseline = &copy
			continue
		}
		if view.Heads != baseline.Heads ||
			view.ProjectionStateDigest != baseline.ProjectionStateDigest ||
			!reflect.DeepEqual(
				view.ProjectionRows,
				baseline.ProjectionRows,
			) {
			t.Fatalf("revocation survivor %s diverged", node.deviceID)
		}
	}
}
