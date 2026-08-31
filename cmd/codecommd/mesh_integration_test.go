package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/joinbootstrap"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingjoiner"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
	"go.etcd.io/bbolt"
)

const (
	daemonMeshIntegrationTimeout        = 45 * time.Second
	daemonMeshIntegrationProcessTimeout = 3 * time.Minute
	daemonMeshIntegrationChildMarker    = "CODECOMM_TEST_DAEMON_MESH_CHILD"
	daemonMeshIntegrationRequired       = "CODECOMM_REQUIRE_DAEMON_MESH"
)

type daemonTestCredentialStore struct {
	mu      sync.RWMutex
	secrets map[credentialstore.Reference][]byte
}

func newDaemonTestCredentialStore() *daemonTestCredentialStore {
	return &daemonTestCredentialStore{
		secrets: make(map[credentialstore.Reference][]byte),
	}
}

func (secrets *daemonTestCredentialStore) Get(
	ctx context.Context,
	reference credentialstore.Reference,
) ([]byte, error) {
	if secrets == nil || ctx == nil {
		return nil, credentialstore.ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	secrets.mu.RLock()
	defer secrets.mu.RUnlock()
	value, found := secrets.secrets[reference]
	if !found {
		return nil, credentialstore.ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (secrets *daemonTestCredentialStore) Create(
	ctx context.Context,
	reference credentialstore.Reference,
	value []byte,
) error {
	if secrets == nil || ctx == nil {
		return credentialstore.ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := reference.Validate(); err != nil {
		return err
	}
	validLength := reference.Kind() == credentialstore.KindInvite &&
		len(value) == pairing.InviteSecretSize ||
		(reference.Kind() == credentialstore.KindIdentity ||
			reference.Kind() == credentialstore.KindEpoch) &&
			len(value) == ed25519.PrivateKeySize
	if !validLength {
		return credentialstore.ErrInvalidSecret
	}
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	if _, found := secrets.secrets[reference]; found {
		return credentialstore.ErrAlreadyExists
	}
	secrets.secrets[reference] = bytes.Clone(value)
	return nil
}

func (secrets *daemonTestCredentialStore) Delete(
	ctx context.Context,
	reference credentialstore.Reference,
) error {
	if secrets == nil || ctx == nil {
		return credentialstore.ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := reference.Validate(); err != nil {
		return err
	}
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	clear(secrets.secrets[reference])
	delete(secrets.secrets, reference)
	return nil
}

// A daemon run owns a handle, not this test's restart-persistent backing map.
func (*daemonTestCredentialStore) Close() error {
	return nil
}

func (secrets *daemonTestCredentialStore) wipe() {
	if secrets == nil {
		return
	}
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	for reference, value := range secrets.secrets {
		clear(value)
		delete(secrets.secrets, reference)
	}
}

type daemonMeshIntegrationNode struct {
	deviceID      domain.DeviceID
	privateKey    ed25519.PrivateKey
	statePath     string
	consensusDir  string
	localEndpoint ipc.Endpoint
	peerEndpoint  netip.AddrPort
	credentials   *daemonTestCredentialStore
	meshCapture   *daemonMeshIntegrationFactoryCapture
	credentialNow func() time.Time
	coverage      canonicalcoverage.ReceiptCollector

	listener net.Listener
	cancel   context.CancelFunc
	exited   chan struct{}
	exitErr  error
	running  bool
}

type daemonMeshIntegrationCredentialClock struct {
	unixNanos atomic.Int64
}

func newDaemonMeshIntegrationCredentialClock(
	now time.Time,
) *daemonMeshIntegrationCredentialClock {
	clock := &daemonMeshIntegrationCredentialClock{}
	clock.Set(now)
	return clock
}

func (clock *daemonMeshIntegrationCredentialClock) Now() time.Time {
	if clock == nil {
		return time.Time{}
	}
	return time.Unix(0, clock.unixNanos.Load()).UTC()
}

func (clock *daemonMeshIntegrationCredentialClock) Set(now time.Time) {
	if clock == nil {
		return
	}
	clock.unixNanos.Store(now.UTC().UnixNano())
}

type daemonMeshIntegrationPairedMember struct {
	member      device.Device
	certificate tls.Certificate
	endpointSet []byte
}

func TestDaemonProductionMeshComposition(t *testing.T) {
	if os.Getenv(daemonMeshIntegrationChildMarker) != "1" {
		runDaemonMeshIntegrationChild(t)
		return
	}
	runDaemonProductionMeshComposition(t)
}

func runDaemonProductionMeshComposition(t *testing.T) {
	t.Helper()
	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 3)
	root := t.TempDir()
	credentialBase := time.Now().UTC().Truncate(time.Second)
	credentialClock := newDaemonMeshIntegrationCredentialClock(
		credentialBase.Add(-28 * time.Minute),
	)
	nodes := newDaemonMeshIntegrationNodes(
		t,
		root,
		selectedAddress,
		listeners,
		credentialClock.Now,
	)
	t.Cleanup(func() {
		for _, node := range nodes {
			node.cleanup(t)
			clear(node.privateKey)
		}
	})

	nonvoter := newDaemonMeshIntegrationNonvoter(t)
	initial := daemonMeshIntegrationInitialState(t, nodes, nonvoter)
	voterIDs := daemonMeshIntegrationDeviceIDs(nodes)
	bootstrap := daemonMeshIntegrationBootstrap(nodes)
	var bootstrapEntry []byte
	for _, node := range nodes {
		initializeDaemonMeshIntegrationStore(t, node.statePath, initial)
		entry := seedDaemonMeshIntegrationRaft(
			t,
			node.consensusDir,
			node.deviceID,
			bootstrap,
		)
		if bootstrapEntry == nil {
			bootstrapEntry = entry
		} else if !bytes.Equal(bootstrapEntry, entry) {
			t.Fatal("Raft bootstrap configuration differs between daemons")
		}
	}

	for _, node := range nodes {
		node.start(t, nodes)
	}
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				voterIDs,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				nonvoter.ID,
				device.StatusActive,
				1,
			)
		},
	)
	exerciseDaemonContentMesh(t, nodes, nonvoter)
	exerciseDaemonContentCredentialRollover(
		t,
		nodes,
		credentialClock,
		credentialBase,
	)
	statuses := exerciseDaemonFollowerProposalForwarding(t, nodes)
	leaderID := domain.DeviceID(*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
		Consensus.LeaderDeviceID)
	leader := daemonMeshIntegrationNodeByID(t, nodes, leaderID)
	inviter := daemonMeshIntegrationFollower(t, nodes, leaderID)
	inviterNode, ready := inviter.meshCapture.consensusNode()
	if !ready || inviterNode.IsLeader() {
		t.Fatal("fresh-device inviter is not a follower")
	}

	client := dialDaemonMeshIntegrationOperator(t, inviter.localEndpoint)
	paired := admitDaemonMeshPairingJoiner(
		t,
		nodes,
		nonvoter.ID,
		inviter,
		leader,
		client,
		selectedAddress,
		credentialClock.Now,
	)
	defer clearDaemonTLSCertificate(&paired.certificate)
	pairedMember := paired.member
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				pairedMember.ID,
				device.StatusActive,
				1,
			)
		},
	)
	pairedContent := establishDaemonMeshPairedContent(
		t,
		nodes,
		leader,
		selectedAddress,
		paired,
	)
	defer func() { _ = pairedContent.Close() }()
	mutationContext, cancelMutation := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	result, err := client.RevokePeer(
		mutationContext,
		ui.RevokePeerRequest{
			DeviceID:                pairedMember.ID,
			ExpectedEntityVersion:   1,
			ExpectedVoterSetVersion: 1,
			VoterDeviceIDs:          voterIDs,
			Reason:                  "production composition revocation proof",
		},
	)
	cancelMutation()
	closeErr := client.Close()
	if err != nil {
		t.Fatalf("RevokePeer(): %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close operator client: %v", closeErr)
	}
	if result.Status != store.OutcomeAccepted ||
		result.Code != "accepted" ||
		result.Duplicate {
		t.Fatalf("RevokePeer() result = %#v", result)
	}

	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				voterIDs,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				pairedMember.ID,
				device.StatusRevoked,
				2,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				nonvoter.ID,
				device.StatusActive,
				1,
			) && daemonMeshIntegrationMutationConverged(statuses)
		},
	)
	assertDaemonMeshPairedContentRevoked(
		t,
		nodes,
		leader,
		selectedAddress,
		paired,
		pairedContent,
	)
	mutationChainIndex := statuses[0].Session.EventChainIndex
	mutationResultIndex := statuses[0].Session.ResultIndex

	restarted := daemonMeshIntegrationFollower(t, nodes, leaderID)
	restarted.stop(t)
	restarted.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		restarted.peerEndpoint,
	)
	restarted.start(t, nodes)

	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				voterIDs,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				pairedMember.ID,
				device.StatusRevoked,
				2,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				nonvoter.ID,
				device.StatusActive,
				1,
			) && daemonMeshIntegrationMutationConverged(statuses) &&
				statuses[restarted.indexIn(nodes)].Session.EventChainIndex >=
					mutationChainIndex &&
				statuses[restarted.indexIn(nodes)].Session.ResultIndex >=
					mutationResultIndex
		},
	)

	exerciseDaemonNextDayCredentialRecovery(
		t,
		nodes,
		credentialClock,
		credentialBase.Add(24*time.Hour),
		voterIDs,
		pairedMember.ID,
		nonvoter.ID,
		mutationChainIndex,
		mutationResultIndex,
	)

	for _, node := range nodes {
		node.stop(t)
	}
	assertDaemonMeshIntegrationDurableMutation(
		t,
		nodes,
		pairedMember.ID,
		nonvoter.ID,
		voterIDs,
		mutationChainIndex,
		mutationResultIndex,
	)
}

func exerciseDaemonNextDayCredentialRecovery(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	clock *daemonMeshIntegrationCredentialClock,
	nextDay time.Time,
	voterIDs []domain.DeviceID,
	revokedDeviceID domain.DeviceID,
	activeDeviceID domain.DeviceID,
	minChainIndex, minResultIndex uint64,
) {
	t.Helper()
	if len(nodes) != 3 || clock == nil || nextDay.IsZero() {
		t.Fatal("invalid next-day credential recovery fixture")
	}
	for _, node := range nodes {
		node.stop(t)
	}
	clock.Set(nextDay)

	first := nodes[0]
	first.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		first.peerEndpoint,
	)
	first.start(t, nodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		[]*daemonMeshIntegrationNode{first},
		func(statuses []ui.Snapshot) bool {
			return len(statuses) == 1
		},
	)
	time.Sleep(3 * time.Second)
	isolated, err := readDaemonMeshIntegrationStatus(first.localEndpoint)
	if err != nil {
		t.Fatalf("read isolated wake status: %v", err)
	}
	if isolated.Consensus.LeaderDeviceID != nil ||
		isolated.Consensus.StrongWrites == "available" {
		t.Fatalf("one-voter wake acquired quorum: %#v", isolated.Consensus)
	}
	if epoch, credentialErr := daemonMeshContentCredentialEpoch(first); credentialErr == nil {
		t.Fatalf("expired one-voter wake exposed epoch %d", epoch)
	}
	firstNode, ready := first.meshCapture.consensusNode()
	if !ready {
		t.Fatal("one-voter wake did not expose consensus state")
	}
	firstAdmission, err := firstNode.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("one-voter admission snapshot: %v", err)
	}
	if epoch, found := firstAdmission.CurrentCredentialEpoch(first.deviceID); !found ||
		epoch != 2 {
		t.Fatalf(
			"one-voter wake credential epoch = (%d, %t), want (2, true)",
			epoch,
			found,
		)
	}

	second := nodes[1]
	second.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		second.peerEndpoint,
	)
	second.start(t, nodes)
	quorum := []*daemonMeshIntegrationNode{first, second}
	waitForDaemonMeshIntegrationCluster(
		t,
		quorum,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				voterIDs,
			)
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, quorum, 3)
	nextDayClient := openReadyDaemonMeshPeersClient(
		t,
		first,
		second,
		clock.Now,
	)
	if err := nextDayClient.Close(); err != nil {
		t.Fatalf("close next-day quorum content client: %v", err)
	}

	third := nodes[2]
	third.listener = listenDaemonMeshIntegrationEndpoint(
		t,
		third.peerEndpoint,
	)
	third.start(t, nodes)
	waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(
				statuses,
				voterIDs,
			) && daemonMeshIntegrationTarget(
				statuses,
				1,
				voterIDs,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				revokedDeviceID,
				device.StatusRevoked,
				2,
			) && daemonMeshIntegrationMemberStatus(
				statuses,
				activeDeviceID,
				device.StatusActive,
				1,
			) && daemonMeshIntegrationMutationConverged(statuses) &&
				statuses[0].Session.EventChainIndex >=
					minChainIndex &&
				statuses[0].Session.ResultIndex >=
					minResultIndex
		},
	)
	waitForDaemonMeshContentCredentialEpoch(t, nodes, 3)
	recoveredClient := openReadyDaemonMeshPeersClient(
		t,
		third,
		first,
		clock.Now,
	)
	if err := recoveredClient.Close(); err != nil {
		t.Fatalf("close fully recovered content client: %v", err)
	}
	waitForDaemonMeshIntegrationStableHeads(
		t,
		nodes,
		daemonSnapshotLeadershipRetry+time.Second,
	)
}

func exerciseDaemonFollowerProposalForwarding(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
) []ui.Snapshot {
	t.Helper()
	voterIDs := daemonMeshIntegrationDeviceIDs(nodes)
	statuses := waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationMutationConverged(statuses)
		},
	)
	leaderID := domain.DeviceID(
		*statuses[daemonMeshIntegrationLeaderIndex(statuses)].
			Consensus.LeaderDeviceID,
	)
	follower := daemonMeshIntegrationFollower(t, nodes, leaderID)
	followerNode, ready := follower.meshCapture.consensusNode()
	if !ready || followerNode.IsLeader() {
		t.Fatal("captured proposal source is not a follower")
	}
	signed := daemonTestTaskEvent(
		t,
		follower.privateKey,
		follower.deviceID,
	)
	baselineChainIndex := statuses[0].Session.EventChainIndex
	baselineResultIndex := statuses[0].Session.ResultIndex
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	var result store.ApplyResult
	for {
		if followerNode.IsLeader() {
			t.Fatal("proposal source became leader before forwarding")
		}
		var err error
		result, err = followerNode.Apply(ctx, signed)
		if err == nil {
			break
		}
		if !errors.Is(
			err,
			consensus.ErrProposalForwardingUnavailable,
		) {
			t.Fatalf("follower Apply(): %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("follower forwarding timed out: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != "accepted" {
		t.Fatalf("follower Apply() result = %+v", result)
	}

	statuses = waitForDaemonMeshIntegrationCluster(
		t,
		nodes,
		func(statuses []ui.Snapshot) bool {
			return daemonMeshIntegrationClusterReady(statuses, voterIDs) &&
				daemonMeshIntegrationTaskConverged(
					statuses,
					daemonTestTaskID,
				) &&
				statuses[0].Session.EventChainIndex >=
					baselineChainIndex+1 &&
				statuses[0].Session.ResultIndex >=
					baselineResultIndex+1
		},
	)
	if followerNode.IsLeader() {
		t.Fatal("proposal source became leader during forwarding proof")
	}
	return statuses
}

func newDaemonMeshIntegrationNodes(
	t *testing.T,
	root string,
	selectedAddress netip.Addr,
	listeners []net.Listener,
	credentialNow func() time.Time,
) []*daemonMeshIntegrationNode {
	t.Helper()
	if credentialNow == nil {
		t.Fatal("daemon mesh integration credential clock is nil")
	}
	nodes := make([]*daemonMeshIntegrationNode, len(listeners))
	for index, listener := range listeners {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{byte(0xa1 + index)}, ed25519.SeedSize),
		)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		deviceID, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatalf("derive device ID %d: %v", index, err)
		}
		endpoint, err := netip.ParseAddrPort(listener.Addr().String())
		if err != nil || endpoint.Addr() != selectedAddress {
			t.Fatalf("reserved listener %d address = %q", index, listener.Addr())
		}
		nodes[index] = &daemonMeshIntegrationNode{
			deviceID:      deviceID,
			privateKey:    privateKey,
			statePath:     filepath.Join(root, fmt.Sprintf("node-%d", index), "state.db"),
			consensusDir:  filepath.Join(root, fmt.Sprintf("node-%d", index), "consensus"),
			localEndpoint: daemonTestEndpoint(t),
			peerEndpoint:  endpoint,
			credentials:   newDaemonTestCredentialStore(),
			meshCapture:   &daemonMeshIntegrationFactoryCapture{},
			credentialNow: credentialNow,
			listener:      listener,
		}
	}
	sort.Slice(nodes, func(left, right int) bool {
		return nodes[left].deviceID < nodes[right].deviceID
	})
	return nodes
}

func daemonMeshIntegrationInitialState(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	nonvoter device.Device,
) store.InitialState {
	t.Helper()
	initial, _, _ := daemonTestInitialState(t)
	deviceIDs := daemonMeshIntegrationDeviceIDs(nodes)
	devices := make([]device.Device, 0, len(nodes)+1)
	for _, node := range nodes {
		devices = append(devices, device.Device{
			ID:                node.deviceID,
			Role:              device.RoleOwner,
			IdentityPublicKey: bytes.Clone(node.privateKey.Public().(ed25519.PublicKey)),
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		})
	}
	devices = append(devices, nonvoter)
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].ID < devices[right].ID
	})
	counters := make([]auditcounter.Counter, len(devices))
	for index, member := range devices {
		counters[index] = auditcounter.Counter{DeviceID: member.ID}
	}
	target, err := voterset.New(daemonTestSessionID, deviceIDs, 1)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	initial.Projections.Devices = devices
	initial.Projections.AuditCounters = counters
	initial.Projections.VoterSet = []voterset.Set{target}
	initial.Projections.CredentialAuthority =
		[]store.CredentialAuthorityRow{{
			SessionID:        daemonTestSessionID,
			VoterDeviceIDs:   deviceIDs,
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}}
	return initial
}

func newDaemonMeshIntegrationNonvoter(t *testing.T) device.Device {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xd1}, ed25519.SeedSize),
	)
	defer clear(privateKey)
	publicKey := bytes.Clone(privateKey.Public().(ed25519.PublicKey))
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("derive nonvoter device ID: %v", err)
	}
	return device.Device{
		ID:                deviceID,
		Role:              device.RoleEditor,
		IdentityPublicKey: publicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func initializeDaemonMeshIntegrationStore(
	t *testing.T,
	path string,
	initial store.InitialState,
) {
	t.Helper()
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(%s): %v", path, err)
	}
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		_ = database.Close()
		t.Fatalf("Initialize(%s): %v", path, err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(%s): %v", path, err)
	}
}

func seedDaemonMeshIntegrationRaft(
	t *testing.T,
	consensusDir string,
	localDeviceID domain.DeviceID,
	configuration raft.Configuration,
) []byte {
	t.Helper()
	if err := os.MkdirAll(consensusDir, 0o700); err != nil {
		t.Fatalf("create consensus directory: %v", err)
	}
	options := *bbolt.DefaultOptions
	options.Timeout = 5 * time.Second
	options.NoFreelistSync = false
	logs, err := raftboltdb.New(raftboltdb.Options{
		Path:        filepath.Join(consensusDir, "raft.db"),
		BoltOptions: &options,
		NoSync:      false,
	})
	if err != nil {
		t.Fatalf("open Raft store: %v", err)
	}
	snapshots, err := raft.NewFileSnapshotStore(consensusDir, 3, io.Discard)
	if err != nil {
		_ = logs.Close()
		t.Fatalf("open Raft snapshots: %v", err)
	}
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(localDeviceID)
	_, inMemory := raft.NewInmemTransport(raft.ServerAddress(localDeviceID))
	if err := raft.BootstrapCluster(
		config,
		logs,
		logs,
		snapshots,
		inMemory,
		configuration,
	); err != nil {
		_ = inMemory.Close()
		_ = logs.Close()
		t.Fatalf("BootstrapCluster(%s): %v", localDeviceID, err)
	}
	var entry raft.Log
	if err := logs.GetLog(1, &entry); err != nil {
		_ = inMemory.Close()
		_ = logs.Close()
		t.Fatalf("read bootstrap entry: %v", err)
	}
	if entry.Type != raft.LogConfiguration || entry.Term != 1 {
		_ = inMemory.Close()
		_ = logs.Close()
		t.Fatalf("bootstrap entry = %#v", entry)
	}
	if err := inMemory.Close(); err != nil {
		_ = logs.Close()
		t.Fatalf("close bootstrap transport: %v", err)
	}
	if err := logs.Close(); err != nil {
		t.Fatalf("close Raft store: %v", err)
	}
	return bytes.Clone(entry.Data)
}

func daemonMeshIntegrationBootstrap(
	nodes []*daemonMeshIntegrationNode,
) raft.Configuration {
	configuration := raft.Configuration{
		Servers: make([]raft.Server, len(nodes)),
	}
	for index, node := range nodes {
		configuration.Servers[index] = raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(node.deviceID),
			Address:  raft.ServerAddress(node.deviceID),
		}
	}
	return configuration
}

func (node *daemonMeshIntegrationNode) start(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
) {
	t.Helper()
	if node == nil || node.running || node.listener == nil {
		t.Fatal("invalid daemon mesh test start")
	}
	options := daemonOptions{
		statePath:     node.statePath,
		consensusDir:  node.consensusDir,
		endpoint:      node.localEndpoint,
		sessionID:     daemonTestSessionID,
		workspaceID:   daemonTestWorkspaceID,
		peerListeners: []netip.AddrPort{node.peerEndpoint},
	}
	for _, peer := range nodes {
		if peer.deviceID == node.deviceID {
			continue
		}
		options.peerRoutes = append(options.peerRoutes, daemonPeerRoute{
			deviceID: peer.deviceID,
			remote:   peer.peerEndpoint,
			local:    node.peerEndpoint.Addr(),
		})
	}
	sort.Slice(options.peerRoutes, func(left, right int) bool {
		return options.peerRoutes[left].deviceID <
			options.peerRoutes[right].deviceID
	})

	reserved := node.listener
	claimed := false
	ctx, cancel := context.WithCancel(context.Background())
	node.cancel = cancel
	node.exited = make(chan struct{})
	node.exitErr = nil
	node.running = true
	node.meshCapture.reset()
	go func() {
		productionDependencies := productionDaemonDependencies()
		node.exitErr = runDaemon(
			ctx,
			options,
			daemonDependencies{
				loadIdentity: func(
					context.Context,
				) (identityHandle, []byte, error) {
					return node.credentials,
						bytes.Clone(node.privateKey),
						nil
				},
				newBootID: productionDependencies.newBootID,
				newMeshFactory: newDaemonMeshIntegrationFactoryConstructor(
					node.meshCapture,
				),
				listenPeer: func(
					_ context.Context,
					endpoint netip.AddrPort,
				) (net.Listener, error) {
					if claimed || endpoint != node.peerEndpoint {
						return nil, fmt.Errorf(
							"unexpected peer listener request %s",
							endpoint,
						)
					}
					claimed = true
					return reserved, nil
				},
				openMulticast:     openDaemonMeshIntegrationMulticast,
				listInterfaces:    productionDependencies.listInterfaces,
				interfaceAddrs:    productionDependencies.interfaceAddrs,
				credentialNow:     node.credentialNow,
				canonicalCoverage: node.coverage,
			},
		)
		close(node.exited)
	}()
}

func (node *daemonMeshIntegrationNode) stop(t *testing.T) {
	t.Helper()
	if node == nil || !node.running || node.cancel == nil {
		t.Fatal("daemon mesh test node is not running")
	}
	node.cancel()
	select {
	case <-node.exited:
	case <-time.After(daemonMeshIntegrationTimeout):
		t.Fatalf("daemon %s did not shut down", node.deviceID)
	}
	node.running = false
	node.cancel = nil
	node.listener = nil
	if node.exitErr != nil {
		t.Fatalf("runDaemon(%s): %v", node.deviceID, node.exitErr)
	}
}

func (node *daemonMeshIntegrationNode) cleanup(t *testing.T) {
	t.Helper()
	if node == nil {
		return
	}
	if node.running {
		node.cancel()
		select {
		case <-node.exited:
			if node.exitErr != nil {
				t.Errorf("runDaemon(%s): %v", node.deviceID, node.exitErr)
			}
		case <-time.After(daemonMeshIntegrationTimeout):
			t.Errorf("daemon %s did not shut down", node.deviceID)
		}
		node.running = false
	}
	if node.listener != nil {
		if err := node.listener.Close(); err != nil &&
			!strings.Contains(err.Error(), "closed network connection") {
			t.Errorf("close reserved listener %s: %v", node.deviceID, err)
		}
		node.listener = nil
	}
	node.credentials.wipe()
}

func waitForDaemonMeshIntegrationCluster(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	ready func([]ui.Snapshot) bool,
) []ui.Snapshot {
	t.Helper()
	_, callerFile, callerLine, _ := runtime.Caller(1)
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var lastErr error
	var lastStatuses []ui.Snapshot
	for time.Now().Before(deadline) {
		statuses := make([]ui.Snapshot, len(nodes))
		complete := true
		for index, node := range nodes {
			select {
			case <-node.exited:
				node.running = false
				t.Fatalf(
					"daemon %s exited before convergence: %v",
					node.deviceID,
					node.exitErr,
				)
			default:
			}
			status, err := readDaemonMeshIntegrationStatus(
				node.localEndpoint,
			)
			if err != nil {
				lastErr = fmt.Errorf("%s: %w", node.deviceID, err)
				complete = false
				break
			}
			statuses[index] = status
		}
		if complete {
			lastStatuses = statuses
			if ready(statuses) {
				return statuses
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	states := make([]string, 0, len(nodes))
	for _, node := range nodes {
		stage, ready := node.meshCapture.lifecycleState()
		state := fmt.Sprintf(
			"%s(running=%t, stage=%q, ready=%t, fatal=%v)",
			node.deviceID,
			node.running,
			stage,
			ready,
			node.meshCapture.fatalError(),
		)
		select {
		case <-node.exited:
			state = fmt.Sprintf(
				"%s(running=%t, exited=%v, stage=%q, ready=%t, fatal=%v)",
				node.deviceID,
				node.running,
				node.exitErr,
				stage,
				ready,
				node.meshCapture.fatalError(),
			)
		default:
		}
		states = append(states, state)
	}
	t.Fatalf(
		"daemon mesh wait at %s:%d did not converge: %v; statuses: %s; nodes: %s",
		filepath.Base(callerFile),
		callerLine,
		lastErr,
		daemonMeshIntegrationStatusSummary(lastStatuses),
		strings.Join(states, ", "),
	)
	return nil
}

func daemonMeshIntegrationStatusSummary(statuses []ui.Snapshot) string {
	if len(statuses) == 0 {
		return "<none>"
	}
	summaries := make([]string, 0, len(statuses))
	for _, status := range statuses {
		taskIDs := make([]string, 0, len(status.Tasks))
		for _, task := range status.Tasks {
			taskIDs = append(taskIDs, task.TaskID)
		}
		summaries = append(summaries, fmt.Sprintf(
			"%s(result=%d, chain=%d, raft=%v, state=%s, role=%s, voter_version=%d, activated_version=%d, target=%v, tasks=%v)",
			status.Session.LocalDeviceID,
			status.Session.ResultIndex,
			status.Session.EventChainIndex,
			status.Session.AppliedRaftIndex,
			status.Consensus.State,
			status.Consensus.Role,
			status.Consensus.VoterSetVersion,
			status.Consensus.ActivatedVoterSetVersion,
			status.Consensus.TargetVoterDeviceIDs,
			taskIDs,
		))
	}
	return strings.Join(summaries, ", ")
}

func readDaemonMeshIntegrationStatus(
	endpoint ipc.Endpoint,
) (ui.Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
		Endpoint:    endpoint,
		SessionID:   daemonTestSessionID,
		WorkspaceID: daemonTestWorkspaceID,
	})
	if err != nil {
		return ui.Snapshot{}, err
	}
	status, statusErr := client.Status(ctx)
	closeErr := client.Close()
	if statusErr != nil {
		return ui.Snapshot{}, statusErr
	}
	if closeErr != nil {
		return ui.Snapshot{}, closeErr
	}
	return status, nil
}

func daemonMeshIntegrationClusterReady(
	statuses []ui.Snapshot,
	liveVoters []domain.DeviceID,
) bool {
	if len(statuses) == 0 || len(liveVoters) == 0 {
		return false
	}
	var leaderID string
	leaderCount := 0
	for _, status := range statuses {
		if status.Consensus.State != "ready" ||
			status.Consensus.LeaderDeviceID == nil ||
			!sameDaemonMeshIntegrationIDs(
				status.Consensus.LiveVoterDeviceIDs,
				liveVoters,
			) {
			return false
		}
		if leaderID == "" {
			leaderID = *status.Consensus.LeaderDeviceID
		} else if leaderID != *status.Consensus.LeaderDeviceID {
			return false
		}
		if status.Consensus.Role == "leader" {
			leaderCount++
			if status.Consensus.StrongWrites != "available" ||
				status.Session.LocalDeviceID != leaderID {
				return false
			}
		} else if status.Consensus.Role != "follower" ||
			status.Consensus.StrongWrites != "waiting" {
			return false
		}
	}
	return leaderCount == 1
}

func daemonMeshIntegrationTarget(
	statuses []ui.Snapshot,
	version uint64,
	target []domain.DeviceID,
) bool {
	for _, status := range statuses {
		if status.Consensus.VoterSetVersion != version ||
			status.Consensus.ActivatedVoterSetVersion != version ||
			!sameDaemonMeshIntegrationIDs(
				status.Consensus.TargetVoterDeviceIDs,
				target,
			) ||
			!sameDaemonMeshIntegrationIDs(
				status.Consensus.ActivatedVoterDeviceIDs,
				target,
			) {
			return false
		}
	}
	return true
}

func daemonMeshIntegrationMemberStatus(
	statuses []ui.Snapshot,
	deviceID domain.DeviceID,
	status device.Status,
	entityVersion uint64,
) bool {
	for _, snapshot := range statuses {
		found := false
		for _, member := range snapshot.Members {
			if member.DeviceID != string(deviceID) {
				continue
			}
			if member.Status != string(status) ||
				member.EntityVersion != entityVersion {
				return false
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func daemonMeshIntegrationMutationConverged(
	statuses []ui.Snapshot,
) bool {
	if len(statuses) == 0 ||
		statuses[0].Session.EventChainIndex < 1 ||
		statuses[0].Session.ResultIndex < 1 {
		return false
	}
	for _, status := range statuses[1:] {
		if status.Session.EventChainIndex !=
			statuses[0].Session.EventChainIndex ||
			status.Session.ResultIndex != statuses[0].Session.ResultIndex {
			return false
		}
	}
	return true
}

func waitForDaemonMeshIntegrationStableHeads(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	stableFor time.Duration,
) {
	t.Helper()
	if len(nodes) == 0 || stableFor <= 0 {
		t.Fatal("invalid daemon mesh stable-head fixture")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	var (
		stableSince  time.Time
		stableChain  uint64
		stableResult uint64
		lastErr      error
	)
	for time.Now().Before(deadline) {
		statuses := make([]ui.Snapshot, len(nodes))
		complete := true
		for index, node := range nodes {
			select {
			case <-node.exited:
				node.running = false
				t.Fatalf(
					"daemon %s exited before stable heads: %v",
					node.deviceID,
					node.exitErr,
				)
			default:
			}
			status, err := readDaemonMeshIntegrationStatus(
				node.localEndpoint,
			)
			if err != nil {
				lastErr = fmt.Errorf("%s: %w", node.deviceID, err)
				complete = false
				break
			}
			statuses[index] = status
		}
		now := time.Now()
		if complete && daemonMeshIntegrationMutationConverged(statuses) {
			chainIndex := statuses[0].Session.EventChainIndex
			resultIndex := statuses[0].Session.ResultIndex
			if stableSince.IsZero() ||
				chainIndex != stableChain ||
				resultIndex != stableResult {
				stableSince = now
				stableChain = chainIndex
				stableResult = resultIndex
			} else if now.Sub(stableSince) >= stableFor {
				return
			}
		} else {
			stableSince = time.Time{}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf(
		"daemon mesh heads did not remain converged for %s: last error %v",
		stableFor,
		lastErr,
	)
}

func daemonMeshIntegrationTaskConverged(
	statuses []ui.Snapshot,
	taskID domain.UUIDv7,
) bool {
	if len(statuses) == 0 || !taskID.Valid() {
		return false
	}
	for _, snapshot := range statuses {
		if snapshot.TaskTotal != 1 ||
			snapshot.Truncated ||
			len(snapshot.Tasks) != 1 ||
			snapshot.Tasks[0].TaskID != string(taskID) ||
			snapshot.Tasks[0].EntityVersion != 1 {
			return false
		}
	}
	return daemonMeshIntegrationMutationConverged(statuses)
}

func daemonMeshIntegrationLeaderIndex(statuses []ui.Snapshot) int {
	for index, status := range statuses {
		if status.Consensus.Role == "leader" {
			return index
		}
	}
	return -1
}

func daemonMeshIntegrationNodeByID(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	deviceID domain.DeviceID,
) *daemonMeshIntegrationNode {
	t.Helper()
	for _, node := range nodes {
		if node.deviceID == deviceID {
			return node
		}
	}
	t.Fatalf("unknown daemon %s", deviceID)
	return nil
}

func daemonMeshIntegrationFollower(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	leaderID domain.DeviceID,
) *daemonMeshIntegrationNode {
	t.Helper()
	for _, node := range nodes {
		if node.deviceID != leaderID {
			return node
		}
	}
	t.Fatal("mesh has no follower to restart")
	return nil
}

func (node *daemonMeshIntegrationNode) indexIn(
	nodes []*daemonMeshIntegrationNode,
) int {
	for index, candidate := range nodes {
		if candidate == node {
			return index
		}
	}
	return -1
}

func dialDaemonMeshIntegrationOperator(
	t *testing.T,
	endpoint ipc.Endpoint,
) *ui.OperatorClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
		Endpoint:    endpoint,
		SessionID:   daemonTestSessionID,
		WorkspaceID: daemonTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("DialOperator(): %v", err)
	}
	return client
}

func admitDaemonMeshPairingJoiner(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	existingNonvoterID domain.DeviceID,
	inviter *daemonMeshIntegrationNode,
	snapshotSigner *daemonMeshIntegrationNode,
	operator *ui.OperatorClient,
	selectedAddress netip.Addr,
	credentialNow func() time.Time,
) daemonMeshIntegrationPairedMember {
	t.Helper()
	if len(nodes) != 3 ||
		!existingNonvoterID.Valid() ||
		inviter == nil ||
		snapshotSigner == nil ||
		inviter.deviceID == snapshotSigner.deviceID ||
		operator == nil ||
		!selectedAddress.IsValid() ||
		credentialNow == nil ||
		credentialNow().IsZero() ||
		inviter.peerEndpoint.Addr() != selectedAddress {
		t.Fatal("invalid daemon pairing fixture")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()

	created, err := operator.CreatePairingInvite(
		ctx,
		pairingservice.CreateInviteRequest{
			Mode:                   pairing.ModeNew,
			Role:                   device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	)
	if err != nil {
		t.Fatalf("CreatePairingInvite(): %v", err)
	}
	invite, err := pairing.ParseInviteCode(created.Code)
	if err != nil {
		t.Fatalf("ParseInviteCode(): %v", err)
	}
	inviteValue := invite.Invite()
	defer clear(inviteValue.Secret[:])
	if inviteValue.InviterDeviceID != inviter.deviceID ||
		len(inviteValue.Endpoints) != 1 ||
		inviteValue.Endpoints[0].IP != selectedAddress ||
		inviteValue.Endpoints[0].Port != inviter.peerEndpoint.Port() {
		t.Fatalf("issued invite endpoint or identity = %+v", inviteValue)
	}

	dialer := net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.IP(selectedAddress.AsSlice()),
		},
	}
	credentials := newDaemonTestCredentialStore()
	t.Cleanup(credentials.wipe)
	statePath := filepath.Join(t.TempDir(), "fresh-device", "state.db")
	reviews := make(chan pairingjoiner.ReviewSubject, 1)
	approvals := make(chan bool, 1)
	type joinOutcome struct {
		result joinbootstrap.Result
		err    error
	}
	outcomes := make(chan joinOutcome, 1)
	go func() {
		result, runErr := joinbootstrap.Run(
			ctx,
			joinbootstrap.Options{
				StatePath:   statePath,
				Credentials: credentials,
				Invite:      invite,
				Confirm: func(
					confirmContext context.Context,
					review pairingjoiner.ReviewSubject,
				) (bool, error) {
					select {
					case reviews <- review:
					case <-confirmContext.Done():
						return false, confirmContext.Err()
					}
					select {
					case approved := <-approvals:
						return approved, nil
					case <-confirmContext.Done():
						return false, confirmContext.Err()
					}
				},
				Dial: dialer.DialContext,
				Now:  credentialNow,
			},
		)
		outcomes <- joinOutcome{result: result, err: runErr}
	}()

	var review pairingjoiner.ReviewSubject
	select {
	case review = <-reviews:
	case outcome := <-outcomes:
		t.Fatalf(
			"joinbootstrap.Run() exited before local review: (%+v, %v)",
			outcome.result,
			outcome.err,
		)
	case <-ctx.Done():
		t.Fatalf("wait for local join review: %v", ctx.Err())
	}
	if review.InviteID != inviteValue.InviteID ||
		review.InviteDigest != invite.Digest() ||
		review.SessionID != inviteValue.SessionID ||
		review.WorkspaceID != inviteValue.WorkspaceID ||
		review.RecoveryGeneration != inviteValue.RecoveryGeneration ||
		review.Mode != pairing.ModeNew ||
		review.SubjectDeviceID != nil ||
		review.ExpectedEntityVersion != nil ||
		review.Role != device.RoleEditor ||
		review.InviterDeviceID != inviter.deviceID ||
		review.InviterIdentityPublicKey !=
			inviteValue.InviterIdentityPublicKey ||
		review.SignedGenesisDigest != inviteValue.SignedGenesisDigest ||
		review.ConnectedEndpoint != inviter.peerEndpoint ||
		review.Core.JoinerDeviceID == inviter.deviceID ||
		review.Core.DaemonVersion != joinbootstrap.CurrentDaemonVersion ||
		review.Core.MaxApplyLevel != joinbootstrap.CurrentMaxApplyLevel ||
		review.Core.InitialEpochBinding.Epoch != 1 ||
		review.Core.InitialEpochBinding.DeviceID !=
			review.Core.JoinerDeviceID ||
		review.Core.InitialEpochBinding.SessionID !=
			daemonTestSessionID ||
		review.Core.InitialEpochBinding.Validate(
			review.Core.JoinerIdentityPublicKey[:],
		) != nil {
		t.Fatalf("joiner local review = %+v", review)
	}

	attempt, err := operator.PairingAttempt(ctx, review.AttemptID)
	if err != nil {
		t.Fatalf("PairingAttempt(): %v", err)
	}
	if !daemonMeshPairingAttemptMatchesReview(attempt, review) ||
		attempt.State != string(store.PairingAttemptAwaitingSAS) ||
		attempt.RemoteConfirmed ||
		attempt.LocalConfirmed {
		t.Fatalf("pairing attempt before local approval = %+v", attempt)
	}
	select {
	case approvals <- true:
	case <-ctx.Done():
		t.Fatalf("approve local join review: %v", ctx.Err())
	}

	for {
		attempt, err = operator.PairingAttempt(ctx, review.AttemptID)
		if err == nil {
			if !daemonMeshPairingAttemptMatchesReview(attempt, review) {
				t.Fatalf("pairing review changed after approval = %+v", attempt)
			}
			if attempt.RemoteConfirmed {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf(
				"wait for remote pairing confirmation: %v (last error: %v)",
				ctx.Err(),
				err,
			)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if attempt.LocalConfirmed {
		t.Fatalf("inviter was already locally confirmed = %+v", attempt)
	}
	localResult, err := operator.ConfirmPairing(ctx, attempt, true)
	if err != nil {
		t.Fatalf("ConfirmPairing(): %v", err)
	}
	if !daemonMeshPairingAttemptMatchesReview(localResult, review) ||
		!localResult.RemoteConfirmed ||
		!localResult.LocalConfirmed {
		t.Fatalf("inviter pairing confirmation = %+v", localResult)
	}

	var outcome joinOutcome
	select {
	case outcome = <-outcomes:
	case <-ctx.Done():
		t.Fatalf("wait for fresh-device bootstrap: %v", ctx.Err())
	}
	if outcome.err != nil {
		t.Fatalf("joinbootstrap.Run(): %v", outcome.err)
	}
	joined := outcome.result
	if joined.SessionID != daemonTestSessionID ||
		joined.WorkspaceID != daemonTestWorkspaceID ||
		joined.RecoveryGeneration != inviteValue.RecoveryGeneration ||
		joined.DeviceID != review.Core.JoinerDeviceID ||
		joined.StatePath != statePath ||
		joined.Resumed {
		t.Fatalf("fresh-device join result = %+v", joined)
	}
	if pending, pendingErr := joinbootstrap.HasPending(statePath); pendingErr != nil ||
		pending {
		t.Fatalf(
			"join pending journal after completion = (%t, %v)",
			pending,
			pendingErr,
		)
	}

	completed, err := operator.PairingAttempt(ctx, review.AttemptID)
	if err != nil {
		t.Fatalf("PairingAttempt(completed): %v", err)
	}
	if !daemonMeshPairingAttemptMatchesReview(completed, review) ||
		completed.State != string(store.PairingAttemptCompleted) ||
		!completed.RemoteConfirmed ||
		!completed.LocalConfirmed {
		t.Fatalf("completed pairing attempt = %+v", completed)
	}

	member, authorization, epochPrivateKey, identityPrivateKey :=
		assertDaemonMeshFreshJoinDurableState(
			t,
			nodes,
			existingNonvoterID,
			snapshotSigner,
			joined,
			review,
			credentials,
			credentialNow,
		)
	defer clear(epochPrivateKey)
	defer clear(identityPrivateKey)
	contentCertificate, contentBinding, err :=
		transport.IssueContentCertificate(
			authorization,
			epochPrivateKey,
		)
	if err != nil ||
		contentBinding.SessionID != joined.SessionID ||
		contentBinding.DeviceID != joined.DeviceID ||
		contentBinding.Epoch != authorization.Epoch {
		t.Fatalf(
			"IssueContentCertificate(joined) = (%+v, %v)",
			contentBinding,
			err,
		)
	}
	interval := time.Duration(
		policy.DefaultAdvertisementIntervalSeconds,
	) * time.Second
	endpointSigner, err := discovery.NewEndpointSigner(
		interval,
		snapshotSigner.peerEndpoint.Port(),
		[]netip.Addr{selectedAddress},
	)
	if err != nil {
		clearDaemonTLSCertificate(&contentCertificate)
		t.Fatalf("NewEndpointSigner(joiner): %v", err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	endpointSet, err := endpointSigner.Sign(
		discovery.EndpointSet{
			SessionID:          daemonTestSessionID,
			WorkspaceID:        daemonTestWorkspaceID,
			RecoveryGeneration: 0,
			DeviceID:           joined.DeviceID,
			EndpointSequence:   1,
			IssuedAt: domain.WholeSecondTimestamp(
				issuedAt.Format(time.RFC3339),
			),
			ExpiresAt: domain.WholeSecondTimestamp(
				issuedAt.Add(
					interval * discovery.EndpointHintTTLIntervals,
				).Format(time.RFC3339),
			),
			Endpoints: []discovery.Endpoint{{
				IP: selectedAddress, Port: snapshotSigner.peerEndpoint.Port(),
			}},
		},
		identityPrivateKey,
	)
	if err != nil {
		clearDaemonTLSCertificate(&contentCertificate)
		t.Fatalf("sign joiner endpoint set: %v", err)
	}
	return daemonMeshIntegrationPairedMember{
		member:      member,
		certificate: contentCertificate,
		endpointSet: endpointSet,
	}
}

func daemonMeshPairingAttemptMatchesReview(
	attempt ui.PairingAttemptStatus,
	review pairingjoiner.ReviewSubject,
) bool {
	return attempt.AttemptID == string(review.AttemptID) &&
		attempt.InviteID == string(review.InviteID) &&
		attempt.RequestDigest == codec.EncodeBase64URL(
			review.RequestDigest[:],
		) &&
		attempt.Mode == string(review.Mode) &&
		attempt.JoinerDeviceID == string(review.Core.JoinerDeviceID) &&
		attempt.JoinerIdentityPublicKey == codec.EncodeBase64URL(
			review.Core.JoinerIdentityPublicKey[:],
		) &&
		attempt.DaemonVersion == review.Core.DaemonVersion &&
		attempt.MaxApplyLevel == review.Core.MaxApplyLevel &&
		attempt.Role == string(review.Role) &&
		attempt.ExpectedEntityVersion == nil &&
		review.ExpectedEntityVersion == nil &&
		attempt.InitialCredentialEpoch ==
			review.Core.InitialEpochBinding.Epoch &&
		attempt.EpochPublicKey == codec.EncodeBase64URL(
			review.Core.InitialEpochBinding.EpochPublicKey[:],
		) &&
		attempt.EpochKeyDigest == codec.EncodeBase64URL(
			review.Core.InitialEpochBinding.KeyDigest[:],
		) &&
		attempt.SAS == review.SAS
}

func assertDaemonMeshFreshJoinDurableState(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	existingNonvoterID domain.DeviceID,
	leader *daemonMeshIntegrationNode,
	joined joinbootstrap.Result,
	review pairingjoiner.ReviewSubject,
	credentials *daemonTestCredentialStore,
	credentialNow func() time.Time,
) (
	device.Device,
	credentialauthorization.Authorization,
	ed25519.PrivateKey,
	ed25519.PrivateKey,
) {
	t.Helper()
	if len(nodes) != 3 ||
		!existingNonvoterID.Valid() ||
		leader == nil ||
		credentials == nil ||
		credentialNow == nil {
		t.Fatal("invalid durable fresh-join assertion fixture")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()

	database, err := store.Open(
		ctx,
		store.Options{Path: joined.StatePath},
	)
	if err != nil {
		t.Fatalf("reopen joined state: %v", err)
	}
	defer func() {
		if database != nil {
			_ = database.Close()
		}
	}()
	mode, err := database.ReplicaEvidenceMode(ctx)
	if err != nil || mode != store.ReplicaEvidenceSettledNonvoter {
		t.Fatalf("joined replica evidence mode = (%q, %v)", mode, err)
	}
	settledView, err := database.VerifiedSettledNonvoterView(ctx)
	if err != nil {
		t.Fatalf("joined VerifiedSettledNonvoterView(): %v", err)
	}
	if settledView.SessionID != joined.SessionID ||
		settledView.WorkspaceID != joined.WorkspaceID ||
		settledView.RecoveryGeneration != joined.RecoveryGeneration ||
		settledView.CurrentTerm != nil ||
		settledView.LastRaftAppliedLogIndex != nil {
		t.Fatalf("joined settled view = %+v", settledView)
	}
	if err := database.VerifyCommitmentHistory(ctx); err != nil {
		t.Fatalf("joined VerifyCommitmentHistory(): %v", err)
	}
	snapshotRoot, found, err :=
		database.VerifiedStandaloneLogicalSnapshotBaseline(ctx)
	if err != nil || !found {
		t.Fatalf(
			"joined snapshot baseline = (found=%t, err=%v)",
			found,
			err,
		)
	}
	snapshotInput := snapshotRoot.Unsigned().Input()
	if snapshotInput.SessionID != settledView.SessionID ||
		snapshotInput.WorkspaceID != settledView.WorkspaceID ||
		snapshotInput.RecoveryGeneration !=
			settledView.RecoveryGeneration ||
		snapshotInput.SignerDeviceID != leader.deviceID ||
		snapshotInput.ChainIndex != settledView.Heads.ChainIndex ||
		store.Digest(snapshotInput.ChainHash) !=
			settledView.Heads.ChainHash ||
		snapshotInput.ResultIndex != settledView.Heads.ResultIndex ||
		store.Digest(snapshotInput.ResultHash) !=
			settledView.Heads.ResultHash ||
		store.Digest(snapshotInput.ProjectionAccumulator) !=
			settledView.Heads.ProjectionAccumulator ||
		store.Digest(snapshotInput.ProjectionStateDigest) !=
			settledView.ProjectionStateDigest ||
		snapshotInput.DigestVersion !=
			settledView.Heads.DigestVersion ||
		snapshotInput.ProjectionSchemaVersion !=
			settledView.Heads.ProjectionSchemaVersion {
		t.Fatalf(
			"joined snapshot cut differs from installed view:\nroot=%+v\nview=%+v",
			snapshotInput,
			settledView,
		)
	}
	progress, err := database.SettledReplicationProgress(ctx)
	if err != nil {
		t.Fatalf("joined SettledReplicationProgress(): %v", err)
	}
	if progress.Blocker != nil || progress.Heads != settledView.Heads {
		t.Fatalf("joined settled replication progress = %+v", progress)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close joined state: %v", err)
	}
	database = nil

	replica, err := consensus.OpenSettledReplica(
		ctx,
		consensus.SettledReplicaOptions{
			StatePath:     joined.StatePath,
			OriginBootID:  daemonTestVerifyBootID,
			LocalDeviceID: joined.DeviceID,
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(joined): %v", err)
	}
	defer func() {
		if replica != nil {
			_ = replica.Close()
		}
	}()
	admission, err := replica.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("joined PeerAdmissionSnapshot(): %v", err)
	}
	sessionID, recoveryGeneration, valid := admission.Lineage()
	appliedChainIndex, applied := admission.AppliedChainIndex()
	member, memberFound := admission.Member(joined.DeviceID)
	if !valid ||
		!applied ||
		sessionID != joined.SessionID ||
		recoveryGeneration != joined.RecoveryGeneration ||
		appliedChainIndex != settledView.Heads.ChainIndex ||
		!memberFound ||
		member.ID != joined.DeviceID ||
		member.Role != device.RoleEditor ||
		!bytes.Equal(
			member.IdentityPublicKey,
			review.Core.JoinerIdentityPublicKey[:],
		) ||
		member.DaemonVersion != joinbootstrap.CurrentDaemonVersion ||
		member.MaxApplyLevel != joinbootstrap.CurrentMaxApplyLevel ||
		member.Status != device.StatusActive ||
		member.EntityVersion != 1 {
		t.Fatalf(
			"joined admission lineage/member = (%s, %d, %t, %d, %t, %+v)",
			sessionID,
			recoveryGeneration,
			valid,
			appliedChainIndex,
			applied,
			member,
		)
	}
	roster, rosterValid := admission.ActiveRoster()
	expectedRoster := make(
		map[domain.DeviceID]struct{},
		len(nodes)+2,
	)
	for _, node := range nodes {
		expectedRoster[node.deviceID] = struct{}{}
	}
	expectedRoster[existingNonvoterID] = struct{}{}
	expectedRoster[joined.DeviceID] = struct{}{}
	if !rosterValid || len(roster) != len(expectedRoster) {
		t.Fatalf("joined active roster = (%+v, %t)", roster, rosterValid)
	}
	for _, rosterMember := range roster {
		if _, expected := expectedRoster[rosterMember.Device.ID]; !expected {
			t.Fatalf(
				"joined active roster has unexpected member %+v",
				rosterMember,
			)
		}
		delete(expectedRoster, rosterMember.Device.ID)
	}
	if len(expectedRoster) != 0 {
		t.Fatalf("joined active roster omitted members: %+v", expectedRoster)
	}
	authority, authorityValid := admission.CredentialAuthority()
	voterIDs := daemonMeshIntegrationDeviceIDs(nodes)
	if !authorityValid ||
		authority.SessionID != joined.SessionID ||
		authority.VoterSetVersion != 1 ||
		!sameDaemonMeshIntegrationDeviceIDs(
			authority.VoterDeviceIDs,
			voterIDs,
		) {
		t.Fatalf(
			"joined credential authority = (%+v, %t)",
			authority,
			authorityValid,
		)
	}
	currentEpoch, currentEpochFound :=
		admission.CurrentCredentialEpoch(joined.DeviceID)
	authorization, authorizationFound :=
		admission.ActiveCredentialAuthorizationAt(
			joined.DeviceID,
			credentialNow(),
		)
	if !currentEpochFound ||
		currentEpoch != review.Core.InitialEpochBinding.Epoch ||
		!authorizationFound ||
		authorization.SessionID != joined.SessionID ||
		authorization.DeviceID != joined.DeviceID ||
		authorization.Epoch != currentEpoch ||
		authorization.Role != credentialauthorization.RoleEditor ||
		authorization.AuthorityVoterSetVersion != 1 ||
		authorization.AuthorizationChainIndex < 1 ||
		authorization.AuthorizationChainIndex > appliedChainIndex {
		t.Fatalf(
			"joined current credential = (epoch=%d, found=%t, authorization=%+v, active=%t)",
			currentEpoch,
			currentEpochFound,
			authorization,
			authorizationFound,
		)
	}
	if err := replica.Close(); err != nil {
		t.Fatalf("close joined settled replica: %v", err)
	}
	replica = nil

	identityBytes, err := credentials.Get(
		ctx,
		credentialstore.IdentityReference(),
	)
	if err != nil || len(identityBytes) != ed25519.PrivateKeySize {
		clear(identityBytes)
		t.Fatalf(
			"load joined identity key = (%d bytes, %v)",
			len(identityBytes),
			err,
		)
	}
	identityPrivateKey := ed25519.PrivateKey(identityBytes)
	identityPublicKey := identityPrivateKey.Public().(ed25519.PublicKey)
	derived, deriveErr := device.DeriveID(identityPublicKey)
	if deriveErr != nil ||
		derived != joined.DeviceID ||
		!bytes.Equal(identityPublicKey, member.IdentityPublicKey) {
		clear(identityPrivateKey)
		t.Fatalf(
			"persisted joined identity = (%s, %v), want %s",
			derived,
			deriveErr,
			joined.DeviceID,
		)
	}
	epochReference, err := credentialstore.EpochReference(
		joined.SessionID,
		joined.DeviceID,
		currentEpoch,
	)
	if err != nil {
		clear(identityPrivateKey)
		t.Fatalf("joined epoch reference: %v", err)
	}
	epochBytes, err := credentials.Get(ctx, epochReference)
	if err != nil || len(epochBytes) != ed25519.PrivateKeySize {
		clear(epochBytes)
		clear(identityPrivateKey)
		t.Fatalf(
			"load joined epoch key = (%d bytes, %v)",
			len(epochBytes),
			err,
		)
	}
	epochPrivateKey := ed25519.PrivateKey(epochBytes)
	epochPublicKey := epochPrivateKey.Public().(ed25519.PublicKey)
	binding := credential.Binding{
		SessionID:      authorization.SessionID,
		DeviceID:       authorization.DeviceID,
		Epoch:          authorization.Epoch,
		EpochPublicKey: authorization.EpochPublicKey,
		KeyDigest:      authorization.KeyDigest,
		Signature:      authorization.BindingSignature,
	}
	if !bytes.Equal(
		epochPublicKey,
		authorization.EpochPublicKey[:],
	) || binding != review.Core.InitialEpochBinding ||
		binding.Validate(identityPublicKey) != nil {
		clear(epochPrivateKey)
		clear(identityPrivateKey)
		t.Fatal("joined credential authorization does not bind persisted keys")
	}
	return member, authorization, epochPrivateKey, identityPrivateKey
}

func assertDaemonMeshIntegrationDurableMutation(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	revokedDeviceID domain.DeviceID,
	activeDeviceID domain.DeviceID,
	voterIDs []domain.DeviceID,
	minChainIndex, minResultIndex uint64,
) {
	t.Helper()
	var baseline *store.StateView
	for _, node := range nodes {
		database, err := store.Open(
			context.Background(),
			store.Options{Path: node.statePath},
		)
		if err != nil {
			t.Fatalf("reopen store %s: %v", node.deviceID, err)
		}
		status, statusErr := database.LocalState().StatusSnapshot(
			context.Background(),
			node.deviceID,
			1,
		)
		view, viewErr := database.View(context.Background())
		verifyErr := database.VerifyCommitmentHistory(context.Background())
		closeErr := database.Close()
		if statusErr != nil {
			t.Fatalf("durable status %s: %v", node.deviceID, statusErr)
		}
		if viewErr != nil {
			t.Fatalf("durable view %s: %v", node.deviceID, viewErr)
		}
		if verifyErr != nil {
			t.Fatalf("verify commitments %s: %v", node.deviceID, verifyErr)
		}
		if closeErr != nil {
			t.Fatalf("close durable store %s: %v", node.deviceID, closeErr)
		}
		targetIDs := status.VoterSet.VoterDeviceIDs()
		authorityIDs := status.CredentialAuthority.VoterDeviceIDs()
		revoked := false
		active := false
		for _, member := range status.Members {
			if member.ID == revokedDeviceID {
				revoked = member.Status == device.StatusRevoked &&
					member.EntityVersion == 2
			}
			if member.ID == activeDeviceID {
				active = member.Status == device.StatusActive &&
					member.EntityVersion == 1
			}
		}
		if status.VoterSet.VoterSetVersion != 1 ||
			status.CredentialAuthority.VoterSetVersion != 1 ||
			!sameDaemonMeshIntegrationDeviceIDs(targetIDs, voterIDs) ||
			!sameDaemonMeshIntegrationDeviceIDs(authorityIDs, voterIDs) ||
			!revoked ||
			!active ||
			status.Heads.ChainIndex < minChainIndex ||
			status.Heads.ResultIndex < minResultIndex {
			t.Fatalf("durable status %s = %#v", node.deviceID, status)
		}
		if baseline == nil {
			cloned := view
			baseline = &cloned
			continue
		}
		if view.Heads != baseline.Heads ||
			view.ProjectionStateDigest != baseline.ProjectionStateDigest ||
			!reflect.DeepEqual(view.ProjectionRows, baseline.ProjectionRows) {
			t.Fatalf(
				"durable state on %s diverged from the first daemon: heads=%+v want=%+v, state=%x want=%x, rows=%d want=%d",
				node.deviceID,
				view.Heads,
				baseline.Heads,
				view.ProjectionStateDigest,
				baseline.ProjectionStateDigest,
				len(view.ProjectionRows),
				len(baseline.ProjectionRows),
			)
		}
	}
}

func sameDaemonMeshIntegrationDeviceIDs(
	actual, expected []domain.DeviceID,
) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func daemonMeshIntegrationDeviceIDs(
	nodes []*daemonMeshIntegrationNode,
) []domain.DeviceID {
	result := make([]domain.DeviceID, len(nodes))
	for index, node := range nodes {
		result[index] = node.deviceID
	}
	return result
}

func sameDaemonMeshIntegrationIDs(
	actual []string,
	expected []domain.DeviceID,
) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != string(expected[index]) {
			return false
		}
	}
	return true
}

func reserveDaemonMeshIntegrationListeners(
	t *testing.T,
	count int,
) (netip.Addr, []net.Listener) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("enumerate network interfaces: %v", err)
	}
	var candidates []netip.Addr
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 ||
			networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			prefix, parseErr := netip.ParsePrefix(address.String())
			if parseErr != nil {
				continue
			}
			candidate := prefix.Addr()
			if candidate.Is4() &&
				validDaemonSelectedAddress(candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].Compare(candidates[right]) < 0
	})
	for _, candidate := range candidates {
		listeners := make([]net.Listener, 0, count)
		for range count {
			listener, listenErr := net.ListenTCP(
				"tcp4",
				net.TCPAddrFromAddrPort(
					netip.AddrPortFrom(candidate, 0),
				),
			)
			if listenErr != nil {
				for _, opened := range listeners {
					_ = opened.Close()
				}
				listeners = nil
				break
			}
			listeners = append(listeners, listener)
		}
		if len(listeners) == count {
			return candidate, listeners
		}
	}
	if os.Getenv(daemonMeshIntegrationRequired) == "1" {
		t.Fatal("no bindable non-loopback IPv4 interface")
	}
	t.Skip("no bindable non-loopback IPv4 interface")
	return netip.Addr{}, nil
}

func listenDaemonMeshIntegrationEndpoint(
	t *testing.T,
	endpoint netip.AddrPort,
) net.Listener {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		listener, err := net.ListenTCP(
			"tcp4",
			net.TCPAddrFromAddrPort(endpoint),
		)
		if err == nil {
			return listener
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("rebind %s: %v", endpoint, lastErr)
	return nil
}

func runDaemonMeshIntegrationChild(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationProcessTimeout,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestDaemonProductionMeshComposition$",
		"-test.count=1",
		"-test.v",
	)
	command.Env = append(
		daemonTestEnvironment(os.Environ()),
		daemonMeshIntegrationChildMarker+"=1",
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"mesh integration child timed out after %s: %v\n%s",
			daemonMeshIntegrationProcessTimeout,
			ctx.Err(),
			output,
		)
	}
	if err != nil {
		t.Fatalf("mesh integration child failed: %v\n%s", err, output)
	}
}
