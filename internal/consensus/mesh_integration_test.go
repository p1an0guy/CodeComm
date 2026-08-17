package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"go.etcd.io/bbolt"
)

const secureMeshChild = "CODECOMM_SECURE_MESH_CHILD"

var (
	meshRejectedEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4623456789ab",
	)
	meshFinalEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4723456789ab",
	)
	meshFinalTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-6323456789ab",
	)
	meshFinalTimestamp = domain.Timestamp("2026-08-11T12:03:00Z")
)

func TestSecureThreeVoterConsensusMesh(t *testing.T) {
	if os.Getenv(secureMeshChild) == "1" {
		runSecureThreeVoterConsensusMesh(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureThreeVoterConsensusMesh$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironment(os.Environ())
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("secure mesh child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("secure mesh child failed: %v\n%s", err, output)
	}
}

func TestSecureThreeVoterColdCommitRecovery(t *testing.T) {
	const childMode = "cold-commit"
	if os.Getenv(secureMeshChild) == childMode {
		runSecureThreeVoterColdCommitRecovery(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureThreeVoterColdCommitRecovery$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		childMode,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("cold-commit child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("cold-commit child failed: %v\n%s", err, output)
	}
}

func runSecureThreeVoterColdCommitRecovery(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	leader := harness.waitForLeader(t, harness.runningNodes())
	harness.waitForCommittedConfiguration(t, harness.runningNodes())
	for _, candidate := range harness.runningNodes() {
		if err := candidate.node.WaitForLeader(meshTestContext(t)); err != nil {
			t.Fatalf(
				"WaitForLeader(%s): %v",
				candidate.identity.deviceID,
				err,
			)
		}
	}
	pending := harness.taskEvent(
		t,
		leader,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		"cold committed tail",
	)
	lastIndex, err := leader.node.stable.LastIndex()
	if err != nil {
		t.Fatalf("leader LastIndex(): %v", err)
	}
	var last raft.Log
	if err := leader.node.stable.GetLog(lastIndex, &last); err != nil {
		t.Fatalf("leader GetLog(%d): %v", lastIndex, err)
	}
	for _, candidate := range harness.runningNodes() {
		candidateLast, err := candidate.node.stable.LastIndex()
		if err != nil {
			t.Fatalf("LastIndex(%s): %v", candidate.identity.deviceID, err)
		}
		if candidateLast != lastIndex {
			t.Fatalf(
				"last index on %s = %d, want %d",
				candidate.identity.deviceID,
				candidateLast,
				lastIndex,
			)
		}
		var candidateLog raft.Log
		if err := candidate.node.stable.GetLog(
			candidateLast,
			&candidateLog,
		); err != nil {
			t.Fatalf("GetLog(%s): %v", candidate.identity.deviceID, err)
		}
		if candidateLog.Term != last.Term ||
			candidateLog.Type != last.Type ||
			!bytes.Equal(candidateLog.Data, last.Data) {
			t.Fatalf(
				"last log on %s differs before cold restart",
				candidate.identity.deviceID,
			)
		}
	}

	for _, candidate := range harness.nodes {
		harness.stopNode(t, candidate)
	}
	pendingIndex := lastIndex + 1
	for _, candidate := range harness.nodes {
		appendColdCommitLog(
			t,
			candidate.consensusDir,
			&raft.Log{
				Index: pendingIndex,
				Term:  last.Term,
				Type:  raft.LogCommand,
				Data:  pending.CanonicalBytes(),
			},
		)
		harness.startNode(t, candidate, false)
	}

	restarted := harness.runningNodes()
	harness.waitForLeader(t, restarted)
	harness.waitForTask(t, restarted, nodeTestTaskID1)
	assertMeshViewsConverged(t, restarted)
}

func appendColdCommitLog(
	t *testing.T,
	consensusDir string,
	entry *raft.Log,
) {
	t.Helper()
	options := *bbolt.DefaultOptions
	options.Timeout = 5 * time.Second
	options.NoFreelistSync = false
	logs, err := raftboltdb.New(raftboltdb.Options{
		Path:        filepath.Join(consensusDir, raftStoreFilename),
		BoltOptions: &options,
		NoSync:      false,
	})
	if err != nil {
		t.Fatalf("open cold-commit Raft store: %v", err)
	}
	if err := logs.StoreLog(entry); err != nil {
		_ = logs.Close()
		t.Fatalf("append cold-commit log: %v", err)
	}
	if err := logs.Close(); err != nil {
		t.Fatalf("close cold-commit Raft store: %v", err)
	}
}

func runSecureThreeVoterConsensusMesh(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	leader := harness.waitForLeader(t, harness.runningNodes())
	harness.waitForCommittedConfiguration(t, harness.runningNodes())
	for _, candidate := range harness.runningNodes() {
		if err := candidate.node.WaitForLeader(meshTestContext(t)); err != nil {
			t.Fatalf(
				"WaitForLeader(%s): %v",
				candidate.identity.deviceID,
				err,
			)
		}
	}
	first := harness.taskEvent(
		t,
		leader,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		"secure mesh first commit",
	)
	if _, err := leader.node.Apply(meshTestContext(t), first); err != nil {
		t.Fatalf("first leader Apply(): %v", err)
	}
	harness.waitForTask(t, harness.runningNodes(), nodeTestTaskID1)
	assertMeshViewsConverged(t, harness.runningNodes())

	lostLeaderID := leader.identity.deviceID
	harness.stopNode(t, leader)
	majority := harness.runningNodes()
	if len(majority) != 2 {
		t.Fatalf("running majority = %d, want 2", len(majority))
	}
	replacement := harness.waitForLeader(t, majority)
	if replacement.identity.deviceID == lostLeaderID {
		t.Fatal("stopped leader retained leadership")
	}
	second := harness.taskEvent(
		t,
		replacement,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		"majority commit after leader loss",
	)
	if _, err := replacement.node.Apply(
		meshTestContext(t),
		second,
	); err != nil {
		t.Fatalf("majority Apply(): %v", err)
	}
	harness.waitForTask(t, majority, nodeTestTaskID2)
	assertMeshViewsConverged(t, majority)

	harness.topology.setPartition(lostLeaderID, true)
	harness.startNode(t, leader, false)
	before, err := leader.node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("isolated View(before): %v", err)
	}
	rejected := harness.taskEvent(
		t,
		leader,
		meshRejectedEventID,
		nodeTestTaskID3,
		nodeTestTimestamp3,
		"isolated minority must not commit",
	)
	if _, err := leader.node.Apply(
		meshTestContext(t),
		rejected,
	); !errors.Is(err, raft.ErrNotLeader) &&
		!errors.Is(err, raft.ErrLeadershipLost) {
		t.Fatalf("isolated minority Apply() error = %v", err)
	}
	leader.nextSequence--
	after, err := leader.node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("isolated View(after): %v", err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest ||
		viewContainsTask(after, nodeTestTaskID3) {
		t.Fatal("isolated minority mutation changed durable state")
	}

	harness.topology.setPartition(lostLeaderID, false)
	harness.waitForTask(t, []*secureMeshNode{leader}, nodeTestTaskID2)
	if err := leader.node.WaitForLeader(meshTestContext(t)); err != nil {
		t.Fatalf("rejoined WaitForLeader(): %v", err)
	}
	all := harness.runningNodes()
	currentLeader := harness.waitForLeader(t, all)
	final := harness.taskEvent(
		t,
		currentLeader,
		meshFinalEventID,
		meshFinalTaskID,
		meshFinalTimestamp,
		"commit after partition healing",
	)
	if _, err := currentLeader.node.Apply(
		meshTestContext(t),
		final,
	); err != nil {
		t.Fatalf("post-heal Apply(): %v", err)
	}
	harness.waitForTask(t, all, meshFinalTaskID)
	assertMeshViewsConverged(t, all)
	for _, candidate := range all {
		view, err := candidate.node.View(meshTestContext(t))
		if err != nil {
			t.Fatalf("final View(%s): %v", candidate.identity.deviceID, err)
		}
		if viewContainsTask(view, nodeTestTaskID3) {
			t.Fatalf(
				"rejected minority task appeared on %s",
				candidate.identity.deviceID,
			)
		}
	}
}

type secureMeshIdentity struct {
	deviceID    domain.DeviceID
	private     ed25519.PrivateKey
	public      ed25519.PublicKey
	certificate tls.Certificate
	bootIDs     []domain.UUIDv7
}

type secureMeshNode struct {
	identity secureMeshIdentity
	index    int

	statePath    string
	consensusDir string
	fakeEndpoint netip.AddrPort
	nextSequence uint64
	startCount   int

	node      *Node
	stream    *transport.ConsensusStreamLayer
	ingress   *transport.Ingress
	verifiers *peerauth.Verifiers
	listener  net.Listener
	serveDone chan error
}

type secureMeshHarness struct {
	initial   store.InitialState
	bootstrap []domain.DeviceID
	nodes     []*secureMeshNode
	resolver  secureMeshResolver
	topology  *secureMeshTopology
}

func newSecureMeshHarness(t *testing.T) *secureMeshHarness {
	t.Helper()
	root := t.TempDir()
	identities := make([]secureMeshIdentity, 3)
	for index := range identities {
		private := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{byte(0x81 + index)}, ed25519.SeedSize),
		)
		certificate, binding, err := transport.IssueIdentityCertificate(
			nodeTestSessionID,
			0,
			private,
		)
		if err != nil {
			t.Fatalf("IssueIdentityCertificate(%d): %v", index, err)
		}
		identities[index] = secureMeshIdentity{
			deviceID:    binding.DeviceID,
			private:     private,
			public:      private.Public().(ed25519.PublicKey),
			certificate: certificate,
			bootIDs: []domain.UUIDv7{
				domain.UUIDv7(fmt.Sprintf(
					"018f47de-89ab-7def-8%d23-%d123456789ab",
					index+3,
					index+7,
				)),
				domain.UUIDv7(fmt.Sprintf(
					"018f47de-89ab-7def-9%d23-%d123456789ab",
					index+3,
					index+7,
				)),
			},
		}
		for _, bootID := range identities[index].bootIDs {
			if !bootID.Valid() {
				t.Fatalf("generated boot ID %q is invalid", bootID)
			}
		}
	}
	sort.Slice(identities, func(left, right int) bool {
		return identities[left].deviceID < identities[right].deviceID
	})

	harness := &secureMeshHarness{
		topology: newSecureMeshTopology(),
		resolver: make(secureMeshResolver, len(identities)),
	}
	for index, identity := range identities {
		endpoint := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 10)}),
			47831,
		)
		candidate := &secureMeshNode{
			identity:     identity,
			index:        index,
			statePath:    filepath.Join(root, fmt.Sprintf("node-%d", index), "state.db"),
			consensusDir: filepath.Join(root, fmt.Sprintf("node-%d", index), "consensus"),
			fakeEndpoint: endpoint,
			nextSequence: 1,
		}
		harness.nodes = append(harness.nodes, candidate)
		harness.bootstrap = append(harness.bootstrap, identity.deviceID)
		harness.resolver[identity.deviceID] = endpoint
	}
	harness.initial = secureMeshInitialState(t, identities)
	for _, candidate := range harness.nodes {
		harness.startNode(t, candidate, true)
	}
	return harness
}

func secureMeshInitialState(
	t *testing.T,
	identities []secureMeshIdentity,
) store.InitialState {
	t.Helper()
	initial, _, _ := nodeTestInitialState(t)
	deviceIDs := make([]domain.DeviceID, len(identities))
	devices := make([]device.Device, len(identities))
	counters := make([]auditcounter.Counter, len(identities))
	for index, identity := range identities {
		deviceIDs[index] = identity.deviceID
		role := device.RoleEditor
		if index == 0 {
			role = device.RoleOwner
		}
		devices[index] = device.Device{
			ID:                identity.deviceID,
			Role:              role,
			IdentityPublicKey: bytes.Clone(identity.public),
			DaemonVersion:     "0.1.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		}
		counters[index] = auditcounter.Counter{
			DeviceID: identity.deviceID,
		}
	}
	target, err := voterset.New(nodeTestSessionID, deviceIDs, 1)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	initial.Projections.Devices = devices
	initial.Projections.AuditCounters = counters
	initial.Projections.VoterSet = []voterset.Set{target}
	initial.Projections.CredentialAuthority =
		[]store.CredentialAuthorityRow{{
			SessionID:        nodeTestSessionID,
			VoterDeviceIDs:   append([]domain.DeviceID(nil), deviceIDs...),
			VoterSetVersion:  1,
			ActivationSource: credentialauthority.ActivationGenesis,
		}}
	return initial
}

func (harness *secureMeshHarness) startNode(
	t *testing.T,
	candidate *secureMeshNode,
	initialize bool,
) {
	t.Helper()
	if candidate.node != nil {
		t.Fatalf("node %s is already running", candidate.identity.deviceID)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen(%s): %v", candidate.identity.deviceID, err)
	}
	candidate.listener = listener
	harness.topology.register(
		candidate.identity.deviceID,
		candidate.fakeEndpoint,
		listener.Addr().String(),
	)

	var initial *store.InitialState
	if initialize {
		initial = &harness.initial
	}
	if candidate.startCount >= len(candidate.identity.bootIDs) {
		t.Fatalf("node %s exhausted test boot IDs", candidate.identity.deviceID)
	}
	bootID := candidate.identity.bootIDs[candidate.startCount]
	candidate.startCount++
	candidate.nextSequence = 1
	node, err := OpenNode(context.Background(), NodeOptions{
		ServerID:                candidate.identity.deviceID,
		StatePath:               candidate.statePath,
		ConsensusDir:            candidate.consensusDir,
		OriginBootID:            bootID,
		InitialState:            initial,
		BootstrapVoterDeviceIDs: harness.bootstrap,
		Clock:                   nodeTestClock(),
		RaftConfig:              secureMeshRaftConfig(),
		TransportFactory: func(
			gate ConsensusTransportGate,
		) (RaftTransport, error) {
			verifiers, err := peerauth.NewVerifiers(
				gate.PeerAdmissionSnapshot,
				time.Now,
			)
			if err != nil {
				return nil, err
			}
			stream, err := transport.NewConsensusStreamLayer(
				transport.ConsensusStreamOptions{
					LocalDeviceID:       candidate.identity.deviceID,
					IdentityCertificate: candidate.identity.certificate,
					Endpoints:           harness.resolver,
					Dialer: secureMeshDialer{
						localDeviceID: candidate.identity.deviceID,
						topology:      harness.topology,
					},
					VerifyExpectedPeer:   verifiers.VerifyExpectedConsensusPeer,
					AuthorizePeer:        gate.AuthorizePeer,
					AuthorizationChanges: gate.AuthorizationChanges(),
					ControlHandler:       http.NotFoundHandler(),
				},
			)
			if err != nil {
				return nil, err
			}
			raftTransport, err := transport.NewConsensusNetworkTransport(
				transport.ConsensusNetworkTransportOptions{
					Stream:               stream,
					LocalServerID:        raft.ServerID(candidate.identity.deviceID),
					Timeout:              2 * time.Second,
					Logger:               hclog.NewNullLogger(),
					AuthorizeReplication: gate.AuthorizeReplication,
					AuthorizeCommitProbe: gate.AuthorizeCommitProbe,
				},
			)
			if err != nil {
				_ = stream.Close()
				return nil, err
			}
			candidate.stream = stream
			candidate.verifiers = verifiers
			return raftTransport, nil
		},
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("OpenNode(%s): %v", candidate.identity.deviceID, err)
	}
	candidate.node = node
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener: listener,
		TLS: transport.ServerTLSOptions{
			IdentityCertificate: candidate.identity.certificate,
			ContentCertificate: func() (tls.Certificate, error) {
				return tls.Certificate{},
					transport.ErrContentCertificateUnavailable
			},
			VerifyPairingPeer: func(
				transport.IdentityCertificate,
			) error {
				return peerauth.ErrPeerNotAdmitted
			},
			VerifyConsensusPeer: candidate.verifiers.VerifyConsensusPeer,
			VerifyContentPeer: func(
				transport.ContentCertificate,
			) (transport.ContentPeerAdmission, error) {
				return transport.ContentPeerAdmission{},
					peerauth.ErrPeerNotAdmitted
			},
		},
		PeerAccessChanges: node.PeerAdmissionChanges(),
		Consensus:         candidate.stream,
	})
	if err != nil {
		_ = node.Close()
		_ = listener.Close()
		harness.topology.unregister(candidate.fakeEndpoint)
		candidate.node = nil
		t.Fatalf("NewIngress(%s): %v", candidate.identity.deviceID, err)
	}
	candidate.ingress = ingress
	candidate.serveDone = make(chan error, 1)
	go func() {
		candidate.serveDone <- ingress.Serve(context.Background())
	}()
}

func (harness *secureMeshHarness) stopNode(
	t *testing.T,
	candidate *secureMeshNode,
) {
	t.Helper()
	if candidate.node == nil {
		return
	}
	if err := candidate.node.Close(); err != nil {
		t.Errorf("Close(%s): %v", candidate.identity.deviceID, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := candidate.ingress.Shutdown(ctx); err != nil {
		t.Errorf("Ingress.Shutdown(%s): %v", candidate.identity.deviceID, err)
	}
	select {
	case err := <-candidate.serveDone:
		if err != nil {
			t.Errorf("Ingress.Serve(%s): %v", candidate.identity.deviceID, err)
		}
	case <-ctx.Done():
		t.Errorf("Ingress.Serve(%s) did not stop", candidate.identity.deviceID)
	}
	harness.topology.unregister(candidate.fakeEndpoint)
	candidate.node = nil
	candidate.stream = nil
	candidate.ingress = nil
	candidate.verifiers = nil
	candidate.listener = nil
	candidate.serveDone = nil
}

func (harness *secureMeshHarness) close(t *testing.T) {
	t.Helper()
	for index := len(harness.nodes) - 1; index >= 0; index-- {
		harness.stopNode(t, harness.nodes[index])
		clear(harness.nodes[index].identity.private)
	}
}

func (harness *secureMeshHarness) runningNodes() []*secureMeshNode {
	result := make([]*secureMeshNode, 0, len(harness.nodes))
	for _, candidate := range harness.nodes {
		if candidate.node != nil {
			result = append(result, candidate)
		}
	}
	return result
}

func (harness *secureMeshHarness) waitForLeader(
	t *testing.T,
	candidates []*secureMeshNode,
) *secureMeshNode {
	t.Helper()
	var leader *secureMeshNode
	awaitMeshCondition(t, 15*time.Second, "one stable mesh leader", func() bool {
		leader = nil
		for _, candidate := range candidates {
			if candidate.node != nil && candidate.node.IsLeader() {
				if leader != nil {
					return false
				}
				leader = candidate
			}
		}
		return leader != nil
	})
	return leader
}

func (harness *secureMeshHarness) waitForCommittedConfiguration(
	t *testing.T,
	candidates []*secureMeshNode,
) {
	t.Helper()
	awaitMeshCondition(
		t,
		15*time.Second,
		"committed configuration on every voter",
		func() bool {
			for _, candidate := range candidates {
				configuration := candidate.node.fsm.committedConfiguration()
				if configuration == nil ||
					len(configuration.Configuration.Servers) != 3 {
					return false
				}
			}
			return true
		},
	)
}

func (harness *secureMeshHarness) waitForTask(
	t *testing.T,
	candidates []*secureMeshNode,
	taskID domain.UUIDv7,
) {
	t.Helper()
	awaitMeshCondition(t, 15*time.Second, "task "+string(taskID), func() bool {
		for _, candidate := range candidates {
			view, err := candidate.node.View(context.Background())
			if err != nil || !viewContainsTask(view, taskID) {
				return false
			}
		}
		return true
	})
}

func (harness *secureMeshHarness) taskEvent(
	t *testing.T,
	candidate *secureMeshNode,
	eventID domain.UUIDv7,
	taskID domain.UUIDv7,
	timestamp domain.Timestamp,
	title string,
) event.SignedEvent {
	t.Helper()
	sequence := candidate.nextSequence
	candidate.nextSequence++
	return nodeTestTaskEvent(
		t,
		candidate.identity.private,
		candidate.identity.deviceID,
		candidate.identity.bootIDs[candidate.startCount-1],
		eventID,
		taskID,
		timestamp,
		sequence,
		title,
	)
}

func assertMeshViewsConverged(
	t *testing.T,
	candidates []*secureMeshNode,
) {
	t.Helper()
	if len(candidates) == 0 {
		t.Fatal("no mesh views to compare")
	}
	baseline, err := candidates[0].node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("View(%s): %v", candidates[0].identity.deviceID, err)
	}
	for _, candidate := range candidates[1:] {
		actual, err := candidate.node.View(meshTestContext(t))
		if err != nil {
			t.Fatalf("View(%s): %v", candidate.identity.deviceID, err)
		}
		if actual.Heads != baseline.Heads ||
			actual.ProjectionStateDigest != baseline.ProjectionStateDigest ||
			!reflect.DeepEqual(actual.ProjectionRows, baseline.ProjectionRows) {
			t.Fatalf(
				"state on %s diverged from %s",
				candidate.identity.deviceID,
				candidates[0].identity.deviceID,
			)
		}
	}
}

func secureMeshRaftConfig() *raft.Config {
	config := nodeTestRaftConfig()
	config.HeartbeatTimeout = 700 * time.Millisecond
	config.ElectionTimeout = 700 * time.Millisecond
	config.LeaderLeaseTimeout = 300 * time.Millisecond
	config.CommitTimeout = 20 * time.Millisecond
	return config
}

func meshTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func awaitMeshCondition(
	t *testing.T,
	timeout time.Duration,
	description string,
	condition func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

type secureMeshResolver map[domain.DeviceID]netip.AddrPort

func (resolver secureMeshResolver) ResolveConsensusEndpoints(
	_ context.Context,
	deviceID domain.DeviceID,
) ([]netip.AddrPort, error) {
	endpoint, exists := resolver[deviceID]
	if !exists {
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	return []netip.AddrPort{endpoint}, nil
}

type secureMeshDialer struct {
	localDeviceID domain.DeviceID
	topology      *secureMeshTopology
}

func (dialer secureMeshDialer) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	address, allowed := dialer.topology.resolve(
		dialer.localDeviceID,
		endpoint,
	)
	if !allowed {
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	var networkDialer net.Dialer
	return networkDialer.DialContext(ctx, "tcp4", address)
}

type secureMeshTopology struct {
	mu          sync.RWMutex
	targets     map[netip.AddrPort]secureMeshTarget
	partitioned map[domain.DeviceID]bool
}

type secureMeshTarget struct {
	deviceID domain.DeviceID
	address  string
}

func newSecureMeshTopology() *secureMeshTopology {
	return &secureMeshTopology{
		targets:     make(map[netip.AddrPort]secureMeshTarget),
		partitioned: make(map[domain.DeviceID]bool),
	}
}

func (topology *secureMeshTopology) register(
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	address string,
) {
	topology.mu.Lock()
	topology.targets[endpoint] = secureMeshTarget{
		deviceID: deviceID,
		address:  address,
	}
	topology.mu.Unlock()
}

func (topology *secureMeshTopology) unregister(endpoint netip.AddrPort) {
	topology.mu.Lock()
	delete(topology.targets, endpoint)
	topology.mu.Unlock()
}

func (topology *secureMeshTopology) setPartition(
	deviceID domain.DeviceID,
	partitioned bool,
) {
	topology.mu.Lock()
	topology.partitioned[deviceID] = partitioned
	topology.mu.Unlock()
}

func (topology *secureMeshTopology) resolve(
	localDeviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (string, bool) {
	topology.mu.RLock()
	defer topology.mu.RUnlock()
	target, exists := topology.targets[endpoint]
	if !exists ||
		topology.partitioned[localDeviceID] ||
		topology.partitioned[target.deviceID] {
		return "", false
	}
	return target.address, true
}

func secureMeshChildEnvironment(base []string) []string {
	return secureMeshChildEnvironmentWithMode(base, "1")
}

func secureMeshChildEnvironmentWithMode(
	base []string,
	mode string,
) []string {
	result := make([]string, 0, len(base)+2)
	var settings []string
	for _, entry := range base {
		switch {
		case strings.HasPrefix(entry, secureMeshChild+"="):
			continue
		case strings.HasPrefix(entry, "GODEBUG="):
			for _, setting := range strings.Split(
				strings.TrimPrefix(entry, "GODEBUG="),
				",",
			) {
				if setting != "" &&
					!strings.HasPrefix(setting, "http2xconnect=") {
					settings = append(settings, setting)
				}
			}
		default:
			result = append(result, entry)
		}
	}
	settings = append(settings, "http2xconnect=1")
	return append(
		result,
		"GODEBUG="+strings.Join(settings, ","),
		secureMeshChild+"="+mode,
	)
}
