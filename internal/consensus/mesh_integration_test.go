package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/testharness/faultnet"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
	"go.etcd.io/bbolt"
)

const (
	secureMeshChild           = "CODECOMM_SECURE_MESH_CHILD"
	secureMeshInProcess       = "CODECOMM_SECURE_MESH_IN_PROCESS"
	secureMeshTestBootIDCount = 24
)

var (
	meshRejectedEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4623456789ab",
	)
	meshFinalEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4723456789ab",
	)
	meshCheckpointEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4823456789ab",
	)
	meshForcedCheckpointEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4923456789ab",
	)
	meshFinalTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-6323456789ab",
	)
	meshFinalTimestamp = domain.Timestamp("2026-08-11T12:03:00Z")
)

func TestSecureThreeVoterConsensusMesh(t *testing.T) {
	if secureMeshRunsInProcess() || os.Getenv(secureMeshChild) == "1" {
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
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == childMode {
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
	var proofTarget *secureMeshNode
	for _, candidate := range harness.runningNodes() {
		if candidate != leader {
			proofTarget = candidate
			break
		}
	}
	if proofTarget == nil {
		t.Fatal("secure mesh has no proof target")
	}
	harness.proveAuthorityCheckpointSigning(
		t,
		leader,
		proofTarget,
	)
	harness.proveRemoteForcedCheckpoint(t, leader)
	expectation := checkpointProofTestExpectation(t)
	expectation.targetDeviceID = proofTarget.identity.deviceID
	if _, err := requestStagingApplyProof(
		meshTestContext(t),
		leader.stream,
		expectation,
	); !errors.Is(err, ErrCheckpointProofRejected) {
		t.Fatalf("voter staging-proof request error = %v", err)
	}
	harness.proveStagingCheckpoint(t, leader, proofTarget)
	harness.proveCredentialEndorsement(t, leader, proofTarget)

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

	checkpointSigningDisabled atomic.Bool
	commitProbeRelease        <-chan struct{}
	node                      *Node
	stream                    *transport.ConsensusStreamLayer
	ingress                   *transport.Ingress
	verifiers                 *peerauth.Verifiers
	listener                  net.Listener
	serveDone                 chan error
}

type secureMeshHarness struct {
	initial                   store.InitialState
	bootstrap                 []domain.DeviceID
	nodes                     []*secureMeshNode
	resolver                  secureMeshResolver
	topology                  *secureMeshTopology
	faults                    *faultnet.Controller
	coverage                  *configurationCoverageCollector
	manualVoterReconciliation bool
	compactSnapshots          bool
}

type secureMeshHarnessOptions struct {
	manualVoterReconciliation bool
	compactSnapshots          bool
}

type secureMeshCheckpointOrigin struct {
	t         *testing.T
	harness   *secureMeshHarness
	candidate *secureMeshNode
	bootID    domain.UUIDv7
	exclusive chan struct{}
	reserved  uint64
	dynamicID bool
}

func (origin *secureMeshCheckpointOrigin) DeviceID() domain.DeviceID {
	if origin == nil || origin.candidate == nil {
		return ""
	}
	return origin.candidate.identity.deviceID
}

func (origin *secureMeshCheckpointOrigin) BootID() domain.UUIDv7 {
	if origin == nil {
		return ""
	}
	return origin.bootID
}

func (origin *secureMeshCheckpointOrigin) RunExclusive(
	ctx context.Context,
	operation func(CheckpointReservation) error,
) error {
	if origin == nil ||
		origin.t == nil ||
		origin.harness == nil ||
		origin.candidate == nil ||
		ctx == nil ||
		operation == nil {
		return ErrCheckpointOriginUnavailable
	}
	select {
	case origin.exclusive <- struct{}{}:
		defer func() { <-origin.exclusive }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return operation(func(
		ctx context.Context,
		checkpoint domain.Checkpoint,
		signature store.Signature,
	) (event.SignedEvent, error) {
		if err := ctx.Err(); err != nil {
			return event.SignedEvent{}, err
		}
		eventID := meshForcedCheckpointEventID
		if origin.dynamicID || origin.reserved > 0 {
			generated, err := uuid.NewV7()
			if err != nil {
				return event.SignedEvent{}, err
			}
			eventID = domain.UUIDv7(generated.String())
		}
		origin.reserved++
		record := store.CheckpointRecord{
			CheckpointEventID:        eventID,
			SessionID:                checkpoint.SessionID,
			WorkspaceID:              checkpoint.WorkspaceID,
			RecoveryGeneration:       checkpoint.RecoveryGeneration,
			AuthorityVoterSetVersion: checkpoint.AuthorityVoterSetVersion,
			SignerDeviceID:           checkpoint.SignerDeviceID,
			Term:                     checkpoint.Term,
			CoveredAppliedLogIndex:   checkpoint.CoveredAppliedLogIndex,
			CoveredChainIndex:        checkpoint.CoveredChainIndex,
			CoveredChainHash:         checkpoint.CoveredChainHash,
			CoveredResultIndex:       checkpoint.CoveredResultIndex,
			CoveredResultHash:        checkpoint.CoveredResultHash,
			ProjectionAccumulator:    checkpoint.ProjectionAccumulator,
			DigestVersion:            checkpoint.DigestVersion,
			ProjectionSchemaVersion:  checkpoint.ProjectionSchemaVersion,
			AuthoritySignature:       signature,
		}
		encoded, err := event.EncodeCheckpoint(checkpoint)
		if err != nil {
			return event.SignedEvent{}, err
		}
		record.CheckpointJSON = encoded
		return origin.harness.checkpointEvent(
			origin.t,
			origin.candidate,
			record,
		), nil
	})
}

func (origin *secureMeshCheckpointOrigin) SubmitCredentialAuthorization(
	ctx context.Context,
	authorization credentialauthorization.Authorization,
) (store.CommandOutcome, error) {
	if origin == nil ||
		origin.candidate == nil ||
		origin.candidate.node == nil ||
		ctx == nil ||
		authorization.AuthorizationChainIndex != 0 {
		return store.CommandOutcome{},
			ErrCredentialAuthorizationOriginUnavailable
	}
	payload, err := secureMeshCredentialAuthorizationPayload(authorization)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	signed, err := secureMeshSignedCommand(
		origin.candidate,
		event.ActorDaemon,
		event.KindCredentialAuthorized,
		event.StringEntityID(string(authorization.DeviceID)),
		nil,
		payload,
		secureMeshEventTimestamp(),
	)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	result, err := origin.candidate.node.Apply(ctx, signed)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	return result.Outcome, nil
}

func secureMeshCredentialAuthorizationPayload(
	authorization credentialauthorization.Authorization,
) ([]byte, error) {
	endorsements := make(
		[]map[string]any,
		len(authorization.ClockEndorsements),
	)
	for index, endorsement := range authorization.ClockEndorsements {
		endorsements[index] = map[string]any{
			"device_id": endorsement.DeviceID,
			"signature": codec.EncodeBase64URL(
				endorsement.Signature[:],
			),
		}
	}
	return json.Marshal(map[string]any{
		"authority_voter_set_version": authorization.AuthorityVoterSetVersion,
		"binding_signature": codec.EncodeBase64URL(
			authorization.BindingSignature[:],
		),
		"clock_endorsements": endorsements,
		"epoch":              authorization.Epoch,
		"epoch_public_key": codec.EncodeBase64URL(
			authorization.EpochPublicKey[:],
		),
		"issued_at":         authorization.IssuedAt,
		"key_digest":        codec.EncodeBase64URL(authorization.KeyDigest[:]),
		"not_before":        authorization.NotBefore,
		"role":              authorization.Role,
		"subject_device_id": authorization.DeviceID,
		"validity_seconds":  authorization.ValiditySeconds,
	})
}

func newSecureMeshHarness(t *testing.T) *secureMeshHarness {
	return newSecureMeshHarnessWithOptions(t, secureMeshHarnessOptions{})
}

func newSecureMeshHarnessWithManualReconciliation(
	t *testing.T,
	manual bool,
) *secureMeshHarness {
	return newSecureMeshHarnessWithOptions(t, secureMeshHarnessOptions{
		manualVoterReconciliation: manual,
	})
}

func newSecureMeshHarnessWithOptions(
	t *testing.T,
	options secureMeshHarnessOptions,
) *secureMeshHarness {
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
				domain.UUIDv7(fmt.Sprintf(
					"018f47de-89ab-7def-a%d23-%d123456789ab",
					index+3,
					index+7,
				)),
			},
		}
		for restart := 3; restart < secureMeshTestBootIDCount; restart++ {
			identities[index].bootIDs = append(
				identities[index].bootIDs,
				domain.UUIDv7(fmt.Sprintf(
					"019b17cc-%04x-7def-b%03x-%012x",
					restart,
					index,
					restart*len(identities)+index+1,
				)),
			)
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

	faults, err := faultnet.NewController(2 * time.Second)
	if err != nil {
		t.Fatalf("faultnet.NewController(): %v", err)
	}
	harness := &secureMeshHarness{
		topology:                  newSecureMeshTopology(),
		faults:                    faults,
		resolver:                  make(secureMeshResolver, len(identities)),
		manualVoterReconciliation: options.manualVoterReconciliation,
		compactSnapshots:          options.compactSnapshots,
	}
	coverageKeys := make(
		map[domain.DeviceID]ed25519.PrivateKey,
		len(identities),
	)
	for index, identity := range identities {
		coverageKeys[identity.deviceID] = identity.private
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
	harness.coverage = &configurationCoverageCollector{
		privateKeys: coverageKeys,
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
	checkpointSigner := CheckpointSignerAdapter{
		SignerDeviceID: candidate.identity.deviceID,
		Sign: func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := ctx.Err(); err != nil {
				return store.Signature{}, err
			}
			if candidate.checkpointSigningDisabled.Load() {
				return store.Signature{},
					errConsensusCheckpointSignerUnavailable
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				candidate.identity.private,
			)
			if err != nil {
				return store.Signature{}, err
			}
			return store.Signature(signature), nil
		},
	}
	snapshotSigner := RaftSnapshotSignerAdapter{
		SignerDeviceID:  candidate.identity.deviceID,
		SignerPublicKey: bytes.Clone(candidate.identity.public),
		Sign: func(
			ctx context.Context,
			unsigned logicalsnapshot.UnsignedRoot,
		) (logicalsnapshot.Root, error) {
			if err := ctx.Err(); err != nil {
				return logicalsnapshot.Root{}, err
			}
			return logicalsnapshot.SignRoot(
				unsigned,
				candidate.identity.private,
			)
		},
	}
	activationSigner := VoterActivationSignerAdapter{
		SignerDeviceID: candidate.identity.deviceID,
		SignProof: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			proof, err := voteractivation.SignProof(
				unsigned,
				candidate.identity.private,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return proof.VoterSignature(), nil
		},
		SignHandoff: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			payload, err := voteractivation.SignAuthorityHandoff(
				unsigned,
				candidate.identity.private,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return payload.HandoffSignature(), nil
		},
	}
	credentialSigner := CredentialEndorsementSignerAdapter{
		SignerDeviceID: candidate.identity.deviceID,
		Sign: func(
			ctx context.Context,
			preimage []byte,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			raw, err := codecommcrypto.SignEd25519(
				candidate.identity.private,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			var signature [ed25519.SignatureSize]byte
			copy(signature[:], raw)
			return signature, nil
		},
	}
	checkpointOrigin := &secureMeshCheckpointOrigin{
		t:         t,
		harness:   harness,
		candidate: candidate,
		bootID:    bootID,
		exclusive: make(chan struct{}, 1),
		dynamicID: harness.manualVoterReconciliation,
	}
	commitProbeRelease := candidate.commitProbeRelease
	transportFactory := func(
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
					faults:        harness.faults,
				},
				VerifyExpectedPeer:   verifiers.VerifyExpectedConsensusPeer,
				AuthorizePeer:        gate.AuthorizePeer,
				AuthorizationChanges: gate.AuthorizationChanges(),
				ControlHandler:       gate.ConsensusControlHandler(),
			},
		)
		if err != nil {
			return nil, err
		}
		authorizeCommitProbe := gate.AuthorizeCommitProbe
		if commitProbeRelease != nil {
			authorizeCommitProbe = func(
				deviceID domain.DeviceID,
			) error {
				<-commitProbeRelease
				return gate.AuthorizeCommitProbe(deviceID)
			}
		}
		raftTransport, err := transport.NewConsensusNetworkTransport(
			transport.ConsensusNetworkTransportOptions{
				Stream:               stream,
				LocalServerID:        raft.ServerID(candidate.identity.deviceID),
				Timeout:              transport.ConsensusRaftOperationTimeout,
				Logger:               hclog.NewNullLogger(),
				AuthorizeReplication: gate.AuthorizeReplication,
				AuthorizeCommitProbe: authorizeCommitProbe,
			},
		)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		candidate.stream = stream
		candidate.verifiers = verifiers
		return raftTransport, nil
	}
	bootstrap, bootstrapErr := meshBootstrapConfiguration(
		candidate.identity.deviceID,
		harness.bootstrap,
	)
	if bootstrapErr != nil {
		_ = listener.Close()
		t.Fatalf(
			"meshBootstrapConfiguration(%s): %v",
			candidate.identity.deviceID,
			bootstrapErr,
		)
	}
	node, err := openNode(context.Background(), nodeOpenOptions{
		ServerID:                    candidate.identity.deviceID,
		StatePath:                   candidate.statePath,
		ConsensusDir:                candidate.consensusDir,
		OriginBootID:                bootID,
		InitialState:                initial,
		TransportFactory:            transportFactory,
		BootstrapConfiguration:      bootstrap,
		CanonicalCoverage:           harness.coverage,
		CheckpointSigner:            checkpointSigner,
		RaftSnapshotSigner:          snapshotSigner,
		VoterActivationSigner:       activationSigner,
		CredentialEndorsementSigner: credentialSigner,
		CheckpointOrigin:            checkpointOrigin,
		DisableVoterReconciliation:  true,
		Clock:                       nodeTestClock(),
		RaftConfig:                  harness.secureMeshRaftConfig(),
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
	if err := harness.faults.Close(); err != nil {
		t.Errorf("fault controller Close(): %v", err)
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
	harness.waitForTaskWithin(t, candidates, taskID, 15*time.Second)
}

func (harness *secureMeshHarness) waitForTaskWithin(
	t *testing.T,
	candidates []*secureMeshNode,
	taskID domain.UUIDv7,
	timeout time.Duration,
) {
	t.Helper()
	awaitMeshCondition(t, timeout, "task "+string(taskID), func() bool {
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

func (harness *secureMeshHarness) proveCredentialEndorsement(
	t *testing.T,
	leader *secureMeshNode,
	endorser *secureMeshNode,
) {
	t.Helper()
	if harness == nil ||
		leader == nil ||
		endorser == nil ||
		leader == endorser {
		t.Fatal("invalid credential endorsement fixture")
	}
	fixedNow := time.Date(
		2026,
		time.August,
		18,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	for _, candidate := range harness.runningNodes() {
		candidate.node.credentialEndorsementNow = func() time.Time {
			return fixedNow
		}
	}
	view, err := leader.node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("credential endorsement View(): %v", err)
	}
	state, err := decodeStateView(view)
	if err != nil {
		t.Fatalf("credential endorsement state: %v", err)
	}
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xc1}, ed25519.SeedSize),
	)
	epochPublic := epochPrivate.Public().(ed25519.PublicKey)
	authorization := credentialauthorization.Authorization{
		SessionID: nodeTestSessionID,
		DeviceID:  leader.identity.deviceID,
		Epoch:     1,
		KeyDigest: sha256.Sum256(epochPublic),
		IssuedAt: domain.WholeSecondTimestamp(
			fixedNow.Format(time.RFC3339),
		),
		AuthorityVoterSetVersion: state.CredentialAuthority.
			VoterSetVersion,
	}
	copy(authorization.EpochPublicKey[:], epochPublic)

	proof, err := requestCredentialEndorsement(
		meshTestContext(t),
		leader.stream,
		endorser.identity.deviceID,
		endorser.identity.public,
		authorization,
	)
	if err != nil ||
		proof.endorserDeviceID != endorser.identity.deviceID {
		t.Fatalf(
			"leader credential endorsement = (%#v, %v)",
			proof,
			err,
		)
	}

	var nonleader *secureMeshNode
	for _, candidate := range harness.runningNodes() {
		if candidate != leader && candidate != endorser {
			nonleader = candidate
			break
		}
	}
	if nonleader == nil {
		t.Fatal("secure mesh lacks a nonleader credential requester")
	}
	if _, err := requestCredentialEndorsement(
		meshTestContext(t),
		nonleader.stream,
		endorser.identity.deviceID,
		endorser.identity.public,
		authorization,
	); !errors.Is(err, ErrCredentialEndorsementRejected) {
		t.Fatalf("nonleader credential endorsement error = %v", err)
	}

	outOfRange := authorization
	outOfRange.IssuedAt = domain.WholeSecondTimestamp(
		fixedNow.Add(
			credentialEndorsementClockSkew + time.Second,
		).Format(time.RFC3339),
	)
	if _, err := requestCredentialEndorsement(
		meshTestContext(t),
		leader.stream,
		endorser.identity.deviceID,
		endorser.identity.public,
		outOfRange,
	); !errors.Is(err, ErrCredentialEndorsementRejected) {
		t.Fatalf("out-of-range credential endorsement error = %v", err)
	}

	binding, err := credential.SignBinding(
		nodeTestSessionID,
		leader.identity.deviceID,
		1,
		epochPublic,
		leader.identity.private,
	)
	if err != nil {
		t.Fatalf("credential.SignBinding(): %v", err)
	}
	committed, outcome, err := leader.node.AuthorizeCredential(
		meshTestContext(t),
		binding,
	)
	if err != nil ||
		outcome.Status != store.OutcomeAccepted ||
		committed.DeviceID != leader.identity.deviceID ||
		committed.Epoch != 1 ||
		len(committed.ClockEndorsements) < 2 {
		t.Fatalf(
			"AuthorizeCredential() = (%#v, %#v, %v)",
			committed,
			outcome,
			err,
		)
	}
	awaitMeshCondition(
		t,
		10*time.Second,
		"committed credential authorization on every voter",
		func() bool {
			for _, candidate := range harness.runningNodes() {
				admission, err :=
					candidate.node.PeerAdmissionSnapshot()
				if err != nil {
					return false
				}
				stored, found := admission.Authorization(
					credentialauthorization.Key{
						SessionID: nodeTestSessionID,
						DeviceID:  leader.identity.deviceID,
						Epoch:     1,
					},
				)
				if !found ||
					stored.KeyDigest != committed.KeyDigest ||
					stored.AuthorizationChainIndex == 0 {
					return false
				}
			}
			return true
		},
	)
}

func (harness *secureMeshHarness) proveStagingCheckpoint(
	t *testing.T,
	leader *secureMeshNode,
	target *secureMeshNode,
) {
	t.Helper()
	if leader == nil || target == nil || leader == target {
		t.Fatal("invalid staging-proof participants")
	}
	harness.changeMeshSuffrage(t, leader, target, raft.Nonvoter)

	record := harness.checkpointRecord(t, leader)
	expectation := stagingCheckpointExpectation{
		targetDeviceID: target.identity.deviceID,
		record:         record,
	}
	if _, err := requestStagingApplyProof(
		meshTestContext(t),
		leader.stream,
		expectation,
	); !errors.Is(err, ErrCheckpointProofUnavailable) {
		t.Fatalf("unapplied staging-proof request error = %v", err)
	}
	checkpoint := harness.checkpointEvent(t, leader, record)
	result, err := leader.node.Apply(meshTestContext(t), checkpoint)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(staging checkpoint) = (%#v, %v)", result, err)
	}
	awaitMeshCondition(
		t,
		15*time.Second,
		"staging checkpoint apply",
		func() bool {
			lookup, found, err := target.node.state.AppliedCheckpoint(
				context.Background(),
				record.CheckpointEventID,
			)
			return err == nil &&
				found &&
				lookup.Record.AuthoritySignature ==
					record.AuthoritySignature
		},
	)
	leaderLookup, found, err := leader.node.state.AppliedCheckpoint(
		meshTestContext(t),
		record.CheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf(
			"leader AppliedCheckpoint() = (%#v, %t, %v)",
			leaderLookup,
			found,
			err,
		)
	}
	proof, err := requestStagingApplyProof(
		meshTestContext(t),
		leader.stream,
		expectation,
	)
	if err != nil ||
		proof.appliedLogIndex != leaderLookup.AppliedLogIndex {
		t.Fatalf("requestStagingApplyProof() = (%#v, %v)", proof, err)
	}
	mismatched := expectation
	mismatched.record.AuthoritySignature[0] ^= 0xff
	if _, err := requestStagingApplyProof(
		meshTestContext(t),
		leader.stream,
		mismatched,
	); !errors.Is(err, ErrCheckpointProofRejected) {
		t.Fatalf("mismatched staging-proof request error = %v", err)
	}
	harness.changeMeshSuffrage(t, leader, target, raft.Voter)
}

func (harness *secureMeshHarness) proveAuthorityCheckpointSigning(
	t *testing.T,
	leader *secureMeshNode,
	signer *secureMeshNode,
) {
	t.Helper()
	if leader == nil || signer == nil || leader == signer {
		t.Fatal("invalid checkpoint-signing participants")
	}
	ctx := meshTestContext(t)
	guard, err := leader.node.acquireRaftEnqueue(ctx)
	if err != nil {
		t.Fatalf("acquire checkpoint enqueue cut: %v", err)
	}
	defer guard.release()
	if err := waitFuture(
		ctx,
		leader.node.raft.Barrier(contextTimeout(ctx)),
	); err != nil {
		t.Fatalf("checkpoint barrier: %v", err)
	}
	view, err := leader.node.View(ctx)
	if err != nil {
		t.Fatalf("checkpoint View(): %v", err)
	}
	term, err := raftTerm(leader.node.raft.Stats())
	if err != nil {
		t.Fatalf("checkpoint term: %v", err)
	}
	checkpoint := domain.Checkpoint{
		SessionID:                view.SessionID,
		WorkspaceID:              view.WorkspaceID,
		RecoveryGeneration:       view.RecoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           signer.identity.deviceID,
		Term:                     term,
		CoveredAppliedLogIndex:   leader.node.raft.AppliedIndex(),
		CoveredChainIndex:        view.Heads.ChainIndex,
		CoveredChainHash:         view.Heads.ChainHash,
		CoveredResultIndex:       view.Heads.ResultIndex,
		CoveredResultHash:        view.Heads.ResultHash,
		ProjectionAccumulator:    view.Heads.ProjectionAccumulator,
		DigestVersion:            view.Heads.DigestVersion,
		ProjectionSchemaVersion:  view.Heads.ProjectionSchemaVersion,
	}
	expectation, err := newCheckpointSigningExpectation(
		checkpoint,
		signer.identity.public,
	)
	if err != nil {
		t.Fatalf("checkpoint signing expectation: %v", err)
	}
	var proof checkpointSignatureProof
	awaitMeshCondition(
		t,
		10*time.Second,
		"authority checkpoint signature",
		func() bool {
			var requestErr error
			proof, requestErr = requestCheckpointSignature(
				context.Background(),
				leader.stream,
				expectation,
			)
			if requestErr == nil {
				return true
			}
			if !errors.Is(
				requestErr,
				ErrCheckpointProofUnavailable,
			) {
				t.Fatalf(
					"requestCheckpointSignature(): %v",
					requestErr,
				)
			}
			return false
		},
	)
	if codecommcrypto.VerifyEd25519(
		signer.identity.public,
		codec.SignatureCheckpoint,
		expectation.checkpointJSON,
		proof.signature[:],
	) != nil {
		t.Fatal("authority checkpoint signature did not verify")
	}

	mismatch := expectation
	mismatch.checkpoint.ProjectionAccumulator[0] ^= 0xff
	mismatch, err = newCheckpointSigningExpectation(
		mismatch.checkpoint,
		signer.identity.public,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := requestCheckpointSignature(
		ctx,
		leader.stream,
		mismatch,
	); !errors.Is(err, ErrCheckpointProofRejected) {
		t.Fatalf("mismatched checkpoint-sign request error = %v", err)
	}

	wrongTarget := expectation
	wrongTarget.checkpoint.SignerDeviceID =
		leader.identity.deviceID
	wrongTarget, err = newCheckpointSigningExpectation(
		wrongTarget.checkpoint,
		leader.identity.public,
	)
	if err != nil {
		t.Fatal(err)
	}
	body, err := encodeCheckpointSignRequest(wrongTarget)
	if err != nil {
		t.Fatal(err)
	}
	response, err := leader.stream.RequestConsensusProof(
		ctx,
		signer.identity.deviceID,
		body,
	)
	if err != nil {
		t.Fatalf("wrong-target checkpoint-sign request: %v", err)
	}
	if response.StatusCode != http.StatusForbidden ||
		response.MediaType != "application/problem+json" {
		t.Fatalf("wrong-target response = %#v", response)
	}
}

func (harness *secureMeshHarness) proveRemoteForcedCheckpoint(
	t *testing.T,
	leader *secureMeshNode,
) {
	t.Helper()
	if leader == nil {
		t.Fatal("forced checkpoint has no leader")
	}
	leader.checkpointSigningDisabled.Store(true)
	defer leader.checkpointSigningDisabled.Store(false)

	var result store.AppliedCheckpointLookup
	awaitMeshCondition(
		t,
		10*time.Second,
		"remote-signed forced checkpoint",
		func() bool {
			var err error
			result, err = leader.node.ForceCheckpoint(
				meshTestContext(t),
			)
			if err == nil {
				return true
			}
			if !errors.Is(err, ErrCheckpointProofUnavailable) &&
				!errors.Is(
					err,
					ErrConsensusAuthorizationUnavailable,
				) {
				t.Fatalf("ForceCheckpoint(): %v", err)
			}
			return false
		},
	)
	if result.Record.SignerDeviceID == leader.identity.deviceID ||
		result.AppliedLogIndex !=
			result.Record.CoveredAppliedLogIndex+1 {
		t.Fatalf("forced checkpoint = %#v", result)
	}
	var signerPublicKey ed25519.PublicKey
	for _, candidate := range harness.nodes {
		if candidate.identity.deviceID ==
			result.Record.SignerDeviceID {
			signerPublicKey = candidate.identity.public
			break
		}
	}
	if codecommcrypto.VerifyEd25519(
		signerPublicKey,
		codec.SignatureCheckpoint,
		result.Record.CheckpointJSON,
		result.Record.AuthoritySignature[:],
	) != nil {
		t.Fatal("forced remote authority signature did not verify")
	}
	awaitMeshCondition(
		t,
		10*time.Second,
		"forced checkpoint replication",
		func() bool {
			for _, candidate := range harness.runningNodes() {
				replica, found, err := candidate.node.state.
					AppliedCheckpoint(
						context.Background(),
						meshForcedCheckpointEventID,
					)
				if err != nil ||
					!found ||
					replica.Record.AuthoritySignature !=
						result.Record.AuthoritySignature {
					return false
				}
			}
			return true
		},
	)
}

func (harness *secureMeshHarness) changeMeshSuffrage(
	t *testing.T,
	leader *secureMeshNode,
	target *secureMeshNode,
	suffrage raft.ServerSuffrage,
) {
	t.Helper()
	configuration := leader.node.fsm.committedConfiguration()
	if configuration == nil {
		t.Fatal("leader has no committed configuration")
	}
	var future raft.IndexFuture
	switch suffrage {
	case raft.Nonvoter:
		future = leader.node.raft.DemoteVoter(
			raft.ServerID(target.identity.deviceID),
			configuration.Index,
			5*time.Second,
		)
	case raft.Voter:
		future = leader.node.raft.AddVoter(
			raft.ServerID(target.identity.deviceID),
			raft.ServerAddress(target.identity.deviceID),
			configuration.Index,
			5*time.Second,
		)
	default:
		t.Fatalf("unsupported test suffrage %v", suffrage)
	}
	if err := waitFuture(meshTestContext(t), future); err != nil {
		t.Fatalf("change target suffrage to %v: %v", suffrage, err)
	}
	awaitMeshCondition(
		t,
		15*time.Second,
		"target suffrage convergence",
		func() bool {
			for _, candidate := range harness.runningNodes() {
				committed := candidate.node.fsm.committedConfiguration()
				if committed == nil ||
					committed.Index < future.Index() ||
					!configurationHasSuffrage(
						committed.Configuration,
						target.identity.deviceID,
						suffrage,
					) {
					return false
				}
			}
			return true
		},
	)
}

func configurationHasSuffrage(
	configuration raft.Configuration,
	deviceID domain.DeviceID,
	suffrage raft.ServerSuffrage,
) bool {
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(deviceID) {
			return server.Address == raft.ServerAddress(deviceID) &&
				server.Suffrage == suffrage
		}
	}
	return false
}

func (harness *secureMeshHarness) checkpointRecord(
	t *testing.T,
	leader *secureMeshNode,
) store.CheckpointRecord {
	t.Helper()
	view, err := leader.node.View(meshTestContext(t))
	if err != nil {
		t.Fatalf("View(checkpoint): %v", err)
	}
	coveredIndex, err := leader.node.stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(checkpoint): %v", err)
	}
	term, err := raftTerm(leader.node.raft.Stats())
	if err != nil {
		t.Fatalf("raftTerm(checkpoint): %v", err)
	}
	record := store.CheckpointRecord{
		CheckpointEventID:        meshCheckpointEventID,
		SessionID:                view.SessionID,
		WorkspaceID:              view.WorkspaceID,
		RecoveryGeneration:       view.RecoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           leader.identity.deviceID,
		Term:                     term,
		CoveredAppliedLogIndex:   coveredIndex,
		CoveredChainIndex:        view.Heads.ChainIndex,
		CoveredChainHash:         view.Heads.ChainHash,
		CoveredResultIndex:       view.Heads.ResultIndex,
		CoveredResultHash:        view.Heads.ResultHash,
		ProjectionAccumulator:    view.Heads.ProjectionAccumulator,
		DigestVersion:            view.Heads.DigestVersion,
		ProjectionSchemaVersion:  view.Heads.ProjectionSchemaVersion,
	}
	record.CheckpointJSON = checkpointProofTestCheckpointJSON(t, record)
	signature, err := codecommcrypto.SignEd25519(
		leader.identity.private,
		codec.SignatureCheckpoint,
		record.CheckpointJSON,
	)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	copy(record.AuthoritySignature[:], signature)
	if err := record.Validate(); err != nil {
		t.Fatalf("checkpoint record: %v", err)
	}
	return record
}

func (harness *secureMeshHarness) checkpointEvent(
	t *testing.T,
	leader *secureMeshNode,
	record store.CheckpointRecord,
) event.SignedEvent {
	t.Helper()
	checkpoint, err := event.DecodeCheckpoint(record.CheckpointJSON)
	if err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	encoded, err := event.EncodeCheckpointPayload(
		checkpoint,
		[ed25519.SignatureSize]byte(record.AuthoritySignature),
	)
	if err != nil {
		t.Fatalf("encode checkpoint payload: %v", err)
	}
	authority, err := event.NewLocalAuthority(
		leader.identity.deviceID,
		leader.identity.bootIDs[leader.startCount-1],
	)
	if err != nil {
		t.Fatalf("checkpoint authority: %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("checkpoint daemon binding: %v", err)
	}
	sequence := leader.nextSequence
	leader.nextSequence++
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindConsensusCheckpoint,
			EntityID: event.NullEntityID(),
			Actions:  []event.Action{},
			Payload:  encoded,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        record.CheckpointEventID,
			SessionID:      record.SessionID,
			WorkspaceID:    record.WorkspaceID,
			CreatedAt:      domain.Timestamp("2026-08-11T12:00:30Z"),
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("build checkpoint proposal: %v", err)
	}
	signed, err := event.Sign(proposal, leader.identity.private)
	if err != nil {
		t.Fatalf("sign checkpoint event: %v", err)
	}
	return signed
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

func (harness *secureMeshHarness) secureMeshRaftConfig() *raft.Config {
	config := secureMeshRaftConfig()
	if harness != nil && harness.compactSnapshots {
		config.TrailingLogs = 0
	}
	return config
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
	faults        *faultnet.Controller
}

func TestSecureMeshTopologyPartitionClosesEstablishedConnections(
	t *testing.T,
) {
	topology := newSecureMeshTopology()
	localDeviceID := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	remoteDeviceID := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	const address = "127.0.0.1:47831"
	topology.register(remoteDeviceID, endpoint, address)

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	tracked, allowed := topology.trackConnection(
		localDeviceID,
		remoteDeviceID,
		endpoint,
		address,
		local,
	)
	if !allowed || tracked == nil {
		_ = local.Close()
		t.Fatal("initial established connection was not tracked")
	}
	if got := topology.activeConnectionCount(remoteDeviceID); got != 1 {
		t.Fatalf("active connection count = %d, want 1", got)
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set peer read deadline: %v", err)
	}

	if closed := topology.setPartition(remoteDeviceID, true); closed != 1 {
		t.Fatalf("partition closed %d established connections, want 1", closed)
	}
	if got := topology.activeConnectionCount(remoteDeviceID); got != 0 {
		t.Fatalf("active connection count after partition = %d, want 0", got)
	}
	if _, allowed := topology.resolve(localDeviceID, endpoint); allowed {
		t.Fatal("partitioned endpoint remained resolvable")
	}
	if _, err := remote.Read(make([]byte, 1)); err == nil {
		t.Fatal("partition left the established connection open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("partition did not close the established connection")
	}

	racingLocal, racingRemote := net.Pipe()
	if connection, allowed := topology.trackConnection(
		localDeviceID,
		remoteDeviceID,
		endpoint,
		address,
		racingLocal,
	); allowed || connection != nil {
		_ = racingLocal.Close()
		_ = racingRemote.Close()
		t.Fatal("partition admitted a newly dialed connection")
	}
	_ = racingLocal.Close()
	_ = racingRemote.Close()

	if closed := topology.setPartition(remoteDeviceID, false); closed != 0 {
		t.Fatalf("healing closed %d connections, want 0", closed)
	}
	if resolved, allowed := topology.resolve(
		localDeviceID,
		endpoint,
	); !allowed ||
		resolved.deviceID != remoteDeviceID ||
		resolved.address != address {
		t.Fatalf(
			"healed resolution = (%+v, %t), want (%s, %q, true)",
			resolved,
			allowed,
			remoteDeviceID,
			address,
		)
	}
}

func TestSecureMeshTopologyPartitionedResolutionResumesOnHeal(
	t *testing.T,
) {
	topology := newSecureMeshTopology()
	localDeviceID := domain.DeviceID("cc1" + strings.Repeat("1", 64))
	remoteDeviceID := domain.DeviceID("cc1" + strings.Repeat("2", 64))
	endpoint := netip.MustParseAddrPort("192.0.2.10:47831")
	const address = "127.0.0.1:47831"
	topology.register(remoteDeviceID, endpoint, address)
	topology.setPartition(remoteDeviceID, true)

	baseContext, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	waitContext := &secureMeshObservedWaitContext{
		Context: baseContext,
		entered: make(chan struct{}),
	}
	type resolution struct {
		target secureMeshTarget
		err    error
	}
	resolved := make(chan resolution, 1)
	go func() {
		target, err := topology.waitForTarget(
			waitContext,
			localDeviceID,
			endpoint,
		)
		resolved <- resolution{target: target, err: err}
	}()

	select {
	case <-waitContext.entered:
	case <-baseContext.Done():
		t.Fatal("partitioned resolution did not wait for topology change")
	}
	select {
	case result := <-resolved:
		t.Fatalf(
			"partitioned resolution completed before heal: (%+v, %v)",
			result.target,
			result.err,
		)
	default:
	}

	topology.setPartition(remoteDeviceID, false)
	select {
	case result := <-resolved:
		if result.err != nil ||
			result.target.deviceID != remoteDeviceID ||
			result.target.address != address {
			t.Fatalf(
				"healed resolution = (%+v, %v), want (%s, %q, nil)",
				result.target,
				result.err,
				remoteDeviceID,
				address,
			)
		}
	case <-baseContext.Done():
		t.Fatal("healed resolution did not resume")
	}

	topology.setPartition(remoteDeviceID, true)
	canceledContext, cancelWait := context.WithCancel(t.Context())
	cancelWait()
	if _, err := topology.waitForTarget(
		canceledContext,
		localDeviceID,
		endpoint,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled partitioned resolution error = %v", err)
	}

	topology.mu.Lock()
	topology.partitionDialDelay = time.Millisecond
	topology.mu.Unlock()
	unavailableContext, cancelUnavailable := context.WithTimeout(
		t.Context(),
		time.Second,
	)
	defer cancelUnavailable()
	if _, err := topology.waitForTarget(
		unavailableContext,
		localDeviceID,
		endpoint,
	); !errors.Is(err, transport.ErrConsensusEndpointUnavailable) {
		t.Fatalf("unhealed partitioned resolution error = %v", err)
	}
}

func (dialer secureMeshDialer) DialConsensusEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	target, err := dialer.topology.waitForTarget(
		ctx,
		dialer.localDeviceID,
		endpoint,
	)
	if err != nil {
		return nil, err
	}
	var networkDialer net.Dialer
	connection, err := networkDialer.DialContext(
		ctx,
		"tcp4",
		target.address,
	)
	if err != nil {
		return nil, err
	}
	faulted, err := dialer.faults.Wrap(
		connection,
		dialer.localDeviceID,
		target.deviceID,
	)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	tracked, allowed := dialer.topology.trackConnection(
		dialer.localDeviceID,
		target.deviceID,
		endpoint,
		target.address,
		faulted,
	)
	if !allowed {
		_ = faulted.Close()
		return nil, transport.ErrConsensusEndpointUnavailable
	}
	return tracked, nil
}

type secureMeshTopology struct {
	mu                 sync.RWMutex
	targets            map[netip.AddrPort]secureMeshTarget
	partitioned        map[domain.DeviceID]bool
	connections        map[*secureMeshTrackedConnection]struct{}
	changes            chan struct{}
	partitionDialDelay time.Duration
}

type secureMeshTarget struct {
	deviceID domain.DeviceID
	address  string
}

type secureMeshTrackedConnection struct {
	net.Conn

	topology       *secureMeshTopology
	localDeviceID  domain.DeviceID
	remoteDeviceID domain.DeviceID

	closeOnce sync.Once
	closeErr  error
}

type secureMeshObservedWaitContext struct {
	context.Context

	entered chan struct{}
	once    sync.Once
}

func (ctx *secureMeshObservedWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() {
		close(ctx.entered)
	})
	return ctx.Context.Done()
}

func (connection *secureMeshTrackedConnection) Close() error {
	if connection == nil {
		return net.ErrClosed
	}
	connection.closeOnce.Do(func() {
		connection.topology.untrackConnection(connection)
		connection.closeErr = connection.Conn.Close()
	})
	return connection.closeErr
}

func newSecureMeshTopology() *secureMeshTopology {
	return &secureMeshTopology{
		targets:     make(map[netip.AddrPort]secureMeshTarget),
		partitioned: make(map[domain.DeviceID]bool),
		connections: make(map[*secureMeshTrackedConnection]struct{}),
		changes:     make(chan struct{}),
		// Avoid saturating Raft's retry backoff before a short partition heals.
		partitionDialDelay: secureMeshRaftConfig().HeartbeatTimeout / 2,
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
	topology.signalChangeLocked()
	topology.mu.Unlock()
}

func (topology *secureMeshTopology) unregister(endpoint netip.AddrPort) {
	topology.mu.Lock()
	target, exists := topology.targets[endpoint]
	delete(topology.targets, endpoint)
	topology.signalChangeLocked()
	var connections []*secureMeshTrackedConnection
	if exists {
		connections = topology.connectionsForDeviceLocked(target.deviceID)
	}
	topology.mu.Unlock()
	closeSecureMeshConnections(connections)
}

func (topology *secureMeshTopology) setPartition(
	deviceID domain.DeviceID,
	partitioned bool,
) int {
	topology.mu.Lock()
	changed := topology.partitioned[deviceID] != partitioned
	topology.partitioned[deviceID] = partitioned
	if changed {
		topology.signalChangeLocked()
	}
	var connections []*secureMeshTrackedConnection
	if partitioned {
		connections = topology.connectionsForDeviceLocked(deviceID)
	}
	topology.mu.Unlock()
	closeSecureMeshConnections(connections)
	return len(connections)
}

func (topology *secureMeshTopology) resolve(
	localDeviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (secureMeshTarget, bool) {
	topology.mu.RLock()
	defer topology.mu.RUnlock()
	target, exists := topology.targets[endpoint]
	if !exists ||
		topology.partitioned[localDeviceID] ||
		topology.partitioned[target.deviceID] {
		return secureMeshTarget{}, false
	}
	return target, true
}

func (topology *secureMeshTopology) waitForTarget(
	ctx context.Context,
	localDeviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (secureMeshTarget, error) {
	if topology == nil || ctx == nil {
		return secureMeshTarget{}, transport.ErrConsensusEndpointUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return secureMeshTarget{}, err
		}
		topology.mu.RLock()
		target, exists := topology.targets[endpoint]
		partitioned := exists &&
			(topology.partitioned[localDeviceID] ||
				topology.partitioned[target.deviceID])
		changes := topology.changes
		partitionDialDelay := topology.partitionDialDelay
		topology.mu.RUnlock()
		if !exists {
			return secureMeshTarget{},
				transport.ErrConsensusEndpointUnavailable
		}
		if !partitioned {
			return target, nil
		}
		if partitionDialDelay <= 0 {
			return secureMeshTarget{},
				transport.ErrConsensusEndpointUnavailable
		}
		timer := time.NewTimer(partitionDialDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return secureMeshTarget{}, ctx.Err()
		case <-changes:
			timer.Stop()
		case <-timer.C:
			if target, allowed := topology.resolve(
				localDeviceID,
				endpoint,
			); allowed {
				return target, nil
			}
			return secureMeshTarget{},
				transport.ErrConsensusEndpointUnavailable
		}
	}
}

func (topology *secureMeshTopology) signalChangeLocked() {
	if topology.changes != nil {
		close(topology.changes)
	}
	topology.changes = make(chan struct{})
}

func (topology *secureMeshTopology) trackConnection(
	localDeviceID domain.DeviceID,
	remoteDeviceID domain.DeviceID,
	endpoint netip.AddrPort,
	address string,
	connection net.Conn,
) (*secureMeshTrackedConnection, bool) {
	if topology == nil || connection == nil {
		return nil, false
	}
	topology.mu.Lock()
	target, exists := topology.targets[endpoint]
	if !exists ||
		target.deviceID != remoteDeviceID ||
		target.address != address ||
		topology.partitioned[localDeviceID] ||
		topology.partitioned[target.deviceID] {
		topology.mu.Unlock()
		return nil, false
	}
	tracked := &secureMeshTrackedConnection{
		Conn:           connection,
		topology:       topology,
		localDeviceID:  localDeviceID,
		remoteDeviceID: remoteDeviceID,
	}
	topology.connections[tracked] = struct{}{}
	topology.mu.Unlock()
	return tracked, true
}

func (topology *secureMeshTopology) untrackConnection(
	connection *secureMeshTrackedConnection,
) {
	if topology == nil || connection == nil {
		return
	}
	topology.mu.Lock()
	delete(topology.connections, connection)
	topology.mu.Unlock()
}

func (topology *secureMeshTopology) activeConnectionCount(
	deviceID domain.DeviceID,
) int {
	if topology == nil {
		return 0
	}
	topology.mu.RLock()
	defer topology.mu.RUnlock()
	return len(topology.connectionsForDeviceLocked(deviceID))
}

func (topology *secureMeshTopology) connectionsForDeviceLocked(
	deviceID domain.DeviceID,
) []*secureMeshTrackedConnection {
	connections := make([]*secureMeshTrackedConnection, 0)
	for connection := range topology.connections {
		if connection.localDeviceID == deviceID ||
			connection.remoteDeviceID == deviceID {
			connections = append(connections, connection)
		}
	}
	return connections
}

func closeSecureMeshConnections(
	connections []*secureMeshTrackedConnection,
) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func secureMeshRunsInProcess() bool {
	return os.Getenv(secureMeshInProcess) == "1"
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
