package raftprobe

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"go.etcd.io/bbolt"
)

const (
	probeSessionID                = "018f47de-89ab-7def-8123-0123456789ab"
	probeWorkspaceID              = "018f47de-89ab-7def-8123-1123456789ab"
	probeSignerDeviceID           = "ccdv1:phase1"
	probeAuthorityVersion  uint64 = 1
	probeDigestVersion     uint32 = 1
	probeProjectionVersion uint32 = 1

	raftHelperEnv        = "CODECOMM_PHASE1_RAFT_HELPER"
	raftHelperRootEnv    = "CODECOMM_PHASE1_RAFT_ROOT"
	raftHelperIDEnv      = "CODECOMM_PHASE1_RAFT_ID"
	raftHelperBindEnv    = "CODECOMM_PHASE1_RAFT_BIND"
	raftHelperCatchupEnv = "CODECOMM_PHASE1_RAFT_EXPECT_CATCHUP"
)

type checkpointPayload struct {
	SessionID                string `json:"session_id"`
	WorkspaceID              string `json:"workspace_id"`
	RecoveryGeneration       uint64 `json:"recovery_generation"`
	AuthorityVoterSetVersion uint64 `json:"authority_voter_set_version"`
	SignerDeviceID           string `json:"signer_device_id"`
	Term                     uint64 `json:"term"`
	CoveredAppliedLogIndex   uint64 `json:"covered_applied_log_index"`
	CoveredChainIndex        uint64 `json:"covered_chain_index"`
	CoveredChainHash         string `json:"covered_chain_hash"`
	CoveredResultIndex       uint64 `json:"covered_result_index"`
	CoveredResultHash        string `json:"covered_result_hash"`
	ProjectionAccumulator    string `json:"projection_accumulator"`
	DigestVersion            uint32 `json:"digest_version"`
	ProjectionSchemaVersion  uint32 `json:"projection_schema_version"`
}

type checkpointProof struct {
	EventID                     string `json:"event_id"`
	CommittedLogIndex           uint64 `json:"committed_log_index"`
	StoredProjectionAccumulator string `json:"stored_projection_accumulator"`
	AccumulatorMatched          bool   `json:"accumulator_matched"`
	checkpointPayload
}

type probeCommand struct {
	Kind       string             `json:"kind"`
	EventID    string             `json:"event_id,omitempty"`
	Key        string             `json:"key,omitempty"`
	Value      string             `json:"value,omitempty"`
	Checkpoint *checkpointPayload `json:"checkpoint,omitempty"`
}

type applyResult struct {
	Index uint64
	Proof *checkpointProof
	Err   string
}

type persistedState struct {
	Values      map[string]string `json:"values"`
	Accumulator string            `json:"accumulator"`
	ChainIndex  uint64            `json:"chain_index"`
	ChainHash   string            `json:"chain_hash"`
	ResultIndex uint64            `json:"result_index"`
	ResultHash  string            `json:"result_hash"`
	LastApplied uint64            `json:"last_applied"`
}

type probeFSM struct {
	mu          sync.RWMutex
	values      map[string]string
	accumulator [sha256.Size]byte
	chainIndex  uint64
	chainHash   [sha256.Size]byte
	resultIndex uint64
	resultHash  [sha256.Size]byte
	lastApplied uint64
	appliedData map[uint64][]byte
	proofs      map[string]checkpointProof

	blockKind   string
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	restores    atomic.Uint64
}

func newProbeFSM(blockKind string) *probeFSM {
	fsm := &probeFSM{
		values:      make(map[string]string),
		appliedData: make(map[uint64][]byte),
		proofs:      make(map[string]checkpointProof),
		blockKind:   blockKind,
	}
	if blockKind != "" {
		fsm.started = make(chan struct{})
		fsm.release = make(chan struct{})
	}
	return fsm
}

func (f *probeFSM) Apply(log *raft.Log) interface{} {
	var command probeCommand
	decoder := json.NewDecoder(bytes.NewReader(log.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return applyResult{Index: log.Index, Err: err.Error()}
	}

	if command.Kind == f.blockKind {
		f.startOnce.Do(func() { close(f.started) })
		<-f.release
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.appliedData[log.Index] = bytes.Clone(log.Data)

	switch command.Kind {
	case "put":
		f.values[command.Key] = command.Value
		f.chainIndex++
		f.chainHash = extendProbeHash("chain", f.chainHash, f.chainIndex, log.Data)
		f.resultIndex++
		f.resultHash = extendProbeHash("result", f.resultHash, f.resultIndex, f.chainHash[:])
		f.accumulator = extendProbeHash("accumulator", f.accumulator, f.resultIndex, log.Data)
		f.lastApplied = log.Index
		return applyResult{Index: log.Index}
	case "checkpoint":
		if command.Checkpoint == nil {
			return applyResult{Index: log.Index, Err: "missing checkpoint"}
		}
		if command.EventID == "" {
			return applyResult{Index: log.Index, Err: "missing event ID"}
		}
		if err := f.validateCheckpointLocked(log, command.Checkpoint); err != nil {
			return applyResult{Index: log.Index, Err: err.Error()}
		}
		proof := checkpointProof{
			EventID:                     command.EventID,
			CommittedLogIndex:           log.Index,
			StoredProjectionAccumulator: hex.EncodeToString(f.accumulator[:]),
			AccumulatorMatched:          true,
			checkpointPayload:           *command.Checkpoint,
		}
		f.proofs[command.EventID] = proof
		f.lastApplied = log.Index
		return applyResult{Index: log.Index, Proof: &proof}
	default:
		return applyResult{Index: log.Index, Err: "unknown command kind"}
	}
}

func (f *probeFSM) validateCheckpointLocked(log *raft.Log, checkpoint *checkpointPayload) error {
	checks := []struct {
		ok   bool
		name string
	}{
		{checkpoint.SessionID == probeSessionID, "session ID"},
		{checkpoint.WorkspaceID == probeWorkspaceID, "workspace ID"},
		{checkpoint.RecoveryGeneration == 0, "recovery generation"},
		{checkpoint.AuthorityVoterSetVersion == probeAuthorityVersion, "authority version"},
		{checkpoint.SignerDeviceID == probeSignerDeviceID, "signer device ID"},
		{checkpoint.Term == log.Term, "term"},
		{log.Index > 0 && checkpoint.CoveredAppliedLogIndex == log.Index-1, "covered applied log index"},
		{checkpoint.CoveredChainIndex == f.chainIndex, "covered chain index"},
		{checkpoint.CoveredChainHash == hex.EncodeToString(f.chainHash[:]), "covered chain hash"},
		{checkpoint.CoveredResultIndex == f.resultIndex, "covered result index"},
		{checkpoint.CoveredResultHash == hex.EncodeToString(f.resultHash[:]), "covered result hash"},
		{checkpoint.ProjectionAccumulator == hex.EncodeToString(f.accumulator[:]), "projection accumulator"},
		{checkpoint.DigestVersion == probeDigestVersion, "digest version"},
		{checkpoint.ProjectionSchemaVersion == probeProjectionVersion, "projection schema version"},
	}
	for _, check := range checks {
		if !check.ok {
			return fmt.Errorf("%s mismatch", check.name)
		}
	}
	return nil
}

func extendProbeHash(domain string, previous [sha256.Size]byte, index uint64, data []byte) [sha256.Size]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(previous[:])
	var encodedIndex [8]byte
	binary.BigEndian.PutUint64(encodedIndex[:], index)
	_, _ = hasher.Write(encodedIndex[:])
	_, _ = hasher.Write(data)
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func (f *probeFSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	values := make(map[string]string, len(f.values))
	for key, value := range f.values {
		values[key] = value
	}
	encoded, err := json.Marshal(persistedState{
		Values:      values,
		Accumulator: hex.EncodeToString(f.accumulator[:]),
		ChainIndex:  f.chainIndex,
		ChainHash:   hex.EncodeToString(f.chainHash[:]),
		ResultIndex: f.resultIndex,
		ResultHash:  hex.EncodeToString(f.resultHash[:]),
		LastApplied: f.lastApplied,
	})
	if err != nil {
		return nil, err
	}
	return probeSnapshot(encoded), nil
}

func (f *probeFSM) Restore(reader io.ReadCloser) error {
	var state persistedState
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return err
	}
	accumulator, err := decodeProbeDigest("accumulator", state.Accumulator)
	if err != nil {
		return err
	}
	chainHash, err := decodeProbeDigest("chain hash", state.ChainHash)
	if err != nil {
		return err
	}
	resultHash, err := decodeProbeDigest("result hash", state.ResultHash)
	if err != nil {
		return err
	}

	f.mu.Lock()
	f.values = state.Values
	copy(f.accumulator[:], accumulator)
	f.chainIndex = state.ChainIndex
	copy(f.chainHash[:], chainHash)
	f.resultIndex = state.ResultIndex
	copy(f.resultHash[:], resultHash)
	f.lastApplied = state.LastApplied
	f.mu.Unlock()
	f.restores.Add(1)
	return nil
}

func decodeProbeDigest(name, encoded string) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("invalid %s length: %d", name, len(decoded))
	}
	return decoded, nil
}

func (f *probeFSM) checkpointPayload(term, coveredAppliedLogIndex uint64) checkpointPayload {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return checkpointPayload{
		SessionID:                probeSessionID,
		WorkspaceID:              probeWorkspaceID,
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: probeAuthorityVersion,
		SignerDeviceID:           probeSignerDeviceID,
		Term:                     term,
		CoveredAppliedLogIndex:   coveredAppliedLogIndex,
		CoveredChainIndex:        f.chainIndex,
		CoveredChainHash:         hex.EncodeToString(f.chainHash[:]),
		CoveredResultIndex:       f.resultIndex,
		CoveredResultHash:        hex.EncodeToString(f.resultHash[:]),
		ProjectionAccumulator:    hex.EncodeToString(f.accumulator[:]),
		DigestVersion:            probeDigestVersion,
		ProjectionSchemaVersion:  probeProjectionVersion,
	}
}

func (f *probeFSM) dataAt(index uint64) []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return bytes.Clone(f.appliedData[index])
}

func (f *probeFSM) proof(eventID string) (checkpointProof, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	proof, ok := f.proofs[eventID]
	return proof, ok
}

func (f *probeFSM) value(key string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	value, ok := f.values[key]
	return value, ok
}

func (f *probeFSM) unblock() {
	if f.release != nil {
		f.releaseOnce.Do(func() { close(f.release) })
	}
}

func checkpointProofsEqual(left, right checkpointProof) bool {
	return left == right
}

type probeSnapshot []byte

func (s probeSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (probeSnapshot) Release() {}

type probeNode struct {
	id        raft.ServerID
	address   raft.ServerAddress
	raft      *raft.Raft
	fsm       *probeFSM
	store     *raftboltdb.BoltStore
	transport *raft.NetworkTransport
	stopped   atomic.Bool
}

func newProbeNode(t *testing.T, root, id, blockKind string) *probeNode {
	t.Helper()
	return newProbeNodeAt(t, root, id, blockKind, "127.0.0.1:0")
}

func newProbeNodeAt(t *testing.T, root, id, blockKind, bindAddress string) *probeNode {
	t.Helper()

	nodeDir := filepath.Join(root, id)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatalf("create node directory: %v", err)
	}

	transport, err := raft.NewTCPTransport(bindAddress, nil, 3, time.Second, io.Discard)
	if err != nil {
		t.Fatalf("create Raft transport: %v", err)
	}

	boltOptions := *bbolt.DefaultOptions
	boltOptions.Timeout = time.Second
	boltOptions.NoFreelistSync = false
	store, err := raftboltdb.New(raftboltdb.Options{
		Path:        filepath.Join(nodeDir, "raft.db"),
		BoltOptions: &boltOptions,
		NoSync:      false,
	})
	if err != nil {
		_ = transport.Close()
		t.Fatalf("create Raft store: %v", err)
	}

	snapshots, err := raft.NewFileSnapshotStore(filepath.Join(nodeDir, "snapshots"), 3, io.Discard)
	if err != nil {
		_ = store.Close()
		_ = transport.Close()
		t.Fatalf("create snapshot store: %v", err)
	}

	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(id)
	// These are the library's real timing parameters, deliberately kept short so
	// elections and transfers complete quickly. One consequence is load-bearing
	// and was found by CI rather than by reading the source: hashicorp/raft bounds
	// LeadershipTransferToServer by ElectionTimeout (raft.go, v1.7.3), so a target
	// that cannot be brought current within one election timeout fails the
	// transfer outright. On slower hosts — GitHub's Windows runners, or any host
	// under I/O contention — 300 ms is not enough for a freshly started
	// subprocess voter to catch up, and the transfer times out even though
	// consensus is healthy.
	//
	// Design §3 step 3.3 depends on targeted transfer during voter-set
	// reconciliation, so production MUST NOT inherit these spike values: it needs
	// an ElectionTimeout that accommodates a catching-up target, or it must
	// transfer only to a voter already proven current (which §3 in fact requires
	// via the checkpoint proof). Recorded in phase-1-status.md as a library
	// constraint on §3.
	electionTimeout := 300 * time.Millisecond
	if runtime.GOOS == "windows" {
		electionTimeout = 2 * time.Second
	}
	if override := os.Getenv("CODECOMM_PHASE1_ELECTION_TIMEOUT"); override != "" {
		if parsed, err := time.ParseDuration(override); err == nil && parsed > 0 {
			electionTimeout = parsed
		}
	}
	config.HeartbeatTimeout = electionTimeout
	config.ElectionTimeout = electionTimeout
	config.CommitTimeout = 20 * time.Millisecond
	config.LeaderLeaseTimeout = electionTimeout / 2
	config.SnapshotInterval = 20 * time.Second
	config.SnapshotThreshold = 4
	config.TrailingLogs = 1
	config.LogLevel = "ERROR"
	config.LogOutput = io.Discard

	fsm := newProbeFSM(blockKind)
	instance, err := raft.NewRaft(config, fsm, store, store, snapshots, transport)
	if err != nil {
		_ = store.Close()
		_ = transport.Close()
		t.Fatalf("create Raft node: %v", err)
	}

	node := &probeNode{
		id:        raft.ServerID(id),
		address:   transport.LocalAddr(),
		raft:      instance,
		fsm:       fsm,
		store:     store,
		transport: transport,
	}
	t.Cleanup(func() { node.stop(t) })
	return node
}

func (n *probeNode) stop(t *testing.T) {
	t.Helper()
	if n.stopped.Swap(true) {
		return
	}
	n.fsm.unblock()
	if err := n.raft.Shutdown().Error(); err != nil {
		t.Errorf("shut down %s: %v", n.id, err)
	}
	if err := n.store.Close(); err != nil {
		t.Errorf("close %s store: %v", n.id, err)
	}
}

func bootstrap(t *testing.T, nodes ...*probeNode) {
	t.Helper()
	servers := make([]raft.Server, 0, len(nodes))
	for _, node := range nodes {
		servers = append(servers, raft.Server{
			Suffrage: raft.Voter,
			ID:       node.id,
			Address:  node.address,
		})
	}
	bootstrapServers(t, nodes[0], servers)
}

func bootstrapServers(t *testing.T, node *probeNode, servers []raft.Server) {
	t.Helper()
	if err := node.raft.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil {
		t.Fatalf("bootstrap cluster: %v", err)
	}
}

type probeProcess struct {
	command *exec.Cmd
	stderr  *bytes.Buffer
	output  <-chan string
	id      raft.ServerID
	address raft.ServerAddress
}

func startProbeProcess(t *testing.T, root, id, bindAddress string, expectCatchup bool) *probeProcess {
	t.Helper()
	if bindAddress == "" {
		bindAddress = "127.0.0.1:0"
	}

	command := exec.Command(os.Args[0], "-test.run=^TestThreeVoterCrashElectionAndRestart$")
	command.Env = append(
		os.Environ(),
		raftHelperEnv+"=1",
		raftHelperRootEnv+"="+root,
		raftHelperIDEnv+"="+id,
		raftHelperBindEnv+"="+bindAddress,
		raftHelperCatchupEnv+"="+strconv.FormatBool(expectCatchup),
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open Raft helper stdout: %v", err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start Raft helper: %v", err)
	}

	output := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			output <- strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			output <- "ERROR " + err.Error()
		}
		close(output)
	}()

	var line string
	select {
	case line = <-output:
	case <-time.After(probeTimeout):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("timed out starting Raft helper; stderr: %s", stderr.String())
	}
	if !strings.HasPrefix(line, "READY ") {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("Raft helper did not become ready: %q; stderr: %s", line, stderr.String())
	}

	process := &probeProcess{
		command: command,
		stderr:  stderr,
		output:  output,
		id:      raft.ServerID(id),
		address: raft.ServerAddress(strings.TrimPrefix(line, "READY ")),
	}
	t.Cleanup(func() {
		if process.command.ProcessState == nil {
			_ = process.command.Process.Kill()
			_ = process.command.Wait()
		}
	})
	return process
}

func (p *probeProcess) waitForOutput(t *testing.T, want string) {
	t.Helper()
	select {
	case line, ok := <-p.output:
		if !ok {
			t.Fatalf("Raft helper %s exited before %q; stderr: %s", p.id, want, p.stderr.String())
		}
		if line != want {
			t.Fatalf("Raft helper %s output %q, want %q", p.id, line, want)
		}
	case <-time.After(probeTimeout):
		t.Fatalf("timed out waiting for Raft helper %s output %q", p.id, want)
	}
}

func (p *probeProcess) kill(t *testing.T) {
	t.Helper()
	if p.command.ProcessState != nil {
		return
	}
	if err := p.command.Process.Kill(); err != nil {
		t.Fatalf("kill Raft helper %s: %v; stderr: %s", p.id, err, p.stderr.String())
	}
	if err := p.command.Wait(); err == nil {
		t.Fatalf("killed Raft helper %s exited successfully", p.id)
	}
}

func runRaftHelper(t *testing.T) {
	t.Helper()
	root := os.Getenv(raftHelperRootEnv)
	id := os.Getenv(raftHelperIDEnv)
	bindAddress := os.Getenv(raftHelperBindEnv)
	if root == "" || id == "" || bindAddress == "" {
		t.Fatal("Raft helper environment is incomplete")
	}
	node := newProbeNodeAt(t, root, id, "", bindAddress)
	fmt.Printf("READY %s\n", node.address)
	if os.Getenv(raftHelperCatchupEnv) == "true" {
		eventually(t, "helper catch-up", func() bool {
			value, ok := node.fsm.value("after-crash")
			if ok {
				fmt.Printf("APPLIED after-crash=%s\n", value)
			}
			return ok
		})
	}
	select {}
}

func waitForLeader(t *testing.T, nodes ...*probeNode) *probeNode {
	t.Helper()
	var leader *probeNode
	eventually(t, "one Raft leader", func() bool {
		leader = nil
		for _, node := range nodes {
			if !node.stopped.Load() && node.raft.State() == raft.Leader {
				if leader != nil {
					return false
				}
				leader = node
			}
		}
		return leader != nil
	})
	return leader
}

func waitForObservedLeaderID(t *testing.T, observer *probeNode, id raft.ServerID) {
	t.Helper()
	eventually(t, "observed leader "+string(id), func() bool {
		_, observedID := observer.raft.LeaderWithID()
		return observedID == id
	})
}

// probeTimeout bounds every wait in this package. It is a variable rather than a
// constant because the spike runs subprocess voters that must spawn, bind TCP,
// and open bbolt before they can participate, and GitHub's Windows runners are
// markedly slower at process creation and file I/O than the Linux and macOS
// ones. A budget tuned for a fast machine turns an ordinary slow start into a
// spurious consensus failure, which is worse than a slow test: it reports a
// safety problem where none exists.
//
// The election parameters themselves are deliberately NOT scaled — those are the
// library behavior under test. Only the harness's patience changes.
var probeTimeout = platformProbeTimeout()

func platformProbeTimeout() time.Duration {
	if override := os.Getenv("CODECOMM_PHASE1_PROBE_TIMEOUT"); override != "" {
		if parsed, err := time.ParseDuration(override); err == nil && parsed > 0 {
			return parsed
		}
	}
	if runtime.GOOS == "windows" {
		return 45 * time.Second
	}
	return 15 * time.Second
}

func eventually(t *testing.T, description string, condition func() bool) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(probeTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s after %s (budget %s, GOOS=%s)",
		description, time.Since(start).Round(time.Millisecond), probeTimeout, runtime.GOOS)
}

func applyCommand(t *testing.T, node *probeNode, command probeCommand) (uint64, applyResult) {
	t.Helper()
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("encode command: %v", err)
	}
	future := node.raft.Apply(encoded, probeTimeout)
	if err := future.Error(); err != nil {
		t.Fatalf("apply command: %v", err)
	}
	result, ok := future.Response().(applyResult)
	if !ok {
		t.Fatalf("unexpected FSM response %T", future.Response())
	}
	if result.Err != "" {
		t.Fatalf("FSM rejected command: %s", result.Err)
	}
	if result.Index != future.Index() {
		t.Fatalf("FSM index %d differs from committed index %d", result.Index, future.Index())
	}
	return future.Index(), result
}

func TestBarrierWaitsForFSMApply(t *testing.T) {
	node := newProbeNode(t, t.TempDir(), "barrier", "put")
	bootstrap(t, node)
	waitForLeader(t, node)

	command := probeCommand{Kind: "put", Key: "gate", Value: "open"}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	applyFuture := node.raft.Apply(encoded, probeTimeout)

	select {
	case <-node.fsm.started:
	case <-time.After(probeTimeout):
		t.Fatal("FSM did not start blocked apply")
	}

	barrierFuture := node.raft.Barrier(probeTimeout)
	barrierDone := make(chan error, 1)
	go func() { barrierDone <- barrierFuture.Error() }()

	select {
	case err := <-barrierDone:
		t.Fatalf("barrier completed before FSM apply: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	node.fsm.unblock()
	if err := <-barrierDone; err != nil {
		t.Fatalf("barrier failed: %v", err)
	}
	if err := applyFuture.Error(); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if value, ok := node.fsm.value("gate"); !ok || value != "open" {
		t.Fatalf("post-barrier state not visible: value=%q present=%t", value, ok)
	}
}

func TestThreeVoterCrashElectionAndRestart(t *testing.T) {
	if os.Getenv(raftHelperEnv) == "1" {
		runRaftHelper(t)
		return
	}

	root := t.TempDir()
	nodes := []*probeNode{
		newProbeNode(t, root, "node-a", ""),
		newProbeNode(t, root, "node-b", ""),
	}
	remote := startProbeProcess(t, root, "node-c", "", false)
	remoteAddress := remote.address
	bootstrapServers(t, nodes[0], []raft.Server{
		{Suffrage: raft.Voter, ID: nodes[0].id, Address: nodes[0].address},
		{Suffrage: raft.Voter, ID: nodes[1].id, Address: nodes[1].address},
		{Suffrage: raft.Voter, ID: remote.id, Address: remote.address},
	})

	var observedLeader raft.ServerID
	eventually(t, "initial three-voter leader", func() bool {
		_, observedLeader = nodes[0].raft.LeaderWithID()
		return observedLeader != ""
	})
	if observedLeader == remote.id {
		remote.kill(t)
		waitForLeader(t, nodes...)
		remote = startProbeProcess(t, root, "node-c", string(remoteAddress), false)
		if remote.address != remoteAddress {
			t.Fatalf("restarted helper address = %s, want %s", remote.address, remoteAddress)
		}
	}
	leader := waitForLeader(t, nodes...)

	proposal := probeCommand{Kind: "put", Key: "first", Value: "committed"}
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"index", "log_index", "term"} {
		if _, ok := decoded[forbidden]; ok {
			t.Fatalf("proposal unexpectedly contains pre-commit ordering field %q", forbidden)
		}
	}

	future := leader.raft.Apply(encoded, probeTimeout)
	if err := future.Error(); err != nil {
		t.Fatalf("apply first command: %v", err)
	}
	result, ok := future.Response().(applyResult)
	if !ok || result.Err != "" {
		t.Fatalf("unexpected apply response: %#v", future.Response())
	}
	if result.Index != future.Index() {
		t.Fatalf("FSM learned index %d, future reported %d", result.Index, future.Index())
	}
	for _, node := range nodes {
		eventually(t, "byte-identical proposal on "+string(node.id), func() bool {
			return bytes.Equal(node.fsm.dataAt(future.Index()), encoded)
		})
	}

	if err := leader.raft.LeadershipTransferToServer(remote.id, remote.address).Error(); err != nil {
		t.Fatalf("targeted leadership transfer: %v", err)
	}
	waitForObservedLeaderID(t, nodes[0], remote.id)

	remote.kill(t)
	replacement := waitForLeader(t, nodes...)
	applyCommand(t, replacement, probeCommand{Kind: "put", Key: "after-crash", Value: "committed"})
	for _, node := range nodes {
		eventually(t, "majority commit on "+string(node.id), func() bool {
			value, ok := node.fsm.value("after-crash")
			return ok && value == "committed"
		})
	}

	remote = startProbeProcess(t, root, "node-c", string(remoteAddress), true)
	if remote.address != remoteAddress {
		t.Fatalf("restarted helper address = %s, want %s", remote.address, remoteAddress)
	}
	remote.waitForOutput(t, "APPLIED after-crash=committed")

	leader = waitForLeader(t, nodes...)
	applyCommand(t, leader, probeCommand{Kind: "put", Key: "after-restart", Value: "committed"})
	if err := leader.raft.LeadershipTransferToServer(remote.id, remote.address).Error(); err != nil {
		t.Fatalf("transfer to restarted follower: %v", err)
	}
	waitForObservedLeaderID(t, nodes[0], remote.id)

	remote.kill(t)
	replacement = waitForLeader(t, nodes...)
	applyCommand(t, replacement, probeCommand{Kind: "put", Key: "after-second-crash", Value: "committed"})
}

func TestStagedNonvoterProvesCheckpointAfterSnapshotApply(t *testing.T) {
	root := t.TempDir()
	leader := newProbeNode(t, root, "leader", "")
	bootstrap(t, leader)
	waitForLeader(t, leader)

	for i := 0; i < 12; i++ {
		applyCommand(t, leader, probeCommand{
			Kind:  "put",
			Key:   "key-" + strconv.Itoa(i),
			Value: "value-" + strconv.Itoa(i),
		})
	}
	if err := leader.raft.Barrier(probeTimeout).Error(); err != nil {
		t.Fatalf("pre-checkpoint barrier: %v", err)
	}
	if err := leader.raft.Snapshot().Error(); err != nil {
		t.Fatalf("take snapshot: %v", err)
	}
	eventually(t, "leader log compaction", func() bool {
		first, err := leader.store.FirstIndex()
		return err == nil && first > 1
	})

	target := newProbeNode(t, root, "target", "checkpoint")
	configuration := leader.raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		t.Fatalf("read configuration: %v", err)
	}
	if err := leader.raft.AddNonvoter(
		target.id,
		target.address,
		configuration.Index(),
		probeTimeout,
	).Error(); err != nil {
		t.Fatalf("add staged nonvoter: %v", err)
	}
	if err := leader.raft.Barrier(probeTimeout).Error(); err != nil {
		t.Fatalf("post-staging barrier: %v", err)
	}

	stats := leader.raft.Stats()
	term, err := strconv.ParseUint(stats["term"], 10, 64)
	if err != nil {
		t.Fatalf("parse leader term: %v", err)
	}
	checkpoint := leader.fsm.checkpointPayload(term, leader.raft.AppliedIndex())
	eventID := "018f47de-89ab-7def-8123-2123456789ab"
	_, leaderResult := applyCommand(t, leader, probeCommand{
		Kind:       "checkpoint",
		EventID:    eventID,
		Checkpoint: &checkpoint,
	})
	if leaderResult.Proof == nil {
		t.Fatal("leader did not return checkpoint proof")
	}

	select {
	case <-target.fsm.started:
	case <-time.After(probeTimeout):
		t.Fatal("staged nonvoter did not reach checkpoint apply")
	}
	if _, ok := target.fsm.proof(eventID); ok {
		t.Fatal("staged nonvoter exposed proof before FSM apply completed")
	}
	if target.fsm.restores.Load() == 0 {
		t.Fatal("staged nonvoter caught up without the required compacted snapshot")
	}

	target.fsm.unblock()
	var targetProof checkpointProof
	eventually(t, "staged checkpoint proof", func() bool {
		var ok bool
		targetProof, ok = target.fsm.proof(eventID)
		return ok
	})
	if !checkpointProofsEqual(*leaderResult.Proof, targetProof) {
		t.Fatalf("target proof mismatch:\nleader: %#v\ntarget: %#v", *leaderResult.Proof, targetProof)
	}
}

func TestCheckpointProofComparisonRejectsEveryMutation(t *testing.T) {
	base := checkpointProof{
		EventID:                     "event",
		CommittedLogIndex:           42,
		StoredProjectionAccumulator: "stored-accumulator",
		AccumulatorMatched:          true,
		checkpointPayload: checkpointPayload{
			SessionID:                "session",
			WorkspaceID:              "workspace",
			RecoveryGeneration:       1,
			AuthorityVoterSetVersion: 2,
			SignerDeviceID:           "device",
			Term:                     3,
			CoveredAppliedLogIndex:   41,
			CoveredChainIndex:        4,
			CoveredChainHash:         "chain",
			CoveredResultIndex:       5,
			CoveredResultHash:        "result",
			ProjectionAccumulator:    "accumulator",
			DigestVersion:            1,
			ProjectionSchemaVersion:  1,
		},
	}

	mutations := map[string]func(*checkpointProof){
		"event":                  func(p *checkpointProof) { p.EventID += "x" },
		"committed index":        func(p *checkpointProof) { p.CommittedLogIndex++ },
		"stored accumulator":     func(p *checkpointProof) { p.StoredProjectionAccumulator += "x" },
		"accumulator comparison": func(p *checkpointProof) { p.AccumulatorMatched = false },
		"session":                func(p *checkpointProof) { p.SessionID += "x" },
		"workspace":              func(p *checkpointProof) { p.WorkspaceID += "x" },
		"generation":             func(p *checkpointProof) { p.RecoveryGeneration++ },
		"authority version":      func(p *checkpointProof) { p.AuthorityVoterSetVersion++ },
		"signer":                 func(p *checkpointProof) { p.SignerDeviceID += "x" },
		"term":                   func(p *checkpointProof) { p.Term++ },
		"covered log":            func(p *checkpointProof) { p.CoveredAppliedLogIndex++ },
		"chain index":            func(p *checkpointProof) { p.CoveredChainIndex++ },
		"chain hash":             func(p *checkpointProof) { p.CoveredChainHash += "x" },
		"result index":           func(p *checkpointProof) { p.CoveredResultIndex++ },
		"result hash":            func(p *checkpointProof) { p.CoveredResultHash += "x" },
		"accumulator":            func(p *checkpointProof) { p.ProjectionAccumulator += "x" },
		"digest version":         func(p *checkpointProof) { p.DigestVersion++ },
		"projection version":     func(p *checkpointProof) { p.ProjectionSchemaVersion++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if checkpointProofsEqual(base, changed) {
				t.Fatal("mutated proof compared equal")
			}
		})
	}
}

func TestCheckpointApplyRejectsEveryCapturedCutMutation(t *testing.T) {
	baseFSM := newProbeFSM("")
	base := baseFSM.checkpointPayload(3, 41)

	apply := func(t *testing.T, checkpoint checkpointPayload) applyResult {
		t.Helper()
		fsm := newProbeFSM("")
		encoded, err := json.Marshal(probeCommand{
			Kind:       "checkpoint",
			EventID:    "event",
			Checkpoint: &checkpoint,
		})
		if err != nil {
			t.Fatal(err)
		}
		result, ok := fsm.Apply(&raft.Log{Index: 42, Term: 3, Data: encoded}).(applyResult)
		if !ok {
			t.Fatal("unexpected checkpoint response type")
		}
		return result
	}

	if result := apply(t, base); result.Err != "" || result.Proof == nil || !result.Proof.AccumulatorMatched {
		t.Fatalf("valid checkpoint result = %#v", result)
	}

	mutations := map[string]func(*checkpointPayload){
		"session":            func(p *checkpointPayload) { p.SessionID += "x" },
		"workspace":          func(p *checkpointPayload) { p.WorkspaceID += "x" },
		"generation":         func(p *checkpointPayload) { p.RecoveryGeneration++ },
		"authority version":  func(p *checkpointPayload) { p.AuthorityVoterSetVersion++ },
		"signer":             func(p *checkpointPayload) { p.SignerDeviceID += "x" },
		"term":               func(p *checkpointPayload) { p.Term++ },
		"covered log":        func(p *checkpointPayload) { p.CoveredAppliedLogIndex++ },
		"chain index":        func(p *checkpointPayload) { p.CoveredChainIndex++ },
		"chain hash":         func(p *checkpointPayload) { p.CoveredChainHash += "x" },
		"result index":       func(p *checkpointPayload) { p.CoveredResultIndex++ },
		"result hash":        func(p *checkpointPayload) { p.CoveredResultHash += "x" },
		"accumulator":        func(p *checkpointPayload) { p.ProjectionAccumulator += "x" },
		"digest version":     func(p *checkpointPayload) { p.DigestVersion++ },
		"projection version": func(p *checkpointPayload) { p.ProjectionSchemaVersion++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if result := apply(t, changed); result.Err == "" {
				t.Fatalf("mutated checkpoint accepted: %#v", result)
			}
		})
	}
}
