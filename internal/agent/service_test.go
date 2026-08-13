package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/store"
	"net/http"
	"net/http/httptest"
)

const (
	agentTestSessionID   = domain.UUIDv7("018f47de-89ab-7def-8123-0123456789ab")
	agentTestWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	agentTestBootID      = domain.UUIDv7("018f47de-89ab-7def-8123-1123456789ab")
	agentTestSessionA    = domain.UUIDv7("018f47de-89ab-7def-8123-2123456789ab")
	agentTestRootA       = domain.UUIDv7("018f47de-89ab-7def-8123-3123456789ab")
	agentTestTaskID      = domain.UUIDv7("018f47de-89ab-7def-8123-4123456789ab")
	agentTestTimestamp   = domain.Timestamp("2026-08-12T12:00:00Z")
)

type fsmConsensus struct {
	mu     sync.Mutex
	fsm    *consensus.FSM
	store  *store.Store
	clock  consensus.ApplyClock
	index  uint64
	err    error
	leader atomic.Bool
}

type cancellationBlockingConsensus struct {
	delegate Consensus
	entered  chan struct{}
	once     sync.Once
}

func (runtime *cancellationBlockingConsensus) Apply(
	ctx context.Context,
	_ event.SignedEvent,
) (store.ApplyResult, error) {
	runtime.once.Do(func() {
		close(runtime.entered)
	})
	<-ctx.Done()
	return store.ApplyResult{}, ctx.Err()
}

func (runtime *cancellationBlockingConsensus) IsLeader() bool {
	return runtime.delegate.IsLeader()
}

func (runtime *cancellationBlockingConsensus) LocalTime() (
	domain.Timestamp,
	int64,
	error,
) {
	return runtime.delegate.LocalTime()
}

func (runtime *fsmConsensus) Apply(
	ctx context.Context,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	runtime.index++
	response, ok := runtime.fsm.Apply(&raft.Log{
		Index: runtime.index,
		Term:  1,
		Type:  raft.LogCommand,
		Data:  signed.CanonicalBytes(),
	}).(consensus.ApplyResponse)
	if !ok {
		return store.ApplyResult{}, errors.New("unexpected FSM response")
	}
	if response.Err != nil {
		runtime.err = response.Err
		return store.ApplyResult{}, response.Err
	}
	return response.Result, nil
}

func (runtime *fsmConsensus) View(ctx context.Context) (store.StateView, error) {
	return runtime.store.View(ctx)
}

func (runtime *fsmConsensus) IsLeader() bool {
	return runtime.leader.Load()
}

func (runtime *fsmConsensus) LocalTime() (domain.Timestamp, int64, error) {
	if runtime.clock == nil {
		return "", 0, errors.New("missing local clock")
	}
	return runtime.clock()
}

func (runtime *fsmConsensus) applyError() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.err
}

type testIDGenerator struct {
	mu     sync.Mutex
	values []domain.UUIDv7
}

func (generator *testIDGenerator) next() (domain.UUIDv7, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	id := domain.UUIDv7(value.String())
	generator.mu.Lock()
	generator.values = append(generator.values, id)
	generator.mu.Unlock()
	return id, nil
}

type recordingRandom struct {
	mu          sync.Mutex
	next        byte
	values      [][]byte
	allocations [][]byte
}

func (source *recordingRandom) Read(buffer []byte) (int, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	for index := range buffer {
		buffer[index] = source.next
	}
	source.values = append(source.values, bytes.Clone(buffer))
	source.allocations = append(source.allocations, buffer)
	return len(buffer), nil
}

func (source *recordingRandom) last() []byte {
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.values) == 0 {
		return nil
	}
	return bytes.Clone(source.values[len(source.values)-1])
}

func (source *recordingRandom) lastAllocationCleared() bool {
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.allocations) == 0 {
		return false
	}
	for _, value := range source.allocations[len(source.allocations)-1] {
		if value != 0 {
			return false
		}
	}
	return true
}

type agentTestHarness struct {
	state     *store.Store
	local     store.LocalState
	service   *Service
	consensus *fsmConsensus
	deviceID  domain.DeviceID
	private   ed25519.PrivateKey
	random    *recordingRandom
}

func newAgentTestHarness(
	t *testing.T,
	sessions []agentsession.Session,
) *agentTestHarness {
	return newAgentTestHarnessWithTasks(t, sessions, nil)
}

func newAgentTestHarnessWithTasks(
	t *testing.T,
	sessions []agentsession.Session,
	tasks []task.Task,
) *agentTestHarness {
	return newAgentTestHarnessWithState(t, sessions, tasks, nil, nil)
}

func newAgentTestHarnessWithState(
	t *testing.T,
	sessions []agentsession.Session,
	tasks []task.Task,
	leases []lease.Lease,
	applyClock consensus.ApplyClock,
) *agentTestHarness {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x31}, ed25519.SeedSize),
	)
	publicKey := append(
		ed25519.PublicKey(nil),
		privateKey.Public().(ed25519.PublicKey)...,
	)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("derive device ID: %v", err)
	}
	sessions = append([]agentsession.Session(nil), sessions...)
	for index := range sessions {
		if sessions[index].DeviceID == "" {
			sessions[index].DeviceID = deviceID
		}
	}
	originScopes := make([]store.OriginScopeRow, len(sessions))
	for index, session := range sessions {
		originScopes[index] = store.OriginScopeRow{
			DeviceID:     session.DeviceID,
			ScopeKind:    store.OriginScopeKindAgent,
			ScopeID:      session.ID,
			LastSequence: 1,
		}
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: publicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	voterTarget, err := voterset.New(
		agentTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("build voter target: %v", err)
	}
	rawGenesis, err := json.Marshal(map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(publicKey),
		"session_id":          agentTestSessionID,
		"workspace_id":        agentTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("marshal genesis: %v", err)
	}
	genesis, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		t.Fatalf("canonicalize genesis: %v", err)
	}
	state, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = state.Close()
	})
	_, err = state.Initialize(context.Background(), store.InitialState{
		SessionID:               agentTestSessionID,
		WorkspaceID:             agentTestWorkspaceID,
		GenesisJSON:             genesis,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			OriginScopes:  originScopes,
			AuditCounters: []auditcounter.Counter{{DeviceID: deviceID}},
			PlanCurrent: []plan.Current{{
				SessionID:     agentTestSessionID,
				EntityVersion: 1,
			}},
			Devices:  []device.Device{member},
			VoterSet: []voterset.Set{voterTarget},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        agentTestSessionID,
				VoterDeviceIDs:   []domain.DeviceID{deviceID},
				VoterSetVersion:  1,
				ActivationSource: credentialauthority.ActivationGenesis,
			}},
			AgentSessions: sessions,
			Tasks:         tasks,
			Leases:        leases,
			CanonicalRefs: []publication.CanonicalRef{{
				RefName:       publication.CanonicalRefName,
				CommitOID:     domain.GitOID("sha1:" + strings.Repeat("1", 40)),
				EntityVersion: 1,
			}},
			SessionPolicy: []policy.Policy{{
				SessionID:     agentTestSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	})
	if err != nil {
		t.Fatalf("initialize store: %v", err)
	}

	if applyClock == nil {
		applyClock = func() (domain.Timestamp, int64, error) {
			return domain.Timestamp("2026-08-12T13:00:00Z"),
				int64(time.Second),
				nil
		}
	}
	fsm, err := consensus.NewFSM(consensus.FSMOptions{
		Store:        state,
		OriginBootID: agentTestBootID,
		Clock:        applyClock,
	})
	if err != nil {
		t.Fatalf("new FSM: %v", err)
	}
	runtime := &fsmConsensus{fsm: fsm, store: state, clock: applyClock}
	runtime.leader.Store(true)
	authority, err := event.NewLocalAuthority(deviceID, agentTestBootID)
	if err != nil {
		t.Fatalf("new local authority: %v", err)
	}
	lifecycleOrigin, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("daemon binding: %v", err)
	}
	ids := &testIDGenerator{}
	randomSource := &recordingRandom{}
	service, err := New(Options{
		Consensus:          runtime,
		LocalState:         state.LocalState(),
		SessionID:          agentTestSessionID,
		WorkspaceID:        agentTestWorkspaceID,
		DeviceID:           deviceID,
		OriginBootID:       agentTestBootID,
		IdentityPrivateKey: privateKey,
		LifecycleOrigin:    lifecycleOrigin,
		Clock: func() domain.Timestamp {
			return agentTestTimestamp
		},
		GenerateID: ids.next,
		Random:     randomSource,
	})
	if err != nil {
		t.Fatalf("new agent service: %v", err)
	}
	t.Cleanup(func() {
		_ = service.Close()
	})
	return &agentTestHarness{
		state:     state,
		local:     state.LocalState(),
		service:   service,
		consensus: runtime,
		deviceID:  deviceID,
		private:   privateKey,
		random:    randomSource,
	}
}

func TestTwoLocalAgentsRaceForOneTaskAndObserveOneWinner(t *testing.T) {
	ready := task.Task{
		ID:            agentTestTaskID,
		Title:         "claim exactly once",
		Body:          "walking skeleton",
		State:         task.StateReady,
		Priority:      task.PriorityHigh,
		BlockedBy:     []domain.UUIDv7{},
		Labels:        []string{"phase-2"},
		EntityVersion: 1,
		CreatedAt:     agentTestTimestamp,
		UpdatedAt:     agentTestTimestamp,
	}
	harness := newAgentTestHarnessWithTasks(t, nil, []task.Task{ready})
	if err := harness.service.Recover(testAgentContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}

	first := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-5123456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-6123456789ab"),
		agentsession.ClientKindCodex,
	)
	second := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-5223456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-6223456789ab"),
		agentsession.ClientKindClaude,
	)
	if first.session.ID == second.session.ID {
		t.Fatal("distinct launches reused an agent session ID")
	}

	type claimResult struct {
		sessionID domain.UUIDv7
		status    store.OutcomeStatus
		code      string
		httpCode  int
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	claim := func(
		client *boundClient,
		body []byte,
	) {
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		request := httptest.NewRequest(
			http.MethodPost,
			commandPath,
			bytes.NewReader(body),
		).WithContext(ctx)
		recorder := httptest.NewRecorder()
		client.Handler().ServeHTTP(recorder, request)
		var response struct {
			Code   string              `json:"code"`
			Status store.OutcomeStatus `json:"status"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			results <- claimResult{
				sessionID: client.agentSessionID,
				httpCode:  recorder.Code,
				code:      "invalid_response",
			}
			return
		}
		results <- claimResult{
			sessionID: client.agentSessionID,
			status:    response.Status,
			code:      response.Code,
			httpCode:  recorder.Code,
		}
	}
	firstRequest := localTaskClaimRequest(
		t,
		domain.UUIDv7("018f47de-89ab-7def-8123-7123456789ab"),
		ready.ID,
		ready.EntityVersion,
	)
	secondRequest := localTaskClaimRequest(
		t,
		domain.UUIDv7("018f47de-89ab-7def-8123-7223456789ab"),
		ready.ID,
		ready.EntityVersion,
	)
	go claim(
		first.client,
		firstRequest,
	)
	go claim(
		second.client,
		secondRequest,
	)
	close(start)

	got := []claimResult{<-results, <-results}
	var winner domain.UUIDv7
	accepted := 0
	rejected := 0
	for _, result := range got {
		if result.httpCode != http.StatusOK {
			t.Fatalf("claim response = %#v", result)
		}
		switch result.status {
		case store.OutcomeAccepted:
			accepted++
			winner = result.sessionID
		case store.OutcomeRejected:
			rejected++
		default:
			t.Fatalf("claim response = %#v", result)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("claim outcomes = %#v", got)
	}

	claimed, found, err := harness.local.Task(
		testAgentContext(t),
		ready.ID,
	)
	if err != nil || !found {
		t.Fatalf("Task() = (%#v, %t, %v)", claimed, found, err)
	}
	if claimed.State != task.StateClaimed ||
		claimed.OwnerDeviceID != harness.deviceID ||
		claimed.OwnerAgentSessionID != winner ||
		claimed.EntityVersion != 2 {
		t.Fatalf("claimed task = %#v, winner = %q", claimed, winner)
	}
	assertAgentObservesTask(t, first.client, claimed)
	assertAgentObservesTask(t, second.client, claimed)
}

func TestLaunchBindCancellationInterruptsWaitWithoutStoppingService(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	managedRootID := domain.UUIDv7("018f47de-89ab-7def-8123-8123456789ab")
	verifiedAt := agentTestTimestamp
	if err := harness.local.RegisterManagedRoot(
		testAgentContext(t),
		store.ManagedRootRecord{
			ManagedRootID:      managedRootID,
			SessionID:          agentTestSessionID,
			WorkspaceID:        agentTestWorkspaceID,
			RecoveryGeneration: 0,
			CanonicalPath:      filepath.Join(t.TempDir(), "root"),
			FilesystemIdentity: "filesystem:bind-cancellation",
			RepositoryIdentity: "repository:bind-cancellation",
			Kind:               store.ManagedRootIsolated,
			GuardStatus:        store.RootGuardHealthy,
			Active:             true,
			LastVerifiedAt:     &verifiedAt,
		},
	); err != nil {
		t.Fatalf("RegisterManagedRoot(): %v", err)
	}
	ticket, err := harness.service.RegisterLaunch(
		testAgentContext(t),
		LaunchOptions{
			ClientKind:      agentsession.ClientKindCodex,
			ConcurrencyMode: store.ConcurrencyIsolated,
			ManagedRootID:   managedRootID,
		},
	)
	if err != nil {
		t.Fatalf("RegisterLaunch(): %v", err)
	}
	proof, err := canonicalObject(map[string]any{
		"launch_selector": ticket.Selector,
	})
	if err != nil {
		t.Fatalf("canonical launch proof: %v", err)
	}
	blocker := &cancellationBlockingConsensus{
		delegate: harness.service.consensus,
		entered:  make(chan struct{}),
	}
	harness.service.consensus = blocker
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, bindErr := harness.service.Bind(
			ctx,
			ipc.VerifiedPeer{},
			ipc.BindRequest{
				ProtocolVersion:  ipc.LocalProtocolVersion,
				ClientInstanceID: domain.UUIDv7("018f47de-89ab-7def-8123-8223456789ab"),
				SessionID:        agentTestSessionID,
				WorkspaceID:      agentTestWorkspaceID,
				Class:            ipc.ClassAgent,
				AgentProof:       proof,
			},
		)
		result <- bindErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("forwarding did not reach consensus")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bind() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Bind() ignored request cancellation")
	}
	if err := harness.service.available(); err != nil {
		t.Fatalf("request cancellation stopped service: %v", err)
	}
}

func TestResumeBindCancellationInterruptsWaitWithoutStoppingService(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	launched := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-8723456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-8823456789ab"),
		agentsession.ClientKindClaude,
	)
	capability := harness.random.last()
	t.Cleanup(func() {
		clear(capability)
	})
	launched.client.Disconnected(context.Background())
	waitForAgentState(
		t,
		harness,
		launched.session.ID,
		agentsession.StateDisconnected,
	)
	waitForNoOriginWorkers(t, harness.service)

	blocker := &cancellationBlockingConsensus{
		delegate: harness.service.consensus,
		entered:  make(chan struct{}),
	}
	harness.service.consensus = blocker
	proof, err := canonicalObject(map[string]any{
		"resume_capability": codec.EncodeBase64URL(capability),
	})
	if err != nil {
		t.Fatalf("canonical resume proof: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, bindErr := harness.service.Bind(
			ctx,
			ipc.VerifiedPeer{},
			ipc.BindRequest{
				ProtocolVersion:  ipc.LocalProtocolVersion,
				ClientInstanceID: domain.UUIDv7("018f47de-89ab-7def-8123-8923456789ab"),
				SessionID:        agentTestSessionID,
				WorkspaceID:      agentTestWorkspaceID,
				Class:            ipc.ClassAgent,
				AgentProof:       proof,
			},
		)
		result <- bindErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("resume forwarding did not reach consensus")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bind() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resume Bind() ignored request cancellation")
	}
	if err := harness.service.available(); err != nil {
		t.Fatalf("request cancellation stopped service: %v", err)
	}
}

func TestOriginWorkersRetireWithoutDroppingQueuedCommands(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	launched := launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-8323456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-8423456789ab"),
		agentsession.ClientKindCodex,
	)

	state := agentsession.StateStarting
	version := uint64(1)
	for iteration := 0; iteration < 40; iteration++ {
		var next agentsession.State
		switch state {
		case agentsession.StateStarting, agentsession.StateWorking:
			next = agentsession.StateIdle
		default:
			next = agentsession.StateWorking
		}
		expectedVersion := version
		payload, err := canonicalObject(map[string]any{"to_state": next})
		if err != nil {
			t.Fatalf("canonical state payload: %v", err)
		}
		requestID, err := harness.service.generateID()
		if err != nil {
			t.Fatalf("generate request ID: %v", err)
		}
		canonicalRequest, err := canonicalObject(map[string]any{
			"operation":  event.KindAgentSessionStateChanged,
			"request_id": requestID,
		})
		if err != nil {
			t.Fatalf("canonical local request: %v", err)
		}
		result, duplicate, err := launched.client.submitCommand(
			testAgentContext(t),
			localCommandRequest{
				Operation: string(event.KindAgentSessionStateChanged),
				RequestID: requestID,
				Command: event.Command{
					Kind:                  event.KindAgentSessionStateChanged,
					EntityID:              event.StringEntityID(string(launched.session.ID)),
					ExpectedEntityVersion: &expectedVersion,
					RationaleSummary:      "",
					Actions:               []event.Action{},
					Payload:               payload,
					Redaction:             defaultRedaction(),
				},
				Canonical: canonicalRequest,
			},
		)
		if err != nil || duplicate || result.Outcome == nil ||
			result.Outcome.Status != store.OutcomeAccepted {
			t.Fatalf(
				"state command %d = (%#v, %t, %v)",
				iteration,
				result,
				duplicate,
				err,
			)
		}
		state = next
		version++
	}

	for iteration := 0; iteration < 128; iteration++ {
		scopeID, err := harness.service.generateID()
		if err != nil {
			t.Fatalf("generate ephemeral scope ID: %v", err)
		}
		harness.service.wakeScope(store.OutboxScope{
			OriginDeviceID:  harness.deviceID,
			OriginScopeKind: store.OriginScopeKindAgent,
			OriginScopeID:   scopeID,
		})
	}
	waitForNoOriginWorkers(t, harness.service)
	harness.service.done.Wait()

	session, found, err := harness.local.AgentSession(
		testAgentContext(t),
		launched.session.ID,
	)
	if err != nil || !found || session.State != state ||
		session.EntityVersion != version {
		t.Fatalf("final agent session = (%#v, %t, %v)", session, found, err)
	}
}

func TestLaunchBindClearsMintedCapabilityAllocation(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	_ = launchAgent(
		t,
		harness,
		domain.UUIDv7("018f47de-89ab-7def-8123-8523456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-8623456789ab"),
		agentsession.ClientKindClaude,
	)
	if !harness.random.lastAllocationCleared() {
		t.Fatal("Bind retained the minted resume capability allocation")
	}
}

type launchedAgent struct {
	session agentsession.Session
	client  *boundClient
}

func launchAgent(
	t *testing.T,
	harness *agentTestHarness,
	managedRootID domain.UUIDv7,
	clientInstanceID domain.UUIDv7,
	clientKind agentsession.ClientKind,
) launchedAgent {
	t.Helper()
	before, err := harness.local.NonterminalAgentSessions(testAgentContext(t))
	if err != nil {
		t.Fatalf("NonterminalAgentSessions(before): %v", err)
	}
	known := make(map[domain.UUIDv7]struct{}, len(before))
	for _, session := range before {
		known[session.ID] = struct{}{}
	}
	verifiedAt := agentTestTimestamp
	if err := harness.local.RegisterManagedRoot(
		testAgentContext(t),
		store.ManagedRootRecord{
			ManagedRootID:      managedRootID,
			SessionID:          agentTestSessionID,
			WorkspaceID:        agentTestWorkspaceID,
			RecoveryGeneration: 0,
			CanonicalPath:      filepath.Join(t.TempDir(), "root"),
			FilesystemIdentity: "filesystem:" + string(managedRootID),
			RepositoryIdentity: "repository:" + string(managedRootID),
			Kind:               store.ManagedRootIsolated,
			GuardStatus:        store.RootGuardHealthy,
			Active:             true,
			LastVerifiedAt:     &verifiedAt,
		},
	); err != nil {
		t.Fatalf("RegisterManagedRoot(): %v", err)
	}
	ticket, err := harness.service.RegisterLaunch(
		testAgentContext(t),
		LaunchOptions{
			ClientKind:      clientKind,
			ConcurrencyMode: store.ConcurrencyIsolated,
			ManagedRootID:   managedRootID,
		},
	)
	if err != nil {
		t.Fatalf("RegisterLaunch(): %v", err)
	}
	proof, err := canonicalObject(map[string]any{
		"launch_selector": ticket.Selector,
	})
	if err != nil {
		t.Fatalf("canonical launch proof: %v", err)
	}
	if _, err := harness.service.Bind(
		testAgentContext(t),
		ipc.VerifiedPeer{},
		ipc.BindRequest{
			ProtocolVersion:  ipc.LocalProtocolVersion,
			ClientInstanceID: clientInstanceID,
			SessionID:        agentTestSessionID,
			WorkspaceID:      agentTestWorkspaceID,
			Class:            ipc.ClassAgent,
			AgentProof:       proof,
		},
	); err != nil {
		t.Fatalf("Bind(launch): %v", err)
	}
	after, err := harness.local.NonterminalAgentSessions(testAgentContext(t))
	if err != nil {
		t.Fatalf("NonterminalAgentSessions(after): %v", err)
	}
	var created agentsession.Session
	for _, session := range after {
		if _, exists := known[session.ID]; !exists {
			if created.ID != "" {
				t.Fatal("one launch created multiple agent sessions")
			}
			created = session
		}
	}
	if created.ID == "" ||
		created.DeviceID != harness.deviceID ||
		created.ClientKind != clientKind ||
		created.State != agentsession.StateStarting {
		t.Fatalf("created agent session = %#v", created)
	}
	binding, err := event.NewMCPBinding(
		harness.deviceID,
		created.ID,
		created.AgentProfileID,
	)
	if err != nil {
		t.Fatalf("NewMCPBinding(): %v", err)
	}
	capability := harness.random.last()
	if len(capability) != 32 {
		t.Fatalf("resume capability length = %d", len(capability))
	}
	client := newLaunchBoundClient(
		harness.service,
		clientInstanceID,
		created.ID,
		created.WorkingRootID,
		binding,
		ticket.LaunchID,
		resumeDigest(capability),
	)
	blocked := httptest.NewRecorder()
	client.Handler().ServeHTTP(
		blocked,
		httptest.NewRequest(http.MethodGet, taskListQueryPath, nil),
	)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("pre-ack task query status = %d", blocked.Code)
	}
	ackBody, err := canonicalObject(map[string]any{
		"resume_capability": codec.EncodeBase64URL(capability),
	})
	if err != nil {
		t.Fatalf("canonical launch acknowledgement: %v", err)
	}
	acknowledged := httptest.NewRecorder()
	client.Handler().ServeHTTP(
		acknowledged,
		httptest.NewRequest(
			http.MethodPost,
			launchAcknowledgementPath,
			bytes.NewReader(ackBody),
		),
	)
	clear(capability)
	if acknowledged.Code != http.StatusNoContent {
		t.Fatalf(
			"launch acknowledgement status = %d, body = %s",
			acknowledged.Code,
			acknowledged.Body.Bytes(),
		)
	}
	return launchedAgent{
		session: created,
		client:  client,
	}
}

func localTaskClaimRequest(
	t *testing.T,
	requestID, taskID domain.UUIDv7,
	expectedVersion uint64,
) []byte {
	t.Helper()
	body, err := canonicalObject(map[string]any{
		"operation":  "task.claim",
		"request_id": requestID,
		"command": map[string]any{
			"kind":                    event.KindTaskClaimed,
			"entity_id":               taskID,
			"expected_entity_version": expectedVersion,
			"rationale_summary":       "",
			"actions":                 []any{},
			"payload":                 map[string]any{},
			"redaction": map[string]any{
				"policy":         event.RedactionDefault,
				"fields_removed": []any{},
			},
		},
	})
	if err != nil {
		t.Fatalf("canonical claim request: %v", err)
	}
	return body
}

func assertAgentObservesTask(
	t *testing.T,
	client *boundClient,
	want task.Task,
) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, taskListQueryPath, nil)
	recorder := httptest.NewRecorder()
	client.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET tasks status = %d, body = %s", recorder.Code, recorder.Body.Bytes())
	}
	var response struct {
		Tasks []taskJSON `json:"tasks"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode task list: %v", err)
	}
	if len(response.Tasks) != 1 ||
		response.Tasks[0].TaskID != string(want.ID) ||
		response.Tasks[0].OwnerAgentSessionID == nil ||
		*response.Tasks[0].OwnerAgentSessionID != string(want.OwnerAgentSessionID) ||
		response.Tasks[0].EntityVersion != want.EntityVersion {
		t.Fatalf("task list = %#v", response.Tasks)
	}
}

func TestRecoverDisconnectsAndReapsLiveAgent(t *testing.T) {
	harness := newAgentTestHarness(t, []agentsession.Session{{
		ID:            agentTestSessionA,
		DeviceID:      "",
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateWorking,
		WorkingRootID: agentTestRootA,
		EntityVersion: 1,
	}})
	assertAgentSessionDevice(t, harness, agentTestSessionA)
	harness.service.disconnectGrace = 15 * time.Millisecond

	if err := harness.service.Recover(testAgentContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	session := waitForAgentState(
		t,
		harness,
		agentTestSessionA,
		agentsession.StateEnded,
	)
	if session.EndReason != agentsession.EndReasonDisconnectTimeout ||
		session.EntityVersion != 3 {
		t.Fatalf("reaped session = %#v", session)
	}
}

func TestResumeWinsDisconnectReapCAS(t *testing.T) {
	harness := newAgentTestHarness(t, []agentsession.Session{{
		ID:            agentTestSessionA,
		DeviceID:      "",
		ClientKind:    agentsession.ClientKindClaude,
		State:         agentsession.StateDisconnected,
		ResumeState:   agentsession.StateWorking,
		WorkingRootID: agentTestRootA,
		EntityVersion: 2,
	}})
	assertAgentSessionDevice(t, harness, agentTestSessionA)
	harness.service.disconnectGrace = 80 * time.Millisecond
	harness.service.onDisconnected(agentTestSessionA)

	current, found, err := harness.local.AgentSession(
		testAgentContext(t),
		agentTestSessionA,
	)
	if err != nil || !found {
		t.Fatalf("AgentSession() = (%#v, %t, %v)", current, found, err)
	}
	if err := harness.service.resumeSession(
		testAgentContext(t),
		current,
		agentsession.StateWorking,
	); err != nil {
		t.Fatalf(
			"resumeSession(): %v (FSM error: %v)",
			err,
			harness.consensus.applyError(),
		)
	}
	time.Sleep(2 * harness.service.disconnectGrace)

	resumed, found, err := harness.local.AgentSession(
		testAgentContext(t),
		agentTestSessionA,
	)
	if err != nil || !found {
		t.Fatalf("AgentSession(resumed) = (%#v, %t, %v)", resumed, found, err)
	}
	if resumed.State != agentsession.StateWorking ||
		resumed.EndReason != agentsession.EndReasonAbsent ||
		resumed.EntityVersion != 3 {
		t.Fatalf("session after reap race = %#v", resumed)
	}
}

func assertAgentSessionDevice(
	t *testing.T,
	harness *agentTestHarness,
	id domain.UUIDv7,
) {
	t.Helper()
	session, found, err := harness.local.AgentSession(context.Background(), id)
	if err == nil && found && session.DeviceID == harness.deviceID {
		return
	}
	t.Fatalf(
		"test fixture must be initialized with device %q before store validation; got (%#v, %t, %v)",
		harness.deviceID,
		session,
		found,
		err,
	)
}

func waitForAgentState(
	t *testing.T,
	harness *agentTestHarness,
	id domain.UUIDv7,
	want agentsession.State,
) agentsession.Session {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		session, found, err := harness.local.AgentSession(context.Background(), id)
		if err != nil {
			t.Fatalf("AgentSession(): %v", err)
		}
		if found && session.State == want {
			return session
		}
		time.Sleep(5 * time.Millisecond)
	}
	session, _, _ := harness.local.AgentSession(context.Background(), id)
	t.Fatalf(
		"session did not reach %q: %#v (FSM error: %v)",
		want,
		session,
		harness.consensus.applyError(),
	)
	return agentsession.Session{}
}

func waitForNoOriginWorkers(t *testing.T, service *Service) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		service.mu.Lock()
		count := len(service.workers)
		service.mu.Unlock()
		if count == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	service.mu.Lock()
	count := len(service.workers)
	service.mu.Unlock()
	t.Fatalf("%d origin workers did not retire", count)
}

func testAgentContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
