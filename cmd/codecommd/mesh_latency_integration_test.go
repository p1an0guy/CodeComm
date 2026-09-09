package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/ipc"
	codecommmcp "github.com/ijonahch/codecomm/internal/mcp"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/testharness/latency"
	"github.com/ijonahch/codecomm/internal/ui"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	phase3MultiAgentEnvironment     = "CODECOMM_PHASE3_MULTI_AGENT"
	sameDeviceLatencyAgentCount     = 32
	sameDeviceLatencySampleCount    = 20
	sameDeviceLatencyTarget         = 100 * time.Millisecond
	sameDeviceLatencyObservationMax = 2 * time.Second
	sameDeviceLatencyConvergenceMax = 3 * time.Minute
)

type sameDeviceLatencyReport struct {
	latency.Report
	OS                string `json:"os"`
	Architecture      string `json:"architecture"`
	DeviceCount       int    `json:"device_count"`
	VoterCount        int    `json:"voter_count"`
	SettledCount      int    `json:"settled_nonvoter_count"`
	AgentCount        int    `json:"agent_count"`
	CodexAgentCount   int    `json:"codex_agent_count"`
	ClaudeAgentCount  int    `json:"claude_agent_count"`
	PostWarmupSamples int    `json:"post_warmup_samples"`
}

type sameDeviceLatencyAgent struct {
	adapter       *codecommmcp.Client
	serverSession *mcpsdk.ServerSession
	session       *mcpsdk.ClientSession
	agentSession  domain.UUIDv7
	workingRoot   domain.UUIDv7
	clientKind    agentsession.ClientKind
}

func TestDaemonSameDeviceVisibilityLatency(t *testing.T) {
	if os.Getenv(phase3MultiAgentEnvironment) != "1" {
		t.Skip(
			"set CODECOMM_PHASE3_MULTI_AGENT=1 to run the same-device latency gate",
		)
	}
	if os.Getenv(daemonMeshIntegrationChildMarker) != "1" {
		runDaemonMeshIntegrationChild(
			t,
			"^TestDaemonSameDeviceVisibilityLatency$",
		)
		return
	}
	registerDaemonIntegrationChildResult(t)
	runDaemonSameDeviceVisibilityLatency(t)
}

func runDaemonSameDeviceVisibilityLatency(t *testing.T) {
	t.Helper()
	selectedAddress, listeners := reserveDaemonMeshIntegrationListeners(t, 8)
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
	settled := append(
		[]*daemonMeshIntegrationNode(nil),
		allNodes[3:]...,
	)
	t.Cleanup(func() {
		cleanupDaemonMeshIntegrationNodes(t, allNodes...)
		for _, node := range allNodes {
			clear(node.privateKey)
		}
	})

	settledMembers := make([]device.Device, len(settled))
	for index, node := range settled {
		settledMembers[index] = device.Device{
			ID:   node.deviceID,
			Role: device.RoleOwner,
			IdentityPublicKey: bytes.Clone(
				node.privateKey.Public().(ed25519.PublicKey),
			),
			DaemonVersion: "0.1.0",
			MaxApplyLevel: 1,
			Status:        device.StatusActive,
			EntityVersion: 1,
		}
	}
	initial := daemonMeshIntegrationInitialState(
		t,
		voters,
		settledMembers...,
	)
	voterIDs := daemonMeshIntegrationDeviceIDs(voters)
	bootstrap := daemonMeshIntegrationBootstrap(voters)
	for _, voter := range voters {
		initializeDaemonMeshIntegrationStore(t, voter.statePath, initial)
		seedDaemonMeshIntegrationRaft(
			t,
			voter.consensusDir,
			voter.deviceID,
			bootstrap,
		)
		voter.start(t, allNodes)
	}
	for _, replica := range settled {
		initializeDaemonMeshIntegrationStore(t, replica.statePath, initial)
		enterDaemonSettledReplicationMode(t, replica.statePath, voterIDs)
	}

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

	for index, replica := range settled {
		certificate := authorizeDaemonSettledCredentialWithSeed(
			t,
			voters,
			leader,
			replica,
			credentialClock.Now(),
			credentialauthorization.RoleOwner,
			byte(0xf1+index),
		)
		bootstrapDaemonSettledReplica(
			t,
			selectedAddress,
			leader,
			replica,
			certificate,
		)
		clearDaemonTLSCertificate(&certificate)
	}
	for _, replica := range settled {
		replica.start(t, allNodes)
	}
	waitForDaemonMeshIntegrationClusterWithin(
		t,
		allNodes,
		sameDeviceLatencyConvergenceMax,
		func(statuses []ui.Snapshot) bool {
			return sameDeviceLatencyTopologyReady(
				statuses,
				len(voters),
				len(allNodes),
				voterIDs,
			)
		},
	)

	service := waitForDaemonLatencyAgentService(t, leader)
	consensusNode, ready := leader.meshCapture.consensusNode()
	if !ready {
		t.Fatal("latency source consensus node was not captured")
	}
	local, err := consensusNode.LocalState()
	if err != nil {
		t.Fatalf("latency source LocalState(): %v", err)
	}
	agents := make([]*sameDeviceLatencyAgent, 0, sameDeviceLatencyAgentCount)
	for index := 0; index < sameDeviceLatencyAgentCount; index++ {
		agents = append(
			agents,
			launchSameDeviceLatencyAgent(
				t,
				service,
				local,
				leader.localEndpoint,
				filepath.Join(root, "agents"),
				leader.deviceID,
				index,
			),
		)
	}
	waitForDaemonMeshIntegrationClusterWithin(
		t,
		allNodes,
		sameDeviceLatencyConvergenceMax,
		func(statuses []ui.Snapshot) bool {
			if !sameDeviceLatencyTopologyReady(
				statuses,
				len(voters),
				len(allNodes),
				voterIDs,
			) {
				return false
			}
			return sameDeviceLatencyAgentsReady(
				statuses,
				leader.deviceID,
				agents,
			)
		},
	)
	for _, client := range agents {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			daemonMeshIntegrationTimeout,
		)
		_, err := callSameDeviceLatencyTool[codecommmcp.ContextGetOutput](
			ctx,
			client.session,
			codecommmcp.ToolContextGet,
			map[string]any{},
		)
		cancel()
		if err != nil {
			t.Fatalf("warm agent context: %v", err)
		}
	}

	warmTitle := "same-device visibility warmup"
	runSameDeviceVisibilitySample(
		t,
		agents[0],
		agents[1],
		warmTitle,
	)
	waitForDaemonMeshIntegrationStableHeads(
		t,
		allNodes,
		250*time.Millisecond,
	)
	requireSameDeviceLatencyCommitments(
		t,
		allNodes,
		leader.deviceID,
	)

	samples := make([]time.Duration, 0, sameDeviceLatencySampleCount)
	exercisedAgents := make(map[domain.UUIDv7]struct{}, len(agents))
	for index := 0; index < sameDeviceLatencySampleCount; index++ {
		source := agents[index%len(agents)]
		observer := agents[(index+13)%len(agents)]
		exercisedAgents[source.agentSession] = struct{}{}
		exercisedAgents[observer.agentSession] = struct{}{}
		samples = append(
			samples,
			runSameDeviceVisibilitySample(
				t,
				source,
				observer,
				fmt.Sprintf(
					"same-device visibility sample %02d",
					index+1,
				),
			),
		)
	}
	if len(exercisedAgents) != len(agents) {
		t.Fatalf(
			"timed samples exercised %d of %d agents",
			len(exercisedAgents),
			len(agents),
		)
	}
	summary, err := latency.Summarize(samples)
	if err != nil {
		t.Fatalf("summarize same-device visibility: %v", err)
	}
	report := sameDeviceLatencyReport{
		Report:            summary,
		OS:                runtime.GOOS,
		Architecture:      runtime.GOARCH,
		DeviceCount:       len(allNodes),
		VoterCount:        len(voters),
		SettledCount:      len(settled),
		AgentCount:        len(agents),
		CodexAgentCount:   sameDeviceLatencyAgentCount / 2,
		ClaudeAgentCount:  sameDeviceLatencyAgentCount / 2,
		PostWarmupSamples: len(samples),
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode same-device latency report: %v", err)
	}
	t.Logf("CODECOMM_PHASE3_SAME_DEVICE_VISIBILITY=%s", encoded)
	if summary.P95() >= sameDeviceLatencyTarget {
		t.Fatalf(
			"same-device visibility p95 = %s, target <%s",
			summary.P95(),
			sameDeviceLatencyTarget,
		)
	}

	waitForDaemonMeshIntegrationClusterWithin(
		t,
		allNodes,
		sameDeviceLatencyConvergenceMax,
		func(statuses []ui.Snapshot) bool {
			if !sameDeviceLatencyTopologyReady(
				statuses,
				len(voters),
				len(allNodes),
				voterIDs,
			) || !sameDeviceLatencyAgentsReady(
				statuses,
				leader.deviceID,
				agents,
			) {
				return false
			}
			expectedTasks := uint64(sameDeviceLatencySampleCount + 1)
			for _, status := range statuses {
				if status.TaskTotal != expectedTasks ||
					status.Truncated ||
					uint64(len(status.Tasks)) != expectedTasks {
					return false
				}
			}
			return true
		},
	)
	requireSameDeviceLatencyCommitments(
		t,
		allNodes,
		leader.deviceID,
	)
}

func sameDeviceLatencyTopologyReady(
	statuses []ui.Snapshot,
	voterCount, deviceCount int,
	voterIDs []domain.DeviceID,
) bool {
	if len(statuses) != deviceCount ||
		voterCount < 1 ||
		voterCount >= deviceCount ||
		!daemonMeshIntegrationMutationConverged(statuses) ||
		!daemonMeshIntegrationTarget(statuses, 1, voterIDs) {
		return false
	}
	for index, status := range statuses {
		if int(status.MemberTotal) != deviceCount ||
			len(status.Members) != deviceCount ||
			status.MembersTruncated {
			return false
		}
		if index < voterCount {
			if status.Consensus.State != "ready" {
				return false
			}
			continue
		}
		if status.Consensus.State != "settled" ||
			status.Session.AppliedRaftIndex != nil {
			return false
		}
	}
	return true
}

func requireSameDeviceLatencyCommitments(
	t *testing.T,
	nodes []*daemonMeshIntegrationNode,
	requiredSigner domain.DeviceID,
) {
	t.Helper()
	if len(nodes) == 0 || !requiredSigner.Valid() {
		t.Fatal("invalid same-device commitment fixture")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		sameDeviceLatencyConvergenceMax,
	)
	defer cancel()
	var expected store.ReplicationWatermark
	for index, node := range nodes {
		if node == nil {
			t.Fatal("same-device commitment node is nil")
		}
		_, local, ready := node.meshCapture.snapshot()
		if !ready {
			t.Fatalf(
				"same-device commitment state unavailable for %s",
				node.deviceID,
			)
		}
		actual, err := local.ExportReplicationWatermark(
			ctx,
			requiredSigner,
		)
		if err != nil {
			t.Fatalf(
				"ExportReplicationWatermark(%s): %v",
				node.deviceID,
				err,
			)
		}
		if index == 0 {
			expected = actual
			continue
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf(
				"replica %s commitment differs: got %+v, want %+v",
				node.deviceID,
				actual,
				expected,
			)
		}
	}
}

func sameDeviceLatencyAgentsReady(
	statuses []ui.Snapshot,
	deviceID domain.DeviceID,
	agents []*sameDeviceLatencyAgent,
) bool {
	if !deviceID.Valid() || len(agents) != sameDeviceLatencyAgentCount {
		return false
	}
	expected := make(map[string]*sameDeviceLatencyAgent, len(agents))
	codexCount := 0
	claudeCount := 0
	for _, candidate := range agents {
		if candidate == nil ||
			!candidate.agentSession.Valid() ||
			!candidate.workingRoot.Valid() ||
			!candidate.clientKind.Valid() {
			return false
		}
		sessionID := string(candidate.agentSession)
		if _, duplicate := expected[sessionID]; duplicate {
			return false
		}
		expected[sessionID] = candidate
		switch candidate.clientKind {
		case agentsession.ClientKindCodex:
			codexCount++
		case agentsession.ClientKindClaude:
			claudeCount++
		default:
			return false
		}
	}
	if codexCount != sameDeviceLatencyAgentCount/2 ||
		claudeCount != sameDeviceLatencyAgentCount/2 {
		return false
	}
	for _, status := range statuses {
		if len(status.Agents) != len(expected) {
			return false
		}
		seen := make(map[string]struct{}, len(status.Agents))
		for _, actual := range status.Agents {
			candidate := expected[actual.AgentSessionID]
			if candidate == nil ||
				actual.DeviceID != string(deviceID) ||
				actual.ClientKind != string(candidate.clientKind) ||
				actual.WorkingRootID != string(candidate.workingRoot) ||
				!agentsession.State(actual.State).Connected() {
				return false
			}
			if _, duplicate := seen[actual.AgentSessionID]; duplicate {
				return false
			}
			seen[actual.AgentSessionID] = struct{}{}
		}
	}
	return true
}

func waitForDaemonLatencyAgentService(
	t *testing.T,
	node *daemonMeshIntegrationNode,
) *agent.Service {
	t.Helper()
	if node == nil {
		t.Fatal("latency source node is nil")
	}
	deadline := time.Now().Add(daemonMeshIntegrationTimeout)
	for time.Now().Before(deadline) {
		if service := node.agentService.Load(); service != nil {
			return service
		}
		select {
		case <-node.exited:
			t.Fatalf(
				"latency source exited before agent service capture: %v",
				node.exitErr,
			)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("latency source agent service was not captured")
	return nil
}

func launchSameDeviceLatencyAgent(
	t *testing.T,
	service *agent.Service,
	local store.LocalState,
	endpoint ipc.Endpoint,
	root string,
	deviceID domain.DeviceID,
	index int,
) *sameDeviceLatencyAgent {
	t.Helper()
	if service == nil ||
		!deviceID.Valid() ||
		index < 0 ||
		index >= sameDeviceLatencyAgentCount {
		t.Fatal("invalid same-device agent fixture")
	}
	managedRootID := sameDeviceLatencyUUID(0x1000 + uint64(index))
	clientInstanceID := sameDeviceLatencyUUID(0x2000 + uint64(index))
	canonicalPath := filepath.Join(root, fmt.Sprintf("agent-%02d", index))
	if err := os.MkdirAll(canonicalPath, 0o700); err != nil {
		t.Fatalf("create managed root %d: %v", index, err)
	}
	verifiedAt := domain.Timestamp(
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	defer cancel()
	if err := local.RegisterManagedRoot(ctx, store.ManagedRootRecord{
		ManagedRootID:      managedRootID,
		SessionID:          daemonTestSessionID,
		WorkspaceID:        daemonTestWorkspaceID,
		RecoveryGeneration: 0,
		CanonicalPath:      canonicalPath,
		FilesystemIdentity: "latency-filesystem:" + string(managedRootID),
		RepositoryIdentity: "latency-repository:" + string(managedRootID),
		Kind:               store.ManagedRootIsolated,
		GuardStatus:        store.RootGuardHealthy,
		Active:             true,
		LastVerifiedAt:     &verifiedAt,
	}); err != nil {
		t.Fatalf("RegisterManagedRoot(%d): %v", index, err)
	}
	clientKind := agentsession.ClientKindCodex
	if index%2 == 1 {
		clientKind = agentsession.ClientKindClaude
	}
	ticket, err := service.RegisterLaunch(ctx, agent.LaunchOptions{
		ClientKind:      clientKind,
		ConcurrencyMode: store.ConcurrencyIsolated,
		ManagedRootID:   managedRootID,
	})
	if err != nil {
		t.Fatalf("RegisterLaunch(%d): %v", index, err)
	}
	adapter, err := codecommmcp.Dial(ctx, codecommmcp.DialOptions{
		Endpoint:         endpoint,
		ClientInstanceID: clientInstanceID,
		SessionID:        daemonTestSessionID,
		WorkspaceID:      daemonTestWorkspaceID,
		LaunchSelector:   ticket.Selector,
	})
	if err != nil {
		t.Fatalf("mcp.Dial(%d): %v", index, err)
	}
	mcpServer, err := codecommmcp.NewServer(adapter)
	if err != nil {
		_ = adapter.Close()
		t.Fatalf("mcp.NewServer(%d): %v", index, err)
	}
	clientTransport, serverTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		_ = adapter.Close()
		t.Fatalf("MCP server Connect(%d): %v", index, err)
	}
	sdkClient := mcpsdk.NewClient(
		&mcpsdk.Implementation{
			Name:    "codecomm-phase3-latency",
			Version: "1",
		},
		nil,
	)
	clientSession, err := sdkClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		_ = adapter.Close()
		t.Fatalf("MCP client Connect(%d): %v", index, err)
	}
	result := &sameDeviceLatencyAgent{
		adapter:       adapter,
		serverSession: serverSession,
		session:       clientSession,
		clientKind:    clientKind,
	}
	t.Cleanup(func() {
		_ = result.session.Close()
		_ = result.serverSession.Close()
		_ = result.adapter.Close()
	})
	self, err := callSameDeviceLatencyTool[codecommmcp.AgentSession](
		ctx,
		result.session,
		codecommmcp.ToolAgentSessionGet,
		map[string]any{},
	)
	if err != nil {
		t.Fatalf("agent.session.get(%d): %v", index, err)
	}
	result.agentSession = domain.UUIDv7(self.AgentSessionID)
	result.workingRoot = domain.UUIDv7(self.WorkingRootID)
	if !result.agentSession.Valid() ||
		!result.workingRoot.Valid() ||
		self.ClientKind != string(clientKind) ||
		self.DeviceID != string(deviceID) {
		t.Fatalf("agent session %d = %#v", index, self)
	}
	return result
}

func runSameDeviceVisibilitySample(
	t *testing.T,
	source, observer *sameDeviceLatencyAgent,
	title string,
) time.Duration {
	t.Helper()
	if source == nil ||
		observer == nil ||
		source == observer ||
		title == "" {
		t.Fatal("invalid same-device latency sample")
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		daemonMeshIntegrationTimeout,
	)
	before, err := callSameDeviceLatencyTool[codecommmcp.ContextGetOutput](
		ctx,
		observer.session,
		codecommmcp.ToolContextGet,
		map[string]any{},
	)
	if err != nil {
		cancel()
		t.Fatalf("read pre-mutation context: %v", err)
	}
	created, acceptedAt, err := callSameDeviceLatencyToolAt[codecommmcp.MutationOutput](
		ctx,
		source.session,
		codecommmcp.ToolTaskCreate,
		map[string]any{
			"title":    title,
			"priority": uint8(task.PriorityNormal),
			"labels":   []string{"phase-3", "latency"},
		},
	)
	cancel()
	if err != nil {
		t.Fatalf("task.create(%q): %v", title, err)
	}
	if created.Status != "accepted" ||
		created.Code != "accepted" ||
		created.Duplicate ||
		!domain.UUIDv7(created.EntityID).Valid() ||
		!domain.UUIDv7(created.EventID).Valid() {
		t.Fatalf("task.create(%q) output = %#v", title, created)
	}

	observeContext, cancelObserve := context.WithTimeout(
		context.Background(),
		sameDeviceLatencyObservationMax,
	)
	defer cancelObserve()
	for {
		observed, observedAt, err := callSameDeviceLatencyToolAt[codecommmcp.ContextGetOutput](
			observeContext,
			observer.session,
			codecommmcp.ToolContextGet,
			map[string]any{},
		)
		if err != nil {
			t.Fatalf("context.get after %q: %v", title, err)
		}
		if observed.Session.ChainIndex > before.Session.ChainIndex &&
			observed.Session.ResultIndex > before.Session.ResultIndex &&
			sameDeviceLatencyContextHasTask(
				observed,
				created.EntityID,
				title,
			) {
			elapsed := observedAt.Sub(acceptedAt)
			if elapsed < 0 {
				t.Fatalf(
					"context.get for %q completed before task.create",
					title,
				)
			}
			return elapsed
		}
		if err := observeContext.Err(); err != nil {
			t.Fatalf(
				"task %s was not visible after %s: %v",
				created.EntityID,
				time.Since(acceptedAt),
				err,
			)
		}
	}
}

func sameDeviceLatencyContextHasTask(
	contextOutput codecommmcp.ContextGetOutput,
	taskID, title string,
) bool {
	for _, candidate := range contextOutput.Tasks {
		if candidate.TaskID == taskID &&
			candidate.Title == title &&
			candidate.State == string(task.StateBacklog) &&
			candidate.EntityVersion == 1 {
			return true
		}
	}
	return false
}

func callSameDeviceLatencyTool[T any](
	ctx context.Context,
	session *mcpsdk.ClientSession,
	name string,
	arguments any,
) (T, error) {
	output, _, err := callSameDeviceLatencyToolAt[T](
		ctx,
		session,
		name,
		arguments,
	)
	return output, err
}

func callSameDeviceLatencyToolAt[T any](
	ctx context.Context,
	session *mcpsdk.ClientSession,
	name string,
	arguments any,
) (T, time.Time, error) {
	var output T
	if ctx == nil || session == nil || name == "" {
		return output, time.Time{}, errors.New("invalid MCP latency call")
	}
	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      name,
		Arguments: arguments,
	})
	returnedAt := time.Now()
	if err != nil {
		return output, returnedAt, err
	}
	if result.IsError {
		return output, returnedAt, fmt.Errorf(
			"MCP tool %s failed: %v",
			name,
			result.Content,
		)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return output, returnedAt, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return output, returnedAt, err
	}
	return output, returnedAt, nil
}

func sameDeviceLatencyUUID(sequence uint64) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf(
		"019b17cc-0009-7def-b456-%012x",
		sequence,
	))
}
