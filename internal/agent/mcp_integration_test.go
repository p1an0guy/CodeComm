package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/ipc"
	codecommmcp "github.com/ijonahch/codecomm/internal/mcp"
	"github.com/ijonahch/codecomm/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestThreeMCPAgentsRaceForTaskAndObserveOneWinner(t *testing.T) {
	ready := task.Task{
		ID:            agentTestTaskID,
		Title:         "claim exactly once through MCP",
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
	endpoint := newMCPTestEndpoint(t)
	localServer, err := ipc.NewServer(ipc.Config{
		Endpoint:    endpoint,
		SessionID:   agentTestSessionID,
		WorkspaceID: agentTestWorkspaceID,
		Binder:      harness.service,
	})
	if err != nil {
		t.Fatalf("ipc.NewServer(): %v", err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- localServer.Serve(serveContext)
	}()
	t.Cleanup(func() {
		cancelServe()
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			3*time.Second,
		)
		defer cancel()
		if err := localServer.Shutdown(shutdownContext); err != nil {
			t.Errorf("local server shutdown: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("local server serve: %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("local server did not stop: %v", shutdownContext.Err())
		}
	})

	agents := []*mcpAgent{
		launchMCPAgent(
			t,
			harness,
			endpoint,
			domain.UUIDv7("018f47de-89ab-7def-8123-5123456789ab"),
			domain.UUIDv7("018f47de-89ab-7def-8123-6123456789ab"),
			agentsession.ClientKindCodex,
		),
		launchMCPAgent(
			t,
			harness,
			endpoint,
			domain.UUIDv7("018f47de-89ab-7def-8123-5223456789ab"),
			domain.UUIDv7("018f47de-89ab-7def-8123-6223456789ab"),
			agentsession.ClientKindClaude,
		),
		launchMCPAgent(
			t,
			harness,
			endpoint,
			domain.UUIDv7("018f47de-89ab-7def-8123-5323456789ab"),
			domain.UUIDv7("018f47de-89ab-7def-8123-6323456789ab"),
			agentsession.ClientKindCodex,
		),
	}
	sessionIDs := make(map[string]struct{}, len(agents))
	for _, client := range agents {
		self := callMCPTool[codecommmcp.AgentSession](
			t,
			client.session,
			codecommmcp.ToolAgentSessionGet,
			map[string]any{},
		)
		if self.ClientKind != string(client.clientKind) ||
			self.State != string(agentsession.StateStarting) {
			t.Fatalf("agent session = %#v", self)
		}
		sessionIDs[self.AgentSessionID] = struct{}{}
		client.agentSessionID = domain.UUIDv7(self.AgentSessionID)
	}
	if len(sessionIDs) != 3 {
		t.Fatalf("three MCP clients produced %d distinct sessions", len(sessionIDs))
	}

	type claimResult struct {
		agentSessionID domain.UUIDv7
		output         codecommmcp.MutationOutput
		err            error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, client := range agents[:2] {
		go func(client *mcpAgent) {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			output, err := callMCPMutation(
				ctx,
				client.session,
				codecommmcp.ToolTaskClaim,
				map[string]any{
					"task_id":                 ready.ID,
					"expected_entity_version": ready.EntityVersion,
				},
			)
			results <- claimResult{
				agentSessionID: client.agentSessionID,
				output:         output,
				err:            err,
			}
		}(client)
	}
	close(start)

	var winner domain.UUIDv7
	accepted := 0
	rejected := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("task.claim through MCP: %v", result.err)
		}
		switch result.output.Status {
		case "accepted":
			accepted++
			winner = result.agentSessionID
		case "rejected":
			rejected++
		default:
			t.Fatalf("claim output = %#v", result.output)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("claim outcomes accepted=%d rejected=%d", accepted, rejected)
	}

	claimed, found, err := harness.local.Task(testAgentContext(t), ready.ID)
	if err != nil || !found {
		t.Fatalf("Task() = (%#v, %t, %v)", claimed, found, err)
	}
	if claimed.State != task.StateClaimed ||
		claimed.OwnerDeviceID != harness.deviceID ||
		claimed.OwnerAgentSessionID != winner ||
		claimed.EntityVersion != 2 {
		t.Fatalf("claimed task = %#v, winner = %q", claimed, winner)
	}
	for _, client := range agents {
		list := callMCPTool[codecommmcp.TaskListOutput](
			t,
			client.session,
			codecommmcp.ToolTaskList,
			map[string]any{},
		)
		assertMCPTaskOwner(t, list.Tasks, claimed)
	}
	contextOutput := callMCPTool[codecommmcp.ContextGetOutput](
		t,
		agents[2].session,
		codecommmcp.ToolContextGet,
		map[string]any{},
	)
	if contextOutput.Self.AgentSessionID != string(agents[2].agentSessionID) ||
		contextOutput.Session.SessionID != string(agentTestSessionID) ||
		contextOutput.Session.WorkspaceID != string(agentTestWorkspaceID) {
		t.Fatalf("context binding = %#v", contextOutput)
	}
	assertMCPTaskOwner(t, contextOutput.Tasks, claimed)

	created := callMCPTool[codecommmcp.MutationOutput](
		t,
		agents[2].session,
		codecommmcp.ToolTaskCreate,
		map[string]any{
			"title":    "created through MCP",
			"priority": uint8(task.PriorityNormal),
			"labels":   []string{"integration", "phase-2"},
		},
	)
	if created.Status != "accepted" ||
		created.Code != "accepted" ||
		!domain.UUIDv7(created.EntityID).Valid() {
		t.Fatalf("task.create output = %#v", created)
	}
	afterCreate := callMCPTool[codecommmcp.TaskListOutput](
		t,
		agents[0].session,
		codecommmcp.ToolTaskList,
		map[string]any{},
	)
	foundCreated := false
	for _, value := range afterCreate.Tasks {
		if value.TaskID == created.EntityID &&
			value.Title == "created through MCP" &&
			value.State == string(task.StateBacklog) {
			foundCreated = true
		}
	}
	if !foundCreated {
		t.Fatalf("task.list did not observe created task: %#v", afterCreate.Tasks)
	}
}

func TestMCPAgentResumesAfterLocalDaemonEndpointRestart(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	if err := harness.service.Recover(testAgentContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	endpoint := newMCPTestEndpoint(t)
	first := startMCPTestServer(t, endpoint, harness.service)
	client := launchMCPAgent(
		t,
		harness,
		endpoint,
		domain.UUIDv7("018f47de-89ab-7def-8123-5423456789ab"),
		domain.UUIDv7("018f47de-89ab-7def-8123-6423456789ab"),
		agentsession.ClientKindCodex,
	)
	before := callMCPTool[codecommmcp.AgentSession](
		t,
		client.session,
		codecommmcp.ToolAgentSessionGet,
		map[string]any{},
	)
	if !domain.UUIDv7(before.AgentSessionID).Valid() {
		t.Fatalf("initial agent session = %#v", before)
	}

	first.stop(t)
	second := startMCPTestServer(t, endpoint, harness.service)
	t.Cleanup(func() { second.stop(t) })
	after := callMCPTool[codecommmcp.AgentSession](
		t,
		client.session,
		codecommmcp.ToolAgentSessionGet,
		map[string]any{},
	)
	if after.AgentSessionID != before.AgentSessionID ||
		after.WorkingRootID != before.WorkingRootID ||
		after.State != before.State ||
		after.EntityVersion <= before.EntityVersion {
		t.Fatalf(
			"resumed agent changed identity/state:\nbefore: %#v\nafter:  %#v",
			before,
			after,
		)
	}
}

type mcpAgent struct {
	adapter        *codecommmcp.Client
	serverSession  *mcpsdk.ServerSession
	session        *mcpsdk.ClientSession
	clientKind     agentsession.ClientKind
	agentSessionID domain.UUIDv7
}

type mcpTestServer struct {
	server *ipc.Server
	cancel context.CancelFunc
	done   <-chan error
}

func startMCPTestServer(
	t *testing.T,
	endpoint ipc.Endpoint,
	binder ipc.Binder,
) *mcpTestServer {
	t.Helper()
	server, err := ipc.NewServer(ipc.Config{
		Endpoint:    endpoint,
		SessionID:   agentTestSessionID,
		WorkspaceID: agentTestWorkspaceID,
		Binder:      binder,
	})
	if err != nil {
		t.Fatalf("ipc.NewServer(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	return &mcpTestServer{
		server: server,
		cancel: cancel,
		done:   done,
	}
}

func (server *mcpTestServer) stop(t *testing.T) {
	t.Helper()
	if server == nil || server.server == nil {
		return
	}
	server.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown(): %v", err)
	}
	select {
	case err := <-server.done:
		if err != nil {
			t.Fatalf("Serve(): %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("server did not stop: %v", ctx.Err())
	}
	server.server = nil
}

func launchMCPAgent(
	t *testing.T,
	harness *agentTestHarness,
	endpoint ipc.Endpoint,
	managedRootID, clientInstanceID domain.UUIDv7,
	clientKind agentsession.ClientKind,
) *mcpAgent {
	t.Helper()
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
	adapter, err := codecommmcp.Dial(
		testAgentContext(t),
		codecommmcp.DialOptions{
			Endpoint:         endpoint,
			ClientInstanceID: clientInstanceID,
			SessionID:        agentTestSessionID,
			WorkspaceID:      agentTestWorkspaceID,
			LaunchSelector:   ticket.Selector,
		},
	)
	if err != nil {
		t.Fatalf("mcp.Dial(): %v", err)
	}
	mcpServer, err := codecommmcp.NewServer(adapter)
	if err != nil {
		_ = adapter.Close()
		t.Fatalf("mcp.NewServer(): %v", err)
	}
	ctx := testAgentContext(t)
	clientTransport, serverTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		_ = adapter.Close()
		t.Fatalf("MCP server Connect(): %v", err)
	}
	sdkClient := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "codecomm-test", Version: "1"},
		nil,
	)
	clientSession, err := sdkClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		_ = adapter.Close()
		t.Fatalf("MCP client Connect(): %v", err)
	}
	result := &mcpAgent{
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
	return result
}

func callMCPTool[T any](
	t *testing.T,
	session *mcpsdk.ClientSession,
	name string,
	arguments any,
) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      name,
		Arguments: arguments,
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if result.IsError {
		t.Fatalf("%s returned tool error: %v", name, result.Content)
	}
	var output T
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("%s structured output: %v", name, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		t.Fatalf("%s decode output: %v", name, err)
	}
	return output
}

func callMCPMutation(
	ctx context.Context,
	session *mcpsdk.ClientSession,
	name string,
	arguments any,
) (codecommmcp.MutationOutput, error) {
	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      name,
		Arguments: arguments,
	})
	if err != nil {
		return codecommmcp.MutationOutput{}, err
	}
	if result.IsError {
		return codecommmcp.MutationOutput{}, fmt.Errorf(
			"MCP tool error: %v",
			result.Content,
		)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return codecommmcp.MutationOutput{}, err
	}
	var output codecommmcp.MutationOutput
	if err := json.Unmarshal(encoded, &output); err != nil {
		return codecommmcp.MutationOutput{}, err
	}
	return output, nil
}

func assertMCPTaskOwner(
	t *testing.T,
	tasks []codecommmcp.Task,
	want task.Task,
) {
	t.Helper()
	for _, value := range tasks {
		if value.TaskID != string(want.ID) {
			continue
		}
		if value.OwnerAgentSessionID == nil ||
			*value.OwnerAgentSessionID != string(want.OwnerAgentSessionID) ||
			value.EntityVersion != want.EntityVersion ||
			value.State != string(want.State) {
			t.Fatalf("MCP task = %#v, want owner %q", value, want.OwnerAgentSessionID)
		}
		return
	}
	t.Fatalf("MCP task list omitted %q: %#v", want.ID, tasks)
}

func newMCPTestEndpoint(t *testing.T) ipc.Endpoint {
	t.Helper()
	var address string
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\codecomm-mcp-` +
			strings.ReplaceAll(uuid.NewString(), "-", "")
	} else {
		directory, err := os.MkdirTemp("", "cc-mcp-")
		if err != nil {
			t.Fatalf("MkdirTemp(): %v", err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Errorf("remove endpoint directory: %v", err)
			}
		})
		address = filepath.Join(directory, "codecomm.sock")
	}
	endpoint, err := ipc.ParseEndpoint(address)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q): %v", address, err)
	}
	return endpoint
}
