package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpTestClientID  = domain.UUIDv7("018f47de-89ab-7def-8123-0123456789ab")
	mcpTestSessionID = domain.UUIDv7("018f47de-89ab-7def-8123-1123456789ab")
	mcpTestWorkspace = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
)

func TestValidateDialProofRequiresExactClosedUnion(t *testing.T) {
	valid := bytes.Repeat([]byte{0x41}, 32)
	validSelector := codec.EncodeBase64URL(valid)
	tests := []struct {
		name    string
		options DialOptions
		want    proofKind
	}{
		{
			name: "launch",
			options: DialOptions{
				LaunchSelector: validSelector,
			},
			want: launchProof,
		},
		{
			name: "resume",
			options: DialOptions{
				ResumeCapability: valid,
			},
			want: resumeProof,
		},
		{
			name:    "missing",
			options: DialOptions{},
		},
		{
			name: "both",
			options: DialOptions{
				LaunchSelector:   validSelector,
				ResumeCapability: valid,
			},
		},
		{
			name: "short launch selector",
			options: DialOptions{
				LaunchSelector: codec.EncodeBase64URL(valid[:31]),
			},
		},
		{
			name: "padded launch selector",
			options: DialOptions{
				LaunchSelector: validSelector + "=",
			},
		},
		{
			name: "short resume capability",
			options: DialOptions{
				ResumeCapability: valid[:31],
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateDialProof(test.options)
			if test.want == 0 {
				if !errors.Is(err, ErrInvalidOptions) {
					t.Fatalf("validateDialProof() error = %v, want %v", err, ErrInvalidOptions)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDialProof() error = %v", err)
			}
			if got.kind != test.want {
				t.Fatalf("proof kind = %d, want %d", got.kind, test.want)
			}
		})
	}
}

func TestClientReconnectsWithRetainedCapabilityAndRetriesExactRequest(
	t *testing.T,
) {
	capability := bytes.Repeat([]byte{0x52}, 32)
	first := &scriptedTransport{
		exchange: func(
			int,
			context.Context,
			string,
			string,
			[]byte,
		) (ipc.ClientResponse, error) {
			return ipc.ClientResponse{}, fmt.Errorf(
				"%w: reset",
				ipc.ErrClientConnectionLost,
			)
		},
	}
	replacement := &scriptedTransport{
		exchange: func(
			call int,
			_ context.Context,
			method, path string,
			body []byte,
		) (ipc.ClientResponse, error) {
			switch call {
			case 1:
				if method != "POST" ||
					path != localBindPath ||
					!bytes.Contains(
						body,
						[]byte(codec.EncodeBase64URL(capability)),
					) {
					t.Fatalf(
						"resume bind = %s %s %s",
						method,
						path,
						body,
					)
				}
				return ipc.ClientResponse{
					StatusCode: 200,
					Body: mustMCPTestCanonicalJSON(t, map[string]any{
						"local_protocol_version": ipc.LocalProtocolVersion,
						"client_instance_id":     mcpTestClientID,
						"session_id":             mcpTestSessionID,
						"workspace_id":           mcpTestWorkspace,
						"client_class":           "agent",
					}),
				}, nil
			case 2:
				if method != "GET" ||
					path != localTasksPath ||
					len(body) != 0 {
					t.Fatalf(
						"retried request = %s %s %s",
						method,
						path,
						body,
					)
				}
				return ipc.ClientResponse{
					StatusCode: 200,
					Body:       []byte(`{"tasks":[]}`),
				}, nil
			default:
				t.Fatalf("unexpected replacement call %d", call)
				return ipc.ClientResponse{}, nil
			}
		},
	}
	dialCalls := 0
	client := &Client{
		transport: first,
		dial: func(context.Context, ipc.Endpoint) (localTransport, error) {
			dialCalls++
			return replacement, nil
		},
		clientInstanceID: mcpTestClientID,
		sessionID:        mcpTestSessionID,
		workspaceID:      mcpTestWorkspace,
		hasResume:        true,
	}
	copy(client.resumeCapability[:], capability)

	response, err := client.exchange(
		context.Background(),
		"GET",
		localTasksPath,
		nil,
	)
	if err != nil {
		t.Fatalf("exchange(): %v", err)
	}
	if response.StatusCode != 200 ||
		string(response.Body) != `{"tasks":[]}` ||
		dialCalls != 1 ||
		first.callCount() != 1 ||
		replacement.callCount() != 2 ||
		!first.isClosed() {
		t.Fatalf(
			"response=%#v dial=%d first=(%d,%t) replacement=%d",
			response,
			dialCalls,
			first.callCount(),
			first.isClosed(),
			replacement.callCount(),
		)
	}
}

func TestClientReconnectRetriesTransientResumeRace(t *testing.T) {
	capability := bytes.Repeat([]byte{0x53}, 32)
	first := &scriptedTransport{
		exchange: func(
			int,
			context.Context,
			string,
			string,
			[]byte,
		) (ipc.ClientResponse, error) {
			return ipc.ClientResponse{}, ipc.ErrClientConnectionLost
		},
	}
	rejected := &scriptedTransport{
		exchange: func(
			int,
			context.Context,
			string,
			string,
			[]byte,
		) (ipc.ClientResponse, error) {
			return ipc.ClientResponse{}, &ipc.ClientError{
				Status: 403,
				Code:   "local_bind_rejected",
			}
		},
	}
	replacement := &scriptedTransport{
		exchange: func(
			call int,
			_ context.Context,
			_, path string,
			_ []byte,
		) (ipc.ClientResponse, error) {
			if call == 1 {
				return ipc.ClientResponse{
					StatusCode: 200,
					Body: mustMCPTestCanonicalJSON(t, map[string]any{
						"local_protocol_version": ipc.LocalProtocolVersion,
						"client_instance_id":     mcpTestClientID,
						"session_id":             mcpTestSessionID,
						"workspace_id":           mcpTestWorkspace,
						"client_class":           "agent",
					}),
				}, nil
			}
			if call != 2 || path != localContextPath {
				t.Fatalf("unexpected successful transport call %d %s", call, path)
			}
			return ipc.ClientResponse{
				StatusCode: 200,
				Body:       []byte(`{"ok":true}`),
			}, nil
		},
	}
	dialCalls := 0
	client := &Client{
		transport: first,
		dial: func(context.Context, ipc.Endpoint) (localTransport, error) {
			dialCalls++
			if dialCalls == 1 {
				return rejected, nil
			}
			return replacement, nil
		},
		clientInstanceID: mcpTestClientID,
		sessionID:        mcpTestSessionID,
		workspaceID:      mcpTestWorkspace,
		hasResume:        true,
	}
	copy(client.resumeCapability[:], capability)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.exchange(ctx, "GET", localContextPath, nil); err != nil {
		t.Fatalf("exchange(): %v", err)
	}
	if dialCalls != 2 || !rejected.isClosed() {
		t.Fatalf(
			"dial calls = %d, rejected closed = %t",
			dialCalls,
			rejected.isClosed(),
		)
	}
}

func TestClientDoesNotReconnectWithoutResumeCapability(t *testing.T) {
	first := &scriptedTransport{
		exchange: func(
			int,
			context.Context,
			string,
			string,
			[]byte,
		) (ipc.ClientResponse, error) {
			return ipc.ClientResponse{}, ipc.ErrClientConnectionLost
		},
	}
	client := &Client{
		transport:        first,
		clientInstanceID: mcpTestClientID,
		sessionID:        mcpTestSessionID,
		workspaceID:      mcpTestWorkspace,
	}
	if _, err := client.exchange(
		context.Background(),
		"GET",
		localTasksPath,
		nil,
	); !errors.Is(err, ErrConnectionLost) {
		t.Fatalf("exchange() error = %v, want %v", err, ErrConnectionLost)
	}
}

func TestSDKToolSurfaceIsClosedAndRejectsAuthorityFields(t *testing.T) {
	local := &Client{
		transport:        usableTestTransport{},
		clientInstanceID: mcpTestClientID,
		sessionID:        mcpTestSessionID,
		workspaceID:      mcpTestWorkspace,
		hasResume:        true,
	}
	server, err := NewServer(local)
	if err != nil {
		t.Fatalf("NewServer(): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientTransport, serverTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect(): %v", err)
	}
	defer serverSession.Close()
	sdkClient := mcpsdk.NewClient(
		&mcpsdk.Implementation{Name: "test", Version: "1"},
		nil,
	)
	clientSession, err := sdkClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect(): %v", err)
	}
	defer clientSession.Close()

	list, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools(): %v", err)
	}
	names := make([]string, len(list.Tools))
	byName := make(map[string]*mcpsdk.Tool, len(list.Tools))
	for index, tool := range list.Tools {
		names[index] = tool.Name
		byName[tool.Name] = tool
	}
	sort.Strings(names)
	want := []string{
		ToolAgentSessionGet,
		ToolContextGet,
		ToolTaskClaim,
		ToolTaskCreate,
		ToolTaskList,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("tool names = %#v, want %#v", names, want)
	}
	for name, tool := range byName {
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s schema: %v", name, err)
		}
		if !bytes.Contains(encoded, []byte(`"additionalProperties":false`)) {
			t.Fatalf("%s input schema is not closed: %s", name, encoded)
		}
	}

	for _, test := range []struct {
		name      string
		tool      string
		arguments string
	}{
		{
			name:      "actor origin",
			tool:      ToolTaskClaim,
			arguments: `{"expected_entity_version":1,"origin":{"actor_type":"human"},"task_id":"018f47de-89ab-7def-8123-2123456789ab"}`,
		},
		{
			name:      "null optional array",
			tool:      ToolTaskCreate,
			arguments: `{"labels":null,"priority":1,"title":"closed schema"}`,
		},
		{
			name:      "read argument",
			tool:      ToolTaskList,
			arguments: `{"limit":1}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
				Name:      test.tool,
				Arguments: json.RawMessage(test.arguments),
			})
			if err != nil {
				t.Fatalf("CallTool(): %v", err)
			}
			if !result.IsError {
				t.Fatalf("CallTool() result = %#v, want schema tool error", result)
			}
		})
	}
}

type usableTestTransport struct{}

func (usableTestTransport) Exchange(
	context.Context,
	string,
	string,
	[]byte,
) (ipc.ClientResponse, error) {
	return ipc.ClientResponse{}, errors.New("unexpected local exchange")
}

func (usableTestTransport) Close() error { return nil }

func (usableTestTransport) Usable() bool { return true }

type scriptedTransport struct {
	mu       sync.Mutex
	calls    int
	closed   bool
	exchange func(
		int,
		context.Context,
		string,
		string,
		[]byte,
	) (ipc.ClientResponse, error)
}

func (transport *scriptedTransport) Exchange(
	ctx context.Context,
	method, path string,
	body []byte,
) (ipc.ClientResponse, error) {
	transport.mu.Lock()
	transport.calls++
	call := transport.calls
	exchange := transport.exchange
	transport.mu.Unlock()
	return exchange(call, ctx, method, path, body)
}

func (transport *scriptedTransport) Close() error {
	transport.mu.Lock()
	transport.closed = true
	transport.mu.Unlock()
	return nil
}

func (transport *scriptedTransport) Usable() bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return !transport.closed
}

func (transport *scriptedTransport) callCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

func (transport *scriptedTransport) isClosed() bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.closed
}

func mustMCPTestCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalJSON(value)
	if err != nil {
		t.Fatalf("canonicalJSON(): %v", err)
	}
	return encoded
}
