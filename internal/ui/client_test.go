package ui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/ipc"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

func TestOperatorClientReadsStatusAndReconnectsAfterDaemonRestart(t *testing.T) {
	endpoint := newUIClientTestEndpoint(t)
	source := uiTestStatusSnapshot(t)
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return source, nil
		}),
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("NewOperatorService(): %v", err)
	}
	first := startUIClientTestServer(t, endpoint, service)
	client, err := DialOperator(testUIClientContext(t), OperatorDialOptions{
		Endpoint:         endpoint,
		ClientInstanceID: uiTestClientID,
		SessionID:        uiTestSessionID,
		WorkspaceID:      uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("DialOperator(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	got, err := client.Status(testUIClientContext(t))
	if err != nil {
		t.Fatalf("Status(first): %v", err)
	}
	if got.TaskTotal != 1 ||
		got.Session.SessionID != string(uiTestSessionID) {
		t.Fatalf("Status(first) = %#v", got)
	}

	first.stop(t)
	if _, err := client.Status(testUIClientContext(t)); err == nil {
		t.Fatal("Status(while stopped) succeeded")
	}
	second := startUIClientTestServer(t, endpoint, service)
	t.Cleanup(func() { second.stop(t) })
	got, err = client.Status(testUIClientContext(t))
	if err != nil {
		t.Fatalf("Status(after restart): %v", err)
	}
	if got.Consensus.StrongWrites !=
		string(coordstatus.StrongWritesAvailable) {
		t.Fatalf("Status(after restart) = %#v", got)
	}
}

func TestDecodeStatusResponseRejectsUnknownNullAndInvalidFields(t *testing.T) {
	valid := snapshotFromCoordination(uiTestStatusSnapshot(t))
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "unknown",
			mutate: func(value map[string]any) {
				value["origin"] = map[string]any{"actor_type": "human"}
			},
		},
		{
			name: "null agents",
			mutate: func(value map[string]any) {
				value["agents"] = nil
			},
		},
		{
			name: "invalid state",
			mutate: func(value map[string]any) {
				consensus := value["consensus"].(map[string]any)
				consensus["state"] = "healthy"
			},
		},
		{
			name: "unknown reconciliation blocker",
			mutate: func(value map[string]any) {
				consensus := value["consensus"].(map[string]any)
				consensus["reconciliation_blocker"] = "anything-goes"
			},
		},
		{
			name: "false reconciliation exactness",
			mutate: func(value map[string]any) {
				consensus := value["consensus"].(map[string]any)
				consensus["configuration_reconciled"] = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var candidate map[string]any
			if err := json.Unmarshal(encoded, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeStatusResponse(raw); !errors.Is(
				err,
				ErrStatusProtocol,
			) {
				t.Fatalf(
					"decodeStatusResponse() error = %v, want %v",
					err,
					ErrStatusProtocol,
				)
			}
		})
	}
}

type uiClientTestServer struct {
	server *ipc.Server
	cancel context.CancelFunc
	done   <-chan error
}

func startUIClientTestServer(
	t *testing.T,
	endpoint ipc.Endpoint,
	binder ipc.Binder,
) *uiClientTestServer {
	t.Helper()
	server, err := ipc.NewServer(ipc.Config{
		Endpoint:    endpoint,
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
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
	return &uiClientTestServer{
		server: server,
		cancel: cancel,
		done:   done,
	}
}

func (server *uiClientTestServer) stop(t *testing.T) {
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

func newUIClientTestEndpoint(t *testing.T) ipc.Endpoint {
	t.Helper()
	var address string
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\codecomm-ui-` +
			strings.ReplaceAll(uuid.NewString(), "-", "")
	} else {
		directory, err := os.MkdirTemp("", "cc-ui-")
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

func testUIClientContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
