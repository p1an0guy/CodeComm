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
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestOperatorClientReadsStatusAndReconnectsAfterDaemonRestart(t *testing.T) {
	endpoint := newUIClientTestEndpoint(t)
	source := uiTestStatusSnapshot(t)
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return source, nil
		}),
		Submitter:   successfulOperatorSubmitter(),
		Pairing:     testPairingOperator{},
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
		string(coordstatus.StrongWritesAvailable) ||
		got.Consensus.LiveConfigurationSource !=
			string(coordstatus.LiveConfigurationLocal) {
		t.Fatalf("Status(after restart) = %#v", got)
	}
	member, found, err := client.Member(
		testUIClientContext(t),
		source.Durable.Member.ID,
	)
	if err != nil || !found ||
		member.DeviceID != string(source.Durable.Member.ID) {
		t.Fatalf("Member(after restart) = (%#v, %t, %v)", member, found, err)
	}
}

func TestOperatorClientReadsExactMemberOutsideStatusRoster(t *testing.T) {
	endpoint := newUIClientTestEndpoint(t)
	snapshot := uiTestStatusSnapshot(t)
	snapshot.Durable.MemberTotal = 2
	snapshot.Durable.MembersTruncated = true
	member := coordstatus.MemberSummary{
		ID:            domain.DeviceID("cc1" + strings.Repeat("a", 64)),
		Role:          snapshot.Durable.Member.Role,
		Status:        snapshot.Durable.Member.Status,
		EntityVersion: 9,
	}
	source := &exactMemberStatusSource{
		snapshot: snapshot,
		member:   member,
	}
	service, err := NewOperatorService(OperatorServiceOptions{
		Source:      source,
		Submitter:   successfulOperatorSubmitter(),
		Pairing:     testPairingOperator{},
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("NewOperatorService(): %v", err)
	}
	server := startUIClientTestServer(t, endpoint, service)
	t.Cleanup(func() { server.stop(t) })
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

	got, found, err := client.Member(testUIClientContext(t), member.ID)
	if err != nil {
		t.Fatalf("Member(found): %v", err)
	}
	if !found ||
		got.DeviceID != string(member.ID) ||
		got.EntityVersion != member.EntityVersion {
		t.Fatalf("Member(found) = (%#v, %t)", got, found)
	}
	missing := domain.DeviceID("cc1" + strings.Repeat("b", 64))
	got, found, err = client.Member(testUIClientContext(t), missing)
	if err != nil || found || got != (MemberStatus{}) {
		t.Fatalf("Member(absent) = (%#v, %t, %v)", got, found, err)
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
			name: "missing live configuration source",
			mutate: func(value map[string]any) {
				consensus := value["consensus"].(map[string]any)
				delete(consensus, "live_configuration_source")
			},
		},
		{
			name: "unknown live configuration source",
			mutate: func(value map[string]any) {
				consensus := value["consensus"].(map[string]any)
				consensus["live_configuration_source"] = "cached"
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

func TestDecodeStatusResponseValidatesSettledUnknownConfiguration(t *testing.T) {
	valid := snapshotFromCoordination(
		uiTestSettledUnknownStatusSnapshot(t),
	)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	got, err := decodeStatusResponse(encoded)
	if err != nil {
		t.Fatalf("decodeStatusResponse(): %v", err)
	}
	if got.Consensus.State != string(coordstatus.ConsensusSettled) ||
		got.Consensus.Role != string(coordstatus.RoleNonvoter) ||
		got.Consensus.LiveConfigurationSource !=
			string(coordstatus.LiveConfigurationUnknown) {
		t.Fatalf("settled snapshot = %#v", got.Consensus)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "leader",
			mutate: func(consensus map[string]any) {
				consensus["leader_device_id"] = valid.Session.LocalDeviceID
			},
		},
		{
			name: "live voter",
			mutate: func(consensus map[string]any) {
				consensus["live_voter_device_ids"] = []string{
					valid.Session.LocalDeviceID,
				}
			},
		},
		{
			name: "live nonvoter",
			mutate: func(consensus map[string]any) {
				consensus["live_nonvoter_device_ids"] = []string{
					valid.Session.LocalDeviceID,
				}
			},
		},
		{
			name: "quorum",
			mutate: func(consensus map[string]any) {
				consensus["quorum_required"] = 1
			},
		},
		{
			name: "exactness claim",
			mutate: func(consensus map[string]any) {
				consensus["configuration_reconciled"] = true
			},
		},
		{
			name: "known reconciliation",
			mutate: func(consensus map[string]any) {
				consensus["reconciliation_state"] = "stable"
			},
		},
		{
			name: "reconciliation device",
			mutate: func(consensus map[string]any) {
				consensus["reconciliation_device_id"] =
					valid.Session.LocalDeviceID
			},
		},
		{
			name: "available writes",
			mutate: func(consensus map[string]any) {
				consensus["strong_writes"] = "available"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var candidate map[string]any
			if err := json.Unmarshal(encoded, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(candidate["consensus"].(map[string]any))
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

func TestConsensusStatusAcceptsVoterReportedTopologyWithoutExactness(
	t *testing.T,
) {
	snapshot := snapshotFromCoordination(
		uiTestSettledUnknownStatusSnapshot(t),
	)
	leader := snapshot.Consensus.TargetVoterDeviceIDs[0]
	snapshot.Consensus.LiveConfigurationSource = string(
		coordstatus.LiveConfigurationVoterReported,
	)
	snapshot.Consensus.LeaderDeviceID = &leader
	snapshot.Consensus.LiveVoterDeviceIDs = []string{leader}
	snapshot.Consensus.QuorumRequired = 1
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	snapshot.Consensus.ConfigurationReconciled = true
	if err := snapshot.Validate(); err == nil {
		t.Fatal("Validate() accepted nonlocal reconciliation exactness")
	}
}

func TestOperatorClientSubmitsExactVoterTarget(t *testing.T) {
	endpoint := newUIClientTestEndpoint(t)
	source := uiTestStatusSnapshot(t)
	var captured operatorcommand.Request
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return source, nil
		}),
		Submitter: operatorSubmitterFunc(func(
			_ context.Context,
			request operatorcommand.Request,
		) (operatorcommand.Result, error) {
			captured = request
			return operatorcommand.Result{
				EventID: uiTestTaskID,
				Outcome: store.CommandOutcome{
					Status: store.OutcomeAccepted,
					Code:   "accepted",
					JSON: []byte(
						`{"code":"accepted","status":"accepted"}`,
					),
				},
			}, nil
		}),
		Pairing:     testPairingOperator{},
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := startUIClientTestServer(t, endpoint, service)
	t.Cleanup(func() { server.stop(t) })
	client, err := DialOperator(testUIClientContext(t), OperatorDialOptions{
		Endpoint:         endpoint,
		ClientInstanceID: uiTestClientID,
		SessionID:        uiTestSessionID,
		WorkspaceID:      uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	target := []domain.DeviceID{source.Durable.Member.ID}
	result, err := client.SetVoters(
		testUIClientContext(t),
		SetVotersRequest{
			RequestID:               uiTestAgentID,
			ExpectedVoterSetVersion: 1,
			VoterDeviceIDs:          target,
		},
	)
	if err != nil {
		t.Fatalf("SetVoters(): %v", err)
	}
	if result.EventID != uiTestTaskID ||
		result.Status != store.OutcomeAccepted ||
		captured.ClientInstanceID != uiTestClientID ||
		captured.Command.RequestID != uiTestAgentID {
		t.Fatalf("result = %#v; request = %#v", result, captured)
	}
	payload := string(captured.Command.Command.Payload)
	if payload != `{"voter_set":["`+string(target[0])+`"]}` {
		t.Fatalf("payload = %s", payload)
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
