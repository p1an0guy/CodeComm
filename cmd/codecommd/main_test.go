package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

const (
	daemonTestSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-0123456789ab",
	)
	daemonTestWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	daemonTestSetupBootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-1123456789ab",
	)
	daemonTestFirstBootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-2123456789ab",
	)
	daemonTestSecondBootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-3123456789ab",
	)
	daemonTestVerifyBootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-4123456789ab",
	)
	daemonTestEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-5123456789ab",
	)
	daemonTestTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-6123456789ab",
	)
	daemonTestTimestamp = domain.Timestamp("2026-08-12T12:00:00Z")
)

func TestDaemonRecoversUnchangedCommitmentsAfterProcessKill(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	endpoint := daemonTestEndpoint(t)
	initial, identityPrivateKey, deviceID := daemonTestInitialState(t)

	setupNode, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: daemonTestSetupBootID,
			InitialState: &initial,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(setup): %v", err)
	}
	waitForDaemonTestLeader(t, setupNode)
	signed := daemonTestTaskEvent(
		t,
		identityPrivateKey,
		deviceID,
	)
	if _, err := setupNode.Apply(daemonTestContext(t), signed); err != nil {
		t.Fatalf("Apply(setup task): %v", err)
	}
	baseline, err := setupNode.View(daemonTestContext(t))
	if err != nil {
		t.Fatalf("View(baseline): %v", err)
	}
	if baseline.Heads.ChainIndex != 1 ||
		baseline.Heads.ResultIndex != 1 {
		t.Fatalf("baseline heads = %#v", baseline.Heads)
	}
	if err := setupNode.Close(); err != nil {
		t.Fatalf("Close(setup): %v", err)
	}

	first := startDaemonTestProcess(
		t,
		statePath,
		consensusDir,
		endpoint,
		daemonTestFirstBootID,
	)
	firstStatus := waitForDaemonTestStatus(t, endpoint)
	assertDaemonStatusMatchesView(t, firstStatus, baseline)
	first.kill(t)

	second := startDaemonTestProcess(
		t,
		statePath,
		consensusDir,
		endpoint,
		daemonTestSecondBootID,
	)
	secondStatus := waitForDaemonTestStatus(t, endpoint)
	assertDaemonStatusMatchesView(t, secondStatus, baseline)
	second.kill(t)

	verified, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: daemonTestVerifyBootID,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(after kill): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })
	waitForDaemonTestLeader(t, verified)
	afterKill, err := verified.View(daemonTestContext(t))
	if err != nil {
		t.Fatalf("View(after kill): %v", err)
	}
	if afterKill.Heads != baseline.Heads ||
		afterKill.ProjectionStateDigest != baseline.ProjectionStateDigest ||
		!reflect.DeepEqual(afterKill.ProjectionRows, baseline.ProjectionRows) {
		t.Fatalf(
			"process-kill recovery drifted durable commitments:\nbaseline: %#v\nafter:    %#v",
			baseline,
			afterKill,
		)
	}
}

func TestDaemonGracefulShutdownClosesConsensusAndLocalWorkers(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	endpoint := daemonTestEndpoint(t)
	initial, identityPrivateKey, deviceID := daemonTestInitialState(t)

	setupNode, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: daemonTestSetupBootID,
			InitialState: &initial,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(setup): %v", err)
	}
	waitForDaemonTestLeader(t, setupNode)
	if err := setupNode.Close(); err != nil {
		t.Fatalf("Close(setup): %v", err)
	}

	runContext, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- runDaemon(
			runContext,
			daemonOptions{
				statePath:    statePath,
				consensusDir: consensusDir,
				endpoint:     endpoint,
				sessionID:    daemonTestSessionID,
				workspaceID:  daemonTestWorkspaceID,
			},
			daemonDependencies{
				loadIdentity: func(
					context.Context,
				) (identityHandle, []byte, error) {
					return testIdentityHandle{},
						bytes.Clone(identityPrivateKey),
						nil
				},
				newBootID: func() (domain.UUIDv7, error) {
					return daemonTestFirstBootID, nil
				},
				newMeshFactory: newDaemonTestMeshFactory,
			},
		)
	}()
	waitForDaemonTestStatusOrExit(t, endpoint, runDone)
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runDaemon() after cancellation: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runDaemon() did not complete graceful shutdown")
	}

	reopened, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: daemonTestVerifyBootID,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(after graceful shutdown): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	waitForDaemonTestLeader(t, reopened)
}

func TestShutdownDaemonComponentsClosesConsensusBeforeWaiting(
	t *testing.T,
) {
	trace := &daemonShutdownTrace{}
	consensus := &recordingDaemonConsensus{trace: trace}
	first := &recordingDaemonComponent{name: "first", trace: trace}
	second := &recordingDaemonComponent{name: "second", trace: trace}

	err := shutdownDaemonComponents(
		consensus,
		func() error {
			trace.events = append(trace.events, "server.join")
			return nil
		},
		first,
		second,
	)
	if err != nil {
		t.Fatalf("shutdownDaemonComponents(): %v", err)
	}
	want := []string{
		"first.begin",
		"second.begin",
		"consensus.close",
		"server.join",
		"first.wait",
		"second.wait",
	}
	if !reflect.DeepEqual(trace.events, want) {
		t.Fatalf("shutdown order = %#v, want %#v", trace.events, want)
	}
}

func TestDaemonServerExitAndJoinFailClosed(t *testing.T) {
	t.Run("unexpected clean exit", func(t *testing.T) {
		err := daemonServerExitError(
			daemonServerResult{name: "peer ingress"},
			nil,
		)
		if !errors.Is(err, errDaemonServerStopped) {
			t.Fatalf("daemonServerExitError() = %v", err)
		}
	})
	t.Run("parent cancellation", func(t *testing.T) {
		err := daemonServerExitError(
			daemonServerResult{
				name: "peer ingress",
				err:  errors.New("late failure"),
			},
			context.Canceled,
		)
		if err != nil {
			t.Fatalf("daemonServerExitError() = %v, want nil", err)
		}
	})
	t.Run("join preserves unexpected failure", func(t *testing.T) {
		serveErr := errors.New("serve failed")
		results := make(chan daemonServerResult, 2)
		results <- daemonServerResult{
			name: "local IPC",
			err:  context.Canceled,
		}
		results <- daemonServerResult{
			name: "peer ingress",
			err:  serveErr,
		}
		err := joinDaemonServers(results, 0, 2, time.Second)
		if !errors.Is(err, serveErr) {
			t.Fatalf("joinDaemonServers() = %v", err)
		}
	})
	t.Run("join is bounded", func(t *testing.T) {
		results := make(chan daemonServerResult)
		err := joinDaemonServers(results, 0, 1, time.Millisecond)
		if !errors.Is(err, errDaemonServerShutdown) {
			t.Fatalf("joinDaemonServers() = %v", err)
		}
	})
}

func TestNilDaemonMeshFactoryRejectsTypedNil(t *testing.T) {
	var typedNil *daemonTestMeshFactory
	if !nilDaemonMeshFactory(typedNil) {
		t.Fatal("nilDaemonMeshFactory() accepted a typed nil")
	}
	if nilDaemonMeshFactory(&daemonTestMeshFactory{
		deviceID: daemonMeshTestDeviceID('9'),
	}) {
		t.Fatal("nilDaemonMeshFactory() rejected a concrete factory")
	}
}

func TestParseDaemonOptionsRejectsIncompleteOrRelativeInput(t *testing.T) {
	endpoint := daemonTestEndpoint(t)
	root := t.TempDir()
	valid := []string{
		"--foreground",
		"--state", filepath.Join(root, "state.db"),
		"--consensus-dir", filepath.Join(root, "consensus"),
		"--endpoint", endpoint.String(),
		"--session", string(daemonTestSessionID),
		"--workspace", string(daemonTestWorkspaceID),
	}
	options, err := parseDaemonOptions(valid, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseDaemonOptions(valid): %v", err)
	}
	if options.sessionID != daemonTestSessionID ||
		options.workspaceID != daemonTestWorkspaceID ||
		options.endpoint.String() != endpoint.String() {
		t.Fatalf("parsed options = %#v", options)
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing foreground", valid[1:]},
		{
			"relative state",
			replaceDaemonTestFlag(valid, "--state", "state.db"),
		},
		{
			"invalid session",
			replaceDaemonTestFlag(valid, "--session", "not-a-session"),
		},
		{"positional", append(append([]string{}, valid...), "extra")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDaemonOptions(
				test.args,
				&bytes.Buffer{},
			); err == nil {
				t.Fatal("parseDaemonOptions() succeeded")
			}
		})
	}
}

// TestDaemonProcessHelper executes the production daemon composition in a
// separate process. The parent terminates it without running defers.
func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv("CODECOMM_TEST_DAEMON_HELPER") != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator == len(os.Args)-1 {
		t.Fatal("missing helper daemon arguments")
	}
	options, err := parseDaemonOptions(
		os.Args[separator+1:],
		os.Stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	bootID := domain.UUIDv7(os.Getenv("CODECOMM_TEST_BOOT_ID"))
	if !bootID.Valid() {
		t.Fatal("invalid helper boot ID")
	}
	_, privateKey, _ := daemonTestInitialState(t)
	err = runDaemon(
		context.Background(),
		options,
		daemonDependencies{
			loadIdentity: func(
				context.Context,
			) (identityHandle, []byte, error) {
				return testIdentityHandle{}, bytes.Clone(privateKey), nil
			},
			newBootID: func() (domain.UUIDv7, error) {
				return bootID, nil
			},
			newMeshFactory: newDaemonMeshTransportFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}

type testIdentityHandle struct{}

func (testIdentityHandle) Close() error {
	return nil
}

func (testIdentityHandle) Get(
	context.Context,
	credentialstore.Reference,
) ([]byte, error) {
	return nil, credentialstore.ErrNotFound
}

func (testIdentityHandle) Create(
	context.Context,
	credentialstore.Reference,
	[]byte,
) error {
	return nil
}

func (testIdentityHandle) Delete(
	context.Context,
	credentialstore.Reference,
) error {
	return nil
}

type daemonTestProcess struct {
	command *exec.Cmd
	stderr  *bytes.Buffer
}

func startDaemonTestProcess(
	t *testing.T,
	statePath, consensusDir string,
	endpoint ipc.Endpoint,
	bootID domain.UUIDv7,
) *daemonTestProcess {
	t.Helper()
	stderr := &bytes.Buffer{}
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestDaemonProcessHelper$",
		"--",
		"--foreground",
		"--state", statePath,
		"--consensus-dir", consensusDir,
		"--endpoint", endpoint.String(),
		"--session", string(daemonTestSessionID),
		"--workspace", string(daemonTestWorkspaceID),
	)
	command.Env = append(
		daemonTestEnvironment(os.Environ()),
		"CODECOMM_TEST_DAEMON_HELPER=1",
		"CODECOMM_TEST_BOOT_ID="+string(bootID),
	)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start daemon helper: %v", err)
	}
	process := &daemonTestProcess{command: command, stderr: stderr}
	t.Cleanup(func() {
		if process.command != nil && process.command.Process != nil {
			_ = process.command.Process.Kill()
			_ = process.command.Wait()
		}
	})
	return process
}

func (process *daemonTestProcess) kill(t *testing.T) {
	t.Helper()
	if process == nil ||
		process.command == nil ||
		process.command.Process == nil {
		t.Fatal("daemon helper is not running")
	}
	if err := process.command.Process.Kill(); err != nil {
		t.Fatalf("kill daemon helper: %v\nstderr: %s", err, process.stderr)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- process.command.Wait()
	}()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("daemon helper did not exit after kill\nstderr: %s", process.stderr)
	}
	process.command = nil
}

func waitForDaemonTestStatus(
	t *testing.T,
	endpoint ipc.Endpoint,
) ui.Snapshot {
	return waitForDaemonTestStatusOrExit(t, endpoint, nil)
}

func waitForDaemonTestStatusOrExit(
	t *testing.T,
	endpoint ipc.Endpoint,
	runDone <-chan error,
) ui.Snapshot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if runDone != nil {
			select {
			case err := <-runDone:
				t.Fatalf(
					"daemon exited before becoming ready: %v",
					err,
				)
			default:
			}
		}
		ctx, cancel := context.WithTimeout(
			context.Background(),
			500*time.Millisecond,
		)
		client, err := ui.DialOperator(ctx, ui.OperatorDialOptions{
			Endpoint:    endpoint,
			SessionID:   daemonTestSessionID,
			WorkspaceID: daemonTestWorkspaceID,
		})
		if err == nil {
			var snapshot ui.Snapshot
			snapshot, err = client.Status(ctx)
			closeErr := client.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil &&
				snapshot.Consensus.StrongWrites == "available" {
				cancel()
				return snapshot
			}
			if err == nil {
				err = fmt.Errorf(
					"strong writes are %s",
					snapshot.Consensus.StrongWrites,
				)
			}
		}
		cancel()
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("daemon status did not become ready: %v", lastErr)
	return ui.Snapshot{}
}

type daemonShutdownTrace struct {
	events          []string
	consensusClosed bool
}

type recordingDaemonConsensus struct {
	trace *daemonShutdownTrace
}

func (consensus *recordingDaemonConsensus) Close() error {
	consensus.trace.events = append(
		consensus.trace.events,
		"consensus.close",
	)
	consensus.trace.consensusClosed = true
	return nil
}

type recordingDaemonComponent struct {
	name  string
	trace *daemonShutdownTrace
}

type daemonTestMeshFactory struct {
	deviceID domain.DeviceID
}

type daemonTestProofTransport struct {
	consensus.RaftTransport
}

func newDaemonTestMeshFactory(
	_ daemonOptions,
	deviceID domain.DeviceID,
	_ tls.Certificate,
) (daemonConsensusTransportFactory, error) {
	if !deviceID.Valid() {
		return nil, errInvalidDaemonDependencies
	}
	return &daemonTestMeshFactory{deviceID: deviceID}, nil
}

func (factory *daemonTestMeshFactory) Build(
	consensus.ConsensusTransportGate,
) (consensus.RaftTransport, error) {
	if factory == nil || !factory.deviceID.Valid() {
		return nil, errInvalidDaemonDependencies
	}
	_, value := raft.NewInmemTransport(
		raft.ServerAddress(factory.deviceID),
	)
	return &daemonTestProofTransport{RaftTransport: value}, nil
}

func (*daemonTestProofTransport) RequestConsensusProof(
	context.Context,
	domain.DeviceID,
	[]byte,
) (transport.ConsensusControlResponse, error) {
	return transport.ConsensusControlResponse{},
		transport.ErrConsensusPeerUnreachable
}

func (*daemonTestMeshFactory) NewIngress(
	context.Context,
	daemonOptions,
	*consensus.Node,
	transport.ContentCertificateProvider,
	transport.ConnectionHandler,
	transport.ConnectionHandler,
	func(context.Context, netip.AddrPort) (net.Listener, error),
) (*transport.Ingress, error) {
	return nil, nil
}

func (*daemonTestMeshFactory) ClearIdentityCertificate() {}

func (*daemonTestMeshFactory) ConsensusRoutes() *transport.ConsensusRouteTable {
	return nil
}

func (*daemonTestMeshFactory) SetAuthenticatedConnectivity(
	transport.ConsensusAuthenticatedDialObserver,
	daemonConnectivityNotifier,
) error {
	return nil
}

func daemonTestEnvironment(base []string) []string {
	result := make([]string, 0, len(base)+1)
	var settings []string
	for _, entry := range base {
		if !strings.HasPrefix(entry, "GODEBUG=") {
			result = append(result, entry)
			continue
		}
		for _, setting := range strings.Split(
			strings.TrimPrefix(entry, "GODEBUG="),
			",",
		) {
			if setting != "" &&
				!strings.HasPrefix(setting, "http2xconnect=") {
				settings = append(settings, setting)
			}
		}
	}
	settings = append(settings, "http2xconnect=1")
	return append(result, "GODEBUG="+strings.Join(settings, ","))
}

func (component *recordingDaemonComponent) BeginClose() error {
	component.trace.events = append(
		component.trace.events,
		component.name+".begin",
	)
	return nil
}

func (component *recordingDaemonComponent) Wait() error {
	if !component.trace.consensusClosed {
		return errors.New("component waited before consensus closed")
	}
	component.trace.events = append(
		component.trace.events,
		component.name+".wait",
	)
	return nil
}

func assertDaemonStatusMatchesView(
	t *testing.T,
	snapshot ui.Snapshot,
	view store.StateView,
) {
	t.Helper()
	if snapshot.Session.EventChainIndex != view.Heads.ChainIndex ||
		snapshot.Session.ResultIndex != view.Heads.ResultIndex ||
		snapshot.Session.SessionID != string(view.SessionID) ||
		snapshot.Session.WorkspaceID != string(view.WorkspaceID) ||
		snapshot.Consensus.StrongWrites != "available" {
		t.Fatalf("daemon status = %#v, baseline = %#v", snapshot, view)
	}
}

func daemonTestInitialState(
	t *testing.T,
) (store.InitialState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	identityPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x31}, ed25519.SeedSize),
	)
	identityPublicKey := bytes.Clone(
		identityPrivateKey.Public().(ed25519.PublicKey),
	)
	deviceID, err := device.DeriveID(identityPublicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: identityPublicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	target, err := voterset.New(
		daemonTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	recoveryPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	rawGenesis, err := json.Marshal(map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(
			recoveryPrivateKey.Public().(ed25519.PublicKey),
		),
		"session_id":   daemonTestSessionID,
		"workspace_id": daemonTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("json.Marshal(genesis): %v", err)
	}
	genesis, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		t.Fatalf("CanonicalizeSignedObject(genesis): %v", err)
	}
	return store.InitialState{
		SessionID:               daemonTestSessionID,
		WorkspaceID:             daemonTestWorkspaceID,
		GenesisJSON:             genesis,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			AuditCounters: []auditcounter.Counter{{DeviceID: deviceID}},
			PlanCurrent: []plan.Current{{
				SessionID:     daemonTestSessionID,
				EntityVersion: 1,
			}},
			Devices:  []device.Device{member},
			VoterSet: []voterset.Set{target},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        daemonTestSessionID,
				VoterDeviceIDs:   []domain.DeviceID{deviceID},
				VoterSetVersion:  1,
				ActivationSource: credentialauthority.ActivationGenesis,
			}},
			CanonicalRefs: []publication.CanonicalRef{{
				RefName: publication.CanonicalRefName,
				CommitOID: domain.GitOID(
					"sha1:" + strings.Repeat("1", 40),
				),
				EntityVersion: 1,
			}},
			SessionPolicy: []policy.Policy{{
				SessionID:     daemonTestSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	}, identityPrivateKey, deviceID
}

func daemonTestTaskEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		deviceID,
		daemonTestSetupBootID,
	)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding(): %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"priority": 2,
		"title":    "survive daemon process kill",
	})
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindTaskCreated,
			EntityID: event.StringEntityID(string(daemonTestTaskID)),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        daemonTestEventID,
			SessionID:      daemonTestSessionID,
			WorkspaceID:    daemonTestWorkspaceID,
			CreatedAt:      daemonTestTimestamp,
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func waitForDaemonTestLeader(
	t *testing.T,
	node *consensus.SingleNode,
) {
	t.Helper()
	if err := node.WaitForLeader(daemonTestContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
}

func daemonTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func daemonTestEndpoint(t *testing.T) ipc.Endpoint {
	t.Helper()
	var address string
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\codecomm-daemon-test-` +
			strings.ReplaceAll(uuid.NewString(), "-", "")
	} else {
		directory, err := os.MkdirTemp("", "ccd-")
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
		t.Fatalf("ipc.ParseEndpoint(%q): %v", address, err)
	}
	return endpoint
}

func replaceDaemonTestFlag(
	args []string,
	name, replacement string,
) []string {
	result := append([]string(nil), args...)
	for index := range result {
		if result[index] == name && index+1 < len(result) {
			result[index+1] = replacement
			return result
		}
	}
	panic(fmt.Sprintf("test flag %q not found", name))
}
