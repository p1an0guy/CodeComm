package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	"github.com/ijonahch/codecomm/internal/store"
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
		os.Environ(),
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
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
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
			if err == nil {
				cancel()
				return snapshot
			}
		}
		cancel()
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("daemon status did not become ready: %v", lastErr)
	return ui.Snapshot{}
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
