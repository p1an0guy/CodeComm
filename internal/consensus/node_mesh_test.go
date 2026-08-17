package consensus

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestOpenNodeUsesInjectedDeviceAddressedTransport(t *testing.T) {
	root := t.TempDir()
	initial, _, deviceID := nodeTestInitialState(t)
	_, transport := raft.NewInmemTransport(
		raft.ServerAddress(deviceID),
	)
	ownedTransport := &countingRaftTransport{Transport: transport}
	node, err := OpenNode(context.Background(), NodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		TransportFactory: func(ConsensusTransportGate) (
			RaftTransport,
			error,
		) {
			return ownedTransport, nil
		},
		BootstrapVoterDeviceIDs: []domain.DeviceID{deviceID},
		Clock:                   nodeTestClock(),
		RaftConfig:              nodeTestRaftConfig(),
	})
	if err != nil {
		t.Fatalf("OpenNode(): %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.WaitForLeader(testContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
	if got := node.Address(); got != raft.ServerAddress(deviceID) {
		t.Fatalf("Address() = %q, want %q", got, deviceID)
	}
	record, found, err := node.state.CommittedRaftConfiguration(
		context.Background(),
	)
	if err != nil || !found || record.LogIndex != 1 {
		t.Fatalf(
			"CommittedRaftConfiguration() = (%#v, %t, %v)",
			record,
			found,
			err,
		)
	}
	committed := node.fsm.committedConfiguration()
	if committed == nil ||
		committed.Index != 1 ||
		!committed.contains(deviceID) {
		t.Fatalf("FSM committed configuration = %#v", committed)
	}

	future := node.raft.GetConfiguration()
	if err := waitFuture(testContext(t), future); err != nil {
		t.Fatalf("GetConfiguration(): %v", err)
	}
	configuration := future.Configuration()
	if len(configuration.Servers) != 1 ||
		configuration.Servers[0] != (raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(deviceID),
			Address:  raft.ServerAddress(deviceID),
		}) {
		t.Fatalf("configuration = %#v", configuration)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if got := ownedTransport.closes.Load(); got != 1 {
		t.Fatalf("transport Close calls = %d, want 1", got)
	}
}

func TestOpenNodeClosesOwnedTransportAfterBootstrapFailure(t *testing.T) {
	root := t.TempDir()
	initial, _, deviceID := nodeTestInitialState(t)
	_, delegate := raft.NewInmemTransport(
		raft.ServerAddress(deviceID),
	)
	transport := &countingRaftTransport{Transport: delegate}
	_, err := OpenNode(context.Background(), NodeOptions{
		ServerID:     deviceID,
		StatePath:    filepath.Join(root, "state", "state.db"),
		ConsensusDir: filepath.Join(root, "consensus"),
		OriginBootID: nodeTestBootID1,
		InitialState: &initial,
		TransportFactory: func(ConsensusTransportGate) (
			RaftTransport,
			error,
		) {
			return transport, nil
		},
		Clock:      nodeTestClock(),
		RaftConfig: nodeTestRaftConfig(),
	})
	if !errors.Is(err, ErrInvalidBootstrapTopology) {
		t.Fatalf(
			"OpenNode() error = %v, want ErrInvalidBootstrapTopology",
			err,
		)
	}
	if got := transport.closes.Load(); got != 1 {
		t.Fatalf("transport Close calls = %d, want 1", got)
	}
}

func TestOpenNodeSeedsMissingConfigurationFromAppliedLog(t *testing.T) {
	root := t.TempDir()
	initial, privateKey, deviceID := nodeTestInitialState(t)
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	open := func(
		initialState *store.InitialState,
		bootID domain.UUIDv7,
	) (*Node, error) {
		_, transport := raft.NewInmemTransport(
			raft.ServerAddress(deviceID),
		)
		return OpenNode(context.Background(), NodeOptions{
			ServerID:                deviceID,
			StatePath:               statePath,
			ConsensusDir:            consensusDir,
			OriginBootID:            bootID,
			InitialState:            initialState,
			BootstrapVoterDeviceIDs: []domain.DeviceID{deviceID},
			Clock:                   nodeTestClock(),
			RaftConfig:              nodeTestRaftConfig(),
			TransportFactory: func(ConsensusTransportGate) (
				RaftTransport,
				error,
			) {
				return transport, nil
			},
		})
	}
	node, err := open(&initial, nodeTestBootID1)
	if err != nil {
		t.Fatalf("OpenNode(initial): %v", err)
	}
	if err := node.WaitForLeader(testContext(t)); err != nil {
		_ = node.Close()
		t.Fatalf("WaitForLeader(): %v", err)
	}
	signed := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"configuration migration evidence",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		_ = node.Close()
		t.Fatalf("Apply(): %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("Close(initial): %v", err)
	}
	tamperSQLite(
		t,
		statePath,
		"DELETE FROM raft_committed_configuration;",
	)

	reopened, err := open(nil, nodeTestBootID2)
	if err != nil {
		t.Fatalf("OpenNode(migrated): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	record, found, err := reopened.state.CommittedRaftConfiguration(
		context.Background(),
	)
	if err != nil || !found || record.LogIndex != 1 {
		t.Fatalf(
			"CommittedRaftConfiguration() = (%#v, %t, %v)",
			record,
			found,
			err,
		)
	}
}

func TestMeshBootstrapConfigurationRequiresCanonicalVoterSet(
	t *testing.T,
) {
	ids := []domain.DeviceID{
		meshTestDeviceID('1'),
		meshTestDeviceID('2'),
		meshTestDeviceID('3'),
	}
	valid, err := meshBootstrapConfiguration(ids[1], ids)
	if err != nil {
		t.Fatalf("meshBootstrapConfiguration(valid): %v", err)
	}
	if len(valid.Servers) != len(ids) {
		t.Fatalf("servers = %d, want %d", len(valid.Servers), len(ids))
	}
	for index, server := range valid.Servers {
		if server.Suffrage != raft.Voter ||
			server.ID != raft.ServerID(ids[index]) ||
			server.Address != raft.ServerAddress(ids[index]) {
			t.Fatalf("server %d = %#v", index, server)
		}
	}

	tests := []struct {
		name  string
		local domain.DeviceID
		ids   []domain.DeviceID
	}{
		{"even count", ids[0], ids[:2]},
		{"unsorted", ids[0], []domain.DeviceID{ids[1], ids[0], ids[2]}},
		{"duplicate", ids[0], []domain.DeviceID{ids[0], ids[0], ids[2]}},
		{"malformed", ids[0], []domain.DeviceID{ids[0], "bad", ids[2]}},
		{"local absent", meshTestDeviceID('4'), ids},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := meshBootstrapConfiguration(
				test.local,
				test.ids,
			); !errors.Is(err, ErrInvalidBootstrapTopology) {
				t.Fatalf(
					"meshBootstrapConfiguration() error = %v",
					err,
				)
			}
		})
	}
}

func TestDeviceAddressedSnapshotConfigurationRejectsAmbiguity(
	t *testing.T,
) {
	first := meshTestDeviceID('1')
	second := meshTestDeviceID('2')
	valid := raft.Configuration{Servers: []raft.Server{
		{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(first),
			Address:  raft.ServerAddress(first),
		},
		{
			Suffrage: raft.Nonvoter,
			ID:       raft.ServerID(second),
			Address:  raft.ServerAddress(second),
		},
	}}
	if err := validateDeviceAddressedSnapshotConfiguration(valid); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*raft.Configuration)
	}{
		{
			"mismatched address",
			func(value *raft.Configuration) {
				value.Servers[1].Address = raft.ServerAddress(first)
			},
		},
		{
			"duplicate ID",
			func(value *raft.Configuration) {
				value.Servers[1].ID = raft.ServerID(first)
				value.Servers[1].Address = raft.ServerAddress(first)
			},
		},
		{
			"staging suffrage",
			func(value *raft.Configuration) {
				value.Servers[1].Suffrage = raft.Staging
			},
		},
		{
			"no voter",
			func(value *raft.Configuration) {
				value.Servers[0].Suffrage = raft.Nonvoter
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := valid.Clone()
			test.mutate(&configuration)
			if err := validateDeviceAddressedSnapshotConfiguration(
				configuration,
			); !errors.Is(err, ErrInvalidRaftTopology) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestColdStartAllowsOnlyCommitProbeReplication(t *testing.T) {
	tests := []struct {
		name        string
		commitIndex uint64
		commitProbe bool
		want        bool
	}{
		{"cold ordinary", 0, false, false},
		{"cold commit probe", 0, true, true},
		{"committed ordinary", 1, false, true},
		{"committed commit probe", 1, true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := replicationClassAllowed(
				test.commitIndex,
				test.commitProbe,
			); got != test.want {
				t.Fatalf(
					"replicationClassAllowed(%d, %t) = %t, want %t",
					test.commitIndex,
					test.commitProbe,
					got,
					test.want,
				)
			}
		})
	}
}

func TestCommittedConfigurationRequiresExactRaftEvidence(t *testing.T) {
	initial, _, _ := nodeTestInitialState(t)
	state, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}

	firstID := meshTestDeviceID('1')
	first := raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(firstID),
		Address:  raft.ServerAddress(firstID),
	}}}
	encoded, err := encodeRaftConfiguration(first)
	if err != nil {
		t.Fatalf("encodeRaftConfiguration(): %v", err)
	}
	if _, err := state.StoreCommittedRaftConfiguration(
		context.Background(),
		1,
		encoded,
	); err != nil {
		t.Fatalf("StoreCommittedRaftConfiguration(): %v", err)
	}
	logs := raft.NewInmemStore()
	if err := logs.StoreLog(&raft.Log{
		Index: 1,
		Term:  1,
		Type:  raft.LogConfiguration,
		Data:  raft.EncodeConfiguration(first),
	}); err != nil {
		t.Fatalf("StoreLog(first): %v", err)
	}
	snapshots := raft.NewInmemSnapshotStore()
	if err := verifyCommittedConfigurationEvidence(
		context.Background(),
		logs,
		snapshots,
		state,
	); err != nil {
		t.Fatalf("verify exact evidence: %v", err)
	}

	secondID := meshTestDeviceID('2')
	second := raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(secondID),
		Address:  raft.ServerAddress(secondID),
	}}}
	if err := logs.StoreLog(&raft.Log{
		Index: 1,
		Term:  1,
		Type:  raft.LogConfiguration,
		Data:  raft.EncodeConfiguration(second),
	}); err != nil {
		t.Fatalf("StoreLog(second): %v", err)
	}
	if err := verifyCommittedConfigurationEvidence(
		context.Background(),
		logs,
		snapshots,
		state,
	); !errors.Is(err, ErrRaftLogCoverage) {
		t.Fatalf("mismatched evidence error = %v", err)
	}
}

func TestAuthorizationChangeSubscriptionsAreSingleConsumer(t *testing.T) {
	gate := newNodeTransportGate(raft.Configuration{})
	t.Cleanup(gate.close)
	first := gate.AuthorizationChanges()
	select {
	case _, open := <-first:
		if !open {
			t.Fatal("first authorization subscription was closed")
		}
	default:
	}
	second := gate.AuthorizationChanges()
	select {
	case _, open := <-second:
		if open {
			t.Fatal("second authorization subscription remained open")
		}
	default:
		t.Fatal("second authorization subscription did not fail closed")
	}
}

type countingRaftTransport struct {
	raft.Transport
	closes atomic.Int32
}

func (transport *countingRaftTransport) Close() error {
	transport.closes.Add(1)
	if closeable, ok := transport.Transport.(raft.WithClose); ok {
		return closeable.Close()
	}
	return nil
}

func meshTestDeviceID(digit byte) domain.DeviceID {
	return domain.DeviceID("cc1" + strings.Repeat(string(digit), 64))
}

var _ RaftTransport = (*countingRaftTransport)(nil)
