package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

type configurationCoverageCollector struct {
	privateKeys  map[domain.DeviceID]ed25519.PrivateKey
	entered      chan struct{}
	release      chan struct{}
	enterOnce    sync.Once
	afterCollect func()
}

func (collector *configurationCoverageCollector) CollectCanonicalCoverage(
	ctx context.Context,
	requirement canonicalcoverage.Requirement,
) ([][]byte, error) {
	if collector.entered != nil {
		collector.enterOnce.Do(func() { close(collector.entered) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-collector.release:
		}
	}
	target := requirement.VoterSet.VoterDeviceIDs()
	required := len(target)/2 + 1
	receipts := make([][]byte, 0, required)
	for _, deviceID := range target {
		privateKey, exists := collector.privateKeys[deviceID]
		if !exists {
			continue
		}
		receipt, err := signConfigurationCoverageReceipt(
			requirement,
			deviceID,
			privateKey,
		)
		if err != nil {
			return nil, err
		}
		receipts = append(
			receipts,
			receipt,
		)
		if len(receipts) == required {
			break
		}
	}
	if collector.afterCollect != nil {
		collector.afterCollect()
	}
	return receipts, nil
}

type configurationChangeFixture struct {
	node         *Node
	ownerID      domain.DeviceID
	ownerPrivate ed25519.PrivateKey
	target       []domain.DeviceID
	stageID      domain.DeviceID
	collector    *configurationCoverageCollector
}

func TestConfigurationChangeRequiresCanonicalCoverage(t *testing.T) {
	fixture := openConfigurationChangeFixture(t, false)
	before := raftConfiguration(t, fixture.node)
	_, err := fixture.node.changeRaftConfiguration(
		testContext(t),
		raftConfigurationChange{
			kind:     raftChangeAddNonvoter,
			deviceID: fixture.stageID,
		},
	)
	if !errors.Is(err, canonicalcoverage.ErrObjectCoverageDegraded) ||
		!errors.Is(err, canonicalcoverage.ErrCollectorUnavailable) {
		t.Fatalf("changeRaftConfiguration() error = %v", err)
	}
	after := raftConfiguration(t, fixture.node)
	if after.Index != before.Index ||
		!sameRaftConfiguration(after.Configuration, before.Configuration) {
		t.Fatal("missing coverage changed the Raft configuration")
	}
}

func TestConfigurationChangeStagesOneCoveredTarget(t *testing.T) {
	fixture := openConfigurationChangeFixture(t, true)
	before := raftConfiguration(t, fixture.node)
	index, err := fixture.node.changeRaftConfiguration(
		testContext(t),
		raftConfigurationChange{
			kind:     raftChangeAddNonvoter,
			deviceID: fixture.stageID,
		},
	)
	if err != nil {
		t.Fatalf("changeRaftConfiguration(): %v", err)
	}
	if index <= before.Index {
		t.Fatalf("configuration index = %d, want > %d", index, before.Index)
	}
	if err := fixture.node.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(): %v", err)
	}
	after := raftConfiguration(t, fixture.node)
	if after.Index != index {
		t.Fatalf("configuration index = %d, want %d", after.Index, index)
	}
	assertRaftServer(
		t,
		after.Configuration,
		fixture.stageID,
		raft.Nonvoter,
	)

	secondIndex, err := fixture.node.changeRaftConfiguration(
		testContext(t),
		raftConfigurationChange{
			kind:     raftChangeAddNonvoter,
			deviceID: fixture.stageID,
		},
	)
	if !errors.Is(err, ErrStaleConfigurationChange) || secondIndex != 0 {
		t.Fatalf(
			"repeated changeRaftConfiguration() = (%d, %v)",
			secondIndex,
			err,
		)
	}
	final := raftConfiguration(t, fixture.node)
	if final.Index != after.Index {
		t.Fatalf(
			"repeated change advanced configuration %d -> %d",
			after.Index,
			final.Index,
		)
	}
}

func TestConfigurationCollectionDoesNotBlockApplyAndFreshnessWins(
	t *testing.T,
) {
	fixture := openConfigurationChangeFixture(t, true)
	fixture.collector.entered = make(chan struct{})
	fixture.collector.release = make(chan struct{})

	changeDone := make(chan error, 1)
	changeContext := testContext(t)
	go func() {
		_, err := fixture.node.changeRaftConfiguration(
			changeContext,
			raftConfigurationChange{
				kind:     raftChangeAddNonvoter,
				deviceID: fixture.stageID,
			},
		)
		changeDone <- err
	}()
	select {
	case <-fixture.collector.entered:
	case <-testContext(t).Done():
		t.Fatal("coverage collection did not start")
	}

	revert := configurationVoterSetEvent(
		t,
		fixture.ownerPrivate,
		fixture.ownerID,
		[]domain.DeviceID{fixture.ownerID},
		2,
		nodeTestEventID2,
		2,
	)
	result, err := fixture.node.Apply(testContext(t), revert)
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("Apply(concurrent target change) = (%#v, %v)", result, err)
	}
	close(fixture.collector.release)

	select {
	case err := <-changeDone:
		if !errors.Is(err, canonicalcoverage.ErrCoverageChanged) ||
			!errors.Is(err, canonicalcoverage.ErrObjectCoverageDegraded) {
			t.Fatalf("changeRaftConfiguration(stale coverage) error = %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("stale configuration change did not return")
	}
	configuration := raftConfiguration(t, fixture.node)
	if len(configuration.Configuration.Servers) != 1 {
		t.Fatalf(
			"stale coverage changed configuration: %#v",
			configuration.Configuration,
		)
	}
}

func TestConfigurationCollectionIsCanceledByNodeClose(t *testing.T) {
	fixture := openConfigurationChangeFixture(t, true)
	fixture.collector.entered = make(chan struct{})
	fixture.collector.release = make(chan struct{})

	changeDone := make(chan error, 1)
	go func() {
		_, err := fixture.node.changeRaftConfiguration(
			context.Background(),
			raftConfigurationChange{
				kind:     raftChangeAddNonvoter,
				deviceID: fixture.stageID,
			},
		)
		changeDone <- err
	}()
	select {
	case <-fixture.collector.entered:
	case <-testContext(t).Done():
		t.Fatal("coverage collection did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- fixture.node.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close(): %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("Close() remained pinned by coverage collection")
	}
	select {
	case err := <-changeDone:
		if !errors.Is(err, context.Canceled) &&
			!errors.Is(err, ErrNodeClosed) {
			t.Fatalf("changeRaftConfiguration() after close error = %v", err)
		}
	case <-testContext(t).Done():
		t.Fatal("configuration change did not observe node close")
	}
}

func TestConfigurationChangeRejectsLeadershipEpochChange(t *testing.T) {
	fixture := openConfigurationChangeFixture(t, true)
	before := raftConfiguration(t, fixture.node)
	originalReader := fixture.node.readLeadershipEpoch
	var changed bool
	fixture.collector.afterCollect = func() {
		changed = true
	}
	fixture.node.readLeadershipEpoch = func() (
		raftLeadershipEpoch,
		error,
	) {
		epoch, err := originalReader()
		if err == nil && changed {
			epoch.term++
		}
		return epoch, err
	}

	_, err := fixture.node.changeRaftConfiguration(
		testContext(t),
		raftConfigurationChange{
			kind:     raftChangeAddNonvoter,
			deviceID: fixture.stageID,
		},
	)
	if !errors.Is(err, ErrLeadershipEpochChanged) {
		t.Fatalf("changeRaftConfiguration() error = %v", err)
	}
	after := raftConfiguration(t, fixture.node)
	if after.Index != before.Index ||
		!sameRaftConfiguration(after.Configuration, before.Configuration) {
		t.Fatal("leadership-epoch change altered the Raft configuration")
	}
}

func openConfigurationChangeFixture(
	t *testing.T,
	withCollector bool,
) configurationChangeFixture {
	t.Helper()

	initial, ownerPrivate, ownerID := nodeTestInitialState(t)
	privateKeys := map[domain.DeviceID]ed25519.PrivateKey{
		ownerID: bytes.Clone(ownerPrivate),
	}
	target := []domain.DeviceID{ownerID}
	for _, seedByte := range []byte{0x32, 0x33} {
		privateKey := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{seedByte}, ed25519.SeedSize),
		)
		publicKey := bytes.Clone(
			privateKey.Public().(ed25519.PublicKey),
		)
		deviceID, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatalf("device.DeriveID(): %v", err)
		}
		privateKeys[deviceID] = privateKey
		target = append(target, deviceID)
		initial.Projections.Devices = append(
			initial.Projections.Devices,
			device.Device{
				ID:                deviceID,
				Role:              device.RoleEditor,
				IdentityPublicKey: publicKey,
				DaemonVersion:     "0.1.0",
				MaxApplyLevel:     1,
				Status:            device.StatusActive,
				EntityVersion:     1,
			},
		)
		initial.Projections.AuditCounters = append(
			initial.Projections.AuditCounters,
			auditcounter.Counter{DeviceID: deviceID},
		)
	}
	sort.Slice(target, func(left, right int) bool {
		return target[left] < target[right]
	})
	collector := &configurationCoverageCollector{privateKeys: privateKeys}
	var configuredCollector canonicalcoverage.ReceiptCollector
	if withCollector {
		configuredCollector = collector
	}

	root := t.TempDir()
	_, transport := raft.NewInmemTransport(raft.ServerAddress(ownerID))
	node, err := OpenNode(context.Background(), NodeOptions{
		ServerID:                ownerID,
		StatePath:               filepath.Join(root, "state", "state.db"),
		ConsensusDir:            filepath.Join(root, "consensus"),
		OriginBootID:            nodeTestBootID1,
		InitialState:            &initial,
		BootstrapVoterDeviceIDs: []domain.DeviceID{ownerID},
		CanonicalCoverage:       configuredCollector,
		Clock:                   nodeTestClock(),
		RaftConfig:              nodeTestRaftConfig(),
		TransportFactory: func(ConsensusTransportGate) (
			RaftTransport,
			error,
		) {
			return transport, nil
		},
	})
	if err != nil {
		t.Fatalf("OpenNode(): %v", err)
	}
	t.Cleanup(func() {
		_ = node.Close()
		for _, privateKey := range privateKeys {
			clear(privateKey)
		}
	})
	if err := node.WaitForLeader(testContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}

	change := configurationVoterSetEvent(
		t,
		ownerPrivate,
		ownerID,
		target,
		1,
		nodeTestEventID1,
		1,
	)
	result, err := node.Apply(testContext(t), change)
	if err != nil ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Outcome.Code != string(reducer.CodeAccepted) {
		t.Fatalf("Apply(voter target) = (%#v, %v)", result, err)
	}
	var stageID domain.DeviceID
	for _, deviceID := range target {
		if deviceID != ownerID {
			stageID = deviceID
			break
		}
	}
	return configurationChangeFixture{
		node:         node,
		ownerID:      ownerID,
		ownerPrivate: ownerPrivate,
		target:       target,
		stageID:      stageID,
		collector:    collector,
	}
}

func configurationVoterSetEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	ownerID domain.DeviceID,
	target []domain.DeviceID,
	expectedVersion uint64,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(ownerID, nodeTestBootID1)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding(): %v", err)
	}
	payload, err := json.Marshal(map[string]any{"voter_set": target})
	if err != nil {
		t.Fatalf("json.Marshal(voter target): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:                  event.KindMembershipVoterSetChanged,
			EntityID:              event.StringEntityID(string(nodeTestSessionID)),
			ExpectedEntityVersion: &expectedVersion,
			Actions:               []event.Action{},
			Payload:               payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      nodeTestTimestamp1,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(voter target): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(voter target): %v", err)
	}
	return signed
}

func signConfigurationCoverageReceipt(
	requirement canonicalcoverage.Requirement,
	voterDeviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) ([]byte, error) {
	subject, err := requirement.Subject()
	if err != nil {
		return nil, err
	}
	unsigned := map[string]any{
		"canonical_ref_version": subject.CanonicalRefVersion,
		"commit_oid":            subject.CommitOID,
		"session_id":            subject.SessionID,
		"voter_device_id":       voterDeviceID,
		"voter_set_version":     subject.VoterSetVersion,
		"workspace_id":          subject.WorkspaceID,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	signedBytes, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, err
	}
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureGitCanonicalCoverage,
		signedBytes,
	)
	if err != nil {
		return nil, err
	}
	unsigned["signature"] = codec.EncodeBase64URL(signature)
	encoded, err = json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func raftConfiguration(
	t *testing.T,
	node *Node,
) *committedRaftConfiguration {
	t.Helper()
	if err := node.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(configuration): %v", err)
	}
	configuration := node.fsm.committedConfiguration()
	if configuration == nil {
		t.Fatal("FSM has no committed configuration")
	}
	return configuration
}

func assertRaftServer(
	t *testing.T,
	configuration raft.Configuration,
	deviceID domain.DeviceID,
	suffrage raft.ServerSuffrage,
) {
	t.Helper()
	for _, server := range configuration.Servers {
		if server.ID == raft.ServerID(deviceID) {
			if server.Address != raft.ServerAddress(deviceID) ||
				server.Suffrage != suffrage {
				t.Fatalf("server %s = %#v", deviceID, server)
			}
			return
		}
	}
	t.Fatalf("configuration omits server %s", deviceID)
}

var _ canonicalcoverage.ReceiptCollector = (*configurationCoverageCollector)(nil)
