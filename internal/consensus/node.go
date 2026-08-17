package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"go.etcd.io/bbolt"
)

const (
	raftStoreFilename = "raft.db"
	snapshotRetention = 3
)

var (
	ErrInvalidNodeOptions       = errors.New("consensus: invalid node options")
	ErrInsecureConsensusPath    = errors.New("consensus: insecure storage path")
	ErrRaftStateMissing         = errors.New("consensus: initialized SQLite has no Raft state")
	ErrStateInitialization      = errors.New("consensus: state initialization required")
	ErrSingleVoterTopology      = errors.New("consensus: Phase 2 requires exactly one local voter")
	ErrInvalidBootstrapTopology = errors.New("consensus: invalid bootstrap voter topology")
	ErrInvalidRaftTopology      = errors.New("consensus: invalid device-addressed Raft topology")
	ErrUnexpectedFSMResponse    = errors.New("consensus: unexpected Raft FSM response")
	ErrSnapshotAnchorCoverage   = errors.New("consensus: SQLite does not cover Raft snapshot anchor")
	ErrRaftLogCoverage          = errors.New("consensus: Raft log/snapshot coverage is invalid")
	ErrNodeClosed               = errors.New("consensus: node is closing or closed")
	ErrLineageMismatch          = errors.New("consensus: active lineage differs from expected lineage")
	ErrLineageReentry           = errors.New("consensus: lineage operation cannot reenter its gate")
	ErrPeerAdmissionUnavailable = errors.New("consensus: applied peer admission unavailable")
)

type lineageOperationContextKey struct{}

// SingleNodeOptions owns the complete Phase 2 local consensus runtime.
// InitialState is required only while creating a new state database or
// completing a bootstrap that crashed after writing the first Raft config.
type SingleNodeOptions struct {
	ServerID     domain.DeviceID
	StatePath    string
	ConsensusDir string
	OriginBootID domain.UUIDv7
	InitialState *store.InitialState

	Clock      ApplyClock
	RaftConfig *raft.Config
	LogOutput  io.Writer
}

// RaftTransport is the owned transport boundary required by a consensus node.
type RaftTransport interface {
	raft.Transport
	raft.WithClose
}

// ConsensusTransportGate is the fail-closed authorization capability passed
// to a mesh transport factory before the resulting node exists.
type ConsensusTransportGate interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	AuthorizePeer(domain.DeviceID) error
	AuthorizeReplication(domain.DeviceID) error
	AuthorizeCommitProbe(domain.DeviceID) error
	AuthorizationChanges() <-chan struct{}
	ConsensusControlHandler() http.Handler
}

// RaftTransportFactory constructs the owned transport around a late-bound
// authorization gate.
type RaftTransportFactory func(ConsensusTransportGate) (RaftTransport, error)

// NodeOptions configures a device-addressed mesh node. OpenNode takes
// ownership of a successfully constructed transport and closes it on every
// later return path. BootstrapVoterDeviceIDs is required while creating Raft
// state, completing interrupted initialization, or awaiting the first durable
// committed-configuration callback.
type NodeOptions struct {
	ServerID     domain.DeviceID
	StatePath    string
	ConsensusDir string
	OriginBootID domain.UUIDv7
	InitialState *store.InitialState

	TransportFactory        RaftTransportFactory
	BootstrapVoterDeviceIDs []domain.DeviceID
	CanonicalCoverage       canonicalcoverage.ReceiptCollector

	Clock      ApplyClock
	RaftConfig *raft.Config
	LogOutput  io.Writer
}

// SingleNode is the durable Raft/SQLite runtime. Its historical name remains
// for API compatibility; OpenNode may construct a multi-voter mesh runtime.
type SingleNode struct {
	raft          *raft.Raft
	fsm           *FSM
	state         *store.Store
	stable        *raftboltdb.BoltStore
	snapshots     *raft.FileSnapshotStore
	transport     RaftTransport
	serverID      raft.ServerID
	clock         ApplyClock
	single        bool
	transportGate *nodeTransportGate
	coverageGate  *canonicalcoverage.Gate

	peerAdmissionChangesClaimed atomic.Bool

	monitorStop chan struct{}
	monitorDone chan struct{}

	lifecycleMu  sync.Mutex
	closing      bool
	closeStarted chan struct{}
	active       sync.WaitGroup
	lineageGate  chan struct{}
	raftEnqueue  chan struct{}

	readLeadershipEpoch func() (raftLeadershipEpoch, error)

	fatalOnce sync.Once
	fatalMu   sync.RWMutex
	fatalErr  error
	fatalSet  chan struct{}

	raftShutdownOnce sync.Once
	raftShutdownErr  error

	proposalMu           sync.Mutex
	proposalFlights      map[domain.UUIDv7]*proposalFlight
	proposalReservations map[domain.UUIDv7][]byte

	fsmScanMu                      sync.Mutex
	fsmScannedCommit               uint64
	committedCommandLogIndex       uint64
	committedConfigurationLogIndex uint64

	closeOnce sync.Once
	closeErr  error
}

// Node is the topology-neutral name for the consensus runtime.
type Node = SingleNode

type nodeOpenOptions struct {
	ServerID     domain.DeviceID
	StatePath    string
	ConsensusDir string
	OriginBootID domain.UUIDv7
	InitialState *store.InitialState

	Transport              RaftTransport
	TransportFactory       RaftTransportFactory
	BootstrapConfiguration raft.Configuration
	CanonicalCoverage      canonicalcoverage.ReceiptCollector
	Single                 bool

	Clock      ApplyClock
	RaftConfig *raft.Config
	LogOutput  io.Writer
}

// OpenSingleNode opens durable stores, completes a one-time bootstrap if
// needed, and starts a real loopback Raft node.
func OpenSingleNode(
	ctx context.Context,
	options SingleNodeOptions,
) (_ *SingleNode, err error) {
	if err := validateSingleNodeOptions(ctx, options); err != nil {
		return nil, err
	}
	return openNode(ctx, nodeOpenOptions{
		ServerID:     options.ServerID,
		StatePath:    options.StatePath,
		ConsensusDir: options.ConsensusDir,
		OriginBootID: options.OriginBootID,
		InitialState: options.InitialState,
		Single:       true,
		Clock:        options.Clock,
		RaftConfig:   options.RaftConfig,
		LogOutput:    options.LogOutput,
	})
}

// OpenNode opens a durable device-addressed Raft/SQLite mesh node.
func OpenNode(
	ctx context.Context,
	options NodeOptions,
) (_ *Node, err error) {
	if err := validateNodeOptions(ctx, options); err != nil {
		return nil, err
	}
	bootstrap, err := meshBootstrapConfiguration(
		options.ServerID,
		options.BootstrapVoterDeviceIDs,
	)
	if err != nil {
		return nil, err
	}
	return openNode(ctx, nodeOpenOptions{
		ServerID:               options.ServerID,
		StatePath:              options.StatePath,
		ConsensusDir:           options.ConsensusDir,
		OriginBootID:           options.OriginBootID,
		InitialState:           options.InitialState,
		TransportFactory:       options.TransportFactory,
		BootstrapConfiguration: bootstrap,
		CanonicalCoverage:      options.CanonicalCoverage,
		Clock:                  options.Clock,
		RaftConfig:             options.RaftConfig,
		LogOutput:              options.LogOutput,
	})
}

func openNode(
	ctx context.Context,
	options nodeOpenOptions,
) (_ *SingleNode, err error) {
	transport := options.Transport
	var transportGate *nodeTransportGate
	defer func() {
		if err != nil && !nilRaftTransport(transport) {
			_ = transport.Close()
		}
		if err != nil && transportGate != nil {
			transportGate.close()
		}
	}()

	consensusDir := filepath.Clean(options.ConsensusDir)
	createdDir, err := prepareConsensusDirectory(consensusDir)
	if err != nil {
		return nil, err
	}

	raftPath := filepath.Join(consensusDir, raftStoreFilename)
	_, statErr := os.Lstat(raftPath)
	newRaftFile := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newRaftFile {
		return nil, fmt.Errorf("consensus: inspect Raft store: %w", statErr)
	}
	if statErr == nil {
		info, err := os.Lstat(raftPath)
		if err != nil {
			return nil, fmt.Errorf("consensus: inspect Raft store: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf(
				"%w: Raft store is not a regular file",
				ErrInsecureConsensusPath,
			)
		}
	}

	boltOptions := *bbolt.DefaultOptions
	boltOptions.Timeout = 5 * time.Second
	boltOptions.NoFreelistSync = false
	stable, err := raftboltdb.New(raftboltdb.Options{
		Path:        raftPath,
		BoltOptions: &boltOptions,
		NoSync:      false,
	})
	if err != nil {
		return nil, fmt.Errorf("consensus: open Raft store: %w", err)
	}
	defer func() {
		if err != nil {
			_ = stable.Close()
		}
	}()
	if newRaftFile || createdDir {
		if syncErr := syncConsensusDirectory(consensusDir); syncErr != nil {
			return nil, fmt.Errorf(
				"consensus: sync new Raft directory entry: %w",
				syncErr,
			)
		}
	}

	logOutput := options.LogOutput
	if logOutput == nil {
		logOutput = io.Discard
	}
	snapshots, err := raft.NewFileSnapshotStore(
		consensusDir,
		snapshotRetention,
		logOutput,
	)
	if err != nil {
		return nil, fmt.Errorf("consensus: open snapshot store: %w", err)
	}
	if options.Single {
		_, transport = raft.NewInmemTransport(
			raft.ServerAddress(options.ServerID),
		)
	} else {
		transportGate = newNodeTransportGate(
			options.BootstrapConfiguration,
		)
		transport, err = options.TransportFactory(transportGate)
		if err != nil {
			return nil, fmt.Errorf(
				"consensus: construct mesh transport: %w",
				err,
			)
		}
		if nilRaftTransport(transport) ||
			transport.LocalAddr() !=
				raft.ServerAddress(options.ServerID) {
			return nil, ErrInvalidRaftTopology
		}
	}

	config, err := nodeRaftConfig(
		options.ServerID,
		options.RaftConfig,
		logOutput,
	)
	if err != nil {
		return nil, err
	}
	hasRaftState, err := raft.HasExistingState(stable, stable, snapshots)
	if err != nil {
		return nil, fmt.Errorf("consensus: inspect Raft state: %w", err)
	}

	state, err := store.Open(ctx, store.Options{
		Path: filepath.Clean(options.StatePath),
		RaftLog: raftDurableIndex{
			logs:      stable,
			snapshots: snapshots,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("consensus: open state store: %w", err)
	}
	defer func() {
		if err != nil {
			_ = state.Close()
		}
	}()

	view, viewErr := state.View(ctx)
	stateInitialized := viewErr == nil
	if viewErr != nil && !errors.Is(viewErr, store.ErrApplyConflict) {
		return nil, fmt.Errorf("consensus: inspect state initialization: %w", viewErr)
	}
	if !hasRaftState && stateInitialized {
		return nil, ErrRaftStateMissing
	}
	if !hasRaftState {
		if options.InitialState == nil {
			return nil, ErrStateInitialization
		}
		configuration := options.BootstrapConfiguration.Clone()
		if options.Single {
			configuration = raft.Configuration{Servers: []raft.Server{{
				Suffrage: raft.Voter,
				ID:       raft.ServerID(options.ServerID),
				Address:  transport.LocalAddr(),
			}}}
		}
		if err := validateInitialBootstrapTarget(
			*options.InitialState,
			configuration,
		); err != nil {
			return nil, err
		}
		if err := raft.BootstrapCluster(
			config,
			stable,
			stable,
			snapshots,
			transport,
			configuration,
		); err != nil {
			return nil, fmt.Errorf("consensus: bootstrap stable state: %w", err)
		}
		hasRaftState = true
	}
	if !stateInitialized {
		if options.InitialState == nil {
			return nil, ErrStateInitialization
		}
		configuration := options.BootstrapConfiguration.Clone()
		if options.Single {
			configuration = raft.Configuration{Servers: []raft.Server{{
				Suffrage: raft.Voter,
				ID:       raft.ServerID(options.ServerID),
				Address:  transport.LocalAddr(),
			}}}
		}
		if err := validateInitialBootstrapTarget(
			*options.InitialState,
			configuration,
		); err != nil {
			return nil, err
		}
		if err := validateBootstrapOnlyRaftState(
			stable,
			snapshots,
			configuration,
			!options.Single,
		); err != nil {
			return nil, err
		}
		if _, err := state.Initialize(ctx, *options.InitialState); err != nil {
			return nil, fmt.Errorf("consensus: initialize state: %w", err)
		}
		view, err = state.View(ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"consensus: inspect initialized state: %w",
				err,
			)
		}
	} else if options.InitialState != nil &&
		!sameInitialLineage(view, *options.InitialState) {
		return nil, fmt.Errorf(
			"%w: supplied genesis differs from the initialized store",
			ErrInvalidNodeOptions,
		)
	}
	if !hasRaftState {
		return nil, ErrRaftStateMissing
	}

	decoded, err := decodeStateView(view)
	if err != nil {
		return nil, fmt.Errorf("consensus: decode initial state: %w", err)
	}
	if options.Single {
		voters := decoded.VoterDeviceIDs()
		if len(voters) != 1 || voters[0] != options.ServerID {
			return nil, ErrSingleVoterTopology
		}
	}
	if err := verifyLatestSnapshotAnchor(
		ctx,
		snapshots,
		state,
		view,
		options.ServerID,
		options.Single,
	); err != nil {
		return nil, err
	}
	if !options.Single {
		if err := seedCommittedConfigurationFromSnapshot(
			ctx,
			snapshots,
			state,
		); err != nil {
			return nil, err
		}
		if err := seedCommittedConfigurationFromAppliedLog(
			ctx,
			stable,
			state,
			view,
		); err != nil {
			return nil, err
		}
	}
	if err := verifyCommittedConfigurationEvidence(
		ctx,
		stable,
		snapshots,
		state,
	); err != nil {
		return nil, err
	}
	if err := validateRaftReplayCoverage(
		stable,
		snapshots,
		options.Single,
	); err != nil {
		return nil, err
	}

	clock := options.Clock
	if clock == nil {
		clock = NewSystemApplyClock()
	}
	validateConfiguration := validateDeviceAddressedSnapshotConfiguration
	if options.Single {
		validateConfiguration = func(configuration raft.Configuration) error {
			return validateSingleRaftConfiguration(
				configuration,
				options.ServerID,
			)
		}
	}
	fsm, err := NewFSM(FSMOptions{
		Store:                 state,
		OriginBootID:          options.OriginBootID,
		Clock:                 clock,
		LogStore:              stable,
		ValidateConfiguration: validateConfiguration,
	})
	if err != nil {
		return nil, err
	}
	if !options.Single && fsm.committedConfiguration() == nil {
		if view.LastRaftAppliedLogIndex != nil ||
			!configurationMatchesDeviceIDs(
				options.BootstrapConfiguration,
				decoded.VoterDeviceIDs(),
			) {
			return nil, fmt.Errorf(
				"%w: no durable committed configuration or safe initial bootstrap",
				ErrStateInitialization,
			)
		}
	}
	fsm.publishPeerAdmission(
		decoded.Admission,
		view.AdmissionRevision,
		true,
	)
	var coverageGate *canonicalcoverage.Gate
	if options.CanonicalCoverage != nil {
		coverageGate, err = canonicalcoverage.NewGate(
			options.CanonicalCoverage,
		)
		if err != nil {
			if !errors.Is(err, canonicalcoverage.ErrCollectorUnavailable) {
				return nil, fmt.Errorf(
					"consensus: construct canonical coverage gate: %w",
					err,
				)
			}
			coverageGate = nil
		}
	}
	node := &SingleNode{
		fsm:           fsm,
		state:         state,
		stable:        stable,
		snapshots:     snapshots,
		transport:     transport,
		serverID:      raft.ServerID(options.ServerID),
		clock:         clock,
		single:        options.Single,
		transportGate: transportGate,
		coverageGate:  coverageGate,
		monitorStop:   make(chan struct{}),
		monitorDone:   make(chan struct{}),
		closeStarted:  make(chan struct{}),
		lineageGate:   make(chan struct{}, 1),
		raftEnqueue:   make(chan struct{}, 1),
		fatalSet:      make(chan struct{}),
		proposalFlights: make(
			map[domain.UUIDv7]*proposalFlight,
		),
		proposalReservations: make(
			map[domain.UUIDv7][]byte,
		),
	}
	instance, err := newRaftSafely(
		config,
		fsm,
		stable,
		stable,
		snapshots,
		transport,
	)
	if err != nil {
		return nil, fmt.Errorf("consensus: start Raft: %w", err)
	}
	node.raft = instance
	node.readLeadershipEpoch = node.currentLeadershipEpoch
	if transportGate != nil {
		transportGate.bind(node)
	}
	go node.monitorFSM()
	return node, nil
}

func configurationMatchesDeviceIDs(
	configuration raft.Configuration,
	deviceIDs []domain.DeviceID,
) bool {
	if len(configuration.Servers) != len(deviceIDs) {
		return false
	}
	for index, server := range configuration.Servers {
		if server.Suffrage != raft.Voter ||
			server.ID != raft.ServerID(deviceIDs[index]) ||
			server.Address != raft.ServerAddress(deviceIDs[index]) {
			return false
		}
	}
	return true
}

type raftDurableIndex struct {
	logs      raft.LogStore
	snapshots raft.SnapshotStore
}

func (state raftDurableIndex) LastIndex() (uint64, error) {
	if state.logs == nil || state.snapshots == nil {
		return 0, ErrRaftStateMissing
	}
	last, err := state.logs.LastIndex()
	if err != nil {
		return 0, err
	}
	metas, err := state.snapshots.List()
	if err != nil {
		return 0, err
	}
	for _, meta := range metas {
		if meta != nil && meta.Index > last {
			last = meta.Index
		}
	}
	return last, nil
}

func validateSingleNodeOptions(
	ctx context.Context,
	options SingleNodeOptions,
) error {
	return validateNodeIdentityAndPaths(
		ctx,
		options.ServerID,
		options.OriginBootID,
		options.StatePath,
		options.ConsensusDir,
	)
}

func validateNodeOptions(
	ctx context.Context,
	options NodeOptions,
) error {
	if err := validateNodeIdentityAndPaths(
		ctx,
		options.ServerID,
		options.OriginBootID,
		options.StatePath,
		options.ConsensusDir,
	); err != nil {
		return err
	}
	if options.TransportFactory == nil {
		return fmt.Errorf(
			"%w: nil mesh transport factory",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

func validateNodeIdentityAndPaths(
	ctx context.Context,
	serverID domain.DeviceID,
	originBootID domain.UUIDv7,
	statePath string,
	consensusDir string,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidNodeOptions)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !serverID.Valid() ||
		!originBootID.Valid() ||
		statePath == "" ||
		!filepath.IsAbs(statePath) ||
		consensusDir == "" ||
		!filepath.IsAbs(consensusDir) {
		return ErrInvalidNodeOptions
	}
	if filepath.Clean(statePath) ==
		filepath.Join(
			filepath.Clean(consensusDir),
			raftStoreFilename,
		) {
		return ErrInvalidNodeOptions
	}
	relative, err := filepath.Rel(
		filepath.Clean(consensusDir),
		filepath.Clean(statePath),
	)
	if err != nil ||
		relative == "." ||
		relative != ".." &&
			!filepath.IsAbs(relative) &&
			!strings.HasPrefix(
				relative,
				".."+string(os.PathSeparator),
			) {
		return fmt.Errorf(
			"%w: state database must be outside the consensus directory",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

func nilRaftTransport(transport RaftTransport) bool {
	if transport == nil {
		return true
	}
	value := reflect.ValueOf(transport)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func meshBootstrapConfiguration(
	localDeviceID domain.DeviceID,
	voterDeviceIDs []domain.DeviceID,
) (raft.Configuration, error) {
	if len(voterDeviceIDs) == 0 {
		return raft.Configuration{}, nil
	}
	switch len(voterDeviceIDs) {
	case 1, 3, 5:
	default:
		return raft.Configuration{}, fmt.Errorf(
			"%w: got %d voters, want 1, 3, or 5",
			ErrInvalidBootstrapTopology,
			len(voterDeviceIDs),
		)
	}
	configuration := raft.Configuration{
		Servers: make([]raft.Server, len(voterDeviceIDs)),
	}
	var (
		previous   domain.DeviceID
		hasLocalID bool
	)
	for index, deviceID := range voterDeviceIDs {
		if !deviceID.Valid() ||
			index > 0 && previous >= deviceID {
			return raft.Configuration{}, fmt.Errorf(
				"%w: voter IDs must be canonical, sorted, and unique",
				ErrInvalidBootstrapTopology,
			)
		}
		configuration.Servers[index] = raft.Server{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(deviceID),
			Address:  raft.ServerAddress(deviceID),
		}
		hasLocalID = hasLocalID || deviceID == localDeviceID
		previous = deviceID
	}
	if !hasLocalID {
		return raft.Configuration{}, fmt.Errorf(
			"%w: local device is not a bootstrap voter",
			ErrInvalidBootstrapTopology,
		)
	}
	return configuration, nil
}

func validateInitialBootstrapTarget(
	initial store.InitialState,
	configuration raft.Configuration,
) error {
	if len(configuration.Servers) == 0 ||
		len(initial.Projections.VoterSet) != 1 {
		return fmt.Errorf(
			"%w: bootstrap configuration and initial voter target are required",
			ErrInvalidBootstrapTopology,
		)
	}
	target := initial.Projections.VoterSet[0]
	if err := target.Validate(); err != nil ||
		target.SessionID != initial.SessionID {
		return fmt.Errorf(
			"%w: invalid initial voter target",
			ErrInvalidBootstrapTopology,
		)
	}
	voterDeviceIDs := target.VoterDeviceIDs()
	if len(voterDeviceIDs) != len(configuration.Servers) {
		return fmt.Errorf(
			"%w: initial voter target differs from bootstrap configuration",
			ErrInvalidBootstrapTopology,
		)
	}
	for index, server := range configuration.Servers {
		if server.Suffrage != raft.Voter ||
			server.ID != raft.ServerID(voterDeviceIDs[index]) {
			return fmt.Errorf(
				"%w: initial voter target differs from bootstrap configuration",
				ErrInvalidBootstrapTopology,
			)
		}
	}
	return nil
}

func validateBootstrapOnlyRaftState(
	logs raft.LogStore,
	snapshots raft.SnapshotStore,
	expected raft.Configuration,
	compareAddresses bool,
) error {
	first, err := logs.FirstIndex()
	if err != nil {
		return fmt.Errorf("consensus: read first bootstrap index: %w", err)
	}
	last, err := logs.LastIndex()
	if err != nil {
		return fmt.Errorf("consensus: read last bootstrap index: %w", err)
	}
	metas, err := snapshots.List()
	if err != nil {
		return fmt.Errorf("consensus: list bootstrap snapshots: %w", err)
	}
	if first != 1 || last != 1 || len(metas) != 0 {
		return fmt.Errorf(
			"%w: uninitialized SQLite may attach only to the first bootstrap config",
			ErrStateInitialization,
		)
	}
	var entry raft.Log
	if err := logs.GetLog(1, &entry); err != nil {
		return fmt.Errorf("consensus: read bootstrap config: %w", err)
	}
	if entry.Index != 1 ||
		entry.Term != 1 ||
		entry.Type != raft.LogConfiguration {
		return fmt.Errorf(
			"%w: malformed first bootstrap config",
			ErrStateInitialization,
		)
	}
	configuration, err := decodeRaftConfiguration(entry.Data)
	if err != nil {
		return fmt.Errorf(
			"%w: malformed bootstrap configuration: %v",
			ErrStateInitialization,
			err,
		)
	}
	if !sameBootstrapConfiguration(
		configuration,
		expected,
		compareAddresses,
	) {
		return fmt.Errorf(
			"%w: bootstrap configuration differs from the supplied initial topology",
			ErrStateInitialization,
		)
	}
	return nil
}

func sameBootstrapConfiguration(
	actual raft.Configuration,
	expected raft.Configuration,
	compareAddresses bool,
) bool {
	if len(actual.Servers) != len(expected.Servers) {
		return false
	}
	for index, actualServer := range actual.Servers {
		expectedServer := expected.Servers[index]
		if actualServer.Suffrage != expectedServer.Suffrage ||
			actualServer.ID != expectedServer.ID ||
			compareAddresses &&
				actualServer.Address != expectedServer.Address {
			return false
		}
	}
	return true
}

func decodeRaftConfiguration(data []byte) (
	configuration raft.Configuration,
	err error,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("decode configuration panic: %v", recovered)
		}
	}()
	return raft.DecodeConfiguration(data), nil
}

func newRaftSafely(
	config *raft.Config,
	fsm raft.FSM,
	logs raft.LogStore,
	stable raft.StableStore,
	snapshots raft.SnapshotStore,
	transport raft.Transport,
) (instance *raft.Raft, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			instance = nil
			err = fmt.Errorf(
				"%w: startup panic: %v",
				ErrRaftLogCoverage,
				recovered,
			)
		}
	}()
	return raft.NewRaft(
		config,
		fsm,
		logs,
		stable,
		snapshots,
		transport,
	)
}

func validateRaftReplayCoverage(
	logs raft.LogStore,
	snapshots raft.SnapshotStore,
	single bool,
) error {
	if logs == nil || snapshots == nil {
		return ErrRaftLogCoverage
	}
	first, err := logs.FirstIndex()
	if err != nil {
		return fmt.Errorf("%w: first log index: %v", ErrRaftLogCoverage, err)
	}
	last, err := logs.LastIndex()
	if err != nil {
		return fmt.Errorf("%w: last log index: %v", ErrRaftLogCoverage, err)
	}
	metas, err := snapshots.List()
	if err != nil {
		return fmt.Errorf("%w: list snapshots: %v", ErrRaftLogCoverage, err)
	}
	var snapshotIndex uint64
	if len(metas) != 0 {
		if metas[0] == nil || metas[0].Index < 1 {
			return fmt.Errorf(
				"%w: latest snapshot metadata is invalid",
				ErrRaftLogCoverage,
			)
		}
		snapshotIndex = metas[0].Index
	}
	if last == 0 {
		if first != 0 || snapshotIndex == 0 {
			return fmt.Errorf(
				"%w: durable state has neither a snapshot nor logs",
				ErrRaftLogCoverage,
			)
		}
		return nil
	}
	if first < 1 || first > last {
		return fmt.Errorf(
			"%w: invalid retained range %d..%d",
			ErrRaftLogCoverage,
			first,
			last,
		)
	}
	requiredFirst := uint64(1)
	if snapshotIndex != 0 {
		if snapshotIndex == ^uint64(0) {
			return fmt.Errorf(
				"%w: snapshot index overflows",
				ErrRaftLogCoverage,
			)
		}
		requiredFirst = snapshotIndex + 1
	}
	if last >= requiredFirst && first > requiredFirst {
		return fmt.Errorf(
			"%w: retained logs start at %d, need %d",
			ErrRaftLogCoverage,
			first,
			requiredFirst,
		)
	}
	for index := first; index <= last; index++ {
		var entry raft.Log
		if err := logs.GetLog(index, &entry); err != nil {
			return fmt.Errorf(
				"%w: missing log %d: %v",
				ErrRaftLogCoverage,
				index,
				err,
			)
		}
		if entry.Index != index || entry.Term < 1 {
			return fmt.Errorf(
				"%w: malformed log %d",
				ErrRaftLogCoverage,
				index,
			)
		}
		switch entry.Type {
		case raft.LogCommand,
			raft.LogBarrier,
			raft.LogNoop:
		case raft.LogConfiguration:
			if !single {
				configuration, err := decodeRaftConfiguration(entry.Data)
				if err != nil {
					return fmt.Errorf(
						"%w: decode configuration at %d: %v",
						ErrRaftLogCoverage,
						index,
						err,
					)
				}
				if err := validateDeviceAddressedSnapshotConfiguration(
					configuration,
				); err != nil {
					return fmt.Errorf(
						"%w: configuration at %d: %w",
						ErrRaftLogCoverage,
						index,
						err,
					)
				}
			}
		default:
			return fmt.Errorf(
				"%w: unsupported log type at %d",
				ErrRaftLogCoverage,
				index,
			)
		}
		if index == ^uint64(0) {
			break
		}
	}
	return nil
}

func nodeRaftConfig(
	serverID domain.DeviceID,
	supplied *raft.Config,
	logOutput io.Writer,
) (*raft.Config, error) {
	var config raft.Config
	if supplied == nil {
		config = *raft.DefaultConfig()
	} else {
		config = *supplied
	}
	config.LocalID = raft.ServerID(serverID)
	config.NoSnapshotRestoreOnStart = true
	config.ShutdownOnRemove = true
	config.LogOutput = logOutput
	if config.ProtocolVersion != raft.ProtocolVersionMax {
		return nil, fmt.Errorf(
			"%w: Raft protocol version must be %d",
			ErrInvalidNodeOptions,
			raft.ProtocolVersionMax,
		)
	}
	if err := raft.ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("%w: Raft config: %v", ErrInvalidNodeOptions, err)
	}
	return &config, nil
}

func prepareConsensusDirectory(path string) (bool, error) {
	if path == "" || !filepath.IsAbs(path) {
		return false, ErrInvalidNodeOptions
	}
	_, priorErr := os.Lstat(path)
	created := errors.Is(priorErr, os.ErrNotExist)
	if priorErr != nil && !created {
		return false, fmt.Errorf("consensus: inspect storage directory: %w", priorErr)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return false, fmt.Errorf("consensus: create storage directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, fmt.Errorf("consensus: inspect storage directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf(
			"%w: storage path is not a real directory",
			ErrInsecureConsensusPath,
		)
	}
	if err := validatePrivateDirectory(info); err != nil {
		return false, err
	}
	return created, nil
}

func sameInitialLineage(
	view store.StateView,
	initial store.InitialState,
) bool {
	return view.RecoveryGeneration == 0 &&
		view.SessionID == initial.SessionID &&
		view.WorkspaceID == initial.WorkspaceID &&
		bytes.Equal(view.GenesisJSON, initial.GenesisJSON) &&
		view.Heads.DigestVersion == initial.DigestVersion &&
		view.Heads.ProjectionSchemaVersion ==
			initial.ProjectionSchemaVersion
}

func verifyLatestSnapshotAnchor(
	ctx context.Context,
	snapshots raft.SnapshotStore,
	state *store.Store,
	view store.StateView,
	serverID domain.DeviceID,
	single bool,
) error {
	metas, err := snapshots.List()
	if err != nil {
		return fmt.Errorf("consensus: list snapshots: %w", err)
	}
	if len(metas) == 0 {
		return nil
	}
	if err := state.VerifyCommitmentHistory(ctx); err != nil {
		return fmt.Errorf(
			"%w: verify snapshot-covered history: %v",
			ErrSnapshotAnchorCoverage,
			err,
		)
	}
	meta, reader, err := snapshots.Open(metas[0].ID)
	if err != nil {
		return fmt.Errorf("consensus: open latest snapshot: %w", err)
	}
	defer reader.Close()
	if err := validateSnapshotMeta(meta, serverID, single); err != nil {
		return fmt.Errorf(
			"%w: invalid snapshot metadata: %v",
			ErrSnapshotAnchorCoverage,
			err,
		)
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxSnapshotAnchorBytes+1))
	if err != nil {
		return fmt.Errorf("consensus: read latest snapshot: %w", err)
	}
	if len(encoded) > maxSnapshotAnchorBytes {
		return ErrInvalidSnapshotAnchor
	}
	if meta.Size != int64(len(encoded)) {
		return fmt.Errorf(
			"%w: metadata size %d differs from anchor size %d",
			ErrSnapshotAnchorCoverage,
			meta.Size,
			len(encoded),
		)
	}
	anchor, err := decodeSnapshotAnchor(encoded)
	if err != nil {
		return err
	}
	if err := validateSnapshotMetaAnchor(meta, anchor); err != nil {
		return fmt.Errorf(
			"%w: metadata term/index differs from anchor: %v",
			ErrSnapshotAnchorCoverage,
			err,
		)
	}
	if !snapshotAnchorCoveredByView(anchor, view) {
		return fmt.Errorf(
			"%w: durable state does not cover anchor",
			ErrSnapshotAnchorCoverage,
		)
	}
	if anchor.LastRaftAppliedLogIndex ==
		*view.LastRaftAppliedLogIndex {
		return nil
	}
	chainHash, err := decodeSnapshotDigest(anchor.ChainHash)
	if err != nil {
		return err
	}
	resultHash, err := decodeSnapshotDigest(anchor.ResultHash)
	if err != nil {
		return err
	}
	projectionAccumulator, err := decodeSnapshotDigest(
		anchor.ProjectionAccumulator,
	)
	if err != nil {
		return err
	}
	projectionStateDigest, err := decodeSnapshotDigest(
		anchor.ProjectionStateDigest,
	)
	if err != nil {
		return err
	}
	if err := state.VerifyCommitmentCut(ctx, store.CommitmentCut{
		SessionID:               domain.UUIDv7(anchor.SessionID),
		RecoveryGeneration:      anchor.RecoveryGeneration,
		ChainIndex:              anchor.ChainIndex,
		ChainHash:               chainHash,
		ResultIndex:             anchor.ResultIndex,
		ResultHash:              resultHash,
		ProjectionAccumulator:   projectionAccumulator,
		ProjectionStateDigest:   projectionStateDigest,
		DigestVersion:           anchor.DigestVersion,
		ProjectionSchemaVersion: anchor.ProjectionSchemaVersion,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrSnapshotAnchorCoverage, err)
	}
	return nil
}

func validateSnapshotMetaAnchor(
	meta *raft.SnapshotMeta,
	anchor snapshotAnchor,
) error {
	if meta == nil {
		return fmt.Errorf(
			"%w: snapshot metadata is nil",
			ErrSnapshotAnchorCoverage,
		)
	}
	if meta.Index < anchor.LastRaftAppliedLogIndex {
		return fmt.Errorf(
			"%w: metadata index %d precedes SQLite index %d",
			ErrSnapshotAnchorCoverage,
			meta.Index,
			anchor.LastRaftAppliedLogIndex,
		)
	}
	if meta.Index == anchor.LastRaftAppliedLogIndex {
		if meta.Term != anchor.CurrentTerm {
			return fmt.Errorf(
				"%w: metadata term %d differs from SQLite term %d",
				ErrSnapshotAnchorCoverage,
				meta.Term,
				anchor.CurrentTerm,
			)
		}
		return nil
	}
	offset := meta.Index - anchor.LastRaftAppliedLogIndex - 1
	if offset >= uint64(len(anchor.RaftTail)) {
		return fmt.Errorf(
			"%w: metadata index %d is not covered by the non-command tail",
			ErrSnapshotAnchorCoverage,
			meta.Index,
		)
	}
	entry := anchor.RaftTail[offset]
	if entry.Index != meta.Index || entry.Term != meta.Term {
		return fmt.Errorf(
			"%w: metadata term/index %d/%d differs from tail %d/%d",
			ErrSnapshotAnchorCoverage,
			meta.Term,
			meta.Index,
			entry.Term,
			entry.Index,
		)
	}
	return nil
}

func seedCommittedConfigurationFromSnapshot(
	ctx context.Context,
	snapshots raft.SnapshotStore,
	state *store.Store,
) error {
	metas, err := snapshots.List()
	if err != nil {
		return fmt.Errorf(
			"consensus: list snapshots for committed configuration: %w",
			err,
		)
	}
	if len(metas) == 0 {
		return nil
	}
	meta := metas[0]
	if meta == nil || meta.ConfigurationIndex < 1 {
		return ErrSnapshotAnchorCoverage
	}
	encoded, err := encodeRaftConfiguration(meta.Configuration)
	if err != nil {
		return fmt.Errorf(
			"%w: encode snapshot configuration: %v",
			ErrSnapshotAnchorCoverage,
			err,
		)
	}
	if _, err := state.StoreCommittedRaftConfiguration(
		ctx,
		meta.ConfigurationIndex,
		encoded,
	); err != nil {
		return fmt.Errorf(
			"%w: persist snapshot configuration: %v",
			ErrSnapshotAnchorCoverage,
			err,
		)
	}
	return nil
}

func seedCommittedConfigurationFromAppliedLog(
	ctx context.Context,
	logs raft.LogStore,
	state *store.Store,
	view store.StateView,
) error {
	if ctx == nil || logs == nil || state == nil {
		return ErrRaftLogCoverage
	}
	_, found, err := state.CommittedRaftConfiguration(ctx)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect committed configuration migration evidence: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	if found || view.LastRaftAppliedLogIndex == nil {
		return nil
	}
	first, err := logs.FirstIndex()
	if err != nil {
		return fmt.Errorf(
			"%w: read first configuration migration index: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	last, err := logs.LastIndex()
	if err != nil {
		return fmt.Errorf(
			"%w: read last configuration migration index: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	applied := *view.LastRaftAppliedLogIndex
	if first == 0 || first > applied || last < applied {
		return fmt.Errorf(
			"%w: applied command has no retained configuration evidence",
			ErrStateInitialization,
		)
	}
	var (
		configuration      raft.Configuration
		configurationIndex uint64
	)
	for index := first; index <= applied; index++ {
		var entry raft.Log
		if err := logs.GetLog(index, &entry); err != nil {
			return fmt.Errorf(
				"%w: read migration log %d: %v",
				ErrRaftLogCoverage,
				index,
				err,
			)
		}
		if entry.Type == raft.LogConfiguration {
			candidate, err := decodeRaftConfiguration(entry.Data)
			if err != nil ||
				validateDeviceAddressedSnapshotConfiguration(candidate) != nil {
				return fmt.Errorf(
					"%w: invalid migration configuration at %d",
					ErrRaftLogCoverage,
					index,
				)
			}
			configuration = candidate
			configurationIndex = index
		}
		if index == ^uint64(0) {
			break
		}
	}
	if configurationIndex == 0 {
		return fmt.Errorf(
			"%w: applied command has no prior configuration",
			ErrStateInitialization,
		)
	}
	encoded, err := encodeRaftConfiguration(configuration)
	if err != nil {
		return fmt.Errorf(
			"%w: encode migration configuration: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	if _, err := state.StoreCommittedRaftConfiguration(
		ctx,
		configurationIndex,
		encoded,
	); err != nil {
		return fmt.Errorf(
			"%w: persist migration configuration: %v",
			ErrRaftLogCoverage,
			err,
		)
	}
	return nil
}

func validateSnapshotMeta(
	meta *raft.SnapshotMeta,
	serverID domain.DeviceID,
	single bool,
) error {
	if meta == nil ||
		meta.Version != raft.SnapshotVersionMax ||
		meta.Index < 1 ||
		meta.Term < 1 ||
		meta.ConfigurationIndex < 1 ||
		meta.ConfigurationIndex > meta.Index ||
		meta.Size < 1 {
		return ErrSnapshotAnchorCoverage
	}
	if !single {
		return validateDeviceAddressedSnapshotConfiguration(
			meta.Configuration,
		)
	}
	return validateSingleRaftConfiguration(
		meta.Configuration,
		serverID,
	)
}

func validateSingleVoterSnapshotMeta(
	meta *raft.SnapshotMeta,
	serverID domain.DeviceID,
) error {
	return validateSnapshotMeta(meta, serverID, true)
}

func validateSingleRaftConfiguration(
	configuration raft.Configuration,
	serverID domain.DeviceID,
) error {
	if len(configuration.Servers) != 1 {
		return ErrSingleVoterTopology
	}
	server := configuration.Servers[0]
	if server.ID != raft.ServerID(serverID) ||
		server.Suffrage != raft.Voter ||
		server.Address != raft.ServerAddress(serverID) {
		return ErrSingleVoterTopology
	}
	return nil
}

func validateDeviceAddressedSnapshotConfiguration(
	configuration raft.Configuration,
) error {
	if len(configuration.Servers) == 0 ||
		len(configuration.Servers) > int(policy.MaxMemberDevices) {
		return ErrInvalidRaftTopology
	}
	seen := make(map[domain.DeviceID]struct{}, len(configuration.Servers))
	voterCount := 0
	for _, server := range configuration.Servers {
		deviceID := domain.DeviceID(server.ID)
		if !deviceID.Valid() ||
			server.Address != raft.ServerAddress(deviceID) {
			return ErrInvalidRaftTopology
		}
		if _, duplicate := seen[deviceID]; duplicate {
			return ErrInvalidRaftTopology
		}
		seen[deviceID] = struct{}{}
		switch server.Suffrage {
		case raft.Voter:
			voterCount++
		case raft.Nonvoter:
		default:
			return ErrInvalidRaftTopology
		}
	}
	if voterCount == 0 {
		return ErrInvalidRaftTopology
	}
	return nil
}

func decodeSnapshotDigest(encoded string) (store.Digest, error) {
	raw, err := codec.DecodeBase64URLExact(encoded, len(store.Digest{}))
	if err != nil {
		return store.Digest{}, ErrInvalidSnapshotAnchor
	}
	var digest store.Digest
	copy(digest[:], raw)
	return digest, nil
}

func snapshotAnchorCoveredByView(
	anchor snapshotAnchor,
	view store.StateView,
) bool {
	if view.CurrentTerm == nil || view.LastRaftAppliedLogIndex == nil {
		return false
	}
	if anchor.SessionID != string(view.SessionID) ||
		anchor.WorkspaceID != string(view.WorkspaceID) ||
		anchor.RecoveryGeneration != view.RecoveryGeneration ||
		anchor.CurrentTerm > *view.CurrentTerm ||
		anchor.LastRaftAppliedLogIndex > *view.LastRaftAppliedLogIndex ||
		anchor.ChainIndex > view.Heads.ChainIndex ||
		anchor.ResultIndex > view.Heads.ResultIndex ||
		anchor.DigestVersion != view.Heads.DigestVersion ||
		anchor.ProjectionSchemaVersion !=
			view.Heads.ProjectionSchemaVersion {
		return false
	}
	if anchor.LastRaftAppliedLogIndex == *view.LastRaftAppliedLogIndex {
		return snapshotAnchorMatchesView(anchor, view)
	}
	if anchor.ResultIndex == view.Heads.ResultIndex &&
		(anchor.ResultHash !=
			codec.EncodeBase64URL(view.Heads.ResultHash[:]) ||
			anchor.ProjectionAccumulator !=
				codec.EncodeBase64URL(view.Heads.ProjectionAccumulator[:]) ||
			anchor.ProjectionStateDigest !=
				codec.EncodeBase64URL(view.ProjectionStateDigest[:])) {
		return false
	}
	if anchor.ChainIndex == view.Heads.ChainIndex &&
		anchor.ChainHash != codec.EncodeBase64URL(view.Heads.ChainHash[:]) {
		return false
	}
	return true
}

func (node *SingleNode) monitorFSM() {
	defer close(node.monitorDone)
	select {
	case err := <-node.fsm.Halted():
		node.recordFatal(err)
		_ = node.shutdownRaft()
	case <-node.monitorStop:
	}
}

func (node *SingleNode) recordFatal(err error) {
	if node == nil || err == nil {
		return
	}
	node.fatalOnce.Do(func() {
		node.fatalMu.Lock()
		node.fatalErr = err
		node.fatalMu.Unlock()
		close(node.fatalSet)
	})
	if node.fsm != nil {
		node.fsm.closePeerAdmissionChanges()
	}
}

// FatalError reports a terminal FSM integrity failure.
func (node *SingleNode) FatalError() error {
	if node == nil {
		return ErrInvalidNodeOptions
	}
	node.fatalMu.RLock()
	err := node.fatalErr
	node.fatalMu.RUnlock()
	if err == nil && node.fsm != nil {
		err = node.fsm.HaltError()
	}
	return err
}

func (node *SingleNode) beginOperation() error {
	if node == nil {
		return ErrInvalidNodeOptions
	}
	node.lifecycleMu.Lock()
	defer node.lifecycleMu.Unlock()
	if node.closing {
		return ErrNodeClosed
	}
	node.active.Add(1)
	return nil
}

func (node *SingleNode) endOperation() {
	node.active.Done()
}

// withLineageGate serializes a durable-lineage check and its side effect with
// any future successor installation using the same callback boundary.
func (node *SingleNode) withLineageGate(
	ctx context.Context,
	operation func() error,
) error {
	if node == nil ||
		ctx == nil ||
		operation == nil ||
		node.lineageGate == nil ||
		node.closeStarted == nil ||
		node.fatalSet == nil {
		return ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := node.beginOperation(); err != nil {
		return err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return err
	}

	select {
	case node.lineageGate <- struct{}{}:
		defer func() { <-node.lineageGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-node.closeStarted:
		return ErrNodeClosed
	case <-node.fatalSet:
		return node.FatalError()
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-node.closeStarted:
		return ErrNodeClosed
	default:
	}
	if err := node.FatalError(); err != nil {
		return err
	}
	return operation()
}

// Address returns this node's Raft transport address.
func (node *SingleNode) Address() raft.ServerAddress {
	if node == nil || node.transport == nil {
		return ""
	}
	return node.transport.LocalAddr()
}

// IsLeader reports whether this node currently owns proposal authority.
func (node *SingleNode) IsLeader() bool {
	if node == nil || node.raft == nil {
		return false
	}
	if node.FatalError() != nil {
		return false
	}
	node.lifecycleMu.Lock()
	closing := node.closing
	node.lifecycleMu.Unlock()
	if closing {
		return false
	}
	_, id := node.raft.LeaderWithID()
	return node.raft.State() == raft.Leader && id == node.serverID
}

// LocalTime reads the same same-boot clock used to arm lease deadlines in
// the FSM. Keeping this clock on the consensus boundary prevents callers
// from comparing deadlines from different monotonic epochs.
func (node *SingleNode) LocalTime() (domain.Timestamp, int64, error) {
	if node == nil || node.clock == nil {
		return "", 0, ErrInvalidNodeOptions
	}
	node.lifecycleMu.Lock()
	closing := node.closing
	node.lifecycleMu.Unlock()
	if closing {
		return "", 0, ErrNodeClosed
	}
	if err := node.FatalError(); err != nil {
		return "", 0, err
	}
	return node.clock()
}

// WaitForLeader waits for a valid leader and for this replica to apply through
// the commit index observed with that leader. A local leader additionally
// completes a barrier before returning.
func (node *SingleNode) WaitForLeader(ctx context.Context) error {
	if node == nil || node.raft == nil || ctx == nil {
		return ErrInvalidNodeOptions
	}
	if err := node.beginOperation(); err != nil {
		return err
	}
	defer node.endOperation()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := node.FatalError(); err != nil {
			return err
		}
		address, id := node.raft.LeaderWithID()
		if id != "" {
			deviceID := domain.DeviceID(id)
			if !deviceID.Valid() ||
				!node.single &&
					address != raft.ServerAddress(deviceID) {
				return ErrInvalidRaftTopology
			}
			if node.raft.State() == raft.Leader &&
				id == node.serverID {
				err := waitFuture(
					ctx,
					node.raft.Barrier(contextTimeout(ctx)),
				)
				if err == nil {
					commitIndex := node.raft.CommitIndex()
					ready, readyErr := node.appliedThroughCommit(
						commitIndex,
					)
					if readyErr != nil {
						return readyErr
					}
					if ready && node.IsLeader() {
						return nil
					}
					continue
				}
				if !errors.Is(err, raft.ErrNotLeader) &&
					!errors.Is(err, raft.ErrLeadershipLost) {
					return err
				}
			} else {
				commitIndex := node.raft.CommitIndex()
				ready, err := node.appliedThroughCommit(commitIndex)
				if err != nil {
					return err
				}
				if ready {
					finalAddress, finalID := node.raft.LeaderWithID()
					if finalAddress == address &&
						finalID == id &&
						node.raft.State() == raft.Follower &&
						node.FatalError() == nil {
						select {
						case <-node.closeStarted:
							return ErrNodeClosed
						default:
						}
						return nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-node.closeStarted:
			return ErrNodeClosed
		case <-ticker.C:
		}
	}
}

func (node *SingleNode) appliedThroughCommit(
	commitIndex uint64,
) (bool, error) {
	if node == nil || node.raft == nil || node.fsm == nil ||
		commitIndex == 0 {
		return false, nil
	}
	commandIndex, configurationIndex, err :=
		node.committedFSMIndexes(commitIndex)
	if err != nil {
		return false, err
	}
	if node.fsm.appliedCommandIndex.Load() < commandIndex {
		return false, nil
	}
	committedConfiguration := node.fsm.committedConfiguration()
	if configurationIndex > 0 &&
		(committedConfiguration == nil ||
			committedConfiguration.Index < configurationIndex) {
		return false, nil
	}
	return node.raft.CommitIndex() == commitIndex, nil
}

func (node *SingleNode) shutdownRaft() error {
	if node == nil || node.raft == nil {
		return ErrInvalidNodeOptions
	}
	node.raftShutdownOnce.Do(func() {
		node.raftShutdownErr = node.raft.Shutdown().Error()
	})
	return node.raftShutdownErr
}

// Apply proposes an exact signed event and returns only its durable outcome.
func (node *SingleNode) Apply(
	ctx context.Context,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	if node == nil || node.raft == nil || ctx == nil {
		return store.ApplyResult{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	if err := node.beginOperation(); err != nil {
		return store.ApplyResult{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return store.ApplyResult{}, err
	}
	return node.apply(ctx, signed, false)
}

// ApplyAtGeneration proposes only while the exact expected lineage remains
// active. Once enqueued, the proposal retains the lineage gate until its Raft
// future resolves so successor installation cannot overtake it.
func (node *SingleNode) ApplyAtGeneration(
	ctx context.Context,
	expectedSessionID domain.UUIDv7,
	expectedRecoveryGeneration uint64,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	if node == nil ||
		node.raft == nil ||
		node.state == nil ||
		ctx == nil ||
		!expectedSessionID.Valid() ||
		!domain.ValidUnsignedInteger(expectedRecoveryGeneration) {
		return store.ApplyResult{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	if lineageOperationActive(ctx) {
		return store.ApplyResult{}, ErrLineageReentry
	}

	var (
		result store.ApplyResult
		err    error
	)
	err = node.withLineageGate(ctx, func() error {
		if signed.Proposal().SessionID != expectedSessionID {
			return fmt.Errorf(
				"%w: signed event belongs to session %q",
				ErrLineageMismatch,
				signed.Proposal().SessionID,
			)
		}
		if err := node.requireLineage(
			ctx,
			expectedSessionID,
			expectedRecoveryGeneration,
		); err != nil {
			return err
		}
		result, err = node.apply(ctx, signed, true)
		return err
	})
	return result, err
}

// RunAtGeneration runs one idempotent durable side effect while the exact
// expected lineage remains installed. The callback must use the supplied
// context, return when it is canceled, and must not reenter this node.
func (node *SingleNode) RunAtGeneration(
	ctx context.Context,
	expectedSessionID domain.UUIDv7,
	expectedRecoveryGeneration uint64,
	operation func(context.Context) error,
) error {
	if node == nil ||
		node.state == nil ||
		ctx == nil ||
		operation == nil ||
		!expectedSessionID.Valid() ||
		!domain.ValidUnsignedInteger(expectedRecoveryGeneration) {
		return ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lineageOperationActive(ctx) {
		return ErrLineageReentry
	}
	return node.withLineageGate(ctx, func() error {
		if err := node.requireLineage(
			ctx,
			expectedSessionID,
			expectedRecoveryGeneration,
		); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		operationContext, cancel, wait := node.lineageOperationContext(ctx)
		defer func() {
			cancel()
			wait()
		}()
		return operation(operationContext)
	})
}

func (node *SingleNode) lineageOperationContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, func()) {
	operationContext, cancel, wait := node.operationContext(ctx)
	operationContext = context.WithValue(
		operationContext,
		lineageOperationContextKey{},
		struct{}{},
	)
	return operationContext, cancel, wait
}

func (node *SingleNode) operationContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, func()) {
	operationContext, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-node.closeStarted:
			cancel()
		case <-node.fatalSet:
			cancel()
		case <-finished:
		}
	}()
	var once sync.Once
	wait := func() {
		once.Do(func() {
			close(finished)
			<-watcherDone
		})
	}
	return operationContext, cancel, wait
}

func lineageOperationActive(ctx context.Context) bool {
	return ctx.Value(lineageOperationContextKey{}) != nil
}

func (node *SingleNode) requireLineage(
	ctx context.Context,
	expectedSessionID domain.UUIDv7,
	expectedRecoveryGeneration uint64,
) error {
	view, err := node.state.View(ctx)
	if err != nil {
		return err
	}
	if view.SessionID != expectedSessionID ||
		view.RecoveryGeneration != expectedRecoveryGeneration {
		return fmt.Errorf(
			"%w: expected %s/%d, active %s/%d",
			ErrLineageMismatch,
			expectedSessionID,
			expectedRecoveryGeneration,
			view.SessionID,
			view.RecoveryGeneration,
		)
	}
	return nil
}

func (node *SingleNode) apply(
	ctx context.Context,
	signed event.SignedEvent,
	waitForResolution bool,
) (store.ApplyResult, error) {
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	if err := node.FatalError(); err != nil {
		return store.ApplyResult{}, err
	}
	proposal := signed.Proposal()
	canonical := signed.CanonicalBytes()
	if !proposal.EventID.Valid() || len(canonical) == 0 {
		return store.ApplyResult{}, ErrInvalidCommand
	}
	flight, owner, committed, found, err := node.beginProposal(
		ctx,
		signed,
		canonical,
	)
	if err != nil {
		return store.ApplyResult{}, node.handleLookupError(err)
	}
	if found {
		return committed, nil
	}
	if owner {
		future, enqueueErr := node.enqueueRaftApply(ctx, canonical)
		if enqueueErr != nil {
			node.finishProposal(
				proposal.EventID,
				flight,
				store.ApplyResult{},
				enqueueErr,
				false,
			)
		} else {
			node.active.Add(1)
			go node.resolveProposal(
				proposal.EventID,
				signed,
				flight,
				future,
			)
		}
	}
	if waitForResolution {
		<-flight.done
		result := flight.result
		if !owner && flight.err == nil {
			result.Duplicate = true
		}
		return result, flight.err
	}
	select {
	case <-flight.done:
		result := flight.result
		if !owner && flight.err == nil {
			result.Duplicate = true
		}
		return result, flight.err
	case <-ctx.Done():
		return store.ApplyResult{}, ctx.Err()
	case <-node.closeStarted:
		return store.ApplyResult{}, ErrNodeClosed
	}
}

func (node *SingleNode) preEnqueueError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-node.closeStarted:
		return ErrNodeClosed
	default:
	}
	return node.FatalError()
}

func (node *SingleNode) resolveProposal(
	eventID domain.UUIDv7,
	signed event.SignedEvent,
	flight *proposalFlight,
	future raft.ApplyFuture,
) {
	defer node.active.Done()

	var result store.ApplyResult
	err := future.Error()
	if err != nil {
		lookup, found, lookupErr := node.lookupCommitted(
			context.Background(),
			signed,
		)
		switch {
		case lookupErr != nil:
			err = node.handleLookupError(lookupErr)
		case found:
			result = lookup
			err = nil
		}
	} else {
		response, ok := future.Response().(ApplyResponse)
		switch {
		case !ok || response.LogIndex != future.Index():
			err = node.haltNode(ErrUnexpectedFSMResponse)
		case response.Err != nil:
			err = response.Err
		default:
			result = response.Result
		}
	}
	uncertain := err != nil && future.Index() > 0
	node.finishProposal(eventID, flight, result, err, uncertain)
}

type proposalFlight struct {
	canonical           []byte
	preserveReservation bool
	done                chan struct{}
	result              store.ApplyResult
	err                 error
}

func (node *SingleNode) beginProposal(
	ctx context.Context,
	signed event.SignedEvent,
	canonical []byte,
) (
	*proposalFlight,
	bool,
	store.ApplyResult,
	bool,
	error,
) {
	eventID := signed.Proposal().EventID
	node.proposalMu.Lock()
	defer node.proposalMu.Unlock()
	if flight, exists := node.proposalFlights[eventID]; exists {
		if !bytes.Equal(flight.canonical, canonical) {
			return nil, false, store.ApplyResult{}, false,
				store.ErrIdempotencyConflict
		}
		return flight, false, store.ApplyResult{}, false, nil
	}
	reservation, reserved := node.proposalReservations[eventID]
	if reserved && !bytes.Equal(reservation, canonical) {
		return nil, false, store.ApplyResult{}, false,
			store.ErrIdempotencyConflict
	}
	result, found, err := node.lookupCommitted(ctx, signed)
	if err != nil {
		return nil, false, store.ApplyResult{}, false, err
	}
	if found {
		delete(node.proposalReservations, eventID)
		return nil, false, result, true, nil
	}
	flight := &proposalFlight{
		canonical:           bytes.Clone(canonical),
		preserveReservation: reserved,
		done:                make(chan struct{}),
	}
	node.proposalFlights[eventID] = flight
	return flight, true, store.ApplyResult{}, false, nil
}

func (node *SingleNode) finishProposal(
	eventID domain.UUIDv7,
	flight *proposalFlight,
	result store.ApplyResult,
	err error,
	uncertain bool,
) {
	node.proposalMu.Lock()
	defer node.proposalMu.Unlock()
	if node.proposalFlights[eventID] != flight {
		panic("consensus: proposal flight ownership changed")
	}
	flight.result = result
	flight.err = err
	if err != nil &&
		(uncertain || flight.preserveReservation) {
		node.proposalReservations[eventID] = bytes.Clone(flight.canonical)
	} else {
		delete(node.proposalReservations, eventID)
	}
	delete(node.proposalFlights, eventID)
	close(flight.done)
}

func (node *SingleNode) lookupCommitted(
	ctx context.Context,
	signed event.SignedEvent,
) (store.ApplyResult, bool, error) {
	lookup, found, err := node.state.LookupCommandResult(
		ctx,
		signed.Proposal().EventID,
	)
	if err != nil || !found {
		return store.ApplyResult{}, found, err
	}
	if !bytes.Equal(lookup.CanonicalProposal, signed.CanonicalBytes()) {
		return store.ApplyResult{}, false, store.ErrIdempotencyConflict
	}
	return store.ApplyResult{
		Heads:             lookup.CurrentHeads,
		Outcome:           lookup.Outcome,
		AdmissionRevision: node.state.AdmissionRevision(),
		Duplicate:         true,
	}, true, nil
}

func (node *SingleNode) handleLookupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrCommandResultCorrupt) ||
		errors.Is(err, store.ErrIntegrityCheck) ||
		errors.Is(err, store.ErrCorrupt) {
		return node.haltNode(fmt.Errorf(
			"committed command lookup failed integrity checks: %w",
			err,
		))
	}
	return err
}

func (node *SingleNode) haltNode(cause error) error {
	if cause == nil {
		return nil
	}
	terminal := fmt.Errorf("consensus: terminal node failure: %w", cause)
	node.recordFatal(terminal)
	_ = node.shutdownRaft()
	return node.FatalError()
}

// Barrier waits until all prior Raft commands have reached SQLite.
func (node *SingleNode) Barrier(ctx context.Context) error {
	if node == nil || node.raft == nil || ctx == nil {
		return ErrInvalidNodeOptions
	}
	if err := node.beginOperation(); err != nil {
		return err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return err
	}
	return waitFuture(ctx, node.raft.Barrier(contextTimeout(ctx)))
}

// Snapshot asks Raft to persist the current SQLite-bound FSM anchor.
func (node *SingleNode) Snapshot(ctx context.Context) error {
	if node == nil || node.raft == nil || ctx == nil {
		return ErrInvalidNodeOptions
	}
	if err := node.beginOperation(); err != nil {
		return err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return err
	}
	return waitFuture(ctx, node.raft.Snapshot())
}

// View returns one transactionally consistent durable state view.
func (node *SingleNode) View(ctx context.Context) (store.StateView, error) {
	if node == nil || node.state == nil || ctx == nil {
		return store.StateView{}, ErrInvalidNodeOptions
	}
	if err := node.beginOperation(); err != nil {
		return store.StateView{}, err
	}
	defer node.endOperation()
	return node.state.View(ctx)
}

// PeerAdmissionSnapshot returns the latest immutable state published only
// after its corresponding SQLite apply transaction committed.
func (node *SingleNode) PeerAdmissionSnapshot() (*peerauth.Snapshot, error) {
	if node == nil || node.fsm == nil {
		return nil, ErrInvalidNodeOptions
	}
	if err := node.beginOperation(); err != nil {
		return nil, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return nil, err
	}
	snapshot := node.fsm.admission.Load()
	if snapshot == nil ||
		snapshot.snapshot == nil ||
		snapshot.revision == 0 ||
		snapshot.revision != node.state.AdmissionRevision() {
		return nil, ErrPeerAdmissionUnavailable
	}
	return snapshot.snapshot, nil
}

// PeerAdmissionChanges claims the access-change subscription for the session's
// single peer-ingress reconciler. A second claim returns a closed channel and
// must fail closed. The consumer reloads the snapshot after every signal.
func (node *SingleNode) PeerAdmissionChanges() <-chan struct{} {
	if node == nil || node.fsm == nil {
		return nil
	}
	if !node.peerAdmissionChangesClaimed.CompareAndSwap(false, true) {
		return closedChangeChannel()
	}
	return node.fsm.authorizationChanges.subscribe()
}

// Status returns one durable coordination cut plus a nearby nonblocking Raft
// observation for local operator surfaces.
func (node *SingleNode) Status(
	ctx context.Context,
) (coordstatus.Snapshot, error) {
	if node == nil || node.raft == nil || node.state == nil || ctx == nil {
		return coordstatus.Snapshot{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return coordstatus.Snapshot{}, err
	}
	if err := node.beginOperation(); err != nil {
		return coordstatus.Snapshot{}, err
	}
	defer node.endOperation()

	localDeviceID := domain.DeviceID(node.serverID)
	durable, err := node.state.LocalState().StatusSnapshot(
		ctx,
		localDeviceID,
		coordstatus.MaxTasks,
	)
	if err != nil {
		return coordstatus.Snapshot{}, err
	}
	runtime := coordstatus.RuntimeSnapshot{
		LocalDeviceID: localDeviceID,
		Role:          raftStatusRole(node.raft.State()),
	}
	configuration := node.fsm.committedConfiguration()
	if configuration == nil && node.transportGate != nil {
		configuration = node.transportGate.effectiveConfiguration(node)
	}
	if configuration == nil && node.single {
		runtime.LiveVoterDeviceIDs = durable.VoterSet.VoterDeviceIDs()
	} else if configuration == nil {
		return coordstatus.Snapshot{}, ErrConsensusAuthorizationUnavailable
	} else {
		for _, server := range configuration.Configuration.Servers {
			if server.Suffrage != raft.Voter {
				continue
			}
			id := domain.DeviceID(server.ID)
			if !id.Valid() {
				return coordstatus.Snapshot{}, ErrInvalidRaftTopology
			}
			runtime.LiveVoterDeviceIDs = append(
				runtime.LiveVoterDeviceIDs,
				id,
			)
		}
		sort.Slice(
			runtime.LiveVoterDeviceIDs,
			func(left, right int) bool {
				return runtime.LiveVoterDeviceIDs[left] <
					runtime.LiveVoterDeviceIDs[right]
			},
		)
	}
	runtime.ConfigurationReconciled = sameDeviceIDs(
		runtime.LiveVoterDeviceIDs,
		durable.VoterSet.VoterDeviceIDs(),
	)
	if node.FatalError() != nil {
		runtime.State = coordstatus.ConsensusHalted
		runtime.StrongWrites = coordstatus.StrongWritesBlocked
	} else {
		commitIndex := node.raft.CommitIndex()
		ready, err := node.appliedThroughCommit(commitIndex)
		if err != nil {
			return coordstatus.Snapshot{}, err
		}
		leaderAddress, leaderID := node.raft.LeaderWithID()
		if leaderID != "" &&
			(node.single ||
				leaderAddress == raft.ServerAddress(leaderID)) &&
			domain.DeviceID(leaderID).Valid() {
			runtime.LeaderDeviceID = domain.DeviceID(leaderID)
		}
		switch runtime.Role {
		case coordstatus.RoleLeader:
			runtime.State = coordstatus.ConsensusElecting
			runtime.StrongWrites = coordstatus.StrongWritesWaiting
			if ready &&
				runtime.LeaderDeviceID == localDeviceID &&
				node.IsLeader() {
				runtime.State = coordstatus.ConsensusReady
				runtime.StrongWrites = coordstatus.StrongWritesAvailable
			}
		case coordstatus.RoleCandidate:
			runtime.State = coordstatus.ConsensusElecting
			runtime.StrongWrites = coordstatus.StrongWritesWaiting
		case coordstatus.RoleFollower:
			runtime.State = coordstatus.ConsensusElecting
			if ready && runtime.LeaderDeviceID != "" {
				runtime.State = coordstatus.ConsensusReady
			}
			runtime.StrongWrites = coordstatus.StrongWritesWaiting
		default:
			runtime.State = coordstatus.ConsensusStarting
			runtime.StrongWrites = coordstatus.StrongWritesWaiting
		}
	}
	runtime.QuorumRequired = len(runtime.LiveVoterDeviceIDs)/2 + 1
	snapshot := coordstatus.Snapshot{
		Durable: durable,
		Runtime: runtime,
	}
	if err := snapshot.Validate(); err != nil {
		return coordstatus.Snapshot{}, fmt.Errorf(
			"consensus: invalid status snapshot: %w",
			err,
		)
	}
	return snapshot, nil
}

func raftStatusRole(state raft.RaftState) coordstatus.ConsensusRole {
	switch state {
	case raft.Follower:
		return coordstatus.RoleFollower
	case raft.Candidate:
		return coordstatus.RoleCandidate
	case raft.Leader:
		return coordstatus.RoleLeader
	case raft.Shutdown:
		return coordstatus.RoleShutdown
	default:
		return coordstatus.RoleShutdown
	}
}

func sameDeviceIDs(left, right []domain.DeviceID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// LocalState returns the restricted local-only durable-state capability. The
// capability remains owned by this node and becomes unusable when it closes.
func (node *SingleNode) LocalState() (store.LocalState, error) {
	if node == nil || node.state == nil {
		return store.LocalState{}, ErrInvalidNodeOptions
	}
	node.lifecycleMu.Lock()
	closing := node.closing
	node.lifecycleMu.Unlock()
	if closing {
		return store.LocalState{}, ErrNodeClosed
	}
	if err := node.FatalError(); err != nil {
		return store.LocalState{}, err
	}
	return node.state.LocalState(), nil
}

func contextTimeout(ctx context.Context) time.Duration {
	deadline, exists := ctx.Deadline()
	if !exists {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}

type raftFuture interface {
	Error() error
}

func waitFuture(ctx context.Context, future raftFuture) error {
	if ctx == nil || future == nil {
		return ErrInvalidNodeOptions
	}
	done := make(chan error, 1)
	go func() {
		done <- future.Error()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops Raft, which closes its owned transport, before durable stores.
func (node *SingleNode) Close() error {
	if node == nil {
		return ErrInvalidNodeOptions
	}
	node.closeOnce.Do(func() {
		node.lifecycleMu.Lock()
		node.closing = true
		close(node.closeStarted)
		node.lifecycleMu.Unlock()
		if node.fsm != nil {
			node.fsm.closePeerAdmissionChanges()
		}
		if node.transportGate != nil {
			node.transportGate.close()
		}
		if node.monitorStop != nil {
			close(node.monitorStop)
		}
		var errs []error
		if node.raft != nil {
			if err := node.shutdownRaft(); err != nil &&
				!errors.Is(err, raft.ErrRaftShutdown) {
				errs = append(errs, fmt.Errorf("shutdown Raft: %w", err))
			}
		}
		node.active.Wait()
		if node.monitorDone != nil {
			<-node.monitorDone
		}
		if node.state != nil {
			if err := node.state.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close state store: %w", err))
			}
		}
		if node.stable != nil {
			if err := node.stable.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close Raft store: %w", err))
			}
		}
		node.closeErr = errors.Join(errs...)
	})
	return node.closeErr
}
