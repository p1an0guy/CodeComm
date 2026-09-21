package consensus

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
)

var (
	ErrConsensusAuthorizationUnavailable = errors.New(
		"consensus: transport authorization unavailable",
	)
	ErrConsensusPeerOutsideConfiguration = errors.New(
		"consensus: peer is outside the committed Raft configuration",
	)
	ErrConsensusReplicationUnauthorized = errors.New(
		"consensus: replication is not authorized",
	)
)

const consensusAuthorizationReadAttempts = 3

// nodeTransportGate breaks the node/transport construction cycle without an
// allow-by-default interval. Before bind, every authorization method fails.
type nodeTransportGate struct {
	bootstrap committedRaftConfiguration
	node      atomic.Pointer[SingleNode]

	changes chan struct{}
	bound   chan *SingleNode
	stop    chan struct{}
	done    chan struct{}

	bindOnce                    sync.Once
	closeOnce                   sync.Once
	authorizationChangesClaimed atomic.Bool
}

func newNodeTransportGate(
	bootstrap raft.Configuration,
) *nodeTransportGate {
	gate := &nodeTransportGate{
		bootstrap: committedRaftConfiguration{
			Index:         1,
			Configuration: bootstrap.Clone(),
		},
		changes: make(chan struct{}, 1),
		bound:   make(chan *SingleNode, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go gate.relay()
	return gate
}

func (gate *nodeTransportGate) bind(node *SingleNode) {
	if gate == nil || node == nil {
		return
	}
	gate.bindOnce.Do(func() {
		gate.node.Store(node)
		select {
		case gate.bound <- node:
		case <-gate.stop:
		}
	})
}

func (gate *nodeTransportGate) relay() {
	defer close(gate.done)
	defer close(gate.changes)
	var node *SingleNode
	select {
	case node = <-gate.bound:
	case <-gate.stop:
		return
	}
	if node == nil || node.fsm == nil {
		return
	}
	subscription := node.fsm.authorizationChanges.subscribe()
	gate.signal()
	for {
		select {
		case _, open := <-subscription:
			if !open {
				return
			}
			gate.signal()
		case <-gate.stop:
			return
		}
	}
}

func (gate *nodeTransportGate) signal() {
	select {
	case gate.changes <- struct{}{}:
	default:
	}
}

func (gate *nodeTransportGate) close() {
	if gate == nil {
		return
	}
	gate.closeOnce.Do(func() {
		close(gate.stop)
		<-gate.done
	})
}

func (gate *nodeTransportGate) AuthorizationChanges() <-chan struct{} {
	if gate == nil {
		return closedChangeChannel()
	}
	if !gate.authorizationChangesClaimed.CompareAndSwap(false, true) {
		return closedChangeChannel()
	}
	return gate.changes
}

func (gate *nodeTransportGate) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	node, err := gate.activeNode()
	if err != nil {
		return nil, err
	}
	return node.peerAdmissionSnapshotForTransport()
}

// ConsensusControlHandler returns the late-bound fail-closed handler used by
// the transport factory while the node is still under construction.
func (gate *nodeTransportGate) ConsensusControlHandler() http.Handler {
	return gate
}

func (gate *nodeTransportGate) AuthorizePeer(
	deviceID domain.DeviceID,
) error {
	if !deviceID.Valid() {
		return ErrConsensusPeerOutsideConfiguration
	}
	node, err := gate.activeNode()
	if err != nil {
		return err
	}
	for range consensusAuthorizationReadAttempts {
		commitIndex := node.raft.CommitIndex()
		_, configurationIndex, err := node.committedFSMIndexes(
			commitIndex,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: %v",
				ErrConsensusAuthorizationUnavailable,
				err,
			)
		}
		if err := gate.authorizeAppliedPeer(
			node,
			deviceID,
			configurationIndex,
		); err != nil {
			return err
		}
		if node.raft.CommitIndex() == commitIndex {
			return nil
		}
	}
	return ErrConsensusAuthorizationUnavailable
}

func (gate *nodeTransportGate) authorizeAppliedPeer(
	node *SingleNode,
	deviceID domain.DeviceID,
	configurationIndex uint64,
) error {
	admission, err := node.peerAdmissionSnapshotForTransport()
	if err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrConsensusAuthorizationUnavailable,
			err,
		)
	}
	member, exists := admission.Member(deviceID)
	if !exists || member.Status != device.StatusActive {
		return ErrConsensusPeerOutsideConfiguration
	}
	configuration := gate.effectiveConfiguration(node)
	if configuration == nil ||
		configuration.Index < configurationIndex ||
		!configuration.contains(deviceID) {
		return ErrConsensusPeerOutsideConfiguration
	}
	return nil
}

func (gate *nodeTransportGate) effectiveConfiguration(
	node *SingleNode,
) *committedRaftConfiguration {
	if node == nil || node.fsm == nil {
		return nil
	}
	configuration := node.fsm.committedConfiguration()
	if configuration == nil &&
		len(gate.bootstrap.Configuration.Servers) != 0 {
		configuration = cloneCommittedRaftConfiguration(&gate.bootstrap)
	}
	return configuration
}

func (gate *nodeTransportGate) AuthorizeReplication(
	deviceID domain.DeviceID,
) error {
	return gate.authorizeReplication(deviceID, false)
}

// AuthorizeCommitProbe permits only the non-mutating no-op/barrier AppendEntries
// class enforced by the maintained transport. It lets an elected leader
// re-establish a volatile commit index without disclosing an unapplied command
// tail.
func (gate *nodeTransportGate) AuthorizeCommitProbe(
	deviceID domain.DeviceID,
) error {
	return gate.authorizeReplication(deviceID, true)
}

func (gate *nodeTransportGate) authorizeReplication(
	deviceID domain.DeviceID,
	commitProbe bool,
) error {
	if err := gate.AuthorizePeer(deviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrConsensusReplicationUnauthorized, err)
	}
	node, err := gate.activeNode()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConsensusReplicationUnauthorized, err)
	}
	for range consensusAuthorizationReadAttempts {
		if !node.isRaftLeaderForTransport() {
			return ErrConsensusReplicationUnauthorized
		}
		commitIndex := node.raft.CommitIndex()
		if !replicationClassAllowed(commitIndex, commitProbe) {
			return ErrConsensusReplicationUnauthorized
		}
		commandIndex, configurationIndex, err :=
			node.committedFSMIndexes(commitIndex)
		if err != nil {
			return fmt.Errorf(
				"%w: %v",
				ErrConsensusReplicationUnauthorized,
				err,
			)
		}
		if node.fsm.appliedCommandIndex.Load() < commandIndex {
			return ErrConsensusReplicationUnauthorized
		}
		if err := gate.authorizeAppliedPeer(
			node,
			deviceID,
			configurationIndex,
		); err != nil {
			return fmt.Errorf(
				"%w: %w",
				ErrConsensusReplicationUnauthorized,
				err,
			)
		}
		if node.raft.CommitIndex() == commitIndex &&
			node.isRaftLeaderForTransport() {
			return nil
		}
	}
	return ErrConsensusReplicationUnauthorized
}

func replicationClassAllowed(
	commitIndex uint64,
	commitProbe bool,
) bool {
	return commitIndex > 0 || commitProbe
}

func (gate *nodeTransportGate) activeNode() (*SingleNode, error) {
	if gate == nil {
		return nil, ErrConsensusAuthorizationUnavailable
	}
	select {
	case <-gate.stop:
		return nil, ErrConsensusAuthorizationUnavailable
	default:
	}
	node := gate.node.Load()
	if node == nil || node.raft == nil || node.fsm == nil {
		return nil, ErrConsensusAuthorizationUnavailable
	}
	if err := node.FatalError(); err != nil {
		return nil, ErrConsensusAuthorizationUnavailable
	}
	node.lifecycleMu.Lock()
	closing := node.closing
	node.lifecycleMu.Unlock()
	if closing {
		return nil, ErrConsensusAuthorizationUnavailable
	}
	return node, nil
}

func (node *SingleNode) committedFSMIndexes(
	commitIndex uint64,
) (uint64, uint64, error) {
	if node == nil || node.stable == nil || node.raft == nil {
		return 0, 0, ErrConsensusAuthorizationUnavailable
	}
	node.fsmScanMu.Lock()
	defer node.fsmScanMu.Unlock()
	if commitIndex <= node.fsmScannedCommit {
		return node.committedCommandLogIndex,
			node.committedConfigurationLogIndex,
			nil
	}
	first, err := node.stable.FirstIndex()
	if err != nil {
		return 0, 0, err
	}
	start := node.fsmScannedCommit + 1
	if first == 0 {
		node.fsmScannedCommit = commitIndex
		return node.committedCommandLogIndex,
			node.committedConfigurationLogIndex,
			nil
	}
	if start < first {
		start = first
	}
	for index := start; index <= commitIndex; index++ {
		var entry raft.Log
		if err := node.stable.GetLog(index, &entry); err != nil {
			return 0, 0, err
		}
		switch entry.Type {
		case raft.LogCommand:
			node.committedCommandLogIndex = index
		case raft.LogConfiguration:
			node.committedConfigurationLogIndex = index
		}
		if index == ^uint64(0) {
			break
		}
	}
	node.fsmScannedCommit = commitIndex
	return node.committedCommandLogIndex,
		node.committedConfigurationLogIndex,
		nil
}

var _ ConsensusTransportGate = (*nodeTransportGate)(nil)
