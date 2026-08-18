package consensus

import (
	"context"
	"time"

	"github.com/hashicorp/raft"
)

const voterReconciliationRetryInterval = 250 * time.Millisecond

const (
	voterReconciliationRetryMax       = 5 * time.Second
	voterReconciliationAttemptTimeout = 30 * time.Second
)

func (node *SingleNode) startVoterReconciliation() {
	if node == nil ||
		node.voterReconcileDone != nil ||
		node.single {
		return
	}
	node.voterReconcileDone = make(chan struct{})
	go node.runVoterReconciliation()
}

func (node *SingleNode) runVoterReconciliation() {
	defer close(node.voterReconcileDone)
	timer := time.NewTimer(0)
	defer timer.Stop()
	leadershipChanges := node.raft.LeaderCh()
	reconciliationChanges := node.fsm.authorizationChanges.
		subscribeWithoutInitial()
	retry := voterReconciliationRetryInterval
	for {
		changed := false
		select {
		case <-node.closeStarted:
			return
		case <-node.fatalSet:
			return
		case _, open := <-leadershipChanges:
			if !open {
				leadershipChanges = nil
			}
			changed = true
		case _, open := <-reconciliationChanges:
			if !open {
				reconciliationChanges = nil
			}
			changed = true
		case <-timer.C:
		}

		var attemptErr error
		if node.raft.State() == raft.Leader {
			// Integrity failures halt inside their boundary. Every other
			// result is retried from a fresh committed cut.
			attemptContext, cancel := context.WithTimeout(
				context.Background(),
				voterReconciliationAttemptTimeout,
			)
			attemptErr = node.ReconcileVoterSet(attemptContext)
			cancel()
		}
		switch {
		case changed:
			retry = voterReconciliationRetryInterval
		case attemptErr != nil:
			retry = min(
				retry*2,
				voterReconciliationRetryMax,
			)
		default:
			retry = voterReconciliationRetryMax
		}
		timer.Reset(retry)
	}
}
