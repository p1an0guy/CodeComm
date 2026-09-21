package consensus

import (
	"context"
	"time"

	"github.com/hashicorp/raft"
)

const gracefulLeadershipTransferTimeout = 3 * time.Second

// acquireGracefulCloseGuard prevents a new application or configuration
// entry from racing the final barrier and leadership handoff.
func (node *SingleNode) acquireGracefulCloseGuard(
	ctx context.Context,
) *raftEnqueueGuard {
	if node == nil ||
		node.raft == nil ||
		node.raftEnqueue == nil ||
		node.closeStarted == nil ||
		ctx == nil {
		return nil
	}
	select {
	case node.raftEnqueue <- struct{}{}:
		return &raftEnqueueGuard{node: node}
	case <-ctx.Done():
		return nil
	case <-node.closeStarted:
		return nil
	}
}

// transferLeadershipBeforeClose drains entries already accepted by Raft and
// performs one bounded handoff. Shutdown remains best-effort when quorum or a
// transfer target is unavailable.
func (node *SingleNode) transferLeadershipBeforeClose(
	ctx context.Context,
) {
	if node == nil ||
		node.raft == nil ||
		node.single ||
		ctx == nil ||
		node.raft.State() != raft.Leader {
		return
	}
	barrier, err := node.enqueueRaftBarrier(ctx)
	if err != nil ||
		waitFuture(ctx, barrier) != nil ||
		node.raft.State() != raft.Leader {
		return
	}
	_ = waitFuture(ctx, node.invokeRaftLeadershipTransferBeforeClose())
}

// invokeRaftLeadershipTransferBeforeClose is the shutdown-only adapter for
// HashiCorp Raft's best-current-voter target selection.
func (node *SingleNode) invokeRaftLeadershipTransferBeforeClose() raft.Future {
	return node.raft.LeadershipTransfer()
}
