package consensus

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

const raftCommitRecoveryPollInterval = 10 * time.Millisecond

// raftEnqueueGuard serializes the ordering cut shared by application commands
// and membership changes. Slow receipt collection happens before acquisition.
type raftEnqueueGuard struct {
	node *SingleNode
	once sync.Once
}

func (node *SingleNode) acquireRaftEnqueue(
	ctx context.Context,
) (*raftEnqueueGuard, error) {
	if node == nil ||
		node.raft == nil ||
		node.raftEnqueue == nil ||
		node.closeStarted == nil ||
		node.fatalSet == nil ||
		ctx == nil {
		return nil, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case node.raftEnqueue <- struct{}{}:
		if err := node.waitForRaftCommitRecovery(ctx); err != nil {
			<-node.raftEnqueue
			return nil, err
		}
		return &raftEnqueueGuard{node: node}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-node.closeStarted:
		return nil, ErrNodeClosed
	case <-node.fatalSet:
		return nil, node.FatalError()
	}
}

func (guard *raftEnqueueGuard) release() {
	if guard == nil || guard.node == nil {
		return
	}
	guard.once.Do(func() {
		<-guard.node.raftEnqueue
	})
}

func (node *SingleNode) enqueueRaftApply(
	ctx context.Context,
	command []byte,
	heldGuard *raftEnqueueGuard,
) (raft.ApplyFuture, error) {
	guard := heldGuard
	if guard == nil {
		var err error
		guard, err = node.acquireRaftEnqueue(ctx)
		if err != nil {
			return nil, err
		}
		defer guard.release()
	} else if guard.node != node {
		return nil, ErrInvalidNodeOptions
	}
	return node.raft.Apply(command, contextTimeout(ctx)), nil
}

// waitForRaftCommitRecovery prevents a cold leader from accepting an
// application or barrier before its election no-op has recovered the volatile
// commit index. Calling Raft while this node is not leader is also forbidden:
// an API send racing a follower-to-leader transition could otherwise be
// consumed by the new leader before that no-op commits.
func (node *SingleNode) waitForRaftCommitRecovery(
	ctx context.Context,
) error {
	if node == nil ||
		node.raft == nil ||
		node.closeStarted == nil ||
		node.fatalSet == nil ||
		ctx == nil {
		return ErrInvalidNodeOptions
	}
	ticker := time.NewTicker(raftCommitRecoveryPollInterval)
	defer ticker.Stop()
	for {
		if err := node.preEnqueueError(ctx); err != nil {
			return err
		}
		if node.raft.State() != raft.Leader {
			return raft.ErrNotLeader
		}
		if node.raft.CommitIndex() > 0 {
			if node.raft.State() != raft.Leader {
				return raft.ErrNotLeader
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-node.closeStarted:
			return ErrNodeClosed
		case <-node.fatalSet:
			return node.FatalError()
		case <-ticker.C:
		}
	}
}

func (node *SingleNode) waitRaftBarrier(ctx context.Context) error {
	future, err := node.enqueueRaftBarrier(ctx)
	if err != nil {
		return err
	}
	return waitFuture(ctx, future)
}

func (node *SingleNode) enqueueRaftBarrier(
	ctx context.Context,
) (raft.Future, error) {
	if err := node.waitForRaftCommitRecovery(ctx); err != nil {
		return nil, err
	}
	return node.raft.Barrier(contextTimeout(ctx)), nil
}

// waitRaftFutureWithGuard keeps the enqueue cut closed until future resolves.
// If the caller leaves first, the waiter assumes ownership and releases the
// guard only after Raft reports the final outcome.
func (node *SingleNode) waitRaftFutureWithGuard(
	ctx context.Context,
	future raftFuture,
	guard *raftEnqueueGuard,
) (error, bool) {
	if node == nil || ctx == nil || future == nil || guard == nil {
		return ErrInvalidNodeOptions, true
	}
	completed := make(chan error)
	abandoned := make(chan struct{})
	node.active.Add(1)
	go func() {
		defer node.active.Done()
		err := future.Error()
		select {
		case completed <- err:
		case <-abandoned:
			guard.release()
		}
	}()
	abandon := func(err error) (error, bool) {
		close(abandoned)
		return err, false
	}
	select {
	case err := <-completed:
		return err, true
	case <-ctx.Done():
		return abandon(ctx.Err())
	case <-node.closeStarted:
		return abandon(ErrNodeClosed)
	case <-node.fatalSet:
		return abandon(node.FatalError())
	}
}
