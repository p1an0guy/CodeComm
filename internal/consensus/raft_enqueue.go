package consensus

import (
	"context"
	"sync"

	"github.com/hashicorp/raft"
)

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
		if err := node.preEnqueueError(ctx); err != nil {
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
) (raft.ApplyFuture, error) {
	guard, err := node.acquireRaftEnqueue(ctx)
	if err != nil {
		return nil, err
	}
	defer guard.release()
	return node.raft.Apply(command, contextTimeout(ctx)), nil
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
