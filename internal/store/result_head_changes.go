package store

import (
	"context"
	"fmt"
	"sync"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

// ResultHead is the latest durable event/result position in the active
// lineage. Callers that receive a change signal reread this value; signals are
// intentionally coalesced and do not represent an event queue.
type ResultHead struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	ChainIndex         uint64
	ResultIndex        uint64
}

type resultHeadChangeSubscriber struct {
	changes     chan struct{}
	stopContext func() bool
}

type resultHeadChangeFeed struct {
	mu          sync.Mutex
	nextID      uint64
	closed      bool
	subscribers map[uint64]*resultHeadChangeSubscriber
}

func newResultHeadChangeFeed() *resultHeadChangeFeed {
	return &resultHeadChangeFeed{
		subscribers: make(map[uint64]*resultHeadChangeSubscriber),
	}
}

// ResultHead returns the latest durable active-lineage position.
func (state LocalState) ResultHead(ctx context.Context) (ResultHead, error) {
	var result ResultHead
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		committed, found, err := readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"%w: store has no active generation",
				ErrApplyConflict,
			)
		}
		workspaceID, err := activeWorkspaceID(conn, committed)
		if err != nil {
			return err
		}
		result = ResultHead{
			SessionID:          committed.sessionID,
			WorkspaceID:        workspaceID,
			RecoveryGeneration: committed.recoveryGeneration,
			ChainIndex:         committed.chainIndex,
			ResultIndex:        committed.resultIndex,
		}
		return nil
	})
	if err != nil {
		return ResultHead{}, err
	}
	return result, nil
}

// SubscribeResultHeadChanges returns a capacity-one, initially-ready change
// channel. After every receive, callers must reread ResultHead. Canceling ctx
// unregisters and closes the subscription; Store.Close closes all subscribers.
func (state LocalState) SubscribeResultHeadChanges(
	ctx context.Context,
) (<-chan struct{}, error) {
	if err := state.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidLocalState)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release, err := state.beginOperation()
	if err != nil {
		return nil, err
	}
	defer release()
	if state.store.resultHeadChanges == nil {
		return nil, ErrInvalidLocalState
	}
	return state.store.resultHeadChanges.subscribe(ctx)
}

func (feed *resultHeadChangeFeed) subscribe(
	ctx context.Context,
) (<-chan struct{}, error) {
	subscriber := &resultHeadChangeSubscriber{
		changes: make(chan struct{}, 1),
	}

	feed.mu.Lock()
	if feed.closed {
		feed.mu.Unlock()
		close(subscriber.changes)
		return nil, ErrClosed
	}
	feed.nextID++
	id := feed.nextID
	feed.subscribers[id] = subscriber
	subscriber.changes <- struct{}{}
	feed.mu.Unlock()

	stopContext := context.AfterFunc(ctx, func() {
		feed.unsubscribeFromContext(id)
	})
	feed.mu.Lock()
	current, registered := feed.subscribers[id]
	if registered && current == subscriber {
		subscriber.stopContext = stopContext
		feed.mu.Unlock()
		return subscriber.changes, nil
	}
	feed.mu.Unlock()
	stopContext()
	return subscriber.changes, nil
}

func (feed *resultHeadChangeFeed) unsubscribeFromContext(id uint64) {
	feed.mu.Lock()
	defer feed.mu.Unlock()
	subscriber, exists := feed.subscribers[id]
	if !exists {
		return
	}
	delete(feed.subscribers, id)
	close(subscriber.changes)
}

func (feed *resultHeadChangeFeed) signal() {
	if feed == nil {
		return
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	if feed.closed {
		return
	}
	for _, subscriber := range feed.subscribers {
		select {
		case subscriber.changes <- struct{}{}:
		default:
		}
	}
}

func (feed *resultHeadChangeFeed) close() {
	if feed == nil {
		return
	}
	feed.mu.Lock()
	if feed.closed {
		feed.mu.Unlock()
		return
	}
	feed.closed = true
	stops := make([]func() bool, 0, len(feed.subscribers))
	for id, subscriber := range feed.subscribers {
		delete(feed.subscribers, id)
		close(subscriber.changes)
		if subscriber.stopContext != nil {
			stops = append(stops, subscriber.stopContext)
		}
	}
	feed.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

func (store *Store) signalResultHeadChange() {
	if store == nil {
		return
	}
	store.resultHeadChanges.signal()
}

func sameResultHeadState(left, right consensusState) bool {
	return left.sessionID == right.sessionID &&
		left.recoveryGeneration == right.recoveryGeneration &&
		left.chainIndex == right.chainIndex &&
		left.chainHash == right.chainHash &&
		left.resultIndex == right.resultIndex &&
		left.resultHash == right.resultHash
}
