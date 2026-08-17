package consensus

import "sync"

const authorizationChangeSubscribersMax = 8

// changeFeed provides bounded coalescing fanout. A closed subscription means
// authorization is unavailable and consumers must fail closed.
type changeFeed struct {
	mu          sync.Mutex
	nextID      uint64
	closed      bool
	subscribers map[uint64]chan struct{}
}

func newChangeFeed() *changeFeed {
	return &changeFeed{subscribers: make(map[uint64]chan struct{})}
}

func closedChangeChannel() <-chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}

func (feed *changeFeed) subscribe() <-chan struct{} {
	return feed.subscribeWithInitial(true)
}

func (feed *changeFeed) subscribeWithoutInitial() <-chan struct{} {
	return feed.subscribeWithInitial(false)
}

func (feed *changeFeed) subscribeWithInitial(
	initial bool,
) <-chan struct{} {
	channel := make(chan struct{}, 1)
	if feed == nil {
		close(channel)
		return channel
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	if feed.closed ||
		len(feed.subscribers) >= authorizationChangeSubscribersMax {
		close(channel)
		return channel
	}
	feed.nextID++
	feed.subscribers[feed.nextID] = channel
	if initial {
		channel <- struct{}{}
	}
	return channel
}

func (feed *changeFeed) signal() {
	if feed == nil {
		return
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	if feed.closed {
		return
	}
	for _, channel := range feed.subscribers {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
}

func (feed *changeFeed) close() {
	if feed == nil {
		return
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	if feed.closed {
		return
	}
	feed.closed = true
	for id, channel := range feed.subscribers {
		close(channel)
		delete(feed.subscribers, id)
	}
}

func (feed *changeFeed) isClosed() bool {
	if feed == nil {
		return true
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	return feed.closed
}
