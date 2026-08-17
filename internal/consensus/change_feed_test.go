package consensus

import (
	"testing"
	"time"
)

func TestAuthorizationChangeFeedFansOutAndCloses(t *testing.T) {
	feed := newChangeFeed()
	first := feed.subscribe()
	second := feed.subscribe()
	for name, subscription := range map[string]<-chan struct{}{
		"first":  first,
		"second": second,
	} {
		select {
		case _, open := <-subscription:
			if !open {
				t.Fatalf("%s subscription closed before initial signal", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s subscription missed initial signal", name)
		}
	}
	feed.signal()
	for name, subscription := range map[string]<-chan struct{}{
		"first":  first,
		"second": second,
	} {
		select {
		case _, open := <-subscription:
			if !open {
				t.Fatalf("%s subscription closed before signal", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s subscription missed signal", name)
		}
	}
	feed.close()
	for name, subscription := range map[string]<-chan struct{}{
		"first":  first,
		"second": second,
	} {
		select {
		case _, open := <-subscription:
			if open {
				t.Fatalf("%s subscription remained open", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s subscription did not close", name)
		}
	}
}

func TestAuthorizationChangeFeedFailsClosedAtSubscriberLimit(t *testing.T) {
	feed := newChangeFeed()
	for range authorizationChangeSubscribersMax {
		subscription := feed.subscribe()
		select {
		case _, open := <-subscription:
			if !open {
				t.Fatal("bounded subscription unexpectedly closed")
			}
		case <-time.After(time.Second):
			t.Fatal("bounded subscription omitted initial signal")
		}
	}
	overflow := feed.subscribe()
	select {
	case _, open := <-overflow:
		if open {
			t.Fatal("overflow subscription remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("overflow subscription did not fail closed")
	}
	feed.close()
}
