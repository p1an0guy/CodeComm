package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestRetryableDaemonSnapshotPublicationErrors(t *testing.T) {
	for _, candidate := range []error{
		raft.ErrNotLeader,
		consensus.ErrProposalForwardingUnavailable,
		fmt.Errorf(
			"forward checkpoint: %w",
			consensus.ErrProposalForwardingUnavailable,
		),
	} {
		if !retryableDaemonSnapshotPublication(candidate) {
			t.Fatalf("error %v was not retryable", candidate)
		}
	}
	if retryableDaemonSnapshotPublication(errors.New("corrupt snapshot")) {
		t.Fatal("unclassified snapshot failure was retryable")
	}
}

func TestDaemonLogicalSnapshotPublisherWakesForAuthorizationChange(
	t *testing.T,
) {
	initial, privateKey, deviceID := daemonTestInitialState(t)
	t.Cleanup(func() { clear(privateKey) })
	repository := openDaemonSnapshotTestRepository(
		t,
		filepath.Join(t.TempDir(), "state.db"),
		initial,
		deviceID,
		privateKey.Public().(ed25519.PublicKey),
	)
	eventIDs := []domain.UUIDv7{
		"018f47de-89ab-7def-8123-b123456789ab",
		"018f47de-89ab-7def-8123-c123456789ab",
	}
	source := &daemonSnapshotWakeSource{
		changes: make(chan struct{}, 1),
		calls:   make(chan int, len(eventIDs)),
		lookups: []store.AppliedCheckpointLookup{
			{
				Record: daemonSnapshotTestCheckpoint(
					t,
					initial,
					deviceID,
					eventIDs[0],
				),
				AppliedLogIndex: 2,
			},
			{
				Record: daemonSnapshotTestCheckpoint(
					t,
					initial,
					deviceID,
					eventIDs[1],
				),
				AppliedLogIndex: 3,
			},
		},
	}
	runContext, cancel := context.WithCancel(context.Background())
	publisher := &daemonLogicalSnapshotPublisher{
		checkpoints: source,
		records:     daemonSnapshotRecordSourceStub{},
		repository:  repository,
		deviceID:    deviceID,
		publicKey: bytesClonePublicKey(
			privateKey.Public().(ed25519.PublicKey),
		),
		privateKey: privateKey,
		build: func(
			ctx context.Context,
			_ snapshotbuilder.RecordSource,
			options snapshotbuilder.Options,
		) (snapshotbuilder.Snapshot, error) {
			return daemonSnapshotTestBuild(ctx, initial, options)
		},
		interval:     time.Hour,
		retry:        time.Second,
		buildTimeout: time.Minute,
		cancel:       cancel,
		done:         make(chan struct{}),
	}
	go publisher.run(runContext)
	t.Cleanup(func() {
		if err := publisher.BeginClose(); err != nil {
			t.Errorf("BeginClose(): %v", err)
		}
		if err := publisher.Wait(); err != nil {
			t.Errorf("Wait(): %v", err)
		}
	})

	waitDaemonSnapshotPublisherCall(t, source.calls, 1)
	source.changes <- struct{}{}
	waitDaemonSnapshotPublisherCall(t, source.calls, 2)

	deadline := time.Now().Add(5 * time.Second)
	for {
		root, err := repository.LatestSnapshot(t.Context())
		if err == nil &&
			root.Unsigned().Input().CheckpointEventID == eventIDs[1] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"latest checkpoint did not reach %s: (%s, %v)",
				eventIDs[1],
				root.Unsigned().Input().CheckpointEventID,
				err,
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type daemonSnapshotWakeSource struct {
	mu sync.Mutex

	lookups []store.AppliedCheckpointLookup
	changes chan struct{}
	calls   chan int
	count   int
}

func (source *daemonSnapshotWakeSource) ForceCheckpoint(
	ctx context.Context,
) (store.AppliedCheckpointLookup, error) {
	if err := ctx.Err(); err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	source.mu.Lock()
	index := source.count
	if index >= len(source.lookups) {
		index = len(source.lookups) - 1
	}
	source.count++
	count := source.count
	lookup := source.lookups[index]
	source.mu.Unlock()
	source.calls <- count
	return lookup, nil
}

func (source *daemonSnapshotWakeSource) SnapshotPublicationChanges() <-chan struct{} {
	return source.changes
}

func waitDaemonSnapshotPublisherCall(
	t testing.TB,
	calls <-chan int,
	want int,
) {
	t.Helper()
	select {
	case got := <-calls:
		if got != want {
			t.Fatalf("publisher call = %d, want %d", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("publisher call %d timed out", want)
	}
}

var _ daemonSnapshotCheckpointSource = (*daemonSnapshotWakeSource)(nil)
