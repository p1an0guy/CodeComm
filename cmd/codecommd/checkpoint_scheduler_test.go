package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

func TestDaemonCheckpointSchedulerTriggersAtAcceptedEventThresholdAndCoalesces(
	t *testing.T,
) {
	clock := newDaemonCheckpointSchedulerTestClock(
		time.Date(2026, 9, 2, 12, 1, 0, 0, time.UTC),
	)
	source := newDaemonCheckpointSchedulerSourceStub(
		checkpointSchedulerTestSnapshot(clock.Now().Add(-time.Minute)),
		clock.Now,
	)
	source.setHeads(109, 119)

	block := make(chan struct{})
	started := make(chan struct{})
	source.forceHook = func(ctx context.Context, call int) error {
		if call != 1 {
			return nil
		}
		close(started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-block:
			return nil
		}
	}

	scheduler := startDaemonCheckpointSchedulerTest(
		t,
		source,
		clock,
	)
	waitForDaemonCheckpointSchedulerTimer(t, clock, 4*time.Minute)
	source.setHeads(110, 120)
	for range 100 {
		scheduler.Wake()
	}
	waitForDaemonCheckpointSchedulerSignal(t, started, "checkpoint attempt")

	for range 100 {
		scheduler.Wake()
	}
	if got := len(scheduler.wake); got != 1 {
		t.Fatalf("coalesced wake count = %d, want 1", got)
	}
	close(block)
	waitForDaemonCheckpointSchedulerCalls(t, source, 1)
	waitForDaemonCheckpointSchedulerCondition(
		t,
		func() bool {
			snapshot := source.currentSnapshot()
			return snapshot.BaselineChainIndex == 111 &&
				snapshot.BaselineResultIndex == 121
		},
		"committed cadence baseline",
	)

	for range 100 {
		scheduler.Wake()
	}
	time.Sleep(20 * time.Millisecond)
	if got := source.forceCallCount(); got != 1 {
		t.Fatalf("ForceCheckpoint calls = %d, want 1", got)
	}
	stopDaemonCheckpointSchedulerTest(t, scheduler)
}

func TestDaemonCheckpointSchedulerTriggersAtCommittedInterval(
	t *testing.T,
) {
	baseline := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(baseline)
	source := newDaemonCheckpointSchedulerSourceStub(
		checkpointSchedulerTestSnapshot(baseline),
		clock.Now,
	)
	scheduler := startDaemonCheckpointSchedulerTest(
		t,
		source,
		clock,
	)

	waitForDaemonCheckpointSchedulerTimer(t, clock, 5*time.Minute)
	clock.Advance(4*time.Minute + 59*time.Second)
	if got := source.forceCallCount(); got != 0 {
		t.Fatalf("early ForceCheckpoint calls = %d, want 0", got)
	}
	clock.Advance(time.Second)
	waitForDaemonCheckpointSchedulerCalls(t, source, 1)

	snapshot := source.currentSnapshot()
	if snapshot.BaselineChainIndex != 11 ||
		snapshot.BaselineResultIndex != 21 ||
		!snapshot.BaselineAt.Equal(clock.Now()) {
		t.Fatalf("post-checkpoint cadence snapshot = %#v", snapshot)
	}
	stopDaemonCheckpointSchedulerTest(t, scheduler)
}

func TestDaemonCheckpointSchedulerRetriesLeadershipChangeWithoutFatal(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	snapshot := checkpointSchedulerTestSnapshot(now)
	snapshot.HeadChainIndex += uint64(snapshot.CheckpointEvents)
	snapshot.HeadResultIndex += uint64(snapshot.CheckpointEvents)
	source := newDaemonCheckpointSchedulerSourceStub(
		snapshot,
		clock.Now,
	)
	source.setLeader(false)
	source.forceErrors = []error{
		fmt.Errorf("leadership raced: %w", raft.ErrNotLeader),
		nil,
	}
	scheduler := startDaemonCheckpointSchedulerTest(
		t,
		source,
		clock,
	)

	waitForDaemonCheckpointSchedulerTimer(
		t,
		clock,
		daemonCheckpointSchedulerRetryInitial,
	)
	if got := source.forceCallCount(); got != 0 {
		t.Fatalf("follower ForceCheckpoint calls = %d, want 0", got)
	}

	source.setLeader(true)
	scheduler.Wake()
	waitForDaemonCheckpointSchedulerCalls(t, source, 1)
	if fatal := scheduler.FatalError(); fatal != nil {
		t.Fatalf("not-leader race became fatal: %v", fatal)
	}

	waitForDaemonCheckpointSchedulerTimer(
		t,
		clock,
		daemonCheckpointSchedulerRetryInitial,
	)
	clock.Advance(daemonCheckpointSchedulerRetryInitial)
	waitForDaemonCheckpointSchedulerCalls(t, source, 2)
	if fatal := scheduler.FatalError(); fatal != nil {
		t.Fatalf("leadership retry became fatal: %v", fatal)
	}
	stopDaemonCheckpointSchedulerTest(t, scheduler)
}

func TestDaemonCheckpointSchedulerConsumesDurableChangeNotifications(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	source := &daemonCheckpointSchedulerNotifyingSource{
		daemonCheckpointSchedulerSourceStub: newDaemonCheckpointSchedulerSourceStub(
			checkpointSchedulerTestSnapshot(now),
			clock.Now,
		),
		changes: make(chan struct{}, 1),
	}
	scheduler := startDaemonCheckpointSchedulerTest(t, source, clock)
	waitForDaemonCheckpointSchedulerTimer(t, clock, 5*time.Minute)

	source.setHeads(110, 120)
	source.changes <- struct{}{}
	waitForDaemonCheckpointSchedulerCalls(
		t,
		source.daemonCheckpointSchedulerSourceStub,
		1,
	)
	stopDaemonCheckpointSchedulerTest(t, scheduler)
}

func TestDaemonCheckpointSchedulerFailsClosedWhenChangeFeedCloses(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	source := &daemonCheckpointSchedulerNotifyingSource{
		daemonCheckpointSchedulerSourceStub: newDaemonCheckpointSchedulerSourceStub(
			checkpointSchedulerTestSnapshot(now),
			clock.Now,
		),
		changes: make(chan struct{}),
	}
	scheduler := startDaemonCheckpointSchedulerTest(t, source, clock)
	waitForDaemonCheckpointSchedulerTimer(t, clock, 5*time.Minute)
	close(source.changes)

	err := waitForDaemonCheckpointScheduler(t, scheduler)
	if !errors.Is(err, errDaemonCheckpointScheduler) {
		t.Fatalf("Wait() error = %v, want scheduler failure", err)
	}
}

func TestDaemonCheckpointSchedulerCancellationInterruptsAttempt(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	snapshot := checkpointSchedulerTestSnapshot(now)
	snapshot.HeadChainIndex += uint64(snapshot.CheckpointEvents)
	snapshot.HeadResultIndex += uint64(snapshot.CheckpointEvents)
	source := newDaemonCheckpointSchedulerSourceStub(
		snapshot,
		clock.Now,
	)
	started := make(chan struct{})
	source.forceHook = func(ctx context.Context, _ int) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	scheduler := startDaemonCheckpointSchedulerTest(
		t,
		source,
		clock,
	)

	waitForDaemonCheckpointSchedulerSignal(t, started, "checkpoint attempt")
	if err := scheduler.BeginClose(); err != nil {
		t.Fatalf("BeginClose(): %v", err)
	}
	if err := waitForDaemonCheckpointScheduler(t, scheduler); err != nil {
		t.Fatalf("Wait(): %v", err)
	}
	if fatal := scheduler.FatalError(); fatal != nil {
		t.Fatalf("cancellation became fatal: %v", fatal)
	}
}

func TestDaemonCheckpointSchedulerSurfacesOnlyTerminalErrors(
	t *testing.T,
) {
	localFailure := errors.New("local checkpoint state failed")
	tests := []struct {
		name   string
		mutate func(*daemonCheckpointSchedulerSourceStub)
	}{
		{
			name: "snapshot read",
			mutate: func(source *daemonCheckpointSchedulerSourceStub) {
				source.snapshotErr = localFailure
			},
		},
		{
			name: "invalid durable cut",
			mutate: func(source *daemonCheckpointSchedulerSourceStub) {
				source.snapshot.BaselineChainIndex =
					source.snapshot.HeadChainIndex + 1
			},
		},
		{
			name: "force checkpoint",
			mutate: func(source *daemonCheckpointSchedulerSourceStub) {
				source.snapshot.HeadChainIndex +=
					uint64(source.snapshot.CheckpointEvents)
				source.snapshot.HeadResultIndex +=
					uint64(source.snapshot.CheckpointEvents)
				source.forceErrors = []error{localFailure}
			},
		},
		{
			name: "consensus fatal",
			mutate: func(source *daemonCheckpointSchedulerSourceStub) {
				source.fatal = localFailure
			},
		},
		{
			name: "successful force without durable baseline",
			mutate: func(source *daemonCheckpointSchedulerSourceStub) {
				source.snapshot.HeadChainIndex +=
					uint64(source.snapshot.CheckpointEvents)
				source.snapshot.HeadResultIndex +=
					uint64(source.snapshot.CheckpointEvents)
				source.autoCommit = false
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(
				2026,
				9,
				2,
				12,
				0,
				0,
				0,
				time.UTC,
			)
			clock := newDaemonCheckpointSchedulerTestClock(now)
			source := newDaemonCheckpointSchedulerSourceStub(
				checkpointSchedulerTestSnapshot(now),
				clock.Now,
			)
			test.mutate(source)
			scheduler := startDaemonCheckpointSchedulerTest(
				t,
				source,
				clock,
			)

			err := waitForDaemonCheckpointScheduler(t, scheduler)
			if !errors.Is(err, errDaemonCheckpointScheduler) {
				t.Fatalf("Wait() error = %v", err)
			}
			if test.name != "invalid durable cut" &&
				test.name !=
					"successful force without durable baseline" &&
				!errors.Is(err, localFailure) {
				t.Fatalf("Wait() error = %v, want local failure", err)
			}
			if fatal := scheduler.FatalError(); !errors.Is(fatal, err) {
				t.Fatalf(
					"FatalError() = %v, want Wait error %v",
					fatal,
					err,
				)
			}
		})
	}
}

func TestDaemonCheckpointSchedulerFutureBaselineUsesObservedElapsedTime(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	snapshot := checkpointSchedulerTestSnapshot(now.Add(time.Hour))
	source := newDaemonCheckpointSchedulerSourceStub(
		snapshot,
		clock.Now,
	)
	scheduler := startDaemonCheckpointSchedulerTest(
		t,
		source,
		clock,
	)

	waitForDaemonCheckpointSchedulerTimer(t, clock, 5*time.Minute)
	clock.Advance(5 * time.Minute)
	waitForDaemonCheckpointSchedulerCalls(t, source, 1)
	stopDaemonCheckpointSchedulerTest(t, scheduler)
}

func TestNewDaemonCheckpointSchedulerRejectsInvalidDependencies(
	t *testing.T,
) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := newDaemonCheckpointSchedulerTestClock(now)
	source := newDaemonCheckpointSchedulerSourceStub(
		checkpointSchedulerTestSnapshot(now),
		clock.Now,
	)

	tests := []struct {
		name    string
		ctx     context.Context
		source  daemonCheckpointCadenceSource
		options daemonCheckpointSchedulerOptions
	}{
		{name: "nil context", source: source},
		{name: "nil source", ctx: t.Context()},
		{
			name:   "negative retry",
			ctx:    t.Context(),
			source: source,
			options: daemonCheckpointSchedulerOptions{
				RetryInitial: -time.Second,
			},
		},
		{
			name:   "reversed retry range",
			ctx:    t.Context(),
			source: source,
			options: daemonCheckpointSchedulerOptions{
				RetryInitial: 2 * time.Second,
				RetryMax:     time.Second,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheduler, err := newDaemonCheckpointScheduler(
				test.ctx,
				test.source,
				test.options,
			)
			if scheduler != nil ||
				!errors.Is(err, errDaemonCheckpointScheduler) {
				t.Fatalf(
					"newDaemonCheckpointScheduler() = (%#v, %v)",
					scheduler,
					err,
				)
			}
		})
	}
}

func TestDaemonCheckpointSchedulerClassifiesOnlyTemporaryErrorsAsRetryable(
	t *testing.T,
) {
	for _, err := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		raft.ErrNotLeader,
		raft.ErrLeadershipLost,
		raft.ErrAbortedByRestore,
		raft.ErrEnqueueTimeout,
		raft.ErrLeadershipTransferInProgress,
		consensus.ErrLeadershipEpochChanged,
		consensus.ErrCheckpointProofUnavailable,
		consensus.ErrConsensusAuthorizationUnavailable,
	} {
		if !retryableDaemonCheckpointSchedulerError(
			fmt.Errorf("wrapped: %w", err),
		) {
			t.Errorf("error %v is not retryable", err)
		}
	}
	for _, err := range []error{
		errors.New("local failure"),
		raft.ErrRaftShutdown,
		consensus.ErrNodeClosed,
		consensus.ErrCheckpointOriginUnavailable,
	} {
		if retryableDaemonCheckpointSchedulerError(err) {
			t.Errorf("error %v unexpectedly retryable", err)
		}
	}
}

func checkpointSchedulerTestSnapshot(
	baseline time.Time,
) daemonCheckpointCadenceSnapshot {
	return daemonCheckpointCadenceSnapshot{
		SessionID:           "018f47de-89ab-7def-8123-0123456789ab",
		WorkspaceID:         "123e4567-e89b-42d3-a456-426614174000",
		RecoveryGeneration:  0,
		HeadChainIndex:      10,
		HeadResultIndex:     20,
		BaselineChainIndex:  10,
		BaselineResultIndex: 20,
		BaselineAt:          baseline,
		CheckpointEvents: policy.
			MinCheckpointEvents,
		CheckpointIntervalSeconds: policy.
			DefaultCheckpointIntervalSeconds,
	}
}

type daemonCheckpointSchedulerSourceStub struct {
	mu sync.Mutex

	snapshot    daemonCheckpointCadenceSnapshot
	snapshotErr error
	leader      bool
	fatal       error
	now         func() time.Time
	autoCommit  bool
	forceErrors []error
	forceHook   func(context.Context, int) error
	forceCalls  int
	calls       chan int
}

type daemonCheckpointSchedulerNotifyingSource struct {
	*daemonCheckpointSchedulerSourceStub
	changes chan struct{}
	err     error
}

func (source *daemonCheckpointSchedulerNotifyingSource) SubscribeCheckpointCadenceChanges(
	ctx context.Context,
) (<-chan struct{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return source.changes, source.err
}

func newDaemonCheckpointSchedulerSourceStub(
	snapshot daemonCheckpointCadenceSnapshot,
	now func() time.Time,
) *daemonCheckpointSchedulerSourceStub {
	return &daemonCheckpointSchedulerSourceStub{
		snapshot:   snapshot,
		leader:     true,
		now:        now,
		autoCommit: true,
		calls:      make(chan int, 16),
	}
}

func (source *daemonCheckpointSchedulerSourceStub) CheckpointCadence(
	ctx context.Context,
) (daemonCheckpointCadenceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return daemonCheckpointCadenceSnapshot{}, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.snapshot, source.snapshotErr
}

func (source *daemonCheckpointSchedulerSourceStub) IsLeader() bool {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.leader
}

func (source *daemonCheckpointSchedulerSourceStub) ForceCheckpoint(
	ctx context.Context,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source.mu.Lock()
	source.forceCalls++
	call := source.forceCalls
	var result error
	if call <= len(source.forceErrors) {
		result = source.forceErrors[call-1]
	}
	hook := source.forceHook
	source.mu.Unlock()

	source.calls <- call
	if hook != nil {
		if err := hook(ctx, call); err != nil {
			return err
		}
	}
	if result != nil {
		return result
	}

	source.mu.Lock()
	defer source.mu.Unlock()
	if source.autoCommit {
		source.snapshot.HeadChainIndex++
		source.snapshot.HeadResultIndex++
		source.snapshot.BaselineChainIndex =
			source.snapshot.HeadChainIndex
		source.snapshot.BaselineResultIndex =
			source.snapshot.HeadResultIndex
		source.snapshot.BaselineAt = source.now()
	}
	return nil
}

func (source *daemonCheckpointSchedulerSourceStub) FatalError() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.fatal
}

func (source *daemonCheckpointSchedulerSourceStub) setHeads(
	chainIndex uint64,
	resultIndex uint64,
) {
	source.mu.Lock()
	source.snapshot.HeadChainIndex = chainIndex
	source.snapshot.HeadResultIndex = resultIndex
	source.mu.Unlock()
}

func (source *daemonCheckpointSchedulerSourceStub) setLeader(
	leader bool,
) {
	source.mu.Lock()
	source.leader = leader
	source.mu.Unlock()
}

func (source *daemonCheckpointSchedulerSourceStub) currentSnapshot() daemonCheckpointCadenceSnapshot {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.snapshot
}

func (source *daemonCheckpointSchedulerSourceStub) forceCallCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.forceCalls
}

type daemonCheckpointSchedulerTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*daemonCheckpointSchedulerTestTimer
}

func newDaemonCheckpointSchedulerTestClock(
	now time.Time,
) *daemonCheckpointSchedulerTestClock {
	return &daemonCheckpointSchedulerTestClock{now: now}
}

func (clock *daemonCheckpointSchedulerTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *daemonCheckpointSchedulerTestClock) NewTimer(
	delay time.Duration,
) daemonCheckpointSchedulerTimer {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	timer := &daemonCheckpointSchedulerTestTimer{
		clock:    clock,
		deadline: clock.now.Add(delay),
		channel:  make(chan time.Time, 1),
		active:   true,
	}
	clock.timers = append(clock.timers, timer)
	return timer
}

func (clock *daemonCheckpointSchedulerTestClock) Advance(
	duration time.Duration,
) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	now := clock.now
	var due []*daemonCheckpointSchedulerTestTimer
	for _, timer := range clock.timers {
		if timer.active && !timer.deadline.After(now) {
			timer.active = false
			due = append(due, timer)
		}
	}
	clock.mu.Unlock()
	for _, timer := range due {
		timer.channel <- now
	}
}

func (clock *daemonCheckpointSchedulerTestClock) hasTimer(
	delay time.Duration,
) bool {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	for _, timer := range clock.timers {
		if timer.active && timer.deadline.Sub(clock.now) == delay {
			return true
		}
	}
	return false
}

type daemonCheckpointSchedulerTestTimer struct {
	clock    *daemonCheckpointSchedulerTestClock
	deadline time.Time
	channel  chan time.Time
	active   bool
}

func (timer *daemonCheckpointSchedulerTestTimer) C() <-chan time.Time {
	return timer.channel
}

func (timer *daemonCheckpointSchedulerTestTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	wasActive := timer.active
	timer.active = false
	return wasActive
}

func startDaemonCheckpointSchedulerTest(
	t testing.TB,
	source daemonCheckpointCadenceSource,
	clock daemonCheckpointSchedulerClock,
) *daemonCheckpointScheduler {
	t.Helper()
	scheduler, err := newDaemonCheckpointScheduler(
		t.Context(),
		source,
		daemonCheckpointSchedulerOptions{
			Clock:          clock,
			RetryInitial:   daemonCheckpointSchedulerRetryInitial,
			RetryMax:       daemonCheckpointSchedulerRetryMax,
			AttemptTimeout: time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("newDaemonCheckpointScheduler(): %v", err)
	}
	return scheduler
}

func stopDaemonCheckpointSchedulerTest(
	t testing.TB,
	scheduler *daemonCheckpointScheduler,
) {
	t.Helper()
	if err := scheduler.BeginClose(); err != nil {
		t.Fatalf("BeginClose(): %v", err)
	}
	if err := waitForDaemonCheckpointScheduler(t, scheduler); err != nil {
		t.Fatalf("Wait(): %v", err)
	}
}

func waitForDaemonCheckpointScheduler(
	t testing.TB,
	scheduler *daemonCheckpointScheduler,
) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		result <- scheduler.Wait()
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint scheduler did not stop")
		return nil
	}
}

func waitForDaemonCheckpointSchedulerCalls(
	t testing.TB,
	source *daemonCheckpointSchedulerSourceStub,
	want int,
) {
	t.Helper()
	for {
		select {
		case got := <-source.calls:
			if got == want {
				return
			}
			if got > want {
				t.Fatalf(
					"ForceCheckpoint call = %d, want %d",
					got,
					want,
				)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("ForceCheckpoint call %d timed out", want)
		}
	}
}

func waitForDaemonCheckpointSchedulerTimer(
	t testing.TB,
	clock *daemonCheckpointSchedulerTestClock,
	delay time.Duration,
) {
	t.Helper()
	waitForDaemonCheckpointSchedulerCondition(
		t,
		func() bool { return clock.hasTimer(delay) },
		fmt.Sprintf("timer %s", delay),
	)
}

func waitForDaemonCheckpointSchedulerSignal(
	t testing.TB,
	signal <-chan struct{},
	name string,
) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s timed out", name)
	}
}

func waitForDaemonCheckpointSchedulerCondition(
	t testing.TB,
	condition func() bool,
	name string,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("%s timed out", name)
		}
		time.Sleep(time.Millisecond)
	}
}

var _ daemonCheckpointCadenceSource = (*daemonCheckpointSchedulerSourceStub)(nil)
