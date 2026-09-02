package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	daemonCheckpointSchedulerRetryInitial   = 250 * time.Millisecond
	daemonCheckpointSchedulerRetryMax       = 5 * time.Second
	daemonCheckpointSchedulerAttemptTimeout = 30 * time.Second
)

var errDaemonCheckpointScheduler = errors.New(
	"codecommd: committed checkpoint cadence failed",
)

// daemonCheckpointCadenceSnapshot is one integrity-verified, transactionally
// consistent view of the active lineage, committed policy, current heads, and
// latest accepted checkpoint cadence baseline.
//
// BaselineChainIndex and BaselineResultIndex name the accepted checkpoint
// event itself, not the cut it covers. Before the generation's first
// checkpoint, they name the durable generation-creation or install cut.
// BaselineAt is the durable local observation time at which that baseline
// became visible; it must not be derived from an untrusted event timestamp.
type daemonCheckpointCadenceSnapshot struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64

	HeadChainIndex      uint64
	HeadResultIndex     uint64
	BaselineChainIndex  uint64
	BaselineResultIndex uint64
	BaselineAt          time.Time

	CheckpointEvents          int64
	CheckpointIntervalSeconds int64
}

// daemonCheckpointCadenceSource is the scheduling boundary.
// CheckpointCadence must return all snapshot fields from one durable cut.
// ForceCheckpoint must synchronously commit an accepted checkpoint before
// returning nil and must honor context cancellation. FatalError reports only
// terminal consensus or local-integrity failures.
type daemonCheckpointCadenceSource interface {
	CheckpointCadence(
		context.Context,
	) (daemonCheckpointCadenceSnapshot, error)
	IsLeader() bool
	ForceCheckpoint(context.Context) error
	FatalError() error
}

type daemonCheckpointCadenceChangeSource interface {
	SubscribeCheckpointCadenceChanges(
		context.Context,
	) (<-chan struct{}, error)
}

type daemonCheckpointRuntimeSource struct {
	state store.LocalState
	node  *consensus.SingleNode
}

func newDaemonCheckpointRuntimeSource(
	state store.LocalState,
	node *consensus.SingleNode,
) (*daemonCheckpointRuntimeSource, error) {
	if node == nil {
		return nil, errDaemonCheckpointScheduler
	}
	return &daemonCheckpointRuntimeSource{
		state: state,
		node:  node,
	}, nil
}

func (source *daemonCheckpointRuntimeSource) CheckpointCadence(
	ctx context.Context,
) (daemonCheckpointCadenceSnapshot, error) {
	if source == nil || source.node == nil || ctx == nil {
		return daemonCheckpointCadenceSnapshot{},
			errDaemonCheckpointScheduler
	}
	cadence, err := source.state.CheckpointCadence(ctx)
	if err != nil {
		return daemonCheckpointCadenceSnapshot{}, err
	}
	baselineAt, err := cadence.BaselineObservedAt.Time()
	if err != nil {
		return daemonCheckpointCadenceSnapshot{}, fmt.Errorf(
			"%w: decode durable baseline time: %v",
			errDaemonCheckpointScheduler,
			err,
		)
	}
	return daemonCheckpointCadenceSnapshot{
		SessionID:                 cadence.SessionID,
		WorkspaceID:               cadence.WorkspaceID,
		RecoveryGeneration:        cadence.RecoveryGeneration,
		HeadChainIndex:            cadence.HeadChainIndex,
		HeadResultIndex:           cadence.HeadResultIndex,
		BaselineChainIndex:        cadence.BaselineChainIndex,
		BaselineResultIndex:       cadence.BaselineResultIndex,
		BaselineAt:                baselineAt,
		CheckpointEvents:          cadence.CheckpointEvents,
		CheckpointIntervalSeconds: cadence.CheckpointIntervalSeconds,
	}, nil
}

func (source *daemonCheckpointRuntimeSource) SubscribeCheckpointCadenceChanges(
	ctx context.Context,
) (<-chan struct{}, error) {
	if source == nil || source.node == nil || ctx == nil {
		return nil, errDaemonCheckpointScheduler
	}
	return source.state.SubscribeResultHeadChanges(ctx)
}

func (source *daemonCheckpointRuntimeSource) IsLeader() bool {
	return source != nil && source.node != nil && source.node.IsLeader()
}

func (source *daemonCheckpointRuntimeSource) ForceCheckpoint(
	ctx context.Context,
) error {
	if source == nil || source.node == nil || ctx == nil {
		return errDaemonCheckpointScheduler
	}
	_, err := source.node.ForceCheckpoint(ctx)
	return err
}

func (source *daemonCheckpointRuntimeSource) FatalError() error {
	if source == nil || source.node == nil {
		return errDaemonCheckpointScheduler
	}
	return source.node.FatalError()
}

type daemonCheckpointSchedulerTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type daemonCheckpointSchedulerClock interface {
	Now() time.Time
	NewTimer(time.Duration) daemonCheckpointSchedulerTimer
}

type daemonCheckpointSchedulerOptions struct {
	Clock          daemonCheckpointSchedulerClock
	RetryInitial   time.Duration
	RetryMax       time.Duration
	AttemptTimeout time.Duration
}

type daemonCheckpointScheduler struct {
	source         daemonCheckpointCadenceSource
	clock          daemonCheckpointSchedulerClock
	retryInitial   time.Duration
	retryMax       time.Duration
	attemptTimeout time.Duration

	cancel    context.CancelFunc
	wake      chan struct{}
	changes   <-chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	fatalMu sync.RWMutex
	fatal   error
}

type daemonCheckpointCadenceObservation struct {
	initialized bool
	snapshot    daemonCheckpointCadenceSnapshot
	observedAt  time.Time
}

type daemonCheckpointPendingCommit struct {
	sessionID           domain.UUIDv7
	workspaceID         domain.UUIDv4
	recoveryGeneration  uint64
	baselineChainIndex  uint64
	baselineResultIndex uint64
}

func newDaemonCheckpointScheduler(
	ctx context.Context,
	source daemonCheckpointCadenceSource,
	options daemonCheckpointSchedulerOptions,
) (*daemonCheckpointScheduler, error) {
	if ctx == nil ||
		nilDaemonCheckpointSchedulerDependency(source) ||
		options.RetryInitial < 0 ||
		options.RetryMax < 0 ||
		options.AttemptTimeout < 0 {
		return nil, errDaemonCheckpointScheduler
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.Clock == nil {
		options.Clock = daemonCheckpointSchedulerWallClock{}
	}
	if nilDaemonCheckpointSchedulerDependency(options.Clock) {
		return nil, errDaemonCheckpointScheduler
	}
	if options.RetryInitial == 0 {
		options.RetryInitial = daemonCheckpointSchedulerRetryInitial
	}
	if options.RetryMax == 0 {
		options.RetryMax = daemonCheckpointSchedulerRetryMax
	}
	if options.AttemptTimeout == 0 {
		options.AttemptTimeout = daemonCheckpointSchedulerAttemptTimeout
	}
	if options.RetryMax < options.RetryInitial {
		return nil, errDaemonCheckpointScheduler
	}

	runContext, cancel := context.WithCancel(ctx)
	var changes <-chan struct{}
	if changeSource, ok := source.(daemonCheckpointCadenceChangeSource); ok {
		var err error
		changes, err = changeSource.SubscribeCheckpointCadenceChanges(
			runContext,
		)
		if err != nil {
			cancel()
			return nil, fmt.Errorf(
				"%w: subscribe committed cadence: %v",
				errDaemonCheckpointScheduler,
				err,
			)
		}
		if changes == nil {
			cancel()
			return nil, errDaemonCheckpointScheduler
		}
	}
	scheduler := &daemonCheckpointScheduler{
		source:         source,
		clock:          options.Clock,
		retryInitial:   options.RetryInitial,
		retryMax:       options.RetryMax,
		attemptTimeout: options.AttemptTimeout,
		cancel:         cancel,
		wake:           make(chan struct{}, 1),
		changes:        changes,
		done:           make(chan struct{}),
	}
	go scheduler.run(runContext)
	return scheduler, nil
}

// Wake coalesces committed-head, policy, and leadership notifications. It is
// a hint: every wake causes a fresh durable snapshot read, while retry and
// interval timers preserve progress if notifications race or are duplicated.
func (scheduler *daemonCheckpointScheduler) Wake() {
	if scheduler == nil || scheduler.wake == nil || scheduler.done == nil {
		return
	}
	select {
	case <-scheduler.done:
		return
	default:
	}
	select {
	case scheduler.wake <- struct{}{}:
	default:
	}
}

func (scheduler *daemonCheckpointScheduler) run(ctx context.Context) {
	defer close(scheduler.done)

	retry := scheduler.retryInitial
	var (
		observation daemonCheckpointCadenceObservation
		pending     *daemonCheckpointPendingCommit
	)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := scheduler.source.FatalError(); err != nil {
			scheduler.fail(fmt.Errorf(
				"%w: consensus source: %w",
				errDaemonCheckpointScheduler,
				err,
			))
			return
		}

		snapshot, err := scheduler.source.CheckpointCadence(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if fatal := scheduler.source.FatalError(); fatal != nil {
				err = errors.Join(err, fatal)
			}
			scheduler.fail(fmt.Errorf(
				"%w: read committed cadence: %w",
				errDaemonCheckpointScheduler,
				err,
			))
			return
		}
		now := scheduler.clock.Now()
		delay, nextObservation, err := checkpointCadenceDelay(
			snapshot,
			now,
			observation,
		)
		if err != nil {
			scheduler.fail(fmt.Errorf(
				"%w: validate committed cadence: %w",
				errDaemonCheckpointScheduler,
				err,
			))
			return
		}
		observation = nextObservation
		if pending != nil {
			if err := pending.requireAdvanced(snapshot); err != nil {
				scheduler.fail(fmt.Errorf(
					"%w: verify forced checkpoint: %w",
					errDaemonCheckpointScheduler,
					err,
				))
				return
			}
			pending = nil
		}

		if delay > 0 {
			retry = scheduler.retryInitial
			woke, err := scheduler.wait(ctx, delay)
			if err != nil {
				scheduler.fail(err)
				return
			}
			if !woke && ctx.Err() != nil {
				return
			}
			continue
		}

		if !scheduler.source.IsLeader() {
			if fatal := scheduler.source.FatalError(); fatal != nil {
				scheduler.fail(fmt.Errorf(
					"%w: consensus source: %w",
					errDaemonCheckpointScheduler,
					fatal,
				))
				return
			}
			woke, err := scheduler.wait(ctx, retry)
			if err != nil {
				scheduler.fail(err)
				return
			}
			if woke {
				retry = scheduler.retryInitial
			} else {
				retry = nextDaemonCheckpointRetry(
					retry,
					scheduler.retryMax,
				)
			}
			continue
		}

		attemptContext, cancel := context.WithTimeout(
			ctx,
			scheduler.attemptTimeout,
		)
		err = scheduler.source.ForceCheckpoint(attemptContext)
		cancel()
		if err == nil {
			pending = &daemonCheckpointPendingCommit{
				sessionID:           snapshot.SessionID,
				workspaceID:         snapshot.WorkspaceID,
				recoveryGeneration:  snapshot.RecoveryGeneration,
				baselineChainIndex:  snapshot.BaselineChainIndex,
				baselineResultIndex: snapshot.BaselineResultIndex,
			}
			retry = scheduler.retryInitial
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if fatal := scheduler.source.FatalError(); fatal != nil {
			scheduler.fail(fmt.Errorf(
				"%w: force checkpoint: %w",
				errDaemonCheckpointScheduler,
				errors.Join(err, fatal),
			))
			return
		}
		if !retryableDaemonCheckpointSchedulerError(err) {
			scheduler.fail(fmt.Errorf(
				"%w: force checkpoint: %w",
				errDaemonCheckpointScheduler,
				err,
			))
			return
		}

		woke, waitErr := scheduler.wait(ctx, retry)
		if waitErr != nil {
			scheduler.fail(waitErr)
			return
		}
		if woke {
			retry = scheduler.retryInitial
		} else {
			retry = nextDaemonCheckpointRetry(retry, scheduler.retryMax)
		}
	}
}

func checkpointCadenceDelay(
	snapshot daemonCheckpointCadenceSnapshot,
	now time.Time,
	previous daemonCheckpointCadenceObservation,
) (
	time.Duration,
	daemonCheckpointCadenceObservation,
	error,
) {
	if err := snapshot.validate(); err != nil {
		return 0, previous, err
	}
	if now.IsZero() {
		return 0, previous, errors.New("clock returned zero time")
	}

	next := daemonCheckpointCadenceObservation{
		initialized: true,
		snapshot:    snapshot,
		observedAt:  now,
	}
	if previous.initialized &&
		sameDaemonCheckpointLineage(previous.snapshot, snapshot) {
		if snapshot.HeadChainIndex < previous.snapshot.HeadChainIndex ||
			snapshot.HeadResultIndex < previous.snapshot.HeadResultIndex {
			return 0, previous, errors.New("durable heads regressed")
		}
		sameBaseline := snapshot.BaselineChainIndex ==
			previous.snapshot.BaselineChainIndex &&
			snapshot.BaselineResultIndex ==
				previous.snapshot.BaselineResultIndex
		advancedBaseline := snapshot.BaselineChainIndex >
			previous.snapshot.BaselineChainIndex &&
			snapshot.BaselineResultIndex >
				previous.snapshot.BaselineResultIndex
		if !sameBaseline && !advancedBaseline {
			return 0, previous, errors.New(
				"checkpoint cadence baseline regressed or split",
			)
		}
		if sameBaseline {
			if !snapshot.BaselineAt.Equal(
				previous.snapshot.BaselineAt,
			) {
				return 0, previous, errors.New(
					"checkpoint cadence baseline time changed",
				)
			}
			next.observedAt = previous.observedAt
		}
	}

	acceptedSinceBaseline :=
		snapshot.HeadChainIndex - snapshot.BaselineChainIndex
	if acceptedSinceBaseline >= uint64(snapshot.CheckpointEvents) {
		return 0, next, nil
	}

	interval := time.Duration(
		snapshot.CheckpointIntervalSeconds,
	) * time.Second
	durableElapsed := now.Sub(snapshot.BaselineAt)
	if durableElapsed < 0 {
		durableElapsed = 0
	}
	observedElapsed := now.Sub(next.observedAt)
	if observedElapsed < 0 {
		observedElapsed = 0
	}
	elapsed := max(durableElapsed, observedElapsed)
	if elapsed >= interval {
		return 0, next, nil
	}
	return interval - elapsed, next, nil
}

func (snapshot daemonCheckpointCadenceSnapshot) validate() error {
	if !snapshot.SessionID.Valid() ||
		!snapshot.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(snapshot.RecoveryGeneration) ||
		!domain.ValidUnsignedInteger(snapshot.HeadChainIndex) ||
		!domain.ValidUnsignedInteger(snapshot.HeadResultIndex) ||
		!domain.ValidUnsignedInteger(snapshot.BaselineChainIndex) ||
		!domain.ValidUnsignedInteger(snapshot.BaselineResultIndex) ||
		snapshot.BaselineAt.IsZero() {
		return errors.New("invalid cadence identity, cut, or baseline time")
	}
	if snapshot.HeadChainIndex > snapshot.HeadResultIndex ||
		snapshot.BaselineChainIndex > snapshot.BaselineResultIndex ||
		snapshot.BaselineChainIndex > snapshot.HeadChainIndex ||
		snapshot.BaselineResultIndex > snapshot.HeadResultIndex {
		return errors.New("inconsistent cadence heads or baseline")
	}
	if snapshot.CheckpointEvents < policy.MinCheckpointEvents ||
		snapshot.CheckpointEvents > policy.MaxCheckpointEvents {
		return fmt.Errorf(
			"checkpoint_events %d is outside %d..%d",
			snapshot.CheckpointEvents,
			policy.MinCheckpointEvents,
			policy.MaxCheckpointEvents,
		)
	}
	if snapshot.CheckpointIntervalSeconds <
		policy.MinCheckpointIntervalSeconds ||
		snapshot.CheckpointIntervalSeconds >
			policy.MaxCheckpointIntervalSeconds {
		return fmt.Errorf(
			"checkpoint_interval_seconds %d is outside %d..%d",
			snapshot.CheckpointIntervalSeconds,
			policy.MinCheckpointIntervalSeconds,
			policy.MaxCheckpointIntervalSeconds,
		)
	}
	return nil
}

func (pending daemonCheckpointPendingCommit) requireAdvanced(
	snapshot daemonCheckpointCadenceSnapshot,
) error {
	if pending.sessionID != snapshot.SessionID ||
		pending.workspaceID != snapshot.WorkspaceID ||
		pending.recoveryGeneration != snapshot.RecoveryGeneration {
		return nil
	}
	if snapshot.BaselineChainIndex <= pending.baselineChainIndex ||
		snapshot.BaselineResultIndex <= pending.baselineResultIndex {
		return errors.New(
			"successful ForceCheckpoint did not advance the durable baseline",
		)
	}
	return nil
}

func sameDaemonCheckpointLineage(
	left daemonCheckpointCadenceSnapshot,
	right daemonCheckpointCadenceSnapshot,
) bool {
	return left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.RecoveryGeneration == right.RecoveryGeneration
}

func retryableDaemonCheckpointSchedulerError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, raft.ErrNotLeader) ||
		errors.Is(err, raft.ErrLeadershipLost) ||
		errors.Is(err, raft.ErrAbortedByRestore) ||
		errors.Is(err, raft.ErrEnqueueTimeout) ||
		errors.Is(err, raft.ErrLeadershipTransferInProgress) ||
		errors.Is(err, consensus.ErrLeadershipEpochChanged) ||
		errors.Is(err, consensus.ErrCheckpointProofUnavailable) ||
		errors.Is(err, consensus.ErrConsensusAuthorizationUnavailable)
}

func nextDaemonCheckpointRetry(
	current time.Duration,
	maximum time.Duration,
) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func (scheduler *daemonCheckpointScheduler) wait(
	ctx context.Context,
	delay time.Duration,
) (bool, error) {
	if delay <= 0 {
		return false, nil
	}
	timer := scheduler.clock.NewTimer(delay)
	if nilDaemonCheckpointSchedulerDependency(timer) {
		return false, fmt.Errorf(
			"%w: clock returned an invalid timer",
			errDaemonCheckpointScheduler,
		)
	}
	timerChannel := timer.C()
	if timerChannel == nil {
		timer.Stop()
		return false, fmt.Errorf(
			"%w: clock returned an invalid timer",
			errDaemonCheckpointScheduler,
		)
	}
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false, nil
	case _, open := <-timerChannel:
		if !open {
			return false, fmt.Errorf(
				"%w: clock timer closed unexpectedly",
				errDaemonCheckpointScheduler,
			)
		}
		return false, nil
	case _, open := <-scheduler.changes:
		if !open {
			if ctx.Err() != nil {
				return false, nil
			}
			return false, fmt.Errorf(
				"%w: committed cadence notification feed closed",
				errDaemonCheckpointScheduler,
			)
		}
		scheduler.drainWakeups()
		return true, nil
	case <-scheduler.wake:
		scheduler.drainWakeups()
		return true, nil
	}
}

func (scheduler *daemonCheckpointScheduler) drainWakeups() {
	for {
		select {
		case <-scheduler.wake:
		default:
			goto changes
		}
	}

changes:
	if scheduler.changes == nil {
		return
	}
	for {
		select {
		case _, open := <-scheduler.changes:
			if !open {
				return
			}
		default:
			return
		}
	}
}

func (scheduler *daemonCheckpointScheduler) BeginClose() error {
	if scheduler == nil || scheduler.cancel == nil {
		return errDaemonCheckpointScheduler
	}
	scheduler.closeOnce.Do(scheduler.cancel)
	return nil
}

func (scheduler *daemonCheckpointScheduler) Wait() error {
	if scheduler == nil || scheduler.done == nil {
		return errDaemonCheckpointScheduler
	}
	<-scheduler.done
	return scheduler.FatalError()
}

func (scheduler *daemonCheckpointScheduler) FatalError() error {
	if scheduler == nil {
		return errDaemonCheckpointScheduler
	}
	scheduler.fatalMu.RLock()
	defer scheduler.fatalMu.RUnlock()
	return scheduler.fatal
}

func (scheduler *daemonCheckpointScheduler) fail(err error) {
	if err == nil {
		err = errDaemonCheckpointScheduler
	}
	scheduler.fatalMu.Lock()
	if scheduler.fatal == nil {
		scheduler.fatal = err
	}
	scheduler.fatalMu.Unlock()
	scheduler.closeOnce.Do(scheduler.cancel)
}

func nilDaemonCheckpointSchedulerDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type daemonCheckpointSchedulerWallClock struct{}

func (daemonCheckpointSchedulerWallClock) Now() time.Time {
	return time.Now()
}

func (daemonCheckpointSchedulerWallClock) NewTimer(
	delay time.Duration,
) daemonCheckpointSchedulerTimer {
	return &daemonCheckpointSchedulerWallTimer{
		timer: time.NewTimer(delay),
	}
}

type daemonCheckpointSchedulerWallTimer struct {
	timer *time.Timer
}

func (timer *daemonCheckpointSchedulerWallTimer) C() <-chan time.Time {
	return timer.timer.C
}

func (timer *daemonCheckpointSchedulerWallTimer) Stop() bool {
	return timer.timer.Stop()
}

var (
	_ daemonCheckpointCadenceSource       = (*daemonCheckpointRuntimeSource)(nil)
	_ daemonCheckpointCadenceChangeSource = (*daemonCheckpointRuntimeSource)(nil)
	_ phasedDaemonComponent               = (*daemonCheckpointScheduler)(nil)
	_ daemonFatalComponent                = (*daemonCheckpointScheduler)(nil)
)
