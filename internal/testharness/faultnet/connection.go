package faultnet

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

type faultConn struct {
	net.Conn

	id               uint64
	controller       *Controller
	dialerDeviceID   domain.DeviceID
	acceptorDeviceID domain.DeviceID
	ctx              context.Context
	done             chan struct{}

	readDeadline  deadlineState
	writeDeadline deadlineState
	readState     directionState
	writeState    directionState

	closeOnce sync.Once
	closeErr  error

	faultMu               sync.Mutex
	readClosedGeneration  uint64
	writeClosedGeneration uint64

	lifecycleMu sync.Mutex
	closed      bool
	closeCause  error
	stopContext func() bool
}

type directionState struct {
	mu sync.Mutex

	hitGeneration      uint64
	truncateGeneration uint64
	truncateForwarded  uint64

	replay       []byte
	replayOffset int
	replayErr    error
}

type deadlineState struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func newFaultConn(
	controller *Controller,
	connection net.Conn,
	dialerDeviceID domain.DeviceID,
	acceptorDeviceID domain.DeviceID,
	ctx context.Context,
) *faultConn {
	return &faultConn{
		Conn:             connection,
		controller:       controller,
		dialerDeviceID:   dialerDeviceID,
		acceptorDeviceID: acceptorDeviceID,
		ctx:              ctx,
		done:             make(chan struct{}),
		readDeadline: deadlineState{
			changed: make(chan struct{}),
		},
		writeDeadline: deadlineState{
			changed: make(chan struct{}),
		},
	}
}

func (connection *faultConn) bindContextCancellation() {
	stop := context.AfterFunc(connection.ctx, func() {
		connection.closeWithCause(context.Cause(connection.ctx))
	})
	connection.lifecycleMu.Lock()
	if connection.closed {
		connection.lifecycleMu.Unlock()
		stop()
		return
	}
	connection.stopContext = stop
	connection.lifecycleMu.Unlock()
}

// Read applies the rule for acceptor -> dialer. One underlying chunk observed
// under Duplicate is returned once now and once from a bounded replay buffer.
func (connection *faultConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	connection.readState.mu.Lock()
	defer connection.readState.mu.Unlock()
	if err := connection.lifecycleError(); err != nil {
		return 0, err
	}
	if len(connection.readState.replay) != 0 {
		return connection.readState.readReplay(buffer)
	}

	link := Link{
		From: connection.acceptorDeviceID,
		To:   connection.dialerDeviceID,
	}
	for {
		state, err := connection.controller.acquireRule(
			link,
			connection,
			&connection.readState,
			0,
		)
		if err != nil {
			return 0, connection.normalizeError(err)
		}
		if state == nil {
			read, readErr := connection.Conn.Read(buffer)
			return read, connection.normalizeError(readErr)
		}

		switch state.rule.Kind {
		case Drop:
			waitErr := connection.waitForFault(
				time.Time{},
				state.release,
				&connection.readDeadline,
			)
			state.releaseOperation(connection.controller, connection)
			if waitErr != nil {
				return 0, waitErr
			}
			continue
		case Delay:
			until := time.Now().Add(state.rule.Delay)
			if err := connection.waitForFault(
				until,
				nil,
				&connection.readDeadline,
			); err != nil {
				state.releaseOperation(connection.controller, connection)
				return 0, err
			}
			read, readErr := connection.Conn.Read(buffer)
			state.addAffected(uint64(read))
			state.releaseOperation(connection.controller, connection)
			return read, connection.normalizeError(readErr)
		case Duplicate:
			limit := min(len(buffer), ReadChunkMax)
			read, readErr := connection.Conn.Read(buffer[:limit])
			if read == 0 {
				state.releaseOperation(connection.controller, connection)
				return 0, connection.normalizeError(readErr)
			}
			state.addAffected(uint64(read))
			connection.readState.replay = append(
				connection.readState.replay[:0],
				buffer[:read]...,
			)
			connection.readState.replayOffset = 0
			connection.readState.replayErr = readErr
			// Defer a terminal error until the replay has been delivered.
			state.releaseOperation(connection.controller, connection)
			return read, nil
		case Truncate:
			remaining := connection.readState.truncateRemaining(state)
			if remaining == 0 {
				closeErr := connection.closeForRule(state)
				state.releaseOperation(connection.controller, connection)
				return 0, errors.Join(io.ErrUnexpectedEOF, closeErr)
			}
			limit := len(buffer)
			if uint64(limit) > remaining {
				limit = int(remaining)
			}
			read, readErr := connection.Conn.Read(buffer[:limit])
			connection.readState.advanceTruncate(uint64(read))
			state.addAffected(uint64(read))
			if uint64(read) == remaining {
				closeErr := connection.closeForRule(state)
				state.releaseOperation(connection.controller, connection)
				return read, errors.Join(
					io.ErrUnexpectedEOF,
					connection.normalizeError(readErr),
					closeErr,
				)
			}
			state.releaseOperation(connection.controller, connection)
			return read, connection.normalizeError(readErr)
		default:
			state.releaseOperation(connection.controller, connection)
			return 0, ErrInvalidRule
		}
	}
}

// Write applies the rule for dialer -> acceptor. Duplicate does not return
// until both the original and one exact replay have been written.
func (connection *faultConn) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	connection.writeState.mu.Lock()
	defer connection.writeState.mu.Unlock()
	if err := connection.lifecycleError(); err != nil {
		return 0, err
	}

	link := Link{
		From: connection.dialerDeviceID,
		To:   connection.acceptorDeviceID,
	}
	for {
		state, err := connection.controller.acquireRule(
			link,
			connection,
			&connection.writeState,
			0,
		)
		if err != nil {
			return 0, connection.normalizeError(err)
		}
		if state == nil {
			written, writeErr := connection.Conn.Write(buffer)
			return written, connection.normalizeError(writeErr)
		}

		switch state.rule.Kind {
		case Drop:
			state.addAffected(uint64(len(buffer)))
			waitErr := connection.waitForFault(
				time.Time{},
				state.release,
				&connection.writeDeadline,
			)
			state.releaseOperation(connection.controller, connection)
			if waitErr != nil {
				return 0, waitErr
			}
			continue
		case Delay:
			until := time.Now().Add(state.rule.Delay)
			if err := connection.waitForFault(
				until,
				nil,
				&connection.writeDeadline,
			); err != nil {
				state.releaseOperation(connection.controller, connection)
				return 0, err
			}
			written, writeErr := connection.Conn.Write(buffer)
			state.addAffected(uint64(written))
			state.releaseOperation(connection.controller, connection)
			return written, connection.normalizeError(writeErr)
		case Duplicate:
			original, originalErr := connection.writeFull(buffer)
			if originalErr != nil {
				state.releaseOperation(connection.controller, connection)
				return original, originalErr
			}
			duplicated, duplicateErr := connection.writeFull(buffer)
			state.addAffected(uint64(duplicated))
			if duplicateErr != nil {
				state.releaseOperation(connection.controller, connection)
				return len(buffer), duplicateErr
			}
			state.releaseOperation(connection.controller, connection)
			return len(buffer), nil
		case Truncate:
			remaining := connection.writeState.truncateRemaining(state)
			if remaining == 0 {
				closeErr := connection.closeForRule(state)
				state.releaseOperation(connection.controller, connection)
				return 0, errors.Join(io.ErrUnexpectedEOF, closeErr)
			}
			limit := len(buffer)
			if uint64(limit) > remaining {
				limit = int(remaining)
			}
			written, writeErr := connection.writeFull(buffer[:limit])
			connection.writeState.advanceTruncate(uint64(written))
			state.addAffected(uint64(written))
			if uint64(written) == remaining {
				closeErr := connection.closeForRule(state)
				state.releaseOperation(connection.controller, connection)
				return written, errors.Join(
					io.ErrUnexpectedEOF,
					writeErr,
					closeErr,
				)
			}
			state.releaseOperation(connection.controller, connection)
			return written, writeErr
		default:
			state.releaseOperation(connection.controller, connection)
			return 0, ErrInvalidRule
		}
	}
}

func (connection *faultConn) writeFull(buffer []byte) (int, error) {
	written := 0
	for written < len(buffer) {
		count, err := connection.Conn.Write(buffer[written:])
		written += count
		if err != nil {
			return written, connection.normalizeError(err)
		}
		if count == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (connection *faultConn) waitForFault(
	until time.Time,
	release <-chan struct{},
	deadline *deadlineState,
) error {
	for {
		if err := connection.lifecycleError(); err != nil {
			return err
		}
		deadlineAt, deadlineChanged := deadline.snapshot()
		now := time.Now()
		if !deadlineAt.IsZero() && !now.Before(deadlineAt) {
			return os.ErrDeadlineExceeded
		}
		if !until.IsZero() && !now.Before(until) {
			return nil
		}

		wakeAt := until
		if wakeAt.IsZero() ||
			!deadlineAt.IsZero() && deadlineAt.Before(wakeAt) {
			wakeAt = deadlineAt
		}
		var timer *time.Timer
		var timerDone <-chan time.Time
		if !wakeAt.IsZero() {
			timer = time.NewTimer(time.Until(wakeAt))
			timerDone = timer.C
		}

		select {
		case <-connection.ctx.Done():
			stopTimer(timer)
			return context.Cause(connection.ctx)
		case <-connection.done:
			stopTimer(timer)
			return connection.lifecycleError()
		case <-connection.controller.done:
			stopTimer(timer)
			return ErrControllerClosed
		case <-release:
			stopTimer(timer)
			return nil
		case <-deadlineChanged:
			stopTimer(timer)
		case <-timerDone:
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (connection *faultConn) closeForRule(state *ruleState) error {
	state.recordClosed(connection)
	return connection.closeWithCause(net.ErrClosed)
}

func (connection *faultConn) Close() error {
	if connection == nil {
		return net.ErrClosed
	}
	return connection.closeWithCause(net.ErrClosed)
}

func (connection *faultConn) closeWithCause(cause error) error {
	if cause == nil {
		cause = net.ErrClosed
	}
	connection.closeOnce.Do(func() {
		connection.lifecycleMu.Lock()
		connection.closed = true
		connection.closeCause = cause
		stopContext := connection.stopContext
		connection.stopContext = nil
		connection.lifecycleMu.Unlock()

		close(connection.done)
		if stopContext != nil {
			stopContext()
		}
		connection.controller.unregister(connection)
		connection.closeErr = connection.Conn.Close()
	})
	return connection.closeErr
}

func (connection *faultConn) lifecycleError() error {
	select {
	case <-connection.done:
		connection.lifecycleMu.Lock()
		cause := connection.closeCause
		connection.lifecycleMu.Unlock()
		if cause == nil {
			return net.ErrClosed
		}
		return cause
	default:
	}
	if err := connection.ctx.Err(); err != nil {
		return context.Cause(connection.ctx)
	}
	return nil
}

func (connection *faultConn) normalizeError(err error) error {
	if err == nil {
		return nil
	}
	if lifecycleErr := connection.lifecycleError(); lifecycleErr != nil {
		return lifecycleErr
	}
	return err
}

func (connection *faultConn) SetDeadline(deadline time.Time) error {
	if connection == nil {
		return net.ErrClosed
	}
	if err := connection.lifecycleError(); err != nil {
		return err
	}
	if err := connection.Conn.SetDeadline(deadline); err != nil {
		return connection.normalizeError(err)
	}
	connection.readDeadline.set(deadline)
	connection.writeDeadline.set(deadline)
	return nil
}

func (connection *faultConn) SetReadDeadline(deadline time.Time) error {
	if connection == nil {
		return net.ErrClosed
	}
	if err := connection.lifecycleError(); err != nil {
		return err
	}
	if err := connection.Conn.SetReadDeadline(deadline); err != nil {
		return connection.normalizeError(err)
	}
	connection.readDeadline.set(deadline)
	return nil
}

func (connection *faultConn) SetWriteDeadline(deadline time.Time) error {
	if connection == nil {
		return net.ErrClosed
	}
	if err := connection.lifecycleError(); err != nil {
		return err
	}
	if err := connection.Conn.SetWriteDeadline(deadline); err != nil {
		return connection.normalizeError(err)
	}
	connection.writeDeadline.set(deadline)
	return nil
}

func (connection *faultConn) markFaultClosed(state *ruleState) bool {
	if connection == nil || state == nil {
		return false
	}
	connection.faultMu.Lock()
	defer connection.faultMu.Unlock()

	var closed *uint64
	switch state.link {
	case Link{
		From: connection.dialerDeviceID,
		To:   connection.acceptorDeviceID,
	}:
		closed = &connection.writeClosedGeneration
	case Link{
		From: connection.acceptorDeviceID,
		To:   connection.dialerDeviceID,
	}:
		closed = &connection.readClosedGeneration
	default:
		return false
	}
	if *closed >= state.generation {
		return false
	}
	*closed = state.generation
	return true
}

func (state *directionState) truncateRemaining(rule *ruleState) uint64 {
	if state.truncateGeneration != rule.generation {
		state.truncateGeneration = rule.generation
		state.truncateForwarded = 0
	}
	if state.truncateForwarded >= rule.rule.TruncateAfter {
		return 0
	}
	return rule.rule.TruncateAfter - state.truncateForwarded
}

func (state *directionState) advanceTruncate(count uint64) {
	state.truncateForwarded = saturatingAdd(
		state.truncateForwarded,
		count,
	)
}

func (state *directionState) readReplay(buffer []byte) (int, error) {
	count := copy(buffer, state.replay[state.replayOffset:])
	state.replayOffset += count
	if state.replayOffset < len(state.replay) {
		return count, nil
	}
	err := state.replayErr
	state.replay = nil
	state.replayOffset = 0
	state.replayErr = nil
	return count, err
}

func (deadline *deadlineState) set(value time.Time) {
	deadline.mu.Lock()
	changed := deadline.changed
	deadline.at = value
	deadline.changed = make(chan struct{})
	close(changed)
	deadline.mu.Unlock()
}

func (deadline *deadlineState) snapshot() (
	time.Time,
	<-chan struct{},
) {
	deadline.mu.Lock()
	defer deadline.mu.Unlock()
	return deadline.at, deadline.changed
}

var _ net.Conn = (*faultConn)(nil)
