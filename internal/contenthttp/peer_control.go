package contenthttp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	ControlRatePerSecond  = 200
	ControlRateBurst      = 800
	ProposalRatePerSecond = 50
	ProposalRateBurst     = 200
	ControlPeerStatesMax  = int(policy.MaxMemberDevices)

	controlTokenUnit      = int64(time.Second)
	controlTokenCapacity  = int64(ControlRateBurst) * controlTokenUnit
	proposalTokenCapacity = int64(ProposalRateBurst) * controlTokenUnit
)

var (
	ErrControlConnectionCapacity = errors.New(
		"content HTTP: control connection capacity reached",
	)
	ErrControlConnectionSuperseded = errors.New(
		"content HTTP: control connection credential is superseded",
	)
	errControlStateUnavailable = errors.New(
		"content HTTP: control state unavailable",
	)
)

type controlRegistry struct {
	mu     sync.Mutex
	now    func() time.Time
	states map[domain.DeviceID]*controlPeerState
}

type controlPeerState struct {
	current        *connectionHandler
	draining       *connectionHandler
	bucket         controlTokenBucket
	proposalBucket controlTokenBucket
	lastSeen       time.Time
}

type controlTokenBucket struct {
	credit int64
	last   time.Time
}

func newControlRegistry(now func() time.Time) (*controlRegistry, error) {
	if now == nil {
		return nil, errControlStateUnavailable
	}
	return &controlRegistry{
		now:    now,
		states: make(map[domain.DeviceID]*controlPeerState),
	}, nil
}

func (registry *controlRegistry) register(
	handler *connectionHandler,
) error {
	if registry == nil ||
		registry.now == nil ||
		handler == nil ||
		!validControlPeer(handler.peer) ||
		!handler.registrationReady() {
		return errControlStateUnavailable
	}
	now := registry.now()
	if now.IsZero() {
		return errControlStateUnavailable
	}

	registry.mu.Lock()
	state, err := registry.stateForRegistrationLocked(handler.peer.DeviceID, now)
	if err != nil {
		registry.mu.Unlock()
		return err
	}
	incumbent := state.current
	if incumbent == nil {
		incumbent = state.draining
	}
	if incumbent != nil &&
		compareControlCredentials(handler.peer, incumbent.peer) < 0 {
		registry.mu.Unlock()
		return ErrControlConnectionSuperseded
	}

	olderDrain := state.draining
	priorCurrent := state.current
	stopPriorCurrent := false
	if priorCurrent != nil {
		stopPriorCurrent = priorCurrent.markDraining()
		state.draining = priorCurrent
	}
	state.current = handler
	state.lastSeen = monotonicControlTime(state.lastSeen, now)
	registry.mu.Unlock()

	if olderDrain != nil && olderDrain != priorCurrent {
		olderDrain.forceClose()
	}
	if stopPriorCurrent {
		priorCurrent.stopConnection()
	}
	return nil
}

func (registry *controlRegistry) unregister(handler *connectionHandler) {
	if registry == nil || handler == nil || !handler.peer.DeviceID.Valid() {
		return
	}
	now := time.Time{}
	if registry.now != nil {
		now = registry.now()
	}
	registry.mu.Lock()
	state := registry.states[handler.peer.DeviceID]
	if state != nil {
		if state.current == handler {
			state.current = nil
		}
		if state.draining == handler {
			state.draining = nil
		}
		if !now.IsZero() {
			state.lastSeen = monotonicControlTime(state.lastSeen, now)
		}
	}
	registry.mu.Unlock()
}

func (registry *controlRegistry) consume(
	deviceID domain.DeviceID,
) (bool, time.Duration, error) {
	if registry == nil || registry.now == nil || !deviceID.Valid() {
		return false, 0, errControlStateUnavailable
	}
	now := registry.now()
	if now.IsZero() {
		return false, 0, errControlStateUnavailable
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	state := registry.states[deviceID]
	if state == nil || state.current == nil && state.draining == nil {
		return false, 0, errControlStateUnavailable
	}
	now = monotonicControlTime(state.lastSeen, now)
	state.lastSeen = now
	allowed, retryAfter := state.bucket.consume(now)
	return allowed, retryAfter, nil
}

func (registry *controlRegistry) consumeProposal(
	deviceID domain.DeviceID,
) (bool, time.Duration, error) {
	if registry == nil || registry.now == nil || !deviceID.Valid() {
		return false, 0, errControlStateUnavailable
	}
	now := registry.now()
	if now.IsZero() {
		return false, 0, errControlStateUnavailable
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	state := registry.states[deviceID]
	if state == nil || state.current == nil && state.draining == nil {
		return false, 0, errControlStateUnavailable
	}
	now = monotonicControlTime(state.lastSeen, now)
	state.lastSeen = now
	allowed, retryAfter := state.proposalBucket.consumeAt(
		now,
		ProposalRatePerSecond,
		proposalTokenCapacity,
	)
	return allowed, retryAfter, nil
}

func (registry *controlRegistry) stateForRegistrationLocked(
	deviceID domain.DeviceID,
	now time.Time,
) (*controlPeerState, error) {
	if state := registry.states[deviceID]; state != nil {
		return state, nil
	}
	if len(registry.states) >= ControlPeerStatesMax {
		var (
			evictionID    domain.DeviceID
			evictionState *controlPeerState
		)
		for candidateID, candidate := range registry.states {
			if candidate == nil ||
				candidate.current != nil ||
				candidate.draining != nil {
				continue
			}
			if evictionState == nil ||
				candidate.lastSeen.Before(evictionState.lastSeen) ||
				candidate.lastSeen.Equal(evictionState.lastSeen) &&
					candidateID < evictionID {
				evictionID = candidateID
				evictionState = candidate
			}
		}
		if evictionState == nil {
			return nil, ErrControlConnectionCapacity
		}
		delete(registry.states, evictionID)
	}
	state := &controlPeerState{
		bucket: controlTokenBucket{
			credit: controlTokenCapacity,
			last:   now,
		},
		proposalBucket: controlTokenBucket{
			credit: proposalTokenCapacity,
			last:   now,
		},
		lastSeen: now,
	}
	registry.states[deviceID] = state
	return state, nil
}

func (bucket *controlTokenBucket) consume(
	now time.Time,
) (bool, time.Duration) {
	return bucket.consumeAt(now, ControlRatePerSecond, controlTokenCapacity)
}

func (bucket *controlTokenBucket) consumeAt(
	now time.Time,
	ratePerSecond int,
	capacity int64,
) (bool, time.Duration) {
	if ratePerSecond < 1 || capacity < controlTokenUnit {
		return false, 0
	}
	if bucket.last.IsZero() {
		bucket.last = now
	}
	now = monotonicControlTime(bucket.last, now)
	elapsed := now.Sub(bucket.last)
	bucket.last = now

	missing := capacity - bucket.credit
	if missing > 0 && elapsed > 0 {
		fillAfter := time.Duration(
			(missing + int64(ratePerSecond) - 1) /
				int64(ratePerSecond),
		)
		if elapsed >= fillAfter {
			bucket.credit = capacity
		} else {
			bucket.credit += int64(elapsed) * int64(ratePerSecond)
		}
	}
	if bucket.credit >= controlTokenUnit {
		bucket.credit -= controlTokenUnit
		return true, 0
	}
	missing = controlTokenUnit - bucket.credit
	retryAfter := time.Duration(
		(missing + int64(ratePerSecond) - 1) /
			int64(ratePerSecond),
	)
	return false, retryAfter
}

func monotonicControlTime(previous, candidate time.Time) time.Time {
	if !previous.IsZero() && candidate.Before(previous) {
		return previous
	}
	return candidate
}

func validControlPeer(peer transport.AuthenticatedPeer) bool {
	return peer.Plane == transport.PlaneContent &&
		peer.SessionID.Valid() &&
		peer.DeviceID.Valid() &&
		peer.Epoch > 0 &&
		domain.ValidUnsignedInteger(peer.Epoch) &&
		peer.AuthorizationChainIndex > 0 &&
		domain.ValidUnsignedInteger(peer.AuthorizationChainIndex)
}

func compareControlCredentials(
	left transport.AuthenticatedPeer,
	right transport.AuthenticatedPeer,
) int {
	if left.SessionID != right.SessionID ||
		left.DeviceID != right.DeviceID {
		return -1
	}
	if left.Epoch < right.Epoch {
		return -1
	}
	if left.Epoch > right.Epoch {
		return 1
	}
	if left.AuthorizationChainIndex < right.AuthorizationChainIndex {
		return -1
	}
	if left.AuthorizationChainIndex > right.AuthorizationChainIndex {
		return 1
	}
	return 0
}

type handlerAdmission uint8

const (
	handlerClosed handlerAdmission = iota
	handlerDraining
	handlerAccepted
)

func newConnectionHandler(
	server *Server,
	peer transport.AuthenticatedPeer,
	stop context.CancelFunc,
) *connectionHandler {
	return &connectionHandler{
		server:    server,
		peer:      peer,
		accepting: true,
		stop:      stop,
	}
}

func (handler *connectionHandler) registrationReady() bool {
	if handler == nil || handler.server == nil || handler.stop == nil {
		return false
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.accepting &&
		!handler.closing &&
		handler.activeCount == 0
}

func (handler *connectionHandler) begin() handlerAdmission {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	switch {
	case handler.closing:
		return handlerClosed
	case !handler.accepting:
		return handlerDraining
	default:
		handler.active.Add(1)
		handler.activeCount++
		return handlerAccepted
	}
}

func (handler *connectionHandler) end() {
	handler.mu.Lock()
	handler.activeCount--
	stop := !handler.accepting && handler.activeCount == 0
	handler.mu.Unlock()
	handler.active.Done()
	if stop {
		handler.stopConnection()
	}
}

func (handler *connectionHandler) markDraining() bool {
	handler.mu.Lock()
	handler.accepting = false
	stop := handler.activeCount == 0
	handler.mu.Unlock()
	return stop
}

func (handler *connectionHandler) forceClose() {
	handler.mu.Lock()
	handler.accepting = false
	handler.closing = true
	handler.mu.Unlock()
	handler.stopConnection()
}

func (handler *connectionHandler) close() {
	handler.mu.Lock()
	handler.accepting = false
	handler.closing = true
	handler.mu.Unlock()
	handler.stopConnection()
	handler.active.Wait()
}

func (handler *connectionHandler) stopConnection() {
	if handler == nil {
		return
	}
	handler.stopOnce.Do(func() {
		if handler.stop != nil {
			handler.stop()
		}
	})
}
