package contenthttp

import (
	"context"
	"errors"
	"net/http"
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
	BulkConnectionsMax    = 2
	BulkStreamsMax        = 1

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
	ErrBulkConnectionCapacity = errors.New(
		"content HTTP: bulk connection capacity reached",
	)
	errControlStateUnavailable = errors.New(
		"content HTTP: control state unavailable",
	)
	errConnectionRouteMismatch = errors.New(
		"content HTTP: connection route class mismatch",
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
	bulkCurrent    [BulkConnectionsMax]*connectionHandler
	bulkDraining   [BulkConnectionsMax]*connectionHandler
	credential     transport.AuthenticatedPeer
	credentialSet  bool
	bucket         controlTokenBucket
	proposalBucket controlTokenBucket
	lastSeen       time.Time
}

type contentConnectionRole uint8

const (
	contentConnectionUnbound contentConnectionRole = iota
	contentConnectionControl
	contentConnectionBulk
)

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
		!validControlPeer(handler.peer) {
		return errControlStateUnavailable
	}
	role := handler.connectionRole()
	if role != contentConnectionControl &&
		role != contentConnectionBulk {
		return errControlStateUnavailable
	}
	if !handler.registrationReady() {
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
	if state.credentialSet &&
		compareControlCredentials(handler.peer, state.credential) < 0 {
		registry.mu.Unlock()
		return ErrControlConnectionSuperseded
	}

	switch role {
	case contentConnectionControl:
		var (
			registered bool
			stop       *connectionHandler
		)
		registered, stop = state.registerControl(handler)
		if !registered {
			registry.mu.Unlock()
			return ErrControlConnectionCapacity
		}
		defer func() {
			if stop != nil {
				stop.stopConnection()
			}
		}()
	case contentConnectionBulk:
		var (
			registered bool
			stop       *connectionHandler
		)
		registered, stop = state.registerBulk(handler)
		if !registered {
			registry.mu.Unlock()
			return ErrBulkConnectionCapacity
		}
		defer func() {
			if stop != nil {
				stop.stopConnection()
			}
		}()
	}
	if !state.credentialSet ||
		compareControlCredentials(handler.peer, state.credential) > 0 {
		state.credential = handler.peer
		state.credentialSet = true
	}
	state.lastSeen = monotonicControlTime(state.lastSeen, now)
	registry.mu.Unlock()
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
		for index := range state.bulkCurrent {
			if state.bulkCurrent[index] == handler {
				state.bulkCurrent[index] = nil
			}
			if state.bulkDraining[index] == handler {
				state.bulkDraining[index] = nil
			}
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
	if state == nil || !state.activeConnections() {
		return false, 0, errControlStateUnavailable
	}
	now = monotonicControlTime(state.lastSeen, now)
	state.lastSeen = now
	allowed, retryAfter := state.bucket.consume(now)
	return allowed, retryAfter, nil
}

func (registry *controlRegistry) consumeRequest(
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
	state, err := registry.stateForRegistrationLocked(deviceID, now)
	if err != nil {
		return false, 0, err
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
	if state == nil || !state.activeConnections() {
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
				candidate.activeConnections() {
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

func (state *controlPeerState) activeConnections() bool {
	if state == nil {
		return false
	}
	if state.current != nil || state.draining != nil {
		return true
	}
	for index := range state.bulkCurrent {
		if state.bulkCurrent[index] != nil ||
			state.bulkDraining[index] != nil {
			return true
		}
	}
	return false
}

func (state *controlPeerState) registerControl(
	handler *connectionHandler,
) (bool, *connectionHandler) {
	if state == nil || handler == nil {
		return false, nil
	}
	if state.current != nil &&
		compareControlCredentials(
			handler.peer,
			state.current.peer,
		) < 0 {
		return false, nil
	}
	if state.current != nil && state.draining != nil {
		return false, nil
	}
	var stop *connectionHandler
	if state.current != nil {
		if state.current.markDraining() {
			stop = state.current
		}
		state.draining = state.current
	}
	state.current = handler
	return true, stop
}

func (state *controlPeerState) registerBulk(
	handler *connectionHandler,
) (bool, *connectionHandler) {
	if state == nil || handler == nil {
		return false, nil
	}

	slot := -1
	for index := range state.bulkCurrent {
		if state.bulkCurrent[index] == nil &&
			state.bulkDraining[index] == nil {
			slot = index
			break
		}
	}
	if slot < 0 {
		for index := range state.bulkCurrent {
			if state.bulkCurrent[index] == nil {
				slot = index
				break
			}
		}
	}
	if slot < 0 {
		for index, current := range state.bulkCurrent {
			if state.bulkDraining[index] != nil {
				continue
			}
			if compareControlCredentials(handler.peer, current.peer) < 0 {
				continue
			}
			if slot < 0 ||
				compareControlCredentials(
					current.peer,
					state.bulkCurrent[slot].peer,
				) < 0 {
				slot = index
			}
		}
	}
	if slot < 0 {
		return false, nil
	}

	var stop *connectionHandler
	if state.bulkCurrent[slot] != nil {
		if state.bulkCurrent[slot].markDraining() {
			stop = state.bulkCurrent[slot]
		}
		state.bulkDraining[slot] = state.bulkCurrent[slot]
	}
	state.bulkCurrent[slot] = handler
	return true, stop
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
	handlerBusy
	handlerRegistering
	handlerAccepted
)

func newConnectionHandler(
	server *Server,
	peer transport.AuthenticatedPeer,
	stop context.CancelFunc,
	drain func(),
) *connectionHandler {
	return &connectionHandler{
		server:    server,
		peer:      peer,
		accepting: true,
		stop:      stop,
		drain:     drain,
	}
}

func (handler *connectionHandler) bindConnectionRole(
	role contentConnectionRole,
) error {
	if handler == nil ||
		(role != contentConnectionControl &&
			role != contentConnectionBulk) {
		return errControlStateUnavailable
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.role != contentConnectionUnbound &&
		handler.role != role {
		return errConnectionRouteMismatch
	}
	handler.role = role
	return nil
}

func (handler *connectionHandler) connectionRole() contentConnectionRole {
	if handler == nil {
		return contentConnectionUnbound
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.role
}

func (handler *connectionHandler) registrationReady() bool {
	if handler == nil || handler.server == nil || handler.stop == nil {
		return false
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.accepting &&
		!handler.closing &&
		handler.role != contentConnectionUnbound &&
		(handler.registering && handler.activeCount == 1 ||
			!handler.registering && handler.activeCount == 0)
}

func (handler *connectionHandler) beginRequest() (
	contentConnectionRole,
	bool,
	handlerAdmission,
) {
	if handler == nil {
		return contentConnectionUnbound, false, handlerClosed
	}
	handler.registrationMu.Lock()
	defer handler.registrationMu.Unlock()
	handler.mu.Lock()
	defer handler.mu.Unlock()

	role := handler.role
	if !handler.registered && handler.registering {
		return role, false, handlerRegistering
	}
	switch {
	case handler.closing:
		return role, handler.registered, handlerClosed
	case !handler.accepting:
		return role, handler.registered, handlerDraining
	case handler.registered &&
		role == contentConnectionBulk &&
		handler.activeCount >= BulkStreamsMax:
		return role, true, handlerBusy
	default:
		if !handler.registered {
			handler.registering = true
		}
		handler.active.Add(1)
		handler.activeCount++
		return role, handler.registered, handlerAccepted
	}
}

func (handler *connectionHandler) finishRegistration() {
	handler.mu.Lock()
	handler.registering = false
	handler.mu.Unlock()
}

func (handler *connectionHandler) begin() handlerAdmission {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	switch {
	case handler.closing:
		return handlerClosed
	case !handler.accepting:
		return handlerDraining
	case handler.role == contentConnectionBulk &&
		handler.activeCount >= BulkStreamsMax:
		return handlerBusy
	default:
		handler.active.Add(1)
		handler.activeCount++
		return handlerAccepted
	}
}

func (handler *connectionHandler) endResponse(writer http.ResponseWriter) {
	handler.mu.Lock()
	handler.activeCount--
	handler.registering = false
	releaseRegistrySlot := handler.activeCount == 0 && !handler.accepting
	if releaseRegistrySlot {
		handler.closing = true
		if writer != nil {
			writer.Header().Set("Connection", "close")
		}
	}
	handler.mu.Unlock()
	handler.active.Done()
	if releaseRegistrySlot &&
		handler.server != nil &&
		handler.server.control != nil {
		handler.server.control.unregister(handler)
	}
}

func (handler *connectionHandler) prepareResponse(
	writer http.ResponseWriter,
) {
	if handler == nil || writer == nil {
		return
	}
	handler.mu.Lock()
	closeConnection := !handler.accepting || handler.closing
	handler.mu.Unlock()
	if closeConnection {
		writer.Header().Set("Connection", "close")
	}
}

func (handler *connectionHandler) markDraining() bool {
	handler.mu.Lock()
	handler.accepting = false
	idle := handler.activeCount == 0
	drain := handler.drain
	handler.mu.Unlock()
	if drain != nil {
		drain()
		return false
	}
	return idle
}

func (handler *connectionHandler) close() {
	handler.mu.Lock()
	handler.accepting = false
	handler.closing = true
	handler.mu.Unlock()
	handler.stopConnection()
	handler.active.Wait()
}

func (handler *connectionHandler) closeAfterResponse(
	writer http.ResponseWriter,
) {
	if writer != nil {
		// Retain the HTTP/1 compatibility signal in addition to the explicit
		// per-connection HTTP/2 graceful shutdown.
		writer.Header().Set("Connection", "close")
	}
	handler.mu.Lock()
	handler.accepting = false
	handler.closing = true
	drain := handler.drain
	handler.mu.Unlock()
	if drain != nil {
		drain()
	}
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
