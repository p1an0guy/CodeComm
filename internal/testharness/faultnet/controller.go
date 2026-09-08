// Package faultnet provides bounded, deterministic, directed byte-stream
// faults for integration tests. Rules are acquired once per non-empty Read or
// Write; an operation already inside the underlying net.Conn when Install
// returns is in flight. Drop is reversible backpressure. Removing Delay closes
// only connections with an acquired delay so blocked underlying I/O retires.
// Duplicate and Truncate are destructive raw-stream faults, so removing either
// closes every connection that acquired that generation. This package is not
// imported by production transports.
package faultnet

import (
	"context"
	"errors"
	"math"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	// ActiveRulesMax bounds controller-owned rule state.
	ActiveRulesMax = 256
	// TrackedConnectionsMax bounds live wrapped connections.
	TrackedConnectionsMax = 1024
	// DelayHardMax prevents an accidentally configured fault from retaining
	// test resources indefinitely.
	DelayHardMax = 30 * time.Second
	// TruncateBytesMax bounds directional counters while remaining well above
	// any expected integration-test transfer.
	TruncateBytesMax = uint64(1 << 40)
	// ReadChunkMax bounds the private replay retained by Duplicate.
	ReadChunkMax = 64 << 10
)

var (
	ErrInvalidController  = errors.New("faultnet: invalid controller")
	ErrInvalidLink        = errors.New("faultnet: invalid directed link")
	ErrInvalidRule        = errors.New("faultnet: invalid rule")
	ErrInvalidHandle      = errors.New("faultnet: invalid rule handle")
	ErrRuleActive         = errors.New("faultnet: directed link already has a rule")
	ErrRuleInactive       = errors.New("faultnet: rule became inactive")
	ErrStaleHandle        = errors.New("faultnet: stale rule handle")
	ErrRuleCapacity       = errors.New("faultnet: active rule capacity reached")
	ErrConnectionCapacity = errors.New(
		"faultnet: tracked connection capacity reached",
	)
	ErrControllerClosed = errors.New("faultnet: controller is closed")
)

// Link identifies one byte direction independently of which peer initiated
// the underlying full-duplex connection.
type Link struct {
	From domain.DeviceID
	To   domain.DeviceID
}

// Valid reports whether the link names two distinct valid devices.
func (link Link) Valid() bool {
	return link.From.Valid() && link.To.Valid() && link.From != link.To
}

// Kind identifies one mutually exclusive fault behavior.
type Kind uint8

const (
	// Drop black-holes a direction without consuming or forwarding bytes.
	// Operations resume after the matching rule is removed.
	Drop Kind = iota + 1
	// Delay waits once before each intercepted non-empty Read or Write.
	Delay
	// Duplicate forwards each intercepted raw chunk exactly twice.
	Duplicate
	// Truncate forwards a per-connection directional byte budget, then closes
	// the physical connection.
	Truncate
)

// Rule configures one directed behavior. Delay is valid only for Delay.
// TruncateAfter is valid only for Truncate and may be zero for immediate
// truncation.
type Rule struct {
	Kind          Kind
	Delay         time.Duration
	TruncateAfter uint64
}

// Handle identifies one installed rule generation. Its fields are
// intentionally private so a caller cannot forge authority over another
// controller or a replacement generation. Handles may be copied.
type Handle struct {
	controller *Controller
	state      *ruleState
	link       Link
	generation uint64
}

// Snapshot is a race-safe view of one rule generation. AffectedBytes counts
// known caller bytes held by Drop, transferred after Delay, replayed by
// Duplicate, or forwarded under a Truncate budget. A blocked read-side Drop
// consumes nothing, so it has no byte count until another action transfers it.
type Snapshot struct {
	ActiveConnections int
	ConnectionsHit    uint64
	Hits              uint64
	AffectedBytes     uint64
	ClosedConnections uint64
}

// Controller owns active rules and wrapped physical connections.
type Controller struct {
	maxDelay time.Duration
	done     chan struct{}

	mu               sync.Mutex
	closed           bool
	nextGeneration   uint64
	nextConnectionID uint64
	active           map[Link]*ruleState
	retiring         map[Link]*ruleState
	connections      map[*faultConn]struct{}

	closeOnce sync.Once
	closeErr  error
}

// NewController constructs a controller whose accepted Delay values cannot
// exceed maxDelay or DelayHardMax.
func NewController(maxDelay time.Duration) (*Controller, error) {
	if maxDelay <= 0 || maxDelay > DelayHardMax {
		return nil, ErrInvalidController
	}
	return &Controller{
		maxDelay:    maxDelay,
		done:        make(chan struct{}),
		active:      make(map[Link]*ruleState),
		retiring:    make(map[Link]*ruleState),
		connections: make(map[*faultConn]struct{}),
	}, nil
}

// Install atomically installs one rule on a currently clear directed link.
func (controller *Controller) Install(
	link Link,
	rule Rule,
) (Handle, error) {
	if controller == nil || !link.Valid() {
		return Handle{}, ErrInvalidLink
	}
	if err := controller.validateRule(rule); err != nil {
		return Handle{}, err
	}

	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return Handle{}, ErrControllerClosed
	}
	if _, exists := controller.active[link]; exists {
		return Handle{}, ErrRuleActive
	}
	if _, retiring := controller.retiring[link]; retiring {
		return Handle{}, ErrRuleActive
	}
	if len(controller.active)+len(controller.retiring) >= ActiveRulesMax ||
		controller.nextGeneration == math.MaxUint64 {
		return Handle{}, ErrRuleCapacity
	}
	controller.nextGeneration++
	state := newRuleState(link, rule, controller.nextGeneration)
	controller.active[link] = state
	return Handle{
		controller: controller,
		state:      state,
		link:       link,
		generation: state.generation,
	}, nil
}

// WaitForHits waits without polling until the rule generation has intercepted
// at least minimum non-empty operations. Removal before the threshold returns
// ErrRuleInactive.
func (controller *Controller) WaitForHits(
	ctx context.Context,
	handle Handle,
	minimum uint64,
) error {
	state, err := controller.validateHandle(handle)
	if err != nil {
		return err
	}
	if ctx == nil || minimum == 0 {
		return ErrInvalidHandle
	}
	for {
		hits, removed, changed := state.waitSnapshot()
		if hits >= minimum {
			return nil
		}
		if removed {
			return ErrRuleInactive
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-changed:
		}
	}
}

// Snapshot returns counters for the exact rule generation named by handle.
// It remains available after removal.
func (controller *Controller) Snapshot(
	handle Handle,
) (Snapshot, error) {
	state, err := controller.validateHandle(handle)
	if err != nil {
		return Snapshot{}, err
	}
	return state.snapshot(), nil
}

// Remove clears exactly the generation named by handle. Drop waiters resume.
// Connections whose in-flight operation acquired Duplicate or Truncate are
// closed because their raw stream may no longer be safely reusable.
//
// Removing an already removed generation is idempotent until a replacement is
// installed. It then returns ErrStaleHandle without affecting the replacement.
func (controller *Controller) Remove(handle Handle) error {
	state, err := controller.validateHandle(handle)
	if err != nil {
		return err
	}

	controller.mu.Lock()
	current := controller.active[handle.link]
	if current != state {
		retiring := controller.retiring[handle.link]
		controller.mu.Unlock()
		if retiring == state {
			<-state.retired
			return nil
		}
		if current != nil {
			return ErrStaleHandle
		}
		if retiring != nil {
			return ErrStaleHandle
		}
		if state.isRemoved() {
			return nil
		}
		return ErrStaleHandle
	}
	delete(controller.active, handle.link)
	controller.retiring[handle.link] = state
	touched := state.deactivate()
	controller.mu.Unlock()

	var closeErrors []error
	for _, connection := range touched {
		state.recordClosed(connection)
		closeErrors = append(
			closeErrors,
			connection.closeWithCause(net.ErrClosed),
		)
	}
	state.completeCleanup(controller)
	<-state.retired
	return errors.Join(closeErrors...)
}

// Wrap registers connection as a physical socket dialed by dialerDeviceID and
// accepted by acceptorDeviceID. On success the returned connection owns the
// input connection. On error ownership remains with the caller.
func (controller *Controller) Wrap(
	connection net.Conn,
	dialerDeviceID domain.DeviceID,
	acceptorDeviceID domain.DeviceID,
) (net.Conn, error) {
	return controller.WrapContext(
		context.Background(),
		connection,
		dialerDeviceID,
		acceptorDeviceID,
	)
}

// WrapContext is Wrap with a connection-lifetime context. Cancellation closes
// the connection and blocked operations return the context cause.
func (controller *Controller) WrapContext(
	ctx context.Context,
	connection net.Conn,
	dialerDeviceID domain.DeviceID,
	acceptorDeviceID domain.DeviceID,
) (net.Conn, error) {
	if controller == nil ||
		ctx == nil ||
		nilNetConn(connection) ||
		!dialerDeviceID.Valid() ||
		!acceptorDeviceID.Valid() ||
		dialerDeviceID == acceptorDeviceID {
		return nil, ErrInvalidController
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}

	wrapped := newFaultConn(
		controller,
		connection,
		dialerDeviceID,
		acceptorDeviceID,
		ctx,
	)
	controller.mu.Lock()
	if controller.closed {
		controller.mu.Unlock()
		return nil, ErrControllerClosed
	}
	if len(controller.connections) >= TrackedConnectionsMax ||
		controller.nextConnectionID == math.MaxUint64 {
		controller.mu.Unlock()
		return nil, ErrConnectionCapacity
	}
	controller.nextConnectionID++
	wrapped.id = controller.nextConnectionID
	controller.connections[wrapped] = struct{}{}
	controller.mu.Unlock()

	wrapped.bindContextCancellation()
	return wrapped, nil
}

// Close removes every rule, wakes every waiter, and closes every registered
// connection. It is safe and idempotent under concurrent calls.
func (controller *Controller) Close() error {
	if controller == nil {
		return ErrInvalidController
	}
	controller.closeOnce.Do(func() {
		controller.mu.Lock()
		controller.closed = true
		close(controller.done)
		type retiredRule struct {
			state       *ruleState
			connections []*faultConn
		}
		retired := make([]retiredRule, 0, len(controller.active))
		for link, state := range controller.active {
			delete(controller.active, link)
			retired = append(retired, retiredRule{
				state:       state,
				connections: state.deactivate(),
			})
		}
		connections := make(
			[]*faultConn,
			0,
			len(controller.connections),
		)
		for connection := range controller.connections {
			connections = append(connections, connection)
		}
		controller.mu.Unlock()

		for _, rule := range retired {
			for _, connection := range rule.connections {
				rule.state.recordClosed(connection)
			}
		}
		closeErrors := make([]error, 0, len(connections))
		cause := errors.Join(ErrControllerClosed, net.ErrClosed)
		for _, connection := range connections {
			closeErrors = append(
				closeErrors,
				connection.closeWithCause(cause),
			)
		}
		controller.closeErr = errors.Join(closeErrors...)
	})
	return controller.closeErr
}

func (controller *Controller) validateRule(rule Rule) error {
	if controller == nil {
		return ErrInvalidController
	}
	switch rule.Kind {
	case Drop, Duplicate:
		if rule.Delay != 0 || rule.TruncateAfter != 0 {
			return ErrInvalidRule
		}
	case Delay:
		if rule.Delay <= 0 ||
			rule.Delay > controller.maxDelay ||
			rule.Delay > DelayHardMax ||
			rule.TruncateAfter != 0 {
			return ErrInvalidRule
		}
	case Truncate:
		if rule.Delay != 0 || rule.TruncateAfter > TruncateBytesMax {
			return ErrInvalidRule
		}
	default:
		return ErrInvalidRule
	}
	return nil
}

func (controller *Controller) validateHandle(
	handle Handle,
) (*ruleState, error) {
	if controller == nil ||
		handle.controller != controller ||
		handle.state == nil ||
		!handle.link.Valid() ||
		handle.generation == 0 ||
		handle.state.link != handle.link ||
		handle.state.generation != handle.generation {
		return nil, ErrInvalidHandle
	}
	return handle.state, nil
}

func (controller *Controller) acquireRule(
	link Link,
	connection *faultConn,
	direction *directionState,
	affectedBytes uint64,
) (*ruleState, error) {
	for {
		controller.mu.Lock()
		if controller.closed {
			controller.mu.Unlock()
			return nil, ErrControllerClosed
		}
		if _, tracked := controller.connections[connection]; !tracked {
			controller.mu.Unlock()
			return nil, net.ErrClosed
		}
		state := controller.active[link]
		if state == nil {
			controller.mu.Unlock()
			return nil, nil
		}
		firstHit := direction.hitGeneration != state.generation
		if state.acquire(connection, affectedBytes, firstHit) {
			direction.hitGeneration = state.generation
			controller.mu.Unlock()
			return state, nil
		}
		controller.mu.Unlock()
	}
}

func (controller *Controller) finishRetirement(state *ruleState) {
	if controller == nil || state == nil {
		return
	}
	controller.mu.Lock()
	if controller.retiring[state.link] == state {
		delete(controller.retiring, state.link)
	}
	controller.mu.Unlock()
}

func (controller *Controller) unregister(connection *faultConn) {
	if controller == nil || connection == nil {
		return
	}
	controller.mu.Lock()
	delete(controller.connections, connection)
	states := make([]*ruleState, 0, len(controller.active))
	for _, state := range controller.active {
		states = append(states, state)
	}
	controller.mu.Unlock()
	for _, state := range states {
		state.detach(connection)
	}
}

func nilNetConn(connection net.Conn) bool {
	if connection == nil {
		return true
	}
	value := reflect.ValueOf(connection)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type ruleState struct {
	link       Link
	rule       Rule
	generation uint64
	release    chan struct{}

	mu                sync.Mutex
	removed           bool
	cleanupComplete   bool
	inFlight          uint64
	retired           chan struct{}
	retiredClosed     bool
	changed           chan struct{}
	hits              uint64
	affectedBytes     uint64
	connectionsHit    uint64
	connections       map[*faultConn]struct{}
	inFlightByConn    map[*faultConn]uint64
	touched           map[*faultConn]struct{}
	closedConnections uint64
}

func newRuleState(link Link, rule Rule, generation uint64) *ruleState {
	return &ruleState{
		link:           link,
		rule:           rule,
		generation:     generation,
		release:        make(chan struct{}),
		retired:        make(chan struct{}),
		changed:        make(chan struct{}),
		connections:    make(map[*faultConn]struct{}),
		inFlightByConn: make(map[*faultConn]uint64),
		touched:        make(map[*faultConn]struct{}),
	}
}

func (state *ruleState) acquire(
	connection *faultConn,
	affectedBytes uint64,
	firstHit bool,
) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.removed {
		return false
	}
	state.inFlight++
	state.inFlightByConn[connection]++
	state.hits = saturatingAdd(state.hits, 1)
	state.affectedBytes = saturatingAdd(
		state.affectedBytes,
		affectedBytes,
	)
	if firstHit {
		state.connectionsHit = saturatingAdd(state.connectionsHit, 1)
	}
	state.connections[connection] = struct{}{}
	if state.rule.Kind == Duplicate || state.rule.Kind == Truncate {
		state.touched[connection] = struct{}{}
	}
	state.signalLocked()
	return true
}

func (state *ruleState) releaseOperation(
	controller *Controller,
	connection *faultConn,
) {
	if state == nil || controller == nil || connection == nil {
		return
	}
	state.mu.Lock()
	if state.inFlight > 0 {
		state.inFlight--
	}
	if state.inFlightByConn != nil {
		switch count := state.inFlightByConn[connection]; {
		case count > 1:
			state.inFlightByConn[connection] = count - 1
		case count == 1:
			delete(state.inFlightByConn, connection)
		}
	}
	ready := state.removed &&
		state.cleanupComplete &&
		state.inFlight == 0
	if ready && !state.retiredClosed {
		state.retiredClosed = true
		close(state.retired)
	}
	state.mu.Unlock()
	if ready {
		controller.finishRetirement(state)
	}
}

func (state *ruleState) completeCleanup(controller *Controller) {
	if state == nil || controller == nil {
		return
	}
	state.mu.Lock()
	state.cleanupComplete = true
	ready := state.removed && state.inFlight == 0
	if ready && !state.retiredClosed {
		state.retiredClosed = true
		close(state.retired)
	}
	state.mu.Unlock()
	if ready {
		controller.finishRetirement(state)
	}
}

func (state *ruleState) addAffected(bytes uint64) {
	if bytes == 0 {
		return
	}
	state.mu.Lock()
	state.affectedBytes = saturatingAdd(state.affectedBytes, bytes)
	state.signalLocked()
	state.mu.Unlock()
}

func (state *ruleState) recordClosed(connection *faultConn) {
	if connection == nil {
		return
	}
	first := connection.markFaultClosed(state)
	state.mu.Lock()
	if state.connections != nil {
		delete(state.connections, connection)
	}
	if state.touched != nil {
		delete(state.touched, connection)
	}
	if first {
		state.closedConnections = saturatingAdd(
			state.closedConnections,
			1,
		)
		state.signalLocked()
	}
	state.mu.Unlock()
}

func (state *ruleState) detach(connection *faultConn) {
	if connection == nil {
		return
	}
	state.mu.Lock()
	_, destructive := state.touched[connection]
	delayed := state.rule.Kind == Delay &&
		state.inFlightByConn[connection] != 0
	delete(state.connections, connection)
	delete(state.inFlightByConn, connection)
	delete(state.touched, connection)
	state.mu.Unlock()
	if destructive || delayed {
		state.recordClosed(connection)
	}
}

func (state *ruleState) deactivate() []*faultConn {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.removed {
		return nil
	}
	state.removed = true
	close(state.release)
	toClose := make(map[*faultConn]struct{}, len(state.touched))
	for connection := range state.touched {
		toClose[connection] = struct{}{}
	}
	if state.rule.Kind == Delay {
		for connection := range state.inFlightByConn {
			toClose[connection] = struct{}{}
		}
	}
	touched := make([]*faultConn, 0, len(toClose))
	for connection := range toClose {
		touched = append(touched, connection)
	}
	state.connections = nil
	state.inFlightByConn = nil
	state.touched = nil
	state.signalLocked()
	return touched
}

func (state *ruleState) isRemoved() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.removed
}

func (state *ruleState) waitSnapshot() (
	uint64,
	bool,
	<-chan struct{},
) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.hits, state.removed, state.changed
}

func (state *ruleState) snapshot() Snapshot {
	state.mu.Lock()
	defer state.mu.Unlock()
	return Snapshot{
		ActiveConnections: len(state.connections),
		ConnectionsHit:    state.connectionsHit,
		Hits:              state.hits,
		AffectedBytes:     state.affectedBytes,
		ClosedConnections: state.closedConnections,
	}
}

func (state *ruleState) signalLocked() {
	close(state.changed)
	state.changed = make(chan struct{})
}

func saturatingAdd(current, delta uint64) uint64 {
	if math.MaxUint64-current < delta {
		return math.MaxUint64
	}
	return current + delta
}
