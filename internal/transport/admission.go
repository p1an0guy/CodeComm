package transport

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	HandshakeTimeout               = 10 * time.Second
	HandshakePendingMax            = 32
	HandshakeAttemptsPerMinute     = 10
	HandshakeAttemptBurst          = 20
	HandshakeSourceMultiplicityMax = 8
	HandshakeTrackedSourcesMax     = 1024
	HandshakeSourceIdleTimeout     = 10 * time.Minute
	HandshakeStateMaxBytes         = 8 << 20
	admissionSourceAccountBytes    = 256
	admissionAttemptWindow         = time.Minute
)

const (
	handshakePermitIssued uint32 = iota
	handshakePermitClaimed
	handshakePermitReleased
)

var (
	ErrInvalidAdmissionConfig = errors.New("transport: invalid admission configuration")
	ErrInvalidAdmissionSource = errors.New("transport: invalid admission source")
	ErrAdmissionClock         = errors.New("transport: invalid admission clock")
	ErrSourceRateLimited      = errors.New("transport: source handshake rate limited")
	ErrSourcePendingLimit     = errors.New("transport: source handshake limit reached")
	ErrHandshakeCapacity      = errors.New("transport: handshake capacity reached")
	ErrAdmissionStateLimit    = errors.New("transport: admission state limit reached")
)

// AdmissionLimiter bounds unauthenticated work before TLS certificate parsing.
// TryAcquire never waits: callers should silently close connections rejected by
// a capacity error. A successful permit must be released when TLS admission
// finishes.
type AdmissionLimiter struct {
	now func() time.Time

	attemptsPerWindow    int64
	attemptWindow        time.Duration
	attemptBurst         int64
	sourceMultiplicities map[netip.Addr]int64
	sourcePendingMax     int
	trackedSourcesMax    int
	sourceIdleTimeout    time.Duration
	stateMaxBytes        int

	mu             sync.Mutex
	sources        map[netip.Addr]*admissionSource
	stateBytes     int
	pending        int
	lastNow        time.Time
	handshakeSlots chan struct{}

	attempts                    uint64
	admitted                    uint64
	sourceRateLimitRejections   uint64
	sourcePendingRejections     uint64
	handshakeCapacityRejections uint64
	stateLimitRejections        uint64
}

type admissionSource struct {
	credit            int64
	attemptsPerWindow int64
	attemptBurst      int64
	refilledAt        time.Time
	lastSeen          time.Time
	pending           int
}

type admissionConfig struct {
	now                  func() time.Time
	attemptsPerWindow    int
	attemptWindow        time.Duration
	attemptBurst         int
	sourceMultiplicities map[netip.Addr]int64
	sourcePendingMax     int
	globalPendingMax     int
	trackedSourcesMax    int
	sourceIdleTimeout    time.Duration
	stateMaxBytes        int
}

// HandshakePermit owns one global handshake slot. Release is safe to call more
// than once, including through copies of the permit value.
type HandshakePermit struct {
	state *handshakePermitState
}

type handshakePermitState struct {
	limiter   *AdmissionLimiter
	source    netip.Addr
	lifecycle atomic.Uint32
}

// AdmissionStats is bounded operational state suitable for metrics and tests.
type AdmissionStats struct {
	TrackedSources              int
	PendingHandshakes           int
	AccountedBytes              int
	Attempts                    uint64
	Admitted                    uint64
	SourceRateLimitRejections   uint64
	SourcePendingRejections     uint64
	HandshakeCapacityRejections uint64
	StateLimitRejections        uint64
}

// AdmissionLimiterOptions configures trusted topology adaptation. A source
// multiplicity models independent device addresses collapsed to one address by
// an in-process transport; production network listeners leave the map empty.
type AdmissionLimiterOptions struct {
	Now                  func() time.Time
	SourceMultiplicities map[netip.Addr]uint8
}

// NewAdmissionLimiter constructs the fixed V1 pre-TLS admission policy.
func NewAdmissionLimiter() *AdmissionLimiter {
	limiter, err := NewAdmissionLimiterWithClock(time.Now)
	if err != nil {
		panic(err)
	}
	return limiter
}

// NewAdmissionLimiterWithClock constructs the fixed V1 policy with an
// injected clock for deterministic lifecycle tests.
func NewAdmissionLimiterWithClock(
	now func() time.Time,
) (*AdmissionLimiter, error) {
	return NewAdmissionLimiterWithOptions(AdmissionLimiterOptions{Now: now})
}

// NewAdmissionLimiterWithOptions constructs the fixed V1 policy and applies a
// bounded trusted-topology multiplicity without changing pending, state, or
// source-idle limits.
func NewAdmissionLimiterWithOptions(
	options AdmissionLimiterOptions,
) (*AdmissionLimiter, error) {
	multiplicities, err := normalizeAdmissionSourceMultiplicities(
		options.SourceMultiplicities,
	)
	if err != nil {
		return nil, err
	}
	return newAdmissionLimiter(admissionConfig{
		now:                  options.Now,
		attemptsPerWindow:    HandshakeAttemptsPerMinute,
		attemptWindow:        admissionAttemptWindow,
		attemptBurst:         HandshakeAttemptBurst,
		sourceMultiplicities: multiplicities,
		sourcePendingMax:     HandshakePendingMax,
		globalPendingMax:     HandshakePendingMax,
		trackedSourcesMax:    HandshakeTrackedSourcesMax,
		sourceIdleTimeout:    HandshakeSourceIdleTimeout,
		stateMaxBytes:        HandshakeStateMaxBytes,
	})
}

func newAdmissionLimiter(config admissionConfig) (*AdmissionLimiter, error) {
	if config.now == nil ||
		config.attemptsPerWindow < 1 ||
		config.attemptWindow <= 0 ||
		config.attemptBurst < 1 ||
		config.sourcePendingMax < 1 ||
		config.globalPendingMax < 1 ||
		config.sourcePendingMax > config.globalPendingMax ||
		config.trackedSourcesMax < 1 ||
		config.sourceIdleTimeout <= 0 ||
		config.stateMaxBytes < admissionSourceAccountBytes {
		return nil, ErrInvalidAdmissionConfig
	}
	for source, multiplicity := range config.sourceMultiplicities {
		canonical, ok := canonicalAdmissionSource(source)
		if !ok ||
			canonical != source ||
			multiplicity < 2 ||
			multiplicity > HandshakeSourceMultiplicityMax {
			return nil, ErrInvalidAdmissionConfig
		}
	}
	window := int64(config.attemptWindow)
	burst := int64(config.attemptBurst)
	if burst > (1<<63-1)/window/
		HandshakeSourceMultiplicityMax {
		return nil, ErrInvalidAdmissionConfig
	}
	multiplicities := make(
		map[netip.Addr]int64,
		len(config.sourceMultiplicities),
	)
	for source, multiplicity := range config.sourceMultiplicities {
		multiplicities[source] = multiplicity
	}
	return &AdmissionLimiter{
		now:                  config.now,
		attemptsPerWindow:    int64(config.attemptsPerWindow),
		attemptWindow:        config.attemptWindow,
		attemptBurst:         burst,
		sourceMultiplicities: multiplicities,
		sourcePendingMax:     config.sourcePendingMax,
		trackedSourcesMax:    config.trackedSourcesMax,
		sourceIdleTimeout:    config.sourceIdleTimeout,
		stateMaxBytes:        config.stateMaxBytes,
		sources:              make(map[netip.Addr]*admissionSource),
		handshakeSlots:       make(chan struct{}, config.globalPendingMax),
	}, nil
}

// TryAcquire applies the source rate/state limits and then attempts to reserve
// one global handshake slot. Every syntactically valid call is an attempt and
// consumes source rate credit even when a pending ceiling rejects it.
func (limiter *AdmissionLimiter) TryAcquire(source netip.Addr) (*HandshakePermit, error) {
	if limiter == nil || limiter.now == nil {
		return nil, ErrInvalidAdmissionConfig
	}
	source, ok := canonicalAdmissionSource(source)
	if !ok {
		return nil, ErrInvalidAdmissionSource
	}
	now := limiter.now()
	if now.IsZero() {
		return nil, ErrAdmissionClock
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	limiter.attempts++
	if !limiter.lastNow.IsZero() && now.Before(limiter.lastNow) {
		now = limiter.lastNow
	} else {
		limiter.lastNow = now
	}
	state, err := limiter.sourceState(source, now)
	if err != nil {
		if errors.Is(err, ErrAdmissionStateLimit) {
			limiter.stateLimitRejections++
		}
		return nil, err
	}
	state.lastSeen = now
	limiter.refill(state, now)
	if state.credit < int64(limiter.attemptWindow) {
		limiter.sourceRateLimitRejections++
		return nil, ErrSourceRateLimited
	}
	state.credit -= int64(limiter.attemptWindow)
	if state.pending >= limiter.sourcePendingMax {
		limiter.sourcePendingRejections++
		return nil, ErrSourcePendingLimit
	}
	select {
	case limiter.handshakeSlots <- struct{}{}:
	default:
		limiter.handshakeCapacityRejections++
		return nil, ErrHandshakeCapacity
	}
	state.pending++
	limiter.pending++
	limiter.admitted++
	return &HandshakePermit{state: &handshakePermitState{
		limiter: limiter,
		source:  source,
	}}, nil
}

func (limiter *AdmissionLimiter) sourceState(
	source netip.Addr,
	now time.Time,
) (*admissionSource, error) {
	if state := limiter.sources[source]; state != nil {
		return state, nil
	}
	if len(limiter.sources) >= limiter.trackedSourcesMax ||
		limiter.stateBytes > limiter.stateMaxBytes-admissionSourceAccountBytes {
		limiter.expireIdle(now)
	}
	for len(limiter.sources) >= limiter.trackedSourcesMax ||
		limiter.stateBytes > limiter.stateMaxBytes-admissionSourceAccountBytes {
		if !limiter.evictOldestIdle() {
			return nil, ErrAdmissionStateLimit
		}
	}
	multiplicity := limiter.sourceMultiplicities[source]
	if multiplicity == 0 {
		multiplicity = 1
	}
	attemptBurst := limiter.attemptBurst * multiplicity
	state := &admissionSource{
		credit: limiter.attemptBurst *
			int64(limiter.attemptWindow) *
			multiplicity,
		attemptsPerWindow: limiter.attemptsPerWindow * multiplicity,
		attemptBurst:      attemptBurst,
		refilledAt:        now,
		lastSeen:          now,
	}
	limiter.sources[source] = state
	limiter.stateBytes += admissionSourceAccountBytes
	return state, nil
}

func (limiter *AdmissionLimiter) refill(state *admissionSource, now time.Time) {
	if state == nil || !now.After(state.refilledAt) {
		return
	}
	capacity := state.attemptBurst * int64(limiter.attemptWindow)
	missing := capacity - state.credit
	elapsed := int64(now.Sub(state.refilledAt))
	if missing <= 0 {
		state.credit = capacity
		state.refilledAt = now
		return
	}
	needed := missing / state.attemptsPerWindow
	if missing%state.attemptsPerWindow != 0 {
		needed++
	}
	if elapsed >= needed {
		state.credit = capacity
	} else {
		state.credit += elapsed * state.attemptsPerWindow
	}
	state.refilledAt = now
}

func normalizeAdmissionSourceMultiplicities(
	input map[netip.Addr]uint8,
) (map[netip.Addr]int64, error) {
	if len(input) == 0 {
		return nil, nil
	}
	result := make(map[netip.Addr]int64, len(input))
	for source, multiplicity := range input {
		canonical, ok := canonicalAdmissionSource(source)
		if !ok ||
			multiplicity < 2 ||
			multiplicity > HandshakeSourceMultiplicityMax {
			return nil, ErrInvalidAdmissionConfig
		}
		if _, duplicate := result[canonical]; duplicate {
			return nil, ErrInvalidAdmissionConfig
		}
		result[canonical] = int64(multiplicity)
	}
	return result, nil
}

func (limiter *AdmissionLimiter) expireIdle(now time.Time) {
	for source, state := range limiter.sources {
		if state.pending == 0 &&
			!now.Before(state.lastSeen.Add(limiter.sourceIdleTimeout)) {
			delete(limiter.sources, source)
			limiter.stateBytes -= admissionSourceAccountBytes
		}
	}
}

func (limiter *AdmissionLimiter) evictOldestIdle() bool {
	var (
		oldestSource netip.Addr
		oldest       *admissionSource
	)
	for source, state := range limiter.sources {
		if state.pending != 0 {
			continue
		}
		if oldest == nil ||
			state.lastSeen.Before(oldest.lastSeen) ||
			state.lastSeen.Equal(oldest.lastSeen) && source.Less(oldestSource) {
			oldestSource = source
			oldest = state
		}
	}
	if oldest == nil {
		return false
	}
	delete(limiter.sources, oldestSource)
	limiter.stateBytes -= admissionSourceAccountBytes
	return true
}

// BeginHandshake transfers this permit to exactly one TLS handshake owner.
// The owner must call Release on every exit path.
func (permit *HandshakePermit) BeginHandshake() bool {
	return permit != nil &&
		permit.state != nil &&
		permit.state.lifecycle.CompareAndSwap(
			handshakePermitIssued,
			handshakePermitClaimed,
		)
}

// Release returns the permit's source and global pending capacity.
func (permit *HandshakePermit) Release() {
	if permit == nil || permit.state == nil {
		return
	}
	state := permit.state
	for {
		lifecycle := state.lifecycle.Load()
		if lifecycle == handshakePermitReleased {
			return
		}
		if state.lifecycle.CompareAndSwap(
			lifecycle,
			handshakePermitReleased,
		) {
			break
		}
	}
	limiter := state.limiter
	limiter.mu.Lock()
	source := limiter.sources[state.source]
	if source == nil || source.pending < 1 || limiter.pending < 1 {
		limiter.mu.Unlock()
		panic("transport: admission permit accounting invariant violated")
	}
	source.pending--
	limiter.pending--
	select {
	case <-limiter.handshakeSlots:
	default:
		limiter.mu.Unlock()
		panic("transport: admission semaphore invariant violated")
	}
	limiter.mu.Unlock()
}

// Stats returns a consistent snapshot without exposing source identities.
func (limiter *AdmissionLimiter) Stats() AdmissionStats {
	if limiter == nil {
		return AdmissionStats{}
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return AdmissionStats{
		TrackedSources:              len(limiter.sources),
		PendingHandshakes:           limiter.pending,
		AccountedBytes:              limiter.stateBytes,
		Attempts:                    limiter.attempts,
		Admitted:                    limiter.admitted,
		SourceRateLimitRejections:   limiter.sourceRateLimitRejections,
		SourcePendingRejections:     limiter.sourcePendingRejections,
		HandshakeCapacityRejections: limiter.handshakeCapacityRejections,
		StateLimitRejections:        limiter.stateLimitRejections,
	}
}

func canonicalAdmissionSource(source netip.Addr) (netip.Addr, bool) {
	if !source.IsValid() {
		return netip.Addr{}, false
	}
	source = source.Unmap().WithZone("")
	if source.IsUnspecified() || source.IsMulticast() {
		return netip.Addr{}, false
	}
	return source, true
}
