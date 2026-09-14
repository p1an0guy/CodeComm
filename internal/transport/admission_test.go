package transport

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type admissionTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *admissionTestClock) read() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *admissionTestClock) advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func newTestAdmissionLimiter(
	t *testing.T,
	clock *admissionTestClock,
	mutate func(*admissionConfig),
) *AdmissionLimiter {
	t.Helper()
	config := admissionConfig{
		now:               clock.read,
		attemptsPerWindow: HandshakeAttemptsPerMinute,
		attemptWindow:     admissionAttemptWindow,
		attemptBurst:      HandshakeAttemptBurst,
		sourcePendingMax:  HandshakePendingMax,
		globalPendingMax:  HandshakePendingMax,
		trackedSourcesMax: HandshakeTrackedSourcesMax,
		sourceIdleTimeout: HandshakeSourceIdleTimeout,
		stateMaxBytes:     HandshakeStateMaxBytes,
	}
	if mutate != nil {
		mutate(&config)
	}
	limiter, err := newAdmissionLimiter(config)
	if err != nil {
		t.Fatalf("newAdmissionLimiter() error = %v", err)
	}
	return limiter
}

func TestAdmissionLimiterRateBurstAndRefill(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(1000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.globalPendingMax = 64
		config.sourcePendingMax = 64
	})
	source := netip.MustParseAddr("192.0.2.10")

	for index := 0; index < HandshakeAttemptBurst; index++ {
		permit, err := limiter.TryAcquire(source)
		if err != nil {
			t.Fatalf("TryAcquire() burst %d error = %v", index, err)
		}
		permit.Release()
	}
	if _, err := limiter.TryAcquire(source); !errors.Is(err, ErrSourceRateLimited) {
		t.Fatalf("TryAcquire() over burst error = %v, want %v", err, ErrSourceRateLimited)
	}

	clock.advance(6*time.Second - time.Nanosecond)
	if _, err := limiter.TryAcquire(source); !errors.Is(err, ErrSourceRateLimited) {
		t.Fatalf("TryAcquire() before refill error = %v, want %v", err, ErrSourceRateLimited)
	}
	stats := limiter.Stats()
	if stats.Attempts != HandshakeAttemptBurst+2 ||
		stats.Admitted != HandshakeAttemptBurst ||
		stats.SourceRateLimitRejections != 2 {
		t.Fatalf("rate-limit counters = %+v", stats)
	}
	clock.advance(time.Nanosecond)
	permit, err := limiter.TryAcquire(source)
	if err != nil {
		t.Fatalf("TryAcquire() after refill error = %v", err)
	}
	permit.Release()

	clock.advance(10 * time.Minute)
	for index := 0; index < HandshakeAttemptBurst; index++ {
		permit, err = limiter.TryAcquire(source)
		if err != nil {
			t.Fatalf("TryAcquire() replenished burst %d error = %v", index, err)
		}
		permit.Release()
	}
}

func TestAdmissionLimiterUsesInjectedClock(t *testing.T) {
	t.Parallel()
	if _, err := NewAdmissionLimiterWithClock(nil); !errors.Is(
		err,
		ErrInvalidAdmissionConfig,
	) {
		t.Fatalf("NewAdmissionLimiterWithClock(nil) error = %v", err)
	}
	clock := &admissionTestClock{now: time.Unix(1500, 0)}
	limiter, err := NewAdmissionLimiterWithClock(clock.read)
	if err != nil {
		t.Fatalf("NewAdmissionLimiterWithClock() error = %v", err)
	}
	source := netip.MustParseAddr("192.0.2.15")
	for range HandshakeAttemptBurst {
		permit, acquireErr := limiter.TryAcquire(source)
		if acquireErr != nil {
			t.Fatalf("TryAcquire() error = %v", acquireErr)
		}
		permit.Release()
	}
	if _, err := limiter.TryAcquire(source); !errors.Is(
		err,
		ErrSourceRateLimited,
	) {
		t.Fatalf("TryAcquire(over burst) error = %v", err)
	}
	clock.advance(6 * time.Second)
	permit, err := limiter.TryAcquire(source)
	if err != nil {
		t.Fatalf("TryAcquire(after injected-clock advance) error = %v", err)
	}
	permit.Release()
}

func TestAdmissionLimiterScalesOnlyCollapsedSourceRate(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(1750, 0)}
	collapsed := netip.MustParseAddr("192.0.2.16")
	ordinary := netip.MustParseAddr("192.0.2.17")
	multiplicities := map[netip.Addr]uint8{collapsed: 4}
	limiter, err := NewAdmissionLimiterWithOptions(
		AdmissionLimiterOptions{
			Now:                  clock.read,
			SourceMultiplicities: multiplicities,
		},
	)
	if err != nil {
		t.Fatalf("NewAdmissionLimiterWithOptions() error = %v", err)
	}
	multiplicities[collapsed] = HandshakeSourceMultiplicityMax

	for index := range 4 * HandshakeAttemptBurst {
		permit, acquireErr := limiter.TryAcquire(collapsed)
		if acquireErr != nil {
			t.Fatalf(
				"TryAcquire(collapsed burst %d) error = %v",
				index,
				acquireErr,
			)
		}
		permit.Release()
	}
	if _, err := limiter.TryAcquire(collapsed); !errors.Is(
		err,
		ErrSourceRateLimited,
	) {
		t.Fatalf("TryAcquire(collapsed over burst) error = %v", err)
	}
	clock.advance(1500 * time.Millisecond)
	permit, err := limiter.TryAcquire(collapsed)
	if err != nil {
		t.Fatalf("TryAcquire(collapsed after refill) error = %v", err)
	}
	permit.Release()

	for index := range HandshakeAttemptBurst {
		permit, acquireErr := limiter.TryAcquire(ordinary)
		if acquireErr != nil {
			t.Fatalf(
				"TryAcquire(ordinary burst %d) error = %v",
				index,
				acquireErr,
			)
		}
		permit.Release()
	}
	if _, err := limiter.TryAcquire(ordinary); !errors.Is(
		err,
		ErrSourceRateLimited,
	) {
		t.Fatalf("TryAcquire(ordinary over burst) error = %v", err)
	}

	collapsedState := limiter.sources[collapsed]
	ordinaryState := limiter.sources[ordinary]
	if collapsedState == nil ||
		ordinaryState == nil ||
		collapsedState.attemptBurst != 4*HandshakeAttemptBurst ||
		collapsedState.attemptsPerWindow !=
			4*HandshakeAttemptsPerMinute ||
		ordinaryState.attemptBurst != HandshakeAttemptBurst ||
		ordinaryState.attemptsPerWindow !=
			HandshakeAttemptsPerMinute ||
		limiter.sourceIdleTimeout != HandshakeSourceIdleTimeout ||
		limiter.sourcePendingMax != HandshakePendingMax {
		t.Fatalf(
			"scaled admission state = collapsed %+v ordinary %+v",
			collapsedState,
			ordinaryState,
		)
	}
}

func TestAdmissionLimiterRejectsInvalidSourceMultiplicities(t *testing.T) {
	t.Parallel()
	validSource := netip.MustParseAddr("192.0.2.18")
	tests := []map[netip.Addr]uint8{
		{{}: 2},
		{netip.IPv4Unspecified(): 2},
		{validSource: 0},
		{validSource: 1},
		{validSource: HandshakeSourceMultiplicityMax + 1},
	}
	for _, multiplicities := range tests {
		if _, err := NewAdmissionLimiterWithOptions(
			AdmissionLimiterOptions{
				Now:                  time.Now,
				SourceMultiplicities: multiplicities,
			},
		); !errors.Is(err, ErrInvalidAdmissionConfig) {
			t.Fatalf(
				"NewAdmissionLimiterWithOptions(%v) error = %v",
				multiplicities,
				err,
			)
		}
	}
}

func TestAdmissionLimiterPendingCeilingsAndRelease(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(2000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.attemptBurst = 20
		config.sourcePendingMax = 2
		config.globalPendingMax = 3
	})
	firstSource := netip.MustParseAddr("192.0.2.1")
	secondSource := netip.MustParseAddr("192.0.2.2")

	first, err := limiter.TryAcquire(firstSource)
	if err != nil {
		t.Fatalf("TryAcquire(first) error = %v", err)
	}
	firstCopy := *first
	second, err := limiter.TryAcquire(firstSource)
	if err != nil {
		t.Fatalf("TryAcquire(second) error = %v", err)
	}
	if _, err := limiter.TryAcquire(firstSource); !errors.Is(err, ErrSourcePendingLimit) {
		t.Fatalf("TryAcquire(source full) error = %v, want %v", err, ErrSourcePendingLimit)
	}
	third, err := limiter.TryAcquire(secondSource)
	if err != nil {
		t.Fatalf("TryAcquire(third) error = %v", err)
	}
	if _, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.3")); !errors.Is(err, ErrHandshakeCapacity) {
		t.Fatalf("TryAcquire(global full) error = %v, want %v", err, ErrHandshakeCapacity)
	}
	stats := limiter.Stats()
	if stats.Attempts != 5 ||
		stats.Admitted != 3 ||
		stats.SourcePendingRejections != 1 ||
		stats.HandshakeCapacityRejections != 1 ||
		stats.SourceRateLimitRejections != 0 ||
		stats.StateLimitRejections != 0 {
		t.Fatalf("admission counters = %+v", stats)
	}

	first.Release()
	firstCopy.Release()
	if got := limiter.Stats().PendingHandshakes; got != 2 {
		t.Fatalf("pending after idempotent release = %d, want 2", got)
	}
	replacement, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.3"))
	if err != nil {
		t.Fatalf("TryAcquire(after release) error = %v", err)
	}
	second.Release()
	third.Release()
	replacement.Release()
	if got := limiter.Stats().PendingHandshakes; got != 0 {
		t.Fatalf("pending after all releases = %d, want 0", got)
	}
}

func TestHandshakePermitHasOneHandshakeOwner(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(2500, 0)}
	limiter := newTestAdmissionLimiter(t, clock, nil)
	permit, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.9"))
	if err != nil {
		t.Fatal(err)
	}
	copyOfPermit := *permit
	if !permit.BeginHandshake() {
		t.Fatal("first BeginHandshake() was rejected")
	}
	if copyOfPermit.BeginHandshake() {
		t.Fatal("copied permit acquired a second handshake")
	}
	permit.Release()
	copyOfPermit.Release()
	if permit.BeginHandshake() {
		t.Fatal("released permit was reused")
	}
	if pending := limiter.Stats().PendingHandshakes; pending != 0 {
		t.Fatalf("pending handshakes = %d, want 0", pending)
	}
}

func TestAdmissionLimiterTrackedSourceEviction(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(3000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.trackedSourcesMax = 2
		config.sourceIdleTimeout = time.Minute
	})
	oldest := netip.MustParseAddr("192.0.2.1")
	active := netip.MustParseAddr("192.0.2.2")
	replacement := netip.MustParseAddr("192.0.2.3")

	permit, err := limiter.TryAcquire(oldest)
	if err != nil {
		t.Fatalf("TryAcquire(oldest) error = %v", err)
	}
	permit.Release()
	clock.advance(time.Second)
	activePermit, err := limiter.TryAcquire(active)
	if err != nil {
		t.Fatalf("TryAcquire(active) error = %v", err)
	}
	clock.advance(time.Second)
	replacementPermit, err := limiter.TryAcquire(replacement)
	if err != nil {
		t.Fatalf("TryAcquire(replacement) error = %v", err)
	}
	if _, found := limiter.sources[oldest]; found {
		t.Fatal("oldest idle source was not evicted")
	}
	if limiter.sources[active] == nil || limiter.sources[replacement] == nil {
		t.Fatal("active or replacement source missing after eviction")
	}
	activePermit.Release()
	replacementPermit.Release()
}

func TestAdmissionLimiterEvictionTieBreaksByAddress(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(3500, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.trackedSourcesMax = 2
	})
	higher := netip.MustParseAddr("192.0.2.2")
	lower := netip.MustParseAddr("192.0.2.1")
	for _, source := range []netip.Addr{higher, lower} {
		permit, err := limiter.TryAcquire(source)
		if err != nil {
			t.Fatalf("TryAcquire(%v) error = %v", source, err)
		}
		permit.Release()
	}
	permit, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.3"))
	if err != nil {
		t.Fatalf("TryAcquire(replacement) error = %v", err)
	}
	permit.Release()
	if _, found := limiter.sources[lower]; found {
		t.Fatal("lower address was not selected for equal-age eviction")
	}
	if limiter.sources[higher] == nil {
		t.Fatal("higher address was unexpectedly evicted")
	}
}

func TestAdmissionLimiterIdleExpiryAndActiveProtection(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(4000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.trackedSourcesMax = 2
		config.sourceIdleTimeout = time.Minute
	})
	active := netip.MustParseAddr("192.0.2.10")
	idle := netip.MustParseAddr("192.0.2.11")
	activePermit, err := limiter.TryAcquire(active)
	if err != nil {
		t.Fatalf("TryAcquire(active) error = %v", err)
	}
	idlePermit, err := limiter.TryAcquire(idle)
	if err != nil {
		t.Fatalf("TryAcquire(idle) error = %v", err)
	}
	idlePermit.Release()
	clock.advance(time.Minute)
	newPermit, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.12"))
	if err != nil {
		t.Fatalf("TryAcquire(new) error = %v", err)
	}
	if limiter.sources[active] == nil {
		t.Fatal("active source was expired")
	}
	if _, found := limiter.sources[idle]; found {
		t.Fatal("idle source was not expired")
	}
	activePermit.Release()
	newPermit.Release()
}

func TestAdmissionLimiterStateByteCeiling(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(5000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.stateMaxBytes = 2 * admissionSourceAccountBytes
		config.trackedSourcesMax = 10
		config.globalPendingMax = 2
		config.sourcePendingMax = 2
	})
	first, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.20"))
	if err != nil {
		t.Fatalf("TryAcquire(first) error = %v", err)
	}
	second, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.21"))
	if err != nil {
		t.Fatalf("TryAcquire(second) error = %v", err)
	}
	if _, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.22")); !errors.Is(err, ErrAdmissionStateLimit) {
		t.Fatalf("TryAcquire(over bytes) error = %v, want %v", err, ErrAdmissionStateLimit)
	}
	stats := limiter.Stats()
	if stats.AccountedBytes != 2*admissionSourceAccountBytes ||
		stats.TrackedSources != 2 ||
		stats.StateLimitRejections != 1 {
		t.Fatalf("Stats() = %+v, want two bounded source entries", stats)
	}
	first.Release()
	second.Release()
}

func TestAdmissionLimiterForgedSourceFloodStaysBounded(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(5500, 0)}
	limiter := newTestAdmissionLimiter(t, clock, nil)
	const attempts = HandshakeTrackedSourcesMax * 4
	for index := 0; index < attempts; index++ {
		source := netip.AddrFrom4([4]byte{
			10,
			byte(index >> 16),
			byte(index >> 8),
			byte(index),
		})
		permit, err := limiter.TryAcquire(source)
		if err != nil {
			t.Fatalf("TryAcquire(%v) error = %v", source, err)
		}
		permit.Release()
	}
	stats := limiter.Stats()
	if stats.TrackedSources != HandshakeTrackedSourcesMax {
		t.Fatalf("tracked sources = %d, want %d", stats.TrackedSources, HandshakeTrackedSourcesMax)
	}
	if stats.AccountedBytes > HandshakeStateMaxBytes {
		t.Fatalf("accounted bytes = %d, limit %d", stats.AccountedBytes, HandshakeStateMaxBytes)
	}
}

func TestAdmissionLimiterCanonicalizesSourceIP(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(6000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, nil)
	mapped := netip.MustParseAddr("::ffff:192.0.2.30")
	plain := netip.MustParseAddr("192.0.2.30")
	first, err := limiter.TryAcquire(mapped)
	if err != nil {
		t.Fatalf("TryAcquire(mapped) error = %v", err)
	}
	first.Release()
	second, err := limiter.TryAcquire(plain)
	if err != nil {
		t.Fatalf("TryAcquire(plain) error = %v", err)
	}
	second.Release()
	if got := limiter.Stats().TrackedSources; got != 1 {
		t.Fatalf("tracked sources = %d, want 1", got)
	}

	for _, source := range []netip.Addr{
		{},
		netip.IPv4Unspecified(),
		netip.IPv6Unspecified(),
		netip.MustParseAddr("239.1.2.3"),
		netip.MustParseAddr("ff02::1"),
	} {
		if _, err := limiter.TryAcquire(source); !errors.Is(err, ErrInvalidAdmissionSource) {
			t.Fatalf("TryAcquire(%v) error = %v, want %v", source, err, ErrInvalidAdmissionSource)
		}
	}
}

func TestAdmissionLimiterClockRegressionDoesNotRefill(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(7000, 0)}
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.attemptBurst = 1
		config.attemptsPerWindow = 1
	})
	source := netip.MustParseAddr("192.0.2.40")
	permit, err := limiter.TryAcquire(source)
	if err != nil {
		t.Fatalf("TryAcquire(first) error = %v", err)
	}
	permit.Release()
	clock.advance(-time.Hour)
	if _, err := limiter.TryAcquire(source); !errors.Is(err, ErrSourceRateLimited) {
		t.Fatalf("TryAcquire(after regression) error = %v, want %v", err, ErrSourceRateLimited)
	}
	clock.advance(time.Hour + time.Minute)
	permit, err = limiter.TryAcquire(source)
	if err != nil {
		t.Fatalf("TryAcquire(after recovery) error = %v", err)
	}
	permit.Release()
}

func TestAdmissionLimiterConcurrentGlobalSemaphore(t *testing.T) {
	t.Parallel()
	clock := &admissionTestClock{now: time.Unix(8000, 0)}
	const globalMax = 8
	limiter := newTestAdmissionLimiter(t, clock, func(config *admissionConfig) {
		config.attemptBurst = 64
		config.sourcePendingMax = globalMax
		config.globalPendingMax = globalMax
		config.trackedSourcesMax = 64
	})
	var (
		admitted atomic.Int64
		wg       sync.WaitGroup
		permits  = make(chan *HandshakePermit, 64)
	)
	for index := 1; index <= 64; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			source := netip.AddrFrom4([4]byte{198, 51, 100, byte(index)})
			permit, err := limiter.TryAcquire(source)
			if err == nil {
				admitted.Add(1)
				permits <- permit
				return
			}
			if !errors.Is(err, ErrHandshakeCapacity) {
				t.Errorf("TryAcquire(%v) error = %v", source, err)
			}
		}(index)
	}
	wg.Wait()
	close(permits)
	if got := admitted.Load(); got != globalMax {
		t.Fatalf("admitted = %d, want %d", got, globalMax)
	}
	if got := limiter.Stats().PendingHandshakes; got != globalMax {
		t.Fatalf("pending = %d, want %d", got, globalMax)
	}
	for permit := range permits {
		permit.Release()
	}
}

func TestAdmissionLimiterRejectsInvalidConfigurationAndClock(t *testing.T) {
	t.Parallel()
	valid := admissionConfig{
		now:               time.Now,
		attemptsPerWindow: 1,
		attemptWindow:     time.Minute,
		attemptBurst:      1,
		sourcePendingMax:  1,
		globalPendingMax:  1,
		trackedSourcesMax: 1,
		sourceIdleTimeout: time.Minute,
		stateMaxBytes:     admissionSourceAccountBytes,
	}
	tests := []struct {
		name   string
		mutate func(*admissionConfig)
	}{
		{name: "nil clock", mutate: func(config *admissionConfig) { config.now = nil }},
		{name: "zero rate", mutate: func(config *admissionConfig) { config.attemptsPerWindow = 0 }},
		{name: "zero window", mutate: func(config *admissionConfig) { config.attemptWindow = 0 }},
		{name: "zero burst", mutate: func(config *admissionConfig) { config.attemptBurst = 0 }},
		{name: "source pending exceeds global", mutate: func(config *admissionConfig) {
			config.sourcePendingMax = 2
		}},
		{name: "zero global pending", mutate: func(config *admissionConfig) { config.globalPendingMax = 0 }},
		{name: "zero tracked", mutate: func(config *admissionConfig) { config.trackedSourcesMax = 0 }},
		{name: "zero idle", mutate: func(config *admissionConfig) { config.sourceIdleTimeout = 0 }},
		{name: "state too small", mutate: func(config *admissionConfig) { config.stateMaxBytes = admissionSourceAccountBytes - 1 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := newAdmissionLimiter(config); !errors.Is(err, ErrInvalidAdmissionConfig) {
				t.Fatalf("newAdmissionLimiter() error = %v, want %v", err, ErrInvalidAdmissionConfig)
			}
		})
	}

	config := valid
	config.now = func() time.Time { return time.Time{} }
	limiter, err := newAdmissionLimiter(config)
	if err != nil {
		t.Fatalf("newAdmissionLimiter() error = %v", err)
	}
	if _, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.50")); !errors.Is(err, ErrAdmissionClock) {
		t.Fatalf("TryAcquire(zero clock) error = %v, want %v", err, ErrAdmissionClock)
	}
}
