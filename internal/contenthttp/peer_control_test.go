package contenthttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestControlTokenBucketEnforcesBurstAndSustainedRate(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	bucket := controlTokenBucket{
		credit: controlTokenCapacity,
		last:   start,
	}
	for request := range ControlRateBurst {
		allowed, retryAfter := bucket.consume(start)
		if !allowed || retryAfter != 0 {
			t.Fatalf("burst request %d = (%t, %s)", request, allowed, retryAfter)
		}
	}
	if allowed, retryAfter := bucket.consume(start); allowed || retryAfter != 5*time.Millisecond {
		t.Fatalf("exhausted bucket = (%t, %s), want retry in 5ms", allowed, retryAfter)
	}
	if allowed, retryAfter := bucket.consume(start.Add(5 * time.Millisecond)); !allowed || retryAfter != 0 {
		t.Fatalf("refilled bucket = (%t, %s)", allowed, retryAfter)
	}
	if allowed, retryAfter := bucket.consume(start.Add(-time.Hour)); allowed || retryAfter != 5*time.Millisecond {
		t.Fatalf("backward clock bucket = (%t, %s)", allowed, retryAfter)
	}
	if allowed, retryAfter := bucket.consume(start.Add(24 * time.Hour)); !allowed || retryAfter != 0 || bucket.credit != controlTokenCapacity-controlTokenUnit {
		t.Fatalf(
			"long refill = (%t, %s, credit=%d)",
			allowed,
			retryAfter,
			bucket.credit,
		)
	}
}

func TestProposalTokenBucketIsIndependentFromControlBudget(t *testing.T) {
	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	handler, _ := newControlTestHandler(
		server,
		controlTestPeer(testPeerDeviceID, 1, 10),
	)
	if err := server.control.register(handler); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.control.unregister(handler) })

	for index := range ProposalRateBurst {
		allowed, retryAfter, err := server.control.consumeProposal(
			testPeerDeviceID,
		)
		if err != nil || !allowed || retryAfter != 0 {
			t.Fatalf(
				"proposal %d = (%t, %s, %v)",
				index,
				allowed,
				retryAfter,
				err,
			)
		}
	}
	if allowed, retryAfter, err := server.control.consumeProposal(
		testPeerDeviceID,
	); err != nil || allowed || retryAfter <= 0 {
		t.Fatalf(
			"proposal over burst = (%t, %s, %v)",
			allowed,
			retryAfter,
			err,
		)
	}
	if allowed, retryAfter, err := server.control.consume(
		testPeerDeviceID,
	); err != nil || !allowed || retryAfter != 0 {
		t.Fatalf(
			"control after proposal saturation = (%t, %s, %v)",
			allowed,
			retryAfter,
			err,
		)
	}
	clock.Advance(time.Second)
	for index := range ProposalRatePerSecond {
		allowed, _, err := server.control.consumeProposal(testPeerDeviceID)
		if err != nil || !allowed {
			t.Fatalf("refilled proposal %d = (%t, %v)", index, allowed, err)
		}
	}
}

func TestControlRegistryRolloverKeepsOneCurrentAndOneDrain(t *testing.T) {
	t.Parallel()

	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	peer := controlTestPeer(testPeerDeviceID, 1, 10)
	first, firstContext := newControlTestHandler(server, peer)
	if err := server.control.register(first); err != nil {
		t.Fatal(err)
	}
	if admission := first.begin(); admission != handlerAccepted {
		t.Fatalf("first admission = %d", admission)
	}

	secondPeer := peer
	secondPeer.Epoch = 2
	secondPeer.AuthorizationChainIndex = 20
	second, secondContext := newControlTestHandler(server, secondPeer)
	if err := server.control.register(second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstContext.Done():
		t.Fatal("active predecessor was closed before draining")
	default:
	}
	if admission := first.begin(); admission != handlerDraining {
		t.Fatalf("predecessor admission = %d", admission)
	}
	assertDrainingProblem(t, first)
	if admission := second.begin(); admission != handlerAccepted {
		t.Fatalf("second admission = %d", admission)
	}

	olderPeer := peer
	older, olderContext := newControlTestHandler(server, olderPeer)
	if err := server.control.register(older); !errors.Is(
		err,
		ErrControlConnectionSuperseded,
	) {
		t.Fatalf("older connection error = %v", err)
	}
	older.close()
	<-olderContext.Done()

	thirdPeer := secondPeer
	thirdPeer.Epoch = 3
	thirdPeer.AuthorizationChainIndex = 30
	third, thirdContext := newControlTestHandler(server, thirdPeer)
	if err := server.control.register(third); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstContext.Done():
	case <-time.After(time.Second):
		t.Fatal("older draining connection was not canceled")
	}
	select {
	case <-secondContext.Done():
		t.Fatal("active immediate predecessor was closed before draining")
	default:
	}
	if admission := second.begin(); admission != handlerDraining {
		t.Fatalf("second predecessor admission = %d", admission)
	}

	server.control.mu.Lock()
	state := server.control.states[testPeerDeviceID]
	if state == nil || state.current != third || state.draining != second {
		server.control.mu.Unlock()
		t.Fatalf("rollover state = %+v", state)
	}
	server.control.mu.Unlock()

	first.end()
	second.end()
	select {
	case <-secondContext.Done():
	case <-time.After(time.Second):
		t.Fatal("drained predecessor did not close")
	}
	third.close()
	<-thirdContext.Done()
	server.control.unregister(first)
	server.control.unregister(second)
	server.control.unregister(third)
}

func TestControlRegistryStateIsBounded(t *testing.T) {
	t.Parallel()

	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	handlers := make([]*connectionHandler, 0, ControlPeerStatesMax+1)
	for index := range ControlPeerStatesMax {
		peer := controlTestPeer(testDeviceID(100+index), 1, 10)
		handler, _ := newControlTestHandler(server, peer)
		if err := server.control.register(handler); err != nil {
			t.Fatalf("register peer %d: %v", index, err)
		}
		handlers = append(handlers, handler)
	}
	extraPeer := controlTestPeer(testDeviceID(100+ControlPeerStatesMax), 1, 10)
	extra, _ := newControlTestHandler(server, extraPeer)
	if err := server.control.register(extra); !errors.Is(
		err,
		ErrControlConnectionCapacity,
	) {
		t.Fatalf("over-capacity registration error = %v", err)
	}

	server.control.mu.Lock()
	stateCount := len(server.control.states)
	server.control.mu.Unlock()
	if stateCount != ControlPeerStatesMax {
		t.Fatalf("tracked peer states = %d", stateCount)
	}

	server.control.unregister(handlers[0])
	handlers[0].close()
	if err := server.control.register(extra); err != nil {
		t.Fatalf("registration after inactive eviction: %v", err)
	}
	server.control.mu.Lock()
	stateCount = len(server.control.states)
	server.control.mu.Unlock()
	if stateCount != ControlPeerStatesMax {
		t.Fatalf("tracked peer states after eviction = %d", stateCount)
	}

	for _, handler := range handlers[1:] {
		server.control.unregister(handler)
		handler.close()
	}
	server.control.unregister(extra)
	extra.close()
}

func TestServerReturnsStablePerDeviceRateProblem(t *testing.T) {
	t.Parallel()

	clock := newControlTestClock()
	harness := startContentHarness(
		t,
		ActiveHandlersMax,
		func(server *Server) { server.control.now = clock.Now },
	)
	for request := range ControlRateBurst {
		allowed, retryAfter, err := harness.server.control.consume(
			harness.fixture.clientBinding.DeviceID,
		)
		if err != nil || !allowed || retryAfter != 0 {
			t.Fatalf(
				"consume request %d = (%t, %s, %v)",
				request,
				allowed,
				retryAfter,
				err,
			)
		}
	}
	before := harness.fixture.policy.verifications.Load()
	response := harness.request(t, http.MethodGet, SessionPath, nil)
	body := assertContentResponse(
		t,
		response,
		http.StatusTooManyRequests,
		"application/problem+json",
	)
	var problem problemResponse
	if err := json.Unmarshal(body, &problem); err != nil ||
		problem.Code != "control_rate_limited" ||
		problem.Status != http.StatusTooManyRequests ||
		!problem.Retryable ||
		response.Header.Get("Retry-After") != "1" {
		t.Fatalf("rate response = %+v error=%v headers=%v", problem, err, response.Header)
	}
	if got := harness.fixture.policy.verifications.Load(); got != before {
		t.Fatalf("rate-limited request reached reauthorization: %d", got-before)
	}

	clock.Advance(5 * time.Millisecond)
	response = harness.request(t, http.MethodGet, SessionPath, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refilled response = %s", response.Status)
	}
	_ = response.Body.Close()
}

func assertDrainingProblem(t testing.TB, handler *connectionHandler) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, SessionPath, nil)
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	var problem problemResponse
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil ||
		response.StatusCode != http.StatusServiceUnavailable ||
		problem.Code != "connection_draining" ||
		!problem.Retryable ||
		response.Header.Get("Retry-After") != "1" {
		t.Fatalf("draining response = %s %+v error=%v", response.Status, problem, err)
	}
}

func newControlTestServer(
	t testing.TB,
	clock *controlTestClock,
) *Server {
	t.Helper()
	server, err := New(newContentTestService(t, testServerDeviceID))
	if err != nil {
		t.Fatal(err)
	}
	server.control.now = clock.Now
	return server
}

func controlTestPeer(
	deviceID domain.DeviceID,
	epoch uint64,
	chainIndex uint64,
) transport.AuthenticatedPeer {
	return transport.AuthenticatedPeer{
		Plane:                   transport.PlaneContent,
		SessionID:               testSessionID,
		DeviceID:                deviceID,
		Epoch:                   epoch,
		AuthorizationChainIndex: chainIndex,
	}
}

func newControlTestHandler(
	server *Server,
	peer transport.AuthenticatedPeer,
) (*connectionHandler, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return newConnectionHandler(server, peer, cancel), ctx
}

type controlTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newControlTestClock() *controlTestClock {
	return &controlTestClock{
		now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
	}
}

func (clock *controlTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *controlTestClock) Advance(elapsed time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(elapsed)
	clock.mu.Unlock()
}
