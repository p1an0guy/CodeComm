package contenthttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
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
	if err := registerControlTestHandler(handler); err != nil {
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
	if err := registerControlTestHandler(first); err != nil {
		t.Fatal(err)
	}
	if admission := first.begin(); admission != handlerAccepted {
		t.Fatalf("first admission = %d", admission)
	}

	secondPeer := peer
	secondPeer.Epoch = 2
	secondPeer.AuthorizationChainIndex = 20
	second, secondContext := newControlTestHandler(server, secondPeer)
	if err := registerControlTestHandler(second); err != nil {
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
	if err := registerControlTestHandler(older); !errors.Is(
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
	third, _ := newControlTestHandler(server, thirdPeer)
	if err := registerControlTestHandler(third); !errors.Is(
		err,
		ErrControlConnectionCapacity,
	) {
		t.Fatalf("third connection before drain error = %v", err)
	}
	select {
	case <-firstContext.Done():
		t.Fatal("active older drain was canceled before its response completed")
	default:
	}
	select {
	case <-secondContext.Done():
		t.Fatal("current connection was closed by refused replacement")
	default:
	}
	endControlTestHandler(first)
	server.control.mu.Lock()
	state := server.control.states[testPeerDeviceID]
	if state == nil || state.current != second || state.draining != nil {
		server.control.mu.Unlock()
		t.Fatalf("completed drain retained registry capacity: %+v", state)
	}
	server.control.mu.Unlock()
	first.close()
	<-firstContext.Done()

	third, thirdContext := newControlTestHandler(server, thirdPeer)
	if err := registerControlTestHandler(third); err != nil {
		t.Fatal(err)
	}
	if admission := second.begin(); admission != handlerDraining {
		t.Fatalf("second predecessor admission = %d", admission)
	}

	server.control.mu.Lock()
	state = server.control.states[testPeerDeviceID]
	if state == nil || state.current != third || state.draining != second {
		server.control.mu.Unlock()
		t.Fatalf("rollover state = %+v", state)
	}
	server.control.mu.Unlock()

	endControlTestHandler(second)
	select {
	case <-secondContext.Done():
		t.Fatal("active predecessor was hard-closed after draining")
	default:
	}
	second.close()
	<-secondContext.Done()
	third.close()
	<-thirdContext.Done()
	server.control.unregister(second)
	server.control.unregister(third)
}

func TestControlRegistryClosesIdleSameCredentialPredecessor(
	t *testing.T,
) {
	t.Parallel()

	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	peer := controlTestPeer(testPeerDeviceID, 1, 10)
	incumbent, incumbentContext := newControlTestHandler(server, peer)
	if err := registerControlTestHandler(incumbent); err != nil {
		t.Fatal(err)
	}
	if admission := incumbent.begin(); admission != handlerAccepted {
		t.Fatalf("incumbent admission = %d", admission)
	}
	endControlTestHandler(incumbent)

	successor, successorContext := newControlTestHandler(server, peer)
	if err := registerControlTestHandler(successor); err != nil {
		t.Fatalf("register equal-credential successor: %v", err)
	}

	server.control.mu.Lock()
	state := server.control.states[testPeerDeviceID]
	if state == nil ||
		state.current != successor ||
		state.draining != incumbent {
		server.control.mu.Unlock()
		t.Fatalf("equal-credential replacement state = %+v", state)
	}
	server.control.mu.Unlock()
	select {
	case <-incumbentContext.Done():
	case <-time.After(time.Second):
		t.Fatal("idle equal-credential predecessor was not closed")
	}
	server.control.unregister(incumbent)
	if admission := successor.begin(); admission != handlerAccepted {
		t.Fatalf("successor admission = %d", admission)
	}
	endControlTestHandler(successor)

	server.control.unregister(successor)
	incumbent.close()
	successor.close()
	<-successorContext.Done()
}

func TestControlRegistryRollsCredentialsPerContentSlot(t *testing.T) {
	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	epochOne := controlTestPeer(testPeerDeviceID, 1, 10)

	control, controlContext := newControlTestHandler(server, epochOne)
	if err := registerControlTestHandler(control); err != nil {
		t.Fatal(err)
	}
	if admission := control.begin(); admission != handlerAccepted {
		t.Fatalf("control admission = %d", admission)
	}

	bulk := make([]*connectionHandler, BulkConnectionsMax)
	bulkContexts := make([]context.Context, BulkConnectionsMax)
	for index := range bulk {
		bulk[index], bulkContexts[index] = newControlTestHandler(
			server,
			epochOne,
		)
		if err := registerBulkTestHandler(bulk[index]); err != nil {
			t.Fatalf("register bulk %d: %v", index, err)
		}
		if admission := bulk[index].begin(); admission != handlerAccepted {
			t.Fatalf("bulk %d admission = %d", index, admission)
		}
		if admission := bulk[index].begin(); admission != handlerBusy {
			t.Fatalf("bulk %d second stream admission = %d", index, admission)
		}
	}

	epochTwo := epochOne
	epochTwo.Epoch = 2
	epochTwo.AuthorizationChainIndex = 20
	replacements := make([]*connectionHandler, BulkConnectionsMax)
	for index := range replacements {
		replacements[index], _ = newControlTestHandler(server, epochTwo)
		if err := registerBulkTestHandler(replacements[index]); err != nil {
			t.Fatalf("register replacement bulk %d: %v", index, err)
		}
	}
	excessPeer := epochTwo
	excessPeer.Epoch = 3
	excessPeer.AuthorizationChainIndex = 30
	excess, excessContext := newControlTestHandler(server, excessPeer)
	if err := registerBulkTestHandler(excess); !errors.Is(
		err,
		ErrBulkConnectionCapacity,
	) {
		t.Fatalf("bulk replacement with occupied drains error = %v", err)
	}
	if _, registered := excess.registeredConnectionRole(); registered {
		t.Fatal("excess bulk replacement was registered")
	}
	excess.close()
	<-excessContext.Done()

	select {
	case <-controlContext.Done():
		t.Fatal("bulk rollover closed the control connection")
	default:
	}
	for index, bulkContext := range bulkContexts {
		select {
		case <-bulkContext.Done():
			t.Fatalf("active bulk predecessor %d closed before drain", index)
		default:
		}
		if admission := bulk[index].begin(); admission != handlerDraining {
			t.Fatalf("bulk predecessor %d admission = %d", index, admission)
		}
	}

	downgrade, downgradeContext := newControlTestHandler(server, epochOne)
	if err := registerControlTestHandler(downgrade); !errors.Is(
		err,
		ErrControlConnectionSuperseded,
	) {
		t.Fatalf("downgraded control registration error = %v", err)
	}
	if _, registered := downgrade.registeredConnectionRole(); registered {
		t.Fatal("downgraded control connection was registered")
	}
	downgrade.close()
	<-downgradeContext.Done()

	server.control.mu.Lock()
	state := server.control.states[testPeerDeviceID]
	if state == nil ||
		state.current != control ||
		state.bulkCurrent[0] != replacements[0] ||
		state.bulkCurrent[1] != replacements[1] ||
		state.bulkDraining[0] != bulk[0] ||
		state.bulkDraining[1] != bulk[1] {
		server.control.mu.Unlock()
		t.Fatalf("per-slot rollover state = %+v", state)
	}
	server.control.mu.Unlock()

	replacementControl, _ := newControlTestHandler(server, epochTwo)
	if err := registerControlTestHandler(replacementControl); err != nil {
		t.Fatal(err)
	}
	server.control.mu.Lock()
	state = server.control.states[testPeerDeviceID]
	if state == nil ||
		state.current != replacementControl ||
		state.draining != control ||
		state.bulkCurrent[0] != replacements[0] ||
		state.bulkCurrent[1] != replacements[1] {
		server.control.mu.Unlock()
		t.Fatalf("control rollover changed bulk slots: %+v", state)
	}
	server.control.mu.Unlock()

	endControlTestHandler(control)
	for index := range bulk {
		endControlTestHandler(bulk[index])
	}
	control.close()
	for _, handler := range bulk {
		handler.close()
	}
	for _, handler := range replacements {
		server.control.unregister(handler)
		handler.close()
	}
	server.control.unregister(replacementControl)
	replacementControl.close()
	server.control.unregister(control)
	for _, handler := range bulk {
		server.control.unregister(handler)
	}
}

func TestBulkRegistryReplacesEqualCredentialReconnect(t *testing.T) {
	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	peer := controlTestPeer(testPeerDeviceID, 1, 10)

	incumbents := make([]*connectionHandler, BulkConnectionsMax)
	contexts := make([]context.Context, BulkConnectionsMax)
	for index := range incumbents {
		incumbents[index], contexts[index] = newControlTestHandler(
			server,
			peer,
		)
		if err := registerBulkTestHandler(incumbents[index]); err != nil {
			t.Fatalf("register incumbent %d: %v", index, err)
		}
		if admission := incumbents[index].begin(); admission != handlerAccepted {
			t.Fatalf("incumbent %d admission = %d", index, admission)
		}
	}

	replacement, replacementContext := newControlTestHandler(server, peer)
	if err := registerBulkTestHandler(replacement); err != nil {
		t.Fatalf("register equal-credential replacement: %v", err)
	}

	server.control.mu.Lock()
	state := server.control.states[testPeerDeviceID]
	currentCount := 0
	drainingCount := 0
	var draining *connectionHandler
	if state != nil {
		for index := range state.bulkCurrent {
			if state.bulkCurrent[index] == replacement {
				currentCount++
			}
			if state.bulkDraining[index] != nil {
				draining = state.bulkDraining[index]
				drainingCount++
			}
		}
	}
	server.control.mu.Unlock()
	if currentCount != 1 || drainingCount != 1 || draining == nil {
		t.Fatalf(
			"equal-credential bulk replacement current=%d draining=%d state=%+v",
			currentCount,
			drainingCount,
			state,
		)
	}
	if admission := draining.begin(); admission != handlerDraining {
		t.Fatalf("replaced bulk admission = %d", admission)
	}
	for index, connectionContext := range contexts {
		select {
		case <-connectionContext.Done():
			t.Fatalf("bulk incumbent %d closed before its response drained", index)
		default:
		}
	}
	if admission := replacement.begin(); admission != handlerAccepted {
		t.Fatalf("replacement admission = %d", admission)
	}
	endControlTestHandler(replacement)

	for _, handler := range incumbents {
		endControlTestHandler(handler)
		server.control.unregister(handler)
		handler.close()
	}
	server.control.unregister(replacement)
	replacement.close()
	<-replacementContext.Done()
}

func TestRetiredContentConnectionsCompleteThenCloseOverHTTP2(t *testing.T) {
	t.Run("equal credential idle reconnect replaces", func(t *testing.T) {
		harness := startContentHarness(t, ActiveHandlersMax)
		harness.ensureControlRegistered(t)

		replacement, replacementTLS := dialAdditionalContentHTTP2(t, harness)
		awaitContentCondition(t, "replacement content connection", func() bool {
			return harness.ingress.Stats().EstablishedConnections == 2
		})
		request, err := http.NewRequest(
			http.MethodGet,
			"https://codecomm.invalid"+SessionPath,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := replacement.RoundTrip(request)
		if err != nil {
			t.Fatalf("replacement RoundTrip() error = %v", err)
		}
		_ = assertContentResponse(
			t,
			response,
			http.StatusOK,
			contentJSONMediaType,
		)

		awaitContentCondition(t, "replaced connection closure", func() bool {
			return harness.ingress.Stats().EstablishedConnections == 1
		})

		retry, err := http.NewRequest(
			http.MethodGet,
			"https://codecomm.invalid"+SessionPath,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		retryResponse, retryErr := replacement.RoundTrip(retry)
		if retryErr != nil {
			t.Fatalf("replacement retry error = %v", retryErr)
		}
		_ = assertContentResponse(
			t,
			retryResponse,
			http.StatusOK,
			contentJSONMediaType,
		)
		_ = replacement.Close()
		_ = replacementTLS.Close()
	})

	t.Run("superseded credential", func(t *testing.T) {
		harness := startContentHarness(t, ActiveHandlersMax)
		newerPeer := controlTestPeer(
			harness.fixture.clientBinding.DeviceID,
			harness.fixture.clientBinding.Epoch+1,
			harness.fixture.clientBinding.AuthorizationChainIndex+1,
		)
		newer, _ := newControlTestHandler(harness.server, newerPeer)
		if err := registerControlTestHandler(newer); err != nil {
			t.Fatal(err)
		}
		defer func() {
			harness.server.control.unregister(newer)
			newer.close()
		}()

		response := harness.request(t, http.MethodGet, SessionPath, nil)
		body := assertContentResponse(
			t,
			response,
			http.StatusServiceUnavailable,
			contentProblemMediaType,
		)
		var problem problemResponse
		if err := json.Unmarshal(body, &problem); err != nil ||
			problem.Code != problemConnectionDraining.code ||
			response.Header.Get("Retry-After") != "1" {
			t.Fatalf(
				"superseded response = %+v error=%v headers=%v",
				problem,
				err,
				response.Header,
			)
		}
		awaitContentCondition(t, "superseded connection closure", func() bool {
			return harness.ingress.Stats().EstablishedConnections == 0
		})
	})

	t.Run("active predecessor drains without truncation", func(t *testing.T) {
		harness := startContentHarness(t, ActiveHandlersMax)
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		harness.service.mu.Lock()
		harness.service.entered = entered
		harness.service.release = release
		harness.service.mu.Unlock()

		type roundTripResult struct {
			response *http.Response
			err      error
		}
		activeDone := make(chan roundTripResult, 1)
		go func() {
			request, err := http.NewRequest(
				http.MethodGet,
				"https://codecomm.invalid"+SessionPath,
				nil,
			)
			if err != nil {
				activeDone <- roundTripResult{err: err}
				return
			}
			response, err := harness.client.RoundTrip(request)
			activeDone <- roundTripResult{response: response, err: err}
		}()
		select {
		case <-entered:
		case <-time.After(contentTestTimeout):
			t.Fatal("active request did not reach the service")
		}

		newerPeer := controlTestPeer(
			harness.fixture.clientBinding.DeviceID,
			harness.fixture.clientBinding.Epoch+1,
			harness.fixture.clientBinding.AuthorizationChainIndex+1,
		)
		newer, _ := newControlTestHandler(harness.server, newerPeer)
		if err := registerControlTestHandler(newer); err != nil {
			t.Fatal(err)
		}
		defer func() {
			harness.server.control.unregister(newer)
			newer.close()
		}()

		if established := harness.ingress.Stats().EstablishedConnections; established != 1 {
			t.Fatalf(
				"connection closed before active response completed: %d",
				established,
			)
		}

		close(release)
		select {
		case result := <-activeDone:
			if result.err != nil {
				t.Fatalf("active RoundTrip() error = %v", result.err)
			}
			_ = assertContentResponse(
				t,
				result.response,
				http.StatusOK,
				contentJSONMediaType,
			)
		case <-time.After(contentTestTimeout):
			t.Fatal("active request did not complete")
		}
		awaitContentCondition(t, "drained predecessor closure", func() bool {
			return harness.ingress.Stats().EstablishedConnections == 0
		})
	})
}

func TestContentHTTP2GracefulDrainAfterHeadersWritten(t *testing.T) {
	base := &http.Server{}
	server, drain, err := newContentHTTP2Connection(
		&http2.Server{},
		base,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() {
		_ = serverConnection.Close()
		_ = clientConnection.Close()
	})

	headersWritten := make(chan struct{})
	release := make(chan struct{})
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		server.ServeConn(serverConnection, &http2.ServeConnOpts{
			BaseConfig: base,
			Handler: http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set("Content-Length", "8")
				writer.WriteHeader(http.StatusOK)
				writer.(http.Flusher).Flush()
				close(headersWritten)
				<-release
				_, _ = writer.Write([]byte("complete"))
			}),
		})
	}()
	client, err := (&http2.Transport{}).NewClientConn(clientConnection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	request, err := http.NewRequest(
		http.MethodGet,
		"https://codecomm.invalid/",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	type roundTripResult struct {
		response *http.Response
		err      error
	}
	responseReady := make(chan roundTripResult, 1)
	go func() {
		response, roundTripErr := client.RoundTrip(request)
		responseReady <- roundTripResult{
			response: response,
			err:      roundTripErr,
		}
	}()

	select {
	case <-headersWritten:
	case <-time.After(contentTestTimeout):
		t.Fatal("handler did not flush response headers")
	}
	var result roundTripResult
	select {
	case result = <-responseReady:
		if result.err != nil {
			t.Fatalf("RoundTrip() error = %v", result.err)
		}
	case <-time.After(contentTestTimeout):
		t.Fatal("client did not receive response headers")
	}
	if !client.CanTakeNewRequest() {
		t.Fatal("connection stopped accepting requests before drain")
	}

	drain()
	awaitContentCondition(t, "HTTP/2 GOAWAY", func() bool {
		return !client.CanTakeNewRequest()
	})
	close(release)
	body, err := io.ReadAll(result.response.Body)
	if err != nil {
		t.Fatalf("read response after GOAWAY: %v", err)
	}
	if err := result.response.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	if string(body) != "complete" {
		t.Fatalf("response body after GOAWAY = %q", body)
	}
	select {
	case <-serveDone:
	case <-time.After(contentTestTimeout):
		t.Fatal("gracefully drained HTTP/2 connection did not close")
	}
}

func TestClosedAndDrainingAdmissionsReturnStructuredProblem(t *testing.T) {
	for _, test := range []struct {
		name    string
		closing bool
	}{
		{name: "draining"},
		{name: "closed", closing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, _ := newControlTestHandler(
				newControlTestServer(t, newControlTestClock()),
				controlTestPeer(testPeerDeviceID, 1, 10),
			)
			handler.mu.Lock()
			handler.accepting = false
			handler.closing = test.closing
			handler.mu.Unlock()

			recorder := httptest.NewRecorder()
			if handler.admitRequest(recorder) {
				t.Fatal("nonaccepting handler admitted request")
			}
			response := recorder.Result()
			body := readContentResponse(t, response)
			var problem problemResponse
			if err := json.Unmarshal(body, &problem); err != nil ||
				response.StatusCode != http.StatusServiceUnavailable ||
				problem.Code != problemConnectionDraining.code ||
				!problem.Retryable ||
				response.Header.Get("Retry-After") != "1" {
				t.Fatalf(
					"admission response = %s %+v error=%v headers=%v",
					response.Status,
					problem,
					err,
					response.Header,
				)
			}
		})
	}
}

func TestContentConnectionRefusesMixedRouteClasses(t *testing.T) {
	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	handler, handlerContext := newControlTestHandler(
		server,
		controlTestPeer(testPeerDeviceID, 1, 10),
	)
	if err := registerControlTestHandler(handler); err != nil {
		t.Fatal(err)
	}

	if err := handler.bindConnectionRole(contentConnectionBulk); !errors.Is(
		err,
		errConnectionRouteMismatch,
	) {
		t.Fatalf("mixed route bind error = %v", err)
	}
	select {
	case <-handlerContext.Done():
		t.Fatal("mixed-route refusal closed a valid control connection")
	default:
	}

	server.control.unregister(handler)
	handler.close()
}

func TestControlRegistryStateIsBounded(t *testing.T) {
	t.Parallel()

	clock := newControlTestClock()
	server := newControlTestServer(t, clock)
	handlers := make([]*connectionHandler, 0, ControlPeerStatesMax+1)
	for index := range ControlPeerStatesMax {
		peer := controlTestPeer(testDeviceID(100+index), 1, 10)
		handler, _ := newControlTestHandler(server, peer)
		if err := registerControlTestHandler(handler); err != nil {
			t.Fatalf("register peer %d: %v", index, err)
		}
		handlers = append(handlers, handler)
	}
	extraPeer := controlTestPeer(testDeviceID(100+ControlPeerStatesMax), 1, 10)
	extra, _ := newControlTestHandler(server, extraPeer)
	if err := registerControlTestHandler(extra); !errors.Is(
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
	if err := registerControlTestHandler(extra); err != nil {
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
	harness.ensureControlRegistered(t)
	harness.server.control.mu.Lock()
	state := harness.server.control.states[harness.fixture.clientBinding.DeviceID]
	if state == nil {
		harness.server.control.mu.Unlock()
		t.Fatal("peer control state is unavailable")
	}
	now := clock.Now()
	state.bucket = controlTokenBucket{
		credit: controlTokenCapacity,
		last:   now,
	}
	state.lastSeen = now
	harness.server.control.mu.Unlock()
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

func TestFreshBulkConnectionBoundsConcurrentReauthorization(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	parts := newContentSnapshotParts(
		t,
		harness.fixture.serverIdentity,
		testSessionID,
		testWorkspaceID,
		0,
		"snapshot.registration-bound",
		[]byte("bounded bulk content"),
	)
	setContentSnapshotParts(harness.service, parts)
	bulk := openSnapshotBulkClient(
		t,
		harness.address,
		harness.fixture,
		parts.root,
	)
	warmup, err := http.NewRequest(
		http.MethodGet,
		"https://codecomm.invalid/v1/not-a-content-route",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	warmup.Header.Set("Accept", contentJSONMediaType)
	warmup.Header.Set("Accept-Encoding", "identity")
	warmupResponse, err := bulk.client.http2.RoundTrip(warmup)
	if err != nil {
		t.Fatalf("warm unregistered HTTP/2 connection: %v", err)
	}
	_ = assertContentResponse(
		t,
		warmupResponse,
		http.StatusNotFound,
		contentProblemMediaType,
	)
	target, valid := snapshotIndexedPath(
		parts.root.Unsigned().Input().ArtifactID,
		"chunks",
		0,
	)
	if !valid {
		t.Fatal("snapshot chunk target is invalid")
	}
	newRequest := func() *http.Request {
		request, err := http.NewRequest(
			http.MethodGet,
			"https://codecomm.invalid"+target,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", snapshotChunkMediaType)
		request.Header.Set("Accept-Encoding", "identity")
		if !setSnapshotScopeHeaders(request.Header, bulk.scope) {
			t.Fatal("snapshot scope headers are invalid")
		}
		return request
	}

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseBarrier)
	harness.fixture.policy.setVerificationBarrier(entered, release)
	before := harness.fixture.policy.verifications.Load()
	firstRequest := newRequest()
	secondRequest := newRequest()

	type roundTripResult struct {
		response *http.Response
		err      error
	}
	firstDone := make(chan roundTripResult, 1)
	go func() {
		response, err := bulk.client.http2.RoundTrip(firstRequest)
		firstDone <- roundTripResult{response: response, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(contentTestTimeout):
		t.Fatal("first bulk stream did not enter reauthorization")
	}

	secondDone := make(chan roundTripResult, 1)
	go func() {
		response, err := bulk.client.http2.RoundTrip(secondRequest)
		secondDone <- roundTripResult{response: response, err: err}
	}()
	var second roundTripResult
	select {
	case second = <-secondDone:
	case <-entered:
		t.Fatal("concurrent unregistered stream entered reauthorization")
	case <-time.After(contentTestTimeout):
		t.Fatal("concurrent unregistered stream did not receive bounded failure")
	}
	if second.err != nil {
		t.Fatalf("concurrent RoundTrip() error = %v", second.err)
	}
	body := assertContentResponse(
		t,
		second.response,
		http.StatusServiceUnavailable,
		contentProblemMediaType,
	)
	var problem problemResponse
	if err := json.Unmarshal(body, &problem); err != nil ||
		problem.Code != problemConnectionRegistrationCapacity.code ||
		!problem.Retryable ||
		second.response.Header.Get("Retry-After") != "1" {
		t.Fatalf(
			"registration-capacity response = %+v error=%v headers=%v",
			problem,
			err,
			second.response.Header,
		)
	}
	if got := harness.fixture.policy.verifications.Load(); got != before+1 {
		t.Fatalf("reauthorization calls = %d, want 1", got-before)
	}

	releaseBarrier()
	var first roundTripResult
	select {
	case first = <-firstDone:
	case <-time.After(contentTestTimeout):
		t.Fatal("first bulk stream did not complete after reauthorization")
	}
	if first.err != nil {
		t.Fatalf("first RoundTrip() error = %v", first.err)
	}
	firstBody := assertContentResponse(
		t,
		first.response,
		http.StatusOK,
		snapshotChunkMediaType,
	)
	if string(firstBody) != "bounded bulk content" {
		t.Fatalf("first response body = %q", firstBody)
	}
}

func TestServerChargesControlRateBeforeEarlyRouteRejection(t *testing.T) {
	t.Run("malformed first request", func(t *testing.T) {
		clock := newControlTestClock()
		harness := startContentHarness(
			t,
			ActiveHandlersMax,
			func(server *Server) { server.control.now = clock.Now },
		)

		response := harness.request(
			t,
			http.MethodGet,
			"/v1/not-a-content-route",
			nil,
		)
		body := assertContentResponse(
			t,
			response,
			http.StatusNotFound,
			contentProblemMediaType,
		)
		var problem problemResponse
		if err := json.Unmarshal(body, &problem); err != nil ||
			problem.Code != problemRouteNotFound.code {
			t.Fatalf("malformed-route response = %+v error=%v", problem, err)
		}

		harness.server.control.mu.Lock()
		state := harness.server.control.states[harness.fixture.clientBinding.DeviceID]
		var credit int64
		if state != nil {
			credit = state.bucket.credit
		}
		harness.server.control.mu.Unlock()
		if state == nil || credit != controlTokenCapacity-controlTokenUnit {
			t.Fatalf("malformed-route control credit = %d state=%+v", credit, state)
		}
		if state.current != nil ||
			state.draining != nil ||
			state.activeConnections() {
			t.Fatalf("malformed first request acquired a connection role: %+v", state)
		}
	})

	t.Run("control route on bulk connection", func(t *testing.T) {
		clock := newControlTestClock()
		harness := startContentHarness(
			t,
			ActiveHandlersMax,
			func(server *Server) { server.control.now = clock.Now },
		)
		parts := newContentSnapshotParts(
			t,
			harness.fixture.serverIdentity,
			testSessionID,
			testWorkspaceID,
			0,
			"snapshot.rate-mismatch",
			[]byte("chunk"),
		)
		setContentSnapshotParts(harness.service, parts)
		bulk := openSnapshotBulkClient(
			t,
			harness.address,
			harness.fixture,
			parts.root,
		)
		if _, err := bulk.SnapshotChunk(context.Background(), 0); err != nil {
			t.Fatalf("register bulk connection: %v", err)
		}

		harness.server.control.mu.Lock()
		state := harness.server.control.states[harness.fixture.clientBinding.DeviceID]
		if state == nil {
			harness.server.control.mu.Unlock()
			t.Fatal("bulk peer control state is unavailable")
		}
		now := clock.Now()
		state.bucket = controlTokenBucket{
			credit: controlTokenCapacity,
			last:   now,
		}
		state.lastSeen = now
		harness.server.control.mu.Unlock()

		request, err := http.NewRequest(
			http.MethodGet,
			"https://codecomm.invalid"+SessionPath,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := bulk.client.http2.RoundTrip(request)
		if err != nil {
			t.Fatalf("mixed-route RoundTrip(): %v", err)
		}
		body := assertContentResponse(
			t,
			response,
			http.StatusNotFound,
			contentProblemMediaType,
		)
		var problem problemResponse
		if err := json.Unmarshal(body, &problem); err != nil ||
			problem.Code != problemRouteNotFound.code {
			t.Fatalf("mixed-route response = %+v error=%v", problem, err)
		}

		harness.server.control.mu.Lock()
		credit := state.bucket.credit
		harness.server.control.mu.Unlock()
		if credit != controlTokenCapacity-controlTokenUnit {
			t.Fatalf("mixed-route control credit = %d", credit)
		}
	})
}

func assertDrainingProblem(t testing.TB, handler *connectionHandler) {
	t.Helper()
	if admission := handler.begin(); admission != handlerDraining {
		t.Fatalf("draining handler admission = %d", admission)
	}
}

func endControlTestHandler(handler *connectionHandler) {
	handler.endResponse(nil)
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
	return newConnectionHandler(server, peer, cancel, nil), ctx
}

func registerControlTestHandler(handler *connectionHandler) error {
	if handler == nil {
		return errControlStateUnavailable
	}
	return handler.ensureConnectionRole(contentConnectionControl)
}

func registerBulkTestHandler(handler *connectionHandler) error {
	if handler == nil {
		return errControlStateUnavailable
	}
	return handler.ensureConnectionRole(contentConnectionBulk)
}

func dialAdditionalContentHTTP2(
	t testing.TB,
	harness *contentHarness,
) (*http2.ClientConn, *tls.Conn) {
	t.Helper()
	dialContext, cancel := context.WithTimeout(
		context.Background(),
		contentTestTimeout,
	)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(
		dialContext,
		"tcp",
		harness.address,
	)
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(raw, harness.fixture.clientConfig.Clone())
	if err := connection.HandshakeContext(dialContext); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	client, err := (&http2.Transport{
		DisableCompression: true,
		MaxHeaderListSize:  HeaderMaxBytes,
		ReadIdleTimeout:    StreamNoProgress,
		PingTimeout:        RequestHeaderTimeout,
		WriteByteTimeout:   StreamNoProgress,
	}).NewClientConn(connection)
	if err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = connection.Close()
	})
	return client, connection
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
