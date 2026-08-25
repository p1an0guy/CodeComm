package contenthttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestEventResultCanonicalRoundTripAndImmutability(t *testing.T) {
	signed := contentTestSignedEvent(t)
	lookup := contentTestCommandResult(t, signed, store.OutcomeAccepted)
	result, err := NewEventResult(lookup, testSessionID, 0)
	if err != nil {
		t.Fatal(err)
	}

	lookup.CanonicalProposal[0] = '['
	lookup.Outcome.JSON[0] = '['
	proposal := result.Proposal()
	outcome := result.Outcome()
	proposal[0] = '['
	outcome.JSON[0] = '['
	if !bytes.Equal(result.Proposal(), signed.CanonicalBytes()) ||
		!bytes.Equal(
			result.Outcome().JSON,
			[]byte(`{"code":"accepted","status":"accepted"}`),
		) {
		t.Fatal("event result aliases caller-owned storage")
	}
	if index, hash, present := result.ChainPosition(); !present ||
		index != 4 ||
		hash != *contentTestCommandResult(
			t,
			signed,
			store.OutcomeAccepted,
		).Tuple.ChainHash {
		t.Fatalf(
			"ChainPosition() = (%d, %x, %t)",
			index,
			hash,
			present,
		)
	}

	encoded, err := result.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeEventResult(
		encoded,
		signed.CanonicalBytes(),
		testSessionID,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ResultIndex() != 7 ||
		decoded.Outcome().Status != store.OutcomeAccepted ||
		!bytes.Equal(decoded.Proposal(), signed.CanonicalBytes()) {
		t.Fatalf("decoded result = %+v", decoded)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 6 {
		t.Fatalf("result fields = %v, error = %v", fields, err)
	}
}

func TestEventResultRejectsMalformedBindings(t *testing.T) {
	signed := contentTestSignedEvent(t)
	valid := contentTestCommandResult(t, signed, store.OutcomeAccepted)
	tests := []struct {
		name   string
		mutate func(*store.CommandResultLookup)
	}{
		{
			name: "event ID",
			mutate: func(value *store.CommandResultLookup) {
				value.EventID = "bad"
			},
		},
		{
			name: "session ID",
			mutate: func(value *store.CommandResultLookup) {
				value.SessionID =
					"01890f47-3e72-7000-8000-000000000799"
			},
		},
		{
			name: "recovery generation",
			mutate: func(value *store.CommandResultLookup) {
				value.RecoveryGeneration = 1
			},
		},
		{
			name: "proposal digest",
			mutate: func(value *store.CommandResultLookup) {
				value.ProposalDigest[0] ^= 0xff
			},
		},
		{
			name: "result index",
			mutate: func(value *store.CommandResultLookup) {
				value.Tuple.ResultIndex = 0
			},
		},
		{
			name: "chain after result",
			mutate: func(value *store.CommandResultLookup) {
				*value.Tuple.ChainIndex = value.Tuple.ResultIndex + 1
			},
		},
		{
			name: "accepted without chain",
			mutate: func(value *store.CommandResultLookup) {
				value.Tuple.ChainIndex = nil
				value.Tuple.ChainHash = nil
			},
		},
		{
			name: "rejected with chain",
			mutate: func(value *store.CommandResultLookup) {
				value.Outcome = store.CommandOutcome{
					Status: store.OutcomeRejected,
					Code:   "entity_not_found",
					JSON: []byte(
						`{"code":"entity_not_found","status":"rejected"}`,
					),
				}
			},
		},
		{
			name: "outcome mismatch",
			mutate: func(value *store.CommandResultLookup) {
				value.Outcome.Code = "changed"
			},
		},
		{
			name: "outcome code alphabet",
			mutate: func(value *store.CommandResultLookup) {
				value.Outcome.Code = "not.allowed"
				value.Outcome.JSON = []byte(
					`{"code":"not.allowed","status":"accepted"}`,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneContentTestLookup(valid)
			test.mutate(&input)
			if _, err := NewEventResult(
				input,
				testSessionID,
				0,
			); !errors.Is(
				err,
				ErrInvalidResponse,
			) {
				t.Fatalf("NewEventResult() error = %v", err)
			}
		})
	}

	rejected := contentTestCommandResult(t, signed, store.OutcomeRejected)
	result, err := NewEventResult(rejected, testSessionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, present := result.ChainPosition(); present {
		t.Fatal("rejected result exposed an event-chain position")
	}
}

func TestServerAcceptsExactEventProposalAndReturnsCommittedResult(
	t *testing.T,
) {
	harness := startContentHarness(t, ActiveHandlersMax)
	signed := contentTestSignedEvent(t)
	result, err := NewEventResult(
		contentTestCommandResult(t, signed, store.OutcomeAccepted),
		testSessionID,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	harness.service.mu.Lock()
	harness.service.eventResult = result
	harness.service.mu.Unlock()

	request, err := http.NewRequest(
		http.MethodPost,
		"https://codecomm.invalid"+EventsPath,
		bytes.NewReader(signed.CanonicalBytes()),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", contentJSONMediaType)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Content-Type", contentJSONMediaType)
	request.Header.Set(
		"Idempotency-Key",
		string(signed.Proposal().EventID),
	)
	response, err := harness.client.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body := assertContentResponse(
		t,
		response,
		http.StatusOK,
		contentJSONMediaType,
	)
	if _, err := decodeEventResult(
		body,
		signed.CanonicalBytes(),
		testSessionID,
		0,
	); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.eventCalls != 1 ||
		harness.service.eventPeer != harness.fixture.clientBinding.DeviceID ||
		harness.service.eventHop != ProposalHopInitial ||
		!bytes.Equal(harness.service.eventBody, signed.CanonicalBytes()) {
		t.Fatalf(
			"event call = count %d peer %s body %s",
			harness.service.eventCalls,
			harness.service.eventPeer,
			harness.service.eventBody,
		)
	}
}

func TestServerRejectsEventTransportBeforeService(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	signed := contentTestSignedEvent(t)
	tests := []struct {
		name      string
		body      []byte
		configure func(*http.Request)
		status    int
		code      string
	}{
		{
			name: "missing idempotency key",
			body: signed.CanonicalBytes(),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", contentJSONMediaType)
			},
			status: http.StatusBadRequest,
			code:   "invalid_event",
		},
		{
			name: "wrong idempotency key",
			body: signed.CanonicalBytes(),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", contentJSONMediaType)
				request.Header.Set(
					"Idempotency-Key",
					"01890f47-3e72-7000-8000-000000000799",
				)
			},
			status: http.StatusBadRequest,
			code:   "invalid_event",
		},
		{
			name: "noncanonical proposal",
			body: append([]byte(" "), signed.CanonicalBytes()...),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", contentJSONMediaType)
				request.Header.Set(
					"Idempotency-Key",
					string(signed.Proposal().EventID),
				)
			},
			status: http.StatusBadRequest,
			code:   "invalid_event",
		},
		{
			name: "wrong media type",
			body: signed.CanonicalBytes(),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", "text/plain")
				request.Header.Set(
					"Idempotency-Key",
					string(signed.Proposal().EventID),
				)
			},
			status: http.StatusBadRequest,
			code:   "invalid_event",
		},
		{
			name: "invalid forwarding hop",
			body: signed.CanonicalBytes(),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", contentJSONMediaType)
				request.Header.Set(
					"Idempotency-Key",
					string(signed.Proposal().EventID),
				)
				request.Header.Set(proposalHopHeader, "2")
			},
			status: http.StatusBadRequest,
			code:   "invalid_event",
		},
		{
			name: "declared oversized event",
			body: bytes.Repeat(
				[]byte{'x'},
				event.MaxEventBytes+1,
			),
			configure: func(request *http.Request) {
				request.Header.Set("Content-Type", contentJSONMediaType)
				request.Header.Set(
					"Idempotency-Key",
					string(signed.Proposal().EventID),
				)
			},
			status: http.StatusRequestEntityTooLarge,
			code:   "event_too_large",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(
				http.MethodPost,
				"https://codecomm.invalid"+EventsPath,
				bytes.NewReader(test.body),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", contentJSONMediaType)
			request.Header.Set("Accept-Encoding", "identity")
			test.configure(request)
			response, err := harness.client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			body := assertContentResponse(
				t,
				response,
				test.status,
				contentProblemMediaType,
			)
			var problem problemResponse
			if err := json.Unmarshal(body, &problem); err != nil ||
				problem.Code != test.code {
				t.Fatalf("problem = %+v, error = %v", problem, err)
			}
		})
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.eventCalls != 0 {
		t.Fatalf("invalid requests reached service %d times", harness.service.eventCalls)
	}
}

func TestMalformedEventConsumesIndependentProposalBudget(t *testing.T) {
	harness := startContentHarness(t, ActiveHandlersMax)
	harness.ensureControlRegistered(t)
	signed := contentTestSignedEvent(t)
	future := time.Now().Add(time.Hour)
	harness.server.control.mu.Lock()
	state := harness.server.control.states[harness.fixture.clientBinding.DeviceID]
	if state == nil {
		harness.server.control.mu.Unlock()
		t.Fatal("peer control state is unavailable")
	}
	state.proposalBucket = controlTokenBucket{
		credit: controlTokenUnit,
		last:   future,
	}
	state.lastSeen = future
	harness.server.control.mu.Unlock()

	malformed, err := http.NewRequest(
		http.MethodPost,
		"https://codecomm.invalid"+EventsPath,
		bytes.NewReader(signed.CanonicalBytes()),
	)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Header.Set("Accept", contentJSONMediaType)
	malformed.Header.Set("Accept-Encoding", "identity")
	malformed.Header.Set("Content-Type", contentJSONMediaType)
	response, err := harness.client.RoundTrip(malformed)
	if err != nil {
		t.Fatal(err)
	}
	assertContentResponse(
		t,
		response,
		http.StatusBadRequest,
		contentProblemMediaType,
	)

	valid, err := http.NewRequest(
		http.MethodPost,
		"https://codecomm.invalid"+EventsPath,
		bytes.NewReader(signed.CanonicalBytes()),
	)
	if err != nil {
		t.Fatal(err)
	}
	valid.Header.Set("Accept", contentJSONMediaType)
	valid.Header.Set("Accept-Encoding", "identity")
	valid.Header.Set("Content-Type", contentJSONMediaType)
	valid.Header.Set(
		"Idempotency-Key",
		string(signed.Proposal().EventID),
	)
	response, err = harness.client.RoundTrip(valid)
	if err != nil {
		t.Fatal(err)
	}
	assertContentResponse(
		t,
		response,
		http.StatusTooManyRequests,
		contentProblemMediaType,
	)
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.eventCalls != 0 {
		t.Fatalf(
			"rate-limited event reached service %d times",
			harness.service.eventCalls,
		)
	}
}

func TestReadEventRequestClosesStalledBodyAtDeadline(t *testing.T) {
	body := &blockingEventRequestBody{
		entered: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	request := &http.Request{
		Body:          body,
		ContentLength: 1,
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	_, err := readEventRequest(ctx, request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf(
			"readEventRequest() error = %v, want %v",
			err,
			context.DeadlineExceeded,
		)
	}
	select {
	case <-body.entered:
	default:
		t.Fatal("stalled body was not read")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("deadline did not close stalled request body")
	}
}

func TestServerMapsEventProposalErrors(t *testing.T) {
	signed := contentTestSignedEvent(t)
	tests := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{
			name: "invalid", err: ErrInvalidEventProposal,
			status: http.StatusBadRequest, code: "invalid_event",
		},
		{
			name: "idempotency conflict", err: ErrEventIdempotencyConflict,
			status: http.StatusConflict, code: "idempotency_conflict",
		},
		{
			name: "leader rate", err: ErrEventProposalRateLimited,
			status: http.StatusTooManyRequests,
			code:   "leader_ingress_rate_limited", retryAfter: "1",
		},
		{
			name: "unavailable", err: ErrEventProposalUnavailable,
			status: http.StatusServiceUnavailable, code: "event_unavailable",
		},
		{
			name: "deadline", err: context.DeadlineExceeded,
			status: http.StatusServiceUnavailable, code: "event_unavailable",
		},
		{
			name: "internal", err: errors.New("unexpected event failure"),
			status: http.StatusInternalServerError, code: "internal_error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := startContentHarness(t, ActiveHandlersMax)
			harness.service.mu.Lock()
			harness.service.eventErr = test.err
			harness.service.mu.Unlock()
			request, err := http.NewRequest(
				http.MethodPost,
				"https://codecomm.invalid"+EventsPath,
				bytes.NewReader(signed.CanonicalBytes()),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", contentJSONMediaType)
			request.Header.Set("Accept-Encoding", "identity")
			request.Header.Set("Content-Type", contentJSONMediaType)
			request.Header.Set(
				"Idempotency-Key",
				string(signed.Proposal().EventID),
			)
			response, err := harness.client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			body := assertContentResponse(
				t,
				response,
				test.status,
				contentProblemMediaType,
			)
			var problem problemResponse
			if err := json.Unmarshal(body, &problem); err != nil ||
				problem.Code != test.code ||
				response.Header.Get("Retry-After") != test.retryAfter {
				t.Fatalf(
					"problem = %+v, headers = %v, error = %v",
					problem,
					response.Header,
					err,
				)
			}
		})
	}
}

func TestClientProposesExactEventAfterLineageBinding(t *testing.T) {
	harness := startRealContentClient(t)
	signed := contentTestSignedEvent(t)
	result, err := NewEventResult(
		contentTestCommandResult(t, signed, store.OutcomeAccepted),
		testSessionID,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	harness.service.mu.Lock()
	harness.service.eventResult = result
	harness.service.mu.Unlock()

	if _, err := harness.client.Propose(
		context.Background(),
		signed,
	); !errors.Is(err, ErrLineageMismatch) {
		t.Fatalf("Propose(before Session) error = %v", err)
	}
	if _, err := harness.client.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	committed, err := harness.client.Propose(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Outcome().Status != store.OutcomeAccepted ||
		!bytes.Equal(committed.Proposal(), signed.CanonicalBytes()) {
		t.Fatalf("Propose() = %+v", committed)
	}
	forwarded, err := harness.client.ForwardProposal(
		context.Background(),
		signed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if forwarded.Outcome().Status != store.OutcomeAccepted ||
		!bytes.Equal(forwarded.Proposal(), signed.CanonicalBytes()) {
		t.Fatalf("ForwardProposal() = %+v", forwarded)
	}
	harness.service.mu.Lock()
	defer harness.service.mu.Unlock()
	if harness.service.eventCalls != 2 ||
		harness.service.eventHop != ProposalHopForwarded {
		t.Fatalf(
			"forwarded service call = (%d, %d)",
			harness.service.eventCalls,
			harness.service.eventHop,
		)
	}
}

func contentTestSignedEvent(t testing.TB) event.SignedEvent {
	t.Helper()
	privateKey := contentPrivateKey(0x91)
	deviceID, err := codec.DeriveDeviceID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := event.NewLocalAuthority(
		domain.DeviceID(deviceID),
		"01890f47-3e72-7000-8000-000000000711",
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindActivityRecorded,
			EntityID:         event.NullEntityID(),
			RationaleSummary: "content transport test",
			Actions:          []event.Action{},
			Payload:          json.RawMessage(`{}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        "01890f47-3e72-7000-8000-000000000712",
			SessionID:      testSessionID,
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      "2026-08-19T12:00:00Z",
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func contentTestCommandResult(
	t testing.TB,
	signed event.SignedEvent,
	status store.OutcomeStatus,
) store.CommandResultLookup {
	t.Helper()
	canonical := signed.CanonicalBytes()
	digest := sha256.Sum256(canonical)
	lookup := store.CommandResultLookup{
		EventID:            signed.Proposal().EventID,
		SessionID:          signed.Proposal().SessionID,
		RecoveryGeneration: 0,
		CanonicalProposal:  canonical,
		ProposalDigest:     digest,
		Tuple: store.CommandResultTuple{
			ResultIndex: 7,
		},
	}
	switch status {
	case store.OutcomeAccepted:
		index := uint64(4)
		hash := store.Digest(
			sha256.Sum256([]byte("content-test-chain")),
		)
		lookup.Outcome = store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		}
		lookup.Tuple.ChainIndex = &index
		lookup.Tuple.ChainHash = &hash
	case store.OutcomeRejected:
		lookup.Outcome = store.CommandOutcome{
			Status: store.OutcomeRejected,
			Code:   "entity_not_found",
			JSON: []byte(
				`{"code":"entity_not_found","status":"rejected"}`,
			),
		}
	default:
		t.Fatalf("unsupported test outcome %q", status)
	}
	return lookup
}

func cloneContentTestLookup(
	input store.CommandResultLookup,
) store.CommandResultLookup {
	result := input
	result.CanonicalProposal = bytes.Clone(input.CanonicalProposal)
	result.Outcome.JSON = bytes.Clone(input.Outcome.JSON)
	if input.Tuple.ChainIndex != nil {
		index := *input.Tuple.ChainIndex
		result.Tuple.ChainIndex = &index
	}
	if input.Tuple.ChainHash != nil {
		hash := *input.Tuple.ChainHash
		result.Tuple.ChainHash = &hash
	}
	return result
}

type blockingEventRequestBody struct {
	enterOnce sync.Once
	closeOnce sync.Once
	entered   chan struct{}
	closed    chan struct{}
}

func (body *blockingEventRequestBody) Read([]byte) (int, error) {
	body.enterOnce.Do(func() { close(body.entered) })
	<-body.closed
	return 0, io.EOF
}

func (body *blockingEventRequestBody) Close() error {
	body.closeOnce.Do(func() { close(body.closed) })
	return nil
}
