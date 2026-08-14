package pairinghttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/transport"
	"golang.org/x/net/http2"
)

const pairingHTTPTestSessionID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000502",
)

var pairingHTTPTestAttemptID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000601",
)

func TestServerBindsPairingRoutesToTLSExporter(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	connection := openTestConnection(t, server)
	defer connection.close(t)

	requestBody := []byte(`{"schema_version":1}`)
	response := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		requestBody,
		"application/json",
	)
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("request response = %s, headers = %v", response.Status, response.Header)
	}
	acknowledgmentBytes := readResponse(t, response)
	if _, err := pairing.ParseRequestAcknowledgment(
		acknowledgmentBytes,
	); err != nil {
		t.Fatalf("request acknowledgment: %v", err)
	}

	confirmationBody := []byte(`{"confirmed":true}`)
	response = roundTrip(
		t,
		connection.client,
		http.MethodPost,
		ConfirmPath,
		confirmationBody,
		"application/json; charset=utf-8",
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("confirmation response = %s", response.Status)
	}
	if _, err := pairing.ParseConfirmationResult(
		readResponse(t, response),
	); err != nil {
		t.Fatalf("confirmation result: %v", err)
	}

	calls := service.snapshot()
	if len(calls) != 2 ||
		calls[0].operation != "request" ||
		calls[1].operation != "confirm" ||
		!bytes.Equal(calls[0].body, requestBody) ||
		!bytes.Equal(calls[1].body, confirmationBody) {
		t.Fatalf("service calls = %+v", calls)
	}
	for index, call := range calls {
		if !bytes.Equal(call.exporter, connection.exporter) ||
			call.peer.Binding != connection.clientBinding {
			t.Fatalf("service call %d TLS binding = %+v", index+1, call)
		}
	}
}

func TestClientUsesOneExporterBoundConnection(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	client, err := OpenClient(context.Background(), harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	invite, core := clientPairingFixture(t, harness)
	expectedRequest, err := pairing.BuildRequest(
		invite,
		core,
		client.exporter[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedRequest, err := expectedRequest.Verify(invite, client.exporter[:])
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := expectedRequest.Digest()
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		core.Value().AttemptID,
		requestDigest,
		invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	confirmationResult, err := pairing.NewConfirmationResult(
		core.Value().AttemptID,
		requestDigest,
		pairing.StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.acknowledgment = acknowledgment
	service.confirmation = confirmationResult

	got, err := client.Request(context.Background(), invite, core)
	if err != nil || !bytes.Equal(
		got.Acknowledgment.CanonicalBytes(),
		acknowledgment.CanonicalBytes(),
	) || got.SAS != verifiedRequest.SAS() {
		t.Fatalf("Request() = (%+v, %v)", got, err)
	}
	retried, err := client.Request(context.Background(), invite, core)
	if err != nil || !bytes.Equal(
		retried.Acknowledgment.CanonicalBytes(),
		acknowledgment.CanonicalBytes(),
	) || retried.SAS != verifiedRequest.SAS() {
		t.Fatalf("Request(retry) = (%+v, %v)", retried, err)
	}
	confirmation, err := pairing.NewConfirmation(
		core.Value().AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Confirm(context.Background(), confirmation)
	if err != nil || !bytes.Equal(
		result.CanonicalBytes(),
		confirmationResult.CanonicalBytes(),
	) {
		t.Fatalf("Confirm() = (%+v, %v)", result, err)
	}

	calls := service.snapshot()
	if len(calls) != 3 {
		t.Fatalf("service calls = %+v", calls)
	}
	for index := 0; index < 2; index++ {
		request, err := pairing.ParseRequest(calls[index].body)
		if err != nil {
			t.Fatalf("request call %d: %v", index+1, err)
		}
		verified, err := request.Verify(invite, calls[index].exporter)
		if err != nil ||
			verified.TranscriptHash() == [sha256.Size]byte{} ||
			verified.SAS() != got.SAS {
			t.Fatalf(
				"request call %d verification = (%+v, %v)",
				index+1,
				verified,
				err,
			)
		}
	}
	if !bytes.Equal(calls[0].body, calls[1].body) ||
		!bytes.Equal(calls[0].exporter, calls[1].exporter) ||
		calls[2].operation != "confirm" ||
		!bytes.Equal(calls[2].exporter, calls[0].exporter) {
		t.Fatalf("client changed connection-bound request: %+v", calls)
	}

	service.requestError = func([]byte) error {
		return pairingservice.ErrRequestRejected
	}
	_, err = client.Request(context.Background(), invite, core)
	var remote *RemoteError
	if !errors.As(err, &remote) ||
		remote.Status != http.StatusForbidden ||
		remote.Code != "pairing_rejected" ||
		remote.CorrelationID == "" {
		t.Fatalf("remote pairing rejection = %#v, error = %v", remote, err)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(
		context.Background(),
		invite,
		core,
	); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Request(after close) error = %v", err)
	}
}

func TestClientRejectsMismatchedAcknowledgment(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	client, err := OpenClient(context.Background(), harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	invite, core := clientPairingFixture(t, harness)

	wrongDigest := sha256.Sum256([]byte("wrong request"))
	service.acknowledgment, err = pairing.NewRequestAcknowledgmentValues(
		core.Value().AttemptID,
		wrongDigest,
		invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(
		context.Background(),
		invite,
		core,
	); !errors.Is(err, ErrResponseProtocol) {
		t.Fatalf("Request(mismatched acknowledgment) error = %v", err)
	}
}

func TestClientBindsOneAttemptAndIrreversibleDecision(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	client, err := OpenClient(context.Background(), harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	invite, core := clientPairingFixture(t, harness)
	wrongKey := testIdentityKey(0x54)
	_, wrongBinding, err := transport.IssueIdentityCertificate(
		pairingHTTPTestSessionID,
		0,
		wrongKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongInviteValue := invite.Invite()
	wrongInviteValue.InviterDeviceID = wrongBinding.DeviceID
	copy(
		wrongInviteValue.InviterIdentityPublicKey[:],
		wrongKey.Public().(ed25519.PublicKey),
	)
	wrongInvite, err := pairing.SignInvite(wrongInviteValue, wrongKey)
	clear(wrongInviteValue.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(
		context.Background(),
		wrongInvite,
		core,
	); !errors.Is(err, ErrPeerMismatch) {
		t.Fatalf(
			"Request(mismatched inviter) error = %v, want %v",
			err,
			ErrPeerMismatch,
		)
	}

	request, err := pairing.BuildRequest(invite, core, client.exporter[:])
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := request.Digest()
	confirmation, err := pairing.NewConfirmation(
		core.Value().AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Confirm(
		context.Background(),
		confirmation,
	); !errors.Is(err, ErrConfirmationUnavailable) {
		t.Fatalf(
			"Confirm(before acknowledgment) error = %v, want %v",
			err,
			ErrConfirmationUnavailable,
		)
	}

	service.acknowledgment, err = pairing.NewRequestAcknowledgmentValues(
		core.Value().AttemptID,
		requestDigest,
		invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	service.confirmation, err = pairing.NewConfirmationResult(
		core.Value().AttemptID,
		requestDigest,
		pairing.StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), invite, core); err != nil {
		t.Fatal(err)
	}

	otherCoreValue := core.Value()
	otherCoreValue.AttemptID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000603",
	)
	otherCore, err := pairing.NewRequestCore(otherCoreValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(
		context.Background(),
		invite,
		otherCore,
	); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf(
			"Request(second attempt) error = %v, want %v",
			err,
			ErrAttemptConflict,
		)
	}

	wrongAttempt, err := pairing.NewConfirmation(
		otherCoreValue.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Confirm(
		context.Background(),
		wrongAttempt,
	); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf(
			"Confirm(second attempt) error = %v, want %v",
			err,
			ErrAttemptConflict,
		)
	}
	if _, err := client.Confirm(context.Background(), confirmation); err != nil {
		t.Fatal(err)
	}

	changedDecision, err := pairing.NewConfirmation(
		core.Value().AttemptID,
		requestDigest,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Confirm(
		context.Background(),
		changedDecision,
	); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf(
			"Confirm(changed decision) error = %v, want %v",
			err,
			ErrDecisionConflict,
		)
	}
	if _, err := client.Confirm(context.Background(), confirmation); err != nil {
		t.Fatalf("Confirm(exact poll) error = %v", err)
	}

	calls := service.snapshot()
	if len(calls) != 3 ||
		calls[0].operation != "request" ||
		calls[1].operation != "confirm" ||
		calls[2].operation != "confirm" {
		t.Fatalf("service calls after local conflicts = %+v", calls)
	}
}

func TestClientRejectsImpossibleDeclineStatus(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	client, err := OpenClient(context.Background(), harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	invite, core := clientPairingFixture(t, harness)
	request, err := pairing.BuildRequest(invite, core, client.exporter[:])
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := request.Digest()
	service.acknowledgment, err = pairing.NewRequestAcknowledgmentValues(
		core.Value().AttemptID,
		requestDigest,
		invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	service.confirmation, err = pairing.NewConfirmationResult(
		core.Value().AttemptID,
		requestDigest,
		pairing.StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(context.Background(), invite, core); err != nil {
		t.Fatal(err)
	}
	decline, err := pairing.NewConfirmation(
		core.Value().AttemptID,
		requestDigest,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Confirm(
		context.Background(),
		decline,
	); !errors.Is(err, ErrResponseProtocol) {
		t.Fatalf(
			"Confirm(impossible decline status) error = %v, want %v",
			err,
			ErrResponseProtocol,
		)
	}

	service.confirmation, err = pairing.NewConfirmationResult(
		core.Value().AttemptID,
		requestDigest,
		pairing.StatusDeclined,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Confirm(context.Background(), decline)
	if err != nil || result.Status != pairing.StatusDeclined {
		t.Fatalf("Confirm(exact decline retry) = (%+v, %v)", result, err)
	}
}

func TestClientCloseInterruptsInFlightRequest(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	service.entered = make(chan struct{})
	service.release = make(chan struct{})
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	client, err := OpenClient(context.Background(), harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	invite, core := clientPairingFixture(t, harness)

	requestDone := make(chan error, 1)
	go func() {
		_, requestErr := client.Request(context.Background(), invite, core)
		requestDone <- requestErr
	}()
	select {
	case <-service.entered:
	case <-testDeadline(t):
		t.Fatal("request did not reach service")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-testDeadline(t):
		t.Fatal("Close() waited for the in-flight request")
	}
	select {
	case err := <-requestDone:
		if !errors.Is(err, ErrClientClosed) {
			t.Fatalf(
				"Request(interrupted) error = %v, want %v",
				err,
				ErrClientClosed,
			)
		}
	case <-testDeadline(t):
		t.Fatal("in-flight request was not interrupted")
	}
}

func TestOpenClientOwnsConnectionOnInvalidContext(t *testing.T) {
	t.Parallel()

	rawServer, rawClient := net.Pipe()
	connection := tls.Client(rawClient, &tls.Config{ //nolint:gosec -- no handshake occurs
		InsecureSkipVerify: true,
	})
	//lint:ignore SA1012 This test verifies nil-context rejection and connection ownership.
	if _, err := OpenClient(nil, connection); !errors.Is(
		err,
		ErrInvalidClient,
	) {
		t.Fatalf("OpenClient(nil context) error = %v, want %v", err, ErrInvalidClient)
	}
	readDone := make(chan error, 1)
	go func() {
		var value [1]byte
		_, readErr := rawServer.Read(value[:])
		readDone <- readErr
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("OpenClient left an invalid-input connection open")
		}
	case <-time.After(time.Second):
		_ = rawServer.Close()
		t.Fatal("OpenClient did not close an invalid-input connection")
	}
	_ = rawServer.Close()
}

func TestServerRejectsNonPairingHTTPShapesBeforeDispatch(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	connection := openTestConnection(t, server)
	defer connection.close(t)

	tests := []struct {
		name        string
		method      string
		path        string
		body        []byte
		contentType string
		status      int
		code        string
	}{
		{
			name: "unknown route", method: http.MethodPost,
			path: "/v1/session", body: []byte(`{}`),
			contentType: "application/json",
			status:      http.StatusNotFound, code: "route_not_found",
		},
		{
			name: "query", method: http.MethodPost,
			path: RequestPath + "?poll=true", body: []byte(`{}`),
			contentType: "application/json",
			status:      http.StatusNotFound, code: "route_not_found",
		},
		{
			name: "method", method: http.MethodGet,
			path: RequestPath, body: []byte(`{}`),
			contentType: "application/json",
			status:      http.StatusMethodNotAllowed, code: "method_not_allowed",
		},
		{
			name: "missing media type", method: http.MethodPost,
			path: RequestPath, body: []byte(`{}`),
			status: http.StatusUnsupportedMediaType,
			code:   "unsupported_media_type",
		},
		{
			name: "unsupported charset", method: http.MethodPost,
			path: RequestPath, body: []byte(`{}`),
			contentType: "application/json; charset=iso-8859-1",
			status:      http.StatusUnsupportedMediaType,
			code:        "unsupported_media_type",
		},
		{
			name: "empty body", method: http.MethodPost,
			path: RequestPath, body: nil,
			contentType: "application/json",
			status:      http.StatusBadRequest, code: "invalid_pairing_message",
		},
		{
			name: "oversized body", method: http.MethodPost,
			path: RequestPath,
			body: bytes.Repeat(
				[]byte{'x'},
				pairing.MaxPairingMessageBytes+1,
			),
			contentType: "application/json",
			status:      http.StatusRequestEntityTooLarge,
			code:        "body_too_large",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := roundTrip(
				t,
				connection.client,
				test.method,
				test.path,
				test.body,
				test.contentType,
			)
			if response.StatusCode != test.status {
				t.Fatalf(
					"response status = %d, want %d",
					response.StatusCode,
					test.status,
				)
			}
			assertProblem(t, response, test.code)
		})
	}
	if calls := service.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid requests reached service: %+v", calls)
	}
}

func TestServerEnforcesExactBodyBoundaryAndRedactsServiceErrors(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	service.requestError = func(body []byte) error {
		switch string(body) {
		case "rejected":
			return pairingservice.ErrRequestRejected
		case "unavailable":
			return errors.New("database path /secret/path: unavailable")
		default:
			return nil
		}
	}
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	connection := openTestConnection(t, server)
	defer connection.close(t)

	exact := bytes.Repeat([]byte{'x'}, pairing.MaxPairingMessageBytes)
	response := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		exact,
		"application/json",
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exact-limit response = %s", response.Status)
	}
	_ = readResponse(t, response)

	response = roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte("rejected"),
		"application/json",
	)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("rejected response = %s", response.Status)
	}
	assertProblem(t, response, "pairing_rejected")

	response = roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte("unavailable"),
		"application/json",
	)
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("internal response = %s", response.Status)
	}
	body := assertProblem(t, response, "internal_error")
	if bytes.Contains(body, []byte("/secret/path")) ||
		bytes.Contains(body, []byte("database")) {
		t.Fatalf("problem response leaked service error: %s", body)
	}
}

func TestServerHandlerCapacityRejectsWithoutQueueing(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	service.entered = make(chan struct{})
	service.release = make(chan struct{})
	server, err := newServer(service, 1)
	if err != nil {
		t.Fatal(err)
	}
	connection := openTestConnection(t, server)
	defer connection.close(t)

	firstDone := make(chan roundTripResult, 1)
	go func() {
		request, err := newPairingHTTPRequest(
			http.MethodPost,
			RequestPath,
			[]byte(`{"first":true}`),
			"application/json",
		)
		if err != nil {
			firstDone <- roundTripResult{err: err}
			return
		}
		response, err := connection.client.RoundTrip(request)
		firstDone <- roundTripResult{response: response, err: err}
	}()
	select {
	case <-service.entered:
	case <-testDeadline(t):
		t.Fatal("first handler did not enter service")
	}

	second := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte(`{"second":true}`),
		"application/json",
	)
	if second.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity response = %s", second.Status)
	}
	assertProblem(t, second, "handler_capacity")
	close(service.release)
	select {
	case first := <-firstDone:
		if first.err != nil {
			t.Fatalf("first RoundTrip(): %v", first.err)
		}
		if first.response.StatusCode != http.StatusOK {
			t.Fatalf("first response = %s", first.response.Status)
		}
		_ = readResponse(t, first.response)
	case <-testDeadline(t):
		t.Fatal("first handler did not finish")
	}
	if calls := service.snapshot(); len(calls) != 1 {
		t.Fatalf("capacity rejection reached service: %+v", calls)
	}
}

func TestServerAbsoluteBodyDeadlineReleasesHandlerCapacity(t *testing.T) {
	service := newRecordingService(t)
	server, err := newServer(service, 1)
	if err != nil {
		t.Fatal(err)
	}
	server.requestTimeout = 500 * time.Millisecond
	server.streamNoProgress = 100 * time.Millisecond
	connection := openTestConnection(t, server)
	defer connection.close(t)

	reader, writer := io.Pipe()
	firstContext, cancelFirst := context.WithTimeout(
		context.Background(),
		6*time.Second,
	)
	defer cancelFirst()
	first, err := http.NewRequestWithContext(
		firstContext,
		http.MethodPost,
		"https://codecomm.test"+RequestPath,
		reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	first.ContentLength = 1 << 10
	first.Header.Set("Content-Type", "application/json")
	firstDone := make(chan roundTripResult, 1)
	firstStartedAt := time.Now()
	go func() {
		response, err := connection.client.RoundTrip(first)
		firstDone <- roundTripResult{response: response, err: err}
	}()
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := writer.Write([]byte(" ")); err != nil {
				return
			}
			<-ticker.C
		}
	}()
	writerStopped := false
	stopWriter := func() {
		if writerStopped {
			return
		}
		writerStopped = true
		_ = writer.Close()
		<-writeDone
	}
	defer stopWriter()

	handlerDeadline := time.NewTimer(3 * time.Second)
	defer handlerDeadline.Stop()
	for len(server.handlers) != 1 {
		select {
		case <-handlerDeadline.C:
			t.Fatal("slow body did not acquire the handler slot")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	capacity := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte(`{"second":true}`),
		"application/json",
	)
	if capacity.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("capacity response = %s", capacity.Status)
	}
	assertProblem(t, capacity, "handler_capacity")

	select {
	case result := <-firstDone:
		if result.err != nil {
			t.Fatalf("slow-body RoundTrip(): %v", result.err)
		}
		if result.response.StatusCode != http.StatusBadRequest {
			t.Fatalf("slow-body response = %s", result.response.Status)
		}
		if elapsed := time.Since(firstStartedAt); elapsed <
			server.requestTimeout/2 {
			t.Fatalf(
				"slow-body response arrived after %s; progress timeout fired before absolute deadline",
				elapsed,
			)
		}
		assertProblem(t, result.response, "invalid_pairing_message")
	case <-time.After(5 * time.Second):
		t.Fatal("absolute request deadline did not release handler capacity")
	}
	stopWriter()

	after := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte(`{"after":true}`),
		"application/json",
	)
	if after.StatusCode != http.StatusOK {
		t.Fatalf("post-timeout response = %s", after.Status)
	}
	_ = readResponse(t, after)
}

func TestServerTimesEveryHTTP2HeaderBlock(t *testing.T) {
	service := newRecordingService(t)
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	server.headerTimeout = 150 * time.Millisecond
	connection := openTestConnection(t, server)
	stopped := false
	defer func() {
		_ = connection.client.Close()
		_ = connection.harness.clientTLS.Close()
		connection.harness.cancel()
		if !stopped {
			select {
			case <-connection.harness.serverDone:
			case <-testDeadline(t):
				t.Fatal("pairing server did not stop")
			}
		}
		clear(connection.exporter)
	}()

	response := roundTrip(
		t,
		connection.client,
		http.MethodPost,
		RequestPath,
		[]byte(`{"first":true}`),
		"application/json",
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("first response = %s", response.Status)
	}
	_ = readResponse(t, response)

	partialHeaders := testHTTP2Frame(
		64,
		http2FrameTypeHeaders,
		http2FlagEndHeaders,
		[]byte{0},
	)
	partialHeaders[8] = 3
	startedAt := time.Now()
	if _, err := connection.harness.clientTLS.Write(partialHeaders); err != nil {
		t.Fatalf("write partial second header: %v", err)
	}
	select {
	case err := <-connection.harness.serverDone:
		stopped = true
		if err != nil {
			t.Fatalf("ServeConn() error = %v", err)
		}
		elapsed := time.Since(startedAt)
		if elapsed < server.headerTimeout/2 || elapsed > 3*time.Second {
			t.Fatalf(
				"partial second header closed after %s, want near %s",
				elapsed,
				server.headerTimeout,
			)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second HTTP/2 header block outlived its deadline")
	}
}

func TestPairingConnectionStateRejectsWrongPlaneAndResumption(t *testing.T) {
	t.Parallel()

	server, err := New(newRecordingService(t))
	if err != nil {
		t.Fatal(err)
	}
	harness := startTestTLS(t, server)
	defer harness.stop(t)
	if _, exporter := harness.handshakeClient(t); exporter != nil {
		clear(exporter)
	}
	valid := harness.clientTLS.ConnectionState()
	if _, exporter, err := pairingConnectionState(valid); err != nil {
		t.Fatalf("pairingConnectionState(valid) error = %v", err)
	} else {
		clear(exporter)
	}

	tests := []struct {
		name   string
		mutate func(*tls.ConnectionState)
	}{
		{name: "incomplete", mutate: func(state *tls.ConnectionState) {
			state.HandshakeComplete = false
		}},
		{name: "old TLS", mutate: func(state *tls.ConnectionState) {
			state.Version = tls.VersionTLS12
		}},
		{name: "wrong plane", mutate: func(state *tls.ConnectionState) {
			state.NegotiatedProtocol = transport.ALPNConsensus
		}},
		{name: "resumed", mutate: func(state *tls.ConnectionState) {
			state.DidResume = true
		}},
		{name: "missing peer", mutate: func(state *tls.ConnectionState) {
			state.PeerCertificates = nil
		}},
		{name: "certificate chain", mutate: func(state *tls.ConnectionState) {
			state.PeerCertificates = append(
				state.PeerCertificates,
				state.PeerCertificates[0],
			)
		}},
	}
	for _, test := range tests {
		state := valid
		test.mutate(&state)
		if _, exporter, err := pairingConnectionState(
			state,
		); !errors.Is(err, ErrTLSBinding) || exporter != nil {
			t.Fatalf(
				"pairingConnectionState(%s) = (%x, %v)",
				test.name,
				exporter,
				err,
			)
		}
	}
}

func TestServerUsesFixedHTTP2Limits(t *testing.T) {
	t.Parallel()

	server, err := New(newRecordingService(t))
	if err != nil {
		t.Fatal(err)
	}
	if cap(server.handlers) != ActiveHandlersMax ||
		server.headerTimeout != RequestHeaderTimeout ||
		server.requestTimeout != RequestTimeout ||
		server.streamNoProgress != StreamNoProgress ||
		server.http2.MaxConcurrentStreams != ControlStreamsMax ||
		server.http2.IdleTimeout != ConnectionIdle ||
		server.http2.WriteByteTimeout != StreamNoProgress ||
		server.http2.MaxUploadBufferPerStream !=
			pairing.MaxPairingMessageBytes {
		t.Fatalf("HTTP/2 limits = %+v, handlers = %d", server.http2, cap(server.handlers))
	}
	if _, err := newServer(newRecordingService(t), ActiveHandlersMax+1); !errors.Is(
		err,
		ErrInvalidOptions,
	) {
		t.Fatalf("oversized handler limit error = %v", err)
	}
}

func TestPairingReadDeadlineCannotExtendAbsoluteRequestBudget(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	requestDeadline := now.Add(RequestTimeout)
	if got, want := pairingReadDeadline(
		now,
		requestDeadline,
		StreamNoProgress,
	), now.Add(StreamNoProgress); !got.Equal(want) {
		t.Fatalf("initial read deadline = %s, want %s", got, want)
	}

	nearAbsoluteDeadline := requestDeadline.Add(-time.Second)
	if got := pairingReadDeadline(
		nearAbsoluteDeadline,
		requestDeadline,
		StreamNoProgress,
	); !got.Equal(requestDeadline) {
		t.Fatalf(
			"near-budget read deadline = %s, want %s",
			got,
			requestDeadline,
		)
	}
	if got := pairingReadDeadline(
		requestDeadline.Add(time.Second),
		requestDeadline,
		StreamNoProgress,
	); !got.Equal(requestDeadline) {
		t.Fatalf(
			"expired-budget read deadline = %s, want %s",
			got,
			requestDeadline,
		)
	}
}

func TestServeConnCanceledContextReleasesPermitAndConnection(t *testing.T) {
	t.Parallel()

	server, err := New(newRecordingService(t))
	if err != nil {
		t.Fatal(err)
	}
	limiter := transport.NewAdmissionLimiter()
	permit, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.20"))
	if err != nil {
		t.Fatal(err)
	}
	rawServer, rawClient := net.Pipe()
	connection := tls.Server(rawServer, &tls.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.ServeConn(
		ctx,
		connection,
		permit,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("ServeConn(canceled) error = %v", err)
	}
	if pending := limiter.Stats().PendingHandshakes; pending != 0 {
		t.Fatalf("pending handshakes = %d, want 0", pending)
	}
	buffer := make([]byte, 1)
	if _, err := rawClient.Read(buffer); err == nil {
		t.Fatal("canceled ServeConn left its connection open")
	}
	_ = rawClient.Close()
}

type recordingService struct {
	mu           sync.Mutex
	calls        []serviceCall
	requestError func([]byte) error
	entered      chan struct{}
	release      chan struct{}
	enterOnce    sync.Once

	acknowledgment pairing.RequestAcknowledgment
	confirmation   pairing.ConfirmationResult
}

type serviceCall struct {
	operation string
	body      []byte
	exporter  []byte
	peer      transport.IdentityCertificate
}

func newRecordingService(t testing.TB) *recordingService {
	t.Helper()
	requestDigest := sha256.Sum256([]byte("request"))
	inviteDigest := sha256.Sum256([]byte("invite"))
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		pairingHTTPTestAttemptID,
		requestDigest,
		inviteDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := pairing.NewConfirmationResult(
		pairingHTTPTestAttemptID,
		requestDigest,
		pairing.StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingService{
		acknowledgment: acknowledgment,
		confirmation:   confirmation,
	}
}

func (service *recordingService) HandleRequest(
	ctx context.Context,
	body []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) (pairingservice.RequestResult, error) {
	service.record("request", body, exporter, peer)
	if service.entered != nil {
		service.enterOnce.Do(func() { close(service.entered) })
		select {
		case <-service.release:
		case <-ctx.Done():
			return pairingservice.RequestResult{}, ctx.Err()
		}
	}
	if service.requestError != nil {
		if err := service.requestError(body); err != nil {
			return pairingservice.RequestResult{}, err
		}
	}
	return pairingservice.RequestResult{
		Acknowledgment: service.acknowledgment,
	}, nil
}

func (service *recordingService) ConfirmRemote(
	_ context.Context,
	body []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) (pairing.ConfirmationResult, error) {
	service.record("confirm", body, exporter, peer)
	return service.confirmation, nil
}

func (service *recordingService) record(
	operation string,
	body []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) {
	service.mu.Lock()
	service.calls = append(service.calls, serviceCall{
		operation: operation,
		body:      bytes.Clone(body),
		exporter:  bytes.Clone(exporter),
		peer:      peer,
	})
	service.mu.Unlock()
}

func (service *recordingService) snapshot() []serviceCall {
	service.mu.Lock()
	defer service.mu.Unlock()
	result := make([]serviceCall, len(service.calls))
	copy(result, service.calls)
	return result
}

type testConnection struct {
	client        *http2.ClientConn
	exporter      []byte
	clientBinding transport.IdentityBinding
	harness       *testTLSHarness
}

type testTLSHarness struct {
	clientTLS     *tls.Conn
	serverKey     ed25519.PrivateKey
	clientKey     ed25519.PrivateKey
	serverBinding transport.IdentityBinding
	clientBinding transport.IdentityBinding
	cancel        context.CancelFunc
	serverDone    <-chan error
}

type roundTripResult struct {
	response *http.Response
	err      error
}

func openTestConnection(
	t testing.TB,
	server *Server,
) *testConnection {
	t.Helper()
	harness := startTestTLS(t, server)
	serverPeer, exporter := harness.handshakeClient(t)
	if serverPeer.Binding != harness.serverBinding {
		harness.stop(t)
		t.Fatalf("server identity = %+v", serverPeer)
	}
	clientTransport := &http2.Transport{
		MaxHeaderListSize: HeaderMaxBytes,
		ReadIdleTimeout:   StreamNoProgress,
		PingTimeout:       RequestHeaderTimeout,
		WriteByteTimeout:  StreamNoProgress,
	}
	client, err := clientTransport.NewClientConn(harness.clientTLS)
	if err != nil {
		clear(exporter)
		harness.stop(t)
		t.Fatalf("HTTP/2 client: %v", err)
	}
	return &testConnection{
		client:        client,
		exporter:      exporter,
		clientBinding: harness.clientBinding,
		harness:       harness,
	}
}

func startTestTLS(
	t testing.TB,
	server *Server,
) *testTLSHarness {
	t.Helper()
	serverKey := testIdentityKey(0x41)
	serverCertificate, serverBinding, err :=
		transport.IssueIdentityCertificate(
			pairingHTTPTestSessionID,
			0,
			serverKey,
		)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := testIdentityKey(0x42)
	clientCertificate, clientBinding, err :=
		transport.IssueIdentityCertificate(
			pairingHTTPTestSessionID,
			0,
			clientKey,
		)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{serverCertificate},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{transport.ALPNPairing},
		SessionTicketsDisabled: true,
	}
	clientConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:       transport.PlanePairing,
			Certificate: clientCertificate,
			VerifyIdentityPeer: func(
				certificate transport.IdentityCertificate,
			) error {
				return certificate.VerifyIdentity(
					pairingHTTPTestSessionID,
					0,
					serverBinding.DeviceID,
					serverKey.Public().(ed25519.PublicKey),
				)
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	rawServer, rawClient := net.Pipe()
	serverTLS := tls.Server(rawServer, serverConfig)
	clientTLS := tls.Client(rawClient, clientConfig)
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	limiter := transport.NewAdmissionLimiter()
	permit, err := limiter.TryAcquire(netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		cancel()
		_ = clientTLS.Close()
		t.Fatalf("handshake permit: %v", err)
	}
	go func() {
		serverDone <- server.ServeConn(ctx, serverTLS, permit)
	}()
	return &testTLSHarness{
		clientTLS: clientTLS, serverKey: serverKey, clientKey: clientKey,
		serverBinding: serverBinding, clientBinding: clientBinding,
		cancel: cancel, serverDone: serverDone,
	}
}

func (harness *testTLSHarness) handshakeClient(
	t testing.TB,
) (transport.IdentityCertificate, []byte) {
	t.Helper()
	handshakeContext, stopHandshake := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	err := harness.clientTLS.HandshakeContext(handshakeContext)
	stopHandshake()
	if err != nil {
		harness.stop(t)
		t.Fatalf("client TLS handshake: %v", err)
	}
	state := harness.clientTLS.ConnectionState()
	if state.NegotiatedProtocol != transport.ALPNPairing ||
		len(state.PeerCertificates) != 1 {
		harness.stop(t)
		t.Fatalf("client TLS state = %+v", state)
	}
	serverPeer, err := transport.ParseIdentityCertificate(
		state.PeerCertificates[0].Raw,
	)
	if err != nil {
		harness.stop(t)
		t.Fatalf("server identity = (%+v, %v)", serverPeer, err)
	}
	exporter, err := state.ExportKeyingMaterial(
		pairing.ExporterLabel,
		[]byte{},
		pairing.ExporterSize,
	)
	if err != nil {
		harness.stop(t)
		t.Fatalf("client exporter: %v", err)
	}
	return serverPeer, exporter
}

func (connection *testConnection) close(t testing.TB) {
	t.Helper()
	if connection == nil {
		return
	}
	_ = connection.client.Close()
	connection.harness.stop(t)
	clear(connection.exporter)
}

func (harness *testTLSHarness) stop(t testing.TB) {
	t.Helper()
	if harness == nil {
		return
	}
	_ = harness.clientTLS.Close()
	harness.cancel()
	select {
	case err := <-harness.serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeConn() error = %v", err)
		}
	case <-testDeadline(t):
		t.Fatal("pairing server did not stop")
	}
}

func roundTrip(
	t testing.TB,
	client *http2.ClientConn,
	method string,
	path string,
	body []byte,
	contentType string,
) *http.Response {
	t.Helper()
	request, err := newPairingHTTPRequest(method, path, body, contentType)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.RoundTrip(request)
	if err != nil {
		t.Fatalf("RoundTrip(%s %s): %v", method, path, err)
	}
	return response
}

func newPairingHTTPRequest(
	method string,
	path string,
	body []byte,
	contentType string,
) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		method,
		"https://codecomm.test"+path,
		reader,
	)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return request, nil
}

func readResponse(t testing.TB, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertProblem(
	t testing.TB,
	response *http.Response,
	code string,
) []byte {
	t.Helper()
	if response.Header.Get("Content-Type") != "application/problem+json" ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("problem headers = %v", response.Header)
	}
	body := readResponse(t, response)
	var problem problemResponse
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("problem JSON = %s: %v", body, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 6 {
		t.Fatalf("problem fields = %v: %v", fields, err)
	}
	if problem.Status != response.StatusCode ||
		problem.Code != code ||
		problem.Type != "urn:codecomm:problem:"+code ||
		problem.Title == "" ||
		problem.CorrelationID == "" {
		t.Fatalf("problem = %+v, status = %d", problem, response.StatusCode)
	}
	if problem.CorrelationID != "unavailable" {
		if _, err := uuid.Parse(problem.CorrelationID); err != nil {
			t.Fatalf("correlation ID = %q: %v", problem.CorrelationID, err)
		}
	}
	return body
}

func testIdentityKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat(
		[]byte{fill},
		ed25519.SeedSize,
	))
}

func clientPairingFixture(
	t testing.TB,
	harness *testTLSHarness,
) (pairing.SignedInvite, pairing.CanonicalRequestCore) {
	t.Helper()
	var secret [pairing.InviteSecretSize]byte
	copy(secret[:], bytes.Repeat([]byte{0x51}, len(secret)))
	inviteValue := pairing.Invite{
		InviteID:               domain.UUIDv7("01890f47-3e72-7000-8000-000000000602"),
		SessionID:              pairingHTTPTestSessionID,
		WorkspaceID:            domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000"),
		RecoveryGeneration:     0,
		CreatedAt:              domain.WholeSecondTimestamp("2026-08-14T12:00:00Z"),
		ExpiresAt:              domain.WholeSecondTimestamp("2026-08-14T12:15:00Z"),
		Secret:                 secret,
		InviterDeviceID:        harness.serverBinding.DeviceID,
		SignedGenesisDigest:    sha256.Sum256([]byte("signed genesis")),
		Mode:                   pairing.ModeNew,
		Role:                   device.RoleEditor,
		InitialCredentialEpoch: 1,
		Endpoints: []pairing.Endpoint{{
			IP: netip.MustParseAddr("192.0.2.10"), Port: 47831,
		}},
	}
	copy(
		inviteValue.InviterIdentityPublicKey[:],
		harness.serverKey.Public().(ed25519.PublicKey),
	)
	invite, err := pairing.SignInvite(inviteValue, harness.serverKey)
	clear(inviteValue.Secret[:])
	if err != nil {
		t.Fatal(err)
	}

	epochKey := testIdentityKey(0x43)
	binding, err := credential.SignBinding(
		pairingHTTPTestSessionID,
		harness.clientBinding.DeviceID,
		1,
		epochKey.Public().(ed25519.PublicKey),
		harness.clientKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	coreValue := pairing.RequestCore{
		AttemptID:           pairingHTTPTestAttemptID,
		JoinerDeviceID:      harness.clientBinding.DeviceID,
		DaemonVersion:       "1.0.0",
		MaxApplyLevel:       1,
		InitialEpochBinding: binding,
	}
	copy(
		coreValue.JoinerIdentityPublicKey[:],
		harness.clientKey.Public().(ed25519.PublicKey),
	)
	core, err := pairing.NewRequestCore(coreValue)
	if err != nil {
		t.Fatal(err)
	}
	return invite, core
}

func testDeadline(t testing.TB) <-chan time.Time {
	t.Helper()
	return time.After(10 * time.Second)
}

var _ Service = (*recordingService)(nil)
