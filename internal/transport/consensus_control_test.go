package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func testConsensusProofRequestReusesAuthenticatedConnection(t *testing.T) {
	const (
		requestBody  = `{"mode":"staging_apply"}`
		responseBody = `{"applied":true}`
	)
	requestSeen := make(chan error, 1)
	peerSeen := make(chan AuthenticatedPeer, 1)
	harness := newConsensusHarnessWithControlHandler(
		t,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.Method != http.MethodPost ||
				request.URL == nil ||
				request.URL.Path != consensusProofPath ||
				request.Host != ConsensusRaftAuthority ||
				request.Header.Get("Content-Type") !=
					consensusJSONMediaType {
				requestSeen <- errors.New("unexpected proof request metadata")
				http.Error(writer, "bad request", http.StatusBadRequest)
				return
			}
			peer, ok := AuthenticatedPeerFromContext(request.Context())
			if !ok || peer.Plane != PlaneConsensus ||
				!peer.DeviceID.Valid() {
				requestSeen <- errors.New("missing authenticated proof peer")
				http.Error(writer, "bad peer", http.StatusForbidden)
				return
			}
			peerSeen <- peer
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != requestBody {
				requestSeen <- errors.New("unexpected proof request body")
				http.Error(writer, "bad body", http.StatusBadRequest)
				return
			}
			requestSeen <- nil
			writer.Header().Set("Content-Type", consensusJSONMediaType)
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, responseBody)
		}),
	)

	response, err := harness.client.RequestConsensusProof(
		t.Context(),
		harness.serverID,
		[]byte(requestBody),
	)
	if err != nil {
		t.Fatalf("RequestConsensusProof(): %v", err)
	}
	if requestErr := <-requestSeen; requestErr != nil {
		t.Fatal(requestErr)
	}
	if peer := <-peerSeen; peer.DeviceID != harness.clientID {
		t.Fatalf("authenticated proof peer = %q", peer.DeviceID)
	}
	if response.StatusCode != http.StatusOK ||
		response.MediaType != consensusJSONMediaType ||
		string(response.Body) != responseBody {
		t.Fatalf("proof response = %#v", response)
	}

	outbound, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(after proof): %v", err)
	}
	inbound := acceptConsensusStream(t, harness.server)
	_ = outbound.Close()
	_ = inbound.Close()
	if got := harness.dialer.count.Load(); got != 1 {
		t.Fatalf("physical connection count = %d, want 1", got)
	}
	harness.assertNoActiveSocketDeadlines(t)
}

func testConsensusCredentialEndorsementUsesClosedControlRoute(t *testing.T) {
	const (
		requestBody  = `{"schema_version":1}`
		responseBody = `{"schema_version":1}`
	)
	requestSeen := make(chan error, 1)
	harness := newConsensusHarnessWithControlHandler(
		t,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.Method != http.MethodPost ||
				request.URL == nil ||
				request.URL.Path !=
					consensusCredentialEndorsementPath ||
				request.Host != ConsensusRaftAuthority ||
				request.Header.Get("Content-Type") !=
					consensusJSONMediaType {
				requestSeen <- errors.New(
					"unexpected credential request metadata",
				)
				http.Error(writer, "bad request", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != requestBody {
				requestSeen <- errors.New(
					"unexpected credential request body",
				)
				http.Error(writer, "bad body", http.StatusBadRequest)
				return
			}
			requestSeen <- nil
			writer.Header().Set("Content-Type", consensusJSONMediaType)
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, responseBody)
		}),
	)

	network := &ConsensusNetworkTransport{
		delegate: &raft.NetworkTransport{},
		control:  harness.client,
	}
	response, err := network.RequestCredentialEndorsement(
		t.Context(),
		harness.serverID,
		[]byte(requestBody),
	)
	if err != nil {
		t.Fatalf("RequestCredentialEndorsement(): %v", err)
	}
	if requestErr := <-requestSeen; requestErr != nil {
		t.Fatal(requestErr)
	}
	if response.StatusCode != http.StatusOK ||
		response.MediaType != consensusJSONMediaType ||
		string(response.Body) != responseBody {
		t.Fatalf("credential response = %#v", response)
	}
}

func testConsensusIdentityControlBypassesOnlyLiveConfiguration(
	t *testing.T,
) {
	const (
		requestBody         = `{"schema_version":1}`
		renewalResponseBody = `{"authorization_chain_index":7}`
		statusResponseBody  = `{"schema_version":1}`
	)
	requests := make(chan string, 2)
	harness := newConsensusHarnessWithControlHandler(
		t,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			switch {
			case request.Method == http.MethodGet &&
				request.URL != nil &&
				request.URL.Path == consensusStatusPath:
				body, err := io.ReadAll(request.Body)
				if err != nil ||
					len(body) != 0 ||
					request.ContentLength != 0 ||
					request.Header.Get("Content-Type") != "" {
					http.Error(
						writer,
						"bad status request",
						http.StatusBadRequest,
					)
					return
				}
				requests <- request.URL.Path
				writer.Header().Set(
					"Content-Type",
					consensusJSONMediaType,
				)
				writer.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(writer, statusResponseBody)
			case request.Method == http.MethodPost &&
				request.URL != nil &&
				request.URL.Path == consensusCredentialRenewalPath &&
				request.Header.Get("Content-Type") ==
					consensusJSONMediaType:
				body, err := io.ReadAll(request.Body)
				if err != nil || string(body) != requestBody {
					http.Error(writer, "bad body", http.StatusBadRequest)
					return
				}
				requests <- request.URL.Path
				writer.Header().Set(
					"Content-Type",
					consensusJSONMediaType,
				)
				writer.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(writer, renewalResponseBody)
			default:
				http.Error(writer, "bad request", http.StatusBadRequest)
			}
		}),
	)
	harness.clientAllowed.Store(harness.serverID, false)
	network := &ConsensusNetworkTransport{
		delegate: &raft.NetworkTransport{},
		control:  harness.client,
	}
	statusResponse, err := network.RequestConsensusStatus(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("RequestConsensusStatus(): %v", err)
	}
	if statusResponse.StatusCode != http.StatusOK ||
		statusResponse.MediaType != consensusJSONMediaType ||
		string(statusResponse.Body) != statusResponseBody {
		t.Fatalf("status response = %#v", statusResponse)
	}
	renewalResponse, err := network.RequestCredentialRenewal(
		t.Context(),
		harness.serverID,
		[]byte(requestBody),
	)
	if err != nil {
		t.Fatalf("RequestCredentialRenewal(): %v", err)
	}
	if renewalResponse.StatusCode != http.StatusOK ||
		renewalResponse.MediaType != consensusJSONMediaType ||
		string(renewalResponse.Body) != renewalResponseBody {
		t.Fatalf("renewal response = %#v", renewalResponse)
	}
	for _, expected := range []string{
		consensusStatusPath,
		consensusCredentialRenewalPath,
	} {
		select {
		case path := <-requests:
			if path != expected {
				t.Fatalf("identity route = %q, want %q", path, expected)
			}
		case <-time.After(consensusTestTimeout):
			t.Fatalf("%s route was not served", expected)
		}
	}

	for name, request := range map[string]func() error{
		"proof": func() error {
			_, err := harness.client.RequestConsensusProof(
				t.Context(),
				harness.serverID,
				[]byte(`{"mode":"staging_apply"}`),
			)
			return err
		},
		"endorsement": func() error {
			_, err := harness.client.RequestCredentialEndorsement(
				t.Context(),
				harness.serverID,
				[]byte(`{"schema_version":1}`),
			)
			return err
		},
		"raft CONNECT": func() error {
			connection, err := harness.client.Dial(
				raft.ServerAddress(harness.serverID),
				consensusTestTimeout,
			)
			if connection != nil {
				_ = connection.Close()
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := request(); !errors.Is(err, ErrConsensusPeerDenied) {
				t.Fatalf("outside-configuration request error = %v", err)
			}
		})
	}
	if got := harness.dialer.count.Load(); got != 1 {
		t.Fatalf("physical connection count = %d, want 1", got)
	}
}

func testConsensusStatusRejectsNoncanonicalResponse(t *testing.T) {
	harness := newConsensusHarnessWithControlHandler(
		t,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.Header().Set("Content-Type", consensusJSONMediaType)
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, `{ "schema_version": 1 }`)
		}),
	)
	if _, err := harness.client.RequestConsensusStatus(
		t.Context(),
		harness.serverID,
	); !errors.Is(err, ErrConsensusControlResponse) {
		t.Fatalf("RequestConsensusStatus() error = %v", err)
	}
}

func testConsensusProofRequestRejectsInvalidInputBeforeDial(t *testing.T) {
	harness := newConsensusHarness(t)
	tooLarge := make([]byte, ConsensusControlBodyMaxBytes+1)
	for name, test := range map[string]struct {
		ctx  context.Context
		body []byte
	}{
		"nil context":   {ctx: nil, body: []byte(`{}`)},
		"empty body":    {ctx: t.Context()},
		"oversize body": {ctx: t.Context(), body: tooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := harness.client.RequestConsensusProof(
				test.ctx,
				harness.serverID,
				test.body,
			)
			if !errors.Is(err, ErrInvalidConsensusControlRequest) {
				t.Fatalf("RequestConsensusProof() error = %v", err)
			}
		})
	}
	if got := harness.dialer.count.Load(); got != 0 {
		t.Fatalf("invalid requests opened %d physical connections", got)
	}
}

func testConsensusProofRequestBoundsAndClassifiesResponses(t *testing.T) {
	tests := map[string]struct {
		handler http.Handler
		wantErr bool
	}{
		"problem response": {
			handler: http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set(
					"Content-Type",
					consensusProblemMediaType,
				)
				writer.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(writer, `{"code":"stale"}`)
			}),
		},
		"wrong media type": {
			handler: http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(writer, "not json")
			}),
			wantErr: true,
		},
		"oversize response": {
			handler: http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				writer.Header().Set("Content-Type", consensusJSONMediaType)
				writer.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(
					writer,
					strings.Repeat(
						"x",
						ConsensusControlBodyMaxBytes+1,
					),
				)
			}),
			wantErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newConsensusHarnessWithControlHandler(
				t,
				test.handler,
			)
			response, err := harness.client.RequestConsensusProof(
				t.Context(),
				harness.serverID,
				[]byte(`{"mode":"staging_apply"}`),
			)
			if test.wantErr {
				if !errors.Is(err, ErrConsensusControlResponse) {
					t.Fatalf("RequestConsensusProof() error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequestConsensusProof(): %v", err)
			}
			if response.StatusCode != http.StatusConflict ||
				response.MediaType != consensusProblemMediaType {
				t.Fatalf("problem response = %#v", response)
			}
		})
	}
}

func testConsensusProofRequestHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	harness := newConsensusHarnessWithControlHandler(
		t,
		http.HandlerFunc(func(
			_ http.ResponseWriter,
			request *http.Request,
		) {
			close(started)
			<-request.Context().Done()
		}),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := harness.client.RequestConsensusProof(
			ctx,
			harness.serverID,
			[]byte(`{"mode":"staging_apply"}`),
		)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(consensusTestTimeout):
		t.Fatal("proof handler did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RequestConsensusProof() error = %v", err)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatal("canceled proof request did not return")
	}
}

func testConsensusProofDenialClosesActiveStreamsWithoutDeadlock(
	t *testing.T,
) {
	harness := newConsensusHarness(t)
	outbound, err := harness.client.Dial(
		raft.ServerAddress(harness.serverID),
		consensusTestTimeout,
	)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	outboundStream, ok := outbound.(*consensusStreamConn)
	if !ok {
		t.Fatalf("Dial() type = %T", outbound)
	}
	inbound := acceptConsensusStream(t, harness.server)
	t.Cleanup(func() {
		_ = outbound.Close()
		_ = inbound.Close()
	})

	peer, err := harness.client.peer(harness.serverID)
	if err != nil {
		t.Fatalf("peer(): %v", err)
	}
	harness.clientAllowed.Store(harness.serverID, false)
	result := make(chan error, 1)
	go func() {
		_, err := harness.client.beginConsensusControlRequest(
			t.Context(),
			peer,
			harness.serverID,
			true,
		)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrConsensusPeerDenied) {
			t.Fatalf("beginConsensusControlRequest() error = %v", err)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatal("authorization denial deadlocked while closing active streams")
	}
	select {
	case <-outboundStream.done:
	case <-time.After(consensusTestTimeout):
		t.Fatal("authorization denial left the outbound stream open")
	}
}
