package consensus

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestConsensusStatusServerReturnsOnlyLocalActiveAuthorization(
	t *testing.T,
) {
	fixture, peer, authorization, now :=
		openConsensusStatusServerFixture(t)
	request := httptest.NewRequest(
		http.MethodGet,
		"https://codecomm.peer"+consensusStatusPath,
		nil,
	)
	response := httptest.NewRecorder()
	fixture.node.serveConsensusStatus(response, request, peer)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"status response = (%d, %q, %q)",
			response.Code,
			response.Header().Get("Content-Type"),
			response.Body.String(),
		)
	}
	decoded, err := decodeConsensusStatusResponse(
		response.Body.Bytes(),
		fixture.ownerDeviceID,
		now,
	)
	if err != nil {
		t.Fatalf("decodeConsensusStatusResponse(): %v", err)
	}
	if decoded.SessionID != nodeTestSessionID ||
		decoded.RecoveryGeneration != 0 ||
		decoded.ServerDeviceID != fixture.ownerDeviceID ||
		decoded.LocalTerm < 1 ||
		decoded.LeaderDeviceID == nil ||
		*decoded.LeaderDeviceID != fixture.ownerDeviceID ||
		len(decoded.LeaderEndpointSet) != 0 ||
		decoded.AdvertisementIntervalSeconds !=
			policy.DefaultAdvertisementIntervalSeconds ||
		decoded.QuorumRequired != 1 ||
		decoded.LastRaftAppliedLogIndex == nil ||
		decoded.MembershipAppliedChainIndex != 1 ||
		decoded.RequesterMembership.Device.ID != peer.DeviceID ||
		decoded.RequesterMembership.CurrentCredentialEpoch != 0 ||
		decoded.RequesterCredentialAuthorization != nil ||
		len(decoded.ActiveRoster) != 2 ||
		decoded.GenerationZeroState.SessionID != nodeTestSessionID ||
		decoded.GenerationZeroState.RecoveryGeneration != 0 ||
		decoded.GenerationZeroState.Heads.ChainIndex != 0 ||
		len(decoded.GenerationZeroState.ProjectionRows) == 0 ||
		!credentialRenewalAuthorizationsEqual(
			decoded.ContentCredentialAuthorization,
			authorization,
		) {
		t.Fatalf("status result = %#v", decoded)
	}
}

func TestConsensusStatusServerAllowsActiveNonconfigurationRequester(
	t *testing.T,
) {
	fixture, peer, _, _ := openConsensusStatusServerFixture(t)
	configuration := fixture.node.fsm.committedConfiguration()
	if configuration == nil ||
		configuration.contains(peer.DeviceID) {
		t.Fatal("requester unexpectedly belongs to live Raft configuration")
	}
	status, _, err := fixture.node.consensusStatusResult(
		t.Context(),
		peer,
	)
	if err != nil {
		t.Fatalf("consensusStatusResult(): %v", err)
	}
	if status.ServerDeviceID != fixture.ownerDeviceID {
		t.Fatalf("status server = %s", status.ServerDeviceID)
	}

	peer.SessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-1123456789ab",
	)
	if _, _, err := fixture.node.consensusStatusResult(
		t.Context(),
		peer,
	); !errors.Is(err, errConsensusStatusDenied) {
		t.Fatalf("wrong-lineage requester error = %v", err)
	}
}

func TestConsensusStatusServerRefusesExpiredOrNonvoterState(
	t *testing.T,
) {
	fixture, peer, authorization, now :=
		openConsensusStatusServerFixture(t)
	fixture.node.credentialEndorsementNow = func() time.Time {
		return now.Add(
			time.Duration(authorization.ValiditySeconds) * time.Second,
		)
	}
	if _, _, err := fixture.node.consensusStatusResult(
		t.Context(),
		peer,
	); !errors.Is(err, ErrConsensusAuthorizationUnavailable) {
		t.Fatalf("expired status error = %v", err)
	}

	localID := fixture.ownerDeviceID
	configuration := &committedRaftConfiguration{
		Index: 1,
		Configuration: raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Nonvoter,
			ID:       raft.ServerID(localID),
			Address:  raft.ServerAddress(localID),
		}}},
	}
	if _, _, err := consensusStatusConfiguration(
		configuration,
		localID,
		"",
		"",
	); !errors.Is(err, ErrConsensusAuthorizationUnavailable) {
		t.Fatalf("nonvoter status error = %v", err)
	}
}

func TestConsensusStatusHTTPShapeIsClosed(t *testing.T) {
	t.Parallel()

	valid := func() *http.Request {
		return httptest.NewRequest(
			http.MethodGet,
			"https://codecomm.peer"+consensusStatusPath,
			nil,
		)
	}
	if err := validateConsensusStatusHTTPRequest(valid()); err != nil {
		t.Fatalf("valid status request: %v", err)
	}
	tests := map[string]func(*http.Request){
		"wrong method": func(request *http.Request) {
			request.Method = http.MethodPost
		},
		"query": func(request *http.Request) {
			request.URL.RawQuery = "detail=full"
		},
		"force query": func(request *http.Request) {
			request.URL.ForceQuery = true
		},
		"media type": func(request *http.Request) {
			request.Header.Set("Content-Type", "application/json")
		},
		"content encoding": func(request *http.Request) {
			request.Header.Set("Content-Encoding", "gzip")
		},
		"transfer encoding": func(request *http.Request) {
			request.TransferEncoding = []string{"chunked"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := valid()
			mutate(request)
			if err := validateConsensusStatusHTTPRequest(request); err == nil {
				t.Fatal("invalid status request was accepted")
			}
		})
	}
	withBody := httptest.NewRequest(
		http.MethodGet,
		"https://codecomm.peer"+consensusStatusPath,
		strings.NewReader("{}"),
	)
	if err := validateConsensusStatusHTTPRequest(
		withBody,
	); !errors.Is(err, errConsensusStatusRequestBody) {
		t.Fatalf("body error = %v", err)
	}

	for _, test := range []struct {
		name    string
		request *http.Request
		status  int
	}{
		{
			name: "body",
			request: httptest.NewRequest(
				http.MethodGet,
				"https://codecomm.peer"+consensusStatusPath,
				strings.NewReader("{}"),
			),
			status: http.StatusBadRequest,
		},
		{
			name: "media type",
			request: func() *http.Request {
				request := valid()
				request.Header.Set("Content-Type", "application/json")
				return request
			}(),
			status: http.StatusUnsupportedMediaType,
		},
	} {
		t.Run("response "+test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			(*SingleNode)(nil).serveConsensusStatus(
				response,
				test.request,
				transport.AuthenticatedPeer{},
			)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if canonical := canonicalConsensusStatusTestJSONFromBytes(
				t,
				response.Body.Bytes(),
			); string(canonical) != response.Body.String() {
				t.Fatalf("problem response is not canonical: %s", response.Body.Bytes())
			}
		})
	}
}

func TestConsensusControlRouteDispatchesStatusOnlyAsBodylessGET(
	t *testing.T,
) {
	t.Parallel()

	for name, test := range map[string]struct {
		method string
		target string
		valid  bool
	}{
		"status": {
			method: http.MethodGet,
			target: consensusStatusPath,
			valid:  true,
		},
		"wrong method": {
			method: http.MethodPost,
			target: consensusStatusPath,
		},
		"query": {
			method: http.MethodGet,
			target: consensusStatusPath + "?all=true",
		},
		"proof remains post": {
			method: http.MethodPost,
			target: consensusProofPath,
			valid:  true,
		},
		"proof get rejected": {
			method: http.MethodGet,
			target: consensusProofPath,
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(
				test.method,
				"https://codecomm.peer"+test.target,
				nil,
			)
			route, ok := consensusControlRouteForRequest(request)
			if ok != test.valid {
				t.Fatalf("route = (%d, %t), want valid %t", route, ok, test.valid)
			}
			if test.valid &&
				test.target == consensusStatusPath &&
				route != consensusControlRouteStatus {
				t.Fatalf("status route = %d", route)
			}
		})
	}
}

func openConsensusStatusServerFixture(
	t *testing.T,
) (
	peerAdmissionTestFixture,
	transport.AuthenticatedPeer,
	credentialauthorization.Authorization,
	time.Time,
) {
	t.Helper()
	fixture := openPeerAdmissionTestNode(t)
	signed, authorization, epochPrivate :=
		nodeTestCredentialAuthorizationEvent(
			t,
			fixture,
			fixture.ownerDeviceID,
			fixture.ownerIdentityPrivate,
			0xe1,
			nodeTestEventID1,
			1,
			1,
		)
	t.Cleanup(func() { clear(epochPrivate) })
	if _, err := fixture.node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(credential authorization): %v", err)
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		t.Fatal(err)
	}
	now := notBefore.Add(time.Minute)
	fixture.node.credentialEndorsementNow = func() time.Time {
		return now
	}
	return fixture, transport.AuthenticatedPeer{
		Plane:              transport.PlaneConsensus,
		SessionID:          nodeTestSessionID,
		DeviceID:           fixture.peerDeviceID,
		RecoveryGeneration: 0,
	}, authorization, now
}

func canonicalConsensusStatusTestJSONFromBytes(
	t testing.TB,
	encoded []byte,
) []byte {
	t.Helper()
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return canonicalConsensusStatusTestJSON(t, value)
}
