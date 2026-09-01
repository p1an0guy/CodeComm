package ui

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	uiManualEndpointPeerID = domain.DeviceID(
		"cc1" + strings.Repeat("b", 64),
	)
	uiManualEndpointTime = domain.Timestamp("2026-09-01T12:34:56Z")
)

type manualEndpointOperatorStub struct {
	records   []store.PeerEndpointRecord
	listErr   error
	addErr    error
	removeErr error
}

func (stub *manualEndpointOperatorStub) ListManualEndpoints(
	context.Context,
) ([]store.PeerEndpointRecord, error) {
	result := make([]store.PeerEndpointRecord, len(stub.records))
	copy(result, stub.records)
	return result, stub.listErr
}

func (stub *manualEndpointOperatorStub) AddManualEndpoint(
	_ context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (store.PeerEndpointRecord, error) {
	if stub.addErr != nil {
		return store.PeerEndpointRecord{}, stub.addErr
	}
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: uiManualEndpointTime,
	}
	for index := range stub.records {
		if stub.records[index].DeviceID == deviceID &&
			stub.records[index].Endpoint == endpoint {
			stub.records[index] = record
			return record, nil
		}
	}
	stub.records = append(stub.records, record)
	return record, nil
}

func (stub *manualEndpointOperatorStub) RemoveManualEndpoint(
	_ context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (bool, error) {
	if stub.removeErr != nil {
		return false, stub.removeErr
	}
	for index := range stub.records {
		if stub.records[index].DeviceID != deviceID ||
			stub.records[index].Endpoint != endpoint {
			continue
		}
		stub.records = append(
			stub.records[:index],
			stub.records[index+1:]...,
		)
		return true, nil
	}
	return false, nil
}

func TestOperatorClientManagesManualEndpoints(t *testing.T) {
	endpoint := newUIClientTestEndpoint(t)
	operator := &manualEndpointOperatorStub{records: []store.PeerEndpointRecord{}}
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(
			func(context.Context) (coordstatus.Snapshot, error) {
				return uiTestStatusSnapshot(t), nil
			},
		),
		Submitter:   successfulOperatorSubmitter(),
		Pairing:     testPairingOperator{},
		Endpoints:   operator,
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("NewOperatorService(): %v", err)
	}
	server := startUIClientTestServer(t, endpoint, service)
	defer server.stop(t)
	client, err := DialOperator(t.Context(), OperatorDialOptions{
		Endpoint:    endpoint,
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("DialOperator(): %v", err)
	}
	defer func() { _ = client.Close() }()

	empty, err := client.ManualEndpoints(t.Context())
	if err != nil || empty.Endpoints == nil || len(empty.Endpoints) != 0 {
		t.Fatalf("empty endpoints = (%+v, %v)", empty, err)
	}
	address := netip.MustParseAddrPort("192.0.2.44:47831")
	added, err := client.AddManualEndpoint(
		t.Context(),
		uiManualEndpointPeerID,
		address,
	)
	if err != nil ||
		added.DeviceID != string(uiManualEndpointPeerID) ||
		added.Endpoint != address.String() ||
		added.ObservedAt != string(uiManualEndpointTime) {
		t.Fatalf("added endpoint = (%+v, %v)", added, err)
	}
	listed, err := client.ManualEndpoints(t.Context())
	if err != nil ||
		!reflect.DeepEqual(listed.Endpoints, []ManualEndpointStatus{added}) {
		t.Fatalf("listed endpoints = (%+v, %v)", listed, err)
	}
	removed, err := client.RemoveManualEndpoint(
		t.Context(),
		uiManualEndpointPeerID,
		address,
	)
	if err != nil || !removed.Removed {
		t.Fatalf("removed endpoint = (%+v, %v)", removed, err)
	}
	removed, err = client.RemoveManualEndpoint(
		t.Context(),
		uiManualEndpointPeerID,
		address,
	)
	if err != nil || removed.Removed {
		t.Fatalf("idempotent removal = (%+v, %v)", removed, err)
	}
}

func TestManualEndpointOperatorRoutesFailClosed(t *testing.T) {
	operator := &manualEndpointOperatorStub{records: []store.PeerEndpointRecord{}}
	handler := newOperatorHandler(
		statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return uiTestStatusSnapshot(t), nil
		}),
		successfulOperatorSubmitter(),
		testPairingOperator{},
		operator,
		uiTestClientID,
	)
	valid := []byte(
		`{"device_id":"` + string(uiManualEndpointPeerID) +
			`","endpoint":"192.0.2.44:47831"}`,
	)
	if _, _, err := decodeManualEndpointRequest(
		httptest.NewRequest(
			http.MethodPost,
			manualEndpointCollectionPath,
			bytes.NewReader(valid),
		),
	); err != nil {
		t.Fatalf("valid manual endpoint fixture: %v", err)
	}
	for _, test := range []struct {
		name   string
		method string
		path   string
		body   []byte
		status int
	}{
		{
			name: "add", method: http.MethodPost,
			path: manualEndpointCollectionPath, body: valid,
			status: http.StatusOK,
		},
		{
			name: "list", method: http.MethodGet,
			path:   manualEndpointCollectionPath,
			status: http.StatusOK,
		},
		{
			name: "remove", method: http.MethodPost,
			path: manualEndpointRemovePath, body: valid,
			status: http.StatusOK,
		},
		{
			name: "extra member", method: http.MethodPost,
			path: manualEndpointCollectionPath,
			body: []byte(
				strings.TrimSuffix(string(valid), "}") +
					`,"extra":true}`,
			),
			status: http.StatusBadRequest,
		},
		{
			name: "hostname", method: http.MethodPost,
			path: manualEndpointCollectionPath,
			body: []byte(
				`{"device_id":"` + string(uiManualEndpointPeerID) +
					`","endpoint":"peer.example:47831"}`,
			),
			status: http.StatusBadRequest,
		},
		{
			name: "encoded path", method: http.MethodGet,
			path:   "/local/v1/peer/%65ndpoints",
			status: http.StatusNotFound,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				test.method,
				test.path,
				bytes.NewReader(test.body),
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf(
					"status = %d, want %d: %s",
					response.Code,
					test.status,
					response.Body.String(),
				)
			}
		})
	}

	unavailable := newOperatorHandler(
		statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return uiTestStatusSnapshot(t), nil
		}),
		successfulOperatorSubmitter(),
		testPairingOperator{},
		nil,
		uiTestClientID,
	)
	response := httptest.NewRecorder()
	unavailable.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodGet,
			manualEndpointCollectionPath,
			nil,
		),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d", response.Code)
	}

	operator.addErr = store.ErrPeerEndpointCapacity
	response = httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			manualEndpointCollectionPath,
			bytes.NewReader(valid),
		),
	)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity status = %d", response.Code)
	}
	operator.addErr = errors.New("route refresh failed")
	response = httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodPost,
			manualEndpointCollectionPath,
			bytes.NewReader(valid),
		),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("route failure status = %d", response.Code)
	}
}
