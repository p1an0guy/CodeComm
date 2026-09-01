package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coordstatus "github.com/ijonahch/codecomm/internal/status"
)

type networkStatusSourceStub struct {
	StatusSource
	network NetworkStatus
	err     error
}

func (source *networkStatusSourceStub) NetworkStatus(
	context.Context,
) (NetworkStatus, error) {
	return source.network, source.err
}

func TestOperatorStatusIncludesLocalNetworkState(t *testing.T) {
	detail := "multicast refresh failed"
	source := &networkStatusSourceStub{
		StatusSource: statusSourceFunc(
			func(context.Context) (coordstatus.Snapshot, error) {
				return uiTestStatusSnapshot(t), nil
			},
		),
		network: NetworkStatus{
			MulticastState:      string(MulticastDegraded),
			MulticastError:      &detail,
			SelectedAddresses:   []string{"192.0.2.10"},
			ManualEndpointCount: 2,
		},
	}
	handler := newOperatorHandler(
		source,
		successfulOperatorSubmitter(),
		testPairingOperator{},
		nil,
		uiTestClientID,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, statusQueryPath, nil),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var snapshot Snapshot
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if snapshot.Validate() != nil ||
		snapshot.Network.MulticastState != string(MulticastDegraded) ||
		snapshot.Network.MulticastError == nil ||
		*snapshot.Network.MulticastError != detail ||
		snapshot.Network.ManualEndpointCount != 2 {
		t.Fatalf("network status = %+v", snapshot.Network)
	}
}

func TestNetworkStatusValidationFailsClosed(t *testing.T) {
	detail := "multicast unavailable"
	valid := []NetworkStatus{
		disabledNetworkStatus(),
		{
			MulticastState:      string(MulticastDisabled),
			SelectedAddresses:   []string{},
			ManualEndpointCount: 2,
		},
		{
			MulticastState:    string(MulticastAvailable),
			SelectedAddresses: []string{"192.0.2.10", "2001:db8::10"},
		},
		{
			MulticastState:    string(MulticastDegraded),
			MulticastError:    &detail,
			SelectedAddresses: []string{},
		},
	}
	for index, status := range valid {
		if err := status.validate(); err != nil {
			t.Fatalf("valid status %d: %v", index, err)
		}
	}

	control := "failed\nretry"
	invalid := []NetworkStatus{
		{},
		{
			MulticastState:    string(MulticastDisabled),
			MulticastError:    &detail,
			SelectedAddresses: []string{},
		},
		{
			MulticastState:    string(MulticastAvailable),
			SelectedAddresses: []string{},
		},
		{
			MulticastState:    string(MulticastDegraded),
			SelectedAddresses: []string{},
		},
		{
			MulticastState:    string(MulticastDegraded),
			MulticastError:    &control,
			SelectedAddresses: []string{},
		},
		{
			MulticastState: string(MulticastAvailable),
			SelectedAddresses: []string{
				"2001:db8::10",
				"192.0.2.10",
			},
		},
		{
			MulticastState:    string(MulticastAvailable),
			SelectedAddresses: []string{"127.0.0.1"},
		},
	}
	for index, status := range invalid {
		if err := status.validate(); err == nil {
			t.Fatalf("invalid status %d was accepted: %+v", index, status)
		}
	}
}

func TestModelRendersMulticastDegradedRecoveryAction(t *testing.T) {
	snapshot := snapshotFromCoordination(uiTestStatusSnapshot(t))
	detail := "join en0: permission denied"
	snapshot.Network = NetworkStatus{
		MulticastState:      string(MulticastDegraded),
		MulticastError:      &detail,
		SelectedAddresses:   []string{"192.0.2.10"},
		ManualEndpointCount: 1,
	}
	model := Model{
		snapshot:    snapshot,
		hasSnapshot: true,
		connection:  ConnectionLive,
		width:       80,
		height:      40,
	}
	view := model.View()
	for _, expected := range []string{
		"Discovery DEGRADED: join en0: permission denied",
		"codecomm peer endpoint add",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("view omitted %q:\n%s", expected, view)
		}
	}
}
