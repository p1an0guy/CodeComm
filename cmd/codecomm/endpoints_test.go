package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

var (
	cliEndpointDeviceA = domain.DeviceID(
		"cc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	cliEndpointDeviceB = domain.DeviceID(
		"cc1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	cliEndpointObservedAt = domain.Timestamp("2026-09-01T12:34:56Z")
)

type cliManualEndpointCall struct {
	deviceID domain.DeviceID
	endpoint netip.AddrPort
}

type cliManualEndpointOperator struct {
	mu sync.Mutex

	records     []store.PeerEndpointRecord
	listCalls   int
	addCalls    []cliManualEndpointCall
	removeCalls []cliManualEndpointCall
}

func (operator *cliManualEndpointOperator) ListManualEndpoints(
	ctx context.Context,
) ([]store.PeerEndpointRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.listCalls++
	result := append([]store.PeerEndpointRecord(nil), operator.records...)
	return result, nil
}

func (operator *cliManualEndpointOperator) AddManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (store.PeerEndpointRecord, error) {
	if err := ctx.Err(); err != nil {
		return store.PeerEndpointRecord{}, err
	}
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: cliEndpointObservedAt,
	}
	if err := record.Validate(); err != nil {
		return store.PeerEndpointRecord{}, err
	}

	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.addCalls = append(operator.addCalls, cliManualEndpointCall{
		deviceID: deviceID,
		endpoint: endpoint,
	})
	for index := range operator.records {
		if operator.records[index].DeviceID == deviceID &&
			operator.records[index].Endpoint == endpoint {
			operator.records[index] = record
			operator.sortRecords()
			return record, nil
		}
	}
	operator.records = append(operator.records, record)
	operator.sortRecords()
	return record, nil
}

func (operator *cliManualEndpointOperator) RemoveManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: cliEndpointObservedAt,
	}
	if err := record.Validate(); err != nil {
		return false, err
	}

	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.removeCalls = append(
		operator.removeCalls,
		cliManualEndpointCall{deviceID: deviceID, endpoint: endpoint},
	)
	for index := range operator.records {
		if operator.records[index].DeviceID != deviceID ||
			operator.records[index].Endpoint != endpoint {
			continue
		}
		operator.records = append(
			operator.records[:index],
			operator.records[index+1:]...,
		)
		return true, nil
	}
	return false, nil
}

func (operator *cliManualEndpointOperator) sortRecords() {
	sort.Slice(operator.records, func(left, right int) bool {
		if operator.records[left].DeviceID != operator.records[right].DeviceID {
			return operator.records[left].DeviceID <
				operator.records[right].DeviceID
		}
		return operator.records[left].Endpoint.Compare(
			operator.records[right].Endpoint,
		) < 0
	})
}

func TestPeerEndpointCLIAddListFilterAndRemoveJSON(t *testing.T) {
	operator := &cliManualEndpointOperator{}
	endpoint := startCLIManualEndpointServer(t, operator)
	common := cliPairingLocalFlags(endpoint)
	ipv4 := netip.MustParseAddrPort("192.0.2.44:47831")
	ipv6 := netip.MustParseAddrPort("[2001:db8::44]:47832")

	for _, test := range []struct {
		name     string
		deviceID domain.DeviceID
		address  netip.AddrPort
	}{
		{
			name:     "canonical IPv4",
			deviceID: cliEndpointDeviceB,
			address:  ipv4,
		},
		{
			name:     "canonical IPv6",
			deviceID: cliEndpointDeviceA,
			address:  ipv6,
		},
	} {
		t.Run("add "+test.name, func(t *testing.T) {
			output := runCLIManualEndpointCommand(
				t,
				manualEndpointCLIArgs(
					[]string{"peer", "endpoint", "add"},
					common,
					"--device", string(test.deviceID),
					"--address", test.address.String(),
				),
			)
			var added ui.ManualEndpointStatus
			decodeCLIManualEndpointJSON(t, output, &added)
			if added != (ui.ManualEndpointStatus{
				DeviceID:   string(test.deviceID),
				Endpoint:   test.address.String(),
				ObservedAt: string(cliEndpointObservedAt),
			}) {
				t.Fatalf("add result = %#v", added)
			}
		})
	}

	output := runCLIManualEndpointCommand(
		t,
		manualEndpointCLIArgs(
			[]string{"peer", "endpoint", "list"},
			common,
		),
	)
	var listed ui.ManualEndpointList
	decodeCLIManualEndpointJSON(t, output, &listed)
	wantAll := []ui.ManualEndpointStatus{
		{
			DeviceID: string(cliEndpointDeviceA), Endpoint: ipv6.String(),
			ObservedAt: string(cliEndpointObservedAt),
		},
		{
			DeviceID: string(cliEndpointDeviceB), Endpoint: ipv4.String(),
			ObservedAt: string(cliEndpointObservedAt),
		},
	}
	if !reflect.DeepEqual(listed.Endpoints, wantAll) {
		t.Fatalf("list result = %#v, want %#v", listed.Endpoints, wantAll)
	}

	output = runCLIManualEndpointCommand(
		t,
		manualEndpointCLIArgs(
			[]string{"peer", "endpoint", "list"},
			common,
			"--device", string(cliEndpointDeviceB),
		),
	)
	var filtered ui.ManualEndpointList
	decodeCLIManualEndpointJSON(t, output, &filtered)
	if !reflect.DeepEqual(
		filtered.Endpoints,
		[]ui.ManualEndpointStatus{wantAll[1]},
	) {
		t.Fatalf("filtered list result = %#v", filtered.Endpoints)
	}

	removeArgs := manualEndpointCLIArgs(
		[]string{"peer", "endpoint", "remove"},
		common,
		"--device", string(cliEndpointDeviceA),
		"--address", ipv6.String(),
	)
	output = runCLIManualEndpointCommand(t, removeArgs)
	var removed ui.ManualEndpointRemoval
	decodeCLIManualEndpointJSON(t, output, &removed)
	if removed != (ui.ManualEndpointRemoval{
		DeviceID: string(cliEndpointDeviceA),
		Endpoint: ipv6.String(),
		Removed:  true,
	}) {
		t.Fatalf("remove result = %#v", removed)
	}

	output = runCLIManualEndpointCommand(t, removeArgs)
	decodeCLIManualEndpointJSON(t, output, &removed)
	if removed.Removed {
		t.Fatalf("idempotent remove result = %#v", removed)
	}

	operator.mu.Lock()
	defer operator.mu.Unlock()
	if operator.listCalls != 2 ||
		!reflect.DeepEqual(operator.addCalls, []cliManualEndpointCall{
			{deviceID: cliEndpointDeviceB, endpoint: ipv4},
			{deviceID: cliEndpointDeviceA, endpoint: ipv6},
		}) ||
		!reflect.DeepEqual(operator.removeCalls, []cliManualEndpointCall{
			{deviceID: cliEndpointDeviceA, endpoint: ipv6},
			{deviceID: cliEndpointDeviceA, endpoint: ipv6},
		}) {
		t.Fatalf(
			"operator calls = lists %d, adds %#v, removes %#v",
			operator.listCalls,
			operator.addCalls,
			operator.removeCalls,
		)
	}
}

func TestPeerEndpointCLIRejectsInvalidVerbsFlagsAndInputs(t *testing.T) {
	common := cliPairingLocalFlags(cliPairingTestEndpoint(t))
	validAdd := []string{
		"--device", string(cliEndpointDeviceA),
		"--address", "192.0.2.44:47831",
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing verb", args: []string{"peer", "endpoint"}},
		{name: "unknown verb", args: []string{"peer", "endpoint", "show"}},
		{
			name: "add unknown flag",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--unknown",
			),
		},
		{
			name: "list unknown flag",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "list"},
				common,
				"--address", "192.0.2.44:47831",
			),
		},
		{
			name: "remove unknown flag",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "remove"},
				common,
				"--unknown",
			),
		},
		{
			name: "add positional",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				append(validAdd, "extra")...,
			),
		},
		{
			name: "list positional",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "list"},
				common,
				"extra",
			),
		},
		{
			name: "remove positional",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "remove"},
				common,
				append(validAdd, "extra")...,
			),
		},
		{
			name: "add missing device",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--address", "192.0.2.44:47831",
			),
		},
		{
			name: "add missing address",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--device", string(cliEndpointDeviceA),
			),
		},
		{
			name: "add invalid device ID",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--device", "cc1invalid",
				"--address", "192.0.2.44:47831",
			),
		},
		{
			name: "list invalid device ID",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "list"},
				common,
				"--device", "cc1invalid",
			),
		},
		{
			name: "remove invalid device ID",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "remove"},
				common,
				"--device", "cc1invalid",
				"--address", "192.0.2.44:47831",
			),
		},
		{
			name: "add hostname",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--device", string(cliEndpointDeviceA),
				"--address", "peer.example:47831",
			),
		},
		{
			name: "remove address without port",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "remove"},
				common,
				"--device", string(cliEndpointDeviceA),
				"--address", "192.0.2.44",
			),
		},
		{
			name: "add unbracketed IPv6",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--device", string(cliEndpointDeviceA),
				"--address", "2001:db8::44:47831",
			),
		},
		{
			name: "add noncanonical IPv6",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "add"},
				common,
				"--device", string(cliEndpointDeviceA),
				"--address", "[2001:0db8:0:0:0:0:0:44]:47831",
			),
		},
		{
			name: "remove noncanonical IPv4",
			args: manualEndpointCLIArgs(
				[]string{"peer", "endpoint", "remove"},
				common,
				"--device", string(cliEndpointDeviceA),
				"--address", "192.0.2.044:47831",
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			err := runCLI(
				t.Context(),
				test.args,
				strings.NewReader(""),
				&output,
				&errorOutput,
			)
			if !errors.Is(err, errInvalidCLI) {
				t.Fatalf(
					"runCLI(%q) error = %v, want %v; stderr = %q",
					test.args,
					err,
					errInvalidCLI,
					errorOutput.String(),
				)
			}
			if output.Len() != 0 {
				t.Fatalf("runCLI(%q) output = %q", test.args, output.String())
			}
		})
	}
}

func TestPeerEndpointCLIRejectsInvalidAddressSemantics(t *testing.T) {
	operator := &cliManualEndpointOperator{}
	endpoint := startCLIManualEndpointServer(t, operator)
	common := cliPairingLocalFlags(endpoint)
	for _, address := range []string{
		"127.0.0.1:47831",
		"0.0.0.0:47831",
		"[::1]:47831",
		"[ff02::1]:47831",
		"192.0.2.44:0",
	} {
		t.Run(address, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			err := runCLI(
				t.Context(),
				manualEndpointCLIArgs(
					[]string{"peer", "endpoint", "add"},
					common,
					"--device", string(cliEndpointDeviceA),
					"--address", address,
				),
				strings.NewReader(""),
				&output,
				&errorOutput,
			)
			if err == nil {
				t.Fatalf("invalid endpoint %q was accepted", address)
			}
			if output.Len() != 0 {
				t.Fatalf("invalid endpoint %q output = %q", address, output.String())
			}
		})
	}

	operator.mu.Lock()
	defer operator.mu.Unlock()
	if len(operator.records) != 0 || len(operator.addCalls) != 0 {
		t.Fatalf(
			"invalid addresses mutated operator: records %#v, calls %#v",
			operator.records,
			operator.addCalls,
		)
	}
}

func TestPeerEndpointCLIReportsUnavailableOperatorService(t *testing.T) {
	endpoint := startCLIManualEndpointServer(t, nil)
	common := cliPairingLocalFlags(endpoint)
	for _, test := range []struct {
		name string
		args []string
	}{
		{
			name: "add",
			args: []string{
				"--device", string(cliEndpointDeviceA),
				"--address", "192.0.2.44:47831",
			},
		},
		{name: "list"},
		{
			name: "remove",
			args: []string{
				"--device", string(cliEndpointDeviceA),
				"--address", "192.0.2.44:47831",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			err := runCLI(
				t.Context(),
				manualEndpointCLIArgs(
					[]string{"peer", "endpoint", test.name},
					common,
					test.args...,
				),
				strings.NewReader(""),
				&output,
				&errorOutput,
			)
			var clientError *ipc.ClientError
			if !errors.As(err, &clientError) ||
				clientError.Status != http.StatusServiceUnavailable ||
				clientError.Code != "manual_endpoints_unavailable" {
				t.Fatalf(
					"unavailable %s error = %v, want HTTP 503 manual_endpoints_unavailable",
					test.name,
					err,
				)
			}
			if output.Len() != 0 {
				t.Fatalf("unavailable %s output = %q", test.name, output.String())
			}
		})
	}
}

func startCLIManualEndpointServer(
	t *testing.T,
	endpoints ui.ManualEndpointOperator,
) ipc.Endpoint {
	t.Helper()
	operator, _, _, _ := newCLIPairingFixture(t)
	endpoint := cliPairingTestEndpoint(t)
	service, err := ui.NewOperatorService(ui.OperatorServiceOptions{
		Source: cliStatusSourceFunc(func(context.Context) (
			coordstatus.Snapshot,
			error,
		) {
			return operator.status, nil
		}),
		Submitter:   operator.submitter,
		Pairing:     operator,
		Endpoints:   endpoints,
		SessionID:   cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID,
	})
	if err != nil {
		t.Fatalf("ui.NewOperatorService(): %v", err)
	}
	server, err := ipc.NewServer(ipc.Config{
		Endpoint:    endpoint,
		SessionID:   cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID,
		Binder:      service,
	})
	if err != nil {
		t.Fatalf("ipc.NewServer(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			3*time.Second,
		)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown(): %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("server did not stop: %v", shutdownContext.Err())
		}
	})
	return endpoint
}

func runCLIManualEndpointCommand(t *testing.T, args []string) string {
	t.Helper()
	var output, errorOutput bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runCLI(
		ctx,
		args,
		strings.NewReader(""),
		&output,
		&errorOutput,
	); err != nil {
		t.Fatalf("runCLI(%q): %v; stderr = %q", args, err, errorOutput.String())
	}
	return output.String()
}

func manualEndpointCLIArgs(
	command []string,
	common []string,
	extra ...string,
) []string {
	result := append([]string(nil), command...)
	result = append(result, common...)
	return append(result, extra...)
}

func decodeCLIManualEndpointJSON(
	t *testing.T,
	output string,
	target any,
) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %q: %v", output, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("output contains trailing JSON: %q", output)
	}
}
