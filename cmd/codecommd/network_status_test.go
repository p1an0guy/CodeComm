package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

type daemonStatusSourceStub struct {
	snapshot coordstatus.Snapshot
	member   coordstatus.MemberSummary
}

func (stub *daemonStatusSourceStub) Status(
	context.Context,
) (coordstatus.Snapshot, error) {
	return stub.snapshot, nil
}

func (stub *daemonStatusSourceStub) Member(
	context.Context,
	domain.DeviceID,
) (coordstatus.MemberSummary, bool, error) {
	return stub.member, stub.member.ID.Valid(), nil
}

type daemonNetworkStatusStateStub struct {
	records []store.PeerEndpointRecord
	err     error
}

func (stub *daemonNetworkStatusStateStub) ListManualEndpoints(
	context.Context,
) ([]store.PeerEndpointRecord, error) {
	return append([]store.PeerEndpointRecord(nil), stub.records...), stub.err
}

func TestDaemonOperatorStatusSourceReportsNetworkModes(t *testing.T) {
	base := &daemonStatusSourceStub{}
	state := &daemonNetworkStatusStateStub{
		records: []store.PeerEndpointRecord{{}, {}},
	}
	disabled, err := newDaemonOperatorStatusSource(base, state, nil)
	if err != nil {
		t.Fatalf("new disabled source: %v", err)
	}
	status, err := disabled.NetworkStatus(t.Context())
	if err != nil ||
		status.MulticastState != string(ui.MulticastDisabled) ||
		status.MulticastError != nil ||
		status.SelectedAddresses == nil ||
		len(status.SelectedAddresses) != 0 ||
		status.ManualEndpointCount != 2 {
		t.Fatalf("disabled network status = (%+v, %v)", status, err)
	}

	local := netip.MustParseAddr("192.0.2.10")
	book := &daemonDiscoveryAddressBook{}
	book.replace(nil, []netip.Addr{local})
	runtime := &daemonDiscoveryRuntime{addresses: book}
	available, err := newDaemonOperatorStatusSource(base, state, runtime)
	if err != nil {
		t.Fatalf("new available source: %v", err)
	}
	status, err = available.NetworkStatus(t.Context())
	if err != nil ||
		status.MulticastState != string(ui.MulticastAvailable) ||
		status.MulticastError != nil ||
		len(status.SelectedAddresses) != 1 ||
		status.SelectedAddresses[0] != local.String() {
		t.Fatalf("available network status = (%+v, %v)", status, err)
	}

	runtime.discoveryErr = errors.New("refresh\nmulticast\tfailed")
	status, err = available.NetworkStatus(t.Context())
	if err != nil ||
		status.MulticastState != string(ui.MulticastDegraded) ||
		status.MulticastError == nil ||
		*status.MulticastError != "refresh multicast failed" {
		t.Fatalf("degraded network status = (%+v, %v)", status, err)
	}
}

func TestDaemonOperatorStatusSourcePropagatesStateFailure(t *testing.T) {
	stateErr := errors.New("endpoint state corrupt")
	source, err := newDaemonOperatorStatusSource(
		&daemonStatusSourceStub{},
		&daemonNetworkStatusStateStub{err: stateErr},
		nil,
	)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	if _, err := source.NetworkStatus(
		t.Context(),
	); !errors.Is(err, stateErr) {
		t.Fatalf("NetworkStatus() error = %v", err)
	}
}

func TestBoundedDaemonNetworkErrorIsSingleLineAndBounded(t *testing.T) {
	value := boundedDaemonNetworkError(errors.New(
		"\n" + strings.Repeat("x", daemonNetworkStatusErrorMaxBytes+100),
	))
	if value == "" ||
		len(value) > daemonNetworkStatusErrorMaxBytes ||
		strings.ContainsAny(value, "\r\n\t") {
		t.Fatalf("bounded error = %q (%d bytes)", value, len(value))
	}
}
