package main

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

type daemonManualEndpointStateStub struct {
	members map[domain.DeviceID]coordstatus.MemberSummary
	records []store.PeerEndpointRecord
}

func (stub *daemonManualEndpointStateStub) MemberStatus(
	_ context.Context,
	deviceID domain.DeviceID,
) (coordstatus.MemberSummary, bool, error) {
	member, found := stub.members[deviceID]
	return member, found, nil
}

func (stub *daemonManualEndpointStateStub) ListManualEndpoints(
	context.Context,
) ([]store.PeerEndpointRecord, error) {
	return append([]store.PeerEndpointRecord(nil), stub.records...), nil
}

func (stub *daemonManualEndpointStateStub) UpsertManualEndpoint(
	_ context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
	observedAt domain.Timestamp,
) error {
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: observedAt,
	}
	if err := record.Validate(); err != nil {
		return err
	}
	for index := range stub.records {
		if stub.records[index].DeviceID == deviceID &&
			stub.records[index].Endpoint == endpoint {
			stub.records[index] = record
			return nil
		}
	}
	stub.records = append(stub.records, record)
	return nil
}

func (stub *daemonManualEndpointStateStub) RemoveManualEndpoint(
	_ context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (bool, error) {
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

type daemonManualEndpointRoutesStub struct {
	calls int
	err   error
}

func (stub *daemonManualEndpointRoutesStub) reconcileManualEndpoints(
	context.Context,
) error {
	stub.calls++
	return stub.err
}

func TestDaemonManualEndpointOperatorPersistsAndReconciles(t *testing.T) {
	localID := domain.DeviceID("cc1" + strings.Repeat("a", 64))
	peerID := domain.DeviceID("cc1" + strings.Repeat("b", 64))
	state := &daemonManualEndpointStateStub{
		members: map[domain.DeviceID]coordstatus.MemberSummary{
			peerID: {
				ID: peerID, Role: device.RoleEditor,
				Status: device.StatusActive, EntityVersion: 1,
			},
		},
		records: []store.PeerEndpointRecord{},
	}
	routes := &daemonManualEndpointRoutesStub{}
	now := time.Date(2026, 9, 1, 12, 34, 56, 123, time.UTC)
	operator, err := newDaemonManualEndpointOperator(
		localID,
		state,
		routes,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("newDaemonManualEndpointOperator(): %v", err)
	}
	address := netip.MustParseAddrPort("192.0.2.77:47831")
	added, err := operator.AddManualEndpoint(
		t.Context(),
		peerID,
		address,
	)
	if err != nil ||
		added.DeviceID != peerID ||
		added.Endpoint != address ||
		added.ObservedAt !=
			domain.Timestamp(now.Format(time.RFC3339Nano)) ||
		routes.calls != 1 {
		t.Fatalf("add = (%+v, %v), route calls %d", added, err, routes.calls)
	}
	listed, err := operator.ListManualEndpoints(t.Context())
	if err != nil ||
		!reflect.DeepEqual(listed, []store.PeerEndpointRecord{added}) {
		t.Fatalf("list = (%+v, %v)", listed, err)
	}
	removed, err := operator.RemoveManualEndpoint(
		t.Context(),
		peerID,
		address,
	)
	if err != nil || !removed || routes.calls != 2 {
		t.Fatalf("remove = (%t, %v), route calls %d", removed, err, routes.calls)
	}
	removed, err = operator.RemoveManualEndpoint(
		t.Context(),
		peerID,
		address,
	)
	if err != nil || removed || routes.calls != 2 {
		t.Fatalf("remove miss = (%t, %v), route calls %d", removed, err, routes.calls)
	}
}

func TestDaemonManualEndpointOperatorRejectsUnavailablePeers(t *testing.T) {
	localID := domain.DeviceID("cc1" + strings.Repeat("a", 64))
	peerID := domain.DeviceID("cc1" + strings.Repeat("b", 64))
	revokedID := domain.DeviceID("cc1" + strings.Repeat("c", 64))
	state := &daemonManualEndpointStateStub{
		members: map[domain.DeviceID]coordstatus.MemberSummary{
			revokedID: {
				ID: revokedID, Role: device.RoleEditor,
				Status: device.StatusRevoked, EntityVersion: 2,
			},
		},
		records: []store.PeerEndpointRecord{},
	}
	routes := &daemonManualEndpointRoutesStub{}
	operator, err := newDaemonManualEndpointOperator(
		localID,
		state,
		routes,
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonManualEndpointOperator(): %v", err)
	}
	address := netip.MustParseAddrPort("192.0.2.77:47831")
	for _, target := range []domain.DeviceID{peerID, revokedID} {
		if _, err := operator.AddManualEndpoint(
			t.Context(),
			target,
			address,
		); !errors.Is(err, ui.ErrManualEndpointPeerUnavailable) {
			t.Fatalf("add for %s error = %v", target, err)
		}
	}
	if _, err := operator.AddManualEndpoint(
		t.Context(),
		localID,
		address,
	); !errors.Is(err, store.ErrInvalidPeerEndpoint) {
		t.Fatalf("self endpoint error = %v", err)
	}
	if len(state.records) != 0 || routes.calls != 0 {
		t.Fatalf("rejected add changed state: %+v, calls %d", state.records, routes.calls)
	}
}

func TestDaemonManualEndpointOperatorSurfacesRouteFailure(t *testing.T) {
	localID := domain.DeviceID("cc1" + strings.Repeat("a", 64))
	peerID := domain.DeviceID("cc1" + strings.Repeat("b", 64))
	state := &daemonManualEndpointStateStub{
		members: map[domain.DeviceID]coordstatus.MemberSummary{
			peerID: {
				ID: peerID, Role: device.RoleEditor,
				Status: device.StatusActive, EntityVersion: 1,
			},
		},
		records: []store.PeerEndpointRecord{},
	}
	refreshErr := errors.New("route refresh failed")
	routes := &daemonManualEndpointRoutesStub{err: refreshErr}
	operator, err := newDaemonManualEndpointOperator(
		localID,
		state,
		routes,
		time.Now,
	)
	if err != nil {
		t.Fatalf("newDaemonManualEndpointOperator(): %v", err)
	}
	address := netip.MustParseAddrPort("192.0.2.77:47831")
	if _, err := operator.AddManualEndpoint(
		t.Context(),
		peerID,
		address,
	); !errors.Is(err, refreshErr) {
		t.Fatalf("route failure error = %v", err)
	}
	if len(state.records) != 1 || routes.calls != 1 {
		t.Fatalf("durable add after route failure = %+v, calls %d", state.records, routes.calls)
	}
}
