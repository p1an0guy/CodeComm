package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

var errDaemonManualEndpoints = errors.New(
	"codecommd: manual endpoint management unavailable",
)

type daemonManualEndpointState interface {
	MemberStatus(
		context.Context,
		domain.DeviceID,
	) (coordstatus.MemberSummary, bool, error)
	ListManualEndpoints(
		context.Context,
	) ([]store.PeerEndpointRecord, error)
	UpsertManualEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
		domain.Timestamp,
	) error
	RemoveManualEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
	) (bool, error)
}

type daemonManualEndpointRoutes interface {
	reconcileManualEndpoints(context.Context) error
}

type daemonManualEndpointOperator struct {
	localDeviceID domain.DeviceID
	state         daemonManualEndpointState
	routes        daemonManualEndpointRoutes
	now           func() time.Time
}

func newDaemonManualEndpointOperator(
	localDeviceID domain.DeviceID,
	state daemonManualEndpointState,
	routes daemonManualEndpointRoutes,
	now func() time.Time,
) (*daemonManualEndpointOperator, error) {
	if !localDeviceID.Valid() ||
		state == nil ||
		routes == nil ||
		now == nil {
		return nil, errDaemonManualEndpoints
	}
	return &daemonManualEndpointOperator{
		localDeviceID: localDeviceID,
		state:         state,
		routes:        routes,
		now:           now,
	}, nil
}

func (operator *daemonManualEndpointOperator) ListManualEndpoints(
	ctx context.Context,
) ([]store.PeerEndpointRecord, error) {
	if operator == nil || operator.state == nil || ctx == nil {
		return nil, errDaemonManualEndpoints
	}
	return operator.state.ListManualEndpoints(ctx)
}

func (operator *daemonManualEndpointOperator) AddManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (store.PeerEndpointRecord, error) {
	if operator == nil ||
		operator.state == nil ||
		operator.routes == nil ||
		operator.now == nil ||
		ctx == nil ||
		!deviceID.Valid() ||
		deviceID == operator.localDeviceID {
		return store.PeerEndpointRecord{}, store.ErrInvalidPeerEndpoint
	}
	member, found, err := operator.state.MemberStatus(ctx, deviceID)
	if err != nil {
		return store.PeerEndpointRecord{}, err
	}
	if !found || member.ID != deviceID || member.Status != device.StatusActive {
		return store.PeerEndpointRecord{}, ui.ErrManualEndpointPeerUnavailable
	}
	observedAt := domain.Timestamp(
		operator.now().UTC().Format(time.RFC3339Nano),
	)
	if !observedAt.Valid() {
		return store.PeerEndpointRecord{}, errDaemonManualEndpoints
	}
	if err := operator.state.UpsertManualEndpoint(
		ctx,
		deviceID,
		endpoint,
		observedAt,
	); err != nil {
		return store.PeerEndpointRecord{}, err
	}
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: observedAt,
	}
	if err := record.Validate(); err != nil {
		return store.PeerEndpointRecord{}, err
	}
	if err := operator.routes.reconcileManualEndpoints(ctx); err != nil {
		return store.PeerEndpointRecord{}, err
	}
	return record, nil
}

func (operator *daemonManualEndpointOperator) RemoveManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (bool, error) {
	if operator == nil ||
		operator.state == nil ||
		operator.routes == nil ||
		ctx == nil {
		return false, errDaemonManualEndpoints
	}
	removed, err := operator.state.RemoveManualEndpoint(
		ctx,
		deviceID,
		endpoint,
	)
	if err != nil || !removed {
		return removed, err
	}
	if err := operator.routes.reconcileManualEndpoints(ctx); err != nil {
		return false, err
	}
	return true, nil
}

var _ ui.ManualEndpointOperator = (*daemonManualEndpointOperator)(nil)
