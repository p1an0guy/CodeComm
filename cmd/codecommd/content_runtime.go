package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonContentConstruction = errors.New(
	"codecommd: content service construction failed",
)

type daemonContentState interface {
	StatusSnapshot(
		context.Context,
		domain.DeviceID,
		int,
	) (coordstatus.DurableSnapshot, error)
	ListMemberSignedEndpointSets(
		context.Context,
		domain.Timestamp,
	) ([]store.MemberSignedEndpointSet, error)
}

type daemonEndpointSetSource interface {
	CurrentEndpointSet() ([]byte, time.Duration, bool)
}

type daemonContentService struct {
	sessionID     domain.UUIDv7
	workspaceID   domain.UUIDv4
	localDeviceID domain.DeviceID
	state         daemonContentState
	endpoints     daemonEndpointSetSource
	now           func() time.Time
}

func newDaemonContentServer(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	localDeviceID domain.DeviceID,
	state daemonContentState,
	endpoints daemonEndpointSetSource,
) (*contenthttp.Server, error) {
	service, err := newDaemonContentService(
		sessionID,
		workspaceID,
		localDeviceID,
		state,
		endpoints,
		time.Now,
	)
	if err != nil {
		return nil, err
	}
	server, err := contenthttp.New(service)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: HTTP server: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	return server, nil
}

func newDaemonContentService(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	localDeviceID domain.DeviceID,
	state daemonContentState,
	endpoints daemonEndpointSetSource,
	now func() time.Time,
) (*daemonContentService, error) {
	if !sessionID.Valid() ||
		!workspaceID.Valid() ||
		!localDeviceID.Valid() ||
		state == nil ||
		endpoints == nil ||
		now == nil {
		return nil, errDaemonContentConstruction
	}
	return &daemonContentService{
		sessionID:     sessionID,
		workspaceID:   workspaceID,
		localDeviceID: localDeviceID,
		state:         state,
		endpoints:     endpoints,
		now:           now,
	}, nil
}

func (service *daemonContentService) Session(
	ctx context.Context,
) (contenthttp.SessionResponse, error) {
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return contenthttp.SessionResponse{}, err
	}
	response, err := contenthttp.NewSessionResponse(
		contenthttp.SessionResponseInput{
			SessionID:            snapshot.SessionID,
			WorkspaceID:          snapshot.WorkspaceID,
			RecoveryGeneration:   snapshot.RecoveryGeneration,
			ServerDeviceID:       service.localDeviceID,
			DaemonVersion:        snapshot.Member.DaemonVersion,
			MaxApplyLevel:        snapshot.Member.MaxApplyLevel,
			RequiredCapabilities: []string{},
		},
	)
	if err != nil {
		return contenthttp.SessionResponse{}, fmt.Errorf(
			"%w: session response: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	return response, nil
}

func (service *daemonContentService) Peers(
	ctx context.Context,
) (contenthttp.PeersResponse, error) {
	snapshot, err := service.snapshot(ctx)
	if err != nil {
		return contenthttp.PeersResponse{}, err
	}
	now := service.now().UTC()
	if now.IsZero() {
		return contenthttp.PeersResponse{}, errDaemonContentConstruction
	}
	nowValue := domain.Timestamp(now.Format(time.RFC3339Nano))
	if !nowValue.Valid() {
		return contenthttp.PeersResponse{}, errDaemonContentConstruction
	}
	remoteSets, err := service.state.ListMemberSignedEndpointSets(
		ctx,
		nowValue,
	)
	if err != nil {
		return contenthttp.PeersResponse{}, fmt.Errorf(
			"%w: list endpoint sets: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	localSet, advertisementInterval, found :=
		service.endpoints.CurrentEndpointSet()
	if !found || len(localSet) == 0 || advertisementInterval <= 0 {
		return contenthttp.PeersResponse{}, fmt.Errorf(
			"%w: local endpoint set unavailable",
			errDaemonContentConstruction,
		)
	}
	verifiedLocalSet, err := discovery.ValidateEndpointSet(
		localSet,
		discovery.EndpointSetExpectation{
			SessionID:             snapshot.SessionID,
			WorkspaceID:           snapshot.WorkspaceID,
			RecoveryGeneration:    snapshot.RecoveryGeneration,
			Member:                snapshot.Member,
			AdvertisementInterval: advertisementInterval,
			Now:                   now,
		},
	)
	if err != nil {
		return contenthttp.PeersResponse{}, fmt.Errorf(
			"%w: local endpoint set: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	localSet = verifiedLocalSet.CanonicalBytes()

	relayed := make(map[domain.DeviceID][]byte, len(remoteSets))
	var previous domain.DeviceID
	for index, endpointSet := range remoteSets {
		if !endpointSet.DeviceID.Valid() ||
			len(endpointSet.EndpointSetJSON) == 0 ||
			index > 0 && previous >= endpointSet.DeviceID {
			return contenthttp.PeersResponse{}, fmt.Errorf(
				"%w: invalid endpoint-set snapshot",
				errDaemonContentConstruction,
			)
		}
		previous = endpointSet.DeviceID
		relayed[endpointSet.DeviceID] = endpointSet.EndpointSetJSON
	}

	members := make([]contenthttp.PeerMember, len(snapshot.Members))
	localFound := false
	for index, member := range snapshot.Members {
		var endpointSet []byte
		switch {
		case member.ID == service.localDeviceID:
			if member.Status != device.StatusActive {
				return contenthttp.PeersResponse{}, fmt.Errorf(
					"%w: local member is inactive",
					errDaemonContentConstruction,
				)
			}
			localFound = true
			endpointSet = localSet
		case member.Status == device.StatusActive:
			endpointSet = relayed[member.ID]
		}
		value, err := contenthttp.NewPeerMember(
			contenthttp.PeerMemberInput{
				DeviceID:      member.ID,
				Role:          member.Role,
				Status:        member.Status,
				EntityVersion: member.EntityVersion,
				EndpointSet:   endpointSet,
			},
		)
		if err != nil {
			return contenthttp.PeersResponse{}, fmt.Errorf(
				"%w: member %s: %v",
				errDaemonContentConstruction,
				member.ID,
				err,
			)
		}
		members[index] = value
	}
	if !localFound {
		return contenthttp.PeersResponse{}, fmt.Errorf(
			"%w: local member absent from roster",
			errDaemonContentConstruction,
		)
	}
	response, err := contenthttp.NewPeersResponse(
		contenthttp.PeersResponseInput{
			SessionID:          snapshot.SessionID,
			WorkspaceID:        snapshot.WorkspaceID,
			RecoveryGeneration: snapshot.RecoveryGeneration,
			ServerDeviceID:     service.localDeviceID,
			Members:            members,
		},
	)
	if err != nil {
		return contenthttp.PeersResponse{}, fmt.Errorf(
			"%w: peers response: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	return response, nil
}

func (service *daemonContentService) snapshot(
	ctx context.Context,
) (coordstatus.DurableSnapshot, error) {
	if service == nil ||
		service.state == nil ||
		ctx == nil {
		return coordstatus.DurableSnapshot{}, errDaemonContentConstruction
	}
	if err := ctx.Err(); err != nil {
		return coordstatus.DurableSnapshot{}, err
	}
	snapshot, err := service.state.StatusSnapshot(
		ctx,
		service.localDeviceID,
		1,
	)
	if err != nil {
		return coordstatus.DurableSnapshot{}, fmt.Errorf(
			"%w: read applied state: %v",
			errDaemonContentConstruction,
			err,
		)
	}
	if snapshot.SessionID != service.sessionID ||
		snapshot.WorkspaceID != service.workspaceID ||
		snapshot.Member.ID != service.localDeviceID ||
		snapshot.Member.Status != device.StatusActive ||
		snapshot.MembersTruncated ||
		snapshot.MemberTotal != uint64(len(snapshot.Members)) {
		return coordstatus.DurableSnapshot{}, fmt.Errorf(
			"%w: inconsistent applied snapshot",
			errDaemonContentConstruction,
		)
	}
	return snapshot, nil
}

var _ contenthttp.Service = (*daemonContentService)(nil)
