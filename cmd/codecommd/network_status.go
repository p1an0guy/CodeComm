package main

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

const daemonNetworkStatusErrorMaxBytes = 512

var errDaemonNetworkStatus = errors.New(
	"codecommd: local network status unavailable",
)

type daemonNetworkStatusState interface {
	ListManualEndpoints(
		context.Context,
	) ([]store.PeerEndpointRecord, error)
}

type daemonOperatorStatusSource struct {
	source    ui.StatusSource
	state     daemonNetworkStatusState
	discovery *daemonDiscoveryRuntime
}

func newDaemonOperatorStatusSource(
	source ui.StatusSource,
	state daemonNetworkStatusState,
	discovery *daemonDiscoveryRuntime,
) (*daemonOperatorStatusSource, error) {
	if source == nil || state == nil {
		return nil, errDaemonNetworkStatus
	}
	return &daemonOperatorStatusSource{
		source:    source,
		state:     state,
		discovery: discovery,
	}, nil
}

func (source *daemonOperatorStatusSource) Status(
	ctx context.Context,
) (coordstatus.Snapshot, error) {
	if source == nil || source.source == nil {
		return coordstatus.Snapshot{}, errDaemonNetworkStatus
	}
	return source.source.Status(ctx)
}

func (source *daemonOperatorStatusSource) Member(
	ctx context.Context,
	deviceID domain.DeviceID,
) (coordstatus.MemberSummary, bool, error) {
	if source == nil || source.source == nil {
		return coordstatus.MemberSummary{}, false, errDaemonNetworkStatus
	}
	return source.source.Member(ctx, deviceID)
}

func (source *daemonOperatorStatusSource) NetworkStatus(
	ctx context.Context,
) (ui.NetworkStatus, error) {
	if source == nil || source.state == nil || ctx == nil {
		return ui.NetworkStatus{}, errDaemonNetworkStatus
	}
	manual, err := source.state.ListManualEndpoints(ctx)
	if err != nil {
		return ui.NetworkStatus{}, err
	}
	status := ui.NetworkStatus{
		MulticastState:      string(ui.MulticastDisabled),
		SelectedAddresses:   []string{},
		ManualEndpointCount: uint64(len(manual)),
	}
	if source.discovery == nil {
		return status, nil
	}
	selected := source.discovery.addresses.selected()
	status.SelectedAddresses = make([]string, len(selected))
	for index, address := range selected {
		status.SelectedAddresses[index] = address.String()
	}
	discoveryErr := source.discovery.DiscoveryError()
	if discoveryErr == nil && len(selected) > 0 {
		status.MulticastState = string(ui.MulticastAvailable)
		return status, nil
	}
	status.MulticastState = string(ui.MulticastDegraded)
	detail := "multicast has no selected local address"
	if discoveryErr != nil {
		detail = boundedDaemonNetworkError(discoveryErr)
	}
	status.MulticastError = &detail
	return status, nil
}

func boundedDaemonNetworkError(err error) string {
	if err == nil {
		return "multicast unavailable"
	}
	value := strings.Join(strings.Fields(err.Error()), " ")
	if value == "" {
		return "multicast unavailable"
	}
	if len(value) <= daemonNetworkStatusErrorMaxBytes {
		return value
	}
	end := 0
	for index := range value {
		if index > daemonNetworkStatusErrorMaxBytes {
			break
		}
		end = index
	}
	if end == 0 || !utf8.ValidString(value[:end]) {
		return "multicast unavailable"
	}
	return value[:end]
}

var (
	_ ui.StatusSource        = (*daemonOperatorStatusSource)(nil)
	_ ui.NetworkStatusSource = (*daemonOperatorStatusSource)(nil)
)
