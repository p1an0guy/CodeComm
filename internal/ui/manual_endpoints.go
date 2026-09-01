package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrManualEndpointProtocol = errors.New(
		"ui: invalid manual endpoint protocol response",
	)
	ErrManualEndpointPeerUnavailable = errors.New(
		"ui: manual endpoint peer is unavailable",
	)
)

const manualEndpointValidationTimestamp = domain.Timestamp(
	"2000-01-01T00:00:00Z",
)

// ManualEndpointOperator owns device-local manual peer routing.
type ManualEndpointOperator interface {
	ListManualEndpoints(
		context.Context,
	) ([]store.PeerEndpointRecord, error)
	AddManualEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
	) (store.PeerEndpointRecord, error)
	RemoveManualEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
	) (bool, error)
}

type ManualEndpointStatus struct {
	DeviceID   string `json:"device_id"`
	Endpoint   string `json:"endpoint"`
	ObservedAt string `json:"observed_at"`
}

type ManualEndpointList struct {
	Endpoints []ManualEndpointStatus `json:"endpoints"`
}

type ManualEndpointRemoval struct {
	DeviceID string `json:"device_id"`
	Endpoint string `json:"endpoint"`
	Removed  bool   `json:"removed"`
}

type manualEndpointWire struct {
	DeviceID string `json:"device_id"`
	Endpoint string `json:"endpoint"`
}

func (handler *operatorHandler) listManualEndpoints(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.endpoints == nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"manual_endpoints_unavailable",
		)
		return
	}
	records, err := handler.endpoints.ListManualEndpoints(request.Context())
	if err != nil {
		writeManualEndpointError(writer, err)
		return
	}
	response := ManualEndpointList{
		Endpoints: make([]ManualEndpointStatus, len(records)),
	}
	for index, record := range records {
		status, err := manualEndpointStatus(record)
		if err != nil {
			writeOperatorError(
				writer,
				http.StatusServiceUnavailable,
				"manual_endpoints_unavailable",
			)
			return
		}
		response.Endpoints[index] = status
	}
	if response.validate() != nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"manual_endpoints_unavailable",
		)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) addManualEndpoint(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.endpoints == nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"manual_endpoints_unavailable",
		)
		return
	}
	deviceID, endpoint, err := decodeManualEndpointRequest(request)
	if err != nil {
		writeOperatorError(
			writer,
			http.StatusBadRequest,
			"invalid_manual_endpoint",
		)
		return
	}
	record, err := handler.endpoints.AddManualEndpoint(
		request.Context(),
		deviceID,
		endpoint,
	)
	if err != nil {
		writeManualEndpointError(writer, err)
		return
	}
	response, err := manualEndpointStatus(record)
	if err != nil ||
		response.DeviceID != string(deviceID) ||
		response.Endpoint != endpoint.String() {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"manual_endpoints_unavailable",
		)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) removeManualEndpoint(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.endpoints == nil {
		writeOperatorError(
			writer,
			http.StatusServiceUnavailable,
			"manual_endpoints_unavailable",
		)
		return
	}
	deviceID, endpoint, err := decodeManualEndpointRequest(request)
	if err != nil {
		writeOperatorError(
			writer,
			http.StatusBadRequest,
			"invalid_manual_endpoint",
		)
		return
	}
	removed, err := handler.endpoints.RemoveManualEndpoint(
		request.Context(),
		deviceID,
		endpoint,
	)
	if err != nil {
		writeManualEndpointError(writer, err)
		return
	}
	writeOperatorJSON(writer, http.StatusOK, ManualEndpointRemoval{
		DeviceID: string(deviceID),
		Endpoint: endpoint.String(),
		Removed:  removed,
	})
}

func decodeManualEndpointRequest(
	request *http.Request,
) (domain.DeviceID, netip.AddrPort, error) {
	if request == nil {
		return "", netip.AddrPort{}, store.ErrInvalidPeerEndpoint
	}
	var input manualEndpointWire
	if decodeClosedOperatorBody(
		request.Body,
		&input,
		"device_id",
		"endpoint",
	) != nil {
		return "", netip.AddrPort{}, store.ErrInvalidPeerEndpoint
	}
	deviceID := domain.DeviceID(input.DeviceID)
	endpoint, err := netip.ParseAddrPort(input.Endpoint)
	if err != nil ||
		!deviceID.Valid() ||
		endpoint.String() != input.Endpoint ||
		!validManualEndpointTarget(deviceID, endpoint) {
		return "", netip.AddrPort{}, store.ErrInvalidPeerEndpoint
	}
	return deviceID, endpoint, nil
}

func manualEndpointStatus(
	record store.PeerEndpointRecord,
) (ManualEndpointStatus, error) {
	if record.SourceKind != store.PeerEndpointManual ||
		record.Validate() != nil {
		return ManualEndpointStatus{}, store.ErrPeerEndpointIntegrity
	}
	result := ManualEndpointStatus{
		DeviceID:   string(record.DeviceID),
		Endpoint:   record.Endpoint.String(),
		ObservedAt: string(record.ObservedAt),
	}
	if result.validate() != nil {
		return ManualEndpointStatus{}, store.ErrPeerEndpointIntegrity
	}
	return result, nil
}

func (value ManualEndpointStatus) validate() error {
	deviceID := domain.DeviceID(value.DeviceID)
	endpoint, err := netip.ParseAddrPort(value.Endpoint)
	if err != nil ||
		!deviceID.Valid() ||
		endpoint.String() != value.Endpoint ||
		!domain.Timestamp(value.ObservedAt).Valid() ||
		!validManualEndpointTarget(deviceID, endpoint) {
		return ErrManualEndpointProtocol
	}
	return nil
}

func (value ManualEndpointList) validate() error {
	if value.Endpoints == nil ||
		len(value.Endpoints) > store.ManualEndpointsPerSessionMax {
		return ErrManualEndpointProtocol
	}
	var (
		previousDevice domain.DeviceID
		previous       netip.AddrPort
	)
	for index, endpoint := range value.Endpoints {
		if endpoint.validate() != nil {
			return ErrManualEndpointProtocol
		}
		deviceID := domain.DeviceID(endpoint.DeviceID)
		address, _ := netip.ParseAddrPort(endpoint.Endpoint)
		if index > 0 &&
			(deviceID < previousDevice ||
				deviceID == previousDevice &&
					address.Compare(previous) <= 0) {
			return ErrManualEndpointProtocol
		}
		previousDevice = deviceID
		previous = address
	}
	return nil
}

func writeManualEndpointError(
	writer http.ResponseWriter,
	err error,
) {
	status := http.StatusServiceUnavailable
	code := "manual_endpoints_unavailable"
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		status = http.StatusRequestTimeout
		code = "manual_endpoint_interrupted"
	case errors.Is(err, store.ErrInvalidPeerEndpoint):
		status = http.StatusBadRequest
		code = "invalid_manual_endpoint"
	case errors.Is(err, ErrManualEndpointPeerUnavailable):
		status = http.StatusConflict
		code = "manual_endpoint_peer_unavailable"
	case errors.Is(err, store.ErrPeerEndpointCapacity):
		status = http.StatusTooManyRequests
		code = "manual_endpoint_capacity"
	}
	writeOperatorError(writer, status, code)
}

func (client *OperatorClient) ManualEndpoints(
	ctx context.Context,
) (ManualEndpointList, error) {
	response, err := client.manualEndpointExchange(
		ctx,
		http.MethodGet,
		manualEndpointCollectionPath,
		nil,
	)
	if err != nil {
		return ManualEndpointList{}, err
	}
	var result ManualEndpointList
	if decodeStatusObject(response, &result) != nil ||
		result.validate() != nil {
		return ManualEndpointList{}, ErrManualEndpointProtocol
	}
	return result, nil
}

func (client *OperatorClient) AddManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (ManualEndpointStatus, error) {
	body, err := manualEndpointBody(deviceID, endpoint)
	if err != nil {
		return ManualEndpointStatus{}, err
	}
	response, err := client.manualEndpointExchange(
		ctx,
		http.MethodPost,
		manualEndpointCollectionPath,
		body,
	)
	if err != nil {
		return ManualEndpointStatus{}, err
	}
	var result ManualEndpointStatus
	if decodeStatusObject(response, &result) != nil ||
		result.validate() != nil ||
		result.DeviceID != string(deviceID) ||
		result.Endpoint != endpoint.String() {
		return ManualEndpointStatus{}, ErrManualEndpointProtocol
	}
	return result, nil
}

func (client *OperatorClient) RemoveManualEndpoint(
	ctx context.Context,
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) (ManualEndpointRemoval, error) {
	body, err := manualEndpointBody(deviceID, endpoint)
	if err != nil {
		return ManualEndpointRemoval{}, err
	}
	response, err := client.manualEndpointExchange(
		ctx,
		http.MethodPost,
		manualEndpointRemovePath,
		body,
	)
	if err != nil {
		return ManualEndpointRemoval{}, err
	}
	var result ManualEndpointRemoval
	if decodeStatusObject(response, &result) != nil ||
		result.DeviceID != string(deviceID) ||
		result.Endpoint != endpoint.String() {
		return ManualEndpointRemoval{}, ErrManualEndpointProtocol
	}
	return result, nil
}

func manualEndpointBody(
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) ([]byte, error) {
	if !deviceID.Valid() ||
		!validManualEndpointTarget(deviceID, endpoint) {
		return nil, ErrInvalidOperatorDial
	}
	return canonicalOperatorJSON(manualEndpointWire{
		DeviceID: string(deviceID),
		Endpoint: endpoint.String(),
	})
}

func validManualEndpointTarget(
	deviceID domain.DeviceID,
	endpoint netip.AddrPort,
) bool {
	record := store.PeerEndpointRecord{
		DeviceID:   deviceID,
		SourceKind: store.PeerEndpointManual,
		Endpoint:   endpoint,
		ObservedAt: manualEndpointValidationTimestamp,
	}
	return record.Validate() == nil
}

func (client *OperatorClient) manualEndpointExchange(
	ctx context.Context,
	method string,
	path string,
	body []byte,
) ([]byte, error) {
	if client == nil || ctx == nil {
		return nil, ErrInvalidOperatorDial
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	transport, err := client.currentTransport()
	if errors.Is(err, ErrStatusConnection) {
		transport, err = client.reconnect(ctx, nil)
	}
	if err != nil {
		return nil, err
	}
	if !transport.Usable() {
		transport, err = client.reconnect(ctx, transport)
		if err != nil {
			return nil, err
		}
	}
	response, err := transport.Exchange(ctx, method, path, body)
	if errors.Is(err, ipc.ErrClientConnectionLost) {
		transport, reconnectErr := client.reconnect(ctx, transport)
		if reconnectErr != nil {
			return nil, reconnectErr
		}
		response, err = transport.Exchange(ctx, method, path, body)
	}
	if err != nil {
		if errors.Is(err, ipc.ErrClientProtocol) {
			return nil, fmt.Errorf(
				"%w: %v",
				ErrManualEndpointProtocol,
				err,
			)
		}
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrManualEndpointProtocol
	}
	return response.Body, nil
}
