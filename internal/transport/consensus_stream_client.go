package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"

	"github.com/ijonahch/codecomm/internal/domain"
	"golang.org/x/net/http2"
)

const (
	consensusJSONMediaType    = "application/json"
	consensusProblemMediaType = "application/problem+json"
	consensusProofPath        = "/v1/consensus/prove"
)

// RequestConsensusProof sends one bounded JSON request to the fixed proof
// route over the peer's existing authenticated consensus connection.
func (layer *ConsensusStreamLayer) RequestConsensusProof(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (ConsensusControlResponse, error) {
	if layer == nil ||
		layer.ctx == nil ||
		ctx == nil ||
		!deviceID.Valid() ||
		deviceID == layer.localDeviceID ||
		len(body) == 0 ||
		len(body) > ConsensusControlBodyMaxBytes {
		return ConsensusControlResponse{},
			ErrInvalidConsensusControlRequest
	}
	if err := ctx.Err(); err != nil {
		return ConsensusControlResponse{}, err
	}
	requestContext, cancel := context.WithTimeout(
		ctx,
		consensusControlRequest,
	)
	stopLayerCancellation := context.AfterFunc(layer.ctx, cancel)
	defer func() {
		stopLayerCancellation()
		cancel()
	}()

	if err := layer.authorize(deviceID); err != nil {
		return ConsensusControlResponse{}, err
	}
	peer, err := layer.peer(deviceID)
	if err != nil {
		return ConsensusControlResponse{}, err
	}
	if err := peer.acquire(requestContext); err != nil {
		return ConsensusControlResponse{}, err
	}
	defer peer.release()

	physical, err := layer.beginConsensusControlRequest(
		requestContext,
		peer,
		deviceID,
	)
	if err != nil {
		return ConsensusControlResponse{}, err
	}
	defer peer.streamClosed()

	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		"https://"+ConsensusRaftAuthority+consensusProofPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return ConsensusControlResponse{},
			ErrInvalidConsensusControlRequest
	}
	request.Header.Set("Accept", consensusJSONMediaType+", "+consensusProblemMediaType)
	request.Header.Set("Content-Type", consensusJSONMediaType)

	response, err := physical.http2.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if requestErr := requestContext.Err(); requestErr != nil {
			return ConsensusControlResponse{}, requestErr
		}
		return ConsensusControlResponse{}, fmt.Errorf(
			"%w: round trip",
			ErrConsensusControlResponse,
		)
	}
	if response == nil || response.Body == nil {
		return ConsensusControlResponse{},
			ErrConsensusControlResponse
	}
	defer response.Body.Close()

	mediaType, err := consensusResponseMediaType(response)
	if err != nil {
		return ConsensusControlResponse{}, err
	}
	if response.ContentLength > ConsensusControlBodyMaxBytes {
		return ConsensusControlResponse{},
			ErrConsensusControlResponse
	}
	limited := io.LimitReader(
		response.Body,
		ConsensusControlBodyMaxBytes+1,
	)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		if requestErr := requestContext.Err(); requestErr != nil {
			return ConsensusControlResponse{}, requestErr
		}
		return ConsensusControlResponse{}, fmt.Errorf(
			"%w: read body",
			ErrConsensusControlResponse,
		)
	}
	if len(responseBody) > ConsensusControlBodyMaxBytes {
		return ConsensusControlResponse{},
			ErrConsensusControlResponse
	}
	if err := layer.verifyExpected(deviceID, physical.identity); err != nil {
		layer.invalidateConsensusPeer(peer, deviceID)
		return ConsensusControlResponse{}, err
	}
	if err := layer.authorize(deviceID); err != nil {
		layer.invalidateConsensusPeer(peer, deviceID)
		return ConsensusControlResponse{}, err
	}
	return ConsensusControlResponse{
		StatusCode: response.StatusCode,
		MediaType:  mediaType,
		Body:       responseBody,
	}, nil
}

func (layer *ConsensusStreamLayer) beginConsensusControlRequest(
	ctx context.Context,
	peer *consensusPeerClient,
	deviceID domain.DeviceID,
) (*consensusPhysicalClient, error) {
	if layer == nil || peer == nil || ctx == nil {
		return nil, ErrInvalidConsensusControlRequest
	}
	peer.mu.Lock()

	if err := layer.openError(); err != nil {
		peer.mu.Unlock()
		return nil, err
	}
	if peer.physical == nil || !peer.physical.usable() {
		if peer.openStreams != 0 {
			peer.mu.Unlock()
			return nil, ErrConsensusEndpointUnavailable
		}
		if peer.physical != nil {
			_ = peer.physical.close()
			peer.physical = nil
		}
		physical, err := layer.dialPhysical(ctx, deviceID)
		if err != nil {
			peer.mu.Unlock()
			return nil, err
		}
		peer.physical = physical
	}
	if err := layer.verifyExpected(
		deviceID,
		peer.physical.identity,
	); err != nil {
		physical := peer.physical
		peer.physical = nil
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, err
	}
	if err := layer.authorize(deviceID); err != nil {
		physical := peer.physical
		peer.physical = nil
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, err
	}
	peer.openStreams++
	physical := peer.physical
	peer.mu.Unlock()
	return physical, nil
}

func (layer *ConsensusStreamLayer) invalidateConsensusPeer(
	peer *consensusPeerClient,
	deviceID domain.DeviceID,
) {
	if layer == nil || peer == nil {
		return
	}
	peer.mu.Lock()
	physical := peer.physical
	peer.physical = nil
	peer.mu.Unlock()
	if physical != nil {
		_ = physical.close()
	}
	layer.closeStreamsForDevice(deviceID)
}

func consensusResponseMediaType(
	response *http.Response,
) (string, error) {
	if response == nil ||
		response.StatusCode < http.StatusContinue ||
		response.StatusCode > 599 ||
		response.Header.Get("Content-Encoding") != "" {
		return "", ErrConsensusControlResponse
	}
	contentLength := response.Header.Get("Content-Length")
	if contentLength != "" {
		value, err := strconv.ParseInt(contentLength, 10, 64)
		if err != nil ||
			value < 0 ||
			value > ConsensusControlBodyMaxBytes {
			return "", ErrConsensusControlResponse
		}
	}
	mediaType, parameters, err := mime.ParseMediaType(
		response.Header.Get("Content-Type"),
	)
	if err != nil || len(parameters) != 0 {
		return "", ErrConsensusControlResponse
	}
	expected := consensusProblemMediaType
	if response.StatusCode >= http.StatusOK &&
		response.StatusCode < http.StatusMultipleChoices {
		expected = consensusJSONMediaType
	}
	if mediaType != expected {
		return "", ErrConsensusControlResponse
	}
	return mediaType, nil
}

func (layer *ConsensusStreamLayer) dialPhysical(
	ctx context.Context,
	deviceID domain.DeviceID,
) (*consensusPhysicalClient, error) {
	endpoints, err := layer.endpoints.ResolveConsensusEndpoints(
		ctx,
		deviceID,
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf(
			"%w: resolve endpoints",
			ErrConsensusEndpointUnavailable,
		)
	}
	if len(endpoints) == 0 ||
		len(endpoints) > ConsensusEndpointCandidatesMax {
		return nil, ErrConsensusEndpointUnavailable
	}
	tlsConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane:       PlaneConsensus,
		Certificate: layer.identityCertificate,
		VerifyIdentityPeer: func(
			certificate IdentityCertificate,
		) error {
			return layer.verifyExpected(deviceID, certificate)
		},
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: TLS configuration",
			ErrInvalidConsensusStreamOptions,
		)
	}

	seen := make(map[netip.AddrPort]struct{}, len(endpoints))
	var lastErr error
	for _, endpoint := range endpoints {
		if !validConsensusEndpoint(endpoint) {
			lastErr = ErrConsensusEndpointUnavailable
			continue
		}
		if _, duplicate := seen[endpoint]; duplicate {
			continue
		}
		seen[endpoint] = struct{}{}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, dialErr := layer.dialer.DialConsensusEndpoint(ctx, endpoint)
		if dialErr != nil || raw == nil {
			if raw != nil {
				_ = raw.Close()
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			lastErr = dialErr
			continue
		}
		connection := tls.Client(raw, tlsConfig.Clone())
		if handshakeErr := connection.HandshakeContext(ctx); handshakeErr != nil {
			_ = connection.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			lastErr = handshakeErr
			continue
		}
		if !validOutboundConsensusConnectionState(
			connection.ConnectionState(),
			deviceID,
		) {
			_ = connection.Close()
			lastErr = ErrTLSAdmission
			continue
		}
		peerCertificate, parseErr := ParseIdentityCertificate(
			connection.ConnectionState().PeerCertificates[0].Raw,
		)
		if parseErr != nil {
			_ = connection.Close()
			lastErr = ErrTLSAdmission
			continue
		}
		if err := layer.authorize(deviceID); err != nil {
			_ = connection.Close()
			return nil, err
		}
		httpConnection, httpErr := newConsensusHTTP2ClientConn(
			ctx,
			connection,
		)
		if httpErr != nil {
			_ = connection.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			lastErr = httpErr
			continue
		}
		if err := ctx.Err(); err != nil {
			_ = httpConnection.Close()
			_ = connection.Close()
			return nil, err
		}
		return &consensusPhysicalClient{
			raw:      connection,
			http2:    httpConnection,
			identity: peerCertificate,
		}, nil
	}
	if lastErr == nil {
		lastErr = ErrConsensusEndpointUnavailable
	}
	return nil, fmt.Errorf(
		"%w: %v",
		ErrConsensusEndpointUnavailable,
		lastErr,
	)
}

func (layer *ConsensusStreamLayer) openOutboundStream(
	setupContext context.Context,
	deviceID domain.DeviceID,
	physical *consensusPhysicalClient,
) (*consensusStreamConn, error) {
	if setupContext == nil || physical == nil || physical.http2 == nil {
		return nil, ErrConsensusEndpointUnavailable
	}
	streamContext, streamCancel := context.WithCancel(layer.ctx)
	requestReader, requestWriter := io.Pipe()
	resources := &consensusOutboundResources{
		cancel:        streamCancel,
		requestReader: requestReader,
		requestWriter: requestWriter,
	}
	connection, bridges := newConsensusStreamConn(
		layer.localDeviceID,
		deviceID,
		resources.close,
	)
	resources.bridges = bridges

	go copyOutboundRequest(
		connection,
		bridges.write,
		requestWriter,
	)
	request, err := http.NewRequestWithContext(
		streamContext,
		http.MethodConnect,
		"https://"+ConsensusRaftAuthority+ConsensusRaftPath,
		requestReader,
	)
	if err != nil {
		_ = connection.Close()
		return nil, ErrConsensusStreamRejected
	}
	request.Header.Set(":protocol", ConsensusRaftProtocol)

	stopSetupCancellation := context.AfterFunc(
		setupContext,
		streamCancel,
	)
	response, err := physical.http2.RoundTrip(request)
	stopSetupCancellation()
	if err != nil {
		_ = connection.Close()
		if setupErr := setupContext.Err(); setupErr != nil {
			return nil, setupErr
		}
		return nil, fmt.Errorf(
			"%w: open extended CONNECT",
			ErrConsensusStreamRejected,
		)
	}
	if setupErr := setupContext.Err(); setupErr != nil {
		_ = response.Body.Close()
		_ = connection.Close()
		return nil, setupErr
	}
	if response.StatusCode != http.StatusOK || response.Body == nil {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		_ = connection.Close()
		return nil, fmt.Errorf(
			"%w: HTTP status %d",
			ErrConsensusStreamRejected,
			response.StatusCode,
		)
	}
	if !resources.attachResponse(response.Body) {
		_ = connection.Close()
		return nil, ErrConsensusStreamClosed
	}
	go copyOutboundResponse(
		connection,
		response.Body,
		bridges.read,
	)
	return connection, nil
}

func newConsensusHTTP2ClientConn(
	ctx context.Context,
	connection net.Conn,
) (*http2.ClientConn, error) {
	if ctx == nil || connection == nil {
		return nil, ErrInvalidConsensusStreamOptions
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	cancelDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = closeConsensusConnectionImmediately(connection)
		close(cancelDone)
	})
	httpConnection, err := newConsensusHTTP2Transport().
		NewClientConn(connection)
	if !stopCancellation() {
		<-cancelDone
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		if httpConnection != nil {
			_ = httpConnection.Close()
		}
		_ = closeConsensusConnectionImmediately(connection)
		return nil, ctxErr
	}
	return httpConnection, err
}

func newConsensusHTTP2Transport() *http2.Transport {
	return &http2.Transport{
		DisableCompression:         true,
		MaxHeaderListSize:          ConsensusHeaderMaxBytes,
		MaxReadFrameSize:           16 << 10,
		MaxDecoderHeaderTableSize:  4 << 10,
		MaxEncoderHeaderTableSize:  4 << 10,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout:            consensusConnectionIdle,
		ReadIdleTimeout:            consensusStreamProgress,
		PingTimeout:                consensusPingTimeout,
	}
}

func validOutboundConsensusConnectionState(
	state tls.ConnectionState,
	expectedDeviceID domain.DeviceID,
) bool {
	if !state.HandshakeComplete ||
		state.Version != tls.VersionTLS13 ||
		state.DidResume ||
		state.NegotiatedProtocol != ALPNConsensus ||
		len(state.PeerCertificates) != 1 {
		return false
	}
	certificate, err := ParseIdentityCertificate(
		state.PeerCertificates[0].Raw,
	)
	return err == nil &&
		certificate.Binding.DeviceID == expectedDeviceID
}

func validConsensusEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	if !endpoint.IsValid() ||
		endpoint.Port() == 0 ||
		address.IsLoopback() ||
		address.IsUnspecified() ||
		address.IsMulticast() ||
		address.Is4In6() {
		return false
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		return address.Zone() != ""
	}
	if address.Zone() != "" {
		return false
	}
	if address.Is4() &&
		address.As4() == [4]byte{255, 255, 255, 255} {
		return false
	}
	return true
}

func copyOutboundRequest(
	connection *consensusStreamConn,
	source net.Conn,
	destination *io.PipeWriter,
) {
	_, err := io.CopyBuffer(
		destination,
		source,
		make([]byte, consensusCopyBufferSize),
	)
	_ = source.Close()
	if err != nil {
		_ = destination.CloseWithError(err)
		_ = connection.Close()
		return
	}
	_ = destination.Close()
}

func copyOutboundResponse(
	connection *consensusStreamConn,
	source io.ReadCloser,
	destination net.Conn,
) {
	_, err := io.CopyBuffer(
		destination,
		source,
		make([]byte, consensusCopyBufferSize),
	)
	_ = source.Close()
	_ = destination.Close()
	if err != nil {
		_ = connection.Close()
	}
}

type consensusOutboundResources struct {
	mu sync.Mutex

	closed        bool
	cancel        context.CancelFunc
	requestReader *io.PipeReader
	requestWriter *io.PipeWriter
	response      io.ReadCloser
	bridges       consensusStreamBridges
}

func (resources *consensusOutboundResources) attachResponse(
	response io.ReadCloser,
) bool {
	if resources == nil || response == nil {
		return false
	}
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if resources.closed {
		_ = response.Close()
		return false
	}
	resources.response = response
	return true
}

func (resources *consensusOutboundResources) close() {
	if resources == nil {
		return
	}
	resources.mu.Lock()
	if resources.closed {
		resources.mu.Unlock()
		return
	}
	resources.closed = true
	cancel := resources.cancel
	requestReader := resources.requestReader
	requestWriter := resources.requestWriter
	response := resources.response
	bridges := resources.bridges
	resources.response = nil
	resources.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if requestReader != nil {
		_ = requestReader.CloseWithError(net.ErrClosed)
	}
	if requestWriter != nil {
		_ = requestWriter.CloseWithError(net.ErrClosed)
	}
	if response != nil {
		_ = response.Close()
	}
	_ = bridges.read.Close()
	_ = bridges.write.Close()
}
