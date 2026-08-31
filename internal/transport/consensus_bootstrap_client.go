package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"golang.org/x/net/http2"
)

// ConsensusBootstrapClientOptions configures the outbound-only identity-plane
// client used before a fresh member has local Raft or settled-replica state.
type ConsensusBootstrapClientOptions struct {
	LocalDeviceID       domain.DeviceID
	PeerDeviceID        domain.DeviceID
	IdentityCertificate tls.Certificate
	Endpoints           ConsensusEndpointResolver
	Dialer              ConsensusEndpointDialer
	VerifyExpectedPeer  ExpectedConsensusPeerVerifier
}

// ConsensusBootstrapClient owns one peer-pinned HTTP/2 consensus connection.
// It exposes only the two routes needed to recover content credentials and
// bootstrap state; it cannot open a Raft stream or endorsement route.
type ConsensusBootstrapClient struct {
	mu sync.Mutex

	localDeviceID       domain.DeviceID
	peerDeviceID        domain.DeviceID
	identityCertificate tls.Certificate
	endpoints           ConsensusEndpointResolver
	dialer              ConsensusEndpointDialer
	verifyExpectedPeer  ExpectedConsensusPeerVerifier

	raw    *tls.Conn
	http2  *http2.ClientConn
	tls    *tls.Config
	closed bool
}

// NewConsensusBootstrapClient validates and snapshots one fresh-member
// identity-plane client. Unlike ConsensusStreamLayer it does not require
// RFC 8441 extended CONNECT because its closed routes are ordinary HTTP.
func NewConsensusBootstrapClient(
	options ConsensusBootstrapClientOptions,
) (*ConsensusBootstrapClient, error) {
	if !options.LocalDeviceID.Valid() ||
		!options.PeerDeviceID.Valid() ||
		options.LocalDeviceID == options.PeerDeviceID ||
		nilConsensusDependency(options.Endpoints) ||
		nilConsensusDependency(options.Dialer) ||
		options.VerifyExpectedPeer == nil {
		return nil, ErrInvalidConsensusStreamOptions
	}
	certificate, err := validateAndCloneTLSCertificate(
		options.IdentityCertificate,
		PlaneConsensus,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: identity certificate",
			ErrInvalidConsensusStreamOptions,
		)
	}
	identity, err := ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil || identity.Binding.DeviceID != options.LocalDeviceID {
		clearTLSCertificate(&certificate)
		return nil, ErrInvalidConsensusStreamOptions
	}
	return &ConsensusBootstrapClient{
		localDeviceID:       options.LocalDeviceID,
		peerDeviceID:        options.PeerDeviceID,
		identityCertificate: certificate,
		endpoints:           options.Endpoints,
		dialer:              options.Dialer,
		verifyExpectedPeer:  options.VerifyExpectedPeer,
	}, nil
}

// RequestConsensusStatus implements the bodyless status requester contract.
func (client *ConsensusBootstrapClient) RequestConsensusStatus(
	ctx context.Context,
	deviceID domain.DeviceID,
) (ConsensusControlResponse, error) {
	return client.request(
		ctx,
		deviceID,
		http.MethodGet,
		consensusStatusPath,
		nil,
		true,
	)
}

// RequestCredentialRenewal implements the signed-binding requester contract.
func (client *ConsensusBootstrapClient) RequestCredentialRenewal(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (ConsensusControlResponse, error) {
	if len(body) == 0 {
		return ConsensusControlResponse{}, ErrInvalidConsensusControlRequest
	}
	return client.request(
		ctx,
		deviceID,
		http.MethodPost,
		consensusCredentialRenewalPath,
		body,
		false,
	)
}

func (client *ConsensusBootstrapClient) request(
	ctx context.Context,
	deviceID domain.DeviceID,
	method string,
	path string,
	body []byte,
	requireCanonical bool,
) (ConsensusControlResponse, error) {
	if client == nil ||
		ctx == nil ||
		deviceID != client.peerDeviceID ||
		len(body) > ConsensusControlBodyMaxBytes {
		return ConsensusControlResponse{}, ErrInvalidConsensusControlRequest
	}
	if err := ctx.Err(); err != nil {
		return ConsensusControlResponse{}, err
	}
	requestContext, cancel := context.WithTimeout(
		ctx,
		consensusControlRequest,
	)
	defer cancel()

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return ConsensusControlResponse{}, ErrConsensusStreamClosed
	}
	if client.http2 == nil || !client.http2.CanTakeNewRequest() {
		if err := client.openLocked(requestContext); err != nil {
			return ConsensusControlResponse{}, err
		}
	}

	var requestBody io.Reader
	if len(body) != 0 {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(
		requestContext,
		method,
		"https://"+ConsensusRaftAuthority+path,
		requestBody,
	)
	if err != nil {
		return ConsensusControlResponse{}, ErrInvalidConsensusControlRequest
	}
	request.Header.Set(
		"Accept",
		consensusJSONMediaType+", "+consensusProblemMediaType,
	)
	if len(body) != 0 {
		request.Header.Set("Content-Type", consensusJSONMediaType)
	}
	response, err := client.http2.RoundTrip(request)
	if err != nil {
		client.closeConnectionLocked()
		if requestErr := requestContext.Err(); requestErr != nil {
			return ConsensusControlResponse{}, requestErr
		}
		return ConsensusControlResponse{}, fmt.Errorf(
			"%w: round trip",
			ErrConsensusControlResponse,
		)
	}
	if response == nil || response.Body == nil {
		client.closeConnectionLocked()
		return ConsensusControlResponse{}, ErrConsensusControlResponse
	}
	defer response.Body.Close()
	mediaType, err := consensusResponseMediaType(response)
	if err != nil {
		client.closeConnectionLocked()
		return ConsensusControlResponse{}, err
	}
	limited := io.LimitReader(
		response.Body,
		ConsensusControlBodyMaxBytes+1,
	)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		client.closeConnectionLocked()
		if requestErr := requestContext.Err(); requestErr != nil {
			return ConsensusControlResponse{}, requestErr
		}
		return ConsensusControlResponse{}, ErrConsensusControlResponse
	}
	if len(responseBody) > ConsensusControlBodyMaxBytes {
		client.closeConnectionLocked()
		return ConsensusControlResponse{}, ErrConsensusControlResponse
	}
	if requireCanonical {
		canonical, canonicalErr := codec.CanonicalizeSignedObject(
			responseBody,
		)
		if canonicalErr != nil || !bytes.Equal(canonical, responseBody) {
			client.closeConnectionLocked()
			return ConsensusControlResponse{}, ErrConsensusControlResponse
		}
	}
	return ConsensusControlResponse{
		StatusCode: response.StatusCode,
		MediaType:  mediaType,
		Body:       responseBody,
	}, nil
}

func (client *ConsensusBootstrapClient) openLocked(
	ctx context.Context,
) error {
	client.closeConnectionLocked()
	endpoints, err := client.endpoints.ResolveConsensusEndpoints(
		ctx,
		client.peerDeviceID,
	)
	if err != nil ||
		len(endpoints) == 0 ||
		len(endpoints) > ConsensusEndpointCandidatesMax {
		return ErrConsensusEndpointUnavailable
	}
	tlsConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane:       PlaneConsensus,
		Certificate: client.identityCertificate,
		VerifyIdentityPeer: func(certificate IdentityCertificate) error {
			return client.verifyExpectedPeer(
				client.peerDeviceID,
				certificate,
			)
		},
	})
	if err != nil {
		return ErrInvalidConsensusStreamOptions
	}
	tlsConfigOwned := true
	defer func() {
		if tlsConfigOwned {
			clearBootstrapTLSConfig(tlsConfig)
		}
	}()
	seen := make(map[netip.AddrPort]struct{}, len(endpoints))
	var failures []error
	for _, endpoint := range endpoints {
		if !validConsensusEndpoint(endpoint) {
			continue
		}
		if _, duplicate := seen[endpoint]; duplicate {
			continue
		}
		seen[endpoint] = struct{}{}
		raw, dialErr := client.dialer.DialConsensusEndpoint(ctx, endpoint)
		if dialErr != nil || raw == nil {
			if raw != nil {
				_ = raw.Close()
			}
			if dialErr != nil {
				failures = append(failures, dialErr)
			}
			continue
		}
		connection := tls.Client(raw, tlsConfig)
		if err := connection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			failures = append(failures, err)
			continue
		}
		state := connection.ConnectionState()
		if !validOutboundConsensusConnectionState(
			state,
			client.peerDeviceID,
		) {
			_ = connection.Close()
			failures = append(failures, ErrTLSAdmission)
			continue
		}
		identity, err := ParseIdentityCertificate(
			state.PeerCertificates[0].Raw,
		)
		if err != nil ||
			client.verifyExpectedPeer(
				client.peerDeviceID,
				identity,
			) != nil {
			_ = connection.Close()
			failures = append(failures, ErrTLSAdmission)
			continue
		}
		httpConnection, err := newConsensusHTTP2ClientConn(ctx, connection)
		if err != nil {
			_ = connection.Close()
			failures = append(failures, err)
			continue
		}
		client.raw = connection
		client.http2 = httpConnection
		client.tls = tlsConfig
		tlsConfigOwned = false
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(
		append(
			[]error{ErrConsensusEndpointUnavailable},
			failures...,
		)...,
	)
}

// Close releases the physical connection and clears the owned certificate.
func (client *ConsensusBootstrapClient) Close() error {
	if client == nil {
		return ErrInvalidConsensusStreamOptions
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil
	}
	client.closed = true
	err := client.closeConnectionLocked()
	clearTLSCertificate(&client.identityCertificate)
	return err
}

func (client *ConsensusBootstrapClient) closeConnectionLocked() error {
	var result error
	if client.http2 != nil {
		result = errors.Join(result, client.http2.Close())
	}
	if client.raw != nil {
		if err := client.raw.Close(); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	client.http2 = nil
	client.raw = nil
	clearBootstrapTLSConfig(client.tls)
	client.tls = nil
	return result
}

func clearBootstrapTLSConfig(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		clearTLSCertificate(&config.Certificates[index])
	}
	config.Certificates = nil
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = nil
}
