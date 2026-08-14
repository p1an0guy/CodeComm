package transport

import (
	"context"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
)

var (
	ErrPeerAuthorizationUnavailable = errors.New(
		"transport: authenticated peer authorization unavailable",
	)
	ErrPeerAuthorizationDenied = errors.New(
		"transport: authenticated peer authorization denied",
	)
)

// AuthenticatedPeer is the bounded peer identity established by ingress TLS.
// RecoveryGeneration applies to identity planes; Epoch and
// AuthorizationChainIndex apply to the content plane.
type AuthenticatedPeer struct {
	Plane                   Plane
	SessionID               domain.UUIDv7
	DeviceID                domain.DeviceID
	RecoveryGeneration      uint64
	Epoch                   uint64
	AuthorizationChainIndex uint64
}

type authenticatedPeerContextKey struct{}

type authenticatedPeerContext struct {
	metadata    AuthenticatedPeer
	reauthorize func() error
}

// AuthenticatedPeerFromContext returns ingress-authenticated peer metadata.
func AuthenticatedPeerFromContext(ctx context.Context) (AuthenticatedPeer, bool) {
	if ctx == nil {
		return AuthenticatedPeer{}, false
	}
	peer, ok := ctx.Value(
		authenticatedPeerContextKey{},
	).(*authenticatedPeerContext)
	if !ok || peer == nil {
		return AuthenticatedPeer{}, false
	}
	return peer.metadata, true
}

// ReauthorizeAuthenticatedPeer verifies that an ingress-authenticated
// connection remains tracked and authorized at the current applied-state cut.
// Peer HTTP handlers call it before accepting every new stream.
func ReauthorizeAuthenticatedPeer(ctx context.Context) error {
	if ctx == nil {
		return ErrPeerAuthorizationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	peer, ok := ctx.Value(
		authenticatedPeerContextKey{},
	).(*authenticatedPeerContext)
	if !ok || peer == nil || peer.reauthorize == nil {
		return ErrPeerAuthorizationUnavailable
	}
	return peer.reauthorize()
}

type peerCredentials struct {
	metadata AuthenticatedPeer
	identity IdentityCertificate
	content  ContentCertificate
}

func parsePeerCredentials(plane Plane, rawCertificate []byte) (peerCredentials, error) {
	switch plane {
	case PlanePairing, PlaneConsensus:
		certificate, err := ParseIdentityCertificate(rawCertificate)
		if err != nil {
			return peerCredentials{}, err
		}
		binding := certificate.Binding
		return peerCredentials{
			metadata: AuthenticatedPeer{
				Plane:              plane,
				SessionID:          binding.SessionID,
				DeviceID:           binding.DeviceID,
				RecoveryGeneration: binding.RecoveryGeneration,
			},
			identity: certificate,
		}, nil
	case PlaneContent:
		certificate, err := ParseContentCertificate(rawCertificate)
		if err != nil {
			return peerCredentials{}, err
		}
		binding := certificate.Binding
		return peerCredentials{
			metadata: AuthenticatedPeer{
				Plane:                   plane,
				SessionID:               binding.SessionID,
				DeviceID:                binding.DeviceID,
				Epoch:                   binding.Epoch,
				AuthorizationChainIndex: binding.AuthorizationChainIndex,
			},
			content: certificate,
		}, nil
	default:
		return peerCredentials{}, ErrTLSAdmission
	}
}
