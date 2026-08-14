package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidTLSOptions             = errors.New("transport: invalid TLS options")
	ErrTLSAdmission                  = errors.New("transport: TLS peer admission failed")
	ErrContentCertificateUnavailable = errors.New("transport: content certificate unavailable")
)

// IdentityPeerVerifier applies pairing- or consensus-plane policy after the
// fixed certificate profile and TLS channel have been verified.
type IdentityPeerVerifier func(IdentityCertificate) error

// ContentPeerAdmission is the monotonic lifetime authorized by the same
// applied-state and wall-clock cut that admitted a content certificate.
type ContentPeerAdmission struct {
	CloseAfter time.Duration
}

func (admission ContentPeerAdmission) validFor(
	certificate ContentCertificate,
) bool {
	certificateLifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	return admission.CloseAfter > 0 &&
		certificateLifetime > 0 &&
		admission.CloseAfter <= certificateLifetime
}

// ContentPeerVerifier applies membership/authorization policy after the fixed
// certificate profile and TLS channel have been verified. Its returned
// lifetime must be armed directly as a monotonic close timer.
type ContentPeerVerifier func(ContentCertificate) (ContentPeerAdmission, error)

// ContentCertificateProvider returns the current local epoch certificate for
// each content handshake. It may return ErrContentCertificateUnavailable while
// pairing and consensus remain available. Implementations must be concurrency safe.
type ContentCertificateProvider func() (tls.Certificate, error)

// ServerTLSOptions configures one listener with three closed ALPN planes.
type ServerTLSOptions struct {
	IdentityCertificate tls.Certificate
	ContentCertificate  ContentCertificateProvider
	VerifyPairingPeer   IdentityPeerVerifier
	VerifyConsensusPeer IdentityPeerVerifier
	VerifyContentPeer   ContentPeerVerifier
}

// ClientTLSOptions configures one connection for exactly one plane.
type ClientTLSOptions struct {
	Plane              Plane
	Certificate        tls.Certificate
	VerifyIdentityPeer IdentityPeerVerifier
	VerifyContentPeer  ContentPeerVerifier
}

// NewServerTLSConfig returns a TLS 1.3-only selector. The selected ALPN fixes
// both the local certificate profile and the only peer verifier that can run.
func NewServerTLSConfig(options ServerTLSOptions) (*tls.Config, error) {
	if options.VerifyPairingPeer == nil ||
		options.VerifyConsensusPeer == nil ||
		options.VerifyContentPeer == nil ||
		options.ContentCertificate == nil {
		return nil, ErrInvalidTLSOptions
	}
	identityCertificate, err := validateAndCloneTLSCertificate(
		options.IdentityCertificate,
		PlaneConsensus,
	)
	if err != nil {
		return nil, err
	}
	identityProfile, err := ParseIdentityCertificate(identityCertificate.Certificate[0])
	if err != nil {
		return nil, ErrInvalidTLSOptions
	}
	configs := map[Plane]*tls.Config{
		PlanePairing: serverPlaneTLSConfig(
			PlanePairing, identityCertificate, options.VerifyPairingPeer, nil,
		),
		PlaneConsensus: serverPlaneTLSConfig(
			PlaneConsensus, identityCertificate, options.VerifyConsensusPeer, nil,
		),
		PlaneContent: serverContentTLSConfig(
			identityProfile.Binding,
			options.ContentCertificate,
			options.VerifyContentPeer,
		),
	}
	config := baseTLSConfig()
	config.NextProtos = []string{ALPNPairing, ALPNConsensus, ALPNContent}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil {
			return nil, ErrTLSAdmission
		}
		plane, err := SelectPlane(hello.SupportedProtos)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTLSAdmission, err)
		}
		selected := configs[plane]
		if selected == nil {
			return nil, ErrTLSAdmission
		}
		return selected, nil
	}
	return config, nil
}

// NewClientTLSConfig returns a TLS 1.3-only config for one exact ALPN. Web PKI
// verification is intentionally replaced by the closed pinned profile.
func NewClientTLSConfig(options ClientTLSOptions) (*tls.Config, error) {
	protocol, err := options.Plane.ALPN()
	if err != nil {
		return nil, ErrInvalidTLSOptions
	}
	if options.Plane == PlaneContent {
		if options.VerifyContentPeer == nil || options.VerifyIdentityPeer != nil {
			return nil, ErrInvalidTLSOptions
		}
	} else if options.VerifyIdentityPeer == nil || options.VerifyContentPeer != nil {
		return nil, ErrInvalidTLSOptions
	}
	certificate, err := validateAndCloneTLSCertificate(options.Certificate, options.Plane)
	if err != nil {
		return nil, err
	}
	config := baseTLSConfig()
	config.InsecureSkipVerify = true // The closed profile below replaces Web PKI.
	config.Certificates = []tls.Certificate{certificate}
	config.NextProtos = []string{protocol}
	config.VerifyConnection = planeConnectionVerifier(
		options.Plane,
		options.VerifyIdentityPeer,
		options.VerifyContentPeer,
	)
	return config, nil
}

func serverContentTLSConfig(
	identity IdentityBinding,
	provider ContentCertificateProvider,
	verifyContent ContentPeerVerifier,
) *tls.Config {
	config := baseTLSConfig()
	config.ClientAuth = tls.RequireAnyClientCert
	config.NextProtos = []string{ALPNContent}
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		certificate, err := loadServerContentCertificate(identity, provider)
		if err != nil {
			return nil, err
		}
		return &certificate, nil
	}
	config.VerifyConnection = planeConnectionVerifier(
		PlaneContent, nil, verifyContent,
	)
	return config
}

func loadServerContentCertificate(
	identity IdentityBinding,
	provider ContentCertificateProvider,
) (tls.Certificate, error) {
	if provider == nil {
		return tls.Certificate{}, ErrInvalidTLSOptions
	}
	certificate, err := provider()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrTLSAdmission, err)
	}
	certificate, err = validateAndCloneTLSCertificate(certificate, PlaneContent)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrTLSAdmission, err)
	}
	profile, err := ParseContentCertificate(certificate.Certificate[0])
	if err != nil || profile.Binding.SessionID != identity.SessionID ||
		profile.Binding.DeviceID != identity.DeviceID {
		return tls.Certificate{}, ErrTLSAdmission
	}
	return certificate, nil
}

func serverPlaneTLSConfig(
	plane Plane,
	certificate tls.Certificate,
	verifyIdentity IdentityPeerVerifier,
	verifyContent ContentPeerVerifier,
) *tls.Config {
	protocol, _ := plane.ALPN()
	config := baseTLSConfig()
	config.Certificates = []tls.Certificate{cloneTLSCertificate(certificate)}
	config.ClientAuth = tls.RequireAnyClientCert
	config.NextProtos = []string{protocol}
	config.VerifyConnection = planeConnectionVerifier(
		plane, verifyIdentity, verifyContent,
	)
	return config
}

func planeConnectionVerifier(
	plane Plane,
	verifyIdentity IdentityPeerVerifier,
	verifyContent ContentPeerVerifier,
) func(tls.ConnectionState) error {
	protocol, _ := plane.ALPN()
	return func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || state.DidResume ||
			state.NegotiatedProtocol != protocol ||
			len(state.PeerCertificates) != 1 {
			return ErrTLSAdmission
		}
		raw := state.PeerCertificates[0].Raw
		switch plane {
		case PlanePairing, PlaneConsensus:
			if verifyIdentity == nil || verifyContent != nil {
				return ErrTLSAdmission
			}
			certificate, err := ParseIdentityCertificate(raw)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrTLSAdmission, err)
			}
			if err := verifyIdentity(certificate); err != nil {
				return fmt.Errorf("%w: %v", ErrTLSAdmission, err)
			}
		case PlaneContent:
			if verifyContent == nil || verifyIdentity != nil {
				return ErrTLSAdmission
			}
			certificate, err := ParseContentCertificate(raw)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrTLSAdmission, err)
			}
			admission, err := verifyContent(certificate)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrTLSAdmission, err)
			}
			if !admission.validFor(certificate) {
				return ErrTLSAdmission
			}
		default:
			return ErrTLSAdmission
		}
		return nil
	}
}

func baseTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	}
}

func validateAndCloneTLSCertificate(
	certificate tls.Certificate,
	plane Plane,
) (tls.Certificate, error) {
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil {
		return tls.Certificate{}, ErrInvalidTLSOptions
	}
	privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return tls.Certificate{}, ErrInvalidTLSOptions
	}
	var publicKey ed25519.PublicKey
	switch plane {
	case PlanePairing, PlaneConsensus:
		parsed, err := ParseIdentityCertificate(certificate.Certificate[0])
		if err != nil {
			return tls.Certificate{}, ErrInvalidTLSOptions
		}
		publicKey = parsed.PublicKey
	case PlaneContent:
		parsed, err := ParseContentCertificate(certificate.Certificate[0])
		if err != nil {
			return tls.Certificate{}, ErrInvalidTLSOptions
		}
		publicKey = parsed.PublicKey
	default:
		return tls.Certificate{}, ErrInvalidTLSOptions
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return tls.Certificate{}, ErrInvalidTLSOptions
	}
	return cloneTLSCertificate(certificate), nil
}

func cloneTLSCertificate(certificate tls.Certificate) tls.Certificate {
	result := tls.Certificate{
		Certificate: make([][]byte, len(certificate.Certificate)),
		OCSPStaple:  bytes.Clone(certificate.OCSPStaple),
		SignedCertificateTimestamps: make(
			[][]byte,
			len(certificate.SignedCertificateTimestamps),
		),
	}
	for index := range certificate.Certificate {
		result.Certificate[index] = bytes.Clone(certificate.Certificate[index])
	}
	for index := range certificate.SignedCertificateTimestamps {
		result.SignedCertificateTimestamps[index] = bytes.Clone(
			certificate.SignedCertificateTimestamps[index],
		)
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		result.PrivateKey = ed25519.PrivateKey(bytes.Clone(privateKey))
	} else {
		result.PrivateKey = certificate.PrivateKey
	}
	return result
}
