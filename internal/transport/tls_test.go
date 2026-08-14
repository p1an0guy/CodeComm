package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTLSALPNSelectsClosedCertificatePlane(t *testing.T) {
	t.Parallel()

	serverIdentityKey := certificatePrivateKey(11)
	serverIdentity, serverBinding, err := issueIdentityCertificate(
		certificateTestSessionID, 3, serverIdentityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x61}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientIdentityKey := certificatePrivateKey(12)
	clientIdentity, clientBinding, err := issueIdentityCertificate(
		certificateTestSessionID, 3, clientIdentityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x62}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	serverEpochKey := certificatePrivateKey(13)
	serverAuthorization := certificateAuthorizationForKeys(
		t, serverIdentityKey, serverEpochKey, 2, 42,
	)
	serverContentCertificate, _, err := issueContentCertificate(
		serverAuthorization, serverEpochKey,
		bytes.NewReader(bytes.Repeat([]byte{0x63}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientEpochKey := certificatePrivateKey(14)
	clientAuthorization := certificateAuthorizationForKeys(
		t, clientIdentityKey, clientEpochKey, 2, 43,
	)
	clientContentCertificate, _, err := issueContentCertificate(
		clientAuthorization, clientEpochKey,
		bytes.NewReader(bytes.Repeat([]byte{0x64}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, _ := serverAuthorization.NotBefore.Time()

	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{
		IdentityCertificate: serverIdentity,
		ContentCertificate:  staticContentCertificate(serverContentCertificate),
		VerifyPairingPeer: func(certificate IdentityCertificate) error {
			return certificate.VerifyIdentity(
				certificateTestSessionID, 3, clientBinding.DeviceID,
				clientIdentityKey.Public().(ed25519.PublicKey),
			)
		},
		VerifyConsensusPeer: func(certificate IdentityCertificate) error {
			return certificate.VerifyIdentity(
				certificateTestSessionID, 3, clientBinding.DeviceID,
				clientIdentityKey.Public().(ed25519.PublicKey),
			)
		},
		VerifyContentPeer: func(certificate ContentCertificate) error {
			return certificate.VerifyAuthorization(clientAuthorization, notBefore)
		},
	})
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	tests := []struct {
		name        string
		plane       Plane
		certificate tls.Certificate
		identity    IdentityPeerVerifier
		content     ContentPeerVerifier
	}{
		{
			name: "pairing", plane: PlanePairing, certificate: clientIdentity,
			identity: func(certificate IdentityCertificate) error {
				return certificate.VerifyIdentity(
					certificateTestSessionID, 3, serverBinding.DeviceID,
					serverIdentityKey.Public().(ed25519.PublicKey),
				)
			},
		},
		{
			name: "consensus", plane: PlaneConsensus, certificate: clientIdentity,
			identity: func(certificate IdentityCertificate) error {
				return certificate.VerifyIdentity(
					certificateTestSessionID, 3, serverBinding.DeviceID,
					serverIdentityKey.Public().(ed25519.PublicKey),
				)
			},
		},
		{
			name: "content", plane: PlaneContent, certificate: clientContentCertificate,
			content: func(certificate ContentCertificate) error {
				return certificate.VerifyAuthorization(serverAuthorization, notBefore)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
				Plane: test.plane, Certificate: test.certificate,
				VerifyIdentityPeer: test.identity, VerifyContentPeer: test.content,
			})
			if err != nil {
				t.Fatalf("NewClientTLSConfig() error = %v", err)
			}
			clientState, serverState, clientErr, serverErr := tlsPipeHandshake(
				t, clientConfig, serverConfig,
			)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("TLS handshake errors = client %v, server %v", clientErr, serverErr)
			}
			protocol, _ := test.plane.ALPN()
			if clientState.Version != tls.VersionTLS13 || serverState.Version != tls.VersionTLS13 ||
				clientState.NegotiatedProtocol != protocol ||
				serverState.NegotiatedProtocol != protocol ||
				clientState.DidResume || serverState.DidResume {
				t.Fatalf("unexpected TLS states: client=%+v server=%+v", clientState, serverState)
			}
		})
	}
}

func TestTLSRejectsAmbiguousAndCrossProfileOffers(t *testing.T) {
	t.Parallel()

	serverConfig, clientIdentity, contentCertificate := tlsTestConfigs(t)
	identityVerifier := func(IdentityCertificate) error { return nil }
	contentVerifier := func(ContentCertificate) error { return nil }

	for _, test := range []struct {
		name        string
		options     ClientTLSOptions
		wantInvalid bool
	}{
		{
			name: "identity on content", wantInvalid: true,
			options: ClientTLSOptions{
				Plane: PlaneContent, Certificate: clientIdentity, VerifyContentPeer: contentVerifier,
			},
		},
		{
			name: "content on pairing", wantInvalid: true,
			options: ClientTLSOptions{
				Plane: PlanePairing, Certificate: contentCertificate, VerifyIdentityPeer: identityVerifier,
			},
		},
		{
			name: "cross callback", wantInvalid: true,
			options: ClientTLSOptions{
				Plane: PlanePairing, Certificate: clientIdentity,
				VerifyIdentityPeer: identityVerifier, VerifyContentPeer: contentVerifier,
			},
		},
	} {
		if _, err := NewClientTLSConfig(test.options); test.wantInvalid &&
			!errors.Is(err, ErrInvalidTLSOptions) {
			t.Errorf("NewClientTLSConfig(%s) error = %v, want %v", test.name, err, ErrInvalidTLSOptions)
		}
	}

	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: PlanePairing, Certificate: clientIdentity, VerifyIdentityPeer: identityVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocols := range [][]string{
		{},
		{ALPNPairing, ALPNContent},
		{"h2"},
	} {
		mutated := clientConfig.Clone()
		mutated.NextProtos = append([]string(nil), protocols...)
		_, _, clientErr, serverErr := tlsPipeHandshake(t, mutated, serverConfig)
		if clientErr == nil || serverErr == nil {
			t.Errorf("protocol offer %q errors = client %v, server %v; want both failures", protocols, clientErr, serverErr)
		}
	}
}

func TestTLSConfigDisablesResumptionAndClonesCertificates(t *testing.T) {
	t.Parallel()

	serverConfig, clientCertificate, _ := tlsTestConfigs(t)
	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: PlaneConsensus, Certificate: clientCertificate,
		VerifyIdentityPeer: func(IdentityCertificate) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !serverConfig.SessionTicketsDisabled || !clientConfig.SessionTicketsDisabled ||
		serverConfig.MinVersion != tls.VersionTLS13 ||
		serverConfig.MaxVersion != tls.VersionTLS13 ||
		clientConfig.MinVersion != tls.VersionTLS13 ||
		clientConfig.MaxVersion != tls.VersionTLS13 ||
		clientConfig.ClientSessionCache != nil {
		t.Fatal("TLS config permits version downgrade or resumption")
	}
	clientCertificate.Certificate[0][0] ^= 1
	clientCertificate.PrivateKey.(ed25519.PrivateKey)[0] ^= 1
	_, _, clientErr, serverErr := tlsPipeHandshake(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("mutating source certificate affected config: client %v, server %v", clientErr, serverErr)
	}
}

func TestTLSRejectsVerifierFailureAndVersionDowngrade(t *testing.T) {
	t.Parallel()

	serverConfig, clientCertificate, _ := tlsTestConfigs(t)
	denied := errors.New("member revoked")
	leaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	verify := planeConnectionVerifier(
		PlaneConsensus,
		func(IdentityCertificate) error { return denied },
		nil,
	)
	verifyErr := verify(tls.ConnectionState{
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: ALPNConsensus,
		PeerCertificates:   []*x509.Certificate{leaf},
	})
	if !errors.Is(verifyErr, ErrTLSAdmission) {
		t.Fatalf("verifier rejection = %v, want %v", verifyErr, ErrTLSAdmission)
	}

	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: PlaneConsensus, Certificate: clientCertificate,
		VerifyIdentityPeer: func(IdentityCertificate) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.MaxVersion = tls.VersionTLS12
	_, _, clientErr, serverErr := tlsPipeHandshake(t, clientConfig, serverConfig)
	if clientErr == nil || serverErr == nil {
		t.Fatalf("TLS 1.2 downgrade errors = client %v, server %v; want both failures", clientErr, serverErr)
	}
}

func TestServerTLSConfigRejectsCrossDeviceCertificateSet(t *testing.T) {
	t.Parallel()

	identityKey := certificatePrivateKey(31)
	identityCertificate, identityBinding, err := issueIdentityCertificate(
		certificateTestSessionID, 1, identityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x73}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentityKey := certificatePrivateKey(32)
	epochKey := certificatePrivateKey(33)
	authorization := certificateAuthorizationForKeys(
		t, otherIdentityKey, epochKey, 1, 1,
	)
	contentCertificate, _, err := issueContentCertificate(
		authorization, epochKey,
		bytes.NewReader(bytes.Repeat([]byte{0x74}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewServerTLSConfig(ServerTLSOptions{
		IdentityCertificate: identityCertificate,
		ContentCertificate:  staticContentCertificate(contentCertificate),
		VerifyPairingPeer:   func(IdentityCertificate) error { return nil },
		VerifyConsensusPeer: func(IdentityCertificate) error { return nil },
		VerifyContentPeer:   func(ContentCertificate) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}
	if _, err := loadServerContentCertificate(
		identityBinding, staticContentCertificate(contentCertificate),
	); !errors.Is(err, ErrTLSAdmission) {
		t.Fatalf("loadServerContentCertificate() error = %v, want %v", err, ErrTLSAdmission)
	}
}

func TestIdentityPlanesRemainAvailableWithoutContentCertificate(t *testing.T) {
	t.Parallel()

	serverKey := certificatePrivateKey(41)
	serverCertificate, serverBinding, err := issueIdentityCertificate(
		certificateTestSessionID, 2, serverKey,
		bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := certificatePrivateKey(42)
	clientCertificate, clientBinding, err := issueIdentityCertificate(
		certificateTestSessionID, 2, clientKey,
		bytes.NewReader(bytes.Repeat([]byte{0x77}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	contentRequested := false
	provider := func() (tls.Certificate, error) {
		contentRequested = true
		return tls.Certificate{}, ErrContentCertificateUnavailable
	}
	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{
		IdentityCertificate: serverCertificate,
		ContentCertificate:  provider,
		VerifyPairingPeer: func(certificate IdentityCertificate) error {
			return certificate.VerifyIdentity(
				certificateTestSessionID, 2, clientBinding.DeviceID,
				clientKey.Public().(ed25519.PublicKey),
			)
		},
		VerifyConsensusPeer: func(IdentityCertificate) error { return nil },
		VerifyContentPeer:   func(ContentCertificate) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientTLSConfig(ClientTLSOptions{
		Plane: PlanePairing, Certificate: clientCertificate,
		VerifyIdentityPeer: func(certificate IdentityCertificate) error {
			return certificate.VerifyIdentity(
				certificateTestSessionID, 2, serverBinding.DeviceID,
				serverKey.Public().(ed25519.PublicKey),
			)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, clientErr, serverErr := tlsPipeHandshake(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("identity handshake errors = client %v, server %v", clientErr, serverErr)
	}
	if contentRequested {
		t.Fatal("identity handshake requested a content certificate")
	}
	if _, err := loadServerContentCertificate(serverBinding, provider); !errors.Is(err, ErrTLSAdmission) {
		t.Fatalf("missing content certificate error = %v, want %v", err, ErrTLSAdmission)
	}
}

func tlsTestConfigs(
	t testing.TB,
) (*tls.Config, tls.Certificate, tls.Certificate) {
	t.Helper()
	serverIdentityKey := certificatePrivateKey(21)
	serverIdentityCertificate, _, err := issueIdentityCertificate(
		certificateTestSessionID, 1, serverIdentityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x71}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clientIdentityKey := certificatePrivateKey(22)
	clientIdentityCertificate, _, err := issueIdentityCertificate(
		certificateTestSessionID, 1, clientIdentityKey,
		bytes.NewReader(bytes.Repeat([]byte{0x72}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	epochKey := certificatePrivateKey(23)
	authorization := certificateAuthorizationForKeys(
		t, serverIdentityKey, epochKey, 2, 42,
	)
	contentCertificate, _, err := issueContentCertificate(
		authorization, epochKey,
		bytes.NewReader(bytes.Repeat([]byte{0x75}, 64)),
	)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := NewServerTLSConfig(ServerTLSOptions{
		IdentityCertificate: serverIdentityCertificate,
		ContentCertificate:  staticContentCertificate(contentCertificate),
		VerifyPairingPeer:   func(IdentityCertificate) error { return nil },
		VerifyConsensusPeer: func(IdentityCertificate) error { return nil },
		VerifyContentPeer:   func(ContentCertificate) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return serverConfig, clientIdentityCertificate, contentCertificate
}

func staticContentCertificate(
	certificate tls.Certificate,
) ContentCertificateProvider {
	return func() (tls.Certificate, error) { return certificate, nil }
}

func tlsPipeHandshake(
	t testing.TB,
	clientConfig *tls.Config,
	serverConfig *tls.Config,
) (tls.ConnectionState, tls.ConnectionState, error, error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	client := tls.Client(clientSide, clientConfig)
	server := tls.Server(serverSide, serverConfig)
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		state tls.ConnectionState
		err   error
	}
	clientResult := make(chan result, 1)
	serverResult := make(chan result, 1)
	go func() {
		err := client.HandshakeContext(ctx)
		clientResult <- result{state: client.ConnectionState(), err: err}
	}()
	go func() {
		err := server.HandshakeContext(ctx)
		serverResult <- result{state: server.ConnectionState(), err: err}
	}()
	clientOutcome := <-clientResult
	serverOutcome := <-serverResult
	return clientOutcome.state, serverOutcome.state, clientOutcome.err, serverOutcome.err
}
