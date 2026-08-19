package pairingjoiner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairinghttp"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestJoinerRealTLSPairingHTTPFlow(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	invite := fixture.options.Invite.Invite()
	defer clear(invite.Secret[:])
	joinerPublicKey := fixture.joinerPrivateKey.Public().(ed25519.PublicKey)
	service := &integrationPairingService{
		invite:                  fixture.options.Invite,
		expectedJoinerDeviceID:  inviteSubjectDeviceID(t, joinerPublicKey),
		expectedJoinerPublicKey: bytes.Clone(joinerPublicKey),
	}
	pairingServer, err := pairinghttp.New(service)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, _, err := transport.IssueIdentityCertificate(
		invite.SessionID,
		invite.RecoveryGeneration,
		fixture.inviterPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTLSCertificate(&serverCertificate)
	verifyJoiner := func(
		certificate transport.IdentityCertificate,
	) error {
		return certificate.VerifyIdentity(
			invite.SessionID,
			invite.RecoveryGeneration,
			service.expectedJoinerDeviceID,
			service.expectedJoinerPublicKey,
		)
	}
	serverTLS, err := integrationServerTLS(
		serverCertificate,
		verifyJoiner,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTLSConfig(serverTLS)

	serverContext, cancelServer := context.WithCancel(
		context.Background(),
	)
	defer cancelServer()
	dialer := newIntegrationDialer(
		t,
		serverContext,
		pairingServer,
		serverTLS,
		verifyJoiner,
	)
	fixture.options.Dialer = dialer
	runtime := testRuntime(nil)
	runtime.openClient = openPairingClient
	runtime.wait = waitContext
	runtime.confirmationPollDelay = time.Millisecond
	joiner, err := newJoiner(fixture.options, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()

	operationContext, cancelOperation := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelOperation()
	review, err := joiner.Begin(operationContext)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	result, err := joiner.Decide(operationContext, true)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if result.Confirmation.Status != pairing.StatusConfirmed ||
		result.Review.SAS != review.SAS ||
		review.SAS == "" ||
		review.ConnectedEndpoint !=
			netip.MustParseAddrPort("192.0.2.10:47831") {
		t.Fatalf("pairing result = %+v", result)
	}

	calls := service.snapshot()
	if len(calls) != 3 ||
		calls[0].operation != "request" ||
		calls[1].operation != "confirm" ||
		calls[2].operation != "confirm" ||
		calls[0].sas != review.SAS {
		t.Fatalf("service calls = %+v", calls)
	}
	for index := 1; index < len(calls); index++ {
		if !bytes.Equal(calls[0].exporter, calls[index].exporter) {
			t.Fatalf("call %d changed TLS exporter", index+1)
		}
	}
	if !bytes.Equal(calls[1].body, calls[2].body) {
		t.Fatal("confirmation poll changed canonical decision")
	}
	if err := dialer.wait(t); err != nil {
		t.Fatalf("pairing server error = %v", err)
	}
}

func TestJoinerRealTLSRejectsUnpinnedInviter(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	invite := fixture.options.Invite.Invite()
	defer clear(invite.Secret[:])
	joinerPublicKey := fixture.joinerPrivateKey.Public().(ed25519.PublicKey)
	service := &integrationPairingService{
		invite:                  fixture.options.Invite,
		expectedJoinerDeviceID:  inviteSubjectDeviceID(t, joinerPublicKey),
		expectedJoinerPublicKey: bytes.Clone(joinerPublicKey),
	}
	pairingServer, err := pairinghttp.New(service)
	if err != nil {
		t.Fatal(err)
	}
	wrongInviterKey := testPrivateKey(0x79)
	serverCertificate, _, err := transport.IssueIdentityCertificate(
		invite.SessionID,
		invite.RecoveryGeneration,
		wrongInviterKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTLSCertificate(&serverCertificate)
	verifyJoiner := func(
		certificate transport.IdentityCertificate,
	) error {
		return certificate.VerifyIdentity(
			invite.SessionID,
			invite.RecoveryGeneration,
			service.expectedJoinerDeviceID,
			service.expectedJoinerPublicKey,
		)
	}
	serverTLS, err := integrationServerTLS(
		serverCertificate,
		verifyJoiner,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTLSConfig(serverTLS)

	serverContext, cancelServer := context.WithCancel(
		context.Background(),
	)
	defer cancelServer()
	dialer := newIntegrationDialer(
		t,
		serverContext,
		pairingServer,
		serverTLS,
		verifyJoiner,
	)
	fixture.options.Dialer = dialer
	runtime := testRuntime(nil)
	runtime.openClient = openPairingClient
	joiner, err := newJoiner(fixture.options, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()

	_, err = joiner.Begin(context.Background())
	if !errors.Is(err, ErrEndpointsUnavailable) {
		t.Fatalf(
			"Begin() error = %v, want %v",
			err,
			ErrEndpointsUnavailable,
		)
	}
	if len(service.snapshot()) != 0 {
		t.Fatal("unpinned inviter reached pairing HTTP service")
	}
	cancelServer()
	if err := dialer.wait(t); !errors.Is(err, pairinghttp.ErrTLSBinding) {
		t.Fatalf(
			"pairing server error = %v, want %v",
			err,
			pairinghttp.ErrTLSBinding,
		)
	}
}

type integrationPairingService struct {
	mu                       sync.Mutex
	invite                   pairing.SignedInvite
	expectedJoinerDeviceID   domain.DeviceID
	expectedJoinerPublicKey  ed25519.PublicKey
	requestDigest            [32]byte
	confirmationRequestCount int
	calls                    []integrationServiceCall
}

type integrationServiceCall struct {
	operation string
	body      []byte
	exporter  []byte
	sas       string
}

func (service *integrationPairingService) HandleRequest(
	ctx context.Context,
	body []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) (pairingservice.RequestResult, error) {
	if err := ctx.Err(); err != nil {
		return pairingservice.RequestResult{}, err
	}
	request, err := pairing.ParseRequest(body)
	if err != nil {
		return pairingservice.RequestResult{}, err
	}
	verified, err := request.Verify(service.invite, exporter)
	if err != nil {
		return pairingservice.RequestResult{}, err
	}
	invite := service.invite.Invite()
	defer clear(invite.Secret[:])
	if err := peer.VerifyIdentity(
		invite.SessionID,
		invite.RecoveryGeneration,
		service.expectedJoinerDeviceID,
		service.expectedJoinerPublicKey,
	); err != nil {
		return pairingservice.RequestResult{}, err
	}
	acknowledgment, err := pairing.NewRequestAcknowledgment(verified)
	if err != nil {
		return pairingservice.RequestResult{}, err
	}
	service.mu.Lock()
	service.requestDigest = verified.RequestDigest()
	service.calls = append(service.calls, integrationServiceCall{
		operation: "request",
		body:      bytes.Clone(body),
		exporter:  bytes.Clone(exporter),
		sas:       verified.SAS(),
	})
	service.mu.Unlock()
	return pairingservice.RequestResult{
		Acknowledgment: acknowledgment,
		Core:           verified.Core().Value(),
		SAS:            verified.SAS(),
	}, nil
}

func (service *integrationPairingService) ConfirmRemote(
	ctx context.Context,
	body []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) (pairing.ConfirmationResult, error) {
	if err := ctx.Err(); err != nil {
		return pairing.ConfirmationResult{}, err
	}
	confirmation, err := pairing.ParseConfirmation(body)
	if err != nil {
		return pairing.ConfirmationResult{}, err
	}
	invite := service.invite.Invite()
	defer clear(invite.Secret[:])
	if err := peer.VerifyIdentity(
		invite.SessionID,
		invite.RecoveryGeneration,
		service.expectedJoinerDeviceID,
		service.expectedJoinerPublicKey,
	); err != nil {
		return pairing.ConfirmationResult{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if confirmation.RequestDigest != service.requestDigest ||
		!confirmation.Confirmed {
		return pairing.ConfirmationResult{},
			errors.New("changed integration confirmation")
	}
	service.confirmationRequestCount++
	status := pairing.StatusAwaitingInviter
	if service.confirmationRequestCount > 1 {
		status = pairing.StatusConfirmed
	}
	service.calls = append(service.calls, integrationServiceCall{
		operation: "confirm",
		body:      bytes.Clone(body),
		exporter:  bytes.Clone(exporter),
	})
	return pairing.NewConfirmationResult(
		confirmation.AttemptID,
		confirmation.RequestDigest,
		status,
	)
}

func (service *integrationPairingService) snapshot() []integrationServiceCall {
	service.mu.Lock()
	defer service.mu.Unlock()
	result := make([]integrationServiceCall, len(service.calls))
	for index, call := range service.calls {
		result[index] = integrationServiceCall{
			operation: call.operation,
			body:      bytes.Clone(call.body),
			exporter:  bytes.Clone(call.exporter),
			sas:       call.sas,
		}
	}
	return result
}

type integrationDialer struct {
	mu         sync.Mutex
	server     *pairinghttp.Server
	tlsConfig  *tls.Config
	verifyPeer transport.IdentityPeerVerifier
	ctx        context.Context
	permit     *transport.HandshakePermit
	done       chan error
	dialed     bool
}

func newIntegrationDialer(
	t testing.TB,
	ctx context.Context,
	server *pairinghttp.Server,
	tlsConfig *tls.Config,
	verifyPeer transport.IdentityPeerVerifier,
) *integrationDialer {
	t.Helper()
	limiter := transport.NewAdmissionLimiter()
	permit, err := limiter.TryAcquire(
		netip.MustParseAddr("192.0.2.200"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &integrationDialer{
		server: server, tlsConfig: tlsConfig, verifyPeer: verifyPeer,
		ctx: ctx, permit: permit, done: make(chan error, 1),
	}
}

func (dialer *integrationDialer) DialPairingEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if dialer.dialed {
		return nil, errors.New("integration dialer is single-use")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if endpoint != netip.MustParseAddrPort("192.0.2.10:47831") {
		return nil, errors.New("unexpected integration endpoint")
	}
	dialer.dialed = true
	serverRaw, clientRaw := net.Pipe()
	serverTLS := tls.Server(serverRaw, dialer.tlsConfig)
	go func() {
		dialer.done <- dialer.server.ServeConn(
			dialer.ctx,
			serverTLS,
			dialer.permit,
			dialer.verifyPeer,
		)
	}()
	return clientRaw, nil
}

func (dialer *integrationDialer) wait(t testing.TB) error {
	t.Helper()
	select {
	case err := <-dialer.done:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("pairing server did not stop")
		return context.DeadlineExceeded
	}
}

func integrationServerTLS(
	certificate tls.Certificate,
	verifyJoiner transport.IdentityPeerVerifier,
) (*tls.Config, error) {
	return transport.NewServerTLSConfig(
		transport.ServerTLSOptions{
			IdentityCertificate: certificate,
			ContentCertificate: func() (tls.Certificate, error) {
				return tls.Certificate{},
					transport.ErrContentCertificateUnavailable
			},
			VerifyPairingPeer: verifyJoiner,
			VerifyConsensusPeer: func(transport.IdentityCertificate) error {
				return errors.New("consensus unavailable")
			},
			VerifyContentPeer: func(
				transport.ContentCertificate,
			) (transport.ContentPeerAdmission, error) {
				return transport.ContentPeerAdmission{},
					errors.New("content unavailable")
			},
		},
	)
}

func inviteSubjectDeviceID(
	t testing.TB,
	publicKey ed25519.PublicKey,
) domain.DeviceID {
	t.Helper()
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return deviceID
}
