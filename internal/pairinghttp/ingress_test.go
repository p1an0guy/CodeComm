package pairinghttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/transport"
)

func TestPairingHTTPComposesWithSharedPeerIngress(t *testing.T) {
	t.Parallel()

	service := newRecordingService(t)
	pairingServer, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := testIdentityKey(0x61)
	serverCertificate, serverBinding, err :=
		transport.IssueIdentityCertificate(
			pairingHTTPTestSessionID,
			0,
			serverKey,
		)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := testIdentityKey(0x62)
	clientCertificate, clientBinding, err :=
		transport.IssueIdentityCertificate(
			pairingHTTPTestSessionID,
			0,
			clientKey,
		)
	if err != nil {
		t.Fatal(err)
	}
	var revoked atomic.Bool
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener: listener,
		TLS: transport.ServerTLSOptions{
			IdentityCertificate: serverCertificate,
			ContentCertificate: func() (tls.Certificate, error) {
				return tls.Certificate{},
					transport.ErrContentCertificateUnavailable
			},
			VerifyPairingPeer: func(
				certificate transport.IdentityCertificate,
			) error {
				if revoked.Load() {
					return errors.New("peer revoked")
				}
				return certificate.VerifyIdentity(
					pairingHTTPTestSessionID,
					0,
					clientBinding.DeviceID,
					clientKey.Public().(ed25519.PublicKey),
				)
			},
			VerifyConsensusPeer: func(
				transport.IdentityCertificate,
			) error {
				return errors.New("not admitted")
			},
			VerifyContentPeer: func(
				transport.ContentCertificate,
			) (transport.ContentPeerAdmission, error) {
				return transport.ContentPeerAdmission{},
					errors.New("content unavailable")
			},
		},
		Pairing: pairingServer,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ingress.Serve(serveContext)
	}()
	var stopOnce sync.Once
	stopIngress := func() {
		stopOnce.Do(func() {
			cancelServe()
			shutdownContext, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()
			if err := ingress.Shutdown(shutdownContext); err != nil {
				t.Errorf("Ingress.Shutdown() error = %v", err)
			}
			select {
			case err := <-serveDone:
				if err != nil {
					t.Errorf("Ingress.Serve() error = %v", err)
				}
			case <-shutdownContext.Done():
				t.Errorf(
					"peer ingress did not stop: %v",
					shutdownContext.Err(),
				)
			}
		})
	}
	t.Cleanup(stopIngress)

	clientTLSConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:       transport.PlanePairing,
			Certificate: clientCertificate,
			VerifyIdentityPeer: func(
				certificate transport.IdentityCertificate,
			) error {
				return certificate.VerifyIdentity(
					pairingHTTPTestSessionID,
					0,
					serverBinding.DeviceID,
					serverKey.Public().(ed25519.PublicKey),
				)
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	dialContext, cancelDial := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelDial()
	rawConnection, err := (&net.Dialer{}).DialContext(
		dialContext,
		"tcp",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := OpenClient(
		dialContext,
		tls.Client(rawConnection, clientTLSConfig),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	harness := &testTLSHarness{
		serverKey: serverKey, clientKey: clientKey,
		serverBinding: serverBinding, clientBinding: clientBinding,
	}
	invite, core := clientPairingFixture(t, harness)
	request, err := pairing.BuildRequest(invite, core, client.exporter[:])
	if err != nil {
		t.Fatal(err)
	}
	verified, err := request.Verify(invite, client.exporter[:])
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := request.Digest()
	service.acknowledgment, err = pairing.NewRequestAcknowledgmentValues(
		core.Value().AttemptID,
		requestDigest,
		invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Request(dialContext, invite, core)
	if err != nil ||
		result.Acknowledgment.RequestDigest != requestDigest ||
		result.SAS != verified.SAS() ||
		result.SAS == "" {
		t.Fatalf("Request() = (%+v, %v)", result, err)
	}

	confirmationResult, err := pairing.NewConfirmationResult(
		core.Value().AttemptID,
		requestDigest,
		pairing.StatusAwaitingInviter,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.confirmation = confirmationResult
	confirmation, err := pairing.NewConfirmation(
		core.Value().AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := client.Confirm(dialContext, confirmation)
	if err != nil || !bytes.Equal(
		confirmed.CanonicalBytes(),
		confirmationResult.CanonicalBytes(),
	) {
		t.Fatalf("Confirm() = (%+v, %v)", confirmed, err)
	}
	revoked.Store(true)
	if _, err := client.Confirm(dialContext, confirmation); err == nil {
		t.Fatal("Confirm() succeeded after current peer policy revoked access")
	}

	calls := service.snapshot()
	if len(calls) != 2 ||
		calls[0].operation != "request" ||
		calls[1].operation != "confirm" {
		t.Fatalf("service calls = %+v", calls)
	}
	for index, call := range calls {
		if call.peer.Binding != clientBinding ||
			!bytes.Equal(call.exporter, client.exporter[:]) {
			t.Fatalf("service call %d TLS binding = %+v", index+1, call)
		}
	}
	if !bytes.Equal(calls[0].exporter, calls[1].exporter) {
		t.Fatal("request and confirmation used different TLS exporters")
	}

	stopIngress()
}
