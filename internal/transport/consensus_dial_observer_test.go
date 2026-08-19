package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
)

type observedConsensusDial struct {
	deviceID          domain.DeviceID
	endpoint          netip.AddrPort
	contextActive     bool
	identityVerified  bool
	liveConfiguration bool
}

func testConsensusAuthenticatedDialObserver(t *testing.T) {
	t.Run("success exact values and connection reuse", func(t *testing.T) {
		var identityVerified atomic.Bool
		var liveConfigurationAuthorized atomic.Bool
		observations := make(chan observedConsensusDial, 2)
		harness := newConsensusHarnessWithAuthenticatedDialObserver(
			t,
			func(
				ctx context.Context,
				deviceID domain.DeviceID,
				endpoint netip.AddrPort,
			) error {
				observations <- observedConsensusDial{
					deviceID:          deviceID,
					endpoint:          endpoint,
					contextActive:     ctx != nil && ctx.Err() == nil,
					identityVerified:  identityVerified.Load(),
					liveConfiguration: liveConfigurationAuthorized.Load(),
				}
				return nil
			},
		)

		verifyExpectedPeer := harness.client.verifyExpectedPeer
		harness.client.verifyExpectedPeer = func(
			expected domain.DeviceID,
			certificate IdentityCertificate,
		) error {
			err := verifyExpectedPeer(expected, certificate)
			if err == nil {
				identityVerified.Store(true)
			}
			return err
		}
		authorizePeer := harness.client.authorizePeer
		harness.client.authorizePeer = func(deviceID domain.DeviceID) error {
			err := authorizePeer(deviceID)
			if err == nil && identityVerified.Load() {
				liveConfigurationAuthorized.Store(true)
			}
			return err
		}

		for attempt := range 2 {
			outbound, err := harness.client.Dial(
				raft.ServerAddress(harness.serverID),
				consensusTestTimeout,
			)
			if err != nil {
				t.Fatalf("Dial(%d): %v", attempt+1, err)
			}
			inbound := acceptConsensusStream(t, harness.server)
			_ = outbound.Close()
			_ = inbound.Close()
		}

		select {
		case observed := <-observations:
			if observed.deviceID != harness.serverID {
				t.Fatalf(
					"observer device ID = %q, want %q",
					observed.deviceID,
					harness.serverID,
				)
			}
			if observed.endpoint != harness.resolver.endpoint {
				t.Fatalf(
					"observer endpoint = %s, want %s",
					observed.endpoint,
					harness.resolver.endpoint,
				)
			}
			if !observed.contextActive ||
				!observed.identityVerified ||
				!observed.liveConfiguration {
				t.Fatalf("observer ordering = %+v", observed)
			}
		default:
			t.Fatal("authenticated physical dial was not observed")
		}
		select {
		case extra := <-observations:
			t.Fatalf("reused physical connection was observed again: %+v", extra)
		default:
		}
		if got := harness.dialer.count.Load(); got != 1 {
			t.Fatalf("physical connection count = %d, want 1", got)
		}
	})

	t.Run("observer failure closes connection", func(t *testing.T) {
		observerErr := errors.New("persist authenticated endpoint")
		var calls atomic.Uint64
		harness := newConsensusHarnessWithAuthenticatedDialObserver(
			t,
			func(
				context.Context,
				domain.DeviceID,
				netip.AddrPort,
			) error {
				calls.Add(1)
				return observerErr
			},
		)

		connection, err := harness.client.Dial(
			raft.ServerAddress(harness.serverID),
			consensusTestTimeout,
		)
		if connection != nil {
			_ = connection.Close()
			t.Fatal("observer failure returned a logical connection")
		}
		if !errors.Is(err, ErrConsensusEndpointUnavailable) ||
			!strings.Contains(err.Error(), observerErr.Error()) {
			t.Fatalf("Dial(observer failure) error = %v", err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("observer calls = %d, want 1", got)
		}
		if got := harness.dialer.count.Load(); got != 1 {
			t.Fatalf("physical connection attempts = %d, want 1", got)
		}
		harness.dialer.wait(t)
		select {
		case stream := <-harness.server.accept:
			_ = stream.Close()
			t.Fatal("observer failure emitted application bytes")
		default:
		}
		peer, peerErr := harness.client.peer(harness.serverID)
		if peerErr != nil {
			t.Fatalf("peer(): %v", peerErr)
		}
		peer.mu.Lock()
		physical := peer.physical
		peer.mu.Unlock()
		if physical != nil {
			t.Fatal("observer failure retained a physical connection")
		}
	})

	t.Run("unauthenticated attempts are not observed", func(t *testing.T) {
		t.Run("endpoint dial failure", func(t *testing.T) {
			assertConsensusDialObserverNotCalled(
				t,
				func(harness *consensusHarness) {
					harness.client.dialer = consensusRejectDialer{}
				},
				harnessServerAddress,
			)
		})
		t.Run("TLS handshake failure", func(t *testing.T) {
			assertConsensusDialObserverNotCalled(
				t,
				func(harness *consensusHarness) {
					harness.client.dialer = consensusTLSFailureDialer{}
				},
				harnessServerAddress,
			)
		})
		t.Run("post-TLS live-configuration denial", func(t *testing.T) {
			var observerCalls atomic.Uint64
			var authorizationCalls atomic.Uint64
			harness := newConsensusHarnessWithAuthenticatedDialObserver(
				t,
				func(
					context.Context,
					domain.DeviceID,
					netip.AddrPort,
				) error {
					observerCalls.Add(1)
					return nil
				},
			)
			authorizePeer := harness.client.authorizePeer
			harness.client.authorizePeer = func(
				deviceID domain.DeviceID,
			) error {
				if authorizationCalls.Add(1) > 1 {
					return ErrConsensusPeerDenied
				}
				return authorizePeer(deviceID)
			}

			connection, err := harness.client.Dial(
				raft.ServerAddress(harness.serverID),
				consensusTestTimeout,
			)
			if connection != nil {
				_ = connection.Close()
				t.Fatal("post-TLS authorization denial returned a connection")
			}
			if !errors.Is(err, ErrConsensusPeerDenied) {
				t.Fatalf("Dial(post-TLS authorization denial) error = %v", err)
			}
			if got := observerCalls.Load(); got != 0 {
				t.Fatalf("observer calls = %d, want 0", got)
			}
			if got := harness.dialer.count.Load(); got != 1 {
				t.Fatalf("physical connection attempts = %d, want 1", got)
			}
			harness.dialer.wait(t)
		})
		t.Run("wrong expected identity", func(t *testing.T) {
			wrongKey := certificatePrivateKey(93)
			_, wrongBinding, err := IssueIdentityCertificate(
				certificateTestSessionID,
				1,
				wrongKey,
			)
			if err != nil {
				t.Fatalf("IssueIdentityCertificate(wrong target): %v", err)
			}
			assertConsensusDialObserverNotCalled(
				t,
				func(harness *consensusHarness) {
					harness.clientAllowed.Store(wrongBinding.DeviceID, true)
					harness.resolver.deviceID = wrongBinding.DeviceID
				},
				func(*consensusHarness) raft.ServerAddress {
					return raft.ServerAddress(wrongBinding.DeviceID)
				},
			)
		})
	})

	t.Run("context cancellation", func(t *testing.T) {
		var calls atomic.Uint64
		var sawCancellation atomic.Bool
		started := make(chan struct{})
		harness := newConsensusHarnessWithAuthenticatedDialObserver(
			t,
			func(
				ctx context.Context,
				_ domain.DeviceID,
				_ netip.AddrPort,
			) error {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-ctx.Done()
				sawCancellation.Store(
					errors.Is(ctx.Err(), context.DeadlineExceeded),
				)
				return ctx.Err()
			},
		)

		connection, err := harness.client.Dial(
			raft.ServerAddress(harness.serverID),
			100*time.Millisecond,
		)
		if connection != nil {
			_ = connection.Close()
			t.Fatal("canceled observer returned a logical connection")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial(canceled observer) error = %v", err)
		}
		select {
		case <-started:
		default:
			t.Fatal("observer was not invoked before cancellation")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("observer calls = %d, want 1", got)
		}
		if !sawCancellation.Load() {
			t.Fatal("observer context did not carry dial cancellation")
		}
		harness.dialer.wait(t)
	})
}

type consensusHarnessAddress func(*consensusHarness) raft.ServerAddress

func harnessServerAddress(harness *consensusHarness) raft.ServerAddress {
	return raft.ServerAddress(harness.serverID)
}

func assertConsensusDialObserverNotCalled(
	t *testing.T,
	configure func(*consensusHarness),
	address consensusHarnessAddress,
) {
	t.Helper()
	var calls atomic.Uint64
	harness := newConsensusHarnessWithAuthenticatedDialObserver(
		t,
		func(
			context.Context,
			domain.DeviceID,
			netip.AddrPort,
		) error {
			calls.Add(1)
			return nil
		},
	)
	configure(harness)
	connection, err := harness.client.Dial(
		address(harness),
		500*time.Millisecond,
	)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("unauthenticated attempt returned a logical connection")
	}
	if !errors.Is(err, ErrConsensusEndpointUnavailable) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial(unauthenticated attempt) error = %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("observer calls = %d, want 0", got)
	}
}

type consensusTLSFailureDialer struct{}

func (consensusTLSFailureDialer) DialConsensusEndpoint(
	context.Context,
	netip.AddrPort,
) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}
