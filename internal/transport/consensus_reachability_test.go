package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

func testConsensusReachabilitySuccess(t *testing.T) {
	harness := newConsensusHarness(t)
	network := newConsensusTestNetworkTransport(
		t,
		harness.client,
		harness.clientID,
		func(domain.DeviceID) error { return nil },
	)
	t.Cleanup(func() { _ = network.Close() })

	token, err := network.ProbeConsensusPeer(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("ProbeConsensusPeer(): %v", err)
	}
	if err := network.VerifyConsensusPeerReachability(
		token,
	); err != nil {
		t.Fatalf("VerifyConsensusPeerReachability(): %v", err)
	}
	second, err := network.ProbeConsensusPeer(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("ProbeConsensusPeer(reuse): %v", err)
	}
	if second.Generation != token.Generation {
		t.Fatalf(
			"reused connection generation = %d, want %d",
			second.Generation,
			token.Generation,
		)
	}
	if got := harness.dialer.count.Load(); got != 1 {
		t.Fatalf("physical connection count = %d, want 1", got)
	}
}

func testConsensusReachabilityTokenInvalidation(t *testing.T) {
	harness := newConsensusHarness(t)
	token, err := harness.client.ProbeConsensusPeer(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("ProbeConsensusPeer(): %v", err)
	}
	peer, err := harness.client.peer(harness.serverID)
	if err != nil {
		t.Fatalf("peer(): %v", err)
	}
	if err := peer.close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close physical connection: %v", err)
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		token,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(closed) error = %v", err)
	}

	replacement, err := harness.client.ProbeConsensusPeer(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("ProbeConsensusPeer(replacement): %v", err)
	}
	if replacement.Generation == token.Generation {
		t.Fatalf(
			"replacement retained generation %d",
			replacement.Generation,
		)
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		replacement,
	); err != nil {
		t.Fatalf("VerifyConsensusPeerReachability(replacement): %v", err)
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		token,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(replaced) error = %v", err)
	}

	wrongDevice := domain.DeviceID("cc1" + strings.Repeat("f", 64))
	wrongDeviceToken := replacement
	wrongDeviceToken.DeviceID = wrongDevice
	if err := harness.client.VerifyConsensusPeerReachability(
		wrongDeviceToken,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(wrong device) error = %v", err)
	}
	forged := replacement
	forged.Generation++
	if err := harness.client.VerifyConsensusPeerReachability(
		forged,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(forged) error = %v", err)
	}

	close(harness.clientChanges)
	deadline := time.Now().Add(consensusTestTimeout)
	for {
		peer.mu.Lock()
		generation := peer.generation
		physical := peer.physical
		peer.mu.Unlock()
		if generation > replacement.Generation && physical == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"authorization closure retained physical generation %d",
				generation,
			)
		}
		time.Sleep(time.Millisecond)
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		replacement,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(auth closed) error = %v", err)
	}
}

func testConsensusReachabilityCancellation(t *testing.T) {
	harness := newConsensusHarness(t)
	dialer := &blockingConsensusProbeDialer{
		entered: make(chan struct{}),
	}
	harness.client.dialer = dialer

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := harness.client.ProbeConsensusPeer(ctx, harness.serverID)
		result <- err
	}()
	select {
	case <-dialer.entered:
	case <-time.After(consensusTestTimeout):
		t.Fatal("reachability probe did not enter dial")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ProbeConsensusPeer() error = %v", err)
		}
	case <-time.After(consensusTestTimeout):
		t.Fatal("canceled reachability probe did not return")
	}
}

func testConsensusReachabilityVerificationIsLocal(t *testing.T) {
	harness := newConsensusHarness(t)
	token, err := harness.client.ProbeConsensusPeer(
		t.Context(),
		harness.serverID,
	)
	if err != nil {
		t.Fatalf("ProbeConsensusPeer(): %v", err)
	}
	dials := harness.dialer.count.Load()
	harness.client.authorizePeer = func(domain.DeviceID) error {
		panic("verification invoked authorization callback")
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		token,
	); err != nil {
		t.Fatalf("VerifyConsensusPeerReachability(): %v", err)
	}
	if got := harness.dialer.count.Load(); got != dials {
		t.Fatalf("verification dial count = %d, want %d", got, dials)
	}

	unknown := ConsensusPeerReachabilityToken{
		DeviceID:   harness.serverID,
		Generation: token.Generation + 1,
	}
	if err := harness.client.VerifyConsensusPeerReachability(
		unknown,
	); !errors.Is(err, ErrConsensusReachabilityTokenStale) {
		t.Fatalf("VerifyConsensusPeerReachability(unknown) error = %v", err)
	}
	if got := harness.dialer.count.Load(); got != dials {
		t.Fatalf("stale verification dial count = %d, want %d", got, dials)
	}
}

type blockingConsensusProbeDialer struct {
	once    sync.Once
	entered chan struct{}
}

func (dialer *blockingConsensusProbeDialer) DialConsensusEndpoint(
	ctx context.Context,
	_ netip.AddrPort,
) (net.Conn, error) {
	dialer.once.Do(func() { close(dialer.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}
