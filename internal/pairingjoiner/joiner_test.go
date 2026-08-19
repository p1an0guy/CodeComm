package pairingjoiner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairinghttp"
)

var (
	joinerTestNow = time.Date(
		2026,
		time.August,
		18,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	joinerTestAttemptID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000701",
	)
	joinerTestInviteID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000702",
	)
	joinerTestSessionID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000703",
	)
	joinerTestWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
)

func TestJoinerCanonicalEndpointRetryReviewAndDecision(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeReadmission)
	identityBefore := bytes.Clone(fixture.options.IdentityPrivateKey)
	epochBefore := bytes.Clone(fixture.options.InitialEpochPrivateKey)
	requestDigest := sha256.Sum256([]byte("joiner request"))
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		fixture.options.AttemptID,
		requestDigest,
		fixture.options.Invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &scriptedClient{
		requestSteps: []requestStep{
			{
				err: &pairinghttp.RemoteError{
					Status:    503,
					Code:      "temporarily_unavailable",
					Retryable: true,
				},
			},
			{
				result: pairinghttp.RequestResult{
					Acknowledgment: acknowledgment,
					SAS:            "0123 4567 8901 2345 6789",
				},
			},
		},
		confirmationStatuses: []pairing.ConfirmationStatus{
			pairing.StatusAwaitingInviter,
			pairing.StatusFinalizing,
			pairing.StatusConfirmed,
		},
	}
	dialer := &scriptedDialer{
		results: []dialResult{
			{err: errors.New("route unavailable")},
			{},
		},
	}
	fixture.options.Dialer = dialer
	runtime := testRuntime(client)
	joiner, err := newJoiner(fixture.options, runtime)
	if err != nil {
		t.Fatalf("newJoiner() error = %v", err)
	}
	t.Cleanup(func() { _ = joiner.Close() })

	config := joiner.tlsConfig
	if config == nil || len(config.Certificates) != 1 {
		t.Fatal("joiner omitted its owned identity certificate")
	}
	privateCopy, ok := config.Certificates[0].PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf(
			"TLS private key type = %T",
			config.Certificates[0].PrivateKey,
		)
	}
	privateBytes := privateCopy
	certificateBytes := config.Certificates[0].Certificate[0]

	review, err := joiner.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	wantEndpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:47831"),
		netip.MustParseAddrPort("[2001:db8::10]:47831"),
	}
	if got := dialer.endpoints(); !equalEndpoints(got, wantEndpoints) {
		t.Fatalf("dialed endpoints = %v, want %v", got, wantEndpoints)
	}
	for index, bounded := range dialer.boundedCalls() {
		if !bounded {
			t.Errorf("dial call %d had no per-attempt deadline", index)
		}
	}
	assertExactReview(t, review, fixture, requestDigest, wantEndpoints[1])

	requestCalls := client.requests()
	if len(requestCalls) != 2 ||
		requestCalls[0].inviteCode != requestCalls[1].inviteCode ||
		!bytes.Equal(
			requestCalls[0].core,
			requestCalls[1].core,
		) {
		t.Fatalf("request retries changed: %+v", requestCalls)
	}

	originalSubject := *fixture.subjectDeviceID
	originalVersion := *fixture.expectedEntityVersion
	*review.SubjectDeviceID = ""
	*review.ExpectedEntityVersion = 999
	result, err := joiner.Decide(context.Background(), true)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if result.Confirmation.Status != pairing.StatusConfirmed ||
		result.Review.SubjectDeviceID == nil ||
		*result.Review.SubjectDeviceID != originalSubject ||
		result.Review.ExpectedEntityVersion == nil ||
		*result.Review.ExpectedEntityVersion != originalVersion {
		t.Fatalf("terminal result = %+v", result)
	}

	confirmations := client.confirmations()
	if len(confirmations) != 3 {
		t.Fatalf("confirmation calls = %d, want 3", len(confirmations))
	}
	for index := 1; index < len(confirmations); index++ {
		if !bytes.Equal(confirmations[0], confirmations[index]) {
			t.Fatalf("confirmation retry %d changed", index+1)
		}
	}
	decision, err := pairing.ParseConfirmation(confirmations[0])
	if err != nil || !decision.Confirmed ||
		decision.AttemptID != fixture.options.AttemptID ||
		decision.RequestDigest != requestDigest {
		t.Fatalf("confirmation = (%+v, %v)", decision, err)
	}
	if _, err := joiner.Decide(
		context.Background(),
		false,
	); !errors.Is(err, ErrDecisionAlreadyMade) {
		t.Fatalf(
			"changed Decide() error = %v, want %v",
			err,
			ErrDecisionAlreadyMade,
		)
	}
	if client.closeCount() != 1 {
		t.Fatalf("client Close() calls = %d, want 1", client.closeCount())
	}
	if joiner.tlsConfig != nil || config.Certificates != nil ||
		!allZero(privateBytes) || !allZero(certificateBytes) {
		t.Fatal("terminal transition retained owned TLS key material")
	}
	if !bytes.Equal(fixture.options.IdentityPrivateKey, identityBefore) ||
		!bytes.Equal(fixture.options.InitialEpochPrivateKey, epochBefore) {
		t.Fatal("joiner mutated caller-owned private keys")
	}
}

func TestJoinerDoesNotFailOverAfterRequestSubmission(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	client := &scriptedClient{
		requestSteps: []requestStep{{
			err: &pairinghttp.RemoteError{
				Status:    403,
				Code:      "invite_rejected",
				Retryable: false,
			},
		}},
	}
	dialer := &scriptedDialer{results: []dialResult{{}, {}}}
	fixture.options.Dialer = dialer
	joiner, err := newJoiner(fixture.options, testRuntime(client))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()

	_, err = joiner.Begin(context.Background())
	var remote *pairinghttp.RemoteError
	if !errors.As(err, &remote) || remote.Code != "invite_rejected" {
		t.Fatalf("Begin() error = %v", err)
	}
	if got := dialer.endpoints(); len(got) != 1 {
		t.Fatalf("dial calls after request submission = %v", got)
	}
	if client.closeCount() != 1 {
		t.Fatalf("client Close() calls = %d, want 1", client.closeCount())
	}
}

func TestPairingProtocolFailureIsNotRetryable(t *testing.T) {
	t.Parallel()

	if retryablePairingError(pairinghttp.ErrResponseProtocol) {
		t.Fatal("invalid pairing response was treated as retryable")
	}
	if !retryablePairingError(context.DeadlineExceeded) {
		t.Fatal("same-connection timeout was not retryable")
	}
	if !retryablePairingError(&pairinghttp.RemoteError{Retryable: true}) {
		t.Fatal("retryable remote response was not retryable")
	}
	if retryablePairingError(&pairinghttp.RemoteError{Retryable: false}) {
		t.Fatal("terminal remote response was retryable")
	}
}

func TestJoinerDecisionCancellationClosesAndConsumesDecision(
	t *testing.T,
) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	requestDigest := sha256.Sum256([]byte("cancel request"))
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		fixture.options.AttemptID,
		requestDigest,
		fixture.options.Invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	client := &scriptedClient{
		requestSteps: []requestStep{{
			result: pairinghttp.RequestResult{
				Acknowledgment: acknowledgment,
				SAS:            "1111 2222 3333 4444 5555",
			},
		}},
		confirm: func(ctx context.Context) (
			pairing.ConfirmationResult,
			error,
		) {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-ctx.Done()
			return pairing.ConfirmationResult{}, ctx.Err()
		},
	}
	fixture.options.Dialer = &scriptedDialer{
		results: []dialResult{{}},
	}
	joiner, err := newJoiner(fixture.options, testRuntime(client))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()
	if _, err := joiner.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}

	decisionContext, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, decisionErr := joiner.Decide(decisionContext, true)
		result <- decisionErr
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Decide() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Decide() did not honor cancellation")
	}
	if _, err := joiner.Decide(
		context.Background(),
		true,
	); !errors.Is(err, ErrDecisionAlreadyMade) {
		t.Fatalf("second Decide() error = %v", err)
	}
	if client.closeCount() != 1 {
		t.Fatalf("client Close() calls = %d, want 1", client.closeCount())
	}
}

func TestJoinerCloseCancelsBlockedEndpointDial(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	entered := make(chan struct{})
	fixture.options.Dialer = EndpointDialerFunc(
		func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	runtime := testRuntime(&scriptedClient{})
	runtime.endpointAttemptTimeout = time.Minute
	runtime.overallAttemptTimeout = time.Minute
	joiner, err := newJoiner(fixture.options, runtime)
	if err != nil {
		t.Fatal(err)
	}

	beginDone := make(chan error, 1)
	go func() {
		_, beginErr := joiner.Begin(context.Background())
		beginDone <- beginErr
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- joiner.Close() }()
	select {
	case err := <-beginDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Begin() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not cancel endpoint dial")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete")
	}
}

func TestJoinerCloseBeforeCancelInstallationDoesNotStall(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	fixture.options.Dialer = EndpointDialerFunc(
		func(context.Context, netip.AddrPort) (net.Conn, error) {
			return nil, errors.New("dial must not run")
		},
	)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	runtime := testRuntime(&scriptedClient{})
	runtime.now = func() time.Time {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
		return joinerTestNow.Add(time.Minute)
	}
	joiner, err := newJoiner(fixture.options, runtime)
	if err != nil {
		t.Fatal(err)
	}

	beginDone := make(chan error, 1)
	go func() {
		_, beginErr := joiner.Begin(context.Background())
		beginDone <- beginErr
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- joiner.Close() }()
	requestedDeadline := time.NewTimer(2 * time.Second)
	requestedPoll := time.NewTicker(time.Millisecond)
	defer requestedDeadline.Stop()
	defer requestedPoll.Stop()
	for {
		joiner.mu.Lock()
		requested := joiner.closeRequested
		joiner.mu.Unlock()
		if requested {
			break
		}
		select {
		case <-requestedDeadline.C:
			t.Fatal("Close() did not request cancellation")
		case <-requestedPoll.C:
		}
	}
	close(release)

	select {
	case err := <-beginDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Begin() error = %v, want %v", err, ErrClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Begin() stalled before cancel installation")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close() stalled before cancel installation")
	}
}

func TestJoinerRejectsInvalidInviteAndKeyBindings(t *testing.T) {
	t.Parallel()

	valid := newJoinerFixture(t, pairing.ModeNew)
	other := newJoinerFixture(t, pairing.ModeReadmission)
	expired := newJoinerFixture(t, pairing.ModeNew)
	runtime := testRuntime(&scriptedClient{})
	runtime.now = func() time.Time {
		return joinerTestNow.Add(pairing.InviteTTL)
	}

	tests := []struct {
		name    string
		options Options
		runtime runtimeOptions
		want    error
	}{
		{
			name:    "expired invite",
			options: expired.options,
			runtime: runtime,
			want:    ErrInviteUnavailable,
		},
		{
			name: "malformed identity key",
			options: mutateOptions(valid.options, func(value *Options) {
				value.IdentityPrivateKey = value.IdentityPrivateKey[:31]
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
		{
			name: "malformed epoch key",
			options: mutateOptions(valid.options, func(value *Options) {
				value.InitialEpochPrivateKey =
					value.InitialEpochPrivateKey[:31]
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
		{
			name: "inviter identity reused by joiner",
			options: mutateOptions(valid.options, func(value *Options) {
				value.IdentityPrivateKey = valid.inviterPrivateKey
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrIdentityMismatch,
		},
		{
			name: "subject identity mismatch",
			options: mutateOptions(other.options, func(value *Options) {
				value.IdentityPrivateKey = testPrivateKey(0x74)
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrIdentityMismatch,
		},
		{
			name: "invalid attempt ID",
			options: mutateOptions(valid.options, func(value *Options) {
				value.AttemptID = ""
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
		{
			name: "invalid daemon version",
			options: mutateOptions(valid.options, func(value *Options) {
				value.DaemonVersion = "v1"
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
		{
			name: "invalid apply level",
			options: mutateOptions(valid.options, func(value *Options) {
				value.MaxApplyLevel = 0
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
		{
			name: "nil dialer",
			options: mutateOptions(valid.options, func(value *Options) {
				value.Dialer = nil
			}),
			runtime: testRuntime(&scriptedClient{}),
			want:    ErrInvalidOptions,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identityBefore := bytes.Clone(
				test.options.IdentityPrivateKey,
			)
			epochBefore := bytes.Clone(
				test.options.InitialEpochPrivateKey,
			)
			joiner, err := newJoiner(test.options, test.runtime)
			if joiner != nil || !errors.Is(err, test.want) {
				t.Fatalf(
					"newJoiner() = (%p, %v), want nil, %v",
					joiner,
					err,
					test.want,
				)
			}
			if !bytes.Equal(
				test.options.IdentityPrivateKey,
				identityBefore,
			) || !bytes.Equal(
				test.options.InitialEpochPrivateKey,
				epochBefore,
			) {
				t.Fatal("failed construction mutated caller keys")
			}
		})
	}
}

func TestJoinerBeginAndDecisionAreSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newJoinerFixture(t, pairing.ModeNew)
	requestDigest := sha256.Sum256([]byte("single use"))
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		fixture.options.AttemptID,
		requestDigest,
		fixture.options.Invite.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &scriptedClient{
		requestSteps: []requestStep{{
			result: pairinghttp.RequestResult{
				Acknowledgment: acknowledgment,
				SAS:            "0000 0001 0002 0003 0004",
			},
		}},
		confirmationStatuses: []pairing.ConfirmationStatus{
			pairing.StatusDeclined,
		},
	}
	fixture.options.Dialer = &scriptedDialer{
		results: []dialResult{{}},
	}
	joiner, err := newJoiner(fixture.options, testRuntime(client))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = joiner.Close() }()

	if _, err := joiner.Decide(
		context.Background(),
		false,
	); !errors.Is(err, ErrReviewUnavailable) {
		t.Fatalf("early Decide() error = %v", err)
	}
	if _, err := joiner.Begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := joiner.Begin(
		context.Background(),
	); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Begin() error = %v", err)
	}
	result, err := joiner.Decide(context.Background(), false)
	if err != nil || result.Confirmation.Status != pairing.StatusDeclined {
		t.Fatalf("Decide(false) = (%+v, %v)", result, err)
	}
}

type joinerFixture struct {
	options               Options
	inviterPrivateKey     ed25519.PrivateKey
	joinerPrivateKey      ed25519.PrivateKey
	subjectDeviceID       *domain.DeviceID
	expectedEntityVersion *uint64
}

func newJoinerFixture(
	t testing.TB,
	mode pairing.Mode,
) joinerFixture {
	t.Helper()
	inviterPrivateKey := testPrivateKey(0x71)
	joinerPrivateKey := testPrivateKey(0x72)
	epochPrivateKey := testPrivateKey(0x73)
	inviterPublicKey := inviterPrivateKey.Public().(ed25519.PublicKey)
	joinerPublicKey := joinerPrivateKey.Public().(ed25519.PublicKey)
	inviterDeviceID, err := device.DeriveID(inviterPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	joinerDeviceID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var subject *domain.DeviceID
	var expectedVersion *uint64
	initialEpoch := uint64(1)
	switch mode {
	case pairing.ModeRebootstrap:
		value := joinerDeviceID
		subject = &value
		initialEpoch = 2
	case pairing.ModeReadmission:
		value := joinerDeviceID
		subject = &value
		version := uint64(4)
		expectedVersion = &version
	}
	var secret [pairing.InviteSecretSize]byte
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	var genesisDigest [sha256.Size]byte
	for index := range genesisDigest {
		genesisDigest[index] = byte(0x80 + index)
	}
	var inviterKey [ed25519.PublicKeySize]byte
	copy(inviterKey[:], inviterPublicKey)
	invite, err := pairing.SignInvite(
		pairing.Invite{
			InviteID:           joinerTestInviteID,
			SessionID:          joinerTestSessionID,
			WorkspaceID:        joinerTestWorkspaceID,
			RecoveryGeneration: 3,
			CreatedAt: domain.WholeSecondTimestamp(
				joinerTestNow.Format(time.RFC3339),
			),
			ExpiresAt: domain.WholeSecondTimestamp(
				joinerTestNow.Add(pairing.InviteTTL).Format(
					time.RFC3339,
				),
			),
			Secret:                   secret,
			InviterDeviceID:          inviterDeviceID,
			InviterIdentityPublicKey: inviterKey,
			SignedGenesisDigest:      genesisDigest,
			Mode:                     mode,
			SubjectDeviceID:          cloneDeviceID(subject),
			ExpectedEntityVersion:    cloneUint64(expectedVersion),
			Role:                     device.RoleEditor,
			InitialCredentialEpoch:   initialEpoch,
			Endpoints: []pairing.Endpoint{
				{
					IP:   netip.MustParseAddr("192.0.2.10"),
					Port: 47831,
				},
				{
					IP:   netip.MustParseAddr("2001:db8::10"),
					Port: 47831,
				},
			},
		},
		inviterPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return joinerFixture{
		options: Options{
			Invite:                 invite,
			IdentityPrivateKey:     bytes.Clone(joinerPrivateKey),
			InitialEpochPrivateKey: bytes.Clone(epochPrivateKey),
			AttemptID:              joinerTestAttemptID,
			DaemonVersion:          "1.2.3",
			MaxApplyLevel:          1,
			Dialer: &scriptedDialer{
				results: []dialResult{{}},
			},
		},
		inviterPrivateKey:     inviterPrivateKey,
		joinerPrivateKey:      joinerPrivateKey,
		subjectDeviceID:       cloneDeviceID(subject),
		expectedEntityVersion: cloneUint64(expectedVersion),
	}
}

func assertExactReview(
	t testing.TB,
	review ReviewSubject,
	fixture joinerFixture,
	requestDigest [sha256.Size]byte,
	endpoint netip.AddrPort,
) {
	t.Helper()
	invite := fixture.options.Invite.Invite()
	defer clear(invite.Secret[:])
	joinerPublicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		fixture.options.IdentityPrivateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(joinerPublicKey)
	joinerDeviceID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if review.AttemptID != fixture.options.AttemptID ||
		review.InviteID != invite.InviteID ||
		review.InviteDigest != fixture.options.Invite.Digest() ||
		review.RequestDigest != requestDigest ||
		review.SessionID != invite.SessionID ||
		review.WorkspaceID != invite.WorkspaceID ||
		review.RecoveryGeneration != invite.RecoveryGeneration ||
		review.CreatedAt != invite.CreatedAt ||
		review.ExpiresAt != invite.ExpiresAt ||
		review.Mode != invite.Mode ||
		review.Role != invite.Role ||
		review.InviterDeviceID != invite.InviterDeviceID ||
		review.InviterIdentityPublicKey !=
			invite.InviterIdentityPublicKey ||
		review.SignedGenesisDigest != invite.SignedGenesisDigest ||
		review.Core.AttemptID != fixture.options.AttemptID ||
		review.Core.JoinerDeviceID != joinerDeviceID ||
		!bytes.Equal(
			review.Core.JoinerIdentityPublicKey[:],
			joinerPublicKey,
		) ||
		review.Core.DaemonVersion != fixture.options.DaemonVersion ||
		review.Core.MaxApplyLevel != fixture.options.MaxApplyLevel ||
		review.Core.InitialEpochBinding.SessionID != invite.SessionID ||
		review.Core.InitialEpochBinding.DeviceID != joinerDeviceID ||
		review.Core.InitialEpochBinding.Epoch !=
			invite.InitialCredentialEpoch ||
		review.Core.InitialEpochBinding.Validate(joinerPublicKey) != nil ||
		review.SAS != "0123 4567 8901 2345 6789" ||
		review.ConnectedEndpoint != endpoint ||
		!equalOptionalDeviceID(
			review.SubjectDeviceID,
			invite.SubjectDeviceID,
		) ||
		!equalOptionalUint64(
			review.ExpectedEntityVersion,
			invite.ExpectedEntityVersion,
		) {
		t.Fatalf("review subject = %+v", review)
	}
}

func testRuntime(client pairingClient) runtimeOptions {
	return runtimeOptions{
		now: func() time.Time {
			return joinerTestNow.Add(time.Minute)
		},
		openClient: func(
			_ context.Context,
			connection *tls.Conn,
		) (pairingClient, error) {
			if scripted, ok := client.(*scriptedClient); ok {
				scripted.attach(connection)
			}
			return client, nil
		},
		wait: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		endpointAttemptTimeout: 100 * time.Millisecond,
		overallAttemptTimeout:  5 * time.Second,
		confirmationPollDelay:  time.Millisecond,
	}
}

type requestStep struct {
	result pairinghttp.RequestResult
	err    error
}

type requestCall struct {
	inviteCode string
	core       []byte
}

type scriptedClient struct {
	mu                   sync.Mutex
	connection           *tls.Conn
	requestSteps         []requestStep
	requestCalls         []requestCall
	confirmationStatuses []pairing.ConfirmationStatus
	confirmationCalls    [][]byte
	confirm              func(context.Context) (
		pairing.ConfirmationResult,
		error,
	)
	closed int
}

func (client *scriptedClient) attach(connection *tls.Conn) {
	client.mu.Lock()
	client.connection = connection
	client.mu.Unlock()
}

func (client *scriptedClient) Request(
	_ context.Context,
	invite pairing.SignedInvite,
	core pairing.CanonicalRequestCore,
) (pairinghttp.RequestResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requestCalls = append(client.requestCalls, requestCall{
		inviteCode: invite.Code(),
		core:       core.CanonicalBytes(),
	})
	if len(client.requestSteps) == 0 {
		return pairinghttp.RequestResult{}, errors.New(
			"unexpected request call",
		)
	}
	step := client.requestSteps[0]
	client.requestSteps = client.requestSteps[1:]
	return step.result, step.err
}

func (client *scriptedClient) Confirm(
	ctx context.Context,
	confirmation pairing.Confirmation,
) (pairing.ConfirmationResult, error) {
	canonical := confirmation.CanonicalBytes()
	client.mu.Lock()
	client.confirmationCalls = append(
		client.confirmationCalls,
		bytes.Clone(canonical),
	)
	custom := client.confirm
	if custom != nil {
		client.mu.Unlock()
		return custom(ctx)
	}
	if len(client.confirmationStatuses) == 0 {
		client.mu.Unlock()
		return pairing.ConfirmationResult{}, errors.New(
			"unexpected confirmation call",
		)
	}
	status := client.confirmationStatuses[0]
	client.confirmationStatuses =
		client.confirmationStatuses[1:]
	client.mu.Unlock()
	return pairing.NewConfirmationResult(
		confirmation.AttemptID,
		confirmation.RequestDigest,
		status,
	)
}

func (client *scriptedClient) Close() error {
	client.mu.Lock()
	client.closed++
	connection := client.connection
	client.connection = nil
	client.mu.Unlock()
	if connection != nil {
		return connection.NetConn().Close()
	}
	return nil
}

func (client *scriptedClient) requests() []requestCall {
	client.mu.Lock()
	defer client.mu.Unlock()
	result := make([]requestCall, len(client.requestCalls))
	for index, call := range client.requestCalls {
		result[index] = requestCall{
			inviteCode: call.inviteCode,
			core:       bytes.Clone(call.core),
		}
	}
	return result
}

func (client *scriptedClient) confirmations() [][]byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	result := make([][]byte, len(client.confirmationCalls))
	for index, value := range client.confirmationCalls {
		result[index] = bytes.Clone(value)
	}
	return result
}

func (client *scriptedClient) closeCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closed
}

type dialResult struct {
	err error
}

type scriptedDialer struct {
	mu       sync.Mutex
	results  []dialResult
	calls    []netip.AddrPort
	bounded  []bool
	peerEnds []net.Conn
}

func (dialer *scriptedDialer) DialPairingEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	_, hasDeadline := ctx.Deadline()
	dialer.calls = append(dialer.calls, endpoint)
	dialer.bounded = append(dialer.bounded, hasDeadline)
	if len(dialer.results) == 0 {
		return nil, errors.New("unexpected dial call")
	}
	result := dialer.results[0]
	dialer.results = dialer.results[1:]
	if result.err != nil {
		return nil, result.err
	}
	client, peer := net.Pipe()
	dialer.peerEnds = append(dialer.peerEnds, peer)
	return client, nil
}

func (dialer *scriptedDialer) endpoints() []netip.AddrPort {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]netip.AddrPort(nil), dialer.calls...)
}

func (dialer *scriptedDialer) boundedCalls() []bool {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]bool(nil), dialer.bounded...)
}

func mutateOptions(
	input Options,
	mutate func(*Options),
) Options {
	mutate(&input)
	return input
}

func testPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat(
		[]byte{fill},
		ed25519.SeedSize,
	))
}

func equalEndpoints(left, right []netip.AddrPort) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalOptionalDeviceID(
	left, right *domain.DeviceID,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalOptionalUint64(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
