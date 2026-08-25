package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const secureCredentialRenewalChild = "credential-renewal"

type countingCredentialRenewalRequester struct {
	delegate credentialRenewalRequester
	calls    atomic.Uint64
}

func (requester *countingCredentialRenewalRequester) RequestCredentialRenewal(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	requester.calls.Add(1)
	return requester.delegate.RequestCredentialRenewal(ctx, deviceID, body)
}

type credentialRenewalForbiddenOrigin struct {
	deviceID domain.DeviceID
	bootID   domain.UUIDv7
	calls    atomic.Uint64
}

func (origin *credentialRenewalForbiddenOrigin) DeviceID() domain.DeviceID {
	return origin.deviceID
}

func (origin *credentialRenewalForbiddenOrigin) BootID() domain.UUIDv7 {
	return origin.bootID
}

func (origin *credentialRenewalForbiddenOrigin) SubmitCredentialAuthorization(
	context.Context,
	credentialauthorization.Authorization,
) (store.CommandOutcome, error) {
	origin.calls.Add(1)
	return store.CommandOutcome{}, errors.New("unexpected local authorization")
}

func TestSecureCredentialRenewalLeaderForwardingAndMinoritySafety(
	t *testing.T,
) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureCredentialRenewalChild {
		runSecureCredentialRenewalLeaderForwardingAndMinoritySafety(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureCredentialRenewalLeaderForwardingAndMinoritySafety$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureCredentialRenewalChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("credential renewal child timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("credential renewal child failed: %v\n%s", err, output)
	}
}

func runSecureCredentialRenewalLeaderForwardingAndMinoritySafety(
	t *testing.T,
) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	nodes := harness.runningNodes()
	leader := harness.waitForLeader(t, nodes)
	harness.waitForCommittedConfiguration(t, nodes)
	for _, candidate := range nodes {
		if err := candidate.node.WaitForLeader(meshTestContext(t)); err != nil {
			t.Fatalf("WaitForLeader(%s): %v", candidate.identity.deviceID, err)
		}
	}
	fixedNow := time.Date(
		2026,
		time.August,
		18,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	for _, candidate := range nodes {
		candidate.node.credentialEndorsementNow = func() time.Time {
			return fixedNow
		}
	}
	var follower, relayedSubject *secureMeshNode
	for _, candidate := range nodes {
		if candidate == leader {
			continue
		}
		if follower == nil {
			follower = candidate
		} else {
			relayedSubject = candidate
		}
	}
	if follower == nil || relayedSubject == nil {
		t.Fatal("credential renewal fixture lacks two followers")
	}
	awaitMeshCondition(
		t,
		10*time.Second,
		"follower identity-mTLS path to leader",
		func() bool {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				500*time.Millisecond,
			)
			defer cancel()
			_, err := follower.stream.ProbeConsensusPeer(
				ctx,
				leader.identity.deviceID,
			)
			return err == nil
		},
	)
	originalRequester := follower.node.credentialRenewalRequester
	if originalRequester == nil {
		t.Fatal("mesh follower has no credential renewal requester")
	}
	countingRequester := &countingCredentialRenewalRequester{
		delegate: originalRequester,
	}
	follower.node.credentialRenewalRequester = countingRequester
	defer func() {
		if follower.node != nil {
			follower.node.credentialRenewalRequester = originalRequester
		}
	}()

	followerBinding := secureCredentialRenewalBinding(
		t,
		follower,
		0xd1,
	)
	authorization, err := follower.node.RenewCredential(
		meshTestContext(t),
		followerBinding,
	)
	if err != nil {
		t.Fatalf("follower RenewCredential(): %v", err)
	}
	assertCredentialRenewalAuthorization(
		t,
		authorization,
		followerBinding,
	)
	if got := countingRequester.calls.Load(); got != 1 {
		t.Fatalf("follower renewal forwards = %d, want 1", got)
	}
	awaitCredentialRenewal(
		t,
		nodes,
		authorization,
	)

	if follower.node.IsLeader() {
		t.Fatal("credential renewal retry fixture unexpectedly changed leader")
	}
	retried, err := follower.node.RenewCredential(
		meshTestContext(t),
		followerBinding,
	)
	if err != nil {
		t.Fatalf("follower retry RenewCredential(): %v", err)
	}
	if !credentialRenewalAuthorizationsEqual(retried, authorization) {
		t.Fatalf(
			"follower retry = %#v, want committed %#v",
			retried,
			authorization,
		)
	}
	if got := countingRequester.calls.Load(); got != 1 {
		t.Fatalf("follower retry forwards = %d, want 1 total", got)
	}

	retryOrigin := &credentialRenewalForbiddenOrigin{
		deviceID: leader.identity.deviceID,
		bootID:   leader.identity.bootIDs[leader.startCount-1],
	}
	originalLeaderOrigin := leader.node.credentialAuthorizationOrigin
	leader.node.credentialAuthorizationOrigin = retryOrigin
	directRetry, err := leader.node.RenewCredential(
		meshTestContext(t),
		followerBinding,
	)
	leader.node.credentialAuthorizationOrigin = originalLeaderOrigin
	if err != nil {
		t.Fatalf("direct retry RenewCredential(): %v", err)
	}
	if !credentialRenewalAuthorizationsEqual(directRetry, authorization) {
		t.Fatalf(
			"direct retry = %#v, want committed %#v",
			directRetry,
			authorization,
		)
	}
	if retryOrigin.calls.Load() != 0 {
		t.Fatal("exact retry invoked the credential authorization origin")
	}

	changedBinding := secureCredentialRenewalBindingAtEpoch(
		t,
		follower,
		1,
		0xd4,
	)
	if _, err := follower.node.RenewCredential(
		meshTestContext(t),
		changedBinding,
	); !errors.Is(err, ErrInvalidCredentialBinding) {
		t.Fatalf("changed current binding error = %v", err)
	}
	if got := countingRequester.calls.Load(); got != 1 {
		t.Fatalf("changed current binding forwards = %d, want 1 total", got)
	}

	successorNow := fixedNow.Add(
		time.Duration(
			credentialauthorization.ValiditySeconds-
				credentialauthorization.RenewalLeadSeconds,
		) * time.Second,
	)
	for _, candidate := range nodes {
		candidate.node.credentialEndorsementNow = func() time.Time {
			return successorNow
		}
	}
	successorBinding := secureCredentialRenewalBindingAtEpoch(
		t,
		follower,
		2,
		0xd5,
	)
	successor, err := follower.node.RenewCredential(
		meshTestContext(t),
		successorBinding,
	)
	if err != nil {
		t.Fatalf("successor RenewCredential(): %v", err)
	}
	assertCredentialRenewalAuthorization(t, successor, successorBinding)
	if got := countingRequester.calls.Load(); got != 2 {
		t.Fatalf("successor renewal forwards = %d, want 2 total", got)
	}
	awaitCredentialRenewal(t, nodes, successor)

	if _, err := follower.node.RenewCredential(
		meshTestContext(t),
		followerBinding,
	); !errors.Is(err, ErrInvalidCredentialBinding) {
		t.Fatalf("stale binding error = %v", err)
	}
	if got := countingRequester.calls.Load(); got != 2 {
		t.Fatalf("stale binding forwards = %d, want 2 total", got)
	}

	relayedBinding := secureCredentialRenewalBinding(
		t,
		relayedSubject,
		0xd2,
	)
	relayed, err := requestCredentialRenewal(
		meshTestContext(t),
		leader.stream,
		follower.identity.deviceID,
		relayedBinding,
		credentialRenewalModeSubmit,
	)
	if err != nil {
		t.Fatalf("submit through follower: %v", err)
	}
	assertCredentialRenewalAuthorization(t, relayed, relayedBinding)
	if got := countingRequester.calls.Load(); got != 3 {
		t.Fatalf("submitted renewal forwards = %d, want 3 total", got)
	}
	awaitCredentialRenewal(t, nodes, relayed)

	minorityBinding := secureCredentialRenewalBinding(
		t,
		leader,
		0xd3,
	)
	forbiddenOrigin := &credentialRenewalForbiddenOrigin{
		deviceID: follower.identity.deviceID,
		bootID:   follower.identity.bootIDs[follower.startCount-1],
	}
	originalOrigin := follower.node.credentialAuthorizationOrigin
	follower.node.credentialAuthorizationOrigin = forbiddenOrigin
	defer func() {
		if follower.node != nil {
			follower.node.credentialAuthorizationOrigin = originalOrigin
		}
	}()
	harness.topology.setPartition(follower.identity.deviceID, true)
	defer harness.topology.setPartition(follower.identity.deviceID, false)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	_, err = follower.node.RenewCredential(ctx, minorityBinding)
	cancel()
	if err == nil {
		t.Fatal("isolated minority authorized a credential")
	}
	if forbiddenOrigin.calls.Load() != 0 {
		t.Fatal("isolated nonleader invoked its local authorization origin")
	}
	assertCredentialRenewalAbsent(t, follower, minorityBinding)
	for _, majorityNode := range nodes {
		if majorityNode != follower {
			assertCredentialRenewalAbsent(t, majorityNode, minorityBinding)
		}
	}
}

func secureCredentialRenewalBinding(
	t testing.TB,
	subject *secureMeshNode,
	seed byte,
) credential.Binding {
	t.Helper()
	return secureCredentialRenewalBindingAtEpoch(t, subject, 1, seed)
}

func secureCredentialRenewalBindingAtEpoch(
	t testing.TB,
	subject *secureMeshNode,
	epoch uint64,
	seed byte,
) credential.Binding {
	t.Helper()
	if subject == nil {
		t.Fatal("nil credential subject")
		return credential.Binding{}
	}
	epochPrivate := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(epochPrivate) })
	binding, err := credential.SignBinding(
		nodeTestSessionID,
		subject.identity.deviceID,
		epoch,
		epochPrivate.Public().(ed25519.PublicKey),
		subject.identity.private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func assertCredentialRenewalAuthorization(
	t testing.TB,
	authorization credentialauthorization.Authorization,
	binding credential.Binding,
) {
	t.Helper()
	if authorization.Validate() != nil ||
		authorization.AuthorizationChainIndex == 0 ||
		!credentialAuthorizationMatchesBinding(authorization, binding) {
		t.Fatalf("credential authorization = %#v", authorization)
	}
}

func awaitCredentialRenewal(
	t *testing.T,
	nodes []*secureMeshNode,
	authorization credentialauthorization.Authorization,
) {
	t.Helper()
	awaitMeshCondition(
		t,
		10*time.Second,
		"credential renewal on every voter",
		func() bool {
			for _, candidate := range nodes {
				admission, err := candidate.node.PeerAdmissionSnapshot()
				if err != nil {
					return false
				}
				stored, found := admission.Authorization(
					authorization.PrimaryKey(),
				)
				if !found ||
					!credentialRenewalAuthorizationsEqual(
						stored,
						authorization,
					) {
					return false
				}
			}
			return true
		},
	)
}

func assertCredentialRenewalAbsent(
	t testing.TB,
	candidate *secureMeshNode,
	binding credential.Binding,
) {
	t.Helper()
	admission, err := candidate.node.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(%s): %v", candidate.identity.deviceID, err)
	}
	if _, found := admission.Authorization(
		credentialauthorization.Key{
			SessionID: binding.SessionID,
			DeviceID:  binding.DeviceID,
			Epoch:     binding.Epoch,
		},
	); found {
		t.Fatalf(
			"credential %s/%d unexpectedly committed on %s",
			binding.DeviceID,
			binding.Epoch,
			candidate.identity.deviceID,
		)
	}
}

var (
	_ credentialRenewalRequester    = (*countingCredentialRenewalRequester)(nil)
	_ CredentialAuthorizationOrigin = (*credentialRenewalForbiddenOrigin)(nil)
)
