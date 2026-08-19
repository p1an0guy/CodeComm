package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const secureMeshProposalForwardingChild = "proposal-forwarding"

func TestApplyForwardedProposalCommitsAndReturnsExactResult(t *testing.T) {
	node, identityPrivate, deviceID := openApplyAtGenerationTestNode(t)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"forwarded task",
	)

	lookup, err := node.ApplyForwardedProposal(
		testContext(t),
		deviceID,
		signed.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("ApplyForwardedProposal(): %v", err)
	}
	if lookup.EventID != nodeTestEventID1 ||
		lookup.Outcome.Status != store.OutcomeAccepted ||
		!bytes.Equal(lookup.CanonicalProposal, signed.CanonicalBytes()) ||
		lookup.Tuple.ResultIndex != 1 ||
		lookup.Tuple.ChainIndex == nil ||
		*lookup.Tuple.ChainIndex != 1 {
		t.Fatalf("forwarded lookup = %+v", lookup)
	}

	duplicate, err := node.ApplyForwardedProposal(
		testContext(t),
		deviceID,
		signed.CanonicalBytes(),
	)
	if err != nil ||
		duplicate.Tuple.ResultIndex != lookup.Tuple.ResultIndex ||
		duplicate.Tuple.ResultHash != lookup.Tuple.ResultHash {
		t.Fatalf("duplicate = (%+v, %v)", duplicate, err)
	}

	changed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"changed collision",
	)
	if _, err := node.ApplyForwardedProposal(
		testContext(t),
		deviceID,
		changed.CanonicalBytes(),
	); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf(
			"changed event ID error = %v, want %v",
			err,
			store.ErrIdempotencyConflict,
		)
	}
}

func TestProposalIngressLimiterBoundsAndRefillsPerOrigin(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	limiter := newProposalIngressLimiter(func() time.Time { return now })
	first := proposalForwardingTestDeviceID(1)
	for index := range LeaderIngressRateBurst {
		if !limiter.consume(first) {
			t.Fatalf("burst proposal %d rejected", index)
		}
	}
	if limiter.consume(first) {
		t.Fatal("proposal beyond burst was accepted")
	}
	now = now.Add(time.Second)
	for index := range LeaderIngressRatePerSecond {
		if !limiter.consume(first) {
			t.Fatalf("refilled proposal %d rejected", index)
		}
	}
	if limiter.consume(first) {
		t.Fatal("proposal beyond one-second refill was accepted")
	}

	for index := 2; index <= 10; index++ {
		if !limiter.consume(proposalForwardingTestDeviceID(index)) {
			t.Fatalf("new sender %d rejected", index)
		}
		if len(limiter.states) > 8 {
			t.Fatalf("limiter retained %d sender states", len(limiter.states))
		}
	}

	inactive := newProposalIngressLimiter(func() time.Time { return now })
	for index := range LeaderIngressRateBurst {
		if !inactive.consumeOrigin(
			proposalForwardingTestDeviceID(index+1),
			false,
		) {
			t.Fatalf("inactive-origin proposal %d rejected", index)
		}
	}
	if inactive.consumeOrigin(proposalForwardingTestDeviceID(999), false) {
		t.Fatal("inactive-origin aggregate exceeded burst")
	}
	if len(inactive.states) != 0 || !inactive.inactiveSet {
		t.Fatal("inactive origins polluted active-origin limiter state")
	}
}

func TestAwaitForwardedProposalApplyHaltsOnResultTupleMismatch(t *testing.T) {
	node, identityPrivate, deviceID := openApplyAtGenerationTestNode(t)
	signed := nodeTestTaskEvent(
		t,
		identityPrivate,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"tuple mismatch",
	)
	lookup, err := node.ApplyForwardedProposal(
		testContext(t),
		deviceID,
		signed.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("ApplyForwardedProposal(): %v", err)
	}
	forwarded := forwardedProposalTestResult(lookup)
	forwarded.ResultIndex++
	if _, err := node.awaitForwardedProposalApply(
		testContext(t),
		signed,
		forwarded,
	); !errors.Is(err, ErrForwardedProposalMismatch) {
		t.Fatalf(
			"awaitForwardedProposalApply() error = %v, want %v",
			err,
			ErrForwardedProposalMismatch,
		)
	}
	if !errors.Is(node.FatalError(), ErrForwardedProposalMismatch) {
		t.Fatalf(
			"FatalError() = %v, want %v",
			node.FatalError(),
			ErrForwardedProposalMismatch,
		)
	}
}

func TestValidForwardedOutcomeRequiresCanonicalCodeAlphabet(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{code: "accepted", want: true},
		{code: "task_not_found_2", want: true},
		{code: "", want: false},
		{code: "UPPERCASE", want: false},
		{code: "contains.dot", want: false},
		{code: "contains-hyphen", want: false},
		{code: "contains/slash", want: false},
		{code: "nonascii_\u00e9", want: false},
		{code: string(bytes.Repeat([]byte{'a'}, 65)), want: false},
	}
	for _, test := range tests {
		if got := validForwardedOutcomeCode(test.code); got != test.want {
			t.Fatalf(
				"validForwardedOutcomeCode(%q) = %t, want %t",
				test.code,
				got,
				test.want,
			)
		}
	}
}

func TestSecureMeshFollowerForwardsOnlyToObservedLeader(t *testing.T) {
	if secureMeshRunsInProcess() ||
		os.Getenv(secureMeshChild) == secureMeshProposalForwardingChild {
		runSecureMeshFollowerForwardsOnlyToObservedLeader(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestSecureMeshFollowerForwardsOnlyToObservedLeader$",
		"-test.count=1",
	)
	command.Env = secureMeshChildEnvironmentWithMode(
		os.Environ(),
		secureMeshProposalForwardingChild,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf(
			"proposal-forwarding child timed out: %v\n%s",
			ctx.Err(),
			output,
		)
	}
	if err != nil {
		t.Fatalf("proposal-forwarding child failed: %v\n%s", err, output)
	}
}

func runSecureMeshFollowerForwardsOnlyToObservedLeader(t *testing.T) {
	harness := newSecureMeshHarness(t)
	defer harness.close(t)

	leader := harness.waitForLeader(t, harness.runningNodes())
	harness.waitForCommittedConfiguration(t, harness.runningNodes())
	var receiver *secureMeshNode
	for _, candidate := range harness.runningNodes() {
		if candidate != leader {
			receiver = candidate
			break
		}
	}
	if receiver == nil {
		t.Fatal("mesh has no follower")
	}
	var source *secureMeshNode
	for _, candidate := range harness.runningNodes() {
		if candidate != leader && candidate != receiver {
			source = candidate
			break
		}
	}
	if source == nil {
		t.Fatal("mesh has no independent proposal source")
	}
	forwarder := &secureMeshDirectProposalForwarder{
		sender:  receiver.identity.deviceID,
		targets: make(map[domain.DeviceID]*Node),
	}
	for _, candidate := range harness.runningNodes() {
		forwarder.targets[candidate.identity.deviceID] = candidate.node
	}
	receiver.node.proposalForwarder = forwarder

	signed := harness.taskEvent(
		t,
		source,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		"follower-forwarded task",
	)
	result, err := receiver.node.ApplyPeerProposal(
		meshTestContext(t),
		source.identity.deviceID,
		signed.CanonicalBytes(),
	)
	if err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("follower ApplyPeerProposal() = (%+v, %v)", result, err)
	}
	targets, proposals := forwarder.snapshot()
	if len(targets) != 1 ||
		targets[0] != leader.identity.deviceID ||
		len(proposals) != 1 ||
		!bytes.Equal(proposals[0], signed.CanonicalBytes()) {
		t.Fatalf(
			"forwarded targets = %v, proposals = %d",
			targets,
			len(proposals),
		)
	}
	harness.waitForTask(
		t,
		harness.runningNodes(),
		nodeTestTaskID1,
	)

	duplicate, err := receiver.node.ApplyPeerProposal(
		meshTestContext(t),
		source.identity.deviceID,
		signed.CanonicalBytes(),
	)
	if err != nil ||
		duplicate.Tuple.ResultIndex != result.Tuple.ResultIndex {
		t.Fatalf("follower duplicate = (%+v, %v)", duplicate, err)
	}
	duplicateTargets, _ := forwarder.snapshot()
	if len(duplicateTargets) != 1 {
		t.Fatal("locally applied duplicate was forwarded again")
	}

	if _, err := receiver.node.ApplyForwardedProposal(
		meshTestContext(t),
		leader.identity.deviceID,
		signed.CanonicalBytes(),
	); !errors.Is(err, raft.ErrNotLeader) {
		t.Fatalf(
			"follower network ingress error = %v, want %v",
			err,
			raft.ErrNotLeader,
		)
	}
	afterTargets, _ := forwarder.snapshot()
	if len(afterTargets) != 1 {
		t.Fatal("follower network ingress recursively forwarded")
	}

	future := time.Now().Add(time.Hour)
	leader.node.proposalIngress.mu.Lock()
	leader.node.proposalIngress.states[source.identity.deviceID] =
		proposalIngressState{
			credit:   0,
			last:     future,
			lastSeen: future,
		}
	leader.node.proposalIngress.mu.Unlock()
	if _, err := leader.node.ApplyForwardedProposal(
		meshTestContext(t),
		receiver.identity.deviceID,
		signed.CanonicalBytes(),
	); !errors.Is(err, ErrProposalIngressRateLimited) {
		t.Fatalf(
			"fanout duplicate error = %v, want %v",
			err,
			ErrProposalIngressRateLimited,
		)
	}

	stalled := &acceptedWithoutApplyForwarder{}
	receiver.node.proposalForwarder = stalled
	stalledProposal := harness.taskEvent(
		t,
		source,
		nodeTestEventID2,
		nodeTestTaskID2,
		nodeTestTimestamp2,
		"forwarded result awaiting local apply",
	)
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		_, err := receiver.node.ApplyPeerProposal(
			ctx,
			source.identity.deviceID,
			stalledProposal.CanonicalBytes(),
		)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf(
				"stalled forwarding attempt %d error = %v",
				attempt,
				err,
			)
		}
	}
	if calls := stalled.callCount(); calls != 1 {
		t.Fatalf("stalled proposal was forwarded %d times, want 1", calls)
	}
}

type secureMeshDirectProposalForwarder struct {
	mu sync.Mutex

	sender    domain.DeviceID
	targets   map[domain.DeviceID]*Node
	calls     []domain.DeviceID
	proposals [][]byte
}

func (forwarder *secureMeshDirectProposalForwarder) ForwardProposal(
	ctx context.Context,
	target domain.DeviceID,
	signed event.SignedEvent,
) (ForwardedProposalResult, error) {
	forwarder.mu.Lock()
	node := forwarder.targets[target]
	forwarder.calls = append(forwarder.calls, target)
	forwarder.proposals = append(
		forwarder.proposals,
		signed.CanonicalBytes(),
	)
	forwarder.mu.Unlock()
	if node == nil {
		return ForwardedProposalResult{},
			ErrProposalForwardingUnavailable
	}
	lookup, err := node.ApplyForwardedProposal(
		ctx,
		forwarder.sender,
		signed.CanonicalBytes(),
	)
	if err != nil {
		return ForwardedProposalResult{}, err
	}
	return forwardedProposalTestResult(lookup), nil
}

func (forwarder *secureMeshDirectProposalForwarder) snapshot() (
	[]domain.DeviceID,
	[][]byte,
) {
	forwarder.mu.Lock()
	defer forwarder.mu.Unlock()
	targets := append([]domain.DeviceID(nil), forwarder.calls...)
	proposals := make([][]byte, len(forwarder.proposals))
	for index, proposal := range forwarder.proposals {
		proposals[index] = bytes.Clone(proposal)
	}
	return targets, proposals
}

func proposalForwardingTestDeviceID(value int) domain.DeviceID {
	return domain.DeviceID(fmt.Sprintf("cc1%064x", value))
}

type acceptedWithoutApplyForwarder struct {
	mu    sync.Mutex
	calls int
}

func (forwarder *acceptedWithoutApplyForwarder) ForwardProposal(
	context.Context,
	domain.DeviceID,
	event.SignedEvent,
) (ForwardedProposalResult, error) {
	forwarder.mu.Lock()
	forwarder.calls++
	forwarder.mu.Unlock()
	chainIndex := uint64(1)
	chainHash := store.Digest{1}
	return ForwardedProposalResult{
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		ResultIndex: 1,
		ChainIndex:  &chainIndex,
		ChainHash:   &chainHash,
	}, nil
}

func (forwarder *acceptedWithoutApplyForwarder) callCount() int {
	forwarder.mu.Lock()
	defer forwarder.mu.Unlock()
	return forwarder.calls
}

func forwardedProposalTestResult(
	lookup store.CommandResultLookup,
) ForwardedProposalResult {
	result := ForwardedProposalResult{
		Outcome: store.CommandOutcome{
			Status: lookup.Outcome.Status,
			Code:   lookup.Outcome.Code,
			JSON:   bytes.Clone(lookup.Outcome.JSON),
		},
		ResultIndex: lookup.Tuple.ResultIndex,
	}
	if lookup.Tuple.ChainIndex != nil {
		chainIndex := *lookup.Tuple.ChainIndex
		result.ChainIndex = &chainIndex
	}
	if lookup.Tuple.ChainHash != nil {
		chainHash := *lookup.Tuple.ChainHash
		result.ChainHash = &chainHash
	}
	return result
}

var _ ProposalForwarder = (*secureMeshDirectProposalForwarder)(nil)
var _ ProposalForwarder = (*acceptedWithoutApplyForwarder)(nil)
