package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	LeaderIngressRatePerSecond = 50
	LeaderIngressRateBurst     = 200
	ProposalForwardTimeout     = 120 * time.Second

	proposalIngressTokenUnit  = int64(time.Second)
	proposalApplyPollInterval = 20 * time.Millisecond
)

var (
	ErrProposalForwardingUnavailable = errors.New(
		"consensus: proposal forwarding unavailable",
	)
	ErrInvalidPeerProposal = errors.New(
		"consensus: invalid peer proposal",
	)
	ErrProposalIngressRateLimited = errors.New(
		"consensus: leader proposal ingress rate limited",
	)
	ErrForwardedProposalMismatch = errors.New(
		"consensus: forwarded proposal result mismatch",
	)
)

// ProposalForwarder sends an exact signed proposal to one observed leader over
// the authenticated content plane. It must not retarget the request itself.
type ProposalForwarder interface {
	ForwardProposal(
		context.Context,
		domain.DeviceID,
		event.SignedEvent,
	) (ForwardedProposalResult, error)
}

// ForwardedProposalResult is the remote peer's exact committed result data
// after the proposal and its digest have been validated by the transport.
type ForwardedProposalResult struct {
	Outcome     store.CommandOutcome
	ResultIndex uint64
	ChainIndex  *uint64
	ChainHash   *store.Digest
}

// ApplyPeerProposal accepts one initial network proposal and may forward it
// once when this replica is a follower.
func (node *SingleNode) ApplyPeerProposal(
	ctx context.Context,
	senderDeviceID domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return node.applyPeerProposal(ctx, senderDeviceID, canonical, true)
}

// ApplyForwardedProposal accepts a one-hop network proposal only while this
// replica is the observed leader. It never forwards again.
func (node *SingleNode) ApplyForwardedProposal(
	ctx context.Context,
	senderDeviceID domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	return node.applyPeerProposal(ctx, senderDeviceID, canonical, false)
}

func (node *SingleNode) applyPeerProposal(
	ctx context.Context,
	senderDeviceID domain.DeviceID,
	canonical []byte,
	allowForward bool,
) (store.CommandResultLookup, error) {
	if node == nil ||
		node.raft == nil ||
		node.state == nil ||
		node.proposalIngress == nil ||
		ctx == nil ||
		!senderDeviceID.Valid() ||
		len(canonical) == 0 ||
		len(canonical) > event.MaxEventBytes {
		return store.CommandResultLookup{}, ErrInvalidPeerProposal
	}
	if err := ctx.Err(); err != nil {
		return store.CommandResultLookup{}, err
	}
	if err := node.beginOperation(); err != nil {
		return store.CommandResultLookup{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return store.CommandResultLookup{}, err
	}
	if !allowForward && !node.IsLeader() {
		return store.CommandResultLookup{}, fmt.Errorf(
			"%w: %w",
			ErrProposalForwardingUnavailable,
			raft.ErrNotLeader,
		)
	}

	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return store.CommandResultLookup{}, err
	}
	sender, exists := admission.Member(senderDeviceID)
	if !exists || sender.Status != device.StatusActive {
		return store.CommandResultLookup{}, ErrInvalidPeerProposal
	}

	proposal, err := event.InspectUnverifiedProposal(canonical)
	if err != nil {
		return store.CommandResultLookup{}, fmt.Errorf(
			"%w: envelope: %v",
			ErrInvalidPeerProposal,
			err,
		)
	}
	origin, exists := admission.Member(proposal.Origin.DeviceID())
	if !exists {
		return store.CommandResultLookup{}, ErrInvalidPeerProposal
	}
	view, err := node.state.View(ctx)
	if err != nil {
		return store.CommandResultLookup{}, err
	}
	signed, err := event.ParseAndVerify(
		canonical,
		event.VerificationContext{
			SessionID:         view.SessionID,
			WorkspaceID:       view.WorkspaceID,
			IdentityPublicKey: origin.IdentityPublicKey,
		},
	)
	if err != nil {
		return store.CommandResultLookup{}, fmt.Errorf(
			"%w: authentication: %v",
			ErrInvalidPeerProposal,
			err,
		)
	}
	originDeviceID := proposal.Origin.DeviceID()
	originActive := origin.Status == device.StatusActive
	ingressCharged := false
	if node.IsLeader() {
		if !node.proposalIngress.consumeOrigin(
			originDeviceID,
			originActive,
		) {
			return store.CommandResultLookup{}, ErrProposalIngressRateLimited
		}
		ingressCharged = true
	}
	if _, err := node.apply(ctx, signed, proposalApplyOptions{
		allowForward:                allowForward,
		leaderIngressDeviceID:       originDeviceID,
		leaderIngressActive:         originActive,
		leaderIngressAlreadyCharged: ingressCharged,
	}); err != nil {
		return store.CommandResultLookup{}, err
	}
	lookup, found, err := node.state.LookupCommandResult(
		ctx,
		proposal.EventID,
	)
	if err != nil {
		return store.CommandResultLookup{}, node.handleLookupError(err)
	}
	if !found || !bytes.Equal(lookup.CanonicalProposal, canonical) {
		return store.CommandResultLookup{}, node.haltNode(
			ErrForwardedProposalMismatch,
		)
	}
	return lookup, nil
}

func (node *SingleNode) resolveForwardedProposal(
	eventID domain.UUIDv7,
	signed event.SignedEvent,
	flight *proposalFlight,
) {
	defer node.active.Done()

	var (
		result    store.ApplyResult
		err       error
		attempted bool
	)
	target, targetErr := node.proposalLeader()
	if targetErr != nil {
		err = targetErr
	} else if node.proposalForwarder == nil {
		err = fmt.Errorf(
			"%w: %w",
			ErrProposalForwardingUnavailable,
			raft.ErrNotLeader,
		)
	} else {
		operationContext, cancelOperation, wait := node.operationContext(
			context.Background(),
		)
		forwardContext, cancelForward := context.WithTimeout(
			operationContext,
			ProposalForwardTimeout,
		)
		attempted = true
		forwarded, forwardErr := node.proposalForwarder.ForwardProposal(
			forwardContext,
			target,
			signed,
		)
		if forwardErr != nil {
			err = forwardErr
		} else if !validForwardedResult(forwarded) {
			err = node.haltNode(ErrForwardedProposalMismatch)
		} else {
			result, err = node.awaitForwardedProposalApply(
				forwardContext,
				signed,
				forwarded,
			)
		}
		cancelForward()
		cancelOperation()
		wait()
	}
	uncertain := attempted &&
		err != nil &&
		!errors.Is(err, store.ErrIdempotencyConflict)
	node.finishProposal(eventID, flight, result, err, uncertain)
}

func (node *SingleNode) awaitForwardedProposalApply(
	ctx context.Context,
	signed event.SignedEvent,
	forwarded ForwardedProposalResult,
) (store.ApplyResult, error) {
	if node == nil || ctx == nil || !validForwardedResult(forwarded) {
		return store.ApplyResult{}, ErrForwardedProposalMismatch
	}
	ticker := time.NewTicker(proposalApplyPollInterval)
	defer ticker.Stop()
	for {
		local, found, err := node.lookupCommittedResult(ctx, signed)
		switch {
		case err != nil:
			return store.ApplyResult{}, node.handleLookupError(err)
		case found:
			if !sameForwardedResult(local, forwarded) {
				return store.ApplyResult{},
					node.haltNode(ErrForwardedProposalMismatch)
			}
			return store.ApplyResult{
				Heads:             local.CurrentHeads,
				Outcome:           local.Outcome,
				AdmissionRevision: node.state.AdmissionRevision(),
				Duplicate:         true,
			}, nil
		}
		select {
		case <-ctx.Done():
			return store.ApplyResult{}, ctx.Err()
		case <-node.closeStarted:
			return store.ApplyResult{}, ErrNodeClosed
		case <-node.fatalSet:
			return store.ApplyResult{}, node.FatalError()
		case <-ticker.C:
		}
	}
}

func (node *SingleNode) proposalLeader() (domain.DeviceID, error) {
	if node == nil || node.raft == nil {
		return "", ErrProposalForwardingUnavailable
	}
	address, leaderID := node.raft.LeaderWithID()
	deviceID := domain.DeviceID(leaderID)
	if !deviceID.Valid() ||
		address != raft.ServerAddress(deviceID) ||
		leaderID == node.serverID {
		return "", fmt.Errorf(
			"%w: %w",
			ErrProposalForwardingUnavailable,
			raft.ErrNotLeader,
		)
	}
	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return "", err
	}
	member, exists := admission.Member(deviceID)
	if !exists || member.Status != device.StatusActive {
		return "", ErrProposalForwardingUnavailable
	}
	return deviceID, nil
}

func validForwardedResult(result ForwardedProposalResult) bool {
	outcome := result.Outcome
	if outcome.Status != store.OutcomeAccepted &&
		outcome.Status != store.OutcomeRejected {
		return false
	}
	if result.ResultIndex < 1 ||
		!domain.ValidUnsignedInteger(result.ResultIndex) {
		return false
	}
	switch outcome.Status {
	case store.OutcomeAccepted:
		if result.ChainIndex == nil ||
			result.ChainHash == nil ||
			*result.ChainIndex < 1 ||
			*result.ChainIndex > result.ResultIndex ||
			!domain.ValidUnsignedInteger(*result.ChainIndex) {
			return false
		}
	case store.OutcomeRejected:
		if result.ChainIndex != nil || result.ChainHash != nil {
			return false
		}
	}
	if !validForwardedOutcomeCode(outcome.Code) ||
		len(outcome.JSON) == 0 ||
		len(outcome.JSON) > event.MaxEventBytes {
		return false
	}
	canonical, err := codec.CanonicalizeSignedObject(outcome.JSON)
	if err != nil || !bytes.Equal(canonical, outcome.JSON) {
		return false
	}
	var fields struct {
		Status string `json:"status"`
		Code   string `json:"code"`
	}
	return json.Unmarshal(outcome.JSON, &fields) == nil &&
		fields.Status == string(outcome.Status) &&
		fields.Code == outcome.Code
}

func validForwardedOutcomeCode(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

func sameForwardedResult(
	local store.CommandResultLookup,
	forwarded ForwardedProposalResult,
) bool {
	return local.Outcome.Status == forwarded.Outcome.Status &&
		local.Outcome.Code == forwarded.Outcome.Code &&
		bytes.Equal(local.Outcome.JSON, forwarded.Outcome.JSON) &&
		local.Tuple.ResultIndex == forwarded.ResultIndex &&
		equalForwardedChainIndex(
			local.Tuple.ChainIndex,
			forwarded.ChainIndex,
		) &&
		equalForwardedChainHash(
			local.Tuple.ChainHash,
			forwarded.ChainHash,
		)
}

func equalForwardedChainIndex(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func equalForwardedChainHash(left, right *store.Digest) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

type proposalIngressLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	capacity    int64
	states      map[domain.DeviceID]proposalIngressState
	inactive    proposalIngressState
	inactiveSet bool
}

type proposalIngressState struct {
	credit   int64
	last     time.Time
	lastSeen time.Time
}

func newProposalIngressLimiter(
	now func() time.Time,
) *proposalIngressLimiter {
	return &proposalIngressLimiter{
		now: now,
		capacity: int64(LeaderIngressRateBurst) *
			proposalIngressTokenUnit,
		states: make(
			map[domain.DeviceID]proposalIngressState,
			int(policy.MaxMemberDevices),
		),
	}
}

func (limiter *proposalIngressLimiter) consume(
	deviceID domain.DeviceID,
) bool {
	return limiter.consumeOrigin(deviceID, true)
}

func (limiter *proposalIngressLimiter) consumeOrigin(
	deviceID domain.DeviceID,
	active bool,
) bool {
	if limiter == nil || limiter.now == nil || !deviceID.Valid() {
		return false
	}
	now := limiter.now()
	if now.IsZero() {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if !active {
		if !limiter.inactiveSet {
			limiter.inactive = proposalIngressState{
				credit: limiter.capacity,
				last:   now,
			}
			limiter.inactiveSet = true
		}
		state, allowed := limiter.consumeState(limiter.inactive, now)
		limiter.inactive = state
		return allowed
	}
	state, exists := limiter.states[deviceID]
	if !exists {
		if len(limiter.states) >= int(policy.MaxMemberDevices) {
			var (
				evictionID    domain.DeviceID
				evictionState proposalIngressState
				found         bool
			)
			for candidateID, candidate := range limiter.states {
				if !found ||
					candidate.lastSeen.Before(evictionState.lastSeen) ||
					candidate.lastSeen.Equal(evictionState.lastSeen) &&
						candidateID < evictionID {
					evictionID = candidateID
					evictionState = candidate
					found = true
				}
			}
			if !found {
				return false
			}
			delete(limiter.states, evictionID)
		}
		state = proposalIngressState{
			credit: limiter.capacity,
			last:   now,
		}
	}
	state, allowed := limiter.consumeState(state, now)
	limiter.states[deviceID] = state
	return allowed
}

func (limiter *proposalIngressLimiter) consumeState(
	state proposalIngressState,
	now time.Time,
) (proposalIngressState, bool) {
	if now.Before(state.last) {
		now = state.last
	}
	elapsed := now.Sub(state.last)
	state.last = now
	state.lastSeen = now
	missing := limiter.capacity - state.credit
	if missing > 0 && elapsed > 0 {
		fillAfter := time.Duration(
			(missing + int64(LeaderIngressRatePerSecond) - 1) /
				int64(LeaderIngressRatePerSecond),
		)
		if elapsed >= fillAfter {
			state.credit = limiter.capacity
		} else {
			state.credit += int64(elapsed) *
				int64(LeaderIngressRatePerSecond)
		}
	}
	allowed := state.credit >= proposalIngressTokenUnit
	if allowed {
		state.credit -= proposalIngressTokenUnit
	}
	return state, allowed
}
