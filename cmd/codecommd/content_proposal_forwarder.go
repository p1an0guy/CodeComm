package main

import (
	"context"
	"errors"
	"sync"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

var errDaemonProposalForwarderUnavailable = errors.New(
	"codecommd: proposal forwarder unavailable",
)

// daemonProposalForwarderRelay breaks the node/content-runtime construction
// cycle without an allow-by-default interval.
type daemonProposalForwarderRelay struct {
	mu        sync.RWMutex
	forwarder consensus.ProposalForwarder
}

func (relay *daemonProposalForwarderRelay) ForwardProposal(
	ctx context.Context,
	target domain.DeviceID,
	signed event.SignedEvent,
) (consensus.ForwardedProposalResult, error) {
	if relay == nil || ctx == nil {
		return consensus.ForwardedProposalResult{},
			errDaemonProposalForwarderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return consensus.ForwardedProposalResult{}, err
	}
	relay.mu.RLock()
	forwarder := relay.forwarder
	relay.mu.RUnlock()
	if forwarder == nil {
		return consensus.ForwardedProposalResult{},
			errDaemonProposalForwarderUnavailable
	}
	return forwarder.ForwardProposal(ctx, target, signed)
}

func (relay *daemonProposalForwarderRelay) set(
	forwarder consensus.ProposalForwarder,
) error {
	if relay == nil || forwarder == nil {
		return errDaemonProposalForwarderUnavailable
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.forwarder != nil {
		return errDaemonProposalForwarderUnavailable
	}
	relay.forwarder = forwarder
	return nil
}

var _ consensus.ProposalForwarder = (*daemonProposalForwarderRelay)(nil)
