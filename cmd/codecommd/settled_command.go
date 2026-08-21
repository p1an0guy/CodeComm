package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonSettledCommand = errors.New(
	"codecommd: settled command forwarding failed",
)

type daemonSettledCommandReplica interface {
	SettledCommandResult(
		context.Context,
		event.SignedEvent,
	) (store.ApplyResult, bool, error)
	SettledCommandLookup(
		context.Context,
		event.SignedEvent,
	) (store.CommandResultLookup, bool, error)
	AwaitForwardedProposal(
		context.Context,
		event.SignedEvent,
		consensus.ForwardedProposalResult,
	) (store.ApplyResult, error)
	VerifyCheckpointReplay(
		context.Context,
		event.SignedEvent,
		store.ApplyResult,
	) error
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	Status(context.Context) (coordstatus.Snapshot, error)
	FatalError() error
}

type daemonSettledProposalClient interface {
	Propose(
		context.Context,
		domain.DeviceID,
		event.SignedEvent,
	) (consensus.ForwardedProposalResult, error)
}

// daemonSettledCommandConsensus adapts local durable outboxes and inbound
// initial-hop proposals to authority peers without claiming Raft leadership.
type daemonSettledCommandConsensus struct {
	sessionID     domain.UUIDv7
	workspaceID   domain.UUIDv4
	generation    uint64
	localDeviceID domain.DeviceID
	replica       daemonSettledCommandReplica
	clock         consensus.ApplyClock

	peerMu sync.RWMutex
	peer   daemonSettledProposalClient
}

func newDaemonSettledCommandConsensus(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
	localDeviceID domain.DeviceID,
	replica daemonSettledCommandReplica,
	clock consensus.ApplyClock,
) (*daemonSettledCommandConsensus, error) {
	if !sessionID.Valid() ||
		!workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(generation) ||
		!localDeviceID.Valid() ||
		replica == nil ||
		clock == nil {
		return nil, errDaemonSettledCommand
	}
	return &daemonSettledCommandConsensus{
		sessionID:     sessionID,
		workspaceID:   workspaceID,
		generation:    generation,
		localDeviceID: localDeviceID,
		replica:       replica,
		clock:         clock,
	}, nil
}

func (runtime *daemonSettledCommandConsensus) setPeer(
	peer daemonSettledProposalClient,
) error {
	if runtime == nil || peer == nil {
		return errDaemonSettledCommand
	}
	runtime.peerMu.Lock()
	defer runtime.peerMu.Unlock()
	if runtime.peer != nil {
		return errDaemonSettledCommand
	}
	runtime.peer = peer
	return nil
}

func (runtime *daemonSettledCommandConsensus) ApplyAtGeneration(
	ctx context.Context,
	sessionID domain.UUIDv7,
	generation uint64,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	if runtime == nil ||
		runtime.replica == nil ||
		ctx == nil ||
		sessionID != runtime.sessionID ||
		generation != runtime.generation ||
		signed.Proposal().SessionID != runtime.sessionID ||
		signed.Proposal().WorkspaceID != runtime.workspaceID ||
		!signed.Proposal().EventID.Valid() {
		return store.ApplyResult{}, errDaemonSettledCommand
	}
	if err := ctx.Err(); err != nil {
		return store.ApplyResult{}, err
	}
	if fatal := runtime.replica.FatalError(); fatal != nil {
		return store.ApplyResult{}, fatal
	}
	if result, found, err := runtime.replica.SettledCommandResult(
		ctx,
		signed,
	); err != nil || found {
		return result, err
	}

	runtime.peerMu.RLock()
	peer := runtime.peer
	runtime.peerMu.RUnlock()
	if peer == nil {
		return store.ApplyResult{},
			consensus.ErrProposalForwardingUnavailable
	}
	status, err := runtime.replica.Status(ctx)
	if err != nil {
		return store.ApplyResult{}, err
	}
	admission, err := runtime.replica.PeerAdmissionSnapshot()
	if err != nil {
		return store.ApplyResult{}, err
	}
	authorityIDs := status.Durable.CredentialAuthority.VoterDeviceIDs()
	attemptErrors := make([]error, 0, len(authorityIDs))
	for _, peerID := range authorityIDs {
		if peerID == runtime.localDeviceID {
			continue
		}
		member, active := admission.Member(peerID)
		if !active || member.Status != device.StatusActive {
			continue
		}
		forwarded, proposeErr := peer.Propose(ctx, peerID, signed)
		if proposeErr == nil {
			return runtime.replica.AwaitForwardedProposal(
				ctx,
				signed,
				forwarded,
			)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return store.ApplyResult{}, ctxErr
		}
		if errors.Is(proposeErr, store.ErrIdempotencyConflict) {
			return store.ApplyResult{}, proposeErr
		}
		attemptErrors = append(attemptErrors, proposeErr)
	}
	return store.ApplyResult{}, fmt.Errorf(
		"%w: %w",
		consensus.ErrProposalForwardingUnavailable,
		errors.Join(attemptErrors...),
	)
}

func (*daemonSettledCommandConsensus) IsLeader() bool {
	return false
}

func (runtime *daemonSettledCommandConsensus) LocalTime() (
	domain.Timestamp,
	int64,
	error,
) {
	if runtime == nil || runtime.clock == nil || runtime.replica == nil {
		return "", 0, errDaemonSettledCommand
	}
	if fatal := runtime.replica.FatalError(); fatal != nil {
		return "", 0, fatal
	}
	return runtime.clock()
}

func (runtime *daemonSettledCommandConsensus) FatalError() error {
	if runtime == nil || runtime.replica == nil {
		return errDaemonSettledCommand
	}
	return runtime.replica.FatalError()
}

func (runtime *daemonSettledCommandConsensus) VerifyCheckpointReplay(
	ctx context.Context,
	signed event.SignedEvent,
	result store.ApplyResult,
) error {
	if runtime == nil || runtime.replica == nil {
		return errDaemonSettledCommand
	}
	return runtime.replica.VerifyCheckpointReplay(ctx, signed, result)
}

func (runtime *daemonSettledCommandConsensus) ApplyPeerProposal(
	ctx context.Context,
	senderDeviceID domain.DeviceID,
	canonical []byte,
) (store.CommandResultLookup, error) {
	signed, err := runtime.verifyPeerProposal(
		ctx,
		senderDeviceID,
		canonical,
	)
	if err != nil {
		return store.CommandResultLookup{}, err
	}
	if _, err := runtime.ApplyAtGeneration(
		ctx,
		runtime.sessionID,
		runtime.generation,
		signed,
	); err != nil {
		return store.CommandResultLookup{}, err
	}
	lookup, found, err := runtime.replica.SettledCommandLookup(ctx, signed)
	if err != nil {
		return store.CommandResultLookup{}, err
	}
	if !found || !bytes.Equal(lookup.CanonicalProposal, canonical) {
		return store.CommandResultLookup{},
			consensus.ErrForwardedProposalMismatch
	}
	return lookup, nil
}

func (*daemonSettledCommandConsensus) ApplyForwardedProposal(
	context.Context,
	domain.DeviceID,
	[]byte,
) (store.CommandResultLookup, error) {
	return store.CommandResultLookup{},
		consensus.ErrProposalForwardingUnavailable
}

func (runtime *daemonSettledCommandConsensus) verifyPeerProposal(
	ctx context.Context,
	senderDeviceID domain.DeviceID,
	canonical []byte,
) (event.SignedEvent, error) {
	if runtime == nil ||
		runtime.replica == nil ||
		ctx == nil ||
		!senderDeviceID.Valid() ||
		senderDeviceID == runtime.localDeviceID ||
		len(canonical) == 0 ||
		len(canonical) > event.MaxEventBytes {
		return event.SignedEvent{}, consensus.ErrInvalidPeerProposal
	}
	if err := ctx.Err(); err != nil {
		return event.SignedEvent{}, err
	}
	admission, err := runtime.replica.PeerAdmissionSnapshot()
	if err != nil {
		return event.SignedEvent{}, err
	}
	sender, exists := admission.Member(senderDeviceID)
	if !exists || sender.Status != device.StatusActive {
		return event.SignedEvent{}, consensus.ErrInvalidPeerProposal
	}
	proposal, err := event.InspectUnverifiedProposal(canonical)
	if err != nil ||
		proposal.SessionID != runtime.sessionID ||
		proposal.WorkspaceID != runtime.workspaceID {
		return event.SignedEvent{}, consensus.ErrInvalidPeerProposal
	}
	origin, exists := admission.Member(proposal.Origin.DeviceID())
	if !exists {
		return event.SignedEvent{}, consensus.ErrInvalidPeerProposal
	}
	signed, err := event.ParseAndVerify(
		canonical,
		event.VerificationContext{
			SessionID:         runtime.sessionID,
			WorkspaceID:       runtime.workspaceID,
			IdentityPublicKey: origin.IdentityPublicKey,
		},
	)
	if err != nil || !bytes.Equal(signed.CanonicalBytes(), canonical) {
		return event.SignedEvent{}, consensus.ErrInvalidPeerProposal
	}
	return signed, nil
}

var (
	_ daemonEventProposalConsensus = (*daemonSettledCommandConsensus)(nil)
)
