package consensus

import (
	"bytes"
	"context"
	"time"

	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

// SettledCommandLookup returns the locally imported result for an exact
// proposal. A miss is not an error; changed bytes under the same event ID are
// an idempotency conflict.
func (replica *SettledReplica) SettledCommandLookup(
	ctx context.Context,
	signed event.SignedEvent,
) (store.CommandResultLookup, bool, error) {
	if replica == nil ||
		replica.state == nil ||
		ctx == nil ||
		!signed.Proposal().EventID.Valid() {
		return store.CommandResultLookup{}, false, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.CommandResultLookup{}, false, err
	}
	if err := replica.beginOperation(); err != nil {
		return store.CommandResultLookup{}, false, err
	}
	defer replica.endOperation()
	lookup, found, err := replica.state.LookupCommandResult(
		ctx,
		signed.Proposal().EventID,
	)
	if err != nil {
		if fatalSettledImportError(err) {
			return store.CommandResultLookup{}, false,
				replica.failSettledIntegrity(
					"lookup command result",
					err,
				)
		}
		return store.CommandResultLookup{}, false, err
	}
	if !found {
		return store.CommandResultLookup{}, false, nil
	}
	if !bytes.Equal(lookup.CanonicalProposal, signed.CanonicalBytes()) {
		return store.CommandResultLookup{}, false,
			store.ErrIdempotencyConflict
	}
	return lookup, true, nil
}

// SettledCommandResult maps an exact local lookup to the command-consensus
// result shape used by durable outbox workers.
func (replica *SettledReplica) SettledCommandResult(
	ctx context.Context,
	signed event.SignedEvent,
) (store.ApplyResult, bool, error) {
	lookup, found, err := replica.SettledCommandLookup(ctx, signed)
	if err != nil || !found {
		return store.ApplyResult{}, found, err
	}
	publication := replica.admission.Load()
	if publication == nil {
		return store.ApplyResult{}, false,
			replica.failSettledIntegrity(
				"load admission revision",
				ErrPeerAdmissionUnavailable,
			)
	}
	return store.ApplyResult{
		Heads:             lookup.CurrentHeads,
		Outcome:           lookup.Outcome,
		AdmissionRevision: publication.revision,
		Duplicate:         true,
	}, true, nil
}

// AwaitForwardedProposal waits until signed replication imports the exact
// result returned by an authority peer.
func (replica *SettledReplica) AwaitForwardedProposal(
	ctx context.Context,
	signed event.SignedEvent,
	forwarded ForwardedProposalResult,
) (store.ApplyResult, error) {
	if replica == nil ||
		ctx == nil ||
		!validForwardedResult(forwarded) {
		return store.ApplyResult{}, ErrForwardedProposalMismatch
	}
	ticker := time.NewTicker(proposalApplyPollInterval)
	defer ticker.Stop()
	for {
		lookup, found, err := replica.SettledCommandLookup(ctx, signed)
		if err != nil {
			return store.ApplyResult{}, err
		}
		if found {
			if !sameForwardedResult(lookup, forwarded) {
				return store.ApplyResult{},
					replica.failSettledIntegrity(
						"compare forwarded result",
						ErrForwardedProposalMismatch,
					)
			}
			publication := replica.admission.Load()
			if publication == nil {
				return store.ApplyResult{},
					replica.failSettledIntegrity(
						"load admission revision",
						ErrPeerAdmissionUnavailable,
					)
			}
			return store.ApplyResult{
				Heads:             lookup.CurrentHeads,
				Outcome:           lookup.Outcome,
				AdmissionRevision: publication.revision,
				Duplicate:         true,
			}, nil
		}
		select {
		case <-ctx.Done():
			return store.ApplyResult{}, ctx.Err()
		case <-replica.closeStarted:
			return store.ApplyResult{}, ErrNodeClosed
		case <-replica.fatalSet:
			return store.ApplyResult{}, replica.FatalError()
		case <-ticker.C:
		}
	}
}
