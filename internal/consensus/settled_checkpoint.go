package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

// VerifyCheckpointReplay proves that a settled replica imported the exact
// terminal checkpoint result without assigning local Raft provenance.
func (replica *SettledReplica) VerifyCheckpointReplay(
	ctx context.Context,
	signed event.SignedEvent,
	result store.ApplyResult,
) error {
	if replica == nil ||
		replica.state == nil ||
		ctx == nil ||
		signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replica.beginOperation(); err != nil {
		return err
	}
	defer replica.endOperation()
	lookup, found, err := replica.SettledCommandLookup(ctx, signed)
	if err != nil {
		return err
	}
	if !found ||
		lookup.Outcome.Status != result.Outcome.Status ||
		lookup.Outcome.Code != result.Outcome.Code ||
		!bytes.Equal(lookup.Outcome.JSON, result.Outcome.JSON) {
		return replica.failSettledIntegrity(
			"verify checkpoint command result",
			errors.New(
				"replayed checkpoint lacks its exact durable command result",
			),
		)
	}

	eventID := signed.Proposal().EventID
	switch result.Outcome.Status {
	case store.OutcomeRejected:
		if result.Outcome.Code != string(reducer.CodeStaleCheckpoint) {
			return replica.failSettledIntegrity(
				"verify rejected checkpoint",
				fmt.Errorf(
					"%w: %s",
					ErrCheckpointCommitRejected,
					result.Outcome.Code,
				),
			)
		}
		if _, exists, err := replica.state.SettledAppliedCheckpoint(
			ctx,
			eventID,
		); err != nil {
			return replica.handleSettledCheckpointError(err)
		} else if exists {
			return replica.failSettledIntegrity(
				"verify rejected checkpoint",
				errors.New(
					"rejected checkpoint has an accepted checkpoint row",
				),
			)
		}
		return nil
	case store.OutcomeAccepted:
	default:
		return replica.failSettledIntegrity(
			"verify checkpoint outcome",
			ErrCheckpointCommitRejected,
		)
	}

	checkpoint, authoritySignature, err :=
		event.DecodeCheckpointPayload(signed.Proposal().Payload)
	if err != nil {
		return replica.failSettledIntegrity(
			"decode replayed checkpoint",
			fmt.Errorf("%w: %v", ErrInvalidCheckpointEvent, err),
		)
	}
	checkpointJSON, err := event.EncodeCheckpoint(checkpoint)
	if err != nil {
		return replica.failSettledIntegrity(
			"encode replayed checkpoint",
			fmt.Errorf("%w: %v", ErrInvalidCheckpointEvent, err),
		)
	}
	record, exists, err := replica.state.SettledAppliedCheckpoint(
		ctx,
		eventID,
	)
	if err != nil {
		return replica.handleSettledCheckpointError(err)
	}
	if !exists ||
		record.CheckpointEventID != eventID ||
		!bytes.Equal(record.CheckpointJSON, checkpointJSON) ||
		record.AuthoritySignature != store.Signature(authoritySignature) {
		return replica.failSettledIntegrity(
			"verify accepted checkpoint",
			errors.New(
				"accepted replayed checkpoint lacks its exact durable binding",
			),
		)
	}
	return nil
}

func (replica *SettledReplica) handleSettledCheckpointError(
	err error,
) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrAppliedCheckpointIntegrity) ||
		fatalSettledImportError(err) {
		return replica.failSettledIntegrity(
			"lookup replayed checkpoint",
			err,
		)
	}
	return err
}
