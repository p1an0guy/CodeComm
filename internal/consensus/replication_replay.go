package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidReplicationReplay = errors.New(
		"consensus: invalid replication replay",
	)
	ErrReplicationOutcomeMismatch = errors.New(
		"consensus: replicated outcome differs from local reduction",
	)
	ErrReplicationSignerUnauthorized = errors.New(
		"consensus: replication signer is not authorized at batch end",
	)
)

type replayedCommand struct {
	signed    event.SignedEvent
	outcome   reducer.Outcome
	result    chain.Result
	encoded   []byte
	mutations []chain.Mutation
	heads     store.ApplyHeads
}

type resultBatchReplay struct {
	commands              []replayedCommand
	heads                 store.ApplyHeads
	projectionRows        []chain.LogicalRow
	projectionStateDigest chain.Digest
	admission             *peerauth.Snapshot
	admissionChanged      bool
}

// replayResultBatch verifies one complete signed batch against an immutable
// local cut. It mutates only in-memory reducer and projection scratch state.
func replayResultBatch(
	ctx context.Context,
	view store.StateView,
	batch replication.Batch,
) (resultBatchReplay, error) {
	if ctx == nil || batch.EncodedLen() == 0 {
		return resultBatchReplay{}, ErrInvalidReplicationReplay
	}
	if err := ctx.Err(); err != nil {
		return resultBatchReplay{}, err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return resultBatchReplay{}, fmt.Errorf(
			"%w: decode starting state: %w",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return resultBatchReplay{}, err
	}
	versions := chain.Versions{
		Digest:           view.Heads.DigestVersion,
		ProjectionSchema: view.Heads.ProjectionSchemaVersion,
	}
	projections, err := store.NewProjectionScratch(
		view.ProjectionRows,
		versions,
	)
	if err != nil {
		return resultBatchReplay{}, fmt.Errorf(
			"%w: initialize projection scratch: %w",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	input := batch.Unsigned().Input()
	if err := validateReplayStart(view, input); err != nil {
		return resultBatchReplay{}, err
	}

	state := decoded.Reducer
	admission := decoded.Admission
	admissionChanged := false
	heads := view.Heads
	commands := make([]replayedCommand, 0, len(input.Results))
	for offset, encoded := range input.Results {
		if err := ctx.Err(); err != nil {
			return resultBatchReplay{}, err
		}
		result, err := chain.DecodeResult(encoded)
		if err != nil {
			return resultBatchReplay{}, replayItemError(offset, err)
		}
		signed, err := verifyReplayProposal(
			state,
			result.Proposal,
			view.SessionID,
			view.WorkspaceID,
		)
		if err != nil {
			return resultBatchReplay{}, replayItemError(offset, err)
		}
		outcome, err := reduceReplicatedCommand(
			state,
			signed,
			result,
			heads,
		)
		if err != nil {
			return resultBatchReplay{}, replayItemError(offset, err)
		}
		outcomeJSON, err := outcome.ResultJSON()
		if err != nil {
			return resultBatchReplay{}, replayItemError(offset, err)
		}
		if !bytes.Equal(outcomeJSON, result.Outcome) {
			return resultBatchReplay{}, replayItemError(
				offset,
				ErrReplicationOutcomeMismatch,
			)
		}
		if err := state.Apply(outcome.Changes); err != nil {
			return resultBatchReplay{}, replayItemError(
				offset,
				fmt.Errorf("advance reducer state: %w", err),
			)
		}
		admission, err = admission.Advance(peerauth.Changes{
			AdvancesEventChain:       outcome.Changes.AdvancesEventChain,
			Devices:                  outcome.Changes.Devices,
			AuditCounters:            outcome.Changes.AuditCounters,
			CredentialAuthorizations: outcome.Changes.CredentialAuthorizations,
		})
		if err != nil {
			return resultBatchReplay{}, replayItemError(
				offset,
				fmt.Errorf("advance peer admission: %w", err),
			)
		}
		admissionChanged = admissionChanged ||
			admissionAccessChanged(outcome.Changes)
		mutations, err := projections.Apply(
			projectionWrites(outcome.Changes),
		)
		if err != nil {
			return resultBatchReplay{}, replayItemError(
				offset,
				fmt.Errorf("advance projection scratch: %w", err),
			)
		}
		nextHeads, err := replayCommandCommitments(
			heads,
			result,
			mutations,
		)
		if err != nil {
			return resultBatchReplay{}, replayItemError(offset, err)
		}
		commands = append(commands, replayedCommand{
			signed:    signed,
			outcome:   outcome,
			result:    result,
			encoded:   bytes.Clone(encoded),
			mutations: cloneReplayMutations(mutations),
			heads:     nextHeads,
		})
		heads = nextHeads
	}
	if err := ctx.Err(); err != nil {
		return resultBatchReplay{}, err
	}
	if heads.ResultIndex != input.ToResultIndex ||
		heads.ResultHash != store.Digest(input.EndResultHash) ||
		heads.ChainIndex != input.EndChainIndex ||
		heads.ChainHash != store.Digest(input.EndChainHash) ||
		heads.ProjectionAccumulator !=
			store.Digest(input.EndProjectionAccumulator) {
		return resultBatchReplay{}, fmt.Errorf(
			"%w: replay ending heads differ from signed envelope",
			ErrInvalidReplicationReplay,
		)
	}
	if err := verifyReplaySigner(state, batch); err != nil {
		return resultBatchReplay{}, err
	}
	stateDigest, err := projections.StateDigest(versions)
	if err != nil {
		return resultBatchReplay{}, fmt.Errorf(
			"%w: final projection state: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	if stateDigest != input.EndProjectionStateDigest {
		return resultBatchReplay{}, fmt.Errorf(
			"%w: replay projection state differs from signed envelope",
			ErrInvalidReplicationReplay,
		)
	}
	return resultBatchReplay{
		commands:              commands,
		heads:                 heads,
		projectionRows:        projections.Rows(),
		projectionStateDigest: stateDigest,
		admission:             admission,
		admissionChanged:      admissionChanged,
	}, nil
}

func validateReplayStart(
	view store.StateView,
	input replication.BatchInput,
) error {
	if view.SessionID != input.SessionID ||
		view.WorkspaceID != input.WorkspaceID ||
		view.RecoveryGeneration != input.RecoveryGeneration ||
		view.Heads.ResultIndex == domain.MaxSafeInteger ||
		input.FromResultIndex != view.Heads.ResultIndex+1 ||
		input.StartResultHash != chain.Digest(view.Heads.ResultHash) ||
		input.StartChainIndex != view.Heads.ChainIndex ||
		input.StartChainHash != chain.Digest(view.Heads.ChainHash) ||
		input.StartProjectionAccumulator !=
			chain.Digest(view.Heads.ProjectionAccumulator) ||
		input.StartProjectionStateDigest !=
			chain.Digest(view.ProjectionStateDigest) {
		return fmt.Errorf(
			"%w: batch does not extend the local lineage and heads",
			ErrInvalidReplicationReplay,
		)
	}
	return nil
}

func verifyReplayProposal(
	state reducer.State,
	encoded []byte,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) (event.SignedEvent, error) {
	deviceID, err := commandOriginDeviceID(encoded)
	if err != nil {
		return event.SignedEvent{}, err
	}
	member, exists := state.Device(deviceID)
	if !exists {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: origin device %q has no retained identity",
			ErrInvalidReplicationReplay,
			deviceID,
		)
	}
	signed, err := event.ParseAndVerify(
		encoded,
		event.VerificationContext{
			SessionID:         sessionID,
			WorkspaceID:       workspaceID,
			IdentityPublicKey: member.IdentityPublicKey,
		},
	)
	if err != nil {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: verify origin proposal: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	return signed, nil
}

func reduceReplicatedCommand(
	state reducer.State,
	signed event.SignedEvent,
	result chain.Result,
	heads store.ApplyHeads,
) (reducer.Outcome, error) {
	if signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return reducer.Reduce(state, signed)
	}
	status, _, err := decodeReplayOutcome(result.Outcome)
	if err != nil {
		return reducer.Outcome{}, err
	}
	if status == string(reducer.StatusRejected) {
		return reducer.ReduceAttestedRejectedCheckpoint(state, signed)
	}
	context, err := replicatedCheckpointContext(signed, heads)
	if err != nil {
		return reducer.Outcome{}, err
	}
	return reducer.ReduceCheckpoint(state, signed, context)
}

func replicatedCheckpointContext(
	signed event.SignedEvent,
	heads store.ApplyHeads,
) (reducer.CheckpointApplyContext, error) {
	checkpoint, _, err := event.DecodeCheckpointPayload(
		signed.Proposal().Payload,
	)
	if err != nil {
		return reducer.CheckpointApplyContext{}, fmt.Errorf(
			"%w: decode checkpoint replay payload: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	if checkpoint.CoveredAppliedLogIndex >= domain.MaxSafeInteger {
		return reducer.CheckpointApplyContext{}, fmt.Errorf(
			"%w: checkpoint successor position is exhausted",
			ErrInvalidReplicationReplay,
		)
	}
	return reducer.CheckpointApplyContext{
		Term:                    checkpoint.Term,
		LogIndex:                checkpoint.CoveredAppliedLogIndex + 1,
		ChainIndex:              heads.ChainIndex,
		ChainHash:               heads.ChainHash,
		ResultIndex:             heads.ResultIndex,
		ResultHash:              heads.ResultHash,
		ProjectionAccumulator:   heads.ProjectionAccumulator,
		DigestVersion:           heads.DigestVersion,
		ProjectionSchemaVersion: heads.ProjectionSchemaVersion,
	}, nil
}

func decodeReplayOutcome(encoded []byte) (string, string, error) {
	var wire struct {
		Code   string `json:"code"`
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil ||
		wire.Code == "" ||
		(wire.Status != string(reducer.StatusAccepted) &&
			wire.Status != string(reducer.StatusRejected)) {
		return "", "", fmt.Errorf(
			"%w: invalid command outcome",
			ErrInvalidReplicationReplay,
		)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", "", fmt.Errorf(
			"%w: command outcome has trailing data",
			ErrInvalidReplicationReplay,
		)
	}
	return wire.Status, wire.Code, nil
}

func replayCommandCommitments(
	prior store.ApplyHeads,
	result chain.Result,
	mutations []chain.Mutation,
) (store.ApplyHeads, error) {
	if prior.ResultIndex == domain.MaxSafeInteger ||
		result.ResultIndex != prior.ResultIndex+1 {
		return store.ApplyHeads{}, fmt.Errorf(
			"%w: result position is not the next dense index",
			ErrInvalidReplicationReplay,
		)
	}
	next := prior
	next.PreviousResultHash = prior.ResultHash
	next.ResultIndex = result.ResultIndex
	if result.ChainIndex != nil {
		if prior.ChainIndex == domain.MaxSafeInteger ||
			*result.ChainIndex != prior.ChainIndex+1 ||
			result.ChainHash == nil {
			return store.ApplyHeads{}, fmt.Errorf(
				"%w: accepted event position is not dense",
				ErrInvalidReplicationReplay,
			)
		}
		eventHash, err := chain.AppendEvent(
			chain.Digest(prior.ChainHash),
			result.Proposal,
		)
		if err != nil || eventHash != *result.ChainHash {
			return store.ApplyHeads{}, fmt.Errorf(
				"%w: accepted event hash differs",
				ErrInvalidReplicationReplay,
			)
		}
		next.ChainIndex = *result.ChainIndex
		next.ChainHash = store.Digest(*result.ChainHash)
	}
	resultHash, _, err := chain.AppendResult(
		chain.Digest(prior.ResultHash),
		result,
	)
	if err != nil {
		return store.ApplyHeads{}, fmt.Errorf(
			"%w: append result: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	next.ResultHash = store.Digest(resultHash)
	accumulator, _, err := chain.AppendAccumulator(
		chain.Digest(prior.ProjectionAccumulator),
		result.ResultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		return store.ApplyHeads{}, fmt.Errorf(
			"%w: append projection accumulator: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	next.ProjectionAccumulator = store.Digest(accumulator)
	return next, nil
}

func verifyReplaySigner(
	state reducer.State,
	batch replication.Batch,
) error {
	metadata := batch.Unsigned().Metadata()
	authority := state.CredentialAuthority()
	member, exists := state.Device(metadata.ServerDeviceID)
	if !exists ||
		member.Status != device.StatusActive ||
		authority.VoterSetVersion != metadata.ServerAuthorityVersion ||
		!authority.Contains(metadata.ServerDeviceID) {
		return ErrReplicationSignerUnauthorized
	}
	if err := replication.VerifyBatch(
		batch,
		member.IdentityPublicKey,
	); err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrInvalidReplicationReplay,
			err,
		)
	}
	return nil
}

func replayItemError(offset int, err error) error {
	return fmt.Errorf(
		"%w: result offset %d: %w",
		ErrInvalidReplicationReplay,
		offset,
		err,
	)
}

func cloneReplayMutations(values []chain.Mutation) []chain.Mutation {
	result := make([]chain.Mutation, len(values))
	for index, value := range values {
		result[index] = chain.Mutation{
			Table:      value.Table,
			PrimaryKey: bytes.Clone(value.PrimaryKey),
			Before:     bytes.Clone(value.Before),
			After:      bytes.Clone(value.After),
		}
	}
	return result
}
