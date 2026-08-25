package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
)

// ReplayCommand independently verifies and persists one artifact command. It
// accepts raw signed record bytes, re-runs origin verification and the frozen
// reducer, derives projection/local writes, and compares the exact artifact
// mutation stream before touching quarantine state.
func (stage *LogicalSnapshotStage) ReplayCommand(
	ctx context.Context,
	encodedResult []byte,
	encodedMutations []byte,
	appliedAt domain.Timestamp,
	originBootID domain.UUIDv7,
	monotonicNowNS int64,
) (ApplyHeads, error) {
	if stage == nil {
		return ApplyHeads{}, ErrInvalidLogicalSnapshotStage
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if err := stage.mutable(); err != nil {
		return ApplyHeads{}, err
	}
	if !stage.reducerReady ||
		stage.projections == nil ||
		stage.sessionID == "" ||
		stage.workspaceID == "" {
		return ApplyHeads{}, stage.failReplay(
			"reducer boundary is not initialized",
			nil,
		)
	}
	if ctx == nil {
		return ApplyHeads{}, stage.failReplay("nil context", nil)
	}
	if err := ctx.Err(); err != nil {
		stage.failed = err
		return ApplyHeads{}, err
	}

	result, err := chain.DecodeResult(encodedResult)
	if err != nil {
		return ApplyHeads{}, stage.failReplay("decode result", err)
	}
	mutations, err := chain.DecodeMutations(encodedMutations)
	if err != nil {
		return ApplyHeads{}, stage.failReplay("decode mutations", err)
	}
	canonicalMutations, err := chain.EncodeMutations(mutations)
	if err != nil || !bytes.Equal(canonicalMutations, encodedMutations) {
		return ApplyHeads{}, stage.failReplay(
			"mutation stream is not canonical",
			err,
		)
	}
	signed, err := stage.verifyReplayProposal(result.Proposal)
	if err != nil {
		return ApplyHeads{}, stage.failReplay("verify proposal", err)
	}
	outcome, err := reduceLogicalSnapshotCommand(
		stage.reducerState,
		signed,
		result,
		stage.heads,
	)
	if err != nil {
		return ApplyHeads{}, stage.failReplay("reduce command", err)
	}
	outcomeJSON, err := outcome.ResultJSON()
	if err != nil {
		return ApplyHeads{}, stage.failReplay("encode reducer outcome", err)
	}
	if !bytes.Equal(outcomeJSON, result.Outcome) {
		return ApplyHeads{}, stage.failReplay(
			"artifact outcome differs from frozen reducer",
			nil,
		)
	}

	writes := projectionWritesFromReducer(outcome.Changes)
	replayedMutations, err := stage.projections.Apply(writes)
	if err != nil {
		return ApplyHeads{}, stage.failReplay(
			"advance projection scratch",
			err,
		)
	}
	replayedMutationBytes, err := chain.EncodeMutations(replayedMutations)
	if err != nil {
		return ApplyHeads{}, stage.failReplay(
			"encode reducer mutations",
			err,
		)
	}
	if !bytes.Equal(replayedMutationBytes, encodedMutations) {
		return ApplyHeads{}, stage.failReplay(
			"artifact mutations differ from frozen reducer",
			nil,
		)
	}

	prior := consensusState{
		sessionID:               stage.sessionID,
		recoveryGeneration:      stage.generation,
		chainIndex:              stage.heads.ChainIndex,
		chainHash:               stage.heads.ChainHash,
		resultIndex:             stage.heads.ResultIndex,
		resultHash:              stage.heads.ResultHash,
		projectionAccumulator:   stage.heads.ProjectionAccumulator,
		digestVersion:           stage.heads.DigestVersion,
		projectionSchemaVersion: stage.heads.ProjectionSchemaVersion,
	}
	nextHeads, _, err := deriveImportedCommandCommitments(
		prior,
		result,
		encodedResult,
		replayedMutations,
	)
	if err != nil {
		return ApplyHeads{}, stage.failReplay(
			"derive command commitments",
			err,
		)
	}
	request, err := buildReducerApplyRequest(
		signed,
		outcome,
		reducerApplyContext{
			recoveryGeneration: stage.generation,
			appliedAt:          appliedAt,
			originBootID:       originBootID,
			monotonicNowNS:     monotonicNowNS,
			priorHeads:         stage.heads,
		},
	)
	if err != nil {
		return ApplyHeads{}, stage.failReplay("map reducer writes", err)
	}
	imported, err := stage.store.importLogicalSnapshotCommand(
		ctx,
		VerifiedCommandImport{
			Proposal:      request.Proposal,
			Outcome:       request.Outcome,
			EncodedResult: bytes.Clone(encodedResult),
			Projections:   request.Projections,
			Mutations:     replayedMutations,
			Heads:         nextHeads,
			Local: ResultBatchLocalWrites{
				AppliedAt:            request.AppliedAt,
				RecordActivity:       request.RecordActivity,
				ActivityTaskID:       request.ActivityTaskID,
				Audit:                request.Audit,
				Checkpoint:           request.Checkpoint,
				LeaseDeadlines:       request.LeaseDeadlines,
				DeleteLeaseDeadlines: request.DeleteLeaseDeadlines,
			},
		},
	)
	if err != nil {
		return ApplyHeads{}, stage.failReplay(
			"persist replayed command",
			err,
		)
	}
	if imported != nextHeads {
		return ApplyHeads{}, stage.failReplay(
			"persistence returned different heads",
			nil,
		)
	}
	if err := stage.reducerState.Apply(outcome.Changes); err != nil {
		return ApplyHeads{}, stage.failReplay(
			"advance reducer state",
			err,
		)
	}
	stage.heads = nextHeads
	return nextHeads, nil
}

func (stage *LogicalSnapshotStage) verifyReplayProposal(
	encoded []byte,
) (event.SignedEvent, error) {
	proposal, err := event.InspectUnverifiedProposal(encoded)
	if err != nil {
		return event.SignedEvent{}, err
	}
	member, exists := stage.reducerState.Device(
		proposal.Origin.DeviceID(),
	)
	if !exists {
		return event.SignedEvent{}, errors.New(
			"origin device has no retained identity",
		)
	}
	return event.ParseAndVerify(
		encoded,
		event.VerificationContext{
			SessionID:         stage.sessionID,
			WorkspaceID:       stage.workspaceID,
			IdentityPublicKey: member.IdentityPublicKey,
		},
	)
}

func reduceLogicalSnapshotCommand(
	state reducer.State,
	signed event.SignedEvent,
	result chain.Result,
	heads ApplyHeads,
) (reducer.Outcome, error) {
	if signed.Proposal().Kind != event.KindConsensusCheckpoint {
		return reducer.Reduce(state, signed)
	}
	status, err := logicalSnapshotOutcomeStatus(result.Outcome)
	if err != nil {
		return reducer.Outcome{}, err
	}
	if status == reducer.StatusRejected {
		return reducer.ReduceAttestedRejectedCheckpoint(state, signed)
	}
	checkpoint, _, err := event.DecodeCheckpointPayload(
		signed.Proposal().Payload,
	)
	if err != nil {
		return reducer.Outcome{}, err
	}
	if checkpoint.CoveredAppliedLogIndex >= domain.MaxSafeInteger {
		return reducer.Outcome{}, errors.New(
			"checkpoint successor position is exhausted",
		)
	}
	return reducer.ReduceCheckpoint(
		state,
		signed,
		reducer.CheckpointApplyContext{
			Term:                    checkpoint.Term,
			LogIndex:                checkpoint.CoveredAppliedLogIndex + 1,
			ChainIndex:              heads.ChainIndex,
			ChainHash:               heads.ChainHash,
			ResultIndex:             heads.ResultIndex,
			ResultHash:              heads.ResultHash,
			ProjectionAccumulator:   heads.ProjectionAccumulator,
			DigestVersion:           heads.DigestVersion,
			ProjectionSchemaVersion: heads.ProjectionSchemaVersion,
		},
	)
}

func logicalSnapshotOutcomeStatus(
	encoded []byte,
) (reducer.Status, error) {
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
		return "", errors.New("invalid command outcome")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("command outcome has trailing data")
	}
	return reducer.Status(wire.Status), nil
}

func (stage *LogicalSnapshotStage) failReplay(
	detail string,
	cause error,
) error {
	var err error
	if cause == nil {
		err = logicalSnapshotStageError(detail, nil)
	} else {
		err = logicalSnapshotStageError(detail, cause)
	}
	stage.failed = err
	return err
}
