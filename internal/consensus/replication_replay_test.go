package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestReplayResultBatchReproducesRaftStateAndRejections(t *testing.T) {
	node, privateKey, deviceID := openApplyAtGenerationTestNode(t)
	start, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(start): %v", err)
	}
	first := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"replicated task",
	)
	if _, err := node.Apply(testContext(t), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	second := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"duplicate entity",
	)
	secondResult, err := node.Apply(testContext(t), second)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	if secondResult.Outcome.Status != store.OutcomeRejected ||
		secondResult.Outcome.Code != string(reducer.CodeEntityAlreadyExists) {
		t.Fatalf("second result = %#v", secondResult)
	}
	end, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(end): %v", err)
	}
	batch := signedReplayBatch(
		t,
		node.state,
		start.Heads.ResultIndex,
		deviceID,
		privateKey,
	)

	replayed, err := replayResultBatch(testContext(t), start, batch)
	if err != nil {
		t.Fatalf("replayResultBatch(): %v", err)
	}
	if len(replayed.commands) != 2 ||
		replayed.commands[0].outcome.Status != reducer.StatusAccepted ||
		replayed.commands[1].outcome.Status != reducer.StatusRejected ||
		replayed.commands[1].outcome.Code !=
			reducer.CodeEntityAlreadyExists {
		t.Fatalf("replayed commands = %#v", replayed.commands)
	}
	assertReplayHeadsEqual(t, replayed.heads, end.Heads)
	if replayed.projectionStateDigest !=
		chain.Digest(end.ProjectionStateDigest) {
		t.Fatalf(
			"projection digest = %x, want %x",
			replayed.projectionStateDigest,
			end.ProjectionStateDigest,
		)
	}
	digest, err := chain.StateDigest(
		chain.Versions{
			Digest:           replayed.heads.DigestVersion,
			ProjectionSchema: replayed.heads.ProjectionSchemaVersion,
		},
		replayed.projectionRows,
	)
	if err != nil || digest != replayed.projectionStateDigest {
		t.Fatalf(
			"returned projection rows digest = %x, err %v",
			digest,
			err,
		)
	}
}

func TestReplayResultBatchRejectsWrongOutcomeAndTerminalAuthority(
	t *testing.T,
) {
	node, privateKey, deviceID := openApplyAtGenerationTestNode(t)
	start, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(start): %v", err)
	}
	signed := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"replicated task",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	valid := signedReplayBatch(
		t,
		node.state,
		start.Heads.ResultIndex,
		deviceID,
		privateKey,
	)

	wrongOutcomeInput := valid.Unsigned().Input()
	first, err := chain.DecodeResult(wrongOutcomeInput.Results[0])
	if err != nil {
		t.Fatalf("chain.DecodeResult(): %v", err)
	}
	first.Outcome = []byte(`{"code":"entity_not_found","status":"accepted"}`)
	wrongOutcomeInput.Results[0], err = chain.EncodeResult(first)
	if err != nil {
		t.Fatalf("chain.EncodeResult(wrong outcome): %v", err)
	}
	rebuildReplayResultHead(t, &wrongOutcomeInput)
	wrongOutcome := signReplayInput(t, wrongOutcomeInput, privateKey)
	if _, err := replayResultBatch(
		testContext(t),
		start,
		wrongOutcome,
	); !errors.Is(
		err,
		ErrReplicationOutcomeMismatch,
	) {
		t.Fatalf(
			"replayResultBatch(wrong outcome) error = %v, want outcome mismatch",
			err,
		)
	}

	wrongAuthorityInput := valid.Unsigned().Input()
	wrongAuthorityInput.ServerAuthorityVersion++
	wrongAuthority := signReplayInput(
		t,
		wrongAuthorityInput,
		privateKey,
	)
	if _, err := replayResultBatch(
		testContext(t),
		start,
		wrongAuthority,
	); !errors.Is(
		err,
		ErrReplicationSignerUnauthorized,
	) {
		t.Fatalf(
			"replayResultBatch(wrong authority) error = %v, want unauthorized signer",
			err,
		)
	}

	wrongProjectionInput := valid.Unsigned().Input()
	wrongProjectionInput.EndProjectionStateDigest[0] ^= 0xff
	wrongProjection := signReplayInput(
		t,
		wrongProjectionInput,
		privateKey,
	)
	if _, err := replayResultBatch(
		testContext(t),
		start,
		wrongProjection,
	); !errors.Is(
		err,
		ErrInvalidReplicationReplay,
	) {
		t.Fatalf(
			"replayResultBatch(wrong projection digest) error = %v, want invalid replay",
			err,
		)
	}
}

func TestReplayResultBatchValidatesStaleCheckpointWithoutRaftProvenance(
	t *testing.T,
) {
	node, origin, privateKey, deviceID := openCheckpointCommitNode(t, nil)
	start, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(start): %v", err)
	}
	prepareStaleCheckpointRetry(
		t,
		node,
		origin,
		privateKey,
		deviceID,
		[]domain.UUIDv7{
			checkpointCommitEventID,
			checkpointCommitRetryEventID,
		},
	)
	if _, err := node.ForceCheckpoint(testContext(t)); err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	end, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(end): %v", err)
	}
	batch := signedReplayBatch(
		t,
		node.state,
		start.Heads.ResultIndex,
		deviceID,
		privateKey,
	)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := replayResultBatch(
		cancelled,
		start,
		batch,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("replayResultBatch(cancelled) error = %v", err)
	}
	replayed, err := replayResultBatch(testContext(t), start, batch)
	if err != nil {
		t.Fatalf("replayResultBatch(): %v", err)
	}
	var stale, accepted bool
	for _, command := range replayed.commands {
		if command.signed.Proposal().Kind !=
			"consensus.checkpoint" {
			continue
		}
		switch {
		case command.outcome.Status == reducer.StatusRejected &&
			command.outcome.Code == reducer.CodeStaleCheckpoint:
			stale = true
		case command.outcome.Status == reducer.StatusAccepted:
			accepted = true
		}
	}
	if !stale || !accepted {
		t.Fatalf(
			"checkpoint replay stale=%t accepted=%t commands=%#v",
			stale,
			accepted,
			replayed.commands,
		)
	}
	assertReplayHeadsEqual(t, replayed.heads, end.Heads)
}

func TestReplayResultBatchValidatesRejectedCheckpointWithoutRaftContext(
	t *testing.T,
) {
	node, privateKey, deviceID := openApplyAtGenerationTestNode(t)
	start, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(start): %v", err)
	}
	signed := invalidReplayCheckpointEvent(
		t,
		privateKey,
		deviceID,
	)
	applied, err := node.Apply(testContext(t), signed)
	if err != nil {
		t.Fatalf("Apply(invalid checkpoint): %v", err)
	}
	if applied.Outcome.Status != store.OutcomeRejected ||
		applied.Outcome.Code != string(reducer.CodeInvalidPayload) {
		t.Fatalf("invalid checkpoint outcome = %+v", applied.Outcome)
	}
	batch := signedReplayBatch(
		t,
		node.state,
		start.Heads.ResultIndex,
		deviceID,
		privateKey,
	)

	replayed, err := replayResultBatch(testContext(t), start, batch)
	if err != nil {
		t.Fatalf("replayResultBatch(): %v", err)
	}
	if len(replayed.commands) != 1 ||
		replayed.commands[0].outcome.Status != reducer.StatusRejected ||
		replayed.commands[0].outcome.Code != reducer.CodeInvalidPayload {
		t.Fatalf("replayed commands = %#v", replayed.commands)
	}
	assertReplayHeadsEqual(t, replayed.heads, applied.Heads)
}

func invalidReplayCheckpointEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(deviceID, nodeTestBootID1)
	if err != nil {
		t.Fatalf("event.NewLocalAuthority(): %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding(): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindConsensusCheckpoint,
			EntityID: event.NullEntityID(),
			Actions:  []event.Action{},
			Payload:  []byte(`{}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        checkpointCommitEventID,
			SessionID:      nodeTestSessionID,
			WorkspaceID:    nodeTestWorkspaceID,
			CreatedAt:      nodeTestTimestamp1,
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatalf("event.BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("event.Sign(): %v", err)
	}
	return signed
}

func signedReplayBatch(
	t *testing.T,
	database *store.Store,
	afterResult uint64,
	signerID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) replication.Batch {
	t.Helper()
	exported, found, err := database.ExportResultRange(
		context.Background(),
		store.ResultRangeOptions{
			AfterResultIndex:          afterResult,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: signerID,
		},
	)
	if err != nil || !found {
		t.Fatalf(
			"ExportResultRange() = found %t, err %v",
			found,
			err,
		)
	}
	return signReplayInput(t, replication.BatchInput{
		FromResultIndex: exported.FromResultIndex,
		ToResultIndex:   exported.ToResultIndex,
		StartResultHash: chain.Digest(exported.StartResultHash),
		EndResultHash:   chain.Digest(exported.EndResultHash),
		StartChainIndex: exported.StartChainIndex,
		StartChainHash:  chain.Digest(exported.StartChainHash),
		EndChainIndex:   exported.EndChainIndex,
		EndChainHash:    chain.Digest(exported.EndChainHash),
		StartProjectionAccumulator: chain.Digest(
			exported.StartProjectionAccumulator,
		),
		EndProjectionAccumulator: chain.Digest(
			exported.EndProjectionAccumulator,
		),
		StartProjectionStateDigest: chain.Digest(
			exported.StartProjectionStateDigest,
		),
		EndProjectionStateDigest: chain.Digest(
			exported.EndProjectionStateDigest,
		),
		Results:                  exported.Results,
		SessionID:                exported.SessionID,
		WorkspaceID:              exported.WorkspaceID,
		RecoveryGeneration:       exported.RecoveryGeneration,
		ServerDeviceID:           signerID,
		ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
		ServerAuthorityVersion:   exported.Authority.VoterSetVersion,
	}, privateKey)
}

func signReplayInput(
	t *testing.T,
	input replication.BatchInput,
	privateKey ed25519.PrivateKey,
) replication.Batch {
	t.Helper()
	unsigned, err := replication.NewUnsignedBatch(input)
	if err != nil {
		t.Fatalf("replication.NewUnsignedBatch(): %v", err)
	}
	batch, err := replication.SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("replication.SignBatch(): %v", err)
	}
	return batch
}

func rebuildReplayResultHead(
	t *testing.T,
	input *replication.BatchInput,
) {
	t.Helper()
	head := input.StartResultHash
	for index, encoded := range input.Results {
		result, err := chain.DecodeResult(encoded)
		if err != nil {
			t.Fatalf("chain.DecodeResult(%d): %v", index, err)
		}
		head, input.Results[index], err = chain.AppendResult(head, result)
		if err != nil {
			t.Fatalf("chain.AppendResult(%d): %v", index, err)
		}
	}
	input.EndResultHash = head
}

func assertReplayHeadsEqual(
	t *testing.T,
	got store.ApplyHeads,
	want store.ApplyHeads,
) {
	t.Helper()
	if got.ChainIndex != want.ChainIndex ||
		got.ChainHash != want.ChainHash ||
		got.ResultIndex != want.ResultIndex ||
		got.ResultHash != want.ResultHash ||
		got.ProjectionAccumulator != want.ProjectionAccumulator ||
		got.DigestVersion != want.DigestVersion ||
		got.ProjectionSchemaVersion !=
			want.ProjectionSchemaVersion {
		t.Fatalf("replay heads = %#v, want %#v", got, want)
	}
}

func TestReplayResultBatchOwnsBatchMemory(t *testing.T) {
	node, privateKey, deviceID := openApplyAtGenerationTestNode(t)
	start, err := node.View(testContext(t))
	if err != nil {
		t.Fatalf("View(start): %v", err)
	}
	signed := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"replicated task",
	)
	if _, err := node.Apply(testContext(t), signed); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	batch := signedReplayBatch(
		t,
		node.state,
		start.Heads.ResultIndex,
		deviceID,
		privateKey,
	)
	replayed, err := replayResultBatch(testContext(t), start, batch)
	if err != nil {
		t.Fatalf("replayResultBatch(): %v", err)
	}
	pristine := bytes.Clone(replayed.commands[0].encoded)
	input := batch.Unsigned().Input()
	input.Results[0][0] ^= 0xff
	if !bytes.Equal(pristine, replayed.commands[0].encoded) {
		t.Fatal("replayed command aliases batch result storage")
	}
}
