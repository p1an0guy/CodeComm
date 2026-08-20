package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
)

const resultBatchVerifiedAt = domain.Timestamp("2026-08-19T20:00:00Z")

func TestImportSettledNonvoterResultBatchPersistsVerifiedCut(t *testing.T) {
	fixture := newResultBatchImportFixture(t)
	beforeRevision := fixture.target.AdmissionRevision()

	got, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	)
	if err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	if got.Heads != fixture.source.second.Heads ||
		got.AttestationID != fixture.request.Batch.AttestationID() ||
		got.AdmissionRevision != beforeRevision+1 ||
		fixture.target.AdmissionRevision() != got.AdmissionRevision {
		t.Fatalf("import result = %+v, revision before = %d", got, beforeRevision)
	}

	view, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	durableHeads := fixture.source.second.Heads
	durableHeads.PreviousResultHash = Digest{}
	if view.Heads != durableHeads ||
		view.ProjectionStateDigest != fixture.request.FinalProjectionDigest ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil {
		t.Fatalf("imported view = %+v", view)
	}
	assertCounts(t, fixture.target, map[string]int64{
		"events":                    1,
		"command_results":           2,
		"event_provenance":          0,
		"raft_command_applications": 0,
		"activity":                  1,
		"audit_events":              2,
		"replication_attestations":  1,
		"replication_cursors":       1,
		"tasks":                     1,
	})

	metadata := fixture.request.Batch.Unsigned().Metadata()
	signature := fixture.request.Batch.Signature()
	var (
		attestationSigner domain.DeviceID
		cursorPeer        domain.DeviceID
		envelope          []byte
		storedSignature   []byte
		serverWatermark   uint64
	)
	err = fixture.target.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			if err := queryOneArgs(
				conn,
				`SELECT signer_device_id, envelope_json, signature,
				        server_applied_result_index
				   FROM replication_attestations
				  WHERE attestation_id = ?1;`,
				[]any{fixture.request.Batch.AttestationID()},
				func(stmt *sqlite.Stmt) {
					attestationSigner = domain.DeviceID(stmt.ColumnText(0))
					envelope = []byte(stmt.ColumnText(1))
					storedSignature = bytes.Clone(columnBytes(stmt, 2))
					serverWatermark = uint64(stmt.ColumnInt64(3))
				},
			); err != nil {
				return err
			}
			return queryOne(
				conn,
				"SELECT peer_device_id FROM replication_cursors;",
				func(stmt *sqlite.Stmt) {
					cursorPeer = domain.DeviceID(stmt.ColumnText(0))
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("read attestation and cursor: %v", err)
	}
	if attestationSigner != metadata.ServerDeviceID ||
		cursorPeer != fixture.request.RelayPeerID ||
		cursorPeer == attestationSigner ||
		!bytes.Equal(envelope, fixture.request.Batch.AttestationEnvelope()) ||
		!bytes.Equal(storedSignature, signature[:]) ||
		serverWatermark != metadata.ServerAppliedResultIndex {
		t.Fatalf(
			"attestation signer=%q cursor=%q watermark=%d envelope/signature match=%t/%t",
			attestationSigner,
			cursorPeer,
			serverWatermark,
			bytes.Equal(envelope, fixture.request.Batch.AttestationEnvelope()),
			bytes.Equal(storedSignature, signature[:]),
		)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(imported): %v", err)
	}
	reopened := openTestStore(t, path, nil)
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopened): %v", err)
	}
}

func TestImportSettledNonvoterResultBatchRejectsTamperAndRollback(t *testing.T) {
	t.Run("tampered heads", func(t *testing.T) {
		fixture := newResultBatchImportFixture(t)
		beforeRevision := fixture.target.AdmissionRevision()
		fixture.request.Commands[0].Heads.ResultHash[0] ^= 0xff

		if _, err := fixture.target.ImportSettledNonvoterResultBatch(
			context.Background(),
			fixture.request,
		); !errors.Is(err, ErrInvalidResultBatchImport) {
			t.Fatalf("tampered import error = %v", err)
		}
		assertResultBatchImportUnchanged(
			t,
			fixture.target,
			fixture.initial,
			beforeRevision,
		)
	})

	t.Run("tampered mutations", func(t *testing.T) {
		fixture := newResultBatchImportFixture(t)
		beforeRevision := fixture.target.AdmissionRevision()
		fixture.request.Commands[0].Mutations = []chain.Mutation{{
			Table: "unknown_table",
		}}

		if _, err := fixture.target.ImportSettledNonvoterResultBatch(
			context.Background(),
			fixture.request,
		); !errors.Is(err, ErrInvalidResultBatchImport) {
			t.Fatalf("tampered import error = %v", err)
		}
		assertResultBatchImportUnchanged(
			t,
			fixture.target,
			fixture.initial,
			beforeRevision,
		)
	})

	t.Run("tampered starting projection digest", func(t *testing.T) {
		fixture := newResultBatchImportFixture(t)
		beforeRevision := fixture.target.AdmissionRevision()
		input := fixture.request.Batch.Unsigned().Input()
		input.StartProjectionStateDigest[0] ^= 0xff
		unsigned, err := replication.NewUnsignedBatch(input)
		if err != nil {
			t.Fatalf("NewUnsignedBatch(): %v", err)
		}
		privateKey := resultBatchPrivateKey(1)
		defer clear(privateKey)
		fixture.request.Batch, err = replication.SignBatch(unsigned, privateKey)
		if err != nil {
			t.Fatalf("SignBatch(): %v", err)
		}

		if _, err := fixture.target.ImportSettledNonvoterResultBatch(
			context.Background(),
			fixture.request,
		); !errors.Is(err, ErrInvalidResultBatchImport) {
			t.Fatalf("tampered import error = %v", err)
		}
		assertResultBatchImportUnchanged(
			t,
			fixture.target,
			fixture.initial,
			beforeRevision,
		)
	})

	t.Run("batch replay rolls back durable start", func(t *testing.T) {
		fixture := newResultBatchImportFixture(t)
		if _, err := fixture.target.ImportSettledNonvoterResultBatch(
			context.Background(),
			fixture.request,
		); err != nil {
			t.Fatalf("first import: %v", err)
		}
		beforeRevision := fixture.target.AdmissionRevision()
		before, err := fixture.target.View(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.target.ImportSettledNonvoterResultBatch(
			context.Background(),
			fixture.request,
		); !errors.Is(err, ErrInvalidResultBatchImport) {
			t.Fatalf("replayed import error = %v", err)
		}
		after, err := fixture.target.View(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if after.Heads != before.Heads ||
			fixture.target.AdmissionRevision() != beforeRevision {
			t.Fatal("rejected replay changed durable heads or admission revision")
		}
		assertCounts(t, fixture.target, map[string]int64{
			"command_results":          2,
			"replication_attestations": 1,
			"replication_cursors":      1,
		})
	})
}

func TestSettledNonvoterReopenRejectsUnsignedProjectionRewrite(t *testing.T) {
	fixture := newResultBatchImportFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}

	input := fixture.request.Batch.Unsigned().Input()
	resultHead := input.StartResultHash
	accumulator := input.StartProjectionAccumulator
	encodedMutations := make([][]byte, len(fixture.request.Commands))
	changedTask := false
	for index, command := range fixture.request.Commands {
		mutations := make([]chain.Mutation, len(command.Mutations))
		for mutationIndex, mutation := range command.Mutations {
			mutations[mutationIndex] = chain.Mutation{
				Table:      mutation.Table,
				PrimaryKey: bytes.Clone(mutation.PrimaryKey),
				Before:     bytes.Clone(mutation.Before),
				After:      bytes.Clone(mutation.After),
			}
			if mutation.Table == "tasks" && mutation.After != nil {
				mutations[mutationIndex].After = bytes.Replace(
					mutation.After,
					[]byte(`"Imported task"`),
					[]byte(`"Forged task"`),
					1,
				)
				changedTask = !bytes.Equal(
					mutations[mutationIndex].After,
					mutation.After,
				)
			}
		}
		var err error
		encodedMutations[index], err = chain.EncodeMutations(mutations)
		if err != nil {
			t.Fatalf("EncodeMutations(%d): %v", index, err)
		}
		result, err := chain.DecodeResult(input.Results[index])
		if err != nil {
			t.Fatalf("DecodeResult(%d): %v", index, err)
		}
		resultHead, _, err = chain.AppendResult(resultHead, result)
		if err != nil {
			t.Fatalf("AppendResult(%d): %v", index, err)
		}
		accumulator, _, err = chain.AppendAccumulator(
			accumulator,
			result.ResultIndex,
			resultHead,
			mutations,
		)
		if err != nil {
			t.Fatalf("AppendAccumulator(%d): %v", index, err)
		}
	}
	if !changedTask || resultHead != input.EndResultHash ||
		accumulator == input.EndProjectionAccumulator {
		t.Fatal("test did not construct a coherent, distinct projection history")
	}

	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			for index, encoded := range encodedMutations {
				if err := execute(
					conn,
					`UPDATE command_results
					    SET projection_mutations_json = ?1
					  WHERE result_index = ?2;`,
					string(encoded),
					input.FromResultIndex+uint64(index),
				); err != nil {
					return err
				}
			}
			if err := execute(
				conn,
				"UPDATE tasks SET title = 'Forged task';",
			); err != nil {
				return err
			}
			return execute(
				conn,
				`UPDATE consensus_state
				    SET projection_accumulator = ?1
				  WHERE singleton = 1;`,
				accumulator[:],
			)
		},
	); err != nil {
		t.Fatalf("rewrite imported projection history: %v", err)
	}
	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := Open(
		context.Background(),
		Options{Path: path},
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"Open(unsigned projection rewrite) error = %v, want evidence failure",
			err,
		)
	}
}

func TestImportSettledNonvoterResultBatchIsAtomicAtFailpoint(t *testing.T) {
	tests := []struct {
		stage      applyStage
		occurrence int
	}{
		{stage: applyAfterEvent, occurrence: 1},
		{stage: applyAfterProvenance, occurrence: 1},
		{stage: applyAfterProjections, occurrence: 1},
		{stage: applyAfterResult, occurrence: 1},
		{stage: applyAfterActivity, occurrence: 1},
		{stage: applyAfterAudit, occurrence: 1},
		// The third command carries the checkpoint and lease deadline.
		{stage: applyAfterCheckpoint, occurrence: 3},
		{stage: applyAfterLeaseDeadlines, occurrence: 3},
		// The first command has a matching queued local proposal.
		{stage: applyAfterOutbox, occurrence: 1},
		{stage: applyAfterConsensus, occurrence: 1},
	}
	covered := make(map[applyStage]struct{}, len(tests))
	for _, test := range tests {
		covered[test.stage] = struct{}{}
	}
	for stage := applyAfterEvent; stage <= applyAfterConsensus; stage++ {
		if _, found := covered[stage]; !found {
			t.Fatalf("apply stage %s has no result-batch atomicity case", stage)
		}
	}

	for _, test := range tests {
		t.Run(test.stage.String(), func(t *testing.T) {
			fixture := newResultBatchAtomicityFixture(t)
			before := captureResultBatchImportAtomicSnapshot(t, fixture.target)
			injected := errors.New("injected result-batch failure")
			occurrence := 0
			fixture.target.applyFailpoint = func(stage applyStage) error {
				if stage != test.stage {
					return nil
				}
				occurrence++
				if occurrence == test.occurrence {
					return injected
				}
				return nil
			}
			defer func() {
				fixture.target.applyFailpoint = nil
			}()

			_, err := fixture.target.ImportSettledNonvoterResultBatch(
				context.Background(),
				fixture.request,
			)
			if err == nil ||
				!errors.Is(err, injected) &&
					!strings.Contains(err.Error(), injected.Error()) {
				t.Fatalf(
					"failpoint import error = %v, want injected failure",
					err,
				)
			}
			if occurrence != test.occurrence {
				t.Fatalf(
					"stage %s reached %d times, want failure on occurrence %d",
					test.stage,
					occurrence,
					test.occurrence,
				)
			}
			fixture.target.applyFailpoint = nil
			assertResultBatchImportAtomicSnapshotUnchanged(
				t,
				fixture.target,
				before,
			)
		})
	}
}

type resultBatchImportFixture struct {
	source  resultRangeFixture
	target  *Store
	initial ApplyHeads
	request VerifiedResultBatchImport
}

type resultBatchImportSourceCommand struct {
	request ApplyRequest
	heads   ApplyHeads
}

func newResultBatchImportFixture(t *testing.T) resultBatchImportFixture {
	t.Helper()
	source := newResultBatchImportSource(t)
	firstProposal := testSignedTaskEvent(t, testEventID, 1)
	firstRequest := acceptedApplyRequest(t, firstProposal)
	firstRequest.Projections.Tasks = []task.Task{resultBatchTaskProjection()}
	secondProposal := testSignedTaskEvent(t, testEventID2, 1)
	secondRequest := rejectedApplyRequest(
		t,
		secondProposal,
		source.first.Heads,
	)
	return newResultBatchImportFixtureFromSource(
		t,
		source,
		[]resultBatchImportSourceCommand{
			{request: firstRequest, heads: source.first.Heads},
			{request: secondRequest, heads: source.second.Heads},
		},
	)
}

func newResultBatchAtomicityFixture(t *testing.T) resultBatchImportFixture {
	t.Helper()
	source := newResultBatchImportSource(t)
	firstProposal := testSignedTaskEvent(t, testEventID, 1)
	firstRequest := acceptedApplyRequest(t, firstProposal)
	firstRequest.Projections.Tasks = []task.Task{resultBatchTaskProjection()}
	secondProposal := testSignedTaskEvent(t, testEventID2, 1)
	secondRequest := rejectedApplyRequest(
		t,
		secondProposal,
		source.first.Heads,
	)
	checkpointRequest := nextCheckpointApplyRequest(
		t,
		source.second.Heads,
		testCheckpointEventID,
		1,
		3,
		domain.Timestamp("2026-08-10T12:00:02Z"),
	)
	checkpointRequest.Projections.Leases = []lease.Lease{
		testActiveLease(
			t,
			checkpointRequest.Proposal.Proposal().Origin.DeviceID(),
		),
	}
	checkpointRequest.LeaseDeadlines = []LeaseDeadlineRecord{{
		LeaseID:             testLeaseID,
		EntityVersion:       1,
		OriginBootID:        testBootID,
		MonotonicDeadlineNS: 123456789,
		DisplayDeadlineAt:   domain.Timestamp("2026-08-10T12:15:02Z"),
	}}
	checkpointResult, err := source.store.Apply(
		context.Background(),
		checkpointRequest,
	)
	if err != nil {
		t.Fatalf("Apply(source checkpoint): %v", err)
	}
	fixture := newResultBatchImportFixtureFromSource(
		t,
		source,
		[]resultBatchImportSourceCommand{
			{request: firstRequest, heads: source.first.Heads},
			{request: secondRequest, heads: source.second.Heads},
			{request: checkpointRequest, heads: checkpointResult.Heads},
		},
	)
	insertOutbox(t, fixture.target, firstProposal)
	return fixture
}

func newResultBatchImportFixtureFromSource(
	t *testing.T,
	source resultRangeFixture,
	sourceCommands []resultBatchImportSourceCommand,
) resultBatchImportFixture {
	t.Helper()
	initialState := resultBatchInitialState(t, source.authorityDeviceID)
	target := openTestStore(
		t,
		filepath.Join(t.TempDir(), "target", "state.db"),
		nil,
	)
	initial, err := target.Initialize(context.Background(), initialState)
	if err != nil {
		t.Fatalf("Initialize(target): %v", err)
	}
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		domain.Timestamp("2026-08-19T19:59:00Z"),
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}

	exported, found, err := source.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex:          initial.ResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: source.authorityDeviceID,
		},
	)
	if err != nil || !found {
		t.Fatalf("ExportResultRange() = found %t, err %v", found, err)
	}
	unsigned, err := replication.NewUnsignedBatch(replication.BatchInput{
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
		ServerDeviceID:           source.authorityDeviceID,
		ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
		ServerAuthorityVersion:   exported.Authority.VoterSetVersion,
	})
	if err != nil {
		t.Fatalf("NewUnsignedBatch(): %v", err)
	}
	batch, err := replication.SignBatch(unsigned, resultBatchPrivateKey(1))
	if err != nil {
		t.Fatalf("SignBatch(): %v", err)
	}

	mutations := resultBatchStoredMutations(t, source.store)
	if len(sourceCommands) != len(mutations) ||
		len(sourceCommands) != len(exported.Results) {
		t.Fatalf(
			"source commands/mutations/results = %d/%d/%d",
			len(sourceCommands),
			len(mutations),
			len(exported.Results),
		)
	}
	commands := make([]ResultBatchCommand, len(sourceCommands))
	for index, sourceCommand := range sourceCommands {
		commands[index] = resultBatchCommand(
			sourceCommand.request,
			mutations[index],
			sourceCommand.heads,
		)
	}
	sourceView, err := source.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(source): %v", err)
	}
	return resultBatchImportFixture{
		source:  source,
		target:  target,
		initial: initial,
		request: VerifiedResultBatchImport{
			RelayPeerID:           resultBatchRelayDeviceID(t),
			Batch:                 batch,
			Commands:              commands,
			VerifiedAt:            resultBatchVerifiedAt,
			FinalProjectionDigest: sourceView.ProjectionStateDigest,
		},
	}
}

func newResultBatchImportSource(t *testing.T) resultRangeFixture {
	t.Helper()
	firstProposal := testSignedTaskEvent(t, testEventID, 1)
	authorityDeviceID := firstProposal.Proposal().Origin.DeviceID()
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "source", "state.db"),
		nil,
	)
	initial, err := database.Initialize(
		context.Background(),
		resultBatchInitialState(t, authorityDeviceID),
	)
	if err != nil {
		t.Fatalf("Initialize(source): %v", err)
	}
	firstRequest := acceptedApplyRequest(t, firstProposal)
	firstRequest.Projections.Tasks = []task.Task{resultBatchTaskProjection()}
	first, err := database.Apply(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("Apply(source first): %v", err)
	}
	secondProposal := testSignedTaskEvent(t, testEventID2, 1)
	second, err := database.Apply(
		context.Background(),
		rejectedApplyRequest(t, secondProposal, first.Heads),
	)
	if err != nil {
		t.Fatalf("Apply(source second): %v", err)
	}
	return resultRangeFixture{
		store:             database,
		initial:           initial,
		first:             first,
		second:            second,
		authorityDeviceID: authorityDeviceID,
	}
}

func resultBatchTaskProjection() task.Task {
	return task.Task{
		ID:            testTaskID,
		Title:         "Imported task",
		Body:          "",
		State:         task.StateBacklog,
		Priority:      task.PriorityNormal,
		BlockedBy:     []domain.UUIDv7{},
		Labels:        []string{},
		EntityVersion: 1,
		CreatedAt:     testAppliedAt,
		UpdatedAt:     testAppliedAt,
	}
}

func resultBatchInitialState(
	t *testing.T,
	authorityDeviceID domain.DeviceID,
) InitialState {
	t.Helper()
	authorityDevice := resultRangeTestAuthorityDevice(t)
	if authorityDevice.ID != authorityDeviceID {
		t.Fatal("authority device mismatch")
	}
	target, err := voterset.New(
		domain.UUIDv7(testSessionID),
		[]domain.DeviceID{authorityDeviceID},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	return commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		ProjectionWrites{
			Devices:  []device.Device{authorityDevice},
			VoterSet: []voterset.Set{target},
			CredentialAuthority: []CredentialAuthorityRow{{
				SessionID:        domain.UUIDv7(testSessionID),
				VoterDeviceIDs:   []domain.DeviceID{authorityDeviceID},
				VoterSetVersion:  1,
				ActivationSource: CredentialAuthorityGenesis,
			}},
		},
	)
}

func resultBatchCommand(
	request ApplyRequest,
	mutations []chain.Mutation,
	heads ApplyHeads,
) ResultBatchCommand {
	return ResultBatchCommand{
		Proposal:    request.Proposal,
		Outcome:     request.Outcome,
		Projections: request.Projections,
		Mutations:   mutations,
		Heads:       heads,
		Local: ResultBatchLocalWrites{
			AppliedAt:            request.AppliedAt,
			RecordActivity:       request.RecordActivity,
			ActivityTaskID:       request.ActivityTaskID,
			Audit:                request.Audit,
			Checkpoint:           request.Checkpoint,
			LeaseDeadlines:       request.LeaseDeadlines,
			DeleteLeaseDeadlines: request.DeleteLeaseDeadlines,
		},
	}
}

func resultBatchStoredMutations(
	t *testing.T,
	database *Store,
) [][]chain.Mutation {
	t.Helper()
	var result [][]chain.Mutation
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var decodeErr error
			err := query(
				conn,
				`SELECT projection_mutations_json
				   FROM command_results ORDER BY result_index;`,
				func(stmt *sqlite.Stmt) {
					if decodeErr != nil {
						return
					}
					var decoded []chain.Mutation
					decoded, decodeErr = chain.DecodeMutations(
						[]byte(stmt.ColumnText(0)),
					)
					result = append(result, decoded)
				},
			)
			if err != nil {
				return err
			}
			return decodeErr
		},
	)
	if err != nil {
		t.Fatalf("read stored mutations: %v", err)
	}
	return result
}

func resultBatchPrivateKey(offset byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index+1) + offset - 1
	}
	return ed25519.NewKeyFromSeed(seed)
}

func resultBatchRelayDeviceID(t *testing.T) domain.DeviceID {
	t.Helper()
	privateKey := resultBatchPrivateKey(17)
	defer clear(privateKey)
	id, err := device.DeriveID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var resultBatchImportAtomicTables = [...]string{
	"events",
	"command_results",
	"event_provenance",
	"raft_command_applications",
	"activity",
	"audit_events",
	"chain_checkpoints",
	"lease_deadlines",
	"replication_attestations",
	"replication_cursors",
	"settled_nonvoter_state",
	"tasks",
	"leases",
	"local_requests",
	"outbox",
}

type resultBatchImportLocalSnapshot struct {
	requestEventID             string
	requestState               string
	requestSignedProposal      []byte
	requestProposalDigest      Digest
	requestTerminalCode        string
	requestTerminalCodePresent bool
	outboxEventID              string
	outboxState                string
	outboxSignedProposal       []byte
	outboxProposalDigest       Digest
}

type resultBatchImportAtomicSnapshot struct {
	view              StateView
	admissionRevision uint64
	settled           settledNonvoterState
	counts            map[string]int64
	local             resultBatchImportLocalSnapshot
}

func captureResultBatchImportAtomicSnapshot(
	t *testing.T,
	database *Store,
) resultBatchImportAtomicSnapshot {
	t.Helper()
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(atomic snapshot): %v", err)
	}
	result := resultBatchImportAtomicSnapshot{
		view:              view,
		admissionRevision: database.AdmissionRevision(),
		counts:            make(map[string]int64, len(resultBatchImportAtomicTables)),
	}
	err = database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			settled, found, err := readSettledNonvoterState(conn)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("settled-nonvoter evidence is missing")
			}
			result.settled = settled
			for _, table := range resultBatchImportAtomicTables {
				var count int64
				if err := queryOne(
					conn,
					"SELECT count(*) FROM "+table+";",
					func(stmt *sqlite.Stmt) {
						count = stmt.ColumnInt64(0)
					},
				); err != nil {
					return err
				}
				result.counts[table] = count
			}

			var rowErr error
			if err := queryOne(
				conn,
				`SELECT event_id, state, signed_proposal_json,
				        proposal_digest, terminal_code
				   FROM local_requests;`,
				func(stmt *sqlite.Stmt) {
					result.local.requestEventID = stmt.ColumnText(0)
					result.local.requestState = stmt.ColumnText(1)
					result.local.requestSignedProposal = bytes.Clone(
						columnBytes(stmt, 2),
					)
					rowErr = copyDigestColumn(
						&result.local.requestProposalDigest,
						stmt,
						3,
					)
					if stmt.ColumnType(4) != sqlite.TypeNull {
						result.local.requestTerminalCodePresent = true
						result.local.requestTerminalCode = stmt.ColumnText(4)
					}
				},
			); err != nil {
				return err
			}
			if rowErr != nil {
				return rowErr
			}
			if err := queryOne(
				conn,
				`SELECT event_id, state, signed_proposal_json,
				        proposal_digest
				   FROM outbox;`,
				func(stmt *sqlite.Stmt) {
					result.local.outboxEventID = stmt.ColumnText(0)
					result.local.outboxState = stmt.ColumnText(1)
					result.local.outboxSignedProposal = bytes.Clone(
						columnBytes(stmt, 2),
					)
					rowErr = copyDigestColumn(
						&result.local.outboxProposalDigest,
						stmt,
						3,
					)
				},
			); err != nil {
				return err
			}
			return rowErr
		},
	)
	if err != nil {
		t.Fatalf("capture atomic snapshot: %v", err)
	}
	return result
}

func assertResultBatchImportAtomicSnapshotUnchanged(
	t *testing.T,
	database *Store,
	before resultBatchImportAtomicSnapshot,
) {
	t.Helper()
	after := captureResultBatchImportAtomicSnapshot(t, database)
	if after.view.Heads != before.view.Heads ||
		!reflect.DeepEqual(
			after.view.CurrentTerm,
			before.view.CurrentTerm,
		) ||
		!reflect.DeepEqual(
			after.view.LastRaftAppliedLogIndex,
			before.view.LastRaftAppliedLogIndex,
		) {
		t.Fatalf(
			"failed import changed consensus heads or Raft watermark: before=%+v after=%+v",
			before.view.Heads,
			after.view.Heads,
		)
	}
	if after.view.ProjectionStateDigest != before.view.ProjectionStateDigest ||
		!reflect.DeepEqual(
			after.view.ProjectionRows,
			before.view.ProjectionRows,
		) {
		t.Fatal("failed import changed logical projections")
	}
	if after.settled != before.settled {
		t.Fatalf(
			"failed import changed settled-nonvoter evidence: before=%+v after=%+v",
			before.settled,
			after.settled,
		)
	}
	for _, table := range resultBatchImportAtomicTables {
		if after.counts[table] != before.counts[table] {
			t.Fatalf(
				"failed import changed %s row count: before=%d after=%d",
				table,
				before.counts[table],
				after.counts[table],
			)
		}
	}
	if !reflect.DeepEqual(after.local, before.local) {
		t.Fatalf(
			"failed import changed queued local proposal: before=%+v after=%+v",
			before.local,
			after.local,
		)
	}
	if after.admissionRevision != before.admissionRevision ||
		after.view.AdmissionRevision != before.view.AdmissionRevision {
		t.Fatalf(
			"failed import changed admission revision: before=%d after=%d",
			before.admissionRevision,
			after.admissionRevision,
		)
	}
	if err := database.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(after failed import): %v", err)
	}
}

func assertResultBatchImportUnchanged(
	t *testing.T,
	database *Store,
	initial ApplyHeads,
	revision uint64,
) {
	t.Helper()
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.Heads != initial || database.AdmissionRevision() != revision {
		t.Fatalf(
			"rejected import changed heads/revision: heads=%+v revision=%d",
			view.Heads,
			database.AdmissionRevision(),
		)
	}
	assertCounts(t, database, map[string]int64{
		"events":                    0,
		"command_results":           0,
		"event_provenance":          0,
		"raft_command_applications": 0,
		"activity":                  0,
		"audit_events":              0,
		"replication_attestations":  0,
		"replication_cursors":       0,
	})
}
