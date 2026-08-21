package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"zombiezen.com/go/sqlite"
)

const logicalSnapshotLaterEventID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000014",
)

func TestExportLogicalSnapshotRecordsProducesValidSemanticSequence(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotExportFixture(t)
	cut, records, err := collectLogicalSnapshotRecords(
		context.Background(),
		fixture.store,
		fixture.options,
	)
	if err != nil {
		t.Fatalf("ExportLogicalSnapshotRecords(): %v", err)
	}
	assertLogicalSnapshotCut(t, fixture, cut, records)
	validateLogicalSnapshotSequence(
		t,
		cut,
		records,
		fixture.privateKey,
	)

	counts := make(map[logicalsnapshot.RecordType]int)
	for _, record := range records {
		counts[record.Type]++
	}
	if counts[logicalsnapshot.RecordGenesis] != 1 ||
		counts[logicalsnapshot.RecordResult] != 3 ||
		counts[logicalsnapshot.RecordMutation] != 3 ||
		counts[logicalsnapshot.RecordEvent] != 2 ||
		counts[logicalsnapshot.RecordProjection] < 3 ||
		counts[logicalsnapshot.RecordCheckpoint] != 1 {
		t.Fatalf("record type counts = %#v", counts)
	}

	pristine := bytes.Clone(records[0].Payload)
	records[0].Payload[0] ^= 0xff
	_, again, err := collectLogicalSnapshotRecords(
		context.Background(),
		fixture.store,
		fixture.options,
	)
	if err != nil || !bytes.Equal(again[0].Payload, pristine) {
		t.Fatalf(
			"second export after caller mutation = %v, first payload %q",
			err,
			again[0].Payload,
		)
	}
}

func TestExportLogicalSnapshotRecordsSupportsSettledEvidence(
	t *testing.T,
) {
	t.Parallel()

	imported := importedSettledCheckpointFixture(t)
	privateKey := resultBatchPrivateKey(1)
	t.Cleanup(func() {
		clear(privateKey)
	})
	options := LogicalSnapshotExportOptions{
		CheckpointEventID: testCheckpointEventID,
		SignerDeviceID:    imported.source.authorityDeviceID,
	}
	cut, records, err := collectLogicalSnapshotRecords(
		context.Background(),
		imported.target,
		options,
	)
	if err != nil {
		t.Fatalf(
			"settled ExportLogicalSnapshotRecords(): %v",
			err,
		)
	}
	if cut.ResultIndex !=
		imported.request.Batch.Unsigned().Input().ToResultIndex ||
		cut.SignerDeviceID != options.SignerDeviceID {
		t.Fatalf("settled cut = %+v", cut)
	}
	validateLogicalSnapshotSequence(t, cut, records, privateKey)
}

func TestExportLogicalSnapshotRecordsRejectsUnauthorizedOrStaleCut(
	t *testing.T,
) {
	t.Parallel()

	t.Run("root signer outside authority", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotExportFixture(t)
		otherKey := resultBatchPrivateKey(29)
		defer clear(otherKey)
		otherID, err := device.DeriveID(
			otherKey.Public().(ed25519.PublicKey),
		)
		if err != nil {
			t.Fatal(err)
		}
		options := fixture.options
		options.SignerDeviceID = otherID
		sinkCalls := 0
		_, err = fixture.store.ExportLogicalSnapshotRecords(
			context.Background(),
			options,
			func(context.Context, logicalsnapshot.Record) error {
				sinkCalls++
				return nil
			},
		)
		if !errors.Is(
			err,
			ErrLogicalSnapshotSignerUnauthorized,
		) {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() error = %v, want unauthorized signer",
				err,
			)
		}
		if sinkCalls != 0 {
			t.Fatalf("unauthorized export emitted %d records", sinkCalls)
		}
	})

	t.Run("checkpoint is no longer latest result", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotExportFixture(t)
		applyLogicalSnapshotLaterResult(
			t,
			fixture.store,
			fixture.checkpoint.Heads,
			4,
		)
		sinkCalls := 0
		_, err := fixture.store.ExportLogicalSnapshotRecords(
			context.Background(),
			fixture.options,
			func(context.Context, logicalsnapshot.Record) error {
				sinkCalls++
				return nil
			},
		)
		if !errors.Is(err, ErrLogicalSnapshotNotCovered) {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() error = %v, want stale cut",
				err,
			)
		}
		if sinkCalls != 0 {
			t.Fatalf("stale checkpoint emitted %d records", sinkCalls)
		}
	})
}

func TestExportLogicalSnapshotRecordsRejectsCheckpointCorruption(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotExportFixture(t)
	executeSettledCheckpointTestSQL(
		t,
		fixture.store,
		`UPDATE chain_checkpoints
		    SET authority_signature = zeroblob(64)
		  WHERE checkpoint_event_id = ?1;`,
		string(testCheckpointEventID),
	)
	sinkCalls := 0
	_, err := fixture.store.ExportLogicalSnapshotRecords(
		context.Background(),
		fixture.options,
		func(context.Context, logicalsnapshot.Record) error {
			sinkCalls++
			return nil
		},
	)
	if !errors.Is(err, ErrLogicalSnapshotIntegrity) ||
		!errors.Is(err, ErrAppliedCheckpointIntegrity) {
		t.Fatalf(
			"ExportLogicalSnapshotRecords() error = %v, want checkpoint integrity",
			err,
		)
	}
	if sinkCalls != 0 {
		t.Fatalf("corrupt checkpoint emitted %d records", sinkCalls)
	}
}

func TestLogicalSnapshotCheckpointCannotChangeSignerAuthority(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotExportFixture(t)
	view, err := fixture.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	var deviceRow chain.LogicalRow
	for _, row := range view.ProjectionRows {
		if row.Table == "devices" {
			deviceRow = row
			break
		}
	}
	if deviceRow.Table == "" {
		t.Fatal("fixture has no device projection")
	}
	encoded, err := chain.EncodeMutations([]chain.Mutation{{
		Table:      deviceRow.Table,
		PrimaryKey: deviceRow.PrimaryKey,
		After:      deviceRow.Row,
	}})
	if err != nil {
		t.Fatalf("EncodeMutations(): %v", err)
	}
	executeSettledCheckpointTestSQL(
		t,
		fixture.store,
		`UPDATE command_results
		    SET projection_mutations_json = ?1
		  WHERE event_id = ?2;`,
		string(encoded),
		string(testCheckpointEventID),
	)
	err = fixture.store.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return verifyLogicalSnapshotCheckpointKeepsAuthority(
				conn,
				testCheckpointEventID,
			)
		},
	)
	if !errors.Is(err, ErrLogicalSnapshotIntegrity) {
		t.Fatalf(
			"verifyLogicalSnapshotCheckpointKeepsAuthority() = %v, want integrity failure",
			err,
		)
	}
}

func TestExportLogicalSnapshotRecordsCancellationAndSinkFailure(
	t *testing.T,
) {
	t.Parallel()

	t.Run("cancellation after record", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotExportFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		sinkCalls := 0
		_, err := fixture.store.ExportLogicalSnapshotRecords(
			ctx,
			fixture.options,
			func(context.Context, logicalsnapshot.Record) error {
				sinkCalls++
				cancel()
				return nil
			},
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() error = %v, want cancellation",
				err,
			)
		}
		if sinkCalls != 1 {
			t.Fatalf("canceled export emitted %d records, want 1", sinkCalls)
		}
	})

	t.Run("sink error", func(t *testing.T) {
		t.Parallel()
		fixture := newLogicalSnapshotExportFixture(t)
		injected := errors.New("injected snapshot sink failure")
		sinkCalls := 0
		_, err := fixture.store.ExportLogicalSnapshotRecords(
			context.Background(),
			fixture.options,
			func(context.Context, logicalsnapshot.Record) error {
				sinkCalls++
				return injected
			},
		)
		if !errors.Is(err, injected) {
			t.Fatalf(
				"ExportLogicalSnapshotRecords() error = %v, want injected error",
				err,
			)
		}
		if errors.Is(err, ErrLogicalSnapshotIntegrity) {
			t.Fatalf(
				"sink failure was mislabeled as snapshot integrity: %v",
				err,
			)
		}
		if sinkCalls != 1 {
			t.Fatalf("failed export emitted %d records, want 1", sinkCalls)
		}
	})
}

func TestExportLogicalSnapshotRecordsKeepsStableCutDuringApply(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotExportFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	type exportResult struct {
		cut     LogicalSnapshotCut
		records []logicalsnapshot.Record
		err     error
	}
	resultChannel := make(chan exportResult, 1)
	go func() {
		var (
			once    sync.Once
			records []logicalsnapshot.Record
		)
		cut, err := fixture.store.ExportLogicalSnapshotRecords(
			context.Background(),
			fixture.options,
			func(_ context.Context, record logicalsnapshot.Record) error {
				once.Do(func() {
					close(entered)
					<-release
				})
				records = append(records, cloneLogicalSnapshotRecord(record))
				return nil
			},
		)
		resultChannel <- exportResult{
			cut:     cut,
			records: records,
			err:     err,
		}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("snapshot export did not reach its first record")
	}

	applyDone := make(chan error, 1)
	laterRequest := logicalSnapshotLaterApplyRequest(
		t,
		fixture.checkpoint.Heads,
		4,
	)
	go func() {
		_, err := fixture.store.Apply(context.Background(), laterRequest)
		applyDone <- err
	}()
	select {
	case err := <-applyDone:
		if err != nil {
			close(release)
			t.Fatalf("concurrent Apply(): %v", err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("concurrent Apply blocked behind snapshot export")
	}
	close(release)

	var exported exportResult
	select {
	case exported = <-resultChannel:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot export did not finish after release")
	}
	if exported.err != nil {
		t.Fatalf("ExportLogicalSnapshotRecords(): %v", exported.err)
	}
	assertLogicalSnapshotCut(
		t,
		fixture,
		exported.cut,
		exported.records,
	)
	validateLogicalSnapshotSequence(
		t,
		exported.cut,
		exported.records,
		fixture.privateKey,
	)
	view, err := fixture.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(after concurrent apply): %v", err)
	}
	if view.Heads.ResultIndex != fixture.checkpoint.Heads.ResultIndex+1 {
		t.Fatalf(
			"current result index = %d, want %d",
			view.Heads.ResultIndex,
			fixture.checkpoint.Heads.ResultIndex+1,
		)
	}
}

type logicalSnapshotExportFixture struct {
	store      *Store
	options    LogicalSnapshotExportOptions
	privateKey ed25519.PrivateKey
	checkpoint ApplyResult
}

func newLogicalSnapshotExportFixture(
	t *testing.T,
) logicalSnapshotExportFixture {
	t.Helper()
	base := newResultRangeFixture(t)
	request := nextCheckpointApplyRequest(
		t,
		base.second.Heads,
		testCheckpointEventID,
		1,
		3,
		domain.Timestamp("2026-08-10T12:00:02Z"),
	)
	checkpoint, err := base.store.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply(checkpoint): %v", err)
	}
	privateKey := resultBatchPrivateKey(1)
	t.Cleanup(func() {
		clear(privateKey)
	})
	return logicalSnapshotExportFixture{
		store: base.store,
		options: LogicalSnapshotExportOptions{
			CheckpointEventID: testCheckpointEventID,
			SignerDeviceID:    base.authorityDeviceID,
		},
		privateKey: privateKey,
		checkpoint: checkpoint,
	}
}

func collectLogicalSnapshotRecords(
	ctx context.Context,
	database *Store,
	options LogicalSnapshotExportOptions,
) (LogicalSnapshotCut, []logicalsnapshot.Record, error) {
	var records []logicalsnapshot.Record
	cut, err := database.ExportLogicalSnapshotRecords(
		ctx,
		options,
		func(_ context.Context, record logicalsnapshot.Record) error {
			records = append(records, cloneLogicalSnapshotRecord(record))
			return nil
		},
	)
	return cut, records, err
}

func cloneLogicalSnapshotRecord(
	record logicalsnapshot.Record,
) logicalsnapshot.Record {
	return logicalsnapshot.Record{
		Type:    record.Type,
		Payload: bytes.Clone(record.Payload),
	}
}

func assertLogicalSnapshotCut(
	t *testing.T,
	fixture logicalSnapshotExportFixture,
	cut LogicalSnapshotCut,
	records []logicalsnapshot.Record,
) {
	t.Helper()
	if cut.SessionID != domain.UUIDv7(testSessionID) ||
		cut.WorkspaceID != testWorkspaceID ||
		cut.RecoveryGeneration != 0 ||
		cut.CheckpointEventID != testCheckpointEventID ||
		cut.ChainIndex != fixture.checkpoint.Heads.ChainIndex ||
		cut.ChainHash != fixture.checkpoint.Heads.ChainHash ||
		cut.ResultIndex != fixture.checkpoint.Heads.ResultIndex ||
		cut.ResultHash != fixture.checkpoint.Heads.ResultHash ||
		cut.ProjectionAccumulator !=
			fixture.checkpoint.Heads.ProjectionAccumulator ||
		cut.AuthorityVersion != 1 ||
		cut.SignerDeviceID != fixture.options.SignerDeviceID ||
		cut.DigestVersion != 1 ||
		cut.ProjectionSchemaVersion != 1 ||
		cut.RecordCount != uint64(len(records)) {
		t.Fatalf("snapshot cut = %+v for %d records", cut, len(records))
	}
	digest, err := fixture.store.ProjectionStateDigest(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}
	if cut.ProjectionStateDigest != digest {
		t.Fatalf(
			"snapshot state digest = %x, want %x",
			cut.ProjectionStateDigest,
			digest,
		)
	}
}

func validateLogicalSnapshotSequence(
	t *testing.T,
	cut LogicalSnapshotCut,
	records []logicalsnapshot.Record,
	privateKey ed25519.PrivateKey,
) {
	t.Helper()
	unsigned, err := logicalsnapshot.NewUnsignedRoot(
		logicalsnapshot.RootInput{
			ArtifactID:              "store-export-test",
			SessionID:               cut.SessionID,
			WorkspaceID:             cut.WorkspaceID,
			RecoveryGeneration:      cut.RecoveryGeneration,
			CheckpointEventID:       cut.CheckpointEventID,
			ChainIndex:              cut.ChainIndex,
			ChainHash:               chain.Digest(cut.ChainHash),
			ResultIndex:             cut.ResultIndex,
			ResultHash:              chain.Digest(cut.ResultHash),
			ProjectionAccumulator:   chain.Digest(cut.ProjectionAccumulator),
			ProjectionStateDigest:   chain.Digest(cut.ProjectionStateDigest),
			AuthorityVersion:        cut.AuthorityVersion,
			SignerDeviceID:          cut.SignerDeviceID,
			DigestVersion:           cut.DigestVersion,
			ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
			ContentEncoding:         logicalsnapshot.EncodingIdentity,
			ExpandedBytes:           1,
			CompressedBytes:         1,
			RecordCount:             cut.RecordCount,
			DescriptorPageCount:     1,
			ChunkCount:              1,
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	root, err := logicalsnapshot.SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	scratch, err := os.CreateTemp(t.TempDir(), "snapshot-sequence-*")
	if err != nil {
		t.Fatalf("CreateTemp(): %v", err)
	}
	t.Cleanup(func() {
		_ = scratch.Close()
	})
	validator, err := logicalsnapshot.NewSequenceValidator(root, scratch)
	if err != nil {
		t.Fatalf("NewSequenceValidator(): %v", err)
	}
	for index, record := range records {
		if err := validator.Consume(record); err != nil {
			t.Fatalf("Consume(record %d, %s): %v", index, record.Type, err)
		}
	}
	if err := validator.Finish(); err != nil {
		t.Fatalf("Finish(): %v", err)
	}
}

func applyLogicalSnapshotLaterResult(
	t *testing.T,
	database *Store,
	previous ApplyHeads,
	logIndex uint64,
) {
	t.Helper()
	request := logicalSnapshotLaterApplyRequest(t, previous, logIndex)
	if _, err := database.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(later result): %v", err)
	}
}

func logicalSnapshotLaterApplyRequest(
	t *testing.T,
	previous ApplyHeads,
	logIndex uint64,
) ApplyRequest {
	t.Helper()
	request := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, logicalSnapshotLaterEventID, 2),
		previous,
	)
	request.LogIndex = logIndex
	request.AppliedAt = domain.Timestamp("2026-08-10T12:00:03Z")
	return request
}
