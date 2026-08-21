package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestSettledAppliedCheckpointReturnsExactImportedBinding(t *testing.T) {
	fixture := importedSettledCheckpointFixture(t)
	want := *fixture.request.Commands[2].Local.Checkpoint

	got, found, err := fixture.target.SettledAppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf(
			"SettledAppliedCheckpoint() = (%#v, %t, %v)",
			got,
			found,
			err,
		)
	}
	if got.CheckpointEventID != want.CheckpointEventID ||
		got.SessionID != want.SessionID ||
		got.WorkspaceID != want.WorkspaceID ||
		got.RecoveryGeneration != want.RecoveryGeneration ||
		got.CoveredAppliedLogIndex != want.CoveredAppliedLogIndex ||
		got.CoveredChainIndex != want.CoveredChainIndex ||
		got.CoveredResultIndex != want.CoveredResultIndex ||
		got.AuthoritySignature != want.AuthoritySignature ||
		!bytes.Equal(got.CheckpointJSON, want.CheckpointJSON) {
		t.Fatalf(
			"SettledAppliedCheckpoint() = %#v, want %#v",
			got,
			want,
		)
	}
	assertCounts(t, fixture.target, map[string]int64{
		"raft_command_applications": 0,
	})

	got.CheckpointJSON[0] ^= 0xff
	again, found, err := fixture.target.SettledAppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf(
			"SettledAppliedCheckpoint(second) = (%#v, %t, %v)",
			again,
			found,
			err,
		)
	}
	if !bytes.Equal(again.CheckpointJSON, want.CheckpointJSON) {
		t.Fatal("SettledAppliedCheckpoint() returned aliased checkpoint bytes")
	}
}

func TestSettledAppliedCheckpointMissAndInputValidation(t *testing.T) {
	fixture := importedSettledCheckpointFixture(t)
	missing := domain.UUIDv7("01890f47-3e72-7000-8000-000000000099")

	if record, found, err := fixture.target.SettledAppliedCheckpoint(
		context.Background(),
		missing,
	); err != nil || found ||
		record.CheckpointEventID != "" ||
		record.CheckpointJSON != nil {
		t.Fatalf(
			"SettledAppliedCheckpoint(miss) = (%#v, %t, %v)",
			record,
			found,
			err,
		)
	}
	if _, _, err := fixture.target.SettledAppliedCheckpoint(
		context.Background(),
		"invalid",
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("SettledAppliedCheckpoint(invalid ID) error = %v", err)
	}
	var nilContext context.Context
	if _, _, err := fixture.target.SettledAppliedCheckpoint(
		nilContext,
		testCheckpointEventID,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("SettledAppliedCheckpoint(nil context) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := fixture.target.SettledAppliedCheckpoint(
		ctx,
		testCheckpointEventID,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("SettledAppliedCheckpoint(canceled) error = %v", err)
	}
}

func TestSettledAppliedCheckpointRequiresSettledEvidenceMode(t *testing.T) {
	database, _ := appliedCheckpointTestState(t)

	record, found, err := database.SettledAppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if !errors.Is(err, ErrAppliedCheckpointIntegrity) ||
		!errors.Is(err, ErrReplicaEvidenceMode) ||
		found ||
		record.CheckpointEventID != "" {
		t.Fatalf(
			"SettledAppliedCheckpoint(Raft mode) = (%#v, %t, %v)",
			record,
			found,
			err,
		)
	}
}

func TestSettledAppliedCheckpointRejectsInconsistentProof(t *testing.T) {
	t.Run("malformed checkpoint", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE chain_checkpoints
			    SET checkpoint_json = '{}'
			  WHERE checkpoint_event_id = ?1;`,
			string(testCheckpointEventID),
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
		)
	})

	t.Run("result binding", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE command_results
			    SET kind = 'task.created'
			  WHERE event_id = ?1;`,
			string(testCheckpointEventID),
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
		)
	})

	t.Run("payload signature binding", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE chain_checkpoints
			    SET authority_signature = zeroblob(64)
			  WHERE checkpoint_event_id = ?1;`,
			string(testCheckpointEventID),
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
		)
	})

	t.Run("active state coverage", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		view, err := fixture.target.View(context.Background())
		if err != nil {
			t.Fatalf("View(): %v", err)
		}
		record := *fixture.request.Commands[2].Local.Checkpoint
		record.CoveredChainIndex = view.Heads.ChainIndex
		record.CoveredChainHash = view.Heads.ChainHash
		record.CoveredResultIndex = view.Heads.ResultIndex
		record.CoveredResultHash = view.Heads.ResultHash
		record.ProjectionAccumulator = view.Heads.ProjectionAccumulator
		record.CheckpointJSON, err = record.canonicalJSON(false)
		if err != nil {
			t.Fatalf("encode uncovered checkpoint: %v", err)
		}
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE chain_checkpoints
			    SET covered_chain_index = ?1,
			        covered_chain_hash = ?2,
			        covered_result_index = ?3,
			        covered_result_hash = ?4,
			        projection_accumulator = ?5,
			        checkpoint_json = ?6
			  WHERE checkpoint_event_id = ?7;`,
			record.CoveredChainIndex,
			record.CoveredChainHash[:],
			record.CoveredResultIndex,
			record.CoveredResultHash[:],
			record.ProjectionAccumulator[:],
			string(record.CheckpointJSON),
			string(testCheckpointEventID),
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
		)
	})

	t.Run("settled evidence", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE settled_nonvoter_state
			    SET baseline_result_hash = zeroblob(32)
			  WHERE singleton = 1;`,
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
			ErrReplicaEvidenceMode,
		)
	})

	t.Run("commitment history", func(t *testing.T) {
		fixture := importedSettledCheckpointFixture(t)
		executeSettledCheckpointTestSQL(
			t,
			fixture.target,
			`UPDATE command_results
			    SET result_hash = zeroblob(32)
			  WHERE event_id = ?1;`,
			string(testCheckpointEventID),
		)
		assertSettledCheckpointIntegrity(
			t,
			fixture.target,
			testCheckpointEventID,
			ErrCommandResultCorrupt,
		)
	})
}

func importedSettledCheckpointFixture(
	t *testing.T,
) resultBatchImportFixture {
	t.Helper()
	fixture := newResultBatchAtomicityFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	return fixture
}

func assertSettledCheckpointIntegrity(
	t *testing.T,
	database *Store,
	eventID domain.UUIDv7,
	causes ...error,
) {
	t.Helper()
	record, found, err := database.SettledAppliedCheckpoint(
		context.Background(),
		eventID,
	)
	if !errors.Is(err, ErrAppliedCheckpointIntegrity) ||
		found ||
		record.CheckpointEventID != "" ||
		record.CheckpointJSON != nil {
		t.Fatalf(
			"SettledAppliedCheckpoint(inconsistent) = (%#v, %t, %v)",
			record,
			found,
			err,
		)
	}
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Fatalf(
				"SettledAppliedCheckpoint() error = %v, want cause %v",
				err,
				cause,
			)
		}
	}
}

func executeSettledCheckpointTestSQL(
	t *testing.T,
	database *Store,
	statement string,
	arguments ...any,
) {
	t.Helper()
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(conn, statement, arguments...)
		},
	)
	if err != nil {
		t.Fatalf("mutate settled checkpoint fixture: %v", err)
	}
}
