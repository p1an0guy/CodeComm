package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestAppliedCheckpointReturnsExactDurableBinding(t *testing.T) {
	state, request := appliedCheckpointTestState(t)

	lookup, found, err := state.AppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf("AppliedCheckpoint() = (%#v, %t, %v)", lookup, found, err)
	}
	if lookup.AppliedLogIndex != request.LogIndex ||
		lookup.Record.CheckpointEventID != testCheckpointEventID ||
		lookup.Record.Term != request.Term ||
		lookup.Record.CoveredAppliedLogIndex != request.LogIndex-1 ||
		!bytes.Equal(
			lookup.Record.CheckpointJSON,
			request.Checkpoint.CheckpointJSON,
		) ||
		lookup.Record.AuthoritySignature !=
			request.Checkpoint.AuthoritySignature {
		t.Fatalf("AppliedCheckpoint() lookup = %#v", lookup)
	}

	lookup.Record.CheckpointJSON[0] ^= 0xff
	again, found, err := state.AppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if err != nil || !found {
		t.Fatalf("AppliedCheckpoint(second) = (%#v, %t, %v)", again, found, err)
	}
	if !bytes.Equal(
		again.Record.CheckpointJSON,
		request.Checkpoint.CheckpointJSON,
	) {
		t.Fatal("AppliedCheckpoint() returned aliased checkpoint bytes")
	}
}

func TestAppliedCheckpointMissAndInputValidation(t *testing.T) {
	state, _ := appliedCheckpointTestState(t)

	missing := domain.UUIDv7("01890f47-3e72-7000-8000-000000000099")
	if lookup, found, err := state.AppliedCheckpoint(
		context.Background(),
		missing,
	); err != nil || found ||
		lookup.AppliedLogIndex != 0 ||
		lookup.Record.CheckpointEventID != "" ||
		lookup.Record.CheckpointJSON != nil {
		t.Fatalf("AppliedCheckpoint(miss) = (%#v, %t, %v)", lookup, found, err)
	}
	if _, _, err := state.AppliedCheckpoint(
		context.Background(),
		"invalid",
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("AppliedCheckpoint(invalid ID) error = %v", err)
	}
	var nilContext context.Context
	if _, _, err := state.AppliedCheckpoint(
		nilContext,
		testCheckpointEventID,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("AppliedCheckpoint(nil context) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := state.AppliedCheckpoint(
		ctx,
		testCheckpointEventID,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("AppliedCheckpoint(canceled) error = %v", err)
	}
}

func TestAppliedCheckpointRejectsBrokenRaftBinding(t *testing.T) {
	state, _ := appliedCheckpointTestState(t)
	err := state.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`DELETE FROM raft_command_applications
			  WHERE recovery_generation = 0 AND log_index = 2;`,
		)
	})
	if err != nil {
		t.Fatalf("delete checkpoint binding: %v", err)
	}

	lookup, found, err := state.AppliedCheckpoint(
		context.Background(),
		testCheckpointEventID,
	)
	if !errors.Is(err, ErrAppliedCheckpointIntegrity) ||
		found ||
		lookup.AppliedLogIndex != 0 ||
		lookup.Record.CheckpointEventID != "" {
		t.Fatalf(
			"AppliedCheckpoint(broken binding) = (%#v, %t, %v)",
			lookup,
			found,
			err,
		)
	}
}

func TestCommitmentScrubRejectsNonterminalCheckpointRowCorruption(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Store)
	}{
		{
			name: "deleted",
			mutate: func(t *testing.T, state *Store) {
				t.Helper()
				executeCheckpointStartupMutation(
					t,
					state,
					`DELETE FROM chain_checkpoints
					  WHERE checkpoint_event_id = ?1;`,
					string(testCheckpointEventID),
				)
			},
		},
		{
			name: "changed",
			mutate: func(t *testing.T, state *Store) {
				t.Helper()
				executeCheckpointStartupMutation(
					t,
					state,
					`UPDATE chain_checkpoints
					    SET authority_signature = zeroblob(64)
					  WHERE checkpoint_event_id = ?1;`,
					string(testCheckpointEventID),
				)
			},
		},
		{
			name: "fabricated",
			mutate: func(t *testing.T, state *Store) {
				t.Helper()
				executeCheckpointStartupMutation(
					t,
					state,
					`INSERT INTO chain_checkpoints(
					    checkpoint_event_id, session_id, workspace_id,
					    recovery_generation, authority_voter_set_version,
					    signer_device_id, term, covered_applied_log_index,
					    covered_chain_index, covered_chain_hash,
					    covered_result_index, covered_result_hash,
					    projection_accumulator, digest_version,
					    projection_schema_version, checkpoint_json,
					    authority_signature
					)
					SELECT ?1, session_id, workspace_id,
					       recovery_generation, authority_voter_set_version,
					       signer_device_id, term, covered_applied_log_index,
					       0, covered_chain_hash, 0, covered_result_hash,
					       projection_accumulator, digest_version,
					       projection_schema_version, checkpoint_json,
					       authority_signature
					  FROM chain_checkpoints
					 WHERE checkpoint_event_id = ?2;`,
					string(testEventID),
					string(testCheckpointEventID),
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			state, _ := appliedCheckpointTestState(t)
			view, err := state.View(context.Background())
			if err != nil {
				t.Fatalf("View(before second checkpoint): %v", err)
			}
			secondID := domain.UUIDv7(
				"01890f47-3e72-7000-8000-000000000092",
			)
			second := nextCheckpointApplyRequest(
				t,
				view.Heads,
				secondID,
				2,
				3,
				domain.Timestamp("2026-08-10T12:00:02Z"),
			)
			if _, err := state.Apply(
				context.Background(),
				second,
			); err != nil {
				t.Fatalf("Apply(second checkpoint): %v", err)
			}

			test.mutate(t, state)
			commitmentAssertReopenScrubFails(
				t,
				state,
				state.Path(),
				ErrAppliedCheckpointIntegrity,
			)
		})
	}
}

func executeCheckpointStartupMutation(
	t *testing.T,
	state *Store,
	statement string,
	args ...any,
) {
	t.Helper()
	if err := state.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(conn, statement, args...)
		},
	); err != nil {
		t.Fatalf("checkpoint startup mutation: %v", err)
	}
}

func appliedCheckpointTestState(
	t *testing.T,
) (*Store, ApplyRequest) {
	t.Helper()
	state := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, state)
	first := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	firstResult, err := state.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	request := nextCheckpointApplyRequest(
		t,
		firstResult.Heads,
		testCheckpointEventID,
		1,
		2,
		domain.Timestamp("2026-08-10T12:00:01Z"),
	)
	if _, err := state.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(checkpoint): %v", err)
	}
	return state, request
}
