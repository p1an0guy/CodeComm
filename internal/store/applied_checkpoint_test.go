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
	if _, _, err := state.AppliedCheckpoint(
		nil,
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
