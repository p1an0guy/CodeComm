package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"zombiezen.com/go/sqlite"
)

func TestSettledNonvoterEvidenceReopensAndRejectsBaselineTamper(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	want := initializeTestStore(t, database)
	if mode, err := database.ReplicaEvidenceMode(
		context.Background(),
	); err != nil || mode != ReplicaEvidenceRaft {
		t.Fatalf(
			"ReplicaEvidenceMode(before transition) = (%q, %v), want %q",
			mode,
			err,
			ReplicaEvidenceRaft,
		)
	}

	got, err := database.EnterSettledNonvoter(
		context.Background(),
		"2026-08-19T20:00:00Z",
	)
	if err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if got != want {
		t.Fatalf("settled baseline = %#v, want %#v", got, want)
	}
	if mode, err := database.ReplicaEvidenceMode(
		context.Background(),
	); err != nil || mode != ReplicaEvidenceSettledNonvoter {
		t.Fatalf(
			"ReplicaEvidenceMode(after transition) = (%q, %v), want %q",
			mode,
			err,
			ReplicaEvidenceSettledNonvoter,
		)
	}
	again, err := database.EnterSettledNonvoter(
		context.Background(),
		"2026-08-19T20:01:00Z",
	)
	if err != nil || again != want {
		t.Fatalf(
			"EnterSettledNonvoter(retry) = (%#v, %v), want %#v",
			again,
			err,
			want,
		)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(settled): %v", err)
	}
	if err := reopened.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE settled_nonvoter_state
				    SET baseline_result_hash = zeroblob(32)
				  WHERE singleton = 1;`,
			)
		},
	); err != nil {
		t.Fatalf("tamper settled baseline: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close(reopened): %v", err)
	}
	if _, err := Open(
		context.Background(),
		Options{Path: path},
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"Open(tampered settled baseline) error = %v, want evidence error",
			err,
		)
	}
}

func TestRaftEvidenceRejectsUnboundResultsAtNullWatermark(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	initializeTestStore(t, database)
	request := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	if _, err := database.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			if err := execute(
				conn,
				"DELETE FROM raft_command_applications;",
			); err != nil {
				return err
			}
			return execute(
				conn,
				`UPDATE consensus_state
				    SET current_term = NULL,
				        last_raft_applied_log_index = NULL
				  WHERE singleton = 1;`,
			)
		},
	); err != nil {
		t.Fatalf("remove Raft evidence: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := Open(
		context.Background(),
		Options{Path: path},
	); !errors.Is(err, ErrRaftCommandBinding) {
		t.Fatalf(
			"Open(unbound result) error = %v, want Raft binding error",
			err,
		)
	}
}

func TestSettledNonvoterReopenReverifiesRaftBaselineBindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	database := openTestStore(t, path, nil)
	initializeTestStore(t, database)
	request := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	if _, err := database.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if _, err := database.EnterSettledNonvoter(
		context.Background(),
		"2026-08-19T20:00:00Z",
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(conn, "DELETE FROM raft_command_applications;")
		},
	); err != nil {
		t.Fatalf("remove settled Raft baseline binding: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := Open(
		context.Background(),
		Options{Path: path},
	); !errors.Is(err, ErrRaftCommandBinding) {
		t.Fatalf(
			"Open(unbound settled baseline) error = %v, want Raft binding error",
			err,
		)
	}
}
