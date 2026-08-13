package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"zombiezen.com/go/sqlite"
)

func TestRaftCommandApplicationsBindEveryAppliedPosition(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, value)
	signed := testSignedTaskEvent(t, testEventID, 1)
	first := acceptedApplyRequest(t, signed)
	if _, err := value.Apply(context.Background(), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}

	duplicate := first
	duplicate.Term = 2
	duplicate.LogIndex = 2
	if _, err := value.Apply(context.Background(), duplicate); err != nil {
		t.Fatalf("Apply(duplicate): %v", err)
	}
	assertCounts(
		t,
		value,
		map[string]int64{"raft_command_applications": 2},
	)
	for _, position := range []struct {
		term  uint64
		index uint64
	}{
		{term: 1, index: 1},
		{term: 2, index: 2},
	} {
		if err := value.VerifyRaftCommand(
			context.Background(),
			position.term,
			position.index,
			signed,
		); err != nil {
			t.Fatalf(
				"VerifyRaftCommand(term=%d, index=%d): %v",
				position.term,
				position.index,
				err,
			)
		}
	}

	tests := []struct {
		name   string
		term   uint64
		index  uint64
		signed bool
	}{
		{name: "wrong term", term: 3, index: 2, signed: true},
		{name: "missing index", term: 2, index: 3, signed: true},
		{name: "wrong event", term: 2, index: 2},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			proposal := testSignedTaskEvent(t, testEventID2, 2)
			if test.signed {
				proposal = signed
			}
			if err := value.VerifyRaftCommand(
				context.Background(),
				test.term,
				test.index,
				proposal,
			); !errors.Is(err, ErrRaftCommandBinding) {
				t.Fatalf(
					"VerifyRaftCommand() error = %v, want ErrRaftCommandBinding",
					err,
				)
			}
		})
	}
}

func TestOpenRejectsTamperedRaftCommandLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	value := openTestStore(t, path, nil)
	initializeTestStore(t, value)
	signed := testSignedTaskEvent(t, testEventID, 1)
	if _, err := value.Apply(
		context.Background(),
		acceptedApplyRequest(t, signed),
	); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	err := value.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE raft_command_applications
				    SET term = term + 1
				  WHERE log_index = 1;`,
			)
		},
	)
	if err != nil {
		t.Fatalf("tamper command ledger: %v", err)
	}
	if err := value.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	if _, err := Open(context.Background(), Options{
		Path:    path,
		RaftLog: fixedRaftLog{lastIndex: 1},
	}); !errors.Is(err, ErrRaftCommandBinding) {
		t.Fatalf(
			"Open(tampered ledger) error = %v, want ErrRaftCommandBinding",
			err,
		)
	}
}

func TestOpenRejectsReorderedFirstSeenRaftCommandBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	value := openTestStore(t, path, nil)
	initializeTestStore(t, value)
	signed := testSignedTaskEvent(t, testEventID, 1)
	first := acceptedApplyRequest(t, signed)
	firstResult, err := value.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	duplicate := first
	duplicate.LogIndex = 2
	if _, err := value.Apply(context.Background(), duplicate); err != nil {
		t.Fatalf("Apply(duplicate): %v", err)
	}
	last := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		firstResult.Heads,
	)
	last.LogIndex = 3
	if _, err := value.Apply(context.Background(), last); err != nil {
		t.Fatalf("Apply(last): %v", err)
	}
	err = value.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE raft_command_applications
				    SET event_id = ?1,
				        proposal_digest = (
				            SELECT proposal_digest
				              FROM command_results
				             WHERE event_id = ?1
				        )
				  WHERE log_index = 1;`,
				string(testEventID2),
			)
		},
	)
	if err != nil {
		t.Fatalf("reorder first-seen command binding: %v", err)
	}
	if err := value.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	if _, err := Open(context.Background(), Options{
		Path:    path,
		RaftLog: fixedRaftLog{lastIndex: 3},
	}); !errors.Is(err, ErrRaftCommandBinding) {
		t.Fatalf(
			"Open(tampered ledger) error = %v, want ErrRaftCommandBinding",
			err,
		)
	}
}
