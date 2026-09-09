package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"zombiezen.com/go/sqlite"
)

func TestVerifyCommitmentHistoryReplaysAcceptedAndRejectedResults(
	t *testing.T,
) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, value)
	first, err := value.Apply(
		context.Background(),
		acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1)),
	)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if _, err := value.Apply(
		context.Background(),
		rejectedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID2, 2),
			first.Heads,
		),
	); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}

	if err := value.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(): %v", err)
	}
}

func TestVerifyCommitmentHistoryRejectsMiddleLinkTampering(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, value)
	first, err := value.Apply(
		context.Background(),
		acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1)),
	)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	if _, err := value.Apply(
		context.Background(),
		rejectedApplyRequest(
			t,
			testSignedTaskEvent(t, testEventID2, 2),
			first.Heads,
		),
	); err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	err = value.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE command_results
				    SET proposal_digest = zeroblob(32)
				  WHERE result_index = 1;`,
			)
		},
	)
	if err != nil {
		t.Fatalf("tamper command history: %v", err)
	}

	if err := value.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrCommandResultCorrupt) {
		t.Fatalf(
			"VerifyCommitmentHistory() error = %v, want ErrCommandResultCorrupt",
			err,
		)
	}
}

func TestVerifyCommitmentHistoryRejectsMutationHistoryTampering(t *testing.T) {
	value := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initialHeads := initializeTestStore(t, value)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections = newProjectionFixture(t).initialWrites
	applied, err := value.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	tamperedAccumulator, _, err := chain.AppendAccumulator(
		chain.Digest(initialHeads.ProjectionAccumulator),
		applied.Heads.ResultIndex,
		chain.Digest(applied.Heads.ResultHash),
		nil,
	)
	if err != nil {
		t.Fatalf("AppendAccumulator(empty): %v", err)
	}
	err = value.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return rewriteCommandResultPayloadForTest(
				conn,
				1,
				func(payload *commandResultPayload) {
					payload.mutations = []byte("[]")
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("tamper mutation history: %v", err)
	}
	err = value.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE consensus_state
				    SET projection_accumulator = ?1
				  WHERE singleton = 1;`,
				tamperedAccumulator[:],
			)
		},
	)
	if err != nil {
		t.Fatalf("tamper accumulator head coherently: %v", err)
	}

	if err := value.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrCommandResultCorrupt) {
		t.Fatalf(
			"VerifyCommitmentHistory() error = %v, want ErrCommandResultCorrupt",
			err,
		)
	}
}
