package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestLookupCommandResultReturnsExactImmutableResultAndCurrentHeads(
	t *testing.T,
) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)

	accepted := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	acceptedResult, err := store.Apply(context.Background(), accepted)
	if err != nil {
		t.Fatalf("Apply(accepted): %v", err)
	}
	rejected := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		acceptedResult.Heads,
	)
	if _, err := store.Apply(context.Background(), rejected); err != nil {
		t.Fatalf("Apply(rejected): %v", err)
	}
	currentHeads := headsFromConsensus(commitmentConsensus(t, store))

	got, found, err := store.LookupCommandResult(
		context.Background(),
		testEventID,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(accepted): %v", err)
	}
	if !found {
		t.Fatal("LookupCommandResult(accepted) found = false")
	}
	if got.EventID != testEventID ||
		got.SessionID != domain.UUIDv7(testSessionID) ||
		got.RecoveryGeneration != 0 {
		t.Fatalf(
			"LookupCommandResult(accepted) identity = (%q, %q, %d)",
			got.EventID,
			got.SessionID,
			got.RecoveryGeneration,
		)
	}
	if !bytes.Equal(
		got.CanonicalProposal,
		accepted.Proposal.CanonicalBytes(),
	) {
		t.Fatal("LookupCommandResult(accepted) changed canonical proposal")
	}
	if got.ProposalDigest != proposalDigest(accepted.Proposal) {
		t.Fatal("LookupCommandResult(accepted) proposal digest mismatch")
	}
	if got.Outcome.Status != accepted.Outcome.Status ||
		got.Outcome.Code != accepted.Outcome.Code ||
		!bytes.Equal(got.Outcome.JSON, accepted.Outcome.JSON) {
		t.Fatalf(
			"LookupCommandResult(accepted) outcome = %+v, want %+v",
			got.Outcome,
			accepted.Outcome,
		)
	}
	if got.Tuple.ResultIndex != acceptedResult.Heads.ResultIndex ||
		got.Tuple.PreviousResultHash !=
			acceptedResult.Heads.PreviousResultHash ||
		got.Tuple.ResultHash != acceptedResult.Heads.ResultHash ||
		got.Tuple.ChainIndex == nil ||
		*got.Tuple.ChainIndex != acceptedResult.Heads.ChainIndex ||
		got.Tuple.ChainHash == nil ||
		*got.Tuple.ChainHash != acceptedResult.Heads.ChainHash {
		t.Fatalf(
			"LookupCommandResult(accepted) tuple = %+v, want heads %+v",
			got.Tuple,
			acceptedResult.Heads,
		)
	}
	if got.CurrentHeads != currentHeads {
		t.Fatalf(
			"LookupCommandResult(accepted) current heads = %+v, want %+v",
			got.CurrentHeads,
			currentHeads,
		)
	}

	pristineProposal := bytes.Clone(got.CanonicalProposal)
	pristineOutcome := bytes.Clone(got.Outcome.JSON)
	got.CanonicalProposal[0] ^= 0xff
	got.Outcome.JSON[0] ^= 0xff
	*got.Tuple.ChainIndex = 99
	got.Tuple.ChainHash[0] ^= 0xff

	again, found, err := store.LookupCommandResult(
		context.Background(),
		testEventID,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(after caller mutation): %v", err)
	}
	if !found ||
		!bytes.Equal(again.CanonicalProposal, pristineProposal) ||
		!bytes.Equal(again.Outcome.JSON, pristineOutcome) ||
		again.Tuple.ChainIndex == nil ||
		*again.Tuple.ChainIndex != acceptedResult.Heads.ChainIndex ||
		again.Tuple.ChainHash == nil ||
		*again.Tuple.ChainHash != acceptedResult.Heads.ChainHash {
		t.Fatal("LookupCommandResult aliases caller-visible bytes or pointers")
	}

	rejectedLookup, found, err := store.LookupCommandResult(
		context.Background(),
		testEventID2,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(rejected): %v", err)
	}
	if !found {
		t.Fatal("LookupCommandResult(rejected) found = false")
	}
	if rejectedLookup.Outcome.Status != OutcomeRejected ||
		rejectedLookup.Tuple.ChainIndex != nil ||
		rejectedLookup.Tuple.ChainHash != nil {
		t.Fatalf(
			"LookupCommandResult(rejected) = %+v, want rejected with nil chain tuple",
			rejectedLookup,
		)
	}
}

func TestLookupCommandResultMiss(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)

	got, found, err := store.LookupCommandResult(
		context.Background(),
		testEventID2,
	)
	if err != nil {
		t.Fatalf("LookupCommandResult(miss): %v", err)
	}
	if found {
		t.Fatalf("LookupCommandResult(miss) = %+v, true; want zero, false", got)
	}
	if len(got.CanonicalProposal) != 0 ||
		len(got.Outcome.JSON) != 0 ||
		got.Tuple.ChainIndex != nil ||
		got.Tuple.ChainHash != nil {
		t.Fatalf("LookupCommandResult(miss) returned nonzero data: %+v", got)
	}
}

func TestLookupCommandResultRejectsCorruption(t *testing.T) {
	tests := []struct {
		name      string
		statement string
	}{
		{
			name: "proposal digest",
			statement: `UPDATE command_results
			               SET proposal_digest = zeroblob(32)
			             WHERE event_id = ?1;`,
		},
		{
			name: "outcome",
			statement: `UPDATE command_results
			               SET outcome_json = '{"code":"changed","status":"accepted"}'
			             WHERE event_id = ?1;`,
		},
		{
			name: "result link",
			statement: `UPDATE command_results
			               SET result_hash = zeroblob(32)
			             WHERE event_id = ?1;`,
		},
		{
			name: "accepted event",
			statement: `UPDATE events
			               SET proposal_digest = zeroblob(32)
			             WHERE event_id = ?1;`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := openTestStore(
				t,
				filepath.Join(t.TempDir(), "session", "state.db"),
				nil,
			)
			initializeTestStore(t, store)
			request := acceptedApplyRequest(
				t,
				testSignedTaskEvent(t, testEventID, 1),
			)
			if _, err := store.Apply(
				context.Background(),
				request,
			); err != nil {
				t.Fatalf("Apply(): %v", err)
			}
			commitmentExecute(
				t,
				store,
				test.statement,
				string(testEventID),
			)

			got, found, err := store.LookupCommandResult(
				context.Background(),
				testEventID,
			)
			if !errors.Is(err, ErrCommandResultCorrupt) {
				t.Fatalf(
					"LookupCommandResult() error = %v, want ErrCommandResultCorrupt",
					err,
				)
			}
			if found || len(got.CanonicalProposal) != 0 {
				t.Fatalf(
					"LookupCommandResult(corrupt) returned data: %+v, %t",
					got,
					found,
				)
			}
		})
	}
}

func TestLookupCommandResultHonorsCancellationAndClosedStore(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.LookupCommandResult(
		ctx,
		testEventID,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"LookupCommandResult(cancelled) error = %v, want context.Canceled",
			err,
		)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, _, err := store.LookupCommandResult(
		context.Background(),
		testEventID,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf(
			"LookupCommandResult(closed) error = %v, want ErrClosed",
			err,
		)
	}
}
