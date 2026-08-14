package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"zombiezen.com/go/sqlite"
)

const commitmentSuccessorSessionID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000022",
)

func TestCommitmentsInitialBoundarySeedsAndRejectsRepeat(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := commitmentInitialState(t, domain.UUIDv7(testSessionID), 0, ProjectionWrites{})

	got, err := store.Initialize(context.Background(), initial)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	stateDigest, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(): %v", err)
	}
	genesisDigest, err := chain.GenesisDigest(initial.GenesisJSON)
	if err != nil {
		t.Fatalf("GenesisDigest(): %v", err)
	}
	eventSeed, err := chain.EventSeed(chain.Boundary{Genesis: genesisDigest})
	if err != nil {
		t.Fatalf("EventSeed(): %v", err)
	}
	resultSeed, err := chain.ResultSeed(chain.Boundary{Genesis: genesisDigest})
	if err != nil {
		t.Fatalf("ResultSeed(): %v", err)
	}
	want := ApplyHeads{
		ChainHash:               eventSeed,
		ResultHash:              resultSeed,
		ProjectionAccumulator:   chain.AccumulatorSeedInitial(genesisDigest, stateDigest),
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
	if got != want {
		t.Fatalf("Initialize() heads = %+v, want %+v", got, want)
	}
	if stored := commitmentDigestQuery(
		t,
		store,
		"SELECT boundary_transform_digest FROM genesis_records WHERE recovery_generation = 0;",
	); stored != stateDigest {
		t.Fatalf("boundary transform digest = %x, want %x", stored, stateDigest)
	}

	before := commitmentConsensus(t, store)
	if _, err := store.Initialize(context.Background(), initial); !errors.Is(
		err,
		ErrApplyConflict,
	) {
		t.Fatalf("repeat Initialize() error = %v, want ErrApplyConflict", err)
	}
	after := commitmentConsensus(t, store)
	if after != before {
		t.Fatalf("repeat Initialize() changed consensus state:\nbefore: %+v\nafter:  %+v", before, after)
	}
	if revision := store.AdmissionRevision(); revision != 2 {
		t.Fatalf("rejected repeat changed admission revision to %d", revision)
	}
	assertCounts(t, store, map[string]int64{
		"genesis_records": 1,
		"consensus_state": 1,
	})
}

func TestCommitmentsSuccessorBoundaryRetainsDenseIndicesAndReopens(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)
	initializeTestStore(t, store)
	fixture := newProjectionFixture(t)

	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections.Tasks = fixture.initialWrites.Tasks
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	second := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		firstResult.Heads,
	)
	secondResult, err := store.Apply(context.Background(), second)
	if err != nil {
		t.Fatalf("Apply(second): %v", err)
	}
	predecessor := secondResult.Heads
	if revision := store.AdmissionRevision(); revision != 4 {
		t.Fatalf("predecessor admission revision = %d, want 4", revision)
	}
	if predecessor.ChainIndex != 1 || predecessor.ResultIndex != 2 {
		t.Fatalf(
			"predecessor positions = (%d, %d), want (1, 2)",
			predecessor.ChainIndex,
			predecessor.ResultIndex,
		)
	}

	predecessorGenesisDigest, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, domain.UUIDv7(testSessionID), 0),
	)
	if err != nil {
		t.Fatalf("GenesisDigest(predecessor): %v", err)
	}
	stateDigest, err := chain.StateDigest(chain.Versions{
		Digest:           1,
		ProjectionSchema: 1,
	}, nil)
	if err != nil {
		t.Fatalf("StateDigest(empty successor): %v", err)
	}
	successor := SuccessorState{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		GenesisJSON: commitmentSuccessorGenesisJSON(
			t,
			predecessor,
			predecessorGenesisDigest,
			stateDigest,
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		Predecessor:               predecessor,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	genesisDigest, err := chain.GenesisDigest(successor.GenesisJSON)
	if err != nil {
		t.Fatalf("GenesisDigest(successor): %v", err)
	}
	boundary := chain.Boundary{
		Genesis:     genesisDigest,
		Generation:  1,
		ChainIndex:  predecessor.ChainIndex,
		ResultIndex: predecessor.ResultIndex,
		ChainHash:   predecessor.ChainHash,
		ResultHash:  predecessor.ResultHash,
	}
	eventSeed, err := chain.EventSeed(boundary)
	if err != nil {
		t.Fatalf("EventSeed(successor): %v", err)
	}
	resultSeed, err := chain.ResultSeed(boundary)
	if err != nil {
		t.Fatalf("ResultSeed(successor): %v", err)
	}
	want := ApplyHeads{
		ChainIndex:  predecessor.ChainIndex,
		ChainHash:   eventSeed,
		ResultIndex: predecessor.ResultIndex,
		ResultHash:  resultSeed,
		ProjectionAccumulator: chain.AccumulatorSeedSuccessor(
			predecessor.ProjectionAccumulator,
			genesisDigest,
			stateDigest,
		),
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}

	got, err := store.InstallSuccessor(context.Background(), successor)
	if err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	if got != want {
		t.Fatalf("successor heads = %+v, want %+v", got, want)
	}
	if revision := store.AdmissionRevision(); revision != 5 {
		t.Fatalf("successor admission revision = %d, want 5", revision)
	}
	if got.ChainHash == predecessor.ChainHash ||
		got.ResultHash == predecessor.ResultHash ||
		got.ProjectionAccumulator == predecessor.ProjectionAccumulator {
		t.Fatal("successor failed to reseed every commitment head")
	}
	assertCounts(t, store, map[string]int64{
		"tasks":           0,
		"events":          1,
		"command_results": 2,
		"genesis_records": 2,
	})
	commitmentAssertDigest(t, store, stateDigest, "successor boundary")
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			`SELECT current_term IS NULL
			   AND last_raft_applied_log_index IS NULL
			   AND chain_index = 1
			   AND result_index = 2
			  FROM consensus_state;`,
			1,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(successor boundary): %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	})
	if revision := reopened.AdmissionRevision(); revision != 1 {
		t.Fatalf("reopened admission revision = %d, want 1", revision)
	}
	if reopenedHeads := headsFromConsensus(commitmentConsensus(t, reopened)); reopenedHeads != want {
		t.Fatalf("reopened heads = %+v, want %+v", reopenedHeads, want)
	}
	commitmentAssertDigest(t, reopened, stateDigest, "reopened successor boundary")

	oldGenerationDuplicate := first
	oldGenerationDuplicate.RecoveryGeneration = 0
	oldGenerationDuplicate.Outcome = CommandOutcome{
		Status: OutcomeStatus("must_not_be_validated"),
	}
	oldGenerationDuplicate.RecordActivity = false
	oldGenerationDuplicate.ActivityTaskID = ""
	oldGenerationDuplicate.Audit = nil
	duplicateResult, err := reopened.Apply(
		context.Background(),
		oldGenerationDuplicate,
	)
	if err != nil {
		t.Fatalf("Apply(predecessor-generation duplicate): %v", err)
	}
	if duplicateResult.AdmissionRevision != 1 ||
		reopened.AdmissionRevision() != 1 {
		t.Fatalf(
			"duplicate admission revision = %d, store = %d, want 1",
			duplicateResult.AdmissionRevision,
			reopened.AdmissionRevision(),
		)
	}
	if !duplicateResult.Duplicate ||
		!sameCommitmentHeads(duplicateResult.Heads, want) ||
		duplicateResult.Outcome.Status != firstResult.Outcome.Status ||
		duplicateResult.Outcome.Code != firstResult.Outcome.Code ||
		!bytes.Equal(
			duplicateResult.Outcome.JSON,
			firstResult.Outcome.JSON,
		) {
		t.Fatalf(
			"predecessor-generation duplicate = %+v, want prior outcome and successor heads",
			duplicateResult,
		)
	}
	afterDuplicate := commitmentConsensus(t, reopened)
	if afterDuplicate.sessionID != commitmentSuccessorSessionID ||
		afterDuplicate.recoveryGeneration != 1 ||
		afterDuplicate.lastAppliedLogIndex != 1 {
		t.Fatalf(
			"predecessor duplicate changed successor lineage: %+v",
			afterDuplicate,
		)
	}
	assertCounts(t, reopened, map[string]int64{
		"events":          1,
		"command_results": 2,
	})
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close(after predecessor duplicate): %v", err)
	}
	reopened, err = Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(after predecessor duplicate): %v", err)
	}
	if reopenedHeads := headsFromConsensus(commitmentConsensus(t, reopened)); reopenedHeads != want {
		t.Fatalf(
			"heads after predecessor duplicate reopen = %+v, want %+v",
			reopenedHeads,
			want,
		)
	}
}

func TestCommitmentsDuplicateRejectsFutureGenerationWithoutMutation(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "session", "state.db")
	store := openTestStore(t, path, nil)
	initializeTestStore(t, store)

	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	if _, err := store.Apply(context.Background(), first); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	before := commitmentConsensus(t, store)
	beforeDigest, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(before future duplicate): %v", err)
	}

	future := first
	future.Term = 2
	future.LogIndex = 2
	future.AppliedAt = domain.Timestamp("2026-08-10T12:00:01Z")
	future.RecoveryGeneration = 7
	if _, err := store.Apply(context.Background(), future); !errors.Is(
		err,
		ErrApplyConflict,
	) {
		t.Fatalf(
			"Apply(future-generation duplicate) error = %v, want ErrApplyConflict",
			err,
		)
	}
	if after := commitmentConsensus(t, store); after != before {
		t.Fatalf(
			"future-generation duplicate changed consensus state:\nbefore: %+v\nafter:  %+v",
			before,
			after,
		)
	}
	if revision := store.AdmissionRevision(); revision != 3 {
		t.Fatalf(
			"future-generation duplicate changed admission revision to %d",
			revision,
		)
	}
	assertCounts(t, store, map[string]int64{
		"events":                    1,
		"command_results":           1,
		"raft_command_applications": 1,
	})
	commitmentAssertDigest(t, store, beforeDigest, "future-generation duplicate")

	if err := store.Close(); err != nil {
		t.Fatalf("Close(after future-generation duplicate): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(after future-generation duplicate): %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened after future-generation duplicate): %v", err)
		}
	})
	if got := commitmentConsensus(t, reopened); got != before {
		t.Fatalf(
			"reopened consensus after future-generation duplicate = %+v, want %+v",
			got,
			before,
		)
	}
	commitmentAssertDigest(
		t,
		reopened,
		beforeDigest,
		"reopened future-generation duplicate",
	)
}

func TestCommitmentsSuccessorGenesisBindingFailsClosed(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	predecessor := initializeTestStore(t, store)
	predecessorGenesisDigest, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, domain.UUIDv7(testSessionID), 0),
	)
	if err != nil {
		t.Fatalf("GenesisDigest(predecessor): %v", err)
	}
	emptyStateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		nil,
	)
	if err != nil {
		t.Fatalf("StateDigest(empty): %v", err)
	}
	valid := SuccessorState{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		GenesisJSON: commitmentSuccessorGenesisJSON(
			t,
			predecessor,
			predecessorGenesisDigest,
			emptyStateDigest,
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		Predecessor:               predecessor,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	before := commitmentConsensus(t, store)

	badTypedHeads := valid
	badTypedHeads.Predecessor.ChainHash = digestWithByte(0x31)
	if _, err := store.InstallSuccessor(
		context.Background(),
		badTypedHeads,
	); !errors.Is(err, ErrInvalidApply) {
		t.Fatalf(
			"InstallSuccessor(mismatched typed heads) error = %v, want ErrInvalidApply",
			err,
		)
	}

	badTransform := valid
	badTransform.Projections.Tasks = newProjectionFixture(t).initialWrites.Tasks
	if _, err := store.InstallSuccessor(
		context.Background(),
		badTransform,
	); !errors.Is(err, ErrApplyConflict) {
		t.Fatalf(
			"InstallSuccessor(mismatched transform) error = %v, want ErrApplyConflict",
			err,
		)
	}

	badPredecessorGenesis := valid
	badPredecessorGenesis.GenesisJSON = commitmentSuccessorGenesisJSON(
		t,
		predecessor,
		digestWithByte(0x42),
		emptyStateDigest,
	)
	if _, err := store.InstallSuccessor(
		context.Background(),
		badPredecessorGenesis,
	); !errors.Is(err, ErrApplyConflict) {
		t.Fatalf(
			"InstallSuccessor(wrong predecessor genesis) error = %v, want ErrApplyConflict",
			err,
		)
	}

	var malformedSignature map[string]any
	if err := json.Unmarshal(valid.GenesisJSON, &malformedSignature); err != nil {
		t.Fatalf("decode valid successor genesis: %v", err)
	}
	malformedSignature["quorum_recovery_signature"] = "AA"
	badSignature := valid
	badSignature.GenesisJSON = commitmentCanonicalJSON(
		t,
		malformedSignature,
	)
	if _, err := store.InstallSuccessor(
		context.Background(),
		badSignature,
	); !errors.Is(err, ErrInvalidApply) {
		t.Fatalf(
			"InstallSuccessor(malformed signature) error = %v, want ErrInvalidApply",
			err,
		)
	}

	if after := commitmentConsensus(t, store); after != before {
		t.Fatalf(
			"rejected successor changed consensus state:\nbefore: %+v\nafter:  %+v",
			before,
			after,
		)
	}
	if revision := store.AdmissionRevision(); revision != 2 {
		t.Fatalf("rejected successors changed admission revision to %d", revision)
	}
	assertCounts(t, store, map[string]int64{
		"genesis_records": 1,
		"tasks":           0,
	})
}

func TestCommitmentsDuplicateAdvancesWatermarkAndCollisionDoesNotMutate(
	t *testing.T,
) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	before := commitmentConsensus(t, store)
	beforeDigest, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(before duplicate): %v", err)
	}

	sameIndex := first
	sameIndex.Outcome = CommandOutcome{
		Status: OutcomeStatus("must_not_be_validated"),
	}
	sameIndex.RecordActivity = false
	sameIndex.ActivityTaskID = ""
	sameIndex.Audit = nil
	sameIndexResult, err := store.Apply(context.Background(), sameIndex)
	if err != nil {
		t.Fatalf("Apply(same-index replay): %v", err)
	}
	if !sameIndexResult.Duplicate ||
		!sameCommitmentHeads(sameIndexResult.Heads, firstResult.Heads) {
		t.Fatalf(
			"same-index replay = %+v, want duplicate with unchanged heads",
			sameIndexResult,
		)
	}
	if afterSameIndex := commitmentConsensus(t, store); afterSameIndex != before {
		t.Fatalf(
			"same-index replay changed consensus state:\nbefore: %+v\nafter:  %+v",
			before,
			afterSameIndex,
		)
	}

	duplicate := first
	duplicate.Term = 2
	duplicate.LogIndex = 2
	duplicate.AppliedAt = domain.Timestamp("2026-08-10T12:00:01Z")
	duplicate.Outcome = CommandOutcome{
		Status: OutcomeStatus("must_not_be_validated"),
		Code:   "",
		JSON:   []byte(`not-json`),
	}
	duplicate.RecordActivity = false
	duplicate.ActivityTaskID = ""
	duplicate.Audit = nil
	duplicate.Projections.Tasks = newProjectionFixture(t).initialWrites.Tasks

	duplicateResult, err := store.Apply(context.Background(), duplicate)
	if err != nil {
		t.Fatalf("Apply(duplicate): %v", err)
	}
	if !duplicateResult.Duplicate {
		t.Fatal("Apply(duplicate) did not report Duplicate")
	}
	if duplicateResult.Outcome.Status != firstResult.Outcome.Status ||
		duplicateResult.Outcome.Code != firstResult.Outcome.Code ||
		!bytes.Equal(duplicateResult.Outcome.JSON, firstResult.Outcome.JSON) {
		t.Fatalf(
			"duplicate outcome = %+v, want durable %+v",
			duplicateResult.Outcome,
			firstResult.Outcome,
		)
	}
	if !sameCommitmentHeads(duplicateResult.Heads, firstResult.Heads) {
		t.Fatalf(
			"duplicate heads = %+v, want unchanged %+v",
			duplicateResult.Heads,
			firstResult.Heads,
		)
	}
	afterDuplicate := commitmentConsensus(t, store)
	commitmentAssertOnlyWatermarkChanged(t, before, afterDuplicate, 2, 2)
	assertCounts(t, store, map[string]int64{
		"events":          1,
		"command_results": 1,
		"activity":        1,
		"audit_events":    1,
		"tasks":           0,
	})
	commitmentAssertDigest(t, store, beforeDigest, "exact duplicate")

	collision := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 2),
	)
	collision.Term = 3
	collision.LogIndex = 3
	collision.AppliedAt = domain.Timestamp("2026-08-10T12:00:02Z")
	if _, err := store.Apply(context.Background(), collision); !errors.Is(
		err,
		ErrIdempotencyConflict,
	) {
		t.Fatalf("Apply(ID collision) error = %v, want ErrIdempotencyConflict", err)
	}
	afterCollision := commitmentConsensus(t, store)
	if afterCollision != afterDuplicate {
		t.Fatalf(
			"event ID collision changed consensus state:\nbefore: %+v\nafter:  %+v",
			afterDuplicate,
			afterCollision,
		)
	}
	assertCounts(t, store, map[string]int64{
		"events":                    1,
		"command_results":           1,
		"raft_command_applications": 2,
		"activity":                  1,
		"audit_events":              1,
		"tasks":                     0,
	})
	commitmentAssertDigest(t, store, beforeDigest, "event ID collision")

	path := store.Path()
	if err := store.Close(); err != nil {
		t.Fatalf("Close(after collision): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(after collision): %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened after collision): %v", err)
		}
	})
	if got := commitmentConsensus(t, reopened); got != afterDuplicate {
		t.Fatalf(
			"reopened consensus after collision = %+v, want %+v",
			got,
			afterDuplicate,
		)
	}
	if revision := store.AdmissionRevision(); revision != 3 {
		t.Fatalf(
			"duplicate or collision changed admission revision to %d",
			revision,
		)
	}
}

func TestCommitmentsTamperedDuplicateLinkFailsClosed(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	request := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	if _, err := store.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	before := commitmentConsensus(t, store)
	tamperedPredecessor := digestWithByte(0x7a)
	commitmentExecute(
		t,
		store,
		"UPDATE command_results SET previous_result_hash = ?1 WHERE event_id = ?2;",
		tamperedPredecessor[:],
		string(testEventID),
	)

	request.Term = 2
	request.LogIndex = 2
	request.AppliedAt = domain.Timestamp("2026-08-10T12:00:01Z")
	if _, err := store.Apply(context.Background(), request); !errors.Is(
		err,
		ErrCommandResultCorrupt,
	) {
		t.Fatalf("Apply(tampered duplicate) error = %v, want ErrCommandResultCorrupt", err)
	}
	after := commitmentConsensus(t, store)
	if after != before {
		t.Fatalf("failed duplicate verification advanced state:\nbefore: %+v\nafter:  %+v", before, after)
	}
	assertCounts(t, store, map[string]int64{
		"events":          1,
		"command_results": 1,
	})
}

func TestCommitmentsStartupRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, *Store)
	}{
		{
			name: "genesis",
			tamper: func(t *testing.T, store *Store) {
				commitmentExecute(
					t,
					store,
					`UPDATE genesis_records
					    SET genesis_json = ?1
					  WHERE recovery_generation = 0;`,
					`{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000002","tampered":true,"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`,
				)
			},
		},
		{
			name: "result row",
			tamper: func(t *testing.T, store *Store) {
				commitmentExecute(
					t,
					store,
					"UPDATE command_results SET result_hash = zeroblob(32) WHERE event_id = ?1;",
					string(testEventID2),
				)
			},
		},
		{
			name: "accepted event row",
			tamper: func(t *testing.T, store *Store) {
				heads := headsFromConsensus(commitmentConsensus(t, store))
				rejected := rejectedApplyRequest(
					t,
					testSignedTaskEvent(t, testAuditEventID, 2),
					heads,
				)
				rejected.LogIndex = 3
				if _, err := store.Apply(
					context.Background(),
					rejected,
				); err != nil {
					t.Fatalf("Apply(rejected tail): %v", err)
				}
				commitmentExecute(
					t,
					store,
					"UPDATE events SET proposal_json = '{}' WHERE event_id = ?1;",
					string(testEventID2),
				)
			},
		},
		{
			name: "consensus result head",
			tamper: func(t *testing.T, store *Store) {
				commitmentExecute(
					t,
					store,
					"UPDATE consensus_state SET result_hash = zeroblob(32);",
				)
			},
		},
		{
			name: "consensus event head",
			tamper: func(t *testing.T, store *Store) {
				commitmentExecute(
					t,
					store,
					"UPDATE consensus_state SET chain_hash = zeroblob(32);",
				)
			},
		},
		{
			name: "forged current result does not anchor",
			tamper: func(t *testing.T, store *Store) {
				stored := commitmentStoredResult(t, store, testEventID2)
				forgedPrevious := digestWithByte(0xa5)
				if forgedPrevious == stored.previousResultHash {
					t.Fatal("forged predecessor unexpectedly equals the true predecessor")
				}
				forgedHash, _, err := chain.AppendResult(
					forgedPrevious,
					chain.Result{
						ResultIndex:    stored.resultIndex,
						Proposal:       stored.proposalJSON,
						Outcome:        stored.outcome.JSON,
						ProposalDigest: stored.proposalDigest,
						ChainIndex:     stored.chainIndex,
						ChainHash:      stored.chainHash,
					},
				)
				if err != nil {
					t.Fatalf("AppendResult(forged predecessor): %v", err)
				}
				commitmentExecute(
					t,
					store,
					`UPDATE command_results
					    SET previous_result_hash = ?1, result_hash = ?2
					  WHERE event_id = ?3;`,
					forgedPrevious[:],
					forgedHash[:],
					string(testEventID2),
				)
				commitmentExecute(
					t,
					store,
					"UPDATE consensus_state SET result_hash = ?1;",
					forgedHash[:],
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session", "state.db")
			store := openTestStore(t, path, nil)
			initializeTestStore(t, store)
			first := acceptedApplyRequest(
				t,
				testSignedTaskEvent(t, testEventID, 1),
			)
			firstResult, err := store.Apply(context.Background(), first)
			if err != nil {
				t.Fatalf("Apply(first): %v", err)
			}
			second := nextProjectionApplyRequest(t, firstResult.Heads)
			if _, err := store.Apply(context.Background(), second); err != nil {
				t.Fatalf("Apply(second): %v", err)
			}

			test.tamper(t, store)
			commitmentAssertReopenFails(t, store, path, ErrCommandResultCorrupt)
		})
	}
}

func TestCommitmentsProjectionAccumulatorUsesExactLogicalRows(
	t *testing.T,
) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initialHeads := initializeTestStore(t, store)
	fixture := newProjectionFixture(t)
	initialTask := fixture.initialWrites.Tasks[0]
	updatedTask := fixture.updatedWrites.Tasks[0]
	initialLogical := commitmentTaskLogicalRow(t, initialTask)
	updatedLogical := commitmentTaskLogicalRow(t, updatedTask)

	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections.Tasks = []task.Task{initialTask}
	wantFirst := commitmentExpectedAcceptedHeads(
		t,
		initialHeads,
		first,
		[]chain.Mutation{{
			Table:      initialLogical.Table,
			PrimaryKey: initialLogical.PrimaryKey,
			After:      initialLogical.Row,
		}},
	)
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(initial task): %v", err)
	}
	if firstResult.Heads != wantFirst {
		t.Fatalf("initial accumulator heads = %+v, want %+v", firstResult.Heads, wantFirst)
	}

	second := nextProjectionApplyRequest(t, firstResult.Heads)
	second.Projections.Tasks = []task.Task{updatedTask}
	wantSecond := commitmentExpectedAcceptedHeads(
		t,
		firstResult.Heads,
		second,
		[]chain.Mutation{{
			Table:      initialLogical.Table,
			PrimaryKey: initialLogical.PrimaryKey,
			Before:     initialLogical.Row,
			After:      updatedLogical.Row,
		}},
	)
	secondResult, err := store.Apply(context.Background(), second)
	if err != nil {
		t.Fatalf("Apply(updated task): %v", err)
	}
	if secondResult.Heads != wantSecond {
		t.Fatalf("updated accumulator heads = %+v, want %+v", secondResult.Heads, wantSecond)
	}
}

func TestCommitmentsProjectionStateDigestIgnoresPhysicalLayout(
	t *testing.T,
) {
	devices := projectionDevices(t, 3)
	reversed := slices.Clone(devices)
	slices.Reverse(reversed)

	firstStore := openTestStore(
		t,
		filepath.Join(t.TempDir(), "first", "state.db"),
		nil,
	)
	firstHeads, err := firstStore.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{Devices: devices},
		),
	)
	if err != nil {
		t.Fatalf("Initialize(first insertion order): %v", err)
	}
	secondStore := openTestStore(
		t,
		filepath.Join(t.TempDir(), "second", "state.db"),
		nil,
	)
	secondHeads, err := secondStore.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{Devices: reversed},
		),
	)
	if err != nil {
		t.Fatalf("Initialize(reverse insertion order): %v", err)
	}

	firstDigest, err := firstStore.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(first): %v", err)
	}
	secondDigest, err := secondStore.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(second): %v", err)
	}
	if firstDigest != secondDigest ||
		firstHeads.ProjectionAccumulator != secondHeads.ProjectionAccumulator {
		t.Fatalf(
			"insertion order changed commitments: digest %x/%x accumulator %x/%x",
			firstDigest,
			secondDigest,
			firstHeads.ProjectionAccumulator,
			secondHeads.ProjectionAccumulator,
		)
	}
	if reflect.DeepEqual(
		commitmentDeviceRowIDs(t, firstStore),
		commitmentDeviceRowIDs(t, secondStore),
	) {
		t.Fatal("opposite insertion orders unexpectedly produced identical rowid assignments")
	}

	err = firstStore.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var busy int64
		if err := queryOne(
			conn,
			"PRAGMA wal_checkpoint(TRUNCATE);",
			func(stmt *sqlite.Stmt) {
				busy = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if busy != 0 {
			return fmt.Errorf("WAL checkpoint reported %d busy connections", busy)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WAL checkpoint: %v", err)
	}
	commitmentAssertDigest(t, firstStore, firstDigest, "WAL checkpoint")

	commitmentExecute(t, firstStore, "VACUUM;")
	commitmentAssertDigest(t, firstStore, firstDigest, "VACUUM")

	rowIDsBefore := commitmentDeviceRowIDs(t, firstStore)
	target := devices[0]
	targetRowID := rowIDsBefore[string(target.ID)]
	for _, candidate := range devices[1:] {
		if rowID := rowIDsBefore[string(candidate.ID)]; rowID > targetRowID {
			target = candidate
			targetRowID = rowID
		}
	}
	candidates := projectionDevices(t, 4)
	replacement := candidates[0]
	replacementFound := false
	for _, candidate := range candidates {
		if _, exists := rowIDsBefore[string(candidate.ID)]; !exists {
			replacement = candidate
			replacementFound = true
			break
		}
	}
	if !replacementFound {
		t.Fatal("could not construct a distinct replacement device")
	}
	commitmentExecute(
		t,
		firstStore,
		"DELETE FROM devices WHERE device_id = ?1;",
		string(target.ID),
	)
	commitmentWriteProjections(
		t,
		firstStore,
		ProjectionWrites{Devices: []device.Device{replacement}},
	)
	reusedRowID := commitmentDeviceRowIDs(t, firstStore)[string(replacement.ID)]
	if reusedRowID != targetRowID {
		t.Fatalf(
			"replacement rowid = %d, want deleted maximum rowid %d to be reused",
			reusedRowID,
			targetRowID,
		)
	}
	commitmentExecute(
		t,
		firstStore,
		"DELETE FROM devices WHERE device_id = ?1;",
		string(replacement.ID),
	)
	commitmentWriteProjections(
		t,
		firstStore,
		ProjectionWrites{Devices: []device.Device{target}},
	)
	commitmentAssertDigest(t, firstStore, firstDigest, "rowid reuse")

	rowIDsBefore = commitmentDeviceRowIDs(t, firstStore)
	commitmentExecute(t, firstStore, "UPDATE devices SET rowid = rowid + 100;")
	rowIDsAfter := commitmentDeviceRowIDs(t, firstStore)
	if reflect.DeepEqual(rowIDsBefore, rowIDsAfter) {
		t.Fatal("rowid rewrite did not change physical row identifiers")
	}
	commitmentAssertDigest(t, firstStore, firstDigest, "rowid rewrite")

	commitmentExecute(
		t,
		firstStore,
		`INSERT INTO peer_endpoints(
		    device_id, source_kind, transport, host, port, observed_at
		) VALUES (?1, 'manual', 'tcp', '127.0.0.1', 43119, ?2);`,
		string(devices[0].ID),
		string(testAppliedAt),
	)
	commitmentAssertDigest(t, firstStore, firstDigest, "excluded-table insert")
}

func TestCommitmentsLogicalProjectionCodecs(t *testing.T) {
	fixture := newProjectionFixture(t)
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	if _, err := store.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			fixture.initialWrites,
		),
	); err != nil {
		t.Fatalf("Initialize(projection fixture): %v", err)
	}

	taskValue := fixture.initialWrites.Tasks[0]
	taskRow := commitmentLogicalRow(
		t,
		store,
		"tasks",
		string(taskValue.ID),
	)
	taskObject := commitmentLogicalObject(t, taskRow)
	wantBlockedBy := commitmentCanonicalJSON(t, taskValue.BlockedBy)
	if !bytes.Equal(taskObject["blocked_by"], wantBlockedBy) {
		t.Fatalf(
			"embedded blocked_by = %s, want embedded JSON %s",
			taskObject["blocked_by"],
			wantBlockedBy,
		)
	}
	if !bytes.Equal(taskObject["intended_device_id"], []byte("null")) {
		t.Fatalf(
			"nullable intended_device_id = %s, want null",
			taskObject["intended_device_id"],
		)
	}

	deviceValue := fixture.initialWrites.Devices[0]
	deviceRow := commitmentLogicalRow(
		t,
		store,
		"devices",
		string(deviceValue.ID),
	)
	deviceObject := commitmentLogicalObject(t, deviceRow)
	var encodedKey string
	if err := json.Unmarshal(deviceObject["identity_public_key"], &encodedKey); err != nil {
		t.Fatalf("decode logical identity_public_key: %v", err)
	}
	if want := codec.EncodeBase64URL(deviceValue.IdentityPublicKey); encodedKey != want {
		t.Fatalf("logical identity_public_key = %q, want base64url %q", encodedKey, want)
	}

	publicationValue := fixture.initialWrites.Publications[0]
	publicationRow := commitmentLogicalRow(
		t,
		store,
		"publications",
		string(publicationValue.Metadata.PublicationID),
	)
	publicationObject := commitmentLogicalObject(t, publicationRow)
	if !bytes.Equal(
		publicationObject["canonical_lineage_member"],
		[]byte("false"),
	) {
		t.Fatalf(
			"logical boolean = %s, want false",
			publicationObject["canonical_lineage_member"],
		)
	}

	authorization := fixture.initialWrites.CredentialAuthorizations[0]
	authorizationRow := commitmentLogicalRow(
		t,
		store,
		"credential_authorizations",
		string(authorization.SessionID),
		string(authorization.DeviceID),
		authorization.Epoch,
	)
	wantPrimaryKey := commitmentCanonicalJSON(t, []any{
		string(authorization.SessionID),
		string(authorization.DeviceID),
		authorization.Epoch,
	})
	if !bytes.Equal(authorizationRow.PrimaryKey, wantPrimaryKey) {
		t.Fatalf(
			"composite primary key = %s, want %s",
			authorizationRow.PrimaryKey,
			wantPrimaryKey,
		)
	}
}

func TestCommitmentsRejectInvalidUTF8LogicalText(t *testing.T) {
	invalid := string([]byte{0xff})
	if _, err := logicalProjectionValue(projectionText, invalid); err == nil {
		t.Fatal("logicalProjectionValue() accepted invalid UTF-8")
	}

	fixture := newProjectionFixture(t)
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	if _, err := store.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{Tasks: fixture.initialWrites.Tasks},
		),
	); err != nil {
		t.Fatalf("Initialize(task projection): %v", err)
	}
	commitmentExecute(
		t,
		store,
		"UPDATE tasks SET body = ?1;",
		invalid,
	)
	if _, err := store.ProjectionStateDigest(context.Background()); err == nil {
		t.Fatal("ProjectionStateDigest() accepted invalid UTF-8 from SQLite")
	}
}

func commitmentInitialState(
	t *testing.T,
	sessionID domain.UUIDv7,
	generation uint64,
	projections ProjectionWrites,
) InitialState {
	t.Helper()
	return InitialState{
		SessionID:               sessionID,
		WorkspaceID:             testWorkspaceID,
		GenesisJSON:             commitmentGenesisJSON(t, sessionID, generation),
		Projections:             projections,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
}

func commitmentGenesisJSON(
	t *testing.T,
	sessionID domain.UUIDv7,
	generation uint64,
) []byte {
	t.Helper()
	value := []byte(fmt.Sprintf(
		`{"recovery_generation":%d,"session_id":%q,"workspace_id":%q}`,
		generation,
		sessionID,
		testWorkspaceID,
	))
	canonical, err := codec.CanonicalizeSignedObject(value)
	if err != nil {
		t.Fatalf("canonicalize genesis: %v", err)
	}
	if !bytes.Equal(canonical, value) {
		t.Fatalf("test genesis is not canonical: %s", value)
	}
	return value
}

func commitmentSuccessorGenesisJSON(
	t *testing.T,
	predecessor ApplyHeads,
	predecessorGenesisDigest Digest,
	postTransformStateDigest Digest,
) []byte {
	t.Helper()
	recoveringSignature := bytes.Repeat([]byte{0x41}, 64)
	recoverySignature := bytes.Repeat([]byte{0x52}, 64)
	return commitmentCanonicalJSON(t, map[string]any{
		"digest_version":                     uint64(1),
		"post_transform_state_digest":        codec.EncodeBase64URL(postTransformStateDigest[:]),
		"predecessor_chain_hash":             codec.EncodeBase64URL(predecessor.ChainHash[:]),
		"predecessor_chain_index":            predecessor.ChainIndex,
		"predecessor_genesis_digest":         codec.EncodeBase64URL(predecessorGenesisDigest[:]),
		"predecessor_projection_accumulator": codec.EncodeBase64URL(predecessor.ProjectionAccumulator[:]),
		"predecessor_result_hash":            codec.EncodeBase64URL(predecessor.ResultHash[:]),
		"predecessor_result_index":           predecessor.ResultIndex,
		"projection_schema_version":          uint64(1),
		"quorum_recovery_signature":          codec.EncodeBase64URL(recoverySignature),
		"recovering_identity_signature":      codec.EncodeBase64URL(recoveringSignature),
		"recovery_generation":                uint64(1),
		"session_id":                         string(commitmentSuccessorSessionID),
		"workspace_id":                       string(testWorkspaceID),
	})
}

func commitmentConsensus(t *testing.T, store *Store) consensusState {
	t.Helper()
	var result consensusState
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var found bool
		var err error
		result, found, err = readConsensusState(conn)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("consensus state not found")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read consensus state: %v", err)
	}
	return result
}

func commitmentAssertOnlyWatermarkChanged(
	t *testing.T,
	before, after consensusState,
	wantTerm, wantLogIndex uint64,
) {
	t.Helper()
	if after.currentTerm != wantTerm ||
		after.lastAppliedLogIndex != wantLogIndex {
		t.Fatalf(
			"Raft watermark = (%d, %d), want (%d, %d)",
			after.currentTerm,
			after.lastAppliedLogIndex,
			wantTerm,
			wantLogIndex,
		)
	}
	after.currentTerm = before.currentTerm
	after.lastAppliedLogIndex = before.lastAppliedLogIndex
	if after != before {
		t.Fatalf(
			"non-watermark consensus state changed:\nbefore: %+v\nafter:  %+v",
			before,
			after,
		)
	}
}

func commitmentDigestQuery(
	t *testing.T,
	store *Store,
	statement string,
) Digest {
	t.Helper()
	var result Digest
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return queryOne(conn, statement, func(stmt *sqlite.Stmt) {
			if err := copyDigestColumn(&result, stmt, 0); err != nil {
				t.Errorf("read digest: %v", err)
			}
		})
	})
	if err != nil {
		t.Fatalf("digest query: %v", err)
	}
	return result
}

func commitmentAssertDigest(
	t *testing.T,
	store *Store,
	want Digest,
	operation string,
) {
	t.Helper()
	got, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatalf("ProjectionStateDigest(%s): %v", operation, err)
	}
	if got != want {
		t.Fatalf("ProjectionStateDigest(%s) = %x, want %x", operation, got, want)
	}
}

func commitmentExecute(
	t *testing.T,
	store *Store,
	statement string,
	arguments ...any,
) {
	t.Helper()
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(conn, statement, arguments...)
	})
	if err != nil {
		t.Fatalf("execute commitment test SQL: %v", err)
	}
}

func commitmentWriteProjections(
	t *testing.T,
	store *Store,
	writes ProjectionWrites,
) {
	t.Helper()
	prepared, err := prepareProjectionWrites(writes)
	if err != nil {
		t.Fatalf("prepare commitment test projections: %v", err)
	}
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return writePreparedProjections(conn, prepared)
	})
	if err != nil {
		t.Fatalf("write commitment test projections: %v", err)
	}
}

func commitmentStoredResult(
	t *testing.T,
	store *Store,
	eventID domain.UUIDv7,
) storedCommandResult {
	t.Helper()
	var result storedCommandResult
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var found bool
		var err error
		result, found, err = readStoredCommandResult(conn, eventID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("command result %s not found", eventID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read stored command result: %v", err)
	}
	return result
}

func commitmentAssertReopenFails(
	t *testing.T,
	store *Store,
	path string,
	want error,
) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("Close(tampered store): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err == nil {
		_ = reopened.Close()
		t.Fatalf("Open(tampered store) succeeded, want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("Open(tampered store) error = %v, want %v", err, want)
	}
}

func commitmentTaskLogicalRow(
	t *testing.T,
	value task.Task,
) chain.LogicalRow {
	t.Helper()
	object := map[string]any{
		"task_id":                string(value.ID),
		"title":                  value.Title,
		"body":                   value.Body,
		"state":                  string(value.State),
		"state_reason":           commitmentNullablePointer(value.StateReason),
		"priority":               uint64(value.Priority),
		"blocked_by":             value.BlockedBy,
		"labels":                 value.Labels,
		"owner_device_id":        commitmentNullableText(value.OwnerDeviceID),
		"owner_agent_session_id": commitmentNullableText(value.OwnerAgentSessionID),
		"intended_device_id":     commitmentNullableText(value.IntendedDeviceID),
		"last_release_reason":    commitmentNullableText(value.LastReleaseReason),
		"entity_version":         value.EntityVersion,
		"created_at":             string(value.CreatedAt),
		"updated_at":             string(value.UpdatedAt),
	}
	return chain.LogicalRow{
		Table:      "tasks",
		PrimaryKey: commitmentCanonicalJSON(t, []any{string(value.ID)}),
		Row:        commitmentCanonicalJSON(t, object),
	}
}

func commitmentExpectedAcceptedHeads(
	t *testing.T,
	previous ApplyHeads,
	request ApplyRequest,
	mutations []chain.Mutation,
) ApplyHeads {
	t.Helper()
	eventHash, err := chain.AppendEvent(
		previous.ChainHash,
		request.Proposal.CanonicalBytes(),
	)
	if err != nil {
		t.Fatalf("AppendEvent(expected): %v", err)
	}
	chainIndex := previous.ChainIndex + 1
	resultIndex := previous.ResultIndex + 1
	proposalHash := sha256.Sum256(request.Proposal.CanonicalBytes())
	resultHash, _, err := chain.AppendResult(
		previous.ResultHash,
		chain.Result{
			ResultIndex:    resultIndex,
			Proposal:       request.Proposal.CanonicalBytes(),
			Outcome:        request.Outcome.JSON,
			ProposalDigest: proposalHash,
			ChainIndex:     &chainIndex,
			ChainHash:      &eventHash,
		},
	)
	if err != nil {
		t.Fatalf("AppendResult(expected): %v", err)
	}
	accumulator, _, err := chain.AppendAccumulator(
		previous.ProjectionAccumulator,
		resultIndex,
		resultHash,
		mutations,
	)
	if err != nil {
		t.Fatalf("AppendAccumulator(expected): %v", err)
	}
	return ApplyHeads{
		ChainIndex:              chainIndex,
		ChainHash:               eventHash,
		ResultIndex:             resultIndex,
		PreviousResultHash:      previous.ResultHash,
		ResultHash:              resultHash,
		ProjectionAccumulator:   accumulator,
		DigestVersion:           previous.DigestVersion,
		ProjectionSchemaVersion: previous.ProjectionSchemaVersion,
	}
}

func commitmentDeviceRowIDs(t *testing.T, store *Store) map[string]int64 {
	t.Helper()
	result := make(map[string]int64)
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return query(conn, "SELECT device_id, rowid FROM devices;", func(stmt *sqlite.Stmt) {
			result[stmt.ColumnText(0)] = stmt.ColumnInt64(1)
		})
	})
	if err != nil {
		t.Fatalf("read device rowids: %v", err)
	}
	return result
}

func commitmentLogicalRow(
	t *testing.T,
	store *Store,
	tableName string,
	keyArguments ...any,
) chain.LogicalRow {
	t.Helper()
	var table projectionTable
	found := false
	for _, candidate := range projectionTables {
		if candidate.name == tableName {
			table = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("projection table %q not found", tableName)
	}
	var result chain.LogicalRow
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var rowFound bool
		var err error
		result, rowFound, err = readProjectionRow(conn, table, keyArguments)
		if err != nil {
			return err
		}
		if !rowFound {
			return fmt.Errorf("%s logical row not found", tableName)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read %s logical row: %v", tableName, err)
	}
	return result
}

func commitmentLogicalObject(
	t *testing.T,
	row chain.LogicalRow,
) map[string]json.RawMessage {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(row.Row, &result); err != nil {
		t.Fatalf("decode %s logical row: %v", row.Table, err)
	}
	return result
}

func commitmentCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal expected logical JSON: %v", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		t.Fatalf("canonicalize expected logical JSON: %v", err)
	}
	return canonical
}

func commitmentNullablePointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func commitmentNullableText[T ~string](value T) any {
	if value == "" {
		return nil
	}
	return string(value)
}
