package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
)

func TestResultHeadChangesCoalesceAcceptedAndRejectedApply(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := database.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")
	if _, err := database.LocalState().ResultHead(
		context.Background(),
	); !errors.Is(err, ErrApplyConflict) {
		t.Fatalf("ResultHead(before initialize) error = %v, want ErrApplyConflict", err)
	}

	initial := initializeTestStore(t, database)
	requireResultHeadChange(t, changes, "initialize")
	assertResultHead(t, database, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         initial.ChainIndex,
		ResultIndex:        initial.ResultIndex,
	})

	accepted := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	acceptedResult, err := database.Apply(context.Background(), accepted)
	if err != nil {
		t.Fatalf("Apply(accepted): %v", err)
	}
	rejected := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 1),
		acceptedResult.Heads,
	)
	rejectedResult, err := database.Apply(context.Background(), rejected)
	if err != nil {
		t.Fatalf("Apply(rejected): %v", err)
	}

	if got := len(changes); got != 1 {
		t.Fatalf("coalesced notification count = %d, want 1", got)
	}
	requireResultHeadChange(t, changes, "coalesced applies")
	assertNoResultHeadChange(t, changes, "second queued apply notification")
	assertResultHead(t, database, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         rejectedResult.Heads.ChainIndex,
		ResultIndex:        rejectedResult.Heads.ResultIndex,
	})
}

func TestResultHeadChangesIgnoreDuplicateRaftReplay(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, database)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := database.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")

	request := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	first, err := database.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply(first): %v", err)
	}
	requireResultHeadChange(t, changes, "first-seen apply")

	duplicate := request
	duplicate.Term = 2
	duplicate.LogIndex = 2
	replayed, err := database.Apply(context.Background(), duplicate)
	if err != nil {
		t.Fatalf("Apply(duplicate): %v", err)
	}
	if !replayed.Duplicate {
		t.Fatal("duplicate Apply() was not identified as a replay")
	}
	assertNoResultHeadChange(t, changes, "duplicate Raft replay")
	assertResultHead(t, database, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         first.Heads.ChainIndex,
		ResultIndex:        first.Heads.ResultIndex,
	})
}

func TestResultHeadChangesIgnoreRolledBackApply(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initial := initializeTestStore(t, database)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := database.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")

	injected := errors.New("injected apply failure")
	database.applyFailpoint = func(stage applyStage) error {
		if stage == applyAfterConsensus {
			return injected
		}
		return nil
	}
	request := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	if _, err := database.Apply(
		context.Background(),
		request,
	); !errors.Is(err, injected) {
		t.Fatalf("Apply() error = %v, want injected failure", err)
	}
	assertNoResultHeadChange(t, changes, "rolled-back apply")
	assertResultHead(t, database, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         initial.ChainIndex,
		ResultIndex:        initial.ResultIndex,
	})

	database.applyFailpoint = nil
	applied, err := database.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply(after rollback): %v", err)
	}
	requireResultHeadChange(t, changes, "committed apply after rollback")
	assertResultHead(t, database, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         applied.Heads.ChainIndex,
		ResultIndex:        applied.Heads.ResultIndex,
	})
}

func TestResultHeadChangesSignalSuccessorBoundary(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	predecessor := initializeTestStore(t, database)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := database.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")

	predecessorGenesisDigest, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, testSessionID, 0),
	)
	if err != nil {
		t.Fatalf("GenesisDigest(predecessor): %v", err)
	}
	stateDigest, err := chain.StateDigest(chain.Versions{
		Digest:           1,
		ProjectionSchema: 1,
	}, nil)
	if err != nil {
		t.Fatalf("StateDigest(successor): %v", err)
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
		ObservedAt:                "2026-08-10T12:00:02Z",
		Predecessor:               predecessor,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	heads, err := database.InstallSuccessor(
		context.Background(),
		successor,
	)
	if err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	requireResultHeadChange(t, changes, "successor boundary")
	assertResultHead(t, database, ResultHead{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		ChainIndex:         heads.ChainIndex,
		ResultIndex:        heads.ResultIndex,
	})
}

func TestResultHeadChangesUnregisterOnCancellationAndClose(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, database)

	for attempt := range 16 {
		ctx, cancel := context.WithCancel(context.Background())
		changes, err := database.LocalState().SubscribeResultHeadChanges(ctx)
		if err != nil {
			t.Fatalf("SubscribeResultHeadChanges(%d): %v", attempt, err)
		}
		requireResultHeadChange(t, changes, "initial")
		cancel()
		requireResultHeadChangesClosed(t, changes, "canceled subscription")
		if got := resultHeadSubscriberCount(database); got != 0 {
			t.Fatalf(
				"subscriber count after cancellation %d = %d, want 0",
				attempt,
				got,
			)
		}
	}

	changes, err := database.LocalState().SubscribeResultHeadChanges(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(close): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	requireResultHeadChangesClosed(t, changes, "store close")
	if got := resultHeadSubscriberCount(database); got != 0 {
		t.Fatalf("subscriber count after store close = %d, want 0", got)
	}
	if _, err := database.LocalState().SubscribeResultHeadChanges(
		context.Background(),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("subscription after Close() error = %v, want ErrClosed", err)
	}
}

func TestResultHeadChangesConcurrentSignalCancelAndClose(t *testing.T) {
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, database)

	const subscriptionCount = 64
	cancels := make([]context.CancelFunc, 0, subscriptionCount)
	changes := make([]<-chan struct{}, 0, subscriptionCount)
	for index := range subscriptionCount {
		ctx, cancel := context.WithCancel(context.Background())
		change, err := database.LocalState().SubscribeResultHeadChanges(ctx)
		if err != nil {
			cancel()
			t.Fatalf(
				"SubscribeResultHeadChanges(%d): %v",
				index,
				err,
			)
		}
		requireResultHeadChange(t, change, "initial")
		cancels = append(cancels, cancel)
		changes = append(changes, change)
	}

	start := make(chan struct{})
	closeErr := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		<-start
		for range 1024 {
			database.signalResultHeadChange()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for _, cancel := range cancels {
			cancel()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		closeErr <- database.Close()
	}()
	close(start)
	workers.Wait()
	if err := <-closeErr; err != nil {
		t.Fatalf("Close(): %v", err)
	}

	for _, change := range changes {
		requireResultHeadChangesEventuallyClosed(
			t,
			change,
			"concurrent subscriber",
		)
	}
	if got := resultHeadSubscriberCount(database); got != 0 {
		t.Fatalf("subscriber count after concurrent close = %d, want 0", got)
	}
}

func TestResultHeadChangesSignalResultBatchImport(t *testing.T) {
	fixture := newResultBatchImportFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := fixture.target.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")

	imported, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	)
	if err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	requireResultHeadChange(t, changes, "result batch import")
	assertResultHead(t, fixture.target, ResultHead{
		SessionID:          testSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
		ChainIndex:         imported.Heads.ChainIndex,
		ResultIndex:        imported.Heads.ResultIndex,
	})
}

func TestResultHeadChangesSignalLogicalSnapshotInstall(t *testing.T) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := fixture.target.LocalState().SubscribeResultHeadChanges(ctx)
	if err != nil {
		t.Fatalf("SubscribeResultHeadChanges(): %v", err)
	}
	requireResultHeadChange(t, changes, "initial")

	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	requireResultHeadChange(t, changes, "logical snapshot install")
	assertResultHead(t, fixture.target, ResultHead{
		SessionID:          installed.Cut.SessionID,
		WorkspaceID:        installed.Cut.WorkspaceID,
		RecoveryGeneration: installed.Cut.RecoveryGeneration,
		ChainIndex:         installed.Heads.ChainIndex,
		ResultIndex:        installed.Heads.ResultIndex,
	})
}

func assertResultHead(t *testing.T, database *Store, want ResultHead) {
	t.Helper()
	got, err := database.LocalState().ResultHead(context.Background())
	if err != nil {
		t.Fatalf("ResultHead(): %v", err)
	}
	if got != want {
		t.Fatalf("ResultHead() = %+v, want %+v", got, want)
	}
}

func requireResultHeadChange(
	t *testing.T,
	changes <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case _, open := <-changes:
		if !open {
			t.Fatalf("%s notification channel closed", description)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s notification", description)
	}
}

func assertNoResultHeadChange(
	t *testing.T,
	changes <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case _, open := <-changes:
		if !open {
			t.Fatalf("%s notification channel closed", description)
		}
		t.Fatalf("received unexpected %s notification", description)
	default:
	}
}

func requireResultHeadChangesClosed(
	t *testing.T,
	changes <-chan struct{},
	description string,
) {
	t.Helper()
	select {
	case _, open := <-changes:
		if open {
			t.Fatalf("%s left a queued notification", description)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s closure", description)
	}
}

func requireResultHeadChangesEventuallyClosed(
	t *testing.T,
	changes <-chan struct{},
	description string,
) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case _, open := <-changes:
			if !open {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s closure", description)
		}
	}
}

func resultHeadSubscriberCount(database *Store) int {
	database.resultHeadChanges.mu.Lock()
	defer database.resultHeadChanges.mu.Unlock()
	return len(database.resultHeadChanges.subscribers)
}
