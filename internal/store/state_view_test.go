package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestAdmissionRevisionWaitsForApplyCriticalSection(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)

	store.applyMu.Lock()
	locked := true
	defer func() {
		if locked {
			store.applyMu.Unlock()
		}
	}()

	started := make(chan struct{})
	revision := make(chan uint64, 1)
	go func() {
		close(started)
		revision <- store.AdmissionRevision()
	}()
	<-started
	select {
	case got := <-revision:
		t.Fatalf(
			"AdmissionRevision() returned %d inside apply critical section",
			got,
		)
	case <-time.After(50 * time.Millisecond):
	}

	store.admissionRevision.Add(1)
	store.applyMu.Unlock()
	locked = false
	select {
	case got := <-revision:
		if got != 2 {
			t.Fatalf("AdmissionRevision() = %d, want 2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("AdmissionRevision() remained blocked after apply unlock")
	}
}

func TestViewReturnsAtomicLogicalStateAndIndependentBytes(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	fixture := newProjectionFixture(t)
	initial := commitmentInitialState(
		t,
		domain.UUIDv7(testSessionID),
		0,
		fixture.initialWrites,
	)
	heads, err := store.Initialize(context.Background(), initial)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}

	got, err := store.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if got.SessionID != initial.SessionID ||
		got.WorkspaceID != initial.WorkspaceID ||
		got.RecoveryGeneration != 0 ||
		!bytes.Equal(got.GenesisJSON, initial.GenesisJSON) {
		t.Fatalf("View() lineage = (%q, %q, %d)", got.SessionID, got.WorkspaceID, got.RecoveryGeneration)
	}
	if got.AdmissionRevision != 2 ||
		store.AdmissionRevision() != got.AdmissionRevision {
		t.Fatalf(
			"View() admission revision = %d, store = %d, want 2",
			got.AdmissionRevision,
			store.AdmissionRevision(),
		)
	}
	if got.CurrentTerm != nil || got.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"View() initial Raft watermark = (%v, %v), want nil",
			got.CurrentTerm,
			got.LastRaftAppliedLogIndex,
		)
	}
	if got.Heads != heads {
		t.Fatalf("View() heads = %+v, want %+v", got.Heads, heads)
	}
	wantDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		got.ProjectionRows,
	)
	if err != nil {
		t.Fatalf("StateDigest(View().ProjectionRows): %v", err)
	}
	if got.ProjectionStateDigest != wantDigest {
		t.Fatalf(
			"View() state digest = %x, want %x",
			got.ProjectionStateDigest,
			wantDigest,
		)
	}
	if len(got.ProjectionRows) == 0 {
		t.Fatal("View() returned no projection rows")
	}

	pristine := cloneLogicalRows(got.ProjectionRows)
	got.GenesisJSON[0] ^= 0xff
	got.ProjectionRows[0].PrimaryKey[0] ^= 0xff
	got.ProjectionRows[0].Row[0] ^= 0xff
	again, err := store.View(context.Background())
	if err != nil {
		t.Fatalf("View() after caller mutation: %v", err)
	}
	if !reflect.DeepEqual(again.ProjectionRows, pristine) {
		t.Fatal("View() aliases caller-visible projection bytes")
	}
	if !bytes.Equal(again.GenesisJSON, initial.GenesisJSON) {
		t.Fatal("View() aliases caller-visible genesis bytes")
	}
}

func TestViewRequiresInitializedOpenStoreAndLiveContext(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	if _, err := store.View(context.Background()); !errors.Is(
		err,
		ErrApplyConflict,
	) {
		t.Fatalf("View() before Initialize() error = %v, want ErrApplyConflict", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.View(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("View(cancelled) error = %v, want context.Canceled", err)
	}

	initializeTestStore(t, store)
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := store.View(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("View(closed) error = %v, want ErrClosed", err)
	}
}

func TestViewRejectsMalformedCommitmentHead(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		if err := execute(conn, "PRAGMA ignore_check_constraints = ON;"); err != nil {
			return err
		}
		return execute(
			conn,
			"UPDATE consensus_state SET chain_hash = zeroblob(31) WHERE singleton = 1;",
		)
	})
	if err != nil {
		t.Fatalf("corrupt consensus head: %v", err)
	}

	if _, err := store.View(context.Background()); !errors.Is(
		err,
		ErrCommandResultCorrupt,
	) {
		t.Fatalf("View() error = %v, want ErrCommandResultCorrupt", err)
	}
}
