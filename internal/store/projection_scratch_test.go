package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"zombiezen.com/go/sqlite"
)

func TestProjectionScratchMatchesSQLiteMutationAndStateDigests(t *testing.T) {
	fixture := newProjectionFixture(t)
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, database)

	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections = fixture.initialWrites
	firstResult, err := database.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(initial projections): %v", err)
	}
	before, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	versions := chain.Versions{
		Digest:           before.Heads.DigestVersion,
		ProjectionSchema: before.Heads.ProjectionSchemaVersion,
	}
	scratch, err := NewProjectionScratch(before.ProjectionRows, versions)
	if err != nil {
		t.Fatalf("NewProjectionScratch(): %v", err)
	}
	mutations, err := scratch.Apply(fixture.updatedWrites)
	if err != nil {
		t.Fatalf("ProjectionScratch.Apply(): %v", err)
	}
	scratchMutationJSON, err := chain.EncodeMutations(mutations)
	if err != nil {
		t.Fatalf("chain.EncodeMutations(): %v", err)
	}

	second := nextProjectionApplyRequest(t, firstResult.Heads)
	second.Projections = fixture.updatedWrites
	if _, err := database.Apply(context.Background(), second); err != nil {
		t.Fatalf("Apply(updated projections): %v", err)
	}
	after, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(after): %v", err)
	}
	scratchDigest, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("ProjectionScratch.StateDigest(): %v", err)
	}
	if scratchDigest != chain.Digest(after.ProjectionStateDigest) {
		t.Fatalf(
			"scratch digest = %x, SQLite digest = %x",
			scratchDigest,
			after.ProjectionStateDigest,
		)
	}

	var storedMutationJSON []byte
	err = database.withConn(context.Background(), func(conn *sqlite.Conn) error {
		payload, err := requireCommandResultPayload(
			conn,
			after.Heads.ResultIndex,
		)
		if err != nil {
			return err
		}
		storedMutationJSON = payload.mutations
		return nil
	})
	if err != nil {
		t.Fatalf("read stored mutations: %v", err)
	}
	if !bytes.Equal(scratchMutationJSON, storedMutationJSON) {
		t.Fatalf(
			"scratch mutations = %s, SQLite mutations = %s",
			scratchMutationJSON,
			storedMutationJSON,
		)
	}
}

func TestProjectionScratchRejectsAtomicallyAndOwnsReturnedMemory(t *testing.T) {
	fixture := newProjectionFixture(t)
	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, database)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections = fixture.initialWrites
	if _, err := database.Apply(context.Background(), first); err != nil {
		t.Fatalf("Apply(initial projections): %v", err)
	}
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	versions := chain.Versions{
		Digest:           view.Heads.DigestVersion,
		ProjectionSchema: view.Heads.ProjectionSchemaVersion,
	}
	scratch, err := NewProjectionScratch(view.ProjectionRows, versions)
	if err != nil {
		t.Fatalf("NewProjectionScratch(): %v", err)
	}
	before, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("StateDigest(before): %v", err)
	}
	if _, err := scratch.Apply(ProjectionWrites{
		PlanRevisions: fixture.initialWrites.PlanRevisions,
	}); err == nil {
		t.Fatal("Apply(duplicate immutable row) succeeded")
	}
	after, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("StateDigest(after): %v", err)
	}
	if after != before {
		t.Fatal("rejected scratch write changed state")
	}

	mutations, err := scratch.Apply(fixture.updatedWrites)
	if err != nil {
		t.Fatalf("Apply(updated projections): %v", err)
	}
	pristine, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("StateDigest(pristine): %v", err)
	}
	mutations[0].After[0] ^= 0xff
	rows := scratch.Rows()
	rows[0].Row[0] ^= 0xff
	got, err := scratch.StateDigest(versions)
	if err != nil {
		t.Fatalf("StateDigest(after caller mutation): %v", err)
	}
	if got != pristine {
		t.Fatal("scratch aliases returned mutations or rows")
	}
}
