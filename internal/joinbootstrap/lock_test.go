package joinbootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/workspacelock"
)

func TestJoinAndWorkspaceLockMutuallyExclude(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "join", "state.db")
	if err := prepareJournalDirectory(statePath); err != nil {
		t.Fatal(err)
	}

	workspace, err := workspacelock.Acquire(statePath)
	if err != nil {
		t.Fatalf("workspacelock.Acquire(): %v", err)
	}
	if _, err := acquireJoinLock(statePath); !errors.Is(
		err,
		ErrStateConflict,
	) {
		t.Fatalf("acquireJoinLock(workspace held) error = %v", err)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("close workspace lock: %v", err)
	}

	join, err := acquireJoinLock(statePath)
	if err != nil {
		t.Fatalf("acquireJoinLock(): %v", err)
	}
	_, err = workspacelock.Acquire(statePath)
	var held *workspacelock.HeldError
	if !errors.Is(err, workspacelock.ErrHeld) ||
		!errors.As(err, &held) ||
		held.PID != os.Getpid() {
		t.Fatalf("workspacelock.Acquire(join held) error = %#v", err)
	}
	if err := join.Close(); err != nil {
		t.Fatalf("close join lock: %v", err)
	}
}
