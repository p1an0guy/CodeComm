//go:build !windows

package workspacelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireRejectsInsecureUnixLockFile(t *testing.T) {
	t.Parallel()

	statePath := workspaceLockTestStatePath(t)
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(statePath); !errors.Is(err, ErrInsecureFile) {
		t.Fatalf("Acquire(insecure mode) error = %v", err)
	}
}

func TestAcquireRejectsUnixSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "state.db")
	path, err := Path(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(statePath); !errors.Is(err, ErrInsecureFile) {
		t.Fatalf("Acquire(symlink) error = %v", err)
	}
}
