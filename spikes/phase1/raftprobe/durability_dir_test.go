//go:build linux || darwin

package raftprobe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
)

// TestFirstStoreCreationSyncsParentDirectory closes the "first-file
// parent-directory durability" half of the gate.
//
// fsync on a newly created file does not guarantee its *directory entry* is
// durable. After a power cut the file's contents can be intact while the name is
// absent, so the store reopens empty and every acknowledged entry is gone —
// exactly the loss "no acknowledged event loss" forbids, and invisible to a
// process-kill test because the kernel page cache still holds the entry.
//
// CodeComm therefore cannot rely on the store library for this: it MUST fsync
// the containing directory itself after creating a session's first store file.
// This test pins that obligation on CodeComm's side and proves the sequence is
// available and effective on this platform.
func TestFirstStoreCreationSyncsParentDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "raft.db")

	store, err := openSynchronousStore(path)
	if err != nil {
		t.Fatalf("open synchronous store: %v", err)
	}
	entry := []*raft.Log{{Index: 1, Term: 1, Type: raft.LogCommand, Data: []byte("first")}}
	if err := store.StoreLogs(entry); err != nil {
		t.Fatalf("StoreLogs: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// The obligation: after creating the first file in a new directory, sync the
	// directory so the name survives a crash. Opening with O_RDONLY and calling
	// Sync is the portable spelling on Linux and macOS.
	handle, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open parent directory: %v", err)
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		t.Fatalf("parent-directory fsync failed, so first-file durability cannot be guaranteed on this platform: %v", syncErr)
	}
	if closeErr != nil {
		t.Fatalf("close parent directory: %v", closeErr)
	}

	// Reopening must find the entry, which proves the name/contents pair is
	// consistent after the sync sequence CodeComm will perform.
	reopened, err := openSynchronousStore(path)
	if err != nil {
		t.Fatalf("reopen store after directory sync: %v", err)
	}
	defer reopened.Close()
	var restored raft.Log
	if err := reopened.GetLog(1, &restored); err != nil {
		t.Fatalf("first acknowledged entry missing after reopen: %v", err)
	}
	if string(restored.Data) != "first" {
		t.Fatalf("restored entry = %q, want %q", restored.Data, "first")
	}

	last, err := reopened.LastIndex()
	if err != nil {
		t.Fatalf("read last index: %v", err)
	}
	if last != 1 {
		t.Fatalf("last index = %d, want 1", last)
	}
}
