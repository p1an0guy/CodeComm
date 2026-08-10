//go:build linux || darwin

package raftprobe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hashicorp/raft"
)

// TestStoreLogsPropagatesSyncFailure closes the "sync-failure propagation" half
// of the design §13 durability gate.
//
// The same-FD write/sync/ACK ordering proof shows the store syncs before it
// acknowledges on the happy path. It says nothing about a sync that *fails*: if
// StoreLogs swallowed an fsync error and returned nil, Raft would treat the
// entry as durable, count it toward a commit quorum, and "no acknowledged event
// loss" (§2.5) would rest on a write that never reached stable storage. That is
// the difference between a durable store and one that looks durable.
//
// Filling the filesystem is the portable way to make the sync path fail without
// patching the dependency: bbolt must grow the file to accommodate a new page,
// and the allocating write or its sync fails with ENOSPC/EIO. The requirement is
// only that the error surfaces — never that a particular syscall produces it.
func TestStoreLogsPropagatesSyncFailure(t *testing.T) {
	// A small file-backed store on a tmpfs-like directory would need root to
	// mount, so bound the *file* instead: set RLIMIT_FSIZE for this process so
	// growing the database past the limit fails. SIGXFSZ must be ignored or the
	// process dies instead of returning an error.
	directory := t.TempDir()
	path := filepath.Join(directory, "raft.db")

	store, err := openSynchronousStore(path)
	if err != nil {
		t.Fatalf("open synchronous store: %v", err)
	}
	defer store.Close()

	// Establish a healthy baseline first: without this, a test that only ever
	// observes failure cannot distinguish "propagates errors" from "never works".
	baseline := []*raft.Log{{Index: 1, Term: 1, Type: raft.LogCommand, Data: []byte("baseline")}}
	if err := store.StoreLogs(baseline); err != nil {
		t.Fatalf("baseline StoreLogs must succeed before injecting failure: %v", err)
	}

	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Skipf("read RLIMIT_FSIZE: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit) })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	capped := syscall.Rlimit{Cur: uint64(info.Size()), Max: limit.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &capped); err != nil {
		t.Skipf("cap RLIMIT_FSIZE: %v", err)
	}

	// Write enough distinct entries that bbolt must allocate beyond the cap.
	var storeErr error
	for index := uint64(2); index < 4096 && storeErr == nil; index++ {
		payload := make([]byte, 8192)
		for i := range payload {
			payload[i] = byte(index)
		}
		storeErr = store.StoreLogs([]*raft.Log{{
			Index: index,
			Term:  1,
			Type:  raft.LogCommand,
			Data:  payload,
		}})
	}

	if storeErr == nil {
		t.Fatal("StoreLogs returned nil for every write past RLIMIT_FSIZE; a store that cannot grow MUST report the failure rather than acknowledge it")
	}
	t.Logf("StoreLogs correctly propagated the write/sync failure: %v", storeErr)

	// The error must be a real I/O failure, not a nil-pointer panic recovered
	// into an opaque value, and must not be a Raft-level "not found" style error
	// that a caller might treat as benign.
	if errors.Is(storeErr, raft.ErrLogNotFound) {
		t.Fatalf("StoreLogs reported ErrLogNotFound for a durability failure: %v", storeErr)
	}
}
