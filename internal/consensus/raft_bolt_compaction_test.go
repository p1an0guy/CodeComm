package consensus

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"go.etcd.io/bbolt"
)

const (
	raftBoltCompactionTestLogCount = 1536
	raftBoltCompactionTestFirstLog = 1401
	raftBoltCompactionTestDataSize = 16 << 10
)

func TestCompactRaftBoltStorePreservesContentAndShrinks(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	createBloatedRaftBoltFixture(t, path)

	beforeInfo := mustLstatRaftBoltTestFile(t, path)
	beforeIdentity := mustInspectRaftBoltTestFile(t, path)
	if !raftBoltReclaimMeaningful(
		beforeInfo.Size(),
		beforeIdentity.liveEstimate,
	) {
		t.Fatalf(
			"fixture size/live estimate = %d/%d, does not trigger compaction",
			beforeInfo.Size(),
			beforeIdentity.liveEstimate,
		)
	}

	if err := compactRaftBoltStore(path); err != nil {
		t.Fatalf("compactRaftBoltStore(): %v", err)
	}

	afterInfo := mustLstatRaftBoltTestFile(t, path)
	afterIdentity := mustInspectRaftBoltTestFile(t, path)
	if !beforeIdentity.sameLogicalContent(afterIdentity) {
		t.Fatal("logical bbolt content changed during compaction")
	}
	if !raftBoltReclaimMeaningful(beforeInfo.Size(), afterInfo.Size()) {
		t.Fatalf(
			"compacted size = %d from %d, want meaningful shrinkage",
			afterInfo.Size(),
			beforeInfo.Size(),
		)
	}
	if afterInfo.Size() != afterIdentity.logicalBytes {
		t.Fatalf(
			"compacted size = %d, logical high-water mark = %d",
			afterInfo.Size(),
			afterIdentity.logicalBytes,
		)
	}
	assertRaftBoltCompactionTempAbsent(t, path)
	assertRaftBoltFixtureReadable(t, path)
}

func TestCompactRaftBoltStoreSkipsUnmeaningfulGrowth(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	createSmallRaftBoltFixture(t, path)
	before := mustReadRaftBoltTestFile(t, path)

	if err := compactRaftBoltStore(path); err != nil {
		t.Fatalf("compactRaftBoltStore(): %v", err)
	}

	after := mustReadRaftBoltTestFile(t, path)
	if !bytes.Equal(before, after) {
		t.Fatal("small Raft store was rewritten without meaningful reclaim")
	}
	assertRaftBoltCompactionTempAbsent(t, path)
}

func TestCompactRaftBoltStoreDoesNotFollowSymlink(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	target := filepath.Join(filepath.Dir(path), "target.db")
	createSmallRaftBoltFixture(t, target)
	before := mustReadRaftBoltTestFile(t, target)
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := compactRaftBoltStore(path)
	if !errors.Is(err, ErrInsecureConsensusPath) {
		t.Fatalf(
			"compactRaftBoltStore(symlink) error = %v, want %v",
			err,
			ErrInsecureConsensusPath,
		)
	}
	after := mustReadRaftBoltTestFile(t, target)
	if !bytes.Equal(after, before) {
		t.Fatal("symlink target changed")
	}
}

func TestCompactRaftBoltStoreReplacementFailurePreservesOriginal(
	t *testing.T,
) {
	path := newPrivateRaftBoltTestPath(t)
	createBloatedRaftBoltFixture(t, path)
	beforeBytes := mustReadRaftBoltTestFile(t, path)
	beforeIdentity := mustInspectRaftBoltTestFile(t, path)
	replacementErr := errors.New("injected replacement failure")
	replaceCalls := 0

	err := compactRaftBoltStoreWithOps(path, raftBoltCompactionOps{
		replace: func(_, _ string) error {
			replaceCalls++
			return replacementErr
		},
		syncDirectory: func(string) error {
			t.Fatal("directory sync ran after failed replacement")
			return nil
		},
	})
	if !errors.Is(err, replacementErr) {
		t.Fatalf(
			"compactRaftBoltStoreWithOps() error = %v, want %v",
			err,
			replacementErr,
		)
	}
	if replaceCalls != 1 {
		t.Fatalf("replacement calls = %d, want 1", replaceCalls)
	}
	afterBytes := mustReadRaftBoltTestFile(t, path)
	if sha256.Sum256(afterBytes) != sha256.Sum256(beforeBytes) ||
		!bytes.Equal(afterBytes, beforeBytes) {
		t.Fatal("failed replacement changed the original Raft store")
	}
	afterIdentity := mustInspectRaftBoltTestFile(t, path)
	if !beforeIdentity.sameLogicalContent(afterIdentity) {
		t.Fatal("failed replacement changed logical Raft content")
	}
	assertRaftBoltCompactionTempAbsent(t, path)
}

func TestCompactRaftBoltStoreDirectorySyncFailurePreservesLogicalContent(
	t *testing.T,
) {
	path := newPrivateRaftBoltTestPath(t)
	createBloatedRaftBoltFixture(t, path)
	beforeIdentity := mustInspectRaftBoltTestFile(t, path)
	syncErr := errors.New("injected directory sync failure")

	err := compactRaftBoltStoreWithOps(path, raftBoltCompactionOps{
		replace: replaceRaftBoltFile,
		syncDirectory: func(string) error {
			return syncErr
		},
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf(
			"compactRaftBoltStoreWithOps() error = %v, want %v",
			err,
			syncErr,
		)
	}
	afterIdentity := mustInspectRaftBoltTestFile(t, path)
	if !beforeIdentity.sameLogicalContent(afterIdentity) {
		t.Fatal("post-replacement sync failure changed logical content")
	}
	assertRaftBoltCompactionTempAbsent(t, path)
	assertRaftBoltFixtureReadable(t, path)
}

func TestCompactRaftBoltStoreClearsStaleTemporaryFile(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	createBloatedRaftBoltFixture(t, path)
	tempPath := filepath.Join(
		filepath.Dir(path),
		"."+filepath.Base(path)+".compact.tmp",
	)
	if err := os.WriteFile(tempPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale temporary file: %v", err)
	}

	if err := compactRaftBoltStore(path); err != nil {
		t.Fatalf("compactRaftBoltStore(): %v", err)
	}

	assertRaftBoltCompactionTempAbsent(t, path)
	assertRaftBoltFixtureReadable(t, path)
}

func TestCompactRaftBoltStoreBoundsAutomaticMaintenance(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	createSmallRaftBoltFixture(t, path)
	oversized := raftBoltCompactionMaxSourceBytes + 1
	if err := os.Truncate(path, oversized); err != nil {
		t.Fatalf("extend fixture: %v", err)
	}
	beforeInfo := mustLstatRaftBoltTestFile(t, path)

	if err := compactRaftBoltStore(path); err != nil {
		t.Fatalf("compactRaftBoltStore(): %v", err)
	}

	afterInfo := mustLstatRaftBoltTestFile(t, path)
	if afterInfo.Size() != beforeInfo.Size() ||
		!os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("oversized automatic maintenance changed the Raft store")
	}
	assertRaftBoltCompactionTempAbsent(t, path)
}

func TestNodeCloseCompactsClosedRaftStoreOnce(t *testing.T) {
	path := newPrivateRaftBoltTestPath(t)
	stable := openRaftBoltTestStore(t, path, false)
	closeErr := errors.New("injected compaction close failure")
	compactionCalls := 0
	node := &SingleNode{
		stable:        stable,
		raftStorePath: path,
		closeStarted:  make(chan struct{}),
		compactRaftStore: func(compactionPath string) error {
			compactionCalls++
			if compactionPath != path {
				t.Fatalf(
					"compaction path = %q, want %q",
					compactionPath,
					path,
				)
			}
			reopened := openRaftBoltTestStore(t, path, false)
			if err := reopened.Close(); err != nil {
				t.Fatalf("close probe store: %v", err)
			}
			return closeErr
		},
	}

	firstErr := node.Close()
	secondErr := node.Close()
	if !errors.Is(firstErr, closeErr) || !errors.Is(secondErr, closeErr) {
		t.Fatalf(
			"Close() errors = (%v, %v), want wrapped compaction error",
			firstErr,
			secondErr,
		)
	}
	if firstErr.Error() != secondErr.Error() {
		t.Fatalf(
			"idempotent Close() errors differ: %q != %q",
			firstErr,
			secondErr,
		)
	}
	if compactionCalls != 1 {
		t.Fatalf("compaction calls = %d, want 1", compactionCalls)
	}
}

func TestReplaceRaftBoltFileReplacesExistingFile(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "candidate.db")
	target := filepath.Join(directory, raftStoreFilename)
	if err := os.WriteFile(source, []byte("candidate"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := replaceRaftBoltFile(source, target); err != nil {
		t.Fatalf("replaceRaftBoltFile(): %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != "candidate" {
		t.Fatalf("replacement content = %q, want candidate", content)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source after replacement error = %v, want not-exist", err)
	}
}

func createBloatedRaftBoltFixture(t *testing.T, path string) {
	t.Helper()
	stable := openRaftBoltTestStore(t, path, false)
	if err := stable.Set([]byte("fixture-key"), []byte("fixture-value")); err != nil {
		t.Fatalf("Set(fixture-key): %v", err)
	}
	const batchSize = 96
	for first := 1; first <= raftBoltCompactionTestLogCount; first += batchSize {
		last := min(first+batchSize-1, raftBoltCompactionTestLogCount)
		logs := make([]*raft.Log, 0, last-first+1)
		for index := first; index <= last; index++ {
			logs = append(logs, &raft.Log{
				Index: uint64(index),
				Term:  uint64(index/128 + 1),
				Type:  raft.LogCommand,
				Data:  raftBoltCompactionTestData(index),
			})
		}
		if err := stable.StoreLogs(logs); err != nil {
			t.Fatalf("StoreLogs(%d-%d): %v", first, last, err)
		}
	}
	if err := stable.DeleteRange(
		1,
		raftBoltCompactionTestFirstLog-1,
	); err != nil {
		t.Fatalf("DeleteRange(): %v", err)
	}
	if err := stable.Close(); err != nil {
		t.Fatalf("close fixture store: %v", err)
	}

	database, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open fixture extension: %v", err)
	}
	updateErr := database.Update(func(tx *bbolt.Tx) error {
		fixture, err := tx.CreateBucketIfNotExists([]byte("fixture"))
		if err != nil {
			return err
		}
		if err := fixture.SetSequence(42); err != nil {
			return err
		}
		if err := fixture.Put([]byte("empty"), []byte{}); err != nil {
			return err
		}
		nested, err := fixture.CreateBucketIfNotExists([]byte("nested"))
		if err != nil {
			return err
		}
		if err := nested.SetSequence(99); err != nil {
			return err
		}
		return nested.Put([]byte{0x00, 0xff}, []byte{0xff, 0x00})
	})
	if err := errors.Join(updateErr, database.Close()); err != nil {
		t.Fatalf("extend fixture: %v", err)
	}
}

func newPrivateRaftBoltTestPath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("secure temporary directory: %v", err)
	}
	return filepath.Join(directory, raftStoreFilename)
}

func createSmallRaftBoltFixture(t *testing.T, path string) {
	t.Helper()
	stable := openRaftBoltTestStore(t, path, false)
	if err := stable.Set([]byte("fixture-key"), []byte("fixture-value")); err != nil {
		t.Fatalf("Set(fixture-key): %v", err)
	}
	if err := stable.StoreLog(&raft.Log{
		Index: 1,
		Term:  1,
		Type:  raft.LogCommand,
		Data:  []byte("small"),
	}); err != nil {
		t.Fatalf("StoreLog(): %v", err)
	}
	if err := stable.Close(); err != nil {
		t.Fatalf("close fixture store: %v", err)
	}
}

func openRaftBoltTestStore(
	t *testing.T,
	path string,
	readOnly bool,
) *raftboltdb.BoltStore {
	t.Helper()
	options := *bbolt.DefaultOptions
	options.Timeout = time.Second
	options.ReadOnly = readOnly
	stable, err := raftboltdb.New(raftboltdb.Options{
		Path:        path,
		BoltOptions: &options,
		NoSync:      false,
	})
	if err != nil {
		t.Fatalf("open Raft Bolt store: %v", err)
	}
	return stable
}

func mustInspectRaftBoltTestFile(
	t *testing.T,
	path string,
) raftBoltLogicalIdentity {
	t.Helper()
	info := mustLstatRaftBoltTestFile(t, path)
	database, err := openRaftBoltForCompaction(path, info, true)
	if err != nil {
		t.Fatalf("openRaftBoltForCompaction(): %v", err)
	}
	identity, inspectErr := inspectRaftBolt(database)
	if err := errors.Join(inspectErr, database.Close()); err != nil {
		t.Fatalf("inspectRaftBolt(): %v", err)
	}
	return identity
}

func mustLstatRaftBoltTestFile(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	return info
}

func mustReadRaftBoltTestFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return content
}

func assertRaftBoltCompactionTempAbsent(t *testing.T, path string) {
	t.Helper()
	tempPath := filepath.Join(
		filepath.Dir(path),
		"."+filepath.Base(path)+".compact.tmp",
	)
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary path error = %v, want not-exist", err)
	}
}

func assertRaftBoltFixtureReadable(t *testing.T, path string) {
	t.Helper()
	stable := openRaftBoltTestStore(t, path, true)
	defer func() {
		if err := stable.Close(); err != nil {
			t.Errorf("close compatibility store: %v", err)
		}
	}()
	first, err := stable.FirstIndex()
	if err != nil {
		t.Fatalf("FirstIndex(): %v", err)
	}
	last, err := stable.LastIndex()
	if err != nil {
		t.Fatalf("LastIndex(): %v", err)
	}
	if first != raftBoltCompactionTestFirstLog ||
		last != raftBoltCompactionTestLogCount {
		t.Fatalf(
			"log range = %d-%d, want %d-%d",
			first,
			last,
			raftBoltCompactionTestFirstLog,
			raftBoltCompactionTestLogCount,
		)
	}
	var entry raft.Log
	const probeIndex = 1450
	if err := stable.GetLog(probeIndex, &entry); err != nil {
		t.Fatalf("GetLog(%d): %v", probeIndex, err)
	}
	if !bytes.Equal(entry.Data, raftBoltCompactionTestData(probeIndex)) {
		t.Fatalf("GetLog(%d) data changed", probeIndex)
	}
	value, err := stable.Get([]byte("fixture-key"))
	if err != nil {
		t.Fatalf("Get(fixture-key): %v", err)
	}
	if string(value) != "fixture-value" {
		t.Fatalf("fixture value = %q", value)
	}
}

func raftBoltCompactionTestData(index int) []byte {
	data := make([]byte, raftBoltCompactionTestDataSize)
	for offset := range data {
		data[offset] = byte((index*31 + offset*17) % 251)
	}
	return data
}
