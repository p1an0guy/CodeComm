package consensus

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestSemanticRestoreFailureQuarantinesFinalizedFileSnapshot(
	t *testing.T,
) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "consensus")
	if _, err := prepareConsensusDirectory(root); err != nil {
		t.Fatalf("prepareConsensusDirectory(): %v", err)
	}
	delegate, err := raft.NewFileSnapshotStore(root, 2, io.Discard)
	if err != nil {
		t.Fatalf("NewFileSnapshotStore(): %v", err)
	}
	readerClosed := false
	trackedDelegate := &raftSnapshotCloseTrackingStore{
		SnapshotStore: delegate,
		onClose: func() {
			readerClosed = true
		},
	}
	fileReject, err := newRaftSnapshotFileRejecter(root)
	if err != nil {
		t.Fatalf("newRaftSnapshotFileRejecter(): %v", err)
	}
	reject := func(id string) error {
		if !readerClosed {
			return errors.New("snapshot reader remained open during rejection")
		}
		return fileReject(id)
	}
	adapter, err := newRaftSnapshotStoreWithReject(
		trackedDelegate,
		reject,
	)
	if err != nil {
		t.Fatalf("newRaftSnapshotStoreWithReject(): %v", err)
	}
	configuration, sourceID := raftSnapshotTestConfiguration()
	_, transport := raft.NewInmemTransport(
		raft.ServerAddress(sourceID),
	)
	defer transport.Close()
	persist := func(index uint64, payload []byte) string {
		t.Helper()
		sink, err := adapter.Create(
			raft.SnapshotVersionMax,
			index,
			3,
			configuration,
			7,
			transport,
		)
		if err != nil {
			t.Fatalf("Create(%d): %v", index, err)
		}
		envelope := raftSnapshotTestEnvelope(
			t,
			configuration,
			sourceID,
			payload,
		)
		envelope.SnapshotIndex = index
		frame := encodeRaftSnapshotTestFrame(t, envelope, payload)
		if _, err := sink.Write(frame); err != nil {
			_ = sink.Cancel()
			t.Fatalf("Write(%d): %v", index, err)
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close(%d): %v", index, err)
		}
		return sink.ID()
	}
	goodID := persist(11, []byte("retained prior snapshot"))
	badID := persist(12, []byte("not a semantic logical snapshot"))

	initial, _, _ := nodeTestInitialState(t)
	database, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	fsm, err := NewFSM(FSMOptions{
		Store:        database,
		OriginBootID: nodeTestBootID1,
		Clock:        nodeTestClock(),
		SnapshotDir:  root,
	})
	if err != nil {
		t.Fatalf("NewFSM(): %v", err)
	}
	_, reader, err := adapter.Open(badID)
	if err != nil {
		t.Fatalf("Open(bad): %v", err)
	}
	restoreErr := fsm.Restore(reader)
	closeErr := reader.Close()
	if restoreErr == nil {
		t.Fatal("semantic restore unexpectedly succeeded")
	}
	if closeErr != nil {
		t.Fatalf("reader.Close(): %v", closeErr)
	}
	if !readerClosed {
		t.Fatal("semantic restore failure did not close the snapshot reader")
	}
	if _, err := os.Stat(filepath.Join(
		root,
		raftSnapshotQuarantineDirectory,
		badID,
	)); err != nil {
		t.Fatalf("quarantined snapshot Stat(): %v", err)
	}
	metas, err := adapter.List()
	if err != nil {
		t.Fatalf("List(after quarantine): %v", err)
	}
	if len(metas) != 1 || metas[0].ID != goodID {
		t.Fatalf("live snapshots = %#v, want only %q", metas, goodID)
	}
	if _, _, err := adapter.Open(badID); err == nil ||
		errors.Is(err, ErrRaftSnapshotMetadataMismatch) {
		t.Fatalf("Open(quarantined) error = %v", err)
	}
	if bytes.Equal([]byte(goodID), []byte(badID)) {
		t.Fatal("test snapshots reused an ID")
	}
}

type raftSnapshotCloseTrackingStore struct {
	raft.SnapshotStore
	onClose func()
}

func (store *raftSnapshotCloseTrackingStore) Open(
	id string,
) (*raft.SnapshotMeta, io.ReadCloser, error) {
	meta, reader, err := store.SnapshotStore.Open(id)
	if err != nil {
		return nil, nil, err
	}
	return meta, &raftSnapshotCloseTrackingReader{
		ReadCloser: reader,
		onClose:    store.onClose,
	}, nil
}

type raftSnapshotCloseTrackingReader struct {
	io.ReadCloser
	onClose func()
}

func (reader *raftSnapshotCloseTrackingReader) Close() error {
	if reader.onClose != nil {
		reader.onClose()
		reader.onClose = nil
	}
	return reader.ReadCloser.Close()
}
