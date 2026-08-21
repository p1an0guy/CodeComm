package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

type daemonSettledReplicaStub struct {
	mu        sync.Mutex
	heads     store.ApplyHeads
	fatal     error
	importErr error
	imports   int
}

func (stub *daemonSettledReplicaStub) ReplicationHeads(
	context.Context,
) (store.ApplyHeads, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.heads, nil
}

func (stub *daemonSettledReplicaStub) ImportResultBatch(
	_ context.Context,
	_ domain.DeviceID,
	batch replication.Batch,
) (store.ResultBatchImportResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.imports++
	metadata := batch.Unsigned().Metadata()
	if stub.importErr != nil {
		err := stub.importErr
		stub.importErr = nil
		stub.heads.ResultIndex = metadata.ToResultIndex
		return store.ResultBatchImportResult{}, err
	}
	stub.heads.ResultIndex = metadata.ToResultIndex
	stub.heads.ResultHash = store.Digest(metadata.EndResultHash)
	return store.ResultBatchImportResult{
		Heads: stub.heads,
	}, nil
}

func (stub *daemonSettledReplicaStub) FatalError() error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.fatal
}

type daemonReplicationClientStub struct {
	mu      sync.Mutex
	batches []replication.Batch
	errs    []error
	after   []uint64
	wait    bool
}

func (stub *daemonReplicationClientStub) Replication(
	ctx context.Context,
	after uint64,
) (replication.Batch, error) {
	stub.mu.Lock()
	stub.after = append(stub.after, after)
	if stub.wait {
		stub.mu.Unlock()
		<-ctx.Done()
		return replication.Batch{}, ctx.Err()
	}
	if len(stub.errs) != 0 {
		err := stub.errs[0]
		stub.errs = stub.errs[1:]
		stub.mu.Unlock()
		return replication.Batch{}, err
	}
	if len(stub.batches) == 0 {
		stub.mu.Unlock()
		return replication.Batch{}, contenthttp.ErrReplicationUnavailable
	}
	batch := stub.batches[0]
	stub.batches = stub.batches[1:]
	stub.mu.Unlock()
	return batch, nil
}

func TestDaemonSettledReplicationImportsAndFailsOver(t *testing.T) {
	batch := daemonSettledReplicationTestBatch(t, 1)
	replica := &daemonSettledReplicaStub{}
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		replica,
	)
	if err != nil {
		t.Fatalf("newDaemonSettledReplication(): %v", err)
	}
	relay := daemonContentTestDeviceID(t, 0xd1)
	stale := &daemonReplicationClientStub{
		errs: []error{contenthttp.ErrReplicationSnapshotRequired},
	}
	if err := runtime.Sync(
		context.Background(),
		relay,
		stale,
	); !errors.Is(err, errDaemonReplicationSnapshotRequired) {
		t.Fatalf("Sync(snapshot-required) error = %v", err)
	}
	healthy := &daemonReplicationClientStub{
		batches: []replication.Batch{batch},
	}
	if err := runtime.Sync(
		context.Background(),
		relay,
		healthy,
	); err != nil {
		t.Fatalf("Sync(healthy): %v", err)
	}
	if replica.imports != 1 ||
		replica.heads.ResultIndex != 1 ||
		len(healthy.after) != 1 ||
		healthy.after[0] != 0 {
		t.Fatalf(
			"catch-up = imports %d, heads %+v, cursors %v",
			replica.imports,
			replica.heads,
			healthy.after,
		)
	}
}

func TestDaemonSettledReplicationDoesNotExcuseInvalidConcurrentPage(
	t *testing.T,
) {
	batch := daemonSettledReplicationTestBatch(t, 1)
	replica := &daemonSettledReplicaStub{
		importErr: store.ErrInvalidResultBatchImport,
	}
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		replica,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &daemonReplicationClientStub{
		batches: []replication.Batch{batch},
	}
	if err := runtime.Sync(
		context.Background(),
		daemonContentTestDeviceID(t, 0xd2),
		client,
	); !errors.Is(err, store.ErrInvalidResultBatchImport) {
		t.Fatalf("Sync() error = %v", err)
	}
	if len(client.after) != 1 || client.after[0] != 0 {
		t.Fatalf("requested cursors = %v, want [0]", client.after)
	}
}

func TestDaemonSettledReplicationKeepsLinkAtUnavailableCursor(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{}
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		replica,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &daemonReplicationClientStub{}
	if err := runtime.Sync(
		context.Background(),
		daemonContentTestDeviceID(t, 0xd5),
		client,
	); err != nil {
		t.Fatalf("Sync(unavailable cursor): %v", err)
	}
	if replica.imports != 0 ||
		len(client.after) != 1 ||
		client.after[0] != 0 {
		t.Fatalf(
			"unavailable cursor = imports %d, requests %v",
			replica.imports,
			client.after,
		)
	}
}

func TestDaemonSettledReplicationPreservesFatalReplicaCause(t *testing.T) {
	fatal := errors.New("settled evidence corrupt")
	replica := &daemonSettledReplicaStub{
		fatal:     fatal,
		importErr: fatal,
	}
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		replica,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &daemonReplicationClientStub{
		batches: []replication.Batch{
			daemonSettledReplicationTestBatch(t, 1),
		},
	}
	err = runtime.Sync(
		context.Background(),
		daemonContentTestDeviceID(t, 0xd4),
		client,
	)
	if !errors.Is(err, errDaemonContentPeerState) ||
		!errors.Is(err, fatal) {
		t.Fatalf(
			"Sync(fatal) error = %v, want state and fatal causes",
			err,
		)
	}
}

func TestDaemonSettledReplicationCancellation(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{}
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		replica,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Sync(
		ctx,
		daemonContentTestDeviceID(t, 0xd3),
		&daemonReplicationClientStub{wait: true},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync(canceled) error = %v", err)
	}
}

func daemonSettledReplicationTestBatch(
	t *testing.T,
	serverWatermark uint64,
) replication.Batch {
	t.Helper()
	snapshot := daemonContentTestSnapshot(t)
	exported := daemonContentTestResultRange(t, snapshot)
	exported.ServerAppliedResultIndex = serverWatermark
	service, err := newDaemonContentService(
		snapshot.SessionID,
		snapshot.WorkspaceID,
		snapshot.RecoveryGeneration,
		snapshot.Member.ID,
		&daemonContentStateStub{
			snapshot:    snapshot,
			resultRange: exported,
			resultFound: true,
		},
		&daemonEndpointSetSourceStub{},
		nil,
		daemonContentTestBatchSigner(t),
		func() time.Time { return time.Now() },
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := service.Replication(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}
