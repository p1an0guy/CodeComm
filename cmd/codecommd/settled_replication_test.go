package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

type daemonSettledReplicaStub struct {
	mu        sync.Mutex
	heads     store.ApplyHeads
	fatal     error
	importErr error
	imports   int
	ackErr    error
	acks      int
	forgotten []domain.DeviceID
}

func (stub *daemonSettledReplicaStub) ReplicationHeads(
	context.Context,
) (store.ApplyHeads, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.heads, nil
}

func (*daemonSettledReplicaStub) VerifiedGenerationZeroView(
	context.Context,
) (store.StateView, error) {
	return store.StateView{}, errors.New("unexpected snapshot boundary lookup")
}

func (*daemonSettledReplicaStub) PeerAdmissionSnapshot() (
	*peerauth.Snapshot,
	error,
) {
	return nil, errors.New("unexpected snapshot admission lookup")
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

func (*daemonSettledReplicaStub) InstallLogicalSnapshot(
	context.Context,
	*consensus.VerifiedLogicalSnapshotStage,
	domain.Timestamp,
) (store.StandaloneLogicalSnapshotInstallResult, error) {
	return store.StandaloneLogicalSnapshotInstallResult{},
		errors.New("unexpected snapshot install")
}

func (stub *daemonSettledReplicaStub) FatalError() error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.fatal
}

func (stub *daemonSettledReplicaStub) ObserveReplicationAcknowledgement(
	_ context.Context,
	_ domain.DeviceID,
	acknowledgement replication.Acknowledgement,
) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.acks++
	if stub.ackErr != nil {
		return stub.ackErr
	}
	metadata := acknowledgement.Unsigned().Metadata()
	stub.heads.ResultIndex = metadata.ResultIndex
	stub.heads.ResultHash = store.Digest(metadata.ResultHash)
	return nil
}

func (stub *daemonSettledReplicaStub) ForgetReplicationPeer(
	peerID domain.DeviceID,
) {
	stub.mu.Lock()
	stub.forgotten = append(stub.forgotten, peerID)
	stub.mu.Unlock()
}

type daemonReplicationClientStub struct {
	mu               sync.Mutex
	batches          []replication.Batch
	acknowledgements []replication.Acknowledgement
	errs             []error
	ackErrs          []error
	after            []uint64
	ackAt            []uint64
	wait             bool
}

func (stub *daemonReplicationClientStub) ReplicationAcknowledgement(
	_ context.Context,
	atResult uint64,
) (replication.Acknowledgement, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.ackAt = append(stub.ackAt, atResult)
	if len(stub.ackErrs) != 0 {
		err := stub.ackErrs[0]
		stub.ackErrs = stub.ackErrs[1:]
		return replication.Acknowledgement{}, err
	}
	if len(stub.acknowledgements) == 0 {
		return replication.Acknowledgement{},
			contenthttp.ErrReplicationUnavailable
	}
	acknowledgement := stub.acknowledgements[0]
	stub.acknowledgements = stub.acknowledgements[1:]
	return acknowledgement, nil
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

func (*daemonReplicationClientStub) LatestSnapshot(
	context.Context,
) (logicalsnapshot.Root, error) {
	return logicalsnapshot.Root{}, contenthttp.ErrSnapshotUnavailable
}

func (*daemonReplicationClientStub) OpenSnapshotBulk(
	context.Context,
	logicalsnapshot.Root,
) (daemonSnapshotBulkClient, error) {
	return nil, contenthttp.ErrSnapshotUnavailable
}

func TestDaemonSettledReplicationImportsAndFailsOver(t *testing.T) {
	batch := daemonSettledReplicationTestBatch(t, 1)
	replica := &daemonSettledReplicaStub{}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
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
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
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

func TestDaemonSettledReplicationKeepsCurrencyUnknownWithoutAcknowledgement(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
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
		client.after[0] != 0 ||
		len(client.ackAt) != 1 ||
		client.ackAt[0] != 0 ||
		replica.acks != 0 {
		t.Fatalf(
			"unavailable cursor = imports %d, requests %v, acknowledgements %v/%d",
			replica.imports,
			client.after,
			client.ackAt,
			replica.acks,
		)
	}
}

func TestDaemonSettledReplicationRecordsEqualCursorAcknowledgement(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
	relay := daemonContentTestDeviceID(t, 0xd6)
	client := &daemonReplicationClientStub{
		acknowledgements: []replication.Acknowledgement{
			daemonSettledReplicationTestAcknowledgement(t),
		},
	}
	if err := runtime.Sync(
		context.Background(),
		relay,
		client,
	); err != nil {
		t.Fatalf("Sync(equal cursor): %v", err)
	}
	if replica.imports != 0 ||
		replica.acks != 1 ||
		len(replica.forgotten) != 1 ||
		replica.forgotten[0] != relay ||
		len(client.after) != 1 ||
		client.after[0] != 0 ||
		len(client.ackAt) != 1 ||
		client.ackAt[0] != 0 {
		t.Fatalf(
			"equal-cursor sync = imports %d, acks %d, forgotten %v, requests %v/%v",
			replica.imports,
			replica.acks,
			replica.forgotten,
			client.after,
			client.ackAt,
		)
	}
}

func TestDaemonSettledReplicationRejectsInvalidAcknowledgement(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{
		ackErr: consensus.ErrInvalidReplicationReplay,
	}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
	client := &daemonReplicationClientStub{
		acknowledgements: []replication.Acknowledgement{
			daemonSettledReplicationTestAcknowledgement(t),
		},
	}
	err := runtime.Sync(
		context.Background(),
		daemonContentTestDeviceID(t, 0xd7),
		client,
	)
	if !errors.Is(err, errDaemonSettledReplication) ||
		!errors.Is(err, consensus.ErrInvalidReplicationReplay) ||
		replica.acks != 1 {
		t.Fatalf(
			"Sync(invalid acknowledgement) = %v, acknowledgements %d",
			err,
			replica.acks,
		)
	}
}

func TestDaemonSettledReplicationPreservesFatalReplicaCause(t *testing.T) {
	fatal := errors.New("settled evidence corrupt")
	replica := &daemonSettledReplicaStub{
		fatal:     fatal,
		importErr: fatal,
	}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
	client := &daemonReplicationClientStub{
		batches: []replication.Batch{
			daemonSettledReplicationTestBatch(t, 1),
		},
	}
	err := runtime.Sync(
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
	if len(client.after) != 0 ||
		len(replica.forgotten) != 0 ||
		replica.imports != 0 {
		t.Fatalf(
			"Sync(fatal) performed work: requests %v, forgotten %v, imports %d",
			client.after,
			replica.forgotten,
			replica.imports,
		)
	}
}

func TestDaemonSettledReplicationCancellation(
	t *testing.T,
) {
	replica := &daemonSettledReplicaStub{}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)
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

func newDaemonSettledReplicationTestRuntime(
	t *testing.T,
	replica daemonSettledReplica,
) *daemonSettledReplication {
	t.Helper()
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		daemonSettledReplicationOptions{
			Replica: replica,
			ScratchRoot: filepath.Join(
				t.TempDir(),
				"snapshot-scratch",
			),
			OriginBootID: daemonTestVerifyBootID,
			Clock:        consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("newDaemonSettledReplication(): %v", err)
	}
	return runtime
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

func daemonSettledReplicationTestAcknowledgement(
	t *testing.T,
) replication.Acknowledgement {
	t.Helper()
	snapshot := daemonContentTestSnapshot(t)
	_, privateKey, deviceID := daemonTestInitialState(t)
	defer clear(privateKey)
	if deviceID != snapshot.Member.ID {
		t.Fatal("acknowledgement fixture identity mismatch")
	}
	unsigned, err := replication.NewUnsignedAcknowledgement(
		replication.AcknowledgementInput{
			SessionID:                snapshot.SessionID,
			WorkspaceID:              snapshot.WorkspaceID,
			RecoveryGeneration:       snapshot.RecoveryGeneration,
			ServerDeviceID:           deviceID,
			ServerAuthorityVersion:   snapshot.CredentialAuthority.VoterSetVersion,
			ResultIndex:              0,
			ChainIndex:               0,
			ServerAppliedResultIndex: 0,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := replication.SignAcknowledgement(
		unsigned,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return acknowledgement
}
