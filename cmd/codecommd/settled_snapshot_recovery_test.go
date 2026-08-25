package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/snapshotbuilder"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	daemonSnapshotRecoveryCheckpointEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-7123456789ab",
	)
	daemonSnapshotRecoveryTailEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-8123456789ab",
	)
	daemonSnapshotRecoveryTailTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-9123456789ab",
	)
)

type daemonSnapshotRecoveryOrigin struct {
	mu         sync.Mutex
	deviceID   domain.DeviceID
	bootID     domain.UUIDv7
	privateKey ed25519.PrivateKey
	next       uint64
}

func (origin *daemonSnapshotRecoveryOrigin) DeviceID() domain.DeviceID {
	return origin.deviceID
}

func (origin *daemonSnapshotRecoveryOrigin) BootID() domain.UUIDv7 {
	return origin.bootID
}

func (origin *daemonSnapshotRecoveryOrigin) RunExclusive(
	ctx context.Context,
	operation func(consensus.CheckpointReservation) error,
) error {
	if origin == nil || ctx == nil || operation == nil {
		return consensus.ErrCheckpointOriginUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	origin.mu.Lock()
	defer origin.mu.Unlock()
	return operation(origin.reserve)
}

func (origin *daemonSnapshotRecoveryOrigin) reserve(
	ctx context.Context,
	checkpoint domain.Checkpoint,
	signature store.Signature,
) (event.SignedEvent, error) {
	if err := ctx.Err(); err != nil {
		return event.SignedEvent{}, err
	}
	payload, err := event.EncodeCheckpointPayload(
		checkpoint,
		[ed25519.SignatureSize]byte(signature),
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	authority, err := event.NewLocalAuthority(
		origin.deviceID,
		origin.bootID,
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		return event.SignedEvent{}, err
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindConsensusCheckpoint,
			EntityID: event.NullEntityID(),
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        daemonSnapshotRecoveryCheckpointEventID,
			SessionID:      checkpoint.SessionID,
			WorkspaceID:    checkpoint.WorkspaceID,
			CreatedAt:      daemonTestTimestamp,
			OriginSequence: origin.next,
		},
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	signed, err := event.Sign(proposal, origin.privateKey)
	if err != nil {
		return event.SignedEvent{}, err
	}
	origin.next++
	return signed, nil
}

type daemonSnapshotRecoveryClient struct {
	root       logicalsnapshot.Root
	pages      []logicalsnapshot.DescriptorPage
	chunks     [][]byte
	tail       replication.Batch
	replicated []uint64
	bulkOpens  int
	bulk       *daemonSnapshotRecoveryBulk
}

func (client *daemonSnapshotRecoveryClient) Replication(
	_ context.Context,
	after uint64,
) (replication.Batch, error) {
	client.replicated = append(client.replicated, after)
	if len(client.replicated) == 1 {
		return replication.Batch{},
			contenthttp.ErrReplicationSnapshotRequired
	}
	return client.tail, nil
}

func (*daemonSnapshotRecoveryClient) ReplicationAcknowledgement(
	context.Context,
	uint64,
) (replication.Acknowledgement, error) {
	return replication.Acknowledgement{},
		errors.New("unexpected acknowledgement request")
}

func (client *daemonSnapshotRecoveryClient) LatestSnapshot(
	context.Context,
) (logicalsnapshot.Root, error) {
	return client.root, nil
}

func (client *daemonSnapshotRecoveryClient) OpenSnapshotBulk(
	_ context.Context,
	_ logicalsnapshot.Root,
) (daemonSnapshotBulkClient, error) {
	client.bulkOpens++
	client.bulk = &daemonSnapshotRecoveryBulk{
		pages:  client.pages,
		chunks: client.chunks,
	}
	return client.bulk, nil
}

type daemonSnapshotRecoveryBulk struct {
	pages      []logicalsnapshot.DescriptorPage
	chunks     [][]byte
	closed     bool
	closeCalls int
}

func (bulk *daemonSnapshotRecoveryBulk) SnapshotManifestPage(
	_ context.Context,
	index uint64,
) (logicalsnapshot.DescriptorPage, error) {
	if bulk.closed || index >= uint64(len(bulk.pages)) {
		return logicalsnapshot.DescriptorPage{},
			contenthttp.ErrSnapshotNotFound
	}
	return bulk.pages[index], nil
}

func (bulk *daemonSnapshotRecoveryBulk) SnapshotChunk(
	_ context.Context,
	index uint64,
) (contenthttp.SnapshotChunk, error) {
	if bulk.closed || index >= uint64(len(bulk.chunks)) {
		return contenthttp.SnapshotChunk{},
			contenthttp.ErrSnapshotNotFound
	}
	return contenthttp.NewSnapshotChunk(
		contenthttp.SnapshotRequestScope{
			SessionID:          daemonTestSessionID,
			WorkspaceID:        daemonTestWorkspaceID,
			RecoveryGeneration: 0,
			ArtifactID:         "snapshot-recovery-test",
		},
		index,
		bulk.chunks[index],
	)
}

func (bulk *daemonSnapshotRecoveryBulk) Close() error {
	bulk.closeCalls++
	bulk.closed = true
	return nil
}

func TestDaemonSettledReplicationInstallsSnapshotAndResumesTail(
	t *testing.T,
) {
	initial, localPrivateKey, localDeviceID, authorityDeviceID :=
		daemonTestSettledInitialState(t)
	defer clear(localPrivateKey)
	_, authorityPrivateKey, derivedAuthorityID := daemonTestInitialState(t)
	defer clear(authorityPrivateKey)
	if derivedAuthorityID != authorityDeviceID {
		t.Fatal("authority identity fixture changed")
	}

	sourceRoot := t.TempDir()
	origin := &daemonSnapshotRecoveryOrigin{
		deviceID:   authorityDeviceID,
		bootID:     daemonTestSecondBootID,
		privateKey: bytes.Clone(authorityPrivateKey),
		next:       1,
	}
	defer clear(origin.privateKey)
	signer := consensus.CheckpointSignerAdapter{
		SignerDeviceID: authorityDeviceID,
		Sign: func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := ctx.Err(); err != nil {
				return store.Signature{}, err
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				authorityPrivateKey,
			)
			return store.Signature(signature), err
		},
	}
	source, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID: authorityDeviceID,
			StatePath: filepath.Join(
				sourceRoot,
				"state",
				"state.db",
			),
			ConsensusDir:     filepath.Join(sourceRoot, "consensus"),
			OriginBootID:     daemonTestSecondBootID,
			InitialState:     &initial,
			CheckpointSigner: signer,
			CheckpointOrigin: origin,
			Clock:            consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(source): %v", err)
	}
	defer func() { _ = source.Close() }()
	waitForDaemonTestLeader(t, source)
	if result, err := source.Apply(
		daemonTestContext(t),
		daemonTestTaskEvent(
			t,
			authorityPrivateKey,
			authorityDeviceID,
		),
	); err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(snapshot task) = (%+v, %v)", result, err)
	}
	checkpoint, err := source.ForceCheckpoint(daemonTestContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	localState, err := source.LocalState()
	if err != nil {
		t.Fatalf("LocalState(): %v", err)
	}
	snapshot, pages, chunks := buildDaemonSnapshotRecoveryArtifact(
		t,
		localState,
		checkpoint.Record.CheckpointEventID,
		authorityDeviceID,
		authorityPrivateKey,
	)
	snapshotInput := snapshot.Root.Unsigned().Input()

	tail := daemonSnapshotRecoveryTaskEvent(
		t,
		authorityPrivateKey,
		authorityDeviceID,
	)
	if result, err := source.Apply(
		daemonTestContext(t),
		tail,
	); err != nil || result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("Apply(tail task) = (%+v, %v)", result, err)
	}
	contentService, err := newDaemonContentService(
		daemonTestSessionID,
		daemonTestWorkspaceID,
		0,
		authorityDeviceID,
		localState,
		&daemonEndpointSetSourceStub{},
		nil,
		func(
			unsigned replication.UnsignedBatch,
		) (replication.Batch, error) {
			return replication.SignBatch(unsigned, authorityPrivateKey)
		},
		func() time.Time { return time.Now() },
	)
	if err != nil {
		t.Fatalf("newDaemonContentService(): %v", err)
	}
	tailBatch, err := contentService.Replication(
		daemonTestContext(t),
		snapshotInput.ResultIndex,
	)
	if err != nil {
		t.Fatalf("Replication(tail): %v", err)
	}

	targetPath := filepath.Join(t.TempDir(), "target", "state.db")
	target, err := store.Open(
		context.Background(),
		store.Options{Path: targetPath},
	)
	if err != nil {
		t.Fatalf("store.Open(target): %v", err)
	}
	if _, err := target.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(target): %v", err)
	}
	storeDaemonTestConfiguration(
		t,
		target,
		[]domain.DeviceID{authorityDeviceID},
		nil,
	)
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		daemonTestTimestamp,
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	replica, err := consensus.OpenSettledReplica(
		context.Background(),
		consensus.SettledReplicaOptions{
			StatePath:     targetPath,
			OriginBootID:  daemonTestVerifyBootID,
			LocalDeviceID: localDeviceID,
			Clock:         consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	defer func() { _ = replica.Close() }()
	scratchRoot := filepath.Join(t.TempDir(), "snapshot-scratch")
	runtime, err := newDaemonSettledReplication(
		context.Background(),
		daemonSettledReplicationOptions{
			Replica:      replica,
			ScratchRoot:  scratchRoot,
			OriginBootID: daemonTestVerifyBootID,
			Clock:        consensus.NewSystemApplyClock(),
		},
	)
	if err != nil {
		t.Fatalf("newDaemonSettledReplication(): %v", err)
	}
	quotaInput := snapshot.Root.Unsigned().Input()
	quotaInput.ExpandedBytes = daemonSnapshotOperationalMaxBytes + 1
	quotaInput.CompressedBytes = quotaInput.ExpandedBytes
	quotaInput.ChunkCount = (quotaInput.CompressedBytes +
		uint64(logicalsnapshot.MaxChunkCompressedBytes) - 1) /
		uint64(logicalsnapshot.MaxChunkCompressedBytes)
	quotaInput.DescriptorPageCount = 1
	if quotaInput.RecordCount < quotaInput.ChunkCount {
		quotaInput.RecordCount = quotaInput.ChunkCount
	}
	quotaUnsigned, err := logicalsnapshot.NewUnsignedRoot(quotaInput)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(over receive quota): %v", err)
	}
	quotaRoot, err := logicalsnapshot.SignRoot(
		quotaUnsigned,
		authorityPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignRoot(over receive quota): %v", err)
	}
	quotaClient := &daemonSnapshotRecoveryClient{root: quotaRoot}
	if err := runtime.Sync(
		daemonTestContext(t),
		authorityDeviceID,
		quotaClient,
	); !errors.Is(err, errDaemonSnapshotReceiveQuota) {
		t.Fatalf("Sync(over receive quota) error = %v, want quota refusal", err)
	}
	if quotaClient.bulkOpens != 0 {
		t.Fatalf(
			"over-quota root opened %d bulk connections",
			quotaClient.bulkOpens,
		)
	}
	invalidSignature := snapshot.Root.Signature()
	invalidSignature[0] ^= 0xff
	invalidRoot, err := logicalsnapshot.NewRoot(
		snapshot.Root.Unsigned(),
		invalidSignature,
	)
	if err != nil {
		t.Fatalf("NewRoot(invalid signature): %v", err)
	}
	invalidClient := &daemonSnapshotRecoveryClient{root: invalidRoot}
	if err := runtime.Sync(
		daemonTestContext(t),
		authorityDeviceID,
		invalidClient,
	); !errors.Is(err, logicalsnapshot.ErrRootSignature) {
		t.Fatalf("Sync(invalid root signature) error = %v", err)
	}
	if invalidClient.bulkOpens != 0 {
		t.Fatalf(
			"invalid root signature opened %d bulk connections",
			invalidClient.bulkOpens,
		)
	}
	client := &daemonSnapshotRecoveryClient{
		root:   snapshot.Root,
		pages:  pages,
		chunks: chunks,
		tail:   tailBatch,
	}
	if err := runtime.Sync(
		daemonTestContext(t),
		authorityDeviceID,
		client,
	); err != nil {
		t.Fatalf("Sync(snapshot fallback): %v", err)
	}
	if !reflect.DeepEqual(
		client.replicated,
		[]uint64{0, snapshotInput.ResultIndex},
	) {
		t.Fatalf("replication cursors = %v", client.replicated)
	}
	if client.bulkOpens != 1 ||
		client.bulk == nil ||
		client.bulk.closeCalls != 1 {
		t.Fatalf(
			"snapshot transfer lifecycle = opens %d, bulk %+v",
			client.bulkOpens,
			client.bulk,
		)
	}
	sourceView, err := source.View(daemonTestContext(t))
	if err != nil {
		t.Fatalf("source View(): %v", err)
	}
	targetView, err := replica.View(daemonTestContext(t))
	if err != nil {
		t.Fatalf("target View(): %v", err)
	}
	if targetView.Heads != sourceView.Heads ||
		targetView.ProjectionStateDigest !=
			sourceView.ProjectionStateDigest ||
		!reflect.DeepEqual(
			targetView.ProjectionRows,
			sourceView.ProjectionRows,
		) ||
		targetView.CurrentTerm != nil ||
		targetView.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"snapshot+tail target differs:\ntarget=%+v\nsource=%+v",
			targetView,
			sourceView,
		)
	}
	staleClient := &daemonSnapshotRecoveryClient{
		root:   snapshot.Root,
		pages:  pages,
		chunks: chunks,
		tail:   tailBatch,
	}
	if err := runtime.Sync(
		daemonTestContext(t),
		authorityDeviceID,
		staleClient,
	); !errors.Is(err, errDaemonReplicationSnapshotRequired) {
		t.Fatalf("Sync(non-advancing snapshot) error = %v", err)
	}
	unchanged, err := replica.View(daemonTestContext(t))
	if err != nil {
		t.Fatalf("View(after non-advancing snapshot): %v", err)
	}
	if unchanged.Heads != targetView.Heads ||
		unchanged.ProjectionStateDigest !=
			targetView.ProjectionStateDigest {
		t.Fatal("non-advancing snapshot changed settled state")
	}
	if err := replica.Close(); err != nil {
		t.Fatalf("Close(replica): %v", err)
	}
	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: targetPath},
	)
	if err != nil {
		t.Fatalf("store.Open(recovered target): %v", err)
	}
	defer reopened.Close()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(target): %v", err)
	}
	entries, err := os.ReadDir(scratchRoot)
	if err != nil {
		t.Fatalf("ReadDir(snapshot scratch): %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("snapshot scratch retained quarantine entries: %v", entries)
	}
}

func TestValidateDaemonInstalledSnapshotCutRejectsEveryMutation(t *testing.T) {
	input, installed := daemonSnapshotRecoveryInstalledCutFixture(t)
	if err := validateDaemonInstalledSnapshotCut(installed, input); err != nil {
		t.Fatalf("valid installed cut: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*store.StandaloneLogicalSnapshotInstallResult)
	}{
		{"cut_session", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.SessionID = ""
		}},
		{"cut_workspace", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.WorkspaceID = ""
		}},
		{"cut_recovery_generation", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.RecoveryGeneration++
		}},
		{"cut_checkpoint", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.CheckpointEventID = ""
		}},
		{"cut_chain_index", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ChainIndex++
		}},
		{"cut_chain_hash", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ChainHash[0] ^= 0xff
		}},
		{"cut_result_index", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ResultIndex++
		}},
		{"cut_result_hash", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ResultHash[0] ^= 0xff
		}},
		{"cut_projection_accumulator", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ProjectionAccumulator[0] ^= 0xff
		}},
		{"cut_projection_state_digest", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ProjectionStateDigest[0] ^= 0xff
		}},
		{"cut_authority_version", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.AuthorityVersion++
		}},
		{"cut_signer", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.SignerDeviceID = daemonContentTestDeviceID(t, 0xe2)
		}},
		{"cut_digest_version", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.DigestVersion++
		}},
		{"cut_projection_schema_version", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.ProjectionSchemaVersion++
		}},
		{"cut_record_count", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Cut.RecordCount++
		}},
		{"heads_chain_index", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ChainIndex++
		}},
		{"heads_chain_hash", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ChainHash[0] ^= 0xff
		}},
		{"heads_result_index", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ResultIndex++
		}},
		{"heads_result_hash", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ResultHash[0] ^= 0xff
		}},
		{"heads_projection_accumulator", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ProjectionAccumulator[0] ^= 0xff
		}},
		{"heads_digest_version", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.DigestVersion++
		}},
		{"heads_projection_schema_version", func(value *store.StandaloneLogicalSnapshotInstallResult) {
			value.Heads.ProjectionSchemaVersion++
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := installed
			mutation.mutate(&changed)
			if err := validateDaemonInstalledSnapshotCut(
				changed,
				input,
			); err == nil {
				t.Fatal("mutated installed cut was accepted")
			}
		})
	}
}

func TestDaemonSettledReplicationLatchesPostInstallCutMismatch(
	t *testing.T,
) {
	input, installed := daemonSnapshotRecoveryInstalledCutFixture(t)
	replica := &daemonSettledReplicaStub{}
	runtime := newDaemonSettledReplicationTestRuntime(t, replica)

	replica.heads = installed.Heads
	installed.Cut.ProjectionStateDigest[0] ^= 0xff
	first := runtime.validateInstalledSnapshotCut(installed, input)
	if !errors.Is(first, errDaemonContentPeerState) {
		t.Fatalf("post-install mismatch = %v, want permanent state error", first)
	}
	changedHeads := replica.heads
	if changedHeads.ResultIndex == 0 {
		t.Fatal("fault injection did not model committed changed state")
	}

	client := &daemonReplicationClientStub{
		batches: []replication.Batch{
			daemonSettledReplicationTestBatch(t, changedHeads.ResultIndex+1),
		},
	}
	second := runtime.Sync(
		context.Background(),
		daemonContentTestDeviceID(t, 0xe3),
		client,
	)
	if second != first {
		t.Fatalf("retry error = %v, want original fatal error %v", second, first)
	}
	if len(client.after) != 0 ||
		len(replica.forgotten) != 0 ||
		replica.heads != changedHeads {
		t.Fatalf(
			"retry continued after fatal mismatch: requests %v, forgotten %v, heads %+v",
			client.after,
			replica.forgotten,
			replica.heads,
		)
	}
}

func daemonSnapshotRecoveryInstalledCutFixture(
	t *testing.T,
) (
	logicalsnapshot.RootInput,
	store.StandaloneLogicalSnapshotInstallResult,
) {
	t.Helper()
	input := logicalsnapshot.RootInput{
		SessionID:               daemonTestSessionID,
		WorkspaceID:             daemonTestWorkspaceID,
		RecoveryGeneration:      1,
		CheckpointEventID:       daemonSnapshotRecoveryCheckpointEventID,
		ChainIndex:              7,
		ChainHash:               [sha256.Size]byte{0x11},
		ResultIndex:             9,
		ResultHash:              [sha256.Size]byte{0x22},
		ProjectionAccumulator:   [sha256.Size]byte{0x33},
		ProjectionStateDigest:   [sha256.Size]byte{0x44},
		AuthorityVersion:        3,
		SignerDeviceID:          daemonContentTestDeviceID(t, 0xe1),
		DigestVersion:           logicalsnapshot.SupportedDigestVersion,
		ProjectionSchemaVersion: logicalsnapshot.SupportedProjectionSchemaVersion,
		RecordCount:             12,
	}
	cut := store.LogicalSnapshotCut{
		SessionID:               input.SessionID,
		WorkspaceID:             input.WorkspaceID,
		RecoveryGeneration:      input.RecoveryGeneration,
		CheckpointEventID:       input.CheckpointEventID,
		ChainIndex:              input.ChainIndex,
		ChainHash:               store.Digest(input.ChainHash),
		ResultIndex:             input.ResultIndex,
		ResultHash:              store.Digest(input.ResultHash),
		ProjectionAccumulator:   store.Digest(input.ProjectionAccumulator),
		ProjectionStateDigest:   store.Digest(input.ProjectionStateDigest),
		AuthorityVersion:        input.AuthorityVersion,
		SignerDeviceID:          input.SignerDeviceID,
		DigestVersion:           input.DigestVersion,
		ProjectionSchemaVersion: input.ProjectionSchemaVersion,
		RecordCount:             input.RecordCount,
	}
	return input, store.StandaloneLogicalSnapshotInstallResult{
		Cut: cut,
		Heads: store.ApplyHeads{
			ChainIndex:              cut.ChainIndex,
			ChainHash:               cut.ChainHash,
			ResultIndex:             cut.ResultIndex,
			ResultHash:              cut.ResultHash,
			ProjectionAccumulator:   cut.ProjectionAccumulator,
			DigestVersion:           cut.DigestVersion,
			ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
		},
	}
}

func TestDaemonSettledSnapshotStartupCleansAllAbandonedAttempts(
	t *testing.T,
) {
	root := filepath.Join(t.TempDir(), "snapshot-scratch")
	now := time.Now()
	if err := prepareDaemonSettledSnapshotScratchAt(root, now); err != nil {
		t.Fatalf("prepare initial scratch root: %v", err)
	}

	staleAttempt := filepath.Join(
		root,
		daemonSettledSnapshotAttemptPrefix+"crashed",
	)
	activeAttempt := filepath.Join(
		root,
		daemonSettledSnapshotAttemptPrefix+"active",
	)
	cache := filepath.Join(
		root,
		daemonSettledSnapshotCachePrefix+
			strings.Repeat("a", sha256.Size*2),
	)
	for _, directory := range []string{
		staleAttempt,
		activeAttempt,
		cache,
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", directory, err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, "sentinel"),
			[]byte("retained"),
			0o600,
		); err != nil {
			t.Fatalf("WriteFile(%s): %v", directory, err)
		}
	}
	if err := os.Chtimes(
		cache,
		now.Add(-time.Hour),
		now.Add(-time.Hour),
	); err != nil {
		t.Fatalf("mark cache active: %v", err)
	}

	if err := prepareDaemonSettledSnapshotRecoveryScratchAt(
		root,
		now,
	); err != nil {
		t.Fatalf("prepare recovered scratch root: %v", err)
	}
	for _, directory := range []string{staleAttempt, activeAttempt} {
		if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("abandoned attempt %s still exists: %v", directory, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(cache, "sentinel"))
	if err != nil || string(content) != "retained" {
		t.Fatalf("retained cache = (%q, %v)", content, err)
	}
}

func buildDaemonSnapshotRecoveryArtifact(
	t *testing.T,
	source snapshotbuilder.RecordSource,
	checkpointEventID domain.UUIDv7,
	signerDeviceID domain.DeviceID,
	privateKey ed25519.PrivateKey,
) (
	snapshotbuilder.Snapshot,
	[]logicalsnapshot.DescriptorPage,
	[][]byte,
) {
	t.Helper()
	artifact, err := os.CreateTemp(t.TempDir(), "snapshot-artifact-*")
	if err != nil {
		t.Fatalf("CreateTemp(artifact): %v", err)
	}
	defer artifact.Close()
	sequence, err := os.CreateTemp(t.TempDir(), "snapshot-sequence-*")
	if err != nil {
		t.Fatalf("CreateTemp(sequence): %v", err)
	}
	defer sequence.Close()
	var pages []logicalsnapshot.DescriptorPage
	var chunks [][]byte
	snapshot, err := snapshotbuilder.Build(
		daemonTestContext(t),
		source,
		snapshotbuilder.Options{
			ArtifactID:        "snapshot-recovery-test",
			CheckpointEventID: checkpointEventID,
			SignerDeviceID:    signerDeviceID,
			SignerPublicKey: bytes.Clone(
				privateKey.Public().(ed25519.PublicKey),
			),
			ArtifactScratch: artifact,
			SequenceScratch: sequence,
			ChunkSink: func(
				_ context.Context,
				_ logicalsnapshot.ChunkDescriptor,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err == nil {
					chunks = append(chunks, encoded)
				}
				return err
			},
			PageSink: func(
				_ context.Context,
				page logicalsnapshot.DescriptorPage,
				content io.Reader,
			) error {
				encoded, err := io.ReadAll(content)
				if err != nil {
					return err
				}
				if !bytes.Equal(encoded, page.CanonicalBytes()) {
					return errors.New("descriptor page bytes changed")
				}
				pages = append(pages, page)
				return nil
			},
			SignRoot: func(
				_ context.Context,
				unsigned logicalsnapshot.UnsignedRoot,
			) (logicalsnapshot.Root, error) {
				return logicalsnapshot.SignRoot(unsigned, privateKey)
			},
		},
	)
	if err != nil {
		t.Fatalf("snapshotbuilder.Build(): %v", err)
	}
	return snapshot, pages, chunks
}

func daemonSnapshotRecoveryTaskEvent(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) event.SignedEvent {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		deviceID,
		daemonTestSetupBootID,
	)
	if err != nil {
		t.Fatalf("NewLocalAuthority(): %v", err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatalf("OperatorBinding(): %v", err)
	}
	payload := []byte(`{"priority":2,"title":"tail after logical snapshot"}`)
	proposal, err := event.BuildProposal(
		event.Command{
			Kind: event.KindTaskCreated,
			EntityID: event.StringEntityID(
				string(daemonSnapshotRecoveryTailTaskID),
			),
			Actions: []event.Action{},
			Payload: payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        daemonSnapshotRecoveryTailEventID,
			SessionID:      daemonTestSessionID,
			WorkspaceID:    daemonTestWorkspaceID,
			CreatedAt:      daemonTestTimestamp,
			OriginSequence: 2,
		},
	)
	if err != nil {
		t.Fatalf("BuildProposal(tail): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign(tail): %v", err)
	}
	return signed
}

var _ consensus.CheckpointOrigin = (*daemonSnapshotRecoveryOrigin)(nil)
