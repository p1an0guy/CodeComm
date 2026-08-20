package consensus

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestSettledReplicaImportsRelayedBatchWithoutRaftProvenance(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	before, err := fixture.replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	beforeRevision := before.AdmissionRevision

	got, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	)
	if err != nil {
		t.Fatalf("ImportResultBatch(): %v", err)
	}
	if got.Heads != fixture.finalApplyHeads ||
		got.AttestationID != fixture.batch.AttestationID() ||
		got.AdmissionRevision != beforeRevision+1 {
		t.Fatalf("import result = %+v", got)
	}
	if fixture.relayDeviceID == fixture.signerDeviceID {
		t.Fatal("test relay unexpectedly equals the batch signer")
	}

	sourceView, err := fixture.source.View(testContext(t))
	if err != nil {
		t.Fatalf("source View(): %v", err)
	}
	targetView, err := fixture.replica.View(testContext(t))
	if err != nil {
		t.Fatalf("target View(): %v", err)
	}
	if targetView.Heads != sourceView.Heads ||
		targetView.ProjectionStateDigest != sourceView.ProjectionStateDigest ||
		targetView.CurrentTerm != nil ||
		targetView.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"target/source mismatch:\ntarget=%+v\nsource=%+v",
			targetView,
			sourceView,
		)
	}
	if err := fixture.replica.state.VerifyCommitmentHistory(
		testContext(t),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(): %v", err)
	}
	if err := fixture.replica.state.VerifyRaftCommand(
		testContext(t),
		1,
		1,
		fixture.first,
	); !errors.Is(err, store.ErrRaftCommandBinding) {
		t.Fatalf(
			"VerifyRaftCommand(imported event) error = %v, want no binding",
			err,
		)
	}
	admission, err := fixture.replica.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(): %v", err)
	}
	if index, valid := admission.AppliedChainIndex(); !valid ||
		index != sourceView.Heads.ChainIndex {
		t.Fatalf(
			"admission chain index = (%d, %t), want %d",
			index,
			valid,
			sourceView.Heads.ChainIndex,
		)
	}

	if err := fixture.replica.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:    fixture.targetPath,
			OriginBootID: nodeTestBootID1,
			Clock:        nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(reopen): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedView, err := reopened.View(testContext(t))
	if err != nil {
		t.Fatalf("View(reopened): %v", err)
	}
	if reopenedView.Heads != targetView.Heads ||
		reopenedView.ProjectionStateDigest != targetView.ProjectionStateDigest {
		t.Fatalf("reopened view = %+v, want %+v", reopenedView, targetView)
	}
}

func TestSettledReplicaFailedReplayLeavesDurableCutUnchanged(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	before, err := fixture.replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	tamperedInput := fixture.batch.Unsigned().Input()
	first, err := chain.DecodeResult(tamperedInput.Results[0])
	if err != nil {
		t.Fatalf("chain.DecodeResult(): %v", err)
	}
	first.Outcome = []byte(`{"code":"entity_not_found","status":"accepted"}`)
	tamperedInput.Results[0], err = chain.EncodeResult(first)
	if err != nil {
		t.Fatalf("chain.EncodeResult(): %v", err)
	}
	rebuildReplayResultHead(t, &tamperedInput)
	tampered := signReplayInput(
		t,
		tamperedInput,
		fixture.signerPrivateKey,
	)

	if _, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		tampered,
	); !errors.Is(err, ErrReplicationOutcomeMismatch) {
		t.Fatalf(
			"ImportResultBatch(tampered) error = %v, want outcome mismatch",
			err,
		)
	}
	after, err := fixture.replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(after failed replay): %v", err)
	}
	if after.Heads != before.Heads ||
		after.ProjectionStateDigest != before.ProjectionStateDigest ||
		after.AdmissionRevision != before.AdmissionRevision {
		t.Fatalf(
			"failed replay changed durable cut:\nbefore=%+v\nafter=%+v",
			before,
			after,
		)
	}

	if _, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	); err != nil {
		t.Fatalf("ImportResultBatch(valid after failure): %v", err)
	}
}

func TestSettledReplicaLocalCorruptionLatchesFatalState(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	heldLocal, err := fixture.replica.LocalState()
	if err != nil {
		t.Fatalf("LocalState(before fatal): %v", err)
	}
	sameLocal, err := fixture.replica.LocalState()
	if err != nil || sameLocal != heldLocal {
		t.Fatalf(
			"LocalState capability identity changed: equal=%t err=%v",
			sameLocal == heldLocal,
			err,
		)
	}
	if _, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	); err != nil {
		t.Fatalf("ImportResultBatch(): %v", err)
	}
	tamperSQLite(
		t,
		fixture.targetPath,
		`UPDATE tasks SET blocked_by_json = '["invalid"]';`,
	)

	_, err = fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	)
	if !errors.Is(err, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"ImportResultBatch(corrupt local state) error = %v, want integrity failure",
			err,
		)
	}
	if fatal := fixture.replica.FatalError(); !errors.Is(
		fatal,
		store.ErrCommandResultCorrupt,
	) {
		t.Fatalf("FatalError() = %v, want integrity failure", fatal)
	}
	if snapshot, snapshotErr := fixture.replica.PeerAdmissionSnapshot(); snapshot != nil || !errors.Is(snapshotErr, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"PeerAdmissionSnapshot() = (%v, %v), want fatal refusal",
			snapshot,
			snapshotErr,
		)
	}
	if _, localErr := fixture.replica.LocalState(); !errors.Is(
		localErr,
		store.ErrCommandResultCorrupt,
	) {
		t.Fatalf("LocalState() error = %v, want fatal refusal", localErr)
	}
	if _, localErr := heldLocal.AllocateOwnEndpointSequence(
		testContext(t),
		fixture.signerDeviceID,
		nodeTestTimestamp2,
	); !errors.Is(localErr, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"pre-fatal LocalState write error = %v, want fatal refusal",
			localErr,
		)
	}
}

func TestSettledReplicaCoherentLocalRewriteLatchesFatalState(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	tamperSQLite(
		t,
		fixture.targetPath,
		`UPDATE devices SET daemon_version = '0.2.0';`,
	)

	_, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	)
	if !errors.Is(err, store.ErrCommandResultCorrupt) {
		t.Fatalf(
			"ImportResultBatch(coherent local rewrite) error = %v, want integrity failure",
			err,
		)
	}
	if fatal := fixture.replica.FatalError(); !errors.Is(
		fatal,
		store.ErrCommandResultCorrupt,
	) {
		t.Fatalf("FatalError() = %v, want integrity failure", fatal)
	}
}

func TestSettledReplicaFatalPublicationExcludesAdmissionReaders(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	terminal := errors.New("terminal integrity failure")

	fixture.replica.admissionMu.Lock()
	result := make(chan error, 1)
	go func() {
		snapshot, err := fixture.replica.PeerAdmissionSnapshot()
		if snapshot != nil {
			result <- errors.New("admission snapshot remained available")
			return
		}
		result <- err
	}()
	fixture.replica.recordFatalLocked(terminal)
	fixture.replica.admissionMu.Unlock()

	if err := <-result; !errors.Is(err, terminal) {
		t.Fatalf("PeerAdmissionSnapshot() error = %v, want %v", err, terminal)
	}
}

func TestOpenSettledReplicaRejectsRaftEvidenceMode(t *testing.T) {
	initial, _, _ := nodeTestInitialState(t)
	path := filepath.Join(t.TempDir(), "state", "state.db")
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	if _, err := database.Initialize(context.Background(), initial); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:    path,
			OriginBootID: nodeTestBootID1,
		},
	); !errors.Is(err, store.ErrReplicaEvidenceMode) {
		t.Fatalf(
			"OpenSettledReplica(Raft evidence) error = %v, want mode error",
			err,
		)
	}
}

func TestSettledReplicaImportsAndReopensAuthorityHandoff(t *testing.T) {
	source, origin := openVoterActivationCommitNode(t)
	start, err := source.View(testContext(t))
	if err != nil {
		t.Fatalf("source View(start): %v", err)
	}
	if err := source.ReconcileVoterSet(testContext(t)); err != nil {
		t.Fatalf("ReconcileVoterSet(): %v", err)
	}
	if err := source.Barrier(testContext(t)); err != nil {
		t.Fatalf("Barrier(): %v", err)
	}
	end, err := source.View(testContext(t))
	if err != nil {
		t.Fatalf("source View(end): %v", err)
	}
	batch := signedReplayBatch(
		t,
		source.state,
		start.Heads.ResultIndex,
		origin.deviceID,
		origin.private,
	)

	initial, _, deviceID := nodeTestInitialState(t)
	if deviceID != origin.deviceID {
		t.Fatal("deterministic authority identity changed")
	}
	targetSet, err := voterset.New(
		nodeTestSessionID,
		[]domain.DeviceID{deviceID},
		2,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	initial.Projections.VoterSet = []voterset.Set{targetSet}
	path := filepath.Join(t.TempDir(), "handoff-target", "state.db")
	database, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(target): %v", err)
	}
	if _, err := database.Initialize(
		context.Background(),
		initial,
	); err != nil {
		t.Fatalf("Initialize(target): %v", err)
	}
	if _, err := database.EnterSettledNonvoter(
		context.Background(),
		nodeTestTimestamp1,
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}

	replica, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:    path,
			OriginBootID: nodeTestBootID1,
			Clock:        nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	relayPrivate := ed25519.NewKeyFromSeed(
		make([]byte, ed25519.SeedSize),
	)
	relayID, err := device.DeriveID(
		relayPrivate.Public().(ed25519.PublicKey),
	)
	clear(relayPrivate)
	if err != nil {
		t.Fatalf("derive relay ID: %v", err)
	}
	imported, err := replica.ImportResultBatch(
		testContext(t),
		relayID,
		batch,
	)
	if err != nil {
		t.Fatalf("ImportResultBatch(handoff): %v", err)
	}
	assertReplayHeadsEqual(t, imported.Heads, end.Heads)
	if err := replica.Close(); err != nil {
		t.Fatalf("Close(imported): %v", err)
	}

	reopened, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:    path,
			OriginBootID: nodeTestBootID1,
			Clock:        nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(reopen handoff): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedView, err := reopened.View(testContext(t))
	if err != nil {
		t.Fatalf("View(reopened): %v", err)
	}
	decoded, err := decodeStateView(reopenedView)
	if err != nil {
		t.Fatalf("decodeStateView(reopened): %v", err)
	}
	if decoded.CredentialAuthority.VoterSetVersion != 2 ||
		decoded.CredentialAuthority.PriorAuthorityHandoff == nil ||
		decoded.CredentialAuthority.PriorAuthoritySigner != deviceID {
		t.Fatalf(
			"reopened authority = %+v",
			decoded.CredentialAuthority,
		)
	}
}

type settledReplicaImportFixture struct {
	source           *SingleNode
	replica          *SettledReplica
	targetPath       string
	signerPrivateKey ed25519.PrivateKey
	signerDeviceID   domain.DeviceID
	relayDeviceID    domain.DeviceID
	first            event.SignedEvent
	batch            replication.Batch
	finalApplyHeads  store.ApplyHeads
}

func newSettledReplicaImportFixture(
	t *testing.T,
) settledReplicaImportFixture {
	t.Helper()
	source, signerPrivateKey, signerDeviceID :=
		openApplyAtGenerationTestNode(t)
	start, err := source.View(testContext(t))
	if err != nil {
		t.Fatalf("source View(start): %v", err)
	}
	first := nodeTestTaskEvent(
		t,
		signerPrivateKey,
		signerDeviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"replicated task",
	)
	if _, err := source.Apply(testContext(t), first); err != nil {
		t.Fatalf("source Apply(first): %v", err)
	}
	second := nodeTestTaskEvent(
		t,
		signerPrivateKey,
		signerDeviceID,
		nodeTestBootID1,
		nodeTestEventID2,
		nodeTestTaskID1,
		nodeTestTimestamp2,
		2,
		"duplicate task",
	)
	final, err := source.Apply(testContext(t), second)
	if err != nil {
		t.Fatalf("source Apply(second): %v", err)
	}
	if final.Outcome.Status != store.OutcomeRejected ||
		final.Outcome.Code != string(reducer.CodeEntityAlreadyExists) {
		t.Fatalf("second outcome = %+v", final.Outcome)
	}
	batch := signedReplayBatch(
		t,
		source.state,
		start.Heads.ResultIndex,
		signerDeviceID,
		signerPrivateKey,
	)

	initial, _, initialDeviceID := nodeTestInitialState(t)
	if initialDeviceID != signerDeviceID {
		t.Fatal("deterministic initial signer changed")
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
		t.Fatalf("target Initialize(): %v", err)
	}
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		domain.Timestamp("2026-08-19T20:00:00Z"),
	); err != nil {
		t.Fatalf("target EnterSettledNonvoter(): %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("target Close(): %v", err)
	}
	replica, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:    targetPath,
			OriginBootID: nodeTestBootID1,
			Clock:        nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	t.Cleanup(func() { _ = replica.Close() })

	relayPrivateKey := ed25519.NewKeyFromSeed(
		make([]byte, ed25519.SeedSize),
	)
	relayDeviceID, err := device.DeriveID(
		relayPrivateKey.Public().(ed25519.PublicKey),
	)
	clear(relayPrivateKey)
	if err != nil {
		t.Fatalf("device.DeriveID(relay): %v", err)
	}
	return settledReplicaImportFixture{
		source:           source,
		replica:          replica,
		targetPath:       targetPath,
		signerPrivateKey: signerPrivateKey,
		signerDeviceID:   signerDeviceID,
		relayDeviceID:    relayDeviceID,
		first:            first,
		batch:            batch,
		finalApplyHeads:  final.Heads,
	}
}
