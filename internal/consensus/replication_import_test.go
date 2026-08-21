package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/replication"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
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
	status, err := fixture.replica.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if status.Runtime.ReplicaCurrency !=
		coordstatus.ReplicaCurrencyUnknown ||
		len(status.Runtime.ObservedAuthorityIDs) != 0 ||
		status.Runtime.ObservedResultIndex != 0 {
		t.Fatalf("settled replica currency = %+v", status.Runtime)
	}

	if err := fixture.replica.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:     fixture.targetPath,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: fixture.settledDeviceID,
			Clock:         nodeTestClock(),
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
	reopenedStatus, err := reopened.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status(reopened): %v", err)
	}
	if reopenedStatus.Runtime.ReplicaCurrency !=
		coordstatus.ReplicaCurrencyUnknown ||
		len(reopenedStatus.Runtime.ObservedAuthorityIDs) != 0 ||
		reopenedStatus.Runtime.ObservedResultIndex != 0 {
		t.Fatalf(
			"reopened replica retained live currency = %+v",
			reopenedStatus.Runtime,
		)
	}
}

func TestSettledReplicaAcknowledgementRequiresLiveRelayObservation(
	t *testing.T,
) {
	fixture := newSettledReplicaImportFixture(t)
	if _, err := fixture.replica.ImportResultBatch(
		testContext(t),
		fixture.relayDeviceID,
		fixture.batch,
	); err != nil {
		t.Fatalf("ImportResultBatch(): %v", err)
	}
	fixture.replica.ForgetReplicationPeer(fixture.relayDeviceID)
	assertSettledReplicaCurrency(
		t,
		fixture.replica,
		coordstatus.ReplicaCurrencyUnknown,
		nil,
		0,
	)

	acknowledgement := settledReplicaTestAcknowledgement(t, fixture)
	if err := fixture.replica.ObserveReplicationAcknowledgement(
		testContext(t),
		fixture.relayDeviceID,
		acknowledgement,
	); err != nil {
		t.Fatalf("ObserveReplicationAcknowledgement(relayed): %v", err)
	}
	assertSettledReplicaCurrency(
		t,
		fixture.replica,
		coordstatus.ReplicaCurrencyUnknown,
		nil,
		0,
	)
	if err := fixture.replica.ObserveReplicationAcknowledgement(
		testContext(t),
		fixture.signerDeviceID,
		acknowledgement,
	); err != nil {
		t.Fatalf("ObserveReplicationAcknowledgement(direct): %v", err)
	}
	assertSettledReplicaCurrency(
		t,
		fixture.replica,
		coordstatus.ReplicaCurrencyCurrent,
		[]domain.DeviceID{fixture.signerDeviceID},
		fixture.finalApplyHeads.ResultIndex,
	)
	progress, err := fixture.replica.ReplicationProgress(testContext(t))
	if err != nil {
		t.Fatalf("ReplicationProgress(): %v", err)
	}
	if len(progress.Observations) != 1 ||
		progress.Observations[0].SignerDeviceID !=
			fixture.signerDeviceID ||
		progress.Observations[0].VerifiedResultIndex !=
			fixture.finalApplyHeads.ResultIndex {
		t.Fatalf("durable acknowledgement progress = %+v", progress)
	}

	fixture.replica.ForgetReplicationPeer(fixture.signerDeviceID)
	assertSettledReplicaCurrency(
		t,
		fixture.replica,
		coordstatus.ReplicaCurrencyUnknown,
		nil,
		0,
	)
}

func TestSettledReplicaRejectsInvalidAcknowledgementWithoutCurrency(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(
			*testing.T,
			settledReplicaImportFixture,
			replication.Acknowledgement,
		) replication.Acknowledgement
	}{
		{
			name: "wrong commitment cut",
			mutate: func(
				t *testing.T,
				fixture settledReplicaImportFixture,
				valid replication.Acknowledgement,
			) replication.Acknowledgement {
				input := valid.Unsigned().Input()
				input.ResultHash[0] ^= 0xff
				unsigned, err := replication.NewUnsignedAcknowledgement(
					input,
				)
				if err != nil {
					t.Fatal(err)
				}
				changed, err := replication.SignAcknowledgement(
					unsigned,
					fixture.signerPrivateKey,
				)
				if err != nil {
					t.Fatal(err)
				}
				return changed
			},
		},
		{
			name: "invalid identity signature",
			mutate: func(
				t *testing.T,
				_ settledReplicaImportFixture,
				valid replication.Acknowledgement,
			) replication.Acknowledgement {
				signature := valid.Signature()
				signature[0] ^= 0xff
				changed, err := replication.NewAcknowledgement(
					valid.Unsigned(),
					signature,
				)
				if err != nil {
					t.Fatal(err)
				}
				return changed
			},
		},
		{
			name: "unauthorized signer",
			mutate: func(
				t *testing.T,
				_ settledReplicaImportFixture,
				valid replication.Acknowledgement,
			) replication.Acknowledgement {
				privateKey := ed25519.NewKeyFromSeed(
					bytes.Repeat([]byte{0xe7}, ed25519.SeedSize),
				)
				defer clear(privateKey)
				serverID, err := device.DeriveID(
					privateKey.Public().(ed25519.PublicKey),
				)
				if err != nil {
					t.Fatal(err)
				}
				input := valid.Unsigned().Input()
				input.ServerDeviceID = serverID
				unsigned, err := replication.NewUnsignedAcknowledgement(
					input,
				)
				if err != nil {
					t.Fatal(err)
				}
				changed, err := replication.SignAcknowledgement(
					unsigned,
					privateKey,
				)
				if err != nil {
					t.Fatal(err)
				}
				return changed
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSettledReplicaImportFixture(t)
			if _, err := fixture.replica.ImportResultBatch(
				testContext(t),
				fixture.relayDeviceID,
				fixture.batch,
			); err != nil {
				t.Fatalf("ImportResultBatch(): %v", err)
			}
			fixture.replica.ForgetReplicationPeer(
				fixture.relayDeviceID,
			)
			acknowledgement := test.mutate(
				t,
				fixture,
				settledReplicaTestAcknowledgement(t, fixture),
			)
			if err := fixture.replica.
				ObserveReplicationAcknowledgement(
					testContext(t),
					fixture.relayDeviceID,
					acknowledgement,
				); !errors.Is(err, ErrInvalidReplicationReplay) {
				t.Fatalf(
					"ObserveReplicationAcknowledgement() error = %v, want %v",
					err,
					ErrInvalidReplicationReplay,
				)
			}
			if err := fixture.replica.FatalError(); err != nil {
				t.Fatalf("invalid peer input latched fatal state: %v", err)
			}
			assertSettledReplicaCurrency(
				t,
				fixture.replica,
				coordstatus.ReplicaCurrencyUnknown,
				nil,
				0,
			)
		})
	}
}

func TestSettledReplicaRejectsRelayedSignaturesAsLiveEvidence(t *testing.T) {
	relayID := settledReplicaTestMemberWithSeed(t, 0xd4).ID
	signerID := settledReplicaTestMemberWithSeed(t, 0xd5).ID
	replica := &SettledReplica{
		replicationObservations: make(
			map[domain.DeviceID]liveReplicationObservation,
		),
	}
	replica.recordLiveReplicationObservation(
		relayID,
		signerID,
		2,
		7,
		9,
	)
	if got := replica.liveReplicationObservationSnapshot(); len(got) != 0 {
		t.Fatalf("relayed signature became live evidence = %+v", got)
	}
	replica.recordLiveReplicationObservation(
		signerID,
		signerID,
		2,
		7,
		9,
	)
	replica.recordLiveReplicationObservation(
		signerID,
		signerID,
		1,
		6,
		8,
	)
	got := replica.liveReplicationObservationSnapshot()
	if len(got) != 1 ||
		got[0].RelayPeerID != signerID ||
		got[0].SignerDeviceID != signerID ||
		got[0].AuthorityVersion != 2 ||
		got[0].VerifiedResultIndex != 7 {
		t.Fatalf("direct signer observations = %+v", got)
	}
	replica.ForgetReplicationPeer(signerID)
	if got := replica.liveReplicationObservationSnapshot(); len(got) != 0 {
		t.Fatalf("forgotten direct observation = %+v", got)
	}
}

func TestSettledReplicaCurrencyRequiresEveryAuthorityAtExactCut(
	t *testing.T,
) {
	firstID := settledReplicaTestMemberWithSeed(t, 0xd5).ID
	secondID := settledReplicaTestMemberWithSeed(t, 0xd6).ID
	authorityIDs := []domain.DeviceID{firstID, secondID}
	slices.Sort(authorityIDs)
	progress := store.SettledReplicationProgress{
		Heads: store.ApplyHeads{ResultIndex: 10},
	}
	live := []liveReplicationObservation{
		{
			SignerDeviceID:           firstID,
			AuthorityVersion:         2,
			VerifiedResultIndex:      10,
			ServerAppliedResultIndex: 10,
		},
		{
			SignerDeviceID:           secondID,
			AuthorityVersion:         2,
			VerifiedResultIndex:      9,
			ServerAppliedResultIndex: 9,
		},
	}
	currency, observed, resultIndex := settledReplicaCurrency(
		progress,
		live,
		authorityIDs,
		2,
	)
	if currency != coordstatus.ReplicaCurrencyUnknown ||
		!slices.Equal(observed, authorityIDs) ||
		resultIndex != 10 {
		t.Fatalf(
			"stale authority currency = %s/%v/%d",
			currency,
			observed,
			resultIndex,
		)
	}

	live[1].VerifiedResultIndex = 10
	live[1].ServerAppliedResultIndex = 10
	currency, observed, resultIndex = settledReplicaCurrency(
		progress,
		live,
		authorityIDs,
		2,
	)
	if currency != coordstatus.ReplicaCurrencyCurrent ||
		!slices.Equal(observed, authorityIDs) ||
		resultIndex != 10 {
		t.Fatalf(
			"exact authority currency = %s/%v/%d",
			currency,
			observed,
			resultIndex,
		)
	}

	live[1].ServerAppliedResultIndex = 11
	currency, observed, resultIndex = settledReplicaCurrency(
		progress,
		live,
		authorityIDs,
		2,
	)
	if currency != coordstatus.ReplicaCurrencyBehind ||
		!slices.Equal(observed, authorityIDs) ||
		resultIndex != 11 {
		t.Fatalf(
			"ahead authority currency = %s/%v/%d",
			currency,
			observed,
			resultIndex,
		)
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

func TestSettledReplicaCommitsSelfRevocationBeforeBecomingIneligible(
	t *testing.T,
) {
	settledMember := settledReplicaTestMember(t)
	source, ownerPrivateKey, ownerDeviceID :=
		openApplyAtGenerationTestNodeWithInitial(
			t,
			func(initial *store.InitialState) {
				addSettledReplicaTestMember(initial, settledMember)
			},
		)
	start, err := source.View(testContext(t))
	if err != nil {
		t.Fatalf("source View(start): %v", err)
	}
	revocation := nodeTestMembershipEvent(
		t,
		ownerPrivateKey,
		ownerDeviceID,
		event.KindMembershipDeviceRevoked,
		settledMember.ID,
		settledMember.EntityVersion,
		map[string]any{
			"device_id":                  settledMember.ID,
			"reason":                     "settled replica retired",
			"voter_set":                  []domain.DeviceID{ownerDeviceID},
			"expected_voter_set_version": uint64(1),
		},
		nodeTestEventID1,
		1,
	)
	applied, err := source.Apply(testContext(t), revocation)
	if err != nil || applied.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("source Apply(revocation) = (%+v, %v)", applied, err)
	}
	batch := signedReplayBatch(
		t,
		source.state,
		start.Heads.ResultIndex,
		ownerDeviceID,
		ownerPrivateKey,
	)

	initial, _, initialOwnerID := nodeTestInitialState(t)
	if initialOwnerID != ownerDeviceID {
		t.Fatal("deterministic owner identity changed")
	}
	addSettledReplicaTestMember(&initial, settledMember)
	targetPath := filepath.Join(t.TempDir(), "target", "state.db")
	target, err := store.Open(
		context.Background(),
		store.Options{Path: targetPath},
	)
	if err != nil {
		t.Fatalf("store.Open(target): %v", err)
	}
	if _, err := target.Initialize(
		context.Background(),
		initial,
	); err != nil {
		t.Fatalf("target Initialize(): %v", err)
	}
	storeSettledReplicaTestConfiguration(
		t,
		target,
		*settledReplicaEligibilityConfiguration(
			ownerDeviceID,
			settledMember.ID,
		),
	)
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		nodeTestTimestamp1,
	); err != nil {
		t.Fatalf("target EnterSettledNonvoter(): %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("target Close(): %v", err)
	}
	replica, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:     targetPath,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: settledMember.ID,
			Clock:         nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	t.Cleanup(func() { _ = replica.Close() })
	imported, err := replica.ImportResultBatch(
		testContext(t),
		ownerDeviceID,
		batch,
	)
	if err != nil {
		t.Fatalf("ImportResultBatch(revocation): %v", err)
	}
	after, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("replica View(after): %v", err)
	}
	if after.Heads.ChainIndex != applied.Heads.ChainIndex ||
		after.Heads.ChainHash != applied.Heads.ChainHash ||
		after.Heads.ResultIndex != applied.Heads.ResultIndex ||
		after.Heads.ResultHash != applied.Heads.ResultHash ||
		after.Heads.ProjectionAccumulator !=
			applied.Heads.ProjectionAccumulator ||
		after.Heads.DigestVersion != applied.Heads.DigestVersion ||
		after.Heads.ProjectionSchemaVersion !=
			applied.Heads.ProjectionSchemaVersion ||
		imported.Heads != applied.Heads ||
		after.AdmissionRevision != imported.AdmissionRevision {
		t.Fatalf(
			"revocation import differs from source:\nsource=%+v\nimport=%+v\nafter=%+v",
			applied,
			imported,
			after,
		)
	}
	admission, err := replica.PeerAdmissionSnapshot()
	if err != nil {
		t.Fatalf("PeerAdmissionSnapshot(): %v", err)
	}
	member, found := admission.Member(settledMember.ID)
	if !found || member.Status != device.StatusRevoked {
		t.Fatalf("revoked admission member = (%+v, %t)", member, found)
	}
	if _, err := replica.ImportResultBatch(
		testContext(t),
		ownerDeviceID,
		batch,
	); !errors.Is(err, ErrSettledReplicaIneligible) {
		t.Fatalf(
			"ImportResultBatch(after revocation) error = %v, want %v",
			err,
			ErrSettledReplicaIneligible,
		)
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
	initial, _, deviceID := nodeTestInitialState(t)
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
			StatePath:     path,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: deviceID,
		},
	); !errors.Is(err, store.ErrReplicaEvidenceMode) {
		t.Fatalf(
			"OpenSettledReplica(Raft evidence) error = %v, want mode error",
			err,
		)
	}
}

func TestOpenSettledReplicaRequiresEligibleApplicationNonvoter(
	t *testing.T,
) {
	tests := []struct {
		name          string
		mutate        func(*testing.T, *store.InitialState, device.Device)
		configuration func(
			domain.DeviceID,
			domain.DeviceID,
		) *raft.Configuration
		localDeviceID func(device.Device) domain.DeviceID
		want          error
	}{
		{
			name:          "eligible",
			configuration: settledReplicaEligibilityConfiguration,
			localDeviceID: func(member device.Device) domain.DeviceID {
				return member.ID
			},
		},
		{
			name:          "missing local device ID",
			configuration: settledReplicaEligibilityConfiguration,
			localDeviceID: func(device.Device) domain.DeviceID {
				return ""
			},
			want: ErrInvalidNodeOptions,
		},
		{
			name: "local device remains in voter target",
			mutate: func(
				t *testing.T,
				initial *store.InitialState,
				member device.Device,
			) {
				t.Helper()
				target, err := voterset.New(
					nodeTestSessionID,
					[]domain.DeviceID{member.ID},
					2,
				)
				if err != nil {
					t.Fatalf("voterset.New(local target): %v", err)
				}
				initial.Projections.VoterSet = []voterset.Set{target}
			},
			configuration: settledReplicaEligibilityConfiguration,
			localDeviceID: func(member device.Device) domain.DeviceID {
				return member.ID
			},
			want: ErrSettledReplicaIneligible,
		},
		{
			name: "local device remains in credential authority",
			mutate: func(
				t *testing.T,
				initial *store.InitialState,
				member device.Device,
			) {
				t.Helper()
				ownerID := initial.Projections.
					CredentialAuthority[0].VoterDeviceIDs[0]
				target, err := voterset.New(
					nodeTestSessionID,
					[]domain.DeviceID{ownerID},
					2,
				)
				if err != nil {
					t.Fatalf("voterset.New(successor target): %v", err)
				}
				initial.Projections.VoterSet = []voterset.Set{target}
				authority := initial.Projections.CredentialAuthority[0]
				authority.VoterDeviceIDs = []domain.DeviceID{
					member.ID,
				}
				initial.Projections.CredentialAuthority =
					[]store.CredentialAuthorityRow{authority}
			},
			configuration: settledReplicaEligibilityConfiguration,
			localDeviceID: func(member device.Device) domain.DeviceID {
				return member.ID
			},
			want: ErrSettledReplicaIneligible,
		},
		{
			name: "local device remains in durable Raft configuration",
			configuration: func(
				ownerID domain.DeviceID,
				localID domain.DeviceID,
			) *raft.Configuration {
				return &raft.Configuration{Servers: []raft.Server{
					{
						Suffrage: raft.Voter,
						ID:       raft.ServerID(ownerID),
						Address:  raft.ServerAddress(ownerID),
					},
					{
						Suffrage: raft.Nonvoter,
						ID:       raft.ServerID(localID),
						Address:  raft.ServerAddress(localID),
					},
				}}
			},
			localDeviceID: func(member device.Device) domain.DeviceID {
				return member.ID
			},
			want: ErrSettledReplicaIneligible,
		},
		{
			name: "durable Raft configuration missing",
			localDeviceID: func(member device.Device) domain.DeviceID {
				return member.ID
			},
			want: ErrSettledReplicaIneligible,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initial, _, ownerID := nodeTestInitialState(t)
			member := settledReplicaTestMember(t)
			addSettledReplicaTestMember(&initial, member)
			if test.mutate != nil {
				test.mutate(t, &initial, member)
			}
			path := filepath.Join(t.TempDir(), "state", "state.db")
			database, err := store.Open(
				context.Background(),
				store.Options{Path: path},
			)
			if err != nil {
				t.Fatalf("store.Open(): %v", err)
			}
			if _, err := database.Initialize(
				context.Background(),
				initial,
			); err != nil {
				t.Fatalf("Initialize(): %v", err)
			}
			if test.configuration != nil {
				configuration := test.configuration(ownerID, member.ID)
				storeSettledReplicaTestConfiguration(
					t,
					database,
					*configuration,
				)
			}
			if _, err := database.EnterSettledNonvoter(
				context.Background(),
				nodeTestTimestamp1,
			); err != nil {
				t.Fatalf("EnterSettledNonvoter(): %v", err)
			}
			if err := database.Close(); err != nil {
				t.Fatalf("Close(setup): %v", err)
			}

			replica, err := OpenSettledReplica(
				context.Background(),
				SettledReplicaOptions{
					StatePath:     path,
					OriginBootID:  nodeTestBootID1,
					LocalDeviceID: test.localDeviceID(member),
					Clock:         nodeTestClock(),
				},
			)
			if test.want == nil {
				if err != nil {
					t.Fatalf("OpenSettledReplica(): %v", err)
				}
				if closeErr := replica.Close(); closeErr != nil {
					t.Fatalf("Close(): %v", closeErr)
				}
				return
			}
			if replica != nil {
				_ = replica.Close()
				t.Fatal("ineligible settled replica returned a runtime")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"OpenSettledReplica() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func settledReplicaEligibilityConfiguration(
	ownerID domain.DeviceID,
	_ domain.DeviceID,
) *raft.Configuration {
	return &raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(ownerID),
		Address:  raft.ServerAddress(ownerID),
	}}}
}

func TestSettledReplicaImportsAndReopensAuthorityHandoff(t *testing.T) {
	settledMember := settledReplicaTestMember(t)
	source, origin := openVoterActivationCommitNodeWithInitial(
		t,
		func(initial *store.InitialState) {
			addSettledReplicaTestMember(initial, settledMember)
		},
	)
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
	addSettledReplicaTestMember(&initial, settledMember)
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
	storeSettledReplicaTestConfiguration(
		t,
		database,
		raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(deviceID),
			Address:  raft.ServerAddress(deviceID),
		}}},
	)
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
			StatePath:     path,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: settledMember.ID,
			Clock:         nodeTestClock(),
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
			StatePath:     path,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: settledMember.ID,
			Clock:         nodeTestClock(),
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
	settledDeviceID  domain.DeviceID
}

func newSettledReplicaImportFixture(
	t *testing.T,
) settledReplicaImportFixture {
	t.Helper()
	settledMember := settledReplicaTestMember(t)
	source, signerPrivateKey, signerDeviceID :=
		openApplyAtGenerationTestNodeWithInitial(
			t,
			func(initial *store.InitialState) {
				addSettledReplicaTestMember(initial, settledMember)
			},
		)
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
	addSettledReplicaTestMember(&initial, settledMember)
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
	storeSettledReplicaTestConfiguration(
		t,
		target,
		raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(signerDeviceID),
			Address:  raft.ServerAddress(signerDeviceID),
		}}},
	)
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
			StatePath:     targetPath,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: settledMember.ID,
			Clock:         nodeTestClock(),
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
		settledDeviceID:  settledMember.ID,
	}
}

func settledReplicaTestAcknowledgement(
	t *testing.T,
	fixture settledReplicaImportFixture,
) replication.Acknowledgement {
	t.Helper()
	view, err := fixture.replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(acknowledgement cut): %v", err)
	}
	batchMetadata := fixture.batch.Unsigned().Metadata()
	unsigned, err := replication.NewUnsignedAcknowledgement(
		replication.AcknowledgementInput{
			SessionID:          view.SessionID,
			WorkspaceID:        view.WorkspaceID,
			RecoveryGeneration: view.RecoveryGeneration,
			ServerDeviceID:     fixture.signerDeviceID,
			ServerAuthorityVersion: batchMetadata.
				ServerAuthorityVersion,
			ResultIndex: view.Heads.ResultIndex,
			ResultHash:  chain.Digest(view.Heads.ResultHash),
			ChainIndex:  view.Heads.ChainIndex,
			ChainHash:   chain.Digest(view.Heads.ChainHash),
			ProjectionAccumulator: chain.Digest(
				view.Heads.ProjectionAccumulator,
			),
			ProjectionStateDigest: chain.Digest(
				view.ProjectionStateDigest,
			),
			ServerAppliedResultIndex: view.Heads.ResultIndex,
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedAcknowledgement(): %v", err)
	}
	acknowledgement, err := replication.SignAcknowledgement(
		unsigned,
		fixture.signerPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignAcknowledgement(): %v", err)
	}
	return acknowledgement
}

func assertSettledReplicaCurrency(
	t *testing.T,
	replica *SettledReplica,
	want coordstatus.ReplicaCurrencyState,
	wantAuthority []domain.DeviceID,
	wantResult uint64,
) {
	t.Helper()
	status, err := replica.Status(testContext(t))
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if status.Runtime.ReplicaCurrency != want ||
		!slices.Equal(
			status.Runtime.ObservedAuthorityIDs,
			wantAuthority,
		) ||
		status.Runtime.ObservedResultIndex != wantResult {
		t.Fatalf(
			"replica currency = %s/%v/%d, want %s/%v/%d",
			status.Runtime.ReplicaCurrency,
			status.Runtime.ObservedAuthorityIDs,
			status.Runtime.ObservedResultIndex,
			want,
			wantAuthority,
			wantResult,
		)
	}
}

func settledReplicaTestMember(t *testing.T) device.Device {
	t.Helper()
	return settledReplicaTestMemberWithSeed(t, 0xd4)
}

func settledReplicaTestMemberWithSeed(
	t *testing.T,
	seed byte,
) device.Device {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
	defer clear(privateKey)
	publicKey := bytes.Clone(
		privateKey.Public().(ed25519.PublicKey),
	)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(settled member): %v", err)
	}
	return device.Device{
		ID:                deviceID,
		Role:              device.RoleEditor,
		IdentityPublicKey: publicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func addSettledReplicaTestMember(
	initial *store.InitialState,
	member device.Device,
) {
	initial.Projections.Devices = append(
		initial.Projections.Devices,
		member,
	)
	sort.Slice(initial.Projections.Devices, func(left, right int) bool {
		return initial.Projections.Devices[left].ID <
			initial.Projections.Devices[right].ID
	})
	initial.Projections.AuditCounters = append(
		initial.Projections.AuditCounters,
		auditcounter.Counter{DeviceID: member.ID},
	)
	sort.Slice(
		initial.Projections.AuditCounters,
		func(left, right int) bool {
			return initial.Projections.AuditCounters[left].DeviceID <
				initial.Projections.AuditCounters[right].DeviceID
		},
	)
}

func storeSettledReplicaTestConfiguration(
	t *testing.T,
	database *store.Store,
	configuration raft.Configuration,
) {
	t.Helper()
	encoded, err := encodeRaftConfiguration(configuration)
	if err != nil {
		t.Fatalf("encodeRaftConfiguration(): %v", err)
	}
	stored, err := database.StoreCommittedRaftConfiguration(
		context.Background(),
		1,
		encoded,
	)
	if err != nil || !stored {
		t.Fatalf(
			"StoreCommittedRaftConfiguration() = (%t, %v)",
			stored,
			err,
		)
	}
}
