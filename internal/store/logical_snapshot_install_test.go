package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/replication"
	"zombiezen.com/go/sqlite"
)

const logicalSnapshotTailEventID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000021",
)

const logicalSnapshotSuccessorCheckpointEventID = domain.UUIDv7(
	"01890f47-3e72-7000-8000-000000000023",
)

func TestInstallStandaloneLogicalSnapshotPersistsEvidenceAndTail(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, root, cut := logicalSnapshotInstallFixture(t)
	localBefore := captureResultBatchImportAtomicSnapshot(
		t,
		fixture.target,
	).local
	if localBefore.requestState != string(LocalRequestSigned) ||
		localBefore.outboxState != "queued" {
		t.Fatalf("pre-install local command = %+v", localBefore)
	}
	if found, err := fixture.target.
		HasVerifiedStandaloneLogicalSnapshotBaseline(
			context.Background(),
		); err != nil || found {
		t.Fatalf(
			"pre-install standalone baseline = (%t, %v), want false",
			found,
			err,
		)
	}
	if baseline, found, err := fixture.target.
		VerifiedStandaloneLogicalSnapshotBaseline(
			context.Background(),
		); err != nil || found || len(baseline.CanonicalBytes()) != 0 {
		t.Fatalf(
			"pre-install signed baseline = (%x, %t, %v), want absent",
			baseline.CanonicalBytes(),
			found,
			err,
		)
	}
	beforeRevision := fixture.target.AdmissionRevision()

	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	wantHeads := fixture.request.Commands[len(fixture.request.Commands)-1].Heads
	wantHeads.PreviousResultHash = Digest{}
	if installed.Heads != wantHeads ||
		installed.Cut != cut ||
		installed.AttestationID != logicalSnapshotAttestationID(root) ||
		installed.AdmissionRevision != beforeRevision+1 {
		t.Fatalf(
			"install result = %+v, want heads %+v, cut %+v, and revision %d",
			installed,
			wantHeads,
			cut,
			beforeRevision+1,
		)
	}
	assertLogicalSnapshotResolvedLocalCommand(
		t,
		fixture.target,
		testEventID,
		fixture.request.Commands[0].Outcome.Code,
	)
	deadline, found, err := fixture.target.LocalState().NextLeaseDeadline(
		context.Background(),
		testBootID,
	)
	if err != nil ||
		!found ||
		deadline.LeaseID != testLeaseID ||
		deadline.EntityVersion != 1 ||
		deadline.OriginBootID != testBootID ||
		deadline.MonotonicDeadlineNS != 900_000_001_000 ||
		deadline.DisplayDeadlineAt != "2026-08-20T01:15:00Z" {
		t.Fatalf(
			"rearmed snapshot lease deadline = (%+v, %t, %v)",
			deadline,
			found,
			err,
		)
	}
	if _, err := stage.View(
		context.Background(),
	); !errors.Is(err, ErrLogicalSnapshotStageConsumed) {
		t.Fatalf("View(consumed stage) error = %v", err)
	}
	other := openTestStore(
		t,
		filepath.Join(t.TempDir(), "other", "state.db"),
		nil,
	)
	if _, err := other.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:01Z"),
	); !errors.Is(err, ErrLogicalSnapshotStageConsumed) {
		t.Fatalf("second install error = %v, want consumed", err)
	}

	assertStandaloneSnapshotState(t, fixture.target, root, cut, 1)
	assertVerifiedStandaloneSnapshotBaseline(t, fixture.target, root)
	tail := logicalSnapshotTailBatch(t, fixture, installed.Heads)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		tail,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(tail): %v", err)
	}
	assertStandaloneSnapshotState(t, fixture.target, root, cut, 2)

	checkpoint, found, err := fixture.target.SettledAppliedCheckpoint(
		context.Background(),
		cut.CheckpointEventID,
	)
	if err != nil || !found ||
		checkpoint.CheckpointEventID != cut.CheckpointEventID {
		t.Fatalf(
			"SettledAppliedCheckpoint() = (%+v, %t, %v)",
			checkpoint,
			found,
			err,
		)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(installed target): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	}()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopened): %v", err)
	}
	if mode, err := reopened.ReplicaEvidenceMode(
		context.Background(),
	); err != nil || mode != ReplicaEvidenceSettledNonvoter {
		t.Fatalf(
			"ReplicaEvidenceMode(reopened) = (%q, %v)",
			mode,
			err,
		)
	}
	if _, err := reopened.VerifiedSettledNonvoterView(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(reopened): %v", err)
	}
	if found, err := reopened.HasVerifiedStandaloneLogicalSnapshotBaseline(
		context.Background(),
	); err != nil || !found {
		t.Fatalf(
			"HasVerifiedStandaloneLogicalSnapshotBaseline() = (%t, %v)",
			found,
			err,
		)
	}
	assertVerifiedStandaloneSnapshotBaseline(t, reopened, root)
}

func TestInstallStandaloneLogicalSnapshotPreservesRebootstrapMarker(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, cut := logicalSnapshotInstallFixture(t)
	firstInstalledAt := domain.Timestamp("2026-08-20T01:00:00Z")
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		t.Context(),
		stage,
		logicalSnapshotInstallOptions(firstInstalledAt),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(initial): %v", err)
	}
	marker := RebootstrapInstallMarker{
		SessionID:             cut.SessionID,
		WorkspaceID:           cut.WorkspaceID,
		RecoveryGeneration:    cut.RecoveryGeneration,
		DeviceID:              cut.SignerDeviceID,
		SnapshotAttestationID: installed.AttestationID,
		InstalledAt:           firstInstalledAt,
	}
	if err := fixture.target.LocalState().withImmediate(
		t.Context(),
		func(conn *sqlite.Conn) error {
			return insertRebootstrapInstallMarker(conn, marker)
		},
	); err != nil {
		t.Fatalf("insert rebootstrap marker: %v", err)
	}

	replacement := openLogicalSnapshotTestStage(t)
	rebuildLogicalSnapshotStage(t, replacement, fixture)
	replacementRoot, artifact := logicalSnapshotTestRoot(t, fixture, cut)
	if err := replacement.VerifyArtifact(
		t.Context(),
		replacementRoot,
		logicalSnapshotTestProof(t, replacementRoot, artifact),
	); err != nil {
		t.Fatalf("VerifyArtifact(replacement): %v", err)
	}
	secondInstalledAt := domain.Timestamp("2026-08-20T01:01:00Z")
	replaced, err := fixture.target.InstallStandaloneLogicalSnapshot(
		t.Context(),
		replacement,
		logicalSnapshotInstallOptions(secondInstalledAt),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(replacement): %v", err)
	}
	marker.SnapshotAttestationID = replaced.AttestationID
	marker.InstalledAt = secondInstalledAt
	got, found, err := fixture.target.LocalState().
		RebootstrapInstallMarker(t.Context())
	if err != nil || !found || got != marker {
		t.Fatalf(
			"rebootstrap marker after replacement = (%+v, %t, %v), want %+v",
			got,
			found,
			err,
			marker,
		)
	}
	if err := fixture.target.VerifyCommitmentHistory(t.Context()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(replacement): %v", err)
	}
}

func assertVerifiedStandaloneSnapshotBaseline(
	t *testing.T,
	state *Store,
	want logicalsnapshot.Root,
) {
	t.Helper()
	got, found, err := state.VerifiedStandaloneLogicalSnapshotBaseline(
		context.Background(),
	)
	if err != nil ||
		!found ||
		!bytes.Equal(got.CanonicalBytes(), want.CanonicalBytes()) ||
		got.Signature() != want.Signature() {
		t.Fatalf(
			"verified signed baseline = (%x, %t, %v), want %x",
			got.CanonicalBytes(),
			found,
			err,
			want.CanonicalBytes(),
		)
	}
}

func TestInstallStandaloneLogicalSnapshotRejectsRegression(t *testing.T) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(base): %v", err)
	}
	baseHeads := fixture.request.Commands[len(fixture.request.Commands)-1].Heads
	tail := logicalSnapshotTailBatch(t, fixture, baseHeads)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		tail,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(tail): %v", err)
	}
	before, err := fixture.target.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(before): %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:02:00Z"),
	); !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("regressive install error = %v", err)
	}
	after, err := fixture.target.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(after): %v", err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest {
		t.Fatal("rejected regressive install changed destination state")
	}
}

func TestInstallStandaloneLogicalSnapshotSuccessorPreservesPredecessorAttestationPrefix(
	t *testing.T,
) {
	t.Parallel()

	authorityDevice := resultRangeTestAuthorityDevice(t)
	initialState := resultBatchInitialState(t, authorityDevice.ID)
	source := openTestStore(
		t,
		filepath.Join(t.TempDir(), "successor-source", "state.db"),
		nil,
	)
	initialHeads, err := source.Initialize(context.Background(), initialState)
	if err != nil {
		t.Fatalf("Initialize(source): %v", err)
	}
	fixture := resultBatchImportFixture{
		source: resultRangeFixture{
			store:             source,
			initial:           initialHeads,
			authorityDeviceID: authorityDevice.ID,
		},
		target: openTestStore(
			t,
			filepath.Join(t.TempDir(), "successor-target", "state.db"),
			nil,
		),
		initial: initialHeads,
	}

	predecessorCheckpoint := nextCheckpointApplyRequest(
		t,
		initialHeads,
		testCheckpointEventID,
		1,
		2,
		"2026-08-20T01:00:00Z",
	)
	predecessorResult, err := source.Apply(
		context.Background(),
		predecessorCheckpoint,
	)
	if err != nil {
		t.Fatalf("Apply(predecessor checkpoint): %v", err)
	}
	predecessorCommand := logicalSnapshotCheckpointCommand(
		t,
		fixture,
		initialHeads,
		predecessorCheckpoint,
		predecessorResult,
	)
	predecessorCut, err := source.ExportLogicalSnapshotRecords(
		context.Background(),
		LogicalSnapshotExportOptions{
			CheckpointEventID: testCheckpointEventID,
			SignerDeviceID:    authorityDevice.ID,
		},
		func(context.Context, logicalsnapshot.Record) error {
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ExportLogicalSnapshotRecords(predecessor): %v", err)
	}
	predecessorRoot, predecessorArtifact := logicalSnapshotTestRoot(
		t,
		fixture,
		predecessorCut,
	)
	predecessorStage := openLogicalSnapshotTestStage(t)
	if _, err := predecessorStage.Initialize(
		context.Background(),
		initialState,
	); err != nil {
		t.Fatalf("Initialize(predecessor stage): %v", err)
	}
	if _, err := predecessorStage.importCommand(
		context.Background(),
		predecessorCommand,
	); err != nil {
		t.Fatalf("ImportCommand(predecessor checkpoint): %v", err)
	}
	if err := predecessorStage.VerifyArtifact(
		context.Background(),
		predecessorRoot,
		logicalSnapshotTestProof(
			t,
			predecessorRoot,
			predecessorArtifact,
		),
	); err != nil {
		t.Fatalf("VerifyArtifact(predecessor): %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		predecessorStage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(predecessor): %v", err)
	}
	predecessorTail := logicalSnapshotTailBatch(
		t,
		fixture,
		predecessorResult.Heads,
	)
	predecessorTerminalHeads := predecessorTail.
		Commands[len(predecessorTail.Commands)-1].Heads
	if predecessorTerminalHeads.ResultIndex <= predecessorCut.ResultIndex {
		t.Fatalf(
			"predecessor tail %d does not advance retained snapshot %d",
			predecessorTerminalHeads.ResultIndex,
			predecessorCut.ResultIndex,
		)
	}

	successor := logicalSnapshotInstallSuccessorState(
		t,
		fixture,
		predecessorTerminalHeads,
	)
	successorHeads, err := fixture.source.store.InstallSuccessor(
		context.Background(),
		successor,
	)
	if err != nil {
		t.Fatalf("InstallSuccessor(source): %v", err)
	}
	checkpointRequest := logicalSnapshotSuccessorCheckpointRequest(
		t,
		successorHeads,
		fixture.source.authorityDeviceID,
	)
	checkpointResult, err := fixture.source.store.Apply(
		context.Background(),
		checkpointRequest,
	)
	if err != nil {
		t.Fatalf("Apply(successor checkpoint): %v", err)
	}
	successorCommand := logicalSnapshotCheckpointCommand(
		t,
		fixture,
		successorHeads,
		checkpointRequest,
		checkpointResult,
	)
	successorCut, err := fixture.source.store.ExportLogicalSnapshotRecords(
		context.Background(),
		LogicalSnapshotExportOptions{
			CheckpointEventID: logicalSnapshotSuccessorCheckpointEventID,
			SignerDeviceID:    fixture.source.authorityDeviceID,
		},
		func(context.Context, logicalsnapshot.Record) error {
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ExportLogicalSnapshotRecords(successor): %v", err)
	}
	successorRoot, successorArtifact := logicalSnapshotTestRoot(
		t,
		fixture,
		successorCut,
	)
	buildSuccessorStage := func(
		boundary SuccessorState,
	) *LogicalSnapshotStage {
		stage := openLogicalSnapshotTestStage(t)
		if _, err := stage.Initialize(
			context.Background(),
			initialState,
		); err != nil {
			t.Fatalf("Initialize(successor stage): %v", err)
		}
		if _, err := stage.importCommand(
			context.Background(),
			predecessorCommand,
		); err != nil {
			t.Fatalf("ImportCommand(successor predecessor): %v", err)
		}
		for index, command := range predecessorTail.Commands {
			if _, err := stage.importCommand(
				context.Background(),
				command,
			); err != nil {
				t.Fatalf(
					"ImportCommand(successor predecessor tail %d): %v",
					index,
					err,
				)
			}
		}
		if _, err := stage.InstallSuccessor(
			context.Background(),
			boundary,
		); err != nil {
			t.Fatalf("InstallSuccessor(stage): %v", err)
		}
		if _, err := stage.importCommand(
			context.Background(),
			successorCommand,
		); err != nil {
			t.Fatalf("ImportCommand(successor checkpoint): %v", err)
		}
		if err := stage.VerifyArtifact(
			context.Background(),
			successorRoot,
			logicalSnapshotTestProof(t, successorRoot, successorArtifact),
		); err != nil {
			t.Fatalf("VerifyArtifact(successor): %v", err)
		}
		return stage
	}
	successorStage := buildSuccessorStage(successor)
	replacementSuccessor := successor
	replacementSuccessor.ObservedAt = "2026-08-20T03:00:00Z"
	replacementStage := buildSuccessorStage(replacementSuccessor)

	predecessorAttestationID := logicalSnapshotAttestationID(predecessorRoot)
	assertLogicalSnapshotAttestationLineage(
		t,
		fixture.target,
		[]logicalSnapshotAttestationLineage{{
			id:         predecessorAttestationID,
			sessionID:  domain.UUIDv7(testSessionID),
			generation: 0,
		}},
	)

	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		successorStage,
		logicalSnapshotInstallOptions("2026-08-20T02:01:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(successor): %v", err)
	}
	successorAttestationID := logicalSnapshotAttestationID(successorRoot)
	if installed.AttestationID != successorAttestationID {
		t.Fatalf(
			"successor attestation ID = %q, want %q",
			installed.AttestationID,
			successorAttestationID,
		)
	}
	assertLogicalSnapshotSuccessorInstall(
		t,
		fixture.target,
		successorCut,
		predecessorAttestationID,
		successorAttestationID,
	)
	firstObserved := logicalSnapshotRecoveryAuditFirstSeen(
		t,
		fixture.target,
		commitmentSuccessorSessionID,
	)
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		replacementStage,
		logicalSnapshotInstallOptions("2026-08-20T03:01:00Z"),
	); err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(replacement): %v", err)
	}
	if after := logicalSnapshotRecoveryAuditFirstSeen(
		t,
		fixture.target,
		commitmentSuccessorSessionID,
	); after != firstObserved {
		t.Fatalf(
			"recovery first-seen time changed from %q to %q",
			firstObserved,
			after,
		)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(successor destination): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(successor destination): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened successor destination): %v", err)
		}
	}()
	assertLogicalSnapshotSuccessorInstall(
		t,
		reopened,
		successorCut,
		predecessorAttestationID,
		successorAttestationID,
	)
}

func logicalSnapshotInstallSuccessorState(
	t *testing.T,
	fixture resultBatchImportFixture,
	predecessor ApplyHeads,
) SuccessorState {
	t.Helper()
	initial := resultBatchInitialState(t, fixture.source.authorityDeviceID)
	projections := initial.Projections
	projections.AuditCounters = slices.Clone(projections.AuditCounters)
	projections.Devices = slices.Clone(projections.Devices)
	projections.CanonicalRefs = slices.Clone(projections.CanonicalRefs)

	target, err := voterset.New(
		commitmentSuccessorSessionID,
		[]domain.DeviceID{fixture.source.authorityDeviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(successor): %v", err)
	}
	projections.VoterSet = []voterset.Set{target}

	projections.CredentialAuthority = slices.Clone(
		projections.CredentialAuthority,
	)
	projections.CredentialAuthority[0].SessionID =
		commitmentSuccessorSessionID
	projections.PlanCurrent = slices.Clone(projections.PlanCurrent)
	projections.PlanCurrent[0].SessionID = commitmentSuccessorSessionID
	projections.SessionPolicy = slices.Clone(projections.SessionPolicy)
	projections.SessionPolicy[0].SessionID = commitmentSuccessorSessionID

	predecessorGenesisDigest, err := chain.GenesisDigest(
		initial.GenesisJSON,
	)
	if err != nil {
		t.Fatalf("GenesisDigest(predecessor): %v", err)
	}
	postTransformDigest := projectionWritesDigest(t, projections)
	return SuccessorState{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		GenesisJSON: logicalSnapshotSuccessorGenesisJSON(
			t,
			predecessor,
			Digest(predecessorGenesisDigest),
			postTransformDigest,
			initial.Projections.Devices[0].IdentityPublicKey,
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		ObservedAt:                "2026-08-20T02:00:00Z",
		Predecessor:               predecessor,
		Projections:               projections,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
}

func logicalSnapshotRecoveryAuditFirstSeen(
	t *testing.T,
	database *Store,
	sessionID domain.UUIDv7,
) domain.Timestamp {
	t.Helper()
	var result domain.Timestamp
	if err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOneArgs(
				conn,
				`SELECT first_seen_at FROM audit_events
				  WHERE source_kind = 'recovery_boundary'
				    AND session_id = ?1;`,
				[]any{string(sessionID)},
				func(stmt *sqlite.Stmt) {
					result = domain.Timestamp(stmt.ColumnText(0))
				},
			)
		},
	); err != nil {
		t.Fatalf("read recovery first-seen time: %v", err)
	}
	if !result.Valid() {
		t.Fatalf("invalid recovery first-seen time %q", result)
	}
	return result
}

func logicalSnapshotSuccessorGenesisJSON(
	t *testing.T,
	predecessor ApplyHeads,
	predecessorGenesisDigest Digest,
	postTransformStateDigest Digest,
	recoveryPublicKey []byte,
) []byte {
	t.Helper()
	return commitmentCanonicalJSON(t, map[string]any{
		"digest_version": uint64(1),
		"post_transform_state_digest": codec.EncodeBase64URL(
			postTransformStateDigest[:],
		),
		"predecessor_chain_hash": codec.EncodeBase64URL(
			predecessor.ChainHash[:],
		),
		"predecessor_chain_index": predecessor.ChainIndex,
		"predecessor_genesis_digest": codec.EncodeBase64URL(
			predecessorGenesisDigest[:],
		),
		"predecessor_projection_accumulator": codec.EncodeBase64URL(
			predecessor.ProjectionAccumulator[:],
		),
		"predecessor_result_hash": codec.EncodeBase64URL(
			predecessor.ResultHash[:],
		),
		"predecessor_result_index":      predecessor.ResultIndex,
		"projection_schema_version":     uint64(1),
		"quorum_recovery_signature":     codec.EncodeBase64URL(bytes.Repeat([]byte{0x52}, 64)),
		"recovering_identity_signature": codec.EncodeBase64URL(bytes.Repeat([]byte{0x41}, 64)),
		"recovery_generation":           uint64(1),
		"recovery_public_key":           codec.EncodeBase64URL(recoveryPublicKey),
		"session_id":                    string(commitmentSuccessorSessionID),
		"workspace_id":                  string(testWorkspaceID),
	})
}

func logicalSnapshotSuccessorCheckpointRequest(
	t *testing.T,
	previous ApplyHeads,
	signerID domain.DeviceID,
) ApplyRequest {
	t.Helper()
	const (
		term     = uint64(1)
		logIndex = uint64(3)
	)
	privateKey := resultBatchPrivateKey(1)
	defer clear(privateKey)

	record := CheckpointRecord{
		CheckpointEventID:        logicalSnapshotSuccessorCheckpointEventID,
		SessionID:                commitmentSuccessorSessionID,
		WorkspaceID:              testWorkspaceID,
		RecoveryGeneration:       1,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           signerID,
		Term:                     term,
		CoveredAppliedLogIndex:   logIndex - 1,
		CoveredChainIndex:        previous.ChainIndex,
		CoveredChainHash:         previous.ChainHash,
		CoveredResultIndex:       previous.ResultIndex,
		CoveredResultHash:        previous.ResultHash,
		ProjectionAccumulator:    previous.ProjectionAccumulator,
		DigestVersion:            previous.DigestVersion,
		ProjectionSchemaVersion:  previous.ProjectionSchemaVersion,
	}
	unsigned, err := record.canonicalJSON(false)
	if err != nil {
		t.Fatalf("canonicalJSON(successor checkpoint): %v", err)
	}
	record.CheckpointJSON = unsigned
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureCheckpoint,
		unsigned,
	)
	if err != nil {
		t.Fatalf("SignEd25519(successor checkpoint): %v", err)
	}
	copy(record.AuthoritySignature[:], signature)
	payload, err := record.canonicalJSON(true)
	if err != nil {
		t.Fatalf("canonicalJSON(signed successor checkpoint): %v", err)
	}

	authority, err := event.NewLocalAuthority(signerID, testBootID)
	if err != nil {
		t.Fatalf("NewLocalAuthority(successor checkpoint): %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding(successor checkpoint): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindConsensusCheckpoint,
			RationaleSummary: "",
			Actions:          []event.Action{},
			Payload:          payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        logicalSnapshotSuccessorCheckpointEventID,
			SessionID:      commitmentSuccessorSessionID,
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      "2026-08-20T02:00:01Z",
			OriginSequence: 2,
		},
	)
	if err != nil {
		t.Fatalf("BuildProposal(successor checkpoint): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign(successor checkpoint): %v", err)
	}
	return ApplyRequest{
		Term:               term,
		LogIndex:           logIndex,
		AppliedAt:          "2026-08-20T02:00:01Z",
		RecoveryGeneration: 1,
		Proposal:           signed,
		Outcome: CommandOutcome{
			Status: OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		Audit: []AuditRecord{{
			SessionID:        commitmentSuccessorSessionID,
			SourceKind:       AuditAcceptedEvent,
			EventID:          logicalSnapshotSuccessorCheckpointEventID,
			ResultIndex:      previous.ResultIndex + 1,
			ReporterDeviceID: signerID,
			SubjectDeviceID:  signerID,
			ActorType:        event.ActorDaemon,
			IPCChannel:       "daemon",
			ActionCode:       string(event.KindConsensusCheckpoint),
			OutcomeCode:      "accepted",
			Subject: "session:" +
				string(commitmentSuccessorSessionID),
			DetailsJSON:      []byte(`{}`),
			FirstSeenAt:      "2026-08-20T02:00:01Z",
			LastSeenAt:       "2026-08-20T02:00:01Z",
			ObservationCount: 1,
		}},
		Checkpoint: &record,
	}
}

func logicalSnapshotCheckpointCommand(
	t *testing.T,
	fixture resultBatchImportFixture,
	previousHeads ApplyHeads,
	request ApplyRequest,
	applied ApplyResult,
) VerifiedCommandImport {
	t.Helper()
	exported, found, err := fixture.source.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex:          previousHeads.ResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: fixture.source.authorityDeviceID,
		},
	)
	if err != nil || !found || len(exported.Results) != 1 {
		t.Fatalf(
			"ExportResultRange(successor checkpoint) = found %t, results %d, err %v",
			found,
			len(exported.Results),
			err,
		)
	}
	mutations := resultBatchStoredMutations(t, fixture.source.store)
	if len(mutations) == 0 {
		t.Fatal("successor checkpoint mutations are missing")
	}
	return resultBatchCommand(
		request,
		exported.Results[0],
		mutations[len(mutations)-1],
		applied.Heads,
	)
}

type logicalSnapshotAttestationLineage struct {
	id         string
	sessionID  domain.UUIDv7
	generation uint64
}

func assertLogicalSnapshotAttestationLineage(
	t *testing.T,
	database *Store,
	want []logicalSnapshotAttestationLineage,
) {
	t.Helper()
	got := make(map[logicalSnapshotAttestationLineage]int)
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var rowErr error
			if err := query(
				conn,
				`SELECT attestation_id, session_id, recovery_generation
				   FROM replication_attestations
				  ORDER BY recovery_generation, attestation_id;`,
				func(stmt *sqlite.Stmt) {
					generation := stmt.ColumnInt64(2)
					if generation < 0 {
						rowErr = errors.New(
							"negative attestation recovery generation",
						)
						return
					}
					row := logicalSnapshotAttestationLineage{
						id:         stmt.ColumnText(0),
						sessionID:  domain.UUIDv7(stmt.ColumnText(1)),
						generation: uint64(generation),
					}
					got[row]++
				},
			); err != nil {
				return err
			}
			return rowErr
		},
	)
	if err != nil {
		t.Fatalf("read replication attestations: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("attestation lineages = %+v, want %+v", got, want)
	}
	for _, expected := range want {
		if got[expected] != 1 {
			t.Fatalf(
				"attestation lineage %+v count = %d, want 1; all = %+v",
				expected,
				got[expected],
				got,
			)
		}
	}
}

func assertLogicalSnapshotSuccessorInstall(
	t *testing.T,
	database *Store,
	cut LogicalSnapshotCut,
	predecessorAttestationID string,
	successorAttestationID string,
) {
	t.Helper()
	assertLogicalSnapshotAttestationLineage(
		t,
		database,
		[]logicalSnapshotAttestationLineage{{
			id:         predecessorAttestationID,
			sessionID:  domain.UUIDv7(testSessionID),
			generation: 0,
		}, {
			id:         successorAttestationID,
			sessionID:  commitmentSuccessorSessionID,
			generation: 1,
		}},
	)
	view, err := database.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(successor): %v", err)
	}
	wantHeads := ApplyHeads{
		ChainIndex:              cut.ChainIndex,
		ChainHash:               cut.ChainHash,
		ResultIndex:             cut.ResultIndex,
		ResultHash:              cut.ResultHash,
		ProjectionAccumulator:   cut.ProjectionAccumulator,
		DigestVersion:           cut.DigestVersion,
		ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
	}
	if view.SessionID != cut.SessionID ||
		view.WorkspaceID != cut.WorkspaceID ||
		view.RecoveryGeneration != cut.RecoveryGeneration ||
		view.Heads != wantHeads ||
		view.ProjectionStateDigest != cut.ProjectionStateDigest {
		t.Fatalf(
			"settled successor view = %+v, want cut %+v",
			view,
			cut,
		)
	}
}

func TestInstallStandaloneLogicalSnapshotRollsBackAndCanRetry(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeRevision := fixture.target.AdmissionRevision()
	beforeCounts := logicalSnapshotInstallCounts(t, fixture.target)
	injected := errors.New("injected logical snapshot install failure")
	fixture.target.applyFailpoint = func(current applyStage) error {
		if current == applyAfterConsensus {
			return injected
		}
		return nil
	}
	_, err = fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if !errors.Is(err, injected) {
		t.Fatalf("failed install error = %v, want injected", err)
	}
	fixture.target.applyFailpoint = nil
	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest ||
		beforeRevision != fixture.target.AdmissionRevision() {
		t.Fatal("failed install changed the durable target cut")
	}
	afterCounts := logicalSnapshotInstallCounts(t, fixture.target)
	for table, want := range beforeCounts {
		if afterCounts[table] != want {
			t.Fatalf(
				"failed install %s rows = %d, want %d",
				table,
				afterCounts[table],
				want,
			)
		}
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:01Z"),
	); err != nil {
		t.Fatalf("retry install: %v", err)
	}
}

func TestInstallStandaloneLogicalSnapshotLockWaitHonorsCancellation(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	stage.mu.Lock()
	defer stage.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := fixture.target.InstallStandaloneLogicalSnapshot(
			ctx,
			stage,
			logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
		)
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled lock wait error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled snapshot install remained blocked on stage lock")
	}
}

func TestInstallStandaloneLogicalSnapshotReverifiesFrozenSource(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	if err := stage.store.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				"UPDATE tasks SET title = 'tampered after verification';",
			)
		},
	); err != nil {
		t.Fatalf("tamper stage: %v", err)
	}
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); !errors.Is(err, ErrInvalidLogicalSnapshotStage) {
		t.Fatalf("install tampered stage error = %v", err)
	}
	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest {
		t.Fatal("rejected stage changed target state")
	}
}

func TestAdvanceLogicalSnapshotOriginCounters(t *testing.T) {
	t.Parallel()

	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	deviceID := resultBatchRelayDeviceID(t)
	ordinaryScope := domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000022",
	)
	exhaustedScope := domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000023",
	)
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			for _, row := range []struct {
				scopeID domain.UUIDv7
				last    uint64
				next    uint64
			}{
				{ordinaryScope, 9, 3},
				{exhaustedScope, domain.MaxSafeInteger, 11},
			} {
				if err := execute(
					conn,
					`INSERT INTO origin_scopes(
					    device_id, scope_kind, scope_id, last_sequence
					) VALUES (?1, 'boot', ?2, ?3);`,
					string(deviceID),
					string(row.scopeID),
					row.last,
				); err != nil {
					return err
				}
				if err := execute(
					conn,
					`INSERT INTO origin_counters(
					    device_id, scope_kind, scope_id,
					    next_sequence, exhausted
					) VALUES (?1, 'boot', ?2, ?3, 0);`,
					string(deviceID),
					string(row.scopeID),
					row.next,
				); err != nil {
					return err
				}
			}
			return advanceLogicalSnapshotOriginCounters(conn)
		},
	); err != nil {
		t.Fatalf("advanceLogicalSnapshotOriginCounters(): %v", err)
	}
	if err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var next int64
			var exhausted bool
			if err := queryOneArgs(
				conn,
				`SELECT next_sequence, exhausted
				   FROM origin_counters
				  WHERE scope_id = ?1;`,
				[]any{string(ordinaryScope)},
				func(stmt *sqlite.Stmt) {
					next = stmt.ColumnInt64(0)
					exhausted = stmt.ColumnBool(1)
				},
			); err != nil {
				return err
			}
			if next != 10 || exhausted {
				return errors.New("ordinary origin counter was not advanced")
			}
			var nextNull bool
			if err := queryOneArgs(
				conn,
				`SELECT next_sequence IS NULL, exhausted
				   FROM origin_counters
				  WHERE scope_id = ?1;`,
				[]any{string(exhaustedScope)},
				func(stmt *sqlite.Stmt) {
					nextNull = stmt.ColumnBool(0)
					exhausted = stmt.ColumnBool(1)
				},
			); err != nil {
				return err
			}
			if !nextNull || !exhausted {
				return errors.New("maximum origin counter was not exhausted")
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestClearSuccessorGitArtifactsPreservesProtectedRetention(
	t *testing.T,
) {
	t.Parallel()

	database := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	fixture := newProjectionFixture(t)
	if _, err := database.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			fixture.initialWrites,
		),
	); err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	protectedDigest := fixture.initialWrites.
		Publications[0].Metadata.ArtifactDigest
	type artifact struct {
		digest         Digest
		kind           string
		state          string
		retention      string
		path           string
		publicationRef bool
	}
	artifacts := []artifact{
		{
			digest:         Digest(protectedDigest),
			kind:           "publication",
			state:          "verified",
			retention:      "preproposal",
			path:           "protected-conflict.bundle",
			publicationRef: true,
		},
		{
			digest:         digestWithByte(0x31),
			kind:           "publication",
			state:          "verified",
			retention:      "preproposal",
			path:           "unprotected-preproposal.bundle",
			publicationRef: true,
		},
		{
			digest:    digestWithByte(0x32),
			kind:      "bootstrap",
			state:     "imported",
			retention: "quarantine",
			path:      "quarantine.bundle",
		},
		{
			digest:    digestWithByte(0x33),
			kind:      "bootstrap",
			state:     "downloading",
			retention: "canonical",
			path:      "inflight.bundle",
		},
		{
			digest:    digestWithByte(0x34),
			kind:      "bootstrap",
			state:     "imported",
			retention: "canonical",
			path:      "canonical.bundle",
		},
		{
			digest:    digestWithByte(0x35),
			kind:      "draft",
			state:     "verified",
			retention: "draft",
			path:      "draft.bundle",
		},
		{
			digest:    digestWithByte(0x36),
			kind:      "snapshot",
			state:     "imported",
			retention: "bootstrap",
			path:      "snapshot.bundle",
		},
	}
	if err := database.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			publication := fixture.initialWrites.Publications[0]
			for _, artifact := range artifacts {
				var (
					proposalEventID any
					publicationID   any
					metadataDigest  any
				)
				if artifact.publicationRef {
					proposalEventID = string(
						publication.Metadata.ProposalEventID,
					)
					publicationID = string(
						publication.Metadata.PublicationID,
					)
					digest := digestWithByte(0x71)
					metadataDigest = digest[:]
				}
				expectedSize := 1
				receivedSize := 1
				if artifact.state == "downloading" {
					expectedSize = 2
				}
				if err := execute(
					conn,
					`INSERT INTO git_artifacts(
					    artifact_digest, artifact_kind, state,
					    proposal_event_id, publication_id,
					    metadata_digest, expected_size, received_size,
					    retention_class, local_path, created_at, updated_at
					) VALUES (
					    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
					    '2026-08-21T00:00:00Z',
					    '2026-08-21T00:00:00Z'
					);`,
					artifact.digest[:],
					artifact.kind,
					artifact.state,
					proposalEventID,
					publicationID,
					metadataDigest,
					expectedSize,
					receivedSize,
					artifact.retention,
					artifact.path,
				); err != nil {
					return err
				}
			}
			return clearSuccessorGitArtifacts(conn)
		},
	); err != nil {
		t.Fatalf("clearSuccessorGitArtifacts(): %v", err)
	}
	if err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var paths []string
			if err := query(
				conn,
				"SELECT local_path FROM git_artifacts ORDER BY local_path;",
				func(stmt *sqlite.Stmt) {
					paths = append(paths, stmt.ColumnText(0))
				},
			); err != nil {
				return err
			}
			want := []string{
				"canonical.bundle",
				"draft.bundle",
				"protected-conflict.bundle",
				"snapshot.bundle",
			}
			if !slices.Equal(paths, want) {
				return fmt.Errorf(
					"retained Git artifacts = %v, want %v",
					paths,
					want,
				)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestInstallStandaloneLogicalSnapshotRequiresRootAndAllowsUpgrade(
	t *testing.T,
) {
	t.Parallel()

	fixture := newResultBatchAtomicityFixture(t)
	stage := openLogicalSnapshotTestStage(t)
	rebuildLogicalSnapshotStage(t, stage, fixture)
	cut := exportLogicalSnapshotTestCut(t, fixture)
	if err := stage.Verify(context.Background(), cut); err != nil {
		t.Fatalf("Verify(cut): %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("install cut-only stage error = %v", err)
	}
	root, expanded := logicalSnapshotTestRoot(t, fixture, cut)
	proof := logicalSnapshotTestProof(t, root, expanded)
	if err := stage.VerifyArtifact(
		context.Background(),
		root,
		logicalsnapshot.VerifiedExpandedArtifact{},
	); !errors.Is(err, ErrInvalidLogicalSnapshotStage) {
		t.Fatalf("VerifyArtifact(zero proof) error = %v", err)
	}
	signature := root.Signature()
	signature[0] ^= 0xff
	otherRoot, err := logicalsnapshot.NewRoot(root.Unsigned(), signature)
	if err != nil {
		t.Fatalf("NewRoot(other): %v", err)
	}
	if err := stage.VerifyArtifact(
		context.Background(),
		otherRoot,
		proof,
	); !errors.Is(err, ErrInvalidLogicalSnapshotStage) {
		t.Fatalf("VerifyArtifact(wrong proof) error = %v", err)
	}
	if err := stage.VerifyArtifact(
		context.Background(),
		root,
		proof,
	); err != nil {
		t.Fatalf("VerifyArtifact(after cut verification): %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:01Z"),
	); err != nil {
		t.Fatalf("install upgraded root-bound stage: %v", err)
	}
}

func TestInstallStandaloneLogicalSnapshotRejectsDerivedViewTamper(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	if err := stage.store.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE activity
				    SET rationale_summary = 'tampered after verification';`,
			)
		},
	); err != nil {
		t.Fatalf("tamper staged activity: %v", err)
	}
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("install tampered derived view error = %v", err)
	}
	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest {
		t.Fatal("rejected derived-view stage changed target state")
	}
}

func TestInstallStandaloneLogicalSnapshotPreservesLocalAuditAndRebuildsIDs(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	var wantRebuiltCount int64
	if err := stage.store.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return queryOne(
				conn,
				`SELECT count(*) FROM audit_events
				  WHERE source_kind != 'local_aggregate';`,
				func(stmt *sqlite.Stmt) {
					wantRebuiltCount = stmt.ColumnInt64(0)
				},
			)
		},
	); err != nil {
		t.Fatalf("count staged audits: %v", err)
	}
	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO audit_events(
				    audit_id, session_id, source_kind, event_id,
				    result_index, reporter_device_id, subject_device_id,
				    subject_credential_epoch, actor_type, ipc_channel,
				    action_code, outcome_code, subject, details_json,
				    first_seen_at, last_seen_at, observation_count
				) VALUES (
				    99, ?1, 'local_aggregate', NULL, NULL, NULL, NULL,
				    NULL, NULL, 'daemon', 'connection.denied', 'denied',
				    'peer:test', '{"class":"local"}', ?2, ?2, 7
				);`,
				testSessionID,
				"2026-08-20T00:59:00Z",
			)
		},
	); err != nil {
		t.Fatalf("insert local audit: %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	if err := fixture.target.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var (
				localCount      int64
				rebuiltCount    int64
				minRebuiltAudit int64
				activityCount   int64
			)
			if err := queryOne(
				conn,
				`SELECT count(*) FROM audit_events
				  WHERE audit_id = 99
				    AND source_kind = 'local_aggregate'
				    AND observation_count = 7;`,
				func(stmt *sqlite.Stmt) {
					localCount = stmt.ColumnInt64(0)
				},
			); err != nil {
				return err
			}
			if err := queryOne(
				conn,
				`SELECT count(*), coalesce(min(audit_id), 0)
				   FROM audit_events
				  WHERE source_kind != 'local_aggregate';`,
				func(stmt *sqlite.Stmt) {
					rebuiltCount = stmt.ColumnInt64(0)
					minRebuiltAudit = stmt.ColumnInt64(1)
				},
			); err != nil {
				return err
			}
			if err := queryOne(
				conn,
				"SELECT count(*) FROM activity;",
				func(stmt *sqlite.Stmt) {
					activityCount = stmt.ColumnInt64(0)
				},
			); err != nil {
				return err
			}
			if localCount != 1 ||
				rebuiltCount != wantRebuiltCount ||
				minRebuiltAudit <= 99 ||
				activityCount != 1 {
				return fmt.Errorf(
					"derived views: local=%d rebuilt=%d min_id=%d activity=%d",
					localCount,
					rebuiltCount,
					minRebuiltAudit,
					activityCount,
				)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestInstallStandaloneLogicalSnapshotRejectsPoisonedResultBoundAudit(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	if _, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		fixture.request,
	); err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
	}
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO audit_events(
				    session_id, source_kind, event_id, result_index,
				    reporter_device_id, subject_device_id,
				    subject_credential_epoch, actor_type, ipc_channel,
				    action_code, outcome_code, subject, details_json,
				    first_seen_at, last_seen_at, observation_count
				)
				SELECT session_id, 'local_aggregate', event_id, result_index,
				       reporter_device_id, NULL, NULL, actor_type, ipc_channel,
				       'alarm.conflict_integrity', outcome_code,
				       'conflict:poisoned',
				       '{"class":"conflict_integrity"}',
				       first_seen_at, last_seen_at, 1
				  FROM audit_events
				 WHERE source_kind != 'local_aggregate'
				 ORDER BY audit_id
				 LIMIT 1;`,
			)
		},
	); err != nil {
		t.Fatalf("insert poisoned audit: %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("install over poisoned audit error = %v", err)
	}
	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest {
		t.Fatal("rejected poisoned-audit install changed destination state")
	}
}

func assertLogicalSnapshotResolvedLocalCommand(
	t *testing.T,
	database *Store,
	eventID domain.UUIDv7,
	outcomeCode string,
) {
	t.Helper()
	if err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var (
				state        string
				terminalCode string
				signedNull   bool
				outboxCount  int64
			)
			if err := queryOneArgs(
				conn,
				`SELECT state, terminal_code,
				        signed_proposal_json IS NULL
				   FROM local_requests
				  WHERE event_id = ?1;`,
				[]any{string(eventID)},
				func(stmt *sqlite.Stmt) {
					state = stmt.ColumnText(0)
					terminalCode = stmt.ColumnText(1)
					signedNull = stmt.ColumnBool(2)
				},
			); err != nil {
				return err
			}
			if err := queryOneArgs(
				conn,
				"SELECT count(*) FROM outbox WHERE event_id = ?1;",
				[]any{string(eventID)},
				func(stmt *sqlite.Stmt) {
					outboxCount = stmt.ColumnInt64(0)
				},
			); err != nil {
				return err
			}
			if state != string(LocalRequestResolved) ||
				terminalCode != outcomeCode ||
				!signedNull ||
				outboxCount != 0 {
				return errors.New(
					"snapshot did not resolve the committed local command",
				)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestLogicalSnapshotStageVerifyArtifactRejectsInvalidSignature(
	t *testing.T,
) {
	t.Parallel()

	fixture := newResultBatchAtomicityFixture(t)
	stage := openLogicalSnapshotTestStage(t)
	rebuildLogicalSnapshotStage(t, stage, fixture)
	root, expanded := logicalSnapshotTestRoot(
		t,
		fixture,
		exportLogicalSnapshotTestCut(t, fixture),
	)
	signature := root.Signature()
	signature[0] ^= 0xff
	tampered, err := logicalsnapshot.NewRoot(root.Unsigned(), signature)
	if err != nil {
		t.Fatalf("NewRoot(tampered): %v", err)
	}
	tamperedProof := logicalSnapshotTestProof(t, tampered, expanded)
	if err := stage.VerifyArtifact(
		context.Background(),
		tampered,
		tamperedProof,
	); !errors.Is(err, logicalsnapshot.ErrRootSignature) {
		t.Fatalf("VerifyArtifact(tampered) error = %v", err)
	}
	if err := stage.VerifyArtifact(
		context.Background(),
		root,
		logicalSnapshotTestProof(t, root, expanded),
	); err != nil {
		t.Fatalf("VerifyArtifact(valid retry): %v", err)
	}
}

func TestLogicalSnapshotCopyPreservesControlFileDecision(t *testing.T) {
	t.Parallel()

	source := openTestStore(
		t,
		filepath.Join(t.TempDir(), "source", "state.db"),
		nil,
	)
	destination := openTestStore(
		t,
		filepath.Join(t.TempDir(), "destination", "state.db"),
		nil,
	)
	eventID := logicalSnapshotTailEventID
	sessionID := domain.UUIDv7(testSessionID)
	deviceID := resultBatchRelayDeviceID(t)
	contentDigest := sha256.Sum256([]byte("approved control content"))
	insertProposal := func(database *Store) {
		t.Helper()
		if err := database.LocalState().withImmediate(
			context.Background(),
			func(conn *sqlite.Conn) error {
				return execute(
					conn,
					`INSERT INTO control_file_proposals(
					    proposal_event_id, session_id, path, operation,
					    content_digest, content_size, diff,
					    proposed_by_device_id, chain_index
					) VALUES (?1, ?2, '.gitignore', 'upsert', ?3, 24, '',
					          ?4, 1);`,
					string(eventID),
					string(sessionID),
					contentDigest[:],
					string(deviceID),
				)
			},
		); err != nil {
			t.Fatalf("insert control proposal: %v", err)
		}
	}
	insertProposal(source)
	insertProposal(destination)
	if err := source.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO control_file_approvals(
				    proposal_event_id, session_id, path, operation,
				    content_digest, decision, content_store_ref,
				    manifest_version, decided_at
				) VALUES (?1, ?2, '.gitignore', 'upsert', ?3, 'pending',
				          NULL, NULL, NULL);`,
				string(eventID),
				string(sessionID),
				contentDigest[:],
			)
		},
	); err != nil {
		t.Fatalf("insert source approval: %v", err)
	}
	if err := destination.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO control_file_approvals(
				    proposal_event_id, session_id, path, operation,
				    content_digest, decision, content_store_ref,
				    manifest_version, decided_at
				) VALUES (?1, ?2, '.gitignore', 'upsert', ?3, 'approved',
				          'control:approved', 7, '2026-08-21T18:00:00Z');`,
				string(eventID),
				string(sessionID),
				contentDigest[:],
			)
		},
	); err != nil {
		t.Fatalf("insert destination approval: %v", err)
	}

	err := source.withConn(
		context.Background(),
		func(sourceConn *sqlite.Conn) error {
			return destination.LocalState().withImmediate(
				context.Background(),
				func(destinationConn *sqlite.Conn) error {
					if err := copyLogicalSnapshotTable(
						sourceConn,
						destinationConn,
						"control_file_proposals",
					); err != nil {
						return err
					}
					if err := mergeLogicalSnapshotControlApprovals(
						sourceConn,
						destinationConn,
					); err != nil {
						return err
					}
					return verifyLogicalSnapshotControlApprovals(
						destinationConn,
					)
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("copy control-file rows: %v", err)
	}
	if err := destination.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var decision, reference string
			var version int64
			if err := queryOneArgs(
				conn,
				`SELECT decision, content_store_ref, manifest_version
				   FROM control_file_approvals
				  WHERE proposal_event_id = ?1;`,
				[]any{string(eventID)},
				func(stmt *sqlite.Stmt) {
					decision = stmt.ColumnText(0)
					reference = stmt.ColumnText(1)
					version = stmt.ColumnInt64(2)
				},
			); err != nil {
				return err
			}
			if decision != "approved" ||
				reference != "control:approved" ||
				version != 7 {
				return errors.New(
					"snapshot copy replaced the local control decision",
				)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := source.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE control_file_approvals
				    SET decision = 'approved',
				        content_store_ref = 'attacker:content',
				        manifest_version = 1,
				        decided_at = '2026-08-21T18:01:00Z'
				  WHERE proposal_event_id = ?1;`,
				string(eventID),
			)
		},
	); err != nil {
		t.Fatalf("tamper source approval: %v", err)
	}
	quarantineTarget := openTestStore(
		t,
		filepath.Join(t.TempDir(), "quarantine-target", "state.db"),
		nil,
	)
	insertProposal(quarantineTarget)
	err = source.withConn(
		context.Background(),
		func(sourceConn *sqlite.Conn) error {
			return quarantineTarget.LocalState().withImmediate(
				context.Background(),
				func(destinationConn *sqlite.Conn) error {
					return mergeLogicalSnapshotControlApprovals(
						sourceConn,
						destinationConn,
					)
				},
			)
		},
	)
	if !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("merge authoritative quarantine approval error = %v", err)
	}
}

func TestStandaloneLogicalSnapshotAttestationTamperBlocksReopen(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, root, _ := logicalSnapshotInstallFixture(t)
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE replication_attestations
				    SET signature = zeroblob(64)
				  WHERE attestation_id = ?1;`,
				logicalSnapshotAttestationID(root),
			)
		},
	); err != nil {
		t.Fatalf("tamper attestation: %v", err)
	}
	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, err := Open(
		context.Background(),
		Options{Path: path},
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"Open(tampered attestation) error = %v, want evidence failure",
			err,
		)
	}
}

func TestHistoricalLogicalSnapshotAttestationTamperFailsExplicitScrub(
	t *testing.T,
) {
	t.Parallel()

	target, root := installHistoricalLogicalSnapshotFixture(t)
	if err := target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`UPDATE replication_attestations
				    SET signature = zeroblob(64)
				  WHERE attestation_id = ?1;`,
				logicalSnapshotAttestationID(root),
			)
		},
	); err != nil {
		t.Fatalf("tamper historical attestation: %v", err)
	}
	path := target.Path()
	if err := target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(
		context.Background(),
		Options{Path: path},
	)
	if err != nil {
		t.Fatalf("Open(tampered historical attestation): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	}()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"VerifyCommitmentHistory(tampered historical attestation) error = %v, want evidence failure",
			err,
		)
	}
}

func TestHistoricalLogicalSnapshotDuplicateFailsExplicitScrub(t *testing.T) {
	t.Parallel()

	target, root := installHistoricalLogicalSnapshotFixture(t)
	attestationID := logicalSnapshotAttestationID(root)
	if err := target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO replication_attestations
				SELECT 'duplicate-historical-snapshot', attestation_kind,
				       session_id, workspace_id, recovery_generation,
				       signer_device_id, authority_voter_set_version,
				       from_result_index, to_result_index,
				       server_applied_result_index, start_result_hash,
				       end_result_hash, start_chain_index, end_chain_index,
				       start_chain_hash, end_chain_hash,
				       start_projection_accumulator,
				       end_projection_accumulator,
				       start_projection_state_digest,
				       end_projection_state_digest, checkpoint_event_id,
				       envelope_json, signature, verified_at
				  FROM replication_attestations
				 WHERE attestation_id = ?1;`,
				attestationID,
			)
		},
	); err != nil {
		t.Fatalf("duplicate historical attestation: %v", err)
	}
	path := target.Path()
	if err := target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(
		context.Background(),
		Options{Path: path},
	)
	if err != nil {
		t.Fatalf("Open(duplicate historical snapshot): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	}()
	if err := reopened.VerifyCommitmentHistory(
		context.Background(),
	); !errors.Is(err, ErrReplicaEvidenceMode) {
		t.Fatalf(
			"VerifyCommitmentHistory(duplicate historical snapshot) error = %v, want evidence failure",
			err,
		)
	}
}

func TestHistoricalResultBatchEvidenceSurvivesRecoveryAndRejectsTamper(
	t *testing.T,
) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		tamper bool
	}{
		{name: "valid"},
		{name: "tampered signature", tamper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newResultBatchImportFixture(t)
			imported, err := fixture.target.ImportSettledNonvoterResultBatch(
				context.Background(),
				fixture.request,
			)
			if err != nil {
				t.Fatalf("ImportSettledNonvoterResultBatch(): %v", err)
			}
			successor := logicalSnapshotInstallSuccessorState(
				t,
				fixture,
				imported.Heads,
			)
			if _, err := fixture.target.InstallSuccessor(
				context.Background(),
				successor,
			); err != nil {
				t.Fatalf("InstallSuccessor(): %v", err)
			}
			if test.tamper {
				if err := fixture.target.LocalState().withImmediate(
					context.Background(),
					func(conn *sqlite.Conn) error {
						return execute(
							conn,
							`UPDATE replication_attestations
							    SET signature = zeroblob(64)
							  WHERE attestation_kind = 'batch'
							    AND recovery_generation = 0;`,
						)
					},
				); err != nil {
					t.Fatalf("tamper historical batch: %v", err)
				}
			}
			path := fixture.target.Path()
			if err := fixture.target.Close(); err != nil {
				t.Fatalf("Close(): %v", err)
			}
			reopened, err := Open(
				context.Background(),
				Options{Path: path},
			)
			if err != nil {
				t.Fatalf("Open(historical batch): %v", err)
			}
			verifyErr := reopened.VerifyCommitmentHistory(
				context.Background(),
			)
			if test.tamper {
				if !errors.Is(verifyErr, ErrReplicaEvidenceMode) {
					t.Fatalf(
						"VerifyCommitmentHistory(tampered historical batch) error = %v, want evidence failure",
						verifyErr,
					)
				}
			} else if verifyErr != nil {
				t.Fatalf(
					"VerifyCommitmentHistory(valid historical batch): %v",
					verifyErr,
				)
			}
			if err := reopened.Close(); err != nil {
				t.Fatalf("Close(reopened): %v", err)
			}
		})
	}
}

func TestHistoricalSnapshotAndTailEvidenceSurviveRecovery(t *testing.T) {
	t.Parallel()

	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	tail := logicalSnapshotTailBatch(t, fixture, installed.Heads)
	imported, err := fixture.target.ImportSettledNonvoterResultBatch(
		context.Background(),
		tail,
	)
	if err != nil {
		t.Fatalf("ImportSettledNonvoterResultBatch(tail): %v", err)
	}
	successor := logicalSnapshotInstallSuccessorState(
		t,
		fixture,
		imported.Heads,
	)
	if _, err := fixture.target.InstallSuccessor(
		context.Background(),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(snapshot and tail evidence): %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close(reopened): %v", err)
	}
}

func TestLogicalSnapshotInstallRejectsOrphanedAttestation(
	t *testing.T,
) {
	t.Parallel()

	fixture, stage, root, _ := logicalSnapshotInstallFixture(t)
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	); err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(initial): %v", err)
	}
	replacement := openLogicalSnapshotTestStage(t)
	rebuildLogicalSnapshotStage(t, replacement, fixture)
	cut := exportLogicalSnapshotTestCut(t, fixture)
	replacementRoot, artifact := logicalSnapshotTestRoot(t, fixture, cut)
	if err := replacement.VerifyArtifact(
		context.Background(),
		replacementRoot,
		logicalSnapshotTestProof(t, replacementRoot, artifact),
	); err != nil {
		t.Fatalf("VerifyArtifact(replacement): %v", err)
	}

	attestationID := logicalSnapshotAttestationID(root)
	if err := fixture.target.LocalState().withImmediate(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(
				conn,
				`INSERT INTO replication_attestations
				SELECT 'orphaned-future-attestation', attestation_kind, ?1,
				       workspace_id, 1, signer_device_id,
				       authority_voter_set_version, from_result_index,
				       to_result_index, server_applied_result_index,
				       start_result_hash, end_result_hash,
				       start_chain_index, end_chain_index,
				       start_chain_hash, end_chain_hash,
				       start_projection_accumulator,
				       end_projection_accumulator,
				       start_projection_state_digest,
				       end_projection_state_digest,
				       checkpoint_event_id, envelope_json, signature,
				       verified_at
				  FROM replication_attestations
				 WHERE attestation_id = ?2;`,
				string(commitmentSuccessorSessionID),
				attestationID,
			)
		},
	); err != nil {
		t.Fatalf("seed orphaned attestation: %v", err)
	}
	if _, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		replacement,
		logicalSnapshotInstallOptions("2026-08-20T02:00:00Z"),
	); !errors.Is(err, ErrLogicalSnapshotInstall) {
		t.Fatalf("replacement with orphaned attestation error = %v", err)
	}
}

func installHistoricalLogicalSnapshotFixture(
	t *testing.T,
) (*Store, logicalsnapshot.Root) {
	t.Helper()
	fixture, stage, root, _ := logicalSnapshotInstallFixture(t)
	installed, err := fixture.target.InstallStandaloneLogicalSnapshot(
		context.Background(),
		stage,
		logicalSnapshotInstallOptions("2026-08-20T01:00:00Z"),
	)
	if err != nil {
		t.Fatalf("InstallStandaloneLogicalSnapshot(): %v", err)
	}
	successor := logicalSnapshotInstallSuccessorState(
		t,
		fixture,
		installed.Heads,
	)
	if _, err := fixture.target.InstallSuccessor(
		context.Background(),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	return fixture.target, root
}

func logicalSnapshotInstallFixture(
	t *testing.T,
) (
	resultBatchImportFixture,
	*LogicalSnapshotStage,
	logicalsnapshot.Root,
	LogicalSnapshotCut,
) {
	t.Helper()
	fixture := newResultBatchAtomicityFixture(t)
	stage := openLogicalSnapshotTestStage(t)
	rebuildLogicalSnapshotStage(t, stage, fixture)
	cut := exportLogicalSnapshotTestCut(t, fixture)
	root, expanded := logicalSnapshotTestRoot(t, fixture, cut)
	if err := stage.VerifyArtifact(
		context.Background(),
		root,
		logicalSnapshotTestProof(t, root, expanded),
	); err != nil {
		t.Fatalf("VerifyArtifact(): %v", err)
	}
	return fixture, stage, root, cut
}

func rebuildLogicalSnapshotStage(
	t *testing.T,
	stage *LogicalSnapshotStage,
	fixture resultBatchImportFixture,
) {
	t.Helper()
	if _, err := stage.Initialize(
		context.Background(),
		resultBatchInitialState(t, fixture.source.authorityDeviceID),
	); err != nil {
		t.Fatalf("Initialize(stage): %v", err)
	}
	for index, command := range fixture.request.Commands {
		if _, err := stage.importCommand(
			context.Background(),
			command,
		); err != nil {
			t.Fatalf("ImportCommand(%d): %v", index, err)
		}
	}
}

func logicalSnapshotTestRoot(
	t *testing.T,
	fixture resultBatchImportFixture,
	cut LogicalSnapshotCut,
) (logicalsnapshot.Root, logicalSnapshotTestArtifact) {
	t.Helper()
	exported, records, err := collectLogicalSnapshotRecords(
		context.Background(),
		fixture.source.store,
		LogicalSnapshotExportOptions{
			CheckpointEventID: cut.CheckpointEventID,
			SignerDeviceID:    cut.SignerDeviceID,
		},
	)
	if err != nil {
		t.Fatalf("collectLogicalSnapshotRecords(): %v", err)
	}
	if exported != cut {
		t.Fatalf("exported cut = %+v, want %+v", exported, cut)
	}
	var artifact bytes.Buffer
	var expandedBytes uint64
	for index, record := range records {
		written, err := logicalsnapshot.WriteRecord(
			&artifact,
			record.Type,
			record.Payload,
		)
		if err != nil {
			t.Fatalf("WriteRecord(%d): %v", index, err)
		}
		expandedBytes += written
	}
	expanded := bytes.Clone(artifact.Bytes())
	artifactDigest := sha256.Sum256(expanded)
	descriptor := logicalsnapshot.ChunkDescriptor{
		ChunkIndex:       0,
		CompressedLength: expandedBytes,
		ExpandedLength:   expandedBytes,
		SHA256:           artifactDigest,
	}
	page, err := logicalsnapshot.NewDescriptorPage(
		logicalsnapshot.DescriptorPageInput{
			ArtifactID:  "snapshot-install-test",
			PageIndex:   0,
			Descriptors: []logicalsnapshot.ChunkDescriptor{descriptor},
		},
	)
	if err != nil {
		t.Fatalf("NewDescriptorPage(): %v", err)
	}
	unsigned, err := logicalsnapshot.NewUnsignedRoot(
		logicalsnapshot.RootInput{
			ArtifactID:              "snapshot-install-test",
			SessionID:               cut.SessionID,
			WorkspaceID:             cut.WorkspaceID,
			RecoveryGeneration:      cut.RecoveryGeneration,
			CheckpointEventID:       cut.CheckpointEventID,
			ChainIndex:              cut.ChainIndex,
			ChainHash:               chain.Digest(cut.ChainHash),
			ResultIndex:             cut.ResultIndex,
			ResultHash:              chain.Digest(cut.ResultHash),
			ProjectionAccumulator:   chain.Digest(cut.ProjectionAccumulator),
			ProjectionStateDigest:   chain.Digest(cut.ProjectionStateDigest),
			AuthorityVersion:        cut.AuthorityVersion,
			SignerDeviceID:          cut.SignerDeviceID,
			DigestVersion:           cut.DigestVersion,
			ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
			ContentEncoding:         logicalsnapshot.EncodingIdentity,
			ExpandedBytes:           expandedBytes,
			CompressedBytes:         expandedBytes,
			RecordCount:             cut.RecordCount,
			DescriptorPageCount:     1,
			ChunkCount:              1,
			ArtifactDigest:          artifactDigest,
			FinalDescriptorPageHash: page.Hash(),
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedRoot(): %v", err)
	}
	privateKey := resultBatchPrivateKey(1)
	defer clear(privateKey)
	root, err := logicalsnapshot.SignRoot(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignRoot(): %v", err)
	}
	return root, logicalSnapshotTestArtifact{
		pages:  [][]byte{page.CanonicalBytes()},
		chunks: [][]byte{expanded},
	}
}

type logicalSnapshotTestArtifact struct {
	pages  [][]byte
	chunks [][]byte
}

func logicalSnapshotTestProof(
	t *testing.T,
	root logicalsnapshot.Root,
	artifact logicalSnapshotTestArtifact,
) logicalsnapshot.VerifiedExpandedArtifact {
	t.Helper()
	expanded, err := os.CreateTemp(t.TempDir(), "snapshot-expanded-*")
	if err != nil {
		t.Fatalf("os.CreateTemp(snapshot expanded): %v", err)
	}
	defer func() {
		if err := expanded.Close(); err != nil {
			t.Errorf("Close(snapshot expanded): %v", err)
		}
	}()
	sequence, err := os.CreateTemp(t.TempDir(), "snapshot-sequence-*")
	if err != nil {
		t.Fatalf("os.CreateTemp(snapshot sequence): %v", err)
	}
	defer func() {
		if err := sequence.Close(); err != nil {
			t.Errorf("Close(snapshot sequence): %v", err)
		}
	}()
	proof, err := logicalsnapshot.VerifyAndExpandArtifact(
		context.Background(),
		root,
		logicalsnapshot.ArtifactVerificationOptions{
			ExpandedArtifact: expanded,
			SequenceScratch:  sequence,
			OpenPage: func(
				_ context.Context,
				index uint64,
			) (io.ReadCloser, error) {
				if index >= uint64(len(artifact.pages)) {
					return nil, io.EOF
				}
				return io.NopCloser(bytes.NewReader(
					bytes.Clone(artifact.pages[index]),
				)), nil
			},
			OpenChunk: func(
				_ context.Context,
				index uint64,
			) (io.ReadCloser, error) {
				if index >= uint64(len(artifact.chunks)) {
					return nil, io.EOF
				}
				return io.NopCloser(bytes.NewReader(
					bytes.Clone(artifact.chunks[index]),
				)), nil
			},
		},
	)
	if err != nil {
		t.Fatalf("VerifyAndExpandArtifact(): %v", err)
	}
	return proof
}

func logicalSnapshotTailBatch(
	t *testing.T,
	fixture resultBatchImportFixture,
	baseline ApplyHeads,
) VerifiedResultBatchImport {
	t.Helper()
	proposal := testSignedTaskEvent(
		t,
		logicalSnapshotTailEventID,
		2,
	)
	request := rejectedApplyRequest(t, proposal, baseline)
	request.LogIndex = 4
	applied, err := fixture.source.store.Apply(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatalf("Apply(source tail): %v", err)
	}
	exported, found, err := fixture.source.store.ExportResultRange(
		context.Background(),
		ResultRangeOptions{
			AfterResultIndex:          baseline.ResultIndex,
			MaxResults:                replication.MaxBatchResults,
			MaxBytes:                  replication.MaxBatchResultsBytes,
			RequiredAuthorityDeviceID: fixture.source.authorityDeviceID,
		},
	)
	if err != nil || !found || len(exported.Results) != 1 {
		t.Fatalf(
			"ExportResultRange(tail) = found %t, results %d, err %v",
			found,
			len(exported.Results),
			err,
		)
	}
	unsigned, err := replication.NewUnsignedBatch(
		replication.BatchInput{
			FromResultIndex: exported.FromResultIndex,
			ToResultIndex:   exported.ToResultIndex,
			StartResultHash: chain.Digest(exported.StartResultHash),
			EndResultHash:   chain.Digest(exported.EndResultHash),
			StartChainIndex: exported.StartChainIndex,
			StartChainHash:  chain.Digest(exported.StartChainHash),
			EndChainIndex:   exported.EndChainIndex,
			EndChainHash:    chain.Digest(exported.EndChainHash),
			StartProjectionAccumulator: chain.Digest(
				exported.StartProjectionAccumulator,
			),
			EndProjectionAccumulator: chain.Digest(
				exported.EndProjectionAccumulator,
			),
			StartProjectionStateDigest: chain.Digest(
				exported.StartProjectionStateDigest,
			),
			EndProjectionStateDigest: chain.Digest(
				exported.EndProjectionStateDigest,
			),
			Results:                  exported.Results,
			SessionID:                exported.SessionID,
			WorkspaceID:              exported.WorkspaceID,
			RecoveryGeneration:       exported.RecoveryGeneration,
			ServerDeviceID:           fixture.source.authorityDeviceID,
			ServerAppliedResultIndex: exported.ServerAppliedResultIndex,
			ServerAuthorityVersion:   exported.Authority.VoterSetVersion,
		},
	)
	if err != nil {
		t.Fatalf("NewUnsignedBatch(tail): %v", err)
	}
	privateKey := resultBatchPrivateKey(1)
	defer clear(privateKey)
	batch, err := replication.SignBatch(unsigned, privateKey)
	if err != nil {
		t.Fatalf("SignBatch(tail): %v", err)
	}
	mutations := resultBatchStoredMutations(t, fixture.source.store)
	if len(mutations) == 0 {
		t.Fatal("source tail mutations are missing")
	}
	view, err := fixture.source.store.View(context.Background())
	if err != nil {
		t.Fatalf("View(source tail): %v", err)
	}
	return VerifiedResultBatchImport{
		RelayPeerID: resultBatchRelayDeviceID(t),
		Batch:       batch,
		Commands: []VerifiedCommandImport{resultBatchCommand(
			request,
			exported.Results[0],
			mutations[len(mutations)-1],
			applied.Heads,
		)},
		VerifiedAt:            "2026-08-20T01:01:00Z",
		FinalProjectionDigest: view.ProjectionStateDigest,
	}
}

func assertStandaloneSnapshotState(
	t *testing.T,
	database *Store,
	root logicalsnapshot.Root,
	cut LogicalSnapshotCut,
	attestationCount int64,
) {
	t.Helper()
	assertCounts(t, database, map[string]int64{
		"event_provenance":             0,
		"raft_command_applications":    0,
		"raft_snapshot_installs":       0,
		"raft_committed_configuration": 0,
		"settled_nonvoter_state":       1,
		"replication_attestations":     attestationCount,
		"lease_deadlines":              1,
	})
	if _, err := database.VerifiedSettledNonvoterView(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var (
				kind         string
				checkpointID string
				envelope     []byte
				signature    []byte
				from, to     int64
				serverNull   bool
			)
			if err := queryOneArgs(
				conn,
				`SELECT attestation_kind, checkpoint_event_id,
				        envelope_json, signature, from_result_index,
				        to_result_index,
				        server_applied_result_index IS NULL
				   FROM replication_attestations
				  WHERE attestation_id = ?1;`,
				[]any{logicalSnapshotAttestationID(root)},
				func(stmt *sqlite.Stmt) {
					kind = stmt.ColumnText(0)
					checkpointID = stmt.ColumnText(1)
					envelope = bytes.Clone([]byte(stmt.ColumnText(2)))
					signature = bytes.Clone(columnBytes(stmt, 3))
					from = stmt.ColumnInt64(4)
					to = stmt.ColumnInt64(5)
					serverNull = stmt.ColumnBool(6)
				},
			); err != nil {
				return err
			}
			rootSignature := root.Signature()
			if kind != "snapshot" ||
				checkpointID != string(cut.CheckpointEventID) ||
				!bytes.Equal(envelope, root.CanonicalBytes()) ||
				!bytes.Equal(signature, rootSignature[:]) ||
				from != 0 ||
				to != int64(cut.ResultIndex) ||
				!serverNull {
				return errors.New("stored snapshot attestation differs")
			}
			return requireNoStandaloneSnapshotRaftEvidence(conn)
		},
	)
	if err != nil {
		t.Fatalf("verify standalone snapshot state: %v", err)
	}
}

func logicalSnapshotInstallCounts(
	t *testing.T,
	database *Store,
) map[string]int64 {
	t.Helper()
	tables := []string{
		"events",
		"command_results",
		"tasks",
		"replication_attestations",
		"settled_nonvoter_state",
		"local_requests",
		"outbox",
	}
	result := make(map[string]int64, len(tables))
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			for _, table := range tables {
				if err := queryOne(
					conn,
					"SELECT count(*) FROM "+table+";",
					func(stmt *sqlite.Stmt) {
						result[table] = stmt.ColumnInt64(0)
					},
				); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("count install tables: %v", err)
	}
	return result
}

func logicalSnapshotInstallOptions(
	at domain.Timestamp,
) StandaloneLogicalSnapshotInstallOptions {
	return StandaloneLogicalSnapshotInstallOptions{
		VerifiedAt:     at,
		OriginBootID:   testBootID,
		InstalledAt:    at,
		MonotonicNowNS: 1_000,
	}
}
