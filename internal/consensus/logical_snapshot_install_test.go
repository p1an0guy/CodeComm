package consensus

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestVerifiedLogicalSnapshotStageInstallsStandalone(t *testing.T) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, &logicalSnapshotTestBoundaries{
			initial: fixture.initial,
		}),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	destination, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "installed", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = destination.Close() })

	installed, err := verified.InstallStandalone(
		context.Background(),
		destination,
		"2026-08-21T17:00:00Z",
	)
	if err != nil {
		t.Fatalf("InstallStandalone(): %v", err)
	}
	if installed.Heads != fixture.sourceView.Heads {
		t.Fatalf(
			"installed heads = %+v, want %+v",
			installed.Heads,
			fixture.sourceView.Heads,
		)
	}
	view, err := destination.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}
	if view.SessionID != fixture.sourceView.SessionID ||
		view.WorkspaceID != fixture.sourceView.WorkspaceID ||
		view.RecoveryGeneration != fixture.sourceView.RecoveryGeneration ||
		view.Heads != fixture.sourceView.Heads ||
		view.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest ||
		view.CurrentTerm != nil ||
		view.LastRaftAppliedLogIndex != nil {
		t.Fatalf(
			"installed/source mismatch:\ninstalled=%+v\nsource=%+v",
			view,
			fixture.sourceView,
		)
	}
	voters, nonvoters, err := settledDurableConfiguration(
		context.Background(),
		destination,
	)
	if err != nil {
		t.Fatalf("settledDurableConfiguration(snapshot): %v", err)
	}
	if len(voters) != 0 || len(nonvoters) != 0 {
		t.Fatalf(
			"standalone snapshot configuration = (%v, %v), want empty",
			voters,
			nonvoters,
		)
	}
	if _, err := verified.InstallStandalone(
		context.Background(),
		destination,
		"2026-08-21T17:00:01Z",
	); !errors.Is(err, store.ErrLogicalSnapshotStageConsumed) {
		t.Fatalf("second InstallStandalone() error = %v", err)
	}
}

func TestVerifiedLogicalSnapshotStageRejectsSameGenerationRaftConversion(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	verified := verifyLogicalSnapshotFixture(t, fixture)
	destination, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "raft-predecessor", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	if _, err := destination.Initialize(
		context.Background(),
		fixture.initial,
	); err != nil {
		t.Fatalf("Initialize(destination): %v", err)
	}

	if _, err := verified.InstallStandalone(
		context.Background(),
		destination,
		"2026-08-21T17:00:00Z",
	); !errors.Is(err, store.ErrLogicalSnapshotInstall) {
		t.Fatalf(
			"same-generation Raft conversion error = %v, want %v",
			err,
			store.ErrLogicalSnapshotInstall,
		)
	}
	mode, err := destination.ReplicaEvidenceMode(context.Background())
	if err != nil || mode != store.ReplicaEvidenceRaft {
		t.Fatalf("destination evidence after rejection = (%q, %v)", mode, err)
	}
}

func TestVerifiedLogicalSnapshotStageAtomicallyMarksRebootstrap(
	t *testing.T,
) {
	t.Parallel()

	retained := settledReplicaTestMember(t)
	fixture := newLogicalSnapshotImportFixtureWithInitial(
		t,
		func(initial *store.InitialState) {
			addSettledReplicaTestMember(initial, retained)
		},
	)
	verified := verifyLogicalSnapshotFixture(t, fixture)
	destination, err := store.Open(
		t.Context(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "rebootstrap", "state.db"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })

	installed, err := verified.InstallStandaloneRebootstrap(
		t.Context(),
		destination,
		"2026-08-21T17:00:00Z",
		retained.ID,
	)
	if err != nil {
		t.Fatalf("InstallStandaloneRebootstrap(): %v", err)
	}
	local := destination.LocalState()
	marker, found, err := local.RebootstrapInstallMarker(t.Context())
	if err != nil || !found ||
		marker.SessionID != fixture.sourceView.SessionID ||
		marker.WorkspaceID != fixture.sourceView.WorkspaceID ||
		marker.RecoveryGeneration != fixture.sourceView.RecoveryGeneration ||
		marker.DeviceID != retained.ID ||
		marker.SnapshotAttestationID != installed.AttestationID {
		t.Fatalf(
			"RebootstrapInstallMarker() = (%+v, %t, %v)",
			marker,
			found,
			err,
		)
	}
	if err := local.ClearRebootstrapInstallMarker(
		t.Context(),
		marker,
	); err != nil {
		t.Fatalf("ClearRebootstrapInstallMarker(): %v", err)
	}
	if marker, found, err = local.RebootstrapInstallMarker(
		t.Context(),
	); err != nil || found {
		t.Fatalf(
			"marker after clear = (%+v, %t, %v)",
			marker,
			found,
			err,
		)
	}
}

func TestVerifiedLogicalSnapshotStageRejectsRebootstrapForAuthority(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	verified := verifyLogicalSnapshotFixture(t, fixture)
	destination, err := store.Open(
		t.Context(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "rebootstrap-voter", "state.db"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })

	if _, err := verified.InstallStandaloneRebootstrap(
		t.Context(),
		destination,
		"2026-08-21T17:00:00Z",
		fixture.signerID,
	); !errors.Is(err, store.ErrRebootstrapInstallMarker) {
		t.Fatalf(
			"InstallStandaloneRebootstrap(authority) error = %v, want %v",
			err,
			store.ErrRebootstrapInstallMarker,
		)
	}
	if _, found, err := destination.LocalState().
		RebootstrapInstallMarker(t.Context()); err != nil || found {
		t.Fatalf("rolled-back marker = (found %t, err %v)", found, err)
	}
}

func TestVerifiedLogicalSnapshotStageInstallsSuccessorOverRaftPredecessor(
	t *testing.T,
) {
	t.Parallel()

	fixture, successor, predecessor := newLogicalSnapshotSuccessorFixture(t)
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, &logicalSnapshotTestBoundaries{
			initial:    fixture.initial,
			successors: []store.SuccessorState{successor},
		}),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	path := filepath.Join(t.TempDir(), "readmission", "state.db")
	destination, err := store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	initial, privateKey, deviceID := nodeTestInitialState(t)
	defer clear(privateKey)
	if _, err := destination.Initialize(
		context.Background(),
		initial,
	); err != nil {
		t.Fatalf("Initialize(destination): %v", err)
	}
	first := nodeTestTaskEvent(
		t,
		privateKey,
		deviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"pre-recovery task",
	)
	applyLogicalSnapshotTestCommand(
		t,
		destination,
		first,
		1,
		1,
		false,
	)
	destinationView, err := destination.View(testContext(t))
	if err != nil {
		t.Fatalf("View(predecessor destination): %v", err)
	}
	if destinationView.SessionID != predecessor.SessionID ||
		destinationView.RecoveryGeneration !=
			predecessor.RecoveryGeneration ||
		destinationView.Heads != predecessor.Heads {
		t.Fatalf(
			"destination predecessor = %+v, want %+v",
			destinationView,
			predecessor,
		)
	}
	installed, err := verified.InstallStandalone(
		context.Background(),
		destination,
		"2026-08-21T17:00:00Z",
	)
	if err != nil {
		t.Fatalf("InstallStandalone(successor): %v", err)
	}
	if installed.Heads != fixture.sourceView.Heads {
		t.Fatalf(
			"installed heads = %+v, want %+v",
			installed.Heads,
			fixture.sourceView.Heads,
		)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("Close(destination): %v", err)
	}
	destination, err = store.Open(
		context.Background(),
		store.Options{Path: path},
	)
	if err != nil {
		t.Fatalf("store.Open(installed successor): %v", err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	reopened, err := destination.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}
	if reopened.SessionID != fixture.sourceView.SessionID ||
		reopened.RecoveryGeneration != 1 ||
		reopened.Heads != fixture.sourceView.Heads ||
		reopened.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatalf(
			"reopened successor/source mismatch:\nreopened=%+v\nsource=%+v",
			reopened,
			fixture.sourceView,
		)
	}
}

func TestVerifiedLogicalSnapshotStageInstallValidatesReceiver(t *testing.T) {
	t.Parallel()

	var verified *VerifiedLogicalSnapshotStage
	if _, err := verified.InstallStandalone(
		context.Background(),
		nil,
		"2026-08-21T17:00:00Z",
	); !errors.Is(err, ErrInvalidLogicalSnapshotImport) {
		t.Fatalf("nil InstallStandalone() error = %v", err)
	}
}

func TestVerifiedLogicalSnapshotStageInstallValidatesMetadataBeforeClock(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	verified := verifyLogicalSnapshotFixture(t, fixture)
	destination, err := store.Open(
		context.Background(),
		store.Options{
			Path: filepath.Join(t.TempDir(), "install-validation", "state.db"),
		},
	)
	if err != nil {
		t.Fatalf("store.Open(): %v", err)
	}
	t.Cleanup(func() { _ = destination.Close() })

	clockCalls := 0
	verified.clock = func() (domain.Timestamp, int64, error) {
		clockCalls++
		return nodeTestClock()()
	}
	for name, test := range map[string]struct {
		ctx        context.Context
		verifiedAt domain.Timestamp
	}{
		"nil context": {
			ctx:        nil,
			verifiedAt: "2026-08-21T17:00:00Z",
		},
		"invalid verification time": {
			ctx:        context.Background(),
			verifiedAt: "not-a-timestamp",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verified.InstallStandalone(
				test.ctx,
				destination,
				test.verifiedAt,
			); !errors.Is(err, ErrInvalidLogicalSnapshotImport) {
				t.Fatalf("InstallStandalone() error = %v", err)
			}
		})
	}
	if clockCalls != 0 {
		t.Fatalf("invalid metadata invoked clock %d times", clockCalls)
	}

	verified.clock = nil
	if _, err := verified.InstallStandalone(
		context.Background(),
		destination,
		"2026-08-21T17:00:00Z",
	); !errors.Is(err, ErrInvalidLogicalSnapshotImport) {
		t.Fatalf("InstallStandalone(nil clock) error = %v", err)
	}
}

func TestSettledReplicaInstallsAheadLogicalSnapshotAndRefreshesAdmission(
	t *testing.T,
) {
	t.Parallel()

	settledMember := settledReplicaTestMember(t)
	fixture := newLogicalSnapshotImportFixtureWithInitial(
		t,
		func(initial *store.InitialState) {
			addSettledReplicaTestMember(initial, settledMember)
		},
	)
	replica := openLogicalSnapshotSettledReplica(
		t,
		fixture.initial,
		settledMember.ID,
		fixture.signerID,
	)
	before, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	if before.Heads.ResultIndex >= fixture.sourceView.Heads.ResultIndex {
		t.Fatalf(
			"destination result index = %d, snapshot = %d",
			before.Heads.ResultIndex,
			fixture.sourceView.Heads.ResultIndex,
		)
	}
	beforePublication := replica.admission.Load()
	replica.recordLiveReplicationObservation(
		fixture.signerID,
		fixture.signerID,
		1,
		before.Heads.ResultIndex,
		fixture.sourceView.Heads.ResultIndex,
	)
	if len(replica.liveReplicationObservationSnapshot()) != 1 {
		t.Fatal("failed to seed stale live replication observation")
	}

	verified := verifyLogicalSnapshotFixture(t, fixture)
	installed, err := replica.InstallLogicalSnapshot(
		testContext(t),
		verified,
		"2026-08-21T18:00:00Z",
	)
	if err != nil {
		t.Fatalf("InstallLogicalSnapshot(): %v", err)
	}
	if installed.Heads != fixture.sourceView.Heads {
		t.Fatalf(
			"installed heads = %+v, want %+v",
			installed.Heads,
			fixture.sourceView.Heads,
		)
	}
	after, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(after): %v", err)
	}
	if after.Heads != fixture.sourceView.Heads ||
		after.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatalf(
			"installed/source mismatch:\ninstalled=%+v\nsource=%+v",
			after,
			fixture.sourceView,
		)
	}
	afterPublication := replica.admission.Load()
	if afterPublication == nil ||
		afterPublication == beforePublication ||
		afterPublication.revision != installed.AdmissionRevision {
		t.Fatalf(
			"admission publication = %+v, before = %+v, revision = %d",
			afterPublication,
			beforePublication,
			installed.AdmissionRevision,
		)
	}
	if _, err := replica.PeerAdmissionSnapshot(); err != nil {
		t.Fatalf("PeerAdmissionSnapshot(): %v", err)
	}
	if observations := replica.liveReplicationObservationSnapshot(); len(
		observations,
	) != 0 {
		t.Fatalf("stale live observations survived install: %+v", observations)
	}
	if _, err := verified.View(
		testContext(t),
	); !errors.Is(err, store.ErrLogicalSnapshotStageConsumed) {
		t.Fatalf("View(consumed stage) error = %v", err)
	}
}

func TestSettledReplicaRejectsIneligibleLogicalSnapshotWithoutConsumption(
	t *testing.T,
) {
	t.Parallel()

	fixture := newLogicalSnapshotImportFixture(t)
	settledMember := settledReplicaTestMember(t)
	targetInitial := fixture.initial
	addSettledReplicaTestMember(&targetInitial, settledMember)
	replica := openLogicalSnapshotSettledReplica(
		t,
		targetInitial,
		settledMember.ID,
		fixture.signerID,
	)
	before, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	beforePublication := replica.admission.Load()
	replica.recordLiveReplicationObservation(
		fixture.signerID,
		fixture.signerID,
		1,
		before.Heads.ResultIndex,
		before.Heads.ResultIndex,
	)

	verified := verifyLogicalSnapshotFixture(t, fixture)
	if _, err := replica.InstallLogicalSnapshot(
		testContext(t),
		verified,
		"2026-08-21T18:01:00Z",
	); !errors.Is(err, ErrSettledReplicaIneligible) {
		t.Fatalf("InstallLogicalSnapshot(ineligible) error = %v", err)
	}
	after, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(after): %v", err)
	}
	if after.Heads != before.Heads ||
		after.ProjectionStateDigest != before.ProjectionStateDigest {
		t.Fatal("ineligible snapshot changed settled state")
	}
	if replica.admission.Load() != beforePublication {
		t.Fatal("ineligible snapshot changed admission publication")
	}
	if len(replica.liveReplicationObservationSnapshot()) != 1 {
		t.Fatal("ineligible snapshot cleared live observations")
	}
	if _, err := verified.View(testContext(t)); err != nil {
		t.Fatalf("View(unconsumed stage): %v", err)
	}
}

func TestSettledReplicaInstallsSuccessorSnapshotBeforeEligibilityTransition(
	t *testing.T,
) {
	t.Parallel()

	settledMember := settledReplicaTestMember(t)
	fixture, successor, predecessor :=
		newLogicalSnapshotSuccessorFixtureWithMutations(
			t,
			func(initial *store.InitialState) {
				addSettledReplicaTestMember(initial, settledMember)
			},
			func(projections *store.ProjectionWrites) {
				for index := range projections.Devices {
					if projections.Devices[index].ID == settledMember.ID {
						projections.Devices[index].Status =
							device.StatusRevoked
						projections.Devices[index].EntityVersion++
						return
					}
				}
				t.Fatal("successor projections omit settled member")
			},
		)
	replica := openLogicalSnapshotSuccessorSettledReplica(
		t,
		fixture.initial,
		predecessor,
		settledMember.ID,
		fixture.signerID,
	)
	statePath := replica.state.Path()
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, &logicalSnapshotTestBoundaries{
			initial:    fixture.initial,
			successors: []store.SuccessorState{successor},
		}),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })

	installed, err := replica.InstallLogicalSnapshot(
		testContext(t),
		verified,
		"2026-08-21T18:01:00Z",
	)
	if err != nil {
		t.Fatalf("InstallLogicalSnapshot(successor): %v", err)
	}
	if installed.Heads != fixture.sourceView.Heads ||
		!replica.transitionRequired.Load() {
		t.Fatalf(
			"successor install = %+v, transition required = %t",
			installed,
			replica.transitionRequired.Load(),
		)
	}
	view, err := replica.View(testContext(t))
	if err != nil {
		t.Fatalf("View(installed successor): %v", err)
	}
	if view.SessionID != fixture.sourceView.SessionID ||
		view.RecoveryGeneration != 1 ||
		view.Heads != fixture.sourceView.Heads ||
		view.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatalf(
			"installed successor/source mismatch:\ninstalled=%+v\nsource=%+v",
			view,
			fixture.sourceView,
		)
	}
	if err := replica.Close(); err != nil {
		t.Fatalf("Close(replica): %v", err)
	}
	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: statePath},
	)
	if err != nil {
		t.Fatalf("store.Open(installed successor): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedView, err := reopened.VerifiedSettledNonvoterView(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(reopened): %v", err)
	}
	if reopenedView.SessionID != fixture.sourceView.SessionID ||
		reopenedView.RecoveryGeneration != 1 ||
		reopenedView.Heads != fixture.sourceView.Heads ||
		reopenedView.ProjectionStateDigest !=
			fixture.sourceView.ProjectionStateDigest {
		t.Fatalf(
			"reopened successor/source mismatch:\nreopened=%+v\nsource=%+v",
			reopenedView,
			fixture.sourceView,
		)
	}
}

func TestSettledReplicaSerializesLogicalSnapshotWithResultImport(
	t *testing.T,
) {
	t.Parallel()

	settledMember := settledReplicaTestMember(t)
	fixture := newLogicalSnapshotImportFixtureWithInitial(
		t,
		func(initial *store.InitialState) {
			addSettledReplicaTestMember(initial, settledMember)
		},
	)
	replica := openLogicalSnapshotSettledReplica(
		t,
		fixture.initial,
		settledMember.ID,
		fixture.signerID,
	)
	verified := verifyLogicalSnapshotFixture(t, fixture)

	clockEntered := make(chan struct{})
	releaseClock := make(chan struct{})
	var enterOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseClock) })
	})
	baseClock := nodeTestClock()
	replica.clock = func() (domain.Timestamp, int64, error) {
		enterOnce.Do(func() { close(clockEntered) })
		<-releaseClock
		return baseClock()
	}

	importDone := make(chan error, 1)
	go func() {
		_, err := replica.ImportResultBatch(
			context.Background(),
			fixture.signerID,
			fixture.batch,
		)
		importDone <- err
	}()
	select {
	case <-clockEntered:
	case <-testContext(t).Done():
		t.Fatal("result import did not enter its serialized apply phase")
	}

	type installResult struct {
		result store.StandaloneLogicalSnapshotInstallResult
		err    error
	}
	installDone := make(chan installResult, 1)
	go func() {
		result, err := replica.InstallLogicalSnapshot(
			context.Background(),
			verified,
			"2026-08-21T18:02:00Z",
		)
		installDone <- installResult{result: result, err: err}
	}()
	select {
	case result := <-installDone:
		t.Fatalf(
			"snapshot install bypassed in-flight result import: %+v",
			result,
		)
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseClock) })
	if err := <-importDone; err != nil {
		t.Fatalf("ImportResultBatch(): %v", err)
	}
	installed := <-installDone
	if installed.err != nil {
		t.Fatalf("InstallLogicalSnapshot(): %v", installed.err)
	}
	if installed.result.Heads != fixture.sourceView.Heads {
		t.Fatalf(
			"serialized install heads = %+v, want %+v",
			installed.result.Heads,
			fixture.sourceView.Heads,
		)
	}
	if observations := replica.liveReplicationObservationSnapshot(); len(
		observations,
	) != 0 {
		t.Fatalf(
			"snapshot did not clear imported live observation: %+v",
			observations,
		)
	}
}

func verifyLogicalSnapshotFixture(
	t *testing.T,
	fixture logicalSnapshotImportFixture,
) *VerifiedLogicalSnapshotStage {
	t.Helper()
	verified, err := VerifyAndStageLogicalSnapshot(
		logicalSnapshotTestContext(t),
		fixture.snapshot.Root,
		fixture.importOptions(t, &logicalSnapshotTestBoundaries{
			initial: fixture.initial,
		}),
	)
	if err != nil {
		t.Fatalf("VerifyAndStageLogicalSnapshot(): %v", err)
	}
	t.Cleanup(func() { _ = verified.Close() })
	return verified
}

func openLogicalSnapshotSettledReplica(
	t *testing.T,
	initial store.InitialState,
	localDeviceID domain.DeviceID,
	voterDeviceID domain.DeviceID,
) *SettledReplica {
	t.Helper()

	targetPath := filepath.Join(t.TempDir(), "settled-target", "state.db")
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
	storeSettledReplicaTestConfiguration(
		t,
		target,
		raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(voterDeviceID),
			Address:  raft.ServerAddress(voterDeviceID),
		}}},
	)
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		"2026-08-21T17:59:00Z",
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	replica, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:     targetPath,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: localDeviceID,
			Clock:         nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	t.Cleanup(func() { _ = replica.Close() })
	return replica
}

func openLogicalSnapshotSuccessorSettledReplica(
	t *testing.T,
	initial store.InitialState,
	predecessor store.StateView,
	localDeviceID domain.DeviceID,
	voterDeviceID domain.DeviceID,
) *SettledReplica {
	t.Helper()

	targetPath := filepath.Join(
		t.TempDir(),
		"settled-successor-target",
		"state.db",
	)
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
	_, privateKey, signerDeviceID := nodeTestInitialState(t)
	defer clear(privateKey)
	first := nodeTestTaskEvent(
		t,
		privateKey,
		signerDeviceID,
		nodeTestBootID1,
		nodeTestEventID1,
		nodeTestTaskID1,
		nodeTestTimestamp1,
		1,
		"pre-recovery task",
	)
	applyLogicalSnapshotTestCommand(t, target, first, 1, 1, false)
	targetView, err := target.View(testContext(t))
	if err != nil {
		t.Fatalf("View(target predecessor): %v", err)
	}
	if targetView.SessionID != predecessor.SessionID ||
		targetView.RecoveryGeneration != predecessor.RecoveryGeneration ||
		targetView.Heads != predecessor.Heads ||
		targetView.ProjectionStateDigest !=
			predecessor.ProjectionStateDigest {
		t.Fatalf(
			"target/source predecessor mismatch:\ntarget=%+v\nsource=%+v",
			targetView,
			predecessor,
		)
	}
	storeSettledReplicaTestConfiguration(
		t,
		target,
		raft.Configuration{Servers: []raft.Server{{
			Suffrage: raft.Voter,
			ID:       raft.ServerID(voterDeviceID),
			Address:  raft.ServerAddress(voterDeviceID),
		}}},
	)
	if _, err := target.EnterSettledNonvoter(
		context.Background(),
		"2026-08-21T17:59:00Z",
	); err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	replica, err := OpenSettledReplica(
		context.Background(),
		SettledReplicaOptions{
			StatePath:     targetPath,
			OriginBootID:  nodeTestBootID1,
			LocalDeviceID: localDeviceID,
			Clock:         nodeTestClock(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSettledReplica(): %v", err)
	}
	t.Cleanup(func() { _ = replica.Close() })
	return replica
}
