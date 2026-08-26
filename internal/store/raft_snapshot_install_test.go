package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"zombiezen.com/go/sqlite"
)

func TestInstallRaftLogicalSnapshotPersistsBaselineAndReopens(
	t *testing.T,
) {
	fixture, stage, _, cut := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	beforeRevision := fixture.target.AdmissionRevision()
	installed, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	)
	if err != nil {
		t.Fatalf("InstallRaftLogicalSnapshot(): %v", err)
	}
	if installed.Heads != raftSnapshotHeads(cut) ||
		installed.Cut != cut ||
		installed.SnapshotID != options.SnapshotID ||
		installed.AdmissionRevision != beforeRevision+1 {
		t.Fatalf("install result = %+v, cut = %+v", installed, cut)
	}
	assertRaftSnapshotInstallView(t, fixture.target, cut, 1, 3)
	assertRaftSnapshotInstallEvidence(t, fixture.target, cut, options)
	record, found, err := fixture.target.VerifiedRaftSnapshotInstall(
		context.Background(),
	)
	if err != nil || !found ||
		record.SnapshotID != options.SnapshotID ||
		record.PayloadDigest != options.PayloadDigest ||
		record.BaselineCommandLogIndex == nil ||
		*record.BaselineCommandLogIndex != 3 {
		t.Fatalf(
			"VerifiedRaftSnapshotInstall() = (%+v, %t, %v)",
			record,
			found,
			err,
		)
	}
	*record.BaselineCommandLogIndex = 99
	again, found, err := fixture.target.VerifiedRaftSnapshotInstall(
		context.Background(),
	)
	if err != nil || !found ||
		again.BaselineCommandLogIndex == nil ||
		*again.BaselineCommandLogIndex != 3 {
		t.Fatalf(
			"VerifiedRaftSnapshotInstall(second) = (%+v, %t, %v)",
			again,
			found,
			err,
		)
	}

	checkpoint, found, err := fixture.target.AppliedCheckpoint(
		context.Background(),
		cut.CheckpointEventID,
	)
	if err != nil || !found ||
		checkpoint.Record.CheckpointEventID != cut.CheckpointEventID ||
		checkpoint.AppliedLogIndex != 3 {
		t.Fatalf(
			"AppliedCheckpoint(snapshot baseline) = (%+v, %t, %v)",
			checkpoint,
			found,
			err,
		)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(installed target): %v", err)
	}
	reopened := openTestStore(t, path, fixedRaftLog{lastIndex: 4})
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopened): %v", err)
	}

	next := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, logicalSnapshotTailEventID, 2),
		installed.Heads,
	)
	next.Term = 2
	next.LogIndex = 5
	next.AppliedAt = domain.Timestamp("2026-08-20T01:00:01Z")
	for index := range next.Audit {
		next.Audit[index].FirstSeenAt = next.AppliedAt
		next.Audit[index].LastSeenAt = next.AppliedAt
	}
	applied, err := reopened.Apply(context.Background(), next)
	if err != nil {
		t.Fatalf("Apply(post-snapshot command): %v", err)
	}
	if applied.Heads.ResultIndex != installed.Heads.ResultIndex+1 {
		t.Fatalf("post-snapshot heads = %+v", applied.Heads)
	}
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(post-snapshot): %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close(post-snapshot): %v", err)
	}

	reopened = openTestStore(t, path, fixedRaftLog{lastIndex: 5})
	view, err := reopened.View(context.Background())
	if err != nil {
		t.Fatalf("View(second reopen): %v", err)
	}
	if view.CurrentTerm == nil ||
		*view.CurrentTerm != 2 ||
		view.LastRaftAppliedLogIndex == nil ||
		*view.LastRaftAppliedLogIndex != 5 ||
		view.Heads.ResultIndex != applied.Heads.ResultIndex {
		t.Fatalf("second-reopen view = %+v", view)
	}
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(second reopen): %v", err)
	}
}

func TestInstallRaftLogicalSnapshotSupportsNullableCommandBaseline(
	t *testing.T,
) {
	fixture, stage, _, cut := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	options.BaselineCommandLogIndex = nil
	options.BaselineCommandTerm = nil
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); err != nil {
		t.Fatalf("InstallRaftLogicalSnapshot(): %v", err)
	}

	view, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.CurrentTerm != nil || view.LastRaftAppliedLogIndex != nil {
		t.Fatalf("nullable baseline view = %+v", view)
	}
	assertRaftSnapshotInstallEvidence(t, fixture.target, cut, options)

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	reopened := openTestStore(t, path, fixedRaftLog{lastIndex: 4})
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopened): %v", err)
	}
	if _, found, err := reopened.AppliedCheckpoint(
		context.Background(),
		cut.CheckpointEventID,
	); !errors.Is(err, ErrAppliedCheckpointIntegrity) || found {
		t.Fatalf(
			"AppliedCheckpoint(without command baseline) = (found=%t, err=%v)",
			found,
			err,
		)
	}
}

func TestRebindVerifiedRaftSnapshotInstallAcceptsOnlyExactReplay(
	t *testing.T,
) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); err != nil {
		t.Fatalf("InstallRaftLogicalSnapshot(): %v", err)
	}
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(before rebind): %v", err)
	}
	beforeRevision := fixture.target.AdmissionRevision()
	rebind := raftSnapshotInstallRebindOptions(options)
	rebind.SnapshotID = "4-1-retried-snapshot"
	record, matched, err := fixture.target.RebindVerifiedRaftSnapshotInstall(
		context.Background(),
		rebind,
	)
	if err != nil || !matched || record.SnapshotID != rebind.SnapshotID {
		t.Fatalf(
			"RebindVerifiedRaftSnapshotInstall() = (%+v, %t, %v)",
			record,
			matched,
			err,
		)
	}
	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(after rebind): %v", err)
	}
	if after.Heads != before.Heads ||
		after.ProjectionStateDigest != before.ProjectionStateDigest ||
		fixture.target.AdmissionRevision() != beforeRevision {
		t.Fatal("receiver-local snapshot rebind changed replicated state")
	}

	tests := []struct {
		name   string
		mutate func(*RaftSnapshotInstallRebindOptions)
	}{
		{
			name: "source",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.SourceServerID = resultBatchRelayDeviceID(t)
			},
		},
		{
			name: "snapshot index",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.SnapshotIndex++
			},
		},
		{
			name: "snapshot term",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.SnapshotTerm++
			},
		},
		{
			name: "configuration index",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.ConfigurationIndex++
			},
		},
		{
			name: "configuration digest",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.ConfigurationDigest[0] ^= 0xff
			},
		},
		{
			name: "payload digest",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				value.PayloadDigest[0] ^= 0xff
			},
		},
		{
			name: "command index",
			mutate: func(value *RaftSnapshotInstallRebindOptions) {
				index := *value.BaselineCommandLogIndex - 1
				value.BaselineCommandLogIndex = &index
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := rebind
			changed.SnapshotID = fmt.Sprintf("4-1-rejected-%d", index)
			changed.BaselineCommandLogIndex = cloneUint64Pointer(
				rebind.BaselineCommandLogIndex,
			)
			changed.BaselineCommandTerm = cloneUint64Pointer(
				rebind.BaselineCommandTerm,
			)
			test.mutate(&changed)
			if rebound, matched, err :=
				fixture.target.RebindVerifiedRaftSnapshotInstall(
					context.Background(),
					changed,
				); err != nil || matched || rebound.SnapshotID != "" {
				t.Fatalf(
					"mismatched rebind = (%+v, %t, %v)",
					rebound,
					matched,
					err,
				)
			}
			current, found, err :=
				fixture.target.VerifiedRaftSnapshotInstall(
					context.Background(),
				)
			if err != nil || !found ||
				current.SnapshotID != rebind.SnapshotID {
				t.Fatalf(
					"rejected rebind changed record = (%+v, %t, %v)",
					current,
					found,
					err,
				)
			}
		})
	}

	replay := ApplyRequest{
		Term:               2,
		LogIndex:           5,
		AppliedAt:          "2026-08-20T01:00:01Z",
		RecoveryGeneration: 0,
		Proposal: fixture.request.Commands[len(
			fixture.request.Commands,
		)-1].Proposal,
	}
	if result, err := fixture.target.Apply(
		context.Background(),
		replay,
	); err != nil || !result.Duplicate {
		t.Fatalf("Apply(post-install duplicate) = (%+v, %v)", result, err)
	}
	advanced := rebind
	advanced.SnapshotID = "4-1-after-command"
	if record, matched, err :=
		fixture.target.RebindVerifiedRaftSnapshotInstall(
			context.Background(),
			advanced,
		); err != nil || matched || record.SnapshotID != "" {
		t.Fatalf(
			"post-command rebind = (%+v, %t, %v)",
			record,
			matched,
			err,
		)
	}
}

func TestVerifiedRaftSnapshotInstallReportsAbsentBaseline(t *testing.T) {
	fixture, _, _, _ := logicalSnapshotInstallFixture(t)
	record, found, err := fixture.target.VerifiedRaftSnapshotInstall(
		context.Background(),
	)
	if err != nil || found || record.SnapshotID != "" {
		t.Fatalf(
			"VerifiedRaftSnapshotInstall(absent) = (%+v, %t, %v)",
			record,
			found,
			err,
		)
	}
}

func TestInstalledRaftSnapshotCanTransitionToSettledNonvoter(
	t *testing.T,
) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	installed, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	)
	if err != nil {
		t.Fatalf("InstallRaftLogicalSnapshot(): %v", err)
	}
	next := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, logicalSnapshotTailEventID, 2),
		installed.Heads,
	)
	next.Term = 2
	next.LogIndex = 5
	next.AppliedAt = domain.Timestamp("2026-08-20T01:00:01Z")
	for index := range next.Audit {
		next.Audit[index].FirstSeenAt = next.AppliedAt
		next.Audit[index].LastSeenAt = next.AppliedAt
	}
	applied, err := fixture.target.Apply(context.Background(), next)
	if err != nil {
		t.Fatalf("Apply(post-snapshot command): %v", err)
	}
	baseline, err := fixture.target.EnterSettledNonvoter(
		context.Background(),
		domain.Timestamp("2026-08-20T01:00:02Z"),
	)
	if err != nil {
		t.Fatalf("EnterSettledNonvoter(): %v", err)
	}
	wantBaseline := applied.Heads
	wantBaseline.PreviousResultHash = Digest{}
	if baseline != wantBaseline {
		t.Fatalf("settled baseline = %+v, want %+v", baseline, wantBaseline)
	}
	if _, err := fixture.target.VerifiedSettledNonvoterView(
		context.Background(),
	); err != nil {
		t.Fatalf("VerifiedSettledNonvoterView(): %v", err)
	}

	path := fixture.target.Path()
	if err := fixture.target.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	reopened := openTestStore(t, path, nil)
	if mode, err := reopened.ReplicaEvidenceMode(
		context.Background(),
	); err != nil || mode != ReplicaEvidenceSettledNonvoter {
		t.Fatalf("ReplicaEvidenceMode() = (%q, %v)", mode, err)
	}
	if err := reopened.VerifyCommitmentHistory(context.Background()); err != nil {
		t.Fatalf("VerifyCommitmentHistory(reopened): %v", err)
	}
}

func TestInstallRaftLogicalSnapshotRollsBackAndCanRetry(t *testing.T) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	before, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(before): %v", err)
	}
	beforeCounts := logicalSnapshotInstallCounts(t, fixture.target)
	beforeRevision := fixture.target.AdmissionRevision()
	injected := errors.New("injected Raft snapshot install failure")
	fixture.target.applyFailpoint = func(stage applyStage) error {
		if stage == applyAfterConsensus {
			return injected
		}
		return nil
	}
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); !errors.Is(err, injected) {
		t.Fatalf("failed install error = %v, want injected", err)
	}
	fixture.target.applyFailpoint = nil

	after, err := fixture.target.View(context.Background())
	if err != nil {
		t.Fatalf("View(after rollback): %v", err)
	}
	if before.Heads != after.Heads ||
		before.ProjectionStateDigest != after.ProjectionStateDigest ||
		beforeRevision != fixture.target.AdmissionRevision() {
		t.Fatal("failed install changed the target cut")
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
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); err != nil {
		t.Fatalf("retry InstallRaftLogicalSnapshot(): %v", err)
	}
}

func TestInstallRaftLogicalSnapshotRejectsTamperedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RaftLogicalSnapshotInstallOptions)
	}{
		{
			name: "source signer",
			mutate: func(options *RaftLogicalSnapshotInstallOptions) {
				options.SourceServerID = resultBatchRelayDeviceID(t)
			},
		},
		{
			name: "snapshot position",
			mutate: func(options *RaftLogicalSnapshotInstallOptions) {
				options.SnapshotIndex = 2
			},
		},
		{
			name: "configuration bytes",
			mutate: func(options *RaftLogicalSnapshotInstallOptions) {
				options.ConfigurationJSON = bytes.Replace(
					options.ConfigurationJSON,
					[]byte(`"voter"`),
					[]byte(`"nonvoter"`),
					1,
				)
			},
		},
		{
			name: "configuration digest",
			mutate: func(options *RaftLogicalSnapshotInstallOptions) {
				options.ConfigurationDigest[0] ^= 0xff
			},
		},
		{
			name: "partial command baseline",
			mutate: func(options *RaftLogicalSnapshotInstallOptions) {
				options.BaselineCommandTerm = nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
			options := raftLogicalSnapshotInstallOptions(
				fixture.source.authorityDeviceID,
			)
			test.mutate(&options)
			before, err := fixture.target.View(context.Background())
			if err != nil {
				t.Fatalf("View(before): %v", err)
			}
			if _, err := fixture.target.InstallRaftLogicalSnapshot(
				context.Background(),
				stage,
				options,
			); !errors.Is(err, ErrRaftSnapshotInstall) {
				t.Fatalf("tampered install error = %v", err)
			}
			after, err := fixture.target.View(context.Background())
			if err != nil {
				t.Fatalf("View(after): %v", err)
			}
			if before.Heads != after.Heads ||
				before.ProjectionStateDigest !=
					after.ProjectionStateDigest {
				t.Fatal("rejected metadata changed the target")
			}
		})
	}
}

func TestInstallRaftLogicalSnapshotRejectsDestinationRaftRegression(
	t *testing.T,
) {
	t.Run("command position", func(t *testing.T) {
		fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
		options := raftLogicalSnapshotInstallOptions(
			fixture.source.authorityDeviceID,
		)
		if _, err := fixture.target.InstallRaftLogicalSnapshot(
			context.Background(),
			stage,
			options,
		); err != nil {
			t.Fatalf("initial install: %v", err)
		}
		replay := ApplyRequest{
			Term:               2,
			LogIndex:           5,
			AppliedAt:          "2026-08-20T01:00:01Z",
			RecoveryGeneration: 0,
			Proposal: fixture.request.Commands[len(
				fixture.request.Commands,
			)-1].Proposal,
		}
		if result, err := fixture.target.Apply(
			context.Background(),
			replay,
		); err != nil || !result.Duplicate {
			t.Fatalf("Apply(duplicate) = (%+v, %v)", result, err)
		}

		other, incoming, _, _ := logicalSnapshotInstallFixture(t)
		options.SourceServerID = other.source.authorityDeviceID
		if _, err := fixture.target.InstallRaftLogicalSnapshot(
			context.Background(),
			incoming,
			options,
		); !errors.Is(err, ErrLogicalSnapshotInstall) {
			t.Fatalf("regressing command position error = %v", err)
		}
		view, err := fixture.target.View(context.Background())
		if err != nil {
			t.Fatalf("View(): %v", err)
		}
		if view.CurrentTerm == nil ||
			*view.CurrentTerm != 2 ||
			view.LastRaftAppliedLogIndex == nil ||
			*view.LastRaftAppliedLogIndex != 5 {
			t.Fatalf("rejected install changed command position: %+v", view)
		}
	})

	t.Run("configuration position", func(t *testing.T) {
		fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
		options := raftLogicalSnapshotInstallOptions(
			fixture.source.authorityDeviceID,
		)
		if _, err := fixture.target.InstallRaftLogicalSnapshot(
			context.Background(),
			stage,
			options,
		); err != nil {
			t.Fatalf("initial install: %v", err)
		}
		if stored, err := fixture.target.StoreCommittedRaftConfiguration(
			context.Background(),
			5,
			options.ConfigurationJSON,
		); err != nil || !stored {
			t.Fatalf(
				"StoreCommittedRaftConfiguration() = (%t, %v)",
				stored,
				err,
			)
		}

		other, incoming, _, _ := logicalSnapshotInstallFixture(t)
		options.SourceServerID = other.source.authorityDeviceID
		options.SnapshotIndex = 6
		options.SnapshotTerm = 2
		if _, err := fixture.target.InstallRaftLogicalSnapshot(
			context.Background(),
			incoming,
			options,
		); !errors.Is(err, ErrLogicalSnapshotInstall) {
			t.Fatalf("regressing configuration error = %v", err)
		}
		configuration, found, err :=
			fixture.target.CommittedRaftConfiguration(
				context.Background(),
			)
		if err != nil || !found || configuration.LogIndex != 5 {
			t.Fatalf(
				"CommittedRaftConfiguration() = (%+v, %t, %v)",
				configuration,
				found,
				err,
			)
		}
	})
}

func raftLogicalSnapshotInstallOptions(
	sourceServerID domain.DeviceID,
) RaftLogicalSnapshotInstallOptions {
	configuration := []byte(fmt.Sprintf(
		`{"servers":[{"address":%q,"id":%q,"suffrage":"voter"}]}`,
		sourceServerID,
		sourceServerID,
	))
	configurationDigest := sha256.Sum256(configuration)
	payloadDigest := sha256.Sum256([]byte("raft-snapshot-payload"))
	baselineIndex := uint64(3)
	baselineTerm := uint64(1)
	return RaftLogicalSnapshotInstallOptions{
		VerifiedAt:              "2026-08-20T01:00:00Z",
		OriginBootID:            testBootID,
		InstalledAt:             "2026-08-20T01:00:00Z",
		MonotonicNowNS:          1_000,
		SourceServerID:          sourceServerID,
		SnapshotID:              "4-1-test-snapshot",
		SnapshotIndex:           4,
		SnapshotTerm:            1,
		ConfigurationIndex:      1,
		ConfigurationJSON:       configuration,
		ConfigurationDigest:     Digest(configurationDigest),
		PayloadDigest:           Digest(payloadDigest),
		BaselineCommandLogIndex: &baselineIndex,
		BaselineCommandTerm:     &baselineTerm,
	}
}

func raftSnapshotInstallRebindOptions(
	options RaftLogicalSnapshotInstallOptions,
) RaftSnapshotInstallRebindOptions {
	return RaftSnapshotInstallRebindOptions{
		SourceServerID:          options.SourceServerID,
		SnapshotID:              options.SnapshotID,
		SnapshotIndex:           options.SnapshotIndex,
		SnapshotTerm:            options.SnapshotTerm,
		ConfigurationIndex:      options.ConfigurationIndex,
		ConfigurationDigest:     options.ConfigurationDigest,
		PayloadDigest:           options.PayloadDigest,
		BaselineCommandLogIndex: cloneUint64Pointer(options.BaselineCommandLogIndex),
		BaselineCommandTerm:     cloneUint64Pointer(options.BaselineCommandTerm),
	}
}

func raftSnapshotHeads(cut LogicalSnapshotCut) ApplyHeads {
	return ApplyHeads{
		ChainIndex:              cut.ChainIndex,
		ChainHash:               cut.ChainHash,
		ResultIndex:             cut.ResultIndex,
		ResultHash:              cut.ResultHash,
		ProjectionAccumulator:   cut.ProjectionAccumulator,
		DigestVersion:           cut.DigestVersion,
		ProjectionSchemaVersion: cut.ProjectionSchemaVersion,
	}
}

func assertRaftSnapshotInstallView(
	t *testing.T,
	database *Store,
	cut LogicalSnapshotCut,
	term uint64,
	logIndex uint64,
) {
	t.Helper()
	view, err := database.View(context.Background())
	if err != nil {
		t.Fatalf("View(): %v", err)
	}
	if view.SessionID != cut.SessionID ||
		view.WorkspaceID != cut.WorkspaceID ||
		view.RecoveryGeneration != cut.RecoveryGeneration ||
		view.Heads != raftSnapshotHeads(cut) ||
		view.ProjectionStateDigest != cut.ProjectionStateDigest ||
		view.CurrentTerm == nil ||
		*view.CurrentTerm != term ||
		view.LastRaftAppliedLogIndex == nil ||
		*view.LastRaftAppliedLogIndex != logIndex {
		t.Fatalf("installed view = %+v, cut = %+v", view, cut)
	}
}

func assertRaftSnapshotInstallEvidence(
	t *testing.T,
	database *Store,
	cut LogicalSnapshotCut,
	options RaftLogicalSnapshotInstallOptions,
) {
	t.Helper()
	err := database.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			state, found, err := readConsensusState(conn)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("active consensus state is missing")
			}
			if err := verifyRaftSnapshotInstallEvidence(conn, state); err != nil {
				return err
			}
			record, found, err := readRaftSnapshotInstallRecord(conn)
			if err != nil {
				return err
			}
			if !found ||
				record.sessionID != cut.SessionID ||
				record.workspaceID != cut.WorkspaceID ||
				record.sourceServerID != options.SourceServerID ||
				record.snapshotID != options.SnapshotID ||
				record.snapshotIndex != options.SnapshotIndex ||
				record.snapshotTerm != options.SnapshotTerm ||
				record.configurationIndex != options.ConfigurationIndex ||
				record.configurationDigest != options.ConfigurationDigest ||
				record.payloadDigest != options.PayloadDigest {
				return fmt.Errorf("stored install record = %+v", record)
			}
			if options.BaselineCommandLogIndex == nil {
				if record.hasBaselineCommand {
					return errors.New("unexpected command baseline")
				}
			} else if !record.hasBaselineCommand ||
				record.baselineCommandLogIndex !=
					*options.BaselineCommandLogIndex ||
				record.baselineCommandTerm != *options.BaselineCommandTerm {
				return fmt.Errorf(
					"stored command baseline = (%d, %d, %t)",
					record.baselineCommandLogIndex,
					record.baselineCommandTerm,
					record.hasBaselineCommand,
				)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("verify Raft snapshot evidence: %v", err)
	}
}

func TestInstallRaftLogicalSnapshotRejectsNonCanonicalConfiguration(
	t *testing.T,
) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	options.ConfigurationJSON = append(
		[]byte{' '},
		options.ConfigurationJSON...,
	)
	options.ConfigurationDigest = Digest(
		sha256.Sum256(options.ConfigurationJSON),
	)
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); !errors.Is(err, ErrRaftSnapshotInstall) {
		t.Fatalf("noncanonical configuration error = %v", err)
	}
}

func TestInstallRaftLogicalSnapshotRejectsInvalidSnapshotID(t *testing.T) {
	fixture, stage, _, _ := logicalSnapshotInstallFixture(t)
	options := raftLogicalSnapshotInstallOptions(
		fixture.source.authorityDeviceID,
	)
	options.SnapshotID = "invalid/snapshot"
	if _, err := fixture.target.InstallRaftLogicalSnapshot(
		context.Background(),
		stage,
		options,
	); !errors.Is(err, ErrRaftSnapshotInstall) {
		t.Fatalf("invalid snapshot ID error = %v", err)
	}
}
