package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

func TestControlManifestGoldenEmptyAndPopulated(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	state := store.LocalState()
	lineage := testControlFileLineage()

	empty, err := state.ControlManifest(context.Background(), lineage)
	if err != nil {
		t.Fatalf("ControlManifest(empty): %v", err)
	}
	assertControlManifestGolden(t, empty, "empty.json")

	firstDigest := sha256.Sum256([]byte("approved instructions\n"))
	first := applyControlFileProposal(
		t,
		store,
		1,
		"AGENTS.md",
		ControlFileUpsert,
		&firstDigest,
	)
	assertPendingControlFileApproval(t, store, first.ProposalEventID)
	projectionBefore, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstDecision := controlFileDecisionInput(first, "2026-08-10T12:01:00Z")
	record, duplicate, err := state.ApproveControlFile(
		context.Background(),
		ControlFileApprovalInput{
			ControlFileDecisionInput: firstDecision,
			ContentStoreRef:          "control/content/agents-v1",
		},
	)
	if err != nil {
		t.Fatalf("ApproveControlFile(first): %v", err)
	}
	if duplicate || record.ManifestVersion != 1 {
		t.Fatalf(
			"first approval = (%+v, duplicate=%v), want version 1 first-seen",
			record,
			duplicate,
		)
	}
	assertProjectionDigestUnchanged(t, store, projectionBefore)

	second := applyControlFileProposal(
		t,
		store,
		2,
		".codecommignore",
		ControlFileDelete,
		nil,
	)
	secondDecision := controlFileDecisionInput(second, "2026-08-10T12:02:00Z")
	if _, duplicate, err := state.ApproveControlFile(
		context.Background(),
		ControlFileApprovalInput{
			ControlFileDecisionInput: secondDecision,
			ContentStoreRef:          "control/tombstones/codecommignore-v1",
		},
	); err != nil {
		t.Fatalf("ApproveControlFile(second): %v", err)
	} else if duplicate {
		t.Fatal("second approval reported an exact replay")
	}

	populated, err := state.ControlManifest(context.Background(), lineage)
	if err != nil {
		t.Fatalf("ControlManifest(populated): %v", err)
	}
	assertControlManifestGolden(t, populated, "populated.json")
	if len(populated.Entries) != 2 ||
		populated.Entries[0].Path != ".codecommignore" ||
		populated.Entries[1].Path != "AGENTS.md" {
		t.Fatalf("manifest order = %+v", populated.Entries)
	}
}

func TestControlFileDecisionsReplacementNoopDeclineAndReplay(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	state := store.LocalState()
	lineage := testControlFileLineage()

	digestA := sha256.Sum256([]byte("approved instructions\n"))
	digestB := sha256.Sum256([]byte("replacement instructions\n"))
	first := applyControlFileProposal(
		t,
		store,
		1,
		"AGENTS.md",
		ControlFileUpsert,
		&digestA,
	)
	firstApproval := ControlFileApprovalInput{
		ControlFileDecisionInput: controlFileDecisionInput(
			first,
			"2026-08-10T12:01:00Z",
		),
		ContentStoreRef: "control/content/agents-a",
	}
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		firstApproval,
	); err != nil {
		t.Fatal(err)
	}

	replacement := applyControlFileProposal(
		t,
		store,
		2,
		"AGENTS.md",
		ControlFileUpsert,
		&digestB,
	)
	replacementApproval := ControlFileApprovalInput{
		ControlFileDecisionInput: controlFileDecisionInput(
			replacement,
			"2026-08-10T12:02:00Z",
		),
		ContentStoreRef: "control/content/agents-b",
	}
	replacementRecord, _, err := state.ApproveControlFile(
		context.Background(),
		replacementApproval,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacementRecord.ManifestVersion != 2 {
		t.Fatalf(
			"replacement manifest version = %d, want 2",
			replacementRecord.ManifestVersion,
		)
	}
	replacedManifest, err := state.ControlManifest(context.Background(), lineage)
	if err != nil {
		t.Fatal(err)
	}

	unchanged := applyControlFileProposal(
		t,
		store,
		3,
		"AGENTS.md",
		ControlFileUpsert,
		&digestB,
	)
	unchangedApproval := ControlFileApprovalInput{
		ControlFileDecisionInput: controlFileDecisionInput(
			unchanged,
			"2026-08-10T12:03:00Z",
		),
		ContentStoreRef: "control/content/agents-b-copy",
	}
	unchangedRecord, duplicate, err := state.ApproveControlFile(
		context.Background(),
		unchangedApproval,
	)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate ||
		unchangedRecord.ManifestVersion != replacedManifest.Version {
		t.Fatalf(
			"unchanged approval = (%+v, duplicate=%v), want current version",
			unchangedRecord,
			duplicate,
		)
	}
	unchangedManifest, err := state.ControlManifest(
		context.Background(),
		lineage,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertSameControlManifestState(t, unchangedManifest, replacedManifest)

	declined := applyControlFileProposal(
		t,
		store,
		4,
		"CLAUDE.md",
		ControlFileUpsert,
		&digestA,
	)
	declineInput := controlFileDecisionInput(
		declined,
		"2026-08-10T12:04:00Z",
	)
	declinedRecord, duplicate, err := state.DeclineControlFile(
		context.Background(),
		declineInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate ||
		declinedRecord.Decision != ControlFileDeclined ||
		declinedRecord.ManifestVersion != 0 {
		t.Fatalf(
			"decline = (%+v, duplicate=%v), want first declined decision",
			declinedRecord,
			duplicate,
		)
	}
	afterDecline, err := state.ControlManifest(context.Background(), lineage)
	if err != nil {
		t.Fatal(err)
	}
	assertSameControlManifestState(t, afterDecline, unchangedManifest)

	replayed, duplicate, err := state.ApproveControlFile(
		context.Background(),
		unchangedApproval,
	)
	if err != nil {
		t.Fatalf("ApproveControlFile(exact replay): %v", err)
	}
	if !duplicate ||
		!controlFileDecisionRecordsEqual(replayed, unchangedRecord) {
		t.Fatalf(
			"approval replay = (%+v, duplicate=%v), want (%+v, true)",
			replayed,
			duplicate,
			unchangedRecord,
		)
	}
	if _, duplicate, err := state.DeclineControlFile(
		context.Background(),
		declineInput,
	); err != nil {
		t.Fatalf("DeclineControlFile(exact replay): %v", err)
	} else if !duplicate {
		t.Fatal("exact decline replay was not identified")
	}

	conflicting := unchangedApproval
	conflicting.ContentStoreRef = "control/content/conflicting"
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		conflicting,
	); !errors.Is(err, ErrControlFileDecisionConflict) {
		t.Fatalf(
			"ApproveControlFile(conflicting replay) error = %v, want conflict",
			err,
		)
	}
	conflictingDecline := declineInput
	conflictingDecline.DecidedAt = "2026-08-10T12:04:01Z"
	if _, _, err := state.DeclineControlFile(
		context.Background(),
		conflictingDecline,
	); !errors.Is(err, ErrControlFileDecisionConflict) {
		t.Fatalf(
			"DeclineControlFile(conflicting replay) error = %v, want conflict",
			err,
		)
	}

	stale := applyControlFileProposal(
		t,
		store,
		5,
		".mcp.json",
		ControlFileUpsert,
		&digestA,
	)
	_ = applyControlFileProposal(
		t,
		store,
		6,
		".mcp.json",
		ControlFileUpsert,
		&digestB,
	)
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		ControlFileApprovalInput{
			ControlFileDecisionInput: controlFileDecisionInput(
				stale,
				"2026-08-10T12:05:00Z",
			),
			ContentStoreRef: "control/content/stale",
		},
	); !errors.Is(err, ErrControlFileProposalStale) {
		t.Fatalf(
			"ApproveControlFile(stale) error = %v, want stale proposal",
			err,
		)
	}

	wrongLineage := firstApproval
	wrongLineage.Lineage.RecoveryGeneration++
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		wrongLineage,
	); !errors.Is(err, ErrControlFileLineageMismatch) {
		t.Fatalf(
			"ApproveControlFile(stale lineage) error = %v, want lineage mismatch",
			err,
		)
	}
}

func TestControlFileDecisionValidationRollbackAndOverflow(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	state := store.LocalState()
	lineage := testControlFileLineage()
	digestA := sha256.Sum256([]byte("approved instructions\n"))
	first := applyControlFileProposal(
		t,
		store,
		1,
		"AGENTS.md",
		ControlFileUpsert,
		&digestA,
	)
	approval := ControlFileApprovalInput{
		ControlFileDecisionInput: controlFileDecisionInput(
			first,
			"2026-08-10T12:01:00Z",
		),
		ContentStoreRef: "control/content/agents-a",
	}

	invalidRef := approval
	invalidRef.ContentStoreRef = "/absolute/reference"
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		invalidRef,
	); !errors.Is(err, ErrInvalidControlFileDecision) {
		t.Fatalf("invalid content reference error = %v", err)
	}
	invalidTime := approval
	invalidTime.DecidedAt = "2026-99-99T99:99:99Z"
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		invalidTime,
	); !errors.Is(err, ErrInvalidControlFileDecision) {
		t.Fatalf("invalid decision time error = %v", err)
	}
	assertPendingControlFileApproval(t, store, first.ProposalEventID)

	injected := errors.New("injected control-file decision failure")
	store.controlFileFailpoint = func(stage controlFileDecisionStage) error {
		if stage == controlFileAfterDecisionWrite {
			return injected
		}
		return nil
	}
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		approval,
	); !errors.Is(err, injected) {
		t.Fatalf("ApproveControlFile(failpoint) error = %v", err)
	}
	assertPendingControlFileApproval(t, store, first.ProposalEventID)
	empty, err := state.ControlManifest(context.Background(), lineage)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Version != InitialControlManifestVersion ||
		empty.PathCount != 0 {
		t.Fatalf("manifest after rollback = %+v", empty)
	}
	store.controlFileFailpoint = nil

	if _, _, err := state.ApproveControlFile(
		context.Background(),
		approval,
	); err != nil {
		t.Fatal(err)
	}
	digestB := sha256.Sum256([]byte("replacement instructions\n"))
	replacement := applyControlFileProposal(
		t,
		store,
		2,
		"AGENTS.md",
		ControlFileUpsert,
		&digestB,
	)
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE control_file_approvals
			    SET manifest_version = ?2
			  WHERE proposal_event_id = ?1;`,
			string(first.ProposalEventID),
			uint64(domain.MaxSafeInteger),
		)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ApproveControlFile(
		context.Background(),
		ControlFileApprovalInput{
			ControlFileDecisionInput: controlFileDecisionInput(
				replacement,
				"2026-08-10T12:02:00Z",
			),
			ContentStoreRef: "control/content/agents-b",
		},
	); !errors.Is(err, ErrControlManifestVersionExhausted) {
		t.Fatalf(
			"ApproveControlFile(overflow) error = %v, want exhaustion",
			err,
		)
	}
	assertPendingControlFileApproval(t, store, replacement.ProposalEventID)
}

func TestControlFileApplyRollbackAndBoundaryInitialization(t *testing.T) {
	t.Run("accepted apply rollback", func(t *testing.T) {
		store := openTestStore(
			t,
			filepath.Join(t.TempDir(), "session", "state.db"),
			nil,
		)
		initializeTestStore(t, store)
		digest := sha256.Sum256([]byte("approved instructions\n"))
		signed, row := controlFileProposalFixture(
			t,
			1,
			"AGENTS.md",
			ControlFileUpsert,
			&digest,
			domain.UUIDv7(testSessionID),
		)
		request := acceptedApplyRequest(t, signed)
		request.ActivityTaskID = ""
		request.Projections.ControlFileProposals = []ControlFileProposalRow{row}
		injected := errors.New("injected apply failure")
		store.applyFailpoint = func(stage applyStage) error {
			if stage == applyAfterProjections {
				return injected
			}
			return nil
		}
		if _, err := store.Apply(
			context.Background(),
			request,
		); !errors.Is(err, injected) {
			t.Fatalf("Apply() error = %v", err)
		}
		assertCounts(t, store, map[string]int64{
			"control_file_proposals": 0,
			"control_file_approvals": 0,
		})
	})

	t.Run("initial boundary", func(t *testing.T) {
		store := openTestStore(
			t,
			filepath.Join(t.TempDir(), "session", "state.db"),
			nil,
		)
		digest := sha256.Sum256([]byte("approved instructions\n"))
		_, row := controlFileProposalFixture(
			t,
			1,
			"AGENTS.md",
			ControlFileUpsert,
			&digest,
			domain.UUIDv7(testSessionID),
		)
		if _, err := store.Initialize(
			context.Background(),
			commitmentInitialState(
				t,
				domain.UUIDv7(testSessionID),
				0,
				ProjectionWrites{
					ControlFileProposals: []ControlFileProposalRow{row},
				},
			),
		); err != nil {
			t.Fatalf("Initialize(): %v", err)
		}
		assertPendingControlFileApproval(t, store, row.ProposalEventID)
		manifest, err := store.LocalState().ControlManifest(
			context.Background(),
			testControlFileLineage(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.PathCount != 0 ||
			manifest.Version != InitialControlManifestVersion {
			t.Fatalf("initial pending manifest = %+v", manifest)
		}
	})
}

func TestControlFileApplyRejectsCrossKindAndPayloadMismatch(t *testing.T) {
	digest := sha256.Sum256([]byte("approved instructions\n"))
	controlSigned, controlRow := controlFileProposalFixture(
		t,
		1,
		"AGENTS.md",
		ControlFileUpsert,
		&digest,
		domain.UUIDv7(testSessionID),
	)
	tests := []struct {
		name   string
		signed event.SignedEvent
		row    ControlFileProposalRow
	}{
		{
			name:   "accepted non-control event",
			signed: testSignedTaskEvent(t, testEventID, 1),
			row:    controlRow,
		},
		{
			name:   "signed payload differs",
			signed: controlSigned,
			row: func() ControlFileProposalRow {
				row := controlRow
				row.Diff = "different projection"
				return row
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := openTestStore(
				t,
				filepath.Join(t.TempDir(), "session", "state.db"),
				nil,
			)
			initializeTestStore(t, value)
			request := acceptedApplyRequest(t, test.signed)
			request.ActivityTaskID = ""
			request.Projections.ControlFileProposals =
				[]ControlFileProposalRow{test.row}
			if _, err := value.Apply(
				context.Background(),
				request,
			); !errors.Is(err, ErrInvalidApply) {
				t.Fatalf("Apply() error = %v, want %v", err, ErrInvalidApply)
			}
			assertCounts(t, value, map[string]int64{
				"control_file_proposals": 0,
				"control_file_approvals": 0,
			})
		})
	}
}

func TestControlFileSuccessorInstallsPendingRows(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	digest := sha256.Sum256([]byte("approved instructions\n"))
	_, predecessorRow := controlFileProposalFixture(
		t,
		1,
		"AGENTS.md",
		ControlFileUpsert,
		&digest,
		domain.UUIDv7(testSessionID),
	)
	predecessor, err := store.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{
				ControlFileProposals: []ControlFileProposalRow{predecessorRow},
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	successorEventID := controlManifestEventID(2)
	successorRow := predecessorRow
	successorRow.ProposalEventID = successorEventID
	successorRow.SessionID = commitmentSuccessorSessionID
	successorRows := ProjectionWrites{
		ControlFileProposals: []ControlFileProposalRow{successorRow},
	}
	postTransformDigest := projectionWritesDigest(t, successorRows)
	predecessorGenesisDigest, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, domain.UUIDv7(testSessionID), 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	successor := SuccessorState{
		SessionID:          commitmentSuccessorSessionID,
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 1,
		GenesisJSON: commitmentSuccessorGenesisJSON(
			t,
			predecessor,
			predecessorGenesisDigest,
			postTransformDigest,
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		Predecessor:               predecessor,
		Projections:               successorRows,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	if _, err := store.InstallSuccessor(
		context.Background(),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	assertPendingControlFileApproval(t, store, successorEventID)
	assertCounts(t, store, map[string]int64{
		"control_file_proposals": 1,
		"control_file_approvals": 1,
	})
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var oldCount int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*) FROM control_file_approvals
			  WHERE proposal_event_id = ?1;`,
			[]any{string(predecessorRow.ProposalEventID)},
			func(stmt *sqlite.Stmt) {
				oldCount = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if oldCount != 0 {
			return errors.New("predecessor approval survived successor")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestControlManifestFailsClosedOnCorruptRows(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*testing.T, *Store, ControlFileProposalRow)
	}{
		{
			name: "missing approval",
			corrupt: func(t *testing.T, store *Store, row ControlFileProposalRow) {
				t.Helper()
				controlManifestExecute(
					t,
					store,
					"DELETE FROM control_file_approvals WHERE proposal_event_id = ?1;",
					string(row.ProposalEventID),
				)
			},
		},
		{
			name: "noncanonical path",
			corrupt: func(t *testing.T, store *Store, row ControlFileProposalRow) {
				t.Helper()
				controlManifestExecute(
					t,
					store,
					"UPDATE control_file_proposals SET path = 'a/../b' WHERE proposal_event_id = ?1;",
					string(row.ProposalEventID),
				)
				controlManifestExecute(
					t,
					store,
					"UPDATE control_file_approvals SET path = 'a/../b' WHERE proposal_event_id = ?1;",
					string(row.ProposalEventID),
				)
			},
		},
		{
			name: "noncanonical time",
			corrupt: func(t *testing.T, store *Store, row ControlFileProposalRow) {
				t.Helper()
				controlManifestExecute(
					t,
					store,
					`UPDATE control_file_approvals
					    SET decided_at = '2026-99-99T99:99:99Z'
					  WHERE proposal_event_id = ?1;`,
					string(row.ProposalEventID),
				)
			},
		},
		{
			name: "unsafe content reference",
			corrupt: func(t *testing.T, store *Store, row ControlFileProposalRow) {
				t.Helper()
				controlManifestExecute(
					t,
					store,
					`UPDATE control_file_approvals
					    SET content_store_ref = '../outside'
					  WHERE proposal_event_id = ?1;`,
					string(row.ProposalEventID),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := openTestStore(
				t,
				filepath.Join(t.TempDir(), "session", "state.db"),
				nil,
			)
			initializeTestStore(t, store)
			digest := sha256.Sum256([]byte("approved instructions\n"))
			row := applyControlFileProposal(
				t,
				store,
				1,
				"AGENTS.md",
				ControlFileUpsert,
				&digest,
			)
			if test.name != "missing approval" &&
				test.name != "noncanonical path" {
				_, _, err := store.LocalState().ApproveControlFile(
					context.Background(),
					ControlFileApprovalInput{
						ControlFileDecisionInput: controlFileDecisionInput(
							row,
							"2026-08-10T12:01:00Z",
						),
						ContentStoreRef: "control/content/agents-a",
					},
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			test.corrupt(t, store, row)
			if _, err := store.LocalState().ControlManifest(
				context.Background(),
				testControlFileLineage(),
			); !errors.Is(err, ErrControlFileStateIntegrity) {
				t.Fatalf(
					"ControlManifest() error = %v, want integrity failure",
					err,
				)
			}
		})
	}
}

type controlManifestGolden struct {
	Version    uint64 `json:"version"`
	Digest     string `json:"digest"`
	EntriesJCS string `json:"entries_jcs"`
}

func assertControlManifestGolden(
	t *testing.T,
	manifest ControlManifest,
	name string,
) {
	t.Helper()
	content, err := os.ReadFile(
		filepath.Join("testdata", "control_manifest", name),
	)
	if err != nil {
		t.Fatal(err)
	}
	var golden controlManifestGolden
	if err := json.Unmarshal(content, &golden); err != nil {
		t.Fatal(err)
	}
	entriesJCS, digest, err := encodeControlManifestEntries(manifest.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != golden.Version ||
		manifest.Digest != digest ||
		codec.EncodeBase64URL(manifest.Digest[:]) != golden.Digest ||
		string(entriesJCS) != golden.EntriesJCS {
		t.Fatalf(
			"manifest = {version:%d digest:%s entries:%s}, want %+v",
			manifest.Version,
			codec.EncodeBase64URL(manifest.Digest[:]),
			entriesJCS,
			golden,
		)
	}
}

func applyControlFileProposal(
	t *testing.T,
	store *Store,
	index uint64,
	path domain.RepositoryPath,
	operation ControlFileOperation,
	digest *[sha256.Size]byte,
) ControlFileProposalRow {
	t.Helper()
	signed, row := controlFileProposalFixture(
		t,
		index,
		path,
		operation,
		digest,
		domain.UUIDv7(testSessionID),
	)
	request := acceptedApplyRequest(t, signed)
	request.LogIndex = index
	request.AppliedAt = domain.Timestamp(
		fmt.Sprintf("2026-08-10T12:00:%02dZ", index),
	)
	request.Audit[0].ResultIndex = index
	request.Audit[0].FirstSeenAt = request.AppliedAt
	request.Audit[0].LastSeenAt = request.AppliedAt
	request.ActivityTaskID = ""
	request.Projections.ControlFileProposals = []ControlFileProposalRow{row}
	if _, err := store.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(control proposal %d): %v", index, err)
	}
	return row
}

func controlFileProposalFixture(
	t *testing.T,
	index uint64,
	path domain.RepositoryPath,
	operation ControlFileOperation,
	digest *[sha256.Size]byte,
	sessionID domain.UUIDv7,
) (event.SignedEvent, ControlFileProposalRow) {
	t.Helper()
	deviceID, privateKey := testStoreSigningIdentity(t)
	binding, err := event.NewMCPBinding(
		deviceID,
		testAgentSessionID,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var encodedDigest any
	var contentSize uint64
	if digest != nil {
		encodedDigest = codec.EncodeBase64URL(digest[:])
		contentSize = 1
	}
	payload, err := json.Marshal(map[string]any{
		"content_digest": encodedDigest,
		"content_size":   contentSize,
		"diff":           "",
		"operation":      string(operation),
		"path":           string(path),
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := controlManifestEventID(index)
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindControlFileChangeProposed,
			EntityID:         event.StringEntityID(string(path)),
			RationaleSummary: "review control file",
			Actions:          []event.Action{},
			Payload:          payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      sessionID,
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      testAppliedAt,
			OriginSequence: index,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	row := ControlFileProposalRow{
		ProposalEventID:    eventID,
		SessionID:          sessionID,
		Path:               path,
		Operation:          operation,
		ContentDigest:      digest,
		ContentSize:        contentSize,
		Diff:               "",
		ProposedByDeviceID: deviceID,
		ChainIndex:         index,
	}
	if err := row.Validate(); err != nil {
		t.Fatalf("control proposal fixture: %v", err)
	}
	return signed, row
}

func controlManifestEventID(index uint64) domain.UUIDv7 {
	return domain.UUIDv7(
		fmt.Sprintf("01890f47-3e72-7000-8000-%012x", 0x100+index),
	)
}

func testControlFileLineage() ControlFileLineage {
	return ControlFileLineage{
		SessionID:          domain.UUIDv7(testSessionID),
		WorkspaceID:        testWorkspaceID,
		RecoveryGeneration: 0,
	}
}

func controlFileDecisionInput(
	row ControlFileProposalRow,
	decidedAt domain.Timestamp,
) ControlFileDecisionInput {
	return ControlFileDecisionInput{
		Lineage: testControlFileLineage(),
		Proposal: ControlFileProposalReference{
			ProposalEventID: row.ProposalEventID,
			Path:            row.Path,
			Operation:       row.Operation,
			ContentDigest:   row.ContentDigest,
			ChainIndex:      row.ChainIndex,
		},
		DecidedAt: decidedAt,
	}
}

func assertPendingControlFileApproval(
	t *testing.T,
	store *Store,
	eventID domain.UUIDv7,
) {
	t.Helper()
	stored, found, err := func() (
		storedControlFileApproval,
		bool,
		error,
	) {
		var (
			row   storedControlFileApproval
			found bool
		)
		err := store.withConn(
			context.Background(),
			func(conn *sqlite.Conn) error {
				var err error
				row, found, err = readStoredControlFileApproval(conn, eventID)
				return err
			},
		)
		return row, found, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	if !found || stored.decision != ControlFilePending {
		t.Fatalf("approval %s = %+v, found=%v", eventID, stored, found)
	}
}

func assertProjectionDigestUnchanged(
	t *testing.T,
	store *Store,
	want Digest,
) {
	t.Helper()
	got, err := store.ProjectionStateDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("projection digest changed from %x to %x", want, got)
	}
}

func assertSameControlManifestState(
	t *testing.T,
	got, want ControlManifest,
) {
	t.Helper()
	if got.Version != want.Version ||
		got.Digest != want.Digest ||
		got.PathCount != want.PathCount ||
		!controlManifestEntriesEqual(got.Entries, want.Entries) {
		t.Fatalf("manifest = %+v, want %+v", got, want)
	}
}

func controlFileDecisionRecordsEqual(
	left, right ControlFileDecisionRecord,
) bool {
	return left.ProposalEventID == right.ProposalEventID &&
		left.SessionID == right.SessionID &&
		left.Path == right.Path &&
		left.Operation == right.Operation &&
		controlFileDigestPointersEqual(
			left.ContentDigest,
			right.ContentDigest,
		) &&
		left.ChainIndex == right.ChainIndex &&
		left.Decision == right.Decision &&
		left.ContentStoreRef == right.ContentStoreRef &&
		left.ManifestVersion == right.ManifestVersion &&
		left.DecidedAt == right.DecidedAt
}

func projectionWritesDigest(
	t *testing.T,
	writes ProjectionWrites,
) Digest {
	t.Helper()
	prepared, err := prepareProjectionWrites(writes)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := projectionTargets(prepared)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]chain.LogicalRow, len(targets))
	for index, target := range targets {
		rows[index] = chain.LogicalRow{
			Table:      target.table.name,
			PrimaryKey: bytes.Clone(target.primaryKey),
			Row:        bytes.Clone(target.expectedAfter),
		}
	}
	digest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		rows,
	)
	if err != nil {
		t.Fatal(err)
	}
	return Digest(digest)
}

func controlManifestExecute(
	t *testing.T,
	store *Store,
	statement string,
	arguments ...any,
) {
	t.Helper()
	if err := store.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			return execute(conn, statement, arguments...)
		},
	); err != nil {
		t.Fatal(err)
	}
}
