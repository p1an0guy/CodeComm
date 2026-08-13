package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"zombiezen.com/go/sqlite"
)

func TestApplyPersistsProjectionWritesAndUpsertsMutableRows(t *testing.T) {
	fixture := newProjectionFixture(t)
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)

	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections = fixture.initialWrites
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(initial projections): %v", err)
	}
	assertProjectionRows(t, store, fixture.initialRows)
	assertProjectionTableCounts(t, store)

	second := nextProjectionApplyRequest(t, firstResult.Heads)
	second.Projections = fixture.updatedWrites
	if _, err := store.Apply(context.Background(), second); err != nil {
		t.Fatalf("Apply(updated projections): %v", err)
	}
	assertProjectionRows(t, store, fixture.updatedRows)
	assertProjectionTableCounts(t, store)
	assertConsensus(t, store, 2, 2, 2)
}

func TestCredentialAuthorityRejectsNoncanonicalOrMisorderedProofs(t *testing.T) {
	valid := newProjectionFixture(t).updatedWrites.CredentialAuthority[0]
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid credential authority: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialAuthorityRow)
	}{
		{
			name: "voter order",
			mutate: func(row *CredentialAuthorityRow) {
				row.ActivationProofs[0], row.ActivationProofs[1] =
					row.ActivationProofs[1], row.ActivationProofs[0]
			},
		},
		{
			name: "mismatched voter tag",
			mutate: func(row *CredentialAuthorityRow) {
				row.ActivationProofs[0].VoterDeviceID = row.VoterDeviceIDs[1]
			},
		},
		{
			name: "noncanonical signed object",
			mutate: func(row *CredentialAuthorityRow) {
				row.ActivationProofs[0].CanonicalJSON = []byte(`{"z":3,"a":1}`)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := valid
			row.ActivationProofs = append([]ActivationProof(nil), valid.ActivationProofs...)
			test.mutate(&row)
			if err := row.Validate(); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}

func TestProjectionDeviceApplyLevelMatchesSchemaBound(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)
	member := projectionDevices(t, 1)[0]
	member.MaxApplyLevel = domain.MaxApplyLevel
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	first.Projections.Devices = []device.Device{member}
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatalf("Apply(max apply level): %v", err)
	}
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT max_apply_level FROM devices;",
			int64(domain.MaxApplyLevel),
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	member.MaxApplyLevel++
	second := nextProjectionApplyRequest(t, firstResult.Heads)
	second.Projections.Devices = []device.Device{member}
	if _, err := store.Apply(context.Background(), second); err == nil {
		t.Fatal("Apply(over-limit apply level) succeeded")
	}
	assertCounts(t, store, map[string]int64{
		"devices":         1,
		"events":          1,
		"command_results": 1,
	})
}

func TestApplyRejectsDuplicateImmutableProjectionRows(t *testing.T) {
	fixture := newProjectionFixture(t)
	tests := []struct {
		name   string
		table  string
		writes ProjectionWrites
	}{
		{
			name:  "plan revision",
			table: "plan_revisions",
			writes: ProjectionWrites{
				PlanRevisions: fixture.initialWrites.PlanRevisions,
			},
		},
		{
			name:  "memory record",
			table: "memory_records",
			writes: ProjectionWrites{
				MemoryRecords: fixture.initialWrites.MemoryRecords,
			},
		},
		{
			name:  "credential authorization",
			table: "credential_authorizations",
			writes: ProjectionWrites{
				CredentialAuthorizations: fixture.initialWrites.CredentialAuthorizations,
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
			first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
			first.Projections = test.writes
			firstResult, err := store.Apply(context.Background(), first)
			if err != nil {
				t.Fatalf("Apply(initial %s): %v", test.table, err)
			}

			duplicate := nextProjectionApplyRequest(t, firstResult.Heads)
			duplicate.Projections = test.writes
			if _, err := store.Apply(context.Background(), duplicate); err == nil {
				t.Fatalf("Apply(duplicate %s) succeeded", test.table)
			}

			assertCounts(t, store, map[string]int64{
				test.table:        1,
				"events":          1,
				"command_results": 1,
				"consensus_state": 1,
			})
			assertConsensus(t, store, 1, 1, 1)
			assertProjectionRows(
				t,
				store,
				[]expectedProjectionRow{findProjectionRow(t, fixture.initialRows, test.table)},
			)
		})
	}
}

type projectionFixture struct {
	initialWrites ProjectionWrites
	updatedWrites ProjectionWrites
	initialRows   []expectedProjectionRow
	updatedRows   []expectedProjectionRow
}

type expectedProjectionRow struct {
	table   string
	columns string
	values  []any
}

type canonicalProjectionJSON string

func newProjectionFixture(t *testing.T) projectionFixture {
	t.Helper()

	sessionID := mustProjectionUUIDv7(t, testSessionID)
	workspaceID := mustProjectionUUIDv4(t, string(testWorkspaceID))
	scopeID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000101")
	taskID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000102")
	dependencyA := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000103")
	dependencyB := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000104")
	revisionID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000105")
	memoryID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000106")
	leaseID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000107")
	agentSessionID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000108")
	workingRootID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-000000000109")
	publicationID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-00000000010a")
	publicationEventID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-00000000010b")
	activationEventID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-00000000010d")
	reviewerSessionID := mustProjectionUUIDv7(t, "01890f47-3e72-7000-8000-00000000010e")

	createdAt := mustProjectionTimestamp(t, "2026-08-10T12:00:00Z")
	updatedAt := mustProjectionTimestamp(t, "2026-08-10T12:00:00.1Z")
	secondUpdatedAt := mustProjectionTimestamp(t, "2026-08-10T12:01:00Z")
	issuedAt := mustProjectionWholeSecondTimestamp(t, "2026-08-10T12:00:00Z")
	notBefore := mustProjectionWholeSecondTimestamp(t, "2026-08-10T12:00:01Z")

	deviceValues := projectionDevices(t, 3)
	voterIDs := make([]domain.DeviceID, len(deviceValues))
	for index := range deviceValues {
		voterIDs[index] = deviceValues[index].ID
	}
	member := deviceValues[0]
	member.Role = device.RoleOwner
	member.DaemonVersion = "1.2.3"
	member.MaxApplyLevel = 4
	member.Status = device.StatusActive
	member.EntityVersion = 1
	if err := member.Validate(); err != nil {
		t.Fatalf("initial device: %v", err)
	}
	updatedMember := member
	updatedMember.Role = device.RoleEditor
	updatedMember.DaemonVersion = "1.3.0"
	updatedMember.MaxApplyLevel = 5
	updatedMember.Status = device.StatusRevoked
	updatedMember.EntityVersion = 2
	if err := updatedMember.Validate(); err != nil {
		t.Fatalf("updated device: %v", err)
	}

	stateReason := "waiting on review"
	initialTask := task.Task{
		ID:                  taskID,
		Title:               "Persist projections",
		Body:                "Exercise every digest-covered table.",
		State:               task.StateBlocked,
		StateReason:         &stateReason,
		Priority:            task.PriorityHigh,
		BlockedBy:           []domain.UUIDv7{dependencyA, dependencyB},
		Labels:              []string{"backend", "urgent"},
		OwnerDeviceID:       member.ID,
		OwnerAgentSessionID: agentSessionID,
		EntityVersion:       1,
		CreatedAt:           createdAt,
		UpdatedAt:           updatedAt,
	}
	if err := initialTask.Validate(); err != nil {
		t.Fatalf("initial task: %v", err)
	}
	updatedTask := initialTask
	updatedTask.State = task.StateReady
	updatedTask.StateReason = nil
	updatedTask.OwnerDeviceID = ""
	updatedTask.OwnerAgentSessionID = ""
	updatedTask.IntendedDeviceID = voterIDs[1]
	updatedTask.LastReleaseReason = task.ReleaseForced
	updatedTask.EntityVersion = 2
	updatedTask.UpdatedAt = secondUpdatedAt
	if err := updatedTask.Validate(); err != nil {
		t.Fatalf("updated task: %v", err)
	}

	revision, err := plan.NewRevision(
		revisionID,
		"",
		"Projection persistence",
		"Persist all projection records atomically.",
		[]domain.UUIDv7{taskID, dependencyA},
		member.ID,
		createdAt,
	)
	if err != nil {
		t.Fatalf("NewRevision(): %v", err)
	}
	initialCurrent := plan.Current{
		SessionID:     sessionID,
		RevisionID:    revisionID,
		EntityVersion: 1,
	}
	updatedCurrent := plan.Current{
		SessionID:     sessionID,
		RevisionID:    revisionID,
		EntityVersion: 2,
	}

	memoryRecord, err := memory.NewRecord(
		memoryID,
		memory.ScopeTask,
		taskID,
		"decision",
		"SQLite rows are authoritative.",
		"",
		createdAt,
	)
	if err != nil {
		t.Fatalf("NewRecord(): %v", err)
	}

	initialLease, err := lease.New(
		lease.Fields{
			ID:                   leaseID,
			HolderDeviceID:       member.ID,
			HolderAgentSessionID: agentSessionID,
			Scope:                lease.ScopePath,
			TTLSeconds:           900,
			Status:               lease.StatusActive,
			EntityVersion:        1,
		},
		[]string{"src/**", "docs/design.md"},
	)
	if err != nil {
		t.Fatalf("lease.New(initial): %v", err)
	}
	updatedLease, err := lease.New(
		lease.Fields{
			ID:                   leaseID,
			HolderDeviceID:       member.ID,
			HolderAgentSessionID: agentSessionID,
			Scope:                lease.ScopeTask,
			TaskID:               taskID,
			TTLSeconds:           1_200,
			Status:               lease.StatusReleased,
			ReleaseReason:        lease.ReleaseForced,
			EntityVersion:        2,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("lease.New(updated): %v", err)
	}

	initialVoterSet, err := voterset.New(sessionID, voterIDs, 1)
	if err != nil {
		t.Fatalf("voterset.New(initial): %v", err)
	}
	updatedVoterSet, err := voterset.New(sessionID, voterIDs, 2)
	if err != nil {
		t.Fatalf("voterset.New(updated): %v", err)
	}

	initialAuthority := CredentialAuthorityRow{
		SessionID:        sessionID,
		VoterDeviceIDs:   voterIDs,
		VoterSetVersion:  1,
		ActivationSource: CredentialAuthorityGenesis,
	}
	authorityHandoff := projectionSignature(0x61)
	updatedAuthority := CredentialAuthorityRow{
		SessionID:                   sessionID,
		VoterDeviceIDs:              voterIDs,
		VoterSetVersion:             2,
		ActivationSource:            CredentialAuthorityHandoff,
		ActivationCheckpointEventID: activationEventID,
		ActivationProofs: []ActivationProof{
			{
				VoterDeviceID: voterIDs[0],
				CanonicalJSON: []byte(`{"a":1,"z":3}`),
			},
			{
				VoterDeviceID: voterIDs[1],
				CanonicalJSON: []byte(`{"a":2,"z":2}`),
			},
			{
				VoterDeviceID: voterIDs[2],
				CanonicalJSON: []byte(`{"a":3,"z":1}`),
			},
		},
		PriorAuthoritySigner:  voterIDs[0],
		PriorAuthorityHandoff: &authorityHandoff,
	}

	initialAgent := agentsession.Session{
		ID:            agentSessionID,
		DeviceID:      member.ID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateDisconnected,
		ResumeState:   agentsession.StateWorking,
		WorkingRootID: workingRootID,
		EntityVersion: 1,
	}
	if err := initialAgent.Validate(); err != nil {
		t.Fatalf("initial agent session: %v", err)
	}
	agentProfile := "codex-pro"
	updatedAgent := initialAgent
	updatedAgent.AgentProfileID = &agentProfile
	updatedAgent.State = agentsession.StateEnded
	updatedAgent.ResumeState = agentsession.StateAbsent
	updatedAgent.EndReason = agentsession.EndReasonOperator
	updatedAgent.EntityVersion = 2
	if err := updatedAgent.Validate(); err != nil {
		t.Fatalf("updated agent session: %v", err)
	}

	baseCommit := mustProjectionGitOID(t, "sha1:"+strings.Repeat("1", 40))
	commitOID := mustProjectionGitOID(t, "sha1:"+strings.Repeat("2", 40))
	treeOID := mustProjectionGitOID(t, "sha1:"+strings.Repeat("3", 40))
	mergeBaseA := mustProjectionGitOID(t, "sha1:"+strings.Repeat("4", 40))
	mergeBaseB := mustProjectionGitOID(t, "sha1:"+strings.Repeat("5", 40))
	canonicalCommit := mustProjectionGitOID(t, "sha1:"+strings.Repeat("6", 40))
	candidateCommit := mustProjectionGitOID(t, "sha1:"+strings.Repeat("7", 40))
	replayCommit := mustProjectionGitOID(t, "sha1:"+strings.Repeat("8", 40))
	updatedCanonicalCommit := mustProjectionGitOID(t, "sha1:"+strings.Repeat("9", 40))
	initialRef := publication.CanonicalRef{
		RefName:       publication.CanonicalRefName,
		CommitOID:     commitOID,
		EntityVersion: 1,
	}
	updatedRef := publication.CanonicalRef{
		RefName:       publication.CanonicalRefName,
		CommitOID:     updatedCanonicalCommit,
		EntityVersion: 2,
	}

	var epochPublicKey [ed25519.PublicKeySize]byte
	for index := range epochPublicKey {
		epochPublicKey[index] = byte(0x20 + index)
	}
	keyDigest := sha256.Sum256(epochPublicKey[:])
	endorsements := make([]ClockEndorsement, len(voterIDs))
	for index, voterID := range voterIDs {
		endorsements[index] = ClockEndorsement{
			DeviceID:  voterID,
			Signature: projectionSignature(byte(0x30 + index)),
		}
	}
	bindingSignature := projectionSignature(0x40)
	credentialAuthorization := CredentialAuthorizationRow{
		SessionID:                sessionID,
		DeviceID:                 member.ID,
		Epoch:                    7,
		EpochPublicKey:           epochPublicKey,
		KeyDigest:                keyDigest,
		Role:                     device.RoleOwner,
		IssuedAt:                 issuedAt,
		NotBefore:                notBefore,
		ValiditySeconds:          1_800,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements:        endorsements,
		BindingSignature:         bindingSignature,
		AuthorizationChainIndex:  3,
	}

	pathA := mustProjectionPath(t, "docs/design.md")
	pathB := mustProjectionPath(t, "src/main.go")
	pathC := mustProjectionPath(t, "src/store.go")
	conflictA := mustProjectionConflictID(t, "ccf1"+strings.Repeat("a", 64))
	conflictB := mustProjectionConflictID(t, "ccf1"+strings.Repeat("b", 64))
	conflictID := mustProjectionConflictID(t, "ccf1"+strings.Repeat("c", 64))
	artifactDigest := publication.SHA256Digest(sha256.Sum256([]byte("artifact")))
	receiptDigest := publication.SHA256Digest(sha256.Sum256([]byte("metadata")))
	receiptSignature := publication.Signature(projectionSignature(0x51))
	receipts := []publication.StagingReceipt{{
		SessionID:                 sessionID,
		WorkspaceID:               workspaceID,
		VoterSetVersion:           1,
		PublicationMetadataDigest: receiptDigest,
		VoterDeviceID:             voterIDs[0],
		StagedResultIndex:         2,
		Signature:                 receiptSignature,
	}}
	metadata := publication.Metadata{
		PublicationID:        publicationID,
		ProposalEventID:      publicationEventID,
		TaskID:               taskID,
		AuthorDeviceID:       member.ID,
		AuthorAgentSessionID: agentSessionID,
		BaseCommit:           baseCommit,
		CommitOID:            commitOID,
		TreeOID:              treeOID,
		ParentOIDs:           []domain.GitOID{baseCommit},
		Paths:                []domain.RepositoryPath{pathA, pathB},
		ArtifactDigest:       artifactDigest,
		ResolvesConflictIDs:  []domain.ConflictID{conflictA, conflictB},
		WorkingRootID:        workingRootID,
	}
	initialPublication := publication.Publication{
		Metadata:        metadata,
		StagingReceipts: receipts,
		State:           publication.StateProposed,
		EntityVersion:   1,
	}
	if err := initialPublication.Validate(); err != nil {
		t.Fatalf("initial publication: %v", err)
	}
	updatedPublication := initialPublication
	updatedPublication.State = publication.StateApplied
	updatedPublication.TerminalSource = publication.TerminalSourceApply
	updatedPublication.CanonicalLineageMember = true
	updatedPublication.ReviewVerdict = publication.ReviewVerdictApprove
	updatedPublication.ReviewerDeviceID = voterIDs[1]
	updatedPublication.ReviewerAgentSessionID = reviewerSessionID
	updatedPublication.ReviewActorType = publication.ReviewActorAgent
	updatedPublication.EntityVersion = 2
	if err := updatedPublication.Validate(); err != nil {
		t.Fatalf("updated publication: %v", err)
	}

	initialConflict := conflict.Conflict{
		ID:              conflictID,
		PublicationID:   publicationID,
		MergeKind:       conflict.MergeKindRebase,
		ReplayCommitOID: replayCommit,
		MergeBaseOIDs:   []domain.GitOID{mergeBaseA, mergeBaseB},
		CanonicalCommit: canonicalCommit,
		CandidateCommit: candidateCommit,
		Paths:           []domain.RepositoryPath{pathB, pathC},
		Status:          conflict.StatusUnresolved,
		EntityVersion:   1,
	}
	if err := initialConflict.Validate(); err != nil {
		t.Fatalf("initial conflict: %v", err)
	}
	updatedConflict := initialConflict
	updatedConflict.Status = conflict.StatusResolved
	updatedConflict.ResolutionKind = conflict.ResolutionKindForced
	updatedConflict.ForceReason = "operator verified the merge"
	updatedConflict.ResolvedByDeviceID = member.ID
	updatedConflict.EntityVersion = 2
	if err := updatedConflict.Validate(); err != nil {
		t.Fatalf("updated conflict: %v", err)
	}

	initialPolicy := policy.Policy{
		SessionID:     sessionID,
		Values:        policy.DefaultValues(),
		EntityVersion: 1,
	}
	updatedPolicy := initialPolicy
	updatedPolicy.Values.CheckpointEvents++
	updatedPolicy.Values.AdvertisementIntervalSeconds++
	updatedPolicy.Values.ClusterMinApplyLevel++
	updatedPolicy.EntityVersion = 2
	if err := updatedPolicy.Validate(); err != nil {
		t.Fatalf("updated policy: %v", err)
	}

	initialWrites := ProjectionWrites{
		OriginScopes: []OriginScopeRow{{
			DeviceID:     member.ID,
			ScopeKind:    OriginScopeKindAgent,
			ScopeID:      scopeID,
			LastSequence: 7,
		}},
		AuditCounters: []auditcounter.Counter{{
			DeviceID:        member.ID,
			CredentialEpoch: 7,
			AcceptedCount:   2,
		}},
		Tasks:         []task.Task{initialTask},
		PlanRevisions: []plan.Revision{revision},
		PlanCurrent:   []plan.Current{initialCurrent},
		MemoryRecords: []memory.Record{memoryRecord},
		Leases:        []lease.Lease{initialLease},
		Devices:       []device.Device{member},
		VoterSet:      []voterset.Set{initialVoterSet},
		CredentialAuthority: []CredentialAuthorityRow{
			initialAuthority,
		},
		AgentSessions:            []agentsession.Session{initialAgent},
		CanonicalRefs:            []publication.CanonicalRef{initialRef},
		CredentialAuthorizations: []CredentialAuthorizationRow{credentialAuthorization},
		Publications:             []publication.Publication{initialPublication},
		MergeConflicts:           []conflict.Conflict{initialConflict},
		SessionPolicy:            []policy.Policy{initialPolicy},
	}
	updatedWrites := ProjectionWrites{
		OriginScopes: []OriginScopeRow{{
			DeviceID:     member.ID,
			ScopeKind:    OriginScopeKindAgent,
			ScopeID:      scopeID,
			LastSequence: 8,
		}},
		AuditCounters: []auditcounter.Counter{{
			DeviceID:        member.ID,
			CredentialEpoch: 8,
			AcceptedCount:   3,
		}},
		Tasks:               []task.Task{updatedTask},
		PlanCurrent:         []plan.Current{updatedCurrent},
		Leases:              []lease.Lease{updatedLease},
		Devices:             []device.Device{updatedMember},
		VoterSet:            []voterset.Set{updatedVoterSet},
		CredentialAuthority: []CredentialAuthorityRow{updatedAuthority},
		AgentSessions:       []agentsession.Session{updatedAgent},
		CanonicalRefs:       []publication.CanonicalRef{updatedRef},
		Publications:        []publication.Publication{updatedPublication},
		MergeConflicts:      []conflict.Conflict{updatedConflict},
		SessionPolicy:       []policy.Policy{updatedPolicy},
	}

	voterIDsJSON := canonicalProjectionValue(t, []domain.DeviceID(voterIDs))
	taskIDsJSON := canonicalProjectionValue(
		t,
		[]domain.UUIDv7{taskID, dependencyA},
	)
	blockedByJSON := canonicalProjectionValue(
		t,
		[]domain.UUIDv7{dependencyA, dependencyB},
	)
	labelsJSON := canonicalProjectionValue(t, []string{"backend", "urgent"})
	pathGlobsJSON := canonicalProjectionValue(
		t,
		[]string{"docs/design.md", "src/**"},
	)
	emptyObjectArrayJSON := canonicalProjectionValue(t, []map[string]int{})
	activationProofsJSON := canonicalProjectionValue(t, []map[string]int{
		{"a": 1, "z": 3},
		{"a": 2, "z": 2},
		{"a": 3, "z": 1},
	})
	endorsementsJSON := make([]map[string]string, len(endorsements))
	for index, endorsement := range endorsements {
		endorsementsJSON[index] = map[string]string{
			"device_id": string(endorsement.DeviceID),
			"signature": codec.EncodeBase64URL(endorsement.Signature[:]),
		}
	}
	clockEndorsementsJSON := canonicalProjectionValue(t, endorsementsJSON)
	parentOIDsJSON := canonicalProjectionValue(t, metadata.ParentOIDs)
	publicationPathsJSON := canonicalProjectionValue(t, metadata.Paths)
	resolvedConflictsJSON := canonicalProjectionValue(t, metadata.ResolvesConflictIDs)
	stagingReceiptsJSON := canonicalProjectionValue(t, []map[string]any{{
		"session_id":                  string(sessionID),
		"workspace_id":                string(workspaceID),
		"voter_set_version":           uint64(1),
		"publication_metadata_digest": codec.EncodeBase64URL(receiptDigest[:]),
		"voter_device_id":             string(voterIDs[0]),
		"staged_result_index":         uint64(2),
		"signature":                   codec.EncodeBase64URL(receiptSignature[:]),
	}})
	mergeBaseOIDsJSON := canonicalProjectionValue(t, initialConflict.MergeBaseOIDs)
	conflictPathsJSON := canonicalProjectionValue(t, initialConflict.Paths)
	initialPolicyJSON := canonicalProjectionValue(t, projectionPolicyJSON(initialPolicy.Values))
	updatedPolicyJSON := canonicalProjectionValue(t, projectionPolicyJSON(updatedPolicy.Values))

	initialRows := []expectedProjectionRow{
		{
			table:   "origin_scopes",
			columns: "device_id, scope_kind, scope_id, last_sequence",
			values:  []any{string(member.ID), "agent", string(scopeID), int64(7)},
		},
		{
			table:   "audit_counters",
			columns: "device_id, credential_epoch, accepted_count",
			values:  []any{string(member.ID), int64(7), int64(2)},
		},
		{
			table: "tasks",
			columns: "task_id, title, body, state, state_reason, priority, " +
				"blocked_by_json, labels_json, owner_device_id, " +
				"owner_agent_session_id, intended_device_id, last_release_reason, " +
				"entity_version, created_at, updated_at",
			values: []any{
				string(taskID),
				initialTask.Title,
				initialTask.Body,
				string(task.StateBlocked),
				stateReason,
				int64(task.PriorityHigh),
				blockedByJSON,
				labelsJSON,
				string(member.ID),
				string(agentSessionID),
				nil,
				nil,
				int64(1),
				string(createdAt),
				string(updatedAt),
			},
		},
		{
			table: "plan_revisions",
			columns: "plan_revision_id, supersedes, title, body, task_ids_json, " +
				"proposed_by_device_id, created_at",
			values: []any{
				string(revisionID),
				nil,
				revision.Title(),
				revision.Body(),
				taskIDsJSON,
				string(member.ID),
				string(createdAt),
			},
		},
		{
			table:   "plan_current",
			columns: "session_id, plan_revision_id, entity_version",
			values:  []any{string(sessionID), string(revisionID), int64(1)},
		},
		{
			table:   "memory_records",
			columns: "memory_id, scope, task_id, key, body, supersedes, created_at",
			values: []any{
				string(memoryID),
				string(memory.ScopeTask),
				string(taskID),
				memoryRecord.Key(),
				memoryRecord.Body(),
				nil,
				string(createdAt),
			},
		},
		{
			table: "leases",
			columns: "lease_id, holder_device_id, holder_agent_session_id, scope, " +
				"task_id, path_globs_json, ttl_seconds, status, release_reason, " +
				"entity_version",
			values: []any{
				string(leaseID),
				string(member.ID),
				string(agentSessionID),
				string(lease.ScopePath),
				nil,
				pathGlobsJSON,
				int64(900),
				string(lease.StatusActive),
				nil,
				int64(1),
			},
		},
		{
			table: "devices",
			columns: "device_id, role, identity_public_key, daemon_version, " +
				"max_apply_level, status, entity_version",
			values: []any{
				string(member.ID),
				string(device.RoleOwner),
				[]byte(member.IdentityPublicKey),
				"1.2.3",
				int64(4),
				string(device.StatusActive),
				int64(1),
			},
		},
		{
			table:   "voter_set",
			columns: "session_id, voter_device_ids_json, voter_set_version",
			values:  []any{string(sessionID), voterIDsJSON, int64(1)},
		},
		{
			table: "credential_authority",
			columns: "session_id, voter_device_ids_json, voter_set_version, " +
				"activation_source, activation_checkpoint_event_id, " +
				"activation_proofs_json, prior_authority_signer, " +
				"prior_authority_handoff",
			values: []any{
				string(sessionID),
				voterIDsJSON,
				int64(1),
				string(CredentialAuthorityGenesis),
				nil,
				emptyObjectArrayJSON,
				nil,
				nil,
			},
		},
		{
			table: "agent_sessions",
			columns: "agent_session_id, device_id, client_kind, agent_profile_id, " +
				"state, resume_state, working_root_id, end_reason, entity_version",
			values: []any{
				string(agentSessionID),
				string(member.ID),
				string(agentsession.ClientKindCodex),
				nil,
				string(agentsession.StateDisconnected),
				string(agentsession.StateWorking),
				string(workingRootID),
				nil,
				int64(1),
			},
		},
		{
			table:   "canonical_refs",
			columns: "ref_name, commit_oid, entity_version",
			values:  []any{publication.CanonicalRefName, string(commitOID), int64(1)},
		},
		{
			table: "credential_authorizations",
			columns: "session_id, device_id, epoch, epoch_public_key, key_digest, " +
				"role, issued_at, not_before, validity_seconds, " +
				"authority_voter_set_version, clock_endorsements_json, " +
				"binding_signature, authorization_chain_index",
			values: []any{
				string(sessionID),
				string(member.ID),
				int64(7),
				epochPublicKey[:],
				keyDigest[:],
				string(device.RoleOwner),
				string(issuedAt),
				string(notBefore),
				int64(1_800),
				int64(1),
				clockEndorsementsJSON,
				bindingSignature[:],
				int64(3),
			},
		},
		{
			table: "publications",
			columns: "publication_id, proposal_event_id, supersedes_publication_id, " +
				"task_id, author_device_id, author_agent_session_id, base_commit, " +
				"commit_oid, tree_oid, parent_oids_json, paths_json, artifact_digest, " +
				"resolves_conflict_ids_json, working_root_id, staging_receipts_json, " +
				"state, terminal_source, canonical_lineage_member, review_verdict, " +
				"reviewer_device_id, reviewer_agent_session_id, review_actor_type, " +
				"decision_reason, entity_version",
			values: []any{
				string(publicationID),
				string(publicationEventID),
				nil,
				string(taskID),
				string(member.ID),
				string(agentSessionID),
				string(baseCommit),
				string(commitOID),
				string(treeOID),
				parentOIDsJSON,
				publicationPathsJSON,
				artifactDigest[:],
				resolvedConflictsJSON,
				string(workingRootID),
				stagingReceiptsJSON,
				string(publication.StateProposed),
				nil,
				false,
				nil,
				nil,
				nil,
				nil,
				nil,
				int64(1),
			},
		},
		{
			table: "merge_conflicts",
			columns: "conflict_id, publication_id, merge_kind, replay_commit_oid, " +
				"merge_base_oids_json, canonical_commit, candidate_commit, paths_json, " +
				"status, resolution_kind, resolution_publication_id, force_reason, " +
				"resolved_by_device_id, entity_version",
			values: []any{
				string(conflictID),
				string(publicationID),
				string(conflict.MergeKindRebase),
				string(replayCommit),
				mergeBaseOIDsJSON,
				string(canonicalCommit),
				string(candidateCommit),
				conflictPathsJSON,
				string(conflict.StatusUnresolved),
				nil,
				nil,
				nil,
				nil,
				int64(1),
			},
		},
		{
			table:   "session_policy",
			columns: "session_id, values_json, entity_version",
			values:  []any{string(sessionID), initialPolicyJSON, int64(1)},
		},
	}

	updatedRows := []expectedProjectionRow{
		{
			table:   "origin_scopes",
			columns: "device_id, scope_kind, scope_id, last_sequence",
			values:  []any{string(member.ID), "agent", string(scopeID), int64(8)},
		},
		{
			table:   "audit_counters",
			columns: "device_id, credential_epoch, accepted_count",
			values:  []any{string(member.ID), int64(8), int64(3)},
		},
		{
			table: "tasks",
			columns: "task_id, title, body, state, state_reason, priority, " +
				"blocked_by_json, labels_json, owner_device_id, " +
				"owner_agent_session_id, intended_device_id, last_release_reason, " +
				"entity_version, created_at, updated_at",
			values: []any{
				string(taskID),
				updatedTask.Title,
				updatedTask.Body,
				string(task.StateReady),
				nil,
				int64(task.PriorityHigh),
				blockedByJSON,
				labelsJSON,
				nil,
				nil,
				string(voterIDs[1]),
				string(task.ReleaseForced),
				int64(2),
				string(createdAt),
				string(secondUpdatedAt),
			},
		},
		{
			table:   "plan_current",
			columns: "session_id, plan_revision_id, entity_version",
			values:  []any{string(sessionID), string(revisionID), int64(2)},
		},
		{
			table: "leases",
			columns: "lease_id, holder_device_id, holder_agent_session_id, scope, " +
				"task_id, path_globs_json, ttl_seconds, status, release_reason, " +
				"entity_version",
			values: []any{
				string(leaseID),
				string(member.ID),
				string(agentSessionID),
				string(lease.ScopeTask),
				string(taskID),
				nil,
				int64(1_200),
				string(lease.StatusReleased),
				string(lease.ReleaseForced),
				int64(2),
			},
		},
		{
			table: "devices",
			columns: "device_id, role, identity_public_key, daemon_version, " +
				"max_apply_level, status, entity_version",
			values: []any{
				string(member.ID),
				string(device.RoleEditor),
				[]byte(member.IdentityPublicKey),
				"1.3.0",
				int64(5),
				string(device.StatusRevoked),
				int64(2),
			},
		},
		{
			table:   "voter_set",
			columns: "session_id, voter_device_ids_json, voter_set_version",
			values:  []any{string(sessionID), voterIDsJSON, int64(2)},
		},
		{
			table: "credential_authority",
			columns: "session_id, voter_device_ids_json, voter_set_version, " +
				"activation_source, activation_checkpoint_event_id, " +
				"activation_proofs_json, prior_authority_signer, " +
				"prior_authority_handoff",
			values: []any{
				string(sessionID),
				voterIDsJSON,
				int64(2),
				string(CredentialAuthorityHandoff),
				string(activationEventID),
				activationProofsJSON,
				string(voterIDs[0]),
				authorityHandoff[:],
			},
		},
		{
			table: "agent_sessions",
			columns: "agent_session_id, device_id, client_kind, agent_profile_id, " +
				"state, resume_state, working_root_id, end_reason, entity_version",
			values: []any{
				string(agentSessionID),
				string(member.ID),
				string(agentsession.ClientKindCodex),
				agentProfile,
				string(agentsession.StateEnded),
				nil,
				string(workingRootID),
				string(agentsession.EndReasonOperator),
				int64(2),
			},
		},
		{
			table:   "canonical_refs",
			columns: "ref_name, commit_oid, entity_version",
			values: []any{
				publication.CanonicalRefName,
				string(updatedCanonicalCommit),
				int64(2),
			},
		},
		{
			table: "publications",
			columns: "publication_id, proposal_event_id, supersedes_publication_id, " +
				"task_id, author_device_id, author_agent_session_id, base_commit, " +
				"commit_oid, tree_oid, parent_oids_json, paths_json, artifact_digest, " +
				"resolves_conflict_ids_json, working_root_id, staging_receipts_json, " +
				"state, terminal_source, canonical_lineage_member, review_verdict, " +
				"reviewer_device_id, reviewer_agent_session_id, review_actor_type, " +
				"decision_reason, entity_version",
			values: []any{
				string(publicationID),
				string(publicationEventID),
				nil,
				string(taskID),
				string(member.ID),
				string(agentSessionID),
				string(baseCommit),
				string(commitOID),
				string(treeOID),
				parentOIDsJSON,
				publicationPathsJSON,
				artifactDigest[:],
				resolvedConflictsJSON,
				string(workingRootID),
				stagingReceiptsJSON,
				string(publication.StateApplied),
				string(publication.TerminalSourceApply),
				true,
				string(publication.ReviewVerdictApprove),
				string(voterIDs[1]),
				string(reviewerSessionID),
				string(publication.ReviewActorAgent),
				nil,
				int64(2),
			},
		},
		{
			table: "merge_conflicts",
			columns: "conflict_id, publication_id, merge_kind, replay_commit_oid, " +
				"merge_base_oids_json, canonical_commit, candidate_commit, paths_json, " +
				"status, resolution_kind, resolution_publication_id, force_reason, " +
				"resolved_by_device_id, entity_version",
			values: []any{
				string(conflictID),
				string(publicationID),
				string(conflict.MergeKindRebase),
				string(replayCommit),
				mergeBaseOIDsJSON,
				string(canonicalCommit),
				string(candidateCommit),
				conflictPathsJSON,
				string(conflict.StatusResolved),
				string(conflict.ResolutionKindForced),
				nil,
				updatedConflict.ForceReason,
				string(member.ID),
				int64(2),
			},
		},
		{
			table:   "session_policy",
			columns: "session_id, values_json, entity_version",
			values:  []any{string(sessionID), updatedPolicyJSON, int64(2)},
		},
	}

	return projectionFixture{
		initialWrites: initialWrites,
		updatedWrites: updatedWrites,
		initialRows:   initialRows,
		updatedRows:   updatedRows,
	}
}

func nextProjectionApplyRequest(t *testing.T, previous ApplyHeads) ApplyRequest {
	t.Helper()
	request := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID2, 2))
	request.LogIndex = previous.ResultIndex + 1
	request.AppliedAt = mustProjectionTimestamp(t, "2026-08-10T12:00:01Z")
	request.Audit[0].ResultIndex = previous.ResultIndex + 1
	request.Audit[0].FirstSeenAt = request.AppliedAt
	request.Audit[0].LastSeenAt = request.AppliedAt
	return request
}

func assertProjectionRows(
	t *testing.T,
	store *Store,
	rows []expectedProjectionRow,
) {
	t.Helper()
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		for _, row := range rows {
			statement := "SELECT " + row.columns + " FROM " + row.table + ";"
			if err := queryOne(conn, statement, func(stmt *sqlite.Stmt) {
				assertProjectionColumns(t, row.table, stmt, row.values)
			}); err != nil {
				return fmt.Errorf("%s: %w", row.table, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertProjectionColumns(
	t *testing.T,
	table string,
	stmt *sqlite.Stmt,
	values []any,
) {
	t.Helper()
	if got := stmt.ColumnCount(); got != len(values) {
		t.Errorf("%s column count = %d, want %d", table, got, len(values))
		return
	}
	for column, value := range values {
		gotType := stmt.ColumnType(column)
		switch want := value.(type) {
		case nil:
			if gotType != sqlite.TypeNull {
				t.Errorf(
					"%s column %d type = %s, want %s",
					table,
					column,
					gotType,
					sqlite.TypeNull,
				)
			}
		case string:
			if gotType != sqlite.TypeText || stmt.ColumnText(column) != want {
				t.Errorf(
					"%s column %d = (%s, %q), want (%s, %q)",
					table,
					column,
					gotType,
					stmt.ColumnText(column),
					sqlite.TypeText,
					want,
				)
			}
		case canonicalProjectionJSON:
			got := stmt.ColumnText(column)
			if gotType != sqlite.TypeText || got != string(want) {
				t.Errorf(
					"%s JSON column %d = (%s, %q), want (%s, %q)",
					table,
					column,
					gotType,
					got,
					sqlite.TypeText,
					want,
				)
				continue
			}
			canonical, err := codec.Canonicalize([]byte(got))
			if err != nil {
				t.Errorf("%s JSON column %d is invalid: %v", table, column, err)
			} else if !bytes.Equal(canonical, []byte(got)) {
				t.Errorf("%s JSON column %d is not canonical: %q", table, column, got)
			}
		case int64:
			if gotType != sqlite.TypeInteger || stmt.ColumnInt64(column) != want {
				t.Errorf(
					"%s column %d = (%s, %d), want (%s, %d)",
					table,
					column,
					gotType,
					stmt.ColumnInt64(column),
					sqlite.TypeInteger,
					want,
				)
			}
		case bool:
			if gotType != sqlite.TypeInteger || stmt.ColumnBool(column) != want {
				t.Errorf(
					"%s boolean column %d = (%s, %t), want (%s, %t)",
					table,
					column,
					gotType,
					stmt.ColumnBool(column),
					sqlite.TypeInteger,
					want,
				)
			}
		case []byte:
			got := columnBytes(stmt, column)
			if gotType != sqlite.TypeBlob || !bytes.Equal(got, want) {
				t.Errorf(
					"%s BLOB column %d = (%s, %x), want (%s, %x)",
					table,
					column,
					gotType,
					got,
					sqlite.TypeBlob,
					want,
				)
			}
		default:
			t.Errorf("%s column %d has unsupported expectation %T", table, column, value)
		}
	}
}

func assertProjectionTableCounts(t *testing.T, store *Store) {
	t.Helper()
	assertCounts(t, store, map[string]int64{
		"origin_scopes":             1,
		"audit_counters":            1,
		"tasks":                     1,
		"plan_revisions":            1,
		"plan_current":              1,
		"memory_records":            1,
		"leases":                    1,
		"devices":                   1,
		"voter_set":                 1,
		"credential_authority":      1,
		"agent_sessions":            1,
		"canonical_refs":            1,
		"credential_authorizations": 1,
		"publications":              1,
		"control_file_proposals":    0,
		"merge_conflicts":           1,
		"session_policy":            1,
	})
}

func findProjectionRow(
	t *testing.T,
	rows []expectedProjectionRow,
	table string,
) expectedProjectionRow {
	t.Helper()
	for _, row := range rows {
		if row.table == table {
			return row
		}
	}
	t.Fatalf("no expected projection row for %s", table)
	return expectedProjectionRow{}
}

func canonicalProjectionValue(t *testing.T, value any) canonicalProjectionJSON {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal expected projection JSON: %v", err)
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		t.Fatalf("canonicalize expected projection JSON: %v", err)
	}
	return canonicalProjectionJSON(canonical)
}

func projectionPolicyJSON(values policy.Values) map[string]int64 {
	return map[string]int64{
		"checkpoint_events":                values.CheckpointEvents,
		"checkpoint_interval_seconds":      values.CheckpointIntervalSeconds,
		"lease_min_ttl_seconds":            values.LeaseMinTTLSeconds,
		"lease_default_ttl_seconds":        values.LeaseDefaultTTLSeconds,
		"lease_max_ttl_seconds":            values.LeaseMaxTTLSeconds,
		"agent_claim_limit":                values.AgentClaimLimit,
		"agent_lease_limit":                values.AgentLeaseLimit,
		"device_claim_limit":               values.DeviceClaimLimit,
		"device_lease_limit":               values.DeviceLeaseLimit,
		"advertisement_interval_seconds":   values.AdvertisementIntervalSeconds,
		"audit_depth_per_device_per_epoch": values.AuditDepthPerDevicePerEpoch,
		"max_member_devices":               values.MaxMemberDevices,
		"max_active_agent_sessions":        values.MaxActiveAgentSessions,
		"cluster_min_apply_level":          values.ClusterMinApplyLevel,
	}
}

func projectionDevices(t *testing.T, count int) []device.Device {
	t.Helper()
	devices := make([]device.Device, count)
	for index := range devices {
		seed := make([]byte, ed25519.SeedSize)
		for offset := range seed {
			seed[offset] = byte((index+1)*17 + offset)
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := append(
			ed25519.PublicKey(nil),
			privateKey.Public().(ed25519.PublicKey)...,
		)
		id, err := device.DeriveID(publicKey)
		if err != nil {
			t.Fatalf("device.DeriveID(): %v", err)
		}
		devices[index] = device.Device{
			ID:                id,
			Role:              device.RoleEditor,
			IdentityPublicKey: publicKey,
			DaemonVersion:     "1.0.0",
			MaxApplyLevel:     1,
			Status:            device.StatusActive,
			EntityVersion:     1,
		}
	}
	sort.Slice(devices, func(left, right int) bool {
		return devices[left].ID < devices[right].ID
	})
	return devices
}

func projectionSignature(value byte) [ed25519.SignatureSize]byte {
	var signature [ed25519.SignatureSize]byte
	for index := range signature {
		signature[index] = value + byte(index)
	}
	return signature
}

func mustProjectionUUIDv7(t *testing.T, text string) domain.UUIDv7 {
	t.Helper()
	value, err := domain.ParseUUIDv7(text)
	if err != nil {
		t.Fatalf("ParseUUIDv7(%q): %v", text, err)
	}
	return value
}

func mustProjectionUUIDv4(t *testing.T, text string) domain.UUIDv4 {
	t.Helper()
	value, err := domain.ParseUUIDv4(text)
	if err != nil {
		t.Fatalf("ParseUUIDv4(%q): %v", text, err)
	}
	return value
}

func mustProjectionTimestamp(t *testing.T, text string) domain.Timestamp {
	t.Helper()
	value, err := domain.ParseTimestamp(text)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", text, err)
	}
	return value
}

func mustProjectionWholeSecondTimestamp(
	t *testing.T,
	text string,
) domain.WholeSecondTimestamp {
	t.Helper()
	value, err := domain.ParseWholeSecondTimestamp(text)
	if err != nil {
		t.Fatalf("ParseWholeSecondTimestamp(%q): %v", text, err)
	}
	return value
}

func mustProjectionGitOID(t *testing.T, text string) domain.GitOID {
	t.Helper()
	value, err := domain.ParseGitOID(text)
	if err != nil {
		t.Fatalf("ParseGitOID(%q): %v", text, err)
	}
	return value
}

func mustProjectionPath(t *testing.T, text string) domain.RepositoryPath {
	t.Helper()
	value, err := domain.ParseRepositoryPath(text)
	if err != nil {
		t.Fatalf("ParseRepositoryPath(%q): %v", text, err)
	}
	return value
}

func mustProjectionConflictID(t *testing.T, text string) domain.ConflictID {
	t.Helper()
	value, err := domain.ParseConflictID(text)
	if err != nil {
		t.Fatalf("ParseConflictID(%q): %v", text, err)
	}
	return value
}
