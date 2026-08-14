package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

const (
	testEventID           = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	testEventID2          = domain.UUIDv7("01890f47-3e72-7000-8000-000000000011")
	testCheckpointEventID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000012")
	testAuditEventID      = domain.UUIDv7("01890f47-3e72-7000-8000-000000000013")
	testTaskID            = domain.UUIDv7("01890f47-3e72-7000-8000-000000000006")
	testLeaseID           = domain.UUIDv7("01890f47-3e72-7000-8000-000000000007")
	testAgentSessionID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000003")
	testBootID            = domain.UUIDv7("01890f47-3e72-7000-8000-000000000004")
)

var (
	testWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	testAppliedAt   = domain.Timestamp("2026-08-10T12:00:00Z")
)

func TestApplyFirstSeenAcceptedAndSequenceReuseRejected(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	insertOutbox(t, store, first.Proposal)

	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if firstResult.AdmissionRevision != 3 ||
		store.AdmissionRevision() != firstResult.AdmissionRevision {
		t.Fatalf(
			"first admission revision = %d, store = %d, want 3",
			firstResult.AdmissionRevision,
			store.AdmissionRevision(),
		)
	}
	assertCounts(t, store, map[string]int64{
		"events":           1,
		"event_provenance": 1,
		"command_results":  1,
		"activity":         1,
		"audit_events":     1,
		"outbox":           0,
		"consensus_state":  1,
	})
	assertConsensus(t, store, 1, 1, 1)

	reused := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 1),
		firstResult.Heads,
	)
	rejectedResult, err := store.Apply(context.Background(), reused)
	if err != nil {
		t.Fatal(err)
	}
	if rejectedResult.AdmissionRevision != 4 ||
		store.AdmissionRevision() != rejectedResult.AdmissionRevision {
		t.Fatalf(
			"rejected admission revision = %d, store = %d, want 4",
			rejectedResult.AdmissionRevision,
			store.AdmissionRevision(),
		)
	}
	assertCounts(t, store, map[string]int64{
		"events":           1,
		"event_provenance": 1,
		"command_results":  2,
		"activity":         1,
		"audit_events":     2,
		"consensus_state":  1,
	})
	assertConsensus(t, store, 2, 1, 2)

	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM command_results WHERE origin_sequence = 1;",
			2,
		)
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM command_results WHERE outcome_status = 'rejected';",
			1,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyRollsBackAtEveryBoundary(t *testing.T) {
	stages := []applyStage{
		applyAfterEvent,
		applyAfterProvenance,
		applyAfterProjections,
		applyAfterResult,
		applyAfterActivity,
		applyAfterAudit,
		applyAfterCheckpoint,
		applyAfterLeaseDeadlines,
		applyAfterOutbox,
		applyAfterConsensus,
	}
	for _, stage := range stages {
		t.Run(stage.String(), func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
			initializeTestStore(t, store)
			request := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
			insertOutbox(t, store, request.Proposal)
			injected := errors.New("injected apply failure")
			store.applyFailpoint = func(current applyStage) error {
				if current == stage {
					return injected
				}
				return nil
			}

			_, err := store.Apply(context.Background(), request)
			if !errors.Is(err, injected) {
				t.Fatalf("Apply() error = %v, want injected failure", err)
			}
			assertCounts(t, store, map[string]int64{
				"events":           0,
				"event_provenance": 0,
				"command_results":  0,
				"activity":         0,
				"audit_events":     0,
				"consensus_state":  1,
				"outbox":           1,
			})
			assertConsensus(t, store, 0, 0, 0)
			if revision := store.AdmissionRevision(); revision != 2 {
				t.Fatalf(
					"failed apply admission revision = %d, want 2",
					revision,
				)
			}
		})
	}
}

func TestApplyCancellationRollsBack(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)
	request := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	ctx, cancel := context.WithCancel(context.Background())
	store.applyFailpoint = func(stage applyStage) error {
		if stage == applyAfterEvent {
			cancel()
			return ctx.Err()
		}
		return nil
	}

	_, err := store.Apply(ctx, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() error = %v, want context.Canceled", err)
	}
	assertCounts(t, store, map[string]int64{
		"events":           0,
		"event_provenance": 0,
		"command_results":  0,
		"consensus_state":  1,
	})
	assertConsensus(t, store, 0, 0, 0)
}

func TestApplyRejectsStaleRaftPositionWithoutWrites(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}

	stale := rejectedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID2, 2),
		firstResult.Heads,
	)
	stale.LogIndex = 1
	_, err = store.Apply(context.Background(), stale)
	if !errors.Is(err, ErrApplyConflict) {
		t.Fatalf("Apply() error = %v, want ErrApplyConflict", err)
	}
	assertCounts(t, store, map[string]int64{"command_results": 1})
}

func TestApplyCommitsCheckpointAndLeaseDeadline(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	initializeTestStore(t, store)
	first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
	firstResult, err := store.Apply(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}

	checkpointRequest := nextCheckpointApplyRequest(
		t,
		firstResult.Heads,
		testCheckpointEventID,
		1,
		2,
		domain.Timestamp("2026-08-10T12:00:01Z"),
	)
	checkpointEvent := checkpointRequest.Proposal
	activeLease := testActiveLease(t, checkpointEvent.Proposal().Origin.DeviceID())
	checkpointRequest.Projections.Leases = []lease.Lease{activeLease}
	checkpointRequest.LeaseDeadlines = []LeaseDeadlineRecord{{
		LeaseID:             testLeaseID,
		EntityVersion:       1,
		OriginBootID:        testBootID,
		MonotonicDeadlineNS: 123456789,
		DisplayDeadlineAt:   domain.Timestamp("2026-08-10T12:15:01Z"),
	}}
	insertOutbox(t, store, checkpointRequest.Proposal)

	checkpointResult, err := store.Apply(context.Background(), checkpointRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertCounts(t, store, map[string]int64{
		"events":            2,
		"event_provenance":  2,
		"command_results":   2,
		"chain_checkpoints": 1,
		"leases":            1,
		"lease_deadlines":   1,
		"outbox":            0,
	})
	assertConsensus(t, store, 2, 2, 2)

	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT covered_result_index FROM chain_checkpoints;",
			1,
		)
		assertIntQuery(
			t,
			conn,
			"SELECT monotonic_deadline_ns FROM lease_deadlines;",
			123456789,
		)
		assertTextQuery(
			t,
			conn,
			"SELECT display_deadline_at FROM lease_deadlines;",
			"2026-08-10T12:15:01Z",
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	releasedLease := activeLease
	releasedLease.Status = lease.StatusReleased
	releasedLease.ReleaseReason = lease.ReleaseVoluntary
	releasedLease.EntityVersion = 2
	releaseRequest := nextAcceptedApplyRequest(
		testSignedDaemonActivityEvent(t, testAuditEventID, 2),
		1,
		3,
		domain.Timestamp("2026-08-10T12:00:02Z"),
	)
	releaseRequest.RecordActivity = true
	releaseRequest.Projections.Leases = []lease.Lease{releasedLease}
	releaseRequest.DeleteLeaseDeadlines = []LeaseDeadlineKey{{
		LeaseID:       testLeaseID,
		EntityVersion: 1,
	}}
	if _, err := store.Apply(context.Background(), releaseRequest); err != nil {
		t.Fatal(err)
	}
	if checkpointResult.Heads.ResultIndex != 2 {
		t.Fatalf("checkpoint result index = %d, want 2", checkpointResult.Heads.ResultIndex)
	}
	assertCounts(t, store, map[string]int64{
		"leases":          1,
		"lease_deadlines": 0,
	})
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(t, conn, "SELECT status FROM leases;", "released")
		assertIntQuery(t, conn, "SELECT entity_version FROM leases;", 2)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyRollsBackCheckpointAndLeaseDeadlineAtEveryBoundary(t *testing.T) {
	stages := []applyStage{
		applyAfterEvent,
		applyAfterProvenance,
		applyAfterProjections,
		applyAfterResult,
		applyAfterActivity,
		applyAfterAudit,
		applyAfterCheckpoint,
		applyAfterLeaseDeadlines,
		applyAfterOutbox,
		applyAfterConsensus,
	}
	for _, stage := range stages {
		t.Run(stage.String(), func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
			initializeTestStore(t, store)
			first := acceptedApplyRequest(t, testSignedTaskEvent(t, testEventID, 1))
			firstResult, err := store.Apply(context.Background(), first)
			if err != nil {
				t.Fatal(err)
			}

			request := nextCheckpointApplyRequest(
				t,
				firstResult.Heads,
				testCheckpointEventID,
				1,
				2,
				domain.Timestamp("2026-08-10T12:00:01Z"),
			)
			request.Projections.Leases = []lease.Lease{
				testActiveLease(
					t,
					request.Proposal.Proposal().Origin.DeviceID(),
				),
			}
			request.LeaseDeadlines = []LeaseDeadlineRecord{{
				LeaseID:             testLeaseID,
				EntityVersion:       1,
				OriginBootID:        testBootID,
				MonotonicDeadlineNS: 123456789,
				DisplayDeadlineAt:   domain.Timestamp("2026-08-10T12:15:01Z"),
			}}
			insertOutbox(t, store, request.Proposal)
			injected := errors.New("injected apply failure")
			store.applyFailpoint = func(current applyStage) error {
				if current == stage {
					return injected
				}
				return nil
			}

			_, err = store.Apply(context.Background(), request)
			if !errors.Is(err, injected) {
				t.Fatalf("Apply() error = %v, want injected failure", err)
			}
			assertCounts(t, store, map[string]int64{
				"events":            1,
				"event_provenance":  1,
				"command_results":   1,
				"chain_checkpoints": 0,
				"leases":            0,
				"lease_deadlines":   0,
				"outbox":            1,
			})
			assertConsensus(t, store, 1, 1, 1)
		})
	}
}

func TestApplyRequestValidatesCheckpointBinding(t *testing.T) {
	previousHeads := ApplyHeads{
		ChainIndex:              1,
		ChainHash:               digestWithByte(0x11),
		ResultIndex:             1,
		ResultHash:              digestWithByte(0x22),
		ProjectionAccumulator:   digestWithByte(0x33),
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	}
	valid := nextCheckpointApplyRequest(
		t,
		previousHeads,
		testCheckpointEventID,
		1,
		2,
		domain.Timestamp("2026-08-10T12:00:01Z"),
	)
	if err := valid.validate(); err != nil {
		t.Fatalf("valid checkpoint request: %v", err)
	}

	otherSessionID := domain.UUIDv7("01890f47-3e72-7000-8000-000000000021")
	otherWorkspaceID := domain.UUIDv4("550e8400-e29b-41d4-a716-446655440001")
	tests := []struct {
		name   string
		mutate func(*ApplyRequest)
	}{
		{
			name: "accepted checkpoint missing row",
			mutate: func(request *ApplyRequest) {
				request.Checkpoint = nil
			},
		},
		{
			name: "row attached to non-checkpoint event",
			mutate: func(request *ApplyRequest) {
				request.Proposal = testSignedTaskEvent(t, testCheckpointEventID, 2)
			},
		},
		{
			name: "session mismatch",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.SessionID = otherSessionID
				request.Checkpoint = &copy
			},
		},
		{
			name: "workspace mismatch",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.WorkspaceID = otherWorkspaceID
				request.Checkpoint = &copy
			},
		},
		{
			name: "generation mismatch",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.RecoveryGeneration++
				request.Checkpoint = &copy
			},
		},
		{
			name: "chain index ahead of result index",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.CoveredChainIndex = copy.CoveredResultIndex + 1
				request.Checkpoint = &copy
			},
		},
		{
			name: "typed field differs from unsigned JSON",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.CoveredResultHash[0] ^= 0xff
				request.Checkpoint = &copy
			},
		},
		{
			name: "unsigned JSON differs from typed fields",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.CheckpointJSON = []byte(`{}`)
				request.Checkpoint = &copy
			},
		},
		{
			name: "row signature differs from proposal",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.AuthoritySignature[0] ^= 0xff
				request.Checkpoint = &copy
			},
		},
		{
			name: "proposal payload differs from row",
			mutate: func(request *ApplyRequest) {
				copy := *request.Checkpoint
				copy.AuthoritySignature[0] ^= 0xff
				payload, err := copy.canonicalJSON(true)
				if err != nil {
					t.Fatal(err)
				}
				request.Proposal = testSignedDaemonEventWithPayload(
					t,
					testCheckpointEventID,
					event.KindConsensusCheckpoint,
					1,
					payload,
					"",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if err := request.validate(); !errors.Is(err, ErrInvalidApply) {
				t.Fatalf("validate() error = %v, want ErrInvalidApply", err)
			}
		})
	}
}

func acceptedApplyRequest(t *testing.T, proposal event.SignedEvent) ApplyRequest {
	t.Helper()
	return ApplyRequest{
		Term:               1,
		LogIndex:           1,
		AppliedAt:          testAppliedAt,
		RecoveryGeneration: 0,
		Proposal:           proposal,
		Outcome: CommandOutcome{
			Status: OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		RecordActivity: true,
		ActivityTaskID: testTaskID,
		Audit: []AuditRecord{{
			SessionID:        domain.UUIDv7(testSessionID),
			SourceKind:       AuditAcceptedEvent,
			EventID:          proposal.Proposal().EventID,
			ResultIndex:      1,
			ReporterDeviceID: proposal.Proposal().Origin.DeviceID(),
			ActorType:        proposal.Proposal().Origin.ActorType(),
			IPCChannel:       "agent",
			ActionCode:       "task.created",
			OutcomeCode:      "accepted",
			Subject:          string(testTaskID),
			DetailsJSON:      []byte(`{}`),
			FirstSeenAt:      testAppliedAt,
			LastSeenAt:       testAppliedAt,
			ObservationCount: 1,
		}},
	}
}

func initializeTestStore(t *testing.T, store *Store) ApplyHeads {
	t.Helper()
	const genesis = `{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000002","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	heads, err := store.Initialize(context.Background(), InitialState{
		SessionID:               domain.UUIDv7(testSessionID),
		WorkspaceID:             testWorkspaceID,
		GenesisJSON:             []byte(genesis),
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
	})
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	return heads
}

func nextAcceptedApplyRequest(
	proposal event.SignedEvent,
	term uint64,
	logIndex uint64,
	appliedAt domain.Timestamp,
) ApplyRequest {
	return ApplyRequest{
		Term:               term,
		LogIndex:           logIndex,
		AppliedAt:          appliedAt,
		RecoveryGeneration: 0,
		Proposal:           proposal,
		Outcome: CommandOutcome{
			Status: OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
	}
}

func rejectedApplyRequest(
	t *testing.T,
	proposal event.SignedEvent,
	previous ApplyHeads,
) ApplyRequest {
	t.Helper()
	return ApplyRequest{
		Term:               1,
		LogIndex:           2,
		AppliedAt:          domain.Timestamp("2026-08-10T12:00:01Z"),
		RecoveryGeneration: 0,
		Proposal:           proposal,
		Outcome: CommandOutcome{
			Status: OutcomeRejected,
			Code:   "origin_sequence_reused",
			JSON: []byte(
				`{"code":"origin_sequence_reused","status":"rejected"}`,
			),
		},
		Audit: []AuditRecord{{
			SessionID:        domain.UUIDv7(testSessionID),
			SourceKind:       AuditCommittedRejection,
			EventID:          proposal.Proposal().EventID,
			ResultIndex:      previous.ResultIndex + 1,
			ReporterDeviceID: proposal.Proposal().Origin.DeviceID(),
			ActorType:        proposal.Proposal().Origin.ActorType(),
			IPCChannel:       "agent",
			ActionCode:       "task.created",
			OutcomeCode:      "origin_sequence_reused",
			Subject:          string(testTaskID),
			DetailsJSON:      []byte(`{}`),
			FirstSeenAt:      domain.Timestamp("2026-08-10T12:00:01Z"),
			LastSeenAt:       domain.Timestamp("2026-08-10T12:00:01Z"),
			ObservationCount: 1,
		}},
	}
}

func testSignedTaskEvent(
	t *testing.T,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	deviceID, err := codec.DeriveDeviceID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := event.NewMCPBinding(
		domain.DeviceID(deviceID),
		testAgentSessionID,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindTaskCreated,
			EntityID:         event.StringEntityID(string(testTaskID)),
			RationaleSummary: "create test task",
			Actions:          []event.Action{},
			Payload:          []byte(`{}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        eventID,
			SessionID:      domain.UUIDv7(testSessionID),
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      testAppliedAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testSignedDaemonActivityEvent(
	t *testing.T,
	eventID domain.UUIDv7,
	sequence uint64,
) event.SignedEvent {
	t.Helper()
	return testSignedDaemonEventWithPayload(
		t,
		eventID,
		event.KindActivityRecorded,
		sequence,
		[]byte(`{}`),
		"release lease deadline",
	)
}

func testSignedDaemonEventWithPayload(
	t *testing.T,
	eventID domain.UUIDv7,
	kind event.Kind,
	sequence uint64,
	payload []byte,
	rationale string,
) event.SignedEvent {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	deviceID, err := codec.DeriveDeviceID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := event.NewLocalAuthority(domain.DeviceID(deviceID), testBootID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             kind,
			RationaleSummary: rationale,
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
			SessionID:      domain.UUIDv7(testSessionID),
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      testAppliedAt,
			OriginSequence: sequence,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testActiveLease(t *testing.T, deviceID domain.DeviceID) lease.Lease {
	t.Helper()
	value, err := lease.New(
		lease.Fields{
			ID:                   testLeaseID,
			HolderDeviceID:       deviceID,
			HolderAgentSessionID: testAgentSessionID,
			Scope:                lease.ScopePath,
			TTLSeconds:           900,
			Status:               lease.StatusActive,
			EntityVersion:        1,
		},
		[]string{"src/**"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func nextCheckpointApplyRequest(
	t *testing.T,
	previous ApplyHeads,
	eventID domain.UUIDv7,
	sequence uint64,
	logIndex uint64,
	appliedAt domain.Timestamp,
) ApplyRequest {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signerID, err := codec.DeriveDeviceID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	record := CheckpointRecord{
		CheckpointEventID:        eventID,
		SessionID:                domain.UUIDv7(testSessionID),
		WorkspaceID:              testWorkspaceID,
		RecoveryGeneration:       0,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           domain.DeviceID(signerID),
		Term:                     1,
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
		t.Fatal(err)
	}
	record.CheckpointJSON = unsigned
	signature, err := codecommcrypto.SignEd25519(
		privateKey,
		codec.SignatureCheckpoint,
		unsigned,
	)
	if err != nil {
		t.Fatal(err)
	}
	copy(record.AuthoritySignature[:], signature)
	payload, err := record.canonicalJSON(true)
	if err != nil {
		t.Fatal(err)
	}
	proposal := testSignedDaemonEventWithPayload(
		t,
		eventID,
		event.KindConsensusCheckpoint,
		sequence,
		payload,
		"",
	)
	request := nextAcceptedApplyRequest(
		proposal,
		1,
		logIndex,
		appliedAt,
	)
	request.Checkpoint = &record
	return request
}

func insertOutbox(t *testing.T, store *Store, signed event.SignedEvent) {
	t.Helper()
	proposal := signed.Proposal()
	scopeKind, scopeID := proposalScope(proposal)
	digest := proposalDigest(signed)
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`INSERT INTO outbox(
			    event_id, session_id, recovery_generation,
			    origin_device_id, origin_scope_kind, origin_scope_id,
			    origin_sequence, kind, signed_proposal_json,
			    proposal_digest, state, queued_at
			) VALUES (
			    ?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
			    'queued', ?10
			);`,
			string(proposal.EventID),
			string(proposal.SessionID),
			string(proposal.Origin.DeviceID()),
			scopeKind,
			scopeID,
			proposal.Origin.Sequence(),
			string(proposal.Kind),
			string(signed.CanonicalBytes()),
			digest[:],
			string(testAppliedAt),
		)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertCounts(t *testing.T, store *Store, counts map[string]int64) {
	t.Helper()
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		for table, want := range counts {
			var got int64
			if err := queryOne(
				conn,
				"SELECT count(*) FROM "+table+";",
				func(stmt *sqlite.Stmt) {
					got = stmt.ColumnInt64(0)
				},
			); err != nil {
				return err
			}
			if got != want {
				t.Errorf("%s row count = %d, want %d", table, got, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertConsensus(
	t *testing.T,
	store *Store,
	wantLogIndex, wantChainIndex, wantResultIndex int64,
) {
	t.Helper()
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		var got [3]int64
		if err := queryOne(
			conn,
			`SELECT last_raft_applied_log_index, chain_index, result_index
			 FROM consensus_state WHERE singleton = 1;`,
			func(stmt *sqlite.Stmt) {
				got = [3]int64{
					stmt.ColumnInt64(0),
					stmt.ColumnInt64(1),
					stmt.ColumnInt64(2),
				}
			},
		); err != nil {
			return err
		}
		want := [3]int64{wantLogIndex, wantChainIndex, wantResultIndex}
		if got != want {
			t.Errorf("consensus indices = %v, want %v", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func digestWithByte(value byte) Digest {
	var digest Digest
	for index := range digest {
		digest[index] = value
	}
	return digest
}
