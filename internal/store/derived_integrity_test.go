package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
)

func TestCommitmentScrubRejectsDerivedActivityTamper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tamper string
	}{
		{
			name:   "missing",
			tamper: "DELETE FROM activity;",
		},
		{
			name: `proposal field`,
			tamper: `UPDATE activity
			           SET rationale_summary = 'substituted';`,
		},
		{
			name: `task association`,
			tamper: `UPDATE activity
			           SET task_id =
			               '01890f47-3e72-7000-8000-000000000099';`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := derivedIntegrityCommandState(t)
			commitmentExecute(t, state, test.tamper)
			commitmentAssertReopenScrubFails(
				t,
				state,
				state.Path(),
				ErrCommandResultCorrupt,
			)
		})
	}
}

func TestCommitmentScrubRejectsAuthoritativeAuditTamper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tamper string
	}{
		{
			name:   "missing",
			tamper: "DELETE FROM audit_events;",
		},
		{
			name: `semantic field`,
			tamper: `UPDATE audit_events
			           SET subject = 'substituted'
			         WHERE source_kind = 'accepted_event';`,
		},
		{
			name: `local time pair`,
			tamper: `UPDATE audit_events
			           SET last_seen_at = '2026-08-10T12:00:01Z'
			         WHERE source_kind = 'accepted_event';`,
		},
		{
			name: `duplicate`,
			tamper: `INSERT INTO audit_events(
				    session_id, source_kind, event_id, result_index,
				    reporter_device_id, subject_device_id,
				    subject_credential_epoch, actor_type, ipc_channel,
				    action_code, outcome_code, subject, details_json,
				    first_seen_at, last_seen_at, observation_count
				)
				SELECT session_id, source_kind, event_id, result_index,
				       reporter_device_id, subject_device_id,
				       subject_credential_epoch, actor_type, ipc_channel,
				       action_code, outcome_code, subject, details_json,
				       first_seen_at, last_seen_at, observation_count
				  FROM audit_events
				 WHERE source_kind = 'accepted_event';`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := derivedIntegrityCommandState(t)
			commitmentExecute(t, state, test.tamper)
			commitmentAssertReopenScrubFails(
				t,
				state,
				state.Path(),
				ErrCommandResultCorrupt,
			)
		})
	}
}

func TestStartupPreservesAndIgnoresLocalAggregateAudit(t *testing.T) {
	t.Parallel()

	state := derivedIntegrityCommandState(t)
	commitmentExecute(
		t,
		state,
		`INSERT INTO audit_events(
		    session_id, source_kind, event_id, result_index,
		    reporter_device_id, subject_device_id,
		    subject_credential_epoch, actor_type, ipc_channel,
		    action_code, outcome_code, subject, details_json,
		    first_seen_at, last_seen_at, observation_count
		) VALUES (
		    ?1, 'local_aggregate', NULL, NULL, NULL, NULL, NULL,
		    NULL, 'daemon', 'connection.denied', 'denied', 'peer:test',
		    '{"class":"local"}', ?2, ?2, 7
		);`,
		testSessionID,
		"2026-08-10T12:01:00Z",
	)
	path := state.Path()
	if err := state.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(with local aggregate): %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close(reopened): %v", err)
		}
	}()
	assertCounts(t, reopened, map[string]int64{"audit_events": 2})
}

func TestCommitmentScrubRejectsReducerAlarmAuditTamper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tamper string
	}{
		{
			name: `missing`,
			tamper: `DELETE FROM audit_events
			          WHERE source_kind = 'local_aggregate';`,
		},
		{
			name: `semantic field`,
			tamper: `UPDATE audit_events
			           SET reporter_device_id = NULL
			         WHERE source_kind = 'local_aggregate';`,
		},
		{
			name: `duplicate`,
			tamper: `INSERT INTO audit_events(
				    session_id, source_kind, event_id, result_index,
				    reporter_device_id, subject_device_id,
				    subject_credential_epoch, actor_type, ipc_channel,
				    action_code, outcome_code, subject, details_json,
				    first_seen_at, last_seen_at, observation_count
				)
				SELECT session_id, source_kind, event_id, result_index,
				       reporter_device_id, subject_device_id,
				       subject_credential_epoch, actor_type, ipc_channel,
				       action_code, outcome_code, subject, details_json,
				       first_seen_at, last_seen_at, observation_count
				  FROM audit_events
				 WHERE source_kind = 'local_aggregate';`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := derivedIntegrityAlarmState(t)
			commitmentExecute(t, state, test.tamper)
			commitmentAssertReopenScrubFails(
				t,
				state,
				state.Path(),
				ErrCommandResultCorrupt,
			)
		})
	}
}

func TestCommitmentScrubRejectsUnexpectedResultBoundLocalAggregate(
	t *testing.T,
) {
	t.Parallel()

	state := derivedIntegrityCommandState(t)
	commitmentExecute(
		t,
		state,
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
		       'conflict:unexpected', '{"class":"conflict_integrity"}',
		       first_seen_at, last_seen_at, 1
		  FROM audit_events
		 WHERE source_kind = 'accepted_event';`,
	)
	commitmentAssertReopenScrubFails(
		t,
		state,
		state.Path(),
		ErrCommandResultCorrupt,
	)
}

func TestCommitmentScrubRejectsRecoveryBoundaryAuditTamper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tamper string
	}{
		{
			name: `missing`,
			tamper: `DELETE FROM audit_events
			          WHERE source_kind = 'recovery_boundary';`,
		},
		{
			name: `details`,
			tamper: `UPDATE audit_events
			           SET details_json =
			               '{"genesis_digest":"wrong","recovery_generation":1}'
			         WHERE source_kind = 'recovery_boundary';`,
		},
		{
			name: `subject`,
			tamper: `UPDATE audit_events
			           SET subject = 'session:substituted'
			         WHERE source_kind = 'recovery_boundary';`,
		},
		{
			name: `local time pair`,
			tamper: `UPDATE audit_events
			           SET last_seen_at = '2026-08-10T12:00:01Z'
			         WHERE source_kind = 'recovery_boundary';`,
		},
		{
			name: `orphan`,
			tamper: `INSERT INTO audit_events(
				    session_id, source_kind, actor_type, ipc_channel,
				    action_code, outcome_code, subject, details_json,
				    first_seen_at, last_seen_at, observation_count
				) VALUES (
				    '01890f47-3e72-7000-8000-000000000099',
				    'recovery_boundary', 'human', 'operator',
				    'cluster.quorum_recovered', 'accepted',
				    'session:01890f47-3e72-7000-8000-000000000099',
				    '{"genesis_digest":"00","recovery_generation":2}',
				    '2026-08-10T12:00:00Z',
				    '2026-08-10T12:00:00Z', 1
				);`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := derivedIntegritySuccessorState(t)
			commitmentExecute(t, state, test.tamper)
			commitmentAssertReopenScrubFails(
				t,
				state,
				state.Path(),
				ErrCommandResultCorrupt,
			)
		})
	}
}

func derivedIntegrityCommandState(t *testing.T) *Store {
	t.Helper()
	state := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, state)
	request := acceptedApplyRequest(
		t,
		testSignedTaskEvent(t, testEventID, 1),
	)
	if _, err := state.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	return state
}

func derivedIntegrityAlarmState(t *testing.T) *Store {
	t.Helper()
	state := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, state)
	proposal := derivedIntegrityConflictEvent(t)
	request := rejectedApplyRequest(t, proposal, ApplyHeads{})
	request.Outcome.Code = string(reducer.CodeConflictIDMismatch)
	request.Outcome.JSON = []byte(
		`{"code":"conflict_id_mismatch","status":"rejected"}`,
	)
	request.Audit[0].ActorType = event.ActorDaemon
	request.Audit[0].IPCChannel = "daemon"
	request.Audit[0].ActionCode = string(event.KindWorkspaceConflictDetected)
	request.Audit[0].OutcomeCode = string(reducer.CodeConflictIDMismatch)
	conflictID, _ := proposal.Proposal().EntityID.Value()
	request.Audit[0].Subject = conflictID
	alarm, required, err := expectedReducerAlarmAudit(
		proposal.Proposal(),
		request.Outcome.Status,
		request.Outcome.Code,
		1,
	)
	if err != nil || !required {
		t.Fatalf("expectedReducerAlarmAudit(): required=%v err=%v", required, err)
	}
	alarm.FirstSeenAt = request.AppliedAt
	alarm.LastSeenAt = request.AppliedAt
	request.Audit = append(request.Audit, alarm)
	if _, err := state.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply(alarm): %v", err)
	}
	return state
}

func derivedIntegrityConflictEvent(t *testing.T) event.SignedEvent {
	t.Helper()
	deviceID, privateKey := testStoreSigningIdentity(t)
	authority, err := event.NewLocalAuthority(deviceID, testBootID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind: event.KindWorkspaceConflictDetected,
			EntityID: event.StringEntityID(
				"ccf1" + strings.Repeat("a", 64),
			),
			Actions: []event.Action{},
			Payload: []byte(`{}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        testEventID,
			SessionID:      domain.UUIDv7(testSessionID),
			WorkspaceID:    testWorkspaceID,
			CreatedAt:      testAppliedAt,
			OriginSequence: 1,
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

func derivedIntegritySuccessorState(t *testing.T) *Store {
	t.Helper()
	state := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	predecessor, err := state.Initialize(
		context.Background(),
		commitmentInitialState(
			t,
			domain.UUIDv7(testSessionID),
			0,
			ProjectionWrites{},
		),
	)
	if err != nil {
		t.Fatalf("Initialize(): %v", err)
	}
	predecessorGenesis, err := chain.GenesisDigest(
		commitmentGenesisJSON(t, domain.UUIDv7(testSessionID), 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, err := chain.StateDigest(
		chain.Versions{Digest: 1, ProjectionSchema: 1},
		nil,
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
			Digest(predecessorGenesis),
			Digest(stateDigest),
		),
		RecoveryAuthorizationJSON: []byte(`{"kind":"test-recovery"}`),
		ObservedAt:                "2026-08-10T12:00:00Z",
		Predecessor:               predecessor,
		DigestVersion:             1,
		ProjectionSchemaVersion:   1,
	}
	if _, err := state.InstallSuccessor(
		context.Background(),
		successor,
	); err != nil {
		t.Fatalf("InstallSuccessor(): %v", err)
	}
	return state
}
