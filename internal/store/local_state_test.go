package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

const (
	testClientInstanceID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000021")
	testRequestID        = domain.UUIDv7("01890f47-3e72-7000-8000-000000000022")
	testLaunchID         = domain.UUIDv7("01890f47-3e72-7000-8000-000000000023")
	testManagedRootID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000024")
	testWorkingRootID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000025")
	testLaunchAgentID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000026")
	testLaunchEventID    = domain.UUIDv7("01890f47-3e72-7000-8000-000000000027")
)

func TestLocalStateReserveCommandIsDurableAndIdempotent(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}

	idCalls := 0
	generate := func() (domain.UUIDv7, error) {
		idCalls++
		return testEventID, nil
	}
	build := operatorTaskBuilder(t, privateKey, deviceID)
	first, duplicate, err := state.ReserveCommand(
		context.Background(),
		input,
		generate,
		build,
	)
	if err != nil {
		t.Fatalf("ReserveCommand() error = %v", err)
	}
	if duplicate {
		t.Fatal("first reservation reported duplicate")
	}
	if first.EventID != testEventID ||
		first.OriginSequence != 1 ||
		first.State != LocalRequestSigned ||
		len(first.SignedProposal) == 0 {
		t.Fatalf("first reservation = %#v", first)
	}

	retry, duplicate, err := state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) {
			t.Fatal("exact retry allocated another event ID")
			return "", nil
		},
		func(domain.UUIDv7, uint64) (event.SignedEvent, error) {
			t.Fatal("exact retry rebuilt the signed proposal")
			return event.SignedEvent{}, nil
		},
	)
	if err != nil {
		t.Fatalf("ReserveCommand(exact retry) error = %v", err)
	}
	if !duplicate ||
		retry.EventID != first.EventID ||
		!bytes.Equal(retry.SignedProposal, first.SignedProposal) {
		t.Fatalf("exact retry = %#v, duplicate = %v", retry, duplicate)
	}

	changed := input
	changed.CanonicalRequest = []byte(
		`{"operation":"task.create","payload":{"title":"changed"}}`,
	)
	if _, _, err := state.ReserveCommand(
		context.Background(),
		changed,
		generate,
		build,
	); !errors.Is(err, ErrLocalIdempotencyConflict) {
		t.Fatalf(
			"ReserveCommand(changed retry) error = %v, want ErrLocalIdempotencyConflict",
			err,
		)
	}
	if idCalls != 1 {
		t.Fatalf("event ID generator calls = %d, want 1", idCalls)
	}

	assertCounts(t, state.store, map[string]int64{
		"local_requests":  1,
		"outbox":          1,
		"origin_counters": 1,
	})
	err = state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			`SELECT next_sequence FROM origin_counters
			  WHERE device_id = '`+string(deviceID)+`'
			    AND scope_kind = 'boot'
			    AND scope_id = '`+string(testBootID)+`';`,
			2,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalStateBackpressurePrecedesIDAndSequenceAllocation(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) (err error) {
		for index := 0; index < MaxUnresolvedCommandsPerOrigin; index++ {
			requestID := fmt.Sprintf(
				"01890f47-3e72-7000-8000-%012x",
				index+0x1000,
			)
			eventID := fmt.Sprintf(
				"01890f47-3e72-7000-8000-%012x",
				index+0x2000,
			)
			if err := execute(
				conn,
				`INSERT INTO local_requests(
				    client_instance_id, request_id, session_id, workspace_id,
				    recovery_generation, binding_class, origin_device_id,
				    origin_scope_kind, origin_scope_id, request_digest,
				    event_id, request_kind, state, signed_proposal_json,
				    proposal_digest, created_at
				) VALUES (
				    ?1, ?2, ?3, ?4, 0, 'operator', ?5, 'boot', ?6,
				    zeroblob(32), ?7, 'task.created', 'signed', '{}',
				    zeroblob(32), ?8
				);`,
				string(testClientInstanceID),
				requestID,
				testSessionID,
				string(testWorkspaceID),
				string(deviceID),
				string(testBootID),
				eventID,
				string(testAppliedAt),
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}
	idCalls := 0
	_, _, err = state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) {
			idCalls++
			return testEventID, nil
		},
		operatorTaskBuilder(t, privateKey, deviceID),
	)
	if !errors.Is(err, ErrLocalBackpressure) {
		t.Fatalf("ReserveCommand() error = %v, want ErrLocalBackpressure", err)
	}
	if idCalls != 0 {
		t.Fatalf("event ID generator calls = %d, want 0", idCalls)
	}
	err = state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(t, conn, "SELECT count(*) FROM origin_counters;", 0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalStateSequenceExhaustionPrecedesIDAllocation(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`INSERT INTO origin_counters(
			    device_id, scope_kind, scope_id, next_sequence, exhausted
			) VALUES (?1, 'boot', ?2, NULL, 1);`,
			string(deviceID),
			string(testBootID),
		)
	})
	if err != nil {
		t.Fatal(err)
	}
	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}
	idCalls := 0
	_, _, err = state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) {
			idCalls++
			return testEventID, nil
		},
		operatorTaskBuilder(t, privateKey, deviceID),
	)
	if !errors.Is(err, ErrOriginSequenceExhausted) {
		t.Fatalf(
			"ReserveCommand() error = %v, want ErrOriginSequenceExhausted",
			err,
		)
	}
	if idCalls != 0 {
		t.Fatalf("event ID generator calls = %d, want 0", idCalls)
	}
}

func TestApplyResolvesAndCompactsLocalRequestAtomically(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}
	record, _, err := state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) { return testEventID, nil },
		operatorTaskBuilder(t, privateKey, deviceID),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed := parseLocalSignedEvent(t, record.SignedProposal, privateKey)
	if _, err := state.store.Apply(
		context.Background(),
		nextAcceptedApplyRequest(signed, 1, 1, testAppliedAt),
	); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	resolved, found, err := state.LookupRequest(
		context.Background(),
		testClientInstanceID,
		testRequestID,
	)
	if err != nil {
		t.Fatalf("LookupRequest() error = %v", err)
	}
	if !found ||
		resolved.State != LocalRequestResolved ||
		resolved.Outcome == nil ||
		resolved.Outcome.Status != OutcomeAccepted ||
		len(resolved.SignedProposal) != 0 {
		t.Fatalf("resolved request = %#v, found = %v", resolved, found)
	}
	err = state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(t, conn, "SELECT count(*) FROM outbox;", 0)
		assertIntQuery(
			t,
			conn,
			`SELECT count(*) FROM local_requests
			  WHERE state = 'resolved'
			    AND signed_proposal_json IS NULL
			    AND terminal_code = 'accepted';`,
			1,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyAbandonsFirstSeenLocalEventIDCollision(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}
	local, _, err := state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) { return testEventID, nil },
		operatorTaskBuilder(t, privateKey, deviceID),
	)
	if err != nil {
		t.Fatal(err)
	}
	incoming := testSignedTaskEvent(t, testEventID, 1)
	if bytes.Equal(local.SignedProposal, incoming.CanonicalBytes()) {
		t.Fatal("collision fixture proposals are equal")
	}
	if _, err := state.store.Apply(
		context.Background(),
		acceptedApplyRequest(t, incoming),
	); err != nil {
		t.Fatalf("Apply(collision) error = %v", err)
	}
	record, found, err := state.LookupRequest(
		context.Background(),
		testClientInstanceID,
		testRequestID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !found ||
		record.State != LocalRequestAbandoned ||
		record.TerminalCode != localEventIDCollisionCode ||
		len(record.SignedProposal) != 0 ||
		record.Outcome != nil {
		t.Fatalf("collision tombstone = %#v, found = %v", record, found)
	}
	assertCounts(t, state.store, map[string]int64{"outbox": 0})
}

func TestDuplicateApplyCollisionDoesNotMutateLocalState(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	original := testSignedTaskEvent(t, testEventID, 1)
	first, err := state.store.Apply(
		context.Background(),
		acceptedApplyRequest(t, original),
	)
	if err != nil {
		t.Fatal(err)
	}
	input := LocalCommandInput{
		ClientInstanceID: testClientInstanceID,
		RequestID:        testRequestID,
		SessionID:        domain.UUIDv7(testSessionID),
		WorkspaceID:      testWorkspaceID,
		BindingClass:     LocalBindingOperator,
		OriginDeviceID:   deviceID,
		OriginScopeKind:  OriginScopeKindBoot,
		OriginScopeID:    testBootID,
		RequestKind:      event.KindTaskCreated,
		CanonicalRequest: []byte(`{"operation":"task.create","payload":{}}`),
		CreatedAt:        testAppliedAt,
	}
	local, _, err := state.ReserveCommand(
		context.Background(),
		input,
		func() (domain.UUIDv7, error) { return testEventID, nil },
		operatorTaskBuilder(t, privateKey, deviceID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(local.SignedProposal, original.CanonicalBytes()) {
		t.Fatal("collision fixture proposals are equal")
	}
	duplicate := nextAcceptedApplyRequest(
		parseLocalSignedEvent(t, local.SignedProposal, privateKey),
		1,
		2,
		testAppliedAt,
	)
	if _, err := state.store.Apply(
		context.Background(),
		duplicate,
	); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Apply(duplicate collision) error = %v", err)
	}
	view, err := state.store.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.LastRaftAppliedLogIndex == nil ||
		*view.LastRaftAppliedLogIndex != 1 ||
		view.Heads.ResultIndex != first.Heads.ResultIndex {
		var logIndex uint64
		if view.LastRaftAppliedLogIndex != nil {
			logIndex = *view.LastRaftAppliedLogIndex
		}
		t.Fatalf(
			"view after collision = log %d, result %d",
			logIndex,
			view.Heads.ResultIndex,
		)
	}
	record, found, err := state.LookupRequest(
		context.Background(),
		testClientInstanceID,
		testRequestID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !found ||
		record.State != LocalRequestSigned ||
		record.TerminalCode != "" ||
		!bytes.Equal(record.SignedProposal, local.SignedProposal) {
		t.Fatalf("collision tombstone = %#v, found = %v", record, found)
	}
	assertCounts(t, state.store, map[string]int64{
		"outbox":                    1,
		"raft_command_applications": 1,
	})
}

func TestLocalStateLaunchReservationAndResumeAuthorization(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	root := registerTestManagedRootAndLaunch(t, state)
	selectorDigest := sha256.Sum256([]byte("test launch selector"))
	request := []byte(`{"launch_selector":"test launch selector"}`)
	idCalls := 0
	start, duplicate, err := state.ReserveLaunchStart(
		context.Background(),
		Digest(selectorDigest),
		testClientInstanceID,
		request,
		deviceID,
		func() (LaunchStartIDs, error) {
			idCalls++
			return LaunchStartIDs{
				AgentSessionID: testLaunchAgentID,
				WorkingRootID:  testWorkingRootID,
				EventID:        testLaunchEventID,
			}, nil
		},
		launchStartBuilder(t, privateKey, deviceID),
	)
	if err != nil {
		t.Fatalf("ReserveLaunchStart() error = %v", err)
	}
	if duplicate ||
		start.Launch.State != LaunchReserved ||
		start.Command.OriginSequence != 1 ||
		start.Launch.AgentSessionID != testLaunchAgentID {
		t.Fatalf("launch reservation = %#v, duplicate = %v", start, duplicate)
	}

	retry, duplicate, err := state.ReserveLaunchStart(
		context.Background(),
		Digest(selectorDigest),
		testClientInstanceID,
		request,
		deviceID,
		func() (LaunchStartIDs, error) {
			t.Fatal("launch retry generated new IDs")
			return LaunchStartIDs{}, nil
		},
		func(LaunchRecord, LaunchStartIDs) (event.SignedEvent, error) {
			t.Fatal("launch retry rebuilt start proposal")
			return event.SignedEvent{}, nil
		},
	)
	if err != nil {
		t.Fatalf("ReserveLaunchStart(retry) error = %v", err)
	}
	if !duplicate ||
		retry.Launch.AgentSessionID != start.Launch.AgentSessionID ||
		!bytes.Equal(retry.Command.SignedProposal, start.Command.SignedProposal) {
		t.Fatalf("launch retry = %#v, duplicate = %v", retry, duplicate)
	}
	if idCalls != 1 {
		t.Fatalf("launch ID generator calls = %d, want 1", idCalls)
	}

	signed := parseLocalSignedEvent(t, start.Command.SignedProposal, privateKey)
	apply := nextAcceptedApplyRequest(signed, 1, 1, testAppliedAt)
	apply.Projections.AgentSessions = []agentsession.Session{{
		ID:            testLaunchAgentID,
		DeviceID:      deviceID,
		ClientKind:    agentsession.ClientKindCodex,
		State:         agentsession.StateStarting,
		WorkingRootID: testWorkingRootID,
		EntityVersion: 1,
	}}
	if _, err := state.store.Apply(context.Background(), apply); err != nil {
		t.Fatalf("Apply(start) error = %v", err)
	}

	token := [32]byte{1, 2, 3, 4}
	tokenDigest := resumeTokenDigest(token[:])
	blockedRoot := root
	blockedRoot.GuardStatus = RootGuardBlocked
	blockedRoot.GuardDetailCode = "identity_changed"
	if err := state.RegisterManagedRoot(
		context.Background(),
		blockedRoot,
	); err != nil {
		t.Fatalf("block managed root: %v", err)
	}
	mintCalls := 0
	if _, err := state.SettleLaunch(
		context.Background(),
		testLaunchID,
		testAppliedAt,
		func() (Digest, error) {
			mintCalls++
			return tokenDigest, nil
		},
	); !errors.Is(err, ErrManagedRootUnavailable) {
		t.Fatalf("SettleLaunch(blocked root) error = %v", err)
	}
	if mintCalls != 0 {
		t.Fatalf("blocked settlement minted %d commitments", mintCalls)
	}
	if err := state.RegisterManagedRoot(context.Background(), root); err != nil {
		t.Fatalf("restore managed root: %v", err)
	}
	settlement, err := state.SettleLaunch(
		context.Background(),
		testLaunchID,
		testAppliedAt,
		func() (Digest, error) { return tokenDigest, nil },
	)
	if err != nil {
		t.Fatalf("SettleLaunch() error = %v", err)
	}
	if settlement.Launch.State != LaunchReserved ||
		settlement.Outcome.Status != OutcomeAccepted {
		t.Fatalf("settlement = %#v", settlement)
	}
	replayed, duplicate, err := state.ReserveLaunchStart(
		context.Background(),
		Digest(selectorDigest),
		testClientInstanceID,
		request,
		deviceID,
		func() (LaunchStartIDs, error) {
			t.Fatal("reserved selector replay generated IDs")
			return LaunchStartIDs{}, nil
		},
		func(LaunchRecord, LaunchStartIDs) (event.SignedEvent, error) {
			t.Fatal("reserved selector replay rebuilt a proposal")
			return event.SignedEvent{}, nil
		},
	)
	if err != nil {
		t.Fatalf("ReserveLaunchStart(lost response) error = %v", err)
	}
	if !duplicate ||
		replayed.Launch.AgentSessionID != testLaunchAgentID ||
		replayed.Command.State != LocalRequestResolved {
		t.Fatalf("lost-response replay = %#v, duplicate = %v", replayed, duplicate)
	}
	replacementToken := [32]byte{5, 6, 7, 8}
	replacementDigest := resumeTokenDigest(replacementToken[:])
	if _, err := state.SettleLaunch(
		context.Background(),
		testLaunchID,
		testAppliedAt,
		func() (Digest, error) { return replacementDigest, nil },
	); err != nil {
		t.Fatalf("SettleLaunch(replacement) error = %v", err)
	}
	if _, err := state.AcknowledgeLaunch(
		context.Background(),
		testLaunchID,
		testClientInstanceID,
		tokenDigest,
	); !errors.Is(err, ErrLaunchUnavailable) {
		t.Fatalf("AcknowledgeLaunch(stale capability) error = %v", err)
	}
	if err := state.RegisterManagedRoot(
		context.Background(),
		blockedRoot,
	); err != nil {
		t.Fatalf("block managed root before ack: %v", err)
	}
	if _, err := state.AcknowledgeLaunch(
		context.Background(),
		testLaunchID,
		testClientInstanceID,
		replacementDigest,
	); !errors.Is(err, ErrLaunchUnavailable) {
		t.Fatalf("AcknowledgeLaunch(blocked root) error = %v", err)
	}
	if err := state.RegisterManagedRoot(context.Background(), root); err != nil {
		t.Fatalf("restore managed root before ack: %v", err)
	}
	acknowledged, err := state.AcknowledgeLaunch(
		context.Background(),
		testLaunchID,
		testClientInstanceID,
		replacementDigest,
	)
	if err != nil {
		t.Fatalf("AcknowledgeLaunch() error = %v", err)
	}
	if acknowledged.State != LaunchConsumed {
		t.Fatalf("acknowledged launch = %#v", acknowledged)
	}
	if _, _, err := state.ReserveLaunchStart(
		context.Background(),
		Digest(selectorDigest),
		testClientInstanceID,
		request,
		deviceID,
		func() (LaunchStartIDs, error) {
			t.Fatal("consumed selector generated IDs")
			return LaunchStartIDs{}, nil
		},
		func(LaunchRecord, LaunchStartIDs) (event.SignedEvent, error) {
			t.Fatal("consumed selector rebuilt a proposal")
			return event.SignedEvent{}, nil
		},
	); !errors.Is(err, ErrLaunchUnavailable) {
		t.Fatalf(
			"ReserveLaunchStart(consumed) error = %v, want ErrLaunchUnavailable",
			err,
		)
	}

	err = state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE agent_sessions
			    SET state = 'disconnected', resume_state = 'starting',
			        entity_version = 2
			  WHERE agent_session_id = ?1;`,
			string(testLaunchAgentID),
		)
	})
	if err != nil {
		t.Fatal(err)
	}
	resume, err := state.AuthorizeResume(
		context.Background(),
		replacementDigest,
		domain.UUIDv7(testSessionID),
		testWorkspaceID,
		deviceID,
	)
	if err != nil {
		t.Fatalf("AuthorizeResume() error = %v", err)
	}
	if resume.AgentSessionID != testLaunchAgentID ||
		resume.WorkingRootID != testWorkingRootID ||
		resume.EntityVersion != 2 {
		t.Fatalf("resume binding = %#v", resume)
	}
	wrong := replacementDigest
	wrong[0] ^= 0xff
	if _, err := state.AuthorizeResume(
		context.Background(),
		wrong,
		domain.UUIDv7(testSessionID),
		testWorkspaceID,
		deviceID,
	); !errors.Is(err, ErrResumeRejected) {
		t.Fatalf("AuthorizeResume(wrong token) error = %v, want ErrResumeRejected", err)
	}
	err = state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE agent_resume_tokens
			    SET working_root_id = ?2
			  WHERE agent_session_id = ?1;`,
			string(testLaunchAgentID),
			"01890f47-3e72-7000-8000-000000000029",
		)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AuthorizeResume(
		context.Background(),
		replacementDigest,
		domain.UUIDv7(testSessionID),
		testWorkspaceID,
		deviceID,
	); !errors.Is(err, ErrResumeRejected) {
		t.Fatalf("AuthorizeResume(malformed context) error = %v", err)
	}
}

func TestManagedRootLineageGuardUpdatesAndIsolatedOccupancy(t *testing.T) {
	state, _, _ := newLocalStateFixture(t)
	root := ManagedRootRecord{
		ManagedRootID:      testManagedRootID,
		SessionID:          domain.UUIDv7(testSessionID),
		WorkspaceID:        testWorkspaceID,
		CanonicalPath:      filepath.Join(t.TempDir(), "isolated-root"),
		FilesystemIdentity: "filesystem:isolated-root",
		RepositoryIdentity: "repository:test",
		Kind:               ManagedRootIsolated,
		GuardStatus:        RootGuardHealthy,
		Active:             true,
		LastVerifiedAt:     &testAppliedAt,
	}
	stale := root
	stale.RecoveryGeneration = 1
	if err := state.RegisterManagedRoot(
		context.Background(),
		stale,
	); !errors.Is(err, ErrLocalLineageMismatch) {
		t.Fatalf("RegisterManagedRoot(stale) error = %v", err)
	}
	if err := state.RegisterManagedRoot(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	blocked := root
	blocked.GuardStatus = RootGuardBlocked
	blocked.GuardDetailCode = "guard_failed"
	if err := state.RegisterManagedRoot(context.Background(), blocked); err != nil {
		t.Fatalf("update managed-root guard: %v", err)
	}
	first := LaunchRegistration{
		LaunchID:        testLaunchID,
		SelectorDigest:  Digest(sha256.Sum256([]byte("first selector"))),
		SessionID:       domain.UUIDv7(testSessionID),
		WorkspaceID:     testWorkspaceID,
		ClientKind:      agentsession.ClientKindCodex,
		ConcurrencyMode: ConcurrencyIsolated,
		ManagedRootID:   testManagedRootID,
		CreatedAt:       testAppliedAt,
	}
	if err := state.RegisterLaunch(
		context.Background(),
		first,
	); !errors.Is(err, ErrManagedRootUnavailable) {
		t.Fatalf("RegisterLaunch(blocked root) error = %v", err)
	}
	if err := state.RegisterManagedRoot(context.Background(), root); err != nil {
		t.Fatalf("restore root guard: %v", err)
	}
	if err := state.RegisterLaunch(context.Background(), first); err != nil {
		t.Fatalf("RegisterLaunch(first) error = %v", err)
	}
	second := first
	second.LaunchID = domain.UUIDv7(
		"01890f47-3e72-7000-8000-000000000028",
	)
	second.SelectorDigest = Digest(sha256.Sum256([]byte("second selector")))
	if err := state.RegisterLaunch(
		context.Background(),
		second,
	); !errors.Is(err, ErrManagedRootUnavailable) {
		t.Fatalf("RegisterLaunch(second isolated) error = %v", err)
	}
}

func TestClearPendingLaunchesRemovesOnlyUnreservedRegistration(t *testing.T) {
	state, privateKey, deviceID := newLocalStateFixture(t)
	registerTestManagedRootAndLaunch(t, state)

	if err := state.ClearPendingLaunches(context.Background()); err != nil {
		t.Fatalf("ClearPendingLaunches(): %v", err)
	}
	if err := state.ClearPendingLaunches(context.Background()); err != nil {
		t.Fatalf("ClearPendingLaunches(repeat): %v", err)
	}
	err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		launch, found, err := readLaunchByID(conn, testLaunchID)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("pending launch survived recovery: %#v", launch)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	selector := Digest(sha256.Sum256([]byte("test launch selector")))
	if _, _, err := state.ReserveLaunchStart(
		context.Background(),
		selector,
		testClientInstanceID,
		[]byte(`{"launch_selector":"test launch selector"}`),
		deviceID,
		func() (LaunchStartIDs, error) {
			return LaunchStartIDs{}, nil
		},
		launchStartBuilder(t, privateKey, deviceID),
	); !errors.Is(err, ErrLaunchNotFound) {
		t.Fatalf(
			"ReserveLaunchStart(cleared) error = %v, want %v",
			err,
			ErrLaunchNotFound,
		)
	}
}

func newLocalStateFixture(
	t *testing.T,
) (LocalState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	privateKey, deviceID := localTestIdentity(t)
	return store.LocalState(), privateKey, deviceID
}

func localTestIdentity(t *testing.T) (ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	deviceID, err := codec.DeriveDeviceID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, domain.DeviceID(deviceID)
}

func operatorTaskBuilder(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) LocalCommandBuilder {
	t.Helper()
	authority, err := event.NewLocalAuthority(deviceID, testBootID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	return func(eventID domain.UUIDv7, sequence uint64) (event.SignedEvent, error) {
		proposal, err := event.BuildProposal(
			event.Command{
				Kind:             event.KindTaskCreated,
				EntityID:         event.StringEntityID(string(testTaskID)),
				RationaleSummary: "",
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
			return event.SignedEvent{}, err
		}
		return event.Sign(proposal, privateKey)
	}
}

func registerTestManagedRootAndLaunch(
	t *testing.T,
	state LocalState,
) ManagedRootRecord {
	t.Helper()
	root := ManagedRootRecord{
		ManagedRootID:      testManagedRootID,
		SessionID:          domain.UUIDv7(testSessionID),
		WorkspaceID:        testWorkspaceID,
		CanonicalPath:      filepath.Join(t.TempDir(), "agent-root"),
		FilesystemIdentity: "filesystem:test-root",
		RepositoryIdentity: "repository:test",
		Kind:               ManagedRootIsolated,
		GuardStatus:        RootGuardHealthy,
		Active:             true,
		LastVerifiedAt:     &testAppliedAt,
	}
	err := state.RegisterManagedRoot(context.Background(), root)
	if err != nil {
		t.Fatalf("RegisterManagedRoot() error = %v", err)
	}
	selectorDigest := sha256.Sum256([]byte("test launch selector"))
	err = state.RegisterLaunch(context.Background(), LaunchRegistration{
		LaunchID:        testLaunchID,
		SelectorDigest:  Digest(selectorDigest),
		SessionID:       domain.UUIDv7(testSessionID),
		WorkspaceID:     testWorkspaceID,
		ClientKind:      agentsession.ClientKindCodex,
		ConcurrencyMode: ConcurrencyIsolated,
		ManagedRootID:   testManagedRootID,
		CreatedAt:       testAppliedAt,
	})
	if err != nil {
		t.Fatalf("RegisterLaunch() error = %v", err)
	}
	return root
}

func launchStartBuilder(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
) LaunchStartBuilder {
	t.Helper()
	return func(
		launch LaunchRecord,
		ids LaunchStartIDs,
	) (event.SignedEvent, error) {
		binding, err := event.NewMCPBinding(
			deviceID,
			ids.AgentSessionID,
			launch.AgentProfileID,
		)
		if err != nil {
			return event.SignedEvent{}, err
		}
		payload := []byte(fmt.Sprintf(
			`{"client_kind":%q,"working_root_id":%q}`,
			launch.ClientKind,
			ids.WorkingRootID,
		))
		proposal, err := event.BuildProposal(
			event.Command{
				Kind:             event.KindAgentSessionStarted,
				EntityID:         event.StringEntityID(string(ids.AgentSessionID)),
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
				EventID:        ids.EventID,
				SessionID:      launch.SessionID,
				WorkspaceID:    launch.WorkspaceID,
				CreatedAt:      testAppliedAt,
				OriginSequence: 1,
			},
		)
		if err != nil {
			return event.SignedEvent{}, err
		}
		return event.Sign(proposal, privateKey)
	}
}

func parseLocalSignedEvent(
	t *testing.T,
	canonical []byte,
	privateKey ed25519.PrivateKey,
) event.SignedEvent {
	t.Helper()
	signed, err := event.ParseAndVerify(canonical, event.VerificationContext{
		SessionID:         domain.UUIDv7(testSessionID),
		WorkspaceID:       testWorkspaceID,
		IdentityPublicKey: privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("ParseAndVerify() error = %v", err)
	}
	return signed
}

func resumeTokenDigest(token []byte) Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("codecomm/v1/agent-resume"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(token)
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}
