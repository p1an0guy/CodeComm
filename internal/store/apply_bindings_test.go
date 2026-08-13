package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

func TestApplyPersistsTasklessActivityFromAcceptedEvent(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	signed := testSignedDaemonActivityEvent(t, testEventID, 1)
	request := acceptedApplyRequest(t, signed)
	request.ActivityTaskID = ""

	if _, err := store.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, store, map[string]int64{"activity": 1})
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(
			t,
			conn,
			"SELECT event_kind FROM activity;",
			string(event.KindActivityRecorded),
		)
		assertTextQuery(
			t,
			conn,
			"SELECT rationale_summary FROM activity;",
			"release lease deadline",
		)
		assertIntQuery(
			t,
			conn,
			"SELECT task_id IS NULL FROM activity;",
			1,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	request.RecordActivity = false
	if err := request.validate(); !errors.Is(err, ErrInvalidApply) {
		t.Fatalf("validate() error = %v, want ErrInvalidApply", err)
	}
}

func TestApplyPersistsControlFileProposal(t *testing.T) {
	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	const path = domain.RepositoryPath("AGENTS.md")
	content := []byte("updated instructions\n")
	digest := sha256.Sum256(content)
	signed := testSignedControlFileEvent(t, testEventID, path, digest)
	request := acceptedApplyRequest(t, signed)
	request.ActivityTaskID = ""
	request.Projections.ControlFileProposals = []ControlFileProposalRow{{
		ProposalEventID:    testEventID,
		SessionID:          domain.UUIDv7(testSessionID),
		Path:               path,
		Operation:          ControlFileUpsert,
		ContentDigest:      &digest,
		ContentSize:        uint64(len(content)),
		Diff:               "@@ -1 +1 @@\n-old\n+updated instructions\n",
		ProposedByDeviceID: signed.Proposal().Origin.DeviceID(),
		ChainIndex:         1,
	}}

	if _, err := store.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	assertCounts(
		t,
		store,
		map[string]int64{
			"control_file_proposals": 1,
			"control_file_approvals": 1,
		},
	)
	err := store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(
			t,
			conn,
			"SELECT path FROM control_file_proposals;",
			string(path),
		)
		assertIntQuery(
			t,
			conn,
			"SELECT content_size FROM control_file_proposals;",
			int64(len(content)),
		)
		assertIntQuery(
			t,
			conn,
			"SELECT chain_index FROM control_file_proposals;",
			1,
		)
		assertTextQuery(
			t,
			conn,
			"SELECT decision FROM control_file_approvals;",
			"pending",
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyRequiresOneMatchingExplicitAuditRow(t *testing.T) {
	signerID, _ := testStoreSigningIdentity(t)
	payload := struct {
		Action                 string `json:"action"`
		Outcome                string `json:"outcome"`
		Subject                string `json:"subject"`
		SubjectDeviceID        string `json:"subject_device_id"`
		SubjectCredentialEpoch uint64 `json:"subject_credential_epoch"`
	}{
		Action:                 "api.mutate",
		Outcome:                "invalid.request",
		Subject:                "task:01890f47",
		SubjectDeviceID:        string(signerID),
		SubjectCredentialEpoch: 0,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := testSignedDaemonEventWithPayload(
		t,
		testAuditEventID,
		event.KindAuditRecorded,
		1,
		encoded,
		"",
	)
	request := acceptedApplyRequest(t, signed)
	request.RecordActivity = false
	request.ActivityTaskID = ""
	epoch := uint64(0)
	request.Audit = []AuditRecord{{
		SessionID:              domain.UUIDv7(testSessionID),
		SourceKind:             AuditEvent,
		EventID:                testAuditEventID,
		ResultIndex:            1,
		ReporterDeviceID:       signerID,
		SubjectDeviceID:        signerID,
		SubjectCredentialEpoch: &epoch,
		ActorType:              event.ActorDaemon,
		IPCChannel:             "peer",
		ActionCode:             payload.Action,
		OutcomeCode:            payload.Outcome,
		Subject:                payload.Subject,
		DetailsJSON:            []byte(`{}`),
		FirstSeenAt:            testAppliedAt,
		LastSeenAt:             testAppliedAt,
		ObservationCount:       1,
	}}
	if err := request.validate(); err != nil {
		t.Fatalf("valid explicit audit request: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ApplyRequest)
	}{
		{
			name: "missing row",
			mutate: func(value *ApplyRequest) {
				value.Audit = nil
			},
		},
		{
			name: "duplicate generic row",
			mutate: func(value *ApplyRequest) {
				generic := value.Audit[0]
				generic.SourceKind = AuditAcceptedEvent
				value.Audit = append(value.Audit, generic)
			},
		},
		{
			name: "wrong source kind",
			mutate: func(value *ApplyRequest) {
				value.Audit[0].SourceKind = AuditAcceptedEvent
			},
		},
		{
			name: "wrong subject",
			mutate: func(value *ApplyRequest) {
				value.Audit[0].Subject = "different"
			},
		},
		{
			name: "wrong result",
			mutate: func(value *ApplyRequest) {
				value.Audit[0].ResultIndex++
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			candidate.Audit = append([]AuditRecord(nil), request.Audit...)
			test.mutate(&candidate)
			err := candidate.validate()
			if test.name == "wrong result" {
				if err != nil {
					t.Fatalf("validate() error = %v, want transactional check", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidApply) {
				t.Fatalf("validate() error = %v, want ErrInvalidApply", err)
			}
		})
	}

	store := openTestStore(
		t,
		filepath.Join(t.TempDir(), "session", "state.db"),
		nil,
	)
	initializeTestStore(t, store)
	wrongResult := request
	wrongResult.Audit = append([]AuditRecord(nil), request.Audit...)
	wrongResult.Audit[0].ResultIndex++
	if _, err := store.Apply(context.Background(), wrongResult); !errors.Is(
		err,
		ErrInvalidApply,
	) {
		t.Fatalf("Apply(wrong result) error = %v, want ErrInvalidApply", err)
	}
	if _, err := store.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, store, map[string]int64{"audit_events": 1})
	err = store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(
			t,
			conn,
			"SELECT source_kind FROM audit_events;",
			string(AuditEvent),
		)
		assertTextQuery(
			t,
			conn,
			"SELECT subject_device_id FROM audit_events;",
			string(signerID),
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyRejectsDuplicateOrMisboundLocalAlarms(t *testing.T) {
	t.Parallel()

	signed := testSignedTaskEvent(t, testEventID, 1)
	previous := ApplyHeads{ResultIndex: 0}
	request := rejectedApplyRequest(t, signed, previous)
	alarm := request.Audit[0]
	alarm.SourceKind = AuditLocalAggregate
	alarm.ActionCode = "alarm.conflict_integrity"
	alarm.Subject = "conflict:example"
	alarm.DetailsJSON = []byte(`{"class":"conflict_integrity"}`)
	request.Audit = append(request.Audit, alarm)
	if err := request.validate(); err != nil {
		t.Fatalf("valid local alarm request: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ApplyRequest)
	}{
		{
			name: "duplicate alarm",
			mutate: func(value *ApplyRequest) {
				value.Audit = append(value.Audit, value.Audit[1])
			},
		},
		{
			name: "wrong event",
			mutate: func(value *ApplyRequest) {
				value.Audit[1].EventID = testEventID2
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := request
			candidate.Audit = append([]AuditRecord(nil), request.Audit...)
			test.mutate(&candidate)
			if err := candidate.validate(); !errors.Is(err, ErrInvalidApply) {
				t.Fatalf(
					"validate() error = %v, want ErrInvalidApply",
					err,
				)
			}
		})
	}
}

func testSignedControlFileEvent(
	t *testing.T,
	eventID domain.UUIDv7,
	path domain.RepositoryPath,
	digest [sha256.Size]byte,
) event.SignedEvent {
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
	payload, err := json.Marshal(struct {
		Path          string `json:"path"`
		Operation     string `json:"operation"`
		ContentDigest string `json:"content_digest"`
		ContentSize   uint64 `json:"content_size"`
		Diff          string `json:"diff"`
	}{
		Path:          string(path),
		Operation:     string(ControlFileUpsert),
		ContentDigest: codec.EncodeBase64URL(digest[:]),
		ContentSize:   uint64(len("updated instructions\n")),
		Diff:          "@@ -1 +1 @@\n-old\n+updated instructions\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindControlFileChangeProposed,
			EntityID:         event.StringEntityID(string(path)),
			RationaleSummary: "update agent instructions",
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

func testStoreSigningIdentity(
	t *testing.T,
) (domain.DeviceID, ed25519.PrivateKey) {
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
	return domain.DeviceID(deviceID), privateKey
}
