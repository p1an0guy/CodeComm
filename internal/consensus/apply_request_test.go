package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	applyTestSessionID = domain.UUIDv7("018f47de-89ab-7def-8123-0123456789ab")
	applyTestWorkspace = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	applyTestEventID   = domain.UUIDv7("018f47de-89ab-7def-8123-1123456789ab")
	applyTestTaskID    = domain.UUIDv7("018f47de-89ab-7def-8123-2123456789ab")
	applyTestAgentID   = domain.UUIDv7("018f47de-89ab-7def-8123-3123456789ab")
	applyTestBootID    = domain.UUIDv7("018f47de-89ab-7def-8123-4123456789ab")
	applyTestLeaseID   = domain.UUIDv7("018f47de-89ab-7def-8123-5123456789ab")
	applyTestTimestamp = domain.Timestamp("2026-08-11T12:00:00Z")
)

func TestBuildApplyRequestMapsAcceptedOutcomeAndAudit(t *testing.T) {
	t.Parallel()

	signed, deviceID := applyTestSignedTask(t)
	value := task.Task{
		ID:            applyTestTaskID,
		Title:         "task",
		State:         task.StateReady,
		Priority:      task.PriorityNormal,
		EntityVersion: 1,
		CreatedAt:     applyTestTimestamp,
		UpdatedAt:     applyTestTimestamp,
	}
	scope := reducer.OriginScope{
		OriginScopeKey: reducer.OriginScopeKey{
			DeviceID: deviceID,
			Kind:     reducer.ScopeAgent,
			ScopeID:  applyTestAgentID,
		},
		LastSequence: 1,
	}
	outcome := reducer.Outcome{
		Status:         reducer.StatusAccepted,
		Code:           reducer.CodeAccepted,
		ActivityTaskID: applyTestTaskID,
		Changes: reducer.Changes{
			AdvancesEventChain: true,
			OriginScopes:       []reducer.OriginScope{scope},
			Tasks:              []task.Task{value},
		},
	}
	request, err := BuildApplyRequest(signed, outcome, applyTestContext())
	if err != nil {
		t.Fatalf("BuildApplyRequest(): %v", err)
	}
	if request.Term != 3 ||
		request.LogIndex != 7 ||
		request.RecoveryGeneration != 0 ||
		request.Proposal.Proposal().EventID != applyTestEventID ||
		request.Outcome.Status != store.OutcomeAccepted ||
		request.Outcome.Code != string(reducer.CodeAccepted) ||
		request.ActivityTaskID != "" ||
		!bytes.Equal(
			request.Outcome.JSON,
			[]byte(`{"code":"accepted","status":"accepted"}`),
		) {
		t.Fatalf("mapped request = %#v", request)
	}
	if len(request.Projections.Tasks) != 1 ||
		!reflect.DeepEqual(request.Projections.Tasks[0], value) ||
		len(request.Projections.OriginScopes) != 1 ||
		request.Projections.OriginScopes[0].DeviceID != deviceID ||
		request.Projections.OriginScopes[0].ScopeKind !=
			store.OriginScopeKindAgent {
		t.Fatalf("mapped projections = %#v", request.Projections)
	}
	if len(request.Audit) != 1 {
		t.Fatalf("audit count = %d, want 1", len(request.Audit))
	}
	audit := request.Audit[0]
	if audit.SourceKind != store.AuditAcceptedEvent ||
		audit.ResultIndex != 5 ||
		audit.ReporterDeviceID != deviceID ||
		audit.SubjectDeviceID != deviceID ||
		audit.IPCChannel != "agent" ||
		audit.ActionCode != string(event.KindTaskCreated) ||
		audit.OutcomeCode != string(reducer.CodeAccepted) ||
		audit.Subject != string(applyTestTaskID) {
		t.Fatalf("mapped audit = %#v", audit)
	}
}

func TestBuildApplyRequestMapsRejectionAndLeaseDeadlines(t *testing.T) {
	t.Parallel()

	signed, deviceID := applyTestSignedTask(t)
	context := applyTestContext()

	rejected := reducer.Outcome{
		Status: reducer.StatusRejected,
		Code:   reducer.CodeInvalidPayload,
		Changes: reducer.Changes{OriginScopes: []reducer.OriginScope{{
			OriginScopeKey: reducer.OriginScopeKey{
				DeviceID: deviceID,
				Kind:     reducer.ScopeAgent,
				ScopeID:  applyTestAgentID,
			},
			LastSequence: 1,
		}}},
	}
	request, err := BuildApplyRequest(signed, rejected, context)
	if err != nil {
		t.Fatalf("BuildApplyRequest(rejected): %v", err)
	}
	if request.Outcome.Status != store.OutcomeRejected ||
		request.Audit[0].SourceKind != store.AuditCommittedRejection ||
		request.RecordActivity ||
		len(request.LeaseDeadlines) != 0 ||
		len(request.DeleteLeaseDeadlines) != 0 {
		t.Fatalf("mapped rejection = %#v", request)
	}

	active, err := lease.New(lease.Fields{
		ID:                   applyTestLeaseID,
		HolderDeviceID:       deviceID,
		HolderAgentSessionID: applyTestAgentID,
		Scope:                lease.ScopeTask,
		TaskID:               applyTestTaskID,
		TTLSeconds:           30,
		Status:               lease.StatusActive,
		EntityVersion:        2,
	}, nil)
	if err != nil {
		t.Fatalf("lease.New(): %v", err)
	}
	accepted := reducer.Outcome{
		Status: reducer.StatusAccepted,
		Code:   reducer.CodeAccepted,
		Changes: reducer.Changes{
			AdvancesEventChain: true,
			OriginScopes:       rejected.Changes.OriginScopes,
			Leases:             []lease.Lease{active},
		},
	}
	request, err = BuildApplyRequest(signed, accepted, context)
	if err != nil {
		t.Fatalf("BuildApplyRequest(active lease): %v", err)
	}
	if len(request.LeaseDeadlines) != 1 ||
		len(request.DeleteLeaseDeadlines) != 1 {
		t.Fatalf(
			"deadline changes = (%d, %d), want (1, 1)",
			len(request.LeaseDeadlines),
			len(request.DeleteLeaseDeadlines),
		)
	}
	deadline := request.LeaseDeadlines[0]
	if deadline.LeaseID != applyTestLeaseID ||
		deadline.EntityVersion != 2 ||
		deadline.OriginBootID != applyTestBootID ||
		deadline.MonotonicDeadlineNS != 30_000_000_100 ||
		deadline.DisplayDeadlineAt !=
			domain.Timestamp("2026-08-11T12:00:30Z") ||
		request.DeleteLeaseDeadlines[0].EntityVersion != 1 {
		t.Fatalf("mapped deadline = %#v", deadline)
	}

	released := active
	released.Status = lease.StatusReleased
	released.ReleaseReason = lease.ReleaseVoluntary
	released.EntityVersion = 3
	accepted.Changes.Leases = []lease.Lease{released}
	request, err = BuildApplyRequest(signed, accepted, context)
	if err != nil {
		t.Fatalf("BuildApplyRequest(released lease): %v", err)
	}
	if len(request.LeaseDeadlines) != 0 ||
		len(request.DeleteLeaseDeadlines) != 1 ||
		request.DeleteLeaseDeadlines[0].EntityVersion != 2 {
		t.Fatalf(
			"release deadline changes = (%#v, %#v)",
			request.LeaseDeadlines,
			request.DeleteLeaseDeadlines,
		)
	}
}

func TestProjectionWritesCoversEveryReducerProjection(t *testing.T) {
	t.Parallel()

	var changes reducer.Changes
	changesValue := reflect.ValueOf(&changes).Elem()
	for index := range changesValue.NumField() {
		field := changesValue.Field(index)
		if field.Kind() == reflect.Slice {
			field.Set(reflect.MakeSlice(field.Type(), 1, 1))
		}
	}

	writesValue := reflect.ValueOf(projectionWrites(changes))
	changesType := changesValue.Type()
	for index := range changesValue.NumField() {
		source := changesValue.Field(index)
		if source.Kind() != reflect.Slice {
			continue
		}
		name := changesType.Field(index).Name
		destination := writesValue.FieldByName(name)
		if !destination.IsValid() {
			t.Fatalf("ProjectionWrites is missing reducer field %s", name)
		}
		if destination.Kind() != reflect.Slice || destination.Len() != 1 {
			t.Fatalf(
				"ProjectionWrites.%s length = %d, want 1",
				name,
				destination.Len(),
			)
		}
	}
}

func TestProjectionWritesMapsCredentialAndControlFileRows(t *testing.T) {
	t.Parallel()

	_, deviceID := applyTestSignedTask(t)
	epochKey := [ed25519.PublicKeySize]byte{0x31}
	keyDigest := sha256.Sum256(epochKey[:])
	signature := [ed25519.SignatureSize]byte{0x41}
	contentDigest := controlfile.SHA256Digest(
		sha256.Sum256([]byte("content")),
	)
	expectedContentDigest := [sha256.Size]byte(contentDigest)
	changes := reducer.Changes{
		CredentialAuthorizations: []credentialauthorization.Authorization{{
			SessionID:                applyTestSessionID,
			DeviceID:                 deviceID,
			Epoch:                    3,
			EpochPublicKey:           epochKey,
			KeyDigest:                keyDigest,
			Role:                     credentialauthorization.RoleEditor,
			IssuedAt:                 "2026-08-11T12:00:00Z",
			NotBefore:                "2026-08-11T12:00:00Z",
			ValiditySeconds:          credentialauthorization.ValiditySeconds,
			AuthorityVoterSetVersion: 2,
			ClockEndorsements: []credentialauthorization.ClockEndorsement{{
				DeviceID:  deviceID,
				Signature: signature,
			}},
			BindingSignature:        signature,
			AuthorizationChainIndex: 9,
		}},
		ControlFileProposals: []controlfile.Proposal{{
			ProposalEventID:    applyTestEventID,
			SessionID:          applyTestSessionID,
			Path:               "AGENTS.md",
			Operation:          controlfile.OperationUpsert,
			ContentDigest:      &contentDigest,
			ContentSize:        7,
			Diff:               "@@ -1 +1 @@\n-old\n+new\n",
			ProposedByDeviceID: deviceID,
			ChainIndex:         8,
		}},
	}

	writes := projectionWrites(changes)
	authorization := writes.CredentialAuthorizations[0]
	if authorization.Role != device.RoleEditor ||
		authorization.ClockEndorsements[0].DeviceID != deviceID ||
		authorization.ClockEndorsements[0].Signature != signature ||
		authorization.BindingSignature != signature {
		t.Fatalf("mapped credential authorization = %#v", authorization)
	}
	proposal := writes.ControlFileProposals[0]
	if proposal.Operation != store.ControlFileUpsert ||
		proposal.ContentDigest == nil ||
		*proposal.ContentDigest != expectedContentDigest {
		t.Fatalf("mapped control-file proposal = %#v", proposal)
	}

	changes.CredentialAuthorizations[0].
		ClockEndorsements[0].Signature[0] ^= 0xff
	(*changes.ControlFileProposals[0].ContentDigest)[0] ^= 0xff
	if writes.CredentialAuthorizations[0].
		ClockEndorsements[0].Signature != signature ||
		*writes.ControlFileProposals[0].ContentDigest != expectedContentDigest {
		t.Fatal("mapped nested credential or control-file data aliases reducer output")
	}
}

func TestBuildApplyRequestMapsExplicitAuditAndLocalAlarm(t *testing.T) {
	t.Parallel()

	auditSigned, deviceID := applyTestSignedDaemonEvent(
		t,
		event.KindAuditRecorded,
		event.NullEntityID(),
		[]byte(`{}`),
	)
	explicit := reducer.AuditRecordedDirective{
		ReporterDeviceID:       deviceID,
		SubjectDeviceID:        deviceID,
		SubjectCredentialEpoch: 4,
		ActionCode:             "api.mutate",
		OutcomeCode:            "invalid.request",
		Subject:                "task:example",
	}
	auditRequest, err := BuildApplyRequest(
		auditSigned,
		reducer.Outcome{
			Status:        reducer.StatusAccepted,
			Code:          reducer.CodeAccepted,
			Changes:       reducer.Changes{AdvancesEventChain: true},
			RecordedAudit: &explicit,
		},
		applyTestContext(),
	)
	if err != nil {
		t.Fatalf("BuildApplyRequest(explicit audit): %v", err)
	}
	if len(auditRequest.Audit) != 1 ||
		auditRequest.Audit[0].SourceKind != store.AuditEvent ||
		auditRequest.Audit[0].SubjectCredentialEpoch == nil ||
		*auditRequest.Audit[0].SubjectCredentialEpoch != 4 ||
		auditRequest.Audit[0].ActionCode != explicit.ActionCode ||
		auditRequest.Audit[0].OutcomeCode != explicit.OutcomeCode ||
		auditRequest.Audit[0].IPCChannel != "daemon" {
		t.Fatalf("mapped explicit audit = %#v", auditRequest.Audit)
	}

	conflictID := "ccf1" + strings.Repeat("a", 64)
	conflictSigned, _ := applyTestSignedDaemonEvent(
		t,
		event.KindWorkspaceConflictDetected,
		event.StringEntityID(conflictID),
		[]byte(`{}`),
	)
	alarmSubject := "conflict:" + conflictID
	alarmOutcome := reducer.Outcome{
		Status: reducer.StatusRejected,
		Code:   reducer.CodeConflictImmutableTupleMismatch,
		Alarm: &reducer.AlarmDirective{
			Class:   reducer.AlarmConflictIntegrity,
			Subject: alarmSubject,
		},
	}
	alarmRequest, err := BuildApplyRequest(
		conflictSigned,
		alarmOutcome,
		applyTestContext(),
	)
	if err != nil {
		t.Fatalf("BuildApplyRequest(alarm): %v", err)
	}
	if len(alarmRequest.Audit) != 2 {
		t.Fatalf("alarm audit count = %d, want 2", len(alarmRequest.Audit))
	}
	alarm := alarmRequest.Audit[1]
	if alarm.SourceKind != store.AuditLocalAggregate ||
		alarm.ResultIndex != 5 ||
		alarm.ActionCode != "alarm.conflict_integrity" ||
		alarm.OutcomeCode !=
			string(reducer.CodeConflictImmutableTupleMismatch) ||
		alarm.Subject != alarmSubject ||
		!bytes.Equal(
			alarm.DetailsJSON,
			[]byte(`{"class":"conflict_integrity"}`),
		) {
		t.Fatalf("mapped local alarm = %#v", alarm)
	}

	alarmOutcome.Alarm.Class = "unknown"
	if _, err := BuildApplyRequest(
		conflictSigned,
		alarmOutcome,
		applyTestContext(),
	); !errors.Is(err, ErrInvalidApplyMapping) {
		t.Fatalf(
			"BuildApplyRequest(unknown alarm) error = %v, want ErrInvalidApplyMapping",
			err,
		)
	}
}

func TestCheckpointRecordMapsAndOwnsProofBytes(t *testing.T) {
	t.Parallel()

	_, deviceID := applyTestSignedTask(t)
	checkpoint := domain.Checkpoint{
		SessionID:                applyTestSessionID,
		WorkspaceID:              applyTestWorkspace,
		RecoveryGeneration:       2,
		AuthorityVoterSetVersion: 3,
		SignerDeviceID:           deviceID,
		Term:                     4,
		CoveredAppliedLogIndex:   5,
		CoveredChainIndex:        6,
		CoveredChainHash:         [sha256.Size]byte{0x51},
		CoveredResultIndex:       7,
		CoveredResultHash:        [sha256.Size]byte{0x61},
		ProjectionAccumulator:    [sha256.Size]byte{0x71},
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	directive := reducer.CheckpointDirective{
		Checkpoint:            checkpoint,
		CanonicalUnsignedJSON: []byte(`{"proof":"value"}`),
		AuthoritySignature:    [ed25519.SignatureSize]byte{0x81},
	}
	record := checkpointRecord(applyTestEventID, directive)
	if record.CheckpointEventID != applyTestEventID ||
		record.SessionID != checkpoint.SessionID ||
		record.WorkspaceID != checkpoint.WorkspaceID ||
		record.RecoveryGeneration != checkpoint.RecoveryGeneration ||
		record.AuthorityVoterSetVersion !=
			checkpoint.AuthorityVoterSetVersion ||
		record.SignerDeviceID != checkpoint.SignerDeviceID ||
		record.Term != checkpoint.Term ||
		record.CoveredAppliedLogIndex !=
			checkpoint.CoveredAppliedLogIndex ||
		record.CoveredChainIndex != checkpoint.CoveredChainIndex ||
		record.CoveredChainHash != checkpoint.CoveredChainHash ||
		record.CoveredResultIndex != checkpoint.CoveredResultIndex ||
		record.CoveredResultHash != checkpoint.CoveredResultHash ||
		record.ProjectionAccumulator != checkpoint.ProjectionAccumulator ||
		record.DigestVersion != checkpoint.DigestVersion ||
		record.ProjectionSchemaVersion !=
			checkpoint.ProjectionSchemaVersion ||
		record.AuthoritySignature != directive.AuthoritySignature ||
		!bytes.Equal(record.CheckpointJSON, directive.CanonicalUnsignedJSON) {
		t.Fatalf("mapped checkpoint record = %#v", record)
	}
	directive.CanonicalUnsignedJSON[0] = '!'
	if record.CheckpointJSON[0] == '!' {
		t.Fatal("mapped checkpoint JSON aliases the reducer directive")
	}
}

func TestBuildApplyRequestRejectsInconsistentInputs(t *testing.T) {
	t.Parallel()

	signed, _ := applyTestSignedTask(t)
	valid := reducer.Outcome{
		Status:  reducer.StatusAccepted,
		Code:    reducer.CodeAccepted,
		Changes: reducer.Changes{AdvancesEventChain: true},
	}
	tests := []struct {
		name    string
		outcome reducer.Outcome
		context ApplyContext
	}{
		{
			name:    "zero term",
			outcome: valid,
			context: func() ApplyContext {
				value := applyTestContext()
				value.Term = 0
				return value
			}(),
		},
		{
			name: "accepted without chain marker",
			outcome: reducer.Outcome{
				Status: reducer.StatusAccepted,
				Code:   reducer.CodeAccepted,
			},
			context: applyTestContext(),
		},
		{
			name: "rejected with chain marker",
			outcome: reducer.Outcome{
				Status:  reducer.StatusRejected,
				Code:    reducer.CodeInvalidPayload,
				Changes: reducer.Changes{AdvancesEventChain: true},
			},
			context: applyTestContext(),
		},
		{
			name: "unknown audit class",
			outcome: reducer.Outcome{
				Status: reducer.StatusAccepted,
				Code:   reducer.CodeAccepted,
				Changes: reducer.Changes{
					AdvancesEventChain: true,
				},
				Audit: &reducer.AuditDirective{Class: "unknown"},
			},
			context: applyTestContext(),
		},
		{
			name: "rejected activity",
			outcome: reducer.Outcome{
				Status:         reducer.StatusRejected,
				Code:           reducer.CodeInvalidPayload,
				RecordActivity: true,
			},
			context: applyTestContext(),
		},
		{
			name: "rejected operator audit",
			outcome: reducer.Outcome{
				Status: reducer.StatusRejected,
				Code:   reducer.CodeInvalidPayload,
				Audit: &reducer.AuditDirective{
					Class: reducer.AuditOperatorOverride,
				},
			},
			context: applyTestContext(),
		},
		{
			name: "rejected explicit audit",
			outcome: reducer.Outcome{
				Status:        reducer.StatusRejected,
				Code:          reducer.CodeInvalidPayload,
				RecordedAudit: &reducer.AuditRecordedDirective{},
			},
			context: applyTestContext(),
		},
		{
			name: "rejected checkpoint",
			outcome: reducer.Outcome{
				Status:     reducer.StatusRejected,
				Code:       reducer.CodeInvalidPayload,
				Checkpoint: &reducer.CheckpointDirective{},
			},
			context: applyTestContext(),
		},
		{
			name: "alarm on wrong kind",
			outcome: reducer.Outcome{
				Status: reducer.StatusRejected,
				Code:   reducer.CodeInvalidPayload,
				Alarm: &reducer.AlarmDirective{
					Class: reducer.AlarmConflictIntegrity,
				},
			},
			context: applyTestContext(),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := BuildApplyRequest(
				signed,
				test.outcome,
				test.context,
			); !errors.Is(err, ErrInvalidApplyMapping) {
				t.Fatalf(
					"BuildApplyRequest() error = %v, want ErrInvalidApplyMapping",
					err,
				)
			}
		})
	}

	for _, kind := range []event.Kind{
		event.KindAuditRecorded,
		event.KindConsensusCheckpoint,
	} {
		signed, _ := applyTestSignedDaemonEvent(
			t,
			kind,
			event.NullEntityID(),
			[]byte(`{}`),
		)
		if _, err := BuildApplyRequest(
			signed,
			valid,
			applyTestContext(),
		); !errors.Is(err, ErrInvalidApplyMapping) {
			t.Fatalf(
				"BuildApplyRequest(%s without directive) error = %v, want ErrInvalidApplyMapping",
				kind,
				err,
			)
		}
	}
}

func applyTestSignedTask(t *testing.T) (event.SignedEvent, domain.DeviceID) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x42}, ed25519.SeedSize),
	)
	deviceIDText, err := codec.DeriveDeviceID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("DeriveDeviceID(): %v", err)
	}
	deviceID := domain.DeviceID(deviceIDText)
	binding, err := event.NewMCPBinding(
		deviceID,
		applyTestAgentID,
		nil,
	)
	if err != nil {
		t.Fatalf("NewMCPBinding(): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     event.KindTaskCreated,
			EntityID: event.StringEntityID(string(applyTestTaskID)),
			Actions:  []event.Action{},
			Payload:  []byte(`{"priority":2,"title":"task"}`),
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        applyTestEventID,
			SessionID:      applyTestSessionID,
			WorkspaceID:    applyTestWorkspace,
			CreatedAt:      applyTestTimestamp,
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatalf("BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	return signed, deviceID
}

func applyTestSignedDaemonEvent(
	t *testing.T,
	kind event.Kind,
	entityID event.EntityID,
	payload []byte,
) (event.SignedEvent, domain.DeviceID) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x52}, ed25519.SeedSize),
	)
	deviceIDText, err := codec.DeriveDeviceID(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("DeriveDeviceID(): %v", err)
	}
	deviceID := domain.DeviceID(deviceIDText)
	authority, err := event.NewLocalAuthority(deviceID, applyTestBootID)
	if err != nil {
		t.Fatalf("NewLocalAuthority(): %v", err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatalf("DaemonBinding(): %v", err)
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:     kind,
			EntityID: entityID,
			Actions:  []event.Action{},
			Payload:  payload,
			Redaction: event.Redaction{
				Policy:        event.RedactionDefault,
				FieldsRemoved: []event.RedactionField{},
			},
		},
		binding,
		event.BuildContext{
			EventID:        applyTestEventID,
			SessionID:      applyTestSessionID,
			WorkspaceID:    applyTestWorkspace,
			CreatedAt:      applyTestTimestamp,
			OriginSequence: 1,
		},
	)
	if err != nil {
		t.Fatalf("BuildProposal(): %v", err)
	}
	signed, err := event.Sign(proposal, privateKey)
	if err != nil {
		t.Fatalf("Sign(): %v", err)
	}
	return signed, deviceID
}

func applyTestContext() ApplyContext {
	return ApplyContext{
		Term:               3,
		LogIndex:           7,
		RecoveryGeneration: 0,
		AppliedAt:          applyTestTimestamp,
		OriginBootID:       applyTestBootID,
		MonotonicNowNS:     100,
		PriorHeads: store.ApplyHeads{
			ResultIndex:             4,
			DigestVersion:           1,
			ProjectionSchemaVersion: 1,
		},
	}
}
