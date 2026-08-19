package ui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	uiTestSessionID   = domain.UUIDv7("018f47de-89ab-7def-8123-0123456789ab")
	uiTestWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	uiTestClientID    = domain.UUIDv7("018f47de-89ab-7def-8123-1123456789ab")
	uiTestAgentID     = domain.UUIDv7("018f47de-89ab-7def-8123-2123456789ab")
	uiTestRootID      = domain.UUIDv7("018f47de-89ab-7def-8123-3123456789ab")
	uiTestTaskID      = domain.UUIDv7("018f47de-89ab-7def-8123-4123456789ab")
)

func TestOperatorServiceBindsOnlyMatchingOperatorClass(t *testing.T) {
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return uiTestStatusSnapshot(t), nil
		}),
		Submitter:   successfulOperatorSubmitter(),
		Pairing:     testPairingOperator{},
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatalf("NewOperatorService(): %v", err)
	}
	valid := ipc.BindRequest{
		ProtocolVersion:  ipc.LocalProtocolVersion,
		ClientInstanceID: uiTestClientID,
		SessionID:        uiTestSessionID,
		WorkspaceID:      uiTestWorkspaceID,
		Class:            ipc.ClassOperator,
	}
	if _, err := service.Bind(
		context.Background(),
		ipc.VerifiedPeer{},
		valid,
	); err != nil {
		t.Fatalf("Bind(operator): %v", err)
	}
	for _, mutate := range []func(*ipc.BindRequest){
		func(request *ipc.BindRequest) { request.Class = ipc.ClassAgent },
		func(request *ipc.BindRequest) {
			request.SessionID = domain.UUIDv7(
				"018f47de-89ab-7def-8123-5123456789ab",
			)
		},
		func(request *ipc.BindRequest) {
			request.WorkspaceID = domain.UUIDv4(
				"650e8400-e29b-41d4-a716-446655440000",
			)
		},
	} {
		request := valid
		mutate(&request)
		if _, err := service.Bind(
			context.Background(),
			ipc.VerifiedPeer{},
			request,
		); !errors.Is(err, ErrOperatorBindRejected) {
			t.Fatalf("Bind(invalid) error = %v, want %v", err, ErrOperatorBindRejected)
		}
	}
}

func TestOperatorStatusHandlerReturnsClosedBoundedProjection(t *testing.T) {
	source := uiTestStatusSnapshot(t)
	handler := newOperatorHandler(statusSourceFunc(
		func(context.Context) (coordstatus.Snapshot, error) {
			return source, nil
		},
	), successfulOperatorSubmitter(), testPairingOperator{}, uiTestClientID)
	request := httptest.NewRequest(
		http.MethodGet,
		statusQueryPath,
		nil,
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var got Snapshot
	decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Snapshot.Validate(): %v", err)
	}
	if got.Session.SessionID != string(uiTestSessionID) ||
		got.Session.LocalDeviceID != string(source.Durable.Member.ID) ||
		got.Consensus.State != string(coordstatus.ConsensusReady) ||
		len(got.Members) != 1 ||
		got.Members[0].EntityVersion != source.Durable.Member.EntityVersion ||
		len(got.Agents) != 1 ||
		got.Agents[0].AgentSessionID != string(uiTestAgentID) ||
		got.TaskTotal != 1 ||
		len(got.Tasks) != 1 ||
		got.Tasks[0].TaskID != string(uiTestTaskID) ||
		strings.Contains(recorder.Body.String(), "task body must stay private") ||
		strings.Contains(recorder.Body.String(), "identity_public_key") {
		t.Fatalf("status snapshot = %#v; body = %s", got, recorder.Body.String())
	}
}

func TestOperatorStatusHandlerFailsClosed(t *testing.T) {
	handler := newOperatorHandler(statusSourceFunc(
		func(context.Context) (coordstatus.Snapshot, error) {
			return coordstatus.Snapshot{}, errors.New("store unavailable")
		},
	), successfulOperatorSubmitter(), testPairingOperator{}, uiTestClientID)
	for _, test := range []struct {
		name    string
		request *http.Request
	}{
		{
			name:    "other path",
			request: httptest.NewRequest(http.MethodGet, "/local/v1/query/other", nil),
		},
		{
			name: "wrong method",
			request: httptest.NewRequest(
				http.MethodPost,
				statusQueryPath,
				strings.NewReader(`{}`),
			),
		},
		{
			name: "query",
			request: httptest.NewRequest(
				http.MethodGet,
				statusQueryPath+"?other=true",
				nil,
			),
		},
		{
			name: "encoded path",
			request: httptest.NewRequest(
				http.MethodGet,
				"/local/v1/query/%73tatus",
				nil,
			),
		},
		{
			name: "forced query",
			request: httptest.NewRequest(
				http.MethodGet,
				statusQueryPath+"?",
				nil,
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf(
					"%s %s status = %d, want 404",
					test.request.Method,
					test.request.URL,
					recorder.Code,
				)
			}
		})
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, statusQueryPath, nil),
	)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed source status = %d, want 503", recorder.Code)
	}
}

func TestOperatorCommandHandlerRoutesOnlyAllowlistedHumanMutations(
	t *testing.T,
) {
	source := uiTestStatusSnapshot(t)
	deviceID := source.Durable.Member.ID
	var captured operatorcommand.Request
	submitter := operatorSubmitterFunc(func(
		_ context.Context,
		request operatorcommand.Request,
	) (operatorcommand.Result, error) {
		captured = request
		return operatorcommand.Result{
			EventID: uiTestTaskID,
			Outcome: store.CommandOutcome{
				Status: store.OutcomeAccepted,
				Code:   "accepted",
				JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
			},
		}, nil
	})
	handler := newOperatorHandler(
		statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return source, nil
		}),
		submitter,
		testPairingOperator{},
		uiTestClientID,
	)
	body, err := operatorCommandBody(
		operatorcommand.OperationRevokePeer,
		uiTestClientID,
		event.KindMembershipDeviceRevoked,
		string(deviceID),
		1,
		map[string]any{
			"device_id":                  deviceID,
			"expected_voter_set_version": uint64(1),
			"reason":                     "retired device",
			"voter_set":                  []domain.DeviceID{deviceID},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, commandPath, bytes.NewReader(body)),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if captured.ClientInstanceID != uiTestClientID ||
		captured.Command.Operation != operatorcommand.OperationRevokePeer ||
		captured.Command.Command.Kind != event.KindMembershipDeviceRevoked ||
		captured.Command.Command.ExpectedEntityVersion == nil ||
		*captured.Command.Command.ExpectedEntityVersion != 1 {
		t.Fatalf("captured request = %#v", captured)
	}

	invalid := bytes.Replace(
		body,
		[]byte(`"membership.device_revoked"`),
		[]byte(`"membership.voter_set_changed"`),
		1,
	)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(
			http.MethodPost,
			commandPath,
			bytes.NewReader(invalid),
		),
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("mismatched operation status = %d", recorder.Code)
	}

	for _, target := range []string{
		"/local/v1/%63ommands",
		commandPath + "?",
		commandPath + "?other=true",
	} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(
			recorder,
			httptest.NewRequest(
				http.MethodPost,
				target,
				bytes.NewReader(body),
			),
		)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf(
				"non-exact command route %q status = %d, want 404",
				target,
				recorder.Code,
			)
		}
	}
}

type statusSourceFunc func(context.Context) (coordstatus.Snapshot, error)

func (function statusSourceFunc) Status(
	ctx context.Context,
) (coordstatus.Snapshot, error) {
	return function(ctx)
}

type operatorSubmitterFunc func(
	context.Context,
	operatorcommand.Request,
) (operatorcommand.Result, error)

func (function operatorSubmitterFunc) SubmitOperatorCommand(
	ctx context.Context,
	request operatorcommand.Request,
) (operatorcommand.Result, error) {
	return function(ctx, request)
}

func successfulOperatorSubmitter() operatorcommand.Submitter {
	return operatorSubmitterFunc(func(
		context.Context,
		operatorcommand.Request,
	) (operatorcommand.Result, error) {
		return operatorcommand.Result{}, nil
	})
}

func uiTestStatusSnapshot(t *testing.T) coordstatus.Snapshot {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat(
		[]byte{0x31},
		ed25519.SeedSize,
	))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	member := device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: publicKey,
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
	target, err := voterset.New(
		uiTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	profile := "codex\x1b]8;;https://invalid.example\x07hostile"
	agent := agentsession.Session{
		ID:             uiTestAgentID,
		DeviceID:       deviceID,
		ClientKind:     agentsession.ClientKindCodex,
		AgentProfileID: &profile,
		State:          agentsession.StateWorking,
		WorkingRootID:  uiTestRootID,
		EntityVersion:  1,
	}
	value := task.Task{
		ID:                  uiTestTaskID,
		Title:               "status task",
		Body:                "task body must stay private",
		State:               task.StateInProgress,
		Priority:            task.PriorityHigh,
		BlockedBy:           []domain.UUIDv7{},
		Labels:              []string{},
		OwnerDeviceID:       deviceID,
		OwnerAgentSessionID: uiTestAgentID,
		EntityVersion:       1,
		CreatedAt:           domain.Timestamp("2026-08-12T10:00:00Z"),
		UpdatedAt:           domain.Timestamp("2026-08-12T10:01:00Z"),
	}
	term := uint64(1)
	applied := uint64(4)
	snapshot := coordstatus.Snapshot{
		Durable: coordstatus.DurableSnapshot{
			SessionID:          uiTestSessionID,
			WorkspaceID:        uiTestWorkspaceID,
			RecoveryGeneration: 0,
			Heads: coordstatus.AppliedHeads{
				CurrentTerm:             &term,
				LastRaftAppliedLogIndex: &applied,
				ChainIndex:              2,
				ResultIndex:             3,
				DigestVersion:           1,
				ProjectionSchemaVersion: 1,
			},
			Member: member,
			Members: []coordstatus.MemberSummary{{
				ID:            member.ID,
				Role:          member.Role,
				Status:        member.Status,
				EntityVersion: member.EntityVersion,
			}},
			MemberTotal:         1,
			VoterSet:            target,
			CredentialAuthority: target,
			AgentSessions:       []agentsession.Session{agent},
			Tasks:               []task.Task{value},
			TaskTotal:           1,
		},
		Runtime: coordstatus.RuntimeSnapshot{
			State:                   coordstatus.ConsensusReady,
			Role:                    coordstatus.RoleLeader,
			LocalDeviceID:           deviceID,
			LeaderDeviceID:          deviceID,
			LiveVoterDeviceIDs:      []domain.DeviceID{deviceID},
			LiveNonvoterDeviceIDs:   []domain.DeviceID{},
			QuorumRequired:          1,
			StrongWrites:            coordstatus.StrongWritesAvailable,
			ConfigurationReconciled: true,
			ReconciliationState:     coordstatus.ReconciliationStable,
			ReconciliationStep:      coordstatus.ReconciliationStepComplete,
			ReconciliationBlocker:   coordstatus.ReconciliationBlockerNone,
		},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("test snapshot: %v", err)
	}
	return snapshot
}
