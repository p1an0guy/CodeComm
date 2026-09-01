package ui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	uiPairingInviteID  = domain.UUIDv7("018f47de-89ab-7def-8123-6123456789ab")
	uiPairingAttemptID = domain.UUIDv7("018f47de-89ab-7def-8123-7123456789ab")
)

type recordingPairingOperator struct {
	createRequest pairingservice.CreateInviteRequest
	createResult  pairingservice.IssuedInvite
	createErr     error
	createCalls   int

	listResult []store.PairingInviteRecord
	listErr    error
	listCalls  int

	revokeID        domain.UUIDv7
	revokeResult    store.PairingInviteRecord
	revokeDuplicate bool
	revokeErr       error
	revokeCalls     int

	attemptID     domain.UUIDv7
	attemptResult pairingservice.AttemptDetails
	attemptErr    error
	attemptCalls  int

	confirmID       domain.UUIDv7
	confirmDigest   [sha256.Size]byte
	confirmDecision bool
	confirmResult   pairingservice.AttemptDetails
	confirmErr      error
	confirmCalls    int
}

func (operator *recordingPairingOperator) CreateInvite(
	_ context.Context,
	request pairingservice.CreateInviteRequest,
) (pairingservice.IssuedInvite, error) {
	operator.createCalls++
	operator.createRequest = request
	return operator.createResult, operator.createErr
}

func (operator *recordingPairingOperator) ListInvites(
	context.Context,
) ([]store.PairingInviteRecord, error) {
	operator.listCalls++
	return operator.listResult, operator.listErr
}

func (operator *recordingPairingOperator) RevokeInvite(
	_ context.Context,
	inviteID domain.UUIDv7,
) (store.PairingInviteRecord, bool, error) {
	operator.revokeCalls++
	operator.revokeID = inviteID
	return operator.revokeResult, operator.revokeDuplicate, operator.revokeErr
}

func (operator *recordingPairingOperator) PairingAttempt(
	_ context.Context,
	attemptID domain.UUIDv7,
) (pairingservice.AttemptDetails, error) {
	operator.attemptCalls++
	operator.attemptID = attemptID
	return operator.attemptResult, operator.attemptErr
}

func (operator *recordingPairingOperator) ConfirmPairing(
	_ context.Context,
	attemptID domain.UUIDv7,
	requestDigest [sha256.Size]byte,
	confirmed bool,
) (pairingservice.AttemptDetails, error) {
	operator.confirmCalls++
	operator.confirmID = attemptID
	operator.confirmDigest = requestDigest
	operator.confirmDecision = confirmed
	result := operator.confirmResult
	if operator.confirmErr == nil &&
		result.Attempt.State == store.PairingAttemptAwaitingSAS {
		result.Attempt.LocalConfirmed = confirmed
		if confirmed {
			result.Attempt.State = store.PairingAttemptCompleted
		} else {
			result.Attempt.State = store.PairingAttemptDeclined
		}
	}
	return result, operator.confirmErr
}

func TestPairingOperatorHandlerRoutesClosedProtocol(t *testing.T) {
	signed, outstanding, details := uiPairingFixture(t)
	revoked := outstanding
	revoked.State = store.PairingInviteRevoked
	revoked.TerminalAt = "2026-08-13T12:02:00Z"
	operator := &recordingPairingOperator{
		createResult: pairingservice.IssuedInvite{
			Invite: signed,
			Record: outstanding,
		},
		listResult:      []store.PairingInviteRecord{outstanding, revoked},
		revokeResult:    revoked,
		revokeDuplicate: true,
		attemptResult:   details,
		confirmResult:   details,
	}
	handler := newOperatorHandler(nil, nil, operator, nil, uiTestClientID)

	createBody := `{"mode":"new","subject_device_id":null,` +
		`"expected_entity_version":null,"role":"editor",` +
		`"initial_credential_epoch":1}`
	create := servePairingOperatorRequest(
		handler,
		http.MethodPost,
		pairingInviteCollectionPath,
		createBody,
	)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", create.Code, create.Body.String())
	}
	var created PairingInviteCreated
	decodePairingOperatorResponse(t, create, &created)
	if created.Code != signed.Code() ||
		created.Invite.InviteID != string(uiPairingInviteID) ||
		operator.createCalls != 1 ||
		operator.createRequest.Mode != pairing.ModeNew ||
		operator.createRequest.Role != device.RoleEditor ||
		operator.createRequest.SubjectDeviceID != nil ||
		operator.createRequest.ExpectedEntityVersion != nil ||
		operator.createRequest.InitialCredentialEpoch != 1 {
		t.Fatalf("created = %#v, request = %#v", created, operator.createRequest)
	}

	list := servePairingOperatorRequest(
		handler,
		http.MethodGet,
		pairingInviteCollectionPath,
		"",
	)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", list.Code, list.Body.String())
	}
	var listed PairingInviteList
	decodePairingOperatorResponse(t, list, &listed)
	if operator.listCalls != 1 ||
		len(listed.Invites) != 2 ||
		listed.Invites[1].State != string(store.PairingInviteRevoked) {
		t.Fatalf("listed = %#v", listed)
	}

	revoke := servePairingOperatorRequest(
		handler,
		http.MethodPost,
		pairingInviteRevokePath,
		`{"invite_id":"`+string(uiPairingInviteID)+`"}`,
	)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", revoke.Code, revoke.Body.String())
	}
	var revokedResponse PairingInviteRevoked
	decodePairingOperatorResponse(t, revoke, &revokedResponse)
	if operator.revokeCalls != 1 ||
		operator.revokeID != uiPairingInviteID ||
		!revokedResponse.Duplicate ||
		revokedResponse.Invite.State != string(store.PairingInviteRevoked) {
		t.Fatalf("revoked = %#v, id = %s", revokedResponse, operator.revokeID)
	}

	attempt := servePairingOperatorRequest(
		handler,
		http.MethodPost,
		pairingAttemptPath,
		`{"attempt_id":"`+string(uiPairingAttemptID)+`"}`,
	)
	if attempt.Code != http.StatusOK {
		t.Fatalf("attempt status = %d, body = %s", attempt.Code, attempt.Body.String())
	}
	var attemptResponse PairingAttemptStatus
	decodePairingOperatorResponse(t, attempt, &attemptResponse)
	if operator.attemptCalls != 1 ||
		operator.attemptID != uiPairingAttemptID ||
		attemptResponse.SAS != details.SAS {
		t.Fatalf("attempt = %#v, id = %s", attemptResponse, operator.attemptID)
	}

	confirmBody := `{"attempt_id":"` + string(uiPairingAttemptID) +
		`","request_digest":"` +
		codec.EncodeBase64URL(details.Attempt.RequestDigest[:]) +
		`","confirmed":true}`
	confirm := servePairingOperatorRequest(
		handler,
		http.MethodPost,
		pairingConfirmPath,
		confirmBody,
	)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", confirm.Code, confirm.Body.String())
	}
	if operator.confirmCalls != 1 ||
		operator.confirmID != uiPairingAttemptID ||
		operator.confirmDigest != [sha256.Size]byte(details.Attempt.RequestDigest) ||
		!operator.confirmDecision {
		t.Fatalf(
			"confirm = (%s, %x, %t)",
			operator.confirmID,
			operator.confirmDigest,
			operator.confirmDecision,
		)
	}
}

func TestPairingOperatorHandlerReturnsAcceptedWhileFinalizing(t *testing.T) {
	_, _, details := uiPairingFixture(t)
	details.Attempt.State = store.PairingAttemptFinalizing
	details.Attempt.LocalConfirmed = true
	details.Attempt.RemoteConfirmed = true
	operator := &recordingPairingOperator{
		confirmResult: details,
		confirmErr:    pairingservice.ErrFinalizationPending,
	}
	body := `{"attempt_id":"` + string(uiPairingAttemptID) +
		`","request_digest":"` +
		codec.EncodeBase64URL(details.Attempt.RequestDigest[:]) +
		`","confirmed":true}`
	response := servePairingOperatorRequest(
		newOperatorHandler(nil, nil, operator, nil, uiTestClientID),
		http.MethodPost,
		pairingConfirmPath,
		body,
	)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got PairingAttemptStatus
	decodePairingOperatorResponse(t, response, &got)
	if got.State != string(store.PairingAttemptFinalizing) {
		t.Fatalf("response = %#v", got)
	}
}

func TestPairingOperatorHandlerRejectsMalformedBodiesAndRoutes(t *testing.T) {
	operator := &recordingPairingOperator{}
	handler := newOperatorHandler(nil, nil, operator, nil, uiTestClientID)
	oversized := `{"attempt_id":"` +
		strings.Repeat("x", maxPairingOperatorBodyBytes) + `"}`
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{"missing field", http.MethodPost, pairingInviteRevokePath, `{}`, 400},
		{"unknown field", http.MethodPost, pairingInviteRevokePath, `{"invite_id":"x","extra":1}`, 400},
		{"duplicate field", http.MethodPost, pairingInviteRevokePath, `{"invite_id":"x","invite_id":"y"}`, 400},
		{"invalid object", http.MethodPost, pairingAttemptPath, `[]`, 400},
		{"oversized", http.MethodPost, pairingAttemptPath, oversized, 400},
		{"invalid digest", http.MethodPost, pairingConfirmPath, `{"attempt_id":"` + string(uiPairingAttemptID) + `","request_digest":"bad","confirmed":true}`, 400},
		{"wrong method", http.MethodGet, pairingAttemptPath, "", 404},
		{"query", http.MethodPost, pairingAttemptPath + "?x=1", `{"attempt_id":"` + string(uiPairingAttemptID) + `"}`, 404},
		{"encoded path", http.MethodPost, "/local/v1/pairing/%61ttempt", `{"attempt_id":"` + string(uiPairingAttemptID) + `"}`, 404},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := servePairingOperatorRequest(
				handler,
				test.method,
				test.path,
				test.body,
			)
			if response.Code != test.status {
				t.Fatalf(
					"status = %d, want %d, body = %s",
					response.Code,
					test.status,
					response.Body.String(),
				)
			}
		})
	}
	if operator.createCalls != 0 ||
		operator.listCalls != 0 ||
		operator.revokeCalls != 0 ||
		operator.attemptCalls != 0 ||
		operator.confirmCalls != 0 {
		t.Fatalf("malformed requests reached pairing operator: %#v", operator)
	}
}

func TestPairingOperatorErrorMapping(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{context.Canceled, http.StatusRequestTimeout, "pairing_interrupted"},
		{context.DeadlineExceeded, http.StatusRequestTimeout, "pairing_interrupted"},
		{pairingservice.ErrInvalidInput, http.StatusBadRequest, "invalid_pairing_request"},
		{pairingservice.ErrInvalidInviter, http.StatusBadRequest, "invalid_pairing_request"},
		{store.ErrPairingInviteLimit, http.StatusTooManyRequests, "pairing_invite_limit"},
		{pairingservice.ErrAwaitingJoinerConfirmation, http.StatusConflict, "awaiting_joiner_confirmation"},
		{pairingservice.ErrConfirmationConflict, http.StatusConflict, "pairing_confirmation_conflict"},
		{pairingservice.ErrInviteNotRevocable, http.StatusConflict, "pairing_invite_not_revocable"},
		{pairingservice.ErrRequestRejected, http.StatusNotFound, "pairing_not_found"},
		{pairingservice.ErrClosed, http.StatusServiceUnavailable, "pairing_closed"},
		{errors.New("provider failed"), http.StatusServiceUnavailable, "pairing_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writePairingOperatorError(recorder, test.err)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
			var response struct {
				Code   string `json:"code"`
				Status int    `json:"status"`
			}
			decodePairingOperatorResponse(t, recorder, &response)
			if response.Code != test.code || response.Status != test.status {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestOperatorClientPairingRoundTripAndRemoteErrors(t *testing.T) {
	signed, outstanding, details := uiPairingFixture(t)
	revoked := outstanding
	revoked.State = store.PairingInviteRevoked
	revoked.TerminalAt = "2026-08-13T12:02:00Z"
	operator := &recordingPairingOperator{
		createResult:  pairingservice.IssuedInvite{Invite: signed, Record: outstanding},
		listResult:    []store.PairingInviteRecord{outstanding},
		revokeResult:  revoked,
		attemptResult: details,
		confirmResult: details,
	}
	endpoint := newUIClientTestEndpoint(t)
	service, err := NewOperatorService(OperatorServiceOptions{
		Source: statusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			return uiTestStatusSnapshot(t), nil
		}),
		Submitter:   successfulOperatorSubmitter(),
		Pairing:     operator,
		SessionID:   uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := startUIClientTestServer(t, endpoint, service)
	t.Cleanup(func() { server.stop(t) })
	client, err := DialOperator(testUIClientContext(t), OperatorDialOptions{
		Endpoint:         endpoint,
		ClientInstanceID: uiTestClientID,
		SessionID:        uiTestSessionID,
		WorkspaceID:      uiTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	created, err := client.CreatePairingInvite(
		testUIClientContext(t),
		pairingservice.CreateInviteRequest{
			Mode:                   pairing.ModeNew,
			Role:                   device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	)
	if err != nil || created.Code != signed.Code() {
		t.Fatalf("CreatePairingInvite() = (%#v, %v)", created, err)
	}
	subject := details.Core.JoinerDeviceID
	version := uint64(7)
	if _, err := client.CreatePairingInvite(
		testUIClientContext(t),
		pairingservice.CreateInviteRequest{
			Mode: pairing.ModeReadmission, SubjectDeviceID: &subject,
			ExpectedEntityVersion: &version, Role: device.RoleEditor,
			InitialCredentialEpoch: 1,
		},
	); !errors.Is(err, ErrPairingProtocol) {
		t.Fatalf("CreatePairingInvite(mismatched echo) error = %v", err)
	}
	listed, err := client.PairingInvites(testUIClientContext(t))
	if err != nil || len(listed.Invites) != 1 {
		t.Fatalf("PairingInvites() = (%#v, %v)", listed, err)
	}
	revokedResponse, err := client.RevokePairingInvite(
		testUIClientContext(t),
		uiPairingInviteID,
	)
	if err != nil || revokedResponse.Invite.State != string(store.PairingInviteRevoked) {
		t.Fatalf("RevokePairingInvite() = (%#v, %v)", revokedResponse, err)
	}
	attempt, err := client.PairingAttempt(
		testUIClientContext(t),
		uiPairingAttemptID,
	)
	if err != nil || attempt.SAS != details.SAS {
		t.Fatalf("PairingAttempt() = (%#v, %v)", attempt, err)
	}
	confirmed, err := client.ConfirmPairing(
		testUIClientContext(t),
		attempt,
		true,
	)
	if err != nil || confirmed.AttemptID != string(uiPairingAttemptID) {
		t.Fatalf("ConfirmPairing() = (%#v, %v)", confirmed, err)
	}
	if operator.confirmDigest != [sha256.Size]byte(details.Attempt.RequestDigest) ||
		!operator.confirmDecision {
		t.Fatalf("confirmation capture = (%x, %t)", operator.confirmDigest, operator.confirmDecision)
	}
	changed := details
	changed.Attempt.RequestDigest[0] ^= 0xff
	operator.confirmResult = changed
	if _, err := client.ConfirmPairing(
		testUIClientContext(t),
		attempt,
		true,
	); !errors.Is(err, ErrPairingProtocol) {
		t.Fatalf("ConfirmPairing(changed digest) error = %v", err)
	}

	operator.revokeErr = pairingservice.ErrInviteNotRevocable
	_, err = client.RevokePairingInvite(testUIClientContext(t), uiPairingInviteID)
	var remote *ipc.ClientError
	if !errors.As(err, &remote) ||
		remote.Status != http.StatusConflict ||
		remote.Code != "pairing_invite_not_revocable" {
		t.Fatalf("RevokePairingInvite(error) = %v", err)
	}
}

func TestPairingProtocolValidationRejectsMutations(t *testing.T) {
	_, outstanding, details := uiPairingFixture(t)
	validInvite := pairingInviteStatus(outstanding)
	inviteMutations := []struct {
		name   string
		mutate func(*PairingInviteStatus)
	}{
		{"invite ID", func(value *PairingInviteStatus) { value.InviteID = "bad" }},
		{"mode", func(value *PairingInviteStatus) { value.Mode = "other" }},
		{"role", func(value *PairingInviteStatus) { value.Role = "root" }},
		{"epoch", func(value *PairingInviteStatus) { value.InitialCredentialEpoch = 0 }},
		{"proof failures", func(value *PairingInviteStatus) { value.ProofFailures = store.MaxPairingProofFailures + 1 }},
		{"state", func(value *PairingInviteStatus) { value.State = "lost" }},
		{"created", func(value *PairingInviteStatus) { value.CreatedAt = "now" }},
		{"subject", func(value *PairingInviteStatus) { subject := "bad"; value.SubjectDeviceID = &subject }},
		{"version", func(value *PairingInviteStatus) { version := uint64(0); value.ExpectedEntityVersion = &version }},
		{"new subject", func(value *PairingInviteStatus) {
			subject := string(details.Core.JoinerDeviceID)
			value.SubjectDeviceID = &subject
		}},
		{"consumed attempt absent", func(value *PairingInviteStatus) {
			value.State = string(store.PairingInviteConsumed)
			value.TerminalAt = stringPointer("2026-08-13T12:01:00Z")
		}},
		{"terminal absent", func(value *PairingInviteStatus) { value.State = string(store.PairingInviteRevoked) }},
	}
	if err := validInvite.validate(); err != nil {
		t.Fatalf("valid invite: %v", err)
	}
	for _, test := range inviteMutations {
		t.Run("invite "+test.name, func(t *testing.T) {
			candidate := validInvite
			test.mutate(&candidate)
			if candidate.validate() == nil {
				t.Fatalf("mutation accepted: %#v", candidate)
			}
		})
	}

	validAttempt := pairingAttemptStatus(details)
	attemptMutations := []struct {
		name   string
		mutate func(*PairingAttemptStatus)
	}{
		{"attempt ID", func(value *PairingAttemptStatus) { value.AttemptID = "bad" }},
		{"invite ID", func(value *PairingAttemptStatus) { value.InviteID = "bad" }},
		{"mode", func(value *PairingAttemptStatus) { value.Mode = "other" }},
		{"device", func(value *PairingAttemptStatus) { value.JoinerDeviceID = "bad" }},
		{"identity key", func(value *PairingAttemptStatus) { value.JoinerIdentityPublicKey = "bad" }},
		{"daemon version", func(value *PairingAttemptStatus) { value.DaemonVersion = "" }},
		{"noncanonical daemon version", func(value *PairingAttemptStatus) { value.DaemonVersion = "1.0.0\nspoof" }},
		{"apply level", func(value *PairingAttemptStatus) { value.MaxApplyLevel = 0 }},
		{"role", func(value *PairingAttemptStatus) { value.Role = "root" }},
		{"version", func(value *PairingAttemptStatus) { version := uint64(0); value.ExpectedEntityVersion = &version }},
		{"epoch", func(value *PairingAttemptStatus) { value.InitialCredentialEpoch = 0 }},
		{"epoch key", func(value *PairingAttemptStatus) { value.EpochPublicKey = "bad" }},
		{"digest", func(value *PairingAttemptStatus) { value.EpochKeyDigest = "bad" }},
		{"state", func(value *PairingAttemptStatus) { value.State = "lost" }},
		{"SAS groups", func(value *PairingAttemptStatus) { value.SAS = "1234 5678" }},
		{"SAS characters", func(value *PairingAttemptStatus) { value.SAS = "0001 0002 0003 0004 abcd" }},
	}
	if err := validAttempt.validate(); err != nil {
		t.Fatalf("valid attempt: %v", err)
	}
	for _, test := range attemptMutations {
		t.Run("attempt "+test.name, func(t *testing.T) {
			candidate := validAttempt
			test.mutate(&candidate)
			if candidate.validate() == nil {
				t.Fatalf("mutation accepted: %#v", candidate)
			}
		})
	}
}

func TestPairingConfirmationReviewSubjectIsImmutable(t *testing.T) {
	_, _, details := uiPairingFixture(t)
	reviewed := pairingAttemptStatus(details)
	mutations := []struct {
		name   string
		mutate func(*PairingAttemptStatus)
	}{
		{"invite", func(value *PairingAttemptStatus) { value.InviteID = string(uiPairingAttemptID) }},
		{"request digest", func(value *PairingAttemptStatus) { value.RequestDigest = strings.Repeat("A", len(value.RequestDigest)) }},
		{"device", func(value *PairingAttemptStatus) { value.JoinerDeviceID = string(details.Invite.IssuerDeviceID) }},
		{"identity", func(value *PairingAttemptStatus) {
			value.JoinerIdentityPublicKey = codec.EncodeBase64URL(make([]byte, ed25519.PublicKeySize))
		}},
		{"version", func(value *PairingAttemptStatus) { value.DaemonVersion = "9.9.9" }},
		{"apply level", func(value *PairingAttemptStatus) { value.MaxApplyLevel++ }},
		{"role", func(value *PairingAttemptStatus) { value.Role = string(device.RoleOwner) }},
		{"expected version", func(value *PairingAttemptStatus) { version := uint64(9); value.ExpectedEntityVersion = &version }},
		{"epoch", func(value *PairingAttemptStatus) { value.InitialCredentialEpoch++ }},
		{"epoch key", func(value *PairingAttemptStatus) {
			value.EpochPublicKey = codec.EncodeBase64URL(make([]byte, ed25519.PublicKeySize))
		}},
		{"key digest", func(value *PairingAttemptStatus) {
			value.EpochKeyDigest = codec.EncodeBase64URL(make([]byte, sha256.Size))
		}},
		{"SAS", func(value *PairingAttemptStatus) { value.SAS = "9999 9999 9999 9999 9999" }},
	}
	if !samePairingReviewSubject(reviewed, reviewed) {
		t.Fatal("identical pairing review subject differs")
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := reviewed
			test.mutate(&changed)
			if samePairingReviewSubject(reviewed, changed) {
				t.Fatalf("mutation was not detected: %#v", changed)
			}
		})
	}
}

func TestOperatorClientRejectsInvalidPairingInputsAndResponses(t *testing.T) {
	_, _, details := uiPairingFixture(t)
	var nilClient *OperatorClient
	if _, err := nilClient.PairingInvites(context.Background()); !errors.Is(err, ErrInvalidOperatorDial) {
		t.Fatalf("nil PairingInvites() error = %v", err)
	}
	client := &OperatorClient{}
	if _, err := client.RevokePairingInvite(context.Background(), "bad"); !errors.Is(err, ErrInvalidOperatorDial) {
		t.Fatalf("invalid RevokePairingInvite() error = %v", err)
	}
	if _, err := client.PairingAttempt(context.Background(), "bad"); !errors.Is(err, ErrInvalidOperatorDial) {
		t.Fatalf("invalid PairingAttempt() error = %v", err)
	}
	invalid := pairingAttemptStatus(details)
	invalid.RequestDigest = "bad"
	if _, err := client.ConfirmPairing(context.Background(), invalid, true); !errors.Is(err, ErrInvalidOperatorDial) {
		t.Fatalf("invalid ConfirmPairing() error = %v", err)
	}
	if _, err := decodePairingAttempt([]byte(`{"attempt_id":"bad"}`), uiPairingAttemptID); !errors.Is(err, ErrPairingProtocol) {
		t.Fatalf("decodePairingAttempt() error = %v", err)
	}
	mismatched := pairingAttemptStatus(details)
	mismatched.AttemptID = string(uiPairingInviteID)
	raw, err := json.Marshal(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePairingAttempt(raw, uiPairingAttemptID); !errors.Is(err, ErrPairingProtocol) {
		t.Fatalf("mismatched decodePairingAttempt() error = %v", err)
	}
}

func uiPairingFixture(
	t *testing.T,
) (pairing.SignedInvite, store.PairingInviteRecord, pairingservice.AttemptDetails) {
	t.Helper()
	inviterPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	inviterPublic := inviterPrivate.Public().(ed25519.PublicKey)
	inviterID, err := device.DeriveID(inviterPublic)
	if err != nil {
		t.Fatal(err)
	}
	joinerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	joinerPublic := joinerPrivate.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublic)
	if err != nil {
		t.Fatal(err)
	}
	epochPublic := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x43}, ed25519.SeedSize),
	).Public().(ed25519.PublicKey)
	binding, err := credential.SignBinding(
		uiTestSessionID,
		joinerID,
		1,
		epochPublic,
		joinerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	inviteValue := pairing.Invite{
		InviteID: uiPairingInviteID, SessionID: uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID, CreatedAt: "2026-08-13T12:00:00Z",
		ExpiresAt: "2026-08-13T12:15:00Z", InviterDeviceID: inviterID,
		Mode: pairing.ModeNew, Role: device.RoleEditor,
		InitialCredentialEpoch: 1,
		Endpoints: []pairing.Endpoint{{
			IP: netip.MustParseAddr("10.0.0.5"), Port: 47831,
		}},
	}
	for index := range inviteValue.Secret {
		inviteValue.Secret[index] = byte(index + 1)
	}
	for index := range inviteValue.SignedGenesisDigest {
		inviteValue.SignedGenesisDigest[index] = byte(0x80 + index)
	}
	copy(inviteValue.InviterIdentityPublicKey[:], inviterPublic)
	signed, err := pairing.SignInvite(inviteValue, inviterPrivate)
	clear(inviteValue.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	outstanding := store.PairingInviteRecord{
		InviteID: uiPairingInviteID, SessionID: uiTestSessionID,
		WorkspaceID: uiTestWorkspaceID, IssuerDeviceID: inviterID,
		InviteDigest: store.Digest(signed.Digest()), Mode: pairing.ModeNew,
		Role: device.RoleEditor, InitialCredentialEpoch: 1,
		State: store.PairingInviteOutstanding, CreatedAt: "2026-08-13T12:00:00Z",
		ExpiresAt: "2026-08-13T12:15:00Z",
	}
	core := pairing.RequestCore{
		AttemptID: uiPairingAttemptID, JoinerDeviceID: joinerID,
		DaemonVersion: "1.2.3", MaxApplyLevel: 1,
		InitialEpochBinding: binding,
	}
	copy(core.JoinerIdentityPublicKey[:], joinerPublic)
	var requestDigest store.Digest
	for index := range requestDigest {
		requestDigest[index] = byte(0xa0 + index)
	}
	consumed := outstanding
	consumed.State = store.PairingInviteConsumed
	consumed.ConsumedAttemptID = uiPairingAttemptID
	consumed.TerminalAt = "2026-08-13T12:01:00Z"
	details := pairingservice.AttemptDetails{
		Invite: consumed,
		Attempt: store.PairingAttemptRecord{
			AttemptID: uiPairingAttemptID, InviteID: uiPairingInviteID,
			RequestDigest: requestDigest, JoinerDeviceID: joinerID,
			State: store.PairingAttemptAwaitingSAS, RemoteConfirmed: true,
			CreatedAt: "2026-08-13T12:01:00Z",
		},
		Core: core,
		SAS:  "0001 0002 0003 0004 0005",
	}
	return signed, outstanding, details
}

func servePairingOperatorRequest(
	handler http.Handler,
	method string,
	path string,
	body string,
) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodePairingOperatorResponse(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	target any,
) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
}

func stringPointer(value string) *string {
	return &value
}
