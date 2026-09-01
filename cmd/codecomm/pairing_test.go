package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/ui"
)

const (
	cliPairingSessionID   = domain.UUIDv7("018f47de-89ab-7def-8123-8123456789ab")
	cliPairingWorkspaceID = domain.UUIDv4("650e8400-e29b-41d4-a716-446655440000")
	cliPairingInviteID    = domain.UUIDv7("018f47de-89ab-7def-8123-9123456789ab")
	cliPairingAttemptID   = domain.UUIDv7("018f47de-89ab-7def-8123-a123456789ab")
)

type cliPairingOperator struct {
	mu sync.Mutex

	createRequest pairingservice.CreateInviteRequest
	createResult  pairingservice.IssuedInvite
	createCalls   int

	listResult []store.PairingInviteRecord
	listCalls  int

	revokeID     domain.UUIDv7
	revokeResult store.PairingInviteRecord
	revokeCalls  int

	attemptID     domain.UUIDv7
	attemptResult pairingservice.AttemptDetails
	attemptCalls  int

	confirmID       domain.UUIDv7
	confirmDigest   [sha256.Size]byte
	confirmDecision bool
	confirmResult   pairingservice.AttemptDetails
	confirmCalls    int

	status    coordstatus.Snapshot
	submitter *cliOperatorSubmitter
}

func (operator *cliPairingOperator) CreateInvite(
	_ context.Context,
	request pairingservice.CreateInviteRequest,
) (pairingservice.IssuedInvite, error) {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.createCalls++
	operator.createRequest = cloneCLICreateInviteRequest(request)
	return operator.createResult, nil
}

func (operator *cliPairingOperator) ListInvites(
	context.Context,
) ([]store.PairingInviteRecord, error) {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.listCalls++
	return append([]store.PairingInviteRecord(nil), operator.listResult...), nil
}

func (operator *cliPairingOperator) RevokeInvite(
	_ context.Context,
	inviteID domain.UUIDv7,
) (store.PairingInviteRecord, bool, error) {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.revokeCalls++
	operator.revokeID = inviteID
	return operator.revokeResult, false, nil
}

func (operator *cliPairingOperator) PairingAttempt(
	_ context.Context,
	attemptID domain.UUIDv7,
) (pairingservice.AttemptDetails, error) {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.attemptCalls++
	operator.attemptID = attemptID
	return operator.attemptResult, nil
}

func (operator *cliPairingOperator) ConfirmPairing(
	_ context.Context,
	attemptID domain.UUIDv7,
	digest [sha256.Size]byte,
	confirmed bool,
) (pairingservice.AttemptDetails, error) {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	operator.confirmCalls++
	operator.confirmID = attemptID
	operator.confirmDigest = digest
	operator.confirmDecision = confirmed
	result := operator.confirmResult
	if result.Attempt.State == store.PairingAttemptAwaitingSAS {
		result.Attempt.LocalConfirmed = confirmed
		if confirmed {
			result.Attempt.State = store.PairingAttemptCompleted
		} else {
			result.Attempt.State = store.PairingAttemptDeclined
		}
	}
	return result, nil
}

type cliStatusSourceFunc func(context.Context) (coordstatus.Snapshot, error)

func (function cliStatusSourceFunc) Status(
	ctx context.Context,
) (coordstatus.Snapshot, error) {
	return function(ctx)
}

func (function cliStatusSourceFunc) Member(
	ctx context.Context,
	deviceID domain.DeviceID,
) (coordstatus.MemberSummary, bool, error) {
	snapshot, err := function(ctx)
	if err != nil {
		return coordstatus.MemberSummary{}, false, err
	}
	for _, member := range snapshot.Durable.Members {
		if member.ID == deviceID {
			return member, true, nil
		}
	}
	return coordstatus.MemberSummary{}, false, nil
}

type cliOperatorSubmitter struct {
	mu       sync.Mutex
	requests []operatorcommand.Request
}

func (submitter *cliOperatorSubmitter) SubmitOperatorCommand(
	_ context.Context,
	request operatorcommand.Request,
) (operatorcommand.Result, error) {
	submitter.mu.Lock()
	submitter.requests = append(submitter.requests, request)
	submitter.mu.Unlock()
	return operatorcommand.Result{
		EventID: domain.UUIDv7("018f47de-89ab-7def-8123-b123456789ab"),
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
	}, nil
}

func TestPeerInviteCLIEndToEnd(t *testing.T) {
	operator, inviterPrivate, inviterID, details := newCLIPairingFixture(t)
	endpoint, stop := startCLIPairingServer(t, operator)
	t.Cleanup(stop)
	common := cliPairingLocalFlags(endpoint)

	createCases := []struct {
		name    string
		flags   []string
		request pairingservice.CreateInviteRequest
	}{
		{
			name: "new defaults",
			request: pairingservice.CreateInviteRequest{
				Mode: pairing.ModeNew, Role: device.RoleEditor,
				InitialCredentialEpoch: 1,
			},
		},
		{
			name:  "rebootstrap",
			flags: []string{"--mode", "rebootstrap", "--subject", string(details.Core.JoinerDeviceID), "--role", "owner", "--epoch", "2"},
			request: pairingservice.CreateInviteRequest{
				Mode: pairing.ModeRebootstrap, SubjectDeviceID: deviceIDPointer(details.Core.JoinerDeviceID),
				Role: device.RoleOwner, InitialCredentialEpoch: 2,
			},
		},
		{
			name:  "readmission",
			flags: []string{"--mode", "readmission", "--subject", string(details.Core.JoinerDeviceID), "--expected-version", "7", "--role", "editor", "--epoch", "1"},
			request: pairingservice.CreateInviteRequest{
				Mode: pairing.ModeReadmission, SubjectDeviceID: deviceIDPointer(details.Core.JoinerDeviceID),
				ExpectedEntityVersion: uint64Pointer(7), Role: device.RoleEditor,
				InitialCredentialEpoch: 1,
			},
		},
	}
	for _, test := range createCases {
		t.Run("create "+test.name, func(t *testing.T) {
			issued := cliIssuedInvite(
				t,
				inviterPrivate,
				inviterID,
				test.request,
			)
			operator.mu.Lock()
			operator.createResult = issued
			operator.mu.Unlock()
			output, _ := runCLIPairingCommand(
				t,
				append(
					append([]string{"peer", "invite", "create"}, common...),
					test.flags...,
				),
				"",
			)
			var result ui.PairingInviteCreated
			decodeCLIResult(t, output, &result)
			operator.mu.Lock()
			captured := cloneCLICreateInviteRequest(operator.createRequest)
			operator.mu.Unlock()
			if result.Code != issued.Invite.Code() ||
				!sameCLICreateInviteRequest(captured, test.request) {
				t.Fatalf("result = %#v, request = %#v", result, captured)
			}
		})
	}

	operator.mu.Lock()
	operator.listResult = []store.PairingInviteRecord{
		operator.createResult.Record,
	}
	operator.mu.Unlock()
	output, _ := runCLIPairingCommand(
		t,
		append([]string{"peer", "invite", "list"}, common...),
		"",
	)
	var listed ui.PairingInviteList
	decodeCLIResult(t, output, &listed)
	if len(listed.Invites) != 1 {
		t.Fatalf("list = %#v", listed)
	}

	revoked := operator.createResult.Record
	revoked.State = store.PairingInviteRevoked
	revoked.TerminalAt = "2026-08-13T12:02:00Z"
	operator.mu.Lock()
	operator.revokeResult = revoked
	operator.mu.Unlock()
	output, _ = runCLIPairingCommand(
		t,
		append(
			append([]string{"peer", "invite", "revoke"}, common...),
			"--invite", string(cliPairingInviteID),
		),
		"",
	)
	var revokedResult ui.PairingInviteRevoked
	decodeCLIResult(t, output, &revokedResult)
	operator.mu.Lock()
	revokeID := operator.revokeID
	operator.mu.Unlock()
	if revokeID != cliPairingInviteID ||
		revokedResult.Invite.State != string(store.PairingInviteRevoked) {
		t.Fatalf("revoke = %#v, id = %s", revokedResult, revokeID)
	}

	output, _ = runCLIPairingCommand(
		t,
		append(
			append([]string{"peer", "invite", "show"}, common...),
			"--attempt", string(cliPairingAttemptID),
		),
		"",
	)
	var shown ui.PairingAttemptStatus
	decodeCLIResult(t, output, &shown)
	if shown.SAS != details.SAS {
		t.Fatalf("show = %#v", shown)
	}

	for _, test := range []struct {
		name      string
		flag      string
		input     string
		confirmed bool
	}{
		{"yes flag", "--yes", "", true},
		{"decline flag", "--decline", "", false},
		{"interactive accept", "", "yes\n", true},
		{"interactive decline", "", "no\n", false},
	} {
		t.Run("confirm "+test.name, func(t *testing.T) {
			args := append(
				append([]string{"peer", "invite", "confirm"}, common...),
				"--attempt", string(cliPairingAttemptID),
			)
			if test.flag != "" {
				args = append(args, test.flag)
			}
			output, prompt := runCLIPairingCommand(t, args, test.input)
			var result ui.PairingAttemptStatus
			decodeCLIResult(t, output, &result)
			operator.mu.Lock()
			capturedID := operator.confirmID
			capturedDigest := operator.confirmDigest
			capturedDecision := operator.confirmDecision
			operator.mu.Unlock()
			if capturedID != cliPairingAttemptID ||
				capturedDigest != [sha256.Size]byte(details.Attempt.RequestDigest) ||
				capturedDecision != test.confirmed {
				t.Fatalf(
					"confirmation = (%s, %x, %t)",
					capturedID,
					capturedDigest,
					capturedDecision,
				)
			}
			if test.flag == "" &&
				(!strings.Contains(prompt, details.SAS) ||
					!strings.Contains(prompt, string(details.Invite.Mode)) ||
					!strings.Contains(prompt, string(details.Core.JoinerDeviceID)) ||
					!strings.Contains(prompt, shown.EpochPublicKey) ||
					!strings.Contains(prompt, shown.EpochKeyDigest)) {
				t.Fatalf("prompt omits reviewed fields: %q", prompt)
			}
		})
	}

	output, prompt := runCLIPairingCommand(
		t,
		append(
			append([]string{"peer", "invite", "confirm"}, common...),
			"--attempt", string(cliPairingAttemptID),
			"--yes",
		),
		"joined\nyes\n",
	)
	var placed ui.PairingAttemptStatus
	decodeCLIResult(t, output, &placed)
	operator.submitter.mu.Lock()
	placementRequests := append(
		[]operatorcommand.Request(nil),
		operator.submitter.requests...,
	)
	operator.submitter.mu.Unlock()
	if len(placementRequests) != 1 {
		t.Fatalf("placement command count = %d", len(placementRequests))
	}
	placement := placementRequests[0].Command
	if placement.Operation != operatorcommand.OperationSetVoters ||
		placement.Command.Kind != event.KindMembershipVoterSetChanged ||
		placement.Command.ExpectedEntityVersion == nil ||
		*placement.Command.ExpectedEntityVersion != 1 ||
		!bytes.Contains(
			placement.Command.Payload,
			[]byte(details.Core.JoinerDeviceID),
		) ||
		!strings.Contains(prompt, "Choose the sole voter") ||
		!strings.Contains(prompt, "Set voter target at version 1") {
		t.Fatalf(
			"placement request/prompt = (%+v, %q)",
			placement,
			prompt,
		)
	}

	operator.mu.Lock()
	before := operator.confirmCalls
	operator.mu.Unlock()
	args := append(
		append([]string{"peer", "invite", "confirm"}, common...),
		"--attempt", string(cliPairingAttemptID),
	)
	var outputBuffer, errorBuffer bytes.Buffer
	err := runCLI(
		context.Background(),
		args,
		strings.NewReader("maybe\n"),
		&outputBuffer,
		&errorBuffer,
	)
	operator.mu.Lock()
	after := operator.confirmCalls
	operator.mu.Unlock()
	if !errors.Is(err, errInvalidCLI) || after != before {
		t.Fatalf("ambiguous decision = %v, confirm calls %d -> %d", err, before, after)
	}
}

func TestPeerInviteCLIParsingRejectsInvalidForms(t *testing.T) {
	endpoint := cliPairingTestEndpoint(t)
	common := cliPairingLocalFlags(endpoint)
	tests := []struct {
		name string
		args []string
	}{
		{"peer missing command", []string{"peer"}},
		{"peer unknown command", []string{"peer", "unknown"}},
		{"invite missing command", []string{"peer", "invite"}},
		{"invite unknown command", []string{"peer", "invite", "unknown"}},
		{"create positional", append(append([]string{"peer", "invite", "create"}, common...), "extra")},
		{"create invalid subject", append(append([]string{"peer", "invite", "create"}, common...), "--subject", "bad")},
		{"create invalid epoch syntax", append(append([]string{"peer", "invite", "create"}, common...), "--epoch", "many")},
		{"list positional", append(append([]string{"peer", "invite", "list"}, common...), "extra")},
		{"revoke missing invite", append([]string{"peer", "invite", "revoke"}, common...)},
		{"revoke invalid invite", append(append([]string{"peer", "invite", "revoke"}, common...), "--invite", "bad")},
		{"show missing attempt", append([]string{"peer", "invite", "show"}, common...)},
		{"show positional", append(append(append([]string{"peer", "invite", "show"}, common...), "--attempt", string(cliPairingAttemptID)), "extra")},
		{"confirm missing attempt", append([]string{"peer", "invite", "confirm"}, common...)},
		{"confirm contradictory", append(append(append([]string{"peer", "invite", "confirm"}, common...), "--attempt", string(cliPairingAttemptID)), "--yes", "--decline")},
		{"confirm positional", append(append(append([]string{"peer", "invite", "confirm"}, common...), "--attempt", string(cliPairingAttemptID)), "extra")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			err := runCLI(
				context.Background(),
				test.args,
				strings.NewReader(""),
				&output,
				&errorOutput,
			)
			if !errors.Is(err, errInvalidCLI) {
				t.Fatalf("runCLI(%q) error = %v, want %v", test.args, err, errInvalidCLI)
			}
			if output.Len() != 0 {
				t.Fatalf("runCLI(%q) output = %q", test.args, output.String())
			}
		})
	}
}

func TestPairingOptionParsersPreserveLocalAndDecisionFields(t *testing.T) {
	endpoint := cliPairingTestEndpoint(t)
	common := cliPairingLocalFlags(endpoint)
	options, attemptID, err := parsePairingAttemptOptions(
		"peer invite show",
		append(common, "--attempt", string(cliPairingAttemptID)),
		&bytes.Buffer{},
	)
	if err != nil ||
		attemptID != cliPairingAttemptID ||
		options.endpoint.String() != endpoint.String() ||
		options.sessionID != cliPairingSessionID ||
		options.workspaceID != cliPairingWorkspaceID {
		t.Fatalf("parsePairingAttemptOptions() = (%#v, %s, %v)", options, attemptID, err)
	}
	for _, test := range []struct {
		flags   []string
		accept  bool
		decline bool
	}{
		{flags: nil},
		{flags: []string{"--yes"}, accept: true},
		{flags: []string{"--decline"}, decline: true},
	} {
		options, attemptID, accept, decline, err :=
			parsePairingConfirmOptions(
				append(
					append(common, "--attempt", string(cliPairingAttemptID)),
					test.flags...,
				),
				&bytes.Buffer{},
			)
		if err != nil ||
			attemptID != cliPairingAttemptID ||
			accept != test.accept ||
			decline != test.decline ||
			options.sessionID != cliPairingSessionID {
			t.Fatalf(
				"parsePairingConfirmOptions(%q) = (%#v, %s, %t, %t, %v)",
				test.flags,
				options,
				attemptID,
				accept,
				decline,
				err,
			)
		}
	}
}

func TestPromptPairingDecisionRejectsAmbiguousAndReadFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		input io.Reader
	}{
		{name: "empty", input: strings.NewReader("")},
		{name: "ambiguous", input: strings.NewReader("YES\n")},
		{name: "read failure", input: pairingDecisionReader{
			value: "yes",
			err:   errors.New("terminal failed"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := promptPairingDecision(
				t.Context(),
				test.input,
				io.Discard,
				"confirm: ",
			); err == nil {
				t.Fatal("promptPairingDecision() succeeded")
			}
		})
	}
}

type pairingDecisionReader struct {
	value string
	err   error
}

func (reader pairingDecisionReader) Read(target []byte) (int, error) {
	return copy(target, reader.value), reader.err
}

func newCLIPairingFixture(
	t *testing.T,
) (
	*cliPairingOperator,
	ed25519.PrivateKey,
	domain.DeviceID,
	pairingservice.AttemptDetails,
) {
	t.Helper()
	inviterPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	inviterID, err := device.DeriveID(inviterPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	joinerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	joinerPublic := joinerPrivate.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublic)
	if err != nil {
		t.Fatal(err)
	}
	epochPublic := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x53}, ed25519.SeedSize),
	).Public().(ed25519.PublicKey)
	binding, err := credential.SignBinding(
		cliPairingSessionID,
		joinerID,
		1,
		epochPublic,
		joinerPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	var digest store.Digest
	for index := range digest {
		digest[index] = byte(0xb0 + index)
	}
	core := pairing.RequestCore{
		AttemptID: cliPairingAttemptID, JoinerDeviceID: joinerID,
		DaemonVersion: "1.2.3", MaxApplyLevel: 1,
		InitialEpochBinding: binding,
	}
	copy(core.JoinerIdentityPublicKey[:], joinerPublic)
	invite := store.PairingInviteRecord{
		InviteID: cliPairingInviteID, SessionID: cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID, IssuerDeviceID: inviterID,
		Mode: pairing.ModeNew, Role: device.RoleEditor,
		InitialCredentialEpoch: 1, State: store.PairingInviteConsumed,
		ConsumedAttemptID: cliPairingAttemptID,
		CreatedAt:         "2026-08-13T12:00:00Z", ExpiresAt: "2026-08-13T12:15:00Z",
		TerminalAt: "2026-08-13T12:01:00Z",
	}
	details := pairingservice.AttemptDetails{
		Invite: invite,
		Attempt: store.PairingAttemptRecord{
			AttemptID: cliPairingAttemptID, InviteID: cliPairingInviteID,
			RequestDigest: digest, JoinerDeviceID: joinerID,
			State: store.PairingAttemptAwaitingSAS, RemoteConfirmed: true,
			CreatedAt: "2026-08-13T12:01:00Z",
		},
		Core: core,
		SAS:  "1001 1002 1003 1004 1005",
	}
	operator := &cliPairingOperator{
		attemptResult: details,
		confirmResult: details,
		submitter:     &cliOperatorSubmitter{},
	}
	operator.status = cliPairingStatusSnapshot(
		t,
		inviterPrivate,
		details,
	)
	return operator, inviterPrivate, inviterID, details
}

func cliPairingStatusSnapshot(
	t *testing.T,
	inviterPrivate ed25519.PrivateKey,
	details pairingservice.AttemptDetails,
) coordstatus.Snapshot {
	t.Helper()
	inviterID := details.Invite.IssuerDeviceID
	joinerID := details.Core.JoinerDeviceID
	target, err := voterset.New(
		cliPairingSessionID,
		[]domain.DeviceID{inviterID},
		1,
	)
	if err != nil {
		t.Fatalf("voterset.New(): %v", err)
	}
	local := device.Device{
		ID: inviterID, Role: device.RoleOwner,
		IdentityPublicKey: bytes.Clone(
			inviterPrivate.Public().(ed25519.PublicKey),
		),
		DaemonVersion: "1.2.3", MaxApplyLevel: 1,
		Status: device.StatusActive, EntityVersion: 1,
	}
	members := []coordstatus.MemberSummary{
		{
			ID: inviterID, Role: device.RoleOwner,
			Status: device.StatusActive, EntityVersion: 1,
		},
		{
			ID: joinerID, Role: details.Invite.Role,
			Status: device.StatusActive, EntityVersion: 1,
		},
	}
	sort.Slice(members, func(left, right int) bool {
		return members[left].ID < members[right].ID
	})
	term, applied := uint64(1), uint64(3)
	snapshot := coordstatus.Snapshot{
		Durable: coordstatus.DurableSnapshot{
			SessionID: cliPairingSessionID, WorkspaceID: cliPairingWorkspaceID,
			Heads: coordstatus.AppliedHeads{
				CurrentTerm: &term, LastRaftAppliedLogIndex: &applied,
				ChainIndex: 1, ResultIndex: 1, DigestVersion: 1,
				ProjectionSchemaVersion: 1,
			},
			Member: local, Members: members, MemberTotal: 2,
			VoterSet: target, CredentialAuthority: target,
		},
		Runtime: coordstatus.RuntimeSnapshot{
			State: coordstatus.ConsensusReady, Role: coordstatus.RoleLeader,
			LocalDeviceID: inviterID, LeaderDeviceID: inviterID,
			LiveConfigurationSource: coordstatus.LiveConfigurationLocal,
			LiveVoterDeviceIDs:      []domain.DeviceID{inviterID},
			LiveNonvoterDeviceIDs:   []domain.DeviceID{},
			QuorumRequired:          1, StrongWrites: coordstatus.StrongWritesAvailable,
			ReplicaCurrency:         coordstatus.ReplicaCurrencyRaft,
			ObservedAuthorityIDs:    []domain.DeviceID{},
			ConfigurationReconciled: true,
			ReconciliationState:     coordstatus.ReconciliationStable,
			ReconciliationStep:      coordstatus.ReconciliationStepComplete,
			ReconciliationBlocker:   coordstatus.ReconciliationBlockerNone,
		},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("pairing status snapshot: %v", err)
	}
	return snapshot
}

func cliIssuedInvite(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	inviterID domain.DeviceID,
	request pairingservice.CreateInviteRequest,
) pairingservice.IssuedInvite {
	t.Helper()
	value := pairing.Invite{
		InviteID: cliPairingInviteID, SessionID: cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID, CreatedAt: "2026-08-13T12:00:00Z",
		ExpiresAt: "2026-08-13T12:15:00Z", InviterDeviceID: inviterID,
		Mode: request.Mode, SubjectDeviceID: cloneCLIDeviceID(request.SubjectDeviceID),
		ExpectedEntityVersion: cloneCLIUint64(request.ExpectedEntityVersion),
		Role:                  request.Role, InitialCredentialEpoch: request.InitialCredentialEpoch,
		Endpoints: []pairing.Endpoint{{
			IP: netip.MustParseAddr("10.0.0.5"), Port: 47831,
		}},
	}
	copy(value.InviterIdentityPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	for index := range value.Secret {
		value.Secret[index] = byte(index + 1)
	}
	for index := range value.SignedGenesisDigest {
		value.SignedGenesisDigest[index] = byte(0x90 + index)
	}
	signed, err := pairing.SignInvite(value, privateKey)
	clear(value.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	record := store.PairingInviteRecord{
		InviteID: cliPairingInviteID, SessionID: cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID, IssuerDeviceID: inviterID,
		InviteDigest: store.Digest(signed.Digest()), Mode: request.Mode,
		SubjectDeviceID:       cloneCLIDeviceID(request.SubjectDeviceID),
		ExpectedEntityVersion: cloneCLIUint64(request.ExpectedEntityVersion),
		Role:                  request.Role, InitialCredentialEpoch: request.InitialCredentialEpoch,
		State: store.PairingInviteOutstanding, CreatedAt: "2026-08-13T12:00:00Z",
		ExpiresAt: "2026-08-13T12:15:00Z",
	}
	return pairingservice.IssuedInvite{Invite: signed, Record: record}
}

func startCLIPairingServer(
	t *testing.T,
	operator *cliPairingOperator,
) (ipc.Endpoint, func()) {
	t.Helper()
	endpoint := cliPairingTestEndpoint(t)
	service, err := ui.NewOperatorService(ui.OperatorServiceOptions{
		Source: cliStatusSourceFunc(func(context.Context) (coordstatus.Snapshot, error) {
			operator.mu.Lock()
			defer operator.mu.Unlock()
			return operator.status, nil
		}),
		Submitter:   operator.submitter,
		Pairing:     operator,
		SessionID:   cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := ipc.NewServer(ipc.Config{
		Endpoint: endpoint, SessionID: cliPairingSessionID,
		WorkspaceID: cliPairingWorkspaceID, Binder: service,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	stop := func() {
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			3*time.Second,
		)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown(): %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-shutdownContext.Done():
			t.Errorf("server did not stop: %v", shutdownContext.Err())
		}
	}
	return endpoint, stop
}

func cliPairingTestEndpoint(t *testing.T) ipc.Endpoint {
	t.Helper()
	var address string
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\codecomm-cli-pairing-` +
			strings.ReplaceAll(uuid.NewString(), "-", "")
	} else {
		directory, err := os.MkdirTemp("", "cc-cli-pair-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Errorf("remove endpoint directory: %v", err)
			}
		})
		address = filepath.Join(directory, "codecomm.sock")
	}
	endpoint, err := ipc.ParseEndpoint(address)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q): %v", address, err)
	}
	return endpoint
}

func cliPairingLocalFlags(endpoint ipc.Endpoint) []string {
	return []string{
		"--endpoint", endpoint.String(),
		"--session", string(cliPairingSessionID),
		"--workspace", string(cliPairingWorkspaceID),
	}
}

func runCLIPairingCommand(
	t *testing.T,
	args []string,
	input string,
) (string, string) {
	t.Helper()
	var output, errorOutput bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runCLI(
		ctx,
		args,
		strings.NewReader(input),
		&output,
		&errorOutput,
	); err != nil {
		t.Fatalf("runCLI(%q): %v; stderr = %q", args, err, errorOutput.String())
	}
	return output.String(), errorOutput.String()
}

func decodeCLIResult(t *testing.T, output string, target any) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %q: %v", output, err)
	}
}

func cloneCLICreateInviteRequest(
	request pairingservice.CreateInviteRequest,
) pairingservice.CreateInviteRequest {
	request.SubjectDeviceID = cloneCLIDeviceID(request.SubjectDeviceID)
	request.ExpectedEntityVersion = cloneCLIUint64(request.ExpectedEntityVersion)
	return request
}

func sameCLICreateInviteRequest(
	left pairingservice.CreateInviteRequest,
	right pairingservice.CreateInviteRequest,
) bool {
	return left.Mode == right.Mode &&
		equalCLIDeviceID(left.SubjectDeviceID, right.SubjectDeviceID) &&
		equalCLIUint64(left.ExpectedEntityVersion, right.ExpectedEntityVersion) &&
		left.Role == right.Role &&
		left.InitialCredentialEpoch == right.InitialCredentialEpoch
}

func cloneCLIDeviceID(value *domain.DeviceID) *domain.DeviceID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneCLIUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalCLIDeviceID(left, right *domain.DeviceID) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func equalCLIUint64(left, right *uint64) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func deviceIDPointer(value domain.DeviceID) *domain.DeviceID {
	return &value
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func (operator *cliPairingOperator) String() string {
	operator.mu.Lock()
	defer operator.mu.Unlock()
	return fmt.Sprintf(
		"creates=%d lists=%d revokes=%d attempts=%d confirms=%d",
		operator.createCalls,
		operator.listCalls,
		operator.revokeCalls,
		operator.attemptCalls,
		operator.confirmCalls,
	)
}
