package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"zombiezen.com/go/sqlite"
)

type pairingLifecycleFixture struct {
	state      LocalState
	ownerKey   ed25519.PrivateKey
	ownerID    domain.DeviceID
	subjectKey ed25519.PrivateKey
	subjectID  domain.DeviceID
}

func TestPairingConsumptionRechecksCommittedEligibility(t *testing.T) {
	tests := []struct {
		name          string
		mode          pairing.Mode
		subjectStatus device.Status
		subjectVoter  bool
		epoch         uint64
		expected      uint64
		mutate        func(*testing.T, pairingLifecycleFixture)
		wantErr       error
	}{
		{name: "new absent", mode: pairing.ModeNew, epoch: 1},
		{
			name: "new identity appears after issue", mode: pairing.ModeNew, epoch: 1,
			mutate: func(t *testing.T, fixture pairingLifecycleFixture) {
				insertPairingSubject(t, fixture, device.StatusActive, 1)
			},
			wantErr: ErrPairingEligibility,
		},
		{
			name: "issuer loses owner role", mode: pairing.ModeNew, epoch: 1,
			mutate: func(t *testing.T, fixture pairingLifecycleFixture) {
				execPairingSQL(
					t,
					fixture.state,
					"UPDATE devices SET role = 'editor' WHERE device_id = ?1;",
					string(fixture.ownerID),
				)
			},
			wantErr: ErrPairingEligibility,
		},
		{
			name: "rebootstrap active nonvoter", mode: pairing.ModeRebootstrap,
			subjectStatus: device.StatusActive, epoch: 1,
		},
		{
			name: "rebootstrap target voter", mode: pairing.ModeRebootstrap,
			subjectStatus: device.StatusActive, subjectVoter: true, epoch: 1,
			wantErr: ErrPairingEligibility,
		},
		{
			name: "rebootstrap wrong next epoch", mode: pairing.ModeRebootstrap,
			subjectStatus: device.StatusActive, epoch: 2,
			wantErr: ErrPairingEligibility,
		},
		{
			name: "rebootstrap wrong status", mode: pairing.ModeRebootstrap,
			subjectStatus: device.StatusRequiresReadmission, epoch: 1,
			wantErr: ErrPairingEligibility,
		},
		{
			name: "readmission exact", mode: pairing.ModeReadmission,
			subjectStatus: device.StatusRequiresReadmission, epoch: 1, expected: 4,
		},
		{
			name: "readmission stale version", mode: pairing.ModeReadmission,
			subjectStatus: device.StatusRequiresReadmission, epoch: 1, expected: 3,
			wantErr: ErrPairingEligibility,
		},
		{
			name: "readmission active", mode: pairing.ModeReadmission,
			subjectStatus: device.StatusActive, epoch: 1, expected: 4,
			wantErr: ErrPairingEligibility,
		},
		{
			name: "readmission target voter", mode: pairing.ModeReadmission,
			subjectStatus: device.StatusRequiresReadmission, subjectVoter: true,
			epoch: 1, expected: 4, wantErr: ErrPairingEligibility,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			includeSubject := test.mode != pairing.ModeNew
			fixture := newPairingLifecycleFixture(
				t,
				includeSubject,
				test.subjectStatus,
				test.subjectVoter,
			)
			invite := fixture.invite(
				t,
				pairingTestUUID(200+index),
				test.mode,
				test.epoch,
				test.expected,
			)
			reserveAndActivatePairingInvite(t, fixture.state, invite)
			if test.mutate != nil {
				test.mutate(t, fixture)
			}
			verified := fixture.verifiedRequest(
				t,
				invite,
				pairingTestUUID(300+index),
			)
			_, _, err := fixture.state.ConsumePairingInvite(
				context.Background(),
				verified,
				"2026-08-13T12:01:00Z",
			)
			if test.wantErr == nil && err != nil {
				t.Fatalf("ConsumePairingInvite() error = %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("ConsumePairingInvite() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestRebootstrapAcceptsExactSuccessorCredentialEpoch(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, true, device.StatusActive, false)
	insertPairingCredentialAuthorization(t, fixture, 1)
	invite := fixture.invite(
		t,
		pairingTestUUID(400),
		pairing.ModeRebootstrap,
		2,
		0,
	)
	reserveAndActivatePairingInvite(t, fixture.state, invite)
	verified := fixture.verifiedRequest(t, invite, pairingTestUUID(401))
	if _, _, err := fixture.state.ConsumePairingInvite(
		context.Background(),
		verified,
		"2026-08-13T12:01:00Z",
	); err != nil {
		t.Fatalf("ConsumePairingInvite() error = %v", err)
	}
}

func TestPairingInviteCapEagerlyExpiresStaleRows(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, false, "", false)
	var first domain.UUIDv7
	for index := 0; index < MaxOutstandingPairingInvites; index++ {
		invite := fixture.invite(
			t,
			pairingTestUUID(500+index),
			pairing.ModeNew,
			1,
			0,
		)
		if index == 0 {
			value := invite.Invite()
			first = value.InviteID
			clear(value.Secret[:])
		}
		reserveAndActivatePairingInvite(t, fixture.state, invite)
	}
	futureValue := fixture.invite(
		t,
		pairingTestUUID(510),
		pairing.ModeNew,
		1,
		0,
	).Invite()
	defer clear(futureValue.Secret[:])
	futureValue.CreatedAt = "2026-08-13T12:16:00Z"
	futureValue.ExpiresAt = "2026-08-13T12:31:00Z"
	future, err := pairing.SignInvite(futureValue, fixture.ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.state.ReservePairingInvite(
		context.Background(),
		future,
	); err != nil {
		t.Fatalf("ReservePairingInvite(after expiry) error = %v", err)
	}
	assertPairingInviteState(t, fixture.state, first, PairingInviteExpired)
	err = fixture.state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM pairing_invites WHERE state IN ('preparing', 'outstanding');",
			1,
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecoverPairingStateAbandonsExpiresAndScrubs(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, false, "", false)
	preparing := fixture.invite(t, pairingTestUUID(410), pairing.ModeNew, 1, 0)
	if _, _, err := fixture.state.ReservePairingInvite(
		context.Background(),
		preparing,
	); err != nil {
		t.Fatal(err)
	}

	outstanding := fixture.invite(t, pairingTestUUID(411), pairing.ModeNew, 1, 0)
	reserveAndActivatePairingInvite(t, fixture.state, outstanding)
	failed := fixture.verifiedRequest(t, outstanding, pairingTestUUID(412))
	if _, _, err := fixture.state.RecordPairingProofFailure(
		context.Background(),
		PairingProofFailureInput{
			InviteID: failed.InviteID(), InviteDigest: Digest(failed.InviteDigest()),
			RequestDigest: Digest(failed.RequestDigest()), RequestCore: failed.Core(),
			TranscriptHash: Digest(failed.TranscriptHash()),
			ObservedAt:     "2026-08-13T12:01:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}

	consumed := fixture.invite(t, pairingTestUUID(413), pairing.ModeNew, 1, 0)
	reserveAndActivatePairingInvite(t, fixture.state, consumed)
	accepted := fixture.verifiedRequest(t, consumed, pairingTestUUID(414))
	attempt, _, err := fixture.state.ConsumePairingInvite(
		context.Background(),
		accepted,
		"2026-08-13T12:02:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := fixture.state.RecoverPairingState(
		context.Background(),
		"2026-08-13T12:16:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.AbandonedPreparing != 1 || result.ExpiredInvites != 1 ||
		result.ExpiredAttempts != 1 {
		t.Fatalf("RecoverPairingState() = %+v", result)
	}
	assertPairingInviteState(t, fixture.state, preparing.Invite().InviteID, PairingInviteAbandoned)
	assertPairingInviteState(t, fixture.state, outstanding.Invite().InviteID, PairingInviteExpired)
	assertPairingInviteState(t, fixture.state, consumed.Invite().InviteID, PairingInviteConsumed)
	stored, found, err := fixture.state.PairingAttempt(context.Background(), attempt.AttemptID)
	if err != nil || !found || stored.State != PairingAttemptExpired {
		t.Fatalf("expired SAS attempt = (%+v, %t, %v)", stored, found, err)
	}
	err = fixture.state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM pairing_attempts WHERE state = 'proof_rejected';",
			0,
		)
		assertIntQuery(t, conn, "SELECT count(*) FROM pairing_secret_deletions;", 3)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.state.RecoverPairingState(
		context.Background(),
		"2026-08-13T12:16:01Z",
	)
	if err != nil || second != (PairingMaintenanceResult{}) {
		t.Fatalf("idempotent recovery = (%+v, %v)", second, err)
	}
}

func TestPairingInviteConcurrentValidProofHasOneWinner(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, false, "", false)
	invite := fixture.invite(t, pairingTestUUID(420), pairing.ModeNew, 1, 0)
	reserveAndActivatePairingInvite(t, fixture.state, invite)

	const contenders = 16
	var (
		start     sync.WaitGroup
		finished  sync.WaitGroup
		mu        sync.Mutex
		successes int
		failures  []error
	)
	start.Add(1)
	finished.Add(contenders)
	for index := 0; index < contenders; index++ {
		verified := fixture.verifiedRequest(
			t,
			invite,
			pairingTestUUID(421+index),
		)
		go func(request pairing.VerifiedRequest) {
			defer finished.Done()
			start.Wait()
			_, _, err := fixture.state.ConsumePairingInvite(
				context.Background(),
				request,
				"2026-08-13T12:01:00Z",
			)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else {
				failures = append(failures, err)
			}
		}(verified)
	}
	start.Done()
	finished.Wait()
	if successes != 1 || len(failures) != contenders-1 {
		t.Fatalf("concurrent consume successes = %d, failures = %d", successes, len(failures))
	}
	for _, err := range failures {
		if !errors.Is(err, ErrPairingInviteUnavailable) {
			t.Fatalf("losing consume error = %v", err)
		}
	}
}

func TestLocalPairingApprovalAtomicallyReservesAdmission(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, false, "", false)
	invite := fixture.invite(
		t,
		pairingTestUUID(430),
		pairing.ModeNew,
		1,
		0,
	)
	reserveAndActivatePairingInvite(t, fixture.state, invite)
	verified := fixture.verifiedRequest(t, invite, pairingTestUUID(431))
	attempt, _, err := fixture.state.ConsumePairingInvite(
		context.Background(),
		verified,
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.state.RecordPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationRemote,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}

	decidedAt := domain.Timestamp("2026-08-13T12:02:01Z")
	authorization := pairingAdmissionAuthorization(
		t,
		fixture.ownerKey,
		fixture.ownerID,
		attempt.AttemptID,
		verified.Core().Value().JoinerDeviceID,
		decidedAt,
	)
	updated, duplicate, err := fixture.state.RecordLocalPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationLocal,
			Confirmed: true,
			DecidedAt: decidedAt,
		},
		authorization,
	)
	if err != nil || duplicate ||
		updated.State != PairingAttemptFinalizing {
		t.Fatalf(
			"RecordLocalPairingConfirmation() = (%+v, %t, %v)",
			updated,
			duplicate,
			err,
		)
	}
	command, found, err := fixture.state.LookupRequest(
		context.Background(),
		attempt.AttemptID,
		attempt.AttemptID,
	)
	if err != nil || !found ||
		command.State != LocalRequestSigned ||
		command.RecoveryGeneration != 0 ||
		command.RequestKind != event.KindMembershipDeviceAdmitted {
		t.Fatalf("reserved admission = (%+v, %t, %v)", command, found, err)
	}
	if err := fixture.state.store.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			var (
				status           string
				clientID         string
				requestID        string
				originBootID     string
				admissionEventID string
				requestDigest    Digest
				proposalDigest   Digest
				rowErr           error
			)
			if err := queryOneArgs(
				conn,
				`SELECT authority_status, operator_client_instance_id,
				        operator_request_id, operator_request_digest,
				        operator_origin_boot_id, admission_event_id,
				        admission_proposal_digest
				   FROM pairing_attempt_finalizations
				  WHERE attempt_id = ?1;`,
				[]any{string(attempt.AttemptID)},
				func(stmt *sqlite.Stmt) {
					status = stmt.ColumnText(0)
					clientID = stmt.ColumnText(1)
					requestID = stmt.ColumnText(2)
					rowErr = copyDigestColumn(&requestDigest, stmt, 3)
					originBootID = stmt.ColumnText(4)
					admissionEventID = stmt.ColumnText(5)
					if rowErr == nil {
						rowErr = copyDigestColumn(&proposalDigest, stmt, 6)
					}
				},
			); err != nil {
				return err
			}
			if rowErr != nil ||
				status != "bound" ||
				clientID != string(attempt.AttemptID) ||
				requestID != string(attempt.AttemptID) ||
				requestDigest != command.RequestDigest ||
				originBootID != string(command.OriginScopeID) ||
				admissionEventID != string(command.EventID) ||
				proposalDigest != command.ProposalDigest {
				t.Fatalf(
					"finalization authority = (%q, %q, %q, %x, %q, %q, %x, %v)",
					status,
					clientID,
					requestID,
					requestDigest,
					originBootID,
					admissionEventID,
					proposalDigest,
					rowErr,
				)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	changedRequest, err := json.Marshal(map[string]any{
		"attempt_id": attempt.AttemptID,
		"changed":    true,
		"confirmed":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	changedCanonical, err := codec.CanonicalizeSignedObject(changedRequest)
	if err != nil {
		t.Fatal(err)
	}
	changedAuthorization := *authorization
	changedAuthorization.Request = authorization.Request
	changedAuthorization.Request.CanonicalRequest = changedCanonical
	changedAdmission := *authorization.Admission
	changedAdmission.Input = authorization.Admission.Input
	changedAdmission.Input.CanonicalRequest = bytes.Clone(changedCanonical)
	changedAuthorization.Admission = &changedAdmission
	if _, _, err := fixture.state.RecordLocalPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationLocal,
			Confirmed: true,
			DecidedAt: decidedAt,
		},
		&changedAuthorization,
	); !errors.Is(err, ErrPairingStateIntegrity) {
		t.Fatalf(
			"changed authorization retry error = %v, want %v",
			err,
			ErrPairingStateIntegrity,
		)
	}
	signed, err := event.ParseAndVerify(
		command.SignedProposal,
		event.VerificationContext{
			SessionID:         domain.UUIDv7(testSessionID),
			WorkspaceID:       testWorkspaceID,
			IdentityPublicKey: fixture.ownerKey.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		t.Fatalf("ParseAndVerify(reserved admission): %v", err)
	}
	proposal := signed.Proposal()
	if proposal.Origin.ActorType() != event.ActorHuman ||
		proposal.CreatedAt != decidedAt ||
		proposal.EntityID != event.StringEntityID(
			string(verified.Core().Value().JoinerDeviceID),
		) {
		t.Fatalf("reserved admission proposal = %+v", proposal)
	}
}

func TestLocalPairingApprovalRollsBackWhenAdmissionReservationFails(t *testing.T) {
	fixture := newPairingLifecycleFixture(t, false, "", false)
	invite := fixture.invite(
		t,
		pairingTestUUID(432),
		pairing.ModeNew,
		1,
		0,
	)
	reserveAndActivatePairingInvite(t, fixture.state, invite)
	verified := fixture.verifiedRequest(t, invite, pairingTestUUID(433))
	attempt, _, err := fixture.state.ConsumePairingInvite(
		context.Background(),
		verified,
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.state.RecordPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationRemote,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}

	authorization := pairingAdmissionAuthorization(
		t,
		fixture.ownerKey,
		fixture.ownerID,
		attempt.AttemptID,
		verified.Core().Value().JoinerDeviceID,
		"2026-08-13T12:02:01Z",
	)
	authorization.Admission.Build = func(
		domain.UUIDv7,
		uint64,
	) (event.SignedEvent, error) {
		return event.SignedEvent{}, errors.New("injected admission builder failure")
	}
	if _, _, err := fixture.state.RecordLocalPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationLocal,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:01Z",
		},
		authorization,
	); err == nil {
		t.Fatal("RecordLocalPairingConfirmation() succeeded")
	}
	stored, found, err := fixture.state.PairingAttempt(
		context.Background(),
		attempt.AttemptID,
	)
	if err != nil || !found ||
		stored.State != PairingAttemptAwaitingSAS ||
		stored.LocalConfirmed {
		t.Fatalf("attempt after rollback = (%+v, %t, %v)", stored, found, err)
	}
	if command, found, err := fixture.state.LookupRequest(
		context.Background(),
		attempt.AttemptID,
		attempt.AttemptID,
	); err != nil || found {
		t.Fatalf("command after rollback = (%+v, %t, %v)", command, found, err)
	}
}

func TestLocalRebootstrapApprovalReservesNoAdmission(t *testing.T) {
	fixture := newPairingLifecycleFixture(
		t,
		true,
		device.StatusActive,
		false,
	)
	invite := fixture.invite(
		t,
		pairingTestUUID(434),
		pairing.ModeRebootstrap,
		1,
		0,
	)
	reserveAndActivatePairingInvite(t, fixture.state, invite)
	verified := fixture.verifiedRequest(t, invite, pairingTestUUID(435))
	attempt, _, err := fixture.state.ConsumePairingInvite(
		context.Background(),
		verified,
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.state.RecordPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationRemote,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}
	authorization := pairingAdmissionAuthorization(
		t,
		fixture.ownerKey,
		fixture.ownerID,
		attempt.AttemptID,
		verified.Core().Value().JoinerDeviceID,
		"2026-08-13T12:02:01Z",
	)
	authorization.Admission = nil
	updated, duplicate, err := fixture.state.RecordLocalPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationLocal,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:01Z",
		},
		authorization,
	)
	if err != nil || duplicate ||
		updated.State != PairingAttemptFinalizing {
		t.Fatalf(
			"RecordLocalPairingConfirmation() = (%+v, %t, %v)",
			updated,
			duplicate,
			err,
		)
	}
	if command, found, err := fixture.state.LookupRequest(
		context.Background(),
		attempt.AttemptID,
		attempt.AttemptID,
	); err != nil || found {
		t.Fatalf(
			"rebootstrap admission command = (%+v, %t, %v)",
			command,
			found,
			err,
		)
	}
	if err := fixture.state.store.withConn(
		context.Background(),
		func(conn *sqlite.Conn) error {
			assertTextQuery(
				t,
				conn,
				`SELECT authority_status
				   FROM pairing_attempt_finalizations
				  WHERE attempt_id = '`+string(attempt.AttemptID)+`';`,
				"bound",
			)
			assertIntQuery(
				t,
				conn,
				`SELECT admission_event_id IS NULL
				         AND admission_proposal_digest IS NULL
				   FROM pairing_attempt_finalizations
				  WHERE attempt_id = '`+string(attempt.AttemptID)+`';`,
				1,
			)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestPairingAuthorityMigrationRevokesUnboundFinalization(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	path := state.store.path
	invite := reserveAndActivatePairingInvite(
		t,
		state,
		pairingTestInvite(t, pairingTestUUID(600), inviterKey, inviterID),
	)
	verified := pairingVerifiedRequest(t, invite, pairingTestUUID(601), 90)
	attempt, _, err := state.ConsumePairingInvite(
		context.Background(),
		verified,
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.RecordPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: attempt.AttemptID,
			Party:     PairingConfirmationRemote,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		if err := execute(
			conn,
			`UPDATE pairing_attempts
			    SET state = 'confirmed',
			        local_confirmed = 1,
			        local_confirmed_at = '2026-08-13T12:02:01Z',
			        terminal_at = '2026-08-13T12:02:01Z'
			  WHERE attempt_id = ?1;`,
			string(attempt.AttemptID),
		); err != nil {
			return err
		}
		if err := execute(conn, "DROP TABLE pairing_attempt_finalizations;"); err != nil {
			return err
		}
		if err := execute(conn, "DROP TABLE raft_committed_configuration;"); err != nil {
			return err
		}
		return execute(conn, "DELETE FROM schema_migrations WHERE version >= 3;")
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(v2 pairing state) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	migrated, found, err := reopened.LocalState().PairingAttempt(
		context.Background(),
		attempt.AttemptID,
	)
	if err != nil || !found || migrated.State != PairingAttemptRevoked {
		t.Fatalf("migrated attempt = (%+v, %t, %v)", migrated, found, err)
	}
}

func TestPairingAuthorityMigrationPreservesLegacyCompletion(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	path := state.store.path
	invite := reserveAndActivatePairingInvite(
		t,
		state,
		pairingTestInvite(t, pairingTestUUID(607), inviterKey, inviterID),
	)
	attempt, _, err := state.ConsumePairingInvite(
		context.Background(),
		pairingVerifiedRequest(t, invite, pairingTestUUID(608), 91),
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	confirmPairingAttempt(
		t,
		state,
		inviterKey,
		inviterID,
		attempt,
		"2026-08-13T12:02:00Z",
		"2026-08-13T12:02:01Z",
	)
	completedAt := domain.Timestamp("2026-08-13T12:02:02Z")
	if _, _, err := state.CompletePairingFinalization(
		context.Background(),
		attempt.AttemptID,
		completedAt,
	); err != nil {
		t.Fatal(err)
	}

	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		if err := execute(conn, "DROP TABLE pairing_attempt_finalizations;"); err != nil {
			return err
		}
		if err := execute(conn, "DROP TABLE raft_committed_configuration;"); err != nil {
			return err
		}
		return execute(conn, "DELETE FROM schema_migrations WHERE version >= 3;")
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return applyMigration(conn, embeddedMigrations[2], systemClock())
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE pairing_attempt_finalizations
			    SET state = 'completed', completed_at = ?2
			  WHERE attempt_id = ?1;`,
			string(attempt.AttemptID),
			string(completedAt),
		)
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(v3 completed pairing state) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	migrated, found, err := reopened.LocalState().PairingAttempt(
		context.Background(),
		attempt.AttemptID,
	)
	if err != nil || !found ||
		migrated.State != PairingAttemptCompleted ||
		migrated.FinalizedAt != completedAt {
		t.Fatalf("migrated completion = (%+v, %t, %v)", migrated, found, err)
	}
	if err := reopened.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertTextQuery(
			t,
			conn,
			`SELECT authority_status
			   FROM pairing_attempt_finalizations
			  WHERE attempt_id = '`+string(attempt.AttemptID)+`';`,
			"legacy_completed",
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func pairingAdmissionAuthorization(
	t *testing.T,
	ownerKey ed25519.PrivateKey,
	ownerID domain.DeviceID,
	attemptID domain.UUIDv7,
	subjectID domain.DeviceID,
	createdAt domain.Timestamp,
) *PairingFinalizationAuthorization {
	t.Helper()
	authority, err := event.NewLocalAuthority(
		ownerID,
		pairingTestUUID(436),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(map[string]any{
		"attempt_id": attemptID,
		"confirmed":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonicalRequest, err := codec.CanonicalizeSignedObject(requestJSON)
	if err != nil {
		t.Fatal(err)
	}
	reservation := &LocalCommandReservation{
		Input: LocalCommandInput{
			ClientInstanceID: attemptID,
			RequestID:        attemptID,
			SessionID:        domain.UUIDv7(testSessionID),
			WorkspaceID:      testWorkspaceID,
			BindingClass:     LocalBindingOperator,
			OriginDeviceID:   ownerID,
			OriginScopeKind:  OriginScopeKindBoot,
			OriginScopeID:    pairingTestUUID(436),
			RequestKind:      event.KindMembershipDeviceAdmitted,
			CanonicalRequest: canonicalRequest,
			CreatedAt:        createdAt,
		},
		GenerateEventID: func() (domain.UUIDv7, error) {
			return attemptID, nil
		},
		Build: func(
			eventID domain.UUIDv7,
			sequence uint64,
		) (event.SignedEvent, error) {
			payload, err := codec.CanonicalizeSignedObject([]byte(`{}`))
			if err != nil {
				return event.SignedEvent{}, err
			}
			proposal, err := event.BuildProposal(
				event.Command{
					Kind:     event.KindMembershipDeviceAdmitted,
					EntityID: event.StringEntityID(string(subjectID)),
					Actions:  []event.Action{},
					Payload:  payload,
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
					CreatedAt:      createdAt,
					OriginSequence: sequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, ownerKey)
		},
	}
	return &PairingFinalizationAuthorization{
		Request: PairingOperatorRequest{
			ClientInstanceID: reservation.Input.ClientInstanceID,
			RequestID:        reservation.Input.RequestID,
			SessionID:        reservation.Input.SessionID,
			WorkspaceID:      reservation.Input.WorkspaceID,
			OriginDeviceID:   reservation.Input.OriginDeviceID,
			OriginBootID:     reservation.Input.OriginScopeID,
			CanonicalRequest: bytes.Clone(reservation.Input.CanonicalRequest),
			CreatedAt:        reservation.Input.CreatedAt,
		},
		Admission: reservation,
	}
}

func TestPairingFinalizationMigrationRevokesPredecessorAttempts(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	path := state.store.path
	createAttempt := func(
		inviteID domain.UUIDv7,
		attemptID domain.UUIDv7,
	) PairingAttemptRecord {
		t.Helper()
		invite := reserveAndActivatePairingInvite(
			t,
			state,
			pairingTestInvite(t, inviteID, inviterKey, inviterID),
		)
		attempt, _, err := state.ConsumePairingInvite(
			context.Background(),
			pairingVerifiedRequest(t, invite, attemptID, byte(attemptID[len(attemptID)-1])),
			"2026-08-13T12:01:00Z",
		)
		if err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	awaiting := createAttempt(pairingTestUUID(602), pairingTestUUID(603))
	confirmed := createAttempt(pairingTestUUID(604), pairingTestUUID(605))
	if _, _, err := state.RecordPairingConfirmation(
		context.Background(),
		PairingConfirmationInput{
			AttemptID: confirmed.AttemptID,
			Party:     PairingConfirmationRemote,
			Confirmed: true,
			DecidedAt: "2026-08-13T12:02:00Z",
		},
	); err != nil {
		t.Fatal(err)
	}
	predecessorSessionID := pairingTestUUID(606)
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		if err := execute(
			conn,
			`UPDATE pairing_attempts
			    SET state = 'confirmed',
			        local_confirmed = 1,
			        local_confirmed_at = '2026-08-13T12:02:01Z',
			        terminal_at = '2026-08-13T12:02:01Z'
			  WHERE attempt_id = ?1;`,
			string(confirmed.AttemptID),
		); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE pairing_invites
			    SET session_id = ?1, recovery_generation = 1
			  WHERE invite_id IN (?2, ?3);`,
			string(predecessorSessionID),
			string(awaiting.InviteID),
			string(confirmed.InviteID),
		); err != nil {
			return err
		}
		if err := execute(conn, "DROP TABLE pairing_attempt_finalizations;"); err != nil {
			return err
		}
		if err := execute(conn, "DROP TABLE raft_committed_configuration;"); err != nil {
			return err
		}
		return execute(conn, "DELETE FROM schema_migrations WHERE version >= 3;")
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), Options{Path: path})
	if err != nil {
		t.Fatalf("Open(v2 predecessor pairing state) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.withConn(context.Background(), func(conn *sqlite.Conn) error {
		for name, attemptID := range map[string]domain.UUIDv7{
			"awaiting":  awaiting.AttemptID,
			"confirmed": confirmed.AttemptID,
		} {
			var (
				persistedState string
				terminalAt     string
			)
			if err := queryOneArgs(
				conn,
				`SELECT state, terminal_at
				   FROM pairing_attempts
				  WHERE attempt_id = ?1;`,
				[]any{string(attemptID)},
				func(stmt *sqlite.Stmt) {
					persistedState = stmt.ColumnText(0)
					terminalAt = stmt.ColumnText(1)
				},
			); err != nil {
				return err
			}
			if persistedState != string(PairingAttemptRevoked) ||
				!domain.Timestamp(terminalAt).Valid() {
				t.Fatalf(
					"%s predecessor attempt = (%q, %q)",
					name,
					persistedState,
					terminalAt,
				)
			}
		}
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM pairing_attempt_finalizations;",
			0,
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func newPairingLifecycleFixture(
	t *testing.T,
	includeSubject bool,
	subjectStatus device.Status,
	subjectVoter bool,
) pairingLifecycleFixture {
	t.Helper()
	ownerKey := testPairingPrivateKey(70)
	ownerID, err := device.DeriveID(ownerKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	subjectKey := testPairingPrivateKey(71)
	subjectID, err := device.DeriveID(subjectKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	devices := []device.Device{{
		ID: ownerID, Role: device.RoleOwner,
		IdentityPublicKey: ownerKey.Public().(ed25519.PublicKey),
		DaemonVersion:     "1.0.0", MaxApplyLevel: 1,
		Status: device.StatusActive, EntityVersion: 1,
	}}
	if includeSubject {
		devices = append(devices, device.Device{
			ID: subjectID, Role: device.RoleEditor,
			IdentityPublicKey: subjectKey.Public().(ed25519.PublicKey),
			DaemonVersion:     "1.0.0", MaxApplyLevel: 1,
			Status: subjectStatus, EntityVersion: 4,
		})
	}
	voterID := ownerID
	if subjectVoter {
		voterID = subjectID
	}
	target, err := voterset.New(
		domain.UUIDv7(testSessionID),
		[]domain.DeviceID{voterID},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	database := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	if _, err := database.Initialize(context.Background(), InitialState{
		SessionID: domain.UUIDv7(testSessionID), WorkspaceID: testWorkspaceID,
		GenesisJSON: []byte(pairingTestGenesis), DigestVersion: 1, ProjectionSchemaVersion: 1,
		Projections: ProjectionWrites{Devices: devices, VoterSet: []voterset.Set{target}},
	}); err != nil {
		t.Fatal(err)
	}
	return pairingLifecycleFixture{
		state: database.LocalState(), ownerKey: ownerKey, ownerID: ownerID,
		subjectKey: subjectKey, subjectID: subjectID,
	}
}

func (fixture pairingLifecycleFixture) invite(
	t testing.TB,
	inviteID domain.UUIDv7,
	mode pairing.Mode,
	epoch uint64,
	expected uint64,
) pairing.SignedInvite {
	t.Helper()
	value := pairing.Invite{
		InviteID: inviteID, SessionID: domain.UUIDv7(testSessionID), WorkspaceID: testWorkspaceID,
		CreatedAt: "2026-08-13T12:00:00Z", ExpiresAt: "2026-08-13T12:15:00Z",
		InviterDeviceID: fixture.ownerID, Mode: mode, Role: device.RoleEditor,
		InitialCredentialEpoch: epoch,
		Endpoints:              []pairing.Endpoint{{IP: netip.MustParseAddr("10.0.0.5"), Port: 47831}},
	}
	copy(value.InviterIdentityPublicKey[:], fixture.ownerKey.Public().(ed25519.PublicKey))
	for index := range value.Secret {
		value.Secret[index] = byte(index + int(inviteID[len(inviteID)-1]))
	}
	if mode != pairing.ModeNew {
		subject := fixture.subjectID
		value.SubjectDeviceID = &subject
	}
	if mode == pairing.ModeReadmission {
		version := expected
		value.ExpectedEntityVersion = &version
	}
	genesisDigest, err := chain.GenesisDigest([]byte(pairingTestGenesis))
	if err != nil {
		t.Fatal(err)
	}
	copy(value.SignedGenesisDigest[:], genesisDigest[:])
	signed, err := pairing.SignInvite(value, fixture.ownerKey)
	clear(value.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (fixture pairingLifecycleFixture) verifiedRequest(
	t testing.TB,
	invite pairing.SignedInvite,
	attemptID domain.UUIDv7,
) pairing.VerifiedRequest {
	t.Helper()
	inviteValue := invite.Invite()
	defer clear(inviteValue.Secret[:])
	epochKey := testPairingPrivateKey(byte(attemptID[len(attemptID)-1]) + 80)
	binding, err := credential.SignBinding(
		inviteValue.SessionID,
		fixture.subjectID,
		inviteValue.InitialCredentialEpoch,
		epochKey.Public().(ed25519.PublicKey),
		fixture.subjectKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	coreValue := pairing.RequestCore{
		AttemptID: attemptID, JoinerDeviceID: fixture.subjectID,
		DaemonVersion: "1.0.0", MaxApplyLevel: 1, InitialEpochBinding: binding,
	}
	copy(coreValue.JoinerIdentityPublicKey[:], fixture.subjectKey.Public().(ed25519.PublicKey))
	core, err := pairing.NewRequestCore(coreValue)
	if err != nil {
		t.Fatal(err)
	}
	exporter := bytes.Repeat([]byte{0x44}, pairing.ExporterSize)
	request, err := pairing.BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := request.Verify(invite, exporter)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func insertPairingSubject(
	t *testing.T,
	fixture pairingLifecycleFixture,
	status device.Status,
	version uint64,
) {
	t.Helper()
	execPairingSQL(
		t,
		fixture.state,
		`INSERT INTO devices(
		    device_id, role, identity_public_key, daemon_version,
		    max_apply_level, status, entity_version
		) VALUES (?1, 'editor', ?2, '1.0.0', 1, ?3, ?4);`,
		string(fixture.subjectID),
		[]byte(fixture.subjectKey.Public().(ed25519.PublicKey)),
		string(status),
		version,
	)
}

func insertPairingCredentialAuthorization(
	t *testing.T,
	fixture pairingLifecycleFixture,
	epoch uint64,
) {
	t.Helper()
	epochKey := bytes.Repeat([]byte{0x55}, ed25519.PublicKeySize)
	keyDigest := sha256.Sum256(epochKey)
	execPairingSQL(
		t,
		fixture.state,
		`INSERT INTO credential_authorizations(
		    session_id, device_id, epoch, epoch_public_key, key_digest, role,
		    issued_at, not_before, validity_seconds, authority_voter_set_version,
		    clock_endorsements_json, binding_signature, authorization_chain_index
		) VALUES (?1, ?2, ?3, ?4, ?5, 'editor',
		          '2026-08-13T11:00:00Z', '2026-08-13T11:00:00Z', 1800, 1,
		          '[{}]', zeroblob(64), ?6);`,
		string(domain.UUIDv7(testSessionID)),
		string(fixture.subjectID),
		epoch,
		epochKey,
		keyDigest[:],
		epoch,
	)
}

func execPairingSQL(t *testing.T, state LocalState, query string, args ...any) {
	t.Helper()
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(conn, query, args...)
	}); err != nil {
		t.Fatal(err)
	}
}

func assertPairingInviteState(
	t *testing.T,
	state LocalState,
	inviteID domain.UUIDv7,
	want PairingInviteState,
) {
	t.Helper()
	record, found, err := state.PairingInvite(context.Background(), inviteID)
	if err != nil || !found || record.State != want {
		t.Fatalf("PairingInvite(%s) = (%+v, %t, %v), want %s", inviteID, record, found, err, want)
	}
}

func testPairingPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}
