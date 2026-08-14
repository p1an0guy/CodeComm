package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"zombiezen.com/go/sqlite"
)

const pairingTestGenesis = `{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000002","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`

func TestPairingInviteReserveActivateAndCap(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	first := pairingTestInvite(t, pairingTestUUID(1), inviterKey, inviterID)

	record, duplicate, err := state.ReservePairingInvite(context.Background(), first)
	if err != nil || duplicate {
		t.Fatalf("ReservePairingInvite() = (%+v, %t, %v), want fresh success", record, duplicate, err)
	}
	if record.State != PairingInvitePreparing || record.InviteDigest != Digest(first.Digest()) {
		t.Fatalf("reserved invite = %+v", record)
	}
	if got, duplicate, err := state.ReservePairingInvite(context.Background(), first); err != nil || !duplicate || !samePairingInvite(got, record) {
		t.Fatalf("duplicate reserve = (%+v, %t, %v)", got, duplicate, err)
	}
	activated, duplicate, err := state.ActivatePairingInvite(
		context.Background(), record.InviteID, record.InviteDigest,
	)
	if err != nil || duplicate || activated.State != PairingInviteOutstanding {
		t.Fatalf("ActivatePairingInvite() = (%+v, %t, %v)", activated, duplicate, err)
	}
	if _, duplicate, err := state.ActivatePairingInvite(
		context.Background(), record.InviteID, record.InviteDigest,
	); err != nil || !duplicate {
		t.Fatalf("duplicate activate = (%t, %v), want duplicate success", duplicate, err)
	}

	for index := 2; index <= MaxOutstandingPairingInvites; index++ {
		invite := pairingTestInvite(t, pairingTestUUID(index), inviterKey, inviterID)
		reserved, _, err := state.ReservePairingInvite(context.Background(), invite)
		if err != nil {
			t.Fatalf("reserve invite %d: %v", index, err)
		}
		if _, _, err := state.ActivatePairingInvite(
			context.Background(), reserved.InviteID, reserved.InviteDigest,
		); err != nil {
			t.Fatalf("activate invite %d: %v", index, err)
		}
	}
	ninth := pairingTestInvite(t, pairingTestUUID(9), inviterKey, inviterID)
	if _, _, err := state.ReservePairingInvite(context.Background(), ninth); !errors.Is(err, ErrPairingInviteLimit) {
		t.Fatalf("ninth reserve error = %v, want %v", err, ErrPairingInviteLimit)
	}

	terminatedAt := domain.Timestamp("2026-08-13T12:01:00Z")
	if _, _, err := state.TerminatePairingInvite(
		context.Background(), record.InviteID, record.InviteDigest,
		PairingInviteRevoked, terminatedAt,
	); err != nil {
		t.Fatalf("TerminatePairingInvite() error = %v", err)
	}
	if _, _, err := state.ReservePairingInvite(context.Background(), ninth); err != nil {
		t.Fatalf("reserve after capacity release error = %v", err)
	}

	listed, err := state.PairingInvites(context.Background(), inviterID)
	if err != nil {
		t.Fatalf("PairingInvites() error = %v", err)
	}
	if len(listed) != MaxOutstandingPairingInvites+1 {
		t.Fatalf("listed invites = %d, want %d", len(listed), MaxOutstandingPairingInvites+1)
	}
}

func TestPairingInviteRejectsWrongGenesisDigest(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := pairingTestInvite(t, pairingTestUUID(10), inviterKey, inviterID)
	value := invite.Invite()
	defer clear(value.Secret[:])
	value.SignedGenesisDigest[0] ^= 1
	wrong, err := pairing.SignInvite(value, inviterKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	if _, _, err := state.ReservePairingInvite(
		context.Background(),
		wrong,
	); !errors.Is(err, ErrPairingGenesisMismatch) {
		t.Fatalf("ReservePairingInvite() error = %v, want %v", err, ErrPairingGenesisMismatch)
	}
}

func TestPairingConsumeAndTwoSidedConfirmation(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(20), inviterKey, inviterID),
	)
	verified := pairingVerifiedRequest(t, invite, pairingTestUUID(21), 3)

	attempt, duplicate, err := state.ConsumePairingInvite(
		context.Background(), verified, "2026-08-13T12:02:00Z",
	)
	if err != nil || duplicate || attempt.State != PairingAttemptAwaitingSAS {
		t.Fatalf("ConsumePairingInvite() = (%+v, %t, %v)", attempt, duplicate, err)
	}
	if got, duplicate, err := state.ConsumePairingInvite(
		context.Background(), verified, "2026-08-13T12:03:00Z",
	); err != nil || !duplicate || got.AttemptID != attempt.AttemptID {
		t.Fatalf("duplicate consume = (%+v, %t, %v)", got, duplicate, err)
	}

	localDecision := PairingConfirmationInput{
		AttemptID: attempt.AttemptID, Party: PairingConfirmationLocal,
		Confirmed: true, DecidedAt: "2026-08-13T12:03:00Z",
	}
	local, duplicate, err := state.RecordPairingConfirmation(context.Background(), localDecision)
	if err != nil || duplicate || !local.LocalConfirmed || local.RemoteConfirmed ||
		local.State != PairingAttemptAwaitingSAS {
		t.Fatalf("local confirmation = (%+v, %t, %v)", local, duplicate, err)
	}
	if _, duplicate, err := state.RecordPairingConfirmation(context.Background(), localDecision); err != nil || !duplicate {
		t.Fatalf("duplicate local confirmation = (%t, %v)", duplicate, err)
	}
	changed := localDecision
	changed.DecidedAt = "2026-08-13T12:03:01Z"
	if _, _, err := state.RecordPairingConfirmation(context.Background(), changed); !errors.Is(err, ErrPairingConflict) {
		t.Fatalf("changed local confirmation error = %v, want %v", err, ErrPairingConflict)
	}

	remoteDecision := PairingConfirmationInput{
		AttemptID: attempt.AttemptID, Party: PairingConfirmationRemote,
		Confirmed: true, DecidedAt: "2026-08-13T12:04:00Z",
	}
	confirmed, duplicate, err := state.RecordPairingConfirmation(context.Background(), remoteDecision)
	if err != nil || duplicate || confirmed.State != PairingAttemptFinalizing ||
		!confirmed.LocalConfirmed || !confirmed.RemoteConfirmed ||
		confirmed.TerminalAt != remoteDecision.DecidedAt {
		t.Fatalf("remote confirmation = (%+v, %t, %v)", confirmed, duplicate, err)
	}
	if _, duplicate, err := state.RecordPairingConfirmation(context.Background(), remoteDecision); err != nil || !duplicate {
		t.Fatalf("duplicate terminal confirmation = (%t, %v)", duplicate, err)
	}
	pending, found, err := state.NextPairingFinalization(context.Background())
	if err != nil || !found || pending.AttemptID != attempt.AttemptID ||
		pending.State != PairingAttemptFinalizing {
		t.Fatalf("NextPairingFinalization() = (%+v, %t, %v)", pending, found, err)
	}
	completedAt := domain.Timestamp("2026-08-13T12:04:01Z")
	completed, duplicate, err := state.CompletePairingFinalization(
		context.Background(),
		attempt.AttemptID,
		completedAt,
	)
	if err != nil || duplicate || completed.State != PairingAttemptCompleted ||
		completed.FinalizedAt != completedAt {
		t.Fatalf("CompletePairingFinalization() = (%+v, %t, %v)", completed, duplicate, err)
	}
	retried, duplicate, err := state.CompletePairingFinalization(
		context.Background(),
		attempt.AttemptID,
		"2026-08-13T12:04:02Z",
	)
	if err != nil || !duplicate || retried.FinalizedAt != completedAt {
		t.Fatalf("duplicate finalization = (%+v, %t, %v)", retried, duplicate, err)
	}
	if pending, found, err := state.NextPairingFinalization(
		context.Background(),
	); err != nil || found {
		t.Fatalf("pending finalization after completion = (%+v, %t, %v)", pending, found, err)
	}

	deletion, found, err := state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found || deletion.InviteID != invite.Invite().InviteID || deletion.Reason != "consumed" {
		t.Fatalf("NextPairingSecretDeletion() = (%+v, %t, %v)", deletion, found, err)
	}
	if duplicate, err := state.CompletePairingSecretDeletion(
		context.Background(), deletion.SessionID, deletion.InviteID,
	); err != nil || duplicate {
		t.Fatalf("CompletePairingSecretDeletion() = (%t, %v)", duplicate, err)
	}
	if duplicate, err := state.CompletePairingSecretDeletion(
		context.Background(), deletion.SessionID, deletion.InviteID,
	); err != nil || !duplicate {
		t.Fatalf("duplicate cleanup completion = (%t, %v)", duplicate, err)
	}
}

func TestPairingProofFailuresAreIdempotentAndThirdVoids(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(30), inviterKey, inviterID),
	)
	var first PairingProofFailureInput
	for index := 1; index <= MaxPairingProofFailures; index++ {
		verified := pairingVerifiedRequest(t, invite, pairingTestUUID(30+index), byte(10+index))
		input := PairingProofFailureInput{
			InviteID: verified.InviteID(), InviteDigest: Digest(verified.InviteDigest()),
			RequestDigest: Digest(verified.RequestDigest()), RequestCore: verified.Core(),
			TranscriptHash: Digest(verified.TranscriptHash()),
			ObservedAt:     domain.Timestamp(fmt.Sprintf("2026-08-13T12:0%d:00Z", index)),
		}
		if index == 1 {
			first = input
		}
		attempt, duplicate, err := state.RecordPairingProofFailure(context.Background(), input)
		if err != nil || duplicate || attempt.State != PairingAttemptProofRejected {
			t.Fatalf("proof failure %d = (%+v, %t, %v)", index, attempt, duplicate, err)
		}
	}
	if _, duplicate, err := state.RecordPairingProofFailure(
		context.Background(),
		first,
	); !errors.Is(err, ErrPairingInviteUnavailable) || duplicate {
		t.Fatalf("terminal proof replay = (%t, %v)", duplicate, err)
	}
	if err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		assertIntQuery(
			t,
			conn,
			"SELECT count(*) FROM pairing_attempts WHERE state = 'proof_rejected';",
			0,
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	listed, err := state.PairingInvites(context.Background(), inviterID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("PairingInvites() = (%+v, %v)", listed, err)
	}
	if listed[0].State != PairingInviteProofExhausted ||
		listed[0].ProofFailures != MaxPairingProofFailures {
		t.Fatalf("invite after failures = %+v", listed[0])
	}
	deletion, found, err := state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found || deletion.Reason != "proof_exhausted" {
		t.Fatalf("cleanup after failures = (%+v, %t, %v)", deletion, found, err)
	}
}

func TestPairingProofAttemptIDCollisionStillConsumesFailureBudget(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t,
		state,
		pairingTestInvite(t, pairingTestUUID(35), inviterKey, inviterID),
	)
	attemptID := pairingTestUUID(36)
	makeInput := func(fill byte, observedAt domain.Timestamp) PairingProofFailureInput {
		t.Helper()
		verified := pairingVerifiedRequest(t, invite, attemptID, fill)
		return PairingProofFailureInput{
			InviteID:       verified.InviteID(),
			InviteDigest:   Digest(verified.InviteDigest()),
			RequestDigest:  Digest(verified.RequestDigest()),
			RequestCore:    verified.Core(),
			TranscriptHash: Digest(verified.TranscriptHash()),
			ObservedAt:     observedAt,
		}
	}

	first := makeInput(40, "2026-08-13T12:01:00Z")
	if _, duplicate, err := state.RecordPairingProofFailure(
		context.Background(),
		first,
	); err != nil || duplicate {
		t.Fatalf("first proof failure = (%t, %v)", duplicate, err)
	}
	if _, duplicate, err := state.RecordPairingProofFailure(
		context.Background(),
		first,
	); err != nil || !duplicate {
		t.Fatalf("exact proof retry = (%t, %v)", duplicate, err)
	}
	for index, input := range []PairingProofFailureInput{
		makeInput(41, "2026-08-13T12:02:00Z"),
		makeInput(42, "2026-08-13T12:03:00Z"),
	} {
		if _, duplicate, err := state.RecordPairingProofFailure(
			context.Background(),
			input,
		); !errors.Is(err, ErrPairingConflict) || duplicate {
			t.Fatalf(
				"colliding proof failure %d = (%t, %v), want conflict",
				index+2,
				duplicate,
				err,
			)
		}
	}
	listed, err := state.PairingInvites(context.Background(), inviterID)
	if err != nil || len(listed) != 1 ||
		listed[0].State != PairingInviteProofExhausted ||
		listed[0].ProofFailures != MaxPairingProofFailures {
		t.Fatalf("invite after colliding failures = (%+v, %v)", listed, err)
	}
}

func TestPairingExpiryCommitsWhileReturningError(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(40), inviterKey, inviterID),
	)
	verified := pairingVerifiedRequest(t, invite, pairingTestUUID(41), 20)
	if _, _, err := state.ConsumePairingInvite(
		context.Background(), verified, "2026-08-13T12:15:00Z",
	); !errors.Is(err, ErrPairingInviteExpired) {
		t.Fatalf("ConsumePairingInvite(at expiry) error = %v, want %v", err, ErrPairingInviteExpired)
	}
	listed, err := state.PairingInvites(context.Background(), inviterID)
	if err != nil || len(listed) != 1 || listed[0].State != PairingInviteExpired {
		t.Fatalf("expired durable invite = (%+v, %v)", listed, err)
	}
	if deletion, found, err := state.NextPairingSecretDeletion(context.Background()); err != nil || !found || deletion.Reason != "expired" {
		t.Fatalf("expiry cleanup = (%+v, %t, %v)", deletion, found, err)
	}
}

func TestPairingDeclineAndCleanupFailureHistory(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(50), inviterKey, inviterID),
	)
	verified := pairingVerifiedRequest(t, invite, pairingTestUUID(51), 30)
	attempt, _, err := state.ConsumePairingInvite(
		context.Background(), verified, "2026-08-13T12:02:00Z",
	)
	if err != nil {
		t.Fatalf("ConsumePairingInvite() error = %v", err)
	}
	decline := PairingConfirmationInput{
		AttemptID: attempt.AttemptID, Party: PairingConfirmationRemote,
		Confirmed: false, DecidedAt: "2026-08-13T12:03:00Z",
	}
	declined, duplicate, err := state.RecordPairingConfirmation(context.Background(), decline)
	if err != nil || duplicate || declined.State != PairingAttemptDeclined ||
		declined.DeclinedBy != PairingConfirmationRemote {
		t.Fatalf("decline = (%+v, %t, %v)", declined, duplicate, err)
	}
	if _, duplicate, err := state.RecordPairingConfirmation(context.Background(), decline); err != nil || !duplicate {
		t.Fatalf("duplicate decline = (%t, %v)", duplicate, err)
	}

	deletion, found, err := state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found {
		t.Fatalf("NextPairingSecretDeletion() = (%+v, %t, %v)", deletion, found, err)
	}
	failedAt := domain.Timestamp("2026-08-13T12:04:00Z")
	failed, duplicate, err := state.FailPairingSecretDeletion(
		context.Background(), deletion.SessionID, deletion.InviteID, "provider_locked", failedAt,
	)
	if err != nil || duplicate || failed.FailureCount != 1 {
		t.Fatalf("FailPairingSecretDeletion() = (%+v, %t, %v)", failed, duplicate, err)
	}
	if got, duplicate, err := state.FailPairingSecretDeletion(
		context.Background(), deletion.SessionID, deletion.InviteID, "provider_locked", failedAt,
	); err != nil || !duplicate || got.FailureCount != 1 {
		t.Fatalf("duplicate cleanup failure = (%+v, %t, %v)", got, duplicate, err)
	}
}

func TestPairingSASAttemptExpiresAndCanBeRevoked(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(52), inviterKey, inviterID),
	)
	verified := pairingVerifiedRequest(t, invite, pairingTestUUID(53), 40)
	attempt, _, err := state.ConsumePairingInvite(
		context.Background(), verified, "2026-08-13T12:02:00Z",
	)
	if err != nil {
		t.Fatalf("ConsumePairingInvite() error = %v", err)
	}
	late := PairingConfirmationInput{
		AttemptID: attempt.AttemptID, Party: PairingConfirmationLocal,
		Confirmed: true, DecidedAt: "2026-08-13T12:15:00Z",
	}
	if _, _, err := state.RecordPairingConfirmation(
		context.Background(),
		late,
	); !errors.Is(err, ErrPairingInviteExpired) {
		t.Fatalf("late confirmation error = %v, want %v", err, ErrPairingInviteExpired)
	}
	stored, found, err := state.PairingAttempt(context.Background(), attempt.AttemptID)
	if err != nil || !found || stored.State != PairingAttemptExpired ||
		stored.TerminalAt != late.DecidedAt {
		t.Fatalf("expired attempt = (%+v, %t, %v)", stored, found, err)
	}

	secondInvite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(54), inviterKey, inviterID),
	)
	secondVerified := pairingVerifiedRequest(t, secondInvite, pairingTestUUID(55), 50)
	second, _, err := state.ConsumePairingInvite(
		context.Background(), secondVerified, "2026-08-13T12:03:00Z",
	)
	if err != nil {
		t.Fatalf("ConsumePairingInvite(second) error = %v", err)
	}
	revokedAt := domain.Timestamp("2026-08-13T12:04:00Z")
	revoked, duplicate, err := state.TerminatePairingAttempt(
		context.Background(), second.AttemptID, PairingAttemptRevoked, revokedAt,
	)
	if err != nil || duplicate || revoked.State != PairingAttemptRevoked {
		t.Fatalf("TerminatePairingAttempt() = (%+v, %t, %v)", revoked, duplicate, err)
	}
	if _, duplicate, err := state.TerminatePairingAttempt(
		context.Background(), second.AttemptID, PairingAttemptRevoked, revokedAt,
	); err != nil || !duplicate {
		t.Fatalf("duplicate termination = (%t, %v)", duplicate, err)
	}
}

func TestPairingTablesContainNoSecretColumn(t *testing.T) {
	state, _, _ := newPairingStateFixture(t)
	err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		for _, table := range []string{"pairing_invites", "pairing_attempts"} {
			columns := queryTextColumn(
				t, conn, "SELECT name FROM pragma_table_info('"+table+"') ORDER BY cid;",
			)
			for _, column := range columns {
				if strings.Contains(column, "secret") || column == "proof" {
					t.Fatalf("%s contains forbidden secret-bearing column %q", table, column)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPairingInviteLookupIsCurrentGenerationAndReturnsCopies(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(55), inviterKey, inviterID),
	)
	inviteID := invite.Invite().InviteID
	record, found, err := state.PairingInvite(context.Background(), inviteID)
	if err != nil || !found || record.InviteID != inviteID {
		t.Fatalf("PairingInvite() = (%+v, %t, %v)", record, found, err)
	}
	if record.SubjectDeviceID != nil {
		*record.SubjectDeviceID = ""
	}
	again, found, err := state.PairingInvite(context.Background(), inviteID)
	if err != nil || !found || again.InviteID != inviteID {
		t.Fatalf("PairingInvite(second) = (%+v, %t, %v)", again, found, err)
	}
	if _, found, err := state.PairingInvite(
		context.Background(), pairingTestUUID(999),
	); err != nil || found {
		t.Fatalf("PairingInvite(missing) = (%t, %v), want (false, nil)", found, err)
	}
}

func TestPairingConsumedInviteCannotReferenceAnotherInvitesAttempt(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	first := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(56), inviterKey, inviterID),
	)
	second := reserveAndActivatePairingInvite(
		t, state, pairingTestInvite(t, pairingTestUUID(57), inviterKey, inviterID),
	)
	failed := pairingVerifiedRequest(t, first, pairingTestUUID(58), 60)
	failure := PairingProofFailureInput{
		InviteID: failed.InviteID(), InviteDigest: Digest(failed.InviteDigest()),
		RequestDigest: Digest(failed.RequestDigest()), RequestCore: failed.Core(),
		TranscriptHash: Digest(failed.TranscriptHash()),
		ObservedAt:     "2026-08-13T12:02:00Z",
	}
	attempt, _, err := state.RecordPairingProofFailure(context.Background(), failure)
	if err != nil {
		t.Fatalf("RecordPairingProofFailure() error = %v", err)
	}
	secondID := second.Invite().InviteID
	err = state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE pairing_invites
			    SET state = 'consumed', consumed_attempt_id = ?2, terminal_at = ?3
			  WHERE invite_id = ?1;`,
			string(secondID), string(attempt.AttemptID), "2026-08-13T12:03:00Z",
		)
	})
	if err == nil {
		t.Fatal("cross-invite consumed attempt reference succeeded")
	}
}

func TestPairingGenerationClearQueuesOutstandingSecret(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := pairingTestInvite(t, pairingTestUUID(60), inviterKey, inviterID)
	record, _, err := state.ReservePairingInvite(context.Background(), invite)
	if err != nil {
		t.Fatalf("ReservePairingInvite() error = %v", err)
	}
	if _, _, err := state.ActivatePairingInvite(
		context.Background(), record.InviteID, record.InviteDigest,
	); err != nil {
		t.Fatalf("ActivatePairingInvite() error = %v", err)
	}
	for index, observedAt := range []domain.Timestamp{
		"2026-08-13T12:01:00Z",
		"2026-08-13T12:02:00Z",
	} {
		failed := pairingVerifiedRequest(
			t,
			invite,
			pairingTestUUID(61+index),
			byte(60+index),
		)
		if _, _, err := state.RecordPairingProofFailure(
			context.Background(),
			PairingProofFailureInput{
				InviteID: failed.InviteID(), InviteDigest: Digest(failed.InviteDigest()),
				RequestDigest: Digest(failed.RequestDigest()), RequestCore: failed.Core(),
				TranscriptHash: Digest(failed.TranscriptHash()),
				ObservedAt:     observedAt,
			},
		); err != nil {
			t.Fatalf("RecordPairingProofFailure(%d) error = %v", index+1, err)
		}
	}
	if err := state.withImmediate(context.Background(), clearGenerationLocalState); err != nil {
		t.Fatalf("clearGenerationLocalState() error = %v", err)
	}
	deletion, found, err := state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found || deletion.Reason != "generation_changed" ||
		deletion.InviteID != record.InviteID ||
		deletion.QueuedAt != "2026-08-13T12:02:00Z" {
		t.Fatalf("generation cleanup = (%+v, %t, %v)", deletion, found, err)
	}
	if _, _, err := state.FailPairingSecretDeletion(
		context.Background(),
		deletion.SessionID,
		deletion.InviteID,
		"credential_unavailable",
		"2026-08-13T12:03:00Z",
	); err != nil {
		t.Fatalf("pre-expiry cleanup failure error = %v", err)
	}
	for index := range 2 {
		stored, found, err := state.PairingAttempt(
			context.Background(),
			pairingTestUUID(61+index),
		)
		if err != nil || found {
			t.Fatalf(
				"unexpected pairing attempt %d after generation clear = (%+v, %t, %v)",
				index+1,
				stored,
				found,
				err,
			)
		}
	}
	var (
		inviteState      PairingInviteState
		inviteTerminalAt domain.Timestamp
	)
	if err := state.store.withConn(context.Background(), func(conn *sqlite.Conn) error {
		return queryOneArgs(
			conn,
			"SELECT state, terminal_at FROM pairing_invites WHERE invite_id = ?1;",
			[]any{string(record.InviteID)},
			func(stmt *sqlite.Stmt) {
				inviteState = PairingInviteState(stmt.ColumnText(0))
				inviteTerminalAt = domain.Timestamp(stmt.ColumnText(1))
			},
		)
	}); err != nil {
		t.Fatalf("read predecessor invite state: %v", err)
	}
	if inviteState != PairingInviteAbandoned ||
		inviteTerminalAt != deletion.QueuedAt {
		t.Fatalf(
			"predecessor invite = (%q, %q), want (%q, %q)",
			inviteState,
			inviteTerminalAt,
			PairingInviteAbandoned,
			deletion.QueuedAt,
		)
	}
}

func TestPairingGenerationClearRevokesOnlyUnfinishedAttempts(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	createAttempt := func(
		inviteSuffix int,
		attemptSuffix int,
	) PairingAttemptRecord {
		t.Helper()
		invite := reserveAndActivatePairingInvite(
			t,
			state,
			pairingTestInvite(
				t,
				pairingTestUUID(inviteSuffix),
				inviterKey,
				inviterID,
			),
		)
		attempt, _, err := state.ConsumePairingInvite(
			context.Background(),
			pairingVerifiedRequest(
				t,
				invite,
				pairingTestUUID(attemptSuffix),
				byte(attemptSuffix),
			),
			"2026-08-13T12:01:00Z",
		)
		if err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	confirm := func(attempt PairingAttemptRecord) {
		t.Helper()
		for index, party := range []PairingConfirmationParty{
			PairingConfirmationRemote,
			PairingConfirmationLocal,
		} {
			if _, _, err := state.RecordPairingConfirmation(
				context.Background(),
				PairingConfirmationInput{
					AttemptID: attempt.AttemptID,
					Party:     party,
					Confirmed: true,
					DecidedAt: domain.Timestamp(
						fmt.Sprintf("2026-08-13T12:02:0%dZ", index),
					),
				},
			); err != nil {
				t.Fatal(err)
			}
		}
	}

	awaiting := createAttempt(70, 71)
	finalizing := createAttempt(72, 73)
	confirm(finalizing)
	completed := createAttempt(74, 75)
	confirm(completed)
	if _, _, err := state.CompletePairingFinalization(
		context.Background(),
		completed.AttemptID,
		"2026-08-13T12:03:00Z",
	); err != nil {
		t.Fatal(err)
	}

	if err := state.withImmediate(
		context.Background(),
		clearGenerationLocalState,
	); err != nil {
		t.Fatalf("clearGenerationLocalState() error = %v", err)
	}
	for name, expected := range map[string]struct {
		id    domain.UUIDv7
		state PairingAttemptState
	}{
		"awaiting":   {id: awaiting.AttemptID, state: PairingAttemptRevoked},
		"finalizing": {id: finalizing.AttemptID, state: PairingAttemptRevoked},
		"completed":  {id: completed.AttemptID, state: PairingAttemptCompleted},
	} {
		t.Run(name, func(t *testing.T) {
			record, found, err := state.PairingAttempt(context.Background(), expected.id)
			if err != nil || !found || record.State != expected.state {
				t.Fatalf(
					"PairingAttempt() = (%+v, %t, %v), want state %q",
					record,
					found,
					err,
					expected.state,
				)
			}
		})
	}
	if pending, found, err := state.NextPairingFinalization(
		context.Background(),
	); err != nil || found {
		t.Fatalf(
			"NextPairingFinalization() = (%+v, %t, %v)",
			pending,
			found,
			err,
		)
	}
}

func TestPairingAttemptRejectsFinalizationModeCorruption(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	invite := reserveAndActivatePairingInvite(
		t,
		state,
		pairingTestInvite(t, pairingTestUUID(80), inviterKey, inviterID),
	)
	attempt, _, err := state.ConsumePairingInvite(
		context.Background(),
		pairingVerifiedRequest(t, invite, pairingTestUUID(81), 81),
		"2026-08-13T12:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	for index, party := range []PairingConfirmationParty{
		PairingConfirmationRemote,
		PairingConfirmationLocal,
	} {
		if _, _, err := state.RecordPairingConfirmation(
			context.Background(),
			PairingConfirmationInput{
				AttemptID: attempt.AttemptID,
				Party:     party,
				Confirmed: true,
				DecidedAt: domain.Timestamp(
					fmt.Sprintf("2026-08-13T12:02:0%dZ", index),
				),
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE pairing_attempt_finalizations
			    SET mode = 'rebootstrap'
			  WHERE attempt_id = ?1;`,
			string(attempt.AttemptID),
		)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.PairingAttempt(
		context.Background(),
		attempt.AttemptID,
	); !errors.Is(err, ErrPairingStateIntegrity) {
		t.Fatalf(
			"PairingAttempt() error = %v, want %v",
			err,
			ErrPairingStateIntegrity,
		)
	}
	if err := state.withImmediate(context.Background(), func(conn *sqlite.Conn) error {
		return execute(
			conn,
			`UPDATE pairing_attempt_finalizations
			    SET mode = 'new', started_at = '2026-08-13T12:02:00Z'
			  WHERE attempt_id = ?1;`,
			string(attempt.AttemptID),
		)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.PairingAttempt(
		context.Background(),
		attempt.AttemptID,
	); !errors.Is(err, ErrPairingStateIntegrity) {
		t.Fatalf(
			"PairingAttempt(started_at) error = %v, want %v",
			err,
			ErrPairingStateIntegrity,
		)
	}
}

func TestRejectedPairingFinalizationDoesNotStarveQueue(t *testing.T) {
	state, inviterKey, inviterID := newPairingStateFixture(t)
	makeFinalizing := func(
		inviteSuffix int,
		attemptSuffix int,
		second int,
	) PairingAttemptRecord {
		t.Helper()
		invite := reserveAndActivatePairingInvite(
			t,
			state,
			pairingTestInvite(
				t,
				pairingTestUUID(inviteSuffix),
				inviterKey,
				inviterID,
			),
		)
		attempt, _, err := state.ConsumePairingInvite(
			context.Background(),
			pairingVerifiedRequest(
				t,
				invite,
				pairingTestUUID(attemptSuffix),
				byte(attemptSuffix),
			),
			"2026-08-13T12:01:00Z",
		)
		if err != nil {
			t.Fatal(err)
		}
		for index, party := range []PairingConfirmationParty{
			PairingConfirmationRemote,
			PairingConfirmationLocal,
		} {
			if _, _, err := state.RecordPairingConfirmation(
				context.Background(),
				PairingConfirmationInput{
					AttemptID: attempt.AttemptID,
					Party:     party,
					Confirmed: true,
					DecidedAt: domain.Timestamp(fmt.Sprintf(
						"2026-08-13T12:02:%02dZ",
						second+index,
					)),
				},
			); err != nil {
				t.Fatal(err)
			}
		}
		return attempt
	}

	first := makeFinalizing(82, 83, 0)
	second := makeFinalizing(84, 85, 2)
	pending, found, err := state.NextPairingFinalization(context.Background())
	if err != nil || !found || pending.AttemptID != first.AttemptID {
		t.Fatalf("first pending = (%+v, %t, %v)", pending, found, err)
	}
	rejected, duplicate, err := state.RejectPairingFinalization(
		context.Background(),
		first.AttemptID,
	)
	if err != nil || duplicate || rejected.State != PairingAttemptRevoked {
		t.Fatalf(
			"RejectPairingFinalization() = (%+v, %t, %v)",
			rejected,
			duplicate,
			err,
		)
	}
	retried, duplicate, err := state.RejectPairingFinalization(
		context.Background(),
		first.AttemptID,
	)
	if err != nil || !duplicate || retried.State != PairingAttemptRevoked {
		t.Fatalf(
			"RejectPairingFinalization(retry) = (%+v, %t, %v)",
			retried,
			duplicate,
			err,
		)
	}
	pending, found, err = state.NextPairingFinalization(context.Background())
	if err != nil || !found || pending.AttemptID != second.AttemptID {
		t.Fatalf("second pending = (%+v, %t, %v)", pending, found, err)
	}
}

func newPairingStateFixture(
	t *testing.T,
) (LocalState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	privateKey, deviceID := localTestIdentity(t)
	store := openTestStore(t, filepath.Join(t.TempDir(), "session", "state.db"), nil)
	_, err := store.Initialize(context.Background(), InitialState{
		SessionID: domain.UUIDv7(testSessionID), WorkspaceID: testWorkspaceID,
		GenesisJSON: []byte(pairingTestGenesis), DigestVersion: 1, ProjectionSchemaVersion: 1,
		Projections: ProjectionWrites{Devices: []device.Device{{
			ID: deviceID, Role: device.RoleOwner,
			IdentityPublicKey: privateKey.Public().(ed25519.PublicKey),
			DaemonVersion:     "1.0.0", MaxApplyLevel: 1,
			Status: device.StatusActive, EntityVersion: 1,
		}}},
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return store.LocalState(), privateKey, deviceID
}

func pairingTestInvite(
	t testing.TB,
	inviteID domain.UUIDv7,
	inviterPrivateKey ed25519.PrivateKey,
	inviterID domain.DeviceID,
) pairing.SignedInvite {
	t.Helper()
	value := pairing.Invite{
		InviteID: inviteID, SessionID: domain.UUIDv7(testSessionID), WorkspaceID: testWorkspaceID,
		CreatedAt: "2026-08-13T12:00:00Z", ExpiresAt: "2026-08-13T12:15:00Z",
		InviterDeviceID: inviterID, Mode: pairing.ModeNew, Role: device.RoleEditor,
		InitialCredentialEpoch: 1,
		Endpoints:              []pairing.Endpoint{{IP: netip.MustParseAddr("10.0.0.5"), Port: 47831}},
	}
	copy(value.InviterIdentityPublicKey[:], inviterPrivateKey.Public().(ed25519.PublicKey))
	for index := range value.Secret {
		value.Secret[index] = byte(index + int(inviteID[len(inviteID)-1]))
	}
	genesisDigest, err := chain.GenesisDigest([]byte(pairingTestGenesis))
	if err != nil {
		t.Fatalf("GenesisDigest() error = %v", err)
	}
	copy(value.SignedGenesisDigest[:], genesisDigest[:])
	signed, err := pairing.SignInvite(value, inviterPrivateKey)
	if err != nil {
		t.Fatalf("SignInvite() error = %v", err)
	}
	return signed
}

func reserveAndActivatePairingInvite(
	t *testing.T,
	state LocalState,
	invite pairing.SignedInvite,
) pairing.SignedInvite {
	t.Helper()
	record, _, err := state.ReservePairingInvite(context.Background(), invite)
	if err != nil {
		t.Fatalf("ReservePairingInvite() error = %v", err)
	}
	if _, _, err := state.ActivatePairingInvite(
		context.Background(), record.InviteID, record.InviteDigest,
	); err != nil {
		t.Fatalf("ActivatePairingInvite() error = %v", err)
	}
	return invite
}

func pairingVerifiedRequest(
	t testing.TB,
	invite pairing.SignedInvite,
	attemptID domain.UUIDv7,
	fill byte,
) pairing.VerifiedRequest {
	t.Helper()
	joinerPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	joinerPublicKey := joinerPrivateKey.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	epochPublicKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{fill + 1}, ed25519.SeedSize),
	).Public().(ed25519.PublicKey)
	binding, err := credential.SignBinding(
		invite.Invite().SessionID, joinerID, invite.Invite().InitialCredentialEpoch,
		epochPublicKey, joinerPrivateKey,
	)
	if err != nil {
		t.Fatalf("SignBinding() error = %v", err)
	}
	coreValue := pairing.RequestCore{
		AttemptID: attemptID, JoinerDeviceID: joinerID, DaemonVersion: "1.0.0",
		MaxApplyLevel: 1, InitialEpochBinding: binding,
	}
	copy(coreValue.JoinerIdentityPublicKey[:], joinerPublicKey)
	core, err := pairing.NewRequestCore(coreValue)
	if err != nil {
		t.Fatalf("NewRequestCore() error = %v", err)
	}
	exporter := bytes.Repeat([]byte{0x55}, pairing.ExporterSize)
	request, err := pairing.BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}
	verified, err := request.Verify(invite, exporter)
	if err != nil {
		t.Fatalf("Request.Verify() error = %v", err)
	}
	return verified
}

func pairingTestUUID(index int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf("01890f47-3e72-7000-8000-%012x", index))
}
