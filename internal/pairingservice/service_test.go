package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	serviceTestSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000502")
	serviceTestWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	serviceTestGenesis     = `{"recovery_generation":0,"session_id":"01890f47-3e72-7000-8000-000000000502","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
)

type serviceFixture struct {
	service           *Service
	authorizer        *AdmissionAuthorizer
	database          *store.Store
	databasePath      string
	state             store.LocalState
	secrets           *fakeSecretStore
	clock             *testClock
	invite            pairing.SignedInvite
	joinerIdentityKey ed25519.PrivateKey
	joinerEpochKey    ed25519.PrivateKey
	peer              transport.IdentityCertificate
	exporter          []byte
}

func TestPairingServiceRequestConfirmationAndCleanup(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	reservations := &recordingBootReservationLane{}
	fixture.service.reservations = reservations
	request := fixture.request(t, serviceTestUUID(601), fixture.exporter)
	fixture.clock.set("2026-08-13T12:01:00Z")
	result, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), fixture.exporter, fixture.peer,
	)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if result.SAS == "" || result.Attempt.State != store.PairingAttemptAwaitingSAS ||
		result.Acknowledgment.Status != pairing.StatusAwaitingSAS {
		t.Fatalf("HandleRequest() result = %+v", result)
	}
	if _, err := pairing.ParseRequestAcknowledgment(result.Acknowledgment.CanonicalBytes()); err != nil {
		t.Fatalf("ParseRequestAcknowledgment() error = %v", err)
	}

	fixture.clock.set("2026-08-13T12:01:01Z")
	retried, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), fixture.exporter, fixture.peer,
	)
	if err != nil || retried.Attempt.AttemptID != result.Attempt.AttemptID ||
		retried.SAS != result.SAS {
		t.Fatalf("same-connection retry = (%+v, %v)", retried, err)
	}
	fixture.clock.set("2026-08-13T12:01:02Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), bytes.Repeat([]byte{0x99}, pairing.ExporterSize),
		fixture.peer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("cross-connection retry error = %v, want %v", err, ErrRequestRejected)
	}

	details, err := fixture.service.Attempt(context.Background(), result.Attempt.AttemptID)
	if err != nil || details.SAS != result.SAS ||
		details.Core.JoinerDeviceID != result.Core.JoinerDeviceID {
		t.Fatalf("Attempt() = (%+v, %v)", details, err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	fixture.clock.set("2026-08-13T12:02:00Z")
	if _, err := fixture.service.ConfirmLocal(
		context.Background(), result.Attempt.AttemptID, requestDigest, true,
	); !errors.Is(err, ErrAwaitingJoinerConfirmation) {
		t.Fatalf("early ConfirmLocal() error = %v, want %v", err, ErrAwaitingJoinerConfirmation)
	}

	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID, requestDigest, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:02:01Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		bytes.Repeat([]byte{0x99}, pairing.ExporterSize),
		fixture.peer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf(
			"cross-connection confirmation error = %v, want %v",
			err,
			ErrRequestRejected,
		)
	}
	remote, err := fixture.service.ConfirmRemote(
		context.Background(), confirmation.CanonicalBytes(), fixture.exporter, fixture.peer,
	)
	if err != nil || remote.Status != pairing.StatusAwaitingInviter {
		t.Fatalf("ConfirmRemote() = (%+v, %v)", remote, err)
	}
	fixture.clock.set("2026-08-13T12:02:02Z")
	confirmed, err := fixture.service.ConfirmLocal(
		context.Background(), result.Attempt.AttemptID, requestDigest, true,
	)
	if err != nil || confirmed.Attempt.State != store.PairingAttemptCompleted {
		t.Fatalf("ConfirmLocal() = (%+v, %v)", confirmed, err)
	}
	if calls, concurrent := reservations.snapshot(); calls != 1 ||
		concurrent {
		t.Fatalf(
			"boot reservation lane = (calls=%d, concurrent=%t)",
			calls,
			concurrent,
		)
	}
	sessionID, workspaceID, deviceID, bootID := reservations.binding()
	if sessionID != serviceTestSessionID ||
		workspaceID != serviceTestWorkspaceID ||
		deviceID != fixture.invite.Invite().InviterDeviceID ||
		bootID != serviceTestUUID(500) {
		t.Fatalf(
			"boot reservation binding = (%s, %s, %s, %s)",
			sessionID,
			workspaceID,
			deviceID,
			bootID,
		)
	}
	admission, found, err := fixture.state.LookupRequest(
		context.Background(),
		result.Attempt.AttemptID,
		result.Attempt.AttemptID,
	)
	if err != nil || !found ||
		admission.RequestKind != event.KindMembershipDeviceAdmitted ||
		admission.BindingClass != store.LocalBindingOperator {
		t.Fatalf(
			"durable admission reservation = (%+v, %t, %v)",
			admission,
			found,
			err,
		)
	}
	fixture.clock.set("2026-08-13T12:02:03Z")
	poll, err := fixture.service.ConfirmRemote(
		context.Background(), confirmation.CanonicalBytes(), fixture.exporter, fixture.peer,
	)
	if err != nil || poll.Status != pairing.StatusConfirmed {
		t.Fatalf("ConfirmRemote(poll) = (%+v, %v)", poll, err)
	}
	fixture.clock.set("2026-08-13T12:02:04Z")
	retried, err = fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil ||
		!bytes.Equal(
			retried.Acknowledgment.CanonicalBytes(),
			result.Acknowledgment.CanonicalBytes(),
		) {
		t.Fatalf("post-completion request retry = (%+v, %v)", retried, err)
	}

	fixture.clock.set("2026-08-13T12:03:00Z")
	processed, err := fixture.service.CleanupOneSecret(context.Background())
	if err != nil || !processed {
		t.Fatalf("CleanupOneSecret() = (%t, %v)", processed, err)
	}
	if fixture.secrets.contains(fixture.inviteReference(t)) {
		t.Fatal("consumed invite secret survived cleanup")
	}
	fixture.clock.set("2026-08-13T12:03:01Z")
	if processed, err := fixture.service.CleanupOneSecret(context.Background()); err != nil || processed {
		t.Fatalf("CleanupOneSecret(empty) = (%t, %v)", processed, err)
	}
}

func TestPairingServiceDeclineBypassesBootReservationLane(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	reservations := &recordingBootReservationLane{}
	fixture.service.reservations = reservations
	request := fixture.request(t, serviceTestUUID(609), fixture.exporter)
	fixture.clock.set("2026-08-13T12:03:10Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	fixture.clock.set("2026-08-13T12:03:11Z")
	declined, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		false,
	)
	if err != nil ||
		declined.Attempt.State != store.PairingAttemptDeclined {
		t.Fatalf("ConfirmLocal(decline) = (%+v, %v)", declined, err)
	}
	if calls, _ := reservations.snapshot(); calls != 0 {
		t.Fatalf("decline entered boot reservation lane %d times", calls)
	}
}

func TestPairingServiceProofFailuresVoidInvite(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	wrongExporter := bytes.Repeat([]byte{0x88}, pairing.ExporterSize)
	for index := 0; index < store.MaxPairingProofFailures; index++ {
		request := fixture.request(t, serviceTestUUID(610+index), fixture.exporter)
		fixture.clock.set(domain.Timestamp(fmt.Sprintf("2026-08-13T12:04:0%dZ", index)))
		_, err := fixture.service.HandleRequest(
			context.Background(), request.CanonicalBytes(), wrongExporter, fixture.peer,
		)
		if !errors.Is(err, ErrRequestRejected) {
			t.Fatalf("failed proof %d error = %v, want %v", index+1, err, ErrRequestRejected)
		}
	}
	value := fixture.invite.Invite()
	record, found, err := fixture.state.PairingInvite(context.Background(), value.InviteID)
	if err != nil || !found || record.State != store.PairingInviteProofExhausted ||
		record.ProofFailures != store.MaxPairingProofFailures {
		t.Fatalf("invite after proof failures = (%+v, %t, %v)", record, found, err)
	}
	fixture.clock.set("2026-08-13T12:05:00Z")
	processed, err := fixture.service.CleanupOneSecret(context.Background())
	if err != nil || !processed || fixture.secrets.contains(fixture.inviteReference(t)) {
		t.Fatalf("proof-exhausted cleanup = (%t, %v)", processed, err)
	}
}

func TestPairingServiceCleanupPersistsProviderFailure(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	request := fixture.request(t, serviceTestUUID(620), fixture.exporter)
	fixture.clock.set("2026-08-13T12:06:00Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), fixture.exporter, fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.secrets.setDeleteError(credentialstore.ErrLocked)
	fixture.clock.set("2026-08-13T12:06:01Z")
	processed, err := fixture.service.CleanupOneSecret(context.Background())
	if !processed || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CleanupOneSecret(failure) = (%t, %v)", processed, err)
	}
	deletion, found, err := fixture.state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found || deletion.FailureCount != 1 ||
		deletion.LastErrorCode != "credential_locked" {
		t.Fatalf("durable cleanup failure = (%+v, %t, %v)", deletion, found, err)
	}
	fixture.secrets.setDeleteError(nil)
	fixture.clock.set("2026-08-13T12:06:02Z")
	processed, err = fixture.service.CleanupOneSecret(context.Background())
	if err != nil || !processed {
		t.Fatalf("CleanupOneSecret(retry) = (%t, %v)", processed, err)
	}
}

func TestPairingServiceRejectsMismatchedPeerAndDecision(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	request := fixture.request(t, serviceTestUUID(630), fixture.exporter)
	otherKey := testPrivateKey(9)
	otherCertificate, _, err := transport.IssueIdentityCertificate(
		serviceTestSessionID, 0, otherKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	otherPeer, err := transport.ParseIdentityCertificate(otherCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:07:00Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), fixture.exporter, otherPeer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("mismatched peer error = %v, want %v", err, ErrRequestRejected)
	}
	fixture.clock.set("2026-08-13T12:07:01Z")
	result, err := fixture.service.HandleRequest(
		context.Background(), request.CanonicalBytes(), fixture.exporter, fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := [32]byte(result.Attempt.RequestDigest)
	wrongDigest[0] ^= 1
	confirmation, err := pairing.NewConfirmation(result.Attempt.AttemptID, wrongDigest, true)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:07:02Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(), confirmation.CanonicalBytes(), fixture.exporter, fixture.peer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("wrong decision digest error = %v, want %v", err, ErrRequestRejected)
	}
}

func TestPairingServiceReportsFinalizingUntilDurableCompletion(t *testing.T) {
	t.Parallel()

	finalizer := &controlledFinalizer{err: errors.New("consensus unavailable")}
	fixture := newServiceFixtureWithFinalizer(t, finalizer)
	request := fixture.request(t, serviceTestUUID(640), fixture.exporter)
	fixture.clock.set("2026-08-13T12:08:00Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:08:01Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	changedDecision, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		changedDecision.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("changed remote decision error = %v, want %v", err, ErrRequestRejected)
	}
	fixture.clock.set("2026-08-13T12:08:02Z")
	details, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if !errors.Is(err, ErrFinalizationPending) ||
		details.Attempt.State != store.PairingAttemptFinalizing {
		t.Fatalf("pending ConfirmLocal() = (%+v, %v)", details, err)
	}
	poll, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil || poll.Status != pairing.StatusFinalizing {
		t.Fatalf("pending poll = (%+v, %v)", poll, err)
	}

	finalizer.setError(nil)
	fixture.clock.set("2026-08-13T12:08:03Z")
	details, err = fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil || details.Attempt.State != store.PairingAttemptCompleted {
		t.Fatalf("retried ConfirmLocal() = (%+v, %v)", details, err)
	}
	poll, err = fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil || poll.Status != pairing.StatusConfirmed || finalizer.callCount() != 2 {
		t.Fatalf("completed poll = (%+v, %v), finalizer calls = %d", poll, err, finalizer.callCount())
	}
}

func TestPairingServiceDurableFinalizationRejectionIsTerminal(t *testing.T) {
	t.Parallel()

	finalizer := &controlledFinalizer{
		err: errors.Join(
			ErrFinalizationRejected,
			errors.New("admission rejected"),
		),
	}
	fixture := newServiceFixtureWithFinalizer(t, finalizer)
	request := fixture.request(t, serviceTestUUID(645), fixture.exporter)
	fixture.clock.set("2026-08-13T12:08:10Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:08:11Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:08:12Z")
	details, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil || details.Attempt.State != store.PairingAttemptRevoked {
		t.Fatalf("ConfirmLocal() = (%+v, %v)", details, err)
	}
	poll, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil || poll.Status != pairing.StatusRevoked {
		t.Fatalf("rejected poll = (%+v, %v)", poll, err)
	}
	if pending, found, err := fixture.state.NextPairingFinalization(
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

func TestPairingServiceFinalizationRejectionDoesNotStarveLaterAttempt(
	t *testing.T,
) {
	t.Parallel()

	finalizer := &controlledFinalizer{err: errors.New("consensus unavailable")}
	fixture := newServiceFixtureWithFinalizer(t, finalizer)
	secondInvite := fixture.addInvite(t, serviceTestUUID(646))
	attempts := make([]store.PairingAttemptRecord, 0, 2)
	for index, invite := range []pairing.SignedInvite{
		fixture.invite,
		secondInvite,
	} {
		request := fixture.requestForInvite(
			t,
			invite,
			serviceTestUUID(647+index),
			fixture.exporter,
		)
		fixture.clock.set(domain.Timestamp(fmt.Sprintf(
			"2026-08-13T12:08:%02dZ",
			20+index*3,
		)))
		result, err := fixture.service.HandleRequest(
			context.Background(),
			request.CanonicalBytes(),
			fixture.exporter,
			fixture.peer,
		)
		if err != nil {
			t.Fatalf("HandleRequest(%d) error = %v", index+1, err)
		}
		requestDigest := [32]byte(result.Attempt.RequestDigest)
		confirmation, err := pairing.NewConfirmation(
			result.Attempt.AttemptID,
			requestDigest,
			true,
		)
		if err != nil {
			t.Fatal(err)
		}
		fixture.clock.set(domain.Timestamp(fmt.Sprintf(
			"2026-08-13T12:08:%02dZ",
			21+index*3,
		)))
		if _, err := fixture.service.ConfirmRemote(
			context.Background(),
			confirmation.CanonicalBytes(),
			fixture.exporter,
			fixture.peer,
		); err != nil {
			t.Fatalf("ConfirmRemote(%d) error = %v", index+1, err)
		}
		fixture.clock.set(domain.Timestamp(fmt.Sprintf(
			"2026-08-13T12:08:%02dZ",
			22+index*3,
		)))
		details, err := fixture.service.ConfirmLocal(
			context.Background(),
			result.Attempt.AttemptID,
			requestDigest,
			true,
		)
		if !errors.Is(err, ErrFinalizationPending) ||
			details.Attempt.State != store.PairingAttemptFinalizing {
			t.Fatalf("ConfirmLocal(%d) = (%+v, %v)", index+1, details, err)
		}
		attempts = append(attempts, details.Attempt)
	}

	finalizer.setError(errors.Join(
		ErrFinalizationRejected,
		errors.New("admission rejected"),
	))
	fixture.clock.set("2026-08-13T12:08:30Z")
	if retry, err := fixture.service.maintainOnce(
		context.Background(),
	); err != nil || retry {
		t.Fatalf("maintainOnce(rejection) = (%t, %v)", retry, err)
	}
	first, found, err := fixture.state.PairingAttempt(
		context.Background(),
		attempts[0].AttemptID,
	)
	if err != nil || !found || first.State != store.PairingAttemptRevoked {
		t.Fatalf("first attempt after rejection = (%+v, %t, %v)", first, found, err)
	}
	pending, found, err := fixture.state.NextPairingFinalization(
		context.Background(),
	)
	if err != nil || !found || pending.AttemptID != attempts[1].AttemptID {
		t.Fatalf("next attempt after rejection = (%+v, %t, %v)", pending, found, err)
	}

	finalizer.setError(nil)
	fixture.clock.set("2026-08-13T12:08:31Z")
	if retry, err := fixture.service.maintainOnce(
		context.Background(),
	); err != nil || retry {
		t.Fatalf("maintainOnce(success) = (%t, %v)", retry, err)
	}
	second, found, err := fixture.state.PairingAttempt(
		context.Background(),
		attempts[1].AttemptID,
	)
	if err != nil || !found || second.State != store.PairingAttemptCompleted {
		t.Fatalf("second attempt after completion = (%+v, %t, %v)", second, found, err)
	}
	if finalizer.callCount() != 4 {
		t.Fatalf("finalizer calls = %d, want 4", finalizer.callCount())
	}
}

func TestPairingServiceRequiresRecoveryAndStopsCleanly(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	inviteValue := fixture.invite.Invite()
	defer clear(inviteValue.Secret[:])
	service, err := New(Options{
		State: fixture.state, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: successfulFinalizer{},
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, serviceTestUUID(650), fixture.exporter)
	if _, err := service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); !errors.Is(err, ErrNotRecovered) {
		t.Fatalf("pre-recovery HandleRequest() error = %v", err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatalf("duplicate Recover() error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Attempt(
		context.Background(),
		serviceTestUUID(650),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close Attempt() error = %v", err)
	}
}

func TestPairingServiceRestartResumesFinalization(t *testing.T) {
	t.Parallel()

	firstFinalizer := &controlledFinalizer{err: errors.New("interrupted")}
	fixture := newServiceFixtureWithFinalizer(t, firstFinalizer)
	request := fixture.request(t, serviceTestUUID(660), fixture.exporter)
	fixture.clock.set("2026-08-13T12:09:00Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:01Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:02Z")
	if _, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	); !errors.Is(err, ErrFinalizationPending) {
		t.Fatalf("ConfirmLocal() error = %v", err)
	}
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: fixture.databasePath},
	)
	if err != nil {
		t.Fatalf("store.Open(restart) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedState := reopened.LocalState()

	inviteValue := fixture.invite.Invite()
	defer clear(inviteValue.Secret[:])
	restarted, err := New(Options{
		State: reopenedState, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: successfulFinalizer{},
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	fixture.clock.set("2026-08-13T12:09:03Z")
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		attempt, found, err := reopenedState.PairingAttempt(
			context.Background(),
			result.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if found && attempt.State == store.PairingAttemptCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("finalization did not resume: (%+v, %t)", attempt, found)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPairingServiceRestartRepeatsFinalizerAfterMarkerFailure(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	markerFailure := errors.New("completion marker unavailable")
	failingState := &failCompletionState{
		State: fixture.state,
		err:   markerFailure,
	}
	finalizer := &controlledFinalizer{}
	inviteValue := fixture.invite.Invite()
	defer clear(inviteValue.Secret[:])
	first, err := New(Options{
		State: failingState, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: finalizer,
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if err := first.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}

	request := fixture.request(t, serviceTestUUID(665), fixture.exporter)
	fixture.clock.set("2026-08-13T12:09:10Z")
	result, err := first.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:11Z")
	if _, err := first.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:12Z")
	if _, err := first.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ConfirmLocal(marker failure) error = %v", err)
	}
	pending, found, err := fixture.state.PairingAttempt(
		context.Background(),
		result.Attempt.AttemptID,
	)
	if err != nil || !found || pending.State != store.PairingAttemptFinalizing ||
		finalizer.callCount() != 1 {
		t.Fatalf(
			"pending marker state = (%+v, %t, %v), finalizer calls = %d",
			pending,
			found,
			err,
			finalizer.callCount(),
		)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: fixture.databasePath},
	)
	if err != nil {
		t.Fatalf("store.Open(restart) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedState := reopened.LocalState()
	restarted, err := New(Options{
		State: reopenedState, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: finalizer,
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	fixture.clock.set("2026-08-13T12:09:13Z")
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		attempt, found, err := reopenedState.PairingAttempt(
			context.Background(),
			result.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if found && attempt.State == store.PairingAttemptCompleted {
			if finalizer.callCount() != 2 {
				t.Fatalf("finalizer calls = %d, want 2", finalizer.callCount())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("finalization did not resume: (%+v, %t)", attempt, found)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPairingServiceRestartRepeatsRejectedFinalizerAfterMarkerFailure(
	t *testing.T,
) {
	t.Parallel()

	fixture := newServiceFixture(t)
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	markerFailure := errors.New("rejection marker unavailable")
	failingState := &failRejectionState{
		State: fixture.state,
		err:   markerFailure,
	}
	finalizer := &controlledFinalizer{
		err: errors.Join(
			ErrFinalizationRejected,
			errors.New("admission rejected"),
		),
	}
	inviteValue := fixture.invite.Invite()
	defer clear(inviteValue.Secret[:])
	first, err := New(Options{
		State: failingState, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: finalizer,
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if err := first.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}

	request := fixture.request(t, serviceTestUUID(666), fixture.exporter)
	fixture.clock.set("2026-08-13T12:09:20Z")
	result, err := first.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [32]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:21Z")
	if _, err := first.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:09:22Z")
	if _, err := first.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ConfirmLocal(marker failure) error = %v", err)
	}
	pending, found, err := fixture.state.PairingAttempt(
		context.Background(),
		result.Attempt.AttemptID,
	)
	if err != nil || !found || pending.State != store.PairingAttemptFinalizing ||
		finalizer.callCount() != 1 {
		t.Fatalf(
			"pending rejection state = (%+v, %t, %v), finalizer calls = %d",
			pending,
			found,
			err,
			finalizer.callCount(),
		)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: fixture.databasePath},
	)
	if err != nil {
		t.Fatalf("store.Open(restart) error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedState := reopened.LocalState()
	restarted, err := New(Options{
		State: reopenedState, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: finalizer,
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	fixture.clock.set("2026-08-13T12:09:23Z")
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		attempt, found, err := reopenedState.PairingAttempt(
			context.Background(),
			result.Attempt.AttemptID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if found && attempt.State == store.PairingAttemptRevoked {
			if finalizer.callCount() != 2 {
				t.Fatalf("finalizer calls = %d, want 2", finalizer.callCount())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejection did not resume: (%+v, %t)", attempt, found)
		}
		time.Sleep(time.Millisecond)
	}
	poll, err := restarted.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil || poll.Status != pairing.StatusRevoked {
		t.Fatalf("restarted rejected poll = (%+v, %v)", poll, err)
	}
}

func TestPairingServiceFinalizerBoundaryRaceIsSuperseded(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		finalizerErr error
	}{
		{name: "durable success"},
		{
			name:         "transient failure",
			finalizerErr: errors.New("consensus unavailable"),
		},
		{
			name: "durable rejection",
			finalizerErr: errors.Join(
				ErrFinalizationRejected,
				errors.New("admission rejected"),
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			finalizer := newBlockingFinalizer(test.finalizerErr)
			fixture := newServiceFixtureWithFinalizer(t, finalizer)
			superseding := &supersedingState{
				State: fixture.state,
				stale: make(map[domain.UUIDv7]struct{}),
			}
			if err := fixture.service.Close(); err != nil {
				t.Fatal(err)
			}
			inviteValue := fixture.invite.Invite()
			defer clear(inviteValue.Secret[:])
			service, err := New(Options{
				State: superseding, Secrets: fixture.secrets,
				Authorizer:        fixture.authorizer,
				IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
				Clock:             fixture.clock.read, Finalizer: finalizer,
				Reservations: noOpBootReservationLane{},
				Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			fixture.service = service
			request := fixture.request(t, serviceTestUUID(667), fixture.exporter)
			fixture.clock.set("2026-08-13T12:09:30Z")
			result, err := fixture.service.HandleRequest(
				context.Background(),
				request.CanonicalBytes(),
				fixture.exporter,
				fixture.peer,
			)
			if err != nil {
				t.Fatal(err)
			}
			requestDigest := [32]byte(result.Attempt.RequestDigest)
			confirmation, err := pairing.NewConfirmation(
				result.Attempt.AttemptID,
				requestDigest,
				true,
			)
			if err != nil {
				t.Fatal(err)
			}
			fixture.clock.set("2026-08-13T12:09:31Z")
			if _, err := fixture.service.ConfirmRemote(
				context.Background(),
				confirmation.CanonicalBytes(),
				fixture.exporter,
				fixture.peer,
			); err != nil {
				t.Fatal(err)
			}

			type confirmationOutcome struct {
				details AttemptDetails
				err     error
			}
			outcome := make(chan confirmationOutcome, 1)
			fixture.clock.set("2026-08-13T12:09:32Z")
			go func() {
				details, err := fixture.service.ConfirmLocal(
					context.Background(),
					result.Attempt.AttemptID,
					requestDigest,
					true,
				)
				outcome <- confirmationOutcome{details: details, err: err}
			}()
			select {
			case <-finalizer.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("finalizer did not start")
			}
			if err := superseding.supersede(
				context.Background(),
				result.Attempt.AttemptID,
			); err != nil {
				t.Fatalf("supersede attempt: %v", err)
			}
			close(finalizer.release)

			var completed confirmationOutcome
			select {
			case completed = <-outcome:
			case <-time.After(2 * time.Second):
				t.Fatal("confirmation did not finish")
			}
			if completed.err != nil ||
				completed.details.Attempt.State != store.PairingAttemptRevoked {
				t.Fatalf(
					"superseded confirmation = (%+v, %v)",
					completed.details,
					completed.err,
				)
			}
			stored, found, err := fixture.state.PairingAttempt(
				context.Background(),
				result.Attempt.AttemptID,
			)
			if err != nil || !found || stored.State != store.PairingAttemptRevoked {
				t.Fatalf("durable superseded attempt = (%+v, %t, %v)", stored, found, err)
			}
			if retry, err := fixture.service.maintainOnce(
				context.Background(),
			); err != nil || retry {
				t.Fatalf("maintainOnce() = (%t, %v)", retry, err)
			}
		})
	}
}

func TestPairingServiceMaintenanceRetriesSecretDeletion(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	request := fixture.request(t, serviceTestUUID(670), fixture.exporter)
	fixture.clock.set("2026-08-13T12:10:00Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.secrets.setDeleteError(credentialstore.ErrLocked)
	inviteValue := fixture.invite.Invite()
	defer clear(inviteValue.Secret[:])
	restarted, err := New(Options{
		State: fixture.state, Secrets: fixture.secrets,
		Authorizer:        fixture.authorizer,
		IdentityPublicKey: inviteValue.InviterIdentityPublicKey[:],
		Clock:             fixture.clock.read, Finalizer: successfulFinalizer{},
		Reservations: noOpBootReservationLane{},
		Nonvoters:    noOpNonvoterGuard{}, MaintenanceInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	fixture.clock.set("2026-08-13T12:10:01Z")
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	deletion, found, err := fixture.state.NextPairingSecretDeletion(context.Background())
	if err != nil || !found || deletion.FailureCount != 1 ||
		deletion.LastErrorCode != "credential_locked" {
		t.Fatalf("startup cleanup failure = (%+v, %t, %v)", deletion, found, err)
	}
	fixture.secrets.setDeleteError(nil)
	deadline := time.Now().Add(2 * time.Second)
	for fixture.secrets.contains(fixture.inviteReference(t)) {
		if time.Now().After(deadline) {
			t.Fatal("maintenance did not delete queued invite secret")
		}
		time.Sleep(time.Millisecond)
	}
	if err := restarted.FatalError(); err != nil {
		t.Fatalf("FatalError() = %v", err)
	}
}

func TestPairingServiceGuardsExistingDeviceLiveConfiguration(t *testing.T) {
	t.Parallel()

	guard := &controlledNonvoterGuard{err: errors.New("still in live configuration")}
	fixture := newServiceFixtureWithMode(
		t,
		successfulFinalizer{},
		guard,
		pairing.ModeRebootstrap,
	)
	request := fixture.request(t, serviceTestUUID(680), fixture.exporter)
	fixture.clock.set("2026-08-13T12:11:00Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("guarded HandleRequest() error = %v", err)
	}
	inviteValue := fixture.invite.Invite()
	inviteID := inviteValue.InviteID
	clear(inviteValue.Secret[:])
	record, found, err := fixture.state.PairingInvite(
		context.Background(),
		inviteID,
	)
	if err != nil || !found || record.State != store.PairingInviteOutstanding {
		t.Fatalf("invite after guard rejection = (%+v, %t, %v)", record, found, err)
	}
	guard.setError(nil)
	fixture.clock.set("2026-08-13T12:11:01Z")
	if _, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	); err != nil {
		t.Fatalf("eligible HandleRequest() error = %v", err)
	}
	if calls, releases := guard.counts(); calls != 2 || releases != 1 {
		t.Fatalf("guard calls/releases = %d/%d, want 2/1", calls, releases)
	}
}

func newServiceFixture(t testing.TB) serviceFixture {
	t.Helper()
	return newServiceFixtureWithFinalizer(t, successfulFinalizer{})
}

func newServiceFixtureWithFinalizer(
	t testing.TB,
	finalizer Finalizer,
) serviceFixture {
	t.Helper()
	return newServiceFixtureWithMode(
		t,
		finalizer,
		noOpNonvoterGuard{},
		pairing.ModeNew,
	)
}

func newServiceFixtureWithMode(
	t testing.TB,
	finalizer Finalizer,
	nonvoters SettledNonvoterGuard,
	mode pairing.Mode,
) serviceFixture {
	t.Helper()
	ctx := context.Background()
	inviterKey := testPrivateKey(1)
	inviterPublicKey := inviterKey.Public().(ed25519.PublicKey)
	inviterID, err := device.DeriveID(inviterPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	joinerIdentityKey := testPrivateKey(2)
	joinerPublicKey := joinerIdentityKey.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	joinerEpochKey := testPrivateKey(3)
	devices := []device.Device{{
		ID: inviterID, Role: device.RoleOwner, IdentityPublicKey: inviterPublicKey,
		DaemonVersion: "1.0.0", MaxApplyLevel: 1, Status: device.StatusActive, EntityVersion: 1,
	}}
	if mode != pairing.ModeNew {
		status := device.StatusActive
		if mode == pairing.ModeReadmission {
			status = device.StatusRequiresReadmission
		}
		devices = append(devices, device.Device{
			ID: joinerID, Role: device.RoleEditor, IdentityPublicKey: joinerPublicKey,
			DaemonVersion: "1.0.0", MaxApplyLevel: 1, Status: status, EntityVersion: 1,
		})
	}
	target, err := voterset.New(
		serviceTestSessionID,
		[]domain.DeviceID{inviterID},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "session", "state.db")
	database, err := store.Open(ctx, store.Options{Path: databasePath})
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Initialize(ctx, store.InitialState{
		SessionID: serviceTestSessionID, WorkspaceID: serviceTestWorkspaceID,
		GenesisJSON: []byte(serviceTestGenesis), DigestVersion: 1, ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			Devices: devices,
			VoterSet: []voterset.Set{
				target,
			},
		},
	}); err != nil {
		t.Fatalf("Store.Initialize() error = %v", err)
	}
	secret := [pairing.InviteSecretSize]byte{}
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	genesisDigest, err := chain.GenesisDigest([]byte(serviceTestGenesis))
	if err != nil {
		t.Fatal(err)
	}
	inviteValue := pairing.Invite{
		InviteID: serviceTestUUID(501), SessionID: serviceTestSessionID,
		WorkspaceID: serviceTestWorkspaceID, RecoveryGeneration: 0,
		CreatedAt: "2026-08-13T12:00:00Z", ExpiresAt: "2026-08-13T12:15:00Z",
		Secret: secret, InviterDeviceID: inviterID, Mode: mode,
		Role: device.RoleEditor, InitialCredentialEpoch: 1,
		Endpoints: []pairing.Endpoint{{IP: netip.MustParseAddr("192.0.2.10"), Port: 47831}},
	}
	copy(inviteValue.InviterIdentityPublicKey[:], inviterPublicKey)
	copy(inviteValue.SignedGenesisDigest[:], genesisDigest[:])
	if mode != pairing.ModeNew {
		subject := joinerID
		inviteValue.SubjectDeviceID = &subject
	}
	if mode == pairing.ModeReadmission {
		version := uint64(1)
		inviteValue.ExpectedEntityVersion = &version
	}
	invite, err := pairing.SignInvite(inviteValue, inviterKey)
	clear(inviteValue.Secret[:])
	if err != nil {
		t.Fatal(err)
	}
	localState := database.LocalState()
	record, _, err := localState.ReservePairingInvite(ctx, invite)
	if err != nil {
		t.Fatal(err)
	}
	secrets := newFakeSecretStore()
	reference, err := credentialstore.InviteReference(serviceTestSessionID, record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	secrets.put(reference, secret[:])
	clear(secret[:])
	if _, _, err := localState.ActivatePairingInvite(ctx, record.InviteID, record.InviteDigest); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: "2026-08-13T12:00:00Z"}
	localAuthority, err := event.NewLocalAuthority(
		inviterID,
		serviceTestUUID(500),
	)
	if err != nil {
		t.Fatal(err)
	}
	operatorOrigin, err := localAuthority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewAdmissionAuthorizer(AdmissionAuthorizerOptions{
		DeviceID:           inviterID,
		OriginBootID:       serviceTestUUID(500),
		IdentityPrivateKey: inviterKey,
		OperatorOrigin:     operatorOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		State: localState, Secrets: secrets, IdentityPublicKey: inviterPublicKey,
		Clock: clock.read, Authorizer: authorizer, Finalizer: finalizer,
		Reservations: noOpBootReservationLane{},
		Nonvoters:    nonvoters, MaintenanceInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	certificate, _, err := transport.IssueIdentityCertificate(
		serviceTestSessionID, 0, joinerIdentityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := transport.ParseIdentityCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{
		service: service, authorizer: authorizer,
		database: database, databasePath: databasePath,
		state: localState, secrets: secrets, clock: clock, invite: invite,
		joinerIdentityKey: joinerIdentityKey, joinerEpochKey: joinerEpochKey, peer: peer,
		exporter: bytes.Repeat([]byte{0x55}, pairing.ExporterSize),
	}
}

func (fixture serviceFixture) request(
	t testing.TB,
	attemptID domain.UUIDv7,
	exporter []byte,
) pairing.Request {
	t.Helper()
	return fixture.requestForInvite(t, fixture.invite, attemptID, exporter)
}

func (fixture serviceFixture) requestForInvite(
	t testing.TB,
	invite pairing.SignedInvite,
	attemptID domain.UUIDv7,
	exporter []byte,
) pairing.Request {
	t.Helper()
	joinerPublicKey := fixture.joinerIdentityKey.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := credential.SignBinding(
		serviceTestSessionID, joinerID, 1,
		fixture.joinerEpochKey.Public().(ed25519.PublicKey), fixture.joinerIdentityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	coreValue := pairing.RequestCore{
		AttemptID: attemptID, JoinerDeviceID: joinerID, DaemonVersion: "1.2.3",
		MaxApplyLevel: 1, InitialEpochBinding: binding,
	}
	copy(coreValue.JoinerIdentityPublicKey[:], joinerPublicKey)
	core, err := pairing.NewRequestCore(coreValue)
	if err != nil {
		t.Fatal(err)
	}
	request, err := pairing.BuildRequest(invite, core, exporter)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func (fixture serviceFixture) addInvite(
	t testing.TB,
	inviteID domain.UUIDv7,
) pairing.SignedInvite {
	t.Helper()
	value := fixture.invite.Invite()
	defer clear(value.Secret[:])
	value.InviteID = inviteID
	for index := range value.Secret {
		value.Secret[index] = byte(index + 101)
	}
	invite, err := pairing.SignInvite(value, testPrivateKey(1))
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := fixture.state.ReservePairingInvite(
		context.Background(),
		invite,
	)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := credentialstore.InviteReference(record.SessionID, record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.secrets.put(reference, value.Secret[:])
	if _, _, err := fixture.state.ActivatePairingInvite(
		context.Background(),
		record.InviteID,
		record.InviteDigest,
	); err != nil {
		t.Fatal(err)
	}
	return invite
}

func (fixture serviceFixture) inviteReference(t testing.TB) credentialstore.Reference {
	t.Helper()
	value := fixture.invite.Invite()
	defer clear(value.Secret[:])
	reference, err := credentialstore.InviteReference(value.SessionID, value.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func serviceTestUUID(suffix int) domain.UUIDv7 {
	return domain.UUIDv7(fmt.Sprintf("01890f47-3e72-7000-8000-%012x", suffix))
}

func testPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

type testClock struct {
	mu  sync.RWMutex
	now domain.Timestamp
}

func (clock *testClock) read() domain.Timestamp {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *testClock) set(now domain.Timestamp) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

type successfulFinalizer struct{}

func (successfulFinalizer) FinalizePairing(context.Context, AttemptDetails) error {
	return nil
}

type controlledFinalizer struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (finalizer *controlledFinalizer) FinalizePairing(
	context.Context,
	AttemptDetails,
) error {
	finalizer.mu.Lock()
	defer finalizer.mu.Unlock()
	finalizer.calls++
	return finalizer.err
}

func (finalizer *controlledFinalizer) setError(err error) {
	finalizer.mu.Lock()
	finalizer.err = err
	finalizer.mu.Unlock()
}

func (finalizer *controlledFinalizer) callCount() int {
	finalizer.mu.Lock()
	defer finalizer.mu.Unlock()
	return finalizer.calls
}

type failCompletionState struct {
	State
	mu     sync.Mutex
	err    error
	failed bool
}

func (state *failCompletionState) CompletePairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
	completedAt domain.Timestamp,
) (store.PairingAttemptRecord, bool, error) {
	state.mu.Lock()
	if !state.failed {
		state.failed = true
		err := state.err
		state.mu.Unlock()
		return store.PairingAttemptRecord{}, false, err
	}
	state.mu.Unlock()
	return state.State.CompletePairingFinalization(ctx, attemptID, completedAt)
}

type failRejectionState struct {
	State
	mu     sync.Mutex
	err    error
	failed bool
}

func (state *failRejectionState) RejectPairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (store.PairingAttemptRecord, bool, error) {
	state.mu.Lock()
	if !state.failed {
		state.failed = true
		err := state.err
		state.mu.Unlock()
		return store.PairingAttemptRecord{}, false, err
	}
	state.mu.Unlock()
	return state.State.RejectPairingFinalization(ctx, attemptID)
}

type supersedingState struct {
	State
	mu    sync.Mutex
	stale map[domain.UUIDv7]struct{}
}

func (state *supersedingState) supersede(
	ctx context.Context,
	attemptID domain.UUIDv7,
) error {
	if _, _, err := state.State.RejectPairingFinalization(
		ctx,
		attemptID,
	); err != nil {
		return err
	}
	state.mu.Lock()
	state.stale[attemptID] = struct{}{}
	state.mu.Unlock()
	return nil
}

func (state *supersedingState) CompletePairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
	completedAt domain.Timestamp,
) (store.PairingAttemptRecord, bool, error) {
	if state.isStale(attemptID) {
		return store.PairingAttemptRecord{}, false, store.ErrPairingLineageMismatch
	}
	return state.State.CompletePairingFinalization(ctx, attemptID, completedAt)
}

func (state *supersedingState) RejectPairingFinalization(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (store.PairingAttemptRecord, bool, error) {
	if state.isStale(attemptID) {
		return store.PairingAttemptRecord{}, false, store.ErrPairingLineageMismatch
	}
	return state.State.RejectPairingFinalization(ctx, attemptID)
}

func (state *supersedingState) isStale(attemptID domain.UUIDv7) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	_, ok := state.stale[attemptID]
	return ok
}

type blockingFinalizer struct {
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func newBlockingFinalizer(err error) *blockingFinalizer {
	return &blockingFinalizer{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		err:     err,
	}
}

func (finalizer *blockingFinalizer) FinalizePairing(
	ctx context.Context,
	_ AttemptDetails,
) error {
	finalizer.once.Do(func() { close(finalizer.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finalizer.release:
		return finalizer.err
	}
}

type noOpNonvoterGuard struct{}

type noOpBootReservationLane struct{}

type recordingBootReservationLane struct {
	mu          sync.Mutex
	calls       int
	active      bool
	concurrent  bool
	sessionID   domain.UUIDv7
	workspaceID domain.UUIDv4
	deviceID    domain.DeviceID
	bootID      domain.UUIDv7
}

func (lane *recordingBootReservationLane) RunOrderedBootReservation(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	operation func(context.Context) error,
) error {
	lane.mu.Lock()
	lane.calls++
	lane.sessionID = sessionID
	lane.workspaceID = workspaceID
	lane.deviceID = deviceID
	lane.bootID = bootID
	if lane.active {
		lane.concurrent = true
	}
	lane.active = true
	lane.mu.Unlock()
	defer func() {
		lane.mu.Lock()
		lane.active = false
		lane.mu.Unlock()
	}()
	return operation(ctx)
}

func (lane *recordingBootReservationLane) snapshot() (int, bool) {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	return lane.calls, lane.concurrent
}

func (lane *recordingBootReservationLane) binding() (
	domain.UUIDv7,
	domain.UUIDv4,
	domain.DeviceID,
	domain.UUIDv7,
) {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	return lane.sessionID, lane.workspaceID, lane.deviceID, lane.bootID
}

func (noOpBootReservationLane) RunOrderedBootReservation(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	operation func(context.Context) error,
) error {
	if ctx == nil ||
		operation == nil ||
		!sessionID.Valid() ||
		!workspaceID.Valid() ||
		!deviceID.Valid() ||
		!bootID.Valid() {
		return ErrInvalidOptions
	}
	return operation(ctx)
}

func (noOpNonvoterGuard) AcquireSettledNonvoter(
	context.Context,
	domain.DeviceID,
) (func(), error) {
	return func() {}, nil
}

type controlledNonvoterGuard struct {
	mu       sync.Mutex
	err      error
	calls    int
	releases int
}

func (guard *controlledNonvoterGuard) AcquireSettledNonvoter(
	context.Context,
	domain.DeviceID,
) (func(), error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.calls++
	if guard.err != nil {
		return nil, guard.err
	}
	return func() {
		guard.mu.Lock()
		guard.releases++
		guard.mu.Unlock()
	}, nil
}

func (guard *controlledNonvoterGuard) setError(err error) {
	guard.mu.Lock()
	guard.err = err
	guard.mu.Unlock()
}

func (guard *controlledNonvoterGuard) counts() (int, int) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.calls, guard.releases
}

type fakeSecretStore struct {
	mu        sync.Mutex
	values    map[string][]byte
	deleteErr error
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{values: make(map[string][]byte)}
}

func (secrets *fakeSecretStore) Get(
	_ context.Context,
	reference credentialstore.Reference,
) ([]byte, error) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	value, ok := secrets.values[reference.String()]
	if !ok {
		return nil, credentialstore.ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (secrets *fakeSecretStore) Delete(
	_ context.Context,
	reference credentialstore.Reference,
) error {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	if secrets.deleteErr != nil {
		return secrets.deleteErr
	}
	if value, ok := secrets.values[reference.String()]; ok {
		clear(value)
		delete(secrets.values, reference.String())
	}
	return nil
}

func (secrets *fakeSecretStore) put(reference credentialstore.Reference, value []byte) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	secrets.values[reference.String()] = bytes.Clone(value)
}

func (secrets *fakeSecretStore) contains(reference credentialstore.Reference) bool {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	_, ok := secrets.values[reference.String()]
	return ok
}

func (secrets *fakeSecretStore) setDeleteError(err error) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	secrets.deleteErr = err
}
