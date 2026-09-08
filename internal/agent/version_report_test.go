package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestBootOriginVersionReportPrecedesHistoricalBootMutation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	olderBootID := domain.UUIDv7(
		"018f47de-89ab-7def-8123-0123456789ac",
	)
	prior := reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		olderBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	recorder := &recordingCheckpointConsensus{
		delegate:  harness.consensus,
		completed: make(chan struct{}),
	}
	harness.boot.consensus = recorder

	reservation, err := harness.boot.ReserveVersionReport(
		bootOriginTestContext(t),
		"0.2.0",
		1,
		1,
	)
	if err != nil {
		t.Fatalf("ReserveVersionReport(): %v", err)
	}
	outcome, err := harness.boot.AwaitVersionReport(
		bootOriginTestContext(t),
		reservation,
	)
	if err != nil {
		t.Fatalf("AwaitVersionReport(): %v", err)
	}
	if outcome.Status != store.OutcomeAccepted {
		t.Fatalf("version-report outcome = %#v", outcome)
	}
	proposals := recorder.proposals()
	if len(proposals) != 1 {
		t.Fatalf("proposals before barrier release = %d, want 1", len(proposals))
	}
	first, err := event.ParseAndVerify(
		proposals[0],
		event.VerificationContext{
			SessionID:         agentTestSessionID,
			WorkspaceID:       agentTestWorkspaceID,
			IdentityPublicKey: harness.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Proposal().Kind != event.KindMembershipVersionReported {
		t.Fatalf("first proposal kind = %s", first.Proposal().Kind)
	}
	current, found, err := harness.local.LookupRequest(
		bootOriginTestContext(t),
		prior.ClientInstanceID,
		prior.RequestID,
	)
	if err != nil || !found || current.State == store.LocalRequestResolved {
		t.Fatalf(
			"historical request before barrier release = (%#v, %t, %v)",
			current,
			found,
			err,
		)
	}

	if err := harness.boot.CompleteVersionReport(
		bootOriginTestContext(t),
		reservation,
	); err != nil {
		t.Fatalf("CompleteVersionReport(): %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, found, err = harness.local.LookupRequest(
			context.Background(),
			prior.ClientInstanceID,
			prior.RequestID,
		)
		if err == nil &&
			found &&
			current.State == store.LocalRequestResolved {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil ||
		!found ||
		current.State != store.LocalRequestResolved ||
		current.Outcome == nil ||
		current.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"historical request after barrier release = (%#v, %t, %v)",
			current,
			found,
			err,
		)
	}
	proposals = recorder.proposals()
	if len(proposals) != 2 {
		t.Fatalf("final proposal count = %d, want 2", len(proposals))
	}
	second, err := event.ParseAndVerify(
		proposals[1],
		event.VerificationContext{
			SessionID:         agentTestSessionID,
			WorkspaceID:       agentTestWorkspaceID,
			IdentityPublicKey: harness.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.Proposal().EventID != prior.EventID {
		t.Fatalf(
			"second proposal event = %s, want %s",
			second.Proposal().EventID,
			prior.EventID,
		)
	}
}

func TestBootOriginVersionReportResumesPendingPriorBootReservation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	blocked := &cancellationBlockingConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
	}
	harness.boot.consensus = blocked
	reservation, err := harness.boot.ReserveVersionReport(
		bootOriginTestContext(t),
		"0.2.0",
		1,
		1,
	)
	if err != nil {
		t.Fatalf("ReserveVersionReport(first boot): %v", err)
	}
	harness.boot.mu.Lock()
	workerStarted := harness.boot.workerStarted
	harness.boot.mu.Unlock()
	if workerStarted {
		t.Fatal("version-report reservation started factory-unsafe background work")
	}
	awaitDone := make(chan error, 1)
	go func() {
		_, awaitErr := harness.boot.AwaitVersionReport(
			context.Background(),
			reservation,
		)
		awaitDone <- awaitErr
	}()
	select {
	case <-blocked.entered:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("first-boot report did not enter forwarding")
	}
	if err := harness.boot.BeginClose(); err != nil {
		t.Fatal(err)
	}
	if err := harness.boot.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-awaitDone:
		if !errors.Is(err, ErrClosed) &&
			!errors.Is(err, context.Canceled) {
			t.Fatalf("first-boot AwaitVersionReport() error = %v", err)
		}
	case <-bootOriginTestContext(t).Done():
		t.Fatal("first-boot AwaitVersionReport() did not stop")
	}

	authority, err := event.NewLocalAuthority(
		harness.deviceID,
		bootOriginTestNextBootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	daemonBinding, err := authority.DaemonBinding()
	if err != nil {
		t.Fatal(err)
	}
	operatorBinding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewBootOrigin(BootOriginOptions{
		Consensus:          harness.consensus,
		LocalState:         harness.local,
		SessionID:          agentTestSessionID,
		WorkspaceID:        agentTestWorkspaceID,
		DeviceID:           harness.deviceID,
		OriginBootID:       bootOriginTestNextBootID,
		IdentityPrivateKey: harness.private,
		DaemonOrigin:       daemonBinding,
		OperatorOrigin:     operatorBinding,
		Clock: func() domain.Timestamp {
			return agentTestTimestamp
		},
		GenerateID: func() (domain.UUIDv7, error) {
			t.Fatal("reused report allocated another identifier")
			return "", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })

	reused, found, err := next.ResumePendingVersionReport(
		bootOriginTestContext(t),
	)
	if err != nil {
		t.Fatalf("ResumePendingVersionReport(next boot): %v", err)
	}
	if !found {
		t.Fatal("prior-boot report was not resumed")
	}
	next.mu.Lock()
	resumeWorkerStarted := next.workerStarted
	next.mu.Unlock()
	if resumeWorkerStarted {
		t.Fatal("version-report resume started factory-unsafe background work")
	}
	if reused.record.EventID != reservation.record.EventID ||
		reused.record.OriginScopeID != reservation.record.OriginScopeID {
		t.Fatalf(
			"reused reservation = %#v, want event %s from scope %s",
			reused.record,
			reservation.record.EventID,
			reservation.record.OriginScopeID,
		)
	}
	outcome, err := next.AwaitVersionReport(
		bootOriginTestContext(t),
		reused,
	)
	if err != nil {
		t.Fatalf("AwaitVersionReport(reused): %v", err)
	}
	if outcome.Status != store.OutcomeAccepted {
		t.Fatalf("reused report outcome = %#v", outcome)
	}
	if err := next.CompleteVersionReport(
		bootOriginTestContext(t),
		reused,
	); err != nil {
		t.Fatalf("CompleteVersionReport(reused): %v", err)
	}
}

func TestBootOriginVersionReportKeepsCorrectionAheadOfConcurrentReservation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	harness.ids = &fixedIDGenerator{values: []domain.UUIDv7{
		"018f47de-89ab-7def-8123-000000000101",
		"018f47de-89ab-7def-8123-000000000102",
		"018f47de-89ab-7def-8123-000000000103",
		"018f47de-89ab-7def-8123-000000000104",
	}}
	harness.boot.generateID = harness.ids.next

	first, err := harness.boot.ReserveVersionReport(
		bootOriginTestContext(t),
		"0.2.0",
		1,
		1,
	)
	if err != nil {
		t.Fatalf("ReserveVersionReport(first): %v", err)
	}
	assertReservationBlocked := func(stage string) {
		t.Helper()
		waitContext, cancelWait := context.WithTimeout(
			context.Background(),
			50*time.Millisecond,
		)
		defer cancelWait()
		invoked := false
		err := harness.boot.RunBootReservation(
			waitContext,
			func(context.Context) error {
				invoked = true
				return nil
			},
		)
		if !errors.Is(err, context.DeadlineExceeded) || invoked {
			t.Fatalf(
				"%s reservation barrier = (invoked=%t, err=%v)",
				stage,
				invoked,
				err,
			)
		}
	}
	assertReservationBlocked("unresolved report")

	firstOutcome, err := harness.boot.AwaitVersionReport(
		bootOriginTestContext(t),
		first,
	)
	if err != nil || firstOutcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"AwaitVersionReport(first) = (%#v, %v)",
			firstOutcome,
			err,
		)
	}
	assertReservationBlocked("resolved report awaiting correction")

	second, err := harness.boot.ReserveVersionReport(
		bootOriginTestContext(t),
		"0.3.0",
		1,
		2,
	)
	if err != nil {
		t.Fatalf("ReserveVersionReport(corrective): %v", err)
	}
	if first.record.OriginSequence != 1 ||
		second.record.OriginSequence != 2 {
		t.Fatalf(
			"report sequences = (%d, %d), want (1, 2)",
			first.record.OriginSequence,
			second.record.OriginSequence,
		)
	}
	secondOutcome, err := harness.boot.AwaitVersionReport(
		bootOriginTestContext(t),
		second,
	)
	if err != nil || secondOutcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"AwaitVersionReport(corrective) = (%#v, %v)",
			secondOutcome,
			err,
		)
	}
	if err := harness.boot.CompleteVersionReport(
		bootOriginTestContext(t),
		second,
	); err != nil {
		t.Fatalf("CompleteVersionReport(corrective): %v", err)
	}

	var queued store.LocalCommandRecord
	err = harness.boot.RunBootReservation(
		bootOriginTestContext(t),
		func(context.Context) error {
			queued = reserveBootOriginOperatorTask(
				t,
				harness.local,
				harness.private,
				harness.deviceID,
				agentTestBootID,
				"018f47de-89ab-7def-8123-000000000105",
				"018f47de-89ab-7def-8123-000000000106",
			)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("RunBootReservation(): %v", err)
	}
	if queued.OriginSequence != 3 {
		t.Fatalf(
			"ordinary reservation sequence = %d, want 3",
			queued.OriginSequence,
		)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, found, lookupErr := harness.local.LookupRequest(
			context.Background(),
			queued.ClientInstanceID,
			queued.RequestID,
		)
		if lookupErr == nil &&
			found &&
			current.State == store.LocalRequestResolved {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("ordinary reservation did not resolve after the correction")
}

func TestBootOriginVersionReportUsesDurableDaemonDeviceProposalOnFollower(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	harness.consensus.leader.Store(false)
	recorder := &recordingCheckpointConsensus{
		delegate:  harness.consensus,
		completed: make(chan struct{}),
	}
	harness.boot.consensus = recorder

	reservation, err := harness.boot.ReserveVersionReport(
		bootOriginTestContext(t),
		"0.2.0",
		1,
		1,
	)
	if err != nil {
		t.Fatalf("ReserveVersionReport(): %v", err)
	}
	outcome, err := harness.boot.AwaitVersionReport(
		bootOriginTestContext(t),
		reservation,
	)
	if err != nil {
		t.Fatalf("AwaitVersionReport(): %v", err)
	}
	if outcome.Status != store.OutcomeAccepted {
		t.Fatalf("version-report outcome = %#v", outcome)
	}
	if err := harness.boot.CompleteVersionReport(
		bootOriginTestContext(t),
		reservation,
	); err != nil {
		t.Fatalf("CompleteVersionReport(): %v", err)
	}

	proposals := recorder.proposals()
	if len(proposals) != 1 {
		t.Fatalf("submitted proposals = %d, want 1", len(proposals))
	}
	signed, err := event.ParseAndVerify(
		proposals[0],
		event.VerificationContext{
			SessionID:         agentTestSessionID,
			WorkspaceID:       agentTestWorkspaceID,
			IdentityPublicKey: harness.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		t.Fatalf("ParseAndVerify(): %v", err)
	}
	payload, err := canonicalObject(map[string]any{
		"daemon_version":  "0.2.0",
		"max_apply_level": uint64(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	proposal := signed.Proposal()
	entityID, entityPresent := proposal.EntityID.Value()
	if proposal.Kind != event.KindMembershipVersionReported ||
		proposal.Origin.ActorType() != event.ActorDaemon ||
		proposal.Origin.DeviceID() != harness.deviceID ||
		proposal.Origin.AgentSessionID() != "" ||
		proposal.ExpectedEntityVersion == nil ||
		*proposal.ExpectedEntityVersion != 1 ||
		!entityPresent ||
		entityID != string(harness.deviceID) ||
		proposal.Origin.Sequence() != 1 ||
		!bytes.Equal(proposal.Payload, payload) {
		t.Fatalf("version-report proposal = %#v", proposal)
	}

	record, found, err := harness.local.LookupRequest(
		bootOriginTestContext(t),
		agentTestBootID,
		bootOriginTestRequestID,
	)
	if err != nil || !found {
		t.Fatalf("LookupRequest() = (%#v, %t, %v)", record, found, err)
	}
	canonicalRequest, err := canonicalObject(map[string]any{
		"daemon_version":          "0.2.0",
		"expected_entity_version": uint64(1),
		"max_apply_level":         uint64(1),
		"operation":               event.KindMembershipVersionReported,
		"request_id":              bootOriginTestRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.EventID != bootOriginTestEventID ||
		record.State != store.LocalRequestResolved ||
		record.BindingClass != store.LocalBindingDaemon ||
		record.RequestKind != event.KindMembershipVersionReported ||
		record.RequestDigest !=
			store.Digest(sha256.Sum256(canonicalRequest)) {
		t.Fatalf("durable version-report request = %#v", record)
	}
}

func TestBootOriginVersionReportRejectsInvalidInputBeforeReservation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	tests := []struct {
		name            string
		daemonVersion   string
		maxApplyLevel   uint64
		expectedVersion uint64
	}{
		{
			name:            "invalid SemVer",
			daemonVersion:   "v1",
			maxApplyLevel:   1,
			expectedVersion: 1,
		},
		{
			name:            "zero apply level",
			daemonVersion:   "0.2.0",
			maxApplyLevel:   0,
			expectedVersion: 1,
		},
		{
			name:            "excessive apply level",
			daemonVersion:   "0.2.0",
			maxApplyLevel:   domain.MaxApplyLevel + 1,
			expectedVersion: 1,
		},
		{
			name:            "zero entity version",
			daemonVersion:   "0.2.0",
			maxApplyLevel:   1,
			expectedVersion: 0,
		},
		{
			name:            "unsafe entity version",
			daemonVersion:   "0.2.0",
			maxApplyLevel:   1,
			expectedVersion: domain.MaxSafeInteger + 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := harness.boot.ReserveVersionReport(
				bootOriginTestContext(t),
				test.daemonVersion,
				test.maxApplyLevel,
				test.expectedVersion,
			)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf(
					"ReserveVersionReport() error = %v, want ErrInvalidOptions",
					err,
				)
			}
		})
	}
	records, err := harness.local.OutboxRecords(bootOriginTestContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("invalid reports reserved %d outbox records", len(records))
	}
}

func TestBootOriginVersionReportRejectsForeignReservation(t *testing.T) {
	harness := newBootOriginActivationHarness(t)
	if _, err := harness.boot.AwaitVersionReport(
		bootOriginTestContext(t),
		VersionReportReservation{},
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf(
			"AwaitVersionReport(zero) error = %v, want ErrInvalidOptions",
			err,
		)
	}
}
