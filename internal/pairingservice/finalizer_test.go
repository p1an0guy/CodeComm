package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/store"
)

func TestDurableFinalizerAppliesExactReservedAdmission(t *testing.T) {
	t.Parallel()

	for _, mode := range []pairing.Mode{
		pairing.ModeNew,
		pairing.ModeReadmission,
	} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			fixture, details := pendingFinalization(t, mode)
			applier := &recordingGenerationApplier{
				result: acceptedFinalizationResult(false),
			}
			finalizer := newTestDurableFinalizer(
				t,
				fixture,
				fixture.state,
				applier,
				&recordingRebootstrapDelegate{},
			)

			if err := finalizer.FinalizePairing(
				context.Background(),
				details,
			); err != nil {
				t.Fatalf("FinalizePairing() error = %v", err)
			}
			applier.result = acceptedFinalizationResult(true)
			if err := finalizer.FinalizePairing(
				context.Background(),
				details,
			); err != nil {
				t.Fatalf("FinalizePairing(retry) error = %v", err)
			}

			command, found, err := fixture.state.LookupRequest(
				context.Background(),
				details.Attempt.AttemptID,
				details.Attempt.AttemptID,
			)
			if err != nil || !found {
				t.Fatalf("LookupRequest() = (%+v, %t, %v)", command, found, err)
			}
			calls := applier.snapshot()
			if len(calls) != 2 {
				t.Fatalf("apply calls = %d, want 2", len(calls))
			}
			for index, call := range calls {
				if call.sessionID != details.Invite.SessionID ||
					call.recoveryGeneration !=
						details.Invite.RecoveryGeneration ||
					!bytes.Equal(
						call.signed.CanonicalBytes(),
						command.SignedProposal,
					) {
					t.Fatalf("apply call %d = %+v", index+1, call)
				}
			}
			if !bytes.Equal(
				calls[0].signed.CanonicalBytes(),
				calls[1].signed.CanonicalBytes(),
			) {
				t.Fatal("retry changed the reserved signed admission")
			}
		})
	}
}

func TestDurableFinalizerReopensAfterCommittedAdmission(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.db")
	consensusDir := filepath.Join(root, "consensus")
	initial, ownerKey, ownerID := finalizerInitialState(t)
	first, err := consensus.OpenSingleNode(
		ctx,
		consensus.SingleNodeOptions{
			ServerID:     ownerID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: serviceTestUUID(993),
			InitialState: &initial,
			Clock:        finalizerApplyClock,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(first): %v", err)
	}
	firstClosed := false
	t.Cleanup(func() {
		if !firstClosed {
			_ = first.Close()
		}
	})
	waitForFinalizerLeader(t, first)
	local, err := first.LocalState()
	if err != nil {
		t.Fatal(err)
	}
	details, authorization := finalizerAdmissionAuthorization(
		t,
		ownerKey,
		ownerID,
		serviceTestUUID(993),
	)
	if authorization.Admission == nil {
		t.Fatal("new-member authorization omitted admission")
	}
	if _, duplicate, err := local.ReserveCommand(
		ctx,
		authorization.Admission.Input,
		authorization.Admission.GenerateEventID,
		authorization.Admission.Build,
	); err != nil || duplicate {
		t.Fatalf("ReserveCommand() = (duplicate=%t, err=%v)", duplicate, err)
	}
	finalizer, err := NewDurableFinalizer(DurableFinalizerOptions{
		State:             local,
		Consensus:         first,
		Rebootstrap:       &recordingRebootstrapDelegate{},
		IdentityPublicKey: ownerKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizer.FinalizePairing(ctx, details); err != nil {
		t.Fatalf("FinalizePairing(first): %v", err)
	}
	resolved, found, err := local.LookupRequest(
		ctx,
		details.Attempt.AttemptID,
		details.Attempt.AttemptID,
	)
	if err != nil || !found ||
		resolved.State != store.LocalRequestResolved ||
		resolved.Outcome == nil ||
		resolved.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("resolved admission = (%+v, %t, %v)", resolved, found, err)
	}
	before, err := first.View(ctx)
	if err != nil || before.LastRaftAppliedLogIndex == nil {
		t.Fatalf("View(before restart) = (%+v, %v)", before, err)
	}
	appliedIndex := *before.LastRaftAppliedLogIndex
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	firstClosed = true

	second, err := consensus.OpenSingleNode(
		ctx,
		consensus.SingleNodeOptions{
			ServerID:     ownerID,
			StatePath:    statePath,
			ConsensusDir: consensusDir,
			OriginBootID: serviceTestUUID(994),
			InitialState: &initial,
			Clock:        finalizerApplyClock,
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(second): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	waitForFinalizerLeader(t, second)
	reopenedLocal, err := second.LocalState()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewDurableFinalizer(DurableFinalizerOptions{
		State:             reopenedLocal,
		Consensus:         second,
		Rebootstrap:       &recordingRebootstrapDelegate{},
		IdentityPublicKey: ownerKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.FinalizePairing(ctx, details); err != nil {
		t.Fatalf("FinalizePairing(restart): %v", err)
	}
	after, err := second.View(ctx)
	if err != nil || after.LastRaftAppliedLogIndex == nil ||
		*after.LastRaftAppliedLogIndex != appliedIndex ||
		after.Heads != before.Heads {
		t.Fatalf("View(after restart) = (%+v, %v), want index %d", after, err, appliedIndex)
	}
}

func TestDurableFinalizerUsesResolvedOutcomeAfterCrash(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		outcome store.CommandOutcome
		wantErr error
	}{
		{
			name:    "accepted",
			outcome: acceptedFinalizationResult(false).Outcome,
		},
		{
			name: "rejected",
			outcome: store.CommandOutcome{
				Status: store.OutcomeRejected,
				Code:   "entity_version_mismatch",
				JSON:   []byte(`{"code":"entity_version_mismatch","status":"rejected"}`),
			},
			wantErr: ErrFinalizationRejected,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture, details := pendingFinalization(t, pairing.ModeNew)
			state := resolvedCommandState{
				base:    fixture.state,
				outcome: test.outcome,
			}
			applier := &recordingGenerationApplier{}
			finalizer := newTestDurableFinalizer(
				t,
				fixture,
				state,
				applier,
				&recordingRebootstrapDelegate{},
			)

			err := finalizer.FinalizePairing(context.Background(), details)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("FinalizePairing() error = %v, want %v", err, test.wantErr)
			}
			if calls := applier.snapshot(); len(calls) != 0 {
				t.Fatalf("resolved retry made %d apply calls", len(calls))
			}
		})
	}
}

func TestDurableFinalizerClassifiesApplyFailures(t *testing.T) {
	t.Parallel()

	stale := errors.Join(
		consensus.ErrLineageMismatch,
		errors.New("successor generation installed"),
	)
	for _, test := range []struct {
		name     string
		result   store.ApplyResult
		applyErr error
		wantErr  error
	}{
		{
			name: "reducer rejection",
			result: store.ApplyResult{Outcome: store.CommandOutcome{
				Status: store.OutcomeRejected,
				Code:   "entity_already_exists",
				JSON:   []byte(`{"code":"entity_already_exists","status":"rejected"}`),
			}},
			wantErr: ErrFinalizationRejected,
		},
		{
			name:     "event ID collision",
			applyErr: store.ErrIdempotencyConflict,
			wantErr:  ErrFinalizationRejected,
		},
		{
			name:     "stale generation",
			applyErr: stale,
			wantErr:  consensus.ErrLineageMismatch,
		},
		{
			name:     "transient failure",
			applyErr: errors.New("quorum unavailable"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture, details := pendingFinalization(t, pairing.ModeNew)
			applier := &recordingGenerationApplier{
				result: test.result,
				err:    test.applyErr,
			}
			finalizer := newTestDurableFinalizer(
				t,
				fixture,
				fixture.state,
				applier,
				&recordingRebootstrapDelegate{},
			)

			err := finalizer.FinalizePairing(context.Background(), details)
			switch {
			case test.name == "transient failure":
				if !errors.Is(err, test.applyErr) ||
					errors.Is(err, ErrFinalizationRejected) {
					t.Fatalf("FinalizePairing() error = %v", err)
				}
			case !errors.Is(err, test.wantErr):
				t.Fatalf("FinalizePairing() error = %v, want %v", err, test.wantErr)
			}
			if calls := applier.snapshot(); len(calls) != 1 {
				t.Fatalf("apply calls = %d, want 1", len(calls))
			}
			if test.name == "event ID collision" {
				record, found, lookupErr := fixture.state.LookupRequest(
					context.Background(),
					details.Attempt.AttemptID,
					details.Attempt.AttemptID,
				)
				if lookupErr != nil || !found ||
					record.State != store.LocalRequestAbandoned ||
					record.TerminalCode !=
						store.LocalEventIDCollisionCode {
					t.Fatalf(
						"collision tombstone = (%+v, %t, %v)",
						record,
						found,
						lookupErr,
					)
				}
			}
		})
	}
}

func TestDurableFinalizerChecksLineageBeforeAdmissionLookup(t *testing.T) {
	t.Parallel()

	fixture, details := pendingFinalization(t, pairing.ModeNew)
	applier := &recordingGenerationApplier{
		gateErr: consensus.ErrLineageMismatch,
	}
	finalizer := newTestDurableFinalizer(
		t,
		fixture,
		panicCommandState{},
		applier,
		&recordingRebootstrapDelegate{},
	)

	err := finalizer.FinalizePairing(context.Background(), details)
	if !errors.Is(err, consensus.ErrLineageMismatch) ||
		errors.Is(err, ErrFinalizationIntegrity) {
		t.Fatalf(
			"FinalizePairing(stale before lookup) error = %v",
			err,
		)
	}
	if calls := applier.snapshot(); len(calls) != 0 {
		t.Fatalf("stale finalization made %d apply calls", len(calls))
	}
}

func TestDurableFinalizerRejectsChangedReservedCommand(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(testing.TB, *store.LocalCommandRecord)
	}{
		{
			name: "operator request digest",
			mutate: func(_ testing.TB, record *store.LocalCommandRecord) {
				record.RequestDigest[0] ^= 1
			},
		},
		{
			name: "event ID",
			mutate: func(_ testing.TB, record *store.LocalCommandRecord) {
				record.EventID = serviceTestUUID(991)
			},
		},
		{
			name: "signed bytes",
			mutate: func(_ testing.TB, record *store.LocalCommandRecord) {
				record.SignedProposal = append(
					bytes.Clone(record.SignedProposal),
					'\n',
				)
				record.ProposalDigest = store.Digest(
					sha256.Sum256(record.SignedProposal),
				)
			},
		},
		{
			name: "validly signed audit metadata",
			mutate: func(t testing.TB, record *store.LocalCommandRecord) {
				resignFinalizationCommand(
					t,
					record,
					func(proposal *event.Proposal) {
						proposal.RationaleSummary = "changed after SAS"
					},
				)
			},
		},
		{
			name: "validly signed action",
			mutate: func(t testing.TB, record *store.LocalCommandRecord) {
				resignFinalizationCommand(
					t,
					record,
					func(proposal *event.Proposal) {
						proposal.Actions = []event.Action{{
							Type:    event.ActionDecisionRecorded,
							Target:  "pairing",
							Summary: "changed after SAS",
							Status:  event.ActionSucceeded,
						}}
					},
				)
			},
		},
		{
			name: "validly signed redaction field",
			mutate: func(t testing.TB, record *store.LocalCommandRecord) {
				resignFinalizationCommand(
					t,
					record,
					func(proposal *event.Proposal) {
						proposal.Redaction.FieldsRemoved =
							[]event.RedactionField{
								event.RedactionSecret,
							}
					},
				)
			},
		},
		{
			name: "recovery generation",
			mutate: func(_ testing.TB, record *store.LocalCommandRecord) {
				record.RecoveryGeneration++
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture, details := pendingFinalization(t, pairing.ModeNew)
			state := mutatingCommandState{
				base: fixture.state,
				mutate: func(record *store.LocalCommandRecord) {
					test.mutate(t, record)
				},
			}
			applier := &recordingGenerationApplier{
				result: acceptedFinalizationResult(false),
			}
			finalizer := newTestDurableFinalizer(
				t,
				fixture,
				state,
				applier,
				&recordingRebootstrapDelegate{},
			)

			err := finalizer.FinalizePairing(context.Background(), details)
			if !errors.Is(err, ErrFinalizationIntegrity) ||
				errors.Is(err, ErrFinalizationRejected) {
				t.Fatalf(
					"FinalizePairing(changed command) error = %v, want %v",
					err,
					ErrFinalizationIntegrity,
				)
			}
			if calls := applier.snapshot(); len(calls) != 0 {
				t.Fatalf("changed command made %d apply calls", len(calls))
			}
		})
	}
}

func TestDurableFinalizerRequiresAndUsesRebootstrapDelegate(t *testing.T) {
	t.Parallel()

	fixture, details := pendingFinalization(t, pairing.ModeRebootstrap)
	applier := &recordingGenerationApplier{}
	delegateErr := errors.New("replacement state unavailable")
	delegate := &recordingRebootstrapDelegate{err: delegateErr}
	finalizer := newTestDurableFinalizer(
		t,
		fixture,
		panicCommandState{},
		applier,
		delegate,
	)

	applier.gateErr = consensus.ErrLineageMismatch
	err := finalizer.FinalizePairing(context.Background(), details)
	if !errors.Is(err, consensus.ErrLineageMismatch) {
		t.Fatalf("FinalizePairing(stale) error = %v", err)
	}
	if calls := delegate.snapshot(); len(calls) != 0 {
		t.Fatalf("stale rebootstrap made %d delegate calls", len(calls))
	}
	applier.gateErr = nil
	err = finalizer.FinalizePairing(context.Background(), details)
	if !errors.Is(err, delegateErr) {
		t.Fatalf("FinalizePairing() error = %v, want %v", err, delegateErr)
	}
	if calls := delegate.snapshot(); len(calls) != 1 ||
		calls[0].Attempt.AttemptID != details.Attempt.AttemptID {
		t.Fatalf("rebootstrap calls = %+v", calls)
	}
	if calls := applier.snapshot(); len(calls) != 0 {
		t.Fatalf("rebootstrap made %d admission apply calls", len(calls))
	}
	if gates := applier.gateSnapshot(); len(gates) != 2 ||
		gates[0].sessionID != details.Invite.SessionID ||
		gates[0].recoveryGeneration != details.Invite.RecoveryGeneration ||
		gates[1] != gates[0] {
		t.Fatalf("rebootstrap lineage gates = %+v", gates)
	}

	invite := fixture.invite.Invite()
	defer clear(invite.Secret[:])
	if _, err := NewDurableFinalizer(DurableFinalizerOptions{
		State:             fixture.state,
		Consensus:         applier,
		IdentityPublicKey: invite.InviterIdentityPublicKey[:],
	}); !errors.Is(err, ErrInvalidDurableFinalizer) {
		t.Fatalf("NewDurableFinalizer(nil delegate) error = %v", err)
	}
}

func TestPairingServiceFinalizationIntegrityFailureIsFatal(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixtureWithFinalizer(
		t,
		&controlledFinalizer{err: ErrFinalizationIntegrity},
	)
	request := fixture.request(t, serviceTestUUID(992), fixture.exporter)
	fixture.clock.set("2026-08-13T12:02:00Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := [sha256.Size]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:02:01Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.peer,
	); err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:02:02Z")
	details, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if !errors.Is(err, ErrFinalizationIntegrity) ||
		details.Attempt.State != store.PairingAttemptFinalizing ||
		!errors.Is(
			fixture.service.FatalError(),
			ErrFinalizationIntegrity,
		) {
		t.Fatalf(
			"ConfirmLocal() = (%+v, %v), fatal = %v",
			details,
			err,
			fixture.service.FatalError(),
		)
	}
	pending, found, err := fixture.state.NextPairingFinalization(
		context.Background(),
	)
	if err != nil || !found ||
		pending.AttemptID != result.Attempt.AttemptID {
		t.Fatalf(
			"NextPairingFinalization() = (%+v, %t, %v)",
			pending,
			found,
			err,
		)
	}
}

func pendingFinalization(
	t testing.TB,
	mode pairing.Mode,
) (serviceFixture, AttemptDetails) {
	t.Helper()

	pending := &controlledFinalizer{err: errors.New("finalization deferred")}
	fixture := newServiceFixtureWithMode(
		t,
		pending,
		noOpNonvoterGuard{},
		mode,
	)
	request := fixture.request(t, serviceTestUUID(980), fixture.exporter)
	fixture.clock.set("2026-08-13T12:01:00Z")
	result, err := fixture.service.HandleRequest(
		context.Background(),
		request.CanonicalBytes(),
		fixture.exporter,
		fixture.peer,
	)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	requestDigest := [sha256.Size]byte(result.Attempt.RequestDigest)
	confirmation, err := pairing.NewConfirmation(
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.set("2026-08-13T12:01:01Z")
	if _, err := fixture.service.ConfirmRemote(
		context.Background(),
		confirmation.CanonicalBytes(),
		fixture.peer,
	); err != nil {
		t.Fatalf("ConfirmRemote() error = %v", err)
	}
	fixture.clock.set("2026-08-13T12:01:02Z")
	details, err := fixture.service.ConfirmLocal(
		context.Background(),
		result.Attempt.AttemptID,
		requestDigest,
		true,
	)
	if !errors.Is(err, ErrFinalizationPending) ||
		details.Attempt.State != store.PairingAttemptFinalizing {
		t.Fatalf("ConfirmLocal() = (%+v, %v)", details, err)
	}
	return fixture, details
}

func newTestDurableFinalizer(
	t testing.TB,
	fixture serviceFixture,
	state FinalizationCommandState,
	applier GenerationCoordinator,
	rebootstrap RebootstrapDelegate,
) *DurableFinalizer {
	t.Helper()

	invite := fixture.invite.Invite()
	defer clear(invite.Secret[:])
	finalizer, err := NewDurableFinalizer(DurableFinalizerOptions{
		State:             state,
		Consensus:         applier,
		Rebootstrap:       rebootstrap,
		IdentityPublicKey: invite.InviterIdentityPublicKey[:],
	})
	if err != nil {
		t.Fatalf("NewDurableFinalizer() error = %v", err)
	}
	return finalizer
}

func acceptedFinalizationResult(duplicate bool) store.ApplyResult {
	return store.ApplyResult{
		Outcome: store.CommandOutcome{
			Status: store.OutcomeAccepted,
			Code:   "accepted",
			JSON:   []byte(`{"code":"accepted","status":"accepted"}`),
		},
		Duplicate: duplicate,
	}
}

func resignFinalizationCommand(
	t testing.TB,
	record *store.LocalCommandRecord,
	mutate func(*event.Proposal),
) {
	t.Helper()
	key := testPrivateKey(1)
	publicKey := key.Public().(ed25519.PublicKey)
	signed, err := event.ParseAndVerify(
		record.SignedProposal,
		event.VerificationContext{
			SessionID:         serviceTestSessionID,
			WorkspaceID:       serviceTestWorkspaceID,
			IdentityPublicKey: publicKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	proposal := signed.Proposal()
	mutate(&proposal)
	changed, err := event.Sign(proposal, key)
	if err != nil {
		t.Fatal(err)
	}
	record.SignedProposal = changed.CanonicalBytes()
	record.ProposalDigest = store.Digest(
		sha256.Sum256(record.SignedProposal),
	)
}

func finalizerInitialState(
	t testing.TB,
) (store.InitialState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	ownerKey := testPrivateKey(1)
	ownerPublicKey := ownerKey.Public().(ed25519.PublicKey)
	ownerID, err := device.DeriveID(ownerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	target, err := voterset.New(
		serviceTestSessionID,
		[]domain.DeviceID{ownerID},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawGenesis, err := json.Marshal(map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(ownerPublicKey),
		"session_id":          serviceTestSessionID,
		"workspace_id":        serviceTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		t.Fatal(err)
	}
	initial := store.InitialState{
		SessionID:               serviceTestSessionID,
		WorkspaceID:             serviceTestWorkspaceID,
		GenesisJSON:             genesis,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			AuditCounters: []auditcounter.Counter{{DeviceID: ownerID}},
			PlanCurrent: []plan.Current{{
				SessionID:     serviceTestSessionID,
				EntityVersion: 1,
			}},
			Devices: []device.Device{{
				ID: ownerID, Role: device.RoleOwner,
				IdentityPublicKey: ownerPublicKey,
				DaemonVersion:     "1.0.0",
				MaxApplyLevel:     1,
				Status:            device.StatusActive,
				EntityVersion:     1,
			}},
			VoterSet: []voterset.Set{target},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        serviceTestSessionID,
				VoterDeviceIDs:   []domain.DeviceID{ownerID},
				VoterSetVersion:  1,
				ActivationSource: credentialauthority.ActivationGenesis,
			}},
			CanonicalRefs: []publication.CanonicalRef{{
				RefName: publication.CanonicalRefName,
				CommitOID: domain.GitOID(
					"sha1:" + strings.Repeat("1", 40),
				),
				EntityVersion: 1,
			}},
			SessionPolicy: []policy.Policy{{
				SessionID:     serviceTestSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	}
	return initial, ownerKey, ownerID
}

func finalizerAdmissionAuthorization(
	t testing.TB,
	ownerKey ed25519.PrivateKey,
	ownerID domain.DeviceID,
	bootID domain.UUIDv7,
) (AttemptDetails, *store.PairingFinalizationAuthorization) {
	t.Helper()
	joinerKey := testPrivateKey(2)
	joinerPublicKey := joinerKey.Public().(ed25519.PublicKey)
	joinerID, err := device.DeriveID(joinerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	epochKey := testPrivateKey(3)
	binding, err := credential.SignBinding(
		serviceTestSessionID,
		joinerID,
		1,
		epochKey.Public().(ed25519.PublicKey),
		joinerKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := serviceTestUUID(996)
	inviteID := serviceTestUUID(995)
	requestDigest := store.Digest(sha256.Sum256(
		[]byte("integration pairing request"),
	))
	core := pairing.RequestCore{
		AttemptID: attemptID, JoinerDeviceID: joinerID,
		DaemonVersion: "1.2.3", MaxApplyLevel: 1,
		InitialEpochBinding: binding,
	}
	copy(core.JoinerIdentityPublicKey[:], joinerPublicKey)
	invite := store.PairingInviteRecord{
		InviteID: inviteID, SessionID: serviceTestSessionID,
		WorkspaceID: serviceTestWorkspaceID, RecoveryGeneration: 0,
		IssuerDeviceID: ownerID, Mode: pairing.ModeNew,
		Role: device.RoleEditor, InitialCredentialEpoch: 1,
		State: store.PairingInviteConsumed, ConsumedAttemptID: attemptID,
		CreatedAt: "2026-08-13T12:00:00Z",
		ExpiresAt: "2026-08-13T12:15:00Z",
	}
	attempt := store.PairingAttemptRecord{
		AttemptID: attemptID, InviteID: inviteID,
		RequestDigest: requestDigest, JoinerDeviceID: joinerID,
		State: store.PairingAttemptAwaitingSAS, RemoteConfirmed: true,
		RemoteConfirmedAt: "2026-08-13T12:01:00Z",
		CreatedAt:         "2026-08-13T12:00:30Z",
	}
	preConfirmation := AttemptDetails{
		Invite: invite, Attempt: attempt, Core: core,
		SAS: "0000 0000 0000 0000 0000",
	}
	authority, err := event.NewLocalAuthority(ownerID, bootID)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewAdmissionAuthorizer(AdmissionAuthorizerOptions{
		DeviceID:           ownerID,
		OriginBootID:       bootID,
		IdentityPrivateKey: ownerKey,
		OperatorOrigin:     operator,
		GenerateID: func() (domain.UUIDv7, error) {
			return serviceTestUUID(997), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	decidedAt := domain.Timestamp("2026-08-13T12:01:01Z")
	authorization, err := authorizer.PreparePairing(
		context.Background(),
		preConfirmation,
		decidedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	attempt.State = store.PairingAttemptFinalizing
	attempt.LocalConfirmed = true
	attempt.LocalConfirmedAt = decidedAt
	attempt.TerminalAt = decidedAt
	return AttemptDetails{
		Invite: invite, Attempt: attempt, Core: core,
		SAS: preConfirmation.SAS,
	}, authorization
}

func finalizerApplyClock() (domain.Timestamp, int64, error) {
	return "2026-08-13T12:02:00Z", int64(time.Second), nil
}

func waitForFinalizerLeader(t testing.TB, node *consensus.SingleNode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
}

type generationApplyCall struct {
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
	signed             event.SignedEvent
}

type recordingGenerationApplier struct {
	calls   []generationApplyCall
	gates   []generationGateCall
	result  store.ApplyResult
	err     error
	gateErr error
}

func (applier *recordingGenerationApplier) ApplyAtGeneration(
	_ context.Context,
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	applier.calls = append(applier.calls, generationApplyCall{
		sessionID:          sessionID,
		recoveryGeneration: recoveryGeneration,
		signed:             signed,
	})
	return applier.result, applier.err
}

func (applier *recordingGenerationApplier) snapshot() []generationApplyCall {
	return append([]generationApplyCall(nil), applier.calls...)
}

type generationGateCall struct {
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
}

func (applier *recordingGenerationApplier) RunAtGeneration(
	ctx context.Context,
	sessionID domain.UUIDv7,
	recoveryGeneration uint64,
	operation func(context.Context) error,
) error {
	applier.gates = append(applier.gates, generationGateCall{
		sessionID:          sessionID,
		recoveryGeneration: recoveryGeneration,
	})
	if applier.gateErr != nil {
		return applier.gateErr
	}
	return operation(ctx)
}

func (applier *recordingGenerationApplier) gateSnapshot() []generationGateCall {
	return append([]generationGateCall(nil), applier.gates...)
}

type recordingRebootstrapDelegate struct {
	calls []AttemptDetails
	err   error
}

func (delegate *recordingRebootstrapDelegate) FinalizeRebootstrap(
	_ context.Context,
	details AttemptDetails,
) error {
	delegate.calls = append(delegate.calls, details)
	return delegate.err
}

func (delegate *recordingRebootstrapDelegate) snapshot() []AttemptDetails {
	return append([]AttemptDetails(nil), delegate.calls...)
}

type resolvedCommandState struct {
	base    FinalizationCommandState
	outcome store.CommandOutcome
}

func (state resolvedCommandState) LookupRequest(
	ctx context.Context,
	clientInstanceID domain.UUIDv7,
	requestID domain.UUIDv7,
) (store.LocalCommandRecord, bool, error) {
	record, found, err := state.base.LookupRequest(
		ctx,
		clientInstanceID,
		requestID,
	)
	if err != nil || !found {
		return record, found, err
	}
	record.State = store.LocalRequestResolved
	record.SignedProposal = nil
	record.OriginSequence = 0
	record.Outcome = &state.outcome
	record.TerminalCode = state.outcome.Code
	return record, true, nil
}

func (state resolvedCommandState) AbandonCommandCollision(
	ctx context.Context,
	input store.LocalCommandCollisionInput,
) (store.LocalCommandRecord, bool, error) {
	return state.base.AbandonCommandCollision(ctx, input)
}

type mutatingCommandState struct {
	base   FinalizationCommandState
	mutate func(*store.LocalCommandRecord)
}

func (state mutatingCommandState) LookupRequest(
	ctx context.Context,
	clientInstanceID domain.UUIDv7,
	requestID domain.UUIDv7,
) (store.LocalCommandRecord, bool, error) {
	record, found, err := state.base.LookupRequest(
		ctx,
		clientInstanceID,
		requestID,
	)
	if err == nil && found {
		state.mutate(&record)
	}
	return record, found, err
}

func (state mutatingCommandState) AbandonCommandCollision(
	ctx context.Context,
	input store.LocalCommandCollisionInput,
) (store.LocalCommandRecord, bool, error) {
	return state.base.AbandonCommandCollision(ctx, input)
}

type panicCommandState struct{}

func (panicCommandState) LookupRequest(
	context.Context,
	domain.UUIDv7,
	domain.UUIDv7,
) (store.LocalCommandRecord, bool, error) {
	panic("rebootstrap read an admission command")
}

func (panicCommandState) AbandonCommandCollision(
	context.Context,
	store.LocalCommandCollisionInput,
) (store.LocalCommandRecord, bool, error) {
	panic("rebootstrap abandoned an admission command")
}

var _ GenerationCoordinator = (*recordingGenerationApplier)(nil)
var _ RebootstrapDelegate = (*recordingRebootstrapDelegate)(nil)
var _ FinalizationCommandState = resolvedCommandState{}
var _ FinalizationCommandState = mutatingCommandState{}
var _ FinalizationCommandState = panicCommandState{}
