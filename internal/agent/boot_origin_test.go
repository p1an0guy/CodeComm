package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/localcommand"
	"github.com/ijonahch/codecomm/internal/operatorcommand"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/voteractivation"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var errBootOriginTestStop = errors.New("stop after reservation")

var (
	_ consensus.CheckpointOrigin              = (*BootOrigin)(nil)
	_ consensus.CredentialAuthorizationOrigin = (*BootOrigin)(nil)
)

const (
	bootOriginTestRequestID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-9123456789ab",
	)
	bootOriginTestEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-a123456789ab",
	)
	bootOriginTestPriorRequestID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-b123456789ab",
	)
	bootOriginTestPriorEventID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-c123456789ab",
	)
	bootOriginTestTaskID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-d123456789ab",
	)
	bootOriginTestNextBootID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-e123456789ab",
	)
)

func TestBootOriginSubmitVoterSetActivationDurablyResolvesExactPayload(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	payload := bootOriginActivationPayload(
		t,
		harness,
		agentTestSessionID,
		agentTestWorkspaceID,
		0,
	)
	encoded, err := voteractivation.EncodeActivationPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingCheckpointConsensus{
		delegate:  harness.consensus,
		completed: make(chan struct{}),
	}
	harness.boot.consensus = recorder

	outcome, err := harness.boot.SubmitVoterSetActivation(
		bootOriginTestContext(t),
		payload,
	)
	if err != nil {
		t.Fatalf(
			"SubmitVoterSetActivation(): %v (fatal=%v, proposals=%d, consensus=%v)",
			err,
			harness.boot.FatalError(),
			len(recorder.proposals()),
			harness.consensus.err,
		)
	}
	if outcome.Status != store.OutcomeAccepted {
		t.Fatalf("activation outcome = %#v", outcome)
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
	proposal := signed.Proposal()
	entityID, entityPresent := proposal.EntityID.Value()
	if proposal.Kind != event.KindMembershipVoterSetActivated ||
		proposal.ExpectedEntityVersion != nil ||
		!entityPresent ||
		entityID != string(agentTestSessionID) ||
		proposal.Origin.Sequence() != 1 ||
		!bytes.Equal(proposal.Payload, encoded) {
		t.Fatalf("activation proposal = %#v", proposal)
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
		"activation": json.RawMessage(encoded),
		"operation":  event.KindMembershipVoterSetActivated,
		"request_id": bootOriginTestRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.EventID != bootOriginTestEventID ||
		record.State != store.LocalRequestResolved ||
		record.RequestDigest != store.Digest(sha256.Sum256(canonicalRequest)) {
		t.Fatalf("durable activation request = %#v", record)
	}
}

func TestBootOriginSubmitCredentialAuthorizationDurablyResolvesExactPayload(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	authorization := bootOriginCredentialAuthorization(t, harness)
	payload, err := encodeCredentialAuthorizationPayload(authorization)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingCheckpointConsensus{
		delegate:  harness.consensus,
		completed: make(chan struct{}),
	}
	harness.boot.consensus = recorder

	outcome, err := harness.boot.SubmitCredentialAuthorization(
		bootOriginTestContext(t),
		authorization,
	)
	if err != nil {
		t.Fatalf("SubmitCredentialAuthorization(): %v", err)
	}
	if outcome.Status != store.OutcomeAccepted {
		t.Fatalf("credential outcome = %#v", outcome)
	}
	if authorization.AuthorizationChainIndex != 0 {
		t.Fatalf(
			"input authorization chain index = %d, want 0",
			authorization.AuthorizationChainIndex,
		)
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
	proposal := signed.Proposal()
	entityID, entityPresent := proposal.EntityID.Value()
	if proposal.Kind != event.KindCredentialAuthorized ||
		proposal.Origin.ActorType() != event.ActorDaemon ||
		proposal.ExpectedEntityVersion != nil ||
		!entityPresent ||
		entityID != string(harness.deviceID) ||
		proposal.Origin.Sequence() != 1 ||
		!bytes.Equal(proposal.Payload, payload) {
		t.Fatalf("credential proposal = %#v", proposal)
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
		"authorization": json.RawMessage(payload),
		"operation":     event.KindCredentialAuthorized,
		"request_id":    bootOriginTestRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.EventID != bootOriginTestEventID ||
		record.State != store.LocalRequestResolved ||
		record.BindingClass != store.LocalBindingDaemon ||
		record.RequestKind != event.KindCredentialAuthorized ||
		record.RequestDigest != store.Digest(sha256.Sum256(canonicalRequest)) {
		t.Fatalf("durable credential request = %#v", record)
	}
}

func TestBootOriginSubmitCredentialAuthorizationRejectsInvalidCandidateBeforeReservation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	authorization := bootOriginCredentialAuthorization(t, harness)
	authorization.AuthorizationChainIndex = 1

	_, err := harness.boot.SubmitCredentialAuthorization(
		bootOriginTestContext(t),
		authorization,
	)
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf(
			"SubmitCredentialAuthorization() error = %v, want ErrInvalidOptions",
			err,
		)
	}
	records, err := harness.local.OutboxRecords(bootOriginTestContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("outbox records = %d, want 0", len(records))
	}
	if remaining := harness.ids.remaining(); remaining != 2 {
		t.Fatalf("remaining generated IDs = %d, want 2", remaining)
	}
}

func TestBootOriginSubmitOperatorCommandSignsHumanAndReplaysExactly(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	harness.ids = &fixedIDGenerator{values: []domain.UUIDv7{
		bootOriginTestEventID,
	}}
	harness.boot.generateID = harness.ids.next
	recorder := &recordingCheckpointConsensus{
		delegate:  harness.consensus,
		completed: make(chan struct{}),
	}
	harness.boot.consensus = recorder

	request := bootOriginOperatorRequest(
		t,
		harness.deviceID,
		bootOriginTestRequestID,
	)
	result, err := harness.boot.SubmitOperatorCommand(
		bootOriginTestContext(t),
		operatorcommand.Request{
			ClientInstanceID: bootOriginTestPriorRequestID,
			Command:          request,
		},
	)
	if err != nil {
		t.Fatalf("SubmitOperatorCommand(): %v", err)
	}
	if result.EventID != bootOriginTestEventID ||
		result.Outcome.Status != store.OutcomeAccepted ||
		result.Duplicate {
		t.Fatalf("result = %#v", result)
	}
	proposals := recorder.proposals()
	if len(proposals) != 1 {
		t.Fatalf("proposals = %d, want 1", len(proposals))
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
	proposal := signed.Proposal()
	if proposal.Origin.ActorType() != event.ActorHuman ||
		proposal.Origin.OriginBootID() != agentTestBootID ||
		proposal.Kind != event.KindMembershipVoterSetChanged ||
		proposal.ExpectedEntityVersion == nil ||
		*proposal.ExpectedEntityVersion != 2 {
		t.Fatalf("proposal = %#v", proposal)
	}

	duplicate, err := harness.boot.SubmitOperatorCommand(
		bootOriginTestContext(t),
		operatorcommand.Request{
			ClientInstanceID: bootOriginTestPriorRequestID,
			Command:          request,
		},
	)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if !duplicate.Duplicate ||
		duplicate.EventID != result.EventID ||
		len(recorder.proposals()) != 1 {
		t.Fatalf("duplicate = %#v; proposals = %d", duplicate, len(recorder.proposals()))
	}

	changed := request
	changed.Canonical = bytes.Replace(
		changed.Canonical,
		[]byte(`"expected_entity_version":2`),
		[]byte(`"expected_entity_version":1`),
		1,
	)
	if _, err := harness.boot.SubmitOperatorCommand(
		bootOriginTestContext(t),
		operatorcommand.Request{
			ClientInstanceID: bootOriginTestPriorRequestID,
			Command:          changed,
		},
	); !errors.Is(err, store.ErrLocalIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
}

func TestBootOriginSubmitDeviceRevocationPreservesBothReviewedCASValues(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	harness.ids = &fixedIDGenerator{values: []domain.UUIDv7{
		bootOriginTestEventID,
	}}
	harness.boot.generateID = harness.ids.next
	var subject domain.DeviceID
	for _, candidate := range harness.target {
		if candidate != harness.deviceID {
			subject = candidate
			break
		}
	}
	if !subject.Valid() {
		t.Fatal("revocation fixture has no nonlocal target voter")
	}
	request := bootOriginRevocationRequest(
		t,
		harness.deviceID,
		subject,
		bootOriginTestRequestID,
	)
	result, err := harness.boot.SubmitOperatorCommand(
		bootOriginTestContext(t),
		operatorcommand.Request{
			ClientInstanceID: bootOriginTestPriorRequestID,
			Command:          request,
		},
	)
	if err != nil {
		t.Fatalf("SubmitOperatorCommand(revoke): %v", err)
	}
	if result.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf("revocation result = %#v", result)
	}
	snapshot, err := harness.local.StatusSnapshot(
		bootOriginTestContext(t),
		harness.deviceID,
		1,
	)
	if err != nil {
		t.Fatalf("StatusSnapshot(): %v", err)
	}
	if snapshot.VoterSet.VoterSetVersion != 3 ||
		!reflect.DeepEqual(
			snapshot.VoterSet.VoterDeviceIDs(),
			[]domain.DeviceID{harness.deviceID},
		) {
		t.Fatalf("voter target after revocation = %#v", snapshot.VoterSet)
	}
	var revoked *coordstatus.MemberSummary
	for index := range snapshot.Members {
		if snapshot.Members[index].ID == subject {
			revoked = &snapshot.Members[index]
			break
		}
	}
	if revoked == nil ||
		revoked.Status != device.StatusRevoked ||
		revoked.EntityVersion != 2 {
		t.Fatalf("revoked member = %#v", revoked)
	}
}

func bootOriginOperatorRequest(
	t *testing.T,
	deviceID domain.DeviceID,
	requestID domain.UUIDv7,
) localcommand.Request {
	t.Helper()
	canonical, err := canonicalObject(map[string]any{
		"command": map[string]any{
			"actions":                 []any{},
			"entity_id":               agentTestSessionID,
			"expected_entity_version": uint64(2),
			"kind":                    event.KindMembershipVoterSetChanged,
			"payload": map[string]any{
				"voter_set": []domain.DeviceID{deviceID},
			},
			"rationale_summary": "",
			"redaction": map[string]any{
				"fields_removed": []string{},
				"policy":         event.RedactionDefault,
			},
		},
		"operation":  operatorcommand.OperationSetVoters,
		"request_id": requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := localcommand.Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func bootOriginRevocationRequest(
	t *testing.T,
	resultingVoter domain.DeviceID,
	subject domain.DeviceID,
	requestID domain.UUIDv7,
) localcommand.Request {
	t.Helper()
	canonical, err := canonicalObject(map[string]any{
		"command": map[string]any{
			"actions":                 []any{},
			"entity_id":               subject,
			"expected_entity_version": uint64(1),
			"kind":                    event.KindMembershipDeviceRevoked,
			"payload": map[string]any{
				"device_id":                  subject,
				"expected_voter_set_version": uint64(2),
				"reason":                     "retired test device",
				"voter_set": []domain.DeviceID{
					resultingVoter,
				},
			},
			"rationale_summary": "",
			"redaction": map[string]any{
				"fields_removed": []string{},
				"policy":         event.RedactionDefault,
			},
		},
		"operation":  operatorcommand.OperationRevokePeer,
		"request_id": requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := localcommand.Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestBootOriginSubmitVoterSetActivationRejectsLineageBeforeReservation(
	t *testing.T,
) {
	harness := newBootOriginActivationHarness(t)
	tests := []struct {
		name       string
		sessionID  domain.UUIDv7
		workspace  domain.UUIDv4
		generation uint64
	}{
		{
			name:       "session",
			sessionID:  bootOriginTestNextBootID,
			workspace:  agentTestWorkspaceID,
			generation: 0,
		},
		{
			name:       "workspace",
			sessionID:  agentTestSessionID,
			workspace:  domain.UUIDv4("550e8400-e29b-41d4-a716-446655440001"),
			generation: 0,
		},
		{
			name:       "recovery generation",
			sessionID:  agentTestSessionID,
			workspace:  agentTestWorkspaceID,
			generation: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := bootOriginActivationPayload(
				t,
				harness,
				test.sessionID,
				test.workspace,
				test.generation,
			)
			_, err := harness.boot.SubmitVoterSetActivation(
				bootOriginTestContext(t),
				payload,
			)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf(
					"SubmitVoterSetActivation() error = %v, want ErrInvalidOptions",
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
		t.Fatalf("outbox records after mismatches = %d, want 0", len(records))
	}
	if remaining := harness.ids.remaining(); remaining != 2 {
		t.Fatalf("remaining generated IDs = %d, want 2", remaining)
	}
}

func TestBootOriginForceCheckpointDrainsPredecessorAndSettles(
	t *testing.T,
) {
	root := t.TempDir()
	initial, privateKey, deviceID := bootOriginInitialState(t)
	ids := &fixedIDGenerator{values: []domain.UUIDv7{
		bootOriginTestRequestID,
		bootOriginTestEventID,
	}}
	authority, err := event.NewLocalAuthority(deviceID, agentTestBootID)
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
	var origin *BootOrigin
	node, err := consensus.OpenSingleNode(
		context.Background(),
		consensus.SingleNodeOptions{
			ServerID:     deviceID,
			StatePath:    filepath.Join(root, "state", "state.db"),
			ConsensusDir: filepath.Join(root, "consensus"),
			OriginBootID: agentTestBootID,
			InitialState: &initial,
			CheckpointSigner: consensus.CheckpointSignerAdapter{
				SignerDeviceID: deviceID,
				Sign: func(
					ctx context.Context,
					checkpoint domain.Checkpoint,
				) (store.Signature, error) {
					if err := ctx.Err(); err != nil {
						return store.Signature{}, err
					}
					signature, err := event.SignCheckpoint(
						checkpoint,
						privateKey,
					)
					return store.Signature(signature), err
				},
			},
			CheckpointOriginFactory: func(
				local store.LocalState,
				submitter consensus.CheckpointCommandSubmitter,
			) (consensus.CheckpointOrigin, error) {
				created, err := NewBootOrigin(BootOriginOptions{
					Consensus:          submitter,
					LocalState:         local,
					SessionID:          agentTestSessionID,
					WorkspaceID:        agentTestWorkspaceID,
					DeviceID:           deviceID,
					OriginBootID:       agentTestBootID,
					IdentityPrivateKey: privateKey,
					DaemonOrigin:       daemonBinding,
					OperatorOrigin:     operatorBinding,
					Clock: func() domain.Timestamp {
						return agentTestTimestamp
					},
					GenerateID: ids.next,
				})
				if err == nil {
					origin = created
				}
				return created, err
			},
			Clock:      consensus.NewSystemApplyClock(),
			RaftConfig: bootOriginRaftConfig(),
		},
	)
	if err != nil {
		t.Fatalf("OpenSingleNode(): %v", err)
	}
	t.Cleanup(func() {
		if origin != nil {
			_ = origin.BeginClose()
		}
		_ = node.Close()
		if origin != nil {
			_ = origin.Wait()
		}
	})
	if err := node.WaitForLeader(bootOriginTestContext(t)); err != nil {
		t.Fatalf("WaitForLeader(): %v", err)
	}
	local, err := node.LocalState()
	if err != nil {
		t.Fatal(err)
	}
	prior := reserveBootOriginOperatorTask(
		t,
		local,
		privateKey,
		deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)

	checkpoint, err := node.ForceCheckpoint(bootOriginTestContext(t))
	if err != nil {
		t.Fatalf("ForceCheckpoint(): %v", err)
	}
	if checkpoint.Record.CoveredChainIndex != 1 ||
		checkpoint.Record.CoveredResultIndex != 1 {
		t.Fatalf(
			"checkpoint did not follow predecessor: %#v",
			checkpoint.Record,
		)
	}
	resolvedPrior, found, err := local.LookupRequest(
		bootOriginTestContext(t),
		prior.ClientInstanceID,
		prior.RequestID,
	)
	if err != nil || !found ||
		resolvedPrior.State != store.LocalRequestResolved ||
		resolvedPrior.Outcome == nil ||
		resolvedPrior.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"predecessor = (%#v, %t, %v)",
			resolvedPrior,
			found,
			err,
		)
	}
	resolvedCheckpoint, found, err := local.LookupRequest(
		bootOriginTestContext(t),
		agentTestBootID,
		bootOriginTestRequestID,
	)
	if err != nil || !found ||
		resolvedCheckpoint.EventID != bootOriginTestEventID ||
		resolvedCheckpoint.State != store.LocalRequestResolved ||
		resolvedCheckpoint.Outcome == nil ||
		resolvedCheckpoint.Outcome.Status != store.OutcomeAccepted {
		t.Fatalf(
			"checkpoint request = (%#v, %t, %v)",
			resolvedCheckpoint,
			found,
			err,
		)
	}
	scopes, err := local.OutboxScopes(bootOriginTestContext(t))
	if err != nil || len(scopes) != 0 {
		t.Fatalf("outbox scopes = (%#v, %v)", scopes, err)
	}
}

func TestBootOriginReplaysExactHistoricalCheckpointAfterReopen(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	prior := reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	priorSigned, err := event.ParseAndVerify(
		prior.SignedProposal,
		event.VerificationContext{
			SessionID:         agentTestSessionID,
			WorkspaceID:       agentTestWorkspaceID,
			IdentityPublicKey: harness.private.Public().(ed25519.PublicKey),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.consensus.ApplyAtGeneration(
		bootOriginTestContext(t),
		agentTestSessionID,
		0,
		priorSigned,
	); err != nil {
		t.Fatalf("apply predecessor: %v", err)
	}
	blocked := &cancellationBlockingConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
	}
	harness.boot.consensus = blocked
	view, err := harness.state.View(bootOriginTestContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if view.LastRaftAppliedLogIndex == nil {
		t.Fatal("predecessor did not establish an applied log index")
	}
	checkpoint := domain.Checkpoint{
		SessionID:                view.SessionID,
		WorkspaceID:              view.WorkspaceID,
		RecoveryGeneration:       view.RecoveryGeneration,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           harness.deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   *view.LastRaftAppliedLogIndex,
		CoveredChainIndex:        view.Heads.ChainIndex,
		CoveredChainHash:         view.Heads.ChainHash,
		CoveredResultIndex:       view.Heads.ResultIndex,
		CoveredResultHash:        view.Heads.ResultHash,
		ProjectionAccumulator:    view.Heads.ProjectionAccumulator,
		DigestVersion:            view.Heads.DigestVersion,
		ProjectionSchemaVersion: view.Heads.
			ProjectionSchemaVersion,
	}
	signature, err := event.SignCheckpoint(checkpoint, harness.private)
	if err != nil {
		t.Fatal(err)
	}
	var reserved event.SignedEvent
	err = harness.boot.RunExclusive(
		bootOriginTestContext(t),
		func(reserve func(
			context.Context,
			domain.Checkpoint,
			store.Signature,
		) (event.SignedEvent, error)) error {
			var reserveErr error
			reserved, reserveErr = reserve(
				context.Background(),
				checkpoint,
				store.Signature(signature),
			)
			if reserveErr != nil {
				return reserveErr
			}
			return errBootOriginTestStop
		},
	)
	if !errors.Is(err, errBootOriginTestStop) {
		t.Fatalf("RunExclusive() error = %v", err)
	}
	select {
	case <-blocked.entered:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("old worker did not claim the reserved checkpoint")
	}
	if err := harness.service.BeginClose(); err != nil {
		t.Fatal(err)
	}
	if err := harness.boot.BeginClose(); err != nil {
		t.Fatal(err)
	}
	if err := harness.service.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := harness.boot.Wait(); err != nil {
		t.Fatal(err)
	}
	statePath := harness.state.Path()
	if err := harness.state.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(
		context.Background(),
		store.Options{Path: statePath},
	)
	if err != nil {
		t.Fatalf("store.Open(reopen): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	applyClock := func() (domain.Timestamp, int64, error) {
		return agentTestTimestamp, int64(time.Second), nil
	}
	fsm, err := consensus.NewFSM(consensus.FSMOptions{
		Store:        reopened,
		OriginBootID: bootOriginTestNextBootID,
		Clock:        applyClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fsmConsensus{
		fsm:   fsm,
		store: reopened,
		clock: applyClock,
		index: checkpoint.CoveredAppliedLogIndex,
	}
	runtime.leader.Store(true)
	recorder := &recordingCheckpointConsensus{
		delegate:       runtime,
		completed:      make(chan struct{}),
		verified:       make(chan struct{}),
		verifyFailures: 1,
	}
	nextAuthority, err := event.NewLocalAuthority(
		harness.deviceID,
		bootOriginTestNextBootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	nextBinding, err := nextAuthority.DaemonBinding()
	if err != nil {
		t.Fatal(err)
	}
	nextOperatorBinding, err := nextAuthority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	nextOrigin, err := NewBootOrigin(BootOriginOptions{
		Consensus:          recorder,
		LocalState:         reopened.LocalState(),
		SessionID:          agentTestSessionID,
		WorkspaceID:        agentTestWorkspaceID,
		DeviceID:           harness.deviceID,
		OriginBootID:       bootOriginTestNextBootID,
		IdentityPrivateKey: harness.private,
		DaemonOrigin:       nextBinding,
		OperatorOrigin:     nextOperatorBinding,
		Clock: func() domain.Timestamp {
			return agentTestTimestamp
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nextOrigin.Close() })
	if err := nextOrigin.Recover(bootOriginTestContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	select {
	case <-recorder.verified:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("historical checkpoint replay did not complete")
	}
	if recorder.verificationCalls() != 2 {
		t.Fatalf(
			"checkpoint verification calls = %d, want 2",
			recorder.verificationCalls(),
		)
	}
	submitted := recorder.proposals()
	if len(submitted) != 1 ||
		!bytes.Equal(submitted[0], reserved.CanonicalBytes()) {
		t.Fatalf(
			"replayed proposals = %d; exact bytes = %t",
			len(submitted),
			len(submitted) == 1 &&
				bytes.Equal(submitted[0], reserved.CanonicalBytes()),
		)
	}
	lookup, found, err := reopened.AppliedCheckpoint(
		bootOriginTestContext(t),
		reserved.Proposal().EventID,
	)
	if err != nil || !found ||
		lookup.AppliedLogIndex != checkpoint.CoveredAppliedLogIndex+1 {
		t.Fatalf(
			"replayed checkpoint = (%#v, %t, %v)",
			lookup,
			found,
			err,
		)
	}
	scopes, err := reopened.LocalState().OutboxScopes(
		bootOriginTestContext(t),
	)
	if err != nil || len(scopes) != 0 {
		t.Fatalf("reopened outbox scopes = (%#v, %v)", scopes, err)
	}
}

func TestBootOriginSerializesWorkerAndCheckpointOperation(t *testing.T) {
	harness := newAgentTestHarness(t, nil)
	blocker := &releasingCheckpointConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	harness.boot.consensus = blocker
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	harness.boot.wakeWorker()
	select {
	case <-blocker.entered:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("worker did not begin forwarding")
	}
	invoked := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- harness.boot.RunExclusive(
			context.Background(),
			func(func(
				context.Context,
				domain.Checkpoint,
				store.Signature,
			) (event.SignedEvent, error)) error {
				close(invoked)
				return errBootOriginTestStop
			},
		)
	}()
	select {
	case <-invoked:
		t.Fatal("checkpoint operation crossed the worker lane")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocker.release)
	select {
	case <-invoked:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("checkpoint operation remained blocked")
	}
	if err := <-done; !errors.Is(err, errBootOriginTestStop) {
		t.Fatalf("RunExclusive() error = %v", err)
	}
}

func TestBootOriginRecoverDoesNotWaitForConsensusAvailability(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	blocker := &cancellationBlockingConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
	}
	harness.boot.consensus = blocker
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)

	if err := harness.boot.Recover(bootOriginTestContext(t)); err != nil {
		t.Fatalf("Recover(): %v", err)
	}
	select {
	case <-blocker.entered:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("recovery worker did not begin durable replay")
	}
}

func TestBootOriginRecoverValidatesEveryHistoricalOutboxRecord(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	attackerKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xa7}, ed25519.SeedSize),
	)
	defer clear(attackerKey)
	attackerDeviceID, err := device.DeriveID(
		attackerKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		attackerKey,
		attackerDeviceID,
		agentTestBootID,
		bootOriginTestRequestID,
		bootOriginTestEventID,
	)

	err = harness.boot.Recover(bootOriginTestContext(t))
	if !errors.Is(err, ErrBootOriginIntegrity) {
		t.Fatalf(
			"Recover() error = %v, want ErrBootOriginIntegrity",
			err,
		)
	}
	if !errors.Is(harness.boot.FatalError(), ErrBootOriginIntegrity) {
		t.Fatalf(
			"FatalError() = %v, want ErrBootOriginIntegrity",
			harness.boot.FatalError(),
		)
	}
}

func TestBootOriginRecoverRejectsBindingClassActorMismatch(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	conn, err := sqlite.OpenConn(
		harness.state.Path(),
		sqlite.OpenReadWrite,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.Execute(
		conn,
		`UPDATE local_requests
		    SET binding_class = 'daemon'
		  WHERE event_id = ?;`,
		&sqlitex.ExecOptions{
			Args: []any{string(bootOriginTestPriorEventID)},
		},
	); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	err = harness.boot.Recover(bootOriginTestContext(t))
	if !errors.Is(err, ErrBootOriginIntegrity) {
		t.Fatalf(
			"Recover() error = %v, want ErrBootOriginIntegrity",
			err,
		)
	}
	if !errors.Is(harness.boot.FatalError(), ErrBootOriginIntegrity) {
		t.Fatalf(
			"FatalError() = %v, want ErrBootOriginIntegrity",
			harness.boot.FatalError(),
		)
	}
}

func TestBootOriginQueuesReservationWhileWorkerAwaitsConsensus(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	blocker := &releasingCheckpointConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	defer close(blocker.release)
	harness.boot.consensus = blocker
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	harness.boot.wakeWorker()
	select {
	case <-blocker.entered:
	case <-bootOriginTestContext(t).Done():
		t.Fatal("worker did not begin forwarding")
	}

	var queued store.LocalCommandRecord
	err := harness.boot.RunBootReservation(
		bootOriginTestContext(t),
		func(context.Context) error {
			queued = reserveBootOriginOperatorTask(
				t,
				harness.local,
				harness.private,
				harness.deviceID,
				agentTestBootID,
				bootOriginTestRequestID,
				bootOriginTestEventID,
			)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("RunBootReservation(): %v", err)
	}
	if queued.OriginSequence != 2 {
		t.Fatalf(
			"queued origin sequence = %d, want 2",
			queued.OriginSequence,
		)
	}
}

func TestBootOriginOrderedReservationDrainsPredecessor(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	prior := reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)

	var queued store.LocalCommandRecord
	err := harness.boot.RunOrderedBootReservation(
		bootOriginTestContext(t),
		agentTestSessionID,
		agentTestWorkspaceID,
		harness.deviceID,
		agentTestBootID,
		func(ctx context.Context) error {
			resolved, found, lookupErr := harness.local.LookupRequest(
				ctx,
				prior.ClientInstanceID,
				prior.RequestID,
			)
			if lookupErr != nil {
				return lookupErr
			}
			if !found ||
				resolved.State != store.LocalRequestResolved ||
				resolved.Outcome == nil ||
				resolved.Outcome.Status != store.OutcomeAccepted {
				return errors.New(
					"ordered reservation ran before its predecessor settled",
				)
			}
			queued = reserveBootOriginOperatorTask(
				t,
				harness.local,
				harness.private,
				harness.deviceID,
				agentTestBootID,
				bootOriginTestRequestID,
				bootOriginTestEventID,
			)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("RunOrderedBootReservation(): %v", err)
	}
	if queued.OriginSequence != 2 {
		t.Fatalf(
			"ordered origin sequence = %d, want 2",
			queued.OriginSequence,
		)
	}
}

func TestBootOriginCancellationBeforeLaneLeavesSequenceUnused(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- harness.boot.RunBootReservation(
			context.Background(),
			func(context.Context) error {
				close(entered)
				<-release
				return nil
			},
		)
	}()
	<-entered
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	invoked := false
	err := harness.boot.RunExclusive(
		cancelled,
		func(func(
			context.Context,
			domain.Checkpoint,
			store.Signature,
		) (event.SignedEvent, error)) error {
			invoked = true
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) || invoked {
		t.Fatalf(
			"canceled RunExclusive() = (invoked=%t, err=%v)",
			invoked,
			err,
		)
	}
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatal(err)
	}
	var record store.LocalCommandRecord
	err = harness.boot.RunBootReservation(
		bootOriginTestContext(t),
		func(context.Context) error {
			record = reserveBootOriginOperatorTask(
				t,
				harness.local,
				harness.private,
				harness.deviceID,
				agentTestBootID,
				bootOriginTestPriorRequestID,
				bootOriginTestPriorEventID,
			)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.OriginSequence != 1 {
		t.Fatalf(
			"first sequence after cancellation = %d, want 1",
			record.OriginSequence,
		)
	}
}

func TestBootOriginRejectsMismatchedOrderedReservationBinding(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	invoked := false
	err := harness.boot.RunOrderedBootReservation(
		bootOriginTestContext(t),
		bootOriginTestNextBootID,
		agentTestWorkspaceID,
		harness.deviceID,
		agentTestBootID,
		func(context.Context) error {
			invoked = true
			return nil
		},
	)
	if !errors.Is(err, ErrBootOriginIntegrity) || invoked {
		t.Fatalf(
			"mismatched reservation = (invoked=%t, err=%v)",
			invoked,
			err,
		)
	}
	if !errors.Is(harness.boot.FatalError(), ErrBootOriginIntegrity) {
		t.Fatalf(
			"FatalError() = %v, want ErrBootOriginIntegrity",
			harness.boot.FatalError(),
		)
	}
}

func TestBootOriginPhasedCloseDoesNotJoinBeforeConsensusStops(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	blocker := &releasingCheckpointConsensus{
		delegate: harness.consensus,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	harness.boot.consensus = blocker
	reserveBootOriginOperatorTask(
		t,
		harness.local,
		harness.private,
		harness.deviceID,
		agentTestBootID,
		bootOriginTestPriorRequestID,
		bootOriginTestPriorEventID,
	)
	harness.boot.wakeWorker()
	<-blocker.entered
	if err := harness.boot.BeginClose(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- harness.boot.Wait()
	}()
	select {
	case err := <-waitDone:
		t.Fatalf("Wait() returned before consensus stopped: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(blocker.release)
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-bootOriginTestContext(t).Done():
		t.Fatal("Wait() did not finish after consensus stopped")
	}
}

func TestBootOriginWaitJoinsActiveReservationBeforeClearingKey(
	t *testing.T,
) {
	harness := newAgentTestHarness(t, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.Once{}
	releaseOperation := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	defer releaseOperation()

	operationDone := make(chan error, 1)
	go func() {
		operationDone <- harness.boot.RunBootReservation(
			context.Background(),
			func(context.Context) error {
				close(entered)
				<-release
				return nil
			},
		)
	}()
	<-entered
	if err := harness.boot.BeginClose(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- harness.boot.Wait()
	}()
	select {
	case err := <-waitDone:
		t.Fatalf("Wait() returned during active reservation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if bytes.Equal(
		harness.boot.privateKey,
		make([]byte, ed25519.PrivateKeySize),
	) {
		t.Fatal("private key cleared while reservation remained active")
	}

	releaseOperation()
	if err := <-operationDone; err != nil {
		t.Fatalf("RunBootReservation() error = %v", err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-bootOriginTestContext(t).Done():
		t.Fatal("Wait() did not join the completed reservation")
	}
	if !bytes.Equal(
		harness.boot.privateKey,
		make([]byte, ed25519.PrivateKeySize),
	) {
		t.Fatal("private key was not cleared after shutdown")
	}
}

type fixedIDGenerator struct {
	mu     sync.Mutex
	values []domain.UUIDv7
}

func (generator *fixedIDGenerator) next() (domain.UUIDv7, error) {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	if len(generator.values) == 0 {
		return "", errors.New("fixed ID generator exhausted")
	}
	value := generator.values[0]
	generator.values = generator.values[1:]
	return value, nil
}

func (generator *fixedIDGenerator) remaining() int {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	return len(generator.values)
}

type bootOriginActivationHarness struct {
	state     *store.Store
	local     store.LocalState
	boot      *BootOrigin
	consensus *fsmConsensus
	deviceID  domain.DeviceID
	private   ed25519.PrivateKey
	target    []domain.DeviceID
	keys      map[domain.DeviceID]ed25519.PrivateKey
	ids       *fixedIDGenerator
}

func newBootOriginActivationHarness(
	t *testing.T,
) *bootOriginActivationHarness {
	t.Helper()
	initial, privateKey, deviceID := bootOriginInitialState(t)
	keys := map[domain.DeviceID]ed25519.PrivateKey{
		deviceID: privateKey,
	}
	target := []domain.DeviceID{deviceID}
	for _, fill := range []byte{0x41, 0x51} {
		key := ed25519.NewKeyFromSeed(
			bytes.Repeat([]byte{fill}, ed25519.SeedSize),
		)
		memberID, err := device.DeriveID(
			key.Public().(ed25519.PublicKey),
		)
		if err != nil {
			t.Fatal(err)
		}
		keys[memberID] = key
		target = append(target, memberID)
		initial.Projections.Devices = append(
			initial.Projections.Devices,
			device.Device{
				ID:                memberID,
				Role:              device.RoleEditor,
				IdentityPublicKey: key.Public().(ed25519.PublicKey),
				DaemonVersion:     "0.1.0",
				MaxApplyLevel:     1,
				Status:            device.StatusActive,
				EntityVersion:     1,
			},
		)
		initial.Projections.AuditCounters = append(
			initial.Projections.AuditCounters,
			auditcounter.Counter{DeviceID: memberID},
		)
	}
	sort.Slice(target, func(left, right int) bool {
		return target[left] < target[right]
	})
	voterTarget, err := voterset.New(agentTestSessionID, target, 2)
	if err != nil {
		t.Fatal(err)
	}
	initial.Projections.VoterSet = []voterset.Set{voterTarget}

	state, err := store.Open(context.Background(), store.Options{
		Path: filepath.Join(t.TempDir(), "state", "state.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Initialize(context.Background(), initial); err != nil {
		_ = state.Close()
		t.Fatalf("Initialize(): %v", err)
	}
	applyClock := func() (domain.Timestamp, int64, error) {
		return agentTestTimestamp, int64(time.Second), nil
	}
	fsm, err := consensus.NewFSM(consensus.FSMOptions{
		Store:        state,
		OriginBootID: agentTestBootID,
		Clock:        applyClock,
	})
	if err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	runtime := &fsmConsensus{
		fsm:   fsm,
		store: state,
		clock: applyClock,
	}
	runtime.leader.Store(true)
	authority, err := event.NewLocalAuthority(deviceID, agentTestBootID)
	if err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	binding, err := authority.DaemonBinding()
	if err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	operatorBinding, err := authority.OperatorBinding()
	if err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	ids := &fixedIDGenerator{values: []domain.UUIDv7{
		bootOriginTestRequestID,
		bootOriginTestEventID,
	}}
	boot, err := NewBootOrigin(BootOriginOptions{
		Consensus:          runtime,
		LocalState:         state.LocalState(),
		SessionID:          agentTestSessionID,
		WorkspaceID:        agentTestWorkspaceID,
		DeviceID:           deviceID,
		OriginBootID:       agentTestBootID,
		IdentityPrivateKey: privateKey,
		DaemonOrigin:       binding,
		OperatorOrigin:     operatorBinding,
		Clock: func() domain.Timestamp {
			return agentTestTimestamp
		},
		GenerateID: ids.next,
	})
	if err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = boot.Close()
		_ = state.Close()
		for _, key := range keys {
			clear(key)
		}
	})
	return &bootOriginActivationHarness{
		state:     state,
		local:     state.LocalState(),
		boot:      boot,
		consensus: runtime,
		deviceID:  deviceID,
		private:   privateKey,
		target:    target,
		keys:      keys,
		ids:       ids,
	}
}

func bootOriginActivationPayload(
	t *testing.T,
	harness *bootOriginActivationHarness,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
) voteractivation.ActivationPayload {
	t.Helper()
	checkpoint := domain.Checkpoint{
		SessionID:                sessionID,
		WorkspaceID:              workspaceID,
		RecoveryGeneration:       generation,
		AuthorityVoterSetVersion: 1,
		SignerDeviceID:           harness.deviceID,
		Term:                     1,
		CoveredAppliedLogIndex:   1,
		CoveredChainIndex:        1,
		CoveredResultIndex:       1,
		DigestVersion:            1,
		ProjectionSchemaVersion:  1,
	}
	copy(
		checkpoint.CoveredChainHash[:],
		bytes.Repeat([]byte{0x61}, len(checkpoint.CoveredChainHash)),
	)
	copy(
		checkpoint.CoveredResultHash[:],
		bytes.Repeat([]byte{0x62}, len(checkpoint.CoveredResultHash)),
	)
	copy(
		checkpoint.ProjectionAccumulator[:],
		bytes.Repeat([]byte{0x63}, len(checkpoint.ProjectionAccumulator)),
	)
	checkpointSignature, err := event.SignCheckpoint(
		checkpoint,
		harness.private,
	)
	if err != nil {
		t.Fatal(err)
	}
	proofs := make([]voteractivation.Proof, len(harness.target))
	for index, voterID := range harness.target {
		unsigned, err := voteractivation.NewUnsignedProof(
			voteractivation.ProofInput{
				SessionID:                       sessionID,
				WorkspaceID:                     workspaceID,
				RecoveryGeneration:              generation,
				TargetVoterSetVersion:           2,
				CurrentAuthorityVoterSetVersion: 1,
				VoterSet:                        harness.target,
				VoterDeviceID:                   voterID,
				LiveConfigurationIndex:          1,
				CheckpointEventID:               bootOriginTestPriorEventID,
				Checkpoint:                      checkpoint,
				CheckpointSignature:             checkpointSignature,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		proofs[index], err = voteractivation.SignProof(
			unsigned,
			harness.keys[voterID],
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	handoff, err := voteractivation.NewUnsignedAuthorityHandoff(
		voteractivation.AuthorityHandoffInput{
			SessionID:                        sessionID,
			WorkspaceID:                      workspaceID,
			RecoveryGeneration:               generation,
			TargetVoterSetVersion:            2,
			ExpectedAuthorityVoterSetVersion: 1,
			VoterSet:                         harness.target,
			ActivationCheckpointEventID:      bootOriginTestPriorEventID,
			ActivationProofs:                 proofs,
			PriorAuthoritySigner:             harness.deviceID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := voteractivation.SignAuthorityHandoff(
		handoff,
		harness.private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func bootOriginCredentialAuthorization(
	t *testing.T,
	harness *bootOriginActivationHarness,
) credentialauthorization.Authorization {
	t.Helper()
	epochPrivateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x71}, ed25519.SeedSize),
	)
	defer clear(epochPrivateKey)
	binding, err := credential.SignBinding(
		agentTestSessionID,
		harness.deviceID,
		1,
		epochPrivateKey.Public().(ed25519.PublicKey),
		harness.private,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization := credentialauthorization.Authorization{
		SessionID:                agentTestSessionID,
		DeviceID:                 harness.deviceID,
		Epoch:                    binding.Epoch,
		EpochPublicKey:           binding.EpochPublicKey,
		KeyDigest:                binding.KeyDigest,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 domain.WholeSecondTimestamp(agentTestTimestamp),
		NotBefore:                domain.WholeSecondTimestamp(agentTestTimestamp),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		BindingSignature:         binding.Signature,
	}
	preimage, err := credentialauthorization.CanonicalEndorsementPreimage(
		authorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := codecommcrypto.SignEd25519(
		harness.private,
		codec.SignatureCredentialTimeEndorsement,
		preimage,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization.ClockEndorsements = []credentialauthorization.ClockEndorsement{{
		DeviceID: harness.deviceID,
	}}
	copy(authorization.ClockEndorsements[0].Signature[:], signature)
	return authorization
}

type releasingCheckpointConsensus struct {
	delegate CheckpointConsensus
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (runtime *releasingCheckpointConsensus) ApplyAtGeneration(
	ctx context.Context,
	sessionID domain.UUIDv7,
	generation uint64,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	runtime.once.Do(func() {
		close(runtime.entered)
	})
	<-runtime.release
	return runtime.delegate.ApplyAtGeneration(
		ctx,
		sessionID,
		generation,
		signed,
	)
}

func (runtime *releasingCheckpointConsensus) IsLeader() bool {
	return runtime.delegate.IsLeader()
}

func (runtime *releasingCheckpointConsensus) FatalError() error {
	return runtime.delegate.FatalError()
}

func (runtime *releasingCheckpointConsensus) VerifyCheckpointReplay(
	ctx context.Context,
	signed event.SignedEvent,
	result store.ApplyResult,
) error {
	return runtime.delegate.VerifyCheckpointReplay(ctx, signed, result)
}

type recordingCheckpointConsensus struct {
	delegate        CheckpointConsensus
	mu              sync.Mutex
	applied         [][]byte
	completed       chan struct{}
	completedOnce   sync.Once
	verified        chan struct{}
	verifiedOnce    sync.Once
	verifyFailures  int
	verifyCallCount int
}

func (runtime *recordingCheckpointConsensus) ApplyAtGeneration(
	ctx context.Context,
	sessionID domain.UUIDv7,
	generation uint64,
	signed event.SignedEvent,
) (store.ApplyResult, error) {
	runtime.mu.Lock()
	runtime.applied = append(
		runtime.applied,
		bytes.Clone(signed.CanonicalBytes()),
	)
	runtime.mu.Unlock()
	result, err := runtime.delegate.ApplyAtGeneration(
		ctx,
		sessionID,
		generation,
		signed,
	)
	if runtime.completed != nil {
		runtime.completedOnce.Do(func() {
			close(runtime.completed)
		})
	}
	return result, err
}

func (runtime *recordingCheckpointConsensus) IsLeader() bool {
	return runtime.delegate.IsLeader()
}

func (runtime *recordingCheckpointConsensus) FatalError() error {
	return runtime.delegate.FatalError()
}

func (runtime *recordingCheckpointConsensus) VerifyCheckpointReplay(
	ctx context.Context,
	signed event.SignedEvent,
	result store.ApplyResult,
) error {
	runtime.mu.Lock()
	runtime.verifyCallCount++
	if runtime.verifyFailures > 0 {
		runtime.verifyFailures--
		runtime.mu.Unlock()
		return errors.New("transient checkpoint lookup failure")
	}
	runtime.mu.Unlock()
	err := runtime.delegate.VerifyCheckpointReplay(ctx, signed, result)
	if err == nil && runtime.verified != nil {
		runtime.verifiedOnce.Do(func() {
			close(runtime.verified)
		})
	}
	return err
}

func (runtime *recordingCheckpointConsensus) proposals() [][]byte {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([][]byte, len(runtime.applied))
	for index := range runtime.applied {
		result[index] = bytes.Clone(runtime.applied[index])
	}
	return result
}

func (runtime *recordingCheckpointConsensus) verificationCalls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.verifyCallCount
}

func (runtime *cancellationBlockingConsensus) VerifyCheckpointReplay(
	ctx context.Context,
	signed event.SignedEvent,
	result store.ApplyResult,
) error {
	delegate, ok := runtime.delegate.(CheckpointConsensus)
	if !ok {
		return errors.New("delegate cannot verify checkpoints")
	}
	return delegate.VerifyCheckpointReplay(ctx, signed, result)
}

func reserveBootOriginOperatorTask(
	t *testing.T,
	local store.LocalState,
	privateKey ed25519.PrivateKey,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	requestID domain.UUIDv7,
	eventID domain.UUIDv7,
) store.LocalCommandRecord {
	t.Helper()
	authority, err := event.NewLocalAuthority(deviceID, bootID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := authority.OperatorBinding()
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := local.ReserveCommand(
		bootOriginTestContext(t),
		store.LocalCommandInput{
			ClientInstanceID: requestID,
			RequestID:        requestID,
			SessionID:        agentTestSessionID,
			WorkspaceID:      agentTestWorkspaceID,
			BindingClass:     store.LocalBindingOperator,
			OriginDeviceID:   deviceID,
			OriginScopeKind:  store.OriginScopeKindBoot,
			OriginScopeID:    bootID,
			RequestKind:      event.KindTaskCreated,
			CanonicalRequest: []byte(
				`{"operation":"boot-origin-test"}`,
			),
			CreatedAt: agentTestTimestamp,
		},
		func() (domain.UUIDv7, error) {
			return eventID, nil
		},
		func(
			generatedEventID domain.UUIDv7,
			sequence uint64,
		) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				event.Command{
					Kind: event.KindTaskCreated,
					EntityID: event.StringEntityID(
						string(bootOriginTestTaskID),
					),
					Actions: []event.Action{},
					Payload: []byte(
						`{"priority":2,"title":"prior command"}`,
					),
					Redaction: defaultRedaction(),
				},
				binding,
				event.BuildContext{
					EventID:        generatedEventID,
					SessionID:      agentTestSessionID,
					WorkspaceID:    agentTestWorkspaceID,
					CreatedAt:      agentTestTimestamp,
					OriginSequence: sequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, privateKey)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func bootOriginInitialState(
	t *testing.T,
) (store.InitialState, ed25519.PrivateKey, domain.DeviceID) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x31}, ed25519.SeedSize),
	)
	publicKey := bytes.Clone(
		privateKey.Public().(ed25519.PublicKey),
	)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	target, err := voterset.New(
		agentTestSessionID,
		[]domain.DeviceID{deviceID},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawGenesis, err := json.Marshal(map[string]any{
		"recovery_generation": uint64(0),
		"recovery_public_key": codec.EncodeBase64URL(publicKey),
		"session_id":          agentTestSessionID,
		"workspace_id":        agentTestWorkspaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := codec.CanonicalizeSignedObject(rawGenesis)
	if err != nil {
		t.Fatal(err)
	}
	return store.InitialState{
		SessionID:               agentTestSessionID,
		WorkspaceID:             agentTestWorkspaceID,
		GenesisJSON:             genesis,
		DigestVersion:           1,
		ProjectionSchemaVersion: 1,
		Projections: store.ProjectionWrites{
			AuditCounters: []auditcounter.Counter{{DeviceID: deviceID}},
			PlanCurrent: []plan.Current{{
				SessionID:     agentTestSessionID,
				EntityVersion: 1,
			}},
			Devices: []device.Device{{
				ID:                deviceID,
				Role:              device.RoleOwner,
				IdentityPublicKey: publicKey,
				DaemonVersion:     "0.1.0",
				MaxApplyLevel:     1,
				Status:            device.StatusActive,
				EntityVersion:     1,
			}},
			VoterSet: []voterset.Set{target},
			CredentialAuthority: []store.CredentialAuthorityRow{{
				SessionID:        agentTestSessionID,
				VoterDeviceIDs:   []domain.DeviceID{deviceID},
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
				SessionID:     agentTestSessionID,
				Values:        policy.DefaultValues(),
				EntityVersion: 1,
			}},
		},
	}, privateKey, deviceID
}

func bootOriginRaftConfig() *raft.Config {
	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 500 * time.Millisecond
	config.ElectionTimeout = 500 * time.Millisecond
	config.CommitTimeout = 10 * time.Millisecond
	config.LeaderLeaseTimeout = 250 * time.Millisecond
	config.SnapshotInterval = time.Hour
	config.SnapshotThreshold = 1_000
	config.TrailingLogs = 32
	config.LogLevel = "ERROR"
	return config
}

func bootOriginTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}
