package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	checkpointSignerCatchUpRetry = 20 * time.Millisecond
	checkpointSignerTimeout      = 2 * time.Second
)

var (
	ErrCheckpointOriginUnavailable = errors.New(
		"consensus: checkpoint event origin is unavailable",
	)
	ErrInvalidCheckpointEvent = errors.New(
		"consensus: checkpoint origin returned an invalid event",
	)
	ErrCheckpointCommitRejected = errors.New(
		"consensus: checkpoint command was rejected",
	)
	errCheckpointCutUnsettled = errors.New(
		"consensus: checkpoint capture cut is unsettled",
	)
	errCheckpointSignerTimeout = errors.New(
		"consensus: checkpoint signer selection timed out",
	)
)

// CheckpointReservation durably reserves and signs one exact daemon-origin
// checkpoint event. A successful reservation must survive process restart.
type CheckpointReservation func(
	context.Context,
	domain.Checkpoint,
	store.Signature,
) (event.SignedEvent, error)

// CheckpointOrigin owns exclusive access to the local boot-origin sequence.
// RunExclusive must wait for earlier boot-origin commands, prevent another
// forwarder from claiming a newly reserved checkpoint until operation
// returns, honor context cancellation while waiting and running, invoke an
// admitted operation synchronously exactly once, and propagate its error.
// Every successful reservation, including a stale-checkpoint retry, must use
// the same device and boot IDs reported here plus a fresh event ID and the next
// boot-origin sequence.
type CheckpointOrigin interface {
	DeviceID() domain.DeviceID
	BootID() domain.UUIDv7
	RunExclusive(
		context.Context,
		func(CheckpointReservation) error,
	) error
}

type checkpointCapture struct {
	leadership      raftLeadershipEpoch
	appliedLogIndex uint64
	view            store.StateView
	state           decodedState
}

// ForceCheckpoint captures and commits one authority-signed checkpoint. It is
// the primitive used by periodic scheduling and voter-set reconciliation.
func (node *SingleNode) ForceCheckpoint(
	ctx context.Context,
) (store.AppliedCheckpointLookup, error) {
	if node == nil || node.raft == nil || node.state == nil || ctx == nil {
		return store.AppliedCheckpointLookup{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	if node.checkpointOrigin == nil {
		return store.AppliedCheckpointLookup{},
			ErrCheckpointOriginUnavailable
	}
	if err := node.beginOperation(); err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()

	var (
		result       store.AppliedCheckpointLookup
		operationErr error
		invoked      bool
	)
	err := node.checkpointOrigin.RunExclusive(
		operationContext,
		func(reserve CheckpointReservation) error {
			if invoked || reserve == nil {
				operationErr = ErrCheckpointOriginUnavailable
				return operationErr
			}
			invoked = true
			result, operationErr = node.forceCheckpointExclusive(
				operationContext,
				reserve,
			)
			return operationErr
		},
	)
	if err != nil {
		return store.AppliedCheckpointLookup{}, err
	}
	if operationErr != nil {
		return store.AppliedCheckpointLookup{}, operationErr
	}
	if !invoked {
		return store.AppliedCheckpointLookup{},
			ErrCheckpointOriginUnavailable
	}
	return result, nil
}

func (node *SingleNode) forceCheckpointExclusive(
	ctx context.Context,
	reserve CheckpointReservation,
) (store.AppliedCheckpointLookup, error) {
	if reserve == nil {
		return store.AppliedCheckpointLookup{},
			ErrCheckpointOriginUnavailable
	}
	var (
		previousEventID  domain.UUIDv7
		previousSequence uint64
	)
	for {
		var (
			reservedEventID  domain.UUIDv7
			reservedSequence uint64
		)
		checkedReserve := func(
			ctx context.Context,
			checkpoint domain.Checkpoint,
			signature store.Signature,
		) (event.SignedEvent, error) {
			signed, err := reserve(ctx, checkpoint, signature)
			if err != nil {
				return event.SignedEvent{}, err
			}
			proposal := signed.Proposal()
			reservedEventID = proposal.EventID
			reservedSequence = proposal.Origin.Sequence()
			if previousEventID.Valid() &&
				(proposal.EventID == previousEventID ||
					previousSequence >= domain.MaxSafeInteger ||
					proposal.Origin.Sequence() !=
						previousSequence+1) {
				return event.SignedEvent{}, fmt.Errorf(
					"%w: stale retry did not advance event identity and origin sequence",
					ErrInvalidCheckpointEvent,
				)
			}
			return signed, nil
		}
		lookup, stale, err := node.forceCheckpointAttempt(
			ctx,
			checkedReserve,
		)
		if err != nil {
			if errors.Is(err, ErrInvalidCheckpointEvent) &&
				reservedEventID.Valid() {
				return store.AppliedCheckpointLookup{},
					node.haltNode(err)
			}
			return store.AppliedCheckpointLookup{}, err
		}
		if !stale {
			return lookup, nil
		}
		if reservedEventID.Valid() {
			previousEventID = reservedEventID
			previousSequence = reservedSequence
		}
		if err := ctx.Err(); err != nil {
			return store.AppliedCheckpointLookup{}, err
		}
	}
}

func (node *SingleNode) forceCheckpointAttempt(
	ctx context.Context,
	reserve CheckpointReservation,
) (store.AppliedCheckpointLookup, bool, error) {
	guard, err := node.acquireRaftEnqueue(ctx)
	if err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	defer guard.release()

	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	if err := waitFuture(
		ctx,
		node.raft.Barrier(contextTimeout(ctx)),
	); err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	if err := node.requireConfigurationLeadershipEpoch(
		leadership,
	); err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	capture, err := node.captureCheckpointState(ctx)
	if err != nil {
		if errors.Is(err, errCheckpointCutUnsettled) {
			return store.AppliedCheckpointLookup{}, true, nil
		}
		return store.AppliedCheckpointLookup{}, false, err
	}
	if capture.leadership != leadership {
		return store.AppliedCheckpointLookup{},
			false,
			ErrLeadershipEpochChanged
	}
	expectation, signature, err := node.collectCheckpointSignature(
		ctx,
		capture,
	)
	if err != nil {
		if errors.Is(err, errCheckpointCutUnsettled) {
			return store.AppliedCheckpointLookup{}, true, nil
		}
		return store.AppliedCheckpointLookup{}, false, err
	}
	if err := node.requireCheckpointCapture(
		ctx,
		expectation,
	); err != nil {
		if errors.Is(err, errCheckpointCutUnsettled) {
			return store.AppliedCheckpointLookup{}, true, nil
		}
		return store.AppliedCheckpointLookup{}, false, err
	}
	signed, err := reserve(
		ctx,
		expectation.checkpoint,
		signature,
	)
	if err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	signed, err = node.validateCheckpointEvent(
		capture,
		expectation,
		signature,
		signed,
	)
	if err != nil {
		return store.AppliedCheckpointLookup{},
			false,
			node.haltNode(err)
	}
	applyResult, err := node.applyCheckpointWithGuard(
		ctx,
		signed,
		guard,
	)
	if err != nil {
		return store.AppliedCheckpointLookup{}, false, err
	}
	if applyResult.Outcome.Status == store.OutcomeRejected {
		if applyResult.Outcome.Code ==
			string(reducer.CodeStaleCheckpoint) {
			return store.AppliedCheckpointLookup{}, true, nil
		}
		return store.AppliedCheckpointLookup{},
			false,
			node.haltNode(fmt.Errorf(
				"%w: %s",
				ErrCheckpointCommitRejected,
				applyResult.Outcome.Code,
			))
	}
	if applyResult.Outcome.Status != store.OutcomeAccepted {
		return store.AppliedCheckpointLookup{},
			false,
			node.haltNode(ErrCheckpointCommitRejected)
	}

	eventID := signed.Proposal().EventID
	lookup, found, err := node.state.AppliedCheckpoint(ctx, eventID)
	if err != nil {
		return store.AppliedCheckpointLookup{},
			false,
			node.handleCheckpointLookupError(err)
	}
	if !found ||
		lookup.AppliedLogIndex !=
			expectation.checkpoint.CoveredAppliedLogIndex+1 ||
		lookup.Record.CheckpointEventID != eventID ||
		!bytes.Equal(
			lookup.Record.CheckpointJSON,
			expectation.checkpointJSON,
		) ||
		lookup.Record.AuthoritySignature != signature {
		return store.AppliedCheckpointLookup{},
			false,
			node.haltNode(errors.New(
				"accepted checkpoint lacks its exact durable binding",
			))
	}
	return lookup, false, nil
}

func (node *SingleNode) handleCheckpointLookupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrAppliedCheckpointIntegrity) ||
		errors.Is(err, store.ErrIntegrityCheck) ||
		errors.Is(err, store.ErrCorrupt) {
		return node.haltNode(fmt.Errorf(
			"committed checkpoint lookup failed integrity checks: %w",
			err,
		))
	}
	return err
}

func (node *SingleNode) captureCheckpointState(
	ctx context.Context,
) (checkpointCapture, error) {
	if node == nil || node.raft == nil || node.state == nil || ctx == nil {
		return checkpointCapture{}, ErrInvalidNodeOptions
	}
	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return checkpointCapture{}, err
	}
	commitBefore := node.raft.CommitIndex()
	appliedBefore := node.raft.AppliedIndex()
	if commitBefore < 1 {
		return checkpointCapture{}, ErrConsensusAuthorizationUnavailable
	}
	if appliedBefore != commitBefore {
		return checkpointCapture{}, errCheckpointCutUnsettled
	}
	ready, err := node.appliedThroughCommit(commitBefore)
	if err != nil {
		return checkpointCapture{}, err
	}
	if !ready {
		return checkpointCapture{}, errCheckpointCutUnsettled
	}
	view, err := node.state.View(ctx)
	if err != nil {
		return checkpointCapture{}, err
	}
	commitAfter := node.raft.CommitIndex()
	appliedAfter := node.raft.AppliedIndex()
	if commitAfter != commitBefore ||
		appliedAfter != appliedBefore {
		return checkpointCapture{}, errCheckpointCutUnsettled
	}
	if view.LastRaftAppliedLogIndex != nil &&
		*view.LastRaftAppliedLogIndex > appliedAfter {
		return checkpointCapture{}, ErrConsensusAuthorizationUnavailable
	}
	if err := node.requireConfigurationLeadershipEpoch(
		leadership,
	); err != nil {
		return checkpointCapture{}, err
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return checkpointCapture{}, err
	}
	if decoded.CredentialAuthority.Validate() != nil ||
		decoded.CredentialAuthority.SessionID != view.SessionID {
		return checkpointCapture{}, ErrConsensusAuthorizationUnavailable
	}
	return checkpointCapture{
		leadership:      leadership,
		appliedLogIndex: appliedAfter,
		view:            view,
		state:           decoded,
	}, nil
}

func (capture checkpointCapture) signingExpectation(
	signerDeviceID domain.DeviceID,
) (checkpointSigningExpectation, error) {
	member, exists := capture.state.Admission.Member(signerDeviceID)
	publicKey, keyExists := capture.state.IdentityPublicKey(signerDeviceID)
	if !exists ||
		member.Status != device.StatusActive ||
		!capture.state.CredentialAuthority.Contains(signerDeviceID) ||
		!keyExists {
		return checkpointSigningExpectation{},
			ErrInvalidCheckpointProof
	}
	checkpoint := domain.Checkpoint{
		SessionID:          capture.view.SessionID,
		WorkspaceID:        capture.view.WorkspaceID,
		RecoveryGeneration: capture.view.RecoveryGeneration,
		AuthorityVoterSetVersion: capture.state.
			CredentialAuthority.VoterSetVersion,
		SignerDeviceID:         signerDeviceID,
		Term:                   capture.leadership.term,
		CoveredAppliedLogIndex: capture.appliedLogIndex,
		CoveredChainIndex:      capture.view.Heads.ChainIndex,
		CoveredChainHash:       capture.view.Heads.ChainHash,
		CoveredResultIndex:     capture.view.Heads.ResultIndex,
		CoveredResultHash:      capture.view.Heads.ResultHash,
		ProjectionAccumulator:  capture.view.Heads.ProjectionAccumulator,
		DigestVersion:          capture.view.Heads.DigestVersion,
		ProjectionSchemaVersion: capture.view.Heads.
			ProjectionSchemaVersion,
	}
	return newCheckpointSigningExpectation(checkpoint, publicKey)
}

func (node *SingleNode) collectCheckpointSignature(
	ctx context.Context,
	capture checkpointCapture,
) (
	checkpointSigningExpectation,
	store.Signature,
	error,
) {
	signingContext, cancel := context.WithTimeout(
		ctx,
		checkpointSignerTimeout,
	)
	defer cancel()
	expectation, signature, err := node.collectCheckpointSignatureWithin(
		signingContext,
		capture,
	)
	if err != nil &&
		ctx.Err() == nil &&
		errors.Is(err, context.DeadlineExceeded) {
		return checkpointSigningExpectation{},
			store.Signature{},
			fmt.Errorf(
				"%w: %w",
				ErrCheckpointProofUnavailable,
				errCheckpointSignerTimeout,
			)
	}
	return expectation, signature, err
}

func (node *SingleNode) collectCheckpointSignatureWithin(
	ctx context.Context,
	capture checkpointCapture,
) (
	checkpointSigningExpectation,
	store.Signature,
	error,
) {
	localDeviceID := domain.DeviceID(node.serverID)
	candidates := capture.state.CredentialAuthority.VoterIDs()
	if capture.state.CredentialAuthority.Contains(localDeviceID) {
		candidates = append(
			[]domain.DeviceID{localDeviceID},
			removeCheckpointSigner(candidates, localDeviceID)...,
		)
	}

	var failures []error
	pending := make([]checkpointSigningExpectation, 0, len(candidates))
	for _, signerDeviceID := range candidates {
		if err := ctx.Err(); err != nil {
			return checkpointSigningExpectation{},
				store.Signature{},
				err
		}
		expectation, err := capture.signingExpectation(
			signerDeviceID,
		)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if signerDeviceID == localDeviceID {
			if node.checkpointSigner == nil {
				failures = append(
					failures,
					errConsensusCheckpointSignerUnavailable,
				)
				continue
			}
			signature, err := node.checkpointSigner.SignCheckpoint(
				ctx,
				expectation.checkpoint,
			)
			if err == nil {
				proof := checkpointSignatureProof{
					expectation: expectation,
					signature:   signature,
				}
				if _, verifyErr := encodeCheckpointSignResponse(
					proof,
				); verifyErr == nil {
					return expectation, signature, nil
				}
				err = errConsensusCheckpointSignerInvalid
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return checkpointSigningExpectation{},
					store.Signature{},
					contextErr
			}
			failures = append(failures, err)
			continue
		}
		if node.checkpointRequester == nil {
			failures = append(
				failures,
				ErrCheckpointProofUnavailable,
			)
			continue
		}
		proof, err := requestCheckpointSignature(
			ctx,
			node.checkpointRequester,
			expectation,
		)
		if err == nil {
			return expectation, proof.signature, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return checkpointSigningExpectation{},
				store.Signature{},
				contextErr
		}
		if errors.Is(err, errCheckpointSignerNotApplied) {
			pending = append(pending, expectation)
		} else {
			failures = append(failures, err)
		}
	}

	if len(pending) > 0 {
		proof, err := retryRemoteCheckpointSignatures(
			ctx,
			node.checkpointRequester,
			pending,
		)
		if err == nil {
			return proof.expectation, proof.signature, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return checkpointSigningExpectation{},
				store.Signature{},
				contextErr
		}
		failures = append(failures, err)
	}
	return checkpointSigningExpectation{},
		store.Signature{},
		fmt.Errorf(
			"%w: %w",
			ErrCheckpointProofUnavailable,
			errors.Join(failures...),
		)
}

func retryRemoteCheckpointSignatures(
	ctx context.Context,
	requester consensusProofRequester,
	pending []checkpointSigningExpectation,
) (checkpointSignatureProof, error) {
	if ctx == nil || requester == nil || len(pending) == 0 {
		return checkpointSignatureProof{}, ErrInvalidCheckpointProof
	}
	candidates := append(
		[]checkpointSigningExpectation(nil),
		pending...,
	)
	var failures []error
	for len(candidates) > 0 {
		if err := waitCheckpointSignerCatchUp(ctx); err != nil {
			return checkpointSignatureProof{}, err
		}
		next := make(
			[]checkpointSigningExpectation,
			0,
			len(candidates),
		)
		for _, expectation := range candidates {
			proof, err := requestCheckpointSignature(
				ctx,
				requester,
				expectation,
			)
			if err == nil {
				return proof, nil
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return checkpointSignatureProof{}, contextErr
			}
			if errors.Is(err, errCheckpointSignerNotApplied) {
				next = append(next, expectation)
			} else {
				failures = append(failures, err)
			}
		}
		candidates = next
	}
	return checkpointSignatureProof{}, fmt.Errorf(
		"%w: %w",
		ErrCheckpointProofUnavailable,
		errors.Join(failures...),
	)
}

func waitCheckpointSignerCatchUp(ctx context.Context) error {
	timer := time.NewTimer(checkpointSignerCatchUpRetry)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func removeCheckpointSigner(
	deviceIDs []domain.DeviceID,
	excluded domain.DeviceID,
) []domain.DeviceID {
	result := make([]domain.DeviceID, 0, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		if deviceID != excluded {
			result = append(result, deviceID)
		}
	}
	return result
}

func (node *SingleNode) requireCheckpointCapture(
	ctx context.Context,
	expected checkpointSigningExpectation,
) error {
	current, err := node.captureCheckpointState(ctx)
	if err != nil {
		return err
	}
	actual, err := current.signingExpectation(
		expected.checkpoint.SignerDeviceID,
	)
	if err != nil ||
		!sameCheckpointSigningExpectation(expected, actual) {
		return errCheckpointCutUnsettled
	}
	return nil
}

func (node *SingleNode) validateCheckpointEvent(
	capture checkpointCapture,
	expectation checkpointSigningExpectation,
	signature store.Signature,
	signed event.SignedEvent,
) (event.SignedEvent, error) {
	localDeviceID := domain.DeviceID(node.serverID)
	publicKey, exists := capture.state.IdentityPublicKey(localDeviceID)
	if !exists {
		return event.SignedEvent{}, ErrInvalidCheckpointEvent
	}
	canonical := signed.CanonicalBytes()
	verified, err := event.ParseAndVerify(
		canonical,
		event.VerificationContext{
			SessionID:         capture.view.SessionID,
			WorkspaceID:       capture.view.WorkspaceID,
			IdentityPublicKey: publicKey,
		},
	)
	if err != nil ||
		!bytes.Equal(verified.CanonicalBytes(), canonical) {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: origin signature",
			ErrInvalidCheckpointEvent,
		)
	}
	expectedPayload, err := event.EncodeCheckpointPayload(
		expectation.checkpoint,
		[ed25519.SignatureSize]byte(signature),
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	proposal := verified.Proposal()
	if proposal.Kind != event.KindConsensusCheckpoint ||
		proposal.SessionID != capture.view.SessionID ||
		proposal.WorkspaceID != capture.view.WorkspaceID ||
		proposal.Origin.DeviceID() != localDeviceID ||
		proposal.Origin.ActorType() != event.ActorDaemon ||
		proposal.Origin.OriginBootID() != node.originBootID ||
		proposal.Origin.AgentSessionID() != "" ||
		!proposal.EntityID.IsNull() ||
		proposal.ExpectedEntityVersion != nil ||
		proposal.RationaleSummary != "" ||
		len(proposal.Actions) != 0 ||
		proposal.Redaction.Policy != event.RedactionDefault ||
		len(proposal.Redaction.FieldsRemoved) != 0 ||
		!bytes.Equal(proposal.Payload, expectedPayload) {
		return event.SignedEvent{}, ErrInvalidCheckpointEvent
	}
	return verified, nil
}

func (node *SingleNode) applyCheckpointWithGuard(
	ctx context.Context,
	signed event.SignedEvent,
	guard *raftEnqueueGuard,
) (store.ApplyResult, error) {
	if guard == nil || guard.node != node {
		return store.ApplyResult{}, ErrInvalidNodeOptions
	}
	proposal := signed.Proposal()
	canonical := signed.CanonicalBytes()
	if !proposal.EventID.Valid() || len(canonical) == 0 {
		return store.ApplyResult{}, ErrInvalidCheckpointEvent
	}
	flight, owner, committed, found, err := node.beginProposal(
		ctx,
		signed,
		canonical,
	)
	if err != nil {
		guard.release()
		return store.ApplyResult{}, node.handleLookupError(err)
	}
	if found {
		guard.release()
		return committed, nil
	}
	if owner {
		if err := node.preEnqueueError(ctx); err != nil {
			node.finishProposal(
				proposal.EventID,
				flight,
				store.ApplyResult{},
				err,
				false,
			)
		} else {
			future, err := node.enqueueRaftApply(
				ctx,
				canonical,
				guard,
			)
			if err != nil {
				node.finishProposal(
					proposal.EventID,
					flight,
					store.ApplyResult{},
					err,
					false,
				)
			} else {
				node.active.Add(1)
				go node.resolveProposal(
					proposal.EventID,
					signed,
					flight,
					future,
				)
			}
		}
	}
	guard.release()

	select {
	case <-flight.done:
		result := flight.result
		if !owner && flight.err == nil {
			result.Duplicate = true
		}
		return result, flight.err
	case <-ctx.Done():
		return store.ApplyResult{}, ctx.Err()
	case <-node.closeStarted:
		return store.ApplyResult{}, ErrNodeClosed
	case <-node.fatalSet:
		return store.ApplyResult{}, node.FatalError()
	}
}

func normalizedCheckpointOrigin(origin CheckpointOrigin) CheckpointOrigin {
	if origin == nil {
		return nil
	}
	value := reflect.ValueOf(origin)
	switch value.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		if value.IsNil() {
			return nil
		}
	}
	return origin
}

func validateCheckpointOrigin(
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	origin CheckpointOrigin,
) error {
	origin = normalizedCheckpointOrigin(origin)
	if origin == nil {
		return nil
	}
	if origin.DeviceID() != deviceID || origin.BootID() != bootID {
		return fmt.Errorf(
			"%w: checkpoint origin belongs to another daemon",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

func checkpointRequesterForTransport(
	single bool,
	origin CheckpointOrigin,
	transport RaftTransport,
) (consensusProofRequester, error) {
	requester, supported := transport.(consensusProofRequester)
	if single || normalizedCheckpointOrigin(origin) == nil || supported {
		return requester, nil
	}
	return nil, fmt.Errorf(
		"%w: mesh checkpoint origin requires proof-capable transport",
		ErrInvalidNodeOptions,
	)
}

func validateCheckpointCapabilities(
	signer CheckpointSigner,
	origin CheckpointOrigin,
) error {
	if normalizedCheckpointOrigin(origin) != nil &&
		normalizedCheckpointSigner(signer) == nil {
		return fmt.Errorf(
			"%w: checkpoint origin requires a local signer",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}
