package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

var (
	ErrVoterActivationOriginUnavailable = errors.New(
		"consensus: durable voter activation origin unavailable",
	)
	ErrVoterActivationCommitRejected = errors.New(
		"consensus: voter activation command rejected",
	)
)

const voterAuthorityHandoffSignerTimeout = 5 * time.Second

// VoterActivationOrigin durably submits one fully signed activation event.
// It shares the checkpoint origin's boot-scoped identity and outbox.
type VoterActivationOrigin interface {
	DeviceID() domain.DeviceID
	BootID() domain.UUIDv7
	SubmitVoterSetActivation(
		context.Context,
		voteractivation.ActivationPayload,
	) (store.CommandOutcome, error)
}

type voterActivationAttempt struct {
	state         decodedState
	configuration committedRaftConfiguration
	leadership    raftLeadershipEpoch
	checkpoint    store.AppliedCheckpointLookup
	proofs        map[domain.DeviceID]voteractivation.Proof
}

func (node *SingleNode) activateVoterSet(
	ctx context.Context,
	expectedState decodedState,
	expectedConfiguration *committedRaftConfiguration,
) error {
	if node == nil ||
		ctx == nil ||
		expectedConfiguration == nil ||
		!credentialAuthorityNeedsActivation(expectedState) {
		return errVoterReconciliationChanged
	}
	if err := node.requireVoterReconciliationCapabilities(); err != nil {
		return err
	}
	leadership, err := node.readConfigurationLeadershipEpoch()
	if err != nil {
		return err
	}
	attempt, err := node.voterActivationAttemptForCut(
		ctx,
		leadership,
		expectedState,
		expectedConfiguration,
	)
	if err != nil {
		return err
	}
	state := attempt.state
	configuration := &attempt.configuration
	checkpoint := attempt.checkpoint
	checkpointValue, err := event.DecodeCheckpoint(
		checkpoint.Record.CheckpointJSON,
	)
	if err != nil {
		return node.haltNode(fmt.Errorf(
			"%w: decode activation checkpoint: %v",
			ErrInvalidVoterActivationProof,
			err,
		))
	}
	if checkpoint.Record.AuthorityVoterSetVersion !=
		state.CredentialAuthority.VoterSetVersion ||
		checkpoint.Record.CoveredAppliedLogIndex < configuration.Index {
		return errVoterReconciliationChanged
	}

	targetIDs := state.VoterSet.VoterDeviceIDs()
	proofs := make([]voteractivation.Proof, len(targetIDs))
	for index, targetID := range targetIDs {
		if !configurationHasDeviceSuffrage(
			configuration.Configuration,
			targetID,
			raft.Voter,
		) {
			return errVoterReconciliationChanged
		}
		publicKey, exists := state.IdentityPublicKey(targetID)
		if !exists {
			return node.haltNode(ErrVoterReconciliationInvalid)
		}
		unsigned, err := voteractivation.NewUnsignedProof(
			voteractivation.ProofInput{
				SessionID:          state.VoterSet.SessionID,
				WorkspaceID:        state.workspaceID,
				RecoveryGeneration: state.recoveryGeneration,
				TargetVoterSetVersion: state.VoterSet.
					VoterSetVersion,
				CurrentAuthorityVoterSetVersion: state.
					CredentialAuthority.VoterSetVersion,
				VoterSet:               targetIDs,
				VoterDeviceID:          targetID,
				LiveConfigurationIndex: configuration.Index,
				CheckpointEventID: checkpoint.Record.
					CheckpointEventID,
				Checkpoint: checkpointValue,
				CheckpointSignature: [ed25519.SignatureSize]byte(
					checkpoint.Record.AuthoritySignature,
				),
			},
		)
		if err != nil {
			return node.haltNode(fmt.Errorf(
				"%w: build target proof: %v",
				ErrInvalidVoterActivationProof,
				err,
			))
		}
		expectation, err := newTargetActivationExpectation(
			targetID,
			unsigned,
			publicKey,
		)
		if err != nil {
			return node.haltNode(err)
		}
		cached, exists := attempt.proofs[targetID]
		if exists &&
			bytes.Equal(
				cached.Unsigned().CanonicalBytes(),
				expectation.unsigned.CanonicalBytes(),
			) &&
			voteractivation.VerifyProof(
				cached,
				expectation.targetPublicKey,
			) == nil {
			proofs[index] = cached
			continue
		}
		proofs[index], err = node.collectTargetActivationProof(
			ctx,
			leadership,
			expectation,
		)
		if err != nil {
			return err
		}
		attempt.proofs[targetID] = proofs[index]
	}

	payload, err := node.collectAuthorityHandoff(
		ctx,
		leadership,
		state,
		proofs,
		checkpoint.Record.CheckpointEventID,
	)
	if err != nil {
		return err
	}
	currentState, _, currentConfiguration, err :=
		node.configurationChangeCut(ctx)
	if err != nil {
		return err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return err
	}
	if !sameVoterActivationCut(
		state,
		configuration,
		currentState,
		currentConfiguration,
	) {
		return errVoterReconciliationChanged
	}

	outcome, err := node.submitVoterSetActivationAtLeadership(
		ctx,
		leadership,
		payload,
	)
	if err != nil {
		return err
	}
	switch outcome.Status {
	case store.OutcomeAccepted:
		if outcome.Code != string(reducer.CodeAccepted) {
			return node.haltNode(fmt.Errorf(
				"%w: accepted outcome code %q",
				ErrVoterActivationCommitRejected,
				outcome.Code,
			))
		}
		node.voterActivationAttempt = nil
		return nil
	case store.OutcomeRejected:
		currentState, _, currentConfiguration, cutErr :=
			node.configurationChangeCut(ctx)
		if cutErr != nil {
			return cutErr
		}
		if !sameVoterActivationCut(
			state,
			configuration,
			currentState,
			currentConfiguration,
		) {
			return errVoterReconciliationChanged
		}
		return node.haltNode(fmt.Errorf(
			"%w: unchanged activation cut rejected with %s",
			ErrVoterActivationCommitRejected,
			outcome.Code,
		))
	default:
		return node.haltNode(ErrVoterActivationCommitRejected)
	}
}

func (node *SingleNode) voterActivationAttemptForCut(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	expectedState decodedState,
	expectedConfiguration *committedRaftConfiguration,
) (*voterActivationAttempt, error) {
	if node == nil || ctx == nil || expectedConfiguration == nil {
		return nil, errVoterReconciliationChanged
	}
	attempt := node.voterActivationAttempt
	if attempt != nil &&
		attempt.leadership == leadership &&
		sameVoterActivationCut(
			attempt.state,
			&attempt.configuration,
			expectedState,
			expectedConfiguration,
		) &&
		attempt.checkpoint.Record.Validate() == nil &&
		attempt.checkpoint.Record.CoveredAppliedLogIndex >=
			expectedConfiguration.Index {
		return attempt, nil
	}

	checkpoint, err := node.ForceCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if err := node.requireConfigurationLeadershipEpoch(leadership); err != nil {
		return nil, err
	}
	state, _, configuration, err := node.configurationChangeCut(ctx)
	if err != nil {
		return nil, err
	}
	if !sameVoterActivationCut(
		expectedState,
		expectedConfiguration,
		state,
		configuration,
	) ||
		checkpoint.Record.AuthorityVoterSetVersion !=
			state.CredentialAuthority.VoterSetVersion ||
		checkpoint.Record.CoveredAppliedLogIndex < configuration.Index {
		return nil, errVoterReconciliationChanged
	}
	attempt = &voterActivationAttempt{
		state: state,
		configuration: committedRaftConfiguration{
			Index:         configuration.Index,
			Configuration: configuration.Configuration.Clone(),
		},
		leadership: leadership,
		checkpoint: checkpoint,
		proofs: make(
			map[domain.DeviceID]voteractivation.Proof,
			len(state.VoterSet.VoterDeviceIDs()),
		),
	}
	node.voterActivationAttempt = attempt
	return attempt, nil
}

func (node *SingleNode) submitVoterSetActivationAtLeadership(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	payload voteractivation.ActivationPayload,
) (store.CommandOutcome, error) {
	attemptContext, cancel := context.WithCancelCause(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-attemptContext.Done():
				return
			case <-node.closeStarted:
				cancel(ErrNodeClosed)
				return
			case <-node.fatalSet:
				cancel(node.FatalError())
				return
			case <-ticker.C:
				if err := node.requireConfigurationLeadershipEpoch(
					leadership,
				); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	outcome, err := node.voterActivationOrigin.SubmitVoterSetActivation(
		attemptContext,
		payload,
	)
	cancel(context.Canceled)
	<-watchDone
	if err != nil {
		if cause := context.Cause(attemptContext); cause != nil &&
			!errors.Is(cause, context.Canceled) {
			return store.CommandOutcome{}, cause
		}
		return store.CommandOutcome{}, err
	}
	return outcome, nil
}

func (node *SingleNode) collectTargetActivationProof(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	expectation targetActivationExpectation,
) (voteractivation.Proof, error) {
	if expectation.targetDeviceID != domain.DeviceID(node.serverID) {
		proof, err := requestTargetActivationProof(
			ctx,
			node.checkpointRequester,
			expectation,
		)
		if err != nil {
			return voteractivation.Proof{}, err
		}
		if err := node.requireConfigurationLeadershipEpoch(
			leadership,
		); err != nil {
			return voteractivation.Proof{}, err
		}
		return proof, nil
	}
	if node.voterActivationSigner == nil {
		return voteractivation.Proof{},
			errConsensusVoterActivationSignerUnavailable
	}
	request := targetActivationRequest{
		targetDeviceID: expectation.targetDeviceID,
		unsigned:       expectation.unsigned,
	}
	authority := stagingProofAuthority{
		term: leadership.term,
		configurationIndex: expectation.unsigned.Input().
			LiveConfigurationIndex,
	}
	before, err := node.targetActivationSigningCut(
		ctx,
		request,
		authority,
	)
	if err != nil {
		return voteractivation.Proof{}, err
	}
	signature, err := node.voterActivationSigner.
		SignVoterActivationProof(ctx, expectation.unsigned)
	if err != nil {
		return voteractivation.Proof{},
			errConsensusVoterActivationSignerUnavailable
	}
	proof, err := voteractivation.NewProof(
		expectation.unsigned,
		signature,
	)
	if err != nil ||
		voteractivation.VerifyProof(
			proof,
			expectation.targetPublicKey,
		) != nil {
		return voteractivation.Proof{},
			errConsensusVoterActivationSignerInvalid
	}
	after, err := node.targetActivationSigningCut(
		ctx,
		request,
		authority,
	)
	if err != nil {
		return voteractivation.Proof{}, err
	}
	if !sameTargetActivationSigningCut(before, after) {
		return voteractivation.Proof{},
			ErrConsensusAuthorizationUnavailable
	}
	return proof, nil
}

func (node *SingleNode) collectAuthorityHandoff(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	state decodedState,
	proofs []voteractivation.Proof,
	checkpointEventID domain.UUIDv7,
) (voteractivation.ActivationPayload, error) {
	var unavailable []error
	signerIDs := state.CredentialAuthority.VoterDeviceIDs
	for index, signerID := range signerIDs {
		member, exists := state.Admission.Member(signerID)
		publicKey, keyExists := state.IdentityPublicKey(signerID)
		if !exists ||
			member.Status != device.StatusActive ||
			!keyExists {
			continue
		}
		unsigned, err := voteractivation.NewUnsignedAuthorityHandoff(
			voteractivation.AuthorityHandoffInput{
				SessionID:          state.VoterSet.SessionID,
				WorkspaceID:        state.workspaceID,
				RecoveryGeneration: state.recoveryGeneration,
				TargetVoterSetVersion: state.VoterSet.
					VoterSetVersion,
				ExpectedAuthorityVoterSetVersion: state.
					CredentialAuthority.VoterSetVersion,
				VoterSet:                    state.VoterSet.VoterDeviceIDs(),
				ActivationCheckpointEventID: checkpointEventID,
				ActivationProofs:            proofs,
				PriorAuthoritySigner:        signerID,
			},
		)
		if err != nil {
			return voteractivation.ActivationPayload{},
				node.haltNode(fmt.Errorf(
					"%w: build authority handoff: %v",
					ErrInvalidVoterActivationProof,
					err,
				))
		}
		expectation, err := newAuthorityHandoffExpectation(
			signerID,
			unsigned,
			publicKey,
		)
		if err != nil {
			return voteractivation.ActivationPayload{},
				node.haltNode(err)
		}
		signerContext, cancel := authorityHandoffSignerContext(
			ctx,
			len(signerIDs)-index,
		)
		payload, err := node.collectOneAuthorityHandoff(
			signerContext,
			leadership,
			expectation,
		)
		cancel()
		if err == nil {
			return payload, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return voteractivation.ActivationPayload{}, contextErr
		}
		if errors.Is(err, ErrVoterActivationProofRejected) ||
			errors.Is(err, ErrVoterActivationProofUnavailable) ||
			errors.Is(err, ErrConsensusAuthorizationUnavailable) ||
			errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) ||
			errors.Is(
				err,
				errConsensusVoterActivationSignerUnavailable,
			) {
			unavailable = append(unavailable, err)
			continue
		}
		return voteractivation.ActivationPayload{}, err
	}
	if len(unavailable) == 0 {
		unavailable = append(
			unavailable,
			ErrConsensusAuthorizationUnavailable,
		)
	}
	return voteractivation.ActivationPayload{}, errors.Join(
		ErrVoterActivationProofUnavailable,
		errors.Join(unavailable...),
	)
}

func authorityHandoffSignerContext(
	parent context.Context,
	remainingSigners int,
) (context.Context, context.CancelFunc) {
	timeout := voterAuthorityHandoffSignerTimeout
	if remainingSigners < 1 {
		remainingSigners = 1
	}
	if deadline, hasDeadline := parent.Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		fairShare := remaining / time.Duration(remainingSigners)
		if fairShare < timeout {
			timeout = fairShare
		}
	}
	if timeout <= 0 {
		timeout = time.Nanosecond
	}
	return context.WithTimeout(parent, timeout)
}

func (node *SingleNode) collectOneAuthorityHandoff(
	ctx context.Context,
	leadership raftLeadershipEpoch,
	expectation authorityHandoffExpectation,
) (voteractivation.ActivationPayload, error) {
	if expectation.signerDeviceID != domain.DeviceID(node.serverID) {
		payload, err := requestAuthorityHandoff(
			ctx,
			node.checkpointRequester,
			expectation,
		)
		if err != nil {
			return voteractivation.ActivationPayload{}, err
		}
		if err := node.requireConfigurationLeadershipEpoch(
			leadership,
		); err != nil {
			return voteractivation.ActivationPayload{}, err
		}
		return payload, nil
	}
	if node.voterActivationSigner == nil {
		return voteractivation.ActivationPayload{},
			errConsensusVoterActivationSignerUnavailable
	}
	first := expectation.unsigned.Input().ActivationProofs[0].
		Unsigned().Input()
	authority := stagingProofAuthority{
		term:               leadership.term,
		configurationIndex: first.LiveConfigurationIndex,
	}
	request := authorityHandoffRequest{
		signerDeviceID: expectation.signerDeviceID,
		unsigned:       expectation.unsigned,
	}
	before, err := node.authorityHandoffSigningCut(
		ctx,
		request,
		authority,
	)
	if err != nil {
		return voteractivation.ActivationPayload{}, err
	}
	signature, err := node.voterActivationSigner.
		SignVoterAuthorityHandoff(ctx, expectation.unsigned)
	if err != nil {
		return voteractivation.ActivationPayload{},
			errConsensusVoterActivationSignerUnavailable
	}
	payload, err := voteractivation.NewActivationPayload(
		expectation.unsigned,
		signature,
	)
	if err != nil ||
		voteractivation.VerifyAuthorityHandoff(
			payload,
			expectation.signerPublicKey,
		) != nil {
		return voteractivation.ActivationPayload{},
			errConsensusVoterActivationSignerInvalid
	}
	after, err := node.authorityHandoffSigningCut(
		ctx,
		request,
		authority,
	)
	if err != nil {
		return voteractivation.ActivationPayload{}, err
	}
	if !sameAuthorityHandoffSigningCut(before, after) {
		return voteractivation.ActivationPayload{},
			ErrConsensusAuthorizationUnavailable
	}
	return payload, nil
}

func credentialAuthorityNeedsActivation(state decodedState) bool {
	return state.VoterSet.Validate() == nil &&
		state.CredentialAuthority.Validate() == nil &&
		state.CredentialAuthority.VoterSetVersion <
			state.VoterSet.VoterSetVersion
}

func sameVoterActivationCut(
	leftState decodedState,
	leftConfiguration *committedRaftConfiguration,
	rightState decodedState,
	rightConfiguration *committedRaftConfiguration,
) bool {
	return leftConfiguration != nil &&
		rightConfiguration != nil &&
		leftConfiguration.Index == rightConfiguration.Index &&
		sameRaftConfiguration(
			leftConfiguration.Configuration,
			rightConfiguration.Configuration,
		) &&
		leftState.VoterSet.SessionID == rightState.VoterSet.SessionID &&
		leftState.workspaceID == rightState.workspaceID &&
		leftState.recoveryGeneration == rightState.recoveryGeneration &&
		sameVoterReconciliationState(leftState, rightState) &&
		sameVoterActivationParticipants(leftState, rightState)
}

func sameVoterActivationParticipants(
	left decodedState,
	right decodedState,
) bool {
	if left.Admission == nil || right.Admission == nil {
		return false
	}
	participants := make(map[domain.DeviceID]struct{})
	for _, id := range left.VoterSet.VoterDeviceIDs() {
		participants[id] = struct{}{}
	}
	for _, id := range left.CredentialAuthority.VoterDeviceIDs {
		participants[id] = struct{}{}
	}
	for id := range participants {
		leftMember, leftExists := left.Admission.Member(id)
		rightMember, rightExists := right.Admission.Member(id)
		if leftExists != rightExists ||
			!leftExists ||
			leftMember.ID != rightMember.ID ||
			leftMember.Role != rightMember.Role ||
			leftMember.DaemonVersion != rightMember.DaemonVersion ||
			leftMember.MaxApplyLevel != rightMember.MaxApplyLevel ||
			leftMember.Status != rightMember.Status ||
			leftMember.EntityVersion != rightMember.EntityVersion ||
			!bytes.Equal(
				leftMember.IdentityPublicKey,
				rightMember.IdentityPublicKey,
			) {
			return false
		}
	}
	return true
}

func normalizedVoterActivationOrigin(
	origin CheckpointOrigin,
) VoterActivationOrigin {
	candidate, ok := origin.(VoterActivationOrigin)
	if !ok || candidate == nil {
		return nil
	}
	value := reflect.ValueOf(candidate)
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
	return candidate
}

func validateVoterActivationOrigin(
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	origin VoterActivationOrigin,
) error {
	if origin == nil {
		return nil
	}
	if origin.DeviceID() != deviceID || origin.BootID() != bootID {
		return fmt.Errorf(
			"%w: activation origin belongs to another daemon",
			ErrInvalidNodeOptions,
		)
	}
	return nil
}

func (node *SingleNode) requireVoterReconciliationCapabilities() error {
	if node == nil ||
		node.single ||
		node.coverageGate == nil ||
		node.readinessGate == nil ||
		node.checkpointOrigin == nil ||
		node.checkpointRequester == nil ||
		node.voterActivationSigner == nil {
		return ErrVoterReconciliationUnavailable
	}
	if node.voterActivationOrigin == nil {
		return fmt.Errorf(
			"%w: %w",
			ErrVoterReconciliationUnavailable,
			ErrVoterActivationOriginUnavailable,
		)
	}
	if err := validateVoterActivationOrigin(
		domain.DeviceID(node.serverID),
		node.originBootID,
		node.voterActivationOrigin,
	); err != nil {
		return err
	}
	return nil
}

func voterActivationOriginForCheckpoint(
	origin CheckpointOrigin,
) VoterActivationOrigin {
	return normalizedVoterActivationOrigin(origin)
}
