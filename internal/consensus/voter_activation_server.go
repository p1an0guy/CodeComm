package consensus

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

var (
	errConsensusVoterActivationSignerUnavailable = errors.New(
		"consensus: voter activation signer is unavailable",
	)
	errConsensusVoterActivationSignerInvalid = errors.New(
		"consensus: voter activation signer returned an invalid signature",
	)
)

type activationStateToken struct {
	sessionID           domain.UUIDv7
	workspaceID         domain.UUIDv4
	recoveryGeneration  uint64
	admissionRevision   uint64
	currentTerm         uint64
	lastAppliedLogIndex uint64
	heads               store.ApplyHeads
	projectionDigest    store.Digest
}

type activationCut struct {
	state              activationStateToken
	term               uint64
	configurationIndex uint64
	configurationJSON  []byte
	decoded            decodedState
	checkpoint         store.AppliedCheckpointLookup
}

type targetActivationSigningCut struct {
	cut         activationCut
	expectation targetActivationExpectation
}

type authorityHandoffSigningCut struct {
	cut         activationCut
	expectation authorityHandoffExpectation
}

func (node *SingleNode) serveTargetActivation(
	writer http.ResponseWriter,
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	requestAuthority stagingProofAuthority,
	body []byte,
) {
	request, err := decodeTargetActivationRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			proofProblemInvalid,
		)
		return
	}
	proof, expectation, err := node.proveTargetActivation(
		ctx,
		peer,
		request,
		requestAuthority,
	)
	if err != nil {
		writeVoterActivationProblem(writer, err)
		return
	}
	response, err := encodeTargetActivationResponse(proof, expectation)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusInternalServerError,
			proofProblemInternal,
		)
		return
	}
	writeConsensusProofJSON(writer, response)
}

func (node *SingleNode) serveAuthorityHandoff(
	writer http.ResponseWriter,
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	requestAuthority stagingProofAuthority,
	body []byte,
) {
	request, err := decodeAuthorityHandoffRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			proofProblemInvalid,
		)
		return
	}
	payload, expectation, err := node.proveAuthorityHandoff(
		ctx,
		peer,
		request,
		requestAuthority,
	)
	if err != nil {
		writeVoterActivationProblem(writer, err)
		return
	}
	response, err := encodeAuthorityHandoffResponse(payload, expectation)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusInternalServerError,
			proofProblemInternal,
		)
		return
	}
	writeConsensusProofJSON(writer, response)
}

func (node *SingleNode) proveTargetActivation(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	request targetActivationRequest,
	requestAuthority stagingProofAuthority,
) (
	voteractivation.Proof,
	targetActivationExpectation,
	error,
) {
	if node == nil || ctx == nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			err
	}
	if err := node.beginOperation(); err != nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			err
	}
	if node.voterActivationSigner == nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			errConsensusVoterActivationSignerUnavailable
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	beforeAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil {
		return voteractivation.Proof{}, targetActivationExpectation{}, err
	}
	if !beforeAuthority.sameRequester(requestAuthority) {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	before, err := node.targetActivationSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return voteractivation.Proof{}, targetActivationExpectation{}, err
	}
	signature, err := node.voterActivationSigner.
		SignVoterActivationProof(ctx, request.unsigned)
	if err != nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			errConsensusVoterActivationSignerUnavailable
	}
	proof, err := voteractivation.NewProof(request.unsigned, signature)
	if err != nil ||
		voteractivation.VerifyProof(
			proof,
			before.expectation.targetPublicKey,
		) != nil {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			errConsensusVoterActivationSignerInvalid
	}

	after, err := node.targetActivationSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return voteractivation.Proof{}, targetActivationExpectation{}, err
	}
	afterAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil ||
		!beforeAuthority.sameRequester(afterAuthority) ||
		!sameTargetActivationSigningCut(before, after) {
		return voteractivation.Proof{},
			targetActivationExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	return proof, before.expectation, nil
}

func (node *SingleNode) proveAuthorityHandoff(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	request authorityHandoffRequest,
	requestAuthority stagingProofAuthority,
) (
	voteractivation.ActivationPayload,
	authorityHandoffExpectation,
	error,
) {
	if node == nil || ctx == nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	if err := node.beginOperation(); err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	if node.voterActivationSigner == nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			errConsensusVoterActivationSignerUnavailable
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	beforeAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	if !beforeAuthority.sameRequester(requestAuthority) {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	before, err := node.authorityHandoffSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	signature, err := node.voterActivationSigner.
		SignVoterAuthorityHandoff(ctx, request.unsigned)
	if err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			errConsensusVoterActivationSignerUnavailable
	}
	payload, err := voteractivation.NewActivationPayload(
		request.unsigned,
		signature,
	)
	if err != nil ||
		voteractivation.VerifyAuthorityHandoff(
			payload,
			before.expectation.signerPublicKey,
		) != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			errConsensusVoterActivationSignerInvalid
	}

	after, err := node.authorityHandoffSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			err
	}
	afterAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil ||
		!beforeAuthority.sameRequester(afterAuthority) ||
		!sameAuthorityHandoffSigningCut(before, after) {
		return voteractivation.ActivationPayload{},
			authorityHandoffExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	return payload, before.expectation, nil
}

func (node *SingleNode) targetActivationSigningCut(
	ctx context.Context,
	request targetActivationRequest,
	requestAuthority stagingProofAuthority,
) (targetActivationSigningCut, error) {
	if node == nil ||
		node.voterActivationSigner == nil ||
		request.targetDeviceID != domain.DeviceID(node.serverID) ||
		node.voterActivationSigner.DeviceID() != request.targetDeviceID {
		return targetActivationSigningCut{}, errConsensusProofDenied
	}
	input := request.unsigned.Input()
	cut, err := node.captureActivationCut(ctx, input.CheckpointEventID)
	if err != nil {
		return targetActivationSigningCut{}, err
	}
	if cut.term != requestAuthority.term ||
		cut.configurationIndex != input.LiveConfigurationIndex {
		return targetActivationSigningCut{}, errConsensusProofStale
	}
	if err := validateActivationStateContext(cut, input); err != nil {
		return targetActivationSigningCut{}, err
	}
	localMember, exists := cut.decoded.Admission.Member(
		request.targetDeviceID,
	)
	localKey, keyExists := cut.decoded.IdentityPublicKey(
		request.targetDeviceID,
	)
	if !exists ||
		localMember.Status != device.StatusActive ||
		!keyExists ||
		!configurationHasDeviceSuffrage(
			cut.decodedConfiguration(),
			request.targetDeviceID,
			raft.Voter,
		) {
		return targetActivationSigningCut{}, errConsensusProofDenied
	}
	expectation, err := newTargetActivationExpectation(
		request.targetDeviceID,
		request.unsigned,
		localKey,
	)
	if err != nil {
		return targetActivationSigningCut{}, errConsensusProofMismatch
	}
	return targetActivationSigningCut{
		cut:         cut,
		expectation: expectation,
	}, nil
}

func (node *SingleNode) authorityHandoffSigningCut(
	ctx context.Context,
	request authorityHandoffRequest,
	requestAuthority stagingProofAuthority,
) (authorityHandoffSigningCut, error) {
	if node == nil ||
		node.voterActivationSigner == nil ||
		request.signerDeviceID != domain.DeviceID(node.serverID) ||
		node.voterActivationSigner.DeviceID() != request.signerDeviceID {
		return authorityHandoffSigningCut{}, errConsensusProofDenied
	}
	input := request.unsigned.Input()
	if len(input.ActivationProofs) == 0 {
		return authorityHandoffSigningCut{}, errConsensusProofMismatch
	}
	firstInput := input.ActivationProofs[0].Unsigned().Input()
	cut, err := node.captureActivationCut(
		ctx,
		input.ActivationCheckpointEventID,
	)
	if err != nil {
		return authorityHandoffSigningCut{}, err
	}
	if cut.term != requestAuthority.term ||
		cut.configurationIndex != firstInput.LiveConfigurationIndex {
		return authorityHandoffSigningCut{}, errConsensusProofStale
	}
	if err := validateHandoffStateContext(cut, input); err != nil {
		return authorityHandoffSigningCut{}, err
	}
	localMember, exists := cut.decoded.Admission.Member(
		request.signerDeviceID,
	)
	localKey, keyExists := cut.decoded.IdentityPublicKey(
		request.signerDeviceID,
	)
	if !exists ||
		localMember.Status != device.StatusActive ||
		!keyExists ||
		!cut.decoded.CredentialAuthority.Contains(
			request.signerDeviceID,
		) {
		return authorityHandoffSigningCut{}, errConsensusProofDenied
	}
	configuration := cut.decodedConfiguration()
	for index, voterID := range input.VoterSet {
		member, memberExists := cut.decoded.Admission.Member(voterID)
		publicKey, proofKeyExists := cut.decoded.IdentityPublicKey(voterID)
		if !memberExists ||
			member.Status != device.StatusActive ||
			!proofKeyExists ||
			!configurationHasDeviceSuffrage(
				configuration,
				voterID,
				raft.Voter,
			) ||
			voteractivation.VerifyProof(
				input.ActivationProofs[index],
				publicKey,
			) != nil {
			return authorityHandoffSigningCut{},
				errConsensusProofMismatch
		}
	}
	expectation, err := newAuthorityHandoffExpectation(
		request.signerDeviceID,
		request.unsigned,
		localKey,
	)
	if err != nil {
		return authorityHandoffSigningCut{}, errConsensusProofMismatch
	}
	return authorityHandoffSigningCut{
		cut:         cut,
		expectation: expectation,
	}, nil
}

func (node *SingleNode) captureActivationCut(
	ctx context.Context,
	checkpointEventID domain.UUIDv7,
) (activationCut, error) {
	if node == nil || node.raft == nil || node.fsm == nil ||
		node.state == nil || ctx == nil || !checkpointEventID.Valid() {
		return activationCut{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return activationCut{}, err
	}
	termBefore, err := raftTerm(node.raft.Stats())
	if err != nil {
		return activationCut{}, ErrConsensusAuthorizationUnavailable
	}
	configurationBefore := node.fsm.committedConfiguration()
	if configurationBefore == nil || configurationBefore.Index < 1 {
		return activationCut{}, ErrConsensusAuthorizationUnavailable
	}
	configurationJSON, err := encodeRaftConfiguration(
		configurationBefore.Configuration,
	)
	if err != nil {
		return activationCut{}, ErrConsensusAuthorizationUnavailable
	}
	viewBefore, err := node.state.View(ctx)
	if err != nil {
		return activationCut{}, err
	}
	beforeToken, err := activationToken(viewBefore)
	if err != nil {
		return activationCut{}, err
	}
	checkpoint, found, err := node.state.AppliedCheckpoint(
		ctx,
		checkpointEventID,
	)
	if err != nil {
		return activationCut{}, err
	}
	if !found {
		return activationCut{}, errConsensusProofNotApplied
	}
	viewAfter, err := node.state.View(ctx)
	if err != nil {
		return activationCut{}, err
	}
	afterToken, err := activationToken(viewAfter)
	if err != nil {
		return activationCut{}, err
	}
	configurationAfter := node.fsm.committedConfiguration()
	termAfter, termErr := raftTerm(node.raft.Stats())
	if termErr != nil ||
		configurationAfter == nil ||
		configurationAfter.Index != configurationBefore.Index ||
		termAfter != termBefore ||
		beforeToken != afterToken {
		return activationCut{}, ErrConsensusAuthorizationUnavailable
	}
	afterConfigurationJSON, err := encodeRaftConfiguration(
		configurationAfter.Configuration,
	)
	if err != nil ||
		!bytes.Equal(configurationJSON, afterConfigurationJSON) {
		return activationCut{}, ErrConsensusAuthorizationUnavailable
	}
	decoded, err := decodeStateView(viewAfter)
	if err != nil {
		return activationCut{}, err
	}
	return activationCut{
		state:              afterToken,
		term:               termAfter,
		configurationIndex: configurationAfter.Index,
		configurationJSON:  bytes.Clone(afterConfigurationJSON),
		decoded:            decoded,
		checkpoint:         checkpoint,
	}, nil
}

func activationToken(view store.StateView) (activationStateToken, error) {
	if view.CurrentTerm == nil || view.LastRaftAppliedLogIndex == nil {
		return activationStateToken{}, ErrConsensusAuthorizationUnavailable
	}
	return activationStateToken{
		sessionID:           view.SessionID,
		workspaceID:         view.WorkspaceID,
		recoveryGeneration:  view.RecoveryGeneration,
		admissionRevision:   view.AdmissionRevision,
		currentTerm:         *view.CurrentTerm,
		lastAppliedLogIndex: *view.LastRaftAppliedLogIndex,
		heads:               view.Heads,
		projectionDigest:    view.ProjectionStateDigest,
	}, nil
}

func validateActivationStateContext(
	cut activationCut,
	input voteractivation.ProofInput,
) error {
	if cut.state.sessionID != input.SessionID ||
		cut.state.workspaceID != input.WorkspaceID ||
		cut.state.recoveryGeneration != input.RecoveryGeneration ||
		cut.decoded.VoterSet.VoterSetVersion !=
			input.TargetVoterSetVersion ||
		!sameDeviceIDs(
			cut.decoded.VoterDeviceIDs(),
			input.VoterSet,
		) ||
		cut.decoded.CredentialAuthority.VoterSetVersion !=
			input.CurrentAuthorityVoterSetVersion {
		return errConsensusProofMismatch
	}
	return validateActivationCheckpoint(cut, input)
}

func validateHandoffStateContext(
	cut activationCut,
	input voteractivation.AuthorityHandoffInput,
) error {
	if cut.state.sessionID != input.SessionID ||
		cut.state.workspaceID != input.WorkspaceID ||
		cut.state.recoveryGeneration != input.RecoveryGeneration ||
		cut.decoded.VoterSet.VoterSetVersion !=
			input.TargetVoterSetVersion ||
		!sameDeviceIDs(
			cut.decoded.VoterDeviceIDs(),
			input.VoterSet,
		) ||
		cut.decoded.CredentialAuthority.VoterSetVersion !=
			input.ExpectedAuthorityVoterSetVersion {
		return errConsensusProofMismatch
	}
	first := input.ActivationProofs[0].Unsigned().Input()
	return validateActivationCheckpoint(cut, first)
}

func validateActivationCheckpoint(
	cut activationCut,
	input voteractivation.ProofInput,
) error {
	record := cut.checkpoint.Record
	checkpointJSON, err := event.EncodeCheckpoint(input.Checkpoint)
	if err != nil ||
		record.CheckpointEventID != input.CheckpointEventID ||
		record.SessionID != input.SessionID ||
		record.WorkspaceID != input.WorkspaceID ||
		record.RecoveryGeneration != input.RecoveryGeneration ||
		record.AuthorityVoterSetVersion !=
			input.CurrentAuthorityVoterSetVersion ||
		record.CoveredAppliedLogIndex < input.LiveConfigurationIndex ||
		cut.checkpoint.AppliedLogIndex >
			cut.state.lastAppliedLogIndex ||
		!bytes.Equal(record.CheckpointJSON, checkpointJSON) ||
		record.AuthoritySignature !=
			store.Signature(input.CheckpointSignature) {
		return errConsensusProofMismatch
	}
	checkpointMember, exists := cut.decoded.Admission.Member(
		record.SignerDeviceID,
	)
	checkpointKey, keyExists := cut.decoded.IdentityPublicKey(
		record.SignerDeviceID,
	)
	if !exists ||
		checkpointMember.Status != device.StatusActive ||
		!keyExists ||
		!cut.decoded.CredentialAuthority.Contains(record.SignerDeviceID) ||
		codecommcrypto.VerifyEd25519(
			checkpointKey,
			codec.SignatureCheckpoint,
			record.CheckpointJSON,
			record.AuthoritySignature[:],
		) != nil {
		return errConsensusProofMismatch
	}
	return nil
}

func (cut activationCut) decodedConfiguration() raft.Configuration {
	configuration, err := decodeRaftConfigurationJSON(cut.configurationJSON)
	if err != nil {
		return raft.Configuration{}
	}
	return configuration
}

func sameTargetActivationSigningCut(
	left targetActivationSigningCut,
	right targetActivationSigningCut,
) bool {
	return sameActivationCut(left.cut, right.cut) &&
		left.expectation.targetDeviceID ==
			right.expectation.targetDeviceID &&
		bytes.Equal(
			left.expectation.unsigned.CanonicalBytes(),
			right.expectation.unsigned.CanonicalBytes(),
		) &&
		bytes.Equal(
			left.expectation.targetPublicKey,
			right.expectation.targetPublicKey,
		)
}

func sameAuthorityHandoffSigningCut(
	left authorityHandoffSigningCut,
	right authorityHandoffSigningCut,
) bool {
	return sameActivationCut(left.cut, right.cut) &&
		left.expectation.signerDeviceID ==
			right.expectation.signerDeviceID &&
		bytes.Equal(
			left.expectation.unsigned.CanonicalBytes(),
			right.expectation.unsigned.CanonicalBytes(),
		) &&
		bytes.Equal(
			left.expectation.signerPublicKey,
			right.expectation.signerPublicKey,
		)
}

func sameActivationCut(left, right activationCut) bool {
	return left.state == right.state &&
		left.term == right.term &&
		left.configurationIndex == right.configurationIndex &&
		bytes.Equal(left.configurationJSON, right.configurationJSON) &&
		sameAppliedCheckpoint(left.checkpoint, right.checkpoint)
}

func sameAppliedCheckpoint(
	left store.AppliedCheckpointLookup,
	right store.AppliedCheckpointLookup,
) bool {
	return left.AppliedLogIndex == right.AppliedLogIndex &&
		left.Record.CheckpointEventID == right.Record.CheckpointEventID &&
		left.Record.SessionID == right.Record.SessionID &&
		left.Record.WorkspaceID == right.Record.WorkspaceID &&
		left.Record.RecoveryGeneration == right.Record.RecoveryGeneration &&
		left.Record.AuthorityVoterSetVersion ==
			right.Record.AuthorityVoterSetVersion &&
		left.Record.SignerDeviceID == right.Record.SignerDeviceID &&
		left.Record.Term == right.Record.Term &&
		left.Record.CoveredAppliedLogIndex ==
			right.Record.CoveredAppliedLogIndex &&
		left.Record.CoveredChainIndex ==
			right.Record.CoveredChainIndex &&
		left.Record.CoveredChainHash == right.Record.CoveredChainHash &&
		left.Record.CoveredResultIndex ==
			right.Record.CoveredResultIndex &&
		left.Record.CoveredResultHash == right.Record.CoveredResultHash &&
		left.Record.ProjectionAccumulator ==
			right.Record.ProjectionAccumulator &&
		left.Record.DigestVersion == right.Record.DigestVersion &&
		left.Record.ProjectionSchemaVersion ==
			right.Record.ProjectionSchemaVersion &&
		left.Record.AuthoritySignature == right.Record.AuthoritySignature &&
		bytes.Equal(
			left.Record.CheckpointJSON,
			right.Record.CheckpointJSON,
		)
}

func writeVoterActivationProblem(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, errConsensusProofDenied):
		writeConsensusProofProblem(
			writer,
			http.StatusForbidden,
			proofProblemForbidden,
		)
	case errors.Is(err, errConsensusProofNotApplied):
		writeConsensusProofProblem(
			writer,
			http.StatusConflict,
			proofProblemNotApplied,
		)
	case errors.Is(err, errConsensusProofStale):
		writeConsensusProofProblem(
			writer,
			http.StatusConflict,
			proofProblemStale,
		)
	case errors.Is(err, errConsensusProofMismatch):
		writeConsensusProofProblem(
			writer,
			http.StatusConflict,
			proofProblemMismatch,
		)
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrNodeClosed),
		errors.Is(err, ErrConsensusAuthorizationUnavailable),
		errors.Is(err, errConsensusVoterActivationSignerUnavailable):
		writeConsensusProofProblem(
			writer,
			http.StatusServiceUnavailable,
			proofProblemUnavailable,
		)
	default:
		writeConsensusProofProblem(
			writer,
			http.StatusInternalServerError,
			proofProblemInternal,
		)
	}
}

func writeConsensusProofJSON(writer http.ResponseWriter, response []byte) {
	if writer == nil ||
		len(response) == 0 ||
		len(response) > transport.ConsensusControlBodyMaxBytes {
		writeConsensusProofProblem(
			writer,
			http.StatusInternalServerError,
			proofProblemInternal,
		)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}
