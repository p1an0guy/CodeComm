package consensus

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

func (node *SingleNode) serveCheckpointSign(
	writer http.ResponseWriter,
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	requestAuthority stagingProofAuthority,
	body []byte,
) {
	request, err := decodeCheckpointSignRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			proofProblemInvalid,
		)
		return
	}
	proof, err := node.proveCheckpointSign(
		ctx,
		peer,
		request,
		requestAuthority,
	)
	if err != nil {
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
			errors.Is(err, errConsensusCheckpointSignerUnavailable):
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
		return
	}
	response, err := encodeCheckpointSignResponse(proof)
	if err != nil ||
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

func (node *SingleNode) proveCheckpointSign(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	request checkpointSignRequest,
	requestAuthority stagingProofAuthority,
) (checkpointSignatureProof, error) {
	if node == nil || ctx == nil {
		return checkpointSignatureProof{}, ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return checkpointSignatureProof{}, err
	}
	if err := node.beginOperation(); err != nil {
		return checkpointSignatureProof{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return checkpointSignatureProof{}, err
	}
	if node.checkpointSigner == nil {
		return checkpointSignatureProof{},
			errConsensusCheckpointSignerUnavailable
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	beforeAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil {
		return checkpointSignatureProof{}, err
	}
	if !beforeAuthority.sameRequester(requestAuthority) {
		return checkpointSignatureProof{},
			ErrConsensusAuthorizationUnavailable
	}
	expectation, err := node.checkpointSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return checkpointSignatureProof{}, err
	}
	signature, err := node.checkpointSigner.SignCheckpoint(
		ctx,
		request.checkpoint,
	)
	if err != nil {
		return checkpointSignatureProof{},
			errConsensusCheckpointSignerUnavailable
	}
	if codecommcrypto.VerifyEd25519(
		expectation.signerPublicKey,
		codec.SignatureCheckpoint,
		expectation.checkpointJSON,
		signature[:],
	) != nil {
		return checkpointSignatureProof{},
			errConsensusCheckpointSignerInvalid
	}

	afterExpectation, err := node.checkpointSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return checkpointSignatureProof{}, err
	}
	afterAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil ||
		!beforeAuthority.sameRequester(afterAuthority) ||
		!sameCheckpointSigningExpectation(
			expectation,
			afterExpectation,
		) {
		return checkpointSignatureProof{},
			ErrConsensusAuthorizationUnavailable
	}
	proof := checkpointSignatureProof{expectation: expectation}
	proof.signature = signature
	return proof, nil
}

func (node *SingleNode) checkpointSigningCut(
	ctx context.Context,
	request checkpointSignRequest,
	requestAuthority stagingProofAuthority,
) (checkpointSigningExpectation, error) {
	if node == nil || node.raft == nil || node.state == nil ||
		ctx == nil ||
		request.checkpoint.SignerDeviceID !=
			domain.DeviceID(node.serverID) {
		return checkpointSigningExpectation{},
			errConsensusProofDenied
	}
	if err := ctx.Err(); err != nil {
		return checkpointSigningExpectation{}, err
	}
	commitBefore := node.raft.CommitIndex()
	appliedBefore := node.raft.AppliedIndex()
	view, err := node.state.View(ctx)
	if err != nil {
		return checkpointSigningExpectation{}, err
	}
	commitAfter := node.raft.CommitIndex()
	appliedAfter := node.raft.AppliedIndex()
	if commitBefore != commitAfter ||
		appliedBefore != appliedAfter ||
		view.LastRaftAppliedLogIndex != nil &&
			*view.LastRaftAppliedLogIndex > appliedAfter {
		return checkpointSigningExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	checkpoint := request.checkpoint
	switch {
	case commitAfter < checkpoint.CoveredAppliedLogIndex ||
		appliedAfter < checkpoint.CoveredAppliedLogIndex:
		return checkpointSigningExpectation{},
			errConsensusProofNotApplied
	case commitAfter > checkpoint.CoveredAppliedLogIndex ||
		appliedAfter > checkpoint.CoveredAppliedLogIndex:
		return checkpointSigningExpectation{},
			errConsensusProofStale
	}
	ready, err := node.appliedThroughCommit(
		checkpoint.CoveredAppliedLogIndex,
	)
	if err != nil {
		return checkpointSigningExpectation{}, err
	}
	if !ready {
		return checkpointSigningExpectation{},
			ErrConsensusAuthorizationUnavailable
	}
	if checkpoint.Term != requestAuthority.term {
		return checkpointSigningExpectation{},
			errConsensusProofStale
	}
	decoded, err := decodeStateView(view)
	if err != nil {
		return checkpointSigningExpectation{}, err
	}
	localDeviceID := domain.DeviceID(node.serverID)
	member, exists := decoded.Admission.Member(localDeviceID)
	identityPublicKey, keyExists := decoded.IdentityPublicKey(
		localDeviceID,
	)
	if !exists ||
		member.Status != device.StatusActive ||
		!keyExists ||
		decoded.CredentialAuthority.Validate() != nil ||
		!decoded.CredentialAuthority.Contains(localDeviceID) ||
		decoded.CredentialAuthority.VoterSetVersion !=
			checkpoint.AuthorityVoterSetVersion {
		return checkpointSigningExpectation{},
			errConsensusProofDenied
	}
	if checkpoint.SessionID != view.SessionID ||
		checkpoint.WorkspaceID != view.WorkspaceID ||
		checkpoint.RecoveryGeneration != view.RecoveryGeneration ||
		checkpoint.CoveredChainIndex != view.Heads.ChainIndex ||
		checkpoint.CoveredChainHash != view.Heads.ChainHash ||
		checkpoint.CoveredResultIndex != view.Heads.ResultIndex ||
		checkpoint.CoveredResultHash != view.Heads.ResultHash ||
		checkpoint.ProjectionAccumulator !=
			view.Heads.ProjectionAccumulator ||
		checkpoint.DigestVersion != view.Heads.DigestVersion ||
		checkpoint.ProjectionSchemaVersion !=
			view.Heads.ProjectionSchemaVersion {
		return checkpointSigningExpectation{},
			errConsensusProofMismatch
	}
	expectation, err := newCheckpointSigningExpectation(
		checkpoint,
		identityPublicKey,
	)
	if err != nil ||
		!bytes.Equal(
			expectation.checkpointJSON,
			request.checkpointJSON,
		) {
		return checkpointSigningExpectation{},
			errConsensusProofMismatch
	}
	return expectation, nil
}

func sameCheckpointSigningExpectation(
	left checkpointSigningExpectation,
	right checkpointSigningExpectation,
) bool {
	return left.checkpoint == right.checkpoint &&
		bytes.Equal(left.checkpointJSON, right.checkpointJSON) &&
		bytes.Equal(left.signerPublicKey, right.signerPublicKey)
}
