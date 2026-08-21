package consensus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

var (
	credentialRenewalProblemInvalid = consensusProofProblemDefinition{
		code:  "invalid_credential_renewal",
		title: "Invalid credential renewal request",
	}
	credentialRenewalProblemForbidden = consensusProofProblemDefinition{
		code:  "credential_renewal_forbidden",
		title: "Credential renewal request forbidden",
	}
	credentialRenewalProblemTooEarly = consensusProofProblemDefinition{
		code:      "credential_renewal_too_early",
		title:     "Credential renewal requested too early",
		retryable: true,
	}
	credentialRenewalProblemRejected = consensusProofProblemDefinition{
		code:  "credential_renewal_rejected",
		title: "Credential renewal rejected",
	}
	credentialRenewalProblemUnavailable = consensusProofProblemDefinition{
		code:      "credential_renewal_unavailable",
		title:     "Credential renewal unavailable",
		retryable: true,
	}
)

// RenewCredential authorizes a signed next-epoch binding at the leader or
// forwards it exactly once to the leader observed by this replica.
func (node *SingleNode) RenewCredential(
	ctx context.Context,
	binding credential.Binding,
) (credentialauthorization.Authorization, error) {
	return node.renewCredential(ctx, binding, true)
}

func (node *SingleNode) renewCredential(
	ctx context.Context,
	binding credential.Binding,
	allowForward bool,
) (credentialauthorization.Authorization, error) {
	if node == nil || node.raft == nil || node.state == nil || ctx == nil {
		return credentialauthorization.Authorization{},
			ErrInvalidNodeOptions
	}
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	if err := node.beginOperation(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	committed, retry, err := node.validateCredentialRenewalBinding(
		ctx,
		binding,
	)
	if err != nil {
		return credentialauthorization.Authorization{}, err
	}
	if retry {
		return committed, nil
	}
	if node.IsLeader() {
		candidate, _, err := node.AuthorizeCredential(ctx, binding)
		if err != nil {
			return credentialauthorization.Authorization{}, err
		}
		return node.loadCommittedCredentialAuthorization(ctx, candidate)
	}
	if !allowForward {
		return credentialauthorization.Authorization{},
			fmt.Errorf("%w: %w", ErrCredentialRenewalUnavailable, raft.ErrNotLeader)
	}

	leaderDeviceID, err := node.credentialRenewalLeader()
	if err != nil {
		return credentialauthorization.Authorization{}, err
	}
	requester := node.credentialRenewalRequester
	if requester == nil {
		requester, _ = node.transport.(credentialRenewalRequester)
	}
	if requester == nil {
		return credentialauthorization.Authorization{},
			ErrCredentialRenewalUnavailable
	}
	return requestCredentialRenewal(
		ctx,
		requester,
		leaderDeviceID,
		binding,
		credentialRenewalModeForward,
	)
}

func (node *SingleNode) validateCredentialRenewalBinding(
	ctx context.Context,
	binding credential.Binding,
) (credentialauthorization.Authorization, bool, error) {
	if node == nil || ctx == nil {
		return credentialauthorization.Authorization{},
			false,
			ErrInvalidCredentialBinding
	}
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{}, false, err
	}
	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return credentialauthorization.Authorization{}, false, err
	}
	sessionID, _, valid := admission.Lineage()
	member, exists := admission.Member(binding.DeviceID)
	currentEpoch, epochExists := admission.CurrentCredentialEpoch(
		binding.DeviceID,
	)
	if !valid ||
		binding.SessionID != sessionID ||
		!exists ||
		member.Status != device.StatusActive ||
		!epochExists ||
		binding.Validate(member.IdentityPublicKey) != nil {
		return credentialauthorization.Authorization{},
			false,
			ErrInvalidCredentialBinding
	}
	if binding.Epoch == currentEpoch {
		committed, found := admission.Authorization(
			credentialauthorization.Key{
				SessionID: binding.SessionID,
				DeviceID:  binding.DeviceID,
				Epoch:     binding.Epoch,
			},
		)
		if !found ||
			committed.Validate() != nil ||
			!credentialAuthorizationMatchesBinding(committed, binding) {
			return credentialauthorization.Authorization{},
				false,
				ErrInvalidCredentialBinding
		}
		return committed, true, nil
	}
	if currentEpoch == domain.MaxSafeInteger ||
		binding.Epoch != currentEpoch+1 {
		return credentialauthorization.Authorization{},
			false,
			ErrInvalidCredentialBinding
	}
	return credentialauthorization.Authorization{}, false, nil
}

func (node *SingleNode) credentialRenewalLeader() (
	domain.DeviceID,
	error,
) {
	if node == nil || node.raft == nil {
		return "", ErrCredentialRenewalUnavailable
	}
	address, leaderID := node.raft.LeaderWithID()
	deviceID := domain.DeviceID(leaderID)
	if !deviceID.Valid() ||
		address != raft.ServerAddress(deviceID) ||
		leaderID == node.serverID {
		return "", ErrCredentialRenewalUnavailable
	}
	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return "", err
	}
	member, exists := admission.Member(deviceID)
	if !exists || member.Status != device.StatusActive {
		return "", ErrCredentialRenewalUnavailable
	}
	return deviceID, nil
}

func (node *SingleNode) loadCommittedCredentialAuthorization(
	ctx context.Context,
	candidate credentialauthorization.Authorization,
) (credentialauthorization.Authorization, error) {
	if node == nil || ctx == nil {
		return credentialauthorization.Authorization{},
			ErrCredentialRenewalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return credentialauthorization.Authorization{}, err
	}
	admission, err := node.PeerAdmissionSnapshot()
	if err != nil {
		return credentialauthorization.Authorization{},
			node.haltNode(fmt.Errorf(
				"%w: load accepted authorization: %v",
				ErrCredentialRenewalMismatch,
				err,
			))
	}
	committed, found := admission.Authorization(candidate.PrimaryKey())
	expected := candidate.Clone()
	expected.AuthorizationChainIndex = committed.AuthorizationChainIndex
	if !found ||
		committed.AuthorizationChainIndex == 0 ||
		committed.Validate() != nil ||
		!reflect.DeepEqual(committed, expected) {
		return credentialauthorization.Authorization{},
			node.haltNode(fmt.Errorf(
				"%w: accepted authorization differs from applied state",
				ErrCredentialRenewalMismatch,
			))
	}
	return committed.Clone(), nil
}

func (node *SingleNode) serveCredentialRenewal(
	writer http.ResponseWriter,
	ctx context.Context,
	_ transport.AuthenticatedPeer,
	body []byte,
) {
	request, err := decodeCredentialRenewalRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			credentialRenewalProblemInvalid,
		)
		return
	}
	authorization, err := node.renewCredential(
		ctx,
		request.binding,
		request.mode == credentialRenewalModeSubmit,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentialBinding),
			errors.Is(err, ErrInvalidCredentialRenewal):
			writeConsensusProofProblem(
				writer,
				http.StatusBadRequest,
				credentialRenewalProblemInvalid,
			)
		case errors.Is(err, ErrCredentialRenewalTooEarly):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				credentialRenewalProblemTooEarly,
			)
		case errors.Is(err, ErrCredentialAuthorizationRejected),
			errors.Is(err, ErrCredentialRenewalRejected):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				credentialRenewalProblemRejected,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, raft.ErrNotLeader),
			errors.Is(err, raft.ErrLeadershipLost),
			errors.Is(err, ErrNodeClosed),
			errors.Is(err, ErrConsensusAuthorizationUnavailable),
			errors.Is(err, ErrCredentialAuthorizationUnavailable),
			errors.Is(err, ErrCredentialAuthorizationOriginUnavailable),
			errors.Is(err, ErrCredentialRenewalUnavailable):
			writeConsensusProofProblem(
				writer,
				http.StatusServiceUnavailable,
				credentialRenewalProblemUnavailable,
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
	response, err := encodeCredentialRenewalResponse(authorization)
	if err != nil {
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
