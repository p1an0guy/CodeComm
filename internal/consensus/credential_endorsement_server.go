package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/transport"
)

const credentialEndorsementClockSkew = 120 * time.Second

var (
	errCredentialEndorsementDenied = errors.New(
		"consensus: credential endorsement denied",
	)
	errCredentialEndorsementClock = errors.New(
		"consensus: credential endorsement time is outside local skew",
	)
	errCredentialEndorsementSignerUnavailable = errors.New(
		"consensus: credential endorsement signer unavailable",
	)
	errCredentialEndorsementSignerInvalid = errors.New(
		"consensus: credential endorsement signer returned an invalid signature",
	)
)

type credentialEndorsementCut struct {
	requesterEntityVersion uint64
	term                   uint64
	configurationIndex     uint64
	authorityVersion       uint64
	authorityDeviceIDs     []domain.DeviceID
	localEntityVersion     uint64
	localPublicKey         ed25519.PublicKey
}

func (node *SingleNode) serveCredentialEndorsement(
	writer http.ResponseWriter,
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	requestAuthority stagingProofAuthority,
	body []byte,
) {
	request, err := decodeCredentialEndorsementRequest(body)
	if err != nil {
		writeConsensusProofProblem(
			writer,
			http.StatusBadRequest,
			credentialProblemInvalid,
		)
		return
	}
	proof, err := node.endorseCredentialTime(
		ctx,
		peer,
		request,
		requestAuthority,
	)
	if err != nil {
		switch {
		case errors.Is(err, errCredentialEndorsementDenied):
			writeConsensusProofProblem(
				writer,
				http.StatusForbidden,
				credentialProblemForbidden,
			)
		case errors.Is(err, errCredentialEndorsementClock):
			writeConsensusProofProblem(
				writer,
				http.StatusConflict,
				credentialProblemClock,
			)
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, ErrNodeClosed),
			errors.Is(err, ErrConsensusAuthorizationUnavailable),
			errors.Is(
				err,
				errCredentialEndorsementSignerUnavailable,
			):
			writeConsensusProofProblem(
				writer,
				http.StatusServiceUnavailable,
				credentialProblemUnavailable,
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
	response, err := encodeCredentialEndorsementResponse(
		proof.request,
		proof.endorserDeviceID,
		proof.signature,
	)
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

func (node *SingleNode) endorseCredentialTime(
	ctx context.Context,
	peer transport.AuthenticatedPeer,
	request credentialEndorsementRequest,
	requestAuthority stagingProofAuthority,
) (credentialEndorsementProof, error) {
	if node == nil || ctx == nil || len(request.canonical) == 0 {
		return credentialEndorsementProof{},
			ErrInvalidCredentialEndorsement
	}
	if err := ctx.Err(); err != nil {
		return credentialEndorsementProof{}, err
	}
	if err := node.beginOperation(); err != nil {
		return credentialEndorsementProof{}, err
	}
	defer node.endOperation()
	if err := node.FatalError(); err != nil {
		return credentialEndorsementProof{}, err
	}
	signer := node.credentialEndorsementSigner
	if signer == nil {
		return credentialEndorsementProof{},
			errCredentialEndorsementSignerUnavailable
	}
	operationContext, cancel, wait := node.operationContext(ctx)
	defer func() {
		cancel()
		wait()
	}()
	ctx = operationContext

	beforeAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil {
		return credentialEndorsementProof{}, err
	}
	if !beforeAuthority.sameRequester(requestAuthority) {
		return credentialEndorsementProof{},
			ErrConsensusAuthorizationUnavailable
	}
	before, err := node.credentialEndorsementSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return credentialEndorsementProof{}, err
	}
	if signer.DeviceID() != domain.DeviceID(node.serverID) {
		return credentialEndorsementProof{},
			errCredentialEndorsementSignerUnavailable
	}
	if err := node.requireCredentialEndorsementTime(
		request.authorization.IssuedAt,
	); err != nil {
		return credentialEndorsementProof{}, err
	}
	signature, err := signer.SignCredentialEndorsement(
		ctx,
		request.authorization,
	)
	if err != nil {
		return credentialEndorsementProof{},
			errCredentialEndorsementSignerUnavailable
	}
	preimage, err := credentialauthorization.
		CanonicalEndorsementPreimage(request.authorization)
	if err != nil ||
		codecommcrypto.VerifyEd25519(
			before.localPublicKey,
			codec.SignatureCredentialTimeEndorsement,
			preimage,
			signature[:],
		) != nil {
		return credentialEndorsementProof{},
			errCredentialEndorsementSignerInvalid
	}
	if err := node.requireCredentialEndorsementTime(
		request.authorization.IssuedAt,
	); err != nil {
		return credentialEndorsementProof{}, err
	}
	after, err := node.credentialEndorsementSigningCut(
		ctx,
		request,
		beforeAuthority,
	)
	if err != nil {
		return credentialEndorsementProof{}, err
	}
	afterAuthority, err := node.consensusProofRequesterAuthority(peer)
	if err != nil ||
		!beforeAuthority.sameRequester(afterAuthority) ||
		!sameCredentialEndorsementCut(before, after) {
		return credentialEndorsementProof{},
			ErrConsensusAuthorizationUnavailable
	}
	return credentialEndorsementProof{
		request:          request,
		endorserDeviceID: domain.DeviceID(node.serverID),
		signature:        signature,
	}, nil
}

func (node *SingleNode) credentialEndorsementSigningCut(
	ctx context.Context,
	request credentialEndorsementRequest,
	requestAuthority stagingProofAuthority,
) (credentialEndorsementCut, error) {
	if node == nil || node.state == nil || ctx == nil {
		return credentialEndorsementCut{},
			ErrConsensusAuthorizationUnavailable
	}
	if err := ctx.Err(); err != nil {
		return credentialEndorsementCut{}, err
	}
	view, err := node.state.View(ctx)
	if err != nil {
		return credentialEndorsementCut{}, err
	}
	state, err := decodeStateView(view)
	if err != nil {
		return credentialEndorsementCut{}, err
	}
	localDeviceID := domain.DeviceID(node.serverID)
	member, exists := state.Admission.Member(localDeviceID)
	publicKey, keyExists := state.IdentityPublicKey(localDeviceID)
	if request.authorization.SessionID != view.SessionID ||
		state.CredentialAuthority.Validate() != nil ||
		request.authorization.AuthorityVoterSetVersion !=
			state.CredentialAuthority.VoterSetVersion ||
		!state.CredentialAuthority.Contains(localDeviceID) ||
		!exists ||
		member.Status != device.StatusActive ||
		!keyExists ||
		requestAuthority.leaderDeviceID == localDeviceID {
		return credentialEndorsementCut{},
			errCredentialEndorsementDenied
	}
	return credentialEndorsementCut{
		requesterEntityVersion: requestAuthority.requesterEntityVersion,
		term:                   requestAuthority.term,
		configurationIndex:     requestAuthority.configurationIndex,
		authorityVersion: state.CredentialAuthority.
			VoterSetVersion,
		authorityDeviceIDs: state.CredentialAuthority.VoterIDs(),
		localEntityVersion: member.EntityVersion,
		localPublicKey:     bytes.Clone(publicKey),
	}, nil
}

func (node *SingleNode) requireCredentialEndorsementTime(
	issuedAt domain.WholeSecondTimestamp,
) error {
	if node == nil || node.credentialEndorsementNow == nil {
		return ErrConsensusAuthorizationUnavailable
	}
	issuedTime, err := issuedAt.Time()
	if err != nil {
		return ErrInvalidCredentialEndorsement
	}
	now := node.credentialEndorsementNow()
	if now.IsZero() {
		return ErrConsensusAuthorizationUnavailable
	}
	if issuedTime.Before(now.Add(-credentialEndorsementClockSkew)) ||
		issuedTime.After(now.Add(credentialEndorsementClockSkew)) {
		return errCredentialEndorsementClock
	}
	return nil
}

func sameCredentialEndorsementCut(
	left credentialEndorsementCut,
	right credentialEndorsementCut,
) bool {
	if left.requesterEntityVersion != right.requesterEntityVersion ||
		left.term != right.term ||
		left.configurationIndex != right.configurationIndex ||
		left.authorityVersion != right.authorityVersion ||
		left.localEntityVersion != right.localEntityVersion ||
		!bytes.Equal(left.localPublicKey, right.localPublicKey) ||
		len(left.authorityDeviceIDs) != len(right.authorityDeviceIDs) {
		return false
	}
	for index := range left.authorityDeviceIDs {
		if left.authorityDeviceIDs[index] != right.authorityDeviceIDs[index] {
			return false
		}
	}
	return true
}
