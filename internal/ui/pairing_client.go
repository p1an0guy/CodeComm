package ui

import (
	"context"
	"errors"
	"net/http"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/store"
)

var ErrPairingProtocol = errors.New("ui: invalid pairing protocol response")

func (client *OperatorClient) CreatePairingInvite(
	ctx context.Context,
	request pairingservice.CreateInviteRequest,
) (PairingInviteCreated, error) {
	var subject *string
	if request.SubjectDeviceID != nil {
		value := string(*request.SubjectDeviceID)
		subject = &value
	}
	body, err := canonicalOperatorJSON(createPairingInviteWire{
		Mode: string(request.Mode), SubjectDeviceID: subject,
		ExpectedEntityVersion:  cloneUint64(request.ExpectedEntityVersion),
		Role:                   string(request.Role),
		InitialCredentialEpoch: request.InitialCredentialEpoch,
	})
	if err != nil {
		return PairingInviteCreated{}, ErrInvalidOperatorDial
	}
	response, err := client.pairingExchange(
		ctx,
		http.MethodPost,
		pairingInviteCollectionPath,
		body,
		http.StatusCreated,
	)
	if err != nil {
		return PairingInviteCreated{}, err
	}
	var result PairingInviteCreated
	if decodeStatusObject(response, &result) != nil ||
		result.Invite.validate() != nil {
		return PairingInviteCreated{}, ErrPairingProtocol
	}
	signed, err := pairing.ParseInviteCode(result.Code)
	if err != nil {
		return PairingInviteCreated{}, ErrPairingProtocol
	}
	value := signed.Invite()
	defer clear(value.Secret[:])
	if value.SessionID != client.options.SessionID ||
		value.WorkspaceID != client.options.WorkspaceID ||
		value.InviteID != domain.UUIDv7(result.Invite.InviteID) ||
		string(value.Mode) != result.Invite.Mode ||
		string(value.Role) != result.Invite.Role ||
		value.InitialCredentialEpoch != result.Invite.InitialCredentialEpoch ||
		!samePairingDeviceID(
			value.SubjectDeviceID,
			result.Invite.SubjectDeviceID,
		) ||
		!sameOptionalUint64(
			value.ExpectedEntityVersion,
			result.Invite.ExpectedEntityVersion,
		) ||
		string(value.Mode) != string(request.Mode) ||
		string(value.Role) != string(request.Role) ||
		value.InitialCredentialEpoch != request.InitialCredentialEpoch ||
		!sameOptionalDeviceID(
			value.SubjectDeviceID,
			request.SubjectDeviceID,
		) ||
		!sameOptionalUint64(
			value.ExpectedEntityVersion,
			request.ExpectedEntityVersion,
		) ||
		string(value.CreatedAt) != result.Invite.CreatedAt ||
		string(value.ExpiresAt) != result.Invite.ExpiresAt {
		return PairingInviteCreated{}, ErrPairingProtocol
	}
	return result, nil
}

func (client *OperatorClient) PairingInvites(
	ctx context.Context,
) (PairingInviteList, error) {
	response, err := client.pairingExchange(
		ctx,
		http.MethodGet,
		pairingInviteCollectionPath,
		nil,
		http.StatusOK,
	)
	if err != nil {
		return PairingInviteList{}, err
	}
	var result PairingInviteList
	if decodeStatusObject(response, &result) != nil ||
		result.Invites == nil {
		return PairingInviteList{}, ErrPairingProtocol
	}
	for _, invite := range result.Invites {
		if invite.validate() != nil {
			return PairingInviteList{}, ErrPairingProtocol
		}
	}
	return result, nil
}

func (client *OperatorClient) RevokePairingInvite(
	ctx context.Context,
	inviteID domain.UUIDv7,
) (PairingInviteRevoked, error) {
	if !inviteID.Valid() {
		return PairingInviteRevoked{}, ErrInvalidOperatorDial
	}
	body, err := canonicalOperatorJSON(inviteIDWire{
		InviteID: string(inviteID),
	})
	if err != nil {
		return PairingInviteRevoked{}, ErrInvalidOperatorDial
	}
	response, err := client.pairingExchange(
		ctx,
		http.MethodPost,
		pairingInviteRevokePath,
		body,
		http.StatusOK,
	)
	if err != nil {
		return PairingInviteRevoked{}, err
	}
	var result PairingInviteRevoked
	if decodeStatusObject(response, &result) != nil ||
		result.Invite.validate() != nil ||
		result.Invite.InviteID != string(inviteID) ||
		result.Invite.State != string(store.PairingInviteRevoked) {
		return PairingInviteRevoked{}, ErrPairingProtocol
	}
	return result, nil
}

func (client *OperatorClient) PairingAttempt(
	ctx context.Context,
	attemptID domain.UUIDv7,
) (PairingAttemptStatus, error) {
	if !attemptID.Valid() {
		return PairingAttemptStatus{}, ErrInvalidOperatorDial
	}
	body, err := canonicalOperatorJSON(attemptIDWire{
		AttemptID: string(attemptID),
	})
	if err != nil {
		return PairingAttemptStatus{}, ErrInvalidOperatorDial
	}
	response, err := client.pairingExchange(
		ctx,
		http.MethodPost,
		pairingAttemptPath,
		body,
		http.StatusOK,
	)
	if err != nil {
		return PairingAttemptStatus{}, err
	}
	return decodePairingAttempt(response, attemptID)
}

func (client *OperatorClient) ConfirmPairing(
	ctx context.Context,
	attempt PairingAttemptStatus,
	confirmed bool,
) (PairingAttemptStatus, error) {
	if attempt.validate() != nil {
		return PairingAttemptStatus{}, ErrInvalidOperatorDial
	}
	body, err := canonicalOperatorJSON(confirmPairingWire{
		AttemptID: attempt.AttemptID, RequestDigest: attempt.RequestDigest,
		Confirmed: confirmed,
	})
	if err != nil {
		return PairingAttemptStatus{}, ErrInvalidOperatorDial
	}
	response, err := client.pairingExchange(
		ctx,
		http.MethodPost,
		pairingConfirmPath,
		body,
		http.StatusOK,
		http.StatusAccepted,
	)
	if err != nil {
		return PairingAttemptStatus{}, err
	}
	result, err := decodePairingAttempt(
		response,
		domain.UUIDv7(attempt.AttemptID),
	)
	if err != nil ||
		!samePairingReviewSubject(attempt, result) ||
		result.LocalConfirmed != confirmed {
		return PairingAttemptStatus{}, ErrPairingProtocol
	}
	return result, nil
}

func decodePairingAttempt(
	response []byte,
	attemptID domain.UUIDv7,
) (PairingAttemptStatus, error) {
	var result PairingAttemptStatus
	if decodeStatusObject(response, &result) != nil ||
		result.validate() != nil ||
		result.AttemptID != string(attemptID) {
		return PairingAttemptStatus{}, ErrPairingProtocol
	}
	return result, nil
}

func (client *OperatorClient) pairingExchange(
	ctx context.Context,
	method string,
	path string,
	body []byte,
	successStatuses ...int,
) ([]byte, error) {
	if client == nil || ctx == nil || len(successStatuses) == 0 {
		return nil, ErrInvalidOperatorDial
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	transport, err := client.currentTransport()
	if errors.Is(err, ErrStatusConnection) {
		transport, err = client.reconnect(ctx, nil)
	}
	if err != nil {
		return nil, err
	}
	if !transport.Usable() {
		transport, err = client.reconnect(ctx, transport)
		if err != nil {
			return nil, err
		}
	}
	response, err := transport.Exchange(ctx, method, path, body)
	if err != nil {
		if errors.Is(err, ipc.ErrClientProtocol) {
			return nil, ErrPairingProtocol
		}
		return nil, err
	}
	for _, status := range successStatuses {
		if response.StatusCode == status {
			return response.Body, nil
		}
	}
	return nil, ErrPairingProtocol
}

func samePairingDeviceID(
	left *domain.DeviceID,
	right *string,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return string(*left) == *right
}

func sameOptionalDeviceID(
	left, right *domain.DeviceID,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameOptionalUint64(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func samePairingReviewSubject(
	left, right PairingAttemptStatus,
) bool {
	return left.AttemptID == right.AttemptID &&
		left.InviteID == right.InviteID &&
		left.RequestDigest == right.RequestDigest &&
		left.Mode == right.Mode &&
		left.JoinerDeviceID == right.JoinerDeviceID &&
		left.JoinerIdentityPublicKey == right.JoinerIdentityPublicKey &&
		left.DaemonVersion == right.DaemonVersion &&
		left.MaxApplyLevel == right.MaxApplyLevel &&
		left.Role == right.Role &&
		sameOptionalUint64(
			left.ExpectedEntityVersion,
			right.ExpectedEntityVersion,
		) &&
		left.InitialCredentialEpoch == right.InitialCredentialEpoch &&
		left.EpochPublicKey == right.EpochPublicKey &&
		left.EpochKeyDigest == right.EpochKeyDigest &&
		left.SAS == right.SAS
}
