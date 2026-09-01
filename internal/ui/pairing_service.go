package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/store"
)

const maxPairingOperatorBodyBytes = 4 << 10

type pairingAttemptDetails = pairingservice.AttemptDetails

// PairingOperator is the human-only local pairing capability.
type PairingOperator interface {
	CreateInvite(
		context.Context,
		pairingservice.CreateInviteRequest,
	) (pairingservice.IssuedInvite, error)
	ListInvites(context.Context) ([]store.PairingInviteRecord, error)
	RevokeInvite(
		context.Context,
		domain.UUIDv7,
	) (store.PairingInviteRecord, bool, error)
	PairingAttempt(
		context.Context,
		domain.UUIDv7,
	) (pairingservice.AttemptDetails, error)
	ConfirmPairing(
		context.Context,
		domain.UUIDv7,
		[sha256.Size]byte,
		bool,
	) (pairingservice.AttemptDetails, error)
}

type createPairingInviteWire struct {
	Mode                   string  `json:"mode"`
	SubjectDeviceID        *string `json:"subject_device_id"`
	ExpectedEntityVersion  *uint64 `json:"expected_entity_version"`
	Role                   string  `json:"role"`
	InitialCredentialEpoch uint64  `json:"initial_credential_epoch"`
}

type inviteIDWire struct {
	InviteID string `json:"invite_id"`
}

type attemptIDWire struct {
	AttemptID string `json:"attempt_id"`
}

type confirmPairingWire struct {
	AttemptID     string `json:"attempt_id"`
	RequestDigest string `json:"request_digest"`
	Confirmed     bool   `json:"confirmed"`
}

func (handler *operatorHandler) createPairingInvite(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.pairing == nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	var input createPairingInviteWire
	if decodeClosedOperatorBody(
		request.Body,
		&input,
		"mode",
		"subject_device_id",
		"expected_entity_version",
		"role",
		"initial_credential_epoch",
	) != nil {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_pairing_request")
		return
	}
	var subject *domain.DeviceID
	if input.SubjectDeviceID != nil {
		value := domain.DeviceID(*input.SubjectDeviceID)
		subject = &value
	}
	issued, err := handler.pairing.CreateInvite(
		request.Context(),
		pairingservice.CreateInviteRequest{
			Mode: pairing.Mode(input.Mode), SubjectDeviceID: subject,
			ExpectedEntityVersion:  cloneUint64(input.ExpectedEntityVersion),
			Role:                   device.Role(input.Role),
			InitialCredentialEpoch: input.InitialCredentialEpoch,
		},
	)
	if err != nil {
		writePairingOperatorError(writer, err)
		return
	}
	response := PairingInviteCreated{
		Code:   issued.Invite.Code(),
		Invite: pairingInviteStatus(issued.Record),
	}
	if response.Code == "" || response.Invite.validate() != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	writeOperatorJSON(writer, http.StatusCreated, response)
}

func (handler *operatorHandler) listPairingInvites(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.pairing == nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	records, err := handler.pairing.ListInvites(request.Context())
	if err != nil {
		writePairingOperatorError(writer, err)
		return
	}
	response := PairingInviteList{
		Invites: make([]PairingInviteStatus, len(records)),
	}
	for index, record := range records {
		response.Invites[index] = pairingInviteStatus(record)
		if response.Invites[index].validate() != nil {
			writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
			return
		}
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) revokePairingInvite(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.pairing == nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	var input inviteIDWire
	if decodeClosedOperatorBody(request.Body, &input, "invite_id") != nil {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_pairing_request")
		return
	}
	record, duplicate, err := handler.pairing.RevokeInvite(
		request.Context(),
		domain.UUIDv7(input.InviteID),
	)
	if err != nil {
		writePairingOperatorError(writer, err)
		return
	}
	response := PairingInviteRevoked{
		Duplicate: duplicate,
		Invite:    pairingInviteStatus(record),
	}
	if response.Invite.validate() != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) pairingAttempt(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.pairing == nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	var input attemptIDWire
	if decodeClosedOperatorBody(request.Body, &input, "attempt_id") != nil {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_pairing_request")
		return
	}
	details, err := handler.pairing.PairingAttempt(
		request.Context(),
		domain.UUIDv7(input.AttemptID),
	)
	if err != nil {
		writePairingOperatorError(writer, err)
		return
	}
	response := pairingAttemptStatus(details)
	if response.validate() != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	writeOperatorJSON(writer, http.StatusOK, response)
}

func (handler *operatorHandler) confirmPairing(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if handler.pairing == nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	var input confirmPairingWire
	if decodeClosedOperatorBody(
		request.Body,
		&input,
		"attempt_id",
		"request_digest",
		"confirmed",
	) != nil {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_pairing_request")
		return
	}
	digestBytes, err := codec.DecodeBase64URLExact(
		input.RequestDigest,
		sha256.Size,
	)
	if err != nil {
		writeOperatorError(writer, http.StatusBadRequest, "invalid_pairing_request")
		return
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	clear(digestBytes)
	details, err := handler.pairing.ConfirmPairing(
		request.Context(),
		domain.UUIDv7(input.AttemptID),
		digest,
		input.Confirmed,
	)
	if err != nil && !errors.Is(err, pairingservice.ErrFinalizationPending) {
		writePairingOperatorError(writer, err)
		return
	}
	response := pairingAttemptStatus(details)
	if response.validate() != nil {
		writeOperatorError(writer, http.StatusServiceUnavailable, "pairing_unavailable")
		return
	}
	status := http.StatusOK
	if err != nil {
		status = http.StatusAccepted
	}
	writeOperatorJSON(writer, status, response)
}

func decodeClosedOperatorBody(
	body io.Reader,
	target any,
	fields ...string,
) error {
	if body == nil || target == nil || len(fields) == 0 {
		return pairingservice.ErrInvalidInput
	}
	raw, err := io.ReadAll(io.LimitReader(
		body,
		maxPairingOperatorBodyBytes+1,
	))
	if err != nil || len(raw) == 0 || len(raw) > maxPairingOperatorBodyBytes {
		return pairingservice.ErrInvalidInput
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return pairingservice.ErrInvalidInput
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(canonical, &members) != nil ||
		len(members) != len(fields) {
		return pairingservice.ErrInvalidInput
	}
	for _, field := range fields {
		if _, exists := members[field]; !exists {
			return pairingservice.ErrInvalidInput
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return pairingservice.ErrInvalidInput
	}
	return nil
}

func writePairingOperatorError(writer http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	code := "pairing_unavailable"
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		status = http.StatusRequestTimeout
		code = "pairing_interrupted"
	case errors.Is(err, pairingservice.ErrInvalidInput),
		errors.Is(err, pairingservice.ErrInvalidInviter):
		status = http.StatusBadRequest
		code = "invalid_pairing_request"
	case errors.Is(err, store.ErrPairingInviteLimit):
		status = http.StatusTooManyRequests
		code = "pairing_invite_limit"
	case errors.Is(err, pairingservice.ErrAwaitingJoinerConfirmation):
		status = http.StatusConflict
		code = "awaiting_joiner_confirmation"
	case errors.Is(err, pairingservice.ErrConfirmationConflict):
		status = http.StatusConflict
		code = "pairing_confirmation_conflict"
	case errors.Is(err, pairingservice.ErrInviteNotRevocable):
		status = http.StatusConflict
		code = "pairing_invite_not_revocable"
	case errors.Is(err, pairingservice.ErrRequestRejected):
		status = http.StatusNotFound
		code = "pairing_not_found"
	case errors.Is(err, pairingservice.ErrClosed):
		code = "pairing_closed"
	}
	writeOperatorError(writer, status, code)
}
