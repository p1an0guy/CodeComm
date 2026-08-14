package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/store"
)

var ErrInvalidAdmissionAuthorizer = errors.New(
	"pairing service: invalid admission authorizer",
)

// IDGenerator returns a never-reused UUIDv7.
type IDGenerator = store.UUIDv7Generator

// AdmissionAuthorizerOptions binds membership admission to the verified local
// operator origin and installation identity.
type AdmissionAuthorizerOptions struct {
	DeviceID           domain.DeviceID
	OriginBootID       domain.UUIDv7
	IdentityPrivateKey ed25519.PrivateKey
	OperatorOrigin     event.Binding
	GenerateID         IDGenerator
}

// AdmissionAuthorizer prepares the exact membership event reserved by the
// second SAS approval. It performs no I/O and grants no authority by itself.
type AdmissionAuthorizer struct {
	deviceID     domain.DeviceID
	originBootID domain.UUIDv7
	privateKey   ed25519.PrivateKey
	origin       event.Binding
	generateID   IDGenerator
}

// NewAdmissionAuthorizer validates one daemon boot's operator authority.
func NewAdmissionAuthorizer(
	options AdmissionAuthorizerOptions,
) (*AdmissionAuthorizer, error) {
	if !options.DeviceID.Valid() ||
		!options.OriginBootID.Valid() ||
		len(options.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidAdmissionAuthorizer
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		options.IdentityPrivateKey,
	)
	if err != nil {
		return nil, ErrInvalidAdmissionAuthorizer
	}
	origin, err := options.OperatorOrigin.Origin(1)
	if err != nil ||
		options.OperatorOrigin.ActorType() != event.ActorHuman ||
		origin.DeviceID() != options.DeviceID ||
		origin.OriginBootID() != options.OriginBootID ||
		origin.AgentSessionID() != "" {
		return nil, ErrInvalidAdmissionAuthorizer
	}
	derived, err := codec.DeriveDeviceID(publicKey)
	if err != nil || derived != string(options.DeviceID) {
		return nil, ErrInvalidAdmissionAuthorizer
	}
	generateID := options.GenerateID
	if generateID == nil {
		generateID = generateAdmissionID
	}
	return &AdmissionAuthorizer{
		deviceID: options.DeviceID, originBootID: options.OriginBootID,
		privateKey: append(ed25519.PrivateKey(nil), options.IdentityPrivateKey...),
		origin:     options.OperatorOrigin, generateID: generateID,
	}, nil
}

// PreparePairing constructs the reservation committed with local SAS
// acceptance. Rebootstrap deliberately returns no membership command.
func (authorizer *AdmissionAuthorizer) PreparePairing(
	ctx context.Context,
	details AttemptDetails,
	decidedAt domain.Timestamp,
) (*store.PairingFinalizationAuthorization, error) {
	if authorizer == nil || ctx == nil {
		return nil, ErrInvalidAdmissionAuthorizer
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := authorizer.validateDetails(details, decidedAt); err != nil {
		return nil, err
	}
	canonicalRequest, err := finalizationCanonicalRequest(details)
	if err != nil {
		return nil, err
	}
	request := store.PairingOperatorRequest{
		ClientInstanceID: details.Attempt.AttemptID,
		RequestID:        details.Attempt.AttemptID,
		SessionID:        details.Invite.SessionID,
		WorkspaceID:      details.Invite.WorkspaceID,
		OriginDeviceID:   authorizer.deviceID,
		OriginBootID:     authorizer.originBootID,
		CanonicalRequest: canonicalRequest,
		CreatedAt:        decidedAt,
	}
	authorization := &store.PairingFinalizationAuthorization{Request: request}
	if details.Invite.Mode == pairing.ModeRebootstrap {
		return authorization, nil
	}

	payload, err := admissionPayload(details)
	if err != nil {
		return nil, err
	}
	expectedVersion := cloneVersion(details.Invite.ExpectedEntityVersion)
	reservation := &store.LocalCommandReservation{
		Input: store.LocalCommandInput{
			ClientInstanceID: request.ClientInstanceID,
			RequestID:        request.RequestID,
			SessionID:        request.SessionID,
			WorkspaceID:      request.WorkspaceID,
			BindingClass:     store.LocalBindingOperator,
			OriginDeviceID:   request.OriginDeviceID,
			OriginScopeKind:  store.OriginScopeKindBoot,
			OriginScopeID:    request.OriginBootID,
			RequestKind:      event.KindMembershipDeviceAdmitted,
			CanonicalRequest: bytes.Clone(request.CanonicalRequest),
			CreatedAt:        request.CreatedAt,
		},
		GenerateEventID: authorizer.generateID,
	}
	reservation.Build = func(
		eventID domain.UUIDv7,
		originSequence uint64,
	) (event.SignedEvent, error) {
		proposal, err := event.BuildProposal(
			event.Command{
				Kind:                  event.KindMembershipDeviceAdmitted,
				EntityID:              event.StringEntityID(string(details.Core.JoinerDeviceID)),
				ExpectedEntityVersion: cloneVersion(expectedVersion),
				RationaleSummary:      "",
				Actions:               []event.Action{},
				Payload:               bytes.Clone(payload),
				Redaction: event.Redaction{
					Policy:        event.RedactionDefault,
					FieldsRemoved: []event.RedactionField{},
				},
			},
			authorizer.origin,
			event.BuildContext{
				EventID:        eventID,
				SessionID:      details.Invite.SessionID,
				WorkspaceID:    details.Invite.WorkspaceID,
				CreatedAt:      decidedAt,
				OriginSequence: originSequence,
			},
		)
		if err != nil {
			return event.SignedEvent{}, err
		}
		return event.Sign(proposal, authorizer.privateKey)
	}
	authorization.Admission = reservation
	return authorization, nil
}

func (authorizer *AdmissionAuthorizer) validateDetails(
	details AttemptDetails,
	decidedAt domain.Timestamp,
) error {
	invite := details.Invite
	attempt := details.Attempt
	core := details.Core
	if !decidedAt.Valid() ||
		invite.IssuerDeviceID != authorizer.deviceID ||
		!invite.SessionID.Valid() ||
		!invite.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(invite.RecoveryGeneration) ||
		!invite.Mode.Valid() ||
		attempt.AttemptID != core.AttemptID ||
		attempt.InviteID != invite.InviteID ||
		attempt.JoinerDeviceID != core.JoinerDeviceID ||
		attempt.State != store.PairingAttemptAwaitingSAS ||
		attempt.LocalConfirmed ||
		!attempt.RemoteConfirmed ||
		core.InitialEpochBinding.SessionID != invite.SessionID ||
		core.InitialEpochBinding.DeviceID != core.JoinerDeviceID ||
		core.InitialEpochBinding.Epoch != invite.InitialCredentialEpoch ||
		core.InitialEpochBinding.Validate(core.JoinerIdentityPublicKey[:]) != nil {
		return ErrInvalidAdmissionAuthorizer
	}
	switch invite.Mode {
	case pairing.ModeNew:
		if invite.SubjectDeviceID != nil ||
			invite.ExpectedEntityVersion != nil {
			return ErrInvalidAdmissionAuthorizer
		}
	case pairing.ModeRebootstrap:
		if invite.SubjectDeviceID == nil ||
			*invite.SubjectDeviceID != core.JoinerDeviceID ||
			invite.ExpectedEntityVersion != nil {
			return ErrInvalidAdmissionAuthorizer
		}
	case pairing.ModeReadmission:
		if invite.SubjectDeviceID == nil ||
			*invite.SubjectDeviceID != core.JoinerDeviceID ||
			invite.ExpectedEntityVersion == nil {
			return ErrInvalidAdmissionAuthorizer
		}
	default:
		return ErrInvalidAdmissionAuthorizer
	}
	return nil
}

func finalizationCanonicalRequest(details AttemptDetails) ([]byte, error) {
	raw, err := json.Marshal(map[string]any{
		"attempt_id":       details.Attempt.AttemptID,
		"confirmed":        true,
		"invite_id":        details.Invite.InviteID,
		"joiner_device_id": details.Core.JoinerDeviceID,
		"mode":             details.Invite.Mode,
		"operation":        "peer.pairing.confirm",
		"request_digest": codec.EncodeBase64URL(
			details.Attempt.RequestDigest[:],
		),
		"role": details.Invite.Role,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrInvalidAdmissionAuthorizer, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrInvalidAdmissionAuthorizer, err)
	}
	return canonical, nil
}

func admissionPayload(details AttemptDetails) ([]byte, error) {
	binding := details.Core.InitialEpochBinding
	raw, err := json.Marshal(map[string]any{
		"daemon_version": details.Core.DaemonVersion,
		"identity_public_key": codec.EncodeBase64URL(
			details.Core.JoinerIdentityPublicKey[:],
		),
		"initial_epoch_binding": map[string]any{
			"binding_signature": codec.EncodeBase64URL(binding.Signature[:]),
			"epoch":             binding.Epoch,
			"epoch_public_key":  codec.EncodeBase64URL(binding.EpochPublicKey[:]),
			"key_digest":        codec.EncodeBase64URL(binding.KeyDigest[:]),
		},
		"max_apply_level": details.Core.MaxApplyLevel,
		"role":            details.Invite.Role,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrInvalidAdmissionAuthorizer, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrInvalidAdmissionAuthorizer, err)
	}
	return canonical, nil
}

func generateAdmissionID() (domain.UUIDv7, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	result := domain.UUIDv7(value.String())
	if !result.Valid() {
		return "", domain.ErrInvalidUUIDv7
	}
	return result, nil
}

func cloneVersion(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
