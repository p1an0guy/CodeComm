package reducer

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

type ownerRecoveryPreimage struct {
	EventID               string `json:"event_id"`
	ExpectedEntityVersion uint64 `json:"expected_entity_version"`
	RecoveryGeneration    uint64 `json:"recovery_generation"`
	SessionID             string `json:"session_id"`
	SubjectDeviceID       string `json:"subject_device_id"`
}

func reduceMembershipOwnerRecovered(
	context reductionContext,
) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"recovery_authorization"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	authorization, code := decodePayload(
		payload["recovery_authorization"],
		[]string{
			"session_id",
			"recovery_generation",
			"event_id",
			"subject_device_id",
			"expected_entity_version",
			"signature",
		},
		nil,
	)
	if code != "" {
		return context.reject(CodeInvalidRecoveryAuthorization), nil
	}
	sessionID, sessionOK := decodeValue[string](authorization, "session_id")
	generation, generationOK := decodeValue[uint64](
		authorization,
		"recovery_generation",
	)
	eventID, eventOK := decodeValue[string](authorization, "event_id")
	subjectText, subjectOK := decodeValue[string](
		authorization,
		"subject_device_id",
	)
	authorizationVersion, versionOK := decodeValue[uint64](
		authorization,
		"expected_entity_version",
	)
	signatureText, signatureOK := decodeValue[string](
		authorization,
		"signature",
	)
	if !sessionOK || !generationOK || !eventOK || !subjectOK ||
		!versionOK || !signatureOK {
		return context.reject(CodeInvalidRecoveryAuthorization), nil
	}

	subjectID := context.subjectDeviceID()
	if subjectID != context.proposal.Origin.DeviceID() ||
		domain.DeviceID(subjectText) != subjectID {
		return context.reject(CodeMembershipSubjectMismatch), nil
	}
	current := context.device
	if current.ID != subjectID ||
		current.Status != device.StatusActive ||
		current.Role != device.RoleEditor {
		return context.reject(CodeInvalidMembershipTransition), nil
	}
	expected := context.proposal.ExpectedEntityVersion
	if expected == nil || *expected != current.EntityVersion {
		return context.reject(CodeEntityVersionMismatch), nil
	}
	if domain.UUIDv7(sessionID) != context.state.sessionID ||
		generation != context.state.recoveryGeneration ||
		domain.UUIDv7(eventID) != context.proposal.EventID ||
		authorizationVersion != *expected {
		return context.reject(CodeInvalidRecoveryAuthorization), nil
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil {
		return context.reject(CodeInvalidRecoveryAuthorization), nil
	}
	unsignedJSON, err := json.Marshal(ownerRecoveryPreimage{
		EventID:               eventID,
		ExpectedEntityVersion: authorizationVersion,
		RecoveryGeneration:    generation,
		SessionID:             sessionID,
		SubjectDeviceID:       subjectText,
	})
	if err != nil {
		return Outcome{}, invalidState(
			"encode owner-recovery preimage: %v",
			err,
		)
	}
	unsigned, err := codec.CanonicalizeSignedObject(unsignedJSON)
	if err != nil {
		return Outcome{}, invalidState(
			"canonicalize owner-recovery preimage: %v",
			err,
		)
	}
	signedInput, err := codec.BuildSignedInput(
		codec.SignatureOwnerRecovery,
		unsigned,
	)
	if err != nil {
		return Outcome{}, invalidState(
			"construct owner-recovery signed input: %v",
			err,
		)
	}
	if !ed25519.Verify(
		context.state.recoveryPublicKey,
		signedInput,
		signature,
	) {
		return context.reject(CodeInvalidRecoveryAuthorization), nil
	}
	if current.EntityVersion == domain.MaxSafeInteger {
		return context.reject(CodeEntityVersionExhausted), nil
	}

	next := current
	next.Role = device.RoleOwner
	next.EntityVersion++
	if err := device.ValidateTransition(
		device.OperationOwnerRecovery,
		&current,
		next,
	); err != nil {
		return Outcome{}, invalidState(
			"owner-recovery transition: %v",
			err,
		)
	}
	return context.acceptMembership(
		[]device.Device{next},
		nil,
		nil,
		nil,
		deviceMembershipOverride(subjectID),
	)
}
