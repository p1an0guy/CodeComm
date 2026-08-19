package ui

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/store"
)

type PairingInviteStatus struct {
	InviteID               string  `json:"invite_id"`
	Mode                   string  `json:"mode"`
	SubjectDeviceID        *string `json:"subject_device_id"`
	ExpectedEntityVersion  *uint64 `json:"expected_entity_version"`
	Role                   string  `json:"role"`
	InitialCredentialEpoch uint64  `json:"initial_credential_epoch"`
	State                  string  `json:"state"`
	ProofFailures          uint64  `json:"proof_failures"`
	ConsumedAttemptID      *string `json:"consumed_attempt_id"`
	CreatedAt              string  `json:"created_at"`
	ExpiresAt              string  `json:"expires_at"`
	TerminalAt             *string `json:"terminal_at"`
}

type PairingInviteCreated struct {
	Code   string              `json:"code"`
	Invite PairingInviteStatus `json:"invite"`
}

type PairingInviteList struct {
	Invites []PairingInviteStatus `json:"invites"`
}

type PairingInviteRevoked struct {
	Duplicate bool                `json:"duplicate"`
	Invite    PairingInviteStatus `json:"invite"`
}

type PairingAttemptStatus struct {
	AttemptID               string  `json:"attempt_id"`
	InviteID                string  `json:"invite_id"`
	RequestDigest           string  `json:"request_digest"`
	Mode                    string  `json:"mode"`
	JoinerDeviceID          string  `json:"joiner_device_id"`
	JoinerIdentityPublicKey string  `json:"joiner_identity_public_key"`
	DaemonVersion           string  `json:"daemon_version"`
	MaxApplyLevel           uint64  `json:"max_apply_level"`
	Role                    string  `json:"role"`
	ExpectedEntityVersion   *uint64 `json:"expected_entity_version"`
	InitialCredentialEpoch  uint64  `json:"initial_credential_epoch"`
	EpochPublicKey          string  `json:"epoch_public_key"`
	EpochKeyDigest          string  `json:"epoch_key_digest"`
	State                   string  `json:"state"`
	RemoteConfirmed         bool    `json:"remote_confirmed"`
	LocalConfirmed          bool    `json:"local_confirmed"`
	SAS                     string  `json:"sas"`
}

func pairingInviteStatus(
	record store.PairingInviteRecord,
) PairingInviteStatus {
	var subject, attempt, terminal *string
	if record.SubjectDeviceID != nil {
		value := string(*record.SubjectDeviceID)
		subject = &value
	}
	if record.ConsumedAttemptID.Valid() {
		value := string(record.ConsumedAttemptID)
		attempt = &value
	}
	if record.TerminalAt != "" {
		value := string(record.TerminalAt)
		terminal = &value
	}
	return PairingInviteStatus{
		InviteID: string(record.InviteID), Mode: string(record.Mode),
		SubjectDeviceID:        subject,
		ExpectedEntityVersion:  cloneUint64(record.ExpectedEntityVersion),
		Role:                   string(record.Role),
		InitialCredentialEpoch: record.InitialCredentialEpoch,
		State:                  string(record.State),
		ProofFailures:          record.ProofFailures,
		ConsumedAttemptID:      attempt,
		CreatedAt:              string(record.CreatedAt),
		ExpiresAt:              string(record.ExpiresAt),
		TerminalAt:             terminal,
	}
}

func pairingAttemptStatus(
	details pairingAttemptDetails,
) PairingAttemptStatus {
	attempt := details.Attempt
	core := details.Core
	return PairingAttemptStatus{
		AttemptID: string(attempt.AttemptID),
		InviteID:  string(attempt.InviteID),
		RequestDigest: codec.EncodeBase64URL(
			attempt.RequestDigest[:],
		),
		Mode:           string(details.Invite.Mode),
		JoinerDeviceID: string(core.JoinerDeviceID),
		JoinerIdentityPublicKey: codec.EncodeBase64URL(
			core.JoinerIdentityPublicKey[:],
		),
		DaemonVersion:          core.DaemonVersion,
		MaxApplyLevel:          core.MaxApplyLevel,
		Role:                   string(details.Invite.Role),
		ExpectedEntityVersion:  cloneUint64(details.Invite.ExpectedEntityVersion),
		InitialCredentialEpoch: core.InitialEpochBinding.Epoch,
		EpochPublicKey: codec.EncodeBase64URL(
			core.InitialEpochBinding.EpochPublicKey[:],
		),
		EpochKeyDigest: codec.EncodeBase64URL(
			core.InitialEpochBinding.KeyDigest[:],
		),
		State:           string(attempt.State),
		RemoteConfirmed: attempt.RemoteConfirmed,
		LocalConfirmed:  attempt.LocalConfirmed,
		SAS:             details.SAS,
	}
}

func (value PairingInviteStatus) validate() error {
	inviteID := domain.UUIDv7(value.InviteID)
	mode := pairing.Mode(value.Mode)
	role := device.Role(value.Role)
	state := store.PairingInviteState(value.State)
	if !inviteID.Valid() ||
		!mode.Valid() ||
		!role.Valid() ||
		value.InitialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(value.InitialCredentialEpoch) ||
		value.ProofFailures > store.MaxPairingProofFailures ||
		!domain.ValidUnsignedInteger(value.ProofFailures) ||
		!validPairingInviteState(state) ||
		!domain.WholeSecondTimestamp(value.CreatedAt).Valid() ||
		!domain.WholeSecondTimestamp(value.ExpiresAt).Valid() {
		return fmt.Errorf("ui: invalid pairing invite status")
	}
	if value.SubjectDeviceID != nil &&
		!domain.DeviceID(*value.SubjectDeviceID).Valid() {
		return fmt.Errorf("ui: invalid pairing invite subject")
	}
	if value.ExpectedEntityVersion != nil &&
		(*value.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*value.ExpectedEntityVersion)) {
		return fmt.Errorf("ui: invalid pairing invite version")
	}
	if value.ConsumedAttemptID != nil &&
		!domain.UUIDv7(*value.ConsumedAttemptID).Valid() {
		return fmt.Errorf("ui: invalid pairing attempt identifier")
	}
	if value.TerminalAt != nil &&
		!domain.Timestamp(*value.TerminalAt).Valid() {
		return fmt.Errorf("ui: invalid pairing terminal time")
	}
	switch mode {
	case pairing.ModeNew:
		if value.SubjectDeviceID != nil ||
			value.ExpectedEntityVersion != nil ||
			value.InitialCredentialEpoch != 1 {
			return fmt.Errorf("ui: invalid new-member invite")
		}
	case pairing.ModeRebootstrap:
		if value.SubjectDeviceID == nil ||
			value.ExpectedEntityVersion != nil {
			return fmt.Errorf("ui: invalid rebootstrap invite")
		}
	case pairing.ModeReadmission:
		if value.SubjectDeviceID == nil ||
			value.ExpectedEntityVersion == nil ||
			value.InitialCredentialEpoch != 1 {
			return fmt.Errorf("ui: invalid readmission invite")
		}
	}
	if (state == store.PairingInviteConsumed) !=
		(value.ConsumedAttemptID != nil) {
		return fmt.Errorf("ui: inconsistent consumed invite")
	}
	if isTerminalPairingInviteState(state) != (value.TerminalAt != nil) {
		return fmt.Errorf("ui: inconsistent terminal invite")
	}
	return nil
}

func (value PairingAttemptStatus) validate() error {
	if !domain.UUIDv7(value.AttemptID).Valid() ||
		!domain.UUIDv7(value.InviteID).Valid() ||
		!pairing.Mode(value.Mode).Valid() ||
		!domain.DeviceID(value.JoinerDeviceID).Valid() ||
		!device.Role(value.Role).Valid() ||
		!device.ValidDaemonVersion(value.DaemonVersion) ||
		value.MaxApplyLevel < 1 ||
		!domain.ValidUnsignedInteger(value.MaxApplyLevel) ||
		value.InitialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(value.InitialCredentialEpoch) {
		return fmt.Errorf("ui: invalid pairing attempt")
	}
	for _, encoded := range []struct {
		text string
		size int
	}{
		{value.RequestDigest, sha256.Size},
		{value.JoinerIdentityPublicKey, 32},
		{value.EpochPublicKey, 32},
		{value.EpochKeyDigest, sha256.Size},
	} {
		if _, err := codec.DecodeBase64URLExact(encoded.text, encoded.size); err != nil {
			return fmt.Errorf("ui: invalid pairing attempt encoding")
		}
	}
	if value.ExpectedEntityVersion != nil &&
		(*value.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*value.ExpectedEntityVersion)) {
		return fmt.Errorf("ui: invalid pairing attempt version")
	}
	switch pairing.Mode(value.Mode) {
	case pairing.ModeNew:
		if value.ExpectedEntityVersion != nil ||
			value.InitialCredentialEpoch != 1 {
			return fmt.Errorf("ui: invalid new-member pairing attempt")
		}
	case pairing.ModeRebootstrap:
		if value.ExpectedEntityVersion != nil {
			return fmt.Errorf("ui: invalid rebootstrap pairing attempt")
		}
	case pairing.ModeReadmission:
		if value.ExpectedEntityVersion == nil ||
			value.InitialCredentialEpoch != 1 {
			return fmt.Errorf("ui: invalid readmission pairing attempt")
		}
	}
	switch store.PairingAttemptState(value.State) {
	case store.PairingAttemptAwaitingSAS,
		store.PairingAttemptFinalizing,
		store.PairingAttemptCompleted,
		store.PairingAttemptDeclined,
		store.PairingAttemptExpired,
		store.PairingAttemptRevoked:
	default:
		return fmt.Errorf("ui: invalid pairing attempt state")
	}
	if !validSAS(value.SAS) {
		return fmt.Errorf("ui: invalid pairing SAS")
	}
	return nil
}

func validPairingInviteState(state store.PairingInviteState) bool {
	switch state {
	case store.PairingInvitePreparing,
		store.PairingInviteOutstanding,
		store.PairingInviteConsumed,
		store.PairingInviteRevoked,
		store.PairingInviteExpired,
		store.PairingInviteProofExhausted,
		store.PairingInviteAbandoned:
		return true
	default:
		return false
	}
}

func isTerminalPairingInviteState(state store.PairingInviteState) bool {
	return validPairingInviteState(state) &&
		state != store.PairingInvitePreparing &&
		state != store.PairingInviteOutstanding
}

func validSAS(value string) bool {
	parts := strings.Split(value, " ")
	if len(parts) != 5 {
		return false
	}
	for _, part := range parts {
		if len(part) != 4 {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}
