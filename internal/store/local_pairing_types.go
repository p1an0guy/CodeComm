package store

import (
	"bytes"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
)

const (
	MaxOutstandingPairingInvites = 8
	MaxPairingProofFailures      = 3
)

var (
	ErrInvalidPairingState      = errors.New("store: invalid pairing request")
	ErrPairingLineageMismatch   = errors.New("store: pairing lineage mismatch")
	ErrPairingGenesisMismatch   = errors.New("store: pairing genesis mismatch")
	ErrPairingInviteLimit       = errors.New("store: pairing invite limit reached")
	ErrPairingInviteNotFound    = errors.New("store: pairing invite not found")
	ErrPairingInviteUnavailable = errors.New("store: pairing invite unavailable")
	ErrPairingInviteExpired     = errors.New("store: pairing invite expired")
	ErrPairingConflict          = errors.New("store: pairing idempotency conflict")
	ErrPairingAttemptNotFound   = errors.New("store: pairing attempt not found")
	ErrPairingStateIntegrity    = errors.New("store: pairing state integrity failure")
	ErrPairingDeletionNotFound  = errors.New("store: pairing secret deletion not found")
	ErrPairingDeletionExhausted = errors.New("store: pairing secret deletion failure counter exhausted")
)

// PairingInviteState is the closed issuer-local invite lifecycle.
type PairingInviteState string

const (
	PairingInvitePreparing      PairingInviteState = "preparing"
	PairingInviteOutstanding    PairingInviteState = "outstanding"
	PairingInviteConsumed       PairingInviteState = "consumed"
	PairingInviteRevoked        PairingInviteState = "revoked"
	PairingInviteExpired        PairingInviteState = "expired"
	PairingInviteProofExhausted PairingInviteState = "proof_exhausted"
	PairingInviteAbandoned      PairingInviteState = "abandoned"
)

func (state PairingInviteState) valid() bool {
	switch state {
	case PairingInvitePreparing,
		PairingInviteOutstanding,
		PairingInviteConsumed,
		PairingInviteRevoked,
		PairingInviteExpired,
		PairingInviteProofExhausted,
		PairingInviteAbandoned:
		return true
	default:
		return false
	}
}

func (state PairingInviteState) terminal() bool {
	return state.valid() && state != PairingInvitePreparing && state != PairingInviteOutstanding
}

// PairingInviteRecord contains no invite secret or complete invite code.
type PairingInviteRecord struct {
	InviteID               domain.UUIDv7
	SessionID              domain.UUIDv7
	WorkspaceID            domain.UUIDv4
	RecoveryGeneration     uint64
	IssuerDeviceID         domain.DeviceID
	InviteDigest           Digest
	Mode                   pairing.Mode
	SubjectDeviceID        *domain.DeviceID
	ExpectedEntityVersion  *uint64
	Role                   device.Role
	InitialCredentialEpoch uint64
	State                  PairingInviteState
	ProofFailures          uint64
	ConsumedAttemptID      domain.UUIDv7
	CreatedAt              domain.WholeSecondTimestamp
	ExpiresAt              domain.WholeSecondTimestamp
	TerminalAt             domain.Timestamp
}

// PairingAttemptState is the closed local proof/SAS lifecycle.
type PairingAttemptState string

const (
	PairingAttemptProofRejected PairingAttemptState = "proof_rejected"
	PairingAttemptAwaitingSAS   PairingAttemptState = "awaiting_sas"
	PairingAttemptConfirmed     PairingAttemptState = "confirmed"
	PairingAttemptDeclined      PairingAttemptState = "declined"
	PairingAttemptExpired       PairingAttemptState = "expired"
	PairingAttemptRevoked       PairingAttemptState = "revoked"
)

func (state PairingAttemptState) valid() bool {
	switch state {
	case PairingAttemptProofRejected,
		PairingAttemptAwaitingSAS,
		PairingAttemptConfirmed,
		PairingAttemptDeclined,
		PairingAttemptExpired,
		PairingAttemptRevoked:
		return true
	default:
		return false
	}
}

// PairingConfirmationParty identifies one side of the two-sided SAS check.
type PairingConfirmationParty string

const (
	PairingConfirmationLocal  PairingConfirmationParty = "local"
	PairingConfirmationRemote PairingConfirmationParty = "remote"
)

func (party PairingConfirmationParty) valid() bool {
	return party == PairingConfirmationLocal || party == PairingConfirmationRemote
}

// PairingAttemptRecord is one bounded proof observation or accepted SAS attempt.
type PairingAttemptRecord struct {
	AttemptID         domain.UUIDv7
	InviteID          domain.UUIDv7
	RequestDigest     Digest
	RequestCore       []byte
	TranscriptHash    Digest
	JoinerDeviceID    domain.DeviceID
	State             PairingAttemptState
	LocalConfirmed    bool
	RemoteConfirmed   bool
	LocalConfirmedAt  domain.Timestamp
	RemoteConfirmedAt domain.Timestamp
	DeclinedBy        PairingConfirmationParty
	CreatedAt         domain.Timestamp
	TerminalAt        domain.Timestamp
}

// PairingProofFailureInput is a structurally valid request whose HMAC failed.
type PairingProofFailureInput struct {
	InviteID       domain.UUIDv7
	InviteDigest   Digest
	RequestDigest  Digest
	RequestCore    pairing.CanonicalRequestCore
	TranscriptHash Digest
	ObservedAt     domain.Timestamp
}

// PairingConfirmationInput records one side of the exact SAS attempt.
type PairingConfirmationInput struct {
	AttemptID domain.UUIDv7
	Party     PairingConfirmationParty
	Confirmed bool
	DecidedAt domain.Timestamp
}

// PairingSecretDeletion is one idempotent native-store cleanup item.
type PairingSecretDeletion struct {
	InviteID      domain.UUIDv7
	SessionID     domain.UUIDv7
	Reason        string
	QueuedAt      domain.Timestamp
	FailureCount  uint64
	LastFailureAt domain.Timestamp
	LastErrorCode string
}

func (record PairingInviteRecord) validate() error {
	if !record.InviteID.Valid() || !record.SessionID.Valid() || !record.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		!record.IssuerDeviceID.Valid() || !record.Mode.Valid() || !record.Role.Valid() ||
		record.InitialCredentialEpoch < 1 ||
		!domain.ValidUnsignedInteger(record.InitialCredentialEpoch) ||
		!record.State.valid() || record.ProofFailures > MaxPairingProofFailures ||
		!record.CreatedAt.Valid() || !record.ExpiresAt.Valid() {
		return ErrPairingStateIntegrity
	}
	createdAt, _ := record.CreatedAt.Time()
	expiresAt, _ := record.ExpiresAt.Time()
	if expiresAt.Sub(createdAt) != pairing.InviteTTL {
		return ErrPairingStateIntegrity
	}
	switch record.Mode {
	case pairing.ModeNew:
		if record.SubjectDeviceID != nil || record.ExpectedEntityVersion != nil ||
			record.InitialCredentialEpoch != 1 {
			return ErrPairingStateIntegrity
		}
	case pairing.ModeRebootstrap:
		if record.SubjectDeviceID == nil || !record.SubjectDeviceID.Valid() ||
			record.ExpectedEntityVersion != nil {
			return ErrPairingStateIntegrity
		}
	case pairing.ModeReadmission:
		if record.SubjectDeviceID == nil || !record.SubjectDeviceID.Valid() ||
			record.ExpectedEntityVersion == nil || *record.ExpectedEntityVersion < 1 ||
			!domain.ValidUnsignedInteger(*record.ExpectedEntityVersion) ||
			record.InitialCredentialEpoch != 1 {
			return ErrPairingStateIntegrity
		}
	default:
		return ErrPairingStateIntegrity
	}
	if record.State.terminal() != (record.TerminalAt != "") ||
		record.State == PairingInviteConsumed != record.ConsumedAttemptID.Valid() ||
		record.State == PairingInviteProofExhausted != (record.ProofFailures == MaxPairingProofFailures) {
		return ErrPairingStateIntegrity
	}
	if record.TerminalAt != "" && !record.TerminalAt.Valid() {
		return ErrPairingStateIntegrity
	}
	return nil
}

func (record PairingAttemptRecord) validate(sessionID domain.UUIDv7) error {
	if !record.AttemptID.Valid() || !record.InviteID.Valid() || !record.JoinerDeviceID.Valid() ||
		!record.State.valid() || !record.CreatedAt.Valid() || len(record.RequestCore) == 0 {
		return ErrPairingStateIntegrity
	}
	core, err := pairing.ParseRequestCore(record.RequestCore, sessionID)
	if err != nil || core.Value().AttemptID != record.AttemptID ||
		core.Value().JoinerDeviceID != record.JoinerDeviceID {
		return ErrPairingStateIntegrity
	}
	terminal := record.State != PairingAttemptAwaitingSAS
	if terminal != (record.TerminalAt != "") || record.TerminalAt != "" && !record.TerminalAt.Valid() {
		return ErrPairingStateIntegrity
	}
	if record.LocalConfirmed != (record.LocalConfirmedAt != "") ||
		record.RemoteConfirmed != (record.RemoteConfirmedAt != "") ||
		record.LocalConfirmedAt != "" && !record.LocalConfirmedAt.Valid() ||
		record.RemoteConfirmedAt != "" && !record.RemoteConfirmedAt.Valid() {
		return ErrPairingStateIntegrity
	}
	switch record.State {
	case PairingAttemptProofRejected:
		if record.LocalConfirmed || record.RemoteConfirmed || record.DeclinedBy != "" {
			return ErrPairingStateIntegrity
		}
	case PairingAttemptAwaitingSAS:
		if record.LocalConfirmed && record.RemoteConfirmed || record.DeclinedBy != "" {
			return ErrPairingStateIntegrity
		}
	case PairingAttemptConfirmed:
		if !record.LocalConfirmed || !record.RemoteConfirmed || record.DeclinedBy != "" {
			return ErrPairingStateIntegrity
		}
	case PairingAttemptDeclined:
		if !record.DeclinedBy.valid() {
			return ErrPairingStateIntegrity
		}
	case PairingAttemptExpired, PairingAttemptRevoked:
		if record.DeclinedBy != "" {
			return ErrPairingStateIntegrity
		}
	}
	return nil
}

func samePairingInvite(left, right PairingInviteRecord) bool {
	return left.InviteID == right.InviteID && left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.RecoveryGeneration == right.RecoveryGeneration &&
		left.IssuerDeviceID == right.IssuerDeviceID && left.InviteDigest == right.InviteDigest &&
		left.Mode == right.Mode && equalDeviceIDPointer(left.SubjectDeviceID, right.SubjectDeviceID) &&
		equalUint64Pointer(left.ExpectedEntityVersion, right.ExpectedEntityVersion) &&
		left.Role == right.Role && left.InitialCredentialEpoch == right.InitialCredentialEpoch &&
		left.CreatedAt == right.CreatedAt && left.ExpiresAt == right.ExpiresAt
}

func samePairingAttemptInput(
	record PairingAttemptRecord,
	inviteID domain.UUIDv7,
	requestDigest Digest,
	requestCore []byte,
	transcriptHash Digest,
	joinerDeviceID domain.DeviceID,
) bool {
	return record.InviteID == inviteID && record.RequestDigest == requestDigest &&
		bytes.Equal(record.RequestCore, requestCore) && record.TranscriptHash == transcriptHash &&
		record.JoinerDeviceID == joinerDeviceID
}

func equalDeviceIDPointer(left, right *domain.DeviceID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalUint64Pointer(left, right *uint64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func timestampBefore(left, right domain.Timestamp) (bool, error) {
	leftTime, err := left.Time()
	if err != nil {
		return false, err
	}
	rightTime, err := right.Time()
	if err != nil {
		return false, err
	}
	return leftTime.Before(rightTime), nil
}
