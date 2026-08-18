// Package credentialauthorization defines immutable content-credential epochs.
package credentialauthorization

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	ValiditySeconds    uint64 = 1_800
	OverlapSeconds     uint64 = 120
	RenewalLeadSeconds uint64 = 300
	MaxEndorsements           = 5
)

var (
	ErrInvalidSessionID          = errors.New("credential authorization: invalid session ID")
	ErrInvalidDeviceID           = errors.New("credential authorization: invalid device ID")
	ErrInvalidEpoch              = errors.New("credential authorization: invalid epoch")
	ErrKeyDigestMismatch         = errors.New("credential authorization: key digest mismatch")
	ErrInvalidRole               = errors.New("credential authorization: invalid role")
	ErrInvalidTimestamp          = errors.New("credential authorization: invalid timestamp")
	ErrNotBeforePrecedesIssuedAt = errors.New("credential authorization: not_before precedes issued_at")
	ErrInvalidValidity           = errors.New("credential authorization: invalid validity")
	ErrInvalidAuthorityVersion   = errors.New("credential authorization: invalid authority version")
	ErrInvalidEndorsementCount   = errors.New("credential authorization: invalid endorsement count")
	ErrInvalidEndorser           = errors.New("credential authorization: invalid endorser")
	ErrEndorsementsNotSorted     = errors.New("credential authorization: endorsements are not sorted and unique")
	ErrInvalidChainIndex         = errors.New("credential authorization: invalid authorization chain index")
	ErrInvalidTransition         = errors.New("credential authorization: invalid transition")
	ErrIdentityChanged           = errors.New("credential authorization: session or device changed")
	ErrEpochNotAdvanced          = errors.New("credential authorization: epoch did not advance by one")
	ErrIssuedAtBelowRenewalFloor = errors.New("credential authorization: issued_at is below renewal floor")
	ErrNotBeforeClampMismatch    = errors.New("credential authorization: not_before does not match clamp")
)

// Role is the historical display role committed with an authorization.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleEditor Role = "editor"
)

// Valid reports whether role belongs to the closed V1 membership role set.
func (role Role) Valid() bool {
	return role == RoleOwner || role == RoleEditor
}

// Key is the immutable projection primary key.
type Key struct {
	SessionID domain.UUIDv7
	DeviceID  domain.DeviceID
	Epoch     uint64
}

// ClockEndorsement is one authority member's credential-time signature.
type ClockEndorsement struct {
	DeviceID  domain.DeviceID
	Signature [ed25519.SignatureSize]byte
}

// Authorization is one immutable content-credential epoch.
type Authorization struct {
	SessionID                domain.UUIDv7
	DeviceID                 domain.DeviceID
	Epoch                    uint64
	EpochPublicKey           [ed25519.PublicKeySize]byte
	KeyDigest                [sha256.Size]byte
	Role                     Role
	IssuedAt                 domain.WholeSecondTimestamp
	NotBefore                domain.WholeSecondTimestamp
	ValiditySeconds          uint64
	AuthorityVoterSetVersion uint64
	ClockEndorsements        []ClockEndorsement
	BindingSignature         [ed25519.SignatureSize]byte
	AuthorizationChainIndex  uint64
}

// PrimaryKey returns the complete projection key.
func (authorization Authorization) PrimaryKey() Key {
	return Key{
		SessionID: authorization.SessionID,
		DeviceID:  authorization.DeviceID,
		Epoch:     authorization.Epoch,
	}
}

// Validate checks persisted-form invariants independent of committed state.
func (authorization Authorization) Validate() error {
	if !authorization.SessionID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, authorization.SessionID)
	}
	if !authorization.DeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidDeviceID, authorization.DeviceID)
	}
	if authorization.Epoch < 1 ||
		!domain.ValidUnsignedInteger(authorization.Epoch) {
		return fmt.Errorf("%w: %d", ErrInvalidEpoch, authorization.Epoch)
	}
	if sha256.Sum256(authorization.EpochPublicKey[:]) != authorization.KeyDigest {
		return ErrKeyDigestMismatch
	}
	if !authorization.Role.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, authorization.Role)
	}
	if !authorization.IssuedAt.Valid() || !authorization.NotBefore.Valid() {
		return ErrInvalidTimestamp
	}
	issuedAt, _ := authorization.IssuedAt.Time()
	notBefore, _ := authorization.NotBefore.Time()
	if notBefore.Before(issuedAt) {
		return ErrNotBeforePrecedesIssuedAt
	}
	if authorization.ValiditySeconds != ValiditySeconds {
		return fmt.Errorf(
			"%w: got %d, want %d",
			ErrInvalidValidity,
			authorization.ValiditySeconds,
			ValiditySeconds,
		)
	}
	if authorization.AuthorityVoterSetVersion < 1 ||
		!domain.ValidUnsignedInteger(authorization.AuthorityVoterSetVersion) {
		return fmt.Errorf(
			"%w: %d",
			ErrInvalidAuthorityVersion,
			authorization.AuthorityVoterSetVersion,
		)
	}
	if len(authorization.ClockEndorsements) < 1 ||
		len(authorization.ClockEndorsements) > MaxEndorsements {
		return fmt.Errorf(
			"%w: got %d",
			ErrInvalidEndorsementCount,
			len(authorization.ClockEndorsements),
		)
	}
	var previous domain.DeviceID
	for index, endorsement := range authorization.ClockEndorsements {
		if !endorsement.DeviceID.Valid() {
			return fmt.Errorf("%w: entry %d", ErrInvalidEndorser, index)
		}
		if index > 0 && previous >= endorsement.DeviceID {
			return fmt.Errorf("%w: entry %d", ErrEndorsementsNotSorted, index)
		}
		previous = endorsement.DeviceID
	}
	if authorization.AuthorizationChainIndex < 1 ||
		!domain.ValidUnsignedInteger(authorization.AuthorizationChainIndex) {
		return fmt.Errorf(
			"%w: %d",
			ErrInvalidChainIndex,
			authorization.AuthorizationChainIndex,
		)
	}
	return nil
}

// ActiveAt reports whether an otherwise-valid authorization is active at the
// exact supplied instant. Activation includes NotBefore and excludes expiry.
func (authorization Authorization) ActiveAt(at time.Time) bool {
	if at.IsZero() || authorization.Validate() != nil {
		return false
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		return false
	}
	expiresAt := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	return !at.Before(notBefore) && at.Before(expiresAt)
}

// ValidateTransition checks the deterministic first/successor time clamps.
func ValidateTransition(
	previous *Authorization,
	next Authorization,
) error {
	if err := next.Validate(); err != nil {
		return fmt.Errorf("%w: destination: %w", ErrInvalidTransition, err)
	}
	if previous == nil {
		if next.Epoch != 1 {
			return fmt.Errorf("%w: got %d, want 1", ErrEpochNotAdvanced, next.Epoch)
		}
		if next.NotBefore != next.IssuedAt {
			return ErrNotBeforeClampMismatch
		}
		return nil
	}
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("%w: source: %w", ErrInvalidTransition, err)
	}
	if next.SessionID != previous.SessionID || next.DeviceID != previous.DeviceID {
		return ErrIdentityChanged
	}
	if previous.Epoch == domain.MaxSafeInteger ||
		next.Epoch != previous.Epoch+1 {
		return fmt.Errorf(
			"%w: %d -> %d",
			ErrEpochNotAdvanced,
			previous.Epoch,
			next.Epoch,
		)
	}

	previousNotBefore, _ := previous.NotBefore.Time()
	issuedAt, _ := next.IssuedAt.Time()
	renewalFloor := previousNotBefore.Add(
		time.Duration(ValiditySeconds-RenewalLeadSeconds) * time.Second,
	)
	if issuedAt.Before(renewalFloor) {
		return ErrIssuedAtBelowRenewalFloor
	}
	overlapFloor := previousNotBefore.Add(
		time.Duration(ValiditySeconds-OverlapSeconds) * time.Second,
	)
	expectedNotBefore := issuedAt
	if overlapFloor.After(expectedNotBefore) {
		expectedNotBefore = overlapFloor
	}
	notBefore, _ := next.NotBefore.Time()
	if !notBefore.Equal(expectedNotBefore) {
		return ErrNotBeforeClampMismatch
	}
	return nil
}

// Clone returns an authorization that does not alias endorsement storage.
func (authorization Authorization) Clone() Authorization {
	result := authorization
	result.ClockEndorsements = append(
		[]ClockEndorsement(nil),
		authorization.ClockEndorsements...,
	)
	return result
}
