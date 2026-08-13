// Package device defines the device membership entity and its pure lifecycle.
package device

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxDaemonVersionBytes = 64

// Role is a device's current committed authorization role.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleEditor Role = "editor"
)

var roles = [...]Role{RoleOwner, RoleEditor}

// Valid reports whether role is a closed V1 device role.
func (role Role) Valid() bool {
	return role == RoleOwner || role == RoleEditor
}

// Roles returns all V1 device roles in stable order.
func Roles() []Role {
	result := make([]Role, len(roles))
	copy(result, roles[:])
	return result
}

// Device is the committed membership projection for one enrolled identity.
// Cross-row membership, authority, actor, and CAS checks belong in reducers.
type Device struct {
	ID                domain.DeviceID
	Role              Role
	IdentityPublicKey ed25519.PublicKey
	DaemonVersion     string
	MaxApplyLevel     uint64
	Status            Status
	EntityVersion     uint64
}

var (
	ErrInvalidID                = errors.New("device: invalid ID")
	ErrInvalidRole              = errors.New("device: invalid role")
	ErrInvalidIdentityPublicKey = errors.New("device: invalid identity public key")
	ErrDeviceIDMismatch         = errors.New("device: device ID does not match identity public key")
	ErrInvalidDaemonVersion     = errors.New("device: invalid daemon version")
	ErrInvalidMaxApplyLevel     = errors.New("device: invalid max apply level")
	ErrInvalidEntityVersion     = errors.New("device: invalid entity version")
)

// DeriveID returns the identity commitment for a raw Ed25519 public key.
func DeriveID(publicKey ed25519.PublicKey) (domain.DeviceID, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidIdentityPublicKey,
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}
	digest := sha256.Sum256(publicKey)
	return domain.DeviceID("cc1" + hex.EncodeToString(digest[:])), nil
}

// Validate verifies the device's local persisted invariants.
func (device Device) Validate() error {
	if !device.ID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, device.ID)
	}
	derivedID, err := DeriveID(device.IdentityPublicKey)
	if err != nil {
		return err
	}
	if device.ID != derivedID {
		return fmt.Errorf("%w: got %q", ErrDeviceIDMismatch, device.ID)
	}
	if !device.Role.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, device.Role)
	}
	if !validDaemonVersion(device.DaemonVersion) {
		return fmt.Errorf(
			"%w: must be ASCII SemVer no longer than %d bytes",
			ErrInvalidDaemonVersion,
			MaxDaemonVersionBytes,
		)
	}
	if device.MaxApplyLevel < 1 || device.MaxApplyLevel > domain.MaxApplyLevel {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidMaxApplyLevel,
			domain.MaxApplyLevel,
		)
	}
	if !device.Status.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, device.Status)
	}
	if device.EntityVersion < 1 || !domain.ValidUnsignedInteger(device.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	return nil
}

func validDaemonVersion(version string) bool {
	if len(version) == 0 || len(version) > MaxDaemonVersionBytes {
		return false
	}

	coreAndPrerelease := version
	if before, build, found := strings.Cut(version, "+"); found {
		if !validIdentifierList(build, false) {
			return false
		}
		coreAndPrerelease = before
	}

	core := coreAndPrerelease
	if before, prerelease, found := strings.Cut(coreAndPrerelease, "-"); found {
		if !validIdentifierList(prerelease, true) {
			return false
		}
		core = before
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

// ValidDaemonVersion reports whether version is canonical ASCII SemVer.
func ValidDaemonVersion(version string) bool {
	return validDaemonVersion(version)
}

func validIdentifierList(list string, rejectNumericLeadingZero bool) bool {
	if list == "" {
		return false
	}
	for _, identifier := range strings.Split(list, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for index := 0; index < len(identifier); index++ {
			char := identifier[index]
			if char < '0' || char > '9' {
				numeric = false
			}
			if !isSemVerIdentifierByte(char) {
				return false
			}
		}
		if rejectNumericLeadingZero && numeric &&
			len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func validNumericIdentifier(identifier string) bool {
	if identifier == "" ||
		len(identifier) > 1 && identifier[0] == '0' {
		return false
	}
	for index := 0; index < len(identifier); index++ {
		if identifier[index] < '0' || identifier[index] > '9' {
			return false
		}
	}
	return true
}

func isSemVerIdentifierByte(char byte) bool {
	return char >= '0' && char <= '9' ||
		char >= 'A' && char <= 'Z' ||
		char >= 'a' && char <= 'z' ||
		char == '-'
}
