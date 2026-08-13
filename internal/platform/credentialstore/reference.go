// Package credentialstore defines the fail-closed boundary to native OS
// credential protection.
package credentialstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ijonahch/codecomm/internal/domain"
)

// Kind identifies the lifecycle and namespace of one private key.
type Kind string

const (
	KindIdentity Kind = "identity"
	KindEpoch    Kind = "epoch"
)

var ErrInvalidReference = errors.New("credentialstore: invalid secret reference")

// Reference is an opaque, non-secret native-store key. Its fields are private
// so callers cannot create aliases between identity and per-session epochs.
type Reference struct {
	kind Kind
	key  string
}

// IdentityReference returns the one installation-wide identity-key reference.
func IdentityReference() Reference {
	return Reference{kind: KindIdentity, key: "identity/v1"}
}

// EpochReference returns a reference scoped to one session, device, and epoch.
func EpochReference(
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
	epoch uint64,
) (Reference, error) {
	if !sessionID.Valid() || !deviceID.Valid() ||
		epoch < 1 || !domain.ValidUnsignedInteger(epoch) {
		return Reference{}, fmt.Errorf(
			"%w: invalid session, device, or epoch",
			ErrInvalidReference,
		)
	}
	return Reference{
		kind: KindEpoch,
		key: strings.Join(
			[]string{
				"epoch",
				"v1",
				string(sessionID),
				string(deviceID),
				strconv.FormatUint(epoch, 10),
			},
			"/",
		),
	}, nil
}

// Kind reports the key lifecycle represented by this reference.
func (reference Reference) Kind() Kind {
	return reference.kind
}

// String returns the non-secret native-store key.
func (reference Reference) String() string {
	return reference.key
}

// Validate rejects zero, malformed, and noncanonical references.
func (reference Reference) Validate() error {
	switch reference.kind {
	case KindIdentity:
		if reference.key != IdentityReference().key {
			return fmt.Errorf("%w: malformed identity reference", ErrInvalidReference)
		}
	case KindEpoch:
		parts := strings.Split(reference.key, "/")
		if len(parts) != 5 || parts[0] != "epoch" || parts[1] != "v1" {
			return fmt.Errorf("%w: malformed epoch reference", ErrInvalidReference)
		}
		sessionID := domain.UUIDv7(parts[2])
		deviceID := domain.DeviceID(parts[3])
		epoch, err := strconv.ParseUint(parts[4], 10, 64)
		if err != nil {
			return fmt.Errorf("%w: malformed epoch: %v", ErrInvalidReference, err)
		}
		canonical, err := EpochReference(sessionID, deviceID, epoch)
		if err != nil || canonical != reference {
			return fmt.Errorf("%w: noncanonical epoch reference", ErrInvalidReference)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidReference, reference.kind)
	}
	return nil
}
