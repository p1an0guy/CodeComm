// Package credential implements content-credential lifecycle primitives.
package credential

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

var (
	ErrInvalidBinding   = errors.New("credential: invalid epoch binding")
	ErrBindingIdentity  = errors.New("credential: binding identity mismatch")
	ErrBindingKeyDigest = errors.New("credential: binding key digest mismatch")
	ErrBindingSignature = errors.New("credential: binding signature invalid")
)

// Binding proves that a device identity selected one content key for an epoch.
type Binding struct {
	SessionID      domain.UUIDv7
	DeviceID       domain.DeviceID
	Epoch          uint64
	EpochPublicKey [ed25519.PublicKeySize]byte
	KeyDigest      [sha256.Size]byte
	Signature      [ed25519.SignatureSize]byte
}

type bindingWire struct {
	DeviceID       string `json:"device_id"`
	Epoch          uint64 `json:"epoch"`
	EpochPublicKey string `json:"epoch_public_key"`
	SessionID      string `json:"session_id"`
}

// SignBinding creates the exact identity-signed binding for one epoch key.
func SignBinding(
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
	epoch uint64,
	epochPublicKey []byte,
	identityPrivateKey []byte,
) (Binding, error) {
	if !sessionID.Valid() || !deviceID.Valid() ||
		epoch < 1 || !domain.ValidUnsignedInteger(epoch) ||
		len(epochPublicKey) != ed25519.PublicKeySize {
		return Binding{}, ErrInvalidBinding
	}
	identityPublicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivateKey)
	if err != nil {
		return Binding{}, err
	}
	derivedID, err := device.DeriveID(identityPublicKey)
	if err != nil || derivedID != deviceID {
		return Binding{}, ErrBindingIdentity
	}

	binding := Binding{SessionID: sessionID, DeviceID: deviceID, Epoch: epoch}
	copy(binding.EpochPublicKey[:], epochPublicKey)
	binding.KeyDigest = sha256.Sum256(binding.EpochPublicKey[:])
	preimage, err := binding.CanonicalPreimage()
	if err != nil {
		return Binding{}, err
	}
	signature, err := codecommcrypto.SignEd25519(
		identityPrivateKey,
		codec.SignatureCredentialBinding,
		preimage,
	)
	if err != nil {
		return Binding{}, err
	}
	copy(binding.Signature[:], signature)
	return binding, nil
}

// Validate verifies all binding fields against the enrolled identity key.
func (binding Binding) Validate(identityPublicKey []byte) error {
	if !binding.SessionID.Valid() || !binding.DeviceID.Valid() ||
		binding.Epoch < 1 || !domain.ValidUnsignedInteger(binding.Epoch) ||
		len(identityPublicKey) != ed25519.PublicKeySize {
		return ErrInvalidBinding
	}
	derivedID, err := device.DeriveID(identityPublicKey)
	if err != nil || derivedID != binding.DeviceID {
		return ErrBindingIdentity
	}
	if sha256.Sum256(binding.EpochPublicKey[:]) != binding.KeyDigest {
		return ErrBindingKeyDigest
	}
	preimage, err := binding.CanonicalPreimage()
	if err != nil {
		return err
	}
	if err := codecommcrypto.VerifyEd25519(
		identityPublicKey,
		codec.SignatureCredentialBinding,
		preimage,
		binding.Signature[:],
	); err != nil {
		return fmt.Errorf("%w: %v", ErrBindingSignature, err)
	}
	return nil
}

// CanonicalPreimage returns the exact JCS object covered by the identity signature.
func (binding Binding) CanonicalPreimage() ([]byte, error) {
	if !binding.SessionID.Valid() || !binding.DeviceID.Valid() ||
		binding.Epoch < 1 || !domain.ValidUnsignedInteger(binding.Epoch) {
		return nil, ErrInvalidBinding
	}
	raw, err := json.Marshal(bindingWire{
		DeviceID:       string(binding.DeviceID),
		Epoch:          binding.Epoch,
		EpochPublicKey: codec.EncodeBase64URL(binding.EpochPublicKey[:]),
		SessionID:      string(binding.SessionID),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidBinding, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidBinding, err)
	}
	return bytes.Clone(canonical), nil
}
