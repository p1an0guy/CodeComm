package codec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrInvalidEd25519PublicKey = errors.New("codec: invalid Ed25519 public key")

// DeriveDeviceID returns cc1 followed by the full lowercase SHA-256 digest of
// one raw Ed25519 public key.
func DeriveDeviceID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidEd25519PublicKey,
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}
	digest := sha256.Sum256(publicKey)
	return "cc1" + hex.EncodeToString(digest[:]), nil
}
