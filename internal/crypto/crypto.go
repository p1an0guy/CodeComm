// Package crypto provides CodeComm's narrow wrappers around the cryptographic
// primitives selected by the V1 protocol suite.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
)

const (
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	Ed25519SignatureSize  = ed25519.SignatureSize
	SHA256Size            = sha256.Size
)

var (
	ErrEntropy                  = errors.New("crypto: secure entropy unavailable")
	ErrInvalidEd25519PublicKey  = errors.New("crypto: invalid Ed25519 public key")
	ErrInvalidEd25519PrivateKey = errors.New("crypto: invalid Ed25519 private key")
	ErrInvalidEd25519Signature  = errors.New("crypto: invalid Ed25519 signature")
	ErrSignatureVerification    = errors.New("crypto: signature verification failed")
)

// SHA256Digest is one complete SHA-256 output.
type SHA256Digest [SHA256Size]byte

// GenerateEd25519KeyPair generates an Ed25519 keypair from the operating
// system's cryptographically secure random source. The returned keys do not
// share backing storage.
func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	return generateEd25519KeyPair(cryptorand.Reader)
}

func generateEd25519KeyPair(entropy io.Reader) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrEntropy, err)
	}

	// ed25519.GenerateKey may return a public-key slice backed by the private
	// key. Clone both so callers cannot mutate one through the other.
	return bytes.Clone(publicKey), bytes.Clone(privateKey), nil
}

// SignEd25519 signs signedBytes under one of codec's closed V1 signature
// labels. signedBytes must already be the canonical bytes required by the
// protected object's protocol definition.
func SignEd25519(
	privateKey []byte,
	label codec.SignatureLabel,
	signedBytes []byte,
) ([]byte, error) {
	key, err := checkedPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	signedInput, err := codec.BuildSignedInput(label, signedBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: build signed input: %w", err)
	}
	return ed25519.Sign(key, signedInput), nil
}

// VerifyEd25519 verifies signature over signedBytes under one of codec's
// closed V1 signature labels.
func VerifyEd25519(
	publicKey []byte,
	label codec.SignatureLabel,
	signedBytes []byte,
	signature []byte,
) error {
	if len(publicKey) != Ed25519PublicKeySize {
		return fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidEd25519PublicKey,
			len(publicKey),
			Ed25519PublicKeySize,
		)
	}
	if len(signature) != Ed25519SignatureSize {
		return fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidEd25519Signature,
			len(signature),
			Ed25519SignatureSize,
		)
	}
	signedInput, err := codec.BuildSignedInput(label, signedBytes)
	if err != nil {
		return fmt.Errorf("crypto: build signed input: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signedInput, signature) {
		return ErrSignatureVerification
	}
	return nil
}

// Ed25519PublicKeyFromPrivateKey validates a complete Ed25519 private key and
// returns a non-aliased copy of its public key.
func Ed25519PublicKeyFromPrivateKey(privateKey []byte) ([]byte, error) {
	key, err := checkedPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(key[ed25519.SeedSize:]), nil
}

// SumSHA256 returns the SHA-256 digest of data.
func SumSHA256(data []byte) SHA256Digest {
	return SHA256Digest(sha256.Sum256(data))
}

func checkedPrivateKey(privateKey []byte) (ed25519.PrivateKey, error) {
	if len(privateKey) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrInvalidEd25519PrivateKey,
			len(privateKey),
			Ed25519PrivateKeySize,
		)
	}

	key := bytes.Clone(privateKey)
	expected := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, expected) != 1 {
		return nil, fmt.Errorf(
			"%w: public-key suffix does not match seed",
			ErrInvalidEd25519PrivateKey,
		)
	}
	return ed25519.PrivateKey(key), nil
}
