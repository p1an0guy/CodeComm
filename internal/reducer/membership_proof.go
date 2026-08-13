package reducer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
)

const initialCredentialEpoch = 1

type initialEpochBinding struct {
	EpochPublicKey   [ed25519.PublicKeySize]byte
	KeyDigest        [sha256.Size]byte
	BindingSignature [ed25519.SignatureSize]byte
}

type credentialBindingPreimage struct {
	DeviceID       string `json:"device_id"`
	Epoch          uint64 `json:"epoch"`
	EpochPublicKey string `json:"epoch_public_key"`
	SessionID      string `json:"session_id"`
}

func decodeInitialEpochBinding(
	raw json.RawMessage,
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
	identityPublicKey []byte,
) (initialEpochBinding, bool) {
	object, code := decodePayload(
		raw,
		[]string{
			"binding_signature",
			"epoch",
			"epoch_public_key",
			"key_digest",
		},
		nil,
	)
	if code != "" {
		return initialEpochBinding{}, false
	}
	epoch, epochOK := decodeValue[uint64](object, "epoch")
	publicKeyText, publicKeyOK := decodeValue[string](
		object,
		"epoch_public_key",
	)
	digestText, digestOK := decodeValue[string](object, "key_digest")
	signatureText, signatureOK := decodeValue[string](
		object,
		"binding_signature",
	)
	if !epochOK || epoch != initialCredentialEpoch ||
		!publicKeyOK || !digestOK || !signatureOK {
		return initialEpochBinding{}, false
	}
	publicKey, err := codec.DecodeBase64URLExact(
		publicKeyText,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return initialEpochBinding{}, false
	}
	digest, err := codec.DecodeBase64URLExact(
		digestText,
		sha256.Size,
	)
	if err != nil {
		return initialEpochBinding{}, false
	}
	signature, err := codec.DecodeBase64URLExact(
		signatureText,
		ed25519.SignatureSize,
	)
	if err != nil {
		return initialEpochBinding{}, false
	}
	computedDigest := sha256.Sum256(publicKey)
	if !bytes.Equal(computedDigest[:], digest) {
		return initialEpochBinding{}, false
	}

	preimageJSON, err := json.Marshal(credentialBindingPreimage{
		DeviceID:       string(deviceID),
		Epoch:          epoch,
		EpochPublicKey: publicKeyText,
		SessionID:      string(sessionID),
	})
	if err != nil {
		return initialEpochBinding{}, false
	}
	preimage, err := codec.CanonicalizeSignedObject(preimageJSON)
	signedInput, signErr := codec.BuildSignedInput(
		codec.SignatureCredentialBinding,
		preimage,
	)
	if err != nil || signErr != nil ||
		len(identityPublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(identityPublicKey, signedInput, signature) {
		return initialEpochBinding{}, false
	}

	var result initialEpochBinding
	copy(result.EpochPublicKey[:], publicKey)
	copy(result.KeyDigest[:], digest)
	copy(result.BindingSignature[:], signature)
	return result, true
}
