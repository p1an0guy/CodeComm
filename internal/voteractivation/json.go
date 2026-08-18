package voteractivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

func marshalCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return codec.CanonicalizeSignedObject(encoded)
}

func decodeClosedCanonical(
	encoded []byte,
	fields map[string]struct{},
	destination any,
) error {
	if destination == nil {
		return ErrInvalidFieldSet
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrNoncanonicalJSON
	}
	var members map[string]json.RawMessage
	if err := decodeStrict(encoded, &members); err != nil ||
		len(members) != len(fields) {
		return ErrInvalidFieldSet
	}
	for field, raw := range members {
		if _, exists := fields[field]; !exists ||
			bytes.Equal(raw, []byte("null")) {
			return ErrInvalidFieldSet
		}
	}
	for field := range fields {
		if _, exists := members[field]; !exists {
			return ErrInvalidFieldSet
		}
	}
	if err := decodeStrict(encoded, destination); err != nil {
		return ErrInvalidFieldSet
	}
	return nil
}

func decodeStrict(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func fieldSet(fields ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result
}

func withField(fields map[string]struct{}, added string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields)+1)
	for field := range fields {
		result[field] = struct{}{}
	}
	result[added] = struct{}{}
	return result
}

func cloneDeviceIDs(ids []domain.DeviceID) []domain.DeviceID {
	return append([]domain.DeviceID(nil), ids...)
}

func deviceIDStrings(ids []domain.DeviceID) []string {
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = string(id)
	}
	return result
}

func parseDeviceIDs(ids []string) []domain.DeviceID {
	result := make([]domain.DeviceID, len(ids))
	for index, id := range ids {
		result[index] = domain.DeviceID(id)
	}
	return result
}

func requireSigner(privateKey []byte, expected domain.DeviceID) error {
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("%w: invalid private key", ErrSignerMismatch)
	}
	return requirePublicSigner(publicKey, expected)
}

func requirePublicSigner(publicKey []byte, expected domain.DeviceID) error {
	if len(publicKey) != ed25519.PublicKeySize || !expected.Valid() {
		return ErrSignerMismatch
	}
	derived, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil || domain.DeviceID(derived) != expected {
		return ErrSignerMismatch
	}
	return nil
}
