package codec

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	// ErrInvalidBase64URL reports text outside canonical unpadded RFC 4648
	// base64url, including ignored whitespace and nonzero trailing bits.
	ErrInvalidBase64URL = errors.New("codec: invalid unpadded base64url")
	// ErrDecodedLength reports a valid value whose decoded size is wrong for
	// its closed protocol field.
	ErrDecodedLength = errors.New("codec: unexpected decoded length")
)

// EncodeBase64URL returns canonical unpadded RFC 4648 base64url text.
func EncodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// DecodeBase64URL decodes canonical unpadded RFC 4648 base64url. It rejects
// padding, whitespace, the standard alphabet, and nonzero trailing bits.
func DecodeBase64URL(text string) ([]byte, error) {
	if !validBase64URLText(text) {
		return nil, fmt.Errorf("%w: encoded length %d", ErrInvalidBase64URL, len(text))
	}

	value, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || EncodeBase64URL(value) != text {
		return nil, fmt.Errorf("%w: encoded length %d", ErrInvalidBase64URL, len(text))
	}
	return value, nil
}

// DecodeBase64URLExact decodes text and requires exactly size bytes.
func DecodeBase64URLExact(text string, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("%w: negative expected size %d", ErrDecodedLength, size)
	}
	if !validBase64URLText(text) {
		return nil, fmt.Errorf("%w: encoded length %d", ErrInvalidBase64URL, len(text))
	}
	if len(text) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, fmt.Errorf(
			"%w: encoded length %d cannot represent %d bytes",
			ErrDecodedLength,
			len(text),
			size,
		)
	}
	value, err := DecodeBase64URL(text)
	if err != nil {
		return nil, err
	}
	if len(value) != size {
		return nil, fmt.Errorf(
			"%w: got %d bytes, want %d",
			ErrDecodedLength,
			len(value),
			size,
		)
	}
	return value, nil
}

func validBase64URLText(text string) bool {
	if len(text)%4 == 1 {
		return false
	}
	for index := range len(text) {
		char := text[index]
		if char >= 'A' && char <= 'Z' ||
			char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' ||
			char == '-' ||
			char == '_' {
			continue
		}
		return false
	}
	return true
}
