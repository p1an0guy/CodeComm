// Package domain defines CodeComm's immutable domain values and state machines.
package domain

import "errors"

const (
	uuidTextLength = 36
	deviceIDLength = 67
)

var (
	// ErrInvalidUUIDv7 reports a noncanonical or non-v7 UUID.
	ErrInvalidUUIDv7 = errors.New("domain: invalid UUIDv7")
	// ErrInvalidUUIDv4 reports a noncanonical or non-v4 UUID.
	ErrInvalidUUIDv4 = errors.New("domain: invalid UUIDv4")
	// ErrInvalidDeviceID reports a malformed CodeComm device identifier.
	ErrInvalidDeviceID = errors.New("domain: invalid device ID")
)

// UUIDv7 is an RFC 9562 UUIDv7 in lowercase canonical text form.
type UUIDv7 string

// ParseUUIDv7 validates and returns an RFC 9562 UUIDv7.
func ParseUUIDv7(text string) (UUIDv7, error) {
	id := UUIDv7(text)
	if !id.Valid() {
		return "", ErrInvalidUUIDv7
	}
	return id, nil
}

// Valid reports whether id is an RFC 9562 UUIDv7 in lowercase canonical text
// form.
func (id UUIDv7) Valid() bool {
	return validCanonicalUUID(string(id), '7')
}

// UUIDv4 is an RFC 9562 UUIDv4 in lowercase canonical text form.
type UUIDv4 string

// ParseUUIDv4 validates and returns an RFC 9562 UUIDv4.
func ParseUUIDv4(text string) (UUIDv4, error) {
	id := UUIDv4(text)
	if !id.Valid() {
		return "", ErrInvalidUUIDv4
	}
	return id, nil
}

// Valid reports whether id is an RFC 9562 UUIDv4 in lowercase canonical text
// form.
func (id UUIDv4) Valid() bool {
	return validCanonicalUUID(string(id), '4')
}

// DeviceID is "cc1" followed by a full lowercase hexadecimal SHA-256 digest.
type DeviceID string

// ParseDeviceID validates and returns a CodeComm device identifier.
func ParseDeviceID(text string) (DeviceID, error) {
	id := DeviceID(text)
	if !id.Valid() {
		return "", ErrInvalidDeviceID
	}
	return id, nil
}

// Valid reports whether id is exactly "cc1" followed by 64 lowercase
// hexadecimal characters.
func (id DeviceID) Valid() bool {
	text := string(id)
	if len(text) != deviceIDLength || text[:3] != "cc1" {
		return false
	}
	for i := 3; i < len(text); i++ {
		if !isLowerHex(text[i]) {
			return false
		}
	}
	return true
}

func validCanonicalUUID(text string, version byte) bool {
	if len(text) != uuidTextLength {
		return false
	}
	for i := 0; i < len(text); i++ {
		switch i {
		case 8, 13, 18, 23:
			if text[i] != '-' {
				return false
			}
		default:
			if !isLowerHex(text[i]) {
				return false
			}
		}
	}

	// RFC 9562 encodes the version in octet 6 and the variant's two most
	// significant bits as 10 in octet 8.
	return text[14] == version && isRFC9562Variant(text[19])
}

func isLowerHex(char byte) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f'
}

func isRFC9562Variant(char byte) bool {
	return char == '8' || char == '9' || char == 'a' || char == 'b'
}
