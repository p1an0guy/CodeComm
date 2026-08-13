package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

var ErrInvalidEntityID = errors.New("event: invalid entity ID")

// EntityID is the string-or-null entity identity carried by every envelope.
// The zero value is the protocol null value.
type EntityID struct {
	value   string
	present bool
}

// StringEntityID constructs a present entity ID. Syntax is validated against
// the selected kind before emission or reduction.
func StringEntityID(value string) EntityID {
	return EntityID{value: value, present: true}
}

// NullEntityID constructs the protocol null entity ID.
func NullEntityID() EntityID {
	return EntityID{}
}

// Value returns the string value and whether the ID is non-null.
func (id EntityID) Value() (string, bool) {
	return id.value, id.present
}

// IsNull reports whether the protocol value is null.
func (id EntityID) IsNull() bool {
	return !id.present
}

// MarshalJSON encodes the entity identity as a JSON string or null.
func (id EntityID) MarshalJSON() ([]byte, error) {
	if !id.present {
		return []byte("null"), nil
	}
	return json.Marshal(id.value)
}

// UnmarshalJSON accepts only a JSON string or null. Kind-specific syntax is
// validated separately.
func (id *EntityID) UnmarshalJSON(input []byte) error {
	if id == nil {
		return ErrInvalidEntityID
	}
	if bytes.Equal(input, []byte("null")) {
		*id = NullEntityID()
		return nil
	}
	var value string
	if err := json.Unmarshal(input, &value); err != nil {
		return fmt.Errorf("%w: must be a string or null", ErrInvalidEntityID)
	}
	*id = StringEntityID(value)
	return nil
}

func (id EntityID) validGeneralForm() bool {
	if !id.present {
		return id.value == ""
	}
	return id.value != "" && len(id.value) <= domain.MaxRepositoryPathBytes
}

func (id EntityID) validFor(entityType EntityIDType) bool {
	switch entityType {
	case EntityUUIDv7, EntitySessionID:
		return id.present && domain.UUIDv7(id.value).Valid()
	case EntityDeviceID:
		return id.present && domain.DeviceID(id.value).Valid()
	case EntityConflictID:
		return id.present && domain.ConflictID(id.value).Valid()
	case EntityRepositoryPath:
		return id.present && domain.RepositoryPath(id.value).Valid()
	case EntityNull:
		return !id.present && id.value == ""
	default:
		return false
	}
}
