package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/ijonahch/codecomm/internal/codec"
)

func validateCanonicalObject(name string, value []byte) error {
	canonical, err := codec.CanonicalizeSignedObject(value)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidObject, name, err)
	}
	if !bytes.Equal(canonical, value) {
		return fmt.Errorf("%w: %s is not canonical", ErrInvalidObject, name)
	}
	return nil
}

func validatePrimaryKey(
	spec tableSpec,
	value []byte,
) ([]json.RawMessage, error) {
	canonical, err := codec.Canonicalize(value)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: table %s: %w",
			ErrInvalidPrimaryKey,
			spec.name,
			err,
		)
	}
	if !bytes.Equal(canonical, value) {
		return nil, fmt.Errorf(
			"%w: table %s: key is not canonical",
			ErrInvalidPrimaryKey,
			spec.name,
		)
	}

	var components []json.RawMessage
	if err := json.Unmarshal(value, &components); err != nil {
		return nil, fmt.Errorf(
			"%w: table %s: key must be an array",
			ErrInvalidPrimaryKey,
			spec.name,
		)
	}
	if len(components) != len(spec.primaryKey) {
		return nil, fmt.Errorf(
			"%w: table %s: got %d components, want %d",
			ErrInvalidPrimaryKey,
			spec.name,
			len(components),
			len(spec.primaryKey),
		)
	}

	for index, field := range spec.primaryKey {
		if err := validatePrimaryKeyComponent(field, components[index]); err != nil {
			return nil, fmt.Errorf(
				"%w: table %s field %s: %v",
				ErrInvalidPrimaryKey,
				spec.name,
				field.name,
				err,
			)
		}
	}
	return components, nil
}

func validatePrimaryKeyComponent(
	field primaryKeyField,
	value json.RawMessage,
) error {
	switch field.kind {
	case primaryKeyString:
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return errors.New("must be a string")
		}
		if text == "" {
			return errors.New("must not be empty")
		}
		return nil
	case primaryKeyPositiveInteger:
		integer, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil || integer == 0 || integer > maxSafeInteger {
			return errors.New("must be a positive exact integer")
		}
		return nil
	default:
		return errors.New("has an unknown component type")
	}
}

func validateLogicalRow(
	spec tableSpec,
	components []json.RawMessage,
	value []byte,
	baseError error,
) error {
	if err := validateCanonicalObject("logical row", value); err != nil {
		return fmt.Errorf("%w: table %s: %w", baseError, spec.name, err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(value, &members); err != nil {
		return fmt.Errorf("%w: table %s: decode row", baseError, spec.name)
	}
	for index, field := range spec.primaryKey {
		member, exists := members[field.name]
		if !exists {
			return fmt.Errorf(
				"%w: table %s: row omits primary-key field %s",
				baseError,
				spec.name,
				field.name,
			)
		}
		if !bytes.Equal(member, components[index]) {
			return fmt.Errorf(
				"%w: table %s: row primary-key field %s differs",
				baseError,
				spec.name,
				field.name,
			)
		}
	}
	if len(members) != len(spec.fields) {
		return fmt.Errorf(
			"%w: table %s: row has %d fields, want %d",
			baseError,
			spec.name,
			len(members),
			len(spec.fields),
		)
	}
	for _, field := range spec.fields {
		member, exists := members[field.name]
		if !exists {
			return fmt.Errorf(
				"%w: table %s: row omits field %s",
				baseError,
				spec.name,
				field.name,
			)
		}
		if err := validateLogicalValue(field, member); err != nil {
			return fmt.Errorf(
				"%w: table %s field %s: %v",
				baseError,
				spec.name,
				field.name,
				err,
			)
		}
	}
	return nil
}

func validateLogicalValue(field logicalField, value json.RawMessage) error {
	if bytes.Equal(value, []byte("null")) {
		if field.nullable {
			return nil
		}
		return errors.New("must not be null")
	}

	switch field.kind {
	case logicalString:
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return errors.New("must be a string")
		}
	case logicalInteger:
		integer, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil || integer > maxSafeInteger {
			return errors.New("must be a nonnegative exact integer")
		}
	case logicalArray:
		var array []json.RawMessage
		if len(value) == 0 || value[0] != '[' ||
			json.Unmarshal(value, &array) != nil {
			return errors.New("must be an array")
		}
	case logicalObject:
		var object map[string]json.RawMessage
		if len(value) == 0 || value[0] != '{' ||
			json.Unmarshal(value, &object) != nil {
			return errors.New("must be an object")
		}
	case logicalBase64URL:
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return errors.New("must be a base64url string")
		}
		if _, err := codec.DecodeBase64URLExact(text, field.decodedSize); err != nil {
			return fmt.Errorf("invalid base64url value: %v", err)
		}
	case logicalBoolean:
		if !bytes.Equal(value, []byte("true")) &&
			!bytes.Equal(value, []byte("false")) {
			return errors.New("must be a boolean")
		}
	default:
		return errors.New("has an unknown logical value type")
	}
	return nil
}
