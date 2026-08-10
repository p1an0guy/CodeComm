// Package codec implements CodeComm's canonical wire encodings.
package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	canonicaljcs "github.com/ucarion/jcs"
)

const (
	maxJSONDepth             = 32
	maxCanonicalJSONBytes    = 4 << 20
	maxSignedObjectJSONBytes = 1 << 20
	maxSafeInteger           = int64(1<<53 - 1)
)

var (
	ErrInvalidUTF8       = errors.New("codec: JSON is not valid UTF-8")
	ErrInvalidSurrogate  = errors.New("codec: invalid UTF-16 surrogate escape")
	ErrDuplicateKey      = errors.New("codec: duplicate object key")
	ErrTrailingData      = errors.New("codec: trailing JSON data")
	ErrNestingTooDeep    = errors.New("codec: JSON nesting exceeds 32")
	ErrSignedObject      = errors.New("codec: signed value must be an object")
	ErrNonInteger        = errors.New("codec: signed number is not an integer")
	ErrIntegerOutOfRange = errors.New("codec: signed integer exceeds the safe range")
	ErrInputTooLarge     = errors.New("codec: JSON exceeds the input limit")
)

// Canonicalize validates input strictly and returns its RFC 8785 encoding.
func Canonicalize(input []byte) ([]byte, error) {
	value, _, err := validateJSON(input, false, maxCanonicalJSONBytes)
	if err != nil {
		return nil, err
	}
	out, err := canonicaljcs.Append(nil, value)
	if err != nil {
		return nil, fmt.Errorf("codec: canonicalize JSON: %w", err)
	}
	return out, nil
}

// CanonicalizeSignedObject canonicalizes an object after enforcing CodeComm's
// signed-number profile. It does not replace a protocol's closed typed decoder
// or its field-specific item and string limits.
func CanonicalizeSignedObject(input []byte) ([]byte, error) {
	value, isObject, err := validateJSON(input, true, maxSignedObjectJSONBytes)
	if err != nil {
		return nil, err
	}
	if !isObject {
		return nil, ErrSignedObject
	}
	out, err := canonicaljcs.Append(nil, value)
	if err != nil {
		return nil, fmt.Errorf("codec: canonicalize signed object: %w", err)
	}
	return out, nil
}

func validateJSON(input []byte, signed bool, maxBytes int) (any, bool, error) {
	if len(input) > maxBytes {
		return nil, false, fmt.Errorf("%w: got %d bytes, limit %d", ErrInputTooLarge, len(input), maxBytes)
	}
	if !utf8.Valid(input) {
		return nil, false, ErrInvalidUTF8
	}
	if err := validateSurrogateEscapes(input); err != nil {
		return nil, false, err
	}

	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	value, isObject, err := consumeValue(dec, 0, signed)
	if err != nil {
		return nil, false, fmt.Errorf("codec: invalid JSON: %w", err)
	}
	if _, err = dec.Token(); err == io.EOF {
		return value, isObject, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrTrailingData, err)
	}
	return nil, false, ErrTrailingData
}

func consumeValue(dec *json.Decoder, depth int, signed bool) (any, bool, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, false, err
	}

	delim, isContainer := token.(json.Delim)
	if !isContainer {
		if number, ok := token.(json.Number); ok {
			if signed {
				if err := validateSignedNumber(string(number)); err != nil {
					return nil, false, err
				}
			}
			value, err := strconv.ParseFloat(string(number), 64)
			if err != nil {
				return nil, false, err
			}
			return value, false, nil
		}
		return token, false, nil
	}

	if delim != '{' && delim != '[' {
		return nil, false, fmt.Errorf("unexpected delimiter %q", delim)
	}
	depth++
	if depth > maxJSONDepth {
		return nil, false, ErrNestingTooDeep
	}

	switch delim {
	case '{':
		keys := make(map[string]struct{})
		object := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, false, errors.New("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return nil, false, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			keys[key] = struct{}{}
			value, _, err := consumeValue(dec, depth, signed)
			if err != nil {
				return nil, false, err
			}
			object[key] = value
		}
		if err := consumeClosingDelimiter(dec, '}'); err != nil {
			return nil, false, err
		}
		return object, true, nil
	case '[':
		var array []any
		for dec.More() {
			value, _, err := consumeValue(dec, depth, signed)
			if err != nil {
				return nil, false, err
			}
			array = append(array, value)
		}
		return array, false, consumeClosingDelimiter(dec, ']')
	default:
		return nil, false, fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func consumeClosingDelimiter(dec *json.Decoder, want json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected delimiter %q, got %q", want, token)
	}
	return nil
}

func validateSignedNumber(token string) error {
	if strings.ContainsAny(token, ".eE") {
		return fmt.Errorf("%w: %s", ErrNonInteger, token)
	}
	value, err := strconv.ParseInt(token, 10, 64)
	if err != nil || value < -maxSafeInteger || value > maxSafeInteger {
		return fmt.Errorf("%w: %s", ErrIntegerOutOfRange, token)
	}
	return nil
}

func validateSurrogateEscapes(input []byte) error {
	for i := 0; i < len(input); i++ {
		if input[i] != '"' {
			continue
		}
		for i++; i < len(input) && input[i] != '"'; {
			if input[i] != '\\' {
				i++
				continue
			}
			if i+1 >= len(input) || input[i+1] != 'u' {
				i += 2
				continue
			}

			first, ok := hexCodeUnit(input, i+2)
			if !ok {
				return ErrInvalidSurrogate
			}
			i += 6
			switch {
			case first >= 0xd800 && first <= 0xdbff:
				if i+6 > len(input) || input[i] != '\\' || input[i+1] != 'u' {
					return ErrInvalidSurrogate
				}
				second, ok := hexCodeUnit(input, i+2)
				if !ok || second < 0xdc00 || second > 0xdfff {
					return ErrInvalidSurrogate
				}
				i += 6
			case first >= 0xdc00 && first <= 0xdfff:
				return ErrInvalidSurrogate
			}
		}
	}
	return nil
}

func hexCodeUnit(input []byte, start int) (uint16, bool) {
	if start+4 > len(input) {
		return 0, false
	}
	var value uint16
	for _, c := range input[start : start+4] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
