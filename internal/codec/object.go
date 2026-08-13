package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

var (
	ErrNoncanonicalObject = errors.New("codec: object is not canonical")
	ErrObjectMember       = errors.New("codec: invalid object member")
	ErrObjectMemberAbsent = errors.New("codec: object member is absent")
)

// RemoveCanonicalObjectMember removes one top-level member without decoding
// and reserializing the remaining values. This preserves unknown members in
// the exact signature preimage.
func RemoveCanonicalObjectMember(
	input []byte,
	target string,
) ([]byte, []byte, error) {
	if target == "" || !utf8.ValidString(target) {
		return nil, nil, ErrObjectMember
	}
	canonical, err := CanonicalizeSignedObject(input)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(input, canonical) {
		return nil, nil, ErrNoncanonicalObject
	}

	members, err := scanCanonicalObjectMembers(input)
	if err != nil {
		return nil, nil, err
	}
	unsigned := make([]byte, 0, len(input))
	unsigned = append(unsigned, '{')
	var value []byte
	found := false
	wrote := false
	for _, member := range members {
		if member.key == target {
			found = true
			value = bytes.Clone(input[member.valueStart:member.valueEnd])
			continue
		}
		if wrote {
			unsigned = append(unsigned, ',')
		}
		unsigned = append(unsigned, input[member.start:member.end]...)
		wrote = true
	}
	unsigned = append(unsigned, '}')
	if !found {
		return nil, nil, fmt.Errorf("%w: %q", ErrObjectMemberAbsent, target)
	}
	return unsigned, value, nil
}

type canonicalObjectMember struct {
	key        string
	start      int
	end        int
	valueStart int
	valueEnd   int
}

func scanCanonicalObjectMembers(
	input []byte,
) ([]canonicalObjectMember, error) {
	if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' {
		return nil, ErrObjectMember
	}
	if len(input) == 2 {
		return nil, nil
	}

	members := make([]canonicalObjectMember, 0, 8)
	for index := 1; index < len(input)-1; {
		memberStart := index
		keyEnd, err := scanCanonicalJSONString(input, index)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(input[index:keyEnd], &key); err != nil {
			return nil, fmt.Errorf("%w: decode key", ErrObjectMember)
		}
		if keyEnd >= len(input) || input[keyEnd] != ':' {
			return nil, fmt.Errorf("%w: missing key separator", ErrObjectMember)
		}
		valueStart := keyEnd + 1
		valueEnd, err := scanCanonicalJSONValue(input, valueStart)
		if err != nil {
			return nil, err
		}
		members = append(members, canonicalObjectMember{
			key:        key,
			start:      memberStart,
			end:        valueEnd,
			valueStart: valueStart,
			valueEnd:   valueEnd,
		})
		index = valueEnd
		switch input[index] {
		case ',':
			index++
		case '}':
			if index != len(input)-1 {
				return nil, fmt.Errorf(
					"%w: unexpected object suffix",
					ErrObjectMember,
				)
			}
			return members, nil
		default:
			return nil, fmt.Errorf(
				"%w: invalid object delimiter",
				ErrObjectMember,
			)
		}
	}
	return nil, fmt.Errorf("%w: unterminated object", ErrObjectMember)
}

func scanCanonicalJSONString(input []byte, start int) (int, error) {
	if start >= len(input) || input[start] != '"' {
		return 0, fmt.Errorf("%w: expected string", ErrObjectMember)
	}
	escaped := false
	for index := start + 1; index < len(input); index++ {
		switch {
		case escaped:
			escaped = false
		case input[index] == '\\':
			escaped = true
		case input[index] == '"':
			return index + 1, nil
		}
	}
	return 0, fmt.Errorf("%w: unterminated string", ErrObjectMember)
}

func scanCanonicalJSONValue(input []byte, start int) (int, error) {
	if start >= len(input) {
		return 0, fmt.Errorf("%w: missing value", ErrObjectMember)
	}
	if input[start] == '"' {
		return scanCanonicalJSONString(input, start)
	}
	if input[start] == '{' || input[start] == '[' {
		depth := 0
		inString := false
		escaped := false
		for index := start; index < len(input); index++ {
			character := input[index]
			if inString {
				switch {
				case escaped:
					escaped = false
				case character == '\\':
					escaped = true
				case character == '"':
					inString = false
				}
				continue
			}
			switch character {
			case '"':
				inString = true
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return index + 1, nil
				}
			}
		}
		return 0, fmt.Errorf("%w: unterminated container", ErrObjectMember)
	}
	for index := start; index < len(input); index++ {
		switch input[index] {
		case ',', '}', ']':
			if index == start {
				return 0, fmt.Errorf("%w: empty value", ErrObjectMember)
			}
			return index, nil
		}
	}
	return 0, fmt.Errorf("%w: unterminated scalar", ErrObjectMember)
}
