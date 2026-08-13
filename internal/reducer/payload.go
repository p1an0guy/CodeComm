package reducer

import (
	"bytes"
	"encoding/json"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/task"
)

type payloadObject map[string]json.RawMessage

func decodePayload(
	input json.RawMessage,
	required []string,
	optional []string,
) (payloadObject, Code) {
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return nil, CodeInvalidPayload
	}
	var object payloadObject
	if err := json.Unmarshal(canonical, &object); err != nil || object == nil {
		return nil, CodeInvalidPayload
	}

	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	for _, field := range optional {
		allowed[field] = struct{}{}
	}
	// Rejection precedence is part of the frozen reducer contract. Keep each
	// class in a separate pass so Go map iteration cannot select the outcome.
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return nil, CodeUnknownPayloadField
		}
	}
	for _, value := range object {
		if bytes.Equal(value, []byte("null")) {
			return nil, CodeInvalidPayload
		}
	}
	for _, field := range required {
		if _, ok := object[field]; !ok {
			return nil, CodeMissingPayloadField
		}
	}
	return object, ""
}

func decodeValue[T any](object payloadObject, field string) (T, bool) {
	var result T
	raw, present := object[field]
	if !present {
		return result, false
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, false
	}
	return result, true
}

func decodePriority(object payloadObject, field string) (task.Priority, bool) {
	value, ok := decodeValue[uint64](object, field)
	if !ok || value > uint64(task.MaxPriority) {
		return 0, false
	}
	return task.Priority(value), true
}

func decodeTaskIDs(object payloadObject, field string) ([]domain.UUIDv7, bool) {
	values, ok := decodeValue[[]string](object, field)
	if !ok {
		return nil, false
	}
	result := make([]domain.UUIDv7, len(values))
	for index, value := range values {
		result[index] = domain.UUIDv7(value)
	}
	return result, true
}

func decodeLabels(object payloadObject, field string) ([]string, bool) {
	values, ok := decodeValue[[]string](object, field)
	if !ok {
		return nil, false
	}
	normalized, err := task.NormalizeLabels(values)
	if err != nil {
		return nil, false
	}
	return normalized, true
}
