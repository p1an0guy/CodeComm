package localcommand

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
)

var ErrInvalidRequest = errors.New("localcommand: invalid request")

// Request is the strict authority-free mutation envelope accepted over local
// IPC. Canonical is retained verbatim for durable idempotency.
type Request struct {
	Operation string
	RequestID domain.UUIDv7
	Command   event.Command
	Canonical []byte
}

// DecodeReader reads at most one bounded local mutation request.
func DecodeReader(input io.Reader) (Request, error) {
	if input == nil {
		return Request{}, ErrInvalidRequest
	}
	raw, err := io.ReadAll(io.LimitReader(
		input,
		int64(event.MaxLocalCommandBytes)+1,
	))
	if err != nil || len(raw) > event.MaxLocalCommandBytes {
		return Request{}, ErrInvalidRequest
	}
	return Decode(raw)
}

// Decode validates and canonicalizes one local mutation request. Operation
// authorization remains the responsibility of the bound client class.
func Decode(input []byte) (Request, error) {
	if len(input) == 0 || len(input) > event.MaxLocalCommandBytes {
		return Request{}, ErrInvalidRequest
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil {
		return Request{}, ErrInvalidRequest
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil ||
		len(members) != 3 {
		return Request{}, ErrInvalidRequest
	}
	for _, field := range []string{"operation", "request_id", "command"} {
		value, exists := members[field]
		if !exists || bytes.Equal(value, []byte("null")) {
			return Request{}, ErrInvalidRequest
		}
	}
	var operation, requestIDText string
	if err := json.Unmarshal(members["operation"], &operation); err != nil ||
		json.Unmarshal(members["request_id"], &requestIDText) != nil ||
		operation == "" {
		return Request{}, ErrInvalidRequest
	}
	requestID := domain.UUIDv7(requestIDText)
	if !requestID.Valid() {
		return Request{}, ErrInvalidRequest
	}
	command, err := event.DecodeLocalCommand(members["command"])
	if err != nil {
		return Request{}, err
	}
	return Request{
		Operation: operation,
		RequestID: requestID,
		Command:   command,
		Canonical: canonical,
	}, nil
}
