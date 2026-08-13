package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ijonahch/codecomm/internal/codec"
)

const problemMediaType = "application/problem+json"

type problem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
	Retryable     bool   `json:"retryable"`
	Detail        string `json:"detail,omitempty"`
}

type requestFailure struct {
	status    int
	code      string
	title     string
	detail    string
	retryable bool
	close     bool
}

func (failure *requestFailure) Error() string {
	return failure.code
}

func newProblem(failure requestFailure, correlationID string) problem {
	return problem{
		Type:          "urn:codecomm:problem:" + failure.code,
		Title:         failure.title,
		Status:        failure.status,
		Code:          failure.code,
		CorrelationID: correlationID,
		Retryable:     failure.retryable,
		Detail:        failure.detail,
	}
}

func marshalProblem(failure requestFailure, correlationID string) []byte {
	encoded, err := json.Marshal(newProblem(failure, correlationID))
	if err != nil {
		panic(fmt.Sprintf("ipc: marshal fixed problem: %v", err))
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		panic(fmt.Sprintf("ipc: canonicalize fixed problem: %v", err))
	}
	return canonical
}

func newCorrelationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("ipc: generate correlation ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func internalFailure() requestFailure {
	return requestFailure{
		status: http.StatusInternalServerError,
		code:   "local_internal_error",
		title:  "Local request failed",
		close:  true,
	}
}
