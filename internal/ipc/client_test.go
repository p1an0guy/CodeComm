package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"
	"testing"
)

func TestReadClientResponseAcceptsOnlyStrictBoundedFraming(t *testing.T) {
	const correlationID = "00112233445566778899aabbccddeeff"
	const body = `{"status":"ok"}`
	valid := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 15\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"X-CodeComm-Correlation-ID: " + correlationID + "\r\n\r\n" +
		body
	response, err := readClientResponse(
		bufio.NewReader(bytes.NewBufferString(valid)),
	)
	if err != nil {
		t.Fatalf("readClientResponse(valid): %v", err)
	}
	if response.status != http.StatusOK ||
		response.contentType != "application/json" ||
		response.correlationID != correlationID ||
		string(response.body) != body {
		t.Fatalf("response = %#v", response)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate length",
			raw: replaceClientTestText(
				valid,
				"Content-Length: 15\r\n",
				"Content-Length: 15\r\nContent-Length: 15\r\n",
			),
		},
		{
			name: "transfer encoding",
			raw: replaceClientTestText(
				valid,
				"Cache-Control: no-store\r\n",
				"Transfer-Encoding: chunked\r\nCache-Control: no-store\r\n",
			),
		},
		{
			name: "noncanonical body",
			raw:  replaceClientTestText(valid, body, `{"status": "ok"}`),
		},
		{
			name: "bad correlation",
			raw: replaceClientTestText(
				valid,
				correlationID,
				"not-a-correlation-id",
			),
		},
		{
			name: "bare line feed",
			raw: replaceClientTestText(
				valid,
				"Content-Type: application/json\r\n",
				"Content-Type: application/json\n",
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readClientResponse(
				bufio.NewReader(bytes.NewBufferString(test.raw)),
			); !errors.Is(err, ErrClientProtocol) {
				t.Fatalf(
					"readClientResponse() error = %v, want %v",
					err,
					ErrClientProtocol,
				)
			}
		})
	}
}

func TestValidClientPathIsClosedToCanonicalLocalV1Paths(t *testing.T) {
	for _, path := range []string{
		"/local/v1/bind",
		"/local/v1/query/status",
		"/local/v1/agent-launch/ack",
	} {
		if !validClientPath(path) {
			t.Errorf("validClientPath(%q) = false", path)
		}
	}
	for _, path := range []string{
		"",
		"/",
		"/local/v1",
		"/local/v1/",
		"/local/v1/query/status?other=true",
		"/local/v1/query/../status",
		"//local/v1/query/status",
		"http://codecomm.local/local/v1/query/status",
		"/local/v1/query/status%2fother",
		"/local/v1/query/status\x00",
	} {
		if validClientPath(path) {
			t.Errorf("validClientPath(%q) = true", path)
		}
	}
}

func replaceClientTestText(value, old, replacement string) string {
	return string(bytes.ReplaceAll(
		[]byte(value),
		[]byte(old),
		[]byte(replacement),
	))
}
