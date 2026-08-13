package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
)

const (
	clientHost                 = "codecomm.local"
	clientProblemMediaType     = "application/problem+json"
	clientCorrelationIDHexSize = 32
	clientMaxPathBytes         = 256
)

var (
	ErrInvalidClientRequest = errors.New("ipc: invalid local client request")
	ErrClientClosed         = errors.New("ipc: local client is closed")
	ErrClientConnectionLost = errors.New("ipc: local daemon connection is unavailable")
	ErrClientProtocol       = errors.New("ipc: invalid local protocol response")
)

// ClientError is a bounded structured error returned by the local daemon.
type ClientError struct {
	Status        int
	Code          string
	CorrelationID string
	Retryable     bool
}

func (failure *ClientError) Error() string {
	if failure == nil {
		return "ipc: local request failed"
	}
	return fmt.Sprintf(
		"ipc: local request failed: %s (HTTP %d, correlation %s)",
		failure.Code,
		failure.Status,
		failure.CorrelationID,
	)
}

// ClientResponse is one successful strict local HTTP/1.1 response.
type ClientResponse struct {
	StatusCode int
	Body       []byte
}

// Client owns one authenticated, non-pipelined local connection.
type Client struct {
	requestMu sync.Mutex
	stateMu   sync.Mutex

	connection *Conn
	reader     *bufio.Reader
	closed     bool
}

// DialClient connects to one owner-restricted local endpoint.
func DialClient(ctx context.Context, endpoint Endpoint) (*Client, error) {
	if ctx == nil {
		return nil, ErrInvalidClientRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := Dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{
		connection: connection,
		reader:     bufio.NewReaderSize(connection, MaxHeaderBytes+1),
	}, nil
}

// Exchange sends one canonical local request. Calls are serialized and never
// pipelined; any ambiguous framing permanently drops the connection.
func (client *Client) Exchange(
	ctx context.Context,
	method, path string,
	body []byte,
) (ClientResponse, error) {
	if client == nil || ctx == nil {
		return ClientResponse{}, ErrInvalidClientRequest
	}
	if err := ctx.Err(); err != nil {
		return ClientResponse{}, err
	}
	if method != http.MethodGet && method != http.MethodPost ||
		!validClientPath(path) ||
		method == http.MethodGet && len(body) != 0 ||
		method == http.MethodPost && len(body) == 0 ||
		len(body) > MaxJSONBytes {
		return ClientResponse{}, ErrInvalidClientRequest
	}
	if len(body) != 0 {
		canonical, err := codec.CanonicalizeSignedObject(body)
		if err != nil || !bytes.Equal(canonical, body) {
			return ClientResponse{}, ErrInvalidClientRequest
		}
	}

	client.requestMu.Lock()
	defer client.requestMu.Unlock()

	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return ClientResponse{}, ErrClientClosed
	}
	if client.connection == nil || client.reader == nil {
		client.stateMu.Unlock()
		return ClientResponse{}, ErrClientConnectionLost
	}
	connection := client.connection
	reader := client.reader
	client.stateMu.Unlock()

	disarm, err := armClientDeadline(ctx, connection)
	if err != nil {
		client.breakConnection(connection)
		return ClientResponse{}, clientTransportError(ctx, err)
	}
	defer disarm()
	if err := writeClientRequest(connection, method, path, body); err != nil {
		client.breakConnection(connection)
		return ClientResponse{}, clientTransportError(ctx, err)
	}
	response, err := readClientResponse(reader)
	if err != nil {
		client.breakConnection(connection)
		if errors.Is(err, ErrClientProtocol) {
			return ClientResponse{}, err
		}
		return ClientResponse{}, clientTransportError(ctx, err)
	}
	if response.close {
		client.breakConnection(connection)
	}
	if response.status < 200 || response.status >= 300 {
		return ClientResponse{}, decodeClientError(response)
	}
	return ClientResponse{
		StatusCode: response.status,
		Body:       response.body,
	}, nil
}

// Usable reports whether the client still owns a live connection.
func (client *Client) Usable() bool {
	if client == nil {
		return false
	}
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	return !client.closed &&
		client.connection != nil &&
		client.reader != nil
}

// Close drops the connection. It is safe to call concurrently and repeatedly.
func (client *Client) Close() error {
	if client == nil {
		return ErrInvalidClientRequest
	}
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil
	}
	client.closed = true
	connection := client.connection
	client.connection = nil
	client.reader = nil
	client.stateMu.Unlock()
	if connection == nil {
		return nil
	}
	return connection.Close()
}

func (client *Client) breakConnection(connection *Conn) {
	client.stateMu.Lock()
	if client.connection == connection {
		client.connection = nil
		client.reader = nil
	}
	client.stateMu.Unlock()
	_ = connection.Close()
}

func validClientPath(path string) bool {
	const prefix = "/local/v1/"
	if len(path) <= len(prefix) ||
		len(path) > clientMaxPathBytes ||
		!strings.HasPrefix(path, prefix) ||
		strings.HasSuffix(path, "/") {
		return false
	}
	segmentLength := 0
	for index := len(prefix); index < len(path); index++ {
		character := path[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '-',
			character == '_':
			segmentLength++
		case character == '/':
			if segmentLength == 0 {
				return false
			}
			segmentLength = 0
		default:
			return false
		}
	}
	return segmentLength > 0
}

func armClientDeadline(
	ctx context.Context,
	connection *Conn,
) (func(), error) {
	deadline := time.Now().Add(IdleTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(callbackDone)
	})
	return func() {
		if !stop() {
			<-callbackDone
		}
		_ = connection.SetDeadline(time.Time{})
	}, nil
}

func normalizeClientContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func clientTransportError(ctx context.Context, err error) error {
	normalized := normalizeClientContextError(ctx, err)
	if normalized != err {
		return normalized
	}
	return fmt.Errorf("%w: %v", ErrClientConnectionLost, err)
}

func writeClientRequest(
	writer io.Writer,
	method, path string,
	body []byte,
) error {
	var header strings.Builder
	header.Grow(192)
	header.WriteString(method)
	header.WriteByte(' ')
	header.WriteString(path)
	header.WriteString(" HTTP/1.1\r\nHost: ")
	header.WriteString(clientHost)
	if method == http.MethodPost {
		header.WriteString("\r\nContent-Type: application/json")
		header.WriteString("\r\nContent-Length: ")
		header.WriteString(strconv.Itoa(len(body)))
	}
	header.WriteString("\r\n\r\n")
	if err := writeFull(writer, []byte(header.String())); err != nil {
		return err
	}
	if len(body) != 0 {
		return writeFull(writer, body)
	}
	return nil
}

type framedClientResponse struct {
	status        int
	contentType   string
	correlationID string
	close         bool
	body          []byte
}

func readClientResponse(
	reader *bufio.Reader,
) (framedClientResponse, error) {
	headerBytes := 0
	statusLine, err := readClientHeaderLine(reader, &headerBytes)
	if err != nil {
		return framedClientResponse{}, err
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) != 3 ||
		parts[0] != "HTTP/1.1" ||
		len(parts[1]) != 3 {
		return framedClientResponse{}, ErrClientProtocol
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil ||
		status < 200 ||
		status > 599 ||
		parts[2] != http.StatusText(status) {
		return framedClientResponse{}, ErrClientProtocol
	}

	headers := make(map[string]string, 6)
	for {
		line, err := readClientHeaderLine(reader, &headerBytes)
		if err != nil {
			return framedClientResponse{}, err
		}
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return framedClientResponse{}, ErrClientProtocol
		}
		name, value, found := strings.Cut(line, ":")
		name = strings.ToLower(name)
		value = strings.TrimSpace(value)
		if !found ||
			!validClientHeaderName(name) ||
			!validClientHeaderValue(value) {
			return framedClientResponse{}, ErrClientProtocol
		}
		if _, duplicate := headers[name]; duplicate {
			return framedClientResponse{}, ErrClientProtocol
		}
		headers[name] = value
	}
	for name := range headers {
		switch name {
		case "content-type",
			"content-length",
			"cache-control",
			"x-content-type-options",
			"x-codecomm-correlation-id",
			"connection":
		default:
			return framedClientResponse{}, ErrClientProtocol
		}
	}
	if headers["cache-control"] != "no-store" ||
		headers["x-content-type-options"] != "nosniff" {
		return framedClientResponse{}, ErrClientProtocol
	}
	correlationID := headers["x-codecomm-correlation-id"]
	if len(correlationID) != clientCorrelationIDHexSize {
		return framedClientResponse{}, ErrClientProtocol
	}
	decodedCorrelationID, err := hex.DecodeString(correlationID)
	if err != nil ||
		hex.EncodeToString(decodedCorrelationID) != correlationID {
		return framedClientResponse{}, ErrClientProtocol
	}
	mediaType, parameters, err := mime.ParseMediaType(
		headers["content-type"],
	)
	if err != nil ||
		mediaType != "application/json" &&
			mediaType != clientProblemMediaType ||
		len(parameters) != 0 {
		return framedClientResponse{}, ErrClientProtocol
	}
	length, err := strconv.ParseInt(headers["content-length"], 10, 64)
	if err != nil || length < 0 || length > MaxJSONBytes {
		return framedClientResponse{}, ErrClientProtocol
	}
	closeResponse := false
	if connectionValue, present := headers["connection"]; present {
		if !strings.EqualFold(connectionValue, "close") {
			return framedClientResponse{}, ErrClientProtocol
		}
		closeResponse = true
	}
	if status == http.StatusNoContent {
		if length != 0 || mediaType != "application/json" {
			return framedClientResponse{}, ErrClientProtocol
		}
		return framedClientResponse{
			status:        status,
			contentType:   mediaType,
			correlationID: correlationID,
			close:         closeResponse,
		}, nil
	}
	if length == 0 {
		return framedClientResponse{}, ErrClientProtocol
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return framedClientResponse{}, err
	}
	canonical, err := codec.CanonicalizeSignedObject(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return framedClientResponse{}, ErrClientProtocol
	}
	return framedClientResponse{
		status:        status,
		contentType:   mediaType,
		correlationID: correlationID,
		close:         closeResponse,
		body:          body,
	}, nil
}

func readClientHeaderLine(
	reader *bufio.Reader,
	total *int,
) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	*total += len(line)
	if *total > MaxHeaderBytes ||
		len(line) < 2 ||
		line[len(line)-2] != '\r' {
		return "", ErrClientProtocol
	}
	line = line[:len(line)-2]
	if bytes.IndexByte(line, 0) >= 0 {
		return "", ErrClientProtocol
	}
	return string(line), nil
}

func validClientHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if !(character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-') {
			return false
		}
	}
	return true
}

func validClientHeaderValue(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

type clientProblemWire struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
	Retryable     bool   `json:"retryable"`
	Detail        string `json:"detail,omitempty"`
}

type clientApplicationErrorWire struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

func decodeClientError(response framedClientResponse) error {
	failure := &ClientError{
		Status:        response.status,
		Code:          "local_protocol_error",
		CorrelationID: response.correlationID,
	}
	switch response.contentType {
	case clientProblemMediaType:
		var wire clientProblemWire
		if err := decodeClientObject(response.body, &wire); err != nil ||
			wire.Status != response.status ||
			wire.CorrelationID != response.correlationID ||
			wire.Code == "" ||
			wire.Type != "urn:codecomm:problem:"+wire.Code ||
			wire.Title == "" {
			return ErrClientProtocol
		}
		failure.Code = wire.Code
		failure.Retryable = wire.Retryable
	case "application/json":
		var wire clientApplicationErrorWire
		if err := decodeClientObject(response.body, &wire); err != nil ||
			wire.Status != response.status ||
			wire.Code == "" {
			return ErrClientProtocol
		}
		failure.Code = wire.Code
	default:
		return ErrClientProtocol
	}
	return failure
}

func decodeClientObject(input []byte, output any) error {
	if output == nil || len(input) == 0 {
		return ErrClientProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrClientProtocol
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrClientProtocol
	}
	return nil
}
