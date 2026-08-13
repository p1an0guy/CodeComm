package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
)

var errIdleConnection = errors.New("ipc: idle local connection")

type connectionBindState uint8

const (
	connectionAwaitingBind connectionBindState = iota
	connectionBound
)

func readRequest(
	connection net.Conn,
	reader *bufio.Reader,
	limits serverLimits,
	bindState connectionBindState,
) (*http.Request, []byte, error) {
	header, err := readHeader(connection, reader, limits, bindState)
	if err != nil {
		return nil, nil, err
	}
	if err := validateRawHeader(header); err != nil {
		return nil, nil, err
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_invalid_http",
			title:  "Invalid HTTP request",
			close:  true,
		}
	}
	request.Body = http.NoBody

	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		return nil, nil, &requestFailure{
			status: http.StatusHTTPVersionNotSupported,
			code:   "local_unsupported_http",
			title:  "Only strict HTTP/1.1 is supported",
			close:  true,
		}
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		return nil, nil, &requestFailure{
			status: http.StatusMethodNotAllowed,
			code:   "local_method_not_allowed",
			title:  "Local method is not allowed",
			close:  true,
		}
	}
	if request.Host == "" ||
		request.URL == nil ||
		request.URL.IsAbs() ||
		request.URL.Host != "" ||
		!strings.HasPrefix(request.RequestURI, "/") {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_unsupported_http",
			title:  "Unsupported HTTP request target",
			close:  true,
		}
	}
	if len(request.TransferEncoding) != 0 ||
		request.Header.Get("Upgrade") != "" ||
		headerHasToken(request.Header, "Connection", "upgrade") ||
		request.Header.Get("Expect") != "" {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_unsupported_framing",
			title:  "Unsupported HTTP framing",
			close:  true,
		}
	}

	hasContentLength := rawHeaderCount(header, "content-length") == 1
	if request.Method == http.MethodPost && !hasContentLength {
		return nil, nil, &requestFailure{
			status: http.StatusLengthRequired,
			code:   "local_length_required",
			title:  "Content-Length is required",
			close:  true,
		}
	}
	if request.Method == http.MethodPost && request.ContentLength == 0 {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_invalid_json",
			title:  "POST body must contain one JSON value",
			close:  true,
		}
	}
	if request.ContentLength < 0 ||
		request.ContentLength > limits.maxJSONBytes {
		return nil, nil, &requestFailure{
			status: http.StatusRequestEntityTooLarge,
			code:   "local_body_too_large",
			title:  "Local JSON body exceeds its limit",
			close:  true,
		}
	}
	if request.Method == http.MethodGet && request.ContentLength != 0 {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_get_body",
			title:  "GET requests cannot contain a body",
			close:  true,
		}
	}
	if request.Method == http.MethodPost {
		if err := validateJSONContentType(request.Header.Get("Content-Type")); err != nil {
			return nil, nil, err
		}
	}

	body := make([]byte, int(request.ContentLength))
	if len(body) > 0 {
		if err := connection.SetReadDeadline(
			time.Now().Add(limits.idleTimeout),
		); err != nil {
			if isClosedConnectionError(err) {
				return nil, nil, incompleteBodyFailure()
			}
			return nil, nil, err
		}
		if _, err := io.ReadFull(reader, body); err != nil {
			if isTimeout(err) {
				return nil, nil, &requestFailure{
					status: http.StatusRequestTimeout,
					code:   "local_body_timeout",
					title:  "Local request body timed out",
					close:  true,
				}
			}
			return nil, nil, incompleteBodyFailure()
		}
		if _, err := codec.Canonicalize(body); err != nil {
			return nil, nil, &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_invalid_json",
				title:  "Invalid JSON body",
				close:  true,
			}
		}
	}
	if pipelined, err := hasPipelinedBytes(connection, reader); err != nil {
		return nil, nil, err
	} else if pipelined {
		return nil, nil, &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_pipelining_forbidden",
			title:  "HTTP pipelining is not supported",
			close:  true,
		}
	}

	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	return request, body, nil
}

func incompleteBodyFailure() *requestFailure {
	return &requestFailure{
		status: http.StatusBadRequest,
		code:   "local_incomplete_body",
		title:  "Local request body ended early",
		close:  true,
	}
}

func readHeader(
	connection net.Conn,
	reader *bufio.Reader,
	limits serverLimits,
	bindState connectionBindState,
) ([]byte, error) {
	firstByteTimeout := limits.headerTimeout
	if bindState == connectionBound {
		firstByteTimeout = limits.idleTimeout
	}
	if err := connection.SetReadDeadline(
		time.Now().Add(firstByteTimeout),
	); err != nil {
		return nil, err
	}
	first, err := reader.ReadByte()
	if err != nil {
		if isTimeout(err) {
			return nil, errIdleConnection
		}
		return nil, err
	}
	if err := connection.SetReadDeadline(
		time.Now().Add(limits.headerTimeout),
	); err != nil && !isClosedConnectionError(err) {
		return nil, err
	}
	header := make([]byte, 1, min(limits.maxHeaderBytes, 4096))
	header[0] = first
	for {
		if len(header) >= 4 &&
			bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
			return header, nil
		}
		if len(header) == limits.maxHeaderBytes {
			return nil, &requestFailure{
				status: http.StatusRequestHeaderFieldsTooLarge,
				code:   "local_headers_too_large",
				title:  "Local request headers exceed their limit",
				close:  true,
			}
		}
		next, err := reader.ReadByte()
		if err != nil {
			if isTimeout(err) {
				return nil, &requestFailure{
					status: http.StatusRequestTimeout,
					code:   "local_header_timeout",
					title:  "Local request headers timed out",
					close:  true,
				}
			}
			return nil, err
		}
		if next == '\n' && (len(header) == 0 || header[len(header)-1] != '\r') {
			return nil, &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_invalid_http",
				title:  "Invalid HTTP request",
				close:  true,
			}
		}
		header = append(header, next)
	}
}

func validateRawHeader(header []byte) error {
	if bytes.IndexByte(header, 0) >= 0 {
		return &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_invalid_http",
			title:  "Invalid HTTP request",
			close:  true,
		}
	}
	lines := bytes.Split(header, []byte("\r\n"))
	if len(lines) < 4 || len(lines[len(lines)-1]) != 0 ||
		len(lines[len(lines)-2]) != 0 {
		return &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_invalid_http",
			title:  "Invalid HTTP request",
			close:  true,
		}
	}
	fieldCounts := make(map[string]int, len(lines)-3)
	for _, line := range lines[1 : len(lines)-2] {
		if len(line) == 0 ||
			line[0] == ' ' ||
			line[0] == '\t' {
			return &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_invalid_http",
				title:  "Invalid HTTP request",
				close:  true,
			}
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_invalid_http",
				title:  "Invalid HTTP request",
				close:  true,
			}
		}
		fieldCounts[strings.ToLower(string(line[:colon]))]++
	}
	for name, count := range fieldCounts {
		if count > 1 {
			return &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_unsupported_framing",
				title:  "Duplicate HTTP headers are not supported",
				close:  true,
			}
		}
		if name == "transfer-encoding" {
			return &requestFailure{
				status: http.StatusBadRequest,
				code:   "local_unsupported_framing",
				title:  "Unsupported HTTP framing",
				close:  true,
			}
		}
	}
	if rawHeaderCount(header, "transfer-encoding") > 0 {
		return &requestFailure{
			status: http.StatusBadRequest,
			code:   "local_unsupported_framing",
			title:  "Unsupported HTTP framing",
			close:  true,
		}
	}
	return nil
}

func rawHeaderCount(header []byte, wanted string) int {
	lines := bytes.Split(header, []byte("\r\n"))
	count := 0
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(string(line[:colon]), wanted) {
			count++
		}
	}
	return count
}

func validateJSONContentType(contentType string) error {
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return &requestFailure{
			status: http.StatusUnsupportedMediaType,
			code:   "local_json_required",
			title:  "Content-Type must be application/json",
			close:  true,
		}
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") ||
			!strings.EqualFold(value, "utf-8") {
			return &requestFailure{
				status: http.StatusUnsupportedMediaType,
				code:   "local_json_required",
				title:  "Content-Type must be application/json",
				close:  true,
			}
		}
	}
	return nil
}

func hasPipelinedBytes(
	connection net.Conn,
	reader *bufio.Reader,
) (bool, error) {
	if reader.Buffered() > 0 {
		return true, nil
	}
	return pendingNativeBytes(connection)
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func isClosedConnectionError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), token) {
				return true
			}
		}
	}
	return false
}
