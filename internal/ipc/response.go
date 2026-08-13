package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
)

var errResponseTooLarge = errors.New("ipc: local response exceeds its limit")

type localResponse struct {
	status      int
	contentType string
	body        []byte
	close       bool
}

func problemResponse(
	failure requestFailure,
	correlationID string,
) localResponse {
	return localResponse{
		status:      failure.status,
		contentType: problemMediaType,
		body:        marshalProblem(failure, correlationID),
		close:       failure.close,
	}
}

type boundedResponseWriter struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	maxBytes int64
	overflow bool
}

func (writer *boundedResponseWriter) Header() http.Header {
	return writer.header
}

func (writer *boundedResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	if status < 200 || status > 599 {
		status = http.StatusInternalServerError
	}
	writer.status = status
}

func (writer *boundedResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	if writer.overflow ||
		int64(writer.body.Len())+int64(len(value)) > writer.maxBytes {
		writer.overflow = true
		return 0, errResponseTooLarge
	}
	return writer.body.Write(value)
}

func invokeHandler(
	ctx context.Context,
	handler http.Handler,
	request *http.Request,
	body []byte,
	correlationID string,
	limits serverLimits,
) (response localResponse) {
	writer := &boundedResponseWriter{
		header:   make(http.Header),
		maxBytes: limits.maxJSONBytes,
	}
	defer func() {
		if recover() != nil {
			response = problemResponse(internalFailure(), correlationID)
		}
	}()
	request = request.Clone(ctx)
	request.Body = http.NoBody
	if len(body) > 0 {
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	handler.ServeHTTP(writer, request)
	if writer.overflow {
		return problemResponse(internalFailure(), correlationID)
	}
	status := writer.status
	if status == 0 {
		status = http.StatusOK
	}
	if status == http.StatusNoContent {
		if writer.body.Len() != 0 {
			return problemResponse(internalFailure(), correlationID)
		}
		return localResponse{
			status:      status,
			contentType: "application/json",
		}
	}

	responseBody := writer.body.Bytes()
	if len(responseBody) == 0 {
		responseBody = []byte("{}")
	}
	canonical, err := codec.Canonicalize(responseBody)
	if err != nil || int64(len(canonical)) > limits.maxJSONBytes {
		return problemResponse(internalFailure(), correlationID)
	}
	contentType := writer.header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil ||
		mediaType != "application/json" && mediaType != problemMediaType ||
		len(parameters) != 0 {
		return problemResponse(internalFailure(), correlationID)
	}
	return localResponse{
		status:      status,
		contentType: mediaType,
		body:        canonical,
	}
}

func marshalJSON(value any, maxBytes int64) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := codec.Canonicalize(encoded)
	if err != nil {
		return nil, err
	}
	if int64(len(canonical)) > maxBytes {
		return nil, errResponseTooLarge
	}
	return canonical, nil
}

func writeResponse(
	connection net.Conn,
	timeout time.Duration,
	status int,
	contentType string,
	body []byte,
	correlationID string,
	closeConnection bool,
) error {
	if status < 200 || status > 599 || http.StatusText(status) == "" {
		return errors.New("ipc: invalid local response status")
	}
	if status == http.StatusNoContent {
		body = nil
	}
	if err := connection.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var header strings.Builder
	header.Grow(256)
	header.WriteString("HTTP/1.1 ")
	header.WriteString(strconv.Itoa(status))
	header.WriteByte(' ')
	header.WriteString(http.StatusText(status))
	header.WriteString("\r\nContent-Type: ")
	header.WriteString(contentType)
	header.WriteString("\r\nContent-Length: ")
	header.WriteString(strconv.Itoa(len(body)))
	header.WriteString("\r\nCache-Control: no-store")
	header.WriteString("\r\nX-Content-Type-Options: nosniff")
	header.WriteString("\r\nX-CodeComm-Correlation-ID: ")
	header.WriteString(correlationID)
	if closeConnection {
		header.WriteString("\r\nConnection: close")
	}
	header.WriteString("\r\n\r\n")
	if err := writeFull(connection, []byte(header.String())); err != nil {
		return err
	}
	if len(body) > 0 {
		if err := writeFull(connection, body); err != nil {
			return err
		}
	}
	return nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if written > 0 {
			value = value[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
