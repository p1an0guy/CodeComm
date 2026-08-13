package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestReadRequestRejectsIncompleteAndStalledBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		write      func(net.Conn)
		idle       time.Duration
		wantCode   string
		wantStatus int
	}{
		{
			name: "incomplete",
			write: func(connection net.Conn) {
				_, _ = connection.Write([]byte(
					"POST /local/v1/bind HTTP/1.1\r\n" +
						"Host: local\r\n" +
						"Content-Type: application/json\r\n" +
						"Content-Length: 4\r\n\r\n{}",
				))
				_ = connection.Close()
			},
			idle:       time.Second,
			wantCode:   "local_incomplete_body",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "timeout",
			write: func(connection net.Conn) {
				_, _ = connection.Write([]byte(
					"POST /local/v1/bind HTTP/1.1\r\n" +
						"Host: local\r\n" +
						"Content-Type: application/json\r\n" +
						"Content-Length: 2\r\n\r\n",
				))
			},
			idle:       20 * time.Millisecond,
			wantCode:   "local_body_timeout",
			wantStatus: http.StatusRequestTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			go test.write(client)
			limits := productionLimits()
			limits.idleTimeout = test.idle
			_, _, err := readRequest(
				server,
				bufio.NewReader(server),
				limits,
				connectionAwaitingBind,
			)
			var failure *requestFailure
			if !errors.As(err, &failure) {
				t.Fatalf("readRequest() error = %v", err)
			}
			if failure.code != test.wantCode || failure.status != test.wantStatus {
				t.Fatalf("request failure = %#v", failure)
			}
		})
	}
}

type fuzzConnection struct {
	*bufio.Reader
}

func (connection *fuzzConnection) Read(value []byte) (int, error) {
	return connection.Reader.Read(value)
}

func (*fuzzConnection) Write([]byte) (int, error) {
	return 0, errors.New("write unsupported")
}

func (*fuzzConnection) Close() error {
	return nil
}

func (*fuzzConnection) LocalAddr() net.Addr {
	return fuzzAddress("local")
}

func (*fuzzConnection) RemoteAddr() net.Addr {
	return fuzzAddress("remote")
}

func (*fuzzConnection) SetDeadline(time.Time) error {
	return nil
}

func (*fuzzConnection) SetReadDeadline(time.Time) error {
	return nil
}

func (*fuzzConnection) SetWriteDeadline(time.Time) error {
	return nil
}

type fuzzAddress string

func (address fuzzAddress) Network() string {
	return "fuzz"
}

func (address fuzzAddress) String() string {
	return string(address)
}

func FuzzLocalHTTPFraming(f *testing.F) {
	f.Add([]byte("GET /local/v1/query/status HTTP/1.1\r\nHost: local\r\n\r\n"))
	f.Add([]byte(
		"POST /local/v1/bind HTTP/1.1\r\n" +
			"Host: local\r\nContent-Type: application/json\r\n" +
			"Content-Length: 2\r\n\r\n{}",
	))
	f.Add([]byte(
		"POST / HTTP/1.1\r\nHost: local\r\n" +
			"Content-Length: 2, 2\r\n\r\n{}",
	))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxHeaderBytes+MaxJSONBytes+1 {
			t.Skip()
		}
		connection := &fuzzConnection{
			Reader: bufio.NewReaderSize(
				bytes.NewReader(input),
				min(len(input)+1, MaxHeaderBytes+1),
			),
		}
		_, _, _ = readRequest(
			connection,
			bufio.NewReader(connection),
			productionLimits(),
			connectionAwaitingBind,
		)
	})
}
