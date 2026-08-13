package ipc

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLocalBindWireFixture(t *testing.T) {
	t.Parallel()

	const requestFixture = `{"client_class":"operator","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	request, err := decodeBindRequest([]byte(requestFixture))
	if err != nil {
		t.Fatalf("decode bind fixture: %v", err)
	}
	if request.Class != ClassOperator ||
		request.ClientInstanceID != testClientInstanceID ||
		request.SessionID != testSessionID ||
		request.WorkspaceID != testWorkspaceID {
		t.Fatalf("decoded bind fixture = %#v", request)
	}

	encoded, err := marshalJSON(bindResponse{
		LocalProtocolVersion: LocalProtocolVersion,
		ClientInstanceID:     string(request.ClientInstanceID),
		SessionID:            string(request.SessionID),
		WorkspaceID:          string(request.WorkspaceID),
		ClientClass:          request.Class.String(),
	}, MaxJSONBytes)
	if err != nil {
		t.Fatalf("encode bind fixture: %v", err)
	}
	const responseFixture = `{"client_class":"operator","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(encoded) != responseFixture {
		t.Fatalf("bind response fixture = %s", encoded)
	}
}

func TestAgentBindResponseFixture(t *testing.T) {
	t.Parallel()

	capability := bytes.Repeat([]byte{0x2a}, 32)
	encoded, err := marshalJSON(launchBindResponse{
		bindResponse: bindResponse{
			LocalProtocolVersion: LocalProtocolVersion,
			ClientInstanceID:     "01890f47-3e72-7000-8000-000000000011",
			SessionID:            "01890f47-3e72-7000-8000-000000000012",
			WorkspaceID:          "550e8400-e29b-41d4-a716-446655440000",
			ClientClass:          "agent",
		},
		ResumeCapability: "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio",
	}, MaxJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = `{"client_class":"agent","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"resume_capability":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio","session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(encoded) != fixture {
		t.Fatalf("agent bind response = %s, want %s", encoded, fixture)
	}

	resumeEncoded, err := marshalJSON(bindResponse{
		LocalProtocolVersion: LocalProtocolVersion,
		ClientInstanceID:     "01890f47-3e72-7000-8000-000000000011",
		SessionID:            "01890f47-3e72-7000-8000-000000000012",
		WorkspaceID:          "550e8400-e29b-41d4-a716-446655440000",
		ClientClass:          "agent",
	}, MaxJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	const resumeFixture = `{"client_class":"agent","client_instance_id":"01890f47-3e72-7000-8000-000000000011","local_protocol_version":1,"session_id":"01890f47-3e72-7000-8000-000000000012","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(resumeEncoded) != resumeFixture {
		t.Fatalf(
			"agent resume bind response = %s, want %s",
			resumeEncoded,
			resumeFixture,
		)
	}
	if len(capability) != 32 {
		t.Fatal("test capability length changed")
	}
}

func TestLocalProblemAndHTTPFramingFixture(t *testing.T) {
	t.Parallel()

	const correlationID = "00112233445566778899aabbccddeeff"
	failure := requestFailure{
		status: http.StatusConflict,
		code:   "local_bind_required",
		title:  "Connection must bind before use",
		close:  true,
	}
	body := marshalProblem(failure, correlationID)
	const problemFixture = `{"code":"local_bind_required","correlation_id":"00112233445566778899aabbccddeeff","retryable":false,"status":409,"title":"Connection must bind before use","type":"urn:codecomm:problem:local_bind_required"}`
	if string(body) != problemFixture {
		t.Fatalf("problem fixture = %s", body)
	}

	server, client := net.Pipe()
	writeResult := make(chan error, 1)
	go func() {
		defer server.Close()
		writeResult <- writeResponse(
			server,
			time.Second,
			failure.status,
			problemMediaType,
			body,
			correlationID,
			true,
		)
	}()
	framed, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read framed response: %v", err)
	}
	_ = client.Close()
	if err := <-writeResult; err != nil {
		t.Fatalf("writeResponse() error = %v", err)
	}
	const headerFixture = "HTTP/1.1 409 Conflict\r\n" +
		"Content-Type: application/problem+json\r\n" +
		"Content-Length: 205\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"X-CodeComm-Correlation-ID: 00112233445566778899aabbccddeeff\r\n" +
		"Connection: close\r\n\r\n"
	if string(framed) != headerFixture+problemFixture {
		t.Fatalf("HTTP response fixture = %q", framed)
	}
}
