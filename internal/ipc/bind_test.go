package ipc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

type invalidBoundClient struct {
	handler http.Handler
	panic   bool
}

func (client *invalidBoundClient) Handler() http.Handler {
	if client.panic {
		panic("invalid handler")
	}
	return client.handler
}

func (*invalidBoundClient) Disconnected(context.Context) {}

type nilReceiverBoundClient struct{}

func (*nilReceiverBoundClient) Handler() http.Handler {
	return http.NotFoundHandler()
}

func (*nilReceiverBoundClient) Disconnected(context.Context) {}

func TestBindResultConstructorsValidateAndSealMetadata(t *testing.T) {
	t.Parallel()

	client := &invalidBoundClient{handler: http.NotFoundHandler()}
	capability := make([]byte, 32)
	for index := range capability {
		capability[index] = byte(index)
	}

	operator, err := NewOperatorBindResult(client)
	if err != nil ||
		operator.kind != bindResultOperator ||
		operator.client != client ||
		len(operator.resumeCapability) != 0 {
		t.Fatalf("NewOperatorBindResult() = %#v, %v", operator, err)
	}
	resume, err := NewAgentResumeBindResult(client)
	if err != nil ||
		resume.kind != bindResultAgentResume ||
		resume.client != client ||
		len(resume.resumeCapability) != 0 {
		t.Fatalf("NewAgentResumeBindResult() = %#v, %v", resume, err)
	}
	launch, err := NewAgentLaunchBindResult(client, capability)
	if err != nil ||
		launch.kind != bindResultAgentLaunch ||
		launch.client != client ||
		len(launch.resumeCapability) != 32 {
		t.Fatalf("NewAgentLaunchBindResult() = %#v, %v", launch, err)
	}
	capability[0] ^= 0xff
	if launch.resumeCapability[0] != 0 {
		t.Fatal("launch result retained aliased capability memory")
	}

	tests := []struct {
		name      string
		construct func() (BindResult, error)
	}{
		{
			name: "nil operator client",
			construct: func() (BindResult, error) {
				return NewOperatorBindResult(nil)
			},
		},
		{
			name: "nil resume client",
			construct: func() (BindResult, error) {
				return NewAgentResumeBindResult(nil)
			},
		},
		{
			name: "typed nil client",
			construct: func() (BindResult, error) {
				var client *nilReceiverBoundClient
				return NewOperatorBindResult(client)
			},
		},
		{
			name: "nil handler",
			construct: func() (BindResult, error) {
				return NewOperatorBindResult(&invalidBoundClient{})
			},
		},
		{
			name: "panicking handler",
			construct: func() (BindResult, error) {
				return NewOperatorBindResult(&invalidBoundClient{panic: true})
			},
		},
		{
			name: "short capability",
			construct: func() (BindResult, error) {
				return NewAgentLaunchBindResult(client, make([]byte, 31))
			},
		},
		{
			name: "long capability",
			construct: func() (BindResult, error) {
				return NewAgentLaunchBindResult(client, make([]byte, 33))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := test.construct()
			if result.kind != 0 ||
				result.client != nil ||
				result.resumeCapability != nil ||
				!errors.Is(err, ErrBindRejected) {
				t.Fatalf(
					"constructor = %#v, %v; want zero, ErrBindRejected",
					result,
					err,
				)
			}
		})
	}
}

const (
	testClientInstanceID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000011")
	testSessionID        = domain.UUIDv7("01890f47-3e72-7000-8000-000000000012")
	testOtherSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000013")
	testWorkspaceID      = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
)

func TestDecodeBindRequestAcceptsClosedOperatorAndAgentForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		proof     string
		class     string
		wantClass ClientClass
	}{
		{
			name:      "operator",
			class:     "operator",
			wantClass: ClassOperator,
		},
		{
			name:      "agent opaque proof",
			class:     "agent",
			proof:     `,"agent_proof":{"kind":"launch","selector":"opaque"}`,
			wantClass: ClassAgent,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := fmt.Sprintf(
				`{"local_protocol_version":1,`+
					`"client_instance_id":%q,`+
					`"session_id":%q,`+
					`"workspace_id":%q,`+
					`"client_class":%q%s}`,
				testClientInstanceID,
				testSessionID,
				testWorkspaceID,
				test.class,
				test.proof,
			)
			request, err := decodeBindRequest([]byte(input))
			if err != nil {
				t.Fatalf("decodeBindRequest() error = %v", err)
			}
			if request.ProtocolVersion != LocalProtocolVersion ||
				request.ClientInstanceID != testClientInstanceID ||
				request.SessionID != testSessionID ||
				request.WorkspaceID != testWorkspaceID ||
				request.Class != test.wantClass {
				t.Fatalf("decoded request = %#v", request)
			}
			if test.wantClass == ClassAgent && string(request.AgentProof) == "" {
				t.Fatal("agent proof was not retained")
			}
		})
	}
}

func TestDecodeBindRequestRejectsOpenOrAmbiguousSchemas(t *testing.T) {
	t.Parallel()

	valid := fmt.Sprintf(
		`{"local_protocol_version":1,`+
			`"client_instance_id":%q,`+
			`"session_id":%q,`+
			`"workspace_id":%q,`+
			`"client_class":"operator"}`,
		testClientInstanceID,
		testSessionID,
		testWorkspaceID,
	)
	tests := []struct {
		name  string
		input string
	}{
		{"unknown field", valid[:len(valid)-1] + `,"origin":null}`},
		{
			"duplicate field",
			valid[:len(valid)-1] + `,"client_class":"operator"}`,
		},
		{
			"missing field",
			fmt.Sprintf(
				`{"local_protocol_version":1,"client_instance_id":%q,`+
					`"session_id":%q,"client_class":"operator"}`,
				testClientInstanceID,
				testSessionID,
			),
		},
		{
			"null field",
			fmt.Sprintf(
				`{"local_protocol_version":1,"client_instance_id":null,`+
					`"session_id":%q,"workspace_id":%q,`+
					`"client_class":"operator"}`,
				testSessionID,
				testWorkspaceID,
			),
		},
		{"trailing data", valid + `{}`},
		{"array", `[]`},
		{
			"operator proof",
			valid[:len(valid)-1] + `,"agent_proof":{}}`,
		},
		{
			"agent missing proof",
			fmt.Sprintf(
				`{"local_protocol_version":1,"client_instance_id":%q,`+
					`"session_id":%q,"workspace_id":%q,`+
					`"client_class":"agent"}`,
				testClientInstanceID,
				testSessionID,
				testWorkspaceID,
			),
		},
		{
			"agent null proof",
			fmt.Sprintf(
				`{"local_protocol_version":1,"client_instance_id":%q,`+
					`"session_id":%q,"workspace_id":%q,`+
					`"client_class":"agent","agent_proof":null}`,
				testClientInstanceID,
				testSessionID,
				testWorkspaceID,
			),
		},
		{
			"agent scalar proof",
			fmt.Sprintf(
				`{"local_protocol_version":1,"client_instance_id":%q,`+
					`"session_id":%q,"workspace_id":%q,`+
					`"client_class":"agent","agent_proof":"secret"}`,
				testClientInstanceID,
				testSessionID,
				testWorkspaceID,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeBindRequest([]byte(test.input))
			if !errors.Is(err, ErrInvalidBindRequest) {
				t.Fatalf(
					"decodeBindRequest() error = %v, want ErrInvalidBindRequest",
					err,
				)
			}
		})
	}
}

func FuzzDecodeBindRequest(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(fmt.Sprintf(
		`{"local_protocol_version":1,"client_instance_id":%q,`+
			`"session_id":%q,"workspace_id":%q,"client_class":"operator"}`,
		testClientInstanceID,
		testSessionID,
		testWorkspaceID,
	)))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeBindRequest(input)
	})
}
