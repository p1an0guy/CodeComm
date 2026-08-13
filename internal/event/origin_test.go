package event

import (
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	testAgentSessionID = domain.UUIDv7("01890f47-3e72-7000-8000-000000000003")
	testBootID         = domain.UUIDv7("01890f47-3e72-7000-8000-000000000004")
)

func TestIPCBindingsConstructOnlyTheirFixedOriginClass(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	profile := "codex/default"
	tests := []struct {
		name        string
		binding     Binding
		wantActor   ActorType
		wantProfile string
		wantAgent   domain.UUIDv7
		wantBoot    domain.UUIDv7
	}{
		{
			name:        "MCP agent",
			binding:     mustMCPBinding(t, deviceID, testAgentSessionID, &profile),
			wantActor:   ActorAgent,
			wantProfile: profile,
			wantAgent:   testAgentSessionID,
		},
		{
			name:      "operator",
			binding:   mustOperatorBinding(t, deviceID, testBootID),
			wantActor: ActorHuman,
			wantBoot:  testBootID,
		},
		{
			name:      "daemon",
			binding:   mustDaemonBinding(t, deviceID, testBootID),
			wantActor: ActorDaemon,
			wantBoot:  testBootID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.binding.ActorType() != test.wantActor {
				t.Fatalf("binding actor = %q, want %q", test.binding.ActorType(), test.wantActor)
			}
			origin, err := test.binding.Origin(1)
			if err != nil {
				t.Fatalf("Origin() error = %v", err)
			}
			if origin.DeviceID() != deviceID ||
				origin.ActorType() != test.wantActor ||
				origin.AgentSessionID() != test.wantAgent ||
				origin.OriginBootID() != test.wantBoot ||
				origin.Sequence() != 1 {
				t.Fatalf("origin = %#v", origin)
			}
			profileValue, profilePresent := origin.AgentProfileID()
			if profileValue != test.wantProfile || profilePresent != (test.wantProfile != "") {
				t.Fatalf(
					"origin profile = %q, %t; want %q, %t",
					profileValue,
					profilePresent,
					test.wantProfile,
					test.wantProfile != "",
				)
			}
		})
	}
}

func TestMCPBindingCannotEmitHumanOnlyKind(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	binding := mustMCPBinding(t, deviceID, testAgentSessionID, nil)
	command := validCommand(KindTaskCancelled)
	version := uint64(1)
	command.ExpectedEntityVersion = &version

	_, err := BuildProposal(command, binding, validBuildContext())
	if !errors.Is(err, ErrActorNotAllowed) {
		t.Fatalf("BuildProposal() error = %v, want ErrActorNotAllowed", err)
	}
}

func TestBindingRejectsMalformedIdentityAndScope(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	profileOverLimit := strings.Repeat("x", MaxAgentProfileIDBytes+1)
	invalidUTF8 := string([]byte{0xff})

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{
			name: "invalid device",
			call: func() error {
				_, err := NewMCPBinding("", testAgentSessionID, nil)
				return err
			},
			want: ErrInvalidOrigin,
		},
		{
			name: "invalid agent session",
			call: func() error {
				_, err := NewMCPBinding(deviceID, "", nil)
				return err
			},
			want: ErrInvalidOrigin,
		},
		{
			name: "profile over limit",
			call: func() error {
				_, err := NewMCPBinding(deviceID, testAgentSessionID, &profileOverLimit)
				return err
			},
			want: ErrInvalidOrigin,
		},
		{
			name: "invalid UTF-8 profile",
			call: func() error {
				_, err := NewMCPBinding(deviceID, testAgentSessionID, &invalidUTF8)
				return err
			},
			want: ErrInvalidOrigin,
		},
		{
			name: "invalid boot",
			call: func() error {
				_, err := NewLocalAuthority(deviceID, "")
				return err
			},
			want: ErrInvalidOrigin,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.call(); !errors.Is(err, test.want) {
				t.Fatalf("constructor error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOriginSequenceBounds(t *testing.T) {
	t.Parallel()

	deviceID, _, _ := testIdentity(t)
	binding := mustDaemonBinding(t, deviceID, testBootID)
	for _, sequence := range []uint64{0, domain.MaxSafeInteger + 1} {
		if _, err := binding.Origin(sequence); !errors.Is(err, ErrInvalidOriginSequence) {
			t.Errorf("Origin(%d) error = %v, want ErrInvalidOriginSequence", sequence, err)
		}
	}
	if _, err := binding.Origin(domain.MaxSafeInteger); err != nil {
		t.Fatalf("Origin(max safe integer) error = %v", err)
	}
}
