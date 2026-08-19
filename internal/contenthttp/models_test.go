package contenthttp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

const (
	testSessionID      = domain.UUIDv7("01890f47-3e72-7000-8000-000000000701")
	testWorkspaceID    = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
	testServerDeviceID = domain.DeviceID(
		"cc11111111111111111111111111111111111111111111111111111111111111111",
	)
	testPeerDeviceID = domain.DeviceID(
		"cc12222222222222222222222222222222222222222222222222222222222222222",
	)
)

func TestSessionResponseCanonicalOrderingAndImmutability(t *testing.T) {
	t.Parallel()

	capabilities := []string{
		"zeta", "codecomm/v1/endpoint-hints", "alpha", "zeta",
	}
	response, err := NewSessionResponse(SessionResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 3, ServerDeviceID: testServerDeviceID,
		DaemonVersion: "1.2.3", MaxApplyLevel: 7,
		RequiredCapabilities: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities[0] = "mutated"
	wantCapabilities := []string{
		"alpha", "codecomm/v1/endpoint-hints", "zeta",
	}
	gotCapabilities := response.RequiredCapabilities()
	if fmt.Sprint(gotCapabilities) != fmt.Sprint(wantCapabilities) {
		t.Fatalf("capabilities = %q, want %q", gotCapabilities, wantCapabilities)
	}
	gotCapabilities[0] = "mutated"
	if response.RequiredCapabilities()[0] != "alpha" {
		t.Fatal("RequiredCapabilities returned aliased storage")
	}
	if response.SessionID() != testSessionID ||
		response.WorkspaceID() != testWorkspaceID ||
		response.RecoveryGeneration() != 3 ||
		response.ServerDeviceID() != testServerDeviceID ||
		response.DaemonVersion() != "1.2.3" ||
		response.MaxApplyLevel() != 7 {
		t.Fatalf("session accessors changed values: %+v", response)
	}

	encoded, err := response.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"daemon_version":"1.2.3","max_apply_level":7,"recovery_generation":3,"required_capabilities":["alpha","codecomm/v1/endpoint-hints","zeta"],"schema_version":1,"server_device_id":"cc11111111111111111111111111111111111111111111111111111111111111111","session_id":"01890f47-3e72-7000-8000-000000000701","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(encoded) != want {
		t.Fatalf("canonical session = %s\nwant = %s", encoded, want)
	}
}

func TestPeersResponseCanonicalOpaqueRelayAndImmutability(t *testing.T) {
	t.Parallel()

	endpointSet := []byte(`{"a":1,"signature":"AA"}`)
	server, err := NewPeerMember(PeerMemberInput{
		DeviceID: testServerDeviceID, Role: device.RoleOwner,
		Status: device.StatusActive, EntityVersion: 7,
		EndpointSet: endpointSet,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpointSet[2] = 'z'
	peer, err := NewPeerMember(PeerMemberInput{
		DeviceID: testPeerDeviceID, Role: device.RoleEditor,
		Status: device.StatusRequiresReadmission, EntityVersion: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewPeersResponse(PeersResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 3, ServerDeviceID: testServerDeviceID,
		Members: []PeerMember{peer, server},
	})
	if err != nil {
		t.Fatal(err)
	}
	members := response.Members()
	if len(members) != 2 ||
		members[0].DeviceID() != testServerDeviceID ||
		members[1].DeviceID() != testPeerDeviceID ||
		members[0].Role() != device.RoleOwner ||
		members[1].Status() != device.StatusRequiresReadmission ||
		members[0].EntityVersion() != 7 {
		t.Fatalf("members = %+v", members)
	}
	mutated := members[0].EndpointSet()
	mutated[0] = '['
	members[0] = PeerMember{}
	if response.Members()[0].EndpointSet()[0] != '{' {
		t.Fatal("Members returned aliased endpoint-set storage")
	}

	encoded, err := response.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"members":[{"device_id":"cc11111111111111111111111111111111111111111111111111111111111111111","endpoint_set":"eyJhIjoxLCJzaWduYXR1cmUiOiJBQSJ9","entity_version":7,"role":"owner","status":"active"},{"device_id":"cc12222222222222222222222222222222222222222222222222222222222222222","entity_version":9,"role":"editor","status":"requires_readmission"}],"recovery_generation":3,"schema_version":1,"server_device_id":"cc11111111111111111111111111111111111111111111111111111111111111111","session_id":"01890f47-3e72-7000-8000-000000000701","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}`
	if string(encoded) != want {
		t.Fatalf("canonical peers = %s\nwant = %s", encoded, want)
	}
}

func TestSessionResponseRejectsInvalidOrUnboundedValues(t *testing.T) {
	t.Parallel()

	valid := SessionResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 1, ServerDeviceID: testServerDeviceID,
		DaemonVersion: "1.0.0", MaxApplyLevel: 1,
		RequiredCapabilities: []string{"codecomm/v1/events"},
	}
	tests := []struct {
		name   string
		mutate func(*SessionResponseInput)
	}{
		{"session", func(v *SessionResponseInput) { v.SessionID = "bad" }},
		{"workspace", func(v *SessionResponseInput) { v.WorkspaceID = "bad" }},
		{"generation", func(v *SessionResponseInput) { v.RecoveryGeneration = domain.MaxSafeInteger + 1 }},
		{"device", func(v *SessionResponseInput) { v.ServerDeviceID = "bad" }},
		{"daemon version", func(v *SessionResponseInput) { v.DaemonVersion = "latest" }},
		{"zero apply level", func(v *SessionResponseInput) { v.MaxApplyLevel = 0 }},
		{"high apply level", func(v *SessionResponseInput) { v.MaxApplyLevel = domain.MaxApplyLevel + 1 }},
		{"empty capability", func(v *SessionResponseInput) { v.RequiredCapabilities = []string{""} }},
		{"control capability", func(v *SessionResponseInput) { v.RequiredCapabilities = []string{"bad\nvalue"} }},
		{"long capability", func(v *SessionResponseInput) {
			v.RequiredCapabilities = []string{strings.Repeat("x", MaxCapabilityBytes+1)}
		}},
		{"too many capabilities", func(v *SessionResponseInput) {
			v.RequiredCapabilities = make([]string, MaxRequiredCapabilities+1)
			for i := range v.RequiredCapabilities {
				v.RequiredCapabilities[i] = fmt.Sprintf("cap-%03d", i)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			input.RequiredCapabilities = append([]string(nil), valid.RequiredCapabilities...)
			test.mutate(&input)
			if _, err := NewSessionResponse(input); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("NewSessionResponse() error = %v", err)
			}
		})
	}
	if _, err := (SessionResponse{}).canonicalBytes(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("zero response canonical error = %v", err)
	}
}

func TestPeerModelsRejectInvalidBoundsAndAmbiguity(t *testing.T) {
	t.Parallel()

	validInput := PeerMemberInput{
		DeviceID: testServerDeviceID, Role: device.RoleOwner,
		Status: device.StatusActive, EntityVersion: 1,
	}
	memberTests := []struct {
		name   string
		mutate func(*PeerMemberInput)
	}{
		{"device", func(v *PeerMemberInput) { v.DeviceID = "bad" }},
		{"role", func(v *PeerMemberInput) { v.Role = "admin" }},
		{"status", func(v *PeerMemberInput) { v.Status = "pending" }},
		{"zero version", func(v *PeerMemberInput) { v.EntityVersion = 0 }},
		{"high version", func(v *PeerMemberInput) { v.EntityVersion = domain.MaxSafeInteger + 1 }},
		{"noncanonical endpoint set", func(v *PeerMemberInput) { v.EndpointSet = []byte(`{"z":1,"a":2}`) }},
		{"nonobject endpoint set", func(v *PeerMemberInput) { v.EndpointSet = []byte(`[]`) }},
		{"oversized endpoint set", func(v *PeerMemberInput) { v.EndpointSet = bytes.Repeat([]byte{'x'}, 16<<10+1) }},
	}
	for _, test := range memberTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput
			test.mutate(&input)
			if _, err := NewPeerMember(input); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("NewPeerMember() error = %v", err)
			}
		})
	}

	server := mustPeerMember(t, testServerDeviceID)
	peer := mustPeerMember(t, testPeerDeviceID)
	base := PeersResponseInput{
		SessionID: testSessionID, WorkspaceID: testWorkspaceID,
		RecoveryGeneration: 1, ServerDeviceID: testServerDeviceID,
		Members: []PeerMember{server, peer},
	}
	responseTests := []struct {
		name   string
		mutate func(*PeersResponseInput)
	}{
		{"empty", func(v *PeersResponseInput) { v.Members = nil }},
		{"duplicate", func(v *PeersResponseInput) { v.Members = []PeerMember{server, server} }},
		{"zero member", func(v *PeersResponseInput) { v.Members = []PeerMember{{}, server} }},
		{"missing server", func(v *PeersResponseInput) { v.Members = []PeerMember{peer} }},
		{"bad session", func(v *PeersResponseInput) { v.SessionID = "bad" }},
		{"bad workspace", func(v *PeersResponseInput) { v.WorkspaceID = "bad" }},
		{"bad generation", func(v *PeersResponseInput) { v.RecoveryGeneration = domain.MaxSafeInteger + 1 }},
		{"bad server", func(v *PeersResponseInput) { v.ServerDeviceID = "bad" }},
		{"too many", func(v *PeersResponseInput) {
			v.Members = make([]PeerMember, int(policy.MaxMemberDevices)+1)
			for index := range v.Members {
				v.Members[index] = mustPeerMember(t, testDeviceID(index+1))
			}
			v.ServerDeviceID = v.Members[0].DeviceID()
		}},
	}
	for _, test := range responseTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := base
			input.Members = append([]PeerMember(nil), base.Members...)
			test.mutate(&input)
			if _, err := NewPeersResponse(input); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("NewPeersResponse() error = %v", err)
			}
		})
	}
	if _, err := (PeersResponse{}).canonicalBytes(); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("zero peers canonical error = %v", err)
	}
}

func mustPeerMember(t testing.TB, id domain.DeviceID) PeerMember {
	t.Helper()
	member, err := NewPeerMember(PeerMemberInput{
		DeviceID: id, Role: device.RoleEditor,
		Status: device.StatusActive, EntityVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func testDeviceID(value int) domain.DeviceID {
	return domain.DeviceID(fmt.Sprintf("cc1%064x", value))
}
