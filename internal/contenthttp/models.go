// Package contenthttp serves the authenticated content-control HTTP/2 plane.
package contenthttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/replication"
)

const (
	SchemaVersion           uint64 = 1
	MaxRequiredCapabilities        = 256
	MaxCapabilityBytes             = 128
)

var ErrInvalidResponse = errors.New("content HTTP: invalid response")

// ProposalHop identifies whether an authenticated event request entered at
// this peer or was already relayed once.
type ProposalHop uint8

const (
	ProposalHopInitial ProposalHop = iota + 1
	ProposalHopForwarded
)

func (hop ProposalHop) valid() bool {
	return hop == ProposalHopInitial || hop == ProposalHopForwarded
}

// Service is the exact V1 content-control surface. Read implementations return
// immutable snapshots taken at one internally consistent state cut.
type Service interface {
	Session(context.Context) (SessionResponse, error)
	Peers(context.Context) (PeersResponse, error)
	Replication(context.Context, uint64) (replication.Batch, error)
	ProposeEvent(
		context.Context,
		domain.DeviceID,
		[]byte,
		ProposalHop,
	) (EventResult, error)
}

// SessionResponseInput contains the values copied into a SessionResponse.
type SessionResponseInput struct {
	SessionID            domain.UUIDv7
	WorkspaceID          domain.UUIDv4
	RecoveryGeneration   uint64
	ServerDeviceID       domain.DeviceID
	DaemonVersion        string
	MaxApplyLevel        uint64
	RequiredCapabilities []string
}

// SessionResponse is an immutable session-capability snapshot.
type SessionResponse struct {
	sessionID            domain.UUIDv7
	workspaceID          domain.UUIDv4
	recoveryGeneration   uint64
	serverDeviceID       domain.DeviceID
	daemonVersion        string
	maxApplyLevel        uint64
	requiredCapabilities []string
	valid                bool
}

// NewSessionResponse validates, sorts, deduplicates, and copies a session
// response.
func NewSessionResponse(input SessionResponseInput) (SessionResponse, error) {
	capabilities, err := normalizeCapabilities(input.RequiredCapabilities)
	if err != nil ||
		!input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!input.ServerDeviceID.Valid() ||
		!device.ValidDaemonVersion(input.DaemonVersion) ||
		input.MaxApplyLevel < 1 ||
		input.MaxApplyLevel > domain.MaxApplyLevel {
		return SessionResponse{}, ErrInvalidResponse
	}
	return SessionResponse{
		sessionID:            input.SessionID,
		workspaceID:          input.WorkspaceID,
		recoveryGeneration:   input.RecoveryGeneration,
		serverDeviceID:       input.ServerDeviceID,
		daemonVersion:        input.DaemonVersion,
		maxApplyLevel:        input.MaxApplyLevel,
		requiredCapabilities: capabilities,
		valid:                true,
	}, nil
}

// SessionID returns the response session identifier.
func (response SessionResponse) SessionID() domain.UUIDv7 {
	return response.sessionID
}

// WorkspaceID returns the response workspace identifier.
func (response SessionResponse) WorkspaceID() domain.UUIDv4 {
	return response.workspaceID
}

// RecoveryGeneration returns the response recovery generation.
func (response SessionResponse) RecoveryGeneration() uint64 {
	return response.recoveryGeneration
}

// ServerDeviceID returns the serving device identifier.
func (response SessionResponse) ServerDeviceID() domain.DeviceID {
	return response.serverDeviceID
}

// DaemonVersion returns the serving daemon's canonical SemVer.
func (response SessionResponse) DaemonVersion() string {
	return response.daemonVersion
}

// MaxApplyLevel returns the serving daemon's maximum apply level.
func (response SessionResponse) MaxApplyLevel() uint64 {
	return response.maxApplyLevel
}

// RequiredCapabilities returns a private copy in canonical order.
func (response SessionResponse) RequiredCapabilities() []string {
	return slices.Clone(response.requiredCapabilities)
}

// PeerMemberInput contains one committed member and its optional exact,
// previously authenticated endpoint-set object.
type PeerMemberInput struct {
	DeviceID      domain.DeviceID
	Role          device.Role
	Status        device.Status
	EntityVersion uint64
	EndpointSet   []byte
}

// PeerMember is an immutable committed member response.
type PeerMember struct {
	deviceID      domain.DeviceID
	role          device.Role
	status        device.Status
	entityVersion uint64
	endpointSet   []byte
	valid         bool
}

// NewPeerMember validates and copies one member. EndpointSet remains opaque;
// the caller is responsible for supplying the latest target-authenticated set.
func NewPeerMember(input PeerMemberInput) (PeerMember, error) {
	if !input.DeviceID.Valid() ||
		!input.Role.Valid() ||
		!input.Status.Valid() ||
		input.EntityVersion < 1 ||
		!domain.ValidUnsignedInteger(input.EntityVersion) {
		return PeerMember{}, ErrInvalidResponse
	}
	endpointSet, err := copyCanonicalEndpointSet(input.EndpointSet)
	if err != nil {
		return PeerMember{}, err
	}
	return PeerMember{
		deviceID:      input.DeviceID,
		role:          input.Role,
		status:        input.Status,
		entityVersion: input.EntityVersion,
		endpointSet:   endpointSet,
		valid:         true,
	}, nil
}

// DeviceID returns the committed device identifier.
func (member PeerMember) DeviceID() domain.DeviceID {
	return member.deviceID
}

// Role returns the exact committed role.
func (member PeerMember) Role() device.Role {
	return member.role
}

// Status returns the exact committed membership status.
func (member PeerMember) Status() device.Status {
	return member.status
}

// EntityVersion returns the exact committed entity version.
func (member PeerMember) EntityVersion() uint64 {
	return member.entityVersion
}

// EndpointSet returns a private copy of the exact signed JCS object. Nil means
// that no current set is available for relay.
func (member PeerMember) EndpointSet() []byte {
	return bytes.Clone(member.endpointSet)
}

// PeersResponseInput contains the values copied into a PeersResponse.
type PeersResponseInput struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	ServerDeviceID     domain.DeviceID
	Members            []PeerMember
}

// PeersResponse is an immutable committed roster plus endpoint-relay snapshot.
type PeersResponse struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	serverDeviceID     domain.DeviceID
	members            []PeerMember
	valid              bool
}

// NewPeersResponse validates, sorts, and copies a peers response.
func NewPeersResponse(input PeersResponseInput) (PeersResponse, error) {
	if !input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(input.RecoveryGeneration) ||
		!input.ServerDeviceID.Valid() ||
		len(input.Members) < 1 ||
		len(input.Members) > int(policy.MaxMemberDevices) {
		return PeersResponse{}, ErrInvalidResponse
	}
	members := make([]PeerMember, len(input.Members))
	serverFound := false
	for index, member := range input.Members {
		copied, err := copyPeerMember(member)
		if err != nil {
			return PeersResponse{}, err
		}
		members[index] = copied
		serverFound = serverFound || copied.deviceID == input.ServerDeviceID
	}
	slices.SortFunc(members, func(left, right PeerMember) int {
		return bytes.Compare([]byte(left.deviceID), []byte(right.deviceID))
	})
	for index := 1; index < len(members); index++ {
		if members[index-1].deviceID == members[index].deviceID {
			return PeersResponse{}, ErrInvalidResponse
		}
	}
	if !serverFound {
		return PeersResponse{}, ErrInvalidResponse
	}
	return PeersResponse{
		sessionID:          input.SessionID,
		workspaceID:        input.WorkspaceID,
		recoveryGeneration: input.RecoveryGeneration,
		serverDeviceID:     input.ServerDeviceID,
		members:            members,
		valid:              true,
	}, nil
}

// SessionID returns the response session identifier.
func (response PeersResponse) SessionID() domain.UUIDv7 {
	return response.sessionID
}

// WorkspaceID returns the response workspace identifier.
func (response PeersResponse) WorkspaceID() domain.UUIDv4 {
	return response.workspaceID
}

// RecoveryGeneration returns the response recovery generation.
func (response PeersResponse) RecoveryGeneration() uint64 {
	return response.recoveryGeneration
}

// ServerDeviceID returns the serving device identifier.
func (response PeersResponse) ServerDeviceID() domain.DeviceID {
	return response.serverDeviceID
}

// Members returns a deep copy in canonical device-ID order.
func (response PeersResponse) Members() []PeerMember {
	members := make([]PeerMember, len(response.members))
	for index, member := range response.members {
		members[index], _ = copyPeerMember(member)
	}
	return members
}

type sessionWire struct {
	SchemaVersion        uint64   `json:"schema_version"`
	SessionID            string   `json:"session_id"`
	WorkspaceID          string   `json:"workspace_id"`
	RecoveryGeneration   uint64   `json:"recovery_generation"`
	ServerDeviceID       string   `json:"server_device_id"`
	DaemonVersion        string   `json:"daemon_version"`
	MaxApplyLevel        uint64   `json:"max_apply_level"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type peersWire struct {
	SchemaVersion      uint64       `json:"schema_version"`
	SessionID          string       `json:"session_id"`
	WorkspaceID        string       `json:"workspace_id"`
	RecoveryGeneration uint64       `json:"recovery_generation"`
	ServerDeviceID     string       `json:"server_device_id"`
	Members            []memberWire `json:"members"`
}

type memberWire struct {
	DeviceID      string  `json:"device_id"`
	Role          string  `json:"role"`
	Status        string  `json:"status"`
	EntityVersion uint64  `json:"entity_version"`
	EndpointSet   *string `json:"endpoint_set,omitempty"`
}

func (response SessionResponse) canonicalBytes() ([]byte, error) {
	if !response.valid {
		return nil, ErrInvalidResponse
	}
	return marshalCanonical(sessionWire{
		SchemaVersion:        SchemaVersion,
		SessionID:            string(response.sessionID),
		WorkspaceID:          string(response.workspaceID),
		RecoveryGeneration:   response.recoveryGeneration,
		ServerDeviceID:       string(response.serverDeviceID),
		DaemonVersion:        response.daemonVersion,
		MaxApplyLevel:        response.maxApplyLevel,
		RequiredCapabilities: slices.Clone(response.requiredCapabilities),
	})
}

func (response PeersResponse) canonicalBytes() ([]byte, error) {
	if !response.valid ||
		len(response.members) < 1 ||
		len(response.members) > int(policy.MaxMemberDevices) {
		return nil, ErrInvalidResponse
	}
	members := make([]memberWire, len(response.members))
	for index, member := range response.members {
		if !member.valid {
			return nil, ErrInvalidResponse
		}
		wire := memberWire{
			DeviceID:      string(member.deviceID),
			Role:          string(member.role),
			Status:        string(member.status),
			EntityVersion: member.entityVersion,
		}
		if len(member.endpointSet) != 0 {
			encoded := codec.EncodeBase64URL(member.endpointSet)
			wire.EndpointSet = &encoded
		}
		members[index] = wire
	}
	return marshalCanonical(peersWire{
		SchemaVersion:      SchemaVersion,
		SessionID:          string(response.sessionID),
		WorkspaceID:        string(response.workspaceID),
		RecoveryGeneration: response.recoveryGeneration,
		ServerDeviceID:     string(response.serverDeviceID),
		Members:            members,
	})
}

func normalizeCapabilities(input []string) ([]string, error) {
	if len(input) > MaxRequiredCapabilities {
		return nil, ErrInvalidResponse
	}
	result := slices.Clone(input)
	for _, capability := range result {
		if !validCapability(capability) {
			return nil, ErrInvalidResponse
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if result == nil {
		result = []string{}
	}
	return result, nil
}

func validCapability(value string) bool {
	if len(value) < 1 || len(value) > MaxCapabilityBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func copyCanonicalEndpointSet(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if len(input) > discovery.MaxEndpointSetBytes {
		return nil, ErrInvalidResponse
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return nil, fmt.Errorf("%w: endpoint set", ErrInvalidResponse)
	}
	return bytes.Clone(input), nil
}

func copyPeerMember(member PeerMember) (PeerMember, error) {
	if !member.valid {
		return PeerMember{}, ErrInvalidResponse
	}
	return NewPeerMember(PeerMemberInput{
		DeviceID:      member.deviceID,
		Role:          member.role,
		Status:        member.status,
		EntityVersion: member.entityVersion,
		EndpointSet:   member.endpointSet,
	})
}

func marshalCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidResponse, err)
	}
	canonical, err := codec.CanonicalizeSignedObject(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %v", ErrInvalidResponse, err)
	}
	return canonical, nil
}
