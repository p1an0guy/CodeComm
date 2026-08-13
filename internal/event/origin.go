package event

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxAgentProfileIDBytes = 128

var (
	ErrInvalidOrigin         = errors.New("event: invalid origin")
	ErrInvalidOriginSequence = errors.New("event: invalid origin sequence")
)

// Binding is daemon-owned identity established by an authenticated local IPC
// channel. Its fields are private so callers cannot pass an actor string into
// event construction.
type Binding struct {
	deviceID       domain.DeviceID
	actorType      ActorType
	agentProfileID string
	profilePresent bool
	agentSessionID domain.UUIDv7
	originBootID   domain.UUIDv7
}

// NewMCPBinding creates the only binding available to an MCP adapter. It is
// unconditionally agent-originated.
func NewMCPBinding(
	deviceID domain.DeviceID,
	agentSessionID domain.UUIDv7,
	agentProfileID *string,
) (Binding, error) {
	binding := Binding{
		deviceID:       deviceID,
		actorType:      ActorAgent,
		agentSessionID: agentSessionID,
	}
	if agentProfileID != nil {
		binding.agentProfileID = *agentProfileID
		binding.profilePresent = true
	}
	if err := binding.validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// LocalAuthority is a daemon-composition-root capability for constructing
// privileged local bindings. Production call sites are restricted by the
// authority-callsite test to codecommd and the verified IPC package; MCP code
// receives only an already-created agent binding.
type LocalAuthority struct {
	deviceID     domain.DeviceID
	originBootID domain.UUIDv7
}

// NewLocalAuthority validates one daemon boot's privileged binding
// capability. Callers must not pass this value into agent or MCP packages.
func NewLocalAuthority(
	deviceID domain.DeviceID,
	originBootID domain.UUIDv7,
) (LocalAuthority, error) {
	authority := LocalAuthority{
		deviceID:     deviceID,
		originBootID: originBootID,
	}
	if _, err := authority.binding(ActorHuman); err != nil {
		return LocalAuthority{}, err
	}
	return authority, nil
}

// OperatorBinding returns a human binding for the verified local CLI/TUI
// operator channel.
func (authority LocalAuthority) OperatorBinding() (Binding, error) {
	return authority.binding(ActorHuman)
}

// DaemonBinding returns a binding for daemon-initiated work.
func (authority LocalAuthority) DaemonBinding() (Binding, error) {
	return authority.binding(ActorDaemon)
}

func (authority LocalAuthority) binding(actor ActorType) (Binding, error) {
	binding := Binding{
		deviceID:     authority.deviceID,
		actorType:    actor,
		originBootID: authority.originBootID,
	}
	if err := binding.validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// ActorType returns the binding's fixed principal class.
func (binding Binding) ActorType() ActorType {
	return binding.actorType
}

// Origin constructs a signed-origin value for the binding's reserved
// sequence. Sequence allocation and durability belong to the store layer.
func (binding Binding) Origin(sequence uint64) (Origin, error) {
	if err := binding.validate(); err != nil {
		return Origin{}, err
	}
	if sequence < 1 || !domain.ValidUnsignedInteger(sequence) {
		return Origin{}, fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidOriginSequence,
			domain.MaxSafeInteger,
		)
	}
	return Origin{
		deviceID:       binding.deviceID,
		actorType:      binding.actorType,
		agentProfileID: binding.agentProfileID,
		profilePresent: binding.profilePresent,
		agentSessionID: binding.agentSessionID,
		originBootID:   binding.originBootID,
		sequence:       sequence,
	}, nil
}

func (binding Binding) validate() error {
	if !binding.deviceID.Valid() || !binding.actorType.Valid() {
		return ErrInvalidOrigin
	}
	switch binding.actorType {
	case ActorAgent:
		if !binding.agentSessionID.Valid() ||
			binding.originBootID != "" ||
			binding.profilePresent && !validAgentProfileID(binding.agentProfileID) ||
			!binding.profilePresent && binding.agentProfileID != "" {
			return ErrInvalidOrigin
		}
	case ActorHuman, ActorDaemon:
		if binding.agentSessionID != "" ||
			!binding.originBootID.Valid() ||
			binding.profilePresent ||
			binding.agentProfileID != "" {
			return ErrInvalidOrigin
		}
	default:
		return ErrInvalidOrigin
	}
	return nil
}

func validAgentProfileID(profile string) bool {
	return len(profile) >= 1 &&
		len(profile) <= MaxAgentProfileIDBytes &&
		utf8.ValidString(profile)
}

// Origin is the immutable daemon-constructed identity block carried by a
// signed proposal.
type Origin struct {
	deviceID       domain.DeviceID
	actorType      ActorType
	agentProfileID string
	profilePresent bool
	agentSessionID domain.UUIDv7
	originBootID   domain.UUIDv7
	sequence       uint64
}

// DeviceID returns the installation identity.
func (origin Origin) DeviceID() domain.DeviceID {
	return origin.deviceID
}

// ActorType returns the daemon-authenticated actor class.
func (origin Origin) ActorType() ActorType {
	return origin.actorType
}

// AgentProfileID returns the optional agent profile.
func (origin Origin) AgentProfileID() (string, bool) {
	return origin.agentProfileID, origin.profilePresent
}

// AgentSessionID returns the agent scope ID, or the zero value for a boot
// scope.
func (origin Origin) AgentSessionID() domain.UUIDv7 {
	return origin.agentSessionID
}

// OriginBootID returns the boot scope ID, or the zero value for an agent
// scope.
func (origin Origin) OriginBootID() domain.UUIDv7 {
	return origin.originBootID
}

// Sequence returns the monotonically reserved sequence in this origin scope.
func (origin Origin) Sequence() uint64 {
	return origin.sequence
}

func (origin Origin) validate() error {
	if !origin.deviceID.Valid() ||
		!origin.actorType.Valid() ||
		origin.sequence < 1 ||
		!domain.ValidUnsignedInteger(origin.sequence) {
		return ErrInvalidOrigin
	}
	switch origin.actorType {
	case ActorAgent:
		if !origin.agentSessionID.Valid() ||
			origin.originBootID != "" ||
			origin.profilePresent && !validAgentProfileID(origin.agentProfileID) ||
			!origin.profilePresent && origin.agentProfileID != "" {
			return ErrInvalidOrigin
		}
	case ActorHuman, ActorDaemon:
		if origin.agentSessionID != "" ||
			!origin.originBootID.Valid() ||
			origin.profilePresent ||
			origin.agentProfileID != "" {
			return ErrInvalidOrigin
		}
	default:
		return ErrInvalidOrigin
	}
	return nil
}
