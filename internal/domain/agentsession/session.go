package agentsession

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
)

const MaxAgentProfileIDBytes = 128

// ClientKind identifies the closed V1 agent adapter class.
type ClientKind string

const (
	ClientKindCodex  ClientKind = "codex"
	ClientKindClaude ClientKind = "claude"
	ClientKindOther  ClientKind = "other"
)

var clientKinds = [...]ClientKind{
	ClientKindCodex,
	ClientKindClaude,
	ClientKindOther,
}

// Valid reports whether kind is a closed V1 client kind.
func (kind ClientKind) Valid() bool {
	switch kind {
	case ClientKindCodex, ClientKindClaude, ClientKindOther:
		return true
	default:
		return false
	}
}

// ClientKinds returns every client kind in stable order.
func ClientKinds() []ClientKind {
	result := make([]ClientKind, len(clientKinds))
	copy(result, clientKinds[:])
	return result
}

// Session is the committed projection of one running agent instance.
type Session struct {
	ID             domain.UUIDv7
	DeviceID       domain.DeviceID
	ClientKind     ClientKind
	AgentProfileID *string
	State          State
	ResumeState    State
	WorkingRootID  domain.UUIDv7
	EndReason      EndReason
	EntityVersion  uint64
}

var (
	ErrInvalidID             = errors.New("agentsession: invalid ID")
	ErrInvalidDeviceID       = errors.New("agentsession: invalid device ID")
	ErrInvalidClientKind     = errors.New("agentsession: invalid client kind")
	ErrInvalidAgentProfileID = errors.New("agentsession: invalid agent profile ID")
	ErrInvalidWorkingRootID  = errors.New("agentsession: invalid working root ID")
	ErrInvalidEntityVersion  = errors.New("agentsession: invalid entity version")
)

// Validate verifies the session's local, persisted invariants. Checks requiring
// other committed rows, actor authorization, local capabilities, or policy
// remain reducer concerns.
func (session Session) Validate() error {
	if !session.ID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidID, session.ID)
	}
	if !session.DeviceID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidDeviceID, session.DeviceID)
	}
	if !session.ClientKind.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidClientKind, session.ClientKind)
	}
	if session.AgentProfileID != nil {
		profile := *session.AgentProfileID
		if !utf8.ValidString(profile) ||
			len(profile) < 1 ||
			len(profile) > MaxAgentProfileIDBytes {
			return fmt.Errorf(
				"%w: must be 1..%d UTF-8 bytes when set",
				ErrInvalidAgentProfileID,
				MaxAgentProfileIDBytes,
			)
		}
	}
	if err := session.Lifecycle().Validate(); err != nil {
		return err
	}
	if !session.WorkingRootID.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidWorkingRootID, session.WorkingRootID)
	}
	if session.EntityVersion < 1 || !domain.ValidUnsignedInteger(session.EntityVersion) {
		return fmt.Errorf(
			"%w: must be in 1..%d",
			ErrInvalidEntityVersion,
			domain.MaxSafeInteger,
		)
	}
	return nil
}

// Lifecycle returns the fields governed by the lifecycle transition table.
func (session Session) Lifecycle() Lifecycle {
	return Lifecycle{
		State:       session.State,
		ResumeState: session.ResumeState,
		EndReason:   session.EndReason,
	}
}
