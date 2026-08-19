// Package operatorcommand defines the narrow mutation boundary between the
// human-only local operator API and the durable boot-origin outbox.
package operatorcommand

import (
	"context"
	"errors"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/localcommand"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	OperationSetVoters  = "cluster.set-voters"
	OperationRevokePeer = "peer.revoke"
)

var ErrInvalidCommand = errors.New("operatorcommand: invalid command")

type Request struct {
	ClientInstanceID domain.UUIDv7
	Command          localcommand.Request
}

type Result struct {
	EventID   domain.UUIDv7
	Outcome   store.CommandOutcome
	Duplicate bool
}

// Submitter accepts only the two Phase 3 owner mutations. Implementations must
// independently enforce the operation-to-kind mapping before signing.
type Submitter interface {
	SubmitOperatorCommand(context.Context, Request) (Result, error)
}

func (request Request) Validate() error {
	if !request.ClientInstanceID.Valid() ||
		!request.Command.RequestID.Valid() ||
		len(request.Command.Canonical) == 0 {
		return ErrInvalidCommand
	}
	command := request.Command.Command
	if command.ExpectedEntityVersion == nil ||
		*command.ExpectedEntityVersion < 1 ||
		!domain.ValidUnsignedInteger(*command.ExpectedEntityVersion) {
		return ErrInvalidCommand
	}
	switch request.Command.Operation {
	case OperationSetVoters:
		if command.Kind != event.KindMembershipVoterSetChanged {
			return ErrInvalidCommand
		}
	case OperationRevokePeer:
		if command.Kind != event.KindMembershipDeviceRevoked {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	return nil
}
