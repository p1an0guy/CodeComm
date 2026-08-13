package reducer

import (
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
)

func reduceAgentSessionStarted(context reductionContext) (Outcome, error) {
	payload, code := decodePayload(
		context.proposal.Payload,
		[]string{"client_kind", "working_root_id"},
		nil,
	)
	if code != "" {
		return context.reject(code), nil
	}
	clientText, ok := decodeValue[string](payload, "client_kind")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	rootText, ok := decodeValue[string](payload, "working_root_id")
	if !ok {
		return context.reject(CodeInvalidPayload), nil
	}
	clientKind := agentsession.ClientKind(clientText)
	workingRootID := domain.UUIDv7(rootText)
	if !clientKind.Valid() || !workingRootID.Valid() {
		return context.reject(CodeInvalidPayload), nil
	}

	id := proposalAgentSessionID(context)
	if existing, exists := context.state.agentSessions[id]; exists {
		if existing.ID != id {
			return Outcome{}, invalidState(
				"agent-session map key does not match collided row",
			)
		}
		if err := existing.Validate(); err != nil {
			return Outcome{}, invalidState(
				"collided agent session %q: %v",
				id,
				err,
			)
		}
		return context.reject(CodeEntityAlreadyExists), nil
	}
	values, err := validatePolicy(context)
	if err != nil {
		return Outcome{}, err
	}
	active, err := validateActiveAgentSessionCount(context)
	if err != nil {
		return Outcome{}, err
	}
	if int64(active) >= values.MaxActiveAgentSessions {
		return context.reject(CodeAgentSessionLimitReached), nil
	}

	var profile *string
	if value, present := context.proposal.Origin.AgentProfileID(); present {
		profile = &value
	}
	next := agentsession.Session{
		ID:             id,
		DeviceID:       context.device.ID,
		ClientKind:     clientKind,
		AgentProfileID: profile,
		State:          agentsession.StateStarting,
		WorkingRootID:  workingRootID,
		EntityVersion:  1,
	}
	if err := agentsession.ValidateTransition(
		agentsession.OperationCreate,
		agentsession.Lifecycle{},
		next.Lifecycle(),
	); err != nil {
		return context.reject(CodeInvalidAgentSessionTransition), nil
	}
	return context.acceptAgentSession(next, nil, nil)
}
