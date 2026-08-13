package reducer

import (
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/event"
)

type reductionContext struct {
	state        State
	proposal     event.Proposal
	device       device.Device
	agentSession *agentsession.Session
	scope        OriginScope
}

func beginReduction(
	state State,
	signed event.SignedEvent,
) (reductionContext, Outcome, bool, error) {
	proposal := signed.Proposal()
	context := reductionContext{state: state, proposal: proposal}
	if !state.sessionID.Valid() || !state.workspaceID.Valid() {
		return context, Outcome{}, false, invalidState("session or workspace identity")
	}
	if err := proposal.ValidateEnvelope(); err != nil {
		return context, rejectWithoutSequence(CodeInvalidEnvelope), true, nil
	}
	if proposal.SessionID != state.sessionID ||
		proposal.WorkspaceID != state.workspaceID {
		return context, rejectWithoutSequence(CodeSessionBindingMismatch), true, nil
	}

	origin := proposal.Origin
	member, exists := state.devices[origin.DeviceID()]
	if !exists {
		return context, rejectWithoutSequence(CodeOriginDeviceNotActive), true, nil
	}
	if member.ID != origin.DeviceID() {
		return context, Outcome{}, false, invalidState("device map key does not match row")
	}
	if err := member.Validate(); err != nil {
		return context, Outcome{}, false, invalidState("device %q: %v", member.ID, err)
	}
	if member.Status != device.StatusActive {
		return context, rejectWithoutSequence(CodeOriginDeviceNotActive), true, nil
	}
	context.device = member
	verified, err := event.ParseAndVerify(
		signed.CanonicalBytes(),
		event.VerificationContext{
			SessionID:         state.sessionID,
			WorkspaceID:       state.workspaceID,
			IdentityPublicKey: member.IdentityPublicKey,
		},
	)
	if err != nil {
		return context, rejectWithoutSequence(CodeInvalidOriginSignature), true, nil
	}
	proposal = verified.Proposal()
	context.proposal = proposal
	origin = proposal.Origin
	if proposal.Kind == event.KindAgentSessionStarted {
		if err := proposal.ValidateKindContract(); err != nil {
			return context,
				rejectWithoutSequence(kindContractCode(err)),
				true,
				nil
		}
	}

	scopeKey, bindingOutcome, bindingDone, err := validateOriginBinding(state, proposal)
	if err != nil || bindingDone {
		return context, bindingOutcome, bindingDone, err
	}
	if origin.ActorType() == event.ActorAgent {
		session, exists := state.agentSessions[origin.AgentSessionID()]
		if exists {
			sessionCopy := session
			context.agentSession = &sessionCopy
		}
	}

	scope, scopeExists := state.originScopes[scopeKey]
	if !scopeExists {
		if scopeKey.Kind == ScopeAgent &&
			proposal.Kind != event.KindAgentSessionStarted {
			return context, rejectWithoutSequence(CodeOriginScopeNotFound), true, nil
		}
		scope = OriginScope{OriginScopeKey: scopeKey}
	} else if err := validateOriginScope(scopeKey, scope); err != nil {
		return context, Outcome{}, false, err
	}

	sequence := origin.Sequence()
	if scopeExists && sequence <= scope.LastSequence {
		return context, rejectWithoutSequence(CodeOriginSequenceReused), true, nil
	}
	if scopeExists && scope.LastSequence == domain.MaxSafeInteger {
		return context, rejectWithoutSequence(CodeOriginSequenceReused), true, nil
	}
	expected := uint64(1)
	if scopeExists {
		expected = scope.LastSequence + 1
	}
	if sequence < expected {
		return context, rejectWithoutSequence(CodeOriginSequenceReused), true, nil
	}
	if sequence > expected {
		return context, rejectWithoutSequence(CodeOriginSequenceGap), true, nil
	}
	scope.LastSequence = sequence
	context.scope = scope

	if err := proposal.ValidateKindContract(); err != nil {
		return context, context.reject(kindContractCode(err)), true, nil
	}
	spec, exists := event.LookupKind(proposal.Kind)
	if !exists {
		return context, Outcome{}, false, fmt.Errorf(
			"%w: %q",
			ErrKindNotImplemented,
			proposal.Kind,
		)
	}
	if !roleSatisfies(member.Role, spec.MinimumRole()) {
		return context, context.reject(CodeInsufficientRole), true, nil
	}
	return context, Outcome{}, false, nil
}

func validateOriginBinding(
	state State,
	proposal event.Proposal,
) (OriginScopeKey, Outcome, bool, error) {
	origin := proposal.Origin
	if origin.ActorType() != event.ActorAgent {
		return OriginScopeKey{
			DeviceID: origin.DeviceID(),
			Kind:     ScopeBoot,
			ScopeID:  origin.OriginBootID(),
		}, Outcome{}, false, nil
	}

	sessionID := origin.AgentSessionID()
	if proposal.Kind == event.KindAgentSessionStarted {
		if _, exists := state.agentSessions[sessionID]; exists {
			return OriginScopeKey{},
				rejectWithoutSequence(CodeEntityAlreadyExists),
				true,
				nil
		}
		if _, burned := state.agentScopeDevices[sessionID]; burned {
			return OriginScopeKey{},
				rejectWithoutSequence(CodeEntityAlreadyExists),
				true,
				nil
		}
		return OriginScopeKey{
			DeviceID: origin.DeviceID(),
			Kind:     ScopeAgent,
			ScopeID:  sessionID,
		}, Outcome{}, false, nil
	}
	session, exists := state.agentSessions[sessionID]
	if !exists {
		return OriginScopeKey{}, rejectWithoutSequence(CodeAgentSessionNotFound), true, nil
	}
	if session.ID != sessionID {
		return OriginScopeKey{}, Outcome{}, false, invalidState(
			"agent-session map key does not match row",
		)
	}
	if err := session.Validate(); err != nil {
		return OriginScopeKey{}, Outcome{}, false, invalidState(
			"agent session %q: %v",
			session.ID,
			err,
		)
	}
	profile, profilePresent := origin.AgentProfileID()
	sessionProfilePresent := session.AgentProfileID != nil
	if session.DeviceID != origin.DeviceID() ||
		profilePresent != sessionProfilePresent ||
		profilePresent && profile != *session.AgentProfileID {
		return OriginScopeKey{},
			rejectWithoutSequence(CodeAgentSessionBindingMismatch),
			true,
			nil
	}
	if !session.State.Connected() {
		return OriginScopeKey{},
			rejectWithoutSequence(CodeAgentSessionNotConnected),
			true,
			nil
	}
	return OriginScopeKey{
		DeviceID: origin.DeviceID(),
		Kind:     ScopeAgent,
		ScopeID:  sessionID,
	}, Outcome{}, false, nil
}

func validateOriginScope(key OriginScopeKey, scope OriginScope) error {
	if scope.OriginScopeKey != key ||
		!key.DeviceID.Valid() ||
		(key.Kind != ScopeAgent && key.Kind != ScopeBoot) ||
		!key.ScopeID.Valid() ||
		scope.LastSequence < 1 ||
		!domain.ValidUnsignedInteger(scope.LastSequence) {
		return invalidState("malformed origin scope")
	}
	return nil
}

func roleSatisfies(role device.Role, requirement event.RoleRequirement) bool {
	switch requirement {
	case event.RoleNone:
		return true
	case event.RoleMember, event.RoleEditor:
		return role == device.RoleEditor || role == device.RoleOwner
	case event.RoleOwner:
		return role == device.RoleOwner
	default:
		return false
	}
}

func kindContractCode(err error) Code {
	switch {
	case errors.Is(err, event.ErrActorNotAllowed):
		return CodeActorNotAllowed
	case errors.Is(err, event.ErrExpectedEntityVersion):
		return CodeExpectedEntityVersion
	default:
		return CodeInvalidKindContract
	}
}

func rejectWithoutSequence(code Code) Outcome {
	return Outcome{Status: StatusRejected, Code: code}
}

func (context reductionContext) reject(code Code) Outcome {
	return Outcome{
		Status: StatusRejected,
		Code:   code,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
		},
	}
}

func (context reductionContext) rejectWithAlarm(
	code Code,
	alarm *AlarmDirective,
) Outcome {
	outcome := context.reject(code)
	outcome.Alarm = alarm
	return outcome
}

func (context reductionContext) acceptTask(
	value task.Task,
	audit *AuditDirective,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState("reducer produced invalid task: %v", err)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
			Tasks:        []task.Task{value},
		},
		ActivityTaskID: value.ID,
		Audit:          audit,
	}, nil
}

func (context reductionContext) acceptLease(
	value lease.Lease,
	audit *AuditDirective,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState("reducer produced invalid lease: %v", err)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
			Leases:       []lease.Lease{value},
		},
		ActivityTaskID: value.TaskID,
		Audit:          audit,
	}, nil
}

func (context reductionContext) acceptAgentSession(
	value agentsession.Session,
	tasks []task.Task,
	leases []lease.Lease,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid agent session: %v",
			err,
		)
	}
	for _, taskValue := range tasks {
		if err := taskValue.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid session-end task %q: %v",
				taskValue.ID,
				err,
			)
		}
	}
	for _, leaseValue := range leases {
		if err := leaseValue.Validate(); err != nil {
			return Outcome{}, invalidState(
				"reducer produced invalid session-end lease %q: %v",
				leaseValue.ID,
				err,
			)
		}
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			Tasks:         tasks,
			Leases:        leases,
			AgentSessions: []agentsession.Session{value},
		},
	}, nil
}

func (context reductionContext) acceptPlanRevision(
	value plan.Revision,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid plan revision: %v",
			err,
		)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			PlanRevisions: []plan.Revision{value},
		},
	}, nil
}

func (context reductionContext) acceptPlanCurrent(
	value plan.Current,
	audit *AuditDirective,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid current plan: %v",
			err,
		)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes: []OriginScope{context.scope},
			PlanCurrent:  []plan.Current{value},
		},
		Audit: audit,
	}, nil
}

func (context reductionContext) acceptMemory(
	value memory.Record,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid memory record: %v",
			err,
		)
	}
	taskID, _ := value.TaskID()
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			MemoryRecords: []memory.Record{value},
		},
		ActivityTaskID: taskID,
	}, nil
}

func (context reductionContext) acceptPolicy(
	value policy.Policy,
	audit *AuditDirective,
) (Outcome, error) {
	if err := value.Validate(); err != nil {
		return Outcome{}, invalidState(
			"reducer produced invalid session policy: %v",
			err,
		)
	}
	return Outcome{
		Status: StatusAccepted,
		Code:   CodeAccepted,
		Changes: Changes{
			OriginScopes:  []OriginScope{context.scope},
			SessionPolicy: []policy.Policy{value},
		},
		Audit: audit,
	}, nil
}

func invalidState(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCommittedState, fmt.Sprintf(format, args...))
}
