package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const agentDisconnectGrace = 90 * time.Second

func (service *Service) resumeSession(
	ctx context.Context,
	session agentsession.Session,
	toState agentsession.State,
) error {
	if session.State != agentsession.StateDisconnected ||
		!toState.Connected() ||
		session.ResumeState != toState {
		return ErrBindRejected
	}
	outcome, err := service.submitDaemonStateChange(
		ctx,
		session.ID,
		toState,
		session.EntityVersion,
	)
	if err != nil {
		return err
	}
	if outcome.Status != store.OutcomeAccepted {
		return fmt.Errorf("%w: %s", ErrCommandRejected, outcome.Code)
	}
	return nil
}

func (service *Service) submitDaemonStateChange(
	ctx context.Context,
	agentSessionID domain.UUIDv7,
	toState agentsession.State,
	expectedVersion uint64,
) (store.CommandOutcome, error) {
	if !agentSessionID.Valid() ||
		!toState.Valid() ||
		expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedVersion) {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	payload, err := canonicalObject(map[string]any{
		"to_state": toState,
	})
	if err != nil {
		return store.CommandOutcome{}, err
	}
	return service.submitDaemonLifecycle(
		ctx,
		agentSessionID,
		expectedVersion,
		event.KindAgentSessionStateChanged,
		payload,
		map[string]any{"to_state": toState},
	)
}

func (service *Service) submitDaemonEnd(
	ctx context.Context,
	agentSessionID domain.UUIDv7,
	reason agentsession.EndReason,
	expectedVersion uint64,
) (store.CommandOutcome, error) {
	if !agentSessionID.Valid() ||
		reason != agentsession.EndReasonDisconnectTimeout ||
		expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedVersion) {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	payload, err := canonicalObject(map[string]any{
		"end_reason": reason,
	})
	if err != nil {
		return store.CommandOutcome{}, err
	}
	return service.submitDaemonLifecycle(
		ctx,
		agentSessionID,
		expectedVersion,
		event.KindAgentSessionEnded,
		payload,
		map[string]any{"end_reason": reason},
	)
}

func (service *Service) submitDaemonLifecycle(
	ctx context.Context,
	agentSessionID domain.UUIDv7,
	expectedVersion uint64,
	kind event.Kind,
	payload []byte,
	requestFields map[string]any,
) (store.CommandOutcome, error) {
	requestFields["agent_session_id"] = agentSessionID
	return service.submitDaemonCommand(
		ctx,
		kind,
		event.StringEntityID(string(agentSessionID)),
		expectedVersion,
		payload,
		requestFields,
	)
}

func (service *Service) submitDaemonCommand(
	ctx context.Context,
	kind event.Kind,
	entityID event.EntityID,
	expectedVersion uint64,
	payload []byte,
	requestFields map[string]any,
) (store.CommandOutcome, error) {
	_, knownKind := event.LookupKind(kind)
	if ctx == nil ||
		!knownKind ||
		expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedVersion) ||
		len(payload) == 0 ||
		requestFields == nil {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	requestID, err := service.generateID()
	if err != nil {
		return store.CommandOutcome{}, err
	}
	now := service.clock()
	if !now.Valid() {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	requestFields["expected_entity_version"] = expectedVersion
	requestFields["operation"] = kind
	requestFields["request_id"] = requestID
	canonicalRequest, err := canonicalObject(requestFields)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	record, _, err := service.local.ReserveCommand(
		ctx,
		store.LocalCommandInput{
			ClientInstanceID: service.originBootID,
			RequestID:        requestID,
			SessionID:        service.sessionID,
			WorkspaceID:      service.workspaceID,
			BindingClass:     store.LocalBindingDaemon,
			OriginDeviceID:   service.deviceID,
			OriginScopeKind:  store.OriginScopeKindBoot,
			OriginScopeID:    service.originBootID,
			RequestKind:      kind,
			CanonicalRequest: canonicalRequest,
			CreatedAt:        now,
		},
		func() (domain.UUIDv7, error) {
			return service.generateID()
		},
		func(eventID domain.UUIDv7, sequence uint64) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				event.Command{
					Kind:                  kind,
					EntityID:              entityID,
					ExpectedEntityVersion: &expectedVersion,
					RationaleSummary:      "",
					Actions:               []event.Action{},
					Payload:               payload,
					Redaction:             defaultRedaction(),
				},
				service.daemonBinding,
				event.BuildContext{
					EventID:        eventID,
					SessionID:      service.sessionID,
					WorkspaceID:    service.workspaceID,
					CreatedAt:      now,
					OriginSequence: sequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, service.privateKey)
		},
	)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	service.wakeCommand(record)
	resolved, err := service.waitResolved(ctx, record)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	if resolved.Outcome == nil {
		return store.CommandOutcome{}, ErrCommandForwarding
	}
	return *resolved.Outcome, nil
}

func (service *Service) onDisconnected(agentSessionID domain.UUIDv7) {
	service.releaseActive(agentSessionID)
	service.startLifecycleReconciliation(agentSessionID)
}

func (service *Service) startLifecycleReconciliation(
	agentSessionID domain.UUIDv7,
) {
	if !agentSessionID.Valid() {
		return
	}
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return
	}
	if _, exists := service.lifecycles[agentSessionID]; exists {
		service.mu.Unlock()
		return
	}
	service.lifecycles[agentSessionID] = struct{}{}
	service.done.Add(1)
	service.mu.Unlock()
	go func() {
		defer service.done.Done()
		defer func() {
			service.mu.Lock()
			delete(service.lifecycles, agentSessionID)
			service.mu.Unlock()
		}()
		service.reconcileLifecycle(agentSessionID)
	}()
}

func (service *Service) reconcileLifecycle(agentSessionID domain.UUIDv7) {
	for {
		session, found, err := service.local.AgentSession(
			service.ctx,
			agentSessionID,
		)
		if err != nil {
			if !waitLifecycleRetry(service.ctx) {
				return
			}
			continue
		}
		if !found || session.State == agentsession.StateEnded {
			return
		}
		if session.State == agentsession.StateDisconnected {
			if !waitDisconnectGrace(
				service.ctx,
				service.disconnectGrace,
			) {
				return
			}
			current, currentFound, err := service.local.AgentSession(
				service.ctx,
				agentSessionID,
			)
			if err != nil {
				if !waitLifecycleRetry(service.ctx) {
					return
				}
				continue
			}
			if !currentFound ||
				current.State == agentsession.StateEnded ||
				current.State.Connected() {
				return
			}
			if current.State != agentsession.StateDisconnected {
				return
			}
			outcome, err := service.submitDaemonEnd(
				service.ctx,
				agentSessionID,
				agentsession.EndReasonDisconnectTimeout,
				current.EntityVersion,
			)
			if err == nil && outcome.Status == store.OutcomeAccepted {
				return
			}
			if !waitLifecycleRetry(service.ctx) {
				return
			}
			continue
		}
		if !session.State.Connected() {
			return
		}
		outcome, err := service.submitDaemonStateChange(
			service.ctx,
			agentSessionID,
			agentsession.StateDisconnected,
			session.EntityVersion,
		)
		if err == nil && outcome.Status == store.OutcomeAccepted {
			continue
		}
		if !waitLifecycleRetry(service.ctx) {
			return
		}
	}
}

func waitDisconnectGrace(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return false
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func waitLifecycleRetry(ctx context.Context) bool {
	timer := time.NewTimer(outboxRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
