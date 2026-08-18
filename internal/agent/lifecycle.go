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
	if service == nil || service.bootOrigin == nil {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	return service.bootOrigin.submitDaemonCommand(
		ctx,
		kind,
		entityID,
		expectedVersion,
		payload,
		requestFields,
	)
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
