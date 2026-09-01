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
		reason != agentsession.EndReasonDisconnectTimeout &&
			reason != agentsession.EndReasonCrashReap ||
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

// CrashReap synchronously ends every imported nonterminal session owned by
// this device before normal agent recovery exposes local launch or resume.
func (service *Service) CrashReap(ctx context.Context) error {
	if err := service.available(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.recoverMu.Lock()
	defer service.recoverMu.Unlock()
	if service.recovered {
		return ErrInvalidOptions
	}
	if err := service.bootOrigin.Recover(ctx); err != nil {
		return err
	}
	if err := service.drainPendingAgentSessionCommands(ctx); err != nil {
		return err
	}

	for {
		sessions, err := service.local.NonterminalAgentSessions(ctx)
		if err != nil {
			return err
		}
		owned := false
		for _, session := range sessions {
			if session.DeviceID != service.deviceID {
				continue
			}
			owned = true
			current := session
			for {
				outcome, err := service.submitDaemonEnd(
					ctx,
					current.ID,
					agentsession.EndReasonCrashReap,
					current.EntityVersion,
				)
				if err != nil {
					return err
				}
				if outcome.Status == store.OutcomeAccepted {
					break
				}
				latest, found, err := service.local.AgentSession(
					ctx,
					current.ID,
				)
				if err != nil {
					return err
				}
				if !found || latest.State == agentsession.StateEnded {
					break
				}
				if latest.DeviceID != service.deviceID ||
					latest.EntityVersion == current.EntityVersion {
					return fmt.Errorf(
						"%w: crash reap %s: %s",
						ErrCommandRejected,
						current.ID,
						outcome.Code,
					)
				}
				current = latest
			}
		}
		if !owned {
			return nil
		}
	}
}

func (service *Service) drainPendingAgentSessionCommands(
	ctx context.Context,
) error {
	for {
		records, err := service.local.OutboxRecords(ctx)
		if err != nil {
			return err
		}
		pending := false
		for _, record := range records {
			switch record.Kind {
			case event.KindAgentSessionStarted,
				event.KindAgentSessionStateChanged,
				event.KindAgentSessionEnded:
				pending = true
				service.wakeScope(store.OutboxScope{
					OriginDeviceID:  record.OriginDeviceID,
					OriginScopeKind: record.OriginScopeKind,
					OriginScopeID:   record.OriginScopeID,
				})
			}
		}
		if !pending {
			return nil
		}
		if err := service.FatalError(); err != nil {
			return err
		}
		timer := time.NewTimer(outboxRetryDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-service.ctx.Done():
			timer.Stop()
			if err := service.FatalError(); err != nil {
				return err
			}
			return ErrClosed
		}
	}
}

// CrashReapPending reports whether this device still owns a nonterminal
// imported session. Callers use it while settled replication is fenced before
// clearing the rebootstrap recovery marker.
func (service *Service) CrashReapPending(ctx context.Context) (bool, error) {
	if err := service.available(); err != nil {
		return false, err
	}
	if ctx == nil {
		return false, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	service.recoverMu.Lock()
	defer service.recoverMu.Unlock()
	if service.recovered {
		return false, ErrInvalidOptions
	}
	sessions, err := service.local.NonterminalAgentSessions(ctx)
	if err != nil {
		return false, err
	}
	for _, session := range sessions {
		if session.DeviceID == service.deviceID {
			return true, nil
		}
	}
	return false, nil
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
