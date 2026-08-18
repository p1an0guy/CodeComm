package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	outboxRetryDelay          = 100 * time.Millisecond
	pairingOutboxPollInterval = time.Second
)

type originWorker struct {
	service *Service
	scope   store.OutboxScope
	wake    chan struct{}
}

func (service *Service) wakeCommand(record store.LocalCommandRecord) {
	service.wakeScope(store.OutboxScope{
		OriginDeviceID:  service.deviceID,
		OriginScopeKind: record.OriginScopeKind,
		OriginScopeID:   record.OriginScopeID,
	})
}

func (service *Service) wakeScope(scope store.OutboxScope) {
	if scope.OriginScopeKind == store.OriginScopeKindBoot {
		service.bootOrigin.wakeWorker()
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return
	}
	worker, exists := service.workers[scope]
	if !exists {
		worker = &originWorker{
			service: service,
			scope:   scope,
			wake:    make(chan struct{}, 1),
		}
		service.workers[scope] = worker
		service.done.Add(1)
		go worker.run()
	}
	select {
	case worker.wake <- struct{}{}:
	default:
	}
}

func (worker *originWorker) run() {
	defer worker.service.done.Done()
	defer worker.remove()
	for {
		select {
		case <-worker.wake:
		case <-worker.service.ctx.Done():
			return
		}
		for {
			if !worker.drain() {
				return
			}
			if !worker.consumeWakeOrRetire() {
				return
			}
		}
	}
}

// drain returns true only after observing an empty durable queue.
func (worker *originWorker) drain() bool {
	if worker.scope.OriginScopeKind != store.OriginScopeKindAgent {
		worker.service.recordFatal(fmt.Errorf(
			"%w: generic worker received a non-agent scope",
			ErrCommandForwarding,
		))
		return false
	}
	for {
		record, found, err := worker.service.local.ClaimNextOutbox(
			worker.service.ctx,
			worker.scope,
		)
		if err != nil {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, store.ErrClosed) {
				return false
			}
			if !worker.retry() {
				return false
			}
			continue
		}
		if !found {
			return true
		}
		signed, err := event.ParseAndVerify(
			record.SignedProposal,
			event.VerificationContext{
				SessionID:         worker.service.sessionID,
				WorkspaceID:       worker.service.workspaceID,
				IdentityPublicKey: worker.service.publicKey,
			},
		)
		if err != nil {
			worker.service.recordFatal(fmt.Errorf(
				"%w: verify durable outbox command: %v",
				ErrCommandForwarding,
				err,
			))
			worker.service.signalResult()
			return false
		}
		if !outboxRecordMatchesSigned(record, signed) {
			worker.service.recordFatal(fmt.Errorf(
				"%w: durable outbox binding mismatch",
				ErrCommandForwarding,
			))
			worker.service.signalResult()
			return false
		}
		// Pairing owns the only V1 admission path and performs additional
		// operator-authority checks before submitting this exact command.
		if signed.Proposal().Kind == event.KindMembershipDeviceAdmitted {
			if !worker.pause(pairingOutboxPollInterval) {
				return false
			}
			continue
		}
		specification, known := event.LookupKind(signed.Proposal().Kind)
		if !known {
			worker.service.recordFatal(fmt.Errorf(
				"%w: durable outbox kind is unknown",
				ErrCommandForwarding,
			))
			worker.service.signalResult()
			return false
		}
		if specification.LeaderScheduled() &&
			signed.Proposal().Origin.ActorType() == event.ActorDaemon &&
			!worker.service.consensus.IsLeader() {
			if !worker.retry() {
				return false
			}
			continue
		}
		result, err := worker.service.consensus.ApplyAtGeneration(
			worker.service.ctx,
			record.SessionID,
			record.RecoveryGeneration,
			signed,
		)
		if err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				resolved, abandonErr := abandonOutboxCollision(
					worker.service.ctx,
					worker.service.local,
					record,
				)
				if abandonErr != nil {
					worker.service.recordFatal(fmt.Errorf(
						"%w: abandon colliding outbox command: %v",
						ErrCommandForwarding,
						abandonErr,
					))
					return false
				}
				if resolved {
					worker.service.signalResult()
					continue
				}
				worker.service.recordFatal(fmt.Errorf(
					"%w: event ID collision poisoned origin scope",
					ErrCommandForwarding,
				))
				return false
			}
			if !worker.retry() {
				return false
			}
			continue
		}
		if originSequenceRejected(result.Outcome) {
			worker.service.recordFatal(fmt.Errorf(
				"%w: committed local command rejected its durable origin sequence",
				ErrCommandForwarding,
			))
			worker.service.signalResult()
			return false
		}
		worker.service.signalResult()
	}
}

func abandonOutboxCollision(
	ctx context.Context,
	local store.LocalState,
	record store.OutboxRecord,
) (bool, error) {
	settled, _, err := local.AbandonCommandCollision(
		ctx,
		store.LocalCommandCollisionInput{
			ClientInstanceID:   record.ClientInstanceID,
			RequestID:          record.RequestID,
			SessionID:          record.SessionID,
			RecoveryGeneration: record.RecoveryGeneration,
			EventID:            record.EventID,
			ProposalDigest:     record.ProposalDigest,
		},
	)
	if err != nil {
		return false, err
	}
	return settled.State == store.LocalRequestResolved, nil
}

func originSequenceRejected(outcome store.CommandOutcome) bool {
	return outcome.Status == store.OutcomeRejected &&
		(outcome.Code == string(reducer.CodeOriginSequenceGap) ||
			outcome.Code == string(reducer.CodeOriginSequenceReused))
}

func outboxRecordMatchesSigned(
	record store.OutboxRecord,
	signed event.SignedEvent,
) bool {
	proposal := signed.Proposal()
	if proposal.EventID != record.EventID ||
		proposal.SessionID != record.SessionID ||
		proposal.Origin.DeviceID() != record.OriginDeviceID ||
		proposal.Origin.Sequence() != record.OriginSequence ||
		proposal.Kind != record.Kind ||
		proposal.CreatedAt != record.QueuedAt {
		return false
	}
	switch record.BindingClass {
	case store.LocalBindingAgent:
		return proposal.Origin.ActorType() == event.ActorAgent &&
			proposal.Origin.AgentSessionID() == record.OriginScopeID &&
			proposal.Origin.OriginBootID() == ""
	case store.LocalBindingOperator:
		return proposal.Origin.ActorType() == event.ActorHuman &&
			proposal.Origin.OriginBootID() == record.OriginScopeID &&
			proposal.Origin.AgentSessionID() == ""
	case store.LocalBindingDaemon:
		return proposal.Origin.ActorType() == event.ActorDaemon &&
			proposal.Origin.OriginBootID() == record.OriginScopeID &&
			proposal.Origin.AgentSessionID() == ""
	default:
		return false
	}
}

// consumeWakeOrRetire serializes wake publication with retirement. A wake
// either remains owned by this worker or observes no map entry and creates a
// replacement; it can never be sent to a worker that has decided to exit.
func (worker *originWorker) consumeWakeOrRetire() bool {
	worker.service.mu.Lock()
	defer worker.service.mu.Unlock()
	if worker.service.workers[worker.scope] != worker {
		return false
	}
	select {
	case <-worker.wake:
		return true
	default:
		delete(worker.service.workers, worker.scope)
		return false
	}
}

func (worker *originWorker) remove() {
	worker.service.mu.Lock()
	if worker.service.workers[worker.scope] == worker {
		delete(worker.service.workers, worker.scope)
	}
	worker.service.mu.Unlock()
}

func (worker *originWorker) retry() bool {
	return worker.pause(outboxRetryDelay)
}

func (worker *originWorker) pause(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-worker.service.ctx.Done():
		return false
	}
}

func (service *Service) signalResult() {
	service.mu.Lock()
	close(service.resultSignal)
	service.resultSignal = make(chan struct{})
	service.mu.Unlock()
}

func (service *Service) waitResolved(
	ctx context.Context,
	record store.LocalCommandRecord,
) (store.LocalCommandRecord, error) {
	for {
		current, found, err := service.local.LookupRequest(
			ctx,
			record.ClientInstanceID,
			record.RequestID,
		)
		if err != nil {
			return store.LocalCommandRecord{}, err
		}
		if !found {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		if current.State == store.LocalRequestResolved {
			return current, nil
		}
		if current.State == store.LocalRequestAbandoned ||
			current.State == store.LocalRequestExpired {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		service.mu.Lock()
		signal := service.resultSignal
		service.mu.Unlock()
		current, found, err = service.local.LookupRequest(
			ctx,
			record.ClientInstanceID,
			record.RequestID,
		)
		if err != nil {
			return store.LocalCommandRecord{}, err
		}
		if !found {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		if current.State == store.LocalRequestResolved {
			return current, nil
		}
		if current.State == store.LocalRequestAbandoned ||
			current.State == store.LocalRequestExpired {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		select {
		case <-signal:
		case <-ctx.Done():
			return store.LocalCommandRecord{}, ctx.Err()
		case <-service.ctx.Done():
			return store.LocalCommandRecord{}, ErrClosed
		}
	}
}
