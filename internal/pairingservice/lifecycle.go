package pairingservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

const (
	cleanupRetryBase = 250 * time.Millisecond
	cleanupRetryMax  = 30 * time.Second
)

// Recover performs startup reconciliation once and starts periodic expiry,
// finalization retry, and native-secret cleanup.
func (service *Service) Recover(ctx context.Context) error {
	if service == nil || service.state == nil || service.clock == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.recoverMu.Lock()
	defer service.recoverMu.Unlock()

	service.mu.RLock()
	if service.closed {
		service.mu.RUnlock()
		return ErrClosed
	}
	if service.recovered {
		service.mu.RUnlock()
		return service.FatalError()
	}
	service.mu.RUnlock()

	now := service.clock()
	if !now.Valid() {
		return ErrUnavailable
	}
	if _, err := service.state.RecoverPairingState(ctx, now); err != nil {
		return service.stateError(ctx, err)
	}
	if err := service.drainSecretCleanup(ctx); err != nil &&
		!errors.Is(err, errSecretCleanupRetry) {
		return err
	}

	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return ErrClosed
	}
	service.recovered = true
	service.done.Add(1)
	service.mu.Unlock()
	go service.maintenanceLoop()
	return nil
}

// Close stops maintenance. Callers must stop network dispatch before closing
// the durable dependencies supplied to this service.
func (service *Service) Close() error {
	if service == nil {
		return ErrInvalidInput
	}
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return nil
	}
	service.closed = true
	service.cancel()
	service.mu.Unlock()
	service.done.Wait()
	return nil
}

// FatalError returns an asynchronous durable-maintenance failure.
func (service *Service) FatalError() error {
	if service == nil {
		return ErrInvalidInput
	}
	service.fatalMu.RLock()
	defer service.fatalMu.RUnlock()
	return service.fatalErr
}

func (service *Service) maintenanceLoop() {
	defer service.done.Done()
	timer := time.NewTimer(service.maintenanceInterval)
	defer timer.Stop()
	retryDelay := cleanupRetryBase
	for {
		select {
		case <-service.ctx.Done():
			return
		case <-timer.C:
		}
		retry, err := service.maintainOnce(service.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			service.setFatal(err)
			return
		}
		delay := service.maintenanceInterval
		if retry {
			delay = retryDelay
			retryDelay = minDuration(retryDelay*2, cleanupRetryMax)
		} else {
			retryDelay = cleanupRetryBase
		}
		timer.Reset(delay)
	}
}

func (service *Service) maintainOnce(ctx context.Context) (bool, error) {
	now := service.clock()
	if !now.Valid() {
		return false, fmt.Errorf("%w: invalid maintenance clock", ErrUnavailable)
	}
	if _, err := service.state.MaintainPairingState(ctx, now); err != nil {
		return false, service.stateError(ctx, err)
	}
	retry := false
	if err := service.finalizeOne(ctx); err != nil {
		if !errors.Is(err, ErrFinalizationPending) {
			return false, err
		}
		retry = true
	}
	if err := service.drainSecretCleanup(ctx); err != nil {
		if !errors.Is(err, errSecretCleanupRetry) {
			return false, err
		}
		retry = true
	}
	return retry, nil
}

func (service *Service) finalizeOne(ctx context.Context) error {
	attempt, found, err := service.state.NextPairingFinalization(ctx)
	if err != nil {
		return service.stateError(ctx, err)
	}
	if !found {
		return nil
	}
	details, err := service.attemptDetails(ctx, attempt.AttemptID)
	if err != nil {
		return err
	}
	_, err = service.finalizeAttempt(ctx, details)
	return err
}

func (service *Service) finalizeAttempt(
	ctx context.Context,
	details AttemptDetails,
) (AttemptDetails, error) {
	service.finalizeMu.Lock()
	defer service.finalizeMu.Unlock()

	current, err := service.attemptDetails(ctx, details.Attempt.AttemptID)
	if err != nil {
		return details, err
	}
	details = current
	if details.Attempt.State == store.PairingAttemptCompleted {
		return details, nil
	}
	if details.Attempt.State != store.PairingAttemptFinalizing {
		return AttemptDetails{}, ErrRequestRejected
	}
	if err := service.finalizer.FinalizePairing(ctx, details); err != nil {
		if ctx.Err() != nil {
			return details, ctx.Err()
		}
		if errors.Is(err, ErrFinalizationIntegrity) ||
			errors.Is(err, ErrInvalidDurableFinalizer) {
			service.setFatal(err)
			return details, err
		}
		if errors.Is(err, ErrFinalizationRejected) {
			rejected, _, rejectErr := service.state.RejectPairingFinalization(
				ctx,
				details.Attempt.AttemptID,
			)
			if rejectErr != nil {
				if errors.Is(rejectErr, store.ErrPairingLineageMismatch) {
					return supersededAttempt(details), nil
				}
				return details, service.stateError(ctx, rejectErr)
			}
			details.Attempt = rejected
			return details, nil
		}
		current, found, stateErr := service.state.PairingAttempt(
			ctx,
			details.Attempt.AttemptID,
		)
		if stateErr != nil {
			if errors.Is(stateErr, store.ErrPairingLineageMismatch) {
				return supersededAttempt(details), nil
			}
			return details, service.stateError(ctx, stateErr)
		}
		if !found {
			return details, ErrRequestRejected
		}
		details.Attempt = current
		if current.State == store.PairingAttemptRevoked {
			return details, nil
		}
		if current.State != store.PairingAttemptFinalizing {
			return details, ErrRequestRejected
		}
		return details, fmt.Errorf("%w: %v", ErrFinalizationPending, err)
	}
	completedAt := service.clock()
	if !completedAt.Valid() {
		return details, fmt.Errorf("%w: invalid finalization clock", ErrUnavailable)
	}
	completed, _, err := service.state.CompletePairingFinalization(
		ctx,
		details.Attempt.AttemptID,
		completedAt,
	)
	if err != nil {
		if errors.Is(err, store.ErrPairingLineageMismatch) {
			return supersededAttempt(details), nil
		}
		return details, service.stateError(ctx, err)
	}
	details.Attempt = completed
	return details, nil
}

func supersededAttempt(details AttemptDetails) AttemptDetails {
	details.Attempt.State = store.PairingAttemptRevoked
	details.Attempt.FinalizedAt = ""
	return details
}

func (service *Service) setFatal(err error) {
	if err == nil {
		return
	}
	service.fatalOnce.Do(func() {
		service.fatalMu.Lock()
		service.fatalErr = err
		service.fatalMu.Unlock()
		service.cancel()
	})
}

// currentTime is for internal operations that already established lifecycle
// eligibility.
func (service *Service) currentTime() (domain.Timestamp, error) {
	now := service.clock()
	if !now.Valid() {
		return "", ErrUnavailable
	}
	return now, nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
