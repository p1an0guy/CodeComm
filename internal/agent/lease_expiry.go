package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
)

const defaultLeasePollInterval = time.Second

var ErrLeaseLeaderRequired = errors.New(
	"agent: lease expiry requires current leader",
)

func (service *Service) rearmLeaseDeadlines(ctx context.Context) error {
	now, monotonicNowNS, err := service.consensus.LocalTime()
	if err != nil {
		return err
	}
	if !now.Valid() || monotonicNowNS < 0 {
		return ErrInvalidOptions
	}
	return service.local.RearmLeaseDeadlines(
		ctx,
		service.originBootID,
		now,
		monotonicNowNS,
	)
}

func (service *Service) startLeaseExpiryReconciliation() {
	service.done.Add(1)
	go func() {
		defer service.done.Done()
		service.reconcileLeaseExpiry()
	}()
}

func (service *Service) reconcileLeaseExpiry() {
	for {
		deadline, found, err := service.local.NextLeaseDeadline(
			service.ctx,
			service.originBootID,
		)
		if err != nil {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, store.ErrClosed) {
				return
			}
			service.recordFatal(fmt.Errorf(
				"agent: read lease deadlines: %w",
				err,
			))
			return
		}
		if !found {
			if !service.waitLeasePoll() {
				return
			}
			continue
		}

		now, monotonicNowNS, err := service.consensus.LocalTime()
		if err != nil || !now.Valid() || monotonicNowNS < 0 {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, store.ErrClosed) {
				return
			}
			if err == nil {
				err = ErrInvalidOptions
			}
			service.recordFatal(fmt.Errorf(
				"agent: read lease clock: %w",
				err,
			))
			return
		}
		if monotonicNowNS < deadline.MonotonicDeadlineNS {
			if !service.waitLeaseDuration(
				deadline.MonotonicDeadlineNS - monotonicNowNS,
			) {
				return
			}
			continue
		}
		if !service.consensus.IsLeader() {
			if !service.waitLeasePoll() {
				return
			}
			continue
		}

		_, err = service.submitDaemonLeaseExpiry(
			service.ctx,
			deadline.LeaseID,
			deadline.EntityVersion,
		)
		if errors.Is(err, ErrLeaseLeaderRequired) {
			continue
		}
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, store.ErrClosed) ||
			errors.Is(err, ErrClosed) {
			return
		}
		if err != nil {
			service.recordFatal(fmt.Errorf(
				"agent: submit lease expiry: %w",
				err,
			))
			return
		}
	}
}

func (service *Service) submitDaemonLeaseExpiry(
	ctx context.Context,
	leaseID domain.UUIDv7,
	expectedVersion uint64,
) (store.CommandOutcome, error) {
	if !leaseID.Valid() ||
		expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedVersion) {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	if !service.consensus.IsLeader() {
		return store.CommandOutcome{}, ErrLeaseLeaderRequired
	}
	payload, err := canonicalObject(map[string]any{
		"release_reason": lease.ReleaseExpired,
	})
	if err != nil {
		return store.CommandOutcome{}, err
	}
	return service.submitDaemonCommand(
		ctx,
		event.KindLeaseReleased,
		event.StringEntityID(string(leaseID)),
		expectedVersion,
		payload,
		map[string]any{
			"lease_id":       leaseID,
			"release_reason": lease.ReleaseExpired,
		},
	)
}

func (service *Service) waitLeasePoll() bool {
	return service.waitLeaseDuration(
		service.leasePollInterval.Nanoseconds(),
	)
}

func (service *Service) waitLeaseDuration(remainingNS int64) bool {
	duration := service.leasePollInterval
	if remainingNS > 0 && remainingNS < duration.Nanoseconds() {
		duration = time.Duration(remainingNS)
	}
	if duration <= 0 {
		duration = time.Nanosecond
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-service.ctx.Done():
		return false
	}
}
