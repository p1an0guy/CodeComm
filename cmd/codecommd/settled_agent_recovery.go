package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonRebootstrapRecovery = errors.New(
	"codecommd: rebootstrap agent recovery failed",
)

type daemonRebootstrapMarkerState interface {
	RebootstrapInstallMarker(
		context.Context,
	) (store.RebootstrapInstallMarker, bool, error)
	ClearRebootstrapInstallMarker(
		context.Context,
		store.RebootstrapInstallMarker,
	) error
}

type daemonAgentRecovery interface {
	CrashReap(context.Context) error
	CrashReapPending(context.Context) (bool, error)
	Recover(context.Context) error
}

type daemonAgentRecoveryBarrier interface {
	WaitCurrent(context.Context) error
	WithCurrent(
		context.Context,
		func(context.Context) error,
	) error
}

type daemonRebootstrapCurrencySource interface {
	Status(context.Context) (coordstatus.Snapshot, error)
	FatalError() error
}

type daemonRebootstrapReplicationFence interface {
	FatalError() error
	withSettledReplicationFence(
		context.Context,
		func(context.Context) error,
	) error
}

type daemonRebootstrapCurrencyBarrier struct {
	replica daemonRebootstrapCurrencySource
	peers   daemonRebootstrapReplicationFence
}

func (barrier daemonRebootstrapCurrencyBarrier) WaitCurrent(
	ctx context.Context,
) error {
	if ctx == nil || barrier.replica == nil || barrier.peers == nil {
		return errDaemonRebootstrapRecovery
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(fatalPollInterval)
	defer ticker.Stop()
	for {
		if err := barrier.replica.FatalError(); err != nil {
			return fmt.Errorf(
				"%w: settled replica: %w",
				errDaemonRebootstrapRecovery,
				err,
			)
		}
		if err := barrier.peers.FatalError(); err != nil {
			return fmt.Errorf(
				"%w: settled peer replication: %w",
				errDaemonRebootstrapRecovery,
				err,
			)
		}
		snapshot, err := barrier.replica.Status(ctx)
		if err != nil {
			return fmt.Errorf(
				"%w: inspect settled replica currency: %w",
				errDaemonRebootstrapRecovery,
				err,
			)
		}
		if snapshot.Runtime.State != coordstatus.ConsensusSettled {
			return fmt.Errorf(
				"%w: replica is not settled",
				errDaemonRebootstrapRecovery,
			)
		}
		if snapshot.Runtime.ReplicaCurrency ==
			coordstatus.ReplicaCurrencyCurrent {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (barrier daemonRebootstrapCurrencyBarrier) WithCurrent(
	ctx context.Context,
	operation func(context.Context) error,
) error {
	if ctx == nil ||
		barrier.replica == nil ||
		barrier.peers == nil ||
		operation == nil {
		return errDaemonRebootstrapRecovery
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(fatalPollInterval)
	defer ticker.Stop()
	for {
		current := false
		err := barrier.peers.withSettledReplicationFence(
			ctx,
			func(fencedContext context.Context) error {
				if err := barrier.replica.FatalError(); err != nil {
					return fmt.Errorf(
						"%w: settled replica: %w",
						errDaemonRebootstrapRecovery,
						err,
					)
				}
				if err := barrier.peers.FatalError(); err != nil {
					return fmt.Errorf(
						"%w: settled peer replication: %w",
						errDaemonRebootstrapRecovery,
						err,
					)
				}
				snapshot, err := barrier.replica.Status(fencedContext)
				if err != nil {
					return fmt.Errorf(
						"%w: inspect fenced replica currency: %w",
						errDaemonRebootstrapRecovery,
						err,
					)
				}
				if snapshot.Runtime.State !=
					coordstatus.ConsensusSettled {
					return fmt.Errorf(
						"%w: replica is not settled",
						errDaemonRebootstrapRecovery,
					)
				}
				if snapshot.Runtime.ReplicaCurrency !=
					coordstatus.ReplicaCurrencyCurrent {
					return nil
				}
				current = true
				return operation(fencedContext)
			},
		)
		if err != nil {
			return err
		}
		if current {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func inspectDaemonRebootstrapInstall(
	ctx context.Context,
	state daemonRebootstrapMarkerState,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	recoveryGeneration uint64,
	deviceID domain.DeviceID,
) (*store.RebootstrapInstallMarker, error) {
	if ctx == nil ||
		state == nil ||
		!sessionID.Valid() ||
		!workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(recoveryGeneration) ||
		!deviceID.Valid() {
		return nil, errDaemonRebootstrapRecovery
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	marker, found, err := state.RebootstrapInstallMarker(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: inspect install marker: %w",
			errDaemonRebootstrapRecovery,
			err,
		)
	}
	if !found {
		return nil, nil
	}
	if marker.SessionID != sessionID ||
		marker.WorkspaceID != workspaceID ||
		marker.RecoveryGeneration != recoveryGeneration ||
		marker.DeviceID != deviceID {
		return nil, fmt.Errorf(
			"%w: marker lineage or device does not match daemon",
			errDaemonRebootstrapRecovery,
		)
	}
	return &marker, nil
}

func recoverSettledAgentState(
	ctx context.Context,
	state daemonRebootstrapMarkerState,
	marker *store.RebootstrapInstallMarker,
	barrier daemonAgentRecoveryBarrier,
	service daemonAgentRecovery,
) error {
	if ctx == nil || state == nil || service == nil {
		return errDaemonRebootstrapRecovery
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if marker != nil {
		if barrier == nil {
			return errDaemonRebootstrapRecovery
		}
		if err := barrier.WaitCurrent(ctx); err != nil {
			return fmt.Errorf(
				"%w: await current replica before crash reap: %w",
				errDaemonRebootstrapRecovery,
				err,
			)
		}
		cleared := false
		for !cleared {
			if err := service.CrashReap(ctx); err != nil {
				return fmt.Errorf(
					"%w: crash-reap imported sessions: %w",
					errDaemonRebootstrapRecovery,
					err,
				)
			}
			if err := barrier.WithCurrent(
				ctx,
				func(fencedContext context.Context) error {
					pending, err := service.CrashReapPending(
						fencedContext,
					)
					if err != nil {
						return err
					}
					if pending {
						return nil
					}
					currentMarker, found, err :=
						state.RebootstrapInstallMarker(
							fencedContext,
						)
					if err != nil {
						return err
					}
					if !found ||
						currentMarker.SessionID != marker.SessionID ||
						currentMarker.WorkspaceID !=
							marker.WorkspaceID ||
						currentMarker.RecoveryGeneration !=
							marker.RecoveryGeneration ||
						currentMarker.DeviceID != marker.DeviceID {
						return errDaemonRebootstrapRecovery
					}
					if err := state.ClearRebootstrapInstallMarker(
						fencedContext,
						currentMarker,
					); err != nil {
						return err
					}
					cleared = true
					return nil
				},
			); err != nil {
				return fmt.Errorf(
					"%w: finalize fenced crash reap: %w",
					errDaemonRebootstrapRecovery,
					err,
				)
			}
		}
	}
	if err := service.Recover(ctx); err != nil {
		return fmt.Errorf(
			"%w: recover local agent state: %w",
			errDaemonRebootstrapRecovery,
			err,
		)
	}
	return nil
}
