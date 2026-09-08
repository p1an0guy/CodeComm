package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/reducer"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonVersionReport = errors.New(
	"codecommd: membership version report failed",
)

type daemonVersionReportState interface {
	StatusSnapshot(
		context.Context,
		domain.DeviceID,
		int,
	) (coordstatus.DurableSnapshot, error)
}

type daemonVersionReportOrigin interface {
	ResumePendingVersionReport(
		context.Context,
	) (agent.VersionReportReservation, bool, error)
	ReserveVersionReport(
		context.Context,
		string,
		uint64,
		uint64,
	) (agent.VersionReportReservation, error)
	AwaitVersionReport(
		context.Context,
		agent.VersionReportReservation,
	) (store.CommandOutcome, error)
	CompleteVersionReport(
		context.Context,
		agent.VersionReportReservation,
	) error
}

type daemonVersionReportOptions struct {
	State         daemonVersionReportState
	Origin        daemonVersionReportOrigin
	Agent         ipc.Binder
	Synchronize   func(context.Context) error
	RecoverAgents func(context.Context) error
	DeviceID      domain.DeviceID
	DaemonVersion string
	MaxApplyLevel uint64
	Prepared      *daemonVersionReportPreparation
}

type daemonVersionReportPreparation struct {
	deviceID        domain.DeviceID
	daemonVersion   string
	maxApplyLevel   uint64
	expectedVersion uint64
	reservation     *agent.VersionReportReservation
}

// daemonVersionReportGate reserves the report before other same-boot
// mutations and withholds independent agent origins until it is committed.
type daemonVersionReportGate struct {
	state         daemonVersionReportState
	origin        daemonVersionReportOrigin
	agent         ipc.Binder
	synchronize   func(context.Context) error
	recoverAgents func(context.Context) error
	deviceID      domain.DeviceID
	daemonVersion string
	maxApplyLevel uint64

	ctx    context.Context
	cancel context.CancelFunc

	mu              sync.RWMutex
	started         bool
	closed          bool
	ready           bool
	fatal           error
	reservation     *agent.VersionReportReservation
	expectedVersion uint64
	finished        chan struct{}
	done            sync.WaitGroup
}

func newDaemonVersionReportGate(
	ctx context.Context,
	options daemonVersionReportOptions,
) (*daemonVersionReportGate, error) {
	if ctx == nil ||
		nilDaemonVersionReportDependency(options.State) ||
		nilDaemonVersionReportDependency(options.Origin) ||
		nilDaemonVersionReportDependency(options.Agent) ||
		options.RecoverAgents == nil ||
		!options.DeviceID.Valid() ||
		!device.ValidDaemonVersion(options.DaemonVersion) ||
		options.MaxApplyLevel < 1 ||
		options.MaxApplyLevel > domain.MaxApplyLevel {
		return nil, errDaemonVersionReport
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runContext, cancel := context.WithCancel(ctx)
	gate := &daemonVersionReportGate{
		state:         options.State,
		origin:        options.Origin,
		agent:         options.Agent,
		synchronize:   options.Synchronize,
		recoverAgents: options.RecoverAgents,
		deviceID:      options.DeviceID,
		daemonVersion: options.DaemonVersion,
		maxApplyLevel: options.MaxApplyLevel,
		ctx:           runContext,
		cancel:        cancel,
		finished:      make(chan struct{}),
	}
	prepared := options.Prepared
	if prepared == nil {
		value, err := prepareDaemonVersionReport(
			ctx,
			options.State,
			options.Origin,
			options.DeviceID,
			options.DaemonVersion,
			options.MaxApplyLevel,
		)
		if err != nil {
			cancel()
			return nil, err
		}
		prepared = &value
	}
	if prepared.deviceID != options.DeviceID ||
		prepared.daemonVersion != options.DaemonVersion ||
		prepared.maxApplyLevel != options.MaxApplyLevel ||
		prepared.expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(prepared.expectedVersion) {
		cancel()
		return nil, errDaemonVersionReport
	}
	if prepared.reservation != nil {
		reservation := *prepared.reservation
		gate.reservation = &reservation
	}
	gate.expectedVersion = prepared.expectedVersion
	return gate, nil
}

func prepareDaemonVersionReport(
	ctx context.Context,
	state daemonVersionReportState,
	origin daemonVersionReportOrigin,
	deviceID domain.DeviceID,
	daemonVersion string,
	maxApplyLevel uint64,
) (daemonVersionReportPreparation, error) {
	if ctx == nil ||
		nilDaemonVersionReportDependency(state) ||
		nilDaemonVersionReportDependency(origin) ||
		!deviceID.Valid() ||
		!device.ValidDaemonVersion(daemonVersion) ||
		maxApplyLevel < 1 ||
		maxApplyLevel > domain.MaxApplyLevel {
		return daemonVersionReportPreparation{}, errDaemonVersionReport
	}
	if err := ctx.Err(); err != nil {
		return daemonVersionReportPreparation{}, err
	}
	member, err := readDaemonVersionReportMember(ctx, state, deviceID)
	if err != nil {
		return daemonVersionReportPreparation{}, err
	}
	prepared := daemonVersionReportPreparation{
		deviceID:        deviceID,
		daemonVersion:   daemonVersion,
		maxApplyLevel:   maxApplyLevel,
		expectedVersion: member.EntityVersion,
	}
	pending, found, err := origin.ResumePendingVersionReport(ctx)
	if err != nil {
		return daemonVersionReportPreparation{}, fmt.Errorf(
			"%w: resume pending durable report: %w",
			errDaemonVersionReport,
			err,
		)
	}
	if found {
		prepared.reservation = &pending
		return prepared, nil
	}
	if member.DaemonVersion == daemonVersion &&
		member.MaxApplyLevel == maxApplyLevel {
		return prepared, nil
	}
	reservation, err := origin.ReserveVersionReport(
		ctx,
		daemonVersion,
		maxApplyLevel,
		member.EntityVersion,
	)
	if err != nil {
		return daemonVersionReportPreparation{}, fmt.Errorf(
			"%w: reserve durable report: %w",
			errDaemonVersionReport,
			err,
		)
	}
	prepared.reservation = &reservation
	return prepared, nil
}

// Start begins the quorum-dependent portion only after peer forwarding has
// been composed. It never waits for the report or agent recovery.
func (gate *daemonVersionReportGate) Start() error {
	if gate == nil {
		return errDaemonVersionReport
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.closed {
		return errDaemonVersionReport
	}
	if gate.started {
		return nil
	}
	if err := gate.ctx.Err(); err != nil {
		return err
	}
	gate.started = true
	gate.done.Add(1)
	go gate.run()
	return nil
}

func (gate *daemonVersionReportGate) requiresReport() bool {
	if gate == nil {
		return false
	}
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	return gate.reservation != nil
}

func (gate *daemonVersionReportGate) run() {
	defer gate.done.Done()
	defer close(gate.finished)
	reservation := gate.reservation
	expectedVersion := gate.expectedVersion
	retriedWithoutVersionAdvance := false
	synchronize := gate.synchronize
	var resolved *agent.VersionReportReservation
resolveReports:
	for reservation != nil {
		outcome, err := gate.origin.AwaitVersionReport(
			gate.ctx,
			*reservation,
		)
		if err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(fmt.Errorf(
					"%w: await durable report: %w",
					errDaemonVersionReport,
					err,
				))
			}
			return
		}
		member, err := gate.readMember(gate.ctx)
		if err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(err)
			}
			return
		}
		if gate.matches(member) {
			completed := *reservation
			resolved = &completed
			reservation = nil
			break
		}
		retryableIntermediate := false
		switch {
		case outcome.Status == store.OutcomeAccepted &&
			member.EntityVersion > expectedVersion:
			retryableIntermediate = true
			retriedWithoutVersionAdvance = false
		case outcome.Status == store.OutcomeRejected &&
			outcome.Code == string(reducer.CodeEntityVersionMismatch) &&
			member.EntityVersion > expectedVersion:
			retryableIntermediate = true
			retriedWithoutVersionAdvance = false
		case outcome.Status == store.OutcomeRejected &&
			outcome.Code == string(reducer.CodeEntityVersionMismatch) &&
			member.EntityVersion == expectedVersion &&
			!retriedWithoutVersionAdvance:
			retryableIntermediate = true
			retriedWithoutVersionAdvance = true
		}
		if !retryableIntermediate {
			gate.fail(fmt.Errorf(
				"%w: authoritative intermediate outcome %s/%s "+
					"did not permit the current report",
				errDaemonVersionReport,
				outcome.Status,
				outcome.Code,
			))
			return
		}
		expectedVersion = member.EntityVersion
		next, err := gate.origin.ReserveVersionReport(
			gate.ctx,
			gate.daemonVersion,
			gate.maxApplyLevel,
			expectedVersion,
		)
		if err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(fmt.Errorf(
					"%w: retry report after CAS race: %w",
					errDaemonVersionReport,
					err,
				))
			}
			return
		}
		reservation = &next
	}
	if synchronize != nil {
		synchronizeMembership := synchronize
		synchronize = nil
		if err := synchronizeMembership(gate.ctx); err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(fmt.Errorf(
					"%w: synchronize committed membership: %w",
					errDaemonVersionReport,
					err,
				))
			}
			return
		}
		member, err := gate.readMember(gate.ctx)
		if err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(err)
			}
			return
		}
		if !gate.matches(member) {
			next, err := gate.origin.ReserveVersionReport(
				gate.ctx,
				gate.daemonVersion,
				gate.maxApplyLevel,
				member.EntityVersion,
			)
			if err != nil {
				if gate.ctx.Err() == nil {
					gate.fail(fmt.Errorf(
						"%w: reserve report after synchronization: %w",
						errDaemonVersionReport,
						err,
					))
				}
				return
			}
			reservation = &next
			resolved = nil
			expectedVersion = member.EntityVersion
			retriedWithoutVersionAdvance = false
			goto resolveReports
		}
	}
	if resolved != nil {
		if err := gate.origin.CompleteVersionReport(
			gate.ctx,
			*resolved,
		); err != nil {
			if gate.ctx.Err() == nil {
				gate.fail(fmt.Errorf(
					"%w: release committed report barrier: %w",
					errDaemonVersionReport,
					err,
				))
			}
			return
		}
	}
	if err := gate.recoverAgents(gate.ctx); err != nil {
		if gate.ctx.Err() == nil {
			gate.fail(fmt.Errorf(
				"%w: recover agent state: %w",
				errDaemonVersionReport,
				err,
			))
		}
		return
	}
	gate.mu.Lock()
	if !gate.closed && gate.fatal == nil && gate.ctx.Err() == nil {
		gate.ready = true
	}
	gate.mu.Unlock()
}

// WaitReady is used only by startup modes whose design explicitly requires
// report and agent recovery completion before any listener begins serving.
func (gate *daemonVersionReportGate) WaitReady(ctx context.Context) error {
	if gate == nil || ctx == nil {
		return errDaemonVersionReport
	}
	gate.mu.RLock()
	started := gate.started
	finished := gate.finished
	gate.mu.RUnlock()
	if !started {
		return errDaemonVersionReport
	}
	select {
	case <-finished:
	case <-ctx.Done():
		return ctx.Err()
	}
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	if gate.fatal != nil {
		return gate.fatal
	}
	if !gate.ready {
		return errDaemonVersionReport
	}
	return nil
}

func (gate *daemonVersionReportGate) readMember(
	ctx context.Context,
) (device.Device, error) {
	return readDaemonVersionReportMember(ctx, gate.state, gate.deviceID)
}

func readDaemonVersionReportMember(
	ctx context.Context,
	state daemonVersionReportState,
	deviceID domain.DeviceID,
) (device.Device, error) {
	snapshot, err := state.StatusSnapshot(ctx, deviceID, 1)
	if err != nil {
		return device.Device{}, fmt.Errorf(
			"%w: read local membership: %w",
			errDaemonVersionReport,
			err,
		)
	}
	member := snapshot.Member
	if member.ID != deviceID ||
		member.Status != device.StatusActive ||
		member.Validate() != nil {
		return device.Device{}, fmt.Errorf(
			"%w: local device is not an active valid member",
			errDaemonVersionReport,
		)
	}
	return member, nil
}

func (gate *daemonVersionReportGate) matches(member device.Device) bool {
	return member.DaemonVersion == gate.daemonVersion &&
		member.MaxApplyLevel == gate.maxApplyLevel
}

// Bind exposes the real agent authority only after report and recovery.
func (gate *daemonVersionReportGate) Bind(
	ctx context.Context,
	peer ipc.VerifiedPeer,
	request ipc.BindRequest,
) (ipc.BindResult, error) {
	if gate == nil || ctx == nil {
		return ipc.BindResult{}, ipc.ErrBindRejected
	}
	gate.mu.RLock()
	ready := gate.ready && !gate.closed && gate.fatal == nil
	binder := gate.agent
	gate.mu.RUnlock()
	if !ready {
		return ipc.BindResult{}, ipc.ErrBindRejected
	}
	return binder.Bind(ctx, peer, request)
}

func (gate *daemonVersionReportGate) fail(err error) {
	if gate == nil || err == nil {
		return
	}
	gate.mu.Lock()
	if gate.fatal == nil {
		gate.fatal = err
		gate.cancel()
	}
	gate.mu.Unlock()
}

func (gate *daemonVersionReportGate) FatalError() error {
	if gate == nil {
		return errDaemonVersionReport
	}
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	return gate.fatal
}

func (gate *daemonVersionReportGate) BeginClose() error {
	if gate == nil {
		return errDaemonVersionReport
	}
	gate.mu.Lock()
	if !gate.closed {
		gate.closed = true
		gate.cancel()
	}
	gate.mu.Unlock()
	return nil
}

func (gate *daemonVersionReportGate) Wait() error {
	if err := gate.BeginClose(); err != nil {
		return err
	}
	gate.done.Wait()
	return nil
}

func nilDaemonVersionReportDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ ipc.Binder            = (*daemonVersionReportGate)(nil)
	_ phasedDaemonComponent = (*daemonVersionReportGate)(nil)
	_ daemonFatalComponent  = (*daemonVersionReportGate)(nil)
)
