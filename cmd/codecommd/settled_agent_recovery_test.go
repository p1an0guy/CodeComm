package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

type daemonStartupRebootstrapStateStub struct {
	marker   store.RebootstrapInstallMarker
	found    bool
	readErr  error
	clearErr error
	calls    *[]string
}

func (state *daemonStartupRebootstrapStateStub) RebootstrapInstallMarker(
	context.Context,
) (store.RebootstrapInstallMarker, bool, error) {
	if state.calls != nil {
		*state.calls = append(*state.calls, "inspect")
	}
	return state.marker, state.found, state.readErr
}

func (state *daemonStartupRebootstrapStateStub) ClearRebootstrapInstallMarker(
	_ context.Context,
	expected store.RebootstrapInstallMarker,
) error {
	if state.calls != nil {
		*state.calls = append(*state.calls, "clear")
	}
	if state.clearErr != nil {
		return state.clearErr
	}
	if !state.found || expected != state.marker {
		return store.ErrRebootstrapInstallMarker
	}
	state.found = false
	return nil
}

type daemonAgentRecoveryStub struct {
	crashErr   error
	pending    bool
	pendingErr error
	recoverErr error
	calls      *[]string
}

func (service *daemonAgentRecoveryStub) CrashReap(context.Context) error {
	if service.calls != nil {
		*service.calls = append(*service.calls, "crash-reap")
	}
	return service.crashErr
}

func (service *daemonAgentRecoveryStub) CrashReapPending(
	context.Context,
) (bool, error) {
	if service.calls != nil {
		*service.calls = append(*service.calls, "pending")
	}
	return service.pending, service.pendingErr
}

func (service *daemonAgentRecoveryStub) Recover(context.Context) error {
	if service.calls != nil {
		*service.calls = append(*service.calls, "recover")
	}
	return service.recoverErr
}

type daemonPartialAgentRecoveryStub struct {
	remaining int
	failOnce  error
	calls     *[]string
}

func (service *daemonPartialAgentRecoveryStub) CrashReap(
	context.Context,
) error {
	if service.calls != nil {
		*service.calls = append(*service.calls, "crash-reap")
	}
	if service.failOnce != nil {
		err := service.failOnce
		service.failOnce = nil
		service.remaining--
		return err
	}
	service.remaining = 0
	return nil
}

func (service *daemonPartialAgentRecoveryStub) Recover(
	context.Context,
) error {
	if service.calls != nil {
		*service.calls = append(*service.calls, "recover")
	}
	if service.remaining != 0 {
		return errors.New("partial sessions remain")
	}
	return nil
}

func (service *daemonPartialAgentRecoveryStub) CrashReapPending(
	context.Context,
) (bool, error) {
	if service.calls != nil {
		*service.calls = append(*service.calls, "pending")
	}
	return service.remaining != 0, nil
}

type daemonAgentRecoveryBarrierStub struct {
	err            error
	withCurrentErr error
	beforeCurrent  func()
	calls          *[]string
}

func (barrier *daemonAgentRecoveryBarrierStub) WaitCurrent(
	context.Context,
) error {
	if barrier.calls != nil {
		*barrier.calls = append(*barrier.calls, "await-current")
	}
	return barrier.err
}

func (barrier *daemonAgentRecoveryBarrierStub) WithCurrent(
	ctx context.Context,
	operation func(context.Context) error,
) error {
	if barrier.calls != nil {
		*barrier.calls = append(*barrier.calls, "fence-current")
	}
	if barrier.withCurrentErr != nil {
		return barrier.withCurrentErr
	}
	if barrier.beforeCurrent != nil {
		before := barrier.beforeCurrent
		barrier.beforeCurrent = nil
		before()
	}
	return operation(ctx)
}

type daemonRebootstrapCurrencySourceStub struct {
	mu       sync.Mutex
	statuses []coordstatus.Snapshot
	fatal    error
	calls    int
}

func (source *daemonRebootstrapCurrencySourceStub) Status(
	context.Context,
) (coordstatus.Snapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	if len(source.statuses) == 0 {
		return coordstatus.Snapshot{
			Runtime: coordstatus.RuntimeSnapshot{
				State:           coordstatus.ConsensusSettled,
				ReplicaCurrency: coordstatus.ReplicaCurrencyUnknown,
			},
		}, nil
	}
	index := min(source.calls-1, len(source.statuses)-1)
	return source.statuses[index], nil
}

func (source *daemonRebootstrapCurrencySourceStub) FatalError() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.fatal
}

func (source *daemonRebootstrapCurrencySourceStub) callCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

type daemonFatalComponentStub struct {
	err        error
	fenceCalls int
	inFence    bool
}

func (component *daemonFatalComponentStub) FatalError() error {
	return component.err
}

func (component *daemonFatalComponentStub) withSettledReplicationFence(
	ctx context.Context,
	operation func(context.Context) error,
) error {
	component.fenceCalls++
	component.inFence = true
	defer func() {
		component.inFence = false
	}()
	return operation(ctx)
}

func TestInspectDaemonRebootstrapInstallBindsLineageAndDevice(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, otherDeviceID :=
		daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	state := &daemonStartupRebootstrapStateStub{marker: marker, found: true}
	got, err := inspectDaemonRebootstrapInstall(
		t.Context(),
		state,
		marker.SessionID,
		marker.WorkspaceID,
		marker.RecoveryGeneration,
		marker.DeviceID,
	)
	if err != nil || got == nil || *got != marker {
		t.Fatalf("inspect marker = (%+v, %v)", got, err)
	}

	for name, mutate := range map[string]func(*store.RebootstrapInstallMarker){
		"session": func(candidate *store.RebootstrapInstallMarker) {
			candidate.SessionID =
				"018f47de-89ab-7def-8123-7123456789ab"
		},
		"workspace": func(candidate *store.RebootstrapInstallMarker) {
			candidate.WorkspaceID =
				"550e8400-e29b-41d4-a716-446655440001"
		},
		"generation": func(candidate *store.RebootstrapInstallMarker) {
			candidate.RecoveryGeneration++
		},
		"device": func(candidate *store.RebootstrapInstallMarker) {
			candidate.DeviceID = otherDeviceID
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := marker
			mutate(&candidate)
			state := &daemonStartupRebootstrapStateStub{
				marker: candidate,
				found:  true,
			}
			if _, err := inspectDaemonRebootstrapInstall(
				t.Context(),
				state,
				marker.SessionID,
				marker.WorkspaceID,
				marker.RecoveryGeneration,
				marker.DeviceID,
			); !errors.Is(err, errDaemonRebootstrapRecovery) {
				t.Fatalf("inspect mismatch error = %v", err)
			}
		})
	}
}

func TestRebootstrapRecoveryWaitsForCurrentReplica(t *testing.T) {
	t.Parallel()

	source := &daemonRebootstrapCurrencySourceStub{
		statuses: []coordstatus.Snapshot{
			{
				Runtime: coordstatus.RuntimeSnapshot{
					State: coordstatus.ConsensusSettled,
					ReplicaCurrency: coordstatus.
						ReplicaCurrencyBehind,
				},
			},
			{
				Runtime: coordstatus.RuntimeSnapshot{
					State: coordstatus.ConsensusSettled,
					ReplicaCurrency: coordstatus.
						ReplicaCurrencyCurrent,
				},
			},
		},
	}
	peers := &daemonFatalComponentStub{}
	barrier := daemonRebootstrapCurrencyBarrier{
		replica: source,
		peers:   peers,
	}
	if err := barrier.WaitCurrent(t.Context()); err != nil {
		t.Fatalf("WaitCurrent(): %v", err)
	}
	if source.callCount() != 2 {
		t.Fatalf("Status() calls = %d, want 2", source.callCount())
	}
	ranFenced := false
	if err := barrier.WithCurrent(
		t.Context(),
		func(context.Context) error {
			ranFenced = peers.inFence
			return nil
		},
	); err != nil {
		t.Fatalf("WithCurrent(): %v", err)
	}
	if !ranFenced || peers.fenceCalls != 1 {
		t.Fatalf(
			"current callback fenced = %t, fence calls = %d",
			ranFenced,
			peers.fenceCalls,
		)
	}

	fatal := errors.New("replication failed")
	barrier.peers = &daemonFatalComponentStub{err: fatal}
	if err := barrier.WaitCurrent(t.Context()); !errors.Is(err, fatal) {
		t.Fatalf("WaitCurrent(fatal) error = %v", err)
	}
}

func TestRecoverSettledAgentStateRetriesEveryCrashBoundary(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, _ := daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	injected := errors.New("injected crash boundary")

	t.Run("before or during crash reap", func(t *testing.T) {
		var calls []string
		state := &daemonStartupRebootstrapStateStub{
			marker: marker,
			found:  true,
			calls:  &calls,
		}
		service := &daemonAgentRecoveryStub{
			crashErr: injected,
			calls:    &calls,
		}
		barrier := &daemonAgentRecoveryBarrierStub{calls: &calls}
		err := recoverSettledAgentState(
			t.Context(),
			state,
			&marker,
			barrier,
			service,
		)
		if !errors.Is(err, injected) ||
			!state.found ||
			!reflect.DeepEqual(
				calls,
				[]string{"await-current", "crash-reap"},
			) {
			t.Fatalf(
				"failed reap = (err %v, marker %t, calls %v)",
				err,
				state.found,
				calls,
			)
		}
	})

	t.Run("after all commits before marker clear", func(t *testing.T) {
		var calls []string
		state := &daemonStartupRebootstrapStateStub{
			marker:   marker,
			found:    true,
			clearErr: injected,
			calls:    &calls,
		}
		service := &daemonAgentRecoveryStub{calls: &calls}
		barrier := &daemonAgentRecoveryBarrierStub{calls: &calls}
		err := recoverSettledAgentState(
			t.Context(),
			state,
			&marker,
			barrier,
			service,
		)
		if !errors.Is(err, injected) ||
			!state.found ||
			!reflect.DeepEqual(
				calls,
				[]string{
					"await-current",
					"crash-reap",
					"fence-current",
					"pending",
					"inspect",
					"clear",
				},
			) {
			t.Fatalf(
				"failed clear = (err %v, marker %t, calls %v)",
				err,
				state.found,
				calls,
			)
		}

		calls = nil
		state.clearErr = nil
		if err := recoverSettledAgentState(
			t.Context(),
			state,
			&marker,
			barrier,
			service,
		); err != nil {
			t.Fatalf("retry recovery: %v", err)
		}
		if state.found ||
			!reflect.DeepEqual(
				calls,
				[]string{
					"await-current",
					"crash-reap",
					"fence-current",
					"pending",
					"inspect",
					"clear",
					"recover",
				},
			) {
			t.Fatalf("retry = (marker %t, calls %v)", state.found, calls)
		}
	})

	t.Run("after marker clear before normal recovery", func(t *testing.T) {
		var calls []string
		state := &daemonStartupRebootstrapStateStub{
			marker: marker,
			found:  true,
			calls:  &calls,
		}
		service := &daemonAgentRecoveryStub{
			recoverErr: injected,
			calls:      &calls,
		}
		barrier := &daemonAgentRecoveryBarrierStub{calls: &calls}
		err := recoverSettledAgentState(
			t.Context(),
			state,
			&marker,
			barrier,
			service,
		)
		if !errors.Is(err, injected) ||
			state.found ||
			!reflect.DeepEqual(
				calls,
				[]string{
					"await-current",
					"crash-reap",
					"fence-current",
					"pending",
					"inspect",
					"clear",
					"recover",
				},
			) {
			t.Fatalf(
				"failed normal recovery = (err %v, marker %t, calls %v)",
				err,
				state.found,
				calls,
			)
		}

		calls = nil
		nextMarker, err := inspectDaemonRebootstrapInstall(
			t.Context(),
			state,
			marker.SessionID,
			marker.WorkspaceID,
			marker.RecoveryGeneration,
			marker.DeviceID,
		)
		if err != nil || nextMarker != nil {
			t.Fatalf("next marker = (%+v, %v)", nextMarker, err)
		}
		nextService := &daemonAgentRecoveryStub{calls: &calls}
		if err := recoverSettledAgentState(
			t.Context(),
			state,
			nextMarker,
			nil,
			nextService,
		); err != nil {
			t.Fatalf("normal recovery retry: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{"inspect", "recover"}) {
			t.Fatalf("normal retry calls = %v", calls)
		}
	})
}

func TestRecoverSettledAgentStateResumesPartialMultiSessionCrashReap(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, _ := daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	injected := errors.New("interrupted after first session")
	var calls []string
	state := &daemonStartupRebootstrapStateStub{
		marker: marker,
		found:  true,
		calls:  &calls,
	}
	barrier := &daemonAgentRecoveryBarrierStub{calls: &calls}
	service := &daemonPartialAgentRecoveryStub{
		remaining: 2,
		failOnce:  injected,
		calls:     &calls,
	}
	if err := recoverSettledAgentState(
		t.Context(),
		state,
		&marker,
		barrier,
		service,
	); !errors.Is(err, injected) {
		t.Fatalf("first partial recovery error = %v", err)
	}
	if !state.found || service.remaining != 1 ||
		!reflect.DeepEqual(
			calls,
			[]string{"await-current", "crash-reap"},
		) {
		t.Fatalf(
			"partial recovery = (marker %t, remaining %d, calls %v)",
			state.found,
			service.remaining,
			calls,
		)
	}

	calls = nil
	if err := recoverSettledAgentState(
		t.Context(),
		state,
		&marker,
		barrier,
		service,
	); err != nil {
		t.Fatalf("resume partial recovery: %v", err)
	}
	if state.found || service.remaining != 0 ||
		!reflect.DeepEqual(
			calls,
			[]string{
				"await-current",
				"crash-reap",
				"fence-current",
				"pending",
				"inspect",
				"clear",
				"recover",
			},
		) {
		t.Fatalf(
			"resumed recovery = (marker %t, remaining %d, calls %v)",
			state.found,
			service.remaining,
			calls,
		)
	}
}

func TestRecoverSettledAgentStateRefreshesSnapshotFallbackMarker(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, _ := daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	refreshed := marker
	refreshed.SnapshotAttestationID = "snapshot:fallback"
	refreshed.InstalledAt = "2026-08-20T01:00:01Z"
	var calls []string
	state := &daemonStartupRebootstrapStateStub{
		marker: marker,
		found:  true,
		calls:  &calls,
	}
	service := &daemonAgentRecoveryStub{calls: &calls}
	barrier := &daemonAgentRecoveryBarrierStub{
		calls: &calls,
		beforeCurrent: func() {
			state.marker = refreshed
			calls = append(calls, "snapshot-fallback")
		},
	}

	if err := recoverSettledAgentState(
		t.Context(),
		state,
		&marker,
		barrier,
		service,
	); err != nil {
		t.Fatalf("recover after snapshot fallback: %v", err)
	}
	if state.found ||
		!reflect.DeepEqual(
			calls,
			[]string{
				"await-current",
				"crash-reap",
				"fence-current",
				"snapshot-fallback",
				"pending",
				"inspect",
				"clear",
				"recover",
			},
		) {
		t.Fatalf(
			"snapshot fallback recovery = (marker %t, calls %v)",
			state.found,
			calls,
		)
	}
}

func TestRecoverSettledAgentStateRejectsInvalidFinalMarker(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, otherDeviceID :=
		daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	for name, mutate := range map[string]func(
		*daemonStartupRebootstrapStateStub,
	){
		"missing": func(state *daemonStartupRebootstrapStateStub) {
			state.found = false
		},
		"changed lineage": func(state *daemonStartupRebootstrapStateStub) {
			state.marker.SessionID =
				"018f47de-89ab-7def-8123-7123456789ab"
		},
		"changed device": func(state *daemonStartupRebootstrapStateStub) {
			state.marker.DeviceID = otherDeviceID
		},
	} {
		t.Run(name, func(t *testing.T) {
			var calls []string
			state := &daemonStartupRebootstrapStateStub{
				marker: marker,
				found:  true,
				calls:  &calls,
			}
			barrier := &daemonAgentRecoveryBarrierStub{
				calls: &calls,
				beforeCurrent: func() {
					mutate(state)
				},
			}
			service := &daemonAgentRecoveryStub{calls: &calls}

			err := recoverSettledAgentState(
				t.Context(),
				state,
				&marker,
				barrier,
				service,
			)
			if !errors.Is(err, errDaemonRebootstrapRecovery) {
				t.Fatalf("invalid final marker error = %v", err)
			}
			for _, call := range calls {
				if call == "clear" || call == "recover" {
					t.Fatalf(
						"invalid final marker reached %q: calls %v",
						call,
						calls,
					)
				}
			}
		})
	}
}

func TestRecoverSettledAgentStateReapsTailArrivingBeforeFence(
	t *testing.T,
) {
	t.Parallel()

	_, privateKey, deviceID, _ := daemonTestSettledInitialState(t)
	clear(privateKey)
	marker := daemonTestRebootstrapMarker(deviceID)
	var calls []string
	state := &daemonStartupRebootstrapStateStub{
		marker: marker,
		found:  true,
		calls:  &calls,
	}
	service := &daemonPartialAgentRecoveryStub{
		remaining: 1,
		calls:     &calls,
	}
	barrier := &daemonAgentRecoveryBarrierStub{
		calls: &calls,
		beforeCurrent: func() {
			service.remaining = 1
			calls = append(calls, "tail-imported")
		},
	}

	if err := recoverSettledAgentState(
		t.Context(),
		state,
		&marker,
		barrier,
		service,
	); err != nil {
		t.Fatalf("recover with tail import: %v", err)
	}
	if state.found || service.remaining != 0 ||
		!reflect.DeepEqual(
			calls,
			[]string{
				"await-current",
				"crash-reap",
				"fence-current",
				"tail-imported",
				"pending",
				"crash-reap",
				"fence-current",
				"pending",
				"inspect",
				"clear",
				"recover",
			},
		) {
		t.Fatalf(
			"tail recovery = (marker %t, remaining %d, calls %v)",
			state.found,
			service.remaining,
			calls,
		)
	}
}

func daemonTestRebootstrapMarker(
	deviceID domain.DeviceID,
) store.RebootstrapInstallMarker {
	return store.RebootstrapInstallMarker{
		SessionID:             daemonTestSessionID,
		WorkspaceID:           daemonTestWorkspaceID,
		RecoveryGeneration:    0,
		DeviceID:              deviceID,
		SnapshotAttestationID: "snapshot:test",
		InstalledAt:           daemonTestTimestamp,
	}
}
