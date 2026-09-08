package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/reducer"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonVersionReportTestBinder = errors.New(
	"version-report test binder called",
)

type daemonVersionReportStateStub struct {
	mu     sync.Mutex
	member device.Device
	err    error
}

func (state *daemonVersionReportStateStub) StatusSnapshot(
	ctx context.Context,
	deviceID domain.DeviceID,
	limit int,
) (coordstatus.DurableSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return coordstatus.DurableSnapshot{}, err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.err != nil {
		return coordstatus.DurableSnapshot{}, state.err
	}
	if deviceID != state.member.ID || limit != 1 {
		return coordstatus.DurableSnapshot{}, errors.New("unexpected status read")
	}
	return coordstatus.DurableSnapshot{Member: state.member}, nil
}

func (state *daemonVersionReportStateStub) set(member device.Device) {
	state.mu.Lock()
	state.member = member
	state.mu.Unlock()
}

type daemonVersionReportReservationCall struct {
	daemonVersion   string
	maxApplyLevel   uint64
	expectedVersion uint64
}

type daemonVersionReportOriginStub struct {
	mu       sync.Mutex
	calls    []daemonVersionReportReservationCall
	outcomes chan store.CommandOutcome
	pending  bool
}

func newDaemonVersionReportOriginStub() *daemonVersionReportOriginStub {
	return &daemonVersionReportOriginStub{
		outcomes: make(chan store.CommandOutcome, 4),
	}
}

func (origin *daemonVersionReportOriginStub) ResumePendingVersionReport(
	ctx context.Context,
) (agent.VersionReportReservation, bool, error) {
	if err := ctx.Err(); err != nil {
		return agent.VersionReportReservation{}, false, err
	}
	origin.mu.Lock()
	defer origin.mu.Unlock()
	found := origin.pending
	origin.pending = false
	return agent.VersionReportReservation{}, found, nil
}

func (origin *daemonVersionReportOriginStub) ReserveVersionReport(
	ctx context.Context,
	daemonVersion string,
	maxApplyLevel uint64,
	expectedVersion uint64,
) (agent.VersionReportReservation, error) {
	if err := ctx.Err(); err != nil {
		return agent.VersionReportReservation{}, err
	}
	origin.mu.Lock()
	origin.calls = append(origin.calls, daemonVersionReportReservationCall{
		daemonVersion:   daemonVersion,
		maxApplyLevel:   maxApplyLevel,
		expectedVersion: expectedVersion,
	})
	origin.mu.Unlock()
	return agent.VersionReportReservation{}, nil
}

func (origin *daemonVersionReportOriginStub) AwaitVersionReport(
	ctx context.Context,
	_ agent.VersionReportReservation,
) (store.CommandOutcome, error) {
	select {
	case outcome := <-origin.outcomes:
		return outcome, nil
	case <-ctx.Done():
		return store.CommandOutcome{}, ctx.Err()
	}
}

func (origin *daemonVersionReportOriginStub) CompleteVersionReport(
	ctx context.Context,
	_ agent.VersionReportReservation,
) error {
	return ctx.Err()
}

func (origin *daemonVersionReportOriginStub) reservations() []daemonVersionReportReservationCall {
	origin.mu.Lock()
	defer origin.mu.Unlock()
	return append(
		[]daemonVersionReportReservationCall(nil),
		origin.calls...,
	)
}

func (origin *daemonVersionReportOriginStub) installPendingReport() {
	origin.mu.Lock()
	origin.pending = true
	origin.mu.Unlock()
}

type daemonVersionReportBinderStub struct {
	mu    sync.Mutex
	calls int
}

func (binder *daemonVersionReportBinderStub) Bind(
	context.Context,
	ipc.VerifiedPeer,
	ipc.BindRequest,
) (ipc.BindResult, error) {
	binder.mu.Lock()
	binder.calls++
	binder.mu.Unlock()
	return ipc.BindResult{}, errDaemonVersionReportTestBinder
}

func (binder *daemonVersionReportBinderStub) count() int {
	binder.mu.Lock()
	defer binder.mu.Unlock()
	return binder.calls
}

func TestDaemonVersionReportGateSkipsUnchangedReportAndRecoversAgents(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	binder := &daemonVersionReportBinderStub{}
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		binder,
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if calls := origin.reservations(); len(calls) != 0 {
		t.Fatalf("unchanged report reservations = %#v", calls)
	}
	if gate.requiresReport() {
		t.Fatal("unchanged membership unexpectedly requires a report")
	}
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery was not called")
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		_, err := gate.Bind(
			context.Background(),
			ipc.VerifiedPeer{},
			ipc.BindRequest{},
		)
		return errors.Is(err, errDaemonVersionReportTestBinder)
	})
	if binder.count() != 1 {
		t.Fatalf("delegated binds = %d, want 1", binder.count())
	}
}

func TestDaemonVersionReportGateReservesWithoutWaitingForQuorumAndGatesBind(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 4
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	binder := &daemonVersionReportBinderStub{}
	recovered := make(chan struct{})

	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		binder,
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	calls := origin.reservations()
	if len(calls) != 1 ||
		calls[0].daemonVersion != "0.1.0" ||
		calls[0].maxApplyLevel != 1 ||
		calls[0].expectedVersion != 4 {
		t.Fatalf("initial reservation = %#v", calls)
	}
	if !gate.requiresReport() {
		t.Fatal("changed membership did not require a report")
	}
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	if _, err := gate.Bind(
		context.Background(),
		ipc.VerifiedPeer{},
		ipc.BindRequest{},
	); !errors.Is(err, ipc.ErrBindRejected) {
		t.Fatalf("Bind(before report) error = %v, want rejection", err)
	}
	if binder.count() != 0 {
		t.Fatal("agent binder was exposed before report commitment")
	}
	waitContext, cancelWait := context.WithTimeout(
		context.Background(),
		10*time.Millisecond,
	)
	if err := gate.WaitReady(waitContext); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		cancelWait()
		t.Fatalf("WaitReady(before report) error = %v", err)
	}
	cancelWait()
	select {
	case <-recovered:
		t.Fatal("agent recovery ran before report commitment")
	default:
	}

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 5
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	readyContext, cancelReady := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancelReady()
	if err := gate.WaitReady(readyContext); err != nil {
		t.Fatalf("WaitReady(after report): %v", err)
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		_, err := gate.Bind(
			context.Background(),
			ipc.VerifiedPeer{},
			ipc.BindRequest{},
		)
		return errors.Is(err, errDaemonVersionReportTestBinder)
	})
}

func TestDaemonVersionReportGateCorrectsAcceptedPendingReportAfterRollback(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	origin.installPendingReport()
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if !gate.requiresReport() {
		t.Fatal("pending prior-binary report did not gate startup")
	}
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	member.DaemonVersion = "0.2.0"
	member.EntityVersion = 2
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		calls := origin.reservations()
		return len(calls) == 1 && calls[0].expectedVersion == 2
	})
	select {
	case <-recovered:
		t.Fatal("agent recovery ran after the stale report")
	default:
	}

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 3
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery did not follow the corrective report")
	}
}

func TestDaemonVersionReportGateRechecksMembershipAfterSynchronization(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGateWithSynchronize(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			member.DaemonVersion = "0.2.0"
			member.EntityVersion = 2
			state.set(member)
			return nil
		},
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if gate.requiresReport() {
		t.Fatal("matching installed snapshot unexpectedly required a report")
	}
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		calls := origin.reservations()
		return len(calls) == 1 && calls[0].expectedVersion == 2
	})
	select {
	case <-recovered:
		t.Fatal("agent recovery ran before the post-sync report")
	default:
	}

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 3
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery did not follow the post-sync report")
	}
}

func TestDaemonVersionReportGateRetriesCASRaceAgainstLatestMember(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 7
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	binder := &daemonVersionReportBinderStub{}
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		binder,
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	member.EntityVersion = 8
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeRejected,
		Code:   "entity_version_mismatch",
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		calls := origin.reservations()
		return len(calls) == 2 && calls[1].expectedVersion == 8
	})

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 9
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery did not follow CAS retry")
	}
}

func TestDaemonVersionReportGateRetriesStaleCASAtCurrentMemberVersion(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 7
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeRejected,
		Code:   string(reducer.CodeEntityVersionMismatch),
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		calls := origin.reservations()
		return len(calls) == 2 && calls[1].expectedVersion == 7
	})

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 8
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery did not follow stale CAS retry")
	}
}

func TestDaemonVersionReportGateSupersedesAcceptedPriorBootReport(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 3
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	recovered := make(chan struct{})
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			close(recovered)
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	member.DaemonVersion = "0.2.0"
	member.EntityVersion = 4
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		calls := origin.reservations()
		return len(calls) == 2 && calls[1].expectedVersion == 4
	})
	select {
	case <-recovered:
		t.Fatal("agent recovery ran before the current report")
	default:
	}

	member.DaemonVersion = "0.1.0"
	member.EntityVersion = 5
	state.set(member)
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeAccepted,
		Code:   "accepted",
	}
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("agent recovery did not follow the current report")
	}
}

func TestDaemonVersionReportGateLatchesRepeatedCASWithoutProgress(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 7
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			t.Error("agent recovery ran after repeated stale CAS")
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	rejected := store.CommandOutcome{
		Status: store.OutcomeRejected,
		Code:   string(reducer.CodeEntityVersionMismatch),
	}
	origin.outcomes <- rejected
	awaitDaemonVersionReportCondition(t, func() bool {
		return len(origin.reservations()) == 2
	})
	origin.outcomes <- rejected
	awaitDaemonVersionReportCondition(t, func() bool {
		return errors.Is(gate.FatalError(), errDaemonVersionReport)
	})
	if calls := origin.reservations(); len(calls) != 2 {
		t.Fatalf("repeated CAS reserved %d reports, want 2", len(calls))
	}
}

func TestDaemonVersionReportGateLatchesAuthoritativeRejection(
	t *testing.T,
) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	member.EntityVersion = 3
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	binder := &daemonVersionReportBinderStub{}
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		binder,
		func(context.Context) error {
			t.Error("agent recovery ran after authoritative rejection")
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	origin.outcomes <- store.CommandOutcome{
		Status: store.OutcomeRejected,
		Code:   "invalid_payload",
	}
	awaitDaemonVersionReportCondition(t, func() bool {
		return errors.Is(gate.FatalError(), errDaemonVersionReport)
	})
	if binder.count() != 0 {
		t.Fatal("agent binder was exposed after report rejection")
	}
}

func TestDaemonVersionReportGateCancellationUnblocksAwait(t *testing.T) {
	member := daemonVersionReportTestMember(t)
	member.DaemonVersion = "0.0.9"
	state := &daemonVersionReportStateStub{member: member}
	origin := newDaemonVersionReportOriginStub()
	gate := newDaemonVersionReportTestGate(
		t,
		state,
		origin,
		&daemonVersionReportBinderStub{},
		func(context.Context) error {
			t.Error("agent recovery ran while report was unresolved")
			return nil
		},
	)
	if err := gate.Start(); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	if err := gate.BeginClose(); err != nil {
		t.Fatalf("BeginClose(): %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- gate.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait() remained blocked on unresolved report")
	}
}

func newDaemonVersionReportTestGate(
	t *testing.T,
	state *daemonVersionReportStateStub,
	origin *daemonVersionReportOriginStub,
	binder *daemonVersionReportBinderStub,
	recoverAgents func(context.Context) error,
) *daemonVersionReportGate {
	t.Helper()
	return newDaemonVersionReportTestGateWithSynchronize(
		t,
		state,
		origin,
		binder,
		nil,
		recoverAgents,
	)
}

func newDaemonVersionReportTestGateWithSynchronize(
	t *testing.T,
	state *daemonVersionReportStateStub,
	origin *daemonVersionReportOriginStub,
	binder *daemonVersionReportBinderStub,
	synchronize func(context.Context) error,
	recoverAgents func(context.Context) error,
) *daemonVersionReportGate {
	t.Helper()
	gate, err := newDaemonVersionReportGate(
		context.Background(),
		daemonVersionReportOptions{
			State:         state,
			Origin:        origin,
			Agent:         binder,
			Synchronize:   synchronize,
			RecoverAgents: recoverAgents,
			DeviceID:      state.member.ID,
			DaemonVersion: "0.1.0",
			MaxApplyLevel: 1,
		},
	)
	if err != nil {
		t.Fatalf("newDaemonVersionReportGate(): %v", err)
	}
	t.Cleanup(func() {
		if err := gate.Wait(); err != nil {
			t.Errorf("version-report gate cleanup: %v", err)
		}
	})
	return gate
}

func daemonVersionReportTestMember(t *testing.T) device.Device {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0xe1}, ed25519.SeedSize),
	)
	t.Cleanup(func() { clear(privateKey) })
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return device.Device{
		ID:                deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: bytes.Clone(publicKey),
		DaemonVersion:     "0.1.0",
		MaxApplyLevel:     1,
		Status:            device.StatusActive,
		EntityVersion:     1,
	}
}

func awaitDaemonVersionReportCondition(
	t *testing.T,
	condition func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("version-report condition did not become true")
}
