package endpointservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
)

const (
	endpointServiceTestSessionID = domain.UUIDv7(
		"018f47de-89ab-7def-8123-0123456789ab",
	)
	endpointServiceTestWorkspaceID = domain.UUIDv4(
		"550e8400-e29b-41d4-a716-446655440000",
	)
	endpointServiceTestInterval = 20 * time.Second
)

var endpointServiceTestNow = time.Date(
	2026, time.August, 19, 12, 0, 0, 123456789, time.UTC,
)

type endpointServiceStateFunc func(
	context.Context,
	domain.DeviceID,
	domain.Timestamp,
) (uint64, error)

func (function endpointServiceStateFunc) AllocateOwnEndpointSequence(
	ctx context.Context,
	deviceID domain.DeviceID,
	now domain.Timestamp,
) (uint64, error) {
	return function(ctx, deviceID, now)
}

func TestRefreshPublishesExactSignedSelectedEndpointSet(t *testing.T) {
	member, privateKey := endpointServiceTestIdentity(t, 0x41)
	inputKey := bytes.Clone(privateKey)
	var (
		allocatedDevice domain.DeviceID
		allocatedAt     domain.Timestamp
	)
	state := endpointServiceStateFunc(func(
		_ context.Context,
		deviceID domain.DeviceID,
		now domain.Timestamp,
	) (uint64, error) {
		allocatedDevice = deviceID
		allocatedAt = now
		return 1787123456789, nil
	})
	service := endpointServiceTestService(t, member, inputKey, state)

	input := RefreshInput{
		AdvertisementInterval: endpointServiceTestInterval,
		SelectedListeners: []netip.AddrPort{
			netip.MustParseAddrPort("[2001:db8::10]:47831"),
			netip.MustParseAddrPort("[fe80::10%en0]:47831"),
			netip.MustParseAddrPort("192.0.2.10:47831"),
		},
	}
	if err := service.Refresh(context.Background(), input); err != nil {
		t.Fatalf("Refresh(): %v", err)
	}
	if allocatedDevice != member.ID {
		t.Fatalf("allocated device = %s, want %s", allocatedDevice, member.ID)
	}
	wantObservedAt := domain.Timestamp(endpointServiceTestNow.Format(time.RFC3339Nano))
	if allocatedAt != wantObservedAt {
		t.Fatalf("allocated at = %s, want %s", allocatedAt, wantObservedAt)
	}

	encoded, found := service.CurrentEndpointSet()
	if !found {
		t.Fatal("CurrentEndpointSet() did not return the publication")
	}
	verified, err := discovery.ValidateEndpointSet(
		encoded,
		discovery.EndpointSetExpectation{
			SessionID:             endpointServiceTestSessionID,
			WorkspaceID:           endpointServiceTestWorkspaceID,
			RecoveryGeneration:    0,
			Member:                member,
			AdvertisementInterval: endpointServiceTestInterval,
			Now:                   endpointServiceTestNow,
		},
	)
	if err != nil {
		t.Fatalf("ValidateEndpointSet(): %v", err)
	}
	value := verified.EndpointSet()
	wantEndpoints := []discovery.Endpoint{
		{IP: netip.MustParseAddr("192.0.2.10"), Port: 47831},
		{IP: netip.MustParseAddr("2001:db8::10"), Port: 47831},
	}
	if value.EndpointSequence != 1787123456789 ||
		!reflect.DeepEqual(value.Endpoints, wantEndpoints) ||
		value.IssuedAt != "2026-08-19T12:00:00Z" ||
		value.ExpiresAt != "2026-08-19T12:02:40Z" {
		t.Fatalf("published endpoint set = %#v", value)
	}

	encoded[0] = '['
	again, found := service.CurrentEndpointSet()
	if !found || len(again) == 0 || again[0] != '{' {
		t.Fatal("CurrentEndpointSet() exposed mutable storage")
	}
	if !bytes.Equal(inputKey, privateKey) {
		t.Fatal("service mutated the caller-owned private key")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, found := service.CurrentEndpointSet(); found {
		t.Fatal("closed service retained a visible publication")
	}
	if len(service.identityPrivateKey) != 0 {
		t.Fatal("closed service retained its private key")
	}
}

func TestRefreshFailurePreservesPriorPublication(t *testing.T) {
	member, privateKey := endpointServiceTestIdentity(t, 0x42)
	var (
		mu       sync.Mutex
		calls    int
		stateErr error
	)
	state := endpointServiceStateFunc(func(
		_ context.Context,
		_ domain.DeviceID,
		_ domain.Timestamp,
	) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if stateErr != nil {
			return 0, stateErr
		}
		return uint64(100 + calls), nil
	})
	service := endpointServiceTestService(t, member, privateKey, state)
	t.Cleanup(func() { _ = service.Close() })
	input := endpointServiceTestRefreshInput()
	if err := service.Refresh(context.Background(), input); err != nil {
		t.Fatalf("first Refresh(): %v", err)
	}
	before, _ := service.CurrentEndpointSet()

	storageErr := errors.New("storage unavailable")
	mu.Lock()
	stateErr = storageErr
	mu.Unlock()
	if err := service.Refresh(context.Background(), input); !errors.Is(err, storageErr) {
		t.Fatalf("second Refresh() error = %v, want %v", err, storageErr)
	}
	after, _ := service.CurrentEndpointSet()
	if !bytes.Equal(after, before) {
		t.Fatal("failed refresh replaced the prior publication")
	}

	invalid := input
	invalid.SelectedListeners = append(
		invalid.SelectedListeners,
		netip.MustParseAddrPort("192.0.2.11:47832"),
	)
	if err := service.Refresh(context.Background(), invalid); !errors.Is(
		err,
		ErrInvalidRefresh,
	) {
		t.Fatalf("Refresh(invalid) error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("storage calls = %d, want 2", calls)
	}
}

func TestCloseCancelsRefreshAndClearsOwnedState(t *testing.T) {
	member, privateKey := endpointServiceTestIdentity(t, 0x43)
	entered := make(chan struct{})
	state := endpointServiceStateFunc(func(
		ctx context.Context,
		_ domain.DeviceID,
		_ domain.Timestamp,
	) (uint64, error) {
		close(entered)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	service := endpointServiceTestService(t, member, privateKey, state)
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- service.Refresh(
			context.Background(),
			endpointServiceTestRefreshInput(),
		)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Refresh() did not reach storage")
	}
	if err := service.BeginClose(); err != nil {
		t.Fatalf("BeginClose(): %v", err)
	}
	if err := service.Wait(); err != nil {
		t.Fatalf("Wait(): %v", err)
	}
	select {
	case err := <-refreshDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Refresh() error = %v, want %v", err, ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Refresh() remained blocked after BeginClose()")
	}
	if len(service.identityPrivateKey) != 0 || service.localState != nil {
		t.Fatal("Wait() retained owned or borrowed state")
	}
	if err := service.Refresh(
		context.Background(),
		endpointServiceTestRefreshInput(),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("Refresh(after close) error = %v, want %v", err, ErrClosed)
	}
}

func TestNewAndRefreshRejectInvalidBindings(t *testing.T) {
	member, privateKey := endpointServiceTestIdentity(t, 0x44)
	state := endpointServiceStateFunc(func(
		context.Context,
		domain.DeviceID,
		domain.Timestamp,
	) (uint64, error) {
		return 1, nil
	})
	wrongMember, _ := endpointServiceTestIdentity(t, 0x45)
	if service, err := New(Options{
		SessionID: endpointServiceTestSessionID, WorkspaceID: endpointServiceTestWorkspaceID,
		DeviceID: wrongMember.ID, IdentityPrivateKey: privateKey, LocalState: state,
	}); !errors.Is(err, ErrInvalidOptions) || service != nil {
		t.Fatalf("New(mismatched identity) = (%#v, %v)", service, err)
	}
	service := endpointServiceTestService(t, member, privateKey, state)
	t.Cleanup(func() { _ = service.Close() })
	for _, input := range []RefreshInput{
		{},
		{AdvertisementInterval: endpointServiceTestInterval},
		{
			AdvertisementInterval: endpointServiceTestInterval,
			SelectedListeners: []netip.AddrPort{
				netip.MustParseAddrPort("[fe80::10%en0]:47831"),
			},
		},
	} {
		if err := service.Refresh(context.Background(), input); !errors.Is(
			err,
			ErrInvalidRefresh,
		) {
			t.Fatalf("Refresh(%#v) error = %v", input, err)
		}
	}
}

func endpointServiceTestService(
	t *testing.T,
	member device.Device,
	privateKey ed25519.PrivateKey,
	state LocalState,
) *Service {
	t.Helper()
	service, err := newService(serviceOptions{
		Options: Options{
			SessionID: endpointServiceTestSessionID, WorkspaceID: endpointServiceTestWorkspaceID,
			RecoveryGeneration: 0, DeviceID: member.ID,
			IdentityPrivateKey: privateKey, LocalState: state,
		},
		now:              func() time.Time { return endpointServiceTestNow },
		operationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newService(): %v", err)
	}
	return service
}

func endpointServiceTestIdentity(
	t *testing.T,
	seed byte,
) (device.Device, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	deviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	return device.Device{
		ID: deviceID, Role: device.RoleOwner, IdentityPublicKey: bytes.Clone(publicKey),
		DaemonVersion: "1.0.0", MaxApplyLevel: 1,
		Status: device.StatusActive, EntityVersion: 1,
	}, privateKey
}

func endpointServiceTestRefreshInput() RefreshInput {
	return RefreshInput{
		AdvertisementInterval: endpointServiceTestInterval,
		SelectedListeners: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:47831"),
		},
	}
}
