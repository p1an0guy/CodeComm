package discoveryservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/transport"
)

const discoveryServiceTestSessionID = domain.UUIDv7(
	"0198bd31-ff40-7d61-8ad8-9f0fc18ce181",
)

func TestServiceAdvertisementCadenceTriggersAndRetryableSends(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now,
		device.StatusActive,
		device.StatusActive,
		1,
	))
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	credentials := newTestCredentials()
	routes := newTestRoutes()
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		credentials,
		routes,
		func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
			return netip.MustParseAddr("192.0.2.10"), true
		},
	)
	t.Cleanup(func() { _ = service.Close() })

	multicast.waitForSend(t)
	if got := multicast.sendCount(); got != 1 {
		t.Fatalf("startup sends = %d, want 1", got)
	}
	waitForCondition(t, func() bool {
		return clock.hasTimer(15 * time.Second)
	}, "jittered advertisement timer")

	retryable := errors.New("one interface unavailable")
	multicast.setSendError(retryable)
	if !clock.fire(15 * time.Second) {
		t.Fatal("jittered advertisement timer was not active")
	}
	multicast.waitForSend(t)
	if err := service.FatalError(); err != nil {
		t.Fatalf("retryable send made service fatal: %v", err)
	}

	multicast.setSendError(nil)
	multicast.trigger()
	multicast.waitForSend(t)
	credentials.waitForNotification(t)
	if got := multicast.sendCount(); got != 3 {
		t.Fatalf("sends after cadence and trigger = %d, want 3", got)
	}
	waitForCondition(t, func() bool {
		return clock.hasTimer(time.Second)
	}, "route maintenance timer")
	if !clock.fire(time.Second) {
		t.Fatal("route maintenance timer was not active")
	}
	routes.waitForExpiry(t)
}

func TestServiceUpdatesCommittedAdvertisementInterval(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now,
		device.StatusActive,
		device.StatusActive,
		1,
	))
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		newTestCredentials(),
		newTestRoutes(),
		func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
			return netip.MustParseAddr("192.0.2.10"), true
		},
	)
	t.Cleanup(func() { _ = service.Close() })
	multicast.waitForSend(t)
	waitForCondition(t, func() bool {
		return clock.hasTimer(15 * time.Second)
	}, "initial advertisement timer")

	if err := service.UpdateAdvertisementInterval(
		context.Background(),
		40*time.Second,
	); err != nil {
		t.Fatalf("UpdateAdvertisementInterval() error = %v", err)
	}
	waitForCondition(t, func() bool {
		return clock.hasTimer(30 * time.Second)
	}, "updated advertisement timer")
	if clock.hasTimer(15 * time.Second) {
		t.Fatal("initial advertisement timer remained active")
	}

	if err := service.UpdateAdvertisementInterval(
		context.Background(),
		time.Second,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf(
			"UpdateAdvertisementInterval(invalid) error = %v, want ErrInvalidOptions",
			err,
		)
	}
	if err := service.BeginClose(); err != nil {
		t.Fatalf("BeginClose() error = %v", err)
	}
	if err := service.UpdateAdvertisementInterval(
		context.Background(),
		20*time.Second,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf(
			"UpdateAdvertisementInterval(closed) error = %v, want ErrClosed",
			err,
		)
	}
}

func TestServiceAcceptsLatestExpiredCredentialAsHintOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshot := serviceTestSnapshot(
		t,
		identities,
		now.Add(-2*time.Hour),
		device.StatusActive,
		device.StatusActive,
		1,
	)
	snapshots := newTestSnapshotSource(snapshot)
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	credentials := newTestCredentials()
	routes := newTestRoutes()
	observations := make(chan RawDiscoveryObservation, 1)
	var (
		lookupMu     sync.Mutex
		lookupIndex  int
		lookupFamily discovery.AddressFamily
	)
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		credentials,
		routes,
		func(index int, family discovery.AddressFamily, _ netip.AddrPort) (netip.Addr, bool) {
			lookupMu.Lock()
			lookupIndex = index
			lookupFamily = family
			lookupMu.Unlock()
			return netip.MustParseAddr("192.0.2.10"), true
		},
		func(
			_ context.Context,
			observation RawDiscoveryObservation,
		) error {
			observations <- observation
			return nil
		},
	)
	t.Cleanup(func() { _ = service.Close() })
	multicast.waitForSend(t)

	remoteAuthorization := identities.remote.authorization(
		t,
		now.Add(-2*time.Hour),
		1,
		2,
	)
	record, found, err := service.resolveCredential(
		t.Context(),
		discoveryServiceTestSessionID,
		1,
		remoteAuthorization.KeyDigest,
	)
	if err != nil || !found || !record.LatestRetained {
		t.Fatalf(
			"resolveCredential(expired latest) = (%+v, %t, %v)",
			record,
			found,
			err,
		)
	}
	notAfter, _ := record.NotAfter.Time()
	if !notAfter.Before(time.Now()) {
		t.Fatalf("resolved credential expires at %v, want expired", notAfter)
	}

	encoded, expiresAt := signedServiceAdvertisement(
		t,
		identities.remote.epochKeys[1],
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        encoded,
		Source:         netip.MustParseAddrPort("192.0.2.20:60412"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 17,
	})
	call := routes.waitForLearnedRoute(t)
	var observation RawDiscoveryObservation
	select {
	case observation = <-observations:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for durable raw observation")
	}
	if observation.DeviceID != identities.remote.deviceID ||
		observation.Endpoint != netip.MustParseAddrPort("192.0.2.20:47831") ||
		observation.SelectedLocalAddress != netip.MustParseAddr("192.0.2.10") ||
		observation.ObservedAt != domain.Timestamp(now.Format(time.RFC3339Nano)) ||
		observation.ExpiresAt != domain.Timestamp(
			expiresAt.UTC().Format(time.RFC3339),
		) {
		t.Fatalf("raw discovery observation = %+v", observation)
	}
	if call.peer != identities.remote.deviceID ||
		call.source != transport.ConsensusRouteDiscovery ||
		len(call.routes) != 1 {
		t.Fatalf("learned route call = %+v", call)
	}
	route := call.routes[0]
	if route.RemoteEndpoint !=
		netip.MustParseAddrPort("192.0.2.20:47831") ||
		route.SelectedLocalAddress != netip.MustParseAddr("192.0.2.10") ||
		!route.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("learned expired-key hint = %+v", route)
	}
	lookupMu.Lock()
	if lookupIndex != 17 || lookupFamily != discovery.AddressFamilyIPv4 {
		t.Fatalf(
			"selected-source lookup = (%d, %v), want (17, ipv4)",
			lookupIndex,
			lookupFamily,
		)
	}
	lookupMu.Unlock()
	credentials.waitForNotification(t)
}

func TestServiceFailsClosedWhenRawObservationCannotPersist(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now.Add(-5*time.Minute),
		device.StatusActive,
		device.StatusActive,
		1,
	))
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	routes := newTestRoutes()
	persistenceErr := errors.New("local endpoint store unavailable")
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		newTestCredentials(),
		routes,
		func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
			return netip.MustParseAddr("192.0.2.10"), true
		},
		func(context.Context, RawDiscoveryObservation) error {
			return persistenceErr
		},
	)
	multicast.waitForSend(t)
	encoded, _ := signedServiceAdvertisement(
		t,
		identities.remote.epochKeys[1],
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        encoded,
		Source:         netip.MustParseAddrPort("192.0.2.20:60412"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 17,
	})
	waitForCondition(t, func() bool {
		fatal := service.FatalError()
		return errors.Is(fatal, ErrObservationPersistence) &&
			errors.Is(fatal, persistenceErr)
	}, "fatal raw-observation persistence failure")
	multicast.waitForClose(t)

	routes.mu.Lock()
	for _, call := range routes.calls {
		if len(call.routes) != 0 {
			routes.mu.Unlock()
			t.Fatal("failed durable observation entered the route table")
		}
	}
	routes.mu.Unlock()
	if err := service.Wait(); !errors.Is(err, ErrObservationPersistence) ||
		!errors.Is(err, persistenceErr) {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestServiceBindsIPv6HintToReceivingInterfaceSource(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now.Add(-5*time.Minute),
		device.StatusActive,
		device.StatusActive,
		1,
	))
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	routes := newTestRoutes()
	credentials := newTestCredentials()
	var gotIndex int
	var gotFamily discovery.AddressFamily
	var gotDestination netip.AddrPort
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		credentials,
		routes,
		func(index int, family discovery.AddressFamily, destination netip.AddrPort) (netip.Addr, bool) {
			gotIndex = index
			gotFamily = family
			gotDestination = destination
			return netip.MustParseAddr("fe80::10%en7"), true
		},
	)
	t.Cleanup(func() { _ = service.Close() })
	multicast.waitForSend(t)

	encoded, _ := signedServiceAdvertisement(
		t,
		identities.remote.epochKeys[1],
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload: encoded,
		Source: netip.AddrPortFrom(
			netip.MustParseAddr("fe80::20%en7"),
			60333,
		),
		Family:         discovery.AddressFamilyIPv6,
		InterfaceIndex: 9,
	})
	call := routes.waitForLearnedRoute(t)
	route := call.routes[0]
	if gotIndex != 9 ||
		gotFamily != discovery.AddressFamilyIPv6 ||
		gotDestination != netip.MustParseAddrPort("[fe80::20%en7]:47831") ||
		route.SelectedLocalAddress !=
			netip.MustParseAddr("fe80::10%en7") ||
		route.RemoteEndpoint !=
			netip.MustParseAddrPort("[fe80::20%en7]:47831") {
		t.Fatalf(
			"selected IPv6 route = %+v, lookup=(%d,%v)",
			route,
			gotIndex,
			gotFamily,
		)
	}
}

func TestServiceRevocationPurgesRoutesAndStopsAdvertising(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now.Add(-5*time.Minute),
		device.StatusActive,
		device.StatusActive,
		1,
	))
	clock := newTestClock(now)
	multicast := newTestMulticast(true)
	routes := newTestRoutes()
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		clock,
		multicast,
		newTestCredentials(),
		routes,
		func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
			return netip.MustParseAddr("192.0.2.10"), true
		},
	)
	multicast.waitForSend(t)
	encoded, _ := signedServiceAdvertisement(
		t,
		identities.remote.epochKeys[1],
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        encoded,
		Source:         netip.MustParseAddrPort("192.0.2.20:60000"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 2,
	})
	routes.waitForLearnedRoute(t)

	snapshots.Set(serviceTestSnapshot(
		t,
		identities,
		now.Add(-5*time.Minute),
		device.StatusRevoked,
		device.StatusActive,
		1,
	))
	waitForCondition(t, func() bool {
		return clock.hasTimer(time.Second)
	}, "route maintenance timer")
	if !clock.fire(time.Second) {
		t.Fatal("route maintenance timer was not active")
	}
	routes.waitForPurge(t, identities.remote.deviceID)
	multicast.waitForClose(t)
	sends := multicast.sendCount()
	multicast.trigger()
	runtime.Gosched()
	if got := multicast.sendCount(); got != sends {
		t.Fatalf("advertisements continued after revocation: %d -> %d", sends, got)
	}
	if err := service.FatalError(); err != nil {
		t.Fatalf("revocation was treated as fatal: %v", err)
	}
	if err := service.Wait(); err != nil {
		t.Fatalf("Wait() after revocation: %v", err)
	}
	if got := multicast.closeCount(); got != 1 {
		t.Fatalf("multicast closes = %d, want 1", got)
	}
}

func TestServiceSilentlyIgnoresHostileDatagrams(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	identities := newServiceTestIdentities(t, 1)
	snapshots := newTestSnapshotSource(serviceTestSnapshot(
		t,
		identities,
		now.Add(-5*time.Minute),
		device.StatusActive,
		device.StatusActive,
		1,
	))
	multicast := newTestMulticast(true)
	routes := newTestRoutes()
	service := newDiscoveryTestService(
		t,
		snapshots.Current,
		newTestClock(now),
		multicast,
		newTestCredentials(),
		routes,
		func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
			return netip.MustParseAddr("192.0.2.10"), true
		},
	)
	t.Cleanup(func() { _ = service.Close() })
	multicast.waitForSend(t)

	multicast.deliverError(discovery.ErrMulticastSource)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        bytes.Repeat([]byte{'x'}, discovery.MaxDatagramBytes+1),
		Source:         netip.MustParseAddrPort("192.0.2.30:60000"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 2,
	})
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        []byte(`{"magic":"codecomm"}`),
		Source:         netip.MustParseAddrPort("192.0.2.31:60000"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 2,
	})
	unknown := serviceTestPrivateKey(0xee)
	unknownAdvertisement, _ := signedServiceAdvertisement(
		t,
		unknown,
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        unknownAdvertisement,
		Source:         netip.MustParseAddrPort("192.0.2.32:60000"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 2,
	})

	valid, _ := signedServiceAdvertisement(
		t,
		identities.remote.epochKeys[1],
		1,
		time.Now(),
	)
	multicast.deliver(discovery.ReceivedDatagram{
		Payload:        valid,
		Source:         netip.MustParseAddrPort("192.0.2.20:60000"),
		Family:         discovery.AddressFamilyIPv4,
		InterfaceIndex: 2,
	})
	routes.waitForLearnedRoute(t)
	if got := routes.learnCount(); got != 1 {
		t.Fatalf("learned route replacements = %d, want 1", got)
	}
	if err := service.FatalError(); err != nil {
		t.Fatalf("hostile input made service fatal: %v", err)
	}
}

func TestServiceLifecycleAndUnexpectedReadFailure(t *testing.T) {
	t.Run("normal close is idempotent", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		identities := newServiceTestIdentities(t, 1)
		multicast := newTestMulticast(true)
		service := newDiscoveryTestService(
			t,
			newTestSnapshotSource(serviceTestSnapshot(
				t,
				identities,
				now.Add(-5*time.Minute),
				device.StatusActive,
				device.StatusActive,
				1,
			)).Current,
			newTestClock(now),
			multicast,
			newTestCredentials(),
			newTestRoutes(),
			func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
				return netip.MustParseAddr("192.0.2.10"), true
			},
		)
		multicast.waitForSend(t)
		if err := service.BeginClose(); err != nil {
			t.Fatalf("BeginClose(): %v", err)
		}
		if err := service.BeginClose(); err != nil {
			t.Fatalf("BeginClose(second): %v", err)
		}
		if err := service.Wait(); err != nil {
			t.Fatalf("Wait(): %v", err)
		}
		if err := service.Close(); err != nil {
			t.Fatalf("Close(second): %v", err)
		}
		if got := multicast.closeCount(); got != 1 {
			t.Fatalf("multicast closes = %d, want 1", got)
		}
		if err := service.FatalError(); err != nil {
			t.Fatalf("FatalError() = %v", err)
		}
	})

	t.Run("unexpected read failure is fatal", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		identities := newServiceTestIdentities(t, 1)
		multicast := newTestMulticast(true)
		service := newDiscoveryTestService(
			t,
			newTestSnapshotSource(serviceTestSnapshot(
				t,
				identities,
				now.Add(-5*time.Minute),
				device.StatusActive,
				device.StatusActive,
				1,
			)).Current,
			newTestClock(now),
			multicast,
			newTestCredentials(),
			newTestRoutes(),
			func(int, discovery.AddressFamily, netip.AddrPort) (netip.Addr, bool) {
				return netip.MustParseAddr("192.0.2.10"), true
			},
		)
		multicast.waitForSend(t)
		multicast.deliverError(errors.New("socket read failed"))
		waitForCondition(t, func() bool {
			return errors.Is(service.FatalError(), ErrMulticastFailure)
		}, "fatal multicast read failure")
		multicast.waitForClose(t)
		if err := service.Wait(); !errors.Is(err, ErrMulticastFailure) {
			t.Fatalf("Wait() error = %v, want %v", err, ErrMulticastFailure)
		}
		if got := multicast.closeCount(); got != 1 {
			t.Fatalf("multicast closes = %d, want 1", got)
		}
	})
}

func newDiscoveryTestService(
	t *testing.T,
	snapshots AdmissionSnapshotProvider,
	clock Clock,
	multicast Multicast,
	credentials CredentialAdvertiser,
	routes RouteTable,
	selected SelectedLocalAddressLookup,
	observers ...RawDiscoveryObserver,
) *Service {
	t.Helper()
	if len(observers) > 1 {
		t.Fatal("more than one raw discovery observer")
	}
	var observer RawDiscoveryObserver
	if len(observers) == 1 {
		observer = observers[0]
	}
	service, err := New(Options{
		SessionID:             discoveryServiceTestSessionID,
		LocalDeviceID:         serviceTestLocalID(t),
		HTTPSPort:             47831,
		AdvertisementInterval: 20 * time.Second,
		Multicast:             multicast,
		AdmissionSnapshots:    snapshots,
		Credentials:           credentials,
		SelectedLocalAddress:  selected,
		Routes:                routes,
		ObserveRawDiscovery:   observer,
		Clock:                 clock,
		Entropy: bytes.NewReader(
			make([]byte, 16<<10),
		),
	})
	if err != nil {
		t.Fatalf("newService(): %v", err)
	}
	return service
}

type serviceTestIdentity struct {
	deviceID    domain.DeviceID
	identityKey ed25519.PrivateKey
	epochKeys   map[uint64]ed25519.PrivateKey
}

type serviceTestIdentities struct {
	local  serviceTestIdentity
	remote serviceTestIdentity
}

func newServiceTestIdentities(
	t *testing.T,
	remoteEpochs uint64,
) serviceTestIdentities {
	t.Helper()
	return serviceTestIdentities{
		local:  newServiceTestIdentity(t, 0x11, 1),
		remote: newServiceTestIdentity(t, 0x22, remoteEpochs),
	}
}

func newServiceTestIdentity(
	t *testing.T,
	seed byte,
	epochs uint64,
) serviceTestIdentity {
	t.Helper()
	identityKey := serviceTestPrivateKey(seed)
	deviceID, err := device.DeriveID(
		identityKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatalf("device.DeriveID(): %v", err)
	}
	result := serviceTestIdentity{
		deviceID:    deviceID,
		identityKey: identityKey,
		epochKeys:   make(map[uint64]ed25519.PrivateKey, epochs),
	}
	for epoch := uint64(1); epoch <= epochs; epoch++ {
		result.epochKeys[epoch] = serviceTestPrivateKey(
			seed + byte(epoch) + 0x40,
		)
	}
	return result
}

func serviceTestLocalID(t *testing.T) domain.DeviceID {
	t.Helper()
	identity := newServiceTestIdentity(t, 0x11, 1)
	return identity.deviceID
}

func serviceTestSnapshot(
	t *testing.T,
	identities serviceTestIdentities,
	notBefore time.Time,
	localStatus device.Status,
	remoteStatus device.Status,
	remoteEpoch uint64,
) *peerauth.Snapshot {
	t.Helper()
	devices := map[domain.DeviceID]device.Device{
		identities.local.deviceID: identities.local.member(localStatus),
		identities.remote.deviceID: identities.remote.member(
			remoteStatus,
		),
	}
	counters := map[domain.DeviceID]auditcounter.Counter{
		identities.local.deviceID: {
			DeviceID:        identities.local.deviceID,
			CredentialEpoch: 1,
		},
		identities.remote.deviceID: {
			DeviceID:        identities.remote.deviceID,
			CredentialEpoch: remoteEpoch,
		},
	}
	authorizations := make(
		map[credentialauthorization.Key]credentialauthorization.Authorization,
		1+remoteEpoch,
	)
	localAuthorization := identities.local.authorization(
		t,
		notBefore,
		1,
		1,
	)
	authorizations[localAuthorization.PrimaryKey()] = localAuthorization
	for epoch := uint64(1); epoch <= remoteEpoch; epoch++ {
		authorization := identities.remote.authorization(
			t,
			notBefore,
			epoch,
			epoch+1,
		)
		authorizations[authorization.PrimaryKey()] = authorization
	}
	snapshot, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:                discoveryServiceTestSessionID,
		RecoveryGeneration:       0,
		AppliedChainIndex:        remoteEpoch + 2,
		Devices:                  devices,
		AuditCounters:            counters,
		CredentialAuthorizations: authorizations,
	})
	if err != nil {
		t.Fatalf("peerauth.NewSnapshot(): %v", err)
	}
	return snapshot
}

func (identity serviceTestIdentity) member(
	status device.Status,
) device.Device {
	return device.Device{
		ID:                identity.deviceID,
		Role:              device.RoleOwner,
		IdentityPublicKey: identity.identityKey.Public().(ed25519.PublicKey),
		DaemonVersion:     "1.0.0",
		MaxApplyLevel:     1,
		Status:            status,
		EntityVersion:     1,
	}
}

func (identity serviceTestIdentity) authorization(
	t *testing.T,
	notBefore time.Time,
	epoch uint64,
	chainIndex uint64,
) credentialauthorization.Authorization {
	t.Helper()
	privateKey := identity.epochKeys[epoch]
	if len(privateKey) == 0 {
		t.Fatalf("missing epoch key %d for %s", epoch, identity.deviceID)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	notBefore = notBefore.UTC().Truncate(time.Second)
	authorization := credentialauthorization.Authorization{
		SessionID:                discoveryServiceTestSessionID,
		DeviceID:                 identity.deviceID,
		Epoch:                    epoch,
		Role:                     credentialauthorization.RoleOwner,
		IssuedAt:                 wholeSecond(notBefore),
		NotBefore:                wholeSecond(notBefore),
		ValiditySeconds:          credentialauthorization.ValiditySeconds,
		AuthorityVoterSetVersion: 1,
		ClockEndorsements: []credentialauthorization.ClockEndorsement{{
			DeviceID: identity.deviceID,
		}},
		AuthorizationChainIndex: chainIndex,
	}
	copy(authorization.EpochPublicKey[:], publicKey)
	authorization.KeyDigest = sha256.Sum256(publicKey)
	return authorization
}

func signedServiceAdvertisement(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	epoch uint64,
	emittedAt time.Time,
) ([]byte, time.Time) {
	t.Helper()
	expires, err := discovery.AdvertisementExpiresAt(emittedAt)
	if err != nil {
		t.Fatalf("AdvertisementExpiresAt(): %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	advertisement, err := discovery.NewAdvertisement(
		discoveryServiceTestSessionID,
		47831,
		epoch,
		sha256.Sum256(publicKey),
		expires,
	)
	if err != nil {
		t.Fatalf("NewAdvertisement(): %v", err)
	}
	encoded, err := discovery.SignAdvertisement(advertisement, privateKey)
	if err != nil {
		t.Fatalf("SignAdvertisement(): %v", err)
	}
	expiresAt, _ := expires.Time()
	return encoded, expiresAt
}

func serviceTestPrivateKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{seed}, ed25519.SeedSize),
	)
}

func wholeSecond(value time.Time) domain.WholeSecondTimestamp {
	return domain.WholeSecondTimestamp(
		value.UTC().Truncate(time.Second).Format(time.RFC3339),
	)
}

type testSnapshotSource struct {
	mu       sync.RWMutex
	snapshot *peerauth.Snapshot
	err      error
}

func newTestSnapshotSource(snapshot *peerauth.Snapshot) *testSnapshotSource {
	return &testSnapshotSource{snapshot: snapshot}
}

func (source *testSnapshotSource) Current() (*peerauth.Snapshot, error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	return source.snapshot, source.err
}

func (source *testSnapshotSource) Set(snapshot *peerauth.Snapshot) {
	source.mu.Lock()
	source.snapshot = snapshot
	source.mu.Unlock()
}

type testMulticastItem struct {
	datagram discovery.ReceivedDatagram
	err      error
}

type testMulticast struct {
	triggers chan struct{}
	inbound  chan testMulticastItem
	closed   chan struct{}
	sent     chan []byte
	closedAt chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	sendErr   error
	sends     int
	closes    int
}

func newTestMulticast(startupTrigger bool) *testMulticast {
	value := &testMulticast{
		triggers: make(chan struct{}, 16),
		inbound:  make(chan testMulticastItem, 32),
		closed:   make(chan struct{}),
		sent:     make(chan []byte, 32),
		closedAt: make(chan struct{}, 1),
	}
	if startupTrigger {
		value.triggers <- struct{}{}
	}
	return value
}

func (multicast *testMulticast) AdvertisementTriggers() <-chan struct{} {
	return multicast.triggers
}

func (multicast *testMulticast) Send(payload []byte) error {
	multicast.mu.Lock()
	select {
	case <-multicast.closed:
		multicast.mu.Unlock()
		return discovery.ErrMulticastClosed
	default:
	}
	multicast.sends++
	err := multicast.sendErr
	multicast.mu.Unlock()
	multicast.sent <- bytes.Clone(payload)
	return err
}

func (multicast *testMulticast) ReceiveDatagram(
	ctx context.Context,
) (discovery.ReceivedDatagram, error) {
	select {
	case <-ctx.Done():
		return discovery.ReceivedDatagram{}, ctx.Err()
	case <-multicast.closed:
		return discovery.ReceivedDatagram{}, discovery.ErrMulticastClosed
	case item := <-multicast.inbound:
		return item.datagram, item.err
	}
}

func (multicast *testMulticast) Close() error {
	multicast.closeOnce.Do(func() {
		multicast.mu.Lock()
		multicast.closes++
		multicast.mu.Unlock()
		close(multicast.closed)
		multicast.closedAt <- struct{}{}
	})
	return nil
}

func (multicast *testMulticast) setSendError(err error) {
	multicast.mu.Lock()
	multicast.sendErr = err
	multicast.mu.Unlock()
}

func (multicast *testMulticast) sendCount() int {
	multicast.mu.Lock()
	defer multicast.mu.Unlock()
	return multicast.sends
}

func (multicast *testMulticast) closeCount() int {
	multicast.mu.Lock()
	defer multicast.mu.Unlock()
	return multicast.closes
}

func (multicast *testMulticast) trigger() {
	multicast.triggers <- struct{}{}
}

func (multicast *testMulticast) deliver(
	datagram discovery.ReceivedDatagram,
) {
	multicast.inbound <- testMulticastItem{datagram: datagram}
}

func (multicast *testMulticast) deliverError(err error) {
	multicast.inbound <- testMulticastItem{err: err}
}

func (multicast *testMulticast) waitForSend(t *testing.T) {
	t.Helper()
	select {
	case <-multicast.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for advertisement")
	}
}

func (multicast *testMulticast) waitForClose(t *testing.T) {
	t.Helper()
	select {
	case <-multicast.closedAt:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for multicast close")
	}
}

type testCredentials struct {
	advertisement []byte
	notifications chan struct{}
}

func newTestCredentials() *testCredentials {
	return &testCredentials{
		advertisement: []byte("signed-advertisement"),
		notifications: make(chan struct{}, 32),
	}
}

func (credentials *testCredentials) DiscoveryAdvertisement(
	uint16,
) ([]byte, error) {
	return bytes.Clone(credentials.advertisement), nil
}

func (credentials *testCredentials) NotifyConnectivityChange() {
	credentials.notifications <- struct{}{}
}

func (credentials *testCredentials) waitForNotification(t *testing.T) {
	t.Helper()
	select {
	case <-credentials.notifications:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for credential connectivity notification")
	}
}

type testRouteCall struct {
	peer   domain.DeviceID
	source transport.ConsensusRouteSource
	routes []transport.ExpiringConsensusRoute
}

type testRoutes struct {
	mu          sync.Mutex
	calls       []testRouteCall
	expirations int
	callSignal  chan testRouteCall
	expire      chan struct{}
}

func newTestRoutes() *testRoutes {
	return &testRoutes{
		callSignal: make(chan testRouteCall, 64),
		expire:     make(chan struct{}, 16),
	}
}

func (routes *testRoutes) Replace(
	peer domain.DeviceID,
	source transport.ConsensusRouteSource,
	values []transport.ExpiringConsensusRoute,
) error {
	call := testRouteCall{
		peer:   peer,
		source: source,
		routes: append([]transport.ExpiringConsensusRoute(nil), values...),
	}
	routes.mu.Lock()
	routes.calls = append(routes.calls, call)
	routes.mu.Unlock()
	routes.callSignal <- call
	return nil
}

func (routes *testRoutes) Expire() int {
	routes.mu.Lock()
	routes.expirations++
	routes.mu.Unlock()
	routes.expire <- struct{}{}
	return 0
}

func (routes *testRoutes) waitForLearnedRoute(t *testing.T) testRouteCall {
	t.Helper()
	for {
		select {
		case call := <-routes.callSignal:
			if len(call.routes) != 0 {
				return call
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for learned route")
		}
	}
}

func (routes *testRoutes) waitForPurge(
	t *testing.T,
	peer domain.DeviceID,
) {
	t.Helper()
	for {
		select {
		case call := <-routes.callSignal:
			if call.peer == peer && len(call.routes) == 0 {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for discovery-route purge")
		}
	}
}

func (routes *testRoutes) waitForExpiry(t *testing.T) {
	t.Helper()
	select {
	case <-routes.expire:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for route expiry")
	}
}

func (routes *testRoutes) learnCount() int {
	routes.mu.Lock()
	defer routes.mu.Unlock()
	count := 0
	for _, call := range routes.calls {
		if len(call.routes) != 0 {
			count++
		}
	}
	return count
}

type testClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*testTimer
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) NewTimer(delay time.Duration) Timer {
	timer := &testTimer{
		clock:  clock,
		ch:     make(chan time.Time, 1),
		delay:  delay,
		active: true,
	}
	clock.mu.Lock()
	clock.timers = append(clock.timers, timer)
	clock.mu.Unlock()
	return timer
}

func (clock *testClock) hasTimer(delay time.Duration) bool {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	for _, timer := range clock.timers {
		timer.mu.Lock()
		active := timer.active && timer.delay == delay
		timer.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

func (clock *testClock) fire(delay time.Duration) bool {
	clock.mu.Lock()
	var selected *testTimer
	for _, timer := range clock.timers {
		timer.mu.Lock()
		if timer.active && timer.delay == delay {
			timer.active = false
			selected = timer
			timer.mu.Unlock()
			break
		}
		timer.mu.Unlock()
	}
	if selected == nil {
		clock.mu.Unlock()
		return false
	}
	clock.now = clock.now.Add(delay)
	now := clock.now
	clock.mu.Unlock()
	selected.ch <- now
	return true
}

type testTimer struct {
	clock *testClock
	ch    chan time.Time

	mu     sync.Mutex
	delay  time.Duration
	active bool
}

func (timer *testTimer) C() <-chan time.Time {
	return timer.ch
}

func (timer *testTimer) Reset(delay time.Duration) bool {
	timer.mu.Lock()
	wasActive := timer.active
	timer.delay = delay
	timer.active = true
	timer.mu.Unlock()
	return wasActive
}

func (timer *testTimer) Stop() bool {
	timer.mu.Lock()
	wasActive := timer.active
	timer.active = false
	timer.mu.Unlock()
	return wasActive
}

func waitForCondition(
	t *testing.T,
	condition func() bool,
	description string,
) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		default:
			runtime.Gosched()
		}
	}
}
