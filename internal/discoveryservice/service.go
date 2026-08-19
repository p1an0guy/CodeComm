// Package discoveryservice orchestrates authenticated multicast discovery.
package discoveryservice

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	routeMaintenanceInterval  = time.Second
	maxDiscoveryRoutesPerPeer = discovery.MaxEndpointsPerSet
)

var (
	ErrInvalidOptions = errors.New(
		"discovery service: invalid options",
	)
	ErrMulticastFailure = errors.New(
		"discovery service: multicast I/O failed",
	)
	ErrClockFailure = errors.New(
		"discovery service: clock failed",
	)
	ErrEntropyFailure = errors.New(
		"discovery service: entropy failed",
	)
	ErrRouteCleanup = errors.New(
		"discovery service: route cleanup failed",
	)
	ErrObservationPersistence = errors.New(
		"discovery service: persist verified observation",
	)
	ErrClosed = errors.New(
		"discovery service: closed",
	)
)

// Multicast is the owned per-session datagram boundary.
type Multicast interface {
	AdvertisementTriggers() <-chan struct{}
	Send([]byte) error
	ReceiveDatagram(context.Context) (discovery.ReceivedDatagram, error)
	Close() error
}

// AdmissionSnapshotProvider returns one immutable applied-state cut.
type AdmissionSnapshotProvider func() (*peerauth.Snapshot, error)

// CredentialAdvertiser signs advertisements and accepts connectivity hints.
// Its lifetime remains owned by the caller.
type CredentialAdvertiser interface {
	DiscoveryAdvertisement(uint16) ([]byte, error)
	NotifyConnectivityChange()
}

// SelectedLocalAddressLookup resolves the selected source address for the
// exact receiving interface, address family, and destination scope.
type SelectedLocalAddressLookup func(
	interfaceIndex int,
	family discovery.AddressFamily,
	destination netip.AddrPort,
) (netip.Addr, bool)

// RawDiscoveryObservation is one authenticated datagram source retained only
// as a bounded routing hint. It grants no membership or content authority.
type RawDiscoveryObservation struct {
	DeviceID             domain.DeviceID
	Endpoint             netip.AddrPort
	SelectedLocalAddress netip.Addr
	ObservedAt           domain.Timestamp
	ExpiresAt            domain.Timestamp
}

// RawDiscoveryObserver persists or audits a verified raw hint before the
// ephemeral route is installed. Returning an error fails the service closed.
type RawDiscoveryObserver func(context.Context, RawDiscoveryObservation) error

// RouteTable is the borrowed discovery-route projection boundary.
type RouteTable interface {
	Replace(
		domain.DeviceID,
		transport.ConsensusRouteSource,
		[]transport.ExpiringConsensusRoute,
	) error
	Expire() int
}

var (
	_ Multicast  = (*discovery.MulticastIO)(nil)
	_ RouteTable = (*transport.ConsensusRouteTable)(nil)
)

// Timer is the resettable clock subset used by the orchestration loop.
type Timer interface {
	C() <-chan time.Time
	Reset(time.Duration) bool
	Stop() bool
}

// Clock supplies deterministic time and timers.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

// Options contains one session's discovery dependencies. On successful New,
// Multicast ownership transfers to the service.
type Options struct {
	SessionID             domain.UUIDv7
	LocalDeviceID         domain.DeviceID
	HTTPSPort             uint16
	AdvertisementInterval time.Duration

	Multicast            Multicast
	AdmissionSnapshots   AdmissionSnapshotProvider
	Credentials          CredentialAdvertiser
	SelectedLocalAddress SelectedLocalAddressLookup
	Routes               RouteTable
	ObserveRawDiscovery  RawDiscoveryObserver

	Clock   Clock
	Entropy io.Reader
}

type serviceOptions struct {
	Options
	maintenanceInterval time.Duration
}

// Service owns multicast receive/advertise loops and ephemeral discovery
// routes. It never grants membership or content-plane authority.
type Service struct {
	sessionID             domain.UUIDv7
	localDeviceID         domain.DeviceID
	httpsPort             uint16
	advertisementInterval time.Duration
	maintenanceInterval   time.Duration

	multicast          Multicast
	admissionSnapshots AdmissionSnapshotProvider
	credentials        CredentialAdvertiser
	selectedLocal      SelectedLocalAddressLookup
	routes             RouteTable
	observeRaw         RawDiscoveryObserver
	clock              Clock
	entropy            io.Reader
	receiver           *discovery.Receiver

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	results chan receivedResult
	updates chan advertisementIntervalUpdate

	mu          sync.RWMutex
	closing     bool
	revoked     bool
	fatalErr    error
	shutdownErr error
	closeErr    error

	closeMulticastOnce sync.Once
	releaseOnce        sync.Once

	learned         map[domain.DeviceID]map[netip.AddrPort]learnedRoute
	nextObservation uint64
}

type learnedRoute struct {
	value       transport.ExpiringConsensusRoute
	observation uint64
}

type receivedResult struct {
	datagram discovery.ReceivedDatagram
	err      error
}

type advertisementIntervalUpdate struct {
	interval time.Duration
	result   chan error
}

type localMembershipState uint8

const (
	localMembershipUnavailable localMembershipState = iota
	localMembershipPermitted
	localMembershipRevoked
)

// New validates dependencies and starts discovery immediately.
func New(options Options) (*Service, error) {
	return newService(serviceOptions{
		Options:             options,
		maintenanceInterval: routeMaintenanceInterval,
	})
}

func newService(options serviceOptions) (*Service, error) {
	if options.Clock == nil {
		options.Clock = wallClock{}
	}
	if options.Entropy == nil {
		options.Entropy = cryptorand.Reader
	}
	if !options.SessionID.Valid() ||
		!options.LocalDeviceID.Valid() ||
		options.HTTPSPort == 0 ||
		nilInterface(options.Multicast) ||
		options.AdmissionSnapshots == nil ||
		nilInterface(options.Credentials) ||
		options.SelectedLocalAddress == nil ||
		nilInterface(options.Routes) ||
		nilInterface(options.Clock) ||
		nilInterface(options.Entropy) ||
		options.maintenanceInterval <= 0 {
		return nil, ErrInvalidOptions
	}
	if _, err := discovery.MulticastBaseInterval(
		options.AdvertisementInterval,
	); err != nil {
		return nil, fmt.Errorf("%w: advertisement interval: %v", ErrInvalidOptions, err)
	}
	if options.Multicast.AdvertisementTriggers() == nil {
		return nil, fmt.Errorf("%w: nil advertisement trigger", ErrInvalidOptions)
	}

	ctx, cancel := context.WithCancel(context.Background())
	service := &Service{
		sessionID:             options.SessionID,
		localDeviceID:         options.LocalDeviceID,
		httpsPort:             options.HTTPSPort,
		advertisementInterval: options.AdvertisementInterval,
		maintenanceInterval:   options.maintenanceInterval,
		multicast:             options.Multicast,
		admissionSnapshots:    options.AdmissionSnapshots,
		credentials:           options.Credentials,
		selectedLocal:         options.SelectedLocalAddress,
		routes:                options.Routes,
		observeRaw:            options.ObserveRawDiscovery,
		clock:                 options.Clock,
		entropy:               options.Entropy,
		ctx:                   ctx,
		cancel:                cancel,
		results:               make(chan receivedResult, 1),
		updates:               make(chan advertisementIntervalUpdate),
		learned: make(
			map[domain.DeviceID]map[netip.AddrPort]learnedRoute,
		),
	}
	receiver, err := discovery.NewReceiver(
		options.SessionID,
		service.resolveCredential,
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: receiver: %v", ErrInvalidOptions, err)
	}
	service.receiver = receiver
	service.wg.Add(2)
	go service.receiveLoop()
	go service.controlLoop()
	return service, nil
}

// UpdateAdvertisementInterval applies a newly committed policy value to the
// running cadence. The control loop owns timer mutation.
func (service *Service) UpdateAdvertisementInterval(
	ctx context.Context,
	interval time.Duration,
) error {
	if service == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if _, err := discovery.MulticastBaseInterval(interval); err != nil {
		return fmt.Errorf("%w: advertisement interval: %v", ErrInvalidOptions, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	service.mu.RLock()
	closed := service.closing || service.revoked
	serviceContext := service.ctx
	updates := service.updates
	service.mu.RUnlock()
	if closed || serviceContext == nil || updates == nil {
		return ErrClosed
	}
	request := advertisementIntervalUpdate{
		interval: interval,
		result:   make(chan error, 1),
	}
	select {
	case updates <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-serviceContext.Done():
		return ErrClosed
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-serviceContext.Done():
		return ErrClosed
	}
}

// BeginClose stops new work and closes the owned multicast handle.
func (service *Service) BeginClose() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.mu.Lock()
	service.closing = true
	service.mu.Unlock()
	service.cancel()
	err := service.closeMulticast()
	service.recordShutdownError(err)
	return err
}

// Wait initiates shutdown, joins both workers, purges learned routes, and
// releases borrowed references.
func (service *Service) Wait() error {
	if service == nil {
		return ErrInvalidOptions
	}
	beginErr := service.BeginClose()
	service.wg.Wait()
	service.mu.RLock()
	result := errors.Join(beginErr, service.shutdownErr, service.fatalErr)
	service.mu.RUnlock()
	service.release()
	return result
}

// Close stops and joins the service.
func (service *Service) Close() error {
	return service.Wait()
}

// FatalError returns the first asynchronous fatal failure.
func (service *Service) FatalError() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.fatalErr
}

func (service *Service) receiveLoop() {
	defer service.wg.Done()
	for {
		datagram, err := service.multicast.ReceiveDatagram(service.ctx)
		if err != nil && ignorableReceiveError(err) {
			continue
		}
		select {
		case service.results <- receivedResult{datagram: datagram, err: err}:
		case <-service.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (service *Service) controlLoop() {
	defer service.wg.Done()
	defer service.finishControlLoop()

	triggers := service.multicast.AdvertisementTriggers()

	// OpenMulticast emits a startup trigger. Consume that coalesced signal
	// because this loop performs its own mandatory immediate advertisement.
	select {
	case _, ok := <-triggers:
		if !ok {
			service.fail(fmt.Errorf(
				"%w: advertisement trigger closed",
				ErrMulticastFailure,
			))
			return
		}
	default:
	}

	if now := service.clock.Now(); now.IsZero() {
		service.fail(ErrClockFailure)
		return
	}
	state := service.localMembership()
	if state == localMembershipRevoked {
		service.stopForRevocation()
		return
	}
	if state == localMembershipPermitted {
		if !service.advertise() {
			return
		}
	}

	advertisementDelay, err := service.nextAdvertisementDelay()
	if err != nil {
		service.fail(err)
		return
	}
	advertisementTimer := service.clock.NewTimer(advertisementDelay)
	maintenanceTimer := service.clock.NewTimer(service.maintenanceInterval)
	if nilInterface(advertisementTimer) ||
		nilInterface(maintenanceTimer) ||
		advertisementTimer.C() == nil ||
		maintenanceTimer.C() == nil {
		if !nilInterface(advertisementTimer) {
			advertisementTimer.Stop()
		}
		if !nilInterface(maintenanceTimer) {
			maintenanceTimer.Stop()
		}
		service.fail(ErrClockFailure)
		return
	}
	defer advertisementTimer.Stop()
	defer maintenanceTimer.Stop()

	for {
		select {
		case <-service.ctx.Done():
			return
		case _, ok := <-triggers:
			if !ok {
				if !service.stopping() {
					service.fail(fmt.Errorf(
						"%w: advertisement trigger closed",
						ErrMulticastFailure,
					))
				}
				return
			}
			service.credentials.NotifyConnectivityChange()
			if !service.advertiseIfPermitted() {
				return
			}
			if !service.resetAdvertisementTimer(advertisementTimer) {
				return
			}
		case <-advertisementTimer.C():
			if !service.advertiseIfPermitted() {
				return
			}
			if !service.resetAdvertisementTimer(advertisementTimer) {
				return
			}
		case update := <-service.updates:
			service.advertisementInterval = update.interval
			if !service.resetAdvertisementTimer(advertisementTimer) {
				update.result <- service.FatalError()
				return
			}
			update.result <- nil
		case <-maintenanceTimer.C():
			if !service.maintainRoutes() {
				return
			}
			resetTimer(maintenanceTimer, service.maintenanceInterval)
		case result := <-service.results:
			if result.err != nil {
				if service.stopping() {
					return
				}
				closeErr := service.closeMulticast()
				service.fail(errors.Join(
					fmt.Errorf(
						"%w: receive: %w",
						ErrMulticastFailure,
						result.err,
					),
					closeErr,
				))
				return
			}
			if !service.accept(result.datagram) {
				return
			}
		}
	}
}

func (service *Service) advertiseIfPermitted() bool {
	switch service.localMembership() {
	case localMembershipRevoked:
		service.stopForRevocation()
		return false
	case localMembershipPermitted:
		return service.advertise()
	default:
		return true
	}
}

func (service *Service) advertise() bool {
	payload, err := service.credentials.DiscoveryAdvertisement(
		service.httpsPort,
	)
	if err != nil ||
		len(payload) == 0 ||
		len(payload) > discovery.MaxDatagramBytes {
		return true
	}
	err = service.multicast.Send(payload)
	if errors.Is(err, discovery.ErrMulticastClosed) {
		if !service.stopping() {
			closeErr := service.closeMulticast()
			service.fail(errors.Join(
				fmt.Errorf("%w: send: %w", ErrMulticastFailure, err),
				closeErr,
			))
		}
		return false
	}
	// Send reports per-interface failures as a joined error. Other usable
	// joins remain active, and the next scheduled or triggered send retries.
	return true
}

func (service *Service) nextAdvertisementDelay() (time.Duration, error) {
	delay, err := discovery.NextAdvertisementDelay(
		service.advertisementInterval,
		service.entropy,
	)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrEntropyFailure, err)
	}
	return delay, nil
}

func (service *Service) resetAdvertisementTimer(timer Timer) bool {
	delay, err := service.nextAdvertisementDelay()
	if err != nil {
		service.fail(err)
		return false
	}
	resetTimer(timer, delay)
	return true
}

func (service *Service) accept(datagram discovery.ReceivedDatagram) bool {
	switch service.localMembership() {
	case localMembershipRevoked:
		service.stopForRevocation()
		return false
	case localMembershipUnavailable:
		return true
	}
	hint, err := service.receiver.Accept(
		service.ctx,
		datagram.Payload,
		datagram.Source,
	)
	if err != nil {
		return true
	}
	switch service.localMembership() {
	case localMembershipRevoked:
		service.stopForRevocation()
		return false
	case localMembershipUnavailable:
		return true
	}
	if !service.learn(hint, datagram) {
		return true
	}
	service.credentials.NotifyConnectivityChange()
	return true
}

func (service *Service) learn(
	hint discovery.Hint,
	datagram discovery.ReceivedDatagram,
) bool {
	expiresAt, err := hint.ExpiresAt.Time()
	if err != nil {
		return false
	}
	now := service.clock.Now()
	if now.IsZero() || !expiresAt.After(now) {
		return false
	}
	observedAt, err := domain.ParseTimestamp(
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		service.fail(ErrClockFailure)
		return false
	}
	local, found := service.selectedLocal(
		datagram.InterfaceIndex,
		datagram.Family,
		hint.Destination,
	)
	if !found ||
		!selectedAddressMatches(local, hint.Destination, datagram.Family) {
		return false
	}
	if service.observeRaw != nil {
		if err := service.observeRaw(service.ctx, RawDiscoveryObservation{
			DeviceID:             hint.ExpectedDeviceID,
			Endpoint:             hint.Destination,
			SelectedLocalAddress: local,
			ObservedAt:           observedAt,
			ExpiresAt:            hint.ExpiresAt,
		}); err != nil {
			service.fail(fmt.Errorf(
				"%w: %w",
				ErrObservationPersistence,
				err,
			))
			return false
		}
	}

	if service.nextObservation == ^uint64(0) {
		if service.purgeAll() != nil {
			return false
		}
		service.nextObservation = 0
	}
	service.nextObservation++
	next := cloneLearnedRoutes(service.learned[hint.ExpectedDeviceID])
	for endpoint, route := range next {
		if !route.value.ExpiresAt.After(now) {
			delete(next, endpoint)
		}
	}
	next[hint.Destination] = learnedRoute{
		value: transport.ExpiringConsensusRoute{
			ConsensusRoute: transport.ConsensusRoute{
				PeerDeviceID:         hint.ExpectedDeviceID,
				RemoteEndpoint:       hint.Destination,
				SelectedLocalAddress: local,
			},
			ExpiresAt: expiresAt,
		},
		observation: service.nextObservation,
	}
	for len(next) > maxDiscoveryRoutesPerPeer {
		delete(next, oldestLearnedEndpoint(next))
	}

	for len(next) > 0 {
		err = service.routes.Replace(
			hint.ExpectedDeviceID,
			transport.ConsensusRouteDiscovery,
			orderedExpiringRoutes(next),
		)
		if err == nil {
			service.learned[hint.ExpectedDeviceID] = next
			return true
		}
		if !errors.Is(err, transport.ErrConsensusRouteCapacity) {
			return false
		}
		delete(next, oldestLearnedEndpoint(next))
	}
	return false
}

func (service *Service) maintainRoutes() bool {
	now := service.clock.Now()
	if now.IsZero() {
		service.fail(ErrClockFailure)
		return false
	}
	snapshot, available := service.currentSnapshot()
	if available {
		member, exists := snapshot.Member(service.localDeviceID)
		if exists && member.Status == device.StatusRevoked {
			service.stopForRevocation()
			return false
		}
		for peer := range service.learned {
			member, exists := snapshot.Member(peer)
			if exists && member.Status == device.StatusActive {
				continue
			}
			if service.purgePeer(peer) == nil {
				delete(service.learned, peer)
			}
		}
	}

	service.routes.Expire()
	for peer, routes := range service.learned {
		for endpoint, route := range routes {
			if !route.value.ExpiresAt.After(now) {
				delete(routes, endpoint)
			}
		}
		if len(routes) == 0 {
			delete(service.learned, peer)
		}
	}
	return true
}

func (service *Service) resolveCredential(
	ctx context.Context,
	sessionID domain.UUIDv7,
	epoch uint64,
	keyDigest [sha256.Size]byte,
) (discovery.CredentialRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return discovery.CredentialRecord{}, false, err
	}
	snapshot, available := service.currentSnapshot()
	if !available || sessionID != service.sessionID {
		return discovery.CredentialRecord{}, false, nil
	}
	local, exists := snapshot.Member(service.localDeviceID)
	if !exists || local.Status == device.StatusRevoked {
		return discovery.CredentialRecord{}, false, nil
	}
	authorization, member, found :=
		snapshot.AuthorizationByEpochDigest(epoch, keyDigest)
	if !found ||
		member.ID == service.localDeviceID ||
		member.Status != device.StatusActive ||
		authorization.Validate() != nil {
		return discovery.CredentialRecord{}, false, nil
	}
	currentEpoch, found := snapshot.CurrentCredentialEpoch(member.ID)
	if !found ||
		authorization.Epoch > currentEpoch ||
		currentEpoch-authorization.Epoch > 1 {
		return discovery.CredentialRecord{}, false, nil
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		return discovery.CredentialRecord{}, false, nil
	}
	notAfter := domain.WholeSecondTimestamp(
		notBefore.Add(
			time.Duration(authorization.ValiditySeconds) * time.Second,
		).UTC().Format(time.RFC3339),
	)
	return discovery.CredentialRecord{
		DeviceID:       member.ID,
		Epoch:          authorization.Epoch,
		PublicKey:      slices.Clone(authorization.EpochPublicKey[:]),
		NotBefore:      authorization.NotBefore,
		NotAfter:       notAfter,
		MemberActive:   true,
		LatestRetained: authorization.Epoch == currentEpoch,
	}, true, nil
}

func (service *Service) localMembership() localMembershipState {
	snapshot, available := service.currentSnapshot()
	if !available {
		return localMembershipUnavailable
	}
	member, exists := snapshot.Member(service.localDeviceID)
	if !exists {
		return localMembershipUnavailable
	}
	if member.Status == device.StatusRevoked {
		return localMembershipRevoked
	}
	return localMembershipPermitted
}

func (service *Service) currentSnapshot() (*peerauth.Snapshot, bool) {
	snapshot, err := service.admissionSnapshots()
	if err != nil || snapshot == nil {
		return nil, false
	}
	sessionID, _, valid := snapshot.Lineage()
	if !valid || sessionID != service.sessionID {
		return nil, false
	}
	return snapshot, true
}

func (service *Service) stopForRevocation() {
	service.mu.Lock()
	service.revoked = true
	service.mu.Unlock()
	purgeErr := service.purgeAll()
	closeErr := service.closeMulticast()
	if err := errors.Join(purgeErr, closeErr); err != nil {
		service.fail(err)
		return
	}
	service.cancel()
}

func (service *Service) purgePeer(peer domain.DeviceID) error {
	if err := service.routes.Replace(
		peer,
		transport.ConsensusRouteDiscovery,
		nil,
	); err != nil {
		return fmt.Errorf("%w: peer %s: %w", ErrRouteCleanup, peer, err)
	}
	return nil
}

func (service *Service) purgeAll() error {
	var result error
	for peer := range service.learned {
		if err := service.purgePeer(peer); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(service.learned, peer)
	}
	return result
}

func (service *Service) finishControlLoop() {
	service.cancel()
	purgeErr := service.purgeAll()
	closeErr := service.closeMulticast()
	err := errors.Join(purgeErr, closeErr)
	if err == nil {
		return
	}
	if service.stopping() {
		service.recordShutdownError(err)
		return
	}
	service.fail(err)
}

func (service *Service) fail(err error) {
	if err == nil {
		return
	}
	service.mu.Lock()
	if service.fatalErr == nil {
		service.fatalErr = err
	}
	service.mu.Unlock()
	service.cancel()
	closeErr := service.closeMulticast()
	if closeErr != nil {
		service.mu.Lock()
		service.fatalErr = errors.Join(service.fatalErr, closeErr)
		service.mu.Unlock()
	}
}

func (service *Service) closeMulticast() error {
	service.closeMulticastOnce.Do(func() {
		err := service.multicast.Close()
		service.mu.Lock()
		service.closeErr = err
		service.mu.Unlock()
	})
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.closeErr
}

func (service *Service) recordShutdownError(err error) {
	if err == nil {
		return
	}
	service.mu.Lock()
	service.shutdownErr = errors.Join(service.shutdownErr, err)
	service.mu.Unlock()
}

func (service *Service) stopping() bool {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.closing || service.revoked
}

func (service *Service) release() {
	service.releaseOnce.Do(func() {
		service.mu.Lock()
		service.multicast = nil
		service.admissionSnapshots = nil
		service.credentials = nil
		service.selectedLocal = nil
		service.routes = nil
		service.observeRaw = nil
		service.clock = nil
		service.entropy = nil
		service.receiver = nil
		service.results = nil
		service.updates = nil
		service.mu.Unlock()
		clear(service.learned)
		service.learned = nil
	})
}

func cloneLearnedRoutes(
	source map[netip.AddrPort]learnedRoute,
) map[netip.AddrPort]learnedRoute {
	result := make(map[netip.AddrPort]learnedRoute, len(source)+1)
	for endpoint, route := range source {
		result[endpoint] = route
	}
	return result
}

func orderedExpiringRoutes(
	routes map[netip.AddrPort]learnedRoute,
) []transport.ExpiringConsensusRoute {
	endpoints := make([]netip.AddrPort, 0, len(routes))
	for endpoint := range routes {
		endpoints = append(endpoints, endpoint)
	}
	slices.SortFunc(endpoints, func(left, right netip.AddrPort) int {
		return left.Compare(right)
	})
	result := make([]transport.ExpiringConsensusRoute, 0, len(endpoints))
	for _, endpoint := range endpoints {
		result = append(result, routes[endpoint].value)
	}
	return result
}

func oldestLearnedEndpoint(
	routes map[netip.AddrPort]learnedRoute,
) netip.AddrPort {
	var (
		oldest    netip.AddrPort
		oldestSet bool
	)
	for endpoint, route := range routes {
		if !oldestSet ||
			route.observation < routes[oldest].observation ||
			route.observation == routes[oldest].observation &&
				endpoint.Compare(oldest) < 0 {
			oldest = endpoint
			oldestSet = true
		}
	}
	return oldest
}

func selectedAddressMatches(
	local netip.Addr,
	remote netip.AddrPort,
	family discovery.AddressFamily,
) bool {
	if !local.IsValid() ||
		!remote.IsValid() ||
		local.Is4In6() ||
		remote.Addr().Is4In6() ||
		local.IsLoopback() ||
		local.IsUnspecified() ||
		local.IsMulticast() ||
		!(local.IsGlobalUnicast() || local.IsLinkLocalUnicast()) {
		return false
	}
	switch family {
	case discovery.AddressFamilyIPv4:
		return local.Is4() &&
			remote.Addr().Is4() &&
			local.Zone() == ""
	case discovery.AddressFamilyIPv6:
		if !local.Is6() || !remote.Addr().Is6() {
			return false
		}
		if local.IsLinkLocalUnicast() ||
			remote.Addr().IsLinkLocalUnicast() {
			return local.Zone() != "" &&
				local.Zone() == remote.Addr().Zone()
		}
		return local.Zone() == "" && remote.Addr().Zone() == ""
	default:
		return false
	}
}

func ignorableReceiveError(err error) bool {
	return errors.Is(err, discovery.ErrMulticastSource) ||
		errors.Is(err, discovery.ErrMulticastInterface) ||
		errors.Is(err, discovery.ErrMulticastDatagramSize)
}

func resetTimer(timer Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C():
		default:
		}
	}
	timer.Reset(delay)
}

func nilInterface(value any) bool {
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

type wallClock struct{}

func (wallClock) Now() time.Time {
	return time.Now()
}

func (wallClock) NewTimer(delay time.Duration) Timer {
	return &wallTimer{timer: time.NewTimer(delay)}
}

type wallTimer struct {
	timer *time.Timer
}

func (timer *wallTimer) C() <-chan time.Time {
	return timer.timer.C
}

func (timer *wallTimer) Reset(delay time.Duration) bool {
	return timer.timer.Reset(delay)
}

func (timer *wallTimer) Stop() bool {
	return timer.timer.Stop()
}
