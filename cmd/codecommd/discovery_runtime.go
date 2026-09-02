package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/discoveryservice"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/endpointservice"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	daemonDiscoveryRefreshInterval = 2 * time.Second
	daemonDiscoveryUpdateTimeout   = 5 * time.Second
)

var errDaemonDiscoveryConstruction = errors.New(
	"codecommd: discovery construction failed",
)

type daemonDiscoveryMulticast interface {
	discoveryservice.Multicast
	RefreshSelected(
		[]discovery.MulticastInterfaceSelection,
	) (discovery.MulticastReport, error)
}

type daemonRuntimeDiscoveryMulticast interface {
	daemonDiscoveryMulticast
	TriggerAdvertisement() error
}

type daemonMulticastOpener func(
	uint16,
	[]discovery.MulticastInterfaceSelection,
) (daemonDiscoveryMulticast, discovery.MulticastReport, error)

type daemonInterfaceLister func() ([]net.Interface, error)

type daemonInterfaceAddressProvider func(
	*net.Interface,
) ([]net.Addr, error)

type daemonDiscoveryAddressKey struct {
	interfaceIndex int
	family         discovery.AddressFamily
	linkLocal      bool
}

type daemonDiscoverySelector struct {
	interfaceName string
	family        discovery.AddressFamily
	linkLocal     bool
	ordinal       uint8
}

type daemonDiscoveryAddressBook struct {
	mu                sync.RWMutex
	addresses         map[daemonDiscoveryAddressKey]netip.Addr
	selectedAddresses []netip.Addr
}

type daemonDiscoverySelection struct {
	interfaces []net.Interface
	addresses  map[daemonDiscoveryAddressKey]netip.Addr
	selected   []netip.Addr
	listeners  []netip.AddrPort
	bindings   map[daemonDiscoverySelector]netip.Addr
}

type daemonDiscoveryCredentials interface {
	discoveryservice.CredentialAdvertiser
	daemonConnectivityNotifier
}

type daemonDiscoveryPolicy interface {
	DiscoveryAdvertisementInterval(context.Context) (time.Duration, error)
}

type daemonEndpointPublisher interface {
	Refresh(context.Context, endpointservice.RefreshInput) error
	Withdraw() error
	CurrentEndpointSet() ([]byte, bool)
	BeginClose() error
	Wait() error
	Close() error
}

type daemonSelectedAddressRoutes interface {
	RebindSelectedAddresses([]netip.Addr, []netip.Addr) error
}

type daemonInboundAddressInvalidator interface {
	CloseConnectionsBoundTo(
		[]netip.Addr,
	) (transport.LocalAddressCloseResult, error)
}

type daemonDiscoveryRuntime struct {
	service               *discoveryservice.Service
	publisher             daemonEndpointPublisher
	reconciler            *daemonEndpointRouteReconciler
	multicast             daemonRuntimeDiscoveryMulticast
	addresses             *daemonDiscoveryAddressBook
	routes                daemonSelectedAddressRoutes
	listeners             *daemonPeerListenerSet
	selectors             []daemonDiscoverySelector
	bindings              map[daemonDiscoverySelector]netip.Addr
	listenerPort          uint16
	localState            daemonDiscoveryPolicy
	listInterfaces        daemonInterfaceLister
	interfaceAddrs        daemonInterfaceAddressProvider
	connectivity          daemonConnectivityNotifier
	advertisementInterval atomic.Int64
	publicationMu         sync.RWMutex
	publicationDirty      bool
	ingressMu             sync.RWMutex
	ingress               daemonInboundAddressInvalidator

	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once

	fatalMu      sync.RWMutex
	fatalErr     error
	discoveryErr error
	closing      bool
}

func incompleteDaemonDiscoveryDependencies(
	dependencies daemonDependencies,
) bool {
	count := 0
	if dependencies.openMulticast != nil {
		count++
	}
	if dependencies.listInterfaces != nil {
		count++
	}
	if dependencies.interfaceAddrs != nil {
		count++
	}
	return count != 0 && count != 3
}

func openDaemonMulticast(
	port uint16,
	selected []discovery.MulticastInterfaceSelection,
) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
	return discovery.OpenSelectedMulticast(port, selected)
}

func newDaemonDiscoveryRuntime(
	ctx context.Context,
	options daemonOptions,
	deviceID domain.DeviceID,
	view store.StateView,
	identityPrivateKey []byte,
	localState store.LocalState,
	admission daemonPeerAdmissionRuntime,
	credentials daemonDiscoveryCredentials,
	meshFactory daemonConsensusTransportFactory,
	dependencies daemonDependencies,
	peerListeners *daemonPeerListenerSet,
) (*daemonDiscoveryRuntime, error) {
	if ctx == nil {
		return nil, errDaemonDiscoveryConstruction
	}
	if len(options.peerListeners) == 0 ||
		dependencies.openMulticast == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !deviceID.Valid() ||
		admission == nil ||
		credentials == nil ||
		meshFactory == nil ||
		peerListeners == nil ||
		dependencies.listInterfaces == nil ||
		dependencies.interfaceAddrs == nil {
		return nil, errDaemonDiscoveryConstruction
	}
	if !slices.Equal(peerListeners.Current(), options.peerListeners) {
		return nil, errDaemonDiscoveryConstruction
	}
	routes := meshFactory.ConsensusRoutes()
	if routes == nil {
		return nil, errDaemonDiscoveryConstruction
	}
	interfaces, err := dependencies.listInterfaces()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: list interfaces: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	selection, err := resolveDaemonDiscoverySelection(
		options.peerListeners,
		interfaces,
		dependencies.interfaceAddrs,
	)
	if err != nil {
		return nil, err
	}
	multicast, _, err := newDaemonRecoveringMulticast(
		discovery.DefaultMulticastPort,
		daemonDiscoveryMulticastSelections(selection),
		dependencies.openMulticast,
	)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = multicast.Close()
		}
	}()
	interval, err := localState.DiscoveryAdvertisementInterval(
		ctx,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: read advertisement interval: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	publisher, err := newDaemonEndpointPublisher(
		ctx,
		options,
		deviceID,
		view.RecoveryGeneration,
		identityPrivateKey,
		localState,
		interval,
	)
	if err != nil {
		return nil, err
	}
	publisherOwned := false
	defer func() {
		if !publisherOwned {
			_ = publisher.Close()
		}
	}()
	book := &daemonDiscoveryAddressBook{}
	book.replace(selection.addresses, daemonDiscoverySelectedAddresses(selection))
	reconciler, err := newDaemonEndpointRouteReconciler(
		deviceID,
		localState,
		routes,
		options.peerRoutes,
		selection.bindings,
	)
	if err != nil {
		return nil, err
	}
	if err := reconciler.reconcile(
		ctx,
		daemonDiscoverySelectedAddresses(selection),
		true,
	); err != nil {
		return nil, err
	}
	service, err := discoveryservice.New(discoveryservice.Options{
		SessionID:             options.sessionID,
		LocalDeviceID:         deviceID,
		HTTPSPort:             options.peerListeners[0].Port(),
		AdvertisementInterval: interval,
		Multicast:             multicast,
		AdmissionSnapshots:    admission.PeerAdmissionSnapshot,
		Credentials:           credentials,
		SelectedLocalAddress:  book.lookup,
		Routes:                routes,
		ObserveRawDiscovery: func(
			ctx context.Context,
			observation discoveryservice.RawDiscoveryObservation,
		) error {
			expiresAt, err := domain.ParseWholeSecondTimestamp(
				string(observation.ExpiresAt),
			)
			if err != nil {
				return err
			}
			return localState.UpsertRawDiscoveryEndpoint(
				ctx,
				observation.DeviceID,
				observation.Endpoint,
				observation.ObservedAt,
				expiresAt,
			)
		},
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: start service: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	refreshContext, cancel := context.WithCancel(context.Background())
	runtime := &daemonDiscoveryRuntime{
		service:        service,
		publisher:      publisher,
		reconciler:     reconciler,
		multicast:      multicast,
		addresses:      book,
		routes:         routes,
		listeners:      peerListeners,
		selectors:      daemonDiscoverySelectors(selection),
		bindings:       cloneDaemonDiscoveryBindings(selection.bindings),
		listenerPort:   options.peerListeners[0].Port(),
		localState:     localState,
		listInterfaces: dependencies.listInterfaces,
		interfaceAddrs: dependencies.interfaceAddrs,
		connectivity:   credentials,
		cancel:         cancel,
		done:           make(chan struct{}),
	}
	runtime.advertisementInterval.Store(int64(interval))
	owned = true
	publisherOwned = true
	go runtime.refreshLoop(refreshContext)
	return runtime, nil
}

func (runtime *daemonDiscoveryRuntime) BeginClose() error {
	if runtime == nil || runtime.service == nil || runtime.publisher == nil ||
		runtime.cancel == nil {
		return errDaemonDiscoveryConstruction
	}
	runtime.fatalMu.Lock()
	runtime.closing = true
	runtime.closeOnce.Do(runtime.cancel)
	runtime.fatalMu.Unlock()
	return errors.Join(
		runtime.service.BeginClose(),
		runtime.publisher.BeginClose(),
	)
}

func (runtime *daemonDiscoveryRuntime) Wait() error {
	if runtime == nil || runtime.service == nil || runtime.publisher == nil ||
		runtime.done == nil {
		return errDaemonDiscoveryConstruction
	}
	beginErr := runtime.BeginClose()
	<-runtime.done
	return errors.Join(
		beginErr,
		runtime.service.Wait(),
		runtime.publisher.Wait(),
	)
}

func (runtime *daemonDiscoveryRuntime) FatalError() error {
	if runtime == nil || runtime.service == nil || runtime.publisher == nil {
		return errDaemonDiscoveryConstruction
	}
	runtime.fatalMu.RLock()
	fatal := runtime.fatalErr
	runtime.fatalMu.RUnlock()
	return errors.Join(runtime.service.FatalError(), fatal)
}

func (runtime *daemonDiscoveryRuntime) refreshLoop(ctx context.Context) {
	defer close(runtime.done)
	ticker := time.NewTicker(daemonDiscoveryRefreshInterval)
	endpointTimer := time.NewTimer(runtime.currentAdvertisementInterval())
	defer ticker.Stop()
	defer endpointTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshChanged, err := runtime.refresh(ctx)
			if err != nil {
				runtime.recordDiscoveryFailure(err)
			} else {
				runtime.clearDiscoveryFailure()
			}
			if refreshChanged {
				resetDaemonDiscoveryTimer(
					endpointTimer,
					runtime.currentAdvertisementInterval(),
				)
			}
			if err := runtime.reconciler.reconcile(
				ctx,
				runtime.addresses.selected(),
				false,
			); err != nil {
				runtime.failRouteRefresh(err)
				return
			}
		case <-endpointTimer.C:
			if !runtime.publishEndpointSet(ctx) {
				return
			}
			resetDaemonDiscoveryTimer(
				endpointTimer,
				runtime.currentAdvertisementInterval(),
			)
		}
	}
}

func (runtime *daemonDiscoveryRuntime) publishEndpointSet(
	ctx context.Context,
) bool {
	runtime.publicationMu.Lock()
	err := runtime.refreshEndpointPublicationLocked(ctx)
	runtime.publicationDirty = err != nil
	runtime.publicationMu.Unlock()
	if err != nil {
		runtime.failEndpointRefresh(err)
		return false
	}
	return true
}

func (runtime *daemonDiscoveryRuntime) failEndpointRefresh(err error) {
	if err == nil {
		return
	}
	runtime.fatalMu.Lock()
	if runtime.closing {
		runtime.fatalMu.Unlock()
		return
	}
	if runtime.fatalErr == nil {
		runtime.fatalErr = fmt.Errorf(
			"%w: refresh endpoint set: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	runtime.fatalMu.Unlock()
	_ = runtime.service.BeginClose()
	runtime.cancel()
}

func (runtime *daemonDiscoveryRuntime) failRouteRefresh(err error) {
	if err == nil {
		return
	}
	runtime.fatalMu.Lock()
	if runtime.closing {
		runtime.fatalMu.Unlock()
		return
	}
	if runtime.fatalErr == nil {
		runtime.fatalErr = fmt.Errorf(
			"%w: refresh endpoint routes: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	runtime.fatalMu.Unlock()
	_ = runtime.service.BeginClose()
	runtime.cancel()
}

func (runtime *daemonDiscoveryRuntime) CurrentEndpointSet() (
	[]byte,
	time.Duration,
	bool,
) {
	if runtime == nil || runtime.publisher == nil {
		return nil, 0, false
	}
	runtime.publicationMu.RLock()
	defer runtime.publicationMu.RUnlock()
	interval := runtime.currentAdvertisementInterval()
	if interval <= 0 {
		return nil, 0, false
	}
	value, found := runtime.publisher.CurrentEndpointSet()
	return value, interval, found
}

func (runtime *daemonDiscoveryRuntime) refresh(
	ctx context.Context,
) (bool, error) {
	if ctx == nil {
		return false, errDaemonDiscoveryConstruction
	}
	interfaces, err := runtime.listInterfaces()
	if err != nil {
		return false, fmt.Errorf("list interfaces: %w", err)
	}
	selection, err := refreshDaemonDiscoverySelection(
		runtime.selectors,
		runtime.bindings,
		runtime.listenerPort,
		interfaces,
		runtime.interfaceAddrs,
	)
	if err != nil {
		return false, err
	}
	forceListenerRebind := slices.Equal(
		runtime.listeners.Current(),
		selection.listeners,
	) && !runtime.addresses.matches(
		selection.addresses,
		daemonDiscoverySelectedAddresses(selection),
	)
	update, err := runtime.listeners.Rebind(
		ctx,
		selection.listeners,
		forceListenerRebind,
	)
	if err != nil {
		return false, fmt.Errorf("replace peer listeners: %w", err)
	}

	var withdrawalErr error
	if update.Changed {
		runtime.publicationMu.Lock()
		withdrawalErr = runtime.publisher.Withdraw()
		runtime.publicationDirty = withdrawalErr != nil ||
			daemonHasPortablePeerListener(update.Current)
		runtime.publicationMu.Unlock()
	}

	appliedSelection, appliedSelectionErr :=
		daemonDiscoverySelectionForListeners(selection, update.Current)
	addressChanged, addressErr := runtime.replaceSelectedAddresses(
		ctx,
		appliedSelection,
	)
	runtime.bindings = cloneDaemonDiscoveryBindings(selection.bindings)
	intervalChanged, intervalErr := runtime.refreshAdvertisementInterval(ctx)

	runtime.publicationMu.Lock()
	publicationWasDirty := runtime.publicationDirty
	publicationNeeded := intervalChanged ||
		publicationWasDirty
	var publicationErr error
	if publicationNeeded {
		publicationErr = runtime.refreshEndpointPublicationLocked(ctx)
		runtime.publicationDirty = publicationErr != nil
	}
	runtime.publicationMu.Unlock()

	_, multicastErr := runtime.multicast.RefreshSelected(
		daemonDiscoveryMulticastSelections(appliedSelection),
	)
	publicationRecovered := publicationWasDirty && publicationErr == nil
	changed := update.Changed ||
		addressChanged ||
		intervalChanged ||
		publicationRecovered
	var triggerErr error
	if changed {
		triggerErr = runtime.multicast.TriggerAdvertisement()
	}
	if multicastErr != nil {
		multicastErr = fmt.Errorf("refresh multicast: %w", multicastErr)
	}
	if publicationErr != nil {
		publicationErr = fmt.Errorf(
			"refresh endpoint publication: %w",
			publicationErr,
		)
	}
	return changed, errors.Join(
		update.TransitionErr,
		withdrawalErr,
		appliedSelectionErr,
		addressErr,
		intervalErr,
		publicationErr,
		multicastErr,
		triggerErr,
	)
}

func daemonDiscoverySelectionForListeners(
	desired daemonDiscoverySelection,
	listeners []netip.AddrPort,
) (daemonDiscoverySelection, error) {
	result := daemonDiscoverySelection{
		addresses: make(
			map[daemonDiscoveryAddressKey]netip.Addr,
			len(listeners),
		),
		selected:  make([]netip.Addr, 0, len(listeners)),
		listeners: slices.Clone(listeners),
		bindings: make(
			map[daemonDiscoverySelector]netip.Addr,
			len(listeners),
		),
	}
	if len(listeners) == 0 {
		return result, nil
	}
	wanted := make(map[netip.AddrPort]struct{}, len(listeners))
	for _, listener := range listeners {
		wanted[listener] = struct{}{}
	}
	interfacesByName := make(
		map[string]net.Interface,
		len(desired.interfaces),
	)
	for _, iface := range desired.interfaces {
		interfacesByName[iface.Name] = iface
	}
	for selector, address := range desired.bindings {
		endpoint := netip.AddrPortFrom(address, listeners[0].Port())
		if _, retained := wanted[endpoint]; !retained {
			continue
		}
		iface, exists := interfacesByName[selector.interfaceName]
		if !exists {
			continue
		}
		delete(wanted, endpoint)
		result.bindings[selector] = address
		key := daemonDiscoveryAddressKey{
			interfaceIndex: iface.Index,
			family:         selector.family,
			linkLocal:      selector.linkLocal,
		}
		if current, exists := result.addresses[key]; !exists ||
			address.Compare(current) < 0 {
			result.addresses[key] = address
		}
		result.selected = append(result.selected, address)
		result.interfaces = append(result.interfaces, iface)
	}
	if len(wanted) != 0 {
		return daemonDiscoverySelection{
				addresses: make(map[daemonDiscoveryAddressKey]netip.Addr),
				bindings:  make(map[daemonDiscoverySelector]netip.Addr),
			}, fmt.Errorf(
				"%w: active listeners do not match refreshed selection",
				errDaemonDiscoveryConstruction,
			)
	}
	sortDaemonDiscoverySelection(&result)
	result.interfaces = slices.CompactFunc(
		result.interfaces,
		func(left, right net.Interface) bool {
			return left.Index == right.Index
		},
	)
	return result, nil
}

func (runtime *daemonDiscoveryRuntime) replaceSelectedAddresses(
	ctx context.Context,
	selection daemonDiscoverySelection,
) (bool, error) {
	if runtime == nil ||
		runtime.routes == nil ||
		runtime.addresses == nil ||
		runtime.reconciler == nil ||
		ctx == nil {
		return false, errDaemonDiscoveryConstruction
	}
	previousBindings, previous := runtime.addresses.snapshot()
	selected := daemonDiscoverySelectedAddresses(selection)
	invalidated := invalidatedDaemonDiscoveryAddresses(
		previousBindings,
		selection.addresses,
		previous,
		selected,
	)
	rebound := retainedDaemonDiscoveryAddresses(invalidated, selected)
	if len(invalidated) != 0 {
		runtime.ingressMu.RLock()
		ingress := runtime.ingress
		runtime.ingressMu.RUnlock()
		if ingress != nil {
			if _, err := ingress.CloseConnectionsBoundTo(
				invalidated,
			); err != nil {
				return false, fmt.Errorf(
					"close vanished-address connections: %w",
					err,
				)
			}
		}
	}
	if err := runtime.routes.RebindSelectedAddresses(
		selected,
		rebound,
	); err != nil {
		return false, fmt.Errorf("replace selected routes: %w", err)
	}
	if err := runtime.reconciler.replaceSelectedBindings(
		selection.bindings,
	); err != nil {
		return false, fmt.Errorf(
			"replace selected route bindings: %w",
			err,
		)
	}
	changed := runtime.addresses.replace(selection.addresses, selected)
	if changed {
		if err := runtime.reconciler.reconcile(
			ctx,
			selected,
			true,
		); err != nil {
			return true, fmt.Errorf(
				"reconcile selected routes: %w",
				err,
			)
		}
		if runtime.connectivity != nil {
			runtime.connectivity.NotifyConnectivityChange()
		}
	}
	return changed, nil
}

func (runtime *daemonDiscoveryRuntime) attachIngress(
	ingress daemonInboundAddressInvalidator,
) error {
	if runtime == nil || ingress == nil {
		return errDaemonDiscoveryConstruction
	}
	runtime.ingressMu.Lock()
	defer runtime.ingressMu.Unlock()
	if runtime.ingress != nil {
		return errDaemonDiscoveryConstruction
	}
	runtime.ingress = ingress
	return nil
}

func (runtime *daemonDiscoveryRuntime) refreshAdvertisementInterval(
	ctx context.Context,
) (bool, error) {
	interval, err := runtime.localState.DiscoveryAdvertisementInterval(ctx)
	if err != nil {
		return false, fmt.Errorf("read advertisement interval: %w", err)
	}
	current := runtime.currentAdvertisementInterval()
	if interval == current {
		return false, nil
	}
	runtime.publicationMu.Lock()
	defer runtime.publicationMu.Unlock()
	current = runtime.currentAdvertisementInterval()
	if interval == current {
		return false, nil
	}
	updateContext, cancel := context.WithTimeout(
		ctx,
		daemonDiscoveryUpdateTimeout,
	)
	defer cancel()
	if err := runtime.service.UpdateAdvertisementInterval(
		updateContext,
		interval,
	); err != nil {
		return false, fmt.Errorf("update advertisement interval: %w", err)
	}
	runtime.advertisementInterval.Store(int64(interval))
	return true, nil
}

func (runtime *daemonDiscoveryRuntime) refreshEndpointPublicationLocked(
	ctx context.Context,
) error {
	if runtime == nil ||
		runtime.publisher == nil ||
		runtime.listeners == nil ||
		ctx == nil {
		return errDaemonDiscoveryConstruction
	}
	listeners := runtime.listeners.Current()
	if !daemonHasPortablePeerListener(listeners) {
		return runtime.publisher.Withdraw()
	}
	err := runtime.publisher.Refresh(
		ctx,
		endpointservice.RefreshInput{
			AdvertisementInterval: runtime.currentAdvertisementInterval(),
			SelectedListeners:     listeners,
		},
	)
	if err == nil {
		return nil
	}
	return errors.Join(err, runtime.publisher.Withdraw())
}

func (runtime *daemonDiscoveryRuntime) currentAdvertisementInterval() time.Duration {
	if runtime == nil {
		return 0
	}
	return time.Duration(runtime.advertisementInterval.Load())
}

func (runtime *daemonDiscoveryRuntime) recordDiscoveryFailure(err error) {
	if err == nil {
		return
	}
	runtime.fatalMu.Lock()
	if !runtime.closing {
		runtime.discoveryErr = fmt.Errorf(
			"codecommd: discovery unavailable: %w",
			err,
		)
	}
	runtime.fatalMu.Unlock()
}

func (runtime *daemonDiscoveryRuntime) clearDiscoveryFailure() {
	runtime.fatalMu.Lock()
	runtime.discoveryErr = nil
	runtime.fatalMu.Unlock()
}

func (runtime *daemonDiscoveryRuntime) DiscoveryError() error {
	if runtime == nil {
		return errDaemonDiscoveryConstruction
	}
	runtime.fatalMu.RLock()
	refreshErr := runtime.discoveryErr
	runtime.fatalMu.RUnlock()
	var multicastErr error
	if multicast, ok := runtime.multicast.(*daemonRecoveringMulticast); ok {
		multicastErr = multicast.LastError()
	}
	return errors.Join(refreshErr, multicastErr)
}

func (runtime *daemonDiscoveryRuntime) reconcileManualEndpoints(
	ctx context.Context,
) error {
	if runtime == nil ||
		runtime.reconciler == nil ||
		runtime.addresses == nil ||
		runtime.connectivity == nil ||
		ctx == nil {
		return errDaemonDiscoveryConstruction
	}
	if err := runtime.reconciler.reconcile(
		ctx,
		runtime.addresses.selected(),
		false,
	); err != nil {
		runtime.recordDiscoveryFailure(err)
		return err
	}
	runtime.connectivity.NotifyConnectivityChange()
	return nil
}

func resetDaemonDiscoveryTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func daemonDiscoverySelectedAddresses(
	selection daemonDiscoverySelection,
) []netip.Addr {
	return append([]netip.Addr(nil), selection.selected...)
}

func resolveDaemonDiscoverySelection(
	listeners []netip.AddrPort,
	interfaces []net.Interface,
	addresses daemonInterfaceAddressProvider,
) (daemonDiscoverySelection, error) {
	if len(listeners) == 0 || len(interfaces) == 0 || addresses == nil {
		return daemonDiscoverySelection{}, errDaemonDiscoveryConstruction
	}
	normalized, err := normalizeDaemonPeerListenerEndpoints(listeners)
	if err != nil {
		return daemonDiscoverySelection{}, fmt.Errorf(
			"%w: invalid selected listeners",
			errDaemonDiscoveryConstruction,
		)
	}
	sortedInterfaces := append([]net.Interface(nil), interfaces...)
	sort.Slice(sortedInterfaces, func(left, right int) bool {
		return sortedInterfaces[left].Index < sortedInterfaces[right].Index
	})
	selectedInterfaces := make(map[int]net.Interface)
	selectedAddresses := make(
		map[daemonDiscoveryAddressKey]netip.Addr,
		len(normalized),
	)
	bindings := make(
		map[daemonDiscoverySelector]netip.Addr,
		len(normalized),
	)
	selectorCounts := make(map[daemonDiscoverySelector]uint8)
	for _, listener := range normalized {
		matches := make([]net.Interface, 0, 1)
		for index := range sortedInterfaces {
			iface := sortedInterfaces[index]
			if iface.Index < 1 ||
				iface.Name == "" ||
				iface.Flags&net.FlagUp == 0 ||
				iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			address := listener.Addr()
			if address.Zone() != "" && address.Zone() != iface.Name {
				continue
			}
			interfaceAddresses, err := addresses(&iface)
			if err != nil {
				continue
			}
			if daemonInterfaceOwnsAddress(
				interfaceAddresses,
				address.WithZone(""),
			) {
				matches = append(matches, iface)
			}
		}
		if len(matches) != 1 {
			return daemonDiscoverySelection{}, fmt.Errorf(
				"%w: listener %s maps to %d interfaces",
				errDaemonDiscoveryConstruction,
				listener,
				len(matches),
			)
		}
		iface := matches[0]
		family := discovery.AddressFamilyIPv6
		if listener.Addr().Is4() {
			family = discovery.AddressFamilyIPv4
		}
		selector := daemonDiscoverySelector{
			interfaceName: iface.Name,
			family:        family,
			linkLocal:     listener.Addr().IsLinkLocalUnicast(),
		}
		selector.ordinal = selectorCounts[selector]
		selectorCounts[daemonDiscoverySelector{
			interfaceName: selector.interfaceName,
			family:        selector.family,
			linkLocal:     selector.linkLocal,
		}]++
		bindings[selector] = listener.Addr()
		key := daemonDiscoveryAddressKey{
			interfaceIndex: iface.Index,
			family:         family,
			linkLocal:      selector.linkLocal,
		}
		if current, exists := selectedAddresses[key]; !exists ||
			listener.Addr().Compare(current) < 0 {
			selectedAddresses[key] = listener.Addr()
		}
		selectedInterfaces[iface.Index] = iface
	}
	result := daemonDiscoverySelection{
		interfaces: make(
			[]net.Interface,
			0,
			len(selectedInterfaces),
		),
		addresses: selectedAddresses,
		selected:  make([]netip.Addr, 0, len(normalized)),
		listeners: slices.Clone(normalized),
		bindings:  bindings,
	}
	for _, iface := range selectedInterfaces {
		result.interfaces = append(result.interfaces, iface)
	}
	for _, listener := range normalized {
		result.selected = append(result.selected, listener.Addr())
	}
	sortDaemonDiscoverySelection(&result)
	return result, nil
}

func refreshDaemonDiscoverySelection(
	selectors []daemonDiscoverySelector,
	previous map[daemonDiscoverySelector]netip.Addr,
	port uint16,
	interfaces []net.Interface,
	addresses daemonInterfaceAddressProvider,
) (daemonDiscoverySelection, error) {
	if len(selectors) == 0 || port == 0 || addresses == nil {
		return daemonDiscoverySelection{}, errDaemonDiscoveryConstruction
	}
	byName := make(map[string]net.Interface, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index < 1 || iface.Name == "" {
			continue
		}
		if _, duplicate := byName[iface.Name]; duplicate {
			return daemonDiscoverySelection{}, fmt.Errorf(
				"%w: duplicate interface name %q",
				errDaemonDiscoveryConstruction,
				iface.Name,
			)
		}
		byName[iface.Name] = iface
	}

	result := daemonDiscoverySelection{
		addresses: make(
			map[daemonDiscoveryAddressKey]netip.Addr,
			len(selectors),
		),
		selected: make([]netip.Addr, 0, len(selectors)),
		listeners: make(
			[]netip.AddrPort,
			0,
			len(selectors),
		),
		bindings: make(
			map[daemonDiscoverySelector]netip.Addr,
			len(selectors),
		),
	}
	orderedSelectors := slices.Clone(selectors)
	sortDaemonDiscoverySelectors(orderedSelectors)
	seenSelectors := make(
		map[daemonDiscoverySelector]struct{},
		len(orderedSelectors),
	)
	selectedInterfaces := make(map[int]net.Interface, len(orderedSelectors))
	interfaceAddresses := make(map[string][]netip.Addr, len(selectors))
	selectorInterfaces := make(
		map[daemonDiscoverySelector]net.Interface,
		len(orderedSelectors),
	)
	selectorCandidates := make(
		map[daemonDiscoverySelector][]netip.Addr,
		len(orderedSelectors),
	)
	for _, selector := range orderedSelectors {
		if _, duplicate := seenSelectors[selector]; duplicate {
			return daemonDiscoverySelection{}, fmt.Errorf(
				"%w: duplicate discovery selector",
				errDaemonDiscoveryConstruction,
			)
		}
		seenSelectors[selector] = struct{}{}
		iface, found := byName[selector.interfaceName]
		if !found ||
			iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		candidates, loaded := interfaceAddresses[iface.Name]
		if !loaded {
			raw, err := addresses(&iface)
			if err != nil {
				return daemonDiscoverySelection{}, fmt.Errorf(
					"interface %s addresses: %w",
					iface.Name,
					err,
				)
			}
			candidates = daemonDiscoveryInterfaceAddresses(iface, raw)
			interfaceAddresses[iface.Name] = candidates
		}
		eligible := daemonDiscoverySelectorAddresses(selector, candidates)
		if len(eligible) == 0 {
			continue
		}
		selectorInterfaces[selector] = iface
		selectorCandidates[selector] = eligible
	}

	chosen := make(
		map[daemonDiscoverySelector]netip.Addr,
		len(selectorCandidates),
	)
	used := make(map[netip.Addr]struct{}, len(selectorCandidates))
	for _, selector := range orderedSelectors {
		eligible := selectorCandidates[selector]
		if preferred, exists := previous[selector]; exists &&
			slices.Contains(eligible, preferred) {
			if _, duplicate := used[preferred]; !duplicate {
				chosen[selector] = preferred
				used[preferred] = struct{}{}
			}
		}
	}
	for _, selector := range orderedSelectors {
		if _, exists := chosen[selector]; exists {
			continue
		}
		for _, candidate := range selectorCandidates[selector] {
			if _, duplicate := used[candidate]; duplicate {
				continue
			}
			chosen[selector] = candidate
			used[candidate] = struct{}{}
			break
		}
	}
	for _, selector := range orderedSelectors {
		selected, exists := chosen[selector]
		if !exists {
			continue
		}
		iface := selectorInterfaces[selector]
		selectedInterfaces[iface.Index] = iface
		result.bindings[selector] = selected
		key := daemonDiscoveryAddressKey{
			interfaceIndex: iface.Index,
			family:         selector.family,
			linkLocal:      selector.linkLocal,
		}
		if current, exists := result.addresses[key]; !exists ||
			selected.Compare(current) < 0 {
			result.addresses[key] = selected
		}
		result.selected = append(result.selected, selected)
		result.listeners = append(
			result.listeners,
			netip.AddrPortFrom(selected, port),
		)
	}
	for _, iface := range selectedInterfaces {
		result.interfaces = append(result.interfaces, iface)
	}
	sortDaemonDiscoverySelection(&result)
	return result, nil
}

func sortDaemonDiscoverySelection(selection *daemonDiscoverySelection) {
	if selection == nil {
		return
	}
	sort.Slice(selection.interfaces, func(left, right int) bool {
		return selection.interfaces[left].Index <
			selection.interfaces[right].Index
	})
	sort.Slice(selection.selected, func(left, right int) bool {
		return selection.selected[left].Compare(selection.selected[right]) < 0
	})
	selection.selected = slices.Compact(selection.selected)
	sort.Slice(selection.listeners, func(left, right int) bool {
		return selection.listeners[left].Compare(
			selection.listeners[right],
		) < 0
	})
	selection.listeners = slices.Compact(selection.listeners)
}

func daemonDiscoveryMulticastSelections(
	selection daemonDiscoverySelection,
) []discovery.MulticastInterfaceSelection {
	byName := make(map[string]net.Interface, len(selection.interfaces))
	for _, iface := range selection.interfaces {
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		byName[iface.Name] = iface
	}
	families := make(
		map[int]map[discovery.AddressFamily]struct{},
		len(selection.interfaces),
	)
	for selector := range selection.bindings {
		iface, exists := byName[selector.interfaceName]
		if !exists {
			continue
		}
		if families[iface.Index] == nil {
			families[iface.Index] = make(
				map[discovery.AddressFamily]struct{},
				2,
			)
		}
		families[iface.Index][selector.family] = struct{}{}
	}
	result := make(
		[]discovery.MulticastInterfaceSelection,
		0,
		len(selection.interfaces),
	)
	for _, iface := range selection.interfaces {
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		selectedFamilies := make(
			[]discovery.AddressFamily,
			0,
			len(families[iface.Index]),
		)
		for family := range families[iface.Index] {
			selectedFamilies = append(selectedFamilies, family)
		}
		sort.Slice(selectedFamilies, func(left, right int) bool {
			return selectedFamilies[left] < selectedFamilies[right]
		})
		if len(selectedFamilies) == 0 {
			continue
		}
		result = append(result, discovery.MulticastInterfaceSelection{
			Interface: iface,
			Families:  selectedFamilies,
		})
	}
	return result
}

func daemonDiscoveryInterfaceAddresses(
	iface net.Interface,
	addresses []net.Addr,
) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		candidate, valid := netip.AddrFromSlice(ip)
		if !valid {
			continue
		}
		candidate = candidate.Unmap()
		if candidate.Is6() && candidate.IsLinkLocalUnicast() {
			candidate = candidate.WithZone(iface.Name)
		}
		if !validDaemonSelectedAddress(candidate) {
			continue
		}
		result = append(result, candidate)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Compare(result[right]) < 0
	})
	return slices.Compact(result)
}

func daemonDiscoverySelectorAddresses(
	selector daemonDiscoverySelector,
	addresses []netip.Addr,
) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		family := discovery.AddressFamilyIPv6
		if address.Is4() {
			family = discovery.AddressFamilyIPv4
		}
		if family == selector.family &&
			address.IsLinkLocalUnicast() == selector.linkLocal {
			result = append(result, address)
		}
	}
	return result
}

func daemonDiscoverySelectors(
	selection daemonDiscoverySelection,
) []daemonDiscoverySelector {
	result := make(
		[]daemonDiscoverySelector,
		0,
		len(selection.bindings),
	)
	for selector := range selection.bindings {
		result = append(result, selector)
	}
	sortDaemonDiscoverySelectors(result)
	return result
}

func sortDaemonDiscoverySelectors(selectors []daemonDiscoverySelector) {
	sort.Slice(selectors, func(left, right int) bool {
		if selectors[left].interfaceName != selectors[right].interfaceName {
			return selectors[left].interfaceName <
				selectors[right].interfaceName
		}
		if selectors[left].family != selectors[right].family {
			return selectors[left].family < selectors[right].family
		}
		if selectors[left].linkLocal != selectors[right].linkLocal {
			return !selectors[left].linkLocal
		}
		return selectors[left].ordinal < selectors[right].ordinal
	})
}

func cloneDaemonDiscoveryBindings(
	bindings map[daemonDiscoverySelector]netip.Addr,
) map[daemonDiscoverySelector]netip.Addr {
	result := make(
		map[daemonDiscoverySelector]netip.Addr,
		len(bindings),
	)
	for selector, address := range bindings {
		result[selector] = address
	}
	return result
}

func daemonHasPortablePeerListener(listeners []netip.AddrPort) bool {
	for _, listener := range listeners {
		if listener.IsValid() &&
			!listener.Addr().IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func invalidatedDaemonDiscoveryAddresses(
	previousBindings map[daemonDiscoveryAddressKey]netip.Addr,
	currentBindings map[daemonDiscoveryAddressKey]netip.Addr,
	previousSelected []netip.Addr,
	currentSelected []netip.Addr,
) []netip.Addr {
	current := make(map[netip.Addr]struct{}, len(currentSelected))
	for _, address := range currentSelected {
		current[address] = struct{}{}
	}
	invalidated := make(map[netip.Addr]struct{}, len(previousSelected))
	for _, address := range previousSelected {
		if _, retained := current[address]; !retained {
			invalidated[address] = struct{}{}
		}
	}
	for key, address := range previousBindings {
		currentAddress, retained := currentBindings[key]
		if !retained || currentAddress != address {
			invalidated[address] = struct{}{}
		}
	}
	result := make([]netip.Addr, 0, len(invalidated))
	for address := range invalidated {
		result = append(result, address)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Compare(result[right]) < 0
	})
	return result
}

func retainedDaemonDiscoveryAddresses(
	candidates []netip.Addr,
	selected []netip.Addr,
) []netip.Addr {
	retained := make(map[netip.Addr]struct{}, len(selected))
	for _, address := range selected {
		retained[address] = struct{}{}
	}
	result := make([]netip.Addr, 0, len(candidates))
	for _, address := range candidates {
		if _, exists := retained[address]; exists {
			result = append(result, address)
		}
	}
	return result
}

func daemonInterfaceOwnsAddress(
	addresses []net.Addr,
	expected netip.Addr,
) bool {
	for _, address := range addresses {
		var candidate net.IP
		switch value := address.(type) {
		case *net.IPNet:
			candidate = value.IP
		case *net.IPAddr:
			candidate = value.IP
		default:
			continue
		}
		parsed, valid := netip.AddrFromSlice(candidate)
		if valid && parsed.Unmap() == expected {
			return true
		}
	}
	return false
}

func (book *daemonDiscoveryAddressBook) lookup(
	interfaceIndex int,
	family discovery.AddressFamily,
	destination netip.AddrPort,
) (netip.Addr, bool) {
	if book == nil {
		return netip.Addr{}, false
	}
	book.mu.RLock()
	defer book.mu.RUnlock()
	address, exists := book.addresses[daemonDiscoveryAddressKey{
		interfaceIndex: interfaceIndex,
		family:         family,
		linkLocal:      destination.Addr().IsLinkLocalUnicast(),
	}]
	return address, exists
}

func (book *daemonDiscoveryAddressBook) replace(
	addresses map[daemonDiscoveryAddressKey]netip.Addr,
	selected []netip.Addr,
) bool {
	if book == nil {
		return false
	}
	next := make(
		map[daemonDiscoveryAddressKey]netip.Addr,
		len(addresses),
	)
	for key, address := range addresses {
		next[key] = address
	}
	book.mu.Lock()
	changed := !slices.Equal(book.selectedAddresses, selected) ||
		len(book.addresses) != len(next)
	if !changed {
		for key, address := range next {
			if book.addresses[key] != address {
				changed = true
				break
			}
		}
	}
	book.addresses = next
	book.selectedAddresses = append([]netip.Addr(nil), selected...)
	book.mu.Unlock()
	return changed
}

func (book *daemonDiscoveryAddressBook) matches(
	addresses map[daemonDiscoveryAddressKey]netip.Addr,
	selected []netip.Addr,
) bool {
	if book == nil {
		return false
	}
	book.mu.RLock()
	defer book.mu.RUnlock()
	if !slices.Equal(book.selectedAddresses, selected) ||
		len(book.addresses) != len(addresses) {
		return false
	}
	for key, address := range addresses {
		if book.addresses[key] != address {
			return false
		}
	}
	return true
}

func (book *daemonDiscoveryAddressBook) snapshot() (
	map[daemonDiscoveryAddressKey]netip.Addr,
	[]netip.Addr,
) {
	if book == nil {
		return nil, nil
	}
	book.mu.RLock()
	defer book.mu.RUnlock()
	addresses := make(
		map[daemonDiscoveryAddressKey]netip.Addr,
		len(book.addresses),
	)
	for key, address := range book.addresses {
		addresses[key] = address
	}
	return addresses, slices.Clone(book.selectedAddresses)
}

func (book *daemonDiscoveryAddressBook) selected() []netip.Addr {
	if book == nil {
		return nil
	}
	book.mu.RLock()
	defer book.mu.RUnlock()
	return append([]netip.Addr(nil), book.selectedAddresses...)
}

var _ phasedDaemonComponent = (*daemonDiscoveryRuntime)(nil)
