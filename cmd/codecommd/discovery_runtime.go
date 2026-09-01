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
	Refresh([]net.Interface) (discovery.MulticastReport, error)
}

type daemonMulticastOpener func(
	uint16,
	[]net.Interface,
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

type daemonDiscoveryAddressBook struct {
	mu                sync.RWMutex
	addresses         map[daemonDiscoveryAddressKey]netip.Addr
	selectedAddresses []netip.Addr
}

type daemonDiscoverySelection struct {
	interfaces []net.Interface
	addresses  map[daemonDiscoveryAddressKey]netip.Addr
	selected   []netip.Addr
}

type daemonDiscoveryCredentials interface {
	discoveryservice.CredentialAdvertiser
	daemonConnectivityNotifier
}

type daemonDiscoveryRuntime struct {
	service               *discoveryservice.Service
	publisher             *endpointservice.Service
	reconciler            *daemonEndpointRouteReconciler
	multicast             daemonDiscoveryMulticast
	addresses             *daemonDiscoveryAddressBook
	routes                *transport.ConsensusRouteTable
	listeners             []netip.AddrPort
	localState            store.LocalState
	listInterfaces        daemonInterfaceLister
	interfaceAddrs        daemonInterfaceAddressProvider
	connectivity          daemonConnectivityNotifier
	advertisementInterval atomic.Int64
	publicationMu         sync.RWMutex

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
	selected []net.Interface,
) (daemonDiscoveryMulticast, discovery.MulticastReport, error) {
	return discovery.OpenMulticast(port, selected)
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
		dependencies.listInterfaces == nil ||
		dependencies.interfaceAddrs == nil {
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
		selection.interfaces,
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
		listeners:      append([]netip.AddrPort(nil), options.peerListeners...),
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
			intervalChanged, err := runtime.refresh(ctx)
			if err != nil {
				runtime.recordDiscoveryFailure(err)
			} else {
				runtime.clearDiscoveryFailure()
			}
			if intervalChanged {
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
	err := runtime.publisher.Refresh(
		ctx,
		endpointservice.RefreshInput{
			AdvertisementInterval: runtime.currentAdvertisementInterval(),
			SelectedListeners:     runtime.listeners,
		},
	)
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
	selection, err := resolveDaemonDiscoverySelection(
		runtime.listeners,
		interfaces,
		runtime.interfaceAddrs,
	)
	if err != nil {
		return false, err
	}
	if err := runtime.replaceSelectedAddresses(selection); err != nil {
		return false, err
	}
	intervalChanged, err := runtime.refreshAdvertisementInterval(ctx)
	if err != nil {
		return false, err
	}
	if _, err := runtime.multicast.Refresh(selection.interfaces); err != nil {
		return intervalChanged, fmt.Errorf("refresh multicast: %w", err)
	}
	return intervalChanged, nil
}

func (runtime *daemonDiscoveryRuntime) replaceSelectedAddresses(
	selection daemonDiscoverySelection,
) error {
	if runtime == nil || runtime.routes == nil || runtime.addresses == nil {
		return errDaemonDiscoveryConstruction
	}
	selected := daemonDiscoverySelectedAddresses(selection)
	if err := runtime.routes.ReplaceSelectedAddresses(selected); err != nil {
		return fmt.Errorf("replace selected routes: %w", err)
	}
	if runtime.addresses.replace(selection.addresses, selected) &&
		runtime.connectivity != nil {
		runtime.connectivity.NotifyConnectivityChange()
	}
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
	if err := runtime.publisher.Refresh(
		updateContext,
		endpointservice.RefreshInput{
			AdvertisementInterval: interval,
			SelectedListeners:     runtime.listeners,
		},
	); err != nil {
		return false, fmt.Errorf("refresh interval endpoint set: %w", err)
	}
	runtime.advertisementInterval.Store(int64(interval))
	return true, nil
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
	sortedInterfaces := append([]net.Interface(nil), interfaces...)
	sort.Slice(sortedInterfaces, func(left, right int) bool {
		return sortedInterfaces[left].Index < sortedInterfaces[right].Index
	})
	selectedInterfaces := make(map[int]net.Interface)
	selectedAddresses := make(
		map[daemonDiscoveryAddressKey]netip.Addr,
		len(listeners),
	)
	selectedRouteAddresses := make([]netip.Addr, 0, len(listeners))
	port := listeners[0].Port()
	for _, listener := range listeners {
		if listener.Port() != port {
			return daemonDiscoverySelection{}, fmt.Errorf(
				"%w: selected listeners use different ports",
				errDaemonDiscoveryConstruction,
			)
		}
		matches := make([]net.Interface, 0, 1)
		for index := range sortedInterfaces {
			iface := sortedInterfaces[index]
			if iface.Index < 1 ||
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
		key := daemonDiscoveryAddressKey{
			interfaceIndex: iface.Index,
			family:         family,
			linkLocal:      listener.Addr().IsLinkLocalUnicast(),
		}
		if current, exists := selectedAddresses[key]; !exists ||
			listener.Addr().Compare(current) < 0 {
			selectedAddresses[key] = listener.Addr()
		}
		selectedRouteAddresses = append(
			selectedRouteAddresses,
			listener.Addr(),
		)
		selectedInterfaces[iface.Index] = iface
	}
	result := daemonDiscoverySelection{
		interfaces: make(
			[]net.Interface,
			0,
			len(selectedInterfaces),
		),
		addresses: selectedAddresses,
		selected:  selectedRouteAddresses,
	}
	for _, iface := range selectedInterfaces {
		result.interfaces = append(result.interfaces, iface)
	}
	sort.Slice(result.interfaces, func(left, right int) bool {
		return result.interfaces[left].Index <
			result.interfaces[right].Index
	})
	sort.Slice(result.selected, func(left, right int) bool {
		return result.selected[left].Compare(result.selected[right]) < 0
	})
	result.selected = slices.Compact(result.selected)
	return result, nil
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

func (book *daemonDiscoveryAddressBook) selected() []netip.Addr {
	if book == nil {
		return nil
	}
	book.mu.RLock()
	defer book.mu.RUnlock()
	return append([]netip.Addr(nil), book.selectedAddresses...)
}

var _ phasedDaemonComponent = (*daemonDiscoveryRuntime)(nil)
