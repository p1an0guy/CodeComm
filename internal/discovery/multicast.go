package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	MaxSelectedInterfaces = 32
	MinMulticastPort      = 1024

	multicastHopLimit = 1
	inboundQueueSize  = 64
)

var (
	ErrInvalidMulticastConfig = errors.New("discovery: invalid multicast configuration")
	ErrNoMulticastJoin        = errors.New("discovery: no selected multicast interface is usable")
	ErrMulticastClosed        = errors.New("discovery: multicast I/O is closed")
	ErrMulticastDatagramSize  = errors.New("discovery: multicast datagram exceeds 1200 bytes")
	ErrMulticastSource        = errors.New("discovery: invalid multicast source")
	ErrMulticastInterface     = errors.New("discovery: receive interface is not selected")
	ErrMulticastRefresh       = errors.New("discovery: multicast interface refresh failed")
)

// AddressFamily identifies one fixed V1 discovery multicast group.
type AddressFamily uint8

const (
	AddressFamilyIPv4 AddressFamily = 4
	AddressFamilyIPv6 AddressFamily = 6
)

func (family AddressFamily) String() string {
	switch family {
	case AddressFamilyIPv4:
		return "ipv4"
	case AddressFamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// InterfaceJoin identifies one active family join on a selected interface.
type InterfaceJoin struct {
	InterfaceIndex int
	InterfaceName  string
	Family         AddressFamily
}

// InterfaceFailure reports a local multicast failure without hiding partial
// startup or refresh success on other selected interfaces.
type InterfaceFailure struct {
	InterfaceIndex int
	InterfaceName  string
	Family         AddressFamily
	Operation      string
	Err            error
}

func (failure InterfaceFailure) Error() string {
	target := failure.InterfaceName
	if target == "" {
		target = strconv.Itoa(failure.InterfaceIndex)
	}
	if failure.Family != 0 {
		target += "/" + failure.Family.String()
	}
	return fmt.Sprintf(
		"discovery: multicast %s on interface %s: %v",
		failure.Operation,
		target,
		failure.Err,
	)
}

func (failure InterfaceFailure) Unwrap() error {
	return failure.Err
}

// MulticastReport is the complete usable join set and any nonfatal failures
// from startup or an interface refresh.
type MulticastReport struct {
	Joins    []InterfaceJoin
	Failures []InterfaceFailure
}

// MulticastIO owns the per-session discovery sockets for one committed port.
// A socket is shared by all selected interfaces of its address family.
type MulticastIO struct {
	port  uint16
	deps  multicastDependencies
	group map[AddressFamily]netip.Addr

	refreshMu sync.Mutex
	mu        sync.RWMutex
	sockets   map[AddressFamily]multicastSocket
	joins     map[joinKey]net.Interface
	closed    bool
	closeErr  error

	inbound     chan inboundDatagram
	advertise   chan struct{}
	done        chan struct{}
	readerGroup sync.WaitGroup
}

type joinKey struct {
	family         AddressFamily
	interfaceIndex int
}

type inboundDatagram struct {
	payload        []byte
	source         netip.AddrPort
	family         AddressFamily
	interfaceIndex int
	err            error
}

type multicastDependencies struct {
	open func(
		AddressFamily,
		uint16,
		*net.Interface,
		netip.Addr,
	) (multicastSocket, error)
	addrs func(*net.Interface) ([]net.Addr, error)
}

type multicastSocket interface {
	SetMulticastHopLimit(int) error
	SetMulticastLoopback(bool) error
	EnableReceiveInterface() error
	JoinGroup(*net.Interface, netip.Addr) error
	LeaveGroup(*net.Interface, netip.Addr) error
	ReadFrom([]byte) (int, net.Addr, int, error)
	WriteTo([]byte, *net.Interface, netip.AddrPort) (int, error)
	Close() error
}

var fixedMulticastGroups = map[AddressFamily]netip.Addr{
	AddressFamilyIPv4: netip.MustParseAddr(DefaultIPv4Group),
	AddressFamilyIPv6: netip.MustParseAddr(DefaultIPv6Group),
}

// OpenMulticast opens the fixed V1 groups on every available family of every
// explicitly selected interface. At least one join must succeed.
func OpenMulticast(
	port uint16,
	selected []net.Interface,
) (*MulticastIO, MulticastReport, error) {
	return openMulticast(port, selected, multicastDependencies{
		open:  openNativeMulticastSocket,
		addrs: interfaceAddrs,
	})
}

func openMulticast(
	port uint16,
	selected []net.Interface,
	deps multicastDependencies,
) (*MulticastIO, MulticastReport, error) {
	if err := validateMulticastInputs(port, selected, deps); err != nil {
		return nil, MulticastReport{}, err
	}

	desired, failures := resolveInterfaceFamilies(selected, deps.addrs)
	sockets := make(map[AddressFamily]multicastSocket, 2)
	joins := make(map[joinKey]net.Interface, len(desired))

	for _, family := range []AddressFamily{AddressFamilyIPv4, AddressFamilyIPv6} {
		keys := desiredFamilyKeys(desired, family)
		if len(keys) == 0 {
			continue
		}
		socket, firstKey, openFailures := openFamilySocket(
			deps.open,
			family,
			port,
			keys,
			desired,
			fixedMulticastGroups[family],
		)
		failures = append(failures, openFailures...)
		if socket == nil {
			continue
		}
		firstInterface := desired[firstKey]
		joins[firstKey] = firstInterface
		for _, key := range keys {
			if key == firstKey {
				continue
			}
			iface := desired[key]
			if err := socket.JoinGroup(&iface, fixedMulticastGroups[family]); err != nil {
				failures = append(failures, interfaceFailure(
					iface,
					family,
					"join",
					err,
				))
				continue
			}
			joins[key] = iface
		}
		if countFamilyJoins(joins, family) == 0 {
			if err := socket.Close(); err != nil {
				failures = append(failures, InterfaceFailure{
					Family:    family,
					Operation: "close",
					Err:       err,
				})
			}
			continue
		}
		sockets[family] = socket
	}

	report := multicastReport(joins, failures)
	if len(joins) == 0 {
		return nil, report, errors.Join(
			ErrNoMulticastJoin,
			failuresError(failures),
		)
	}

	value := &MulticastIO{
		port:      port,
		deps:      deps,
		group:     cloneGroups(fixedMulticastGroups),
		sockets:   sockets,
		joins:     joins,
		inbound:   make(chan inboundDatagram, inboundQueueSize),
		advertise: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	for family, socket := range sockets {
		value.startReader(family, socket)
	}
	value.signalAdvertisement()
	return value, report, nil
}

// AdvertisementTriggers is a coalescing signal emitted at startup and after
// every successful interface refresh.
func (multicast *MulticastIO) AdvertisementTriggers() <-chan struct{} {
	if multicast == nil {
		return nil
	}
	return multicast.advertise
}

// Done is closed when Close starts shutting down multicast I/O.
func (multicast *MulticastIO) Done() <-chan struct{} {
	if multicast == nil {
		return nil
	}
	return multicast.done
}

// Send transmits one bounded advertisement once per active interface/family.
func (multicast *MulticastIO) Send(payload []byte) error {
	if multicast == nil {
		return ErrMulticastClosed
	}
	if len(payload) > MaxDatagramBytes {
		return ErrMulticastDatagramSize
	}

	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	if multicast.closed {
		return ErrMulticastClosed
	}

	keys := sortedJoinKeys(multicast.joins)
	failures := make([]error, 0)
	for _, key := range keys {
		iface := multicast.joins[key]
		socket := multicast.sockets[key.family]
		destination := netip.AddrPortFrom(
			multicast.group[key.family],
			multicast.port,
		)
		written, err := socket.WriteTo(payload, &iface, destination)
		if err == nil && written != len(payload) {
			err = errors.New("short datagram write")
		}
		if err != nil {
			failures = append(failures, interfaceFailure(
				iface,
				key.family,
				"send",
				err,
			))
		}
	}
	return errors.Join(failures...)
}

// Receive returns one bounded datagram and its literal source. Cancellation or
// Close unblocks the call. Oversize/truncated datagrams are never returned.
func (multicast *MulticastIO) Receive(
	ctx context.Context,
) ([]byte, netip.AddrPort, error) {
	if multicast == nil {
		return nil, netip.AddrPort{}, ErrMulticastClosed
	}
	if ctx == nil {
		return nil, netip.AddrPort{}, ErrInvalidMulticastConfig
	}

	for {
		select {
		case <-ctx.Done():
			return nil, netip.AddrPort{}, ctx.Err()
		case <-multicast.done:
			return nil, netip.AddrPort{}, ErrMulticastClosed
		case datagram := <-multicast.inbound:
			multicast.mu.RLock()
			if multicast.closed {
				multicast.mu.RUnlock()
				return nil, netip.AddrPort{}, ErrMulticastClosed
			}
			if datagram.interfaceIndex != 0 {
				_, active := multicast.joins[joinKey{
					family:         datagram.family,
					interfaceIndex: datagram.interfaceIndex,
				}]
				if !active {
					multicast.mu.RUnlock()
					continue
				}
			}
			multicast.mu.RUnlock()
			if datagram.err != nil {
				return nil, netip.AddrPort{}, datagram.err
			}
			return datagram.payload, datagram.source, nil
		}
	}
}

// Refresh atomically replaces the logical join set after all additions and
// removals succeed. Partial family/interface availability is retained in the
// returned report; an all-family failure leaves the prior set active.
func (multicast *MulticastIO) Refresh(
	selected []net.Interface,
) (MulticastReport, error) {
	if multicast == nil {
		return MulticastReport{}, ErrMulticastClosed
	}
	if err := validateSelectedInterfaces(selected); err != nil {
		return MulticastReport{}, err
	}
	desired, failures := resolveInterfaceFamilies(selected, multicast.deps.addrs)

	multicast.refreshMu.Lock()
	defer multicast.refreshMu.Unlock()
	multicast.mu.Lock()
	if multicast.closed {
		report := multicastReport(multicast.joins, failures)
		multicast.mu.Unlock()
		return report, ErrMulticastClosed
	}

	newSockets := make(map[AddressFamily]multicastSocket, 2)
	prejoined := make(map[joinKey]struct{}, 2)
	for _, family := range []AddressFamily{AddressFamilyIPv4, AddressFamilyIPv6} {
		keys := desiredFamilyKeys(desired, family)
		if len(keys) == 0 ||
			multicast.sockets[family] != nil {
			continue
		}
		socket, firstKey, openFailures := openFamilySocket(
			multicast.deps.open,
			family,
			multicast.port,
			keys,
			desired,
			multicast.group[family],
		)
		failures = append(failures, openFailures...)
		if socket == nil {
			continue
		}
		newSockets[family] = socket
		prejoined[firstKey] = struct{}{}
	}

	candidate := make(map[joinKey]net.Interface, len(desired))
	added := make([]joinKey, 0, len(desired))
	for _, key := range sortedJoinKeys(desired) {
		iface := desired[key]
		if _, exists := multicast.joins[key]; exists {
			candidate[key] = iface
			continue
		}
		socket := multicast.sockets[key.family]
		if socket == nil {
			socket = newSockets[key.family]
		}
		if socket == nil {
			continue
		}
		if _, alreadyJoined := prejoined[key]; alreadyJoined {
			candidate[key] = iface
			added = append(added, key)
			continue
		}
		if err := socket.JoinGroup(&iface, multicast.group[key.family]); err != nil {
			failures = append(failures, interfaceFailure(
				iface,
				key.family,
				"join",
				err,
			))
			continue
		}
		candidate[key] = iface
		added = append(added, key)
	}

	if len(candidate) == 0 {
		rollbackErr := rollbackAdded(
			added,
			desired,
			multicast.sockets,
			newSockets,
			multicast.group,
		)
		closeErr := closeSocketMap(newSockets)
		report := multicastReport(multicast.joins, failures)
		multicast.mu.Unlock()
		return report, errors.Join(
			ErrNoMulticastJoin,
			failuresError(failures),
			rollbackErr,
			closeErr,
		)
	}

	removed := removedJoinKeys(multicast.joins, candidate)
	left := make([]joinKey, 0, len(removed))
	var leaveFailure error
	for _, key := range removed {
		iface := multicast.joins[key]
		socket := multicast.sockets[key.family]
		if err := socket.LeaveGroup(&iface, multicast.group[key.family]); err != nil {
			failure := interfaceFailure(
				iface,
				key.family,
				"leave",
				err,
			)
			failures = append(failures, failure)
			leaveFailure = errors.Join(leaveFailure, failure)
			break
		}
		left = append(left, key)
	}
	if leaveFailure != nil {
		restoreErr := restoreRemoved(
			left,
			multicast.joins,
			multicast.sockets,
			multicast.group,
		)
		rollbackErr := rollbackAdded(
			added,
			desired,
			multicast.sockets,
			newSockets,
			multicast.group,
		)
		closeErr := closeSocketMap(newSockets)
		report := multicastReport(multicast.joins, failures)
		if restoreErr != nil || rollbackErr != nil {
			sockets := multicast.failClosedLocked(errors.Join(
				ErrMulticastRefresh,
				leaveFailure,
				restoreErr,
				rollbackErr,
				closeErr,
			))
			multicast.mu.Unlock()
			closeErr = errors.Join(closeErr, closeSocketMap(sockets))
			multicast.readerGroup.Wait()
			return report, errors.Join(
				ErrMulticastRefresh,
				leaveFailure,
				restoreErr,
				rollbackErr,
				closeErr,
			)
		}
		multicast.mu.Unlock()
		return report, errors.Join(
			ErrMulticastRefresh,
			leaveFailure,
			closeErr,
		)
	}

	for family, socket := range newSockets {
		if countFamilyJoins(candidate, family) == 0 {
			if err := socket.Close(); err != nil {
				failures = append(failures, InterfaceFailure{
					Family:    family,
					Operation: "close",
					Err:       err,
				})
			}
			continue
		}
		multicast.sockets[family] = socket
		multicast.startReader(family, socket)
	}
	multicast.joins = candidate
	report := multicastReport(candidate, failures)
	multicast.mu.Unlock()
	multicast.signalAdvertisement()
	return report, nil
}

// Close is idempotent and unblocks every current Receive and socket reader.
func (multicast *MulticastIO) Close() error {
	if multicast == nil {
		return nil
	}

	multicast.refreshMu.Lock()
	defer multicast.refreshMu.Unlock()
	multicast.mu.Lock()
	if multicast.closed {
		err := multicast.closeErr
		multicast.mu.Unlock()
		multicast.readerGroup.Wait()
		return err
	}
	multicast.closed = true
	close(multicast.done)
	sockets := multicast.sockets
	multicast.sockets = nil
	multicast.joins = nil
	multicast.mu.Unlock()

	closeErr := closeSocketMap(sockets)
	multicast.readerGroup.Wait()
	multicast.mu.Lock()
	multicast.closeErr = closeErr
	multicast.mu.Unlock()
	return closeErr
}

func (multicast *MulticastIO) startReader(
	family AddressFamily,
	socket multicastSocket,
) {
	multicast.readerGroup.Add(1)
	go func() {
		defer multicast.readerGroup.Done()
		buffer := make([]byte, MaxDatagramBytes+1)
		for {
			n, source, interfaceIndex, err := socket.ReadFrom(buffer)
			if err != nil {
				if multicast.isClosed() || errors.Is(err, net.ErrClosed) {
					return
				}
				if isDatagramTooLargeError(err) {
					continue
				}
				multicast.failFromReader(fmt.Errorf(
					"discovery: multicast receive %s: %w",
					family,
					err,
				))
				return
			}
			if n < 0 || n > len(buffer) {
				continue
			}
			if n > MaxDatagramBytes {
				continue
			}
			addrPort, selectedIndex, err := multicast.normalizeSource(
				family,
				source,
				interfaceIndex,
			)
			if err != nil {
				if errors.Is(err, ErrMulticastInterface) {
					continue
				}
				multicast.deliver(inboundDatagram{
					family: family,
					err:    err,
				})
				continue
			}
			multicast.deliver(inboundDatagram{
				payload:        append([]byte(nil), buffer[:n]...),
				source:         addrPort,
				family:         family,
				interfaceIndex: selectedIndex,
			})
		}
	}()
}

func (multicast *MulticastIO) failFromReader(cause error) {
	multicast.mu.Lock()
	if multicast.closed {
		multicast.mu.Unlock()
		return
	}
	sockets := multicast.failClosedLocked(cause)
	multicast.mu.Unlock()

	closeErr := closeSocketMap(sockets)
	multicast.mu.Lock()
	multicast.closeErr = errors.Join(multicast.closeErr, closeErr)
	multicast.mu.Unlock()
}

func (multicast *MulticastIO) deliver(datagram inboundDatagram) {
	select {
	case multicast.inbound <- datagram:
	case <-multicast.done:
	}
}

func (multicast *MulticastIO) normalizeSource(
	family AddressFamily,
	source net.Addr,
	interfaceIndex int,
) (netip.AddrPort, int, error) {
	addrPort, sourceZone, err := literalAddrPort(source)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	address := addrPort.Addr()
	switch family {
	case AddressFamilyIPv4:
		if !address.Is4() {
			return netip.AddrPort{}, 0, ErrMulticastSource
		}
	case AddressFamilyIPv6:
		if !address.Is6() || address.Is4In6() {
			return netip.AddrPort{}, 0, ErrMulticastSource
		}
	default:
		return netip.AddrPort{}, 0, ErrMulticastSource
	}

	if address.Is6() && address.IsLinkLocalUnicast() {
		iface, ok := multicast.selectedReceiveInterface(
			family,
			interfaceIndex,
			sourceZone,
		)
		if !ok {
			return netip.AddrPort{}, 0, ErrMulticastInterface
		}
		address = address.WithZone(iface.Name)
		return netip.AddrPortFrom(address, addrPort.Port()), iface.Index, nil
	}
	address = address.WithZone("")
	if interfaceIndex != 0 &&
		!multicast.joinIsActive(family, interfaceIndex) {
		return netip.AddrPort{}, 0, ErrMulticastInterface
	}
	return netip.AddrPortFrom(address, addrPort.Port()), interfaceIndex, nil
}

func (multicast *MulticastIO) selectedReceiveInterface(
	family AddressFamily,
	interfaceIndex int,
	sourceZone string,
) (net.Interface, bool) {
	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	if interfaceIndex > 0 {
		iface, ok := multicast.joins[joinKey{
			family:         family,
			interfaceIndex: interfaceIndex,
		}]
		return iface, ok
	}
	for key, iface := range multicast.joins {
		if key.family != family {
			continue
		}
		if sourceZone == iface.Name ||
			sourceZone == strconv.Itoa(iface.Index) {
			return iface, true
		}
	}
	return net.Interface{}, false
}

func (multicast *MulticastIO) joinIsActive(
	family AddressFamily,
	interfaceIndex int,
) bool {
	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	_, ok := multicast.joins[joinKey{
		family:         family,
		interfaceIndex: interfaceIndex,
	}]
	return ok
}

func (multicast *MulticastIO) isClosed() bool {
	multicast.mu.RLock()
	defer multicast.mu.RUnlock()
	return multicast.closed
}

func (multicast *MulticastIO) signalAdvertisement() {
	select {
	case multicast.advertise <- struct{}{}:
	default:
	}
}

func (multicast *MulticastIO) failClosedLocked(cause error) map[AddressFamily]multicastSocket {
	if !multicast.closed {
		multicast.closed = true
		close(multicast.done)
	}
	multicast.closeErr = cause
	sockets := multicast.sockets
	multicast.sockets = nil
	multicast.joins = nil
	return sockets
}

func configuredMulticastSocket(
	open func(
		AddressFamily,
		uint16,
		*net.Interface,
		netip.Addr,
	) (multicastSocket, error),
	family AddressFamily,
	port uint16,
	iface *net.Interface,
	group netip.Addr,
) (multicastSocket, error) {
	socket, err := open(family, port, iface, group)
	if err != nil {
		return nil, err
	}
	if err := socket.SetMulticastHopLimit(multicastHopLimit); err != nil {
		return nil, errors.Join(err, socket.Close())
	}
	if err := socket.SetMulticastLoopback(true); err != nil {
		return nil, errors.Join(err, socket.Close())
	}
	if err := socket.EnableReceiveInterface(); err != nil {
		return nil, errors.Join(err, socket.Close())
	}
	return socket, nil
}

func openFamilySocket(
	open func(
		AddressFamily,
		uint16,
		*net.Interface,
		netip.Addr,
	) (multicastSocket, error),
	family AddressFamily,
	port uint16,
	keys []joinKey,
	interfaces map[joinKey]net.Interface,
	group netip.Addr,
) (multicastSocket, joinKey, []InterfaceFailure) {
	failures := make([]InterfaceFailure, 0)
	for _, key := range keys {
		iface := interfaces[key]
		socket, err := configuredMulticastSocket(
			open,
			family,
			port,
			&iface,
			group,
		)
		if err == nil {
			return socket, key, failures
		}
		failures = append(failures, interfaceFailure(
			iface,
			family,
			"open",
			err,
		))
	}
	return nil, joinKey{}, failures
}

func validateMulticastInputs(
	port uint16,
	selected []net.Interface,
	deps multicastDependencies,
) error {
	if port < MinMulticastPort ||
		deps.open == nil ||
		deps.addrs == nil {
		return ErrInvalidMulticastConfig
	}
	return validateSelectedInterfaces(selected)
}

func validateSelectedInterfaces(selected []net.Interface) error {
	if len(selected) == 0 || len(selected) > MaxSelectedInterfaces {
		return ErrInvalidMulticastConfig
	}
	indices := make(map[int]struct{}, len(selected))
	names := make(map[string]struct{}, len(selected))
	var failures []error
	for _, iface := range selected {
		switch {
		case iface.Index <= 0 || iface.Name == "":
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				ErrInvalidMulticastConfig,
			))
		case iface.Flags&net.FlagUp == 0:
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				errors.New("interface is down"),
			))
		case iface.Flags&net.FlagMulticast == 0:
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				errors.New("interface does not support multicast"),
			))
		case iface.Flags&net.FlagLoopback != 0:
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				errors.New("loopback interface is forbidden"),
			))
		}
		if _, duplicate := indices[iface.Index]; duplicate {
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				errors.New("duplicate interface index"),
			))
		}
		if _, duplicate := names[iface.Name]; duplicate {
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"validate",
				errors.New("duplicate interface name"),
			))
		}
		indices[iface.Index] = struct{}{}
		names[iface.Name] = struct{}{}
	}
	if len(failures) != 0 {
		return errors.Join(
			ErrInvalidMulticastConfig,
			errors.Join(failures...),
		)
	}
	return nil
}

func resolveInterfaceFamilies(
	selected []net.Interface,
	addrs func(*net.Interface) ([]net.Addr, error),
) (map[joinKey]net.Interface, []InterfaceFailure) {
	desired := make(map[joinKey]net.Interface, len(selected)*2)
	failures := make([]InterfaceFailure, 0)
	for _, selectedInterface := range selected {
		iface := selectedInterface
		addresses, err := addrs(&iface)
		if err != nil {
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"addresses",
				err,
			))
			continue
		}
		families := availableFamilies(addresses)
		if len(families) == 0 {
			failures = append(failures, interfaceFailure(
				iface,
				0,
				"addresses",
				errors.New("interface has no usable IP address"),
			))
			continue
		}
		for _, family := range families {
			desired[joinKey{
				family:         family,
				interfaceIndex: iface.Index,
			}] = iface
		}
	}
	return desired, failures
}

func availableFamilies(addresses []net.Addr) []AddressFamily {
	var hasIPv4, hasIPv6 bool
	for _, networkAddress := range addresses {
		address, ok := literalIP(networkAddress)
		if !ok ||
			address.IsUnspecified() ||
			address.IsMulticast() {
			continue
		}
		switch {
		case address.Is4():
			hasIPv4 = true
		case address.Is6() && !address.Is4In6():
			hasIPv6 = true
		}
	}
	result := make([]AddressFamily, 0, 2)
	if hasIPv4 {
		result = append(result, AddressFamilyIPv4)
	}
	if hasIPv6 {
		result = append(result, AddressFamilyIPv6)
	}
	return result
}

func literalIP(address net.Addr) (netip.Addr, bool) {
	switch value := address.(type) {
	case *net.IPNet:
		result, ok := netip.AddrFromSlice(value.IP)
		return result.Unmap(), ok
	case *net.IPAddr:
		result, ok := netip.AddrFromSlice(value.IP)
		return result.Unmap(), ok
	default:
		return netip.Addr{}, false
	}
}

func literalAddrPort(source net.Addr) (netip.AddrPort, string, error) {
	udp, ok := source.(*net.UDPAddr)
	if !ok || udp == nil || udp.Port < 0 || udp.Port > 65535 {
		return netip.AddrPort{}, "", ErrMulticastSource
	}
	address, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, "", ErrMulticastSource
	}
	address = address.Unmap()
	if !address.IsValid() {
		return netip.AddrPort{}, "", ErrMulticastSource
	}
	return netip.AddrPortFrom(address, uint16(udp.Port)), udp.Zone, nil
}

func interfaceAddrs(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func interfaceFailure(
	iface net.Interface,
	family AddressFamily,
	operation string,
	err error,
) InterfaceFailure {
	return InterfaceFailure{
		InterfaceIndex: iface.Index,
		InterfaceName:  iface.Name,
		Family:         family,
		Operation:      operation,
		Err:            err,
	}
}

func failuresError(failures []InterfaceFailure) error {
	result := make([]error, len(failures))
	for index := range failures {
		result[index] = failures[index]
	}
	return errors.Join(result...)
}

func multicastReport(
	joins map[joinKey]net.Interface,
	failures []InterfaceFailure,
) MulticastReport {
	keys := sortedJoinKeys(joins)
	report := MulticastReport{
		Joins:    make([]InterfaceJoin, 0, len(keys)),
		Failures: slices.Clone(failures),
	}
	for _, key := range keys {
		iface := joins[key]
		report.Joins = append(report.Joins, InterfaceJoin{
			InterfaceIndex: iface.Index,
			InterfaceName:  iface.Name,
			Family:         key.family,
		})
	}
	return report
}

func sortedJoinKeys[T any](values map[joinKey]T) []joinKey {
	keys := make([]joinKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(left, right joinKey) int {
		if left.interfaceIndex != right.interfaceIndex {
			return left.interfaceIndex - right.interfaceIndex
		}
		return int(left.family) - int(right.family)
	})
	return keys
}

func desiredFamilyKeys(
	desired map[joinKey]net.Interface,
	family AddressFamily,
) []joinKey {
	keys := make([]joinKey, 0)
	for key := range desired {
		if key.family == family {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(left, right joinKey) int {
		return left.interfaceIndex - right.interfaceIndex
	})
	return keys
}

func removedJoinKeys(
	current map[joinKey]net.Interface,
	candidate map[joinKey]net.Interface,
) []joinKey {
	removed := make(map[joinKey]struct{})
	for key := range current {
		if _, retained := candidate[key]; !retained {
			removed[key] = struct{}{}
		}
	}
	return sortedJoinKeys(removed)
}

func countFamilyJoins(
	joins map[joinKey]net.Interface,
	family AddressFamily,
) int {
	count := 0
	for key := range joins {
		if key.family == family {
			count++
		}
	}
	return count
}

func rollbackAdded(
	added []joinKey,
	desired map[joinKey]net.Interface,
	currentSockets map[AddressFamily]multicastSocket,
	newSockets map[AddressFamily]multicastSocket,
	groups map[AddressFamily]netip.Addr,
) error {
	var result error
	for index := len(added) - 1; index >= 0; index-- {
		key := added[index]
		socket := currentSockets[key.family]
		if socket == nil {
			socket = newSockets[key.family]
		}
		iface := desired[key]
		if err := socket.LeaveGroup(&iface, groups[key.family]); err != nil {
			result = errors.Join(result, interfaceFailure(
				iface,
				key.family,
				"rollback leave",
				err,
			))
		}
	}
	return result
}

func restoreRemoved(
	left []joinKey,
	current map[joinKey]net.Interface,
	sockets map[AddressFamily]multicastSocket,
	groups map[AddressFamily]netip.Addr,
) error {
	var result error
	for index := len(left) - 1; index >= 0; index-- {
		key := left[index]
		iface := current[key]
		if err := sockets[key.family].JoinGroup(
			&iface,
			groups[key.family],
		); err != nil {
			result = errors.Join(result, interfaceFailure(
				iface,
				key.family,
				"rollback join",
				err,
			))
		}
	}
	return result
}

func closeSocketMap(sockets map[AddressFamily]multicastSocket) error {
	var result error
	for _, family := range []AddressFamily{AddressFamilyIPv4, AddressFamilyIPv6} {
		if socket := sockets[family]; socket != nil {
			result = errors.Join(result, socket.Close())
		}
	}
	return result
}

func cloneGroups(
	groups map[AddressFamily]netip.Addr,
) map[AddressFamily]netip.Addr {
	return map[AddressFamily]netip.Addr{
		AddressFamilyIPv4: groups[AddressFamilyIPv4],
		AddressFamilyIPv6: groups[AddressFamilyIPv6],
	}
}

type nativeIPv4Socket struct {
	packet *ipv4.PacketConn
	sendMu sync.Mutex
}

func (socket *nativeIPv4Socket) SetMulticastHopLimit(value int) error {
	return socket.packet.SetMulticastTTL(value)
}

func (socket *nativeIPv4Socket) SetMulticastLoopback(enabled bool) error {
	return socket.packet.SetMulticastLoopback(enabled)
}

func (socket *nativeIPv4Socket) EnableReceiveInterface() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return socket.packet.SetControlMessage(ipv4.FlagInterface, true)
}

func (socket *nativeIPv4Socket) JoinGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	return socket.packet.JoinGroup(iface, udpAddr(group, 0, ""))
}

func (socket *nativeIPv4Socket) LeaveGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	return socket.packet.LeaveGroup(iface, udpAddr(group, 0, ""))
}

func (socket *nativeIPv4Socket) ReadFrom(
	buffer []byte,
) (int, net.Addr, int, error) {
	n, control, source, err := socket.packet.ReadFrom(buffer)
	if err != nil {
		return 0, nil, 0, err
	}
	interfaceIndex := 0
	if control != nil {
		interfaceIndex = control.IfIndex
	}
	return n, source, interfaceIndex, nil
}

func (socket *nativeIPv4Socket) WriteTo(
	payload []byte,
	iface *net.Interface,
	destination netip.AddrPort,
) (int, error) {
	socket.sendMu.Lock()
	defer socket.sendMu.Unlock()
	if err := socket.packet.SetMulticastInterface(iface); err != nil {
		return 0, err
	}
	return socket.packet.WriteTo(
		payload,
		nil,
		udpAddr(destination.Addr(), destination.Port(), ""),
	)
}

func (socket *nativeIPv4Socket) Close() error {
	return socket.packet.Close()
}

type nativeIPv6Socket struct {
	packet *ipv6.PacketConn
	sendMu sync.Mutex
}

func (socket *nativeIPv6Socket) SetMulticastHopLimit(value int) error {
	return socket.packet.SetMulticastHopLimit(value)
}

func (socket *nativeIPv6Socket) SetMulticastLoopback(enabled bool) error {
	return socket.packet.SetMulticastLoopback(enabled)
}

func (socket *nativeIPv6Socket) EnableReceiveInterface() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return socket.packet.SetControlMessage(ipv6.FlagInterface, true)
}

func (socket *nativeIPv6Socket) JoinGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	return socket.packet.JoinGroup(iface, udpAddr(group, 0, ""))
}

func (socket *nativeIPv6Socket) LeaveGroup(
	iface *net.Interface,
	group netip.Addr,
) error {
	return socket.packet.LeaveGroup(iface, udpAddr(group, 0, ""))
}

func (socket *nativeIPv6Socket) ReadFrom(
	buffer []byte,
) (int, net.Addr, int, error) {
	n, control, source, err := socket.packet.ReadFrom(buffer)
	if err != nil {
		return 0, nil, 0, err
	}
	interfaceIndex := 0
	if control != nil {
		interfaceIndex = control.IfIndex
	}
	return n, source, interfaceIndex, nil
}

func (socket *nativeIPv6Socket) WriteTo(
	payload []byte,
	iface *net.Interface,
	destination netip.AddrPort,
) (int, error) {
	socket.sendMu.Lock()
	defer socket.sendMu.Unlock()
	if err := socket.packet.SetMulticastInterface(iface); err != nil {
		return 0, err
	}
	return socket.packet.WriteTo(
		payload,
		nil,
		udpAddr(
			destination.Addr(),
			destination.Port(),
			iface.Name,
		),
	)
}

func (socket *nativeIPv6Socket) Close() error {
	return socket.packet.Close()
}

func openNativeMulticastSocket(
	family AddressFamily,
	port uint16,
	iface *net.Interface,
	group netip.Addr,
) (multicastSocket, error) {
	var (
		network string
		zone    string
	)
	switch family {
	case AddressFamilyIPv4:
		network = "udp4"
	case AddressFamilyIPv6:
		network = "udp6"
		zone = iface.Name
	default:
		return nil, ErrInvalidMulticastConfig
	}
	connection, err := net.ListenMulticastUDP(
		network,
		iface,
		udpAddr(group, port, zone),
	)
	if err != nil {
		return nil, err
	}
	switch family {
	case AddressFamilyIPv4:
		return &nativeIPv4Socket{
			packet: ipv4.NewPacketConn(connection),
		}, nil
	case AddressFamilyIPv6:
		return &nativeIPv6Socket{
			packet: ipv6.NewPacketConn(connection),
		}, nil
	default:
		_ = connection.Close()
		return nil, ErrInvalidMulticastConfig
	}
}

func udpAddr(address netip.Addr, port uint16, zone string) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(address.AsSlice()),
		Port: int(port),
		Zone: zone,
	}
}
