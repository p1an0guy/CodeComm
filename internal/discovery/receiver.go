package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	DiscoveryRatePerMinute = 20
	TrackedSourcesMax      = 1024
	DiscoveryStateMaxBytes = 8 << 20
	NonceCacheEntries      = 256
	NonceCacheTTL          = 5 * time.Minute
	CredentialClockSkew    = 120 * time.Second

	sourceStateAccountBytes = 512
	nonceAccountBytes       = 64
	attemptAccountBytes     = 32
)

var (
	ErrInvalidSource        = errors.New("discovery: invalid datagram source")
	ErrDatagramRateLimited  = errors.New("discovery: datagram source rate limited")
	ErrNonceReplay          = errors.New("discovery: advertisement nonce replay")
	ErrDiscoveryStateLimit  = errors.New("discovery: receiver state limit reached")
	ErrCredentialUnknown    = errors.New("discovery: advertising credential is unknown")
	ErrCredentialInactive   = errors.New("discovery: advertising credential is not usable")
	ErrCredentialResolution = errors.New("discovery: resolve advertising credential")
)

// CredentialRecord is the applied local authorization for one advertised
// epoch key. LatestRetained permits an expired key to authenticate only an
// endpoint hint; it never revives content access.
type CredentialRecord struct {
	DeviceID       domain.DeviceID
	Epoch          uint64
	PublicKey      ed25519.PublicKey
	NotBefore      domain.WholeSecondTimestamp
	NotAfter       domain.WholeSecondTimestamp
	MemberActive   bool
	LatestRetained bool
}

// CredentialResolver resolves only applied, locally retained authorization
// state. A missing record is ordinary hostile-network input, not an error.
type CredentialResolver func(
	context.Context,
	domain.UUIDv7,
	uint64,
	[sha256.Size]byte,
) (CredentialRecord, bool, error)

// Hint is a short-lived dial candidate. ExpectedDeviceID must still
// authenticate in TLS before application bytes are sent.
type Hint struct {
	ExpectedDeviceID          domain.DeviceID
	Destination               netip.AddrPort
	ExpiresAt                 domain.Timestamp
	CredentialEpoch           uint64
	AdvertisingKeyDigest      [sha256.Size]byte
	SignerCurrentlyAuthorized bool
}

// Receiver applies the unauthenticated-source bounds before resolving a key
// or performing Ed25519 verification.
type Receiver struct {
	sessionID domain.UUIDv7
	resolve   CredentialResolver
	now       func() time.Time

	ratePerMinute int
	sourceMax     int
	stateMaxBytes int

	mu         sync.Mutex
	sources    map[netip.Addr]*sourceState
	stateBytes int
}

type receiverOptions struct {
	sessionID     domain.UUIDv7
	resolve       CredentialResolver
	now           func() time.Time
	ratePerMinute int
	sourceMax     int
	stateMaxBytes int
}

type sourceState struct {
	lastSeen time.Time
	attempts []time.Time
	nonces   []nonceRecord
}

type nonceRecord struct {
	value      [AdvertisementNonceSize]byte
	observedAt time.Time
}

// ReceiverStats is bounded operational state suitable for tests and metrics.
type ReceiverStats struct {
	TrackedSources int
	CachedNonces   int
	AccountedBytes int
}

// NewReceiver constructs the fixed V1 discovery receiver.
func NewReceiver(
	sessionID domain.UUIDv7,
	resolve CredentialResolver,
) (*Receiver, error) {
	return newReceiver(receiverOptions{
		sessionID:     sessionID,
		resolve:       resolve,
		now:           time.Now,
		ratePerMinute: DiscoveryRatePerMinute,
		sourceMax:     TrackedSourcesMax,
		stateMaxBytes: DiscoveryStateMaxBytes,
	})
}

func newReceiver(options receiverOptions) (*Receiver, error) {
	if !options.sessionID.Valid() ||
		options.resolve == nil ||
		options.now == nil ||
		options.ratePerMinute < 1 ||
		options.sourceMax < 1 ||
		options.stateMaxBytes <
			sourceStateAccountBytes+nonceAccountBytes+attemptAccountBytes {
		return nil, ErrInvalidAdvertisement
	}
	return &Receiver{
		sessionID:     options.sessionID,
		resolve:       options.resolve,
		now:           options.now,
		ratePerMinute: options.ratePerMinute,
		sourceMax:     options.sourceMax,
		stateMaxBytes: options.stateMaxBytes,
		sources:       make(map[netip.Addr]*sourceState),
	}, nil
}

// Accept returns a bounded raw discovery hint only after the retained epoch
// key authenticates the datagram. The UDP source port is deliberately ignored.
func (receiver *Receiver) Accept(
	ctx context.Context,
	input []byte,
	source netip.AddrPort,
) (Hint, error) {
	if receiver == nil || receiver.resolve == nil || ctx == nil {
		return Hint{}, ErrInvalidAdvertisement
	}
	if err := ctx.Err(); err != nil {
		return Hint{}, err
	}
	sourceAddress := source.Addr()
	if !validDiscoverySource(sourceAddress) {
		return Hint{}, ErrInvalidSource
	}
	if len(input) > MaxDatagramBytes {
		return Hint{}, ErrAdvertisementTooLarge
	}
	if err := preflightAdvertisementRouting(
		input,
		receiver.sessionID,
	); err != nil {
		return Hint{}, err
	}

	now := receiver.now()
	if now.IsZero() {
		return Hint{}, ErrInvalidAdvertisement
	}
	if err := receiver.reserveAttempt(sourceAddress, now); err != nil {
		return Hint{}, err
	}
	unverified, err := ParseAdvertisement(input, receiver.sessionID)
	if err != nil {
		return Hint{}, err
	}
	if err := unverified.ValidateTime(now); err != nil {
		return Hint{}, err
	}
	advertisement := unverified.Advertisement()
	if err := receiver.reserveNonce(
		sourceAddress,
		advertisement.AdvertisementNonce,
		now,
	); err != nil {
		return Hint{}, err
	}

	record, found, err := receiver.resolve(
		ctx,
		receiver.sessionID,
		advertisement.CredentialEpoch,
		advertisement.AdvertisingKeyDigest,
	)
	if err != nil {
		return Hint{}, fmt.Errorf("%w: %v", ErrCredentialResolution, err)
	}
	if !found {
		return Hint{}, ErrCredentialUnknown
	}
	current, err := validateCredentialRecord(
		record,
		advertisement,
		now,
	)
	if err != nil {
		return Hint{}, err
	}
	verified, err := unverified.Verify(record.PublicKey)
	if err != nil {
		return Hint{}, err
	}
	destination := netip.AddrPortFrom(
		sourceAddress,
		advertisement.HTTPSPort,
	)
	if !destination.IsValid() {
		return Hint{}, ErrInvalidSource
	}
	return Hint{
		ExpectedDeviceID:          record.DeviceID,
		Destination:               destination,
		ExpiresAt:                 verified.Advertisement().ExpiresAt,
		CredentialEpoch:           verified.Advertisement().CredentialEpoch,
		AdvertisingKeyDigest:      verified.Advertisement().AdvertisingKeyDigest,
		SignerCurrentlyAuthorized: current,
	}, nil
}

// Stats returns a consistent bounded-state snapshot.
func (receiver *Receiver) Stats() ReceiverStats {
	if receiver == nil {
		return ReceiverStats{}
	}
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	result := ReceiverStats{
		TrackedSources: len(receiver.sources),
		AccountedBytes: receiver.stateBytes,
	}
	for _, source := range receiver.sources {
		result.CachedNonces += len(source.nonces)
	}
	return result
}

func (receiver *Receiver) reserveAttempt(
	address netip.Addr,
	now time.Time,
) error {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()

	state, exists := receiver.sources[address]
	if !exists {
		for len(receiver.sources) >= receiver.sourceMax {
			if !receiver.evictOldestSource(netip.Addr{}) {
				return ErrDiscoveryStateLimit
			}
		}
		if !receiver.ensureMemory(sourceStateAccountBytes, netip.Addr{}) {
			return ErrDiscoveryStateLimit
		}
		state = &sourceState{lastSeen: now}
		receiver.sources[address] = state
		receiver.stateBytes += sourceStateAccountBytes
	}
	state.lastSeen = now

	state.attempts = pruneTimes(
		state.attempts,
		now.Add(-time.Minute),
	)
	if len(state.attempts) >= receiver.ratePerMinute {
		return ErrDatagramRateLimited
	}
	if len(state.attempts) == cap(state.attempts) {
		if !receiver.growAttempts(address, state) {
			return ErrDiscoveryStateLimit
		}
	}
	state.attempts = append(state.attempts, now)
	return nil
}

func (receiver *Receiver) reserveNonce(
	address netip.Addr,
	nonce [AdvertisementNonceSize]byte,
	now time.Time,
) error {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()

	state, exists := receiver.sources[address]
	if !exists {
		return ErrDiscoveryStateLimit
	}
	state.lastSeen = now
	state.nonces = pruneNonces(
		state.nonces,
		now.Add(-NonceCacheTTL),
	)
	for _, prior := range state.nonces {
		if bytes.Equal(prior.value[:], nonce[:]) {
			return ErrNonceReplay
		}
	}
	if len(state.nonces) == NonceCacheEntries {
		copy(state.nonces, state.nonces[1:])
		state.nonces[len(state.nonces)-1] = nonceRecord{
			value:      nonce,
			observedAt: now,
		}
		return nil
	}
	if len(state.nonces) == cap(state.nonces) {
		if !receiver.growNonces(address, state) {
			return ErrDiscoveryStateLimit
		}
	}
	state.nonces = append(state.nonces, nonceRecord{
		value:      nonce,
		observedAt: now,
	})
	return nil
}

func (receiver *Receiver) growAttempts(
	address netip.Addr,
	state *sourceState,
) bool {
	nextCapacity := min(
		max(4, cap(state.attempts)+4),
		receiver.ratePerMinute,
	)
	if nextCapacity <= cap(state.attempts) {
		return false
	}
	extra := (nextCapacity - cap(state.attempts)) *
		attemptAccountBytes
	if !receiver.ensureMemory(extra, address) {
		return false
	}
	next := make([]time.Time, len(state.attempts), nextCapacity)
	copy(next, state.attempts)
	state.attempts = next
	receiver.stateBytes += extra
	return true
}

func (receiver *Receiver) growNonces(
	address netip.Addr,
	state *sourceState,
) bool {
	nextCapacity := min(
		max(16, cap(state.nonces)+16),
		NonceCacheEntries,
	)
	if nextCapacity <= cap(state.nonces) {
		return false
	}
	extra := (nextCapacity - cap(state.nonces)) *
		nonceAccountBytes
	if !receiver.ensureMemory(extra, address) {
		return false
	}
	next := make([]nonceRecord, len(state.nonces), nextCapacity)
	copy(next, state.nonces)
	state.nonces = next
	receiver.stateBytes += extra
	return true
}

func (receiver *Receiver) ensureMemory(
	extra int,
	protected netip.Addr,
) bool {
	if extra < 0 || extra > receiver.stateMaxBytes {
		return false
	}
	for receiver.stateBytes >
		receiver.stateMaxBytes-extra {
		if !receiver.evictOldestSource(protected) {
			return false
		}
	}
	return true
}

func (receiver *Receiver) evictOldestSource(
	protected netip.Addr,
) bool {
	var (
		oldestAddress netip.Addr
		oldestState   *sourceState
	)
	for address, state := range receiver.sources {
		if protected.IsValid() && address == protected {
			continue
		}
		if oldestState == nil ||
			state.lastSeen.Before(oldestState.lastSeen) ||
			state.lastSeen.Equal(oldestState.lastSeen) &&
				address.Less(oldestAddress) {
			oldestAddress = address
			oldestState = state
		}
	}
	if oldestState == nil {
		return false
	}
	receiver.stateBytes -= sourceAccountedBytes(oldestState)
	delete(receiver.sources, oldestAddress)
	return true
}

func sourceAccountedBytes(state *sourceState) int {
	if state == nil {
		return 0
	}
	return sourceStateAccountBytes +
		cap(state.attempts)*attemptAccountBytes +
		cap(state.nonces)*nonceAccountBytes
}

func pruneTimes(values []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(values) &&
		!values[first].After(cutoff) {
		first++
	}
	if first == 0 {
		return values
	}
	copy(values, values[first:])
	return values[:len(values)-first]
}

func pruneNonces(
	values []nonceRecord,
	cutoff time.Time,
) []nonceRecord {
	first := 0
	for first < len(values) &&
		!values[first].observedAt.After(cutoff) {
		first++
	}
	if first == 0 {
		return values
	}
	copy(values, values[first:])
	clear(values[len(values)-first:])
	return values[:len(values)-first]
}

func validDiscoverySource(address netip.Addr) bool {
	if !address.IsValid() ||
		address.IsUnspecified() ||
		address.IsLoopback() ||
		address.IsMulticast() ||
		address.Is4In6() {
		return false
	}
	if address.Is4() {
		bytes := address.As4()
		if bytes == [4]byte{255, 255, 255, 255} {
			return false
		}
		return address.Zone() == ""
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		return address.Zone() != ""
	}
	return address.Zone() == ""
}

func validateCredentialRecord(
	record CredentialRecord,
	advertisement Advertisement,
	now time.Time,
) (bool, error) {
	if !record.DeviceID.Valid() ||
		record.Epoch != advertisement.CredentialEpoch ||
		len(record.PublicKey) != ed25519.PublicKeySize ||
		sha256.Sum256(record.PublicKey) !=
			advertisement.AdvertisingKeyDigest ||
		!record.MemberActive ||
		!record.NotBefore.Valid() ||
		!record.NotAfter.Valid() {
		return false, ErrCredentialUnknown
	}
	notBefore, _ := record.NotBefore.Time()
	notAfter, _ := record.NotAfter.Time()
	if !notAfter.After(notBefore) {
		return false, ErrCredentialUnknown
	}
	now = now.UTC()
	current := !now.Add(CredentialClockSkew).Before(notBefore) &&
		now.Before(notAfter)
	if current {
		return true, nil
	}
	if now.Before(notAfter) || !record.LatestRetained {
		return false, ErrCredentialInactive
	}
	return false, nil
}
