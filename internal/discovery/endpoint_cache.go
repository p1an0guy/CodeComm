package discovery

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/policy"
)

var (
	ErrEndpointCache            = errors.New("discovery: invalid endpoint cache")
	ErrEndpointCacheFull        = errors.New("discovery: endpoint cache is full")
	ErrEndpointSequenceRollback = errors.New("discovery: endpoint sequence rollback")
	ErrEndpointSequenceConflict = errors.New("discovery: endpoint sequence reused with different bytes")
)

// EndpointSetUpdate describes how a verified endpoint set affected retention.
type EndpointSetUpdate uint8

const (
	EndpointSetStored EndpointSetUpdate = iota + 1
	EndpointSetReplaced
	EndpointSetIdempotent
)

// EndpointCache retains at most one current signed set per active member and
// enforces the source-owned sequence high-water rule.
type EndpointCache struct {
	maxEntries int

	mu      sync.Mutex
	entries map[domain.DeviceID]cachedEndpointSet
}

type cachedEndpointSet struct {
	value     VerifiedEndpointSet
	expiresAt time.Time
}

// NewEndpointCache constructs a cache bounded by committed membership policy.
func NewEndpointCache(maxEntries int) (*EndpointCache, error) {
	if maxEntries < int(policy.MinMemberDevices) ||
		maxEntries > int(policy.MaxMemberDevices) {
		return nil, ErrEndpointCache
	}
	return &EndpointCache{
		maxEntries: maxEntries,
		entries:    make(map[domain.DeviceID]cachedEndpointSet, maxEntries),
	}, nil
}

// Accept verifies and atomically retains one source-owned endpoint set.
func (cache *EndpointCache) Accept(
	input []byte,
	expected EndpointSetExpectation,
) (VerifiedEndpointSet, EndpointSetUpdate, error) {
	if cache == nil || cache.entries == nil {
		return VerifiedEndpointSet{}, 0, ErrEndpointCache
	}
	verified, err := ValidateEndpointSet(input, expected)
	if err != nil {
		return VerifiedEndpointSet{}, 0, err
	}
	value := verified.EndpointSet()
	expiresAt, err := value.ExpiresAt.Time()
	if err != nil {
		return VerifiedEndpointSet{}, 0, ErrEndpointSetTime
	}
	canonical := verified.CanonicalBytes()

	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.expireLocked(expected.Now)

	current, exists := cache.entries[value.DeviceID]
	if exists {
		currentValue := current.value.EndpointSet()
		switch {
		case value.EndpointSequence < currentValue.EndpointSequence:
			return VerifiedEndpointSet{}, 0, ErrEndpointSequenceRollback
		case value.EndpointSequence == currentValue.EndpointSequence:
			if !bytes.Equal(canonical, current.value.CanonicalBytes()) {
				return VerifiedEndpointSet{}, 0, ErrEndpointSequenceConflict
			}
			return cloneVerifiedEndpointSet(current.value), EndpointSetIdempotent, nil
		}
		cache.entries[value.DeviceID] = cachedEndpointSet{
			value:     cloneVerifiedEndpointSet(verified),
			expiresAt: expiresAt,
		}
		return cloneVerifiedEndpointSet(verified), EndpointSetReplaced, nil
	}
	if len(cache.entries) >= cache.maxEntries {
		return VerifiedEndpointSet{}, 0, ErrEndpointCacheFull
	}
	cache.entries[value.DeviceID] = cachedEndpointSet{
		value:     cloneVerifiedEndpointSet(verified),
		expiresAt: expiresAt,
	}
	return cloneVerifiedEndpointSet(verified), EndpointSetStored, nil
}

// Current returns the retained set if it remains live at now.
func (cache *EndpointCache) Current(
	deviceID domain.DeviceID,
	now time.Time,
) (VerifiedEndpointSet, bool) {
	if cache == nil || cache.entries == nil ||
		!deviceID.Valid() || now.IsZero() {
		return VerifiedEndpointSet{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.expireLocked(now)
	current, exists := cache.entries[deviceID]
	if !exists {
		return VerifiedEndpointSet{}, false
	}
	return cloneVerifiedEndpointSet(current.value), true
}

// Purge removes all retained routing authority for one member.
func (cache *EndpointCache) Purge(deviceID domain.DeviceID) {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	delete(cache.entries, deviceID)
	cache.mu.Unlock()
}

// PurgeAll removes endpoint sets after a recovery-generation change.
func (cache *EndpointCache) PurgeAll() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	clear(cache.entries)
	cache.mu.Unlock()
}

func (cache *EndpointCache) expireLocked(now time.Time) {
	now = now.UTC()
	for deviceID, current := range cache.entries {
		if !current.expiresAt.After(now) {
			delete(cache.entries, deviceID)
		}
	}
}

func cloneVerifiedEndpointSet(value VerifiedEndpointSet) VerifiedEndpointSet {
	return VerifiedEndpointSet{
		value:     value.value.clone(),
		canonical: value.CanonicalBytes(),
	}
}
