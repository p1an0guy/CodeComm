package discovery

import (
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"

	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
)

const (
	MaxMulticastBaseInterval = 48 * time.Second
	AdvertisementLifetime    = 60 * time.Second
)

// MulticastBaseInterval keeps the longest jittered delay within the signed
// advertisement lifetime while preserving the configured endpoint-set TTL.
func MulticastBaseInterval(configured time.Duration) (time.Duration, error) {
	if err := validateEndpointAdvertisementInterval(configured); err != nil {
		return 0, err
	}
	return min(configured, MaxMulticastBaseInterval), nil
}

// NextAdvertisementDelay samples independent uniform +/-25 percent jitter.
func NextAdvertisementDelay(
	configured time.Duration,
	entropy io.Reader,
) (time.Duration, error) {
	base, err := MulticastBaseInterval(configured)
	if err != nil {
		return 0, err
	}
	if entropy == nil {
		return 0, codecommcrypto.ErrEntropy
	}
	jitter := base / 4
	span := big.NewInt(int64(2*jitter) + 1)
	sample, err := cryptorand.Int(entropy, span)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", codecommcrypto.ErrEntropy, err)
	}
	return base - jitter + time.Duration(sample.Int64()), nil
}

// AdvertisementExpiresAt returns the canonical receiver-bounded lifetime.
func AdvertisementExpiresAt(emittedAt time.Time) (domain.Timestamp, error) {
	if emittedAt.IsZero() {
		return "", ErrInvalidAdvertisement
	}
	expiresAt := emittedAt.UTC().Truncate(time.Second).Add(AdvertisementLifetime)
	value := domain.Timestamp(expiresAt.Format(time.RFC3339))
	if !value.Valid() {
		return "", ErrInvalidAdvertisement
	}
	return value, nil
}
