package discovery

import (
	"bytes"
	"errors"
	"testing"
	"time"

	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
)

func TestMulticastCadenceClampsConfiguredInterval(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		configured time.Duration
		want       time.Duration
	}{
		{configured: 5 * time.Second, want: 5 * time.Second},
		{configured: 20 * time.Second, want: 20 * time.Second},
		{configured: 48 * time.Second, want: 48 * time.Second},
		{configured: 300 * time.Second, want: 48 * time.Second},
	} {
		got, err := MulticastBaseInterval(test.configured)
		if err != nil || got != test.want {
			t.Fatalf("MulticastBaseInterval(%v) = (%v, %v), want %v", test.configured, got, err, test.want)
		}
	}
}

func TestNextAdvertisementDelayBoundsAndEntropyFailure(t *testing.T) {
	t.Parallel()

	minimum, err := NextAdvertisementDelay(300*time.Second, bytes.NewReader(make([]byte, 8)))
	if err != nil {
		t.Fatalf("NextAdvertisementDelay() error = %v", err)
	}
	if minimum != 36*time.Second {
		t.Fatalf("minimum delay = %v, want 36s", minimum)
	}
	if _, err := NextAdvertisementDelay(20*time.Second, nil); !errors.Is(err, codecommcrypto.ErrEntropy) {
		t.Fatalf("nil entropy error = %v, want %v", err, codecommcrypto.ErrEntropy)
	}
}

func TestAdvertisementExpiresAtUsesSixtySecondWholeSecondWindow(t *testing.T) {
	t.Parallel()

	emitted := time.Date(2026, 8, 13, 12, 0, 0, 999_999_999, time.FixedZone("offset", -7*60*60))
	got, err := AdvertisementExpiresAt(emitted)
	if err != nil {
		t.Fatalf("AdvertisementExpiresAt() error = %v", err)
	}
	if want := "2026-08-13T19:01:00Z"; string(got) != want {
		t.Fatalf("AdvertisementExpiresAt() = %q, want %q", got, want)
	}
}
