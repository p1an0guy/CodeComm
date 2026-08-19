package store

import (
	"context"
	"testing"
	"time"

	"github.com/ijonahch/codecomm/internal/domain/policy"
)

func TestDiscoveryAdvertisementIntervalReadsCommittedPolicy(
	t *testing.T,
) {
	fixture := newPeerEndpointFixture(t, 1)

	got, err := fixture.store.LocalState().
		DiscoveryAdvertisementInterval(context.Background())
	if err != nil {
		t.Fatalf("DiscoveryAdvertisementInterval(): %v", err)
	}
	want := time.Duration(
		policy.DefaultAdvertisementIntervalSeconds,
	) * time.Second
	if got != want {
		t.Fatalf(
			"DiscoveryAdvertisementInterval() = %s, want %s",
			got,
			want,
		)
	}
}
