package store

import (
	"context"
	"time"

	"zombiezen.com/go/sqlite"
)

// DiscoveryAdvertisementInterval returns the active generation's committed
// multicast cadence. The value is validated as part of the same local read.
func (state LocalState) DiscoveryAdvertisementInterval(
	ctx context.Context,
) (time.Duration, error) {
	var interval time.Duration
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		values, err := readPeerEndpointPolicy(conn, lineage.sessionID)
		if err != nil {
			return err
		}
		interval = time.Duration(
			values.AdvertisementIntervalSeconds,
		) * time.Second
		return nil
	})
	if err != nil {
		return 0, err
	}
	return interval, nil
}
