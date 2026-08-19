package transport

import (
	"context"
	"fmt"

	"github.com/ijonahch/codecomm/internal/domain"
)

// ProbeConsensusPeer actively verifies reachability over the peer's reusable,
// mutually authenticated HTTP/2 consensus connection.
func (layer *ConsensusStreamLayer) ProbeConsensusPeer(
	ctx context.Context,
	deviceID domain.DeviceID,
) (ConsensusPeerReachabilityToken, error) {
	if layer == nil || layer.ctx == nil || ctx == nil ||
		!deviceID.Valid() || deviceID == layer.localDeviceID {
		return ConsensusPeerReachabilityToken{},
			ErrInvalidConsensusStreamOptions
	}
	if err := ctx.Err(); err != nil {
		return ConsensusPeerReachabilityToken{}, err
	}
	probeContext, cancel := context.WithCancel(ctx)
	stopLayerCancellation := context.AfterFunc(layer.ctx, cancel)
	defer func() {
		stopLayerCancellation()
		cancel()
	}()

	if err := layer.authorize(deviceID); err != nil {
		return ConsensusPeerReachabilityToken{}, err
	}
	peer, err := layer.peer(deviceID)
	if err != nil {
		return ConsensusPeerReachabilityToken{}, err
	}
	physical, generation, err := layer.reachabilityPhysical(
		probeContext,
		peer,
		deviceID,
	)
	if err != nil {
		return ConsensusPeerReachabilityToken{}, err
	}
	if err := physical.http2.Ping(probeContext); err != nil {
		layer.invalidateConsensusPhysical(peer, deviceID, physical, generation)
		if probeErr := probeContext.Err(); probeErr != nil {
			return ConsensusPeerReachabilityToken{}, probeErr
		}
		return ConsensusPeerReachabilityToken{}, fmt.Errorf(
			"%w: HTTP/2 PING",
			ErrConsensusPeerUnreachable,
		)
	}
	if err := layer.verifyExpected(deviceID, physical.identity); err != nil {
		layer.invalidateConsensusPhysical(peer, deviceID, physical, generation)
		return ConsensusPeerReachabilityToken{}, err
	}
	if err := layer.authorize(deviceID); err != nil {
		layer.invalidateConsensusPhysical(peer, deviceID, physical, generation)
		return ConsensusPeerReachabilityToken{}, err
	}

	peer.mu.Lock()
	current := peer.physical == physical &&
		peer.generation == generation &&
		physical.usable()
	peer.mu.Unlock()
	if !current {
		return ConsensusPeerReachabilityToken{},
			ErrConsensusReachabilityTokenStale
	}
	return ConsensusPeerReachabilityToken{
		DeviceID:   deviceID,
		Generation: generation,
	}, nil
}

// VerifyConsensusPeerReachability checks token freshness using locked
// in-memory connection state only. It never resolves, dials, waits, or invokes
// authorization callbacks.
func (layer *ConsensusStreamLayer) VerifyConsensusPeerReachability(
	token ConsensusPeerReachabilityToken,
) error {
	if layer == nil || !token.DeviceID.Valid() || token.Generation == 0 {
		return ErrConsensusReachabilityTokenStale
	}
	layer.mu.Lock()
	if layer.closed || !layer.authorizationAvailable {
		layer.mu.Unlock()
		return ErrConsensusReachabilityTokenStale
	}
	peer := layer.peers[token.DeviceID]
	layer.mu.Unlock()
	if peer == nil {
		return ErrConsensusReachabilityTokenStale
	}
	peer.mu.Lock()
	fresh := peer.generation == token.Generation &&
		peer.physical != nil &&
		peer.physical.usable()
	peer.mu.Unlock()
	if !fresh {
		return ErrConsensusReachabilityTokenStale
	}
	return nil
}

func (layer *ConsensusStreamLayer) reachabilityPhysical(
	ctx context.Context,
	peer *consensusPeerClient,
	deviceID domain.DeviceID,
) (*consensusPhysicalClient, uint64, error) {
	if layer == nil || ctx == nil || peer == nil {
		return nil, 0, ErrInvalidConsensusStreamOptions
	}
	peer.mu.Lock()
	if err := layer.openError(); err != nil {
		peer.mu.Unlock()
		return nil, 0, err
	}
	if peer.physical == nil || !peer.physical.usable() {
		if peer.openStreams != 0 {
			peer.mu.Unlock()
			return nil, 0, ErrConsensusEndpointUnavailable
		}
		if peer.physical != nil {
			physical := peer.detachPhysicalLocked()
			_ = physical.close()
		}
		physical, err := layer.dialPhysical(ctx, deviceID, true)
		if err != nil {
			peer.mu.Unlock()
			return nil, 0, err
		}
		if !peer.attachPhysicalLocked(physical) {
			peer.mu.Unlock()
			_ = physical.close()
			return nil, 0, ErrConsensusEndpointUnavailable
		}
	}
	if err := layer.verifyExpected(deviceID, peer.physical.identity); err != nil {
		physical := peer.detachPhysicalLocked()
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, 0, err
	}
	if err := layer.authorize(deviceID); err != nil {
		physical := peer.detachPhysicalLocked()
		peer.mu.Unlock()
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
		return nil, 0, err
	}
	physical := peer.physical
	generation := peer.generation
	peer.mu.Unlock()
	return physical, generation, nil
}

func (layer *ConsensusStreamLayer) invalidateConsensusPhysical(
	peer *consensusPeerClient,
	deviceID domain.DeviceID,
	expected *consensusPhysicalClient,
	generation uint64,
) {
	if layer == nil || peer == nil || expected == nil {
		return
	}
	peer.mu.Lock()
	var physical *consensusPhysicalClient
	if peer.physical == expected && peer.generation == generation {
		physical = peer.detachPhysicalLocked()
	}
	peer.mu.Unlock()
	if physical != nil {
		_ = physical.close()
		layer.closeStreamsForDevice(deviceID)
	}
}
