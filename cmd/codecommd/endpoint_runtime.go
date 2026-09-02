package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/endpointservice"
	"github.com/ijonahch/codecomm/internal/store"
)

func newDaemonEndpointPublisher(
	ctx context.Context,
	options daemonOptions,
	deviceID domain.DeviceID,
	recoveryGeneration uint64,
	identityPrivateKey []byte,
	localState store.LocalState,
	advertisementInterval time.Duration,
) (*endpointservice.Service, error) {
	if ctx == nil || len(options.peerListeners) == 0 {
		return nil, errDaemonDiscoveryConstruction
	}
	publisher, err := endpointservice.New(endpointservice.Options{
		SessionID:          options.sessionID,
		WorkspaceID:        options.workspaceID,
		RecoveryGeneration: recoveryGeneration,
		DeviceID:           deviceID,
		IdentityPrivateKey: identityPrivateKey,
		LocalState:         localState,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: endpoint publisher: %v",
			errDaemonDiscoveryConstruction,
			err,
		)
	}
	var publicationErr error
	if daemonHasPortablePeerListener(options.peerListeners) {
		publicationErr = publisher.Refresh(
			ctx,
			endpointservice.RefreshInput{
				AdvertisementInterval: advertisementInterval,
				SelectedListeners:     options.peerListeners,
			},
		)
	} else {
		publicationErr = publisher.Withdraw()
	}
	if publicationErr != nil {
		_ = publisher.Close()
		return nil, fmt.Errorf(
			"%w: publish endpoint set: %v",
			errDaemonDiscoveryConstruction,
			publicationErr,
		)
	}
	return publisher, nil
}
