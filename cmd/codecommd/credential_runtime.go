package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	"github.com/ijonahch/codecomm/internal/credentialservice"
	"github.com/ijonahch/codecomm/internal/domain"
)

var errDaemonCredentialConstruction = errors.New(
	"codecommd: content credential construction failed",
)

func newDaemonCredentialService(
	ctx context.Context,
	sessionID domain.UUIDv7,
	deviceID domain.DeviceID,
	identityPrivateKey ed25519.PrivateKey,
	secrets daemonCredentialHandle,
	node *consensus.Node,
) (*credentialservice.Service, error) {
	if ctx == nil ||
		!sessionID.Valid() ||
		!deviceID.Valid() ||
		len(identityPrivateKey) != ed25519.PrivateKeySize ||
		secrets == nil ||
		node == nil {
		return nil, errDaemonCredentialConstruction
	}
	service, err := credentialservice.New(credentialservice.Options{
		SessionID: sessionID,
		DeviceID:  deviceID,
		Secrets:   secrets,
		Consensus: node,
		Sign: func(
			ctx context.Context,
			epoch uint64,
			publicKey ed25519.PublicKey,
		) (credential.Binding, error) {
			if err := ctx.Err(); err != nil {
				return credential.Binding{}, err
			}
			return credential.SignBinding(
				sessionID,
				deviceID,
				epoch,
				publicKey,
				identityPrivateKey,
			)
		},
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			errDaemonCredentialConstruction,
			err,
		)
	}
	if err := service.Recover(ctx); err != nil {
		_ = service.Close()
		return nil, fmt.Errorf(
			"%w: recover: %v",
			errDaemonCredentialConstruction,
			err,
		)
	}
	return service, nil
}

var _ phasedDaemonComponent = (*credentialservice.Service)(nil)
