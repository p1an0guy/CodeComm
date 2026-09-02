package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairinghttp"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
)

var errDaemonPairingConstruction = errors.New(
	"codecommd: pairing construction failed",
)

type daemonCredentialHandle interface {
	identityHandle
	Get(
		context.Context,
		credentialstore.Reference,
	) ([]byte, error)
	Create(
		context.Context,
		credentialstore.Reference,
		[]byte,
	) error
	Delete(context.Context, credentialstore.Reference) error
}

type daemonPairingRuntime struct {
	service  *pairingservice.Service
	operator *pairingservice.Operator
	server   *pairinghttp.Server
}

func newDaemonPairingRuntime(
	ctx context.Context,
	options daemonOptions,
	deviceID domain.DeviceID,
	identityPrivateKey ed25519.PrivateKey,
	identityPublicKey ed25519.PublicKey,
	credentials daemonCredentialHandle,
	view store.StateView,
	localState store.LocalState,
	node *consensus.Node,
	bootOrigin *agent.BootOrigin,
	operatorBinding event.Binding,
	originBootID domain.UUIDv7,
	peerListeners *daemonPeerListenerSet,
) (_ daemonPairingRuntime, resultErr error) {
	if ctx == nil ||
		!deviceID.Valid() ||
		len(identityPrivateKey) != ed25519.PrivateKeySize ||
		len(identityPublicKey) != ed25519.PublicKeySize ||
		credentials == nil ||
		node == nil ||
		bootOrigin == nil ||
		(len(options.peerListeners) != 0) != (peerListeners != nil) ||
		view.SessionID != options.sessionID ||
		view.WorkspaceID != options.workspaceID ||
		view.RecoveryGeneration > domain.MaxSafeInteger {
		return daemonPairingRuntime{}, errDaemonPairingConstruction
	}
	genesis, err := chain.GenesisDigest(view.GenesisJSON)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: genesis digest: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	var genesisDigest [sha256.Size]byte
	copy(genesisDigest[:], genesis[:])
	authorizer, err := pairingservice.NewAdmissionAuthorizer(
		pairingservice.AdmissionAuthorizerOptions{
			DeviceID: deviceID, OriginBootID: originBootID,
			IdentityPrivateKey: identityPrivateKey,
			OperatorOrigin:     operatorBinding,
		},
	)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: admission authorizer: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	authorizerOwned := false
	defer func() {
		if !authorizerOwned {
			resultErr = errors.Join(resultErr, authorizer.Close())
		}
	}()
	finalizer, err := pairingservice.NewDurableFinalizer(
		pairingservice.DurableFinalizerOptions{
			State: localState, Consensus: node,
			Rebootstrap:       daemonRebootstrapFinalizer{state: localState},
			Nonvoters:         node,
			IdentityPublicKey: identityPublicKey,
		},
	)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: durable finalizer: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	service, err := pairingservice.New(pairingservice.Options{
		State: localState, Secrets: credentials,
		Authorizer: authorizer, Finalizer: finalizer,
		Reservations: bootOrigin, Nonvoters: node,
		IdentityPublicKey: identityPublicKey,
	})
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: service: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	authorizerOwned = true
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, service.Close())
		}
	}()
	if err := service.Recover(ctx); err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: recover service: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	inviterOptions := pairingservice.InviterOptions{
		State: localState, Secrets: credentials,
		SessionID: options.sessionID, WorkspaceID: options.workspaceID,
		RecoveryGeneration:  view.RecoveryGeneration,
		IssuerDeviceID:      deviceID,
		IdentityPublicKey:   identityPublicKey,
		SignedGenesisDigest: genesisDigest,
		Sign: func(value pairing.Invite) (pairing.SignedInvite, error) {
			return pairing.SignInvite(value, identityPrivateKey)
		},
	}
	if peerListeners != nil {
		inviterOptions.EndpointProvider = func() ([]pairing.Endpoint, error) {
			return daemonPairingEndpoints(peerListeners.Current())
		}
	}
	inviter, err := pairingservice.NewInviter(inviterOptions)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: inviter: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	operator, err := pairingservice.NewOperator(inviter, service)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: operator: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	server, err := pairinghttp.New(service)
	if err != nil {
		return daemonPairingRuntime{}, fmt.Errorf(
			"%w: HTTP server: %v",
			errDaemonPairingConstruction,
			err,
		)
	}
	owned = true
	return daemonPairingRuntime{
		service: service, operator: operator, server: server,
	}, nil
}

func daemonPairingEndpoints(
	listeners []netip.AddrPort,
) ([]pairing.Endpoint, error) {
	var port uint16
	result := make(
		[]pairing.Endpoint,
		0,
		min(len(listeners), pairing.MaxInviteEndpoints),
	)
	for _, listener := range listeners {
		address := listener.Addr()
		if address.Is6() && address.IsLinkLocalUnicast() {
			continue
		}
		if port == 0 {
			port = listener.Port()
		}
		if listener.Port() != port {
			return nil, fmt.Errorf(
				"%w: selected peer listeners use different ports",
				errDaemonPairingConstruction,
			)
		}
		if len(result) == pairing.MaxInviteEndpoints {
			return nil, fmt.Errorf(
				"%w: too many invite endpoints",
				errDaemonPairingConstruction,
			)
		}
		result = append(result, pairing.Endpoint{
			IP: address, Port: listener.Port(),
		})
	}
	slices.SortFunc(result, compareDaemonPairingEndpoints)
	for index := 1; index < len(result); index++ {
		if compareDaemonPairingEndpoints(result[index-1], result[index]) == 0 {
			return nil, fmt.Errorf(
				"%w: duplicate invite endpoint",
				errDaemonPairingConstruction,
			)
		}
	}
	return result, nil
}

func compareDaemonPairingEndpoints(left, right pairing.Endpoint) int {
	if left.IP.Is4() != right.IP.Is4() {
		if left.IP.Is4() {
			return -1
		}
		return 1
	}
	if order := left.IP.Compare(right.IP); order != 0 {
		return order
	}
	return int(left.Port) - int(right.Port)
}

type daemonRebootstrapState interface {
	RevalidateRebootstrapEligibility(
		context.Context,
		store.PairingInviteRecord,
		pairing.RequestCore,
	) error
}

type daemonRebootstrapFinalizer struct {
	state daemonRebootstrapState
}

func (finalizer daemonRebootstrapFinalizer) FinalizeRebootstrap(
	ctx context.Context,
	details pairingservice.AttemptDetails,
) error {
	if finalizer.state == nil || ctx == nil {
		return pairingservice.ErrInvalidDurableFinalizer
	}
	err := finalizer.state.RevalidateRebootstrapEligibility(
		ctx,
		details.Invite,
		details.Core,
	)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrPairingEligibility):
		return fmt.Errorf(
			"%w: retained member is no longer eligible",
			pairingservice.ErrFinalizationRejected,
		)
	case errors.Is(err, store.ErrPairingStateIntegrity),
		errors.Is(err, store.ErrLocalStateIntegrity),
		errors.Is(err, store.ErrIntegrityCheck),
		errors.Is(err, store.ErrCorrupt):
		return fmt.Errorf(
			"%w: rebootstrap eligibility: %v",
			pairingservice.ErrFinalizationIntegrity,
			err,
		)
	default:
		return fmt.Errorf("codecommd: revalidate rebootstrap: %w", err)
	}
}
