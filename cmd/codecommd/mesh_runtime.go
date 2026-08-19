package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/consensus"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/voteractivation"
)

const daemonConsensusTransportTimeout = 10 * time.Second

var (
	errDaemonIdentityMismatch = errors.New(
		"codecommd: installation identity is not the active enrolled member",
	)
	errDaemonMeshConstruction = errors.New(
		"codecommd: secure mesh construction failed",
	)
)

type daemonMeshPreflight struct {
	recoveryGeneration uint64
	bootstrapVoterIDs  []domain.DeviceID
}

type daemonConsensusTransportFactory interface {
	Build(consensus.ConsensusTransportGate) (consensus.RaftTransport, error)
	NewIngress(
		context.Context,
		daemonOptions,
		*consensus.Node,
		transport.ContentCertificateProvider,
		transport.ConnectionHandler,
		transport.ConnectionHandler,
		func(context.Context, netip.AddrPort) (net.Listener, error),
	) (*transport.Ingress, error)
	ConsensusRoutes() *transport.ConsensusRouteTable
	SetAuthenticatedDialObserver(
		transport.ConsensusAuthenticatedDialObserver,
	) error
	ClearIdentityCertificate()
}

type daemonMeshFactoryConstructor func(
	daemonOptions,
	domain.DeviceID,
	tls.Certificate,
) (daemonConsensusTransportFactory, error)

type daemonMeshTransportFactory struct {
	deviceID            domain.DeviceID
	identityCertificate tls.Certificate
	routes              *transport.ConsensusRouteTable
	authenticatedDials  *daemonAuthenticatedDialRelay

	stream    *transport.ConsensusStreamLayer
	verifiers *peerauth.Verifiers
}

func inspectDaemonMeshState(
	ctx context.Context,
	options daemonOptions,
	deviceID domain.DeviceID,
	identityPublicKey []byte,
) (_ daemonMeshPreflight, resultErr error) {
	database, err := store.Open(ctx, store.Options{Path: options.statePath})
	if err != nil {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: inspect state: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	defer func() {
		resultErr = errors.Join(resultErr, database.Close())
	}()

	view, err := database.View(ctx)
	if err != nil {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: inspect lineage: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	if view.SessionID != options.sessionID ||
		view.WorkspaceID != options.workspaceID {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: got session %s and workspace %s",
			errDaemonLineageMismatch,
			view.SessionID,
			view.WorkspaceID,
		)
	}
	status, err := database.LocalState().StatusSnapshot(ctx, deviceID, 1)
	if err != nil {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: inspect local membership: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	if status.Member.ID != deviceID ||
		status.Member.Status != device.StatusActive ||
		!bytes.Equal(status.Member.IdentityPublicKey, identityPublicKey) {
		return daemonMeshPreflight{}, errDaemonIdentityMismatch
	}
	_, hasCommittedConfiguration, err :=
		database.CommittedRaftConfiguration(ctx)
	if err != nil {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: inspect committed configuration: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	var bootstrapVoterIDs []domain.DeviceID
	if !hasCommittedConfiguration &&
		view.LastRaftAppliedLogIndex == nil {
		bootstrapVoterIDs = status.VoterSet.VoterDeviceIDs()
	}
	return daemonMeshPreflight{
		recoveryGeneration: view.RecoveryGeneration,
		bootstrapVoterIDs:  bootstrapVoterIDs,
	}, nil
}

func newDaemonMeshTransportFactory(
	options daemonOptions,
	deviceID domain.DeviceID,
	identityCertificate tls.Certificate,
) (daemonConsensusTransportFactory, error) {
	routes := make([]transport.ConsensusRoute, len(options.peerRoutes))
	for index, route := range options.peerRoutes {
		if route.deviceID == deviceID {
			return nil, fmt.Errorf(
				"%w: a peer route names the local device",
				errInvalidDaemonOptions,
			)
		}
		routes[index] = transport.ConsensusRoute{
			PeerDeviceID:         route.deviceID,
			RemoteEndpoint:       route.remote,
			SelectedLocalAddress: route.local,
		}
	}
	selected := make([]netip.Addr, 0, len(options.peerListeners))
	for _, listener := range options.peerListeners {
		address := listener.Addr()
		if len(selected) == 0 || selected[len(selected)-1] != address {
			selected = append(selected, address)
		}
	}
	resolver, err := transport.NewConsensusRouteTable(selected, routes)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: consensus routes: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	return &daemonMeshTransportFactory{
		deviceID:            deviceID,
		identityCertificate: cloneDaemonTLSCertificate(identityCertificate),
		routes:              resolver,
		authenticatedDials:  &daemonAuthenticatedDialRelay{},
	}, nil
}

func (factory *daemonMeshTransportFactory) Build(
	gate consensus.ConsensusTransportGate,
) (consensus.RaftTransport, error) {
	if factory == nil ||
		gate == nil ||
		!factory.deviceID.Valid() ||
		factory.routes == nil ||
		factory.authenticatedDials == nil ||
		factory.stream != nil ||
		factory.verifiers != nil {
		return nil, errDaemonMeshConstruction
	}
	verifiers, err := peerauth.NewVerifiers(
		gate.PeerAdmissionSnapshot,
		time.Now,
	)
	if err != nil {
		return nil, err
	}
	stream, err := transport.NewConsensusStreamLayer(
		transport.ConsensusStreamOptions{
			LocalDeviceID:            factory.deviceID,
			IdentityCertificate:      factory.identityCertificate,
			Endpoints:                factory.routes,
			Dialer:                   factory.routes,
			VerifyExpectedPeer:       verifiers.VerifyExpectedConsensusPeer,
			AuthorizePeer:            gate.AuthorizePeer,
			ObserveAuthenticatedDial: factory.authenticatedDials.observe,
			AuthorizationChanges:     gate.AuthorizationChanges(),
			ControlHandler:           gate.ConsensusControlHandler(),
		},
	)
	if err != nil {
		return nil, err
	}
	raftTransport, err := transport.NewConsensusNetworkTransport(
		transport.ConsensusNetworkTransportOptions{
			Stream:               stream,
			LocalServerID:        raft.ServerID(factory.deviceID),
			Timeout:              daemonConsensusTransportTimeout,
			Logger:               hclog.NewNullLogger(),
			AuthorizeReplication: gate.AuthorizeReplication,
			AuthorizeCommitProbe: gate.AuthorizeCommitProbe,
		},
	)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	factory.stream = stream
	factory.verifiers = verifiers
	return raftTransport, nil
}

func (factory *daemonMeshTransportFactory) NewIngress(
	ctx context.Context,
	options daemonOptions,
	node *consensus.Node,
	contentCertificate transport.ContentCertificateProvider,
	pairingHandler transport.ConnectionHandler,
	contentHandler transport.ConnectionHandler,
	listen func(context.Context, netip.AddrPort) (net.Listener, error),
) (*transport.Ingress, error) {
	if len(options.peerListeners) == 0 {
		return nil, nil
	}
	if factory == nil ||
		factory.stream == nil ||
		factory.verifiers == nil ||
		node == nil ||
		contentCertificate == nil ||
		pairingHandler == nil ||
		listen == nil {
		return nil, errDaemonMeshConstruction
	}
	listener, err := openDaemonPeerListeners(
		ctx,
		options.peerListeners,
		listen,
	)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = listener.Close()
		}
	}()
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener: listener,
		TLS: transport.ServerTLSOptions{
			IdentityCertificate: factory.identityCertificate,
			ContentCertificate:  contentCertificate,
			VerifyPairingPeer: func(
				certificate transport.IdentityCertificate,
			) error {
				return factory.verifiers.VerifyPairingPeer(certificate)
			},
			VerifyConsensusPeer: factory.verifiers.VerifyConsensusPeer,
			VerifyContentPeer:   factory.verifiers.VerifyContentPeer,
		},
		PeerAccessChanges: node.PeerAdmissionChanges(),
		Pairing:           pairingHandler,
		Consensus:         factory.stream,
		Content:           contentHandler,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"%w: peer ingress: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	owned = true
	return ingress, nil
}

func (factory *daemonMeshTransportFactory) ClearIdentityCertificate() {
	if factory == nil {
		return
	}
	clearDaemonTLSCertificate(&factory.identityCertificate)
}

func (factory *daemonMeshTransportFactory) ConsensusRoutes() *transport.ConsensusRouteTable {
	if factory == nil {
		return nil
	}
	return factory.routes
}

func (factory *daemonMeshTransportFactory) SetAuthenticatedDialObserver(
	observer transport.ConsensusAuthenticatedDialObserver,
) error {
	if factory == nil || factory.authenticatedDials == nil {
		return errDaemonMeshConstruction
	}
	if err := factory.authenticatedDials.set(observer); err != nil {
		return fmt.Errorf(
			"%w: authenticated dial observer: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	return nil
}

func openDaemonPeerListeners(
	ctx context.Context,
	endpoints []netip.AddrPort,
	listen func(context.Context, netip.AddrPort) (net.Listener, error),
) (net.Listener, error) {
	if ctx == nil || len(endpoints) == 0 || listen == nil {
		return nil, errDaemonMeshConstruction
	}
	listeners := make([]net.Listener, 0, len(endpoints))
	closeListeners := func() error {
		errs := make([]error, 0, len(listeners))
		for _, listener := range listeners {
			errs = append(errs, listener.Close())
		}
		return errors.Join(errs...)
	}
	for _, endpoint := range endpoints {
		listener, err := listen(ctx, endpoint)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf(
					"%w: listen on %s: %v",
					errDaemonMeshConstruction,
					endpoint,
					err,
				),
				closeListeners(),
			)
		}
		if listener == nil {
			return nil, errors.Join(
				errDaemonMeshConstruction,
				closeListeners(),
			)
		}
		listeners = append(listeners, listener)
	}
	aggregate, err := transport.NewAggregateListener(listeners...)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf(
				"%w: aggregate peer listeners: %v",
				errDaemonMeshConstruction,
				err,
			),
			closeListeners(),
		)
	}
	return aggregate, nil
}

func listenDaemonPeer(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Listener, error) {
	if ctx == nil || !endpoint.IsValid() {
		return nil, errDaemonMeshConstruction
	}
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	var listenConfig net.ListenConfig
	return listenConfig.Listen(ctx, network, endpoint.String())
}

func newDaemonVoterActivationSigner(
	deviceID domain.DeviceID,
	identityPrivateKey []byte,
) consensus.VoterActivationSigner {
	return consensus.VoterActivationSignerAdapter{
		SignerDeviceID: deviceID,
		SignProof: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedProof,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			proof, err := voteractivation.SignProof(
				unsigned,
				identityPrivateKey,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return proof.VoterSignature(), nil
		},
		SignHandoff: func(
			ctx context.Context,
			unsigned voteractivation.UnsignedAuthorityHandoff,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			payload, err := voteractivation.SignAuthorityHandoff(
				unsigned,
				identityPrivateKey,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			return payload.HandoffSignature(), nil
		},
	}
}

func newDaemonCredentialEndorsementSigner(
	deviceID domain.DeviceID,
	identityPrivateKey []byte,
) consensus.CredentialEndorsementSigner {
	return consensus.CredentialEndorsementSignerAdapter{
		SignerDeviceID: deviceID,
		Sign: func(
			ctx context.Context,
			preimage []byte,
		) ([ed25519.SignatureSize]byte, error) {
			if err := ctx.Err(); err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			signature, err := codecommcrypto.SignEd25519(
				identityPrivateKey,
				codec.SignatureCredentialTimeEndorsement,
				preimage,
			)
			if err != nil {
				return [ed25519.SignatureSize]byte{}, err
			}
			var result [ed25519.SignatureSize]byte
			copy(result[:], signature)
			clear(signature)
			return result, nil
		},
	}
}

func cloneDaemonTLSCertificate(
	certificate tls.Certificate,
) tls.Certificate {
	cloned := tls.Certificate{
		Certificate: make([][]byte, len(certificate.Certificate)),
		Leaf:        certificate.Leaf,
	}
	for index, value := range certificate.Certificate {
		cloned.Certificate[index] = bytes.Clone(value)
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		cloned.PrivateKey = ed25519.PrivateKey(bytes.Clone(privateKey))
	} else {
		cloned.PrivateKey = certificate.PrivateKey
	}
	return cloned
}

func clearDaemonTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(privateKey)
	}
	*certificate = tls.Certificate{}
}
