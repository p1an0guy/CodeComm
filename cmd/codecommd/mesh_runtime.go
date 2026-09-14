package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
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
	evidenceMode       store.ReplicaEvidenceMode
	bootstrapVoterIDs  []domain.DeviceID
}

type daemonPeerAdmissionRuntime interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	PeerAdmissionChanges() <-chan struct{}
}

type daemonSettledControlAdmission interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	ConsensusAuthorizationChanges() <-chan struct{}
}

type daemonSettledControlTransport interface {
	consensus.ConsensusStatusRequester
	consensus.CredentialRenewalRequester
	contentVerifiers() *peerauth.Verifiers
	phasedDaemonComponent
}

type daemonConsensusTransportFactory interface {
	Build(consensus.ConsensusTransportGate) (consensus.RaftTransport, error)
	BuildSettledControl(
		daemonSettledControlAdmission,
	) (daemonSettledControlTransport, error)
	NewIngress(
		context.Context,
		daemonOptions,
		daemonPeerAdmissionRuntime,
		transport.ContentCertificateProvider,
		transport.ConnectionHandler,
		transport.ConnectionHandler,
		net.Listener,
	) (*transport.Ingress, error)
	ConsensusRoutes() *transport.ConsensusRouteTable
	SetAuthenticatedConnectivity(
		transport.ConsensusAuthenticatedDialObserver,
		daemonConnectivityNotifier,
	) error
	ClearIdentityCertificate()
}

type daemonMeshFactoryConstructor func(
	daemonOptions,
	domain.DeviceID,
	tls.Certificate,
	func() time.Time,
) (daemonConsensusTransportFactory, error)

type daemonMeshTransportFactory struct {
	deviceID            domain.DeviceID
	identityCertificate tls.Certificate
	routes              *transport.ConsensusRouteTable
	authenticatedDials  *daemonAuthenticatedDialRelay
	credentialNow       func() time.Time
	admissionNow        func() time.Time
	admissionSources    map[netip.Addr]uint8

	stream    *transport.ConsensusStreamLayer
	verifiers *peerauth.Verifiers
}

type daemonSettledControlStream struct {
	stream    *transport.ConsensusStreamLayer
	verifiers *peerauth.Verifiers

	closeOnce sync.Once
	closeErr  error
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
	evidenceMode, err := database.ReplicaEvidenceMode(ctx)
	if err != nil {
		return daemonMeshPreflight{}, fmt.Errorf(
			"%w: inspect replica evidence mode: %v",
			errDaemonMeshConstruction,
			err,
		)
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
	if evidenceMode == store.ReplicaEvidenceRaft &&
		!hasCommittedConfiguration &&
		view.LastRaftAppliedLogIndex == nil {
		bootstrapVoterIDs = status.VoterSet.VoterDeviceIDs()
	}
	return daemonMeshPreflight{
		recoveryGeneration: view.RecoveryGeneration,
		evidenceMode:       evidenceMode,
		bootstrapVoterIDs:  bootstrapVoterIDs,
	}, nil
}

func newDaemonMeshTransportFactory(
	options daemonOptions,
	deviceID domain.DeviceID,
	identityCertificate tls.Certificate,
	credentialNow func() time.Time,
) (daemonConsensusTransportFactory, error) {
	return newDaemonMeshTransportFactoryWithDialContext(
		options,
		deviceID,
		identityCertificate,
		credentialNow,
		nil,
	)
}

func newDaemonMeshTransportFactoryWithDialContext(
	options daemonOptions,
	deviceID domain.DeviceID,
	identityCertificate tls.Certificate,
	credentialNow func() time.Time,
	dialContext transport.ConsensusRouteDialContext,
) (daemonConsensusTransportFactory, error) {
	if credentialNow == nil {
		return nil, errDaemonMeshConstruction
	}
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
	var resolver *transport.ConsensusRouteTable
	var err error
	if dialContext == nil {
		resolver, err = transport.NewConsensusRouteTable(selected, routes)
	} else {
		resolver, err = transport.NewConsensusRouteTableWithDialContext(
			selected,
			routes,
			dialContext,
		)
	}
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
		credentialNow:       credentialNow,
		admissionNow:        time.Now,
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
		factory.stream != nil {
		return nil, errDaemonMeshConstruction
	}
	if err := factory.prepareVerifiers(gate); err != nil {
		return nil, err
	}
	verifiers := factory.verifiers
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
			Timeout:              transport.ConsensusRaftOperationTimeout,
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

func (factory *daemonMeshTransportFactory) BuildSettledControl(
	admission daemonSettledControlAdmission,
) (daemonSettledControlTransport, error) {
	if factory == nil ||
		admission == nil ||
		!factory.deviceID.Valid() ||
		factory.routes == nil ||
		factory.authenticatedDials == nil ||
		factory.stream != nil {
		return nil, errDaemonMeshConstruction
	}
	if err := factory.prepareSettledVerifiers(admission); err != nil {
		return nil, err
	}
	stream, err := transport.NewConsensusStreamLayer(
		transport.ConsensusStreamOptions{
			LocalDeviceID:       factory.deviceID,
			IdentityCertificate: factory.identityCertificate,
			Endpoints:           factory.routes,
			Dialer:              factory.routes,
			VerifyExpectedPeer: factory.verifiers.
				VerifyExpectedConsensusPeer,
			AuthorizePeer: func(domain.DeviceID) error {
				return consensus.ErrConsensusPeerOutsideConfiguration
			},
			ObserveAuthenticatedDial: factory.authenticatedDials.observe,
			AuthorizationChanges: admission.
				ConsensusAuthorizationChanges(),
			ControlHandler: http.NotFoundHandler(),
		},
	)
	if err != nil {
		return nil, err
	}
	factory.stream = stream
	return &daemonSettledControlStream{
		stream:    stream,
		verifiers: factory.verifiers,
	}, nil
}

func (factory *daemonMeshTransportFactory) NewIngress(
	ctx context.Context,
	options daemonOptions,
	admission daemonPeerAdmissionRuntime,
	contentCertificate transport.ContentCertificateProvider,
	pairingHandler transport.ConnectionHandler,
	contentHandler transport.ConnectionHandler,
	listener net.Listener,
) (*transport.Ingress, error) {
	if len(options.peerListeners) == 0 {
		if listener != nil {
			return nil, errDaemonMeshConstruction
		}
		return nil, nil
	}
	if factory == nil ||
		admission == nil ||
		contentCertificate == nil ||
		listener == nil ||
		factory.admissionNow == nil {
		return nil, errDaemonMeshConstruction
	}
	if err := factory.prepareVerifiers(admission); err != nil {
		return nil, err
	}
	if factory.stream == nil &&
		pairingHandler == nil &&
		contentHandler == nil {
		return nil, errDaemonMeshConstruction
	}
	owned := false
	defer func() {
		if !owned {
			_ = listener.Close()
		}
	}()
	limiter, err := transport.NewAdmissionLimiterWithOptions(
		transport.AdmissionLimiterOptions{
			Now:                  factory.admissionNow,
			SourceMultiplicities: factory.admissionSources,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: peer admission limiter: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	ingress, err := transport.NewIngress(transport.IngressOptions{
		Listener:  listener,
		Admission: limiter,
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
		PeerAccessChanges: admission.PeerAdmissionChanges(),
		PeerAuthenticated: newDaemonAuthenticatedPeerObserver(
			factory.authenticatedDials,
		),
		Pairing:   pairingHandler,
		Consensus: factory.stream,
		Content:   contentHandler,
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

func (factory *daemonMeshTransportFactory) prepareVerifiers(
	admission interface {
		PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	},
) error {
	if factory == nil ||
		admission == nil ||
		factory.credentialNow == nil {
		return errDaemonMeshConstruction
	}
	if factory.verifiers != nil {
		return nil
	}
	verifiers, err := peerauth.NewVerifiers(
		admission.PeerAdmissionSnapshot,
		factory.credentialNow,
	)
	if err != nil {
		return err
	}
	factory.verifiers = verifiers
	return nil
}

func (factory *daemonMeshTransportFactory) prepareSettledVerifiers(
	admission interface {
		PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	},
) error {
	if factory == nil ||
		admission == nil ||
		factory.credentialNow == nil ||
		factory.verifiers != nil {
		return errDaemonMeshConstruction
	}
	verifiers, err := peerauth.NewVerifiersWithProvisional(
		admission.PeerAdmissionSnapshot,
		factory.credentialNow,
		peerauth.NewProvisionalAuthorizations(),
	)
	if err != nil {
		return err
	}
	factory.verifiers = verifiers
	return nil
}

func (factory *daemonMeshTransportFactory) ClearIdentityCertificate() {
	if factory == nil {
		return
	}
	clearDaemonTLSCertificate(&factory.identityCertificate)
}

func (runtime *daemonSettledControlStream) RequestCredentialRenewal(
	ctx context.Context,
	deviceID domain.DeviceID,
	body []byte,
) (transport.ConsensusControlResponse, error) {
	if runtime == nil || runtime.stream == nil {
		return transport.ConsensusControlResponse{},
			errDaemonMeshConstruction
	}
	return runtime.stream.RequestCredentialRenewal(ctx, deviceID, body)
}

func (runtime *daemonSettledControlStream) RequestConsensusStatus(
	ctx context.Context,
	deviceID domain.DeviceID,
) (transport.ConsensusControlResponse, error) {
	if runtime == nil || runtime.stream == nil {
		return transport.ConsensusControlResponse{},
			errDaemonMeshConstruction
	}
	return runtime.stream.RequestConsensusStatus(ctx, deviceID)
}

func (runtime *daemonSettledControlStream) contentVerifiers() *peerauth.Verifiers {
	if runtime == nil {
		return nil
	}
	return runtime.verifiers
}

func (runtime *daemonSettledControlStream) BeginClose() error {
	if runtime == nil || runtime.stream == nil {
		return errDaemonMeshConstruction
	}
	runtime.closeOnce.Do(func() {
		runtime.closeErr = runtime.stream.Close()
	})
	return runtime.closeErr
}

func (runtime *daemonSettledControlStream) Wait() error {
	return runtime.BeginClose()
}

func (factory *daemonMeshTransportFactory) ConsensusRoutes() *transport.ConsensusRouteTable {
	if factory == nil {
		return nil
	}
	return factory.routes
}

func (factory *daemonMeshTransportFactory) SetAuthenticatedConnectivity(
	observer transport.ConsensusAuthenticatedDialObserver,
	notifier daemonConnectivityNotifier,
) error {
	if factory == nil || factory.authenticatedDials == nil {
		return errDaemonMeshConstruction
	}
	if err := factory.authenticatedDials.set(observer, notifier); err != nil {
		return fmt.Errorf(
			"%w: authenticated connectivity observer: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	return nil
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
