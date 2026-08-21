package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/canonicalcoverage"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credentialservice"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/pairingservice"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

const fatalPollInterval = 100 * time.Millisecond
const daemonPeerShutdownTimeout = 30 * time.Second

var (
	errInvalidDaemonOptions      = errors.New("codecommd: invalid options")
	errDaemonLineageMismatch     = errors.New("codecommd: state lineage mismatch")
	errInvalidDaemonDependencies = errors.New("codecommd: invalid dependencies")
	errDaemonServerStopped       = errors.New("codecommd: server stopped unexpectedly")
	errDaemonServerShutdown      = errors.New("codecommd: server shutdown timed out")
)

type daemonOptions struct {
	statePath     string
	consensusDir  string
	endpoint      ipc.Endpoint
	sessionID     domain.UUIDv7
	workspaceID   domain.UUIDv4
	peerListeners []netip.AddrPort
	peerRoutes    []daemonPeerRoute
}

type identityHandle interface {
	Close() error
}

type phasedDaemonComponent interface {
	BeginClose() error
	Wait() error
}

type daemonConsensusCloser interface {
	Close() error
}

type daemonServerResult struct {
	name string
	err  error
}

type daemonDependencies struct {
	loadIdentity   func(context.Context) (identityHandle, []byte, error)
	newBootID      func() (domain.UUIDv7, error)
	newMeshFactory daemonMeshFactoryConstructor
	listenPeer     func(
		context.Context,
		netip.AddrPort,
	) (net.Listener, error)
	openMulticast     daemonMulticastOpener
	listInterfaces    daemonInterfaceLister
	interfaceAddrs    daemonInterfaceAddressProvider
	credentialNow     func() time.Time
	canonicalCoverage canonicalcoverage.ReceiptCollector
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	options, err := parseDaemonOptions(os.Args[1:], os.Stderr)
	if err == nil {
		err = runDaemon(ctx, options, productionDaemonDependencies())
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseDaemonOptions(
	args []string,
	errorOutput io.Writer,
) (daemonOptions, error) {
	if errorOutput == nil {
		return daemonOptions{}, errInvalidDaemonOptions
	}
	flags := flag.NewFlagSet("codecommd", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	foreground := flags.Bool(
		"foreground",
		false,
		"run as an explicitly managed foreground daemon",
	)
	statePath := flags.String("state", "", "absolute state.db path")
	consensusDir := flags.String(
		"consensus-dir",
		"",
		"absolute Raft storage directory",
	)
	endpointText := flags.String(
		"endpoint",
		"",
		"supervisor-assigned Unix socket or named pipe",
	)
	sessionText := flags.String("session", "", "session UUIDv7")
	workspaceText := flags.String("workspace", "", "workspace UUIDv4")
	var peerListenerValues daemonStringList
	var peerRouteValues daemonStringList
	flags.Var(
		&peerListenerValues,
		"peer-listen",
		"selected literal peer listener IP and port; repeat per interface",
	)
	flags.Var(
		&peerRouteValues,
		"peer-route",
		"peer device ID, remote literal endpoint, and selected local IP",
	)
	if err := flags.Parse(args); err != nil {
		return daemonOptions{}, fmt.Errorf("%w: %v", errInvalidDaemonOptions, err)
	}
	if !*foreground || flags.NArg() != 0 {
		return daemonOptions{}, fmt.Errorf(
			"%w: --foreground and no positional arguments are required",
			errInvalidDaemonOptions,
		)
	}
	if !cleanAbsolutePath(*statePath) ||
		!cleanAbsolutePath(*consensusDir) {
		return daemonOptions{}, fmt.Errorf(
			"%w: state and consensus paths must be clean and absolute",
			errInvalidDaemonOptions,
		)
	}
	endpoint, err := ipc.ParseEndpoint(*endpointText)
	if err != nil {
		return daemonOptions{}, fmt.Errorf(
			"%w: endpoint: %v",
			errInvalidDaemonOptions,
			err,
		)
	}
	sessionID := domain.UUIDv7(*sessionText)
	workspaceID := domain.UUIDv4(*workspaceText)
	if !sessionID.Valid() || !workspaceID.Valid() {
		return daemonOptions{}, fmt.Errorf(
			"%w: invalid session or workspace identifier",
			errInvalidDaemonOptions,
		)
	}
	peerListeners, peerRoutes, err := parseDaemonMeshOptions(
		peerListenerValues,
		peerRouteValues,
	)
	if err != nil {
		return daemonOptions{}, err
	}
	return daemonOptions{
		statePath:     *statePath,
		consensusDir:  *consensusDir,
		endpoint:      endpoint,
		sessionID:     sessionID,
		workspaceID:   workspaceID,
		peerListeners: peerListeners,
		peerRoutes:    peerRoutes,
	}, nil
}

func cleanAbsolutePath(path string) bool {
	return path != "" &&
		filepath.IsAbs(path) &&
		filepath.Clean(path) == path
}

func productionDaemonDependencies() daemonDependencies {
	return daemonDependencies{
		loadIdentity: func(
			ctx context.Context,
		) (identityHandle, []byte, error) {
			return credentialstore.OpenRequired(
				ctx,
				credentialstore.IdentityReference(),
			)
		},
		newBootID: func() (domain.UUIDv7, error) {
			value, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			result := domain.UUIDv7(value.String())
			if !result.Valid() {
				return "", domain.ErrInvalidUUIDv7
			}
			return result, nil
		},
		newMeshFactory: newDaemonMeshTransportFactory,
		listenPeer:     listenDaemonPeer,
		openMulticast:  openDaemonMulticast,
		listInterfaces: net.Interfaces,
		credentialNow:  time.Now,
		interfaceAddrs: func(
			iface *net.Interface,
		) ([]net.Addr, error) {
			return iface.Addrs()
		},
	}
}

func runDaemon(
	ctx context.Context,
	options daemonOptions,
	dependencies daemonDependencies,
) (resultErr error) {
	if ctx == nil ||
		dependencies.loadIdentity == nil ||
		dependencies.newBootID == nil ||
		dependencies.newMeshFactory == nil ||
		len(options.peerListeners) != 0 &&
			dependencies.listenPeer == nil ||
		incompleteDaemonDiscoveryDependencies(dependencies) {
		return errInvalidDaemonDependencies
	}
	if !cleanAbsolutePath(options.statePath) ||
		!cleanAbsolutePath(options.consensusDir) ||
		!options.sessionID.Valid() ||
		!options.workspaceID.Valid() {
		return errInvalidDaemonOptions
	}
	if err := validateDaemonMeshOptions(options); err != nil {
		return err
	}
	if _, err := ipc.ParseEndpoint(options.endpoint.String()); err != nil {
		return fmt.Errorf("%w: endpoint: %v", errInvalidDaemonOptions, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	credentialNow := dependencies.credentialNow
	if credentialNow == nil {
		credentialNow = time.Now
	}

	credentialHandle, identityPrivateKey, err :=
		dependencies.loadIdentity(ctx)
	if err != nil {
		return err
	}
	if credentialHandle == nil {
		clear(identityPrivateKey)
		return errInvalidDaemonDependencies
	}
	defer func() {
		clear(identityPrivateKey)
		resultErr = errors.Join(resultErr, credentialHandle.Close())
	}()

	identityPublicKey, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(identityPrivateKey)
	if err != nil {
		return fmt.Errorf("codecommd: load identity key: %w", err)
	}
	deviceID, err := device.DeriveID(identityPublicKey)
	if err != nil {
		return fmt.Errorf("codecommd: derive device identity: %w", err)
	}
	meshPreflight, err := inspectDaemonMeshState(
		ctx,
		options,
		deviceID,
		identityPublicKey,
	)
	if err != nil {
		return err
	}
	identityCertificate, identityBinding, err :=
		transport.IssueIdentityCertificate(
			options.sessionID,
			meshPreflight.recoveryGeneration,
			identityPrivateKey,
		)
	if err != nil {
		return fmt.Errorf(
			"%w: issue identity certificate: %v",
			errDaemonMeshConstruction,
			err,
		)
	}
	defer clearDaemonTLSCertificate(&identityCertificate)
	if identityBinding.DeviceID != deviceID {
		return errDaemonIdentityMismatch
	}
	meshFactory, err := dependencies.newMeshFactory(
		options,
		deviceID,
		identityCertificate,
		credentialNow,
	)
	if err != nil {
		return err
	}
	if nilDaemonMeshFactory(meshFactory) {
		return errInvalidDaemonDependencies
	}
	defer meshFactory.ClearIdentityCertificate()
	originBootID, err := dependencies.newBootID()
	if err != nil {
		return fmt.Errorf("codecommd: generate origin boot ID: %w", err)
	}
	if !originBootID.Valid() {
		return fmt.Errorf(
			"%w: generated origin boot ID is invalid",
			errInvalidDaemonDependencies,
		)
	}
	if meshPreflight.evidenceMode ==
		store.ReplicaEvidenceSettledNonvoter {
		credentials, ok := credentialHandle.(daemonCredentialHandle)
		if !ok {
			return errInvalidDaemonDependencies
		}
		return runSettledDaemon(
			ctx,
			options,
			dependencies,
			deviceID,
			identityPrivateKey,
			originBootID,
			meshPreflight,
			meshFactory,
			credentials,
			credentialNow,
		)
	}
	if meshPreflight.evidenceMode != store.ReplicaEvidenceRaft {
		return fmt.Errorf(
			"%w: unknown evidence mode %q",
			errDaemonMeshConstruction,
			meshPreflight.evidenceMode,
		)
	}
	authority, err := event.NewLocalAuthority(deviceID, originBootID)
	if err != nil {
		return fmt.Errorf("codecommd: create local authority: %w", err)
	}
	daemonBinding, err := authority.DaemonBinding()
	if err != nil {
		return fmt.Errorf("codecommd: create daemon binding: %w", err)
	}
	operatorBinding, err := authority.OperatorBinding()
	if err != nil {
		return fmt.Errorf("codecommd: create operator binding: %w", err)
	}
	checkpointSigner := consensus.CheckpointSignerAdapter{
		SignerDeviceID: deviceID,
		Sign: func(
			signContext context.Context,
			checkpoint domain.Checkpoint,
		) (store.Signature, error) {
			if err := signContext.Err(); err != nil {
				return store.Signature{}, err
			}
			signature, err := event.SignCheckpoint(
				checkpoint,
				identityPrivateKey,
			)
			return store.Signature(signature), err
		},
	}

	processClock := consensus.NewSystemApplyClock()
	var bootOrigin *agent.BootOrigin
	proposalForwarder := &daemonProposalForwarderRelay{}
	node, err := consensus.OpenNode(
		ctx,
		consensus.NodeOptions{
			ServerID:         deviceID,
			StatePath:        options.statePath,
			ConsensusDir:     options.consensusDir,
			OriginBootID:     originBootID,
			TransportFactory: meshFactory.Build,
			BootstrapVoterDeviceIDs: append(
				[]domain.DeviceID(nil),
				meshPreflight.bootstrapVoterIDs...,
			),
			CheckpointSigner: checkpointSigner,
			VoterActivationSigner: newDaemonVoterActivationSigner(
				deviceID,
				identityPrivateKey,
			),
			CredentialEndorsementSigner: newDaemonCredentialEndorsementSigner(
				deviceID,
				identityPrivateKey,
			),
			CheckpointOriginFactory: func(
				localState store.LocalState,
				submitter consensus.CheckpointCommandSubmitter,
			) (consensus.CheckpointOrigin, error) {
				created, err := agent.NewBootOrigin(
					agent.BootOriginOptions{
						Consensus:          submitter,
						LocalState:         localState,
						SessionID:          options.sessionID,
						WorkspaceID:        options.workspaceID,
						DeviceID:           deviceID,
						OriginBootID:       originBootID,
						IdentityPrivateKey: identityPrivateKey,
						DaemonOrigin:       daemonBinding,
						OperatorOrigin:     operatorBinding,
					},
				)
				if err == nil {
					bootOrigin = created
				}
				return created, err
			},
			ProposalForwarder: proposalForwarder,
			CanonicalCoverage: dependencies.canonicalCoverage,
			Clock:             processClock,
			CredentialNow:     credentialNow,
		},
	)
	if err != nil {
		return err
	}
	if bootOrigin == nil {
		_ = node.Close()
		return errInvalidDaemonDependencies
	}
	var (
		agentService       *agent.Service
		credentialService  *credentialservice.Service
		pairingService     *pairingservice.Service
		peerIngress        *transport.Ingress
		discoveryRuntime   *daemonDiscoveryRuntime
		contentPeerRuntime *daemonContentPeerRuntime
	)
	runtimeClosed := false
	defer func() {
		if runtimeClosed {
			return
		}
		components := make([]phasedDaemonComponent, 0, 6)
		if agentService != nil {
			components = append(components, agentService)
		}
		if contentPeerRuntime != nil {
			components = append(components, contentPeerRuntime)
		}
		if discoveryRuntime != nil {
			components = append(components, discoveryRuntime)
		}
		if pairingService != nil {
			components = append(components, pairingService)
		}
		if credentialService != nil {
			components = append(components, credentialService)
		}
		components = append(components, bootOrigin)
		resultErr = errors.Join(
			resultErr,
			shutdownDaemonRuntime(
				node,
				peerIngress,
				nil,
				components...,
			),
		)
	}()
	view, err := node.View(ctx)
	if err != nil {
		return fmt.Errorf("codecommd: read initialized state: %w", err)
	}
	if view.SessionID != options.sessionID ||
		view.WorkspaceID != options.workspaceID ||
		view.RecoveryGeneration != meshPreflight.recoveryGeneration {
		return fmt.Errorf(
			"%w: got session %s, workspace %s, and generation %d",
			errDaemonLineageMismatch,
			view.SessionID,
			view.WorkspaceID,
			view.RecoveryGeneration,
		)
	}

	localState, err := node.LocalState()
	if err != nil {
		return err
	}
	agentService, err = agent.New(agent.Options{
		Consensus:          node,
		LocalState:         localState,
		SessionID:          options.sessionID,
		WorkspaceID:        options.workspaceID,
		DeviceID:           deviceID,
		OriginBootID:       originBootID,
		IdentityPrivateKey: identityPrivateKey,
		LifecycleOrigin:    daemonBinding,
		BootOrigin:         bootOrigin,
	})
	if err != nil {
		return err
	}
	if err := agentService.Recover(ctx); err != nil {
		return fmt.Errorf("codecommd: recover local agent state: %w", err)
	}
	credentials, ok := credentialHandle.(daemonCredentialHandle)
	if !ok {
		return errInvalidDaemonDependencies
	}
	credentialService, err = newDaemonCredentialService(
		ctx,
		options.sessionID,
		deviceID,
		ed25519.PrivateKey(identityPrivateKey),
		credentials,
		node,
		credentialNow,
	)
	if err != nil {
		return err
	}
	if err := meshFactory.SetAuthenticatedConnectivity(
		newDaemonAuthenticatedEndpointObserver(
			localState,
			time.Now,
			credentialService,
		),
		credentialService,
	); err != nil {
		return err
	}
	pairingRuntime, err := newDaemonPairingRuntime(
		ctx,
		options,
		deviceID,
		ed25519.PrivateKey(identityPrivateKey),
		ed25519.PublicKey(identityPublicKey),
		credentials,
		view,
		localState,
		node,
		bootOrigin,
		operatorBinding,
		originBootID,
	)
	if err != nil {
		return err
	}
	pairingService = pairingRuntime.service
	discoveryRuntime, err = newDaemonDiscoveryRuntime(
		ctx,
		options,
		deviceID,
		view,
		identityPrivateKey,
		localState,
		node,
		credentialService,
		meshFactory,
		dependencies,
	)
	if err != nil {
		return err
	}
	var contentHandler transport.ConnectionHandler
	if discoveryRuntime != nil {
		contentHandler, err = newDaemonContentServer(
			options.sessionID,
			options.workspaceID,
			view.RecoveryGeneration,
			deviceID,
			localState,
			discoveryRuntime,
			node,
			identityPrivateKey,
		)
		if err != nil {
			return err
		}
		contentPeerRuntime, err = newDaemonContentPeerRuntime(
			ctx,
			options.sessionID,
			options.workspaceID,
			view.RecoveryGeneration,
			deviceID,
			localState,
			node,
			credentialService.ContentCertificate,
			meshFactory.ConsensusRoutes(),
			credentialNow,
		)
		if err != nil {
			return err
		}
		if err := proposalForwarder.set(contentPeerRuntime); err != nil {
			return err
		}
	}
	peerIngress, err = meshFactory.NewIngress(
		ctx,
		options,
		node,
		credentialService.ContentCertificate,
		pairingRuntime.server,
		contentHandler,
		dependencies.listenPeer,
	)
	if err != nil {
		return err
	}
	meshFactory.ClearIdentityCertificate()

	operatorService, err := ui.NewOperatorService(ui.OperatorServiceOptions{
		Source:      node,
		Submitter:   bootOrigin,
		Pairing:     pairingRuntime.operator,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
	})
	if err != nil {
		return err
	}
	router, err := ipc.NewClassRouter(operatorService, agentService)
	if err != nil {
		return err
	}
	localServer, err := ipc.NewServer(ipc.Config{
		Endpoint:    options.endpoint,
		SessionID:   options.sessionID,
		WorkspaceID: options.workspaceID,
		Binder:      router,
	})
	if err != nil {
		return err
	}
	serveErr := serveUntilStopped(
		ctx,
		localServer,
		node,
		agentService,
		bootOrigin,
		credentialService,
		pairingService,
		peerIngress,
		discoveryRuntime,
		contentPeerRuntime,
	)
	runtimeClosed = true
	return serveErr
}

func serveUntilStopped(
	ctx context.Context,
	server *ipc.Server,
	node *consensus.SingleNode,
	agentService *agent.Service,
	bootOrigin *agent.BootOrigin,
	credentialService *credentialservice.Service,
	pairingService *pairingservice.Service,
	peerIngress *transport.Ingress,
	discoveryRuntime *daemonDiscoveryRuntime,
	contentPeerRuntime *daemonContentPeerRuntime,
) error {
	components := []phasedDaemonComponent{agentService}
	fatalComponents := []daemonFatalComponent{
		node,
		agentService,
		credentialService,
		pairingService,
	}
	if contentPeerRuntime != nil {
		components = append(components, contentPeerRuntime)
		fatalComponents = append(fatalComponents, contentPeerRuntime)
	}
	if discoveryRuntime != nil {
		components = append(components, discoveryRuntime)
		fatalComponents = append(fatalComponents, discoveryRuntime)
	}
	components = append(
		components,
		pairingService,
		credentialService,
		bootOrigin,
	)
	return serveDaemonRuntime(
		ctx,
		server,
		node,
		peerIngress,
		components,
		fatalComponents,
	)
}

type daemonFatalComponent interface {
	FatalError() error
}

func serveDaemonRuntime(
	ctx context.Context,
	server *ipc.Server,
	consensusRuntime daemonConsensusCloser,
	peerIngress *transport.Ingress,
	components []phasedDaemonComponent,
	fatalComponents []daemonFatalComponent,
) error {
	if ctx == nil || server == nil || consensusRuntime == nil {
		return errInvalidDaemonDependencies
	}
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	serverResults := make(chan daemonServerResult, 2)
	serverCount := 1
	go func() {
		serverResults <- daemonServerResult{
			name: "local IPC",
			err:  server.Serve(serveContext),
		}
	}()
	if peerIngress != nil {
		serverCount++
		go func() {
			serverResults <- daemonServerResult{
				name: "peer ingress",
				err:  peerIngress.Serve(serveContext),
			}
		}()
	}

	ticker := time.NewTicker(fatalPollInterval)
	defer ticker.Stop()
	stop := func(cause error, completed int) error {
		cancel()
		joinServers := func() error {
			return joinDaemonServers(
				serverResults,
				completed,
				serverCount,
				daemonPeerShutdownTimeout,
			)
		}
		return errors.Join(
			cause,
			shutdownDaemonRuntime(
				consensusRuntime,
				peerIngress,
				joinServers,
				components...,
			),
		)
	}
	for {
		select {
		case result := <-serverResults:
			return stop(daemonServerExitError(result, ctx.Err()), 1)
		case <-ctx.Done():
			return stop(nil, 0)
		case <-ticker.C:
			for _, component := range fatalComponents {
				if component == nil {
					return stop(errInvalidDaemonDependencies, 0)
				}
				if fatal := component.FatalError(); fatal != nil {
					return stop(fatal, 0)
				}
			}
		}
	}
}

func shutdownDaemonRuntime(
	consensus daemonConsensusCloser,
	peerIngress *transport.Ingress,
	joinServers func() error,
	components ...phasedDaemonComponent,
) error {
	var shutdownErrors []error
	if peerIngress != nil {
		_ = peerIngress.BeginShutdown()
	}
	for _, component := range components {
		if component == nil {
			shutdownErrors = append(
				shutdownErrors,
				errInvalidDaemonDependencies,
			)
			continue
		}
		shutdownErrors = append(
			shutdownErrors,
			component.BeginClose(),
		)
	}
	if consensus == nil {
		shutdownErrors = append(
			shutdownErrors,
			errInvalidDaemonDependencies,
		)
	} else {
		shutdownErrors = append(shutdownErrors, consensus.Close())
	}
	if peerIngress != nil {
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			daemonPeerShutdownTimeout,
		)
		shutdownErrors = append(
			shutdownErrors,
			peerIngress.Shutdown(shutdownContext),
		)
		cancel()
	}
	if joinServers != nil {
		shutdownErrors = append(shutdownErrors, joinServers())
	}
	for _, component := range components {
		if component != nil {
			shutdownErrors = append(
				shutdownErrors,
				component.Wait(),
			)
		}
	}
	return errors.Join(shutdownErrors...)
}

func shutdownDaemonComponents(
	consensus daemonConsensusCloser,
	joinServer func() error,
	components ...phasedDaemonComponent,
) error {
	return shutdownDaemonRuntime(
		consensus,
		nil,
		joinServer,
		components...,
	)
}

func nilDaemonMeshFactory(factory daemonConsensusTransportFactory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func daemonServerExitError(
	result daemonServerResult,
	parentErr error,
) error {
	if parentErr != nil {
		return nil
	}
	if result.err == nil {
		return fmt.Errorf(
			"%w: %s",
			errDaemonServerStopped,
			result.name,
		)
	}
	return fmt.Errorf("codecommd: %s: %w", result.name, result.err)
}

func joinDaemonServers(
	results <-chan daemonServerResult,
	completed int,
	total int,
	timeout time.Duration,
) error {
	if results == nil || completed < 0 || total < completed || timeout <= 0 {
		return errInvalidDaemonDependencies
	}
	errs := make([]error, 0, total-completed)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for completed < total {
		select {
		case result, open := <-results:
			if !open {
				errs = append(errs, errDaemonServerShutdown)
				return errors.Join(errs...)
			}
			completed++
			if result.err == nil ||
				errors.Is(result.err, context.Canceled) ||
				errors.Is(result.err, net.ErrClosed) {
				continue
			}
			errs = append(
				errs,
				fmt.Errorf(
					"codecommd: %s: %w",
					result.name,
					result.err,
				),
			)
		case <-timer.C:
			errs = append(errs, errDaemonServerShutdown)
			return errors.Join(errs...)
		}
	}
	return errors.Join(errs...)
}
