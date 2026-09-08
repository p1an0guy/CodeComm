package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/ijonahch/codecomm/internal/agent"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credentialservice"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
	"github.com/ijonahch/codecomm/internal/ui"
)

func runSettledDaemon(
	ctx context.Context,
	options daemonOptions,
	dependencies daemonDependencies,
	deviceID domain.DeviceID,
	identityPrivateKey []byte,
	originBootID domain.UUIDv7,
	preflight daemonMeshPreflight,
	meshFactory daemonConsensusTransportFactory,
	credentials daemonCredentialHandle,
	credentialNow func() time.Time,
	peerListeners *daemonPeerListenerSet,
) (resultErr error) {
	if ctx == nil ||
		!deviceID.Valid() ||
		len(identityPrivateKey) != ed25519.PrivateKeySize ||
		!originBootID.Valid() ||
		preflight.evidenceMode != store.ReplicaEvidenceSettledNonvoter ||
		len(preflight.bootstrapVoterIDs) != 0 ||
		meshFactory == nil ||
		credentials == nil ||
		credentialNow == nil {
		return errInvalidDaemonDependencies
	}
	processClock := consensus.NewSystemApplyClock()
	replica, err := consensus.OpenSettledReplica(
		ctx,
		consensus.SettledReplicaOptions{
			StatePath:     options.statePath,
			OriginBootID:  originBootID,
			LocalDeviceID: deviceID,
			Clock:         processClock,
		},
	)
	if err != nil {
		return err
	}
	var (
		agentService        *agent.Service
		bootOrigin          *agent.BootOrigin
		commandConsensus    *daemonSettledCommandConsensus
		credentialConsensus *daemonSettledCredentialConsensus
		credentialService   *credentialservice.Service
		discoveryRuntime    *daemonDiscoveryRuntime
		contentPeerRuntime  *daemonContentPeerRuntime
		peerIngress         *transport.Ingress
		snapshotRepository  *daemonLogicalSnapshotRepository
		versionReport       *daemonVersionReportGate
	)
	runtimeClosed := false
	defer func() {
		if runtimeClosed {
			return
		}
		components := settledDaemonComponents(
			agentService,
			versionReport,
			bootOrigin,
			credentialConsensus,
			credentialService,
			discoveryRuntime,
			contentPeerRuntime,
			snapshotRepository,
		)
		resultErr = errors.Join(
			resultErr,
			shutdownDaemonRuntime(
				replica,
				peerIngress,
				nil,
				components...,
			),
		)
	}()

	view, err := replica.View(ctx)
	if err != nil {
		return err
	}
	if view.SessionID != options.sessionID ||
		view.WorkspaceID != options.workspaceID ||
		view.RecoveryGeneration != preflight.recoveryGeneration {
		return fmt.Errorf(
			"%w: got session %s, workspace %s, and generation %d",
			errDaemonLineageMismatch,
			view.SessionID,
			view.WorkspaceID,
			view.RecoveryGeneration,
		)
	}
	localState, err := replica.LocalState()
	if err != nil {
		return err
	}
	rebootstrapMarker, err := inspectDaemonRebootstrapInstall(
		ctx,
		localState,
		options.sessionID,
		options.workspaceID,
		view.RecoveryGeneration,
		deviceID,
	)
	if err != nil {
		return err
	}
	authority, err := event.NewLocalAuthority(deviceID, originBootID)
	if err != nil {
		return fmt.Errorf("codecommd: create settled local authority: %w", err)
	}
	daemonBinding, err := authority.DaemonBinding()
	if err != nil {
		return fmt.Errorf("codecommd: create settled daemon binding: %w", err)
	}
	operatorBinding, err := authority.OperatorBinding()
	if err != nil {
		return fmt.Errorf(
			"codecommd: create settled operator binding: %w",
			err,
		)
	}
	commandConsensus, err = newDaemonSettledCommandConsensus(
		options.sessionID,
		options.workspaceID,
		view.RecoveryGeneration,
		deviceID,
		replica,
		processClock,
	)
	if err != nil {
		return err
	}
	bootOrigin, err = agent.NewBootOrigin(agent.BootOriginOptions{
		Consensus:          commandConsensus,
		LocalState:         localState,
		SessionID:          options.sessionID,
		WorkspaceID:        options.workspaceID,
		DeviceID:           deviceID,
		OriginBootID:       originBootID,
		IdentityPrivateKey: ed25519.PrivateKey(identityPrivateKey),
		DaemonOrigin:       daemonBinding,
		OperatorOrigin:     operatorBinding,
	})
	if err != nil {
		return err
	}
	agentService, err = agent.New(agent.Options{
		Consensus:          commandConsensus,
		LocalState:         localState,
		SessionID:          options.sessionID,
		WorkspaceID:        options.workspaceID,
		DeviceID:           deviceID,
		OriginBootID:       originBootID,
		IdentityPrivateKey: ed25519.PrivateKey(identityPrivateKey),
		LifecycleOrigin:    daemonBinding,
		BootOrigin:         bootOrigin,
	})
	if err != nil {
		return err
	}
	var synchronizeMembership func(context.Context) error
	if rebootstrapMarker != nil {
		synchronizeMembership = func(
			recoveryContext context.Context,
		) error {
			return (daemonRebootstrapCurrencyBarrier{
				replica: replica,
				peers:   contentPeerRuntime,
			}).WaitCurrent(recoveryContext)
		}
	}
	versionReport, err = newDaemonVersionReportGate(
		ctx,
		daemonVersionReportOptions{
			State:       localState,
			Origin:      bootOrigin,
			Agent:       agentService,
			Synchronize: synchronizeMembership,
			RecoverAgents: func(recoveryContext context.Context) error {
				return recoverSettledAgentState(
					recoveryContext,
					localState,
					rebootstrapMarker,
					daemonRebootstrapCurrencyBarrier{
						replica: replica,
						peers:   contentPeerRuntime,
					},
					agentService,
				)
			},
			DeviceID:      deviceID,
			DaemonVersion: dependencies.daemonVersion,
			MaxApplyLevel: dependencies.maxApplyLevel,
		},
	)
	if err != nil {
		return err
	}
	controlTransport, err := meshFactory.BuildSettledControl(replica)
	if err != nil {
		return err
	}
	credentialConsensus, err = newDaemonSettledCredentialConsensus(
		options.sessionID,
		deviceID,
		replica,
		controlTransport,
	)
	if err != nil {
		_ = controlTransport.BeginClose()
		_ = controlTransport.Wait()
		return err
	}
	credentialService, err = newDaemonCredentialService(
		ctx,
		options.sessionID,
		deviceID,
		ed25519.PrivateKey(identityPrivateKey),
		credentials,
		credentialConsensus,
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
	discoveryRuntime, err = newDaemonDiscoveryRuntime(
		ctx,
		options,
		deviceID,
		view,
		identityPrivateKey,
		localState,
		replica,
		credentialService,
		meshFactory,
		dependencies,
		peerListeners,
	)
	if err != nil {
		return err
	}

	var manualEndpoints ui.ManualEndpointOperator
	if discoveryRuntime != nil {
		manualEndpoints, err = newDaemonManualEndpointOperator(
			deviceID,
			localState,
			discoveryRuntime,
			time.Now,
		)
		if err != nil {
			return err
		}
	}
	var contentHandler transport.ConnectionHandler
	if discoveryRuntime != nil {
		snapshotRepository, err = openDaemonLogicalSnapshotRepository(
			ctx,
			options.statePath,
			options.sessionID,
			options.workspaceID,
			view.RecoveryGeneration,
			deviceID,
			ed25519.PrivateKey(identityPrivateKey).
				Public().(ed25519.PublicKey),
		)
		if err != nil {
			return err
		}
		contentHandler, err = newDaemonContentServer(
			options.sessionID,
			options.workspaceID,
			view.RecoveryGeneration,
			deviceID,
			localState,
			discoveryRuntime,
			commandConsensus,
			identityPrivateKey,
			snapshotRepository,
		)
		if err != nil {
			return err
		}
		contentPeerRuntime, err = newDaemonSettledContentPeerRuntime(
			ctx,
			options.sessionID,
			options.workspaceID,
			view.RecoveryGeneration,
			deviceID,
			options.statePath,
			originBootID,
			localState,
			replica,
			credentialService.ContentCertificate,
			meshFactory.ConsensusRoutes(),
			credentialNow,
			replica,
			controlTransport,
			processClock,
		)
		if err != nil {
			return err
		}
		if dependencies.observeContentPeers != nil {
			dependencies.observeContentPeers(contentPeerRuntime)
		}
		if err := commandConsensus.setPeer(contentPeerRuntime); err != nil {
			return err
		}
	}
	peerIngress, err = meshFactory.NewIngress(
		ctx,
		options,
		replica,
		credentialService.ContentCertificate,
		nil,
		contentHandler,
		daemonPeerListenerOrNil(peerListeners),
	)
	if err != nil {
		return err
	}
	if discoveryRuntime != nil {
		if err := discoveryRuntime.attachIngress(peerIngress); err != nil {
			return err
		}
	}
	meshFactory.ClearIdentityCertificate()
	if err := versionReport.Start(); err != nil {
		return err
	}
	if rebootstrapMarker != nil || !versionReport.requiresReport() {
		if err := versionReport.WaitReady(ctx); err != nil {
			return err
		}
	}

	operatorStatusSource, err := newDaemonOperatorStatusSource(
		replica,
		localState,
		discoveryRuntime,
	)
	if err != nil {
		return err
	}
	var operatorService *ui.OperatorService
	if manualEndpoints == nil {
		operatorService, err = ui.NewMutationOperatorService(
			operatorStatusSource,
			bootOrigin,
			options.sessionID,
			options.workspaceID,
		)
	} else {
		operatorService, err = ui.NewMutationOperatorServiceWithEndpoints(
			operatorStatusSource,
			bootOrigin,
			manualEndpoints,
			options.sessionID,
			options.workspaceID,
		)
	}
	if err != nil {
		return err
	}
	router, err := ipc.NewClassRouter(operatorService, versionReport)
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
	components := settledDaemonComponents(
		agentService,
		versionReport,
		bootOrigin,
		credentialConsensus,
		credentialService,
		discoveryRuntime,
		contentPeerRuntime,
		snapshotRepository,
	)
	fatalComponents := []daemonFatalComponent{
		replica,
		versionReport,
		agentService,
		bootOrigin,
		credentialService,
	}
	if discoveryRuntime != nil {
		fatalComponents = append(fatalComponents, discoveryRuntime)
	}
	if contentPeerRuntime != nil {
		fatalComponents = append(fatalComponents, contentPeerRuntime)
	}
	resultErr = serveDaemonRuntime(
		ctx,
		localServer,
		replica,
		peerIngress,
		components,
		fatalComponents,
	)
	runtimeClosed = true
	return resultErr
}

func settledDaemonComponents(
	agents *agent.Service,
	versionReport *daemonVersionReportGate,
	boot *agent.BootOrigin,
	control *daemonSettledCredentialConsensus,
	credentials *credentialservice.Service,
	discovery *daemonDiscoveryRuntime,
	content *daemonContentPeerRuntime,
	snapshots *daemonLogicalSnapshotRepository,
) []phasedDaemonComponent {
	components := make([]phasedDaemonComponent, 0, 8)
	if versionReport != nil {
		components = append(components, versionReport)
	}
	if agents != nil {
		components = append(components, agents)
	}
	if content != nil {
		components = append(components, content)
	}
	if snapshots != nil {
		components = append(components, snapshots)
	}
	if discovery != nil {
		components = append(components, discovery)
	}
	if credentials != nil {
		components = append(components, credentials)
	}
	if control != nil {
		components = append(components, control)
	}
	if boot != nil {
		components = append(components, boot)
	}
	return components
}
