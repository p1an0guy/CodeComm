package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/replication"
	coordstatus "github.com/ijonahch/codecomm/internal/status"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	daemonContentPeerRefreshInterval    = 2 * time.Second
	daemonContentPeerDialTimeout        = 10 * time.Second
	daemonContentPeerRequestTimeout     = 30 * time.Second
	daemonContentPeerReplicationTimeout = 30 * time.Minute
	daemonContentPeerBootstrapTimeout   = 3 * time.Second
	daemonContentPeerRetryInitial       = 250 * time.Millisecond
	daemonContentPeerRetryMaximum       = 30 * time.Second
	daemonContentPeerDiagnosticMaxBytes = 1024
)

var errDaemonContentPeerConstruction = errors.New(
	"codecommd: content peer runtime construction failed",
)

var errDaemonContentPeerState = errors.New(
	"codecommd: content peer local state failure",
)

type daemonContentPeerState interface {
	StatusSnapshot(
		context.Context,
		domain.DeviceID,
		int,
	) (coordstatus.DurableSnapshot, error)
	ReplaceMemberSignedEndpointSet(
		context.Context,
		[]byte,
		domain.Timestamp,
	) (store.MemberEndpointSetUpdate, error)
	UpsertAuthenticatedEndpoint(
		context.Context,
		domain.DeviceID,
		netip.AddrPort,
		domain.Timestamp,
	) error
}

type daemonContentPeerAdmission interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
}

type daemonContentPeerRoutes interface {
	transport.ConsensusEndpointResolver
	transport.ConsensusEndpointDialer
}

type daemonContentPeerReplication interface {
	Sync(
		context.Context,
		domain.DeviceID,
		daemonReplicationClient,
	) error
	ForgetPeer(domain.DeviceID)
}

type daemonSettledReplicationFencer interface {
	withFence(context.Context, func(context.Context) error) error
}

type daemonContentPeerRuntime struct {
	sessionID     domain.UUIDv7
	workspaceID   domain.UUIDv4
	generation    uint64
	localDeviceID domain.DeviceID
	state         daemonContentPeerState
	admission     daemonContentPeerAdmission
	certificate   transport.ContentCertificateProvider
	routes        daemonContentPeerRoutes
	verifiers     *peerauth.Verifiers
	now           func() time.Time
	credentialNow func() time.Time
	jitter        func(time.Duration) time.Duration
	replication   daemonContentPeerReplication
	status        consensus.ConsensusStatusRequester

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	workersMu sync.Mutex
	workers   map[domain.DeviceID]*daemonContentPeerWorker

	fatalMu  sync.RWMutex
	fatalErr error
	closing  bool
	close    sync.Once
}

type daemonContentPeerWorker struct {
	deviceID domain.DeviceID
	cancel   context.CancelFunc
	done     chan struct{}

	diagnosticMu  sync.RWMutex
	lastTransient daemonContentPeerTransientErrorSnapshot

	connectionMu sync.RWMutex
	connection   *daemonContentPeerConnection
}

type daemonContentPeerTransientErrorSnapshot struct {
	PeerID    domain.DeviceID
	Operation string
	Message   string
}

type daemonContentPeerConnection struct {
	mu sync.RWMutex

	client           *contenthttp.Client
	tlsConfig        *tls.Config
	openSnapshotBulk func(
		context.Context,
		logicalsnapshot.Root,
	) (daemonSnapshotBulkClient, error)
	localEpoch  uint64
	remoteEpoch uint64
}

type daemonSnapshotBulkConnection struct {
	mu        sync.Mutex
	client    *contenthttp.SnapshotBulkClient
	tlsConfig *tls.Config
}

func newDaemonContentPeerRuntime(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
	localDeviceID domain.DeviceID,
	state daemonContentPeerState,
	admission daemonContentPeerAdmission,
	certificate transport.ContentCertificateProvider,
	routes daemonContentPeerRoutes,
	now func() time.Time,
) (*daemonContentPeerRuntime, error) {
	return newDaemonContentPeerRuntimeWithReplication(
		ctx,
		sessionID,
		workspaceID,
		generation,
		localDeviceID,
		state,
		admission,
		certificate,
		routes,
		now,
		nil,
		nil,
		nil,
	)
}

func newDaemonSettledContentPeerRuntime(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
	localDeviceID domain.DeviceID,
	statePath string,
	originBootID domain.UUIDv7,
	state daemonContentPeerState,
	admission daemonContentPeerAdmission,
	certificate transport.ContentCertificateProvider,
	routes daemonContentPeerRoutes,
	now func() time.Time,
	replica daemonSettledReplica,
	control daemonSettledControlTransport,
	clock consensus.ApplyClock,
) (*daemonContentPeerRuntime, error) {
	if !cleanAbsolutePath(statePath) ||
		!originBootID.Valid() ||
		control == nil ||
		control.contentVerifiers() == nil ||
		clock == nil {
		return nil, errDaemonContentPeerConstruction
	}
	replicationRuntime, err := newDaemonSettledReplication(
		ctx,
		daemonSettledReplicationOptions{
			Replica:      replica,
			ScratchRoot:  daemonSettledSnapshotScratchRoot(statePath),
			OriginBootID: originBootID,
			Clock:        clock,
		},
	)
	if err != nil {
		return nil, err
	}
	return newDaemonContentPeerRuntimeWithReplication(
		ctx,
		sessionID,
		workspaceID,
		generation,
		localDeviceID,
		state,
		admission,
		certificate,
		routes,
		now,
		replicationRuntime,
		control.contentVerifiers(),
		control,
	)
}

func newDaemonContentPeerRuntimeWithReplication(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	generation uint64,
	localDeviceID domain.DeviceID,
	state daemonContentPeerState,
	admission daemonContentPeerAdmission,
	certificate transport.ContentCertificateProvider,
	routes daemonContentPeerRoutes,
	now func() time.Time,
	replicationRuntime daemonContentPeerReplication,
	contentVerifiers *peerauth.Verifiers,
	statusRequester consensus.ConsensusStatusRequester,
) (*daemonContentPeerRuntime, error) {
	if ctx == nil ||
		!sessionID.Valid() ||
		!workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(generation) ||
		!localDeviceID.Valid() ||
		state == nil ||
		admission == nil ||
		certificate == nil ||
		routes == nil ||
		now == nil {
		return nil, errDaemonContentPeerConstruction
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if (contentVerifiers == nil) != (statusRequester == nil) {
		return nil, errDaemonContentPeerConstruction
	}
	verifiers := contentVerifiers
	if verifiers == nil {
		var err error
		verifiers, err = peerauth.NewVerifiers(
			admission.PeerAdmissionSnapshot,
			now,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: peer verifiers: %v",
				errDaemonContentPeerConstruction,
				err,
			)
		}
	}
	runtimeContext, cancel := context.WithCancel(context.Background())
	runtime := &daemonContentPeerRuntime{
		sessionID:     sessionID,
		workspaceID:   workspaceID,
		generation:    generation,
		localDeviceID: localDeviceID,
		state:         state,
		admission:     admission,
		certificate:   certificate,
		routes:        routes,
		verifiers:     verifiers,
		now:           time.Now,
		credentialNow: now,
		jitter:        daemonContentPeerRetryDelay,
		replication:   replicationRuntime,
		status:        statusRequester,
		ctx:           runtimeContext,
		cancel:        cancel,
		done:          make(chan struct{}),
		workers:       make(map[domain.DeviceID]*daemonContentPeerWorker),
	}
	if err := runtime.reconcileWorkers(ctx); err != nil {
		cancel()
		return nil, err
	}
	go runtime.run()
	return runtime, nil
}

func (runtime *daemonContentPeerRuntime) withSettledReplicationFence(
	ctx context.Context,
	operation func(context.Context) error,
) error {
	if runtime == nil || ctx == nil || operation == nil {
		return errDaemonContentPeerConstruction
	}
	fencer, ok := runtime.replication.(daemonSettledReplicationFencer)
	if !ok || fencer == nil {
		return errDaemonContentPeerConstruction
	}
	return fencer.withFence(ctx, operation)
}

func (runtime *daemonContentPeerRuntime) run() {
	defer close(runtime.done)
	defer runtime.stopWorkers()
	ticker := time.NewTicker(daemonContentPeerRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-runtime.ctx.Done():
			return
		case <-ticker.C:
			if err := runtime.reconcileWorkers(runtime.ctx); err != nil {
				runtime.fail(err)
				return
			}
		}
	}
}

func (runtime *daemonContentPeerRuntime) reconcileWorkers(
	ctx context.Context,
) error {
	if runtime == nil || runtime.state == nil || ctx == nil {
		return errDaemonContentPeerConstruction
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := runtime.state.StatusSnapshot(
		ctx,
		runtime.localDeviceID,
		1,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: read applied membership: %v",
			errDaemonContentPeerConstruction,
			err,
		)
	}
	if snapshot.SessionID != runtime.sessionID ||
		snapshot.WorkspaceID != runtime.workspaceID ||
		snapshot.RecoveryGeneration != runtime.generation ||
		snapshot.Member.ID != runtime.localDeviceID ||
		snapshot.Member.Status != device.StatusActive ||
		snapshot.MembersTruncated ||
		snapshot.MemberTotal != uint64(len(snapshot.Members)) {
		return fmt.Errorf(
			"%w: inconsistent applied membership",
			errDaemonContentPeerConstruction,
		)
	}
	desired := make(map[domain.DeviceID]struct{}, len(snapshot.Members)-1)
	for _, member := range snapshot.Members {
		if member.ID == runtime.localDeviceID ||
			member.Status != device.StatusActive {
			continue
		}
		desired[member.ID] = struct{}{}
	}

	var removed []*daemonContentPeerWorker
	runtime.workersMu.Lock()
	for id, worker := range runtime.workers {
		if _, retained := desired[id]; retained {
			continue
		}
		delete(runtime.workers, id)
		worker.cancel()
		removed = append(removed, worker)
	}
	for id := range desired {
		if runtime.workers[id] != nil {
			continue
		}
		workerContext, cancel := context.WithCancel(runtime.ctx)
		worker := &daemonContentPeerWorker{
			deviceID: id,
			cancel:   cancel,
			done:     make(chan struct{}),
		}
		runtime.workers[id] = worker
		go runtime.runWorker(workerContext, worker)
	}
	runtime.workersMu.Unlock()
	for _, worker := range removed {
		select {
		case <-worker.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (runtime *daemonContentPeerRuntime) runWorker(
	ctx context.Context,
	worker *daemonContentPeerWorker,
) {
	defer close(worker.done)
	var connection *daemonContentPeerConnection
	defer func() {
		if runtime.replication != nil {
			runtime.replication.ForgetPeer(worker.deviceID)
		}
		if connection != nil {
			worker.clearConnection(connection)
			_ = connection.Close()
		}
	}()
	retry := daemonContentPeerRetryInitial
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if connection == nil {
			var err error
			connection, err = runtime.dialPeer(ctx, worker.deviceID)
			if err != nil {
				if errors.Is(err, errDaemonContentPeerState) &&
					ctx.Err() == nil {
					runtime.fail(err)
					return
				}
				if ctx.Err() == nil {
					worker.recordTransientError("dial", err)
				}
				if !runtime.waitWorker(ctx, runtime.jitter(retry)) {
					return
				}
				retry = min(retry*2, daemonContentPeerRetryMaximum)
				continue
			}
			worker.setConnection(connection)
		}
		if runtime.localCredentialAdvanced(connection.localEpoch) ||
			runtime.remoteCredentialAdvanced(
				worker.deviceID,
				connection.remoteEpoch,
			) {
			replacement, err := runtime.dialPeer(ctx, worker.deviceID)
			if err == nil {
				worker.setConnection(replacement)
				_ = connection.Close()
				connection = replacement
			} else if errors.Is(err, errDaemonContentPeerState) &&
				ctx.Err() == nil {
				runtime.fail(err)
				return
			} else if err != nil && ctx.Err() == nil {
				worker.recordTransientError("dial", err)
			}
		}
		if err := runtime.syncPeer(ctx, worker.deviceID, connection); err != nil {
			if runtime.replication != nil {
				runtime.replication.ForgetPeer(worker.deviceID)
			}
			worker.clearConnection(connection)
			_ = connection.Close()
			connection = nil
			if errors.Is(err, errDaemonContentPeerState) &&
				ctx.Err() == nil {
				runtime.fail(err)
				return
			}
			if ctx.Err() == nil {
				worker.recordTransientError("sync", err)
			}
			if !runtime.waitWorker(ctx, runtime.jitter(retry)) {
				return
			}
			retry = min(retry*2, daemonContentPeerRetryMaximum)
			continue
		}
		worker.clearTransientError()
		retry = daemonContentPeerRetryInitial
		if !runtime.waitWorker(ctx, daemonContentPeerRefreshInterval) {
			return
		}
	}
}

func (runtime *daemonContentPeerRuntime) dialPeer(
	ctx context.Context,
	peerID domain.DeviceID,
) (*daemonContentPeerConnection, error) {
	if runtime == nil || ctx == nil || !peerID.Valid() ||
		peerID == runtime.localDeviceID {
		return nil, errDaemonContentPeerConstruction
	}
	dialContext, cancel := context.WithTimeout(
		ctx,
		daemonContentPeerDialTimeout,
	)
	defer cancel()
	bootstrapErr := runtime.bootstrapPeerAuthorization(
		dialContext,
		peerID,
	)
	endpoints, err := runtime.routes.ResolveConsensusEndpoints(
		dialContext,
		peerID,
	)
	if err != nil ||
		len(endpoints) == 0 ||
		len(endpoints) > transport.ConsensusEndpointCandidatesMax {
		return nil, fmt.Errorf(
			"%w: resolve content endpoints",
			errDaemonContentPeerConstruction,
		)
	}
	certificate, err := runtime.certificate()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: local content credential",
			errDaemonContentPeerConstruction,
		)
	}
	if len(certificate.Certificate) != 1 {
		clearDaemonTLSCertificate(&certificate)
		return nil, fmt.Errorf(
			"%w: local content credential profile",
			errDaemonContentPeerConstruction,
		)
	}
	profile, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil ||
		profile.Binding.SessionID != runtime.sessionID ||
		profile.Binding.DeviceID != runtime.localDeviceID {
		clearDaemonTLSCertificate(&certificate)
		return nil, fmt.Errorf(
			"%w: local content credential profile",
			errDaemonContentPeerConstruction,
		)
	}
	defer clearDaemonTLSCertificate(&certificate)

	endpoints = slices.Compact(endpoints)
	var lastErr error
	for _, endpoint := range endpoints {
		if err := dialContext.Err(); err != nil {
			return nil, err
		}
		raw, dialErr := runtime.routes.DialConsensusEndpoint(
			dialContext,
			endpoint,
		)
		if dialErr != nil || raw == nil {
			if raw != nil {
				_ = raw.Close()
			}
			lastErr = dialErr
			continue
		}
		admission, configErr := transport.NewContentAdmissionRecorder(
			func(
				remote transport.ContentCertificate,
			) (transport.ContentPeerAdmission, error) {
				return runtime.verifiers.VerifyExpectedContentPeer(
					peerID,
					remote,
				)
			},
		)
		if configErr != nil {
			_ = raw.Close()
			return nil, fmt.Errorf(
				"%w: content admission recorder",
				errDaemonContentPeerConstruction,
			)
		}
		tlsConfig, configErr := transport.NewClientTLSConfig(
			transport.ClientTLSOptions{
				Plane:             transport.PlaneContent,
				Certificate:       certificate,
				VerifyContentPeer: admission.Verify,
			},
		)
		if configErr != nil {
			_ = raw.Close()
			return nil, fmt.Errorf(
				"%w: client TLS configuration",
				errDaemonContentPeerConstruction,
			)
		}
		tlsConnection := tls.Client(raw, tlsConfig)
		client, openErr := contenthttp.OpenClient(
			dialContext,
			tlsConnection,
			peerID,
			admission,
		)
		if openErr != nil {
			clearDaemonClientTLSConfig(tlsConfig)
			lastErr = openErr
			continue
		}
		connectionState := tlsConnection.ConnectionState()
		remoteProfile, parseErr := transport.ParseContentCertificate(
			connectionState.PeerCertificates[0].Raw,
		)
		if parseErr != nil || remoteProfile.Binding.DeviceID != peerID {
			_ = client.Close()
			clearDaemonClientTLSConfig(tlsConfig)
			lastErr = contenthttp.ErrPeerMismatch
			continue
		}
		if err := runtime.recordAuthenticatedEndpoint(
			dialContext,
			peerID,
			endpoint,
		); err != nil {
			_ = client.Close()
			clearDaemonClientTLSConfig(tlsConfig)
			lastErr = err
			continue
		}
		session, sessionErr := client.Session(dialContext)
		if sessionErr != nil ||
			session.SessionID() != runtime.sessionID ||
			session.WorkspaceID() != runtime.workspaceID ||
			session.RecoveryGeneration() != runtime.generation ||
			session.ServerDeviceID() != peerID ||
			len(session.RequiredCapabilities()) != 0 {
			_ = client.Close()
			clearDaemonClientTLSConfig(tlsConfig)
			lastErr = sessionErr
			if lastErr == nil {
				lastErr = contenthttp.ErrLineageMismatch
			}
			continue
		}
		return &daemonContentPeerConnection{
			client:    client,
			tlsConfig: tlsConfig,
			openSnapshotBulk: func(
				bulkContext context.Context,
				root logicalsnapshot.Root,
			) (daemonSnapshotBulkClient, error) {
				return runtime.dialSnapshotBulk(
					bulkContext,
					peerID,
					endpoint,
					root,
				)
			},
			localEpoch:  profile.Binding.Epoch,
			remoteEpoch: remoteProfile.Binding.Epoch,
		}, nil
	}
	if lastErr == nil {
		lastErr = transport.ErrConsensusEndpointUnavailable
	}
	if bootstrapErr != nil {
		lastErr = errors.Join(lastErr, bootstrapErr)
	}
	return nil, fmt.Errorf(
		"%w: content dial: %v",
		errDaemonContentPeerConstruction,
		lastErr,
	)
}

func (runtime *daemonContentPeerRuntime) dialSnapshotBulk(
	ctx context.Context,
	peerID domain.DeviceID,
	endpoint netip.AddrPort,
	root logicalsnapshot.Root,
) (_ daemonSnapshotBulkClient, resultErr error) {
	if runtime == nil ||
		ctx == nil ||
		!peerID.Valid() ||
		peerID == runtime.localDeviceID ||
		!endpoint.IsValid() ||
		len(root.CanonicalBytes()) == 0 {
		return nil, errDaemonContentPeerConstruction
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialContext, cancel := context.WithTimeout(
		ctx,
		daemonContentPeerDialTimeout,
	)
	defer cancel()
	input := root.Unsigned().Input()
	if input.SessionID != runtime.sessionID ||
		input.WorkspaceID != runtime.workspaceID ||
		input.RecoveryGeneration != runtime.generation {
		return nil, contenthttp.ErrLineageMismatch
	}
	certificate, err := runtime.certificate()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: local bulk credential",
			errDaemonContentPeerConstruction,
		)
	}
	defer clearDaemonTLSCertificate(&certificate)
	if len(certificate.Certificate) != 1 {
		return nil, fmt.Errorf(
			"%w: local bulk credential profile",
			errDaemonContentPeerConstruction,
		)
	}
	profile, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	if err != nil ||
		profile.Binding.SessionID != runtime.sessionID ||
		profile.Binding.DeviceID != runtime.localDeviceID {
		return nil, fmt.Errorf(
			"%w: local bulk credential profile",
			errDaemonContentPeerConstruction,
		)
	}
	raw, err := runtime.routes.DialConsensusEndpoint(
		dialContext,
		endpoint,
	)
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, fmt.Errorf(
			"%w: dial snapshot bulk endpoint: %v",
			errDaemonContentPeerConstruction,
			err,
		)
	}
	admission, err := transport.NewContentAdmissionRecorder(
		func(
			remote transport.ContentCertificate,
		) (transport.ContentPeerAdmission, error) {
			return runtime.verifiers.VerifyExpectedContentPeer(
				peerID,
				remote,
			)
		},
	)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf(
			"%w: bulk admission recorder",
			errDaemonContentPeerConstruction,
		)
	}
	tlsConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       certificate,
			VerifyContentPeer: admission.Verify,
		},
	)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf(
			"%w: bulk TLS configuration",
			errDaemonContentPeerConstruction,
		)
	}
	client, err := contenthttp.OpenSnapshotBulkClient(
		dialContext,
		tls.Client(raw, tlsConfig),
		peerID,
		admission,
		root,
	)
	if err != nil {
		clearDaemonClientTLSConfig(tlsConfig)
		return nil, err
	}
	connection := &daemonSnapshotBulkConnection{
		client:    client,
		tlsConfig: tlsConfig,
	}
	if err := runtime.recordAuthenticatedEndpoint(
		dialContext,
		peerID,
		endpoint,
	); err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	return connection, nil
}

func (runtime *daemonContentPeerRuntime) bootstrapPeerAuthorization(
	ctx context.Context,
	peerID domain.DeviceID,
) error {
	if runtime == nil ||
		ctx == nil ||
		!peerID.Valid() ||
		peerID == runtime.localDeviceID {
		return errDaemonContentPeerConstruction
	}
	if runtime.status == nil {
		return nil
	}
	snapshot, err := runtime.admission.PeerAdmissionSnapshot()
	if err != nil {
		return fmt.Errorf(
			"%w: read bootstrap admission: %v",
			errDaemonContentPeerConstruction,
			err,
		)
	}
	sessionID, generation, valid := snapshot.Lineage()
	appliedAuthority, authorityValid := snapshot.CredentialAuthority()
	now := runtime.credentialNow()
	if !valid ||
		sessionID != runtime.sessionID ||
		generation != runtime.generation ||
		!authorityValid ||
		now.IsZero() {
		return errDaemonContentPeerConstruction
	}
	requestContext, cancel := context.WithTimeout(
		ctx,
		daemonContentPeerBootstrapTimeout,
	)
	defer cancel()
	status, err := consensus.RequestConsensusStatusAt(
		requestContext,
		runtime.status,
		peerID,
		now,
	)
	if err != nil {
		return err
	}
	if status.SessionID != runtime.sessionID ||
		status.WorkspaceID != runtime.workspaceID ||
		status.RecoveryGeneration != runtime.generation ||
		status.ServerDeviceID != peerID {
		return consensus.ErrConsensusStatusMismatch
	}
	authorization := status.ContentCredentialAuthorization
	var installErr error
	switch {
	case authorization.AuthorityVoterSetVersion ==
		appliedAuthority.VoterSetVersion:
		installErr = runtime.verifiers.InstallProvisionalAuthorization(
			peerID,
			authorization,
		)
	case authorization.AuthorityVoterSetVersion >
		appliedAuthority.VoterSetVersion &&
		status.CredentialAuthority.VoterSetVersion ==
			authorization.AuthorityVoterSetVersion:
		installErr = runtime.verifiers.
			InstallProvisionalAuthorizationAfterHandoff(
				peerID,
				runtime.workspaceID,
				authorization,
				status.CredentialAuthority,
			)
	default:
		return nil
	}
	if installErr != nil {
		return fmt.Errorf(
			"%w: peer %s: %v",
			errDaemonContentPeerConstruction,
			peerID,
			installErr,
		)
	}
	return nil
}

func (runtime *daemonContentPeerRuntime) syncPeer(
	ctx context.Context,
	peerID domain.DeviceID,
	connection *daemonContentPeerConnection,
) error {
	if runtime == nil || ctx == nil || !peerID.Valid() ||
		connection == nil || connection.client == nil {
		return errDaemonContentPeerConstruction
	}
	requestContext, cancel := context.WithTimeout(
		ctx,
		daemonContentPeerRequestTimeout,
	)
	defer cancel()
	response, err := connection.Peers(requestContext)
	if err != nil {
		return err
	}
	if response.SessionID() != runtime.sessionID ||
		response.WorkspaceID() != runtime.workspaceID ||
		response.RecoveryGeneration() != runtime.generation ||
		response.ServerDeviceID() != peerID {
		return contenthttp.ErrLineageMismatch
	}
	observedAt, err := runtime.timestamp()
	if err != nil {
		return err
	}
	for _, member := range response.Members() {
		endpointSet := member.EndpointSet()
		if member.DeviceID() == runtime.localDeviceID ||
			len(endpointSet) == 0 {
			continue
		}
		_, err := runtime.state.ReplaceMemberSignedEndpointSet(
			requestContext,
			endpointSet,
			observedAt,
		)
		if errors.Is(err, store.ErrPeerEndpointSequenceRollback) {
			continue
		}
		if err != nil {
			if requestContext.Err() != nil {
				return requestContext.Err()
			}
			if !contentPeerSetRefusal(err) {
				return fmt.Errorf(
					"%w: retain endpoint set for %s: %w",
					errDaemonContentPeerState,
					member.DeviceID(),
					err,
				)
			}
			return fmt.Errorf(
				"%w: retain endpoint set for %s: %v",
				errDaemonContentPeerConstruction,
				member.DeviceID(),
				err,
			)
		}
	}
	if runtime.replication != nil {
		replicationContext, cancelReplication := context.WithTimeout(
			ctx,
			daemonContentPeerReplicationTimeout,
		)
		defer cancelReplication()
		if err := runtime.replication.Sync(
			replicationContext,
			peerID,
			connection,
		); err != nil {
			return err
		}
	}
	return nil
}

// ForwardProposal sends an exact signed proposal only to the caller-selected
// active peer over its current authenticated content-control connection.
func (runtime *daemonContentPeerRuntime) ForwardProposal(
	ctx context.Context,
	target domain.DeviceID,
	signed event.SignedEvent,
) (consensus.ForwardedProposalResult, error) {
	if runtime == nil ||
		ctx == nil ||
		!target.Valid() ||
		target == runtime.localDeviceID ||
		!signed.Proposal().EventID.Valid() ||
		signed.Proposal().SessionID != runtime.sessionID ||
		signed.Proposal().WorkspaceID != runtime.workspaceID {
		return consensus.ForwardedProposalResult{},
			errDaemonContentPeerConstruction
	}
	if err := ctx.Err(); err != nil {
		return consensus.ForwardedProposalResult{}, err
	}
	runtime.workersMu.Lock()
	worker := runtime.workers[target]
	runtime.workersMu.Unlock()
	if worker == nil {
		return consensus.ForwardedProposalResult{},
			consensus.ErrProposalForwardingUnavailable
	}
	connection := worker.currentConnection()
	if connection == nil {
		return consensus.ForwardedProposalResult{},
			consensus.ErrProposalForwardingUnavailable
	}
	result, err := connection.ForwardProposal(ctx, signed)
	if err != nil {
		return consensus.ForwardedProposalResult{},
			normalizeDaemonProposalForwardingError(err)
	}
	return daemonForwardedProposalResult(result), nil
}

// Propose sends an initial-hop proposal to one selected active peer. That
// peer may forward once to its observed leader.
func (runtime *daemonContentPeerRuntime) Propose(
	ctx context.Context,
	target domain.DeviceID,
	signed event.SignedEvent,
) (consensus.ForwardedProposalResult, error) {
	if runtime == nil ||
		ctx == nil ||
		!target.Valid() ||
		target == runtime.localDeviceID ||
		!signed.Proposal().EventID.Valid() ||
		signed.Proposal().SessionID != runtime.sessionID ||
		signed.Proposal().WorkspaceID != runtime.workspaceID {
		return consensus.ForwardedProposalResult{},
			errDaemonContentPeerConstruction
	}
	if err := ctx.Err(); err != nil {
		return consensus.ForwardedProposalResult{}, err
	}
	runtime.workersMu.Lock()
	worker := runtime.workers[target]
	runtime.workersMu.Unlock()
	if worker == nil {
		return consensus.ForwardedProposalResult{},
			consensus.ErrProposalForwardingUnavailable
	}
	connection := worker.currentConnection()
	if connection == nil {
		return consensus.ForwardedProposalResult{},
			consensus.ErrProposalForwardingUnavailable
	}
	result, err := connection.Propose(ctx, signed)
	if err != nil {
		return consensus.ForwardedProposalResult{},
			normalizeDaemonProposalForwardingError(err)
	}
	return daemonForwardedProposalResult(result), nil
}

func daemonForwardedProposalResult(
	result contenthttp.EventResult,
) consensus.ForwardedProposalResult {
	chainIndex, chainHash, accepted := result.ChainPosition()
	forwarded := consensus.ForwardedProposalResult{
		Outcome:     result.Outcome(),
		ResultIndex: result.ResultIndex(),
	}
	if accepted {
		forwarded.ChainIndex = &chainIndex
		forwarded.ChainHash = &chainHash
	}
	return forwarded
}

func normalizeDaemonProposalForwardingError(err error) error {
	if err == nil {
		return nil
	}
	var remote *contenthttp.RemoteError
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, contenthttp.ErrClientClosed),
		errors.Is(err, contenthttp.ErrConnectionUnavailable):
		return consensus.ErrProposalForwardingUnavailable
	case errors.As(err, &remote) &&
		remote.Code == "idempotency_conflict":
		return store.ErrIdempotencyConflict
	case errors.As(err, &remote) &&
		remote.Code == "leader_ingress_rate_limited":
		return consensus.ErrProposalIngressRateLimited
	case errors.As(err, &remote) && remote.Retryable:
		return consensus.ErrProposalForwardingUnavailable
	default:
		return err
	}
}

func (runtime *daemonContentPeerRuntime) recordAuthenticatedEndpoint(
	ctx context.Context,
	peerID domain.DeviceID,
	endpoint netip.AddrPort,
) error {
	observedAt, err := runtime.timestamp()
	if err != nil {
		return err
	}
	if err := runtime.state.UpsertAuthenticatedEndpoint(
		ctx,
		peerID,
		endpoint,
		observedAt,
	); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, store.ErrPeerEndpointCapacity) {
			return nil
		}
		return fmt.Errorf(
			"%w: retain authenticated endpoint: %w",
			errDaemonContentPeerState,
			err,
		)
	}
	return nil
}

func contentPeerSetRefusal(err error) bool {
	return errors.Is(err, store.ErrInvalidPeerEndpointSet) ||
		errors.Is(err, store.ErrPeerEndpointSequenceConflict) ||
		errors.Is(err, store.ErrPeerEndpointCapacity)
}

func (runtime *daemonContentPeerRuntime) timestamp() (domain.Timestamp, error) {
	if runtime == nil || runtime.now == nil {
		return "", errDaemonContentPeerConstruction
	}
	value := domain.Timestamp(runtime.now().UTC().Format(time.RFC3339Nano))
	if !value.Valid() {
		return "", errDaemonContentPeerConstruction
	}
	return value, nil
}

func (runtime *daemonContentPeerRuntime) localCredentialAdvanced(
	currentEpoch uint64,
) bool {
	if runtime == nil || currentEpoch < 1 {
		return false
	}
	certificate, err := runtime.certificate()
	if err != nil {
		return false
	}
	defer clearDaemonTLSCertificate(&certificate)
	if len(certificate.Certificate) != 1 {
		return false
	}
	profile, err := transport.ParseContentCertificate(
		certificate.Certificate[0],
	)
	return err == nil &&
		profile.Binding.SessionID == runtime.sessionID &&
		profile.Binding.DeviceID == runtime.localDeviceID &&
		profile.Binding.Epoch > currentEpoch
}

func (runtime *daemonContentPeerRuntime) remoteCredentialAdvanced(
	peerID domain.DeviceID,
	currentEpoch uint64,
) bool {
	if runtime == nil ||
		runtime.admission == nil ||
		runtime.credentialNow == nil ||
		!peerID.Valid() ||
		peerID == runtime.localDeviceID ||
		currentEpoch < 1 {
		return false
	}
	now := runtime.credentialNow()
	if now.IsZero() {
		return false
	}
	snapshot, err := runtime.admission.PeerAdmissionSnapshot()
	if err != nil || snapshot == nil {
		return false
	}
	authorization, active := snapshot.ActiveCredentialAuthorizationAt(
		peerID,
		now,
	)
	return active && authorization.Epoch > currentEpoch
}

func (runtime *daemonContentPeerRuntime) waitWorker(
	ctx context.Context,
	delay time.Duration,
) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func daemonContentPeerRetryDelay(backoff time.Duration) time.Duration {
	if backoff <= 0 {
		return 0
	}
	floor := backoff * 3 / 4
	ceiling := backoff * 5 / 4
	if ceiling <= floor {
		return backoff
	}
	return floor + time.Duration(
		rand.Int64N(int64(ceiling-floor)+1),
	)
}

func (runtime *daemonContentPeerRuntime) fail(err error) {
	if runtime == nil || err == nil {
		return
	}
	runtime.fatalMu.Lock()
	if runtime.closing {
		runtime.fatalMu.Unlock()
		return
	}
	if runtime.fatalErr == nil {
		runtime.fatalErr = err
	}
	runtime.cancel()
	runtime.fatalMu.Unlock()
}

func (runtime *daemonContentPeerRuntime) stopWorkers() {
	runtime.workersMu.Lock()
	workers := make([]*daemonContentPeerWorker, 0, len(runtime.workers))
	for id, worker := range runtime.workers {
		delete(runtime.workers, id)
		worker.cancel()
		workers = append(workers, worker)
	}
	runtime.workersMu.Unlock()
	for _, worker := range workers {
		<-worker.done
	}
}

func (runtime *daemonContentPeerRuntime) FatalError() error {
	if runtime == nil {
		return errDaemonContentPeerConstruction
	}
	runtime.fatalMu.RLock()
	defer runtime.fatalMu.RUnlock()
	return runtime.fatalErr
}

func (runtime *daemonContentPeerRuntime) transientPeerErrors() []daemonContentPeerTransientErrorSnapshot {
	if runtime == nil {
		return nil
	}
	runtime.workersMu.Lock()
	workers := make([]*daemonContentPeerWorker, 0, len(runtime.workers))
	for _, worker := range runtime.workers {
		workers = append(workers, worker)
	}
	runtime.workersMu.Unlock()

	snapshots := make(
		[]daemonContentPeerTransientErrorSnapshot,
		0,
		len(workers),
	)
	for _, worker := range workers {
		if snapshot, ok := worker.transientError(); ok {
			snapshots = append(snapshots, snapshot)
		}
	}
	slices.SortFunc(
		snapshots,
		func(
			left daemonContentPeerTransientErrorSnapshot,
			right daemonContentPeerTransientErrorSnapshot,
		) int {
			return strings.Compare(string(left.PeerID), string(right.PeerID))
		},
	)
	return snapshots
}

func (runtime *daemonContentPeerRuntime) BeginClose() error {
	if runtime == nil || runtime.cancel == nil {
		return errDaemonContentPeerConstruction
	}
	runtime.fatalMu.Lock()
	runtime.closing = true
	runtime.close.Do(runtime.cancel)
	runtime.fatalMu.Unlock()
	return nil
}

func (runtime *daemonContentPeerRuntime) Wait() error {
	if runtime == nil || runtime.done == nil {
		return errDaemonContentPeerConstruction
	}
	if err := runtime.BeginClose(); err != nil {
		return err
	}
	<-runtime.done
	return runtime.FatalError()
}

func (connection *daemonContentPeerConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	var err error
	if connection.client != nil {
		err = connection.client.Close()
		connection.client = nil
	}
	connection.openSnapshotBulk = nil
	clearDaemonClientTLSConfig(connection.tlsConfig)
	connection.tlsConfig = nil
	connection.localEpoch = 0
	connection.remoteEpoch = 0
	return err
}

func (connection *daemonContentPeerConnection) Peers(
	ctx context.Context,
) (contenthttp.PeersResponse, error) {
	if connection == nil || ctx == nil {
		return contenthttp.PeersResponse{},
			errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return contenthttp.PeersResponse{}, contenthttp.ErrClientClosed
	}
	return connection.client.Peers(ctx)
}

func (connection *daemonContentPeerConnection) ForwardProposal(
	ctx context.Context,
	signed event.SignedEvent,
) (contenthttp.EventResult, error) {
	if connection == nil || ctx == nil {
		return contenthttp.EventResult{},
			errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return contenthttp.EventResult{}, contenthttp.ErrClientClosed
	}
	return connection.client.ForwardProposal(ctx, signed)
}

func (connection *daemonContentPeerConnection) Propose(
	ctx context.Context,
	signed event.SignedEvent,
) (contenthttp.EventResult, error) {
	if connection == nil || ctx == nil {
		return contenthttp.EventResult{},
			errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return contenthttp.EventResult{}, contenthttp.ErrClientClosed
	}
	return connection.client.Propose(ctx, signed)
}

func (connection *daemonContentPeerConnection) Replication(
	ctx context.Context,
	afterResult uint64,
) (replication.Batch, error) {
	if connection == nil || ctx == nil {
		return replication.Batch{}, errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return replication.Batch{}, contenthttp.ErrClientClosed
	}
	return connection.client.Replication(ctx, afterResult)
}

func (connection *daemonContentPeerConnection) ReplicationAcknowledgement(
	ctx context.Context,
	atResult uint64,
) (replication.Acknowledgement, error) {
	if connection == nil || ctx == nil {
		return replication.Acknowledgement{},
			errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return replication.Acknowledgement{},
			contenthttp.ErrClientClosed
	}
	return connection.client.ReplicationAcknowledgement(ctx, atResult)
}

func (connection *daemonContentPeerConnection) LatestSnapshot(
	ctx context.Context,
) (logicalsnapshot.Root, error) {
	if connection == nil || ctx == nil {
		return logicalsnapshot.Root{}, errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil {
		return logicalsnapshot.Root{}, contenthttp.ErrClientClosed
	}
	return connection.client.LatestSnapshot(ctx)
}

func (connection *daemonSnapshotBulkConnection) SnapshotManifestPage(
	ctx context.Context,
	pageIndex uint64,
) (logicalsnapshot.DescriptorPage, error) {
	if connection == nil || ctx == nil {
		return logicalsnapshot.DescriptorPage{},
			errDaemonContentPeerConstruction
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.client == nil {
		return logicalsnapshot.DescriptorPage{},
			contenthttp.ErrClientClosed
	}
	return connection.client.SnapshotManifestPage(ctx, pageIndex)
}

func (connection *daemonContentPeerConnection) OpenSnapshotBulk(
	ctx context.Context,
	root logicalsnapshot.Root,
) (daemonSnapshotBulkClient, error) {
	if connection == nil || ctx == nil {
		return nil, errDaemonContentPeerConstruction
	}
	connection.mu.RLock()
	defer connection.mu.RUnlock()
	if connection.client == nil || connection.openSnapshotBulk == nil {
		return nil, contenthttp.ErrClientClosed
	}
	return connection.openSnapshotBulk(ctx, root)
}

func (connection *daemonSnapshotBulkConnection) SnapshotChunk(
	ctx context.Context,
	chunkIndex uint64,
) (contenthttp.SnapshotChunk, error) {
	if connection == nil || ctx == nil {
		return contenthttp.SnapshotChunk{},
			errDaemonContentPeerConstruction
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.client == nil {
		return contenthttp.SnapshotChunk{}, contenthttp.ErrClientClosed
	}
	return connection.client.SnapshotChunk(ctx, chunkIndex)
}

func (connection *daemonSnapshotBulkConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	var err error
	if connection.client != nil {
		err = connection.client.Close()
		connection.client = nil
	}
	clearDaemonClientTLSConfig(connection.tlsConfig)
	connection.tlsConfig = nil
	return err
}

func (worker *daemonContentPeerWorker) recordTransientError(
	operation string,
	err error,
) {
	if worker == nil ||
		err == nil ||
		(operation != "dial" && operation != "sync") {
		return
	}
	message := strings.ToValidUTF8(err.Error(), "\uFFFD")
	if len(message) > daemonContentPeerDiagnosticMaxBytes {
		end := daemonContentPeerDiagnosticMaxBytes
		for end > 0 && !utf8.RuneStart(message[end]) {
			end--
		}
		message = message[:end]
	}
	worker.diagnosticMu.Lock()
	worker.lastTransient = daemonContentPeerTransientErrorSnapshot{
		PeerID:    worker.deviceID,
		Operation: operation,
		Message:   message,
	}
	worker.diagnosticMu.Unlock()
}

func (worker *daemonContentPeerWorker) clearTransientError() {
	if worker == nil {
		return
	}
	worker.diagnosticMu.Lock()
	worker.lastTransient = daemonContentPeerTransientErrorSnapshot{}
	worker.diagnosticMu.Unlock()
}

func (worker *daemonContentPeerWorker) transientError() (
	daemonContentPeerTransientErrorSnapshot,
	bool,
) {
	if worker == nil {
		return daemonContentPeerTransientErrorSnapshot{}, false
	}
	worker.diagnosticMu.RLock()
	defer worker.diagnosticMu.RUnlock()
	snapshot := worker.lastTransient
	return snapshot, snapshot.PeerID.Valid() &&
		(snapshot.Operation == "dial" || snapshot.Operation == "sync") &&
		snapshot.Message != ""
}

func (worker *daemonContentPeerWorker) setConnection(
	connection *daemonContentPeerConnection,
) {
	if worker == nil || connection == nil {
		return
	}
	worker.connectionMu.Lock()
	worker.connection = connection
	worker.connectionMu.Unlock()
}

func (worker *daemonContentPeerWorker) clearConnection(
	connection *daemonContentPeerConnection,
) {
	if worker == nil || connection == nil {
		return
	}
	worker.connectionMu.Lock()
	if worker.connection == connection {
		worker.connection = nil
	}
	worker.connectionMu.Unlock()
}

func (worker *daemonContentPeerWorker) currentConnection() *daemonContentPeerConnection {
	if worker == nil {
		return nil
	}
	worker.connectionMu.RLock()
	defer worker.connectionMu.RUnlock()
	return worker.connection
}

func clearDaemonClientTLSConfig(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		clearDaemonTLSCertificate(&config.Certificates[index])
	}
	config.Certificates = nil
}

var _ phasedDaemonComponent = (*daemonContentPeerRuntime)(nil)
var _ consensus.ProposalForwarder = (*daemonContentPeerRuntime)(nil)
