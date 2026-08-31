package joinbootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/contenthttp"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/logicalsnapshot"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	joinSnapshotMaxBytes      uint64 = 256 << 20
	joinSnapshotMaxRecords    uint64 = 100_000
	joinSnapshotMaxChunks     uint64 = 4_096
	joinSnapshotMaxPages      uint64 = 1
	joinSnapshotMaxGeneration uint64 = 255
	joinSnapshotRetryDelay           = 250 * time.Millisecond
)

var (
	ErrBootstrapUnavailable = errors.New(
		"join bootstrap: remote bootstrap is unavailable",
	)
	ErrBootstrapMismatch = errors.New(
		"join bootstrap: remote bootstrap differs from invite pins",
	)
)

type contentConnection struct {
	client    *contenthttp.Client
	tlsConfig *tls.Config
	endpoint  netip.AddrPort
}

type bulkConnection struct {
	client    *contenthttp.SnapshotBulkClient
	tlsConfig *tls.Config
}

func completeBootstrap(
	ctx context.Context,
	options Options,
	routes *pinnedEndpoints,
	journal *pendingJournal,
	identityPrivate []byte,
	epochPrivate []byte,
	bootID domain.UUIDv7,
) (resultErr error) {
	if journal == nil {
		return ErrBootstrapMismatch
	}
	identityCertificate, identityBinding, err :=
		transport.IssueIdentityCertificate(
			journal.SessionID,
			journal.RecoveryGeneration,
			identityPrivate,
		)
	if err != nil {
		return fmt.Errorf("join bootstrap: issue identity certificate: %w", err)
	}
	defer clearTLSCertificate(&identityCertificate)
	if identityBinding.DeviceID != journal.LocalDeviceID {
		return ErrBootstrapMismatch
	}
	leader, err := resolveInitialBootstrapLeader(
		ctx,
		options.StatePath,
		journal,
		routes,
		identityCertificate,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: resolve initial leader: %w", err)
	}
	defer func() {
		if leader != nil {
			resultErr = errors.Join(resultErr, leader.Close())
		}
	}()
	status := leader.status
	selectedEpochPrivate, binding, err := selectJoinCredential(
		ctx,
		options,
		journal,
		status,
		identityPrivate,
		epochPrivate,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: select content credential: %w", err)
	}
	defer clear(selectedEpochPrivate)
	authorization, err := consensus.SubmitCredentialRenewal(
		ctx,
		leader.control,
		leader.peer.deviceID,
		binding,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: authorize content credential: %w", err)
	}
	if !authorizationMatchesBinding(authorization, binding) {
		return ErrBootstrapMismatch
	}
	status, err = waitForCredentialStatus(
		ctx,
		leader.control,
		*journal,
		leader.peer,
		authorization,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: observe content credential: %w", err)
	}
	if err := waitForCredentialActivation(
		ctx,
		options.Now,
		authorization,
	); err != nil {
		return fmt.Errorf("join bootstrap: activate content credential: %w", err)
	}
	if err := leader.Close(); err != nil {
		return fmt.Errorf("join bootstrap: close initial leader: %w", err)
	}
	leader = nil
	leader, err = waitForBootstrapLeader(
		ctx,
		*journal,
		routes,
		identityCertificate,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: resolve current leader: %w", err)
	}
	status, err = waitForCredentialStatus(
		ctx,
		leader.control,
		*journal,
		leader.peer,
		authorization,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: revalidate content credential: %w", err)
	}
	contentCertificate, contentBinding, err :=
		transport.IssueContentCertificate(
			authorization,
			selectedEpochPrivate,
		)
	if err != nil {
		return fmt.Errorf("join bootstrap: issue content certificate: %w", err)
	}
	defer clearTLSCertificate(&contentCertificate)
	if contentBinding.SessionID != journal.SessionID ||
		contentBinding.DeviceID != journal.LocalDeviceID ||
		contentBinding.Epoch != journal.CredentialEpoch {
		return ErrBootstrapMismatch
	}

	content, err := openContentConnection(
		ctx,
		options,
		*journal,
		leader.peer,
		contentCertificate,
		status.ContentCredentialAuthorization,
	)
	if err != nil {
		return fmt.Errorf("join bootstrap: open content plane: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, content.Close())
	}()
	session, err := content.client.Session(ctx)
	if err != nil {
		return fmt.Errorf("join bootstrap: read session metadata: %w", err)
	}
	if session.SessionID() != journal.SessionID ||
		session.WorkspaceID() != journal.WorkspaceID ||
		session.RecoveryGeneration() != journal.RecoveryGeneration ||
		session.ServerDeviceID() != leader.peer.deviceID ||
		len(session.RequiredCapabilities()) != 0 {
		return ErrBootstrapMismatch
	}

	if err := installLatestSnapshot(
		ctx,
		options,
		journal,
		leader.peer,
		status,
		authorization,
		content,
		contentCertificate,
		bootID,
	); err != nil {
		return fmt.Errorf("join bootstrap: install logical snapshot: %w", err)
	}
	return nil
}

func validateJoinConsensusStatus(
	status consensus.ConsensusStatusResult,
	journal pendingJournal,
	peer bootstrapPeer,
) error {
	requester := status.RequesterMembership.Device
	if status.SessionID != journal.SessionID ||
		status.WorkspaceID != journal.WorkspaceID ||
		status.RecoveryGeneration != journal.RecoveryGeneration ||
		status.ServerDeviceID != peer.deviceID ||
		status.GenerationZeroState.WorkspaceID != journal.WorkspaceID ||
		requester.ID != journal.LocalDeviceID ||
		requester.Role != journal.ApprovedRole ||
		requester.DaemonVersion != journal.ApprovedDaemonVersion ||
		requester.MaxApplyLevel != journal.ApprovedMaxApplyLevel ||
		requester.EntityVersion != 1 ||
		!bytes.Equal(
			requester.IdentityPublicKey,
			journal.LocalIdentityPublicKey[:],
		) {
		return ErrBootstrapMismatch
	}
	var inviterFound, peerFound bool
	for _, member := range status.ActiveRoster {
		if member.Device.ID == journal.InviterDeviceID {
			if !bytes.Equal(
				member.Device.IdentityPublicKey,
				journal.InviterIdentityPublicKey[:],
			) {
				return ErrBootstrapMismatch
			}
			inviterFound = true
		}
		if member.Device.ID == peer.deviceID {
			if !bytes.Equal(
				member.Device.IdentityPublicKey,
				peer.identityPublicKey,
			) {
				return ErrBootstrapMismatch
			}
			peerFound = true
		}
	}
	if !inviterFound || !peerFound {
		return ErrBootstrapMismatch
	}
	return nil
}

func selectJoinCredential(
	ctx context.Context,
	options Options,
	journal *pendingJournal,
	status consensus.ConsensusStatusResult,
	identityPrivate []byte,
	loadedEpochPrivate []byte,
) ([]byte, credential.Binding, error) {
	if ctx == nil ||
		journal == nil ||
		options.Credentials == nil ||
		options.generateKeyPair == nil ||
		options.Now == nil {
		return nil, credential.Binding{}, ErrBootstrapMismatch
	}
	now := options.Now()
	if now.IsZero() {
		return nil, credential.Binding{}, ErrBootstrapMismatch
	}
	currentEpoch := status.RequesterMembership.CurrentCredentialEpoch
	targetEpoch := currentEpoch
	if currentEpoch == 0 {
		targetEpoch = journal.InitialCredentialEpoch
		if targetEpoch != 1 ||
			status.RequesterCredentialAuthorization != nil {
			return nil, credential.Binding{}, ErrBootstrapMismatch
		}
	} else {
		current := status.RequesterCredentialAuthorization
		if current == nil || current.Epoch != currentEpoch {
			return nil, credential.Binding{}, ErrBootstrapMismatch
		}
		expired, err := credentialAuthorizationExpiredAt(*current, now)
		if err != nil {
			return nil, credential.Binding{}, err
		}
		if expired {
			if currentEpoch == domain.MaxSafeInteger {
				return nil, credential.Binding{}, ErrBootstrapMismatch
			}
			targetEpoch = currentEpoch + 1
		}
	}

	selectedPrivate := loadedEpochPrivate
	selectedIsNew := false
	if targetEpoch != journal.CredentialEpoch {
		if journal.CredentialEpoch != currentEpoch ||
			targetEpoch != currentEpoch+1 {
			return nil, credential.Binding{}, ErrStateConflict
		}
		reference, err := credentialstore.EpochReference(
			journal.SessionID,
			journal.LocalDeviceID,
			targetEpoch,
		)
		if err != nil {
			return nil, credential.Binding{}, err
		}
		privateKey, publicKey, err := loadOrCreateKey(
			ctx,
			options.Credentials,
			reference,
			options.generateKeyPair,
		)
		if err != nil {
			return nil, credential.Binding{}, err
		}
		journal.CredentialEpoch = targetEpoch
		copy(journal.LocalEpochPublicKey[:], publicKey)
		clear(publicKey)
		if err := writePendingJournal(
			options.StatePath,
			*journal,
		); err != nil {
			clear(privateKey)
			return nil, credential.Binding{}, err
		}
		selectedPrivate = privateKey
		selectedIsNew = true
	}
	if targetEpoch != journal.CredentialEpoch {
		return nil, credential.Binding{}, ErrStateConflict
	}
	publicKey, err :=
		codecommcrypto.Ed25519PublicKeyFromPrivateKey(selectedPrivate)
	if err != nil ||
		!bytes.Equal(publicKey, journal.LocalEpochPublicKey[:]) {
		clear(publicKey)
		if selectedIsNew {
			clear(selectedPrivate)
		}
		return nil, credential.Binding{}, ErrStateConflict
	}
	clear(publicKey)
	binding, err := credentialBinding(*journal, identityPrivate)
	if err != nil {
		if selectedIsNew {
			clear(selectedPrivate)
		}
		return nil, credential.Binding{}, err
	}
	return selectedPrivate, binding, nil
}

func credentialAuthorizationExpiredAt(
	authorization credentialauthorization.Authorization,
	now time.Time,
) (bool, error) {
	if authorization.Validate() != nil || now.IsZero() {
		return false, ErrBootstrapMismatch
	}
	notBefore, err := authorization.NotBefore.Time()
	if err != nil {
		return false, ErrBootstrapMismatch
	}
	expiresAt := notBefore.Add(
		time.Duration(authorization.ValiditySeconds) * time.Second,
	)
	return !now.Before(expiresAt), nil
}

func waitForCredentialStatus(
	ctx context.Context,
	control consensus.ConsensusStatusRequester,
	journal pendingJournal,
	peer bootstrapPeer,
	authorization credentialauthorization.Authorization,
) (consensus.ConsensusStatusResult, error) {
	for {
		status, err := consensus.RequestConsensusStatus(
			ctx,
			control,
			peer.deviceID,
		)
		if err == nil {
			if validationErr := validateJoinConsensusStatus(
				status,
				journal,
				peer,
			); validationErr != nil {
				return consensus.ConsensusStatusResult{}, validationErr
			}
			current := status.RequesterCredentialAuthorization
			switch {
			case status.RequesterMembership.CurrentCredentialEpoch >
				authorization.Epoch:
				return consensus.ConsensusStatusResult{},
					ErrBootstrapMismatch
			case status.RequesterMembership.CurrentCredentialEpoch ==
				authorization.Epoch &&
				current != nil:
				if !reflect.DeepEqual(*current, authorization) {
					return consensus.ConsensusStatusResult{},
						ErrBootstrapMismatch
				}
				return status, nil
			}
		} else if !errors.Is(
			err,
			consensus.ErrConsensusStatusUnavailable,
		) {
			return consensus.ConsensusStatusResult{}, err
		}
		timer := time.NewTimer(joinSnapshotRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return consensus.ConsensusStatusResult{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func waitForCredentialActivation(
	ctx context.Context,
	now func() time.Time,
	authorization credentialauthorization.Authorization,
) error {
	for {
		current := now()
		if current.IsZero() {
			return ErrBootstrapMismatch
		}
		if authorization.ActiveAt(current) {
			return nil
		}
		expired, err := credentialAuthorizationExpiredAt(
			authorization,
			current,
		)
		if err != nil || expired {
			return ErrBootstrapMismatch
		}
		timer := time.NewTimer(joinSnapshotRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func authorizationMatchesBinding(
	authorization credentialauthorization.Authorization,
	binding credential.Binding,
) bool {
	return authorization.Validate() == nil &&
		authorization.SessionID == binding.SessionID &&
		authorization.DeviceID == binding.DeviceID &&
		authorization.Epoch == binding.Epoch &&
		authorization.EpochPublicKey == binding.EpochPublicKey &&
		authorization.KeyDigest == binding.KeyDigest &&
		authorization.BindingSignature == binding.Signature
}

func openContentConnection(
	ctx context.Context,
	options Options,
	journal pendingJournal,
	peer bootstrapPeer,
	localCertificate tls.Certificate,
	remoteAuthorization credentialauthorization.Authorization,
) (*contentConnection, error) {
	if peer.routes == nil {
		return nil, ErrBootstrapMismatch
	}
	endpoints, err := peer.routes.ResolveConsensusEndpoints(
		ctx,
		peer.deviceID,
	)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, endpoint := range endpoints {
		raw, err := peer.routes.DialConsensusEndpoint(ctx, endpoint)
		if err != nil || raw == nil {
			if raw != nil {
				_ = raw.Close()
			}
			if err != nil {
				failures = append(failures, err)
			}
			continue
		}
		admission, err := bootstrapContentAdmission(
			journal,
			peer,
			remoteAuthorization,
			options.Now,
		)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		tlsConfig, err := transport.NewClientTLSConfig(
			transport.ClientTLSOptions{
				Plane:             transport.PlaneContent,
				Certificate:       localCertificate,
				VerifyContentPeer: admission.Verify,
			},
		)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		client, err := contenthttp.OpenClient(
			ctx,
			tls.Client(raw, tlsConfig),
			peer.deviceID,
			admission,
		)
		if err != nil {
			clearClientTLSConfig(tlsConfig)
			failures = append(failures, err)
			continue
		}
		return &contentConnection{
			client:    client,
			tlsConfig: tlsConfig,
			endpoint:  endpoint,
		}, nil
	}
	return nil, errors.Join(
		append([]error{ErrBootstrapUnavailable}, failures...)...,
	)
}

func (connection *contentConnection) Close() error {
	if connection == nil {
		return nil
	}
	var result error
	if connection.client != nil {
		result = connection.client.Close()
	}
	clearClientTLSConfig(connection.tlsConfig)
	connection.client = nil
	connection.tlsConfig = nil
	return result
}

func bootstrapContentAdmission(
	journal pendingJournal,
	peer bootstrapPeer,
	authorization credentialauthorization.Authorization,
	now func() time.Time,
) (*transport.ContentAdmissionRecorder, error) {
	if now == nil ||
		authorization.DeviceID != peer.deviceID ||
		authorization.SessionID != journal.SessionID {
		return nil, ErrBootstrapMismatch
	}
	return transport.NewContentAdmissionRecorder(
		func(
			certificate transport.ContentCertificate,
		) (transport.ContentPeerAdmission, error) {
			current := now()
			if current.IsZero() ||
				certificate.Binding.DeviceID !=
					peer.deviceID ||
				certificate.VerifyAuthorization(
					authorization,
					current,
				) != nil {
				return transport.ContentPeerAdmission{},
					ErrBootstrapMismatch
			}
			closeAfter, err := certificate.CloseAfter(current)
			if err != nil {
				return transport.ContentPeerAdmission{}, err
			}
			return transport.ContentPeerAdmission{
				CloseAfter: closeAfter,
			}, nil
		},
	)
}

func installLatestSnapshot(
	ctx context.Context,
	options Options,
	journal *pendingJournal,
	peer bootstrapPeer,
	status consensus.ConsensusStatusResult,
	authorization credentialauthorization.Authorization,
	content *contentConnection,
	contentCertificate tls.Certificate,
	bootID domain.UUIDv7,
) (resultErr error) {
	if journal == nil {
		return ErrBootstrapMismatch
	}
	root, err := waitForSnapshot(
		ctx,
		content.client,
		*journal,
		peer,
		authorization.AuthorizationChainIndex,
	)
	if err != nil {
		return err
	}
	if err := recordSnapshotInstallation(
		options.StatePath,
		journal,
		peer,
		authorization.AuthorizationChainIndex,
		root,
	); err != nil {
		return err
	}
	boundaries, err := consensus.NewFreshDeviceLogicalSnapshotBoundaryVerifier(
		status.GenerationZeroState,
		journal.RecoveryGeneration,
		chain.Digest(journal.SignedGenesisDigest),
	)
	if err != nil {
		return err
	}
	scratch, err := newSnapshotScratch(options.StatePath)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, scratch.Close())
	}()

	var bulk *bulkConnection
	defer func() {
		if bulk != nil {
			resultErr = errors.Join(resultErr, bulk.Close())
		}
	}()
	openBulk := func(
		openContext context.Context,
	) (*contenthttp.SnapshotBulkClient, error) {
		if bulk != nil {
			return bulk.client, nil
		}
		var err error
		bulk, err = openSnapshotBulk(
			openContext,
			options,
			*journal,
			peer,
			content.endpoint,
			contentCertificate,
			status.ContentCredentialAuthorization,
			root,
		)
		if err != nil {
			return nil, err
		}
		return bulk.client, nil
	}
	verified, err := consensus.VerifyAndStageLogicalSnapshot(
		ctx,
		root,
		consensus.LogicalSnapshotImportOptions{
			ExpandedArtifact: scratch.expanded,
			SequenceScratch:  scratch.sequence,
			BoundaryScratch:  scratch.boundary,
			OpenPage: func(
				openContext context.Context,
				index uint64,
			) (io.ReadCloser, error) {
				client, err := openBulk(openContext)
				if err != nil {
					return nil, err
				}
				page, err := client.SnapshotManifestPage(
					openContext,
					index,
				)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(
					bytes.NewReader(page.CanonicalBytes()),
				), nil
			},
			OpenChunk: func(
				openContext context.Context,
				index uint64,
			) (io.ReadCloser, error) {
				client, err := openBulk(openContext)
				if err != nil {
					return nil, err
				}
				chunk, err := client.SnapshotChunk(openContext, index)
				if err != nil {
					return nil, err
				}
				return io.NopCloser(
					bytes.NewReader(chunk.Bytes()),
				), nil
			},
			PreflightRoot: func(
				_ context.Context,
				candidate logicalsnapshot.Root,
			) error {
				return preflightSnapshotRoot(
					*journal,
					peer,
					authorization.AuthorizationChainIndex,
					candidate,
				)
			},
			StagePath:    scratch.stagePath,
			OriginBootID: bootID,
			Clock:        options.applyClock,
			Boundaries:   boundaries,
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, verified.Close())
	}()
	destination, err := openJoinDestination(
		ctx,
		options.StatePath,
		journal,
	)
	if err != nil {
		return err
	}
	verifiedAt, _, err := options.applyClock()
	if err != nil {
		_ = destination.Close()
		return err
	}
	installed, err := verified.InstallStandalone(
		ctx,
		destination,
		verifiedAt,
	)
	closeErr := destination.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err := validateInstalledCut(
		*journal,
		peer,
		root,
		installed,
	); err != nil {
		return err
	}
	completed, err := verifyCompletedState(
		ctx,
		options.StatePath,
		*journal,
		bootID,
	)
	if err != nil {
		return err
	}
	if !completed {
		return ErrStateConflict
	}
	return nil
}

func recordSnapshotInstallation(
	statePath string,
	journal *pendingJournal,
	peer bootstrapPeer,
	minimumAuthorizationCut uint64,
	root logicalsnapshot.Root,
) error {
	if journal == nil ||
		!peer.deviceID.Valid() ||
		len(peer.identityPublicKey) != ed25519.PublicKeySize ||
		minimumAuthorizationCut < 1 ||
		!domain.ValidUnsignedInteger(minimumAuthorizationCut) {
		return ErrStateConflict
	}
	canonical := root.CanonicalBytes()
	if preflightSnapshotRoot(
		*journal,
		peer,
		minimumAuthorizationCut,
		root,
	) != nil {
		return ErrBootstrapMismatch
	}
	switch journal.Phase {
	case journalPhaseDecisionApproved, journalPhaseConfirmed:
		journal.Phase = journalPhaseInstalling
	case journalPhaseInstalling, journalPhaseInstallingOwned:
	default:
		return ErrStateConflict
	}
	journal.SnapshotRoot = canonical
	journal.SnapshotSignerDeviceID = peer.deviceID
	copy(
		journal.SnapshotSignerPublicKey[:],
		peer.identityPublicKey,
	)
	journal.MinimumAuthorizationCut = minimumAuthorizationCut
	return writePendingJournal(statePath, *journal)
}

func openJoinDestination(
	ctx context.Context,
	statePath string,
	journal *pendingJournal,
) (*store.Store, error) {
	if ctx == nil || journal == nil {
		return nil, ErrStateConflict
	}
	switch journal.Phase {
	case journalPhaseDecisionApproved, journalPhaseConfirmed:
		return nil, ErrStateConflict
	case journalPhaseInstalling:
		if err := requireUnusedDestination(statePath); err != nil {
			return nil, err
		}
		journal.Phase = journalPhaseInstallingOwned
		if err := writePendingJournal(statePath, *journal); err != nil {
			return nil, err
		}
		fallthrough
	case journalPhaseInstallingOwned:
		info, err := os.Lstat(statePath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return openPrivateJoinStore(
				ctx,
				statePath,
				true,
			)
		case err != nil:
			return nil, err
		case !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0:
			return nil, ErrStateConflict
		default:
			if err := validateJournalFile(statePath, info); err != nil {
				return nil, errors.Join(ErrStateConflict, err)
			}
			return openPrivateJoinStore(ctx, statePath, false)
		}
	default:
		return nil, ErrStateConflict
	}
}

func openPrivateJoinStore(
	ctx context.Context,
	statePath string,
	requireNew bool,
) (*store.Store, error) {
	database, err := store.Open(
		ctx,
		store.Options{
			Path:       statePath,
			RequireNew: requireNew,
		},
	)
	if err != nil {
		return nil, err
	}
	info, statErr := os.Lstat(statePath)
	if statErr == nil &&
		(!info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0) {
		statErr = ErrStateConflict
	}
	if statErr == nil {
		statErr = validateJournalFile(statePath, info)
	}
	if statErr != nil {
		return nil, errors.Join(
			ErrStateConflict,
			statErr,
			database.Close(),
		)
	}
	return database, nil
}

func waitForSnapshot(
	ctx context.Context,
	client *contenthttp.Client,
	journal pendingJournal,
	peer bootstrapPeer,
	minimumChainIndex uint64,
) (logicalsnapshot.Root, error) {
	for {
		root, err := client.LatestSnapshot(ctx)
		if err == nil {
			if preflightErr := preflightSnapshotRoot(
				journal,
				peer,
				minimumChainIndex,
				root,
			); preflightErr == nil {
				return root, nil
			} else if !errors.Is(
				preflightErr,
				ErrBootstrapUnavailable,
			) {
				return logicalsnapshot.Root{}, preflightErr
			}
		} else if !errors.Is(err, contenthttp.ErrSnapshotNotFound) &&
			!errors.Is(err, contenthttp.ErrSnapshotUnavailable) {
			return logicalsnapshot.Root{}, err
		}
		timer := time.NewTimer(joinSnapshotRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return logicalsnapshot.Root{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func preflightSnapshotRoot(
	journal pendingJournal,
	peer bootstrapPeer,
	minimumChainIndex uint64,
	root logicalsnapshot.Root,
) error {
	if len(root.CanonicalBytes()) == 0 {
		return ErrBootstrapMismatch
	}
	input := root.Unsigned().Input()
	if input.SessionID != journal.SessionID ||
		input.WorkspaceID != journal.WorkspaceID ||
		input.RecoveryGeneration != journal.RecoveryGeneration ||
		input.SignerDeviceID != peer.deviceID {
		return ErrBootstrapMismatch
	}
	if input.ChainIndex < minimumChainIndex {
		return ErrBootstrapUnavailable
	}
	if input.ExpandedBytes > joinSnapshotMaxBytes ||
		input.CompressedBytes > joinSnapshotMaxBytes ||
		input.RecordCount > joinSnapshotMaxRecords ||
		input.ChunkCount > joinSnapshotMaxChunks ||
		input.DescriptorPageCount > joinSnapshotMaxPages ||
		input.RecoveryGeneration > joinSnapshotMaxGeneration {
		return ErrBootstrapMismatch
	}
	if err := logicalsnapshot.VerifyRoot(
		root,
		peer.identityPublicKey,
	); err != nil {
		return ErrBootstrapMismatch
	}
	return nil
}

func openSnapshotBulk(
	ctx context.Context,
	options Options,
	journal pendingJournal,
	peer bootstrapPeer,
	endpoint netip.AddrPort,
	localCertificate tls.Certificate,
	remoteAuthorization credentialauthorization.Authorization,
	root logicalsnapshot.Root,
) (*bulkConnection, error) {
	if peer.routes == nil {
		return nil, ErrBootstrapMismatch
	}
	raw, err := peer.routes.DialConsensusEndpoint(ctx, endpoint)
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, errors.Join(ErrBootstrapUnavailable, err)
	}
	admission, err := bootstrapContentAdmission(
		journal,
		peer,
		remoteAuthorization,
		options.Now,
	)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	tlsConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:             transport.PlaneContent,
			Certificate:       localCertificate,
			VerifyContentPeer: admission.Verify,
		},
	)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	client, err := contenthttp.OpenSnapshotBulkClient(
		ctx,
		tls.Client(raw, tlsConfig),
		peer.deviceID,
		admission,
		root,
	)
	if err != nil {
		clearClientTLSConfig(tlsConfig)
		return nil, err
	}
	return &bulkConnection{client: client, tlsConfig: tlsConfig}, nil
}

func (connection *bulkConnection) Close() error {
	if connection == nil {
		return nil
	}
	var result error
	if connection.client != nil {
		result = connection.client.Close()
	}
	clearClientTLSConfig(connection.tlsConfig)
	connection.client = nil
	connection.tlsConfig = nil
	return result
}

func validateInstalledCut(
	journal pendingJournal,
	peer bootstrapPeer,
	root logicalsnapshot.Root,
	installed store.StandaloneLogicalSnapshotInstallResult,
) error {
	input := root.Unsigned().Input()
	if installed.Cut.SessionID != journal.SessionID ||
		installed.Cut.WorkspaceID != journal.WorkspaceID ||
		installed.Cut.RecoveryGeneration != journal.RecoveryGeneration ||
		installed.Cut.SignerDeviceID != peer.deviceID ||
		installed.Cut.ChainIndex != input.ChainIndex ||
		installed.Cut.ResultIndex != input.ResultIndex ||
		installed.Cut.ChainHash != store.Digest(input.ChainHash) ||
		installed.Cut.ResultHash != store.Digest(input.ResultHash) ||
		installed.Cut.ProjectionAccumulator !=
			store.Digest(input.ProjectionAccumulator) ||
		installed.Cut.ProjectionStateDigest !=
			store.Digest(input.ProjectionStateDigest) {
		return ErrBootstrapMismatch
	}
	return nil
}

type snapshotScratch struct {
	directory string
	expanded  *os.File
	sequence  *os.File
	boundary  *os.File
	stagePath string
}

func newSnapshotScratch(statePath string) (_ *snapshotScratch, err error) {
	parent := filepath.Dir(statePath)
	if err := prepareJournalDirectory(statePath); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(parent, ".join-snapshot-*")
	if err != nil {
		return nil, err
	}
	scratch := &snapshotScratch{
		directory: directory,
		stagePath: filepath.Join(directory, "stage.db"),
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, scratch.Close())
		}
	}()
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if err := validateJournalDirectory(directory, directoryInfo); err != nil {
		return nil, err
	}
	for destination, name := range map[**os.File]string{
		&scratch.expanded: "expanded.bin",
		&scratch.sequence: "sequence.bin",
		&scratch.boundary: "boundary.bin",
	} {
		file, openErr := os.OpenFile(
			filepath.Join(directory, name),
			os.O_CREATE|os.O_EXCL|os.O_RDWR,
			0o600,
		)
		if openErr != nil {
			return nil, openErr
		}
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return nil, statErr
		}
		if validationErr := validateJournalFile(
			file.Name(),
			info,
		); validationErr != nil {
			_ = file.Close()
			return nil, validationErr
		}
		*destination = file
	}
	return scratch, nil
}

func (scratch *snapshotScratch) Close() error {
	if scratch == nil {
		return nil
	}
	var result error
	for _, file := range []*os.File{
		scratch.expanded,
		scratch.sequence,
		scratch.boundary,
	} {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	if scratch.directory != "" {
		result = errors.Join(result, os.RemoveAll(scratch.directory))
	}
	return result
}

func clearClientTLSConfig(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		clearTLSCertificate(&config.Certificates[index])
	}
	config.Certificates = nil
}
