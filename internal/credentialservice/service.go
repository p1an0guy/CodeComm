// Package credentialservice manages local content-credential rotation.
package credentialservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/consensus"
	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/discovery"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	rotationRetryInitial = time.Second
	rotationRetryMaximum = 30 * time.Second
	rotationPollInterval = 5 * time.Second
)

var (
	ErrInvalidOptions = errors.New(
		"credential service: invalid options",
	)
	ErrClosed = errors.New(
		"credential service: closed",
	)
	ErrCredentialIntegrity = errors.New(
		"credential service: credential integrity failure",
	)
)

// SecretStore is the protected native-store subset used for epoch keys.
type SecretStore interface {
	Get(context.Context, credentialstore.Reference) ([]byte, error)
	Create(context.Context, credentialstore.Reference, []byte) error
	Delete(context.Context, credentialstore.Reference) error
}

// Consensus is the identity-authenticated renewal boundary.
type Consensus interface {
	PeerAdmissionSnapshot() (*peerauth.Snapshot, error)
	RenewCredential(
		context.Context,
		credential.Binding,
	) (credentialauthorization.Authorization, error)
}

// BindingSigner signs one already-persisted epoch public key.
type BindingSigner func(
	context.Context,
	uint64,
	ed25519.PublicKey,
) (credential.Binding, error)

// Options contains the device-scoped rotation dependencies.
type Options struct {
	SessionID domain.UUIDv7
	DeviceID  domain.DeviceID
	Secrets   SecretStore
	Consensus Consensus
	Sign      BindingSigner
	// Now is the shared credential wall clock. Nil uses time.Now.
	Now func() time.Time
}

type serviceOptions struct {
	Options
	now          func() time.Time
	generateKey  func() (ed25519.PrivateKey, error)
	retryInitial time.Duration
	retryMaximum time.Duration
	pollInterval time.Duration
}

type retainedCertificate struct {
	authorization credentialauthorization.Authorization
	certificate   tls.Certificate
}

// Service owns candidate-key persistence, renewal retries, and the current
// local content-certificate provider.
type Service struct {
	sessionID domain.UUIDv7
	deviceID  domain.DeviceID
	secrets   SecretStore
	consensus Consensus
	sign      BindingSigner

	now          func() time.Time
	generateKey  func() (ed25519.PrivateKey, error)
	retryInitial time.Duration
	retryMaximum time.Duration
	pollInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	done   chan struct{}

	startMu sync.Mutex
	started bool
	closed  bool
	// shutdownInactive retains the immutable applied cut captured before the
	// consensus owner closes. Wait uses it after the renewal worker exits so a
	// self-revocation cannot race durable epoch-key erasure.
	shutdownInactive *peerauth.Snapshot

	stateMu                sync.RWMutex
	certificates           map[uint64]retainedCertificate
	provisionalCertificate *retainedCertificate
	fatalErr               error

	closeOnce sync.Once
	closeErr  error
}

// New validates dependencies without performing native-store or network I/O.
func New(options Options) (*Service, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return newService(serviceOptions{
		Options:      options,
		now:          now,
		generateKey:  generateEpochKey,
		retryInitial: rotationRetryInitial,
		retryMaximum: rotationRetryMaximum,
		pollInterval: rotationPollInterval,
	})
}

func newService(options serviceOptions) (*Service, error) {
	if !options.SessionID.Valid() ||
		!options.DeviceID.Valid() ||
		nilInterface(options.Secrets) ||
		nilInterface(options.Consensus) ||
		options.Sign == nil ||
		options.now == nil ||
		options.generateKey == nil ||
		options.retryInitial <= 0 ||
		options.retryMaximum < options.retryInitial ||
		options.pollInterval <= 0 {
		return nil, ErrInvalidOptions
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		sessionID:    options.SessionID,
		deviceID:     options.DeviceID,
		secrets:      options.Secrets,
		consensus:    options.Consensus,
		sign:         options.Sign,
		now:          options.now,
		generateKey:  options.generateKey,
		retryInitial: options.retryInitial,
		retryMaximum: options.retryMaximum,
		pollInterval: options.pollInterval,
		ctx:          ctx,
		cancel:       cancel,
		wake:         make(chan struct{}, 1),
		done:         make(chan struct{}),
		certificates: make(map[uint64]retainedCertificate, 2),
	}, nil
}

// Recover loads usable retained keys before starting the retry worker. A
// missing epoch key closes only the content plane; the worker renews when the
// committed renewal floor permits it.
func (service *Service) Recover(ctx context.Context) error {
	if service == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.startMu.Lock()
	defer service.startMu.Unlock()
	if service.closed {
		return ErrClosed
	}
	if service.started {
		return ErrInvalidOptions
	}
	snapshot, err := service.consensus.PeerAdmissionSnapshot()
	if err != nil {
		return fmt.Errorf("%w: load applied admission: %v", ErrInvalidOptions, err)
	}
	if err := service.refreshCertificates(ctx, snapshot); err != nil {
		return err
	}
	service.started = true
	go service.run()
	service.signal()
	return nil
}

// ContentCertificate returns a private copy of the greatest locally active
// retained epoch. Missing, future, and expired epochs fail closed.
func (service *Service) ContentCertificate() (tls.Certificate, error) {
	if service == nil {
		return tls.Certificate{}, transport.ErrContentCertificateUnavailable
	}
	now := service.now()
	service.stateMu.RLock()
	if service.fatalErr != nil || now.IsZero() {
		service.stateMu.RUnlock()
		return tls.Certificate{}, transport.ErrContentCertificateUnavailable
	}
	var selected *retainedCertificate
	for _, retained := range service.certificates {
		if !retained.authorization.ActiveAt(now) {
			continue
		}
		if selected == nil ||
			retained.authorization.Epoch >
				selected.authorization.Epoch {
			value := retained
			selected = &value
		}
	}
	if provisional := service.provisionalCertificate; provisional != nil &&
		provisional.authorization.ActiveAt(now) &&
		(selected == nil ||
			provisional.authorization.Epoch >
				selected.authorization.Epoch) {
		value := *provisional
		selected = &value
	}
	if selected == nil {
		service.stateMu.RUnlock()
		return tls.Certificate{}, transport.ErrContentCertificateUnavailable
	}
	certificate := cloneTLSCertificate(selected.certificate)
	service.stateMu.RUnlock()
	return certificate, nil
}

// DiscoveryAdvertisement signs one fresh bounded multicast datagram with the
// greatest active epoch, or the latest retained epoch after expiry.
func (service *Service) DiscoveryAdvertisement(
	httpsPort uint16,
) ([]byte, error) {
	if service == nil || httpsPort == 0 {
		return nil, discovery.ErrInvalidAdvertisement
	}
	now := service.now()
	if now.IsZero() {
		return nil, discovery.ErrInvalidAdvertisement
	}
	service.stateMu.RLock()
	if service.fatalErr != nil {
		service.stateMu.RUnlock()
		return nil, discovery.ErrInvalidAdvertisement
	}
	var selected *retainedCertificate
	for _, retained := range service.certificates {
		if selected == nil {
			value := retained
			selected = &value
			continue
		}
		retainedActive := retained.authorization.ActiveAt(now)
		selectedActive := selected.authorization.ActiveAt(now)
		if retainedActive && !selectedActive ||
			retainedActive == selectedActive &&
				retained.authorization.Epoch >
					selected.authorization.Epoch {
			value := retained
			selected = &value
		}
	}
	if provisional := service.provisionalCertificate; provisional != nil {
		provisionalActive := provisional.authorization.ActiveAt(now)
		selectedActive := selected != nil &&
			selected.authorization.ActiveAt(now)
		if selected == nil ||
			provisionalActive && !selectedActive ||
			provisionalActive == selectedActive &&
				provisional.authorization.Epoch >
					selected.authorization.Epoch {
			value := *provisional
			selected = &value
		}
	}
	if selected == nil {
		service.stateMu.RUnlock()
		return nil, discovery.ErrInvalidAdvertisement
	}
	privateKey, ok := selected.certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		service.stateMu.RUnlock()
		return nil, discovery.ErrInvalidAdvertisement
	}
	privateKey = ed25519.PrivateKey(bytes.Clone(privateKey))
	authorization := selected.authorization.Clone()
	service.stateMu.RUnlock()
	defer clear(privateKey)

	expiresAt, err := discovery.AdvertisementExpiresAt(now)
	if err != nil {
		return nil, err
	}
	advertisement, err := discovery.NewAdvertisement(
		service.sessionID,
		httpsPort,
		authorization.Epoch,
		authorization.KeyDigest,
		expiresAt,
	)
	if err != nil {
		return nil, err
	}
	return discovery.SignAdvertisement(advertisement, privateKey)
}

// NotifyConnectivityChange schedules an immediate bounded renewal attempt.
func (service *Service) NotifyConnectivityChange() {
	if service == nil {
		return
	}
	service.signal()
}

// FatalError reports a local integrity or protected-store failure.
func (service *Service) FatalError() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.stateMu.RLock()
	defer service.stateMu.RUnlock()
	return service.fatalErr
}

// BeginClose stops new work without waiting for an in-flight renewal.
func (service *Service) BeginClose() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.startMu.Lock()
	if service.closed {
		service.startMu.Unlock()
		return nil
	}
	snapshot, err := service.consensus.PeerAdmissionSnapshot()
	if err == nil && snapshot != nil {
		member, exists := snapshot.Member(service.deviceID)
		if exists && member.Status != device.StatusActive {
			service.shutdownInactive = snapshot
		}
	}
	service.closed = true
	started := service.started
	service.cancel()
	if !started {
		close(service.done)
	}
	service.startMu.Unlock()
	return nil
}

// Wait joins the worker and clears every in-memory epoch-key copy.
func (service *Service) Wait() error {
	if err := service.BeginClose(); err != nil {
		return err
	}
	<-service.done
	service.closeOnce.Do(func() {
		service.startMu.Lock()
		inactive := service.shutdownInactive
		service.shutdownInactive = nil
		service.startMu.Unlock()
		if inactive != nil {
			service.closeErr = service.eraseInactiveMemberKeys(
				context.Background(),
				inactive,
			)
		}
		service.stateMu.Lock()
		clearRetainedCertificates(service.certificates)
		clear(service.certificates)
		clearRetainedCertificate(service.provisionalCertificate)
		service.provisionalCertificate = nil
		service.stateMu.Unlock()
	})
	return service.closeErr
}

// Close stops and joins the service.
func (service *Service) Close() error {
	return service.Wait()
}

func (service *Service) run() {
	defer close(service.done)
	retry := service.retryInitial
	delay := time.Duration(0)
	for {
		if !service.wait(delay) {
			return
		}
		next, transient, fatal := service.reconcile(service.ctx)
		if fatal != nil {
			service.setFatal(fatal)
			return
		}
		if transient != nil {
			delay = retry
			retry = min(retry*2, service.retryMaximum)
			continue
		}
		retry = service.retryInitial
		delay = service.pollInterval
		now := service.now()
		if !next.IsZero() && !now.IsZero() {
			until := next.Sub(now)
			if until <= 0 {
				delay = 0
			} else if until < delay {
				delay = until
			}
		}
	}
}

func (service *Service) wait(delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-service.ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-service.ctx.Done():
		return false
	case <-service.wake:
		return true
	case <-timer.C:
		return true
	}
}

func (service *Service) reconcile(
	ctx context.Context,
) (time.Time, error, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err, nil
	}
	now := service.now()
	if now.IsZero() {
		return time.Time{}, nil, ErrCredentialIntegrity
	}
	snapshot, err := service.consensus.PeerAdmissionSnapshot()
	if err != nil {
		return time.Time{}, err, nil
	}
	if err := service.refreshCertificates(ctx, snapshot); err != nil {
		return time.Time{}, nil, err
	}
	member, exists := snapshot.Member(service.deviceID)
	if !exists ||
		member.ID != service.deviceID ||
		member.Status != device.StatusActive {
		return time.Time{}, nil, nil
	}
	sessionID, _, valid := snapshot.Lineage()
	if !valid || sessionID != service.sessionID {
		return time.Time{}, nil, ErrCredentialIntegrity
	}
	currentEpoch, exists := snapshot.CurrentCredentialEpoch(service.deviceID)
	if !exists || !domain.ValidUnsignedInteger(currentEpoch) {
		return time.Time{}, nil, ErrCredentialIntegrity
	}
	pending, err := service.provisionalAwaitingApply(currentEpoch, now)
	if err != nil {
		return time.Time{}, nil, err
	}
	if pending {
		return time.Time{}, nil, nil
	}
	nextEpoch := uint64(1)
	var renewalAt time.Time
	if currentEpoch != 0 {
		if currentEpoch == domain.MaxSafeInteger {
			return time.Time{}, nil, ErrCredentialIntegrity
		}
		current, found := snapshot.Authorization(
			credentialauthorization.Key{
				SessionID: service.sessionID,
				DeviceID:  service.deviceID,
				Epoch:     currentEpoch,
			},
		)
		if !found || current.Validate() != nil {
			return time.Time{}, nil, ErrCredentialIntegrity
		}
		notBefore, timeErr := current.NotBefore.Time()
		if timeErr != nil {
			return time.Time{}, nil, ErrCredentialIntegrity
		}
		renewalAt = notBefore.Add(
			time.Duration(
				credentialauthorization.ValiditySeconds-
					credentialauthorization.RenewalLeadSeconds,
			) * time.Second,
		)
		if now.Before(renewalAt) {
			return renewalAt, nil, nil
		}
		nextEpoch = currentEpoch + 1
	}

	privateKey, err := service.loadOrCreateCandidate(ctx, nextEpoch)
	if err != nil {
		return time.Time{}, nil, err
	}
	defer clear(privateKey)
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf(
			"%w: candidate key: %v",
			ErrCredentialIntegrity,
			err,
		)
	}
	binding, err := service.sign(
		ctx,
		nextEpoch,
		ed25519.PublicKey(publicKey),
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return time.Time{}, ctxErr, nil
		}
		return time.Time{}, nil, fmt.Errorf(
			"%w: sign binding: %v",
			ErrCredentialIntegrity,
			err,
		)
	}
	if binding.SessionID != service.sessionID ||
		binding.DeviceID != service.deviceID ||
		binding.Epoch != nextEpoch ||
		!bytes.Equal(binding.EpochPublicKey[:], publicKey) ||
		binding.Validate(member.IdentityPublicKey) != nil {
		return time.Time{}, nil, ErrCredentialIntegrity
	}
	authorization, err := service.consensus.RenewCredential(ctx, binding)
	if err != nil {
		transient, fatal := classifyRenewalError(err)
		return time.Time{}, transient, fatal
	}
	if err := validateRenewalResponse(binding, authorization); err != nil {
		return time.Time{}, nil, err
	}
	if err := service.installProvisionalCertificate(
		privateKey,
		authorization,
	); err != nil {
		return time.Time{}, nil, err
	}
	return time.Time{}, nil, nil
}

func (service *Service) refreshCertificates(
	ctx context.Context,
	snapshot *peerauth.Snapshot,
) error {
	if snapshot == nil {
		return ErrCredentialIntegrity
	}
	sessionID, _, valid := snapshot.Lineage()
	if !valid || sessionID != service.sessionID {
		return ErrCredentialIntegrity
	}
	member, exists := snapshot.Member(service.deviceID)
	if !exists {
		service.replaceCertificates(nil)
		service.clearProvisionalCertificate()
		return ErrCredentialIntegrity
	}
	if member.Status != device.StatusActive {
		return service.eraseInactiveMemberKeys(ctx, snapshot)
	}
	currentEpoch, exists := snapshot.CurrentCredentialEpoch(service.deviceID)
	if !exists || !domain.ValidUnsignedInteger(currentEpoch) {
		return ErrCredentialIntegrity
	}
	if currentEpoch == 0 {
		service.replaceCertificates(nil)
		return nil
	}

	desired := make(
		map[uint64]credentialauthorization.Authorization,
		2,
	)
	now := service.now()
	if now.IsZero() {
		return ErrCredentialIntegrity
	}
	first := currentEpoch
	if first > 1 {
		first--
	}
	for epoch := first; epoch <= currentEpoch; epoch++ {
		authorization, found := snapshot.Authorization(
			credentialauthorization.Key{
				SessionID: service.sessionID,
				DeviceID:  service.deviceID,
				Epoch:     epoch,
			},
		)
		if !found || authorization.Validate() != nil {
			return ErrCredentialIntegrity
		}
		if epoch == currentEpoch || authorization.ActiveAt(now) {
			desired[epoch] = authorization
		}
	}
	provisionalCommitted, err := service.reconcileProvisionalCertificate(
		snapshot,
		currentEpoch,
	)
	if err != nil {
		return err
	}

	service.stateMu.RLock()
	existing := make(
		map[uint64]retainedCertificate,
		len(service.certificates),
	)
	for epoch, retained := range service.certificates {
		existing[epoch] = retainedCertificate{
			authorization: retained.authorization.Clone(),
			certificate:   cloneTLSCertificate(retained.certificate),
		}
	}
	service.stateMu.RUnlock()
	defer clearRetainedCertificates(existing)

	next := make(map[uint64]retainedCertificate, len(desired))
	for epoch, authorization := range desired {
		if retained, found := existing[epoch]; found &&
			reflect.DeepEqual(
				retained.authorization,
				authorization,
			) {
			next[epoch] = retainedCertificate{
				authorization: retained.authorization.Clone(),
				certificate: cloneTLSCertificate(
					retained.certificate,
				),
			}
			continue
		}
		reference, err := credentialstore.EpochReference(
			service.sessionID,
			service.deviceID,
			epoch,
		)
		if err != nil {
			clearRetainedCertificates(next)
			return ErrCredentialIntegrity
		}
		privateKey, err := service.secrets.Get(ctx, reference)
		if errors.Is(err, credentialstore.ErrNotFound) {
			continue
		}
		if err != nil {
			clearRetainedCertificates(next)
			return fmt.Errorf(
				"%w: load epoch %d: %v",
				ErrCredentialIntegrity,
				epoch,
				err,
			)
		}
		certificate, _, issueErr := transport.IssueContentCertificate(
			authorization,
			privateKey,
		)
		clear(privateKey)
		if issueErr != nil {
			clearRetainedCertificates(next)
			return fmt.Errorf(
				"%w: issue epoch %d certificate: %v",
				ErrCredentialIntegrity,
				epoch,
				issueErr,
			)
		}
		next[epoch] = retainedCertificate{
			authorization: authorization.Clone(),
			certificate:   certificate,
		}
	}
	service.replaceCertificates(next)
	if provisionalCommitted {
		service.clearProvisionalCertificate()
	}

	obsolete := make([]uint64, 0, 2)
	if currentEpoch > 2 {
		obsolete = append(obsolete, currentEpoch-2)
	}
	if currentEpoch > 1 {
		if _, retained := desired[currentEpoch-1]; !retained {
			obsolete = append(obsolete, currentEpoch-1)
		}
	}
	for _, epoch := range obsolete {
		reference, err := credentialstore.EpochReference(
			service.sessionID,
			service.deviceID,
			epoch,
		)
		if err != nil {
			return ErrCredentialIntegrity
		}
		if err := service.secrets.Delete(ctx, reference); err != nil &&
			!errors.Is(err, credentialstore.ErrNotFound) {
			return fmt.Errorf(
				"%w: erase epoch %d: %v",
				ErrCredentialIntegrity,
				epoch,
				err,
			)
		}
	}
	return nil
}

func (service *Service) eraseInactiveMemberKeys(
	ctx context.Context,
	snapshot *peerauth.Snapshot,
) error {
	service.replaceCertificates(nil)
	service.clearProvisionalCertificate()

	currentEpoch, exists := snapshot.CurrentCredentialEpoch(service.deviceID)
	if !exists || !domain.ValidUnsignedInteger(currentEpoch) {
		return ErrCredentialIntegrity
	}
	epochs := make(map[uint64]struct{}, 3)
	if currentEpoch == 0 {
		epochs[1] = struct{}{}
	} else {
		epochs[currentEpoch] = struct{}{}
		if currentEpoch > 1 {
			epochs[currentEpoch-1] = struct{}{}
		}
		if currentEpoch < domain.MaxSafeInteger {
			epochs[currentEpoch+1] = struct{}{}
		}
	}
	for epoch := range epochs {
		reference, err := credentialstore.EpochReference(
			service.sessionID,
			service.deviceID,
			epoch,
		)
		if err != nil {
			return ErrCredentialIntegrity
		}
		if err := service.secrets.Delete(ctx, reference); err != nil &&
			!errors.Is(err, credentialstore.ErrNotFound) {
			return fmt.Errorf(
				"%w: erase inactive-member epoch %d: %v",
				ErrCredentialIntegrity,
				epoch,
				err,
			)
		}
	}
	return nil
}

func (service *Service) loadOrCreateCandidate(
	ctx context.Context,
	epoch uint64,
) (ed25519.PrivateKey, error) {
	reference, err := credentialstore.EpochReference(
		service.sessionID,
		service.deviceID,
		epoch,
	)
	if err != nil {
		return nil, ErrCredentialIntegrity
	}
	stored, err := service.secrets.Get(ctx, reference)
	if err == nil {
		return ed25519.PrivateKey(stored), nil
	}
	if !errors.Is(err, credentialstore.ErrNotFound) {
		return nil, fmt.Errorf(
			"%w: load candidate epoch %d: %v",
			ErrCredentialIntegrity,
			epoch,
			err,
		)
	}
	privateKey, err := service.generateKey()
	if err != nil ||
		len(privateKey) != ed25519.PrivateKeySize {
		clear(privateKey)
		return nil, fmt.Errorf(
			"%w: generate candidate epoch %d",
			ErrCredentialIntegrity,
			epoch,
		)
	}
	if err := service.secrets.Create(ctx, reference, privateKey); err != nil {
		if !errors.Is(err, credentialstore.ErrAlreadyExists) {
			clear(privateKey)
			return nil, fmt.Errorf(
				"%w: persist candidate epoch %d: %v",
				ErrCredentialIntegrity,
				epoch,
				err,
			)
		}
		clear(privateKey)
		stored, err = service.secrets.Get(ctx, reference)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: reload candidate epoch %d: %v",
				ErrCredentialIntegrity,
				epoch,
				err,
			)
		}
		return ed25519.PrivateKey(stored), nil
	}
	result := ed25519.PrivateKey(bytes.Clone(privateKey))
	clear(privateKey)
	return result, nil
}

func validateRenewalResponse(
	binding credential.Binding,
	authorization credentialauthorization.Authorization,
) error {
	if authorization.Validate() != nil ||
		authorization.SessionID != binding.SessionID ||
		authorization.DeviceID != binding.DeviceID ||
		authorization.Epoch != binding.Epoch ||
		authorization.EpochPublicKey != binding.EpochPublicKey ||
		authorization.KeyDigest != binding.KeyDigest ||
		authorization.BindingSignature != binding.Signature {
		return ErrCredentialIntegrity
	}
	return nil
}

func (service *Service) installProvisionalCertificate(
	privateKey ed25519.PrivateKey,
	authorization credentialauthorization.Authorization,
) error {
	if service == nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		authorization.Validate() != nil ||
		authorization.SessionID != service.sessionID ||
		authorization.DeviceID != service.deviceID {
		return ErrCredentialIntegrity
	}
	certificate, _, err := transport.IssueContentCertificate(
		authorization,
		privateKey,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: issue provisional epoch %d certificate: %v",
			ErrCredentialIntegrity,
			authorization.Epoch,
			err,
		)
	}
	next := &retainedCertificate{
		authorization: authorization.Clone(),
		certificate:   certificate,
	}
	service.stateMu.Lock()
	previous := service.provisionalCertificate
	service.provisionalCertificate = next
	service.stateMu.Unlock()
	clearRetainedCertificate(previous)
	return nil
}

func (service *Service) reconcileProvisionalCertificate(
	snapshot *peerauth.Snapshot,
	currentEpoch uint64,
) (bool, error) {
	service.stateMu.RLock()
	provisional := cloneRetainedCertificate(service.provisionalCertificate)
	service.stateMu.RUnlock()
	if provisional == nil {
		return false, nil
	}
	defer clearRetainedCertificate(provisional)
	if provisional.authorization.Epoch > currentEpoch {
		if provisional.authorization.Epoch != currentEpoch+1 {
			return false, ErrCredentialIntegrity
		}
		return false, nil
	}
	committed, found := snapshot.Authorization(
		provisional.authorization.PrimaryKey(),
	)
	if !found ||
		!reflect.DeepEqual(committed, provisional.authorization) {
		return false, ErrCredentialIntegrity
	}
	return true, nil
}

func (service *Service) provisionalAwaitingApply(
	currentEpoch uint64,
	now time.Time,
) (bool, error) {
	service.stateMu.RLock()
	provisional := cloneRetainedCertificate(service.provisionalCertificate)
	service.stateMu.RUnlock()
	if provisional == nil {
		return false, nil
	}
	defer clearRetainedCertificate(provisional)
	if currentEpoch == domain.MaxSafeInteger ||
		provisional.authorization.Epoch != currentEpoch+1 {
		return false, ErrCredentialIntegrity
	}
	notBefore, err := provisional.authorization.NotBefore.Time()
	if err != nil {
		return false, ErrCredentialIntegrity
	}
	expiresAt := notBefore.Add(
		time.Duration(provisional.authorization.ValiditySeconds) *
			time.Second,
	)
	if now.Before(expiresAt) {
		return true, nil
	}
	service.clearProvisionalCertificate()
	return false, nil
}

func classifyRenewalError(err error) (transient, fatal error) {
	if err == nil {
		return nil, nil
	}
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, consensus.ErrCredentialRenewalUnavailable):
		return err, nil
	case errors.Is(err, consensus.ErrInvalidCredentialRenewal),
		errors.Is(err, consensus.ErrCredentialRenewalRejected),
		errors.Is(err, consensus.ErrCredentialRenewalMismatch),
		errors.Is(err, consensus.ErrInvalidCredentialBinding):
		return nil, fmt.Errorf(
			"%w: renewal response: %w",
			ErrCredentialIntegrity,
			err,
		)
	default:
		return err, nil
	}
}

func (service *Service) clearProvisionalCertificate() {
	if service == nil {
		return
	}
	service.stateMu.Lock()
	previous := service.provisionalCertificate
	service.provisionalCertificate = nil
	service.stateMu.Unlock()
	clearRetainedCertificate(previous)
}

func (service *Service) replaceCertificates(
	next map[uint64]retainedCertificate,
) {
	if next == nil {
		next = make(map[uint64]retainedCertificate)
	}
	service.stateMu.Lock()
	old := service.certificates
	service.certificates = next
	service.stateMu.Unlock()
	clearRetainedCertificates(old)
}

func (service *Service) setFatal(err error) {
	if err == nil {
		return
	}
	service.stateMu.Lock()
	if service.fatalErr == nil {
		service.fatalErr = err
		clearRetainedCertificates(service.certificates)
		clear(service.certificates)
		clearRetainedCertificate(service.provisionalCertificate)
		service.provisionalCertificate = nil
	}
	service.stateMu.Unlock()
}

func (service *Service) signal() {
	select {
	case service.wake <- struct{}{}:
	default:
	}
}

func generateEpochKey() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	return privateKey, err
}

func cloneTLSCertificate(certificate tls.Certificate) tls.Certificate {
	result := tls.Certificate{
		Certificate: make([][]byte, len(certificate.Certificate)),
		Leaf:        certificate.Leaf,
	}
	for index, value := range certificate.Certificate {
		result.Certificate[index] = bytes.Clone(value)
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		result.PrivateKey = ed25519.PrivateKey(bytes.Clone(privateKey))
	} else {
		result.PrivateKey = certificate.PrivateKey
	}
	return result
}

func cloneRetainedCertificate(
	value *retainedCertificate,
) *retainedCertificate {
	if value == nil {
		return nil
	}
	return &retainedCertificate{
		authorization: value.authorization.Clone(),
		certificate:   cloneTLSCertificate(value.certificate),
	}
}

func clearRetainedCertificate(value *retainedCertificate) {
	if value == nil {
		return
	}
	clearTLSCertificate(&value.certificate)
	*value = retainedCertificate{}
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(privateKey)
	}
	*certificate = tls.Certificate{}
}

func clearRetainedCertificates(
	certificates map[uint64]retainedCertificate,
) {
	for epoch, retained := range certificates {
		clearTLSCertificate(&retained.certificate)
		delete(certificates, epoch)
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ transport.ContentCertificateProvider = (&Service{}).ContentCertificate
