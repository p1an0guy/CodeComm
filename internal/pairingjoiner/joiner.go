// Package pairingjoiner orchestrates the joiner side of one exporter-bound
// pairing attempt. It persists nothing; callers retain ownership of durable
// identity and epoch keys.
package pairingjoiner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/credential"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/pairinghttp"
	"github.com/ijonahch/codecomm/internal/transport"
)

const (
	endpointAttemptTimeout = transport.HandshakeTimeout
	overallAttemptTimeout  = pairing.InviteTTL
	confirmationPollDelay  = time.Second
)

var (
	ErrInvalidOptions       = errors.New("pairing joiner: invalid options")
	ErrInviteUnavailable    = errors.New("pairing joiner: invite is unavailable")
	ErrIdentityMismatch     = errors.New("pairing joiner: identity does not match invite")
	ErrEndpointsUnavailable = errors.New("pairing joiner: all invite endpoints are unavailable")
	ErrAlreadyStarted       = errors.New("pairing joiner: attempt already started")
	ErrReviewUnavailable    = errors.New("pairing joiner: review is unavailable")
	ErrDecisionAlreadyMade  = errors.New("pairing joiner: local decision already made")
	ErrClosed               = errors.New("pairing joiner: closed")
	ErrUnexpectedStatus     = errors.New("pairing joiner: unexpected confirmation status")
)

// EndpointDialer dials one exact invite endpoint using the caller's selected
// local source and interface policy.
type EndpointDialer interface {
	DialPairingEndpoint(context.Context, netip.AddrPort) (net.Conn, error)
}

// EndpointDialerFunc adapts a function to EndpointDialer.
type EndpointDialerFunc func(context.Context, netip.AddrPort) (net.Conn, error)

// DialPairingEndpoint calls the adapted function.
func (function EndpointDialerFunc) DialPairingEndpoint(
	ctx context.Context,
	endpoint netip.AddrPort,
) (net.Conn, error) {
	if function == nil {
		return nil, ErrEndpointsUnavailable
	}
	return function(ctx, endpoint)
}

// Options contains caller-persisted key material and immutable attempt input.
// New clones private keys and never clears or otherwise mutates these slices.
type Options struct {
	Invite                 pairing.SignedInvite
	IdentityPrivateKey     []byte
	InitialEpochPrivateKey []byte
	AttemptID              domain.UUIDv7
	DaemonVersion          string
	MaxApplyLevel          uint64
	Dialer                 EndpointDialer
}

// ReviewSubject is the exact immutable subject the joiner operator approves or
// declines after comparing SAS with the inviter.
type ReviewSubject struct {
	AttemptID                domain.UUIDv7
	InviteID                 domain.UUIDv7
	InviteDigest             [sha256.Size]byte
	RequestDigest            [sha256.Size]byte
	SessionID                domain.UUIDv7
	WorkspaceID              domain.UUIDv4
	RecoveryGeneration       uint64
	CreatedAt                domain.WholeSecondTimestamp
	ExpiresAt                domain.WholeSecondTimestamp
	Mode                     pairing.Mode
	SubjectDeviceID          *domain.DeviceID
	ExpectedEntityVersion    *uint64
	Role                     device.Role
	InviterDeviceID          domain.DeviceID
	InviterIdentityPublicKey [ed25519.PublicKeySize]byte
	SignedGenesisDigest      [sha256.Size]byte
	Core                     pairing.RequestCore
	SAS                      string
	ConnectedEndpoint        netip.AddrPort
}

// Result is the inviter's exact terminal response paired with the immutable
// subject that the local operator reviewed.
type Result struct {
	Review       ReviewSubject
	Confirmation pairing.ConfirmationResult
}

type pairingClient interface {
	Request(
		context.Context,
		pairing.SignedInvite,
		pairing.CanonicalRequestCore,
	) (pairinghttp.RequestResult, error)
	Confirm(
		context.Context,
		pairing.Confirmation,
	) (pairing.ConfirmationResult, error)
	Close() error
}

type clientOpener func(context.Context, *tls.Conn) (pairingClient, error)

type waitFunction func(context.Context, time.Duration) error

type runtimeOptions struct {
	now                    func() time.Time
	openClient             clientOpener
	wait                   waitFunction
	endpointAttemptTimeout time.Duration
	overallAttemptTimeout  time.Duration
	confirmationPollDelay  time.Duration
}

type lifecycleState uint8

const (
	stateReady lifecycleState = iota
	stateBeginning
	stateReview
	stateDeciding
	stateClosed
)

// Joiner owns one bounded pairing attempt and one exporter-bound connection.
// Begin and Decide are each single-use. Close may be called concurrently.
type Joiner struct {
	operationMu sync.Mutex
	mu          sync.Mutex

	state          lifecycleState
	closeRequested bool
	decisionMade   bool

	invite       pairing.SignedInvite
	inviteValue  pairing.Invite
	core         pairing.CanonicalRequestCore
	dialer       EndpointDialer
	runtime      runtimeOptions
	tlsConfig    *tls.Config
	client       pairingClient
	review       ReviewSubject
	operationCtx context.Context
	cancel       context.CancelFunc
	stopClose    func() bool
}

// New validates and snapshots one pairing attempt. The invite signature,
// lifetime, mode, identity/device relation, epoch key, binding, and TLS
// certificate are all checked before a Joiner is returned.
func New(options Options) (*Joiner, error) {
	return newJoiner(options, defaultRuntimeOptions())
}

func newJoiner(
	options Options,
	runtime runtimeOptions,
) (_ *Joiner, err error) {
	if runtime.now == nil || runtime.openClient == nil || runtime.wait == nil ||
		runtime.endpointAttemptTimeout <= 0 ||
		runtime.overallAttemptTimeout <= 0 ||
		runtime.confirmationPollDelay <= 0 ||
		nilInterface(options.Dialer) ||
		!options.AttemptID.Valid() ||
		!device.ValidDaemonVersion(options.DaemonVersion) ||
		options.MaxApplyLevel < 1 ||
		options.MaxApplyLevel > domain.MaxApplyLevel {
		return nil, ErrInvalidOptions
	}
	if err := options.Invite.Validate(); err != nil {
		return nil, errors.Join(ErrInviteUnavailable, err)
	}
	if err := options.Invite.ValidateTime(runtime.now()); err != nil {
		return nil, errors.Join(ErrInviteUnavailable, err)
	}

	identityPrivateKey := bytes.Clone(options.IdentityPrivateKey)
	defer clear(identityPrivateKey)
	epochPrivateKey := bytes.Clone(options.InitialEpochPrivateKey)
	defer clear(epochPrivateKey)
	identityPublicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		identityPrivateKey,
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	defer clear(identityPublicKey)
	epochPublicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		epochPrivateKey,
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	defer clear(epochPublicKey)

	joinerDeviceID, err := device.DeriveID(identityPublicKey)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	inviteValue := options.Invite.Invite()
	defer clear(inviteValue.Secret[:])
	if joinerDeviceID == inviteValue.InviterDeviceID ||
		inviteValue.SubjectDeviceID != nil &&
			*inviteValue.SubjectDeviceID != joinerDeviceID {
		return nil, ErrIdentityMismatch
	}

	binding, err := credential.SignBinding(
		inviteValue.SessionID,
		joinerDeviceID,
		inviteValue.InitialCredentialEpoch,
		epochPublicKey,
		identityPrivateKey,
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	if err := binding.Validate(identityPublicKey); err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	coreValue := pairing.RequestCore{
		AttemptID:           options.AttemptID,
		JoinerDeviceID:      joinerDeviceID,
		DaemonVersion:       options.DaemonVersion,
		MaxApplyLevel:       options.MaxApplyLevel,
		InitialEpochBinding: binding,
	}
	copy(coreValue.JoinerIdentityPublicKey[:], identityPublicKey)
	core, err := pairing.NewRequestCore(coreValue)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}

	identityCertificate, identityBinding, err :=
		transport.IssueIdentityCertificate(
			inviteValue.SessionID,
			inviteValue.RecoveryGeneration,
			identityPrivateKey,
		)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	defer clearTLSCertificate(&identityCertificate)
	if identityBinding.SessionID != inviteValue.SessionID ||
		identityBinding.RecoveryGeneration !=
			inviteValue.RecoveryGeneration ||
		identityBinding.DeviceID != joinerDeviceID {
		return nil, ErrIdentityMismatch
	}

	pinnedSessionID := inviteValue.SessionID
	pinnedGeneration := inviteValue.RecoveryGeneration
	pinnedDeviceID := inviteValue.InviterDeviceID
	pinnedIdentityKey := inviteValue.InviterIdentityPublicKey
	tlsConfig, err := transport.NewClientTLSConfig(
		transport.ClientTLSOptions{
			Plane:       transport.PlanePairing,
			Certificate: identityCertificate,
			VerifyIdentityPeer: func(
				certificate transport.IdentityCertificate,
			) error {
				return certificate.VerifyIdentity(
					pinnedSessionID,
					pinnedGeneration,
					pinnedDeviceID,
					pinnedIdentityKey[:],
				)
			},
		},
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}

	clear(inviteValue.Secret[:])
	return &Joiner{
		state:       stateReady,
		invite:      options.Invite,
		inviteValue: inviteValue,
		core:        core,
		dialer:      options.Dialer,
		runtime:     runtime,
		tlsConfig:   tlsConfig,
	}, nil
}

// Begin tries signed invite endpoints in their canonical order, establishes a
// pinned pairing TLS connection, and obtains the durable request
// acknowledgment and SAS. ctx must remain live through the later Decide call.
func (joiner *Joiner) Begin(ctx context.Context) (ReviewSubject, error) {
	if joiner == nil || ctx == nil {
		return ReviewSubject{}, ErrInvalidOptions
	}
	joiner.operationMu.Lock()
	defer joiner.operationMu.Unlock()

	joiner.mu.Lock()
	switch {
	case joiner.state == stateClosed || joiner.closeRequested:
		joiner.mu.Unlock()
		return ReviewSubject{}, ErrClosed
	case joiner.state != stateReady:
		joiner.mu.Unlock()
		return ReviewSubject{}, ErrAlreadyStarted
	}
	joiner.state = stateBeginning
	joiner.mu.Unlock()

	if err := ctx.Err(); err != nil {
		joiner.teardownDuringOperation()
		return ReviewSubject{}, err
	}
	if err := joiner.invite.ValidateTime(joiner.runtime.now()); err != nil {
		joiner.teardownDuringOperation()
		return ReviewSubject{}, errors.Join(ErrInviteUnavailable, err)
	}
	remaining, err := joiner.remainingAttemptTime()
	if err != nil {
		joiner.teardownDuringOperation()
		return ReviewSubject{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, remaining)
	joiner.mu.Lock()
	if joiner.closeRequested {
		joiner.mu.Unlock()
		cancel()
		joiner.teardownDuringOperation()
		return ReviewSubject{}, ErrClosed
	}
	joiner.operationCtx = operationCtx
	joiner.cancel = cancel
	joiner.stopClose = context.AfterFunc(operationCtx, func() {
		_ = joiner.Close()
	})
	joiner.mu.Unlock()

	client, endpoint, err := joiner.openCanonicalEndpoint(operationCtx)
	if err != nil {
		joiner.teardownDuringOperation()
		return ReviewSubject{}, err
	}
	requestResult, err := joiner.requestUntilAcknowledged(
		operationCtx,
		client,
	)
	if err != nil {
		_ = client.Close()
		joiner.teardownDuringOperation()
		return ReviewSubject{}, err
	}

	review := joiner.buildReview(requestResult, endpoint)
	joiner.mu.Lock()
	if joiner.closeRequested || operationCtx.Err() != nil {
		joiner.mu.Unlock()
		_ = client.Close()
		joiner.teardownDuringOperation()
		return ReviewSubject{}, contextError(ctx, operationCtx)
	}
	joiner.client = client
	joiner.review = review
	joiner.invite = pairing.SignedInvite{}
	joiner.state = stateReview
	joiner.mu.Unlock()
	return review.clone(), nil
}

// Decide consumes the one local yes/no decision, sends it, and polls only the
// exact canonical confirmation over the original connection until the inviter
// returns a terminal status or a context is canceled. Every return closes the
// attempt and clears all owned certificate/private-key copies.
func (joiner *Joiner) Decide(
	ctx context.Context,
	confirmed bool,
) (Result, error) {
	if joiner == nil || ctx == nil {
		return Result{}, ErrInvalidOptions
	}
	joiner.operationMu.Lock()
	defer joiner.operationMu.Unlock()

	joiner.mu.Lock()
	switch {
	case joiner.decisionMade:
		joiner.mu.Unlock()
		return Result{}, ErrDecisionAlreadyMade
	case joiner.state == stateClosed || joiner.closeRequested:
		joiner.mu.Unlock()
		return Result{}, ErrClosed
	case joiner.state != stateReview || joiner.client == nil ||
		joiner.operationCtx == nil:
		joiner.mu.Unlock()
		return Result{}, ErrReviewUnavailable
	}
	joiner.decisionMade = true
	joiner.state = stateDeciding
	client := joiner.client
	review := joiner.review.clone()
	operationCtx := joiner.operationCtx
	joiner.mu.Unlock()

	callCtx, cancel := joinedContext(operationCtx, ctx)
	defer cancel()
	if err := callCtx.Err(); err != nil {
		joiner.teardownDuringOperation()
		return Result{}, contextError(ctx, operationCtx)
	}
	confirmation, err := pairing.NewConfirmation(
		review.AttemptID,
		review.RequestDigest,
		confirmed,
	)
	if err != nil {
		joiner.teardownDuringOperation()
		return Result{}, errors.Join(ErrReviewUnavailable, err)
	}

	for {
		response, confirmErr := client.Confirm(callCtx, confirmation)
		switch {
		case confirmErr == nil && terminalStatus(response.Status):
			result := Result{
				Review:       review,
				Confirmation: response,
			}
			joiner.teardownDuringOperation()
			return result, nil
		case confirmErr == nil && !pendingStatus(response.Status):
			joiner.teardownDuringOperation()
			return Result{}, ErrUnexpectedStatus
		case confirmErr != nil && callCtx.Err() != nil:
			joiner.teardownDuringOperation()
			return Result{}, contextError(ctx, operationCtx)
		case confirmErr != nil && !retryablePairingError(confirmErr):
			joiner.teardownDuringOperation()
			return Result{}, confirmErr
		}
		if err := joiner.runtime.wait(
			callCtx,
			joiner.runtime.confirmationPollDelay,
		); err != nil {
			joiner.teardownDuringOperation()
			return Result{}, contextError(ctx, operationCtx)
		}
	}
}

// Close cancels the attempt, closes its connection, and clears all owned
// certificate and private-key copies. It is idempotent and concurrency safe.
func (joiner *Joiner) Close() error {
	if joiner == nil {
		return ErrInvalidOptions
	}

	joiner.mu.Lock()
	if joiner.state == stateClosed {
		joiner.mu.Unlock()
		return nil
	}
	joiner.closeRequested = true
	cancel := joiner.cancel
	joiner.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	joiner.operationMu.Lock()
	defer joiner.operationMu.Unlock()
	return joiner.teardownDuringOperation()
}

func (joiner *Joiner) remainingAttemptTime() (time.Duration, error) {
	expiresAt, err := joiner.inviteValue.ExpiresAt.Time()
	if err != nil {
		return 0, errors.Join(ErrInviteUnavailable, err)
	}
	remaining := expiresAt.Sub(joiner.runtime.now().UTC())
	if remaining <= 0 {
		return 0, errors.Join(ErrInviteUnavailable, pairing.ErrInviteTime)
	}
	if remaining > joiner.runtime.overallAttemptTimeout {
		remaining = joiner.runtime.overallAttemptTimeout
	}
	return remaining, nil
}

func (joiner *Joiner) openCanonicalEndpoint(
	ctx context.Context,
) (pairingClient, netip.AddrPort, error) {
	failures := make([]error, 0, len(joiner.inviteValue.Endpoints))
	for _, endpoint := range joiner.inviteValue.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, netip.AddrPort{}, err
		}
		target := netip.AddrPortFrom(endpoint.IP, endpoint.Port)
		attemptCtx, cancel := context.WithTimeout(
			ctx,
			joiner.runtime.endpointAttemptTimeout,
		)
		raw, err := joiner.dialer.DialPairingEndpoint(
			attemptCtx,
			target,
		)
		if err != nil && raw != nil {
			_ = raw.Close()
			raw = nil
		}
		if err == nil && raw == nil {
			err = ErrEndpointsUnavailable
		}
		if err != nil {
			cancel()
			failures = append(
				failures,
				fmt.Errorf("%s: %w", target, err),
			)
			continue
		}
		client, openErr := joiner.runtime.openClient(
			attemptCtx,
			tls.Client(raw, joiner.tlsConfig),
		)
		cancel()
		if openErr == nil && !nilInterface(client) {
			return client, target, nil
		}
		if openErr == nil {
			_ = raw.Close()
			openErr = ErrEndpointsUnavailable
		}
		failures = append(
			failures,
			fmt.Errorf("%s: %w", target, openErr),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, netip.AddrPort{}, err
	}
	return nil, netip.AddrPort{}, errors.Join(
		append([]error{ErrEndpointsUnavailable}, failures...)...,
	)
}

func (joiner *Joiner) requestUntilAcknowledged(
	ctx context.Context,
	client pairingClient,
) (pairinghttp.RequestResult, error) {
	for {
		result, err := client.Request(ctx, joiner.invite, joiner.core)
		switch {
		case err == nil:
			return result, nil
		case ctx.Err() != nil:
			return pairinghttp.RequestResult{}, ctx.Err()
		case !retryablePairingError(err):
			return pairinghttp.RequestResult{}, err
		}
		if err := joiner.runtime.wait(
			ctx,
			joiner.runtime.confirmationPollDelay,
		); err != nil {
			return pairinghttp.RequestResult{}, err
		}
	}
}

func (joiner *Joiner) buildReview(
	result pairinghttp.RequestResult,
	endpoint netip.AddrPort,
) ReviewSubject {
	value := joiner.inviteValue
	core := joiner.core.Value()
	return ReviewSubject{
		AttemptID:                core.AttemptID,
		InviteID:                 value.InviteID,
		InviteDigest:             joiner.invite.Digest(),
		RequestDigest:            result.Acknowledgment.RequestDigest,
		SessionID:                value.SessionID,
		WorkspaceID:              value.WorkspaceID,
		RecoveryGeneration:       value.RecoveryGeneration,
		CreatedAt:                value.CreatedAt,
		ExpiresAt:                value.ExpiresAt,
		Mode:                     value.Mode,
		SubjectDeviceID:          cloneDeviceID(value.SubjectDeviceID),
		ExpectedEntityVersion:    cloneUint64(value.ExpectedEntityVersion),
		Role:                     value.Role,
		InviterDeviceID:          value.InviterDeviceID,
		InviterIdentityPublicKey: value.InviterIdentityPublicKey,
		SignedGenesisDigest:      value.SignedGenesisDigest,
		Core:                     core,
		SAS:                      result.SAS,
		ConnectedEndpoint:        endpoint,
	}
}

func (joiner *Joiner) teardownDuringOperation() error {
	joiner.mu.Lock()
	if joiner.state == stateClosed {
		joiner.mu.Unlock()
		return nil
	}
	joiner.state = stateClosed
	joiner.closeRequested = true
	cancel := joiner.cancel
	joiner.cancel = nil
	stopClose := joiner.stopClose
	joiner.stopClose = nil
	client := joiner.client
	joiner.client = nil
	tlsConfig := joiner.tlsConfig
	joiner.tlsConfig = nil
	joiner.invite = pairing.SignedInvite{}
	clear(joiner.inviteValue.Secret[:])
	joiner.inviteValue = pairing.Invite{}
	joiner.core = pairing.CanonicalRequestCore{}
	joiner.review = ReviewSubject{}
	joiner.operationCtx = nil
	joiner.mu.Unlock()

	if stopClose != nil {
		stopClose()
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if client != nil {
		closeErr = client.Close()
	}
	clearTLSConfig(tlsConfig)
	return closeErr
}

func defaultRuntimeOptions() runtimeOptions {
	return runtimeOptions{
		now:                    time.Now,
		openClient:             openPairingClient,
		wait:                   waitContext,
		endpointAttemptTimeout: endpointAttemptTimeout,
		overallAttemptTimeout:  overallAttemptTimeout,
		confirmationPollDelay:  confirmationPollDelay,
	}
}

func openPairingClient(
	ctx context.Context,
	connection *tls.Conn,
) (pairingClient, error) {
	return pairinghttp.OpenClient(ctx, connection)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func joinedContext(
	operationCtx context.Context,
	callCtx context.Context,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(operationCtx)
	stop := context.AfterFunc(callCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func contextError(
	callCtx context.Context,
	operationCtx context.Context,
) error {
	if callCtx != nil && callCtx.Err() != nil {
		return callCtx.Err()
	}
	if operationCtx != nil && operationCtx.Err() != nil {
		return operationCtx.Err()
	}
	return context.Canceled
}

func retryablePairingError(err error) bool {
	var remote *pairinghttp.RemoteError
	if errors.As(err, &remote) {
		return remote.Retryable
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func pendingStatus(status pairing.ConfirmationStatus) bool {
	return status == pairing.StatusAwaitingInviter ||
		status == pairing.StatusFinalizing
}

func terminalStatus(status pairing.ConfirmationStatus) bool {
	switch status {
	case pairing.StatusConfirmed, pairing.StatusDeclined,
		pairing.StatusExpired, pairing.StatusRevoked:
		return true
	default:
		return false
	}
}

func (subject ReviewSubject) clone() ReviewSubject {
	subject.SubjectDeviceID = cloneDeviceID(subject.SubjectDeviceID)
	subject.ExpectedEntityVersion = cloneUint64(
		subject.ExpectedEntityVersion,
	)
	return subject
}

func cloneDeviceID(value *domain.DeviceID) *domain.DeviceID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func clearTLSConfig(config *tls.Config) {
	if config == nil {
		return
	}
	for index := range config.Certificates {
		clearTLSCertificate(&config.Certificates[index])
	}
	config.Certificates = nil
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = nil
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	for index := range certificate.Certificate {
		clear(certificate.Certificate[index])
	}
	clear(certificate.OCSPStaple)
	for index := range certificate.SignedCertificateTimestamps {
		clear(certificate.SignedCertificateTimestamps[index])
	}
	if privateKey, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(privateKey)
	}
	*certificate = tls.Certificate{}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
