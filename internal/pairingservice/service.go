// Package pairingservice composes pairing wire validation, TLS identity, local
// SQLite state, and native one-use secrets. Membership authority remains in
// the idempotent committed-command finalizer supplied by the daemon.
package pairingservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/pairing"
	"github.com/ijonahch/codecomm/internal/platform/credentialstore"
	"github.com/ijonahch/codecomm/internal/store"
	"github.com/ijonahch/codecomm/internal/transport"
)

var (
	ErrInvalidOptions             = errors.New("pairing service: invalid options")
	ErrInvalidInput               = errors.New("pairing service: invalid input")
	ErrRequestRejected            = errors.New("pairing service: request rejected")
	ErrConfirmationConflict       = errors.New("pairing service: confirmation conflict")
	ErrAwaitingJoinerConfirmation = errors.New("pairing service: awaiting joiner confirmation")
	ErrFinalizationPending        = errors.New("pairing service: durable finalization pending")
	ErrFinalizationRejected       = errors.New("pairing service: durable finalization rejected")
	ErrNotRecovered               = errors.New("pairing service: startup recovery not completed")
	ErrClosed                     = errors.New("pairing service: closed")
	ErrUnavailable                = errors.New("pairing service: unavailable")
)

const defaultMaintenanceInterval = time.Second

// State is the local durable subset required by pairing orchestration.
type State interface {
	PairingInvite(context.Context, domain.UUIDv7) (store.PairingInviteRecord, bool, error)
	PairingAttempt(context.Context, domain.UUIDv7) (store.PairingAttemptRecord, bool, error)
	ConsumePairingInvite(context.Context, pairing.VerifiedRequest, domain.Timestamp) (store.PairingAttemptRecord, bool, error)
	RecordPairingProofFailure(context.Context, store.PairingProofFailureInput) (store.PairingAttemptRecord, bool, error)
	RecordPairingConfirmation(context.Context, store.PairingConfirmationInput) (store.PairingAttemptRecord, bool, error)
	RecordLocalPairingConfirmation(context.Context, store.PairingConfirmationInput, *store.PairingFinalizationAuthorization) (store.PairingAttemptRecord, bool, error)
	RecoverPairingState(context.Context, domain.Timestamp) (store.PairingMaintenanceResult, error)
	MaintainPairingState(context.Context, domain.Timestamp) (store.PairingMaintenanceResult, error)
	NextPairingFinalization(context.Context) (store.PairingAttemptRecord, bool, error)
	CompletePairingFinalization(context.Context, domain.UUIDv7, domain.Timestamp) (store.PairingAttemptRecord, bool, error)
	RejectPairingFinalization(context.Context, domain.UUIDv7) (store.PairingAttemptRecord, bool, error)
	NextPairingSecretDeletion(context.Context) (store.PairingSecretDeletion, bool, error)
	CompletePairingSecretDeletion(context.Context, domain.UUIDv7, domain.UUIDv7) (bool, error)
	FailPairingSecretDeletion(context.Context, domain.UUIDv7, domain.UUIDv7, string, domain.Timestamp) (store.PairingSecretDeletion, bool, error)
}

// Clock supplies local receive/decision times. Peer input never supplies an
// authoritative pairing timestamp.
type Clock func() domain.Timestamp

// Finalizer performs the mode-specific durable action. Returning nil means
// admission/readmission committed or rebootstrap state was durably installed.
// An error wrapping ErrFinalizationRejected means the authoritative operation
// durably rejected and this attempt must end. Other errors are retryable. The
// implementation must be idempotent because restart may repeat every outcome.
// It must also fence its durable action to details.Invite's exact session and
// recovery generation: a successor may supersede the attempt while this call
// is in flight.
type Finalizer interface {
	FinalizePairing(context.Context, AttemptDetails) error
}

// FinalizationAuthorizer constructs the exact human-origin request evidence
// while the verified local approval is still on the call stack. New and
// readmission modes also include their admission reservation.
type FinalizationAuthorizer interface {
	PreparePairing(
		context.Context,
		AttemptDetails,
		domain.Timestamp,
	) (*store.PairingFinalizationAuthorization, error)
}

// SettledNonvoterGuard excludes a subject from live Raft configuration while
// an existing-device invite is transactionally consumed.
type SettledNonvoterGuard interface {
	AcquireSettledNonvoter(context.Context, domain.DeviceID) (release func(), err error)
}

// SecretStore is implemented by the native credential store. Get returns a
// caller-owned buffer; Delete is idempotent.
type SecretStore interface {
	Get(context.Context, credentialstore.Reference) ([]byte, error)
	Delete(context.Context, credentialstore.Reference) error
}

// Options fixes the inviter identity and durable dependencies.
type Options struct {
	State               State
	Secrets             SecretStore
	Authorizer          FinalizationAuthorizer
	Finalizer           Finalizer
	Nonvoters           SettledNonvoterGuard
	IdentityPublicKey   []byte
	Clock               Clock
	MaintenanceInterval time.Duration
}

// Service owns one session daemon's inviter-side pairing flow.
type Service struct {
	state               State
	secrets             SecretStore
	authorizer          FinalizationAuthorizer
	finalizer           Finalizer
	nonvoters           SettledNonvoterGuard
	identityPublicKey   [ed25519.PublicKeySize]byte
	deviceID            domain.DeviceID
	clock               Clock
	maintenanceInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	done   sync.WaitGroup

	recoverMu  sync.Mutex
	finalizeMu sync.Mutex
	mu         sync.RWMutex
	recovered  bool
	closed     bool

	fatalOnce sync.Once
	fatalMu   sync.RWMutex
	fatalErr  error
}

// RequestResult is safe for local SAS display and peer acknowledgment.
type RequestResult struct {
	Acknowledgment pairing.RequestAcknowledgment
	Attempt        store.PairingAttemptRecord
	Core           pairing.RequestCore
	SAS            string
}

// AttemptDetails is the exact local operator review subject.
type AttemptDetails struct {
	Invite  store.PairingInviteRecord
	Attempt store.PairingAttemptRecord
	Core    pairing.RequestCore
	SAS     string
}

// New validates a pairing service without reading native secret material.
func New(options Options) (*Service, error) {
	if options.State == nil || options.Secrets == nil ||
		options.Authorizer == nil || options.Finalizer == nil ||
		options.Nonvoters == nil ||
		len(options.IdentityPublicKey) != ed25519.PublicKeySize ||
		options.MaintenanceInterval < 0 {
		return nil, ErrInvalidOptions
	}
	deviceID, err := device.DeriveID(options.IdentityPublicKey)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	clock := options.Clock
	if clock == nil {
		clock = func() domain.Timestamp {
			return domain.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		}
	}
	interval := options.MaintenanceInterval
	if interval == 0 {
		interval = defaultMaintenanceInterval
	}
	serviceContext, cancel := context.WithCancel(context.Background())
	service := &Service{
		state: options.State, secrets: options.Secrets,
		authorizer: options.Authorizer, finalizer: options.Finalizer,
		nonvoters: options.Nonvoters, deviceID: deviceID, clock: clock,
		maintenanceInterval: interval, ctx: serviceContext, cancel: cancel,
	}
	copy(service.identityPublicKey[:], options.IdentityPublicKey)
	return service, nil
}

// HandleRequest validates and consumes one exporter-bound request. A valid
// proof is durably consumed before the returned acknowledgment may be sent.
func (service *Service) HandleRequest(
	ctx context.Context,
	canonicalRequest []byte,
	exporter []byte,
	peer transport.IdentityCertificate,
) (RequestResult, error) {
	observedAt, err := service.callTime(ctx)
	if err != nil {
		return RequestResult{}, err
	}
	request, err := pairing.ParseRequest(canonicalRequest)
	if err != nil {
		return RequestResult{}, fmt.Errorf("%w: malformed request", ErrRequestRejected)
	}
	invite, found, err := service.state.PairingInvite(ctx, request.InviteID())
	if err != nil {
		return RequestResult{}, service.stateError(ctx, err)
	}
	if !found || invite.IssuerDeviceID != service.deviceID {
		return RequestResult{}, ErrRequestRejected
	}
	verificationContext, err := pairing.NewVerificationContext(
		invite.InviteID, invite.SessionID, [sha256.Size]byte(invite.InviteDigest),
		service.identityPublicKey[:], invite.SubjectDeviceID, invite.InitialCredentialEpoch,
	)
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	proofAttempt, err := request.PrepareVerification(verificationContext, exporter)
	if err != nil {
		return RequestResult{}, fmt.Errorf("%w: request binding", ErrRequestRejected)
	}
	core := proofAttempt.Core().Value()
	if err := peer.VerifyIdentity(
		invite.SessionID, invite.RecoveryGeneration, core.JoinerDeviceID,
		core.JoinerIdentityPublicKey[:],
	); err != nil {
		return RequestResult{}, fmt.Errorf("%w: peer identity", ErrRequestRejected)
	}
	if invite.State == store.PairingInviteConsumed {
		return service.acceptedRetry(ctx, invite, proofAttempt)
	}
	if invite.State != store.PairingInviteOutstanding {
		return RequestResult{}, ErrRequestRejected
	}

	reference, err := credentialstore.InviteReference(invite.SessionID, invite.InviteID)
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	secretBytes, err := service.secrets.Get(ctx, reference)
	if err != nil {
		return RequestResult{}, service.secretError(ctx, err)
	}
	defer clear(secretBytes)
	if len(secretBytes) != pairing.InviteSecretSize {
		return RequestResult{}, ErrUnavailable
	}
	var secret [pairing.InviteSecretSize]byte
	copy(secret[:], secretBytes)
	defer clear(secret[:])
	verified, proofErr := proofAttempt.VerifyProof(secret)
	if proofErr != nil {
		if !errors.Is(proofErr, pairing.ErrInviteProof) {
			return RequestResult{}, ErrUnavailable
		}
		_, _, recordErr := service.state.RecordPairingProofFailure(
			ctx,
			store.PairingProofFailureInput{
				InviteID: invite.InviteID, InviteDigest: invite.InviteDigest,
				RequestDigest:  store.Digest(proofAttempt.RequestDigest()),
				RequestCore:    proofAttempt.Core(),
				TranscriptHash: store.Digest(proofAttempt.TranscriptHash()),
				ObservedAt:     observedAt,
			},
		)
		if recordErr != nil {
			if errors.Is(recordErr, store.ErrPairingConflict) {
				return RequestResult{}, ErrRequestRejected
			}
			return RequestResult{}, service.stateError(ctx, recordErr)
		}
		return RequestResult{}, ErrRequestRejected
	}
	acknowledgment, err := pairing.NewRequestAcknowledgment(verified)
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	release := func() {}
	if invite.Mode != pairing.ModeNew {
		release, err = service.nonvoters.AcquireSettledNonvoter(
			ctx,
			core.JoinerDeviceID,
		)
		if err != nil {
			if ctx.Err() != nil {
				return RequestResult{}, ctx.Err()
			}
			return RequestResult{}, ErrRequestRejected
		}
		if release == nil {
			return RequestResult{}, ErrUnavailable
		}
	}
	defer release()
	attempt, _, err := service.state.ConsumePairingInvite(ctx, verified, observedAt)
	if err != nil {
		return RequestResult{}, service.stateError(ctx, err)
	}
	return RequestResult{
		Acknowledgment: acknowledgment, Attempt: attempt, Core: core, SAS: verified.SAS(),
	}, nil
}

func (service *Service) acceptedRetry(
	ctx context.Context,
	invite store.PairingInviteRecord,
	proofAttempt pairing.ProofAttempt,
) (RequestResult, error) {
	core := proofAttempt.Core()
	coreValue := core.Value()
	attempt, found, err := service.state.PairingAttempt(ctx, coreValue.AttemptID)
	if err != nil {
		return RequestResult{}, service.stateError(ctx, err)
	}
	if !found || attempt.State == store.PairingAttemptProofRejected ||
		invite.ConsumedAttemptID != attempt.AttemptID ||
		attempt.InviteID != invite.InviteID ||
		attempt.RequestDigest != store.Digest(proofAttempt.RequestDigest()) ||
		!bytes.Equal(attempt.RequestCore, core.CanonicalBytes()) ||
		attempt.TranscriptHash != store.Digest(proofAttempt.TranscriptHash()) ||
		attempt.JoinerDeviceID != coreValue.JoinerDeviceID {
		return RequestResult{}, ErrRequestRejected
	}
	acknowledgment, err := pairing.NewRequestAcknowledgmentValues(
		attempt.AttemptID, [sha256.Size]byte(attempt.RequestDigest),
		[sha256.Size]byte(invite.InviteDigest),
	)
	if err != nil {
		return RequestResult{}, ErrUnavailable
	}
	return RequestResult{
		Acknowledgment: acknowledgment, Attempt: attempt, Core: coreValue,
		SAS: pairing.RenderSAS([sha256.Size]byte(attempt.TranscriptHash)),
	}, nil
}

func (service *Service) validateCall(ctx context.Context) error {
	if service == nil || service.state == nil || service.secrets == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.mu.RLock()
	closed, recovered := service.closed, service.recovered
	service.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if !recovered {
		return ErrNotRecovered
	}
	if err := service.FatalError(); err != nil {
		return err
	}
	return nil
}

func (service *Service) callTime(ctx context.Context) (domain.Timestamp, error) {
	if err := service.validateCall(ctx); err != nil {
		return "", err
	}
	now := service.clock()
	if !now.Valid() {
		return "", ErrUnavailable
	}
	return now, nil
}

func (service *Service) stateError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, store.ErrPairingConflict) {
		return ErrConfirmationConflict
	}
	if errors.Is(err, store.ErrPairingInviteExpired) ||
		errors.Is(err, store.ErrPairingInviteUnavailable) ||
		errors.Is(err, store.ErrPairingInviteNotFound) ||
		errors.Is(err, store.ErrPairingEligibility) ||
		errors.Is(err, store.ErrPairingNotFinalizing) {
		return ErrRequestRejected
	}
	return fmt.Errorf("%w: durable pairing state", ErrUnavailable)
}

func (service *Service) secretError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: native invite secret", ErrUnavailable)
}
