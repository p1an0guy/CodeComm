// Package agent owns local agent launch, bind, lifecycle, and command
// authority. It is the only layer that turns an agent proof into an
// event.Binding.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/ipc"
	"github.com/ijonahch/codecomm/internal/store"
)

var (
	ErrInvalidOptions    = errors.New("agent: invalid options")
	ErrClosed            = errors.New("agent: service is closed")
	ErrInvalidProof      = errors.New("agent: invalid proof")
	ErrBindRejected      = errors.New("agent: bind rejected")
	ErrAgentAlreadyBound = errors.New("agent: session is already bound")
	ErrCommandRejected   = errors.New("agent: command was rejected")
	ErrCommandForwarding = errors.New("agent: command forwarding failed")
	ErrRandomSource      = errors.New("agent: secure random source failed")
)

// CommandConsensus is the committed-command boundary shared by local outbox
// owners.
type CommandConsensus interface {
	ApplyAtGeneration(
		context.Context,
		domain.UUIDv7,
		uint64,
		event.SignedEvent,
	) (store.ApplyResult, error)
	IsLeader() bool
}

type CheckpointConsensus interface {
	CommandConsensus
	FatalError() error
	VerifyCheckpointReplay(
		context.Context,
		event.SignedEvent,
		store.ApplyResult,
	) error
}

// Consensus adds the same-boot clock needed by agent lease management.
type Consensus interface {
	CommandConsensus
	LocalTime() (domain.Timestamp, int64, error)
}

type Clock func() domain.Timestamp
type IDGenerator func() (domain.UUIDv7, error)

type Options struct {
	Consensus          Consensus
	LocalState         store.LocalState
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	DeviceID           domain.DeviceID
	OriginBootID       domain.UUIDv7
	IdentityPrivateKey ed25519.PrivateKey
	LifecycleOrigin    event.Binding
	BootOrigin         *BootOrigin

	Clock      Clock
	GenerateID IDGenerator
	Random     io.Reader
}

// Service is a concurrency-safe local IPC binder and durable outbox owner.
type Service struct {
	consensus    Consensus
	local        store.LocalState
	sessionID    domain.UUIDv7
	workspaceID  domain.UUIDv4
	deviceID     domain.DeviceID
	originBootID domain.UUIDv7
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	clock        Clock
	generateID   IDGenerator
	random       io.Reader
	bootOrigin   *BootOrigin

	ctx    context.Context
	cancel context.CancelFunc
	done   sync.WaitGroup
	clear  sync.Once

	randomMu  sync.Mutex
	recoverMu sync.Mutex
	recovered bool

	fatalOnce sync.Once
	fatalMu   sync.RWMutex
	fatalErr  error

	mu           sync.Mutex
	closed       bool
	active       map[domain.UUIDv7]struct{}
	lifecycles   map[domain.UUIDv7]struct{}
	proofFlights map[string]chan struct{}
	workers      map[store.OutboxScope]*originWorker
	resultSignal chan struct{}

	disconnectGrace   time.Duration
	leasePollInterval time.Duration
}

func New(options Options) (*Service, error) {
	if options.Consensus == nil ||
		options.BootOrigin == nil ||
		!options.SessionID.Valid() ||
		!options.WorkspaceID.Valid() ||
		!options.DeviceID.Valid() ||
		!options.OriginBootID.Valid() ||
		len(options.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidOptions
	}
	publicKey, err := codecommcrypto.Ed25519PublicKeyFromPrivateKey(
		options.IdentityPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: identity key: %v", ErrInvalidOptions, err)
	}
	derived, err := codec.DeriveDeviceID(ed25519.PublicKey(publicKey))
	if err != nil || derived != string(options.DeviceID) {
		return nil, fmt.Errorf("%w: identity key does not match device", ErrInvalidOptions)
	}
	daemonOrigin, err := options.LifecycleOrigin.Origin(1)
	if err != nil ||
		options.LifecycleOrigin.ActorType() != event.ActorDaemon ||
		daemonOrigin.DeviceID() != options.DeviceID ||
		daemonOrigin.OriginBootID() != options.OriginBootID ||
		daemonOrigin.AgentSessionID() != "" {
		return nil, fmt.Errorf("%w: invalid daemon binding", ErrInvalidOptions)
	}
	if !options.BootOrigin.matches(
		options.LocalState,
		options.SessionID,
		options.WorkspaceID,
		options.DeviceID,
		options.OriginBootID,
	) {
		return nil, fmt.Errorf(
			"%w: boot origin does not match service",
			ErrInvalidOptions,
		)
	}
	clock := options.Clock
	if clock == nil {
		clock = func() domain.Timestamp {
			return domain.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		}
	}
	generateID := options.GenerateID
	if generateID == nil {
		generateID = generateUUIDv7
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	now := clock()
	if !now.Valid() {
		return nil, fmt.Errorf("%w: clock returned invalid timestamp", ErrInvalidOptions)
	}
	localNow, monotonicNowNS, err := options.Consensus.LocalTime()
	if err != nil || !localNow.Valid() || monotonicNowNS < 0 {
		return nil, fmt.Errorf(
			"%w: consensus returned invalid local time",
			ErrInvalidOptions,
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		consensus:         options.Consensus,
		local:             options.LocalState,
		sessionID:         options.SessionID,
		workspaceID:       options.WorkspaceID,
		deviceID:          options.DeviceID,
		originBootID:      options.OriginBootID,
		privateKey:        append(ed25519.PrivateKey(nil), options.IdentityPrivateKey...),
		publicKey:         append(ed25519.PublicKey(nil), publicKey...),
		clock:             clock,
		generateID:        generateID,
		random:            randomSource,
		bootOrigin:        options.BootOrigin,
		ctx:               ctx,
		cancel:            cancel,
		active:            make(map[domain.UUIDv7]struct{}),
		lifecycles:        make(map[domain.UUIDv7]struct{}),
		proofFlights:      make(map[string]chan struct{}),
		workers:           make(map[store.OutboxScope]*originWorker),
		resultSignal:      make(chan struct{}),
		disconnectGrace:   agentDisconnectGrace,
		leasePollInterval: defaultLeasePollInterval,
	}, nil
}

func generateUUIDv7() (domain.UUIDv7, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	id := domain.UUIDv7(value.String())
	if !id.Valid() {
		return "", domain.ErrInvalidUUIDv7
	}
	return id, nil
}

type LaunchOptions struct {
	ClientKind      agentsession.ClientKind
	AgentProfileID  *string
	ConcurrencyMode store.ConcurrencyMode
	ManagedRootID   domain.UUIDv7
}

type LaunchTicket struct {
	LaunchID domain.UUIDv7
	Selector string
}

// RegisterLaunch creates a durable launch before starting the vendor process.
func (service *Service) RegisterLaunch(
	ctx context.Context,
	options LaunchOptions,
) (LaunchTicket, error) {
	if err := service.available(); err != nil {
		return LaunchTicket{}, err
	}
	launchID, err := service.generateID()
	if err != nil || !launchID.Valid() {
		return LaunchTicket{}, fmt.Errorf("agent: generate launch ID: %w", err)
	}
	selector, err := service.randomBytes(32)
	if err != nil {
		return LaunchTicket{}, err
	}
	defer clear(selector)
	digest := selectorDigest(selector)
	now := service.clock()
	if !now.Valid() {
		return LaunchTicket{}, ErrInvalidOptions
	}
	if err := service.local.RegisterLaunch(ctx, store.LaunchRegistration{
		LaunchID:        launchID,
		SelectorDigest:  digest,
		SessionID:       service.sessionID,
		WorkspaceID:     service.workspaceID,
		ClientKind:      options.ClientKind,
		AgentProfileID:  cloneString(options.AgentProfileID),
		ConcurrencyMode: options.ConcurrencyMode,
		ManagedRootID:   options.ManagedRootID,
		CreatedAt:       now,
	}); err != nil {
		return LaunchTicket{}, err
	}
	return LaunchTicket{
		LaunchID: launchID,
		Selector: codec.EncodeBase64URL(selector),
	}, nil
}

// Recover starts workers for every durable queue left by a prior process.
func (service *Service) Recover(ctx context.Context) error {
	if err := service.available(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service.recoverMu.Lock()
	defer service.recoverMu.Unlock()
	if err := service.available(); err != nil {
		return err
	}
	if service.recovered {
		return nil
	}
	if err := service.rearmLeaseDeadlines(ctx); err != nil {
		return err
	}
	if err := service.local.ClearPendingLaunches(ctx); err != nil {
		return err
	}
	if err := service.bootOrigin.Recover(ctx); err != nil {
		return err
	}
	scopes, err := service.local.OutboxScopes(ctx)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		service.wakeScope(scope)
	}
	sessions, err := service.local.NonterminalAgentSessions(ctx)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.DeviceID == service.deviceID &&
			session.State != agentsession.StateEnded {
			service.startLifecycleReconciliation(session.ID)
		}
	}
	service.startLeaseExpiryReconciliation()
	service.recovered = true
	return nil
}

// Bind implements ipc.Binder. Only the fixed agent class is accepted.
func (service *Service) Bind(
	ctx context.Context,
	_ ipc.VerifiedPeer,
	request ipc.BindRequest,
) (ipc.BindResult, error) {
	if err := service.available(); err != nil {
		return ipc.BindResult{}, err
	}
	if ctx == nil ||
		request.Class != ipc.ClassAgent ||
		request.ProtocolVersion != ipc.LocalProtocolVersion ||
		request.SessionID != service.sessionID ||
		request.WorkspaceID != service.workspaceID {
		return ipc.BindResult{}, ErrBindRejected
	}
	if err := ctx.Err(); err != nil {
		return ipc.BindResult{}, err
	}
	proof, err := decodeProof(request.AgentProof)
	clear(request.AgentProof)
	if err != nil {
		return ipc.BindResult{}, err
	}
	defer clear(proof.value)
	releaseFlight, err := service.beginProofFlight(ctx, proof.flightKey())
	if err != nil {
		return ipc.BindResult{}, err
	}
	defer releaseFlight()

	switch proof.kind {
	case proofLaunch:
		return service.bindLaunch(ctx, request, proof.value)
	case proofResume:
		return service.bindResume(ctx, request, proof.value)
	default:
		return ipc.BindResult{}, ErrInvalidProof
	}
}

func (service *Service) bindLaunch(
	ctx context.Context,
	request ipc.BindRequest,
	selector []byte,
) (_ ipc.BindResult, err error) {
	digest := selectorDigest(selector)
	canonicalRequest, err := canonicalLaunchBindRequest(request, selector)
	if err != nil {
		return ipc.BindResult{}, err
	}
	start, _, err := service.local.ReserveLaunchStart(
		ctx,
		digest,
		request.ClientInstanceID,
		canonicalRequest,
		service.deviceID,
		func() (store.LaunchStartIDs, error) {
			agentSessionID, err := service.generateID()
			if err != nil {
				return store.LaunchStartIDs{}, err
			}
			workingRootID, err := service.generateID()
			if err != nil {
				return store.LaunchStartIDs{}, err
			}
			eventID, err := service.generateID()
			if err != nil {
				return store.LaunchStartIDs{}, err
			}
			return store.LaunchStartIDs{
				AgentSessionID: agentSessionID,
				WorkingRootID:  workingRootID,
				EventID:        eventID,
			}, nil
		},
		func(
			launch store.LaunchRecord,
			ids store.LaunchStartIDs,
		) (event.SignedEvent, error) {
			return service.buildAgentStart(launch, ids)
		},
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	service.wakeCommand(start.Command)
	resolved, err := service.waitResolved(ctx, start.Command)
	if err != nil {
		return ipc.BindResult{}, err
	}
	if resolved.Outcome == nil {
		return ipc.BindResult{}, ErrCommandForwarding
	}
	if !service.claimActive(start.Launch.AgentSessionID) {
		return ipc.BindResult{}, ErrAgentAlreadyBound
	}
	claimed := true
	defer func() {
		if err != nil && claimed {
			service.releaseActive(start.Launch.AgentSessionID)
		}
	}()

	var capability []byte
	defer func() {
		clear(capability)
	}()
	settlement, err := service.local.SettleLaunch(
		ctx,
		start.Launch.LaunchID,
		service.clock(),
		func() (store.Digest, error) {
			value, err := service.randomBytes(32)
			if err != nil {
				return store.Digest{}, err
			}
			capability = value
			return resumeDigest(value), nil
		},
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	if settlement.Outcome.Status != store.OutcomeAccepted {
		return ipc.BindResult{}, fmt.Errorf(
			"%w: %s",
			ErrCommandRejected,
			settlement.Outcome.Code,
		)
	}
	session, found, err := service.local.AgentSession(
		ctx,
		start.Launch.AgentSessionID,
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	if !found || session.State == agentsession.StateEnded {
		return ipc.BindResult{}, ErrBindRejected
	}
	if session.State == agentsession.StateDisconnected {
		if err := service.resumeSession(
			ctx,
			session,
			session.ResumeState,
		); err != nil {
			return ipc.BindResult{}, err
		}
	} else if !session.State.Connected() {
		return ipc.BindResult{}, ErrBindRejected
	}
	binding, err := event.NewMCPBinding(
		service.deviceID,
		start.Launch.AgentSessionID,
		start.Launch.AgentProfileID,
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	client := newLaunchBoundClient(
		service,
		request.ClientInstanceID,
		start.Launch.AgentSessionID,
		start.Launch.WorkingRootID,
		binding,
		start.Launch.LaunchID,
		resumeDigest(capability),
	)
	result, err := ipc.NewAgentLaunchBindResult(client, capability)
	if err != nil {
		return ipc.BindResult{}, err
	}
	claimed = false
	return result, nil
}

func (service *Service) bindResume(
	ctx context.Context,
	request ipc.BindRequest,
	token []byte,
) (_ ipc.BindResult, err error) {
	resume, err := service.local.AuthorizeResume(
		ctx,
		resumeDigest(token),
		service.sessionID,
		service.workspaceID,
		service.deviceID,
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	if !service.claimActive(resume.AgentSessionID) {
		return ipc.BindResult{}, ErrAgentAlreadyBound
	}
	claimed := true
	defer func() {
		if err != nil && claimed {
			service.releaseActive(resume.AgentSessionID)
		}
	}()
	session, found, err := service.local.AgentSession(
		ctx,
		resume.AgentSessionID,
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	if !found ||
		session.EntityVersion != resume.EntityVersion ||
		session.ResumeState != resume.ResumeState {
		return ipc.BindResult{}, ErrBindRejected
	}
	if err := service.resumeSession(
		ctx,
		session,
		resume.ResumeState,
	); err != nil {
		return ipc.BindResult{}, err
	}
	binding, err := event.NewMCPBinding(
		service.deviceID,
		resume.AgentSessionID,
		resume.AgentProfileID,
	)
	if err != nil {
		return ipc.BindResult{}, err
	}
	client := newBoundClient(
		service,
		request.ClientInstanceID,
		resume.AgentSessionID,
		resume.WorkingRootID,
		binding,
	)
	result, err := ipc.NewAgentResumeBindResult(client)
	if err != nil {
		return ipc.BindResult{}, err
	}
	claimed = false
	return result, nil
}

func (service *Service) buildAgentStart(
	launch store.LaunchRecord,
	ids store.LaunchStartIDs,
) (event.SignedEvent, error) {
	binding, err := event.NewMCPBinding(
		service.deviceID,
		ids.AgentSessionID,
		launch.AgentProfileID,
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	payload, err := canonicalObject(map[string]any{
		"client_kind":     launch.ClientKind,
		"working_root_id": ids.WorkingRootID,
	})
	if err != nil {
		return event.SignedEvent{}, err
	}
	now := service.clock()
	if !now.Valid() {
		return event.SignedEvent{}, ErrInvalidOptions
	}
	proposal, err := event.BuildProposal(
		event.Command{
			Kind:             event.KindAgentSessionStarted,
			EntityID:         event.StringEntityID(string(ids.AgentSessionID)),
			RationaleSummary: "",
			Actions:          []event.Action{},
			Payload:          payload,
			Redaction:        defaultRedaction(),
		},
		binding,
		event.BuildContext{
			EventID:        ids.EventID,
			SessionID:      service.sessionID,
			WorkspaceID:    service.workspaceID,
			CreatedAt:      now,
			OriginSequence: 1,
		},
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	return event.Sign(proposal, service.privateKey)
}

func (service *Service) available() error {
	if service == nil ||
		service.consensus == nil ||
		!service.sessionID.Valid() ||
		!service.workspaceID.Valid() {
		return ErrInvalidOptions
	}
	service.mu.Lock()
	closed := service.closed
	service.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if err := service.FatalError(); err != nil {
		return err
	}
	return nil
}

func (service *Service) recordFatal(cause error) {
	if service == nil || cause == nil {
		return
	}
	service.fatalOnce.Do(func() {
		service.fatalMu.Lock()
		service.fatalErr = cause
		service.fatalMu.Unlock()
		service.cancel()
	})
}

// FatalError returns the first terminal background-service failure.
func (service *Service) FatalError() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.fatalMu.RLock()
	fatal := service.fatalErr
	service.fatalMu.RUnlock()
	if fatal != nil {
		return fatal
	}
	if service.bootOrigin != nil {
		return service.bootOrigin.FatalError()
	}
	return nil
}

func (service *Service) randomBytes(size int) ([]byte, error) {
	if size < 1 || size > 1024 {
		return nil, ErrInvalidOptions
	}
	value := make([]byte, size)
	service.randomMu.Lock()
	_, err := io.ReadFull(service.random, value)
	service.randomMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	return value, nil
}

func (service *Service) beginProofFlight(
	ctx context.Context,
	key string,
) (func(), error) {
	for {
		service.mu.Lock()
		if service.closed {
			service.mu.Unlock()
			return nil, ErrClosed
		}
		existing, found := service.proofFlights[key]
		if !found {
			done := make(chan struct{})
			service.proofFlights[key] = done
			service.mu.Unlock()
			return func() {
				service.mu.Lock()
				if service.proofFlights[key] == done {
					delete(service.proofFlights, key)
					close(done)
				}
				service.mu.Unlock()
			}, nil
		}
		service.mu.Unlock()
		select {
		case <-existing:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-service.ctx.Done():
			return nil, ErrClosed
		}
	}
}

func (service *Service) claimActive(id domain.UUIDv7) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return false
	}
	if _, exists := service.active[id]; exists {
		return false
	}
	service.active[id] = struct{}{}
	return true
}

func (service *Service) releaseActive(id domain.UUIDv7) {
	service.mu.Lock()
	delete(service.active, id)
	service.mu.Unlock()
}

// BeginClose cancels background work without waiting for an already-enqueued
// consensus future. The daemon closes Raft before joining the service.
func (service *Service) BeginClose() error {
	if service == nil {
		return ErrInvalidOptions
	}
	service.recoverMu.Lock()
	defer service.recoverMu.Unlock()
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return nil
	}
	service.closed = true
	service.cancel()
	service.mu.Unlock()
	return nil
}

// Wait joins background work and clears the service's private-key copy.
func (service *Service) Wait() error {
	if service == nil {
		return ErrInvalidOptions
	}
	if err := service.BeginClose(); err != nil {
		return err
	}
	service.done.Wait()
	service.clear.Do(func() {
		clear(service.privateKey)
	})
	return nil
}

// Close stops background workers. Durable queued commands remain recoverable.
func (service *Service) Close() error {
	if err := service.BeginClose(); err != nil {
		return err
	}
	return service.Wait()
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
