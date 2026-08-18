package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ijonahch/codecomm/internal/codec"
	codecommcrypto "github.com/ijonahch/codecomm/internal/crypto"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"github.com/ijonahch/codecomm/internal/store"
	"golang.org/x/sync/semaphore"
)

var ErrBootOriginIntegrity = errors.New(
	"agent: boot-origin durable state integrity failure",
)

const bootOriginLaneCapacity int64 = 1 << 20

type BootOriginOptions struct {
	Consensus          CheckpointConsensus
	LocalState         store.LocalState
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	DeviceID           domain.DeviceID
	OriginBootID       domain.UUIDv7
	IdentityPrivateKey ed25519.PrivateKey
	DaemonOrigin       event.Binding

	Clock      Clock
	GenerateID IDGenerator
}

// BootOrigin exclusively owns forwarding and reservation for local boot
// scopes. New work may be reserved before Recover; the worker starts lazily.
type BootOrigin struct {
	consensus     CheckpointConsensus
	local         store.LocalState
	sessionID     domain.UUIDv7
	workspaceID   domain.UUIDv4
	deviceID      domain.DeviceID
	originBootID  domain.UUIDv7
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	daemonBinding event.Binding
	clock         Clock
	generateID    IDGenerator
	scope         store.OutboxScope

	ctx    context.Context
	cancel context.CancelFunc
	done   sync.WaitGroup
	lane   *semaphore.Weighted
	wake   chan struct{}

	recoverMu sync.Mutex
	recovered bool

	fatalOnce sync.Once
	fatalMu   sync.RWMutex
	fatalErr  error

	mu            sync.Mutex
	closed        bool
	workerStarted bool
	resultSignal  chan struct{}
	clearOnce     sync.Once
}

func NewBootOrigin(options BootOriginOptions) (*BootOrigin, error) {
	if options.Consensus == nil ||
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
	derived, err := codec.DeriveDeviceID(publicKey)
	if err != nil || derived != string(options.DeviceID) {
		return nil, fmt.Errorf(
			"%w: identity key does not match device",
			ErrInvalidOptions,
		)
	}
	daemonOrigin, err := options.DaemonOrigin.Origin(1)
	if err != nil ||
		options.DaemonOrigin.ActorType() != event.ActorDaemon ||
		daemonOrigin.DeviceID() != options.DeviceID ||
		daemonOrigin.OriginBootID() != options.OriginBootID ||
		daemonOrigin.AgentSessionID() != "" {
		return nil, fmt.Errorf(
			"%w: invalid daemon binding",
			ErrInvalidOptions,
		)
	}
	clock := options.Clock
	if clock == nil {
		clock = func() domain.Timestamp {
			return domain.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		}
	}
	if now := clock(); !now.Valid() {
		return nil, fmt.Errorf(
			"%w: clock returned invalid timestamp",
			ErrInvalidOptions,
		)
	}
	generateID := options.GenerateID
	if generateID == nil {
		generateID = generateUUIDv7
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &BootOrigin{
		consensus:     options.Consensus,
		local:         options.LocalState,
		sessionID:     options.SessionID,
		workspaceID:   options.WorkspaceID,
		deviceID:      options.DeviceID,
		originBootID:  options.OriginBootID,
		privateKey:    bytes.Clone(options.IdentityPrivateKey),
		publicKey:     bytes.Clone(publicKey),
		daemonBinding: options.DaemonOrigin,
		clock:         clock,
		generateID:    generateID,
		scope: store.OutboxScope{
			OriginDeviceID:  options.DeviceID,
			OriginScopeKind: store.OriginScopeKindBoot,
			OriginScopeID:   options.OriginBootID,
		},
		ctx:          ctx,
		cancel:       cancel,
		lane:         semaphore.NewWeighted(bootOriginLaneCapacity),
		wake:         make(chan struct{}, 1),
		resultSignal: make(chan struct{}),
	}, nil
}

func (origin *BootOrigin) DeviceID() domain.DeviceID {
	if origin == nil {
		return ""
	}
	return origin.deviceID
}

func (origin *BootOrigin) BootID() domain.UUIDv7 {
	if origin == nil {
		return ""
	}
	return origin.originBootID
}

// Recover validates all durable queues and wakes the sole boot-scope worker.
func (origin *BootOrigin) Recover(ctx context.Context) error {
	if err := origin.available(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	origin.recoverMu.Lock()
	defer origin.recoverMu.Unlock()
	if origin.recovered {
		return nil
	}
	records, err := origin.local.OutboxRecords(ctx)
	if err != nil {
		if bootOriginFatal(err) {
			err = fmt.Errorf(
				"%w: validate durable outbox: %v",
				ErrBootOriginIntegrity,
				err,
			)
			origin.recordFatal(err)
		}
		return err
	}
	for _, record := range records {
		if record.OriginScopeKind != store.OriginScopeKindBoot {
			continue
		}
		scope := store.OutboxScope{
			OriginDeviceID:  record.OriginDeviceID,
			OriginScopeKind: record.OriginScopeKind,
			OriginScopeID:   record.OriginScopeID,
		}
		if _, err := origin.validateBootOutboxRecord(
			record,
			scope,
		); err != nil {
			origin.recordFatal(err)
			return err
		}
	}
	origin.recovered = true
	origin.wakeWorker()
	return nil
}

// RunExclusive drains every earlier command from this boot scope, then invokes
// operation once while all normal reservations and the recovery worker are
// excluded.
func (origin *BootOrigin) RunExclusive(
	ctx context.Context,
	operation func(
		func(
			context.Context,
			domain.Checkpoint,
			store.Signature,
		) (event.SignedEvent, error),
	) error,
) error {
	if err := origin.available(); err != nil {
		return err
	}
	if ctx == nil || operation == nil {
		return ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()

	for {
		if err := origin.acquireExclusive(operationContext); err != nil {
			return err
		}
		status, err := origin.drainScopeLocked(
			operationContext,
			origin.scope,
		)
		if err != nil {
			origin.releaseExclusive()
			if bootOriginFatal(err) {
				origin.recordFatal(err)
			}
			return err
		}
		if status == bootDrainBlocked {
			origin.releaseExclusive()
			if !waitBootOriginRetry(
				operationContext,
				pairingOutboxPollInterval,
			) {
				return operationContext.Err()
			}
			continue
		}

		var reservationMu sync.Mutex
		active := true
		reserve := func(
			reservationContext context.Context,
			checkpoint domain.Checkpoint,
			signature store.Signature,
		) (event.SignedEvent, error) {
			reservationMu.Lock()
			defer reservationMu.Unlock()
			if !active {
				return event.SignedEvent{}, ErrClosed
			}
			return origin.reserveCheckpoint(
				reservationContext,
				checkpoint,
				signature,
			)
		}
		err = operation(reserve)
		reservationMu.Lock()
		active = false
		reservationMu.Unlock()
		origin.releaseExclusive()
		origin.signalResult()
		origin.wakeWorker()
		if bootOriginFatal(err) {
			origin.recordFatal(err)
		}
		return err
	}
}

// RunOrderedBootReservation drains earlier commands from the current boot
// scope and reserves one external command while checkpoint capture and the
// boot worker are excluded.
func (origin *BootOrigin) RunOrderedBootReservation(
	ctx context.Context,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
	operation func(context.Context) error,
) error {
	if err := origin.available(); err != nil {
		return err
	}
	if ctx == nil ||
		operation == nil ||
		sessionID != origin.sessionID ||
		workspaceID != origin.workspaceID ||
		deviceID != origin.deviceID ||
		bootID != origin.originBootID {
		if ctx != nil &&
			operation != nil &&
			sessionID.Valid() &&
			workspaceID.Valid() &&
			deviceID.Valid() &&
			bootID.Valid() {
			err := fmt.Errorf(
				"%w: ordered reservation binding mismatch",
				ErrBootOriginIntegrity,
			)
			origin.recordFatal(err)
			return err
		}
		return ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()

	for {
		if err := origin.acquireExclusive(operationContext); err != nil {
			return err
		}
		status, err := origin.drainScopeLocked(
			operationContext,
			origin.scope,
		)
		if err != nil {
			origin.releaseExclusive()
			if bootOriginFatal(err) {
				origin.recordFatal(err)
			}
			return err
		}
		if status == bootDrainBlocked {
			origin.releaseExclusive()
			if !waitBootOriginRetry(
				operationContext,
				pairingOutboxPollInterval,
			) {
				return operationContext.Err()
			}
			continue
		}

		err = operation(operationContext)
		origin.releaseExclusive()
		origin.wakeWorker()
		if bootOriginFatal(err) {
			origin.recordFatal(err)
		}
		return err
	}
}

// RunBootReservation serializes an atomic external boot-scope reservation
// with checkpoint capture and wakes replay even when the caller's commit
// outcome is uncertain.
func (origin *BootOrigin) RunBootReservation(
	ctx context.Context,
	operation func(context.Context) error,
) error {
	if err := origin.available(); err != nil {
		return err
	}
	if ctx == nil || operation == nil {
		return ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	if err := origin.acquireShared(operationContext); err != nil {
		return err
	}
	err := operation(operationContext)
	origin.releaseShared()
	origin.wakeWorker()
	if bootOriginFatal(err) {
		origin.recordFatal(err)
	}
	return err
}

func (origin *BootOrigin) reserveCheckpoint(
	ctx context.Context,
	checkpoint domain.Checkpoint,
	signature store.Signature,
) (event.SignedEvent, error) {
	if ctx == nil {
		return event.SignedEvent{}, ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return event.SignedEvent{}, err
	}
	payload, err := event.EncodeCheckpointPayload(
		checkpoint,
		[ed25519.SignatureSize]byte(signature),
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	requestID, err := origin.generateID()
	if err != nil {
		return event.SignedEvent{}, err
	}
	if !requestID.Valid() {
		return event.SignedEvent{}, ErrInvalidOptions
	}
	now := origin.clock()
	if !now.Valid() {
		return event.SignedEvent{}, ErrInvalidOptions
	}
	canonicalRequest, err := canonicalObject(map[string]any{
		"checkpoint": json.RawMessage(payload),
		"operation":  event.KindConsensusCheckpoint,
		"request_id": requestID,
	})
	if err != nil {
		return event.SignedEvent{}, err
	}
	record, _, err := origin.local.ReserveCommand(
		ctx,
		store.LocalCommandInput{
			ClientInstanceID: origin.originBootID,
			RequestID:        requestID,
			SessionID:        origin.sessionID,
			WorkspaceID:      origin.workspaceID,
			BindingClass:     store.LocalBindingDaemon,
			OriginDeviceID:   origin.deviceID,
			OriginScopeKind:  store.OriginScopeKindBoot,
			OriginScopeID:    origin.originBootID,
			RequestKind:      event.KindConsensusCheckpoint,
			CanonicalRequest: canonicalRequest,
			CreatedAt:        now,
		},
		store.UUIDv7Generator(origin.generateID),
		func(
			eventID domain.UUIDv7,
			originSequence uint64,
		) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				event.Command{
					Kind:             event.KindConsensusCheckpoint,
					EntityID:         event.NullEntityID(),
					RationaleSummary: "",
					Actions:          []event.Action{},
					Payload:          payload,
					Redaction:        defaultRedaction(),
				},
				origin.daemonBinding,
				event.BuildContext{
					EventID:        eventID,
					SessionID:      origin.sessionID,
					WorkspaceID:    origin.workspaceID,
					CreatedAt:      now,
					OriginSequence: originSequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, origin.privateKey)
		},
	)
	if err != nil {
		return event.SignedEvent{}, err
	}
	return origin.parseReserved(record)
}

func (origin *BootOrigin) submitDaemonCommand(
	ctx context.Context,
	kind event.Kind,
	entityID event.EntityID,
	expectedVersion uint64,
	payload []byte,
	requestFields map[string]any,
) (store.CommandOutcome, error) {
	_, knownKind := event.LookupKind(kind)
	if err := origin.available(); err != nil {
		return store.CommandOutcome{}, err
	}
	if ctx == nil ||
		!knownKind ||
		expectedVersion < 1 ||
		!domain.ValidUnsignedInteger(expectedVersion) ||
		len(payload) == 0 ||
		requestFields == nil {
		return store.CommandOutcome{}, ErrInvalidOptions
	}
	operationContext, cancel := origin.operationContext(ctx)
	defer cancel()
	if err := origin.acquireShared(operationContext); err != nil {
		return store.CommandOutcome{}, err
	}
	record, err := origin.reserveDaemonCommandLocked(
		operationContext,
		kind,
		entityID,
		expectedVersion,
		payload,
		requestFields,
	)
	origin.releaseShared()
	if err != nil {
		return store.CommandOutcome{}, err
	}
	origin.wakeWorker()
	resolved, err := origin.waitResolved(operationContext, record)
	if err != nil {
		return store.CommandOutcome{}, err
	}
	if resolved.Outcome == nil {
		return store.CommandOutcome{}, ErrCommandForwarding
	}
	return *resolved.Outcome, nil
}

func (origin *BootOrigin) reserveDaemonCommandLocked(
	ctx context.Context,
	kind event.Kind,
	entityID event.EntityID,
	expectedVersion uint64,
	payload []byte,
	requestFields map[string]any,
) (store.LocalCommandRecord, error) {
	requestID, err := origin.generateID()
	if err != nil {
		return store.LocalCommandRecord{}, err
	}
	if !requestID.Valid() {
		return store.LocalCommandRecord{}, ErrInvalidOptions
	}
	now := origin.clock()
	if !now.Valid() {
		return store.LocalCommandRecord{}, ErrInvalidOptions
	}
	fields := make(map[string]any, len(requestFields)+3)
	for key, value := range requestFields {
		fields[key] = value
	}
	fields["expected_entity_version"] = expectedVersion
	fields["operation"] = kind
	fields["request_id"] = requestID
	canonicalRequest, err := canonicalObject(fields)
	if err != nil {
		return store.LocalCommandRecord{}, err
	}
	record, _, err := origin.local.ReserveCommand(
		ctx,
		store.LocalCommandInput{
			ClientInstanceID: origin.originBootID,
			RequestID:        requestID,
			SessionID:        origin.sessionID,
			WorkspaceID:      origin.workspaceID,
			BindingClass:     store.LocalBindingDaemon,
			OriginDeviceID:   origin.deviceID,
			OriginScopeKind:  store.OriginScopeKindBoot,
			OriginScopeID:    origin.originBootID,
			RequestKind:      kind,
			CanonicalRequest: canonicalRequest,
			CreatedAt:        now,
		},
		store.UUIDv7Generator(origin.generateID),
		func(
			eventID domain.UUIDv7,
			originSequence uint64,
		) (event.SignedEvent, error) {
			proposal, err := event.BuildProposal(
				event.Command{
					Kind:                  kind,
					EntityID:              entityID,
					ExpectedEntityVersion: &expectedVersion,
					RationaleSummary:      "",
					Actions:               []event.Action{},
					Payload:               payload,
					Redaction:             defaultRedaction(),
				},
				origin.daemonBinding,
				event.BuildContext{
					EventID:        eventID,
					SessionID:      origin.sessionID,
					WorkspaceID:    origin.workspaceID,
					CreatedAt:      now,
					OriginSequence: originSequence,
				},
			)
			if err != nil {
				return event.SignedEvent{}, err
			}
			return event.Sign(proposal, origin.privateKey)
		},
	)
	return record, err
}

func (origin *BootOrigin) parseReserved(
	record store.LocalCommandRecord,
) (event.SignedEvent, error) {
	signed, err := event.ParseAndVerify(
		record.SignedProposal,
		event.VerificationContext{
			SessionID:         origin.sessionID,
			WorkspaceID:       origin.workspaceID,
			IdentityPublicKey: origin.publicKey,
		},
	)
	if err != nil ||
		!bytes.Equal(signed.CanonicalBytes(), record.SignedProposal) {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: reserved proposal failed verification",
			ErrBootOriginIntegrity,
		)
	}
	proposal := signed.Proposal()
	if proposal.EventID != record.EventID ||
		proposal.Origin.Sequence() != record.OriginSequence ||
		proposal.Kind != record.RequestKind ||
		record.OriginDeviceID != origin.deviceID ||
		record.OriginScopeKind != store.OriginScopeKindBoot ||
		record.OriginScopeID != origin.originBootID {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: reserved proposal binding mismatch",
			ErrBootOriginIntegrity,
		)
	}
	return signed, nil
}

type bootDrainStatus uint8

const (
	bootDrainEmpty bootDrainStatus = iota
	bootDrainBlocked
)

func (origin *BootOrigin) drainScopeLocked(
	ctx context.Context,
	scope store.OutboxScope,
) (bootDrainStatus, error) {
	for {
		record, found, err := origin.local.ClaimNextOutbox(ctx, scope)
		if err != nil {
			return bootDrainEmpty, err
		}
		if !found {
			return bootDrainEmpty, nil
		}
		signed, err := origin.validateBootOutboxRecord(record, scope)
		if err != nil {
			return bootDrainEmpty, err
		}
		proposal := signed.Proposal()
		if proposal.Kind == event.KindMembershipDeviceAdmitted {
			return bootDrainBlocked, nil
		}
		specification, known := event.LookupKind(proposal.Kind)
		if !known {
			return bootDrainEmpty, fmt.Errorf(
				"%w: durable outbox kind is unknown",
				ErrBootOriginIntegrity,
			)
		}
		if specification.LeaderScheduled() &&
			proposal.Origin.ActorType() == event.ActorDaemon &&
			!origin.consensus.IsLeader() {
			return bootDrainBlocked, nil
		}
		result, err := origin.consensus.ApplyAtGeneration(
			ctx,
			record.SessionID,
			record.RecoveryGeneration,
			signed,
		)
		if err != nil {
			if errors.Is(err, store.ErrIdempotencyConflict) {
				resolved, abandonErr := abandonOutboxCollision(
					ctx,
					origin.local,
					record,
				)
				if abandonErr != nil {
					return bootDrainEmpty, abandonErr
				}
				if resolved {
					origin.signalResult()
					continue
				}
				return bootDrainEmpty, fmt.Errorf(
					"%w: event ID collision poisoned boot scope",
					ErrBootOriginIntegrity,
				)
			}
			return bootDrainEmpty, err
		}
		if originSequenceRejected(result.Outcome) {
			return bootDrainEmpty, fmt.Errorf(
				"%w: committed command rejected its durable boot sequence",
				ErrBootOriginIntegrity,
			)
		}
		if proposal.Kind == event.KindConsensusCheckpoint {
			for {
				err := origin.consensus.VerifyCheckpointReplay(
					ctx,
					signed,
					result,
				)
				if err == nil {
					break
				}
				if contextErr := ctx.Err(); contextErr != nil {
					return bootDrainEmpty, contextErr
				}
				if fatal := origin.consensus.FatalError(); fatal != nil {
					return bootDrainEmpty, fmt.Errorf(
						"%w: verify replayed checkpoint: %v",
						ErrBootOriginIntegrity,
						fatal,
					)
				}
				if bootOriginFatal(err) {
					return bootDrainEmpty, fmt.Errorf(
						"%w: verify replayed checkpoint: %v",
						ErrBootOriginIntegrity,
						err,
					)
				}
				if !waitBootOriginRetry(ctx, outboxRetryDelay) {
					return bootDrainEmpty, ctx.Err()
				}
			}
		}
		origin.signalResult()
	}
}

func (origin *BootOrigin) validateBootOutboxRecord(
	record store.OutboxRecord,
	scope store.OutboxScope,
) (event.SignedEvent, error) {
	if scope.OriginScopeKind != store.OriginScopeKindBoot ||
		scope.OriginDeviceID != origin.deviceID {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: boot queue belongs to another device or scope",
			ErrBootOriginIntegrity,
		)
	}
	signed, err := event.ParseAndVerify(
		record.SignedProposal,
		event.VerificationContext{
			SessionID:         origin.sessionID,
			WorkspaceID:       origin.workspaceID,
			IdentityPublicKey: origin.publicKey,
		},
	)
	if err != nil ||
		!bytes.Equal(signed.CanonicalBytes(), record.SignedProposal) ||
		!outboxRecordMatchesSigned(record, signed) {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: durable outbox binding mismatch",
			ErrBootOriginIntegrity,
		)
	}
	proposal := signed.Proposal()
	if proposal.Origin.DeviceID() != origin.deviceID ||
		proposal.Origin.ActorType() == event.ActorAgent ||
		proposal.Origin.OriginBootID() != scope.OriginScopeID ||
		proposal.Origin.AgentSessionID() != "" {
		return event.SignedEvent{}, fmt.Errorf(
			"%w: invalid boot-origin proposal",
			ErrBootOriginIntegrity,
		)
	}
	return signed, nil
}

func (origin *BootOrigin) drainBootQueues(
	ctx context.Context,
) (bool, error) {
	if err := origin.acquireShared(ctx); err != nil {
		return false, err
	}
	defer origin.releaseShared()
	scopes, err := origin.local.OutboxScopes(ctx)
	if err != nil {
		return false, err
	}
	pending := false
	for _, scope := range scopes {
		if scope.OriginScopeKind != store.OriginScopeKindBoot {
			continue
		}
		if scope.OriginDeviceID != origin.deviceID {
			return false, fmt.Errorf(
				"%w: boot queue belongs to another device",
				ErrBootOriginIntegrity,
			)
		}
		status, err := origin.drainScopeLocked(ctx, scope)
		if err != nil {
			return false, err
		}
		pending = pending || status == bootDrainBlocked
	}
	return pending, nil
}

func (origin *BootOrigin) run() {
	defer origin.done.Done()
	for {
		select {
		case <-origin.wake:
		case <-origin.ctx.Done():
			return
		}
		for {
			pending, err := origin.drainBootQueues(origin.ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) ||
					errors.Is(err, store.ErrClosed) ||
					errors.Is(err, ErrClosed) {
					return
				}
				if bootOriginFatal(err) {
					origin.recordFatal(err)
					return
				}
				if !waitBootOriginRetry(
					origin.ctx,
					outboxRetryDelay,
				) {
					return
				}
				continue
			}
			if !pending {
				break
			}
			if !waitBootOriginRetry(
				origin.ctx,
				pairingOutboxPollInterval,
			) {
				return
			}
		}
	}
}

func (origin *BootOrigin) wakeWorker() {
	if origin == nil {
		return
	}
	origin.mu.Lock()
	if origin.closed {
		origin.mu.Unlock()
		return
	}
	if !origin.workerStarted {
		origin.workerStarted = true
		origin.done.Add(1)
		go origin.run()
	}
	select {
	case origin.wake <- struct{}{}:
	default:
	}
	origin.mu.Unlock()
}

func (origin *BootOrigin) waitResolved(
	ctx context.Context,
	record store.LocalCommandRecord,
) (store.LocalCommandRecord, error) {
	for {
		current, found, err := origin.local.LookupRequest(
			ctx,
			record.ClientInstanceID,
			record.RequestID,
		)
		if err != nil {
			return store.LocalCommandRecord{}, err
		}
		if !found {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		if current.State == store.LocalRequestResolved {
			return current, nil
		}
		if current.State == store.LocalRequestAbandoned ||
			current.State == store.LocalRequestExpired {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		origin.mu.Lock()
		signal := origin.resultSignal
		origin.mu.Unlock()
		current, found, err = origin.local.LookupRequest(
			ctx,
			record.ClientInstanceID,
			record.RequestID,
		)
		if err != nil {
			return store.LocalCommandRecord{}, err
		}
		if !found {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		if current.State == store.LocalRequestResolved {
			return current, nil
		}
		if current.State == store.LocalRequestAbandoned ||
			current.State == store.LocalRequestExpired {
			return store.LocalCommandRecord{}, ErrCommandForwarding
		}
		select {
		case <-signal:
		case <-ctx.Done():
			return store.LocalCommandRecord{}, ctx.Err()
		case <-origin.ctx.Done():
			return store.LocalCommandRecord{}, ErrClosed
		}
	}
}

func (origin *BootOrigin) signalResult() {
	origin.mu.Lock()
	close(origin.resultSignal)
	origin.resultSignal = make(chan struct{})
	origin.mu.Unlock()
}

func (origin *BootOrigin) acquireShared(ctx context.Context) error {
	if origin == nil || origin.lane == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if err := origin.lane.Acquire(ctx, 1); err != nil {
		return err
	}
	return nil
}

func (origin *BootOrigin) releaseShared() {
	origin.lane.Release(1)
}

func (origin *BootOrigin) acquireExclusive(ctx context.Context) error {
	if origin == nil || origin.lane == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if err := origin.lane.Acquire(
		ctx,
		bootOriginLaneCapacity,
	); err != nil {
		return err
	}
	return nil
}

func (origin *BootOrigin) releaseExclusive() {
	origin.lane.Release(bootOriginLaneCapacity)
}

func (origin *BootOrigin) operationContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	operationContext, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(origin.ctx, cancel)
	if origin.ctx.Err() != nil {
		cancel()
	}
	return operationContext, func() {
		stop()
		cancel()
	}
}

func (origin *BootOrigin) available() error {
	if origin == nil ||
		origin.consensus == nil ||
		!origin.sessionID.Valid() ||
		!origin.workspaceID.Valid() ||
		!origin.deviceID.Valid() ||
		!origin.originBootID.Valid() ||
		origin.lane == nil {
		return ErrInvalidOptions
	}
	origin.mu.Lock()
	closed := origin.closed
	origin.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return origin.FatalError()
}

func (origin *BootOrigin) matches(
	local store.LocalState,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	deviceID domain.DeviceID,
	bootID domain.UUIDv7,
) bool {
	return origin != nil &&
		origin.local == local &&
		origin.sessionID == sessionID &&
		origin.workspaceID == workspaceID &&
		origin.deviceID == deviceID &&
		origin.originBootID == bootID
}

func (origin *BootOrigin) recordFatal(cause error) {
	if origin == nil || cause == nil {
		return
	}
	origin.fatalOnce.Do(func() {
		origin.fatalMu.Lock()
		origin.fatalErr = cause
		origin.fatalMu.Unlock()
		origin.cancel()
	})
}

func (origin *BootOrigin) FatalError() error {
	if origin == nil {
		return ErrInvalidOptions
	}
	origin.fatalMu.RLock()
	defer origin.fatalMu.RUnlock()
	return origin.fatalErr
}

// BeginClose cancels producers and workers without waiting for an in-flight
// consensus future. The node owner can then close Raft before calling Wait.
func (origin *BootOrigin) BeginClose() error {
	if origin == nil {
		return ErrInvalidOptions
	}
	origin.mu.Lock()
	if origin.closed {
		origin.mu.Unlock()
		return nil
	}
	origin.closed = true
	origin.cancel()
	origin.mu.Unlock()
	return nil
}

// Wait joins workers and clears the origin's private-key copy.
func (origin *BootOrigin) Wait() error {
	if origin == nil {
		return ErrInvalidOptions
	}
	if err := origin.BeginClose(); err != nil {
		return err
	}
	origin.done.Wait()
	if err := origin.acquireExclusive(context.Background()); err != nil {
		return err
	}
	defer origin.releaseExclusive()
	origin.clearOnce.Do(func() {
		clear(origin.privateKey)
	})
	return nil
}

func (origin *BootOrigin) Close() error {
	if err := origin.BeginClose(); err != nil {
		return err
	}
	return origin.Wait()
}

func bootOriginFatal(err error) bool {
	return errors.Is(err, ErrBootOriginIntegrity) ||
		errors.Is(err, store.ErrLocalStateIntegrity) ||
		errors.Is(err, store.ErrIntegrityCheck) ||
		errors.Is(err, store.ErrCorrupt) ||
		errors.Is(err, store.ErrIdempotencyConflict)
}

func waitBootOriginRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
