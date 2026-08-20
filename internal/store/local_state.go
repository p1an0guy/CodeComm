package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	MaxUnresolvedCommandsPerOrigin       = 256
	MaxUnresolvedCommandsPerSession      = 4096
	ReservedCheckpointCommandsPerSession = 1
)

var (
	ErrInvalidLocalState        = errors.New("store: invalid local state request")
	ErrLocalLineageMismatch     = errors.New("store: local request lineage mismatch")
	ErrLocalIdempotencyConflict = errors.New("store: local idempotency conflict")
	ErrLocalBackpressure        = errors.New("store: local command backpressure")
	ErrOriginSequenceExhausted  = errors.New("store: origin sequence exhausted")
	ErrOriginScopeUninitialized = errors.New("store: origin scope is not initialized")
	ErrLocalStateIntegrity      = errors.New("store: local state integrity failure")
	ErrOutboxEmpty              = errors.New("store: outbox is empty")
	ErrManagedRootConflict      = errors.New("store: managed root conflicts with existing state")
	ErrManagedRootUnavailable   = errors.New("store: managed root is unavailable")
	ErrLaunchConflict           = errors.New("store: launch registration conflicts with existing state")
	ErrLaunchNotFound           = errors.New("store: launch registration not found")
	ErrLaunchUnavailable        = errors.New("store: launch registration is unavailable")
	ErrLaunchPending            = errors.New("store: launch start has no committed result")
	ErrResumeRejected           = errors.New("store: agent resume rejected")
)

// LocalState is a restricted capability for local-only durable state. It
// intentionally exposes neither Store.Close nor the underlying SQLite pool.
type LocalState struct {
	store          *Store
	operationGuard *localStateOperationGuard
}

// LocalState returns the local-only state capability owned by store.
func (store *Store) LocalState() LocalState {
	return LocalState{store: store}
}

// LocalStateOperationGuard starts one capability operation. A successful
// guard must return a non-nil release function that remains held until the
// complete SQLite operation finishes.
type LocalStateOperationGuard func() (release func(), err error)

type localStateOperationGuard struct {
	begin LocalStateOperationGuard
}

// LocalStateWithGuard returns a local-only capability whose every operation
// is covered by guard. It lets a higher-level runtime revoke already-issued
// capabilities before publishing terminal state or closing their store.
func (store *Store) LocalStateWithGuard(
	guard LocalStateOperationGuard,
) LocalState {
	if guard == nil {
		return LocalState{}
	}
	return LocalState{
		store: store,
		operationGuard: &localStateOperationGuard{
			begin: guard,
		},
	}
}

type LocalBindingClass string

const (
	LocalBindingOperator LocalBindingClass = "operator"
	LocalBindingAgent    LocalBindingClass = "agent"
	LocalBindingDaemon   LocalBindingClass = "daemon"
)

func (class LocalBindingClass) valid() bool {
	switch class {
	case LocalBindingOperator, LocalBindingAgent, LocalBindingDaemon:
		return true
	default:
		return false
	}
}

type LocalRequestState string

const (
	LocalRequestPreparing LocalRequestState = "preparing"
	LocalRequestSigned    LocalRequestState = "signed"
	LocalRequestPending   LocalRequestState = "pending"
	LocalRequestResolved  LocalRequestState = "resolved"
	LocalRequestAbandoned LocalRequestState = "abandoned"
	LocalRequestExpired   LocalRequestState = "expired"
)

func (state LocalRequestState) valid() bool {
	switch state {
	case LocalRequestPreparing,
		LocalRequestSigned,
		LocalRequestPending,
		LocalRequestResolved,
		LocalRequestAbandoned,
		LocalRequestExpired:
		return true
	default:
		return false
	}
}

// LocalCommandInput is the authority-free durable identity of one local
// mutation. CanonicalRequest is hashed but never retained.
type LocalCommandInput struct {
	ClientInstanceID domain.UUIDv7
	RequestID        domain.UUIDv7
	SessionID        domain.UUIDv7
	WorkspaceID      domain.UUIDv4
	BindingClass     LocalBindingClass
	OriginDeviceID   domain.DeviceID
	OriginScopeKind  OriginScopeKind
	OriginScopeID    domain.UUIDv7
	RequestKind      event.Kind
	CanonicalRequest []byte
	CreatedAt        domain.Timestamp
}

// LocalCommandBuilder builds and signs an event after the store has checked
// idempotency, capacity, and sequence availability. It runs inside the local
// transaction and must not call back into this store.
type LocalCommandBuilder func(
	eventID domain.UUIDv7,
	originSequence uint64,
) (event.SignedEvent, error)

// UUIDv7Generator is invoked only after idempotency, lineage, backpressure,
// and sequence-exhaustion checks pass.
type UUIDv7Generator func() (domain.UUIDv7, error)

// LocalCommandReservation contains the authority-bound work needed to reserve
// one exact signed proposal inside a caller-owned local transaction.
type LocalCommandReservation struct {
	Input           LocalCommandInput
	GenerateEventID UUIDv7Generator
	Build           LocalCommandBuilder
}

func (reservation *LocalCommandReservation) validate() (Digest, error) {
	if reservation == nil ||
		reservation.GenerateEventID == nil ||
		reservation.Build == nil {
		return Digest{}, ErrInvalidLocalState
	}
	return reservation.Input.validate()
}

// LocalCommandRecord is one durable local request mapping. SignedProposal is
// present only while unresolved; Outcome is present only after commitment.
type LocalCommandRecord struct {
	ClientInstanceID   domain.UUIDv7
	RequestID          domain.UUIDv7
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	BindingClass       LocalBindingClass
	OriginDeviceID     domain.DeviceID
	OriginScopeKind    OriginScopeKind
	OriginScopeID      domain.UUIDv7
	RequestDigest      Digest
	EventID            domain.UUIDv7
	RequestKind        event.Kind
	State              LocalRequestState
	OriginSequence     uint64
	SignedProposal     []byte
	ProposalDigest     Digest
	Outcome            *CommandOutcome
	TerminalCode       string
	CreatedAt          domain.Timestamp
}

// LocalCommandCollisionInput identifies an exact unresolved local command
// whose event ID is already durably bound to different signed bytes.
type LocalCommandCollisionInput struct {
	ClientInstanceID   domain.UUIDv7
	RequestID          domain.UUIDv7
	SessionID          domain.UUIDv7
	RecoveryGeneration uint64
	EventID            domain.UUIDv7
	ProposalDigest     Digest
}

// OutboxScope identifies one independently ordered proposal queue.
type OutboxScope struct {
	OriginDeviceID  domain.DeviceID
	OriginScopeKind OriginScopeKind
	OriginScopeID   domain.UUIDv7
}

func (scope OutboxScope) validate() error {
	if !scope.OriginDeviceID.Valid() ||
		!validOriginScopeKind(scope.OriginScopeKind) ||
		!scope.OriginScopeID.Valid() {
		return ErrInvalidLocalState
	}
	return nil
}

// OutboxRecord is the exact signed proposal at the head of an origin queue.
type OutboxRecord struct {
	OutboxID           int64
	ClientInstanceID   domain.UUIDv7
	RequestID          domain.UUIDv7
	BindingClass       LocalBindingClass
	EventID            domain.UUIDv7
	SessionID          domain.UUIDv7
	RecoveryGeneration uint64
	OriginDeviceID     domain.DeviceID
	OriginScopeKind    OriginScopeKind
	OriginScopeID      domain.UUIDv7
	OriginSequence     uint64
	Kind               event.Kind
	SignedProposal     []byte
	ProposalDigest     Digest
	State              string
	QueuedAt           domain.Timestamp
}

type localLineage struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
}

func (state LocalState) validate() error {
	if state.store == nil || state.store.pool == nil {
		return ErrInvalidLocalState
	}
	return nil
}

func (state LocalState) beginOperation() (func(), error) {
	if state.operationGuard == nil {
		return func() {}, nil
	}
	release, err := state.operationGuard.begin()
	if err != nil {
		return nil, err
	}
	if release == nil {
		return nil, ErrInvalidLocalState
	}
	return release, nil
}

func (state LocalState) withImmediate(
	ctx context.Context,
	fn func(*sqlite.Conn) error,
) error {
	if err := state.validate(); err != nil {
		return err
	}
	if ctx == nil || fn == nil {
		return fmt.Errorf("%w: nil context or operation", ErrInvalidLocalState)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := state.beginOperation()
	if err != nil {
		return err
	}
	defer release()
	state.store.applyMu.Lock()
	defer state.store.applyMu.Unlock()
	return state.store.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		previousInterrupt := conn.SetInterrupt(ctx.Done())
		defer conn.SetInterrupt(previousInterrupt)
		end, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		defer end(&err)
		return fn(conn)
	})
}

func readLocalLineage(conn *sqlite.Conn) (localLineage, error) {
	consensus, found, err := readConsensusState(conn)
	if err != nil {
		return localLineage{}, err
	}
	if !found {
		return localLineage{}, fmt.Errorf(
			"%w: store has no active generation",
			ErrLocalLineageMismatch,
		)
	}
	var workspaceID domain.UUIDv4
	if err := queryOneArgs(
		conn,
		`SELECT workspace_id
		   FROM genesis_records
		  WHERE recovery_generation = ?1 AND session_id = ?2;`,
		[]any{consensus.recoveryGeneration, string(consensus.sessionID)},
		func(stmt *sqlite.Stmt) {
			workspaceID = domain.UUIDv4(stmt.ColumnText(0))
		},
	); err != nil {
		return localLineage{}, err
	}
	lineage := localLineage{
		sessionID:          consensus.sessionID,
		workspaceID:        workspaceID,
		recoveryGeneration: consensus.recoveryGeneration,
	}
	if !lineage.sessionID.Valid() ||
		!lineage.workspaceID.Valid() ||
		!domain.ValidUnsignedInteger(lineage.recoveryGeneration) {
		return localLineage{}, ErrLocalStateIntegrity
	}
	return lineage, nil
}

func (lineage localLineage) matches(
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
) bool {
	return lineage.sessionID == sessionID &&
		lineage.workspaceID == workspaceID
}

func validateCanonicalLocalRequest(input []byte) (Digest, error) {
	if len(input) == 0 || len(input) > event.MaxLocalCommandBytes {
		return Digest{}, ErrInvalidLocalState
	}
	canonical, err := codec.CanonicalizeSignedObject(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return Digest{}, fmt.Errorf(
			"%w: request must be a canonical JSON object",
			ErrInvalidLocalState,
		)
	}
	return Digest(sha256.Sum256(canonical)), nil
}

func (input LocalCommandInput) validate() (Digest, error) {
	if !input.ClientInstanceID.Valid() ||
		!input.RequestID.Valid() ||
		!input.SessionID.Valid() ||
		!input.WorkspaceID.Valid() ||
		!input.BindingClass.valid() ||
		!input.OriginDeviceID.Valid() ||
		!validOriginScopeKind(input.OriginScopeKind) ||
		!input.OriginScopeID.Valid() ||
		!input.CreatedAt.Valid() {
		return Digest{}, ErrInvalidLocalState
	}
	if _, exists := event.LookupKind(input.RequestKind); !exists {
		return Digest{}, ErrInvalidLocalState
	}
	switch input.BindingClass {
	case LocalBindingAgent:
		if input.OriginScopeKind != OriginScopeKindAgent {
			return Digest{}, ErrInvalidLocalState
		}
	case LocalBindingOperator, LocalBindingDaemon:
		if input.OriginScopeKind != OriginScopeKindBoot {
			return Digest{}, ErrInvalidLocalState
		}
	default:
		return Digest{}, ErrInvalidLocalState
	}
	return validateCanonicalLocalRequest(input.CanonicalRequest)
}

// ReserveCommand atomically allocates the next origin sequence and event ID,
// stores the exact signed proposal, and queues it for forwarding.
func (state LocalState) ReserveCommand(
	ctx context.Context,
	input LocalCommandInput,
	generateEventID UUIDv7Generator,
	build LocalCommandBuilder,
) (LocalCommandRecord, bool, error) {
	reservation := &LocalCommandReservation{
		Input:           input,
		GenerateEventID: generateEventID,
		Build:           build,
	}
	requestDigest, err := reservation.validate()
	if err != nil {
		return LocalCommandRecord{}, false, err
	}

	var (
		result    LocalCommandRecord
		duplicate bool
	)
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		result, duplicate, err = reserveLocalCommand(
			conn,
			reservation,
			requestDigest,
		)
		return err
	})
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	return result, duplicate, nil
}

func reserveLocalCommand(
	conn *sqlite.Conn,
	reservation *LocalCommandReservation,
	requestDigest Digest,
) (LocalCommandRecord, bool, error) {
	if conn == nil || reservation == nil {
		return LocalCommandRecord{}, false, ErrInvalidLocalState
	}
	input := reservation.Input
	lineage, err := readLocalLineage(conn)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	if !lineage.matches(input.SessionID, input.WorkspaceID) {
		return LocalCommandRecord{}, false, ErrLocalLineageMismatch
	}
	existing, found, err := readLocalRequestByKey(
		conn,
		input.ClientInstanceID,
		input.RequestID,
	)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	if found {
		if existing.RecoveryGeneration != lineage.recoveryGeneration ||
			!localRequestMatchesInput(existing, input, requestDigest) {
			return LocalCommandRecord{}, false, ErrLocalIdempotencyConflict
		}
		return existing, true, nil
	}

	if err := checkLocalBackpressure(
		conn,
		lineage,
		input.OriginScopeKind,
		input.OriginScopeID,
		input.RequestKind,
	); err != nil {
		return LocalCommandRecord{}, false, err
	}
	sequence, counterFound, err := nextOriginSequence(
		conn,
		input.OriginDeviceID,
		input.OriginScopeKind,
		input.OriginScopeID,
		input.OriginScopeKind == OriginScopeKindBoot,
	)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	eventID, err := reservation.GenerateEventID()
	if err != nil {
		return LocalCommandRecord{}, false, fmt.Errorf(
			"store: generate event ID: %w",
			err,
		)
	}
	if !eventID.Valid() {
		return LocalCommandRecord{}, false, ErrInvalidLocalState
	}
	signed, err := reservation.Build(eventID, sequence)
	if err != nil {
		return LocalCommandRecord{}, false, fmt.Errorf(
			"store: build signed proposal: %w",
			err,
		)
	}
	if err := validateReservedProposal(
		input,
		eventID,
		sequence,
		signed,
	); err != nil {
		return LocalCommandRecord{}, false, err
	}
	if err := advanceOriginCounter(
		conn,
		input.OriginDeviceID,
		input.OriginScopeKind,
		input.OriginScopeID,
		sequence,
		counterFound,
	); err != nil {
		return LocalCommandRecord{}, false, err
	}
	record, err := insertLocalCommand(
		conn,
		lineage,
		input,
		requestDigest,
		signed,
	)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	return record, false, nil
}

func validateReservedProposal(
	input LocalCommandInput,
	eventID domain.UUIDv7,
	sequence uint64,
	signed event.SignedEvent,
) error {
	return validateReservedProposalFields(
		input,
		eventID,
		sequence,
		signed.Proposal(),
		signed.CanonicalBytes(),
	)
}

func validateReservedProposalFields(
	input LocalCommandInput,
	eventID domain.UUIDv7,
	sequence uint64,
	proposal event.Proposal,
	canonical []byte,
) error {
	if proposal.EventID != eventID ||
		proposal.SessionID != input.SessionID ||
		proposal.WorkspaceID != input.WorkspaceID ||
		proposal.CreatedAt != input.CreatedAt ||
		proposal.Kind != input.RequestKind ||
		proposal.Origin.DeviceID() != input.OriginDeviceID ||
		proposal.Origin.Sequence() != sequence ||
		len(canonical) == 0 {
		return ErrInvalidLocalState
	}
	switch input.BindingClass {
	case LocalBindingAgent:
		if proposal.Origin.ActorType() != event.ActorAgent ||
			proposal.Origin.AgentSessionID() != input.OriginScopeID ||
			proposal.Origin.OriginBootID() != "" {
			return ErrInvalidLocalState
		}
	case LocalBindingOperator:
		if proposal.Origin.ActorType() != event.ActorHuman ||
			proposal.Origin.OriginBootID() != input.OriginScopeID ||
			proposal.Origin.AgentSessionID() != "" {
			return ErrInvalidLocalState
		}
	case LocalBindingDaemon:
		if proposal.Origin.ActorType() != event.ActorDaemon ||
			proposal.Origin.OriginBootID() != input.OriginScopeID ||
			proposal.Origin.AgentSessionID() != "" {
			return ErrInvalidLocalState
		}
	default:
		return ErrInvalidLocalState
	}
	return nil
}

func checkLocalBackpressure(
	conn *sqlite.Conn,
	lineage localLineage,
	scopeKind OriginScopeKind,
	scopeID domain.UUIDv7,
	kind event.Kind,
) error {
	var scopeCount, sessionCount int64
	if err := queryOneArgs(
		conn,
		`SELECT
		    count(*) FILTER (
		        WHERE origin_scope_kind = ?3 AND origin_scope_id = ?4
		    ),
		    count(*)
		   FROM local_requests
		  WHERE session_id = ?1
		    AND recovery_generation = ?2
		    AND state IN ('preparing', 'signed', 'pending');`,
		[]any{
			string(lineage.sessionID),
			lineage.recoveryGeneration,
			scopeKind,
			string(scopeID),
		},
		func(stmt *sqlite.Stmt) {
			scopeCount = stmt.ColumnInt64(0)
			sessionCount = stmt.ColumnInt64(1)
		},
	); err != nil {
		return err
	}
	sessionLimit := int64(
		MaxUnresolvedCommandsPerSession -
			ReservedCheckpointCommandsPerSession,
	)
	if kind == event.KindConsensusCheckpoint {
		sessionLimit = MaxUnresolvedCommandsPerSession
	}
	if scopeCount >= MaxUnresolvedCommandsPerOrigin ||
		sessionCount >= sessionLimit {
		return ErrLocalBackpressure
	}
	return nil
}

func nextOriginSequence(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	scopeKind OriginScopeKind,
	scopeID domain.UUIDv7,
	allowCreate bool,
) (sequence uint64, found bool, err error) {
	var (
		next      int64
		exhausted bool
		rowErr    error
	)
	count := 0
	err = queryArgs(
		conn,
		`SELECT next_sequence, exhausted
		   FROM origin_counters
		  WHERE device_id = ?1 AND scope_kind = ?2 AND scope_id = ?3;`,
		[]any{string(deviceID), scopeKind, string(scopeID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			exhausted = stmt.ColumnBool(1)
			if stmt.ColumnType(0) != sqlite.TypeNull {
				next = stmt.ColumnInt64(0)
			}
		},
	)
	if err != nil {
		return 0, false, err
	}
	if rowErr != nil {
		return 0, false, rowErr
	}
	if !found {
		if !allowCreate {
			return 0, false, ErrOriginScopeUninitialized
		}
		return 1, false, nil
	}
	if exhausted {
		return 0, true, ErrOriginSequenceExhausted
	}
	if next < 1 || !domain.ValidUnsignedInteger(uint64(next)) {
		return 0, true, ErrLocalStateIntegrity
	}
	return uint64(next), true, nil
}

func advanceOriginCounter(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	scopeKind OriginScopeKind,
	scopeID domain.UUIDv7,
	sequence uint64,
	found bool,
) error {
	if sequence < 1 || !domain.ValidUnsignedInteger(sequence) {
		return ErrInvalidLocalState
	}
	if !found {
		if sequence != 1 {
			return ErrLocalStateIntegrity
		}
		return execute(
			conn,
			`INSERT INTO origin_counters(
			    device_id, scope_kind, scope_id, next_sequence, exhausted
			) VALUES (?1, ?2, ?3, 2, 0);`,
			string(deviceID),
			scopeKind,
			string(scopeID),
		)
	}
	if sequence == domain.MaxSafeInteger {
		return execute(
			conn,
			`UPDATE origin_counters
			    SET next_sequence = NULL, exhausted = 1
			  WHERE device_id = ?1 AND scope_kind = ?2 AND scope_id = ?3
			    AND next_sequence = ?4 AND exhausted = 0;`,
			string(deviceID),
			scopeKind,
			string(scopeID),
			sequence,
		)
	}
	return execute(
		conn,
		`UPDATE origin_counters
		    SET next_sequence = ?5
		  WHERE device_id = ?1 AND scope_kind = ?2 AND scope_id = ?3
		    AND next_sequence = ?4 AND exhausted = 0;`,
		string(deviceID),
		scopeKind,
		string(scopeID),
		sequence,
		sequence+1,
	)
}

func insertLocalCommand(
	conn *sqlite.Conn,
	lineage localLineage,
	input LocalCommandInput,
	requestDigest Digest,
	signed event.SignedEvent,
) (LocalCommandRecord, error) {
	proposal := signed.Proposal()
	digest := proposalDigest(signed)
	if err := execute(
		conn,
		`INSERT INTO local_requests(
		    client_instance_id, request_id, session_id, workspace_id,
		    recovery_generation, binding_class, origin_device_id,
		    origin_scope_kind, origin_scope_id, request_digest, event_id,
		    request_kind, state, signed_proposal_json, proposal_digest,
		    terminal_code, created_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
		    'signed', ?13, ?14, NULL, ?15
		);`,
		string(input.ClientInstanceID),
		string(input.RequestID),
		string(input.SessionID),
		string(input.WorkspaceID),
		lineage.recoveryGeneration,
		string(input.BindingClass),
		string(input.OriginDeviceID),
		input.OriginScopeKind,
		string(input.OriginScopeID),
		requestDigest[:],
		string(proposal.EventID),
		string(input.RequestKind),
		string(signed.CanonicalBytes()),
		digest[:],
		string(input.CreatedAt),
	); err != nil {
		return LocalCommandRecord{}, err
	}
	if err := execute(
		conn,
		`INSERT INTO outbox(
		    event_id, session_id, recovery_generation, origin_device_id,
		    origin_scope_kind, origin_scope_id, origin_sequence, kind,
		    signed_proposal_json, proposal_digest, state, queued_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued', ?11
		);`,
		string(proposal.EventID),
		string(proposal.SessionID),
		lineage.recoveryGeneration,
		string(proposal.Origin.DeviceID()),
		input.OriginScopeKind,
		string(input.OriginScopeID),
		proposal.Origin.Sequence(),
		string(proposal.Kind),
		string(signed.CanonicalBytes()),
		digest[:],
		string(input.CreatedAt),
	); err != nil {
		return LocalCommandRecord{}, err
	}
	return LocalCommandRecord{
		ClientInstanceID:   input.ClientInstanceID,
		RequestID:          input.RequestID,
		SessionID:          input.SessionID,
		WorkspaceID:        input.WorkspaceID,
		RecoveryGeneration: lineage.recoveryGeneration,
		BindingClass:       input.BindingClass,
		OriginDeviceID:     input.OriginDeviceID,
		OriginScopeKind:    input.OriginScopeKind,
		OriginScopeID:      input.OriginScopeID,
		RequestDigest:      requestDigest,
		EventID:            proposal.EventID,
		RequestKind:        input.RequestKind,
		State:              LocalRequestSigned,
		OriginSequence:     proposal.Origin.Sequence(),
		SignedProposal:     signed.CanonicalBytes(),
		ProposalDigest:     digest,
		CreatedAt:          input.CreatedAt,
	}, nil
}

func localRequestMatchesInput(
	record LocalCommandRecord,
	input LocalCommandInput,
	requestDigest Digest,
) bool {
	return record.ClientInstanceID == input.ClientInstanceID &&
		record.RequestID == input.RequestID &&
		record.SessionID == input.SessionID &&
		record.WorkspaceID == input.WorkspaceID &&
		record.BindingClass == input.BindingClass &&
		record.OriginDeviceID == input.OriginDeviceID &&
		record.OriginScopeKind == input.OriginScopeKind &&
		record.OriginScopeID == input.OriginScopeID &&
		record.RequestDigest == requestDigest &&
		record.RequestKind == input.RequestKind
}

// LookupRequest reads one durable idempotency mapping and, when resolved, its
// immutable command outcome.
func (state LocalState) LookupRequest(
	ctx context.Context,
	clientInstanceID domain.UUIDv7,
	requestID domain.UUIDv7,
) (LocalCommandRecord, bool, error) {
	if !clientInstanceID.Valid() || !requestID.Valid() {
		return LocalCommandRecord{}, false, ErrInvalidLocalState
	}
	var (
		record LocalCommandRecord
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		record, found, err = readLocalRequestByKey(
			conn,
			clientInstanceID,
			requestID,
		)
		return err
	})
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	return record, found, nil
}

func readLocalRequestByKey(
	conn *sqlite.Conn,
	clientInstanceID domain.UUIDv7,
	requestID domain.UUIDv7,
) (LocalCommandRecord, bool, error) {
	var (
		record LocalCommandRecord
		found  bool
		rowErr error
	)
	count := 0
	err := queryArgs(
		conn,
		`SELECT client_instance_id, request_id, session_id, workspace_id,
		        recovery_generation, binding_class, origin_device_id,
		        origin_scope_kind, origin_scope_id, request_digest, event_id,
		        request_kind, state, signed_proposal_json, proposal_digest,
		        terminal_code, created_at
		   FROM local_requests
		  WHERE client_instance_id = ?1 AND request_id = ?2;`,
		[]any{string(clientInstanceID), string(requestID)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			record, rowErr = scanLocalCommandRecord(stmt)
		},
	)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	if rowErr != nil {
		return LocalCommandRecord{}, false, rowErr
	}
	if !found {
		return LocalCommandRecord{}, false, nil
	}
	if err := validateLocalCommandRecord(record); err != nil {
		return LocalCommandRecord{}, false, err
	}
	if record.State == LocalRequestResolved {
		stored, exists, err := readStoredCommandResult(conn, record.EventID)
		if err != nil {
			return LocalCommandRecord{}, false, err
		}
		if !exists {
			return LocalCommandRecord{}, false, ErrLocalStateIntegrity
		}
		if err := verifyStoredCommandResult(conn, stored); err != nil {
			return LocalCommandRecord{}, false, err
		}
		if stored.sessionID != record.SessionID ||
			stored.recoveryGeneration != record.RecoveryGeneration ||
			stored.proposalDigest != record.ProposalDigest ||
			stored.outcome.Code != record.TerminalCode {
			return LocalCommandRecord{}, false, ErrLocalStateIntegrity
		}
		outcome := stored.outcome
		outcome.JSON = bytes.Clone(stored.outcome.JSON)
		record.Outcome = &outcome
	}
	if len(record.SignedProposal) != 0 {
		var generation, sequence int64
		if err := queryOneArgs(
			conn,
			`SELECT recovery_generation, origin_sequence
			   FROM outbox
			  WHERE event_id = ?1;`,
			[]any{string(record.EventID)},
			func(stmt *sqlite.Stmt) {
				generation = stmt.ColumnInt64(0)
				sequence = stmt.ColumnInt64(1)
			},
		); err != nil {
			return LocalCommandRecord{}, false, err
		}
		if generation < 0 ||
			uint64(generation) != record.RecoveryGeneration ||
			sequence < 1 {
			return LocalCommandRecord{}, false, ErrLocalStateIntegrity
		}
		record.OriginSequence = uint64(sequence)
	}
	return record, true, nil
}

func scanLocalCommandRecord(
	stmt *sqlite.Stmt,
) (LocalCommandRecord, error) {
	record := LocalCommandRecord{
		ClientInstanceID: domain.UUIDv7(stmt.ColumnText(0)),
		RequestID:        domain.UUIDv7(stmt.ColumnText(1)),
		SessionID:        domain.UUIDv7(stmt.ColumnText(2)),
		WorkspaceID:      domain.UUIDv4(stmt.ColumnText(3)),
		BindingClass:     LocalBindingClass(stmt.ColumnText(5)),
		OriginDeviceID:   domain.DeviceID(stmt.ColumnText(6)),
		OriginScopeKind:  stmt.ColumnText(7),
		OriginScopeID:    domain.UUIDv7(stmt.ColumnText(8)),
		EventID:          domain.UUIDv7(stmt.ColumnText(10)),
		RequestKind:      event.Kind(stmt.ColumnText(11)),
		State:            LocalRequestState(stmt.ColumnText(12)),
		CreatedAt:        domain.Timestamp(stmt.ColumnText(16)),
	}
	generation := stmt.ColumnInt64(4)
	if generation < 0 {
		return LocalCommandRecord{}, ErrLocalStateIntegrity
	}
	record.RecoveryGeneration = uint64(generation)
	if err := copyDigestColumn(&record.RequestDigest, stmt, 9); err != nil {
		return LocalCommandRecord{}, err
	}
	if stmt.ColumnType(13) != sqlite.TypeNull {
		record.SignedProposal = []byte(stmt.ColumnText(13))
	}
	if stmt.ColumnType(14) != sqlite.TypeNull {
		if err := copyDigestColumn(
			&record.ProposalDigest,
			stmt,
			14,
		); err != nil {
			return LocalCommandRecord{}, err
		}
	}
	if stmt.ColumnType(15) != sqlite.TypeNull {
		record.TerminalCode = stmt.ColumnText(15)
	}
	return record, nil
}

func validateLocalCommandRecord(record LocalCommandRecord) error {
	if !record.ClientInstanceID.Valid() ||
		!record.RequestID.Valid() ||
		!record.SessionID.Valid() ||
		!record.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		!record.BindingClass.valid() ||
		!record.OriginDeviceID.Valid() ||
		!validOriginScopeKind(record.OriginScopeKind) ||
		!record.OriginScopeID.Valid() ||
		!record.EventID.Valid() ||
		!record.State.valid() ||
		!record.CreatedAt.Valid() {
		return ErrLocalStateIntegrity
	}
	if _, exists := event.LookupKind(record.RequestKind); !exists {
		return ErrLocalStateIntegrity
	}
	switch record.State {
	case LocalRequestSigned, LocalRequestPending:
		if len(record.SignedProposal) == 0 || record.TerminalCode != "" {
			return ErrLocalStateIntegrity
		}
		if Digest(sha256.Sum256(record.SignedProposal)) != record.ProposalDigest {
			return ErrLocalStateIntegrity
		}
	case LocalRequestResolved:
		if len(record.SignedProposal) != 0 || record.TerminalCode == "" {
			return ErrLocalStateIntegrity
		}
	case LocalRequestAbandoned, LocalRequestExpired:
		if len(record.SignedProposal) != 0 || record.TerminalCode == "" {
			return ErrLocalStateIntegrity
		}
	case LocalRequestPreparing:
		if len(record.SignedProposal) != 0 || record.TerminalCode != "" {
			return ErrLocalStateIntegrity
		}
	}
	switch record.BindingClass {
	case LocalBindingAgent:
		if record.OriginScopeKind != OriginScopeKindAgent {
			return ErrLocalStateIntegrity
		}
	case LocalBindingOperator, LocalBindingDaemon:
		if record.OriginScopeKind != OriginScopeKindBoot {
			return ErrLocalStateIntegrity
		}
	}
	return nil
}

// ClaimNextOutbox marks and returns the lowest sequence still awaiting a
// committed result for scope. A forwarding row is returned again after crash.
func (state LocalState) ClaimNextOutbox(
	ctx context.Context,
	scope OutboxScope,
) (OutboxRecord, bool, error) {
	if err := scope.validate(); err != nil {
		return OutboxRecord{}, false, err
	}
	var (
		record OutboxRecord
		found  bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		var rowErr error
		count := 0
		if err := queryArgs(
			conn,
			`SELECT o.outbox_id, r.client_instance_id, r.request_id,
				        r.binding_class, o.event_id, o.session_id,
				        o.recovery_generation,
				        o.origin_device_id, o.origin_scope_kind,
				        o.origin_scope_id, o.origin_sequence, o.kind,
				        o.signed_proposal_json, o.proposal_digest,
				        o.state, o.queued_at
				   FROM outbox AS o
				   LEFT JOIN local_requests AS r
				     ON r.event_id = o.event_id
				    AND r.session_id = o.session_id
				    AND r.workspace_id = ?4
				    AND r.recovery_generation = o.recovery_generation
				    AND r.origin_device_id = o.origin_device_id
				    AND r.origin_scope_kind = o.origin_scope_kind
				    AND r.origin_scope_id = o.origin_scope_id
				    AND r.request_kind = o.kind
				    AND r.signed_proposal_json = o.signed_proposal_json
				    AND r.proposal_digest = o.proposal_digest
				    AND r.created_at = o.queued_at
				    AND r.state IN ('signed', 'pending')
				  WHERE o.origin_device_id = ?1
				    AND o.origin_scope_kind = ?2
				    AND o.origin_scope_id = ?3
				  ORDER BY o.origin_sequence, o.outbox_id
				  LIMIT 1;`,
			[]any{
				string(scope.OriginDeviceID),
				scope.OriginScopeKind,
				string(scope.OriginScopeID),
				string(lineage.workspaceID),
			},
			func(stmt *sqlite.Stmt) {
				count++
				found = true
				record, rowErr = scanOutboxRecord(stmt)
			},
		); err != nil {
			return err
		}
		if rowErr != nil {
			return rowErr
		}
		if count > 1 {
			return ErrLocalStateIntegrity
		}
		if !found {
			return nil
		}
		if err := validateOutboxRecord(record, scope, lineage); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE outbox SET state = 'forwarding'
			  WHERE outbox_id = ?1;`,
			record.OutboxID,
		); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE local_requests SET state = 'pending'
			  WHERE event_id = ?1 AND state IN ('signed', 'pending');`,
			string(record.EventID),
		); err != nil {
			return err
		}
		record.State = "forwarding"
		return nil
	})
	if err != nil {
		return OutboxRecord{}, false, err
	}
	return record, found, nil
}

// OutboxRecords returns an integrity-checked snapshot of every durable
// proposal awaiting forwarding. It does not claim or mutate any row.
func (state LocalState) OutboxRecords(
	ctx context.Context,
) ([]OutboxRecord, error) {
	var records []OutboxRecord
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		var rowErr error
		seen := make(map[int64]struct{})
		if err := queryArgs(
			conn,
			`SELECT o.outbox_id, r.client_instance_id, r.request_id,
			        r.binding_class, o.event_id, o.session_id,
			        o.recovery_generation,
			        o.origin_device_id, o.origin_scope_kind,
			        o.origin_scope_id, o.origin_sequence, o.kind,
			        o.signed_proposal_json, o.proposal_digest,
			        o.state, o.queued_at
			   FROM outbox AS o
			   LEFT JOIN local_requests AS r
			     ON r.event_id = o.event_id
			    AND r.session_id = o.session_id
			    AND r.workspace_id = ?1
			    AND r.recovery_generation = o.recovery_generation
			    AND r.origin_device_id = o.origin_device_id
			    AND r.origin_scope_kind = o.origin_scope_kind
			    AND r.origin_scope_id = o.origin_scope_id
			    AND r.request_kind = o.kind
			    AND r.signed_proposal_json = o.signed_proposal_json
			    AND r.proposal_digest = o.proposal_digest
			    AND r.created_at = o.queued_at
			    AND r.state IN ('signed', 'pending')
			  ORDER BY o.outbox_id;`,
			[]any{string(lineage.workspaceID)},
			func(stmt *sqlite.Stmt) {
				if rowErr != nil {
					return
				}
				record, err := scanOutboxRecord(stmt)
				if err != nil {
					rowErr = err
					return
				}
				scope := OutboxScope{
					OriginDeviceID:  record.OriginDeviceID,
					OriginScopeKind: record.OriginScopeKind,
					OriginScopeID:   record.OriginScopeID,
				}
				if _, duplicate := seen[record.OutboxID]; duplicate {
					rowErr = ErrLocalStateIntegrity
					return
				}
				if err := scope.validate(); err != nil {
					rowErr = ErrLocalStateIntegrity
					return
				}
				if err := validateOutboxRecord(
					record,
					scope,
					lineage,
				); err != nil {
					rowErr = err
					return
				}
				seen[record.OutboxID] = struct{}{}
				record.SignedProposal = bytes.Clone(
					record.SignedProposal,
				)
				records = append(records, record)
			},
		); err != nil {
			return err
		}
		return rowErr
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func scanOutboxRecord(stmt *sqlite.Stmt) (OutboxRecord, error) {
	record := OutboxRecord{
		OutboxID:         stmt.ColumnInt64(0),
		ClientInstanceID: domain.UUIDv7(stmt.ColumnText(1)),
		RequestID:        domain.UUIDv7(stmt.ColumnText(2)),
		BindingClass:     LocalBindingClass(stmt.ColumnText(3)),
		EventID:          domain.UUIDv7(stmt.ColumnText(4)),
		SessionID:        domain.UUIDv7(stmt.ColumnText(5)),
		OriginDeviceID:   domain.DeviceID(stmt.ColumnText(7)),
		OriginScopeKind:  stmt.ColumnText(8),
		OriginScopeID:    domain.UUIDv7(stmt.ColumnText(9)),
		Kind:             event.Kind(stmt.ColumnText(11)),
		SignedProposal:   []byte(stmt.ColumnText(12)),
		State:            stmt.ColumnText(14),
		QueuedAt:         domain.Timestamp(stmt.ColumnText(15)),
	}
	generation := stmt.ColumnInt64(6)
	sequence := stmt.ColumnInt64(10)
	if generation < 0 || sequence < 1 {
		return OutboxRecord{}, ErrLocalStateIntegrity
	}
	record.RecoveryGeneration = uint64(generation)
	record.OriginSequence = uint64(sequence)
	if err := copyDigestColumn(
		&record.ProposalDigest,
		stmt,
		13,
	); err != nil {
		return OutboxRecord{}, err
	}
	return record, nil
}

func validateOutboxRecord(
	record OutboxRecord,
	scope OutboxScope,
	lineage localLineage,
) error {
	if record.OutboxID < 1 ||
		!record.ClientInstanceID.Valid() ||
		!record.RequestID.Valid() ||
		!record.BindingClass.valid() ||
		!record.EventID.Valid() ||
		!record.SessionID.Valid() ||
		record.SessionID != lineage.sessionID ||
		!domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		record.RecoveryGeneration != lineage.recoveryGeneration ||
		record.OriginDeviceID != scope.OriginDeviceID ||
		record.OriginScopeKind != scope.OriginScopeKind ||
		record.OriginScopeID != scope.OriginScopeID ||
		record.OriginSequence < 1 ||
		!domain.ValidUnsignedInteger(record.OriginSequence) ||
		len(record.SignedProposal) == 0 ||
		(record.State != "queued" && record.State != "forwarding") ||
		!record.QueuedAt.Valid() {
		return ErrLocalStateIntegrity
	}
	if _, exists := event.LookupKind(record.Kind); !exists {
		return ErrLocalStateIntegrity
	}
	switch record.BindingClass {
	case LocalBindingAgent:
		if record.OriginScopeKind != OriginScopeKindAgent {
			return ErrLocalStateIntegrity
		}
	case LocalBindingOperator, LocalBindingDaemon:
		if record.OriginScopeKind != OriginScopeKindBoot {
			return ErrLocalStateIntegrity
		}
	default:
		return ErrLocalStateIntegrity
	}
	proposal, err := event.InspectUnverifiedProposal(
		record.SignedProposal,
	)
	if err != nil ||
		validateReservedProposalFields(
			LocalCommandInput{
				SessionID:       record.SessionID,
				WorkspaceID:     lineage.workspaceID,
				BindingClass:    record.BindingClass,
				OriginDeviceID:  record.OriginDeviceID,
				OriginScopeKind: record.OriginScopeKind,
				OriginScopeID:   record.OriginScopeID,
				RequestKind:     record.Kind,
				CreatedAt:       record.QueuedAt,
			},
			record.EventID,
			record.OriginSequence,
			proposal,
			record.SignedProposal,
		) != nil {
		return ErrLocalStateIntegrity
	}
	if Digest(sha256.Sum256(record.SignedProposal)) != record.ProposalDigest {
		return ErrLocalStateIntegrity
	}
	return nil
}

// OutboxScopes lists durable nonempty origin queues in stable order.
func (state LocalState) OutboxScopes(
	ctx context.Context,
) ([]OutboxScope, error) {
	var scopes []OutboxScope
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		var stale int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM outbox
			  WHERE session_id <> ?1 OR recovery_generation <> ?2;`,
			[]any{string(lineage.sessionID), lineage.recoveryGeneration},
			func(stmt *sqlite.Stmt) {
				stale = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if stale != 0 {
			return ErrLocalStateIntegrity
		}
		var rowErr error
		if err := query(
			conn,
			`SELECT DISTINCT origin_device_id, origin_scope_kind, origin_scope_id
			   FROM outbox
			  ORDER BY origin_device_id, origin_scope_kind, origin_scope_id;`,
			func(stmt *sqlite.Stmt) {
				scope := OutboxScope{
					OriginDeviceID:  domain.DeviceID(stmt.ColumnText(0)),
					OriginScopeKind: stmt.ColumnText(1),
					OriginScopeID:   domain.UUIDv7(stmt.ColumnText(2)),
				}
				if err := scope.validate(); err != nil {
					rowErr = ErrLocalStateIntegrity
					return
				}
				scopes = append(scopes, scope)
			},
		); err != nil {
			return err
		}
		return rowErr
	})
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

// LocalEventIDCollisionCode terminally identifies a generated event ID that
// was already committed with different signed bytes.
const LocalEventIDCollisionCode = "local_event_id_collision"

// compactLocalProposal removes an outbox entry only after proving whether its
// local request is the exact proposal that obtained the committed result. A
// different local proposal under the same event ID is terminally abandoned.
func compactLocalProposal(
	conn *sqlite.Conn,
	recoveryGeneration uint64,
	signed event.SignedEvent,
	authoritativeProposal []byte,
	authoritativeDigest Digest,
	terminalStatus OutcomeStatus,
	terminalCode string,
) error {
	proposal := signed.Proposal()
	eventID := proposal.EventID
	if !domain.ValidUnsignedInteger(recoveryGeneration) ||
		!eventID.Valid() ||
		len(authoritativeProposal) == 0 ||
		!bytes.Equal(signed.CanonicalBytes(), authoritativeProposal) ||
		Digest(sha256.Sum256(authoritativeProposal)) != authoritativeDigest ||
		!terminalStatus.valid() ||
		!validCode(terminalCode, false) {
		return ErrLocalStateIntegrity
	}
	local, found, err := readLocalRequestForCompaction(conn, eventID)
	if err != nil {
		return err
	}
	outbox, outboxFound, err := readOutboxForCompaction(conn, eventID)
	if err != nil {
		return err
	}
	if !found {
		if !outboxFound {
			return nil
		}
		return ErrLocalStateIntegrity
	}
	if local.RecoveryGeneration != recoveryGeneration {
		return ErrLocalStateIntegrity
	}
	switch local.State {
	case LocalRequestSigned, LocalRequestPending:
		if !outboxFound ||
			!outbox.matchesLocal(local) {
			return ErrLocalStateIntegrity
		}
		localProposal, err := inspectAndValidateLocalProposal(conn, local)
		if err != nil ||
			!outbox.matchesProposal(
				local.RecoveryGeneration,
				localProposal,
				local.SignedProposal,
				local.ProposalDigest,
			) {
			return ErrLocalStateIntegrity
		}
		exact := local.ProposalDigest == authoritativeDigest &&
			bytes.Equal(local.SignedProposal, authoritativeProposal)
		nextState := LocalRequestResolved
		nextCode := terminalCode
		if !exact {
			nextState = LocalRequestAbandoned
			nextCode = LocalEventIDCollisionCode
		} else {
			if err := verifyLocalCheckpointResolution(
				conn,
				signed,
				terminalStatus,
				terminalCode,
			); err != nil {
				return err
			}
		}
		if err := deleteExactOutbox(conn, outbox); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE local_requests
			    SET state = ?4,
			        publication_metadata_json = NULL,
			        publication_metadata_digest = NULL,
			        artifact_digest = NULL,
			        signed_proposal_json = NULL,
			        terminal_code = ?5
			  WHERE client_instance_id = ?1
			    AND request_id = ?2
			    AND event_id = ?3
			    AND state IN ('signed', 'pending');`,
			string(local.ClientInstanceID),
			string(local.RequestID),
			string(eventID),
			string(nextState),
			nextCode,
		); err != nil {
			return err
		}
		return requireOneChangedRow(conn)
	case LocalRequestResolved:
		if local.ProposalDigest != authoritativeDigest ||
			local.TerminalCode != terminalCode ||
			outboxFound {
			return ErrLocalStateIntegrity
		}
		if err := validateLocalProposalBinding(local, signed); err != nil {
			return err
		}
		return verifyLocalCheckpointResolution(
			conn,
			signed,
			terminalStatus,
			terminalCode,
		)
	case LocalRequestAbandoned:
		if local.TerminalCode != LocalEventIDCollisionCode || outboxFound {
			return ErrLocalStateIntegrity
		}
		return nil
	default:
		return ErrLocalStateIntegrity
	}
}

type compactOutboxRecord struct {
	outboxID           int64
	eventID            domain.UUIDv7
	sessionID          domain.UUIDv7
	recoveryGeneration uint64
	originDeviceID     domain.DeviceID
	originScopeKind    string
	originScopeID      domain.UUIDv7
	originSequence     uint64
	kind               event.Kind
	signedProposal     []byte
	proposalDigest     Digest
	state              string
	queuedAt           domain.Timestamp
}

func readLocalRequestForCompaction(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) (LocalCommandRecord, bool, error) {
	var (
		record LocalCommandRecord
		found  bool
		rowErr error
		count  int
	)
	err := queryArgs(
		conn,
		`SELECT client_instance_id, request_id, session_id, workspace_id,
		        recovery_generation, binding_class, origin_device_id,
		        origin_scope_kind, origin_scope_id, request_digest, event_id,
		        request_kind, state, signed_proposal_json, proposal_digest,
		        terminal_code, created_at
		   FROM local_requests
		  WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			found = true
			record, rowErr = scanLocalCommandRecord(stmt)
		},
	)
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	if rowErr != nil || count > 1 {
		return LocalCommandRecord{}, false, ErrLocalStateIntegrity
	}
	if found {
		if err := validateLocalCommandRecord(record); err != nil {
			return LocalCommandRecord{}, false, err
		}
	}
	return record, found, nil
}

func readOutboxForCompaction(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
) (compactOutboxRecord, bool, error) {
	var (
		record compactOutboxRecord
		found  bool
		rowErr error
		count  int
	)
	err := queryArgs(
		conn,
		`SELECT outbox_id, event_id, session_id, recovery_generation,
		        origin_device_id, origin_scope_kind, origin_scope_id,
		        origin_sequence, kind, signed_proposal_json,
		        proposal_digest, state, queued_at
		   FROM outbox
		  WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			found = true
			generation := stmt.ColumnInt64(3)
			sequence := stmt.ColumnInt64(7)
			if generation < 0 || sequence < 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			record = compactOutboxRecord{
				outboxID:           stmt.ColumnInt64(0),
				eventID:            domain.UUIDv7(stmt.ColumnText(1)),
				sessionID:          domain.UUIDv7(stmt.ColumnText(2)),
				recoveryGeneration: uint64(generation),
				originDeviceID:     domain.DeviceID(stmt.ColumnText(4)),
				originScopeKind:    stmt.ColumnText(5),
				originScopeID:      domain.UUIDv7(stmt.ColumnText(6)),
				originSequence:     uint64(sequence),
				kind:               event.Kind(stmt.ColumnText(8)),
				signedProposal:     []byte(stmt.ColumnText(9)),
				state:              stmt.ColumnText(11),
				queuedAt:           domain.Timestamp(stmt.ColumnText(12)),
			}
			rowErr = copyDigestColumn(
				&record.proposalDigest,
				stmt,
				10,
			)
		},
	)
	if err != nil {
		return compactOutboxRecord{}, false, err
	}
	if rowErr != nil || count > 1 {
		return compactOutboxRecord{}, false, ErrLocalStateIntegrity
	}
	return record, found, nil
}

func (record compactOutboxRecord) matchesProposal(
	recoveryGeneration uint64,
	proposal event.Proposal,
	canonical []byte,
	digest Digest,
) bool {
	if record.outboxID < 1 ||
		record.eventID != proposal.EventID ||
		record.sessionID != proposal.SessionID ||
		record.recoveryGeneration != recoveryGeneration ||
		record.originDeviceID != proposal.Origin.DeviceID() ||
		record.originSequence != proposal.Origin.Sequence() ||
		record.kind != proposal.Kind ||
		!bytes.Equal(record.signedProposal, canonical) ||
		record.proposalDigest != digest ||
		Digest(sha256.Sum256(record.signedProposal)) != digest ||
		(record.state != "queued" && record.state != "forwarding") ||
		record.queuedAt != proposal.CreatedAt {
		return false
	}
	switch proposal.Origin.ActorType() {
	case event.ActorAgent:
		return record.originScopeKind == OriginScopeKindAgent &&
			record.originScopeID == proposal.Origin.AgentSessionID() &&
			proposal.Origin.OriginBootID() == ""
	case event.ActorHuman, event.ActorDaemon:
		return record.originScopeKind == OriginScopeKindBoot &&
			record.originScopeID == proposal.Origin.OriginBootID() &&
			proposal.Origin.AgentSessionID() == ""
	default:
		return false
	}
}

func (record compactOutboxRecord) matchesLocal(
	local LocalCommandRecord,
) bool {
	return record.outboxID >= 1 &&
		record.eventID == local.EventID &&
		record.sessionID == local.SessionID &&
		record.recoveryGeneration == local.RecoveryGeneration &&
		record.originDeviceID == local.OriginDeviceID &&
		record.originScopeKind == local.OriginScopeKind &&
		record.originScopeID == local.OriginScopeID &&
		record.originSequence >= 1 &&
		domain.ValidUnsignedInteger(record.originSequence) &&
		record.kind == local.RequestKind &&
		bytes.Equal(record.signedProposal, local.SignedProposal) &&
		record.proposalDigest == local.ProposalDigest &&
		Digest(sha256.Sum256(record.signedProposal)) ==
			record.proposalDigest &&
		(record.state == "queued" || record.state == "forwarding") &&
		record.queuedAt == local.CreatedAt
}

func validateLocalProposalBinding(
	record LocalCommandRecord,
	signed event.SignedEvent,
) error {
	return validateLocalProposal(
		record,
		signed.Proposal(),
		signed.CanonicalBytes(),
	)
}

func validateLocalProposal(
	record LocalCommandRecord,
	proposal event.Proposal,
	canonical []byte,
) error {
	input := LocalCommandInput{
		ClientInstanceID: record.ClientInstanceID,
		RequestID:        record.RequestID,
		SessionID:        record.SessionID,
		WorkspaceID:      record.WorkspaceID,
		BindingClass:     record.BindingClass,
		OriginDeviceID:   record.OriginDeviceID,
		OriginScopeKind:  record.OriginScopeKind,
		OriginScopeID:    record.OriginScopeID,
		RequestKind:      record.RequestKind,
		CreatedAt:        record.CreatedAt,
	}
	if err := validateReservedProposalFields(
		input,
		record.EventID,
		proposal.Origin.Sequence(),
		proposal,
		canonical,
	); err != nil {
		return ErrLocalStateIntegrity
	}
	return nil
}

func inspectAndValidateLocalProposal(
	conn *sqlite.Conn,
	record LocalCommandRecord,
) (event.Proposal, error) {
	proposal, err := event.InspectUnverifiedProposal(
		record.SignedProposal,
	)
	if err != nil ||
		validateLocalProposal(
			record,
			proposal,
			record.SignedProposal,
		) != nil {
		return event.Proposal{}, ErrLocalStateIntegrity
	}
	member, found, err := readStatusMember(conn, record.OriginDeviceID)
	if err != nil {
		return event.Proposal{}, ErrLocalStateIntegrity
	}
	if found {
		signed, err := event.ParseAndVerify(
			record.SignedProposal,
			event.VerificationContext{
				SessionID:         record.SessionID,
				WorkspaceID:       record.WorkspaceID,
				IdentityPublicKey: member.IdentityPublicKey,
			},
		)
		if err != nil ||
			!bytes.Equal(
				signed.CanonicalBytes(),
				record.SignedProposal,
			) {
			return event.Proposal{}, ErrLocalStateIntegrity
		}
	}
	return proposal, nil
}

func verifyLocalCheckpointResolution(
	conn *sqlite.Conn,
	signed event.SignedEvent,
	status OutcomeStatus,
	code string,
) error {
	proposal := signed.Proposal()
	if proposal.Kind != event.KindConsensusCheckpoint {
		return nil
	}
	stored, found, err := readStoredCommandResult(conn, proposal.EventID)
	if err != nil ||
		!found ||
		verifyStoredCommandResult(conn, stored) != nil ||
		stored.outcome.Status != status ||
		stored.outcome.Code != code ||
		stored.proposalDigest != proposalDigest(signed) ||
		!bytes.Equal(stored.proposalJSON, signed.CanonicalBytes()) {
		return ErrLocalStateIntegrity
	}

	record, checkpointFound, err := readCheckpointRecord(
		conn,
		proposal.EventID,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLocalStateIntegrity, err)
	}
	switch status {
	case OutcomeRejected:
		if code != event.CheckpointStaleOutcomeCode || checkpointFound {
			return ErrLocalStateIntegrity
		}
		return nil
	case OutcomeAccepted:
		if !checkpointFound {
			return ErrLocalStateIntegrity
		}
	default:
		return ErrLocalStateIntegrity
	}

	checkpoint, signature, err := event.DecodeCheckpointPayload(
		proposal.Payload,
	)
	if err != nil ||
		record.Validate() != nil ||
		record.CheckpointEventID != proposal.EventID ||
		record.checkpoint() != checkpoint ||
		record.AuthoritySignature != Signature(signature) {
		return ErrLocalStateIntegrity
	}
	return nil
}

func deleteExactOutbox(
	conn *sqlite.Conn,
	record compactOutboxRecord,
) error {
	if err := execute(
		conn,
		`DELETE FROM outbox
		  WHERE outbox_id = ?1
		    AND event_id = ?2
		    AND recovery_generation = ?3
		    AND proposal_digest = ?4;`,
		record.outboxID,
		string(record.eventID),
		record.recoveryGeneration,
		record.proposalDigest[:],
	); err != nil {
		return err
	}
	return requireOneChangedRow(conn)
}
