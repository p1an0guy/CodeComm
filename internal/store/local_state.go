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
	MaxUnresolvedCommandsPerOrigin  = 256
	MaxUnresolvedCommandsPerSession = 4096
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
	store *Store
}

// LocalState returns the local-only state capability owned by store.
func (store *Store) LocalState() LocalState {
	return LocalState{store: store}
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
	OutboxID        int64
	EventID         domain.UUIDv7
	SessionID       domain.UUIDv7
	OriginDeviceID  domain.DeviceID
	OriginScopeKind OriginScopeKind
	OriginScopeID   domain.UUIDv7
	OriginSequence  uint64
	Kind            event.Kind
	SignedProposal  []byte
	ProposalDigest  Digest
	State           string
	QueuedAt        domain.Timestamp
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
	requestDigest, err := input.validate()
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	if generateEventID == nil || build == nil {
		return LocalCommandRecord{}, false, ErrInvalidLocalState
	}

	var (
		result    LocalCommandRecord
		duplicate bool
	)
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(input.SessionID, input.WorkspaceID) {
			return ErrLocalLineageMismatch
		}
		existing, found, err := readLocalRequestByKey(
			conn,
			input.ClientInstanceID,
			input.RequestID,
		)
		if err != nil {
			return err
		}
		if found {
			if existing.RecoveryGeneration != lineage.recoveryGeneration ||
				!localRequestMatchesInput(existing, input, requestDigest) {
				return ErrLocalIdempotencyConflict
			}
			result = existing
			duplicate = true
			return nil
		}

		if err := checkLocalBackpressure(
			conn,
			lineage,
			input.OriginScopeKind,
			input.OriginScopeID,
		); err != nil {
			return err
		}
		sequence, counterFound, err := nextOriginSequence(
			conn,
			input.OriginDeviceID,
			input.OriginScopeKind,
			input.OriginScopeID,
			input.OriginScopeKind == OriginScopeKindBoot,
		)
		if err != nil {
			return err
		}
		eventID, err := generateEventID()
		if err != nil {
			return fmt.Errorf("store: generate event ID: %w", err)
		}
		if !eventID.Valid() {
			return ErrInvalidLocalState
		}
		signed, err := build(eventID, sequence)
		if err != nil {
			return fmt.Errorf("store: build signed proposal: %w", err)
		}
		if err := validateReservedProposal(input, eventID, sequence, signed); err != nil {
			return err
		}
		if err := advanceOriginCounter(
			conn,
			input.OriginDeviceID,
			input.OriginScopeKind,
			input.OriginScopeID,
			sequence,
			counterFound,
		); err != nil {
			return err
		}
		result, err = insertLocalCommand(
			conn,
			lineage,
			input,
			requestDigest,
			signed,
		)
		return err
	})
	if err != nil {
		return LocalCommandRecord{}, false, err
	}
	return result, duplicate, nil
}

func validateReservedProposal(
	input LocalCommandInput,
	eventID domain.UUIDv7,
	sequence uint64,
	signed event.SignedEvent,
) error {
	proposal := signed.Proposal()
	if proposal.EventID != eventID ||
		proposal.SessionID != input.SessionID ||
		proposal.WorkspaceID != input.WorkspaceID ||
		proposal.CreatedAt != input.CreatedAt ||
		proposal.Kind != input.RequestKind ||
		proposal.Origin.DeviceID() != input.OriginDeviceID ||
		proposal.Origin.Sequence() != sequence ||
		len(signed.CanonicalBytes()) == 0 {
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
	if scopeCount >= MaxUnresolvedCommandsPerOrigin ||
		sessionCount >= MaxUnresolvedCommandsPerSession {
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
		    event_id, session_id, origin_device_id, origin_scope_kind,
		    origin_scope_id, origin_sequence, kind, signed_proposal_json,
		    proposal_digest, state, queued_at
		) VALUES (
		    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'queued', ?10
		);`,
		string(proposal.EventID),
		string(proposal.SessionID),
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
			record.ClientInstanceID = domain.UUIDv7(stmt.ColumnText(0))
			record.RequestID = domain.UUIDv7(stmt.ColumnText(1))
			record.SessionID = domain.UUIDv7(stmt.ColumnText(2))
			record.WorkspaceID = domain.UUIDv4(stmt.ColumnText(3))
			generation := stmt.ColumnInt64(4)
			if generation < 0 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			record.RecoveryGeneration = uint64(generation)
			record.BindingClass = LocalBindingClass(stmt.ColumnText(5))
			record.OriginDeviceID = domain.DeviceID(stmt.ColumnText(6))
			record.OriginScopeKind = stmt.ColumnText(7)
			record.OriginScopeID = domain.UUIDv7(stmt.ColumnText(8))
			if err := copyDigestColumn(&record.RequestDigest, stmt, 9); err != nil {
				rowErr = err
				return
			}
			record.EventID = domain.UUIDv7(stmt.ColumnText(10))
			record.RequestKind = event.Kind(stmt.ColumnText(11))
			record.State = LocalRequestState(stmt.ColumnText(12))
			if stmt.ColumnType(13) != sqlite.TypeNull {
				record.SignedProposal = []byte(stmt.ColumnText(13))
			}
			if stmt.ColumnType(14) != sqlite.TypeNull {
				if err := copyDigestColumn(&record.ProposalDigest, stmt, 14); err != nil {
					rowErr = err
					return
				}
			}
			if stmt.ColumnType(15) != sqlite.TypeNull {
				record.TerminalCode = stmt.ColumnText(15)
			}
			record.CreatedAt = domain.Timestamp(stmt.ColumnText(16))
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
		var sequence int64
		if err := queryOneArgs(
			conn,
			`SELECT origin_sequence
			   FROM outbox
			  WHERE event_id = ?1;`,
			[]any{string(record.EventID)},
			func(stmt *sqlite.Stmt) {
				sequence = stmt.ColumnInt64(0)
			},
		); err != nil {
			return LocalCommandRecord{}, false, err
		}
		if sequence < 1 {
			return LocalCommandRecord{}, false, ErrLocalStateIntegrity
		}
		record.OriginSequence = uint64(sequence)
	}
	return record, true, nil
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
		var rowErr error
		count := 0
		if err := queryArgs(
			conn,
			`SELECT outbox_id, event_id, session_id, origin_device_id,
			        origin_scope_kind, origin_scope_id, origin_sequence,
			        kind, signed_proposal_json, proposal_digest, state,
			        queued_at
			   FROM outbox
			  WHERE origin_device_id = ?1
			    AND origin_scope_kind = ?2
			    AND origin_scope_id = ?3
			  ORDER BY origin_sequence, outbox_id
			  LIMIT 1;`,
			[]any{
				string(scope.OriginDeviceID),
				scope.OriginScopeKind,
				string(scope.OriginScopeID),
			},
			func(stmt *sqlite.Stmt) {
				count++
				found = true
				record.OutboxID = stmt.ColumnInt64(0)
				record.EventID = domain.UUIDv7(stmt.ColumnText(1))
				record.SessionID = domain.UUIDv7(stmt.ColumnText(2))
				record.OriginDeviceID = domain.DeviceID(stmt.ColumnText(3))
				record.OriginScopeKind = stmt.ColumnText(4)
				record.OriginScopeID = domain.UUIDv7(stmt.ColumnText(5))
				sequence := stmt.ColumnInt64(6)
				if sequence < 1 {
					rowErr = ErrLocalStateIntegrity
					return
				}
				record.OriginSequence = uint64(sequence)
				record.Kind = event.Kind(stmt.ColumnText(7))
				record.SignedProposal = []byte(stmt.ColumnText(8))
				if err := copyDigestColumn(&record.ProposalDigest, stmt, 9); err != nil {
					rowErr = err
					return
				}
				record.State = stmt.ColumnText(10)
				record.QueuedAt = domain.Timestamp(stmt.ColumnText(11))
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
		if err := validateOutboxRecord(record, scope); err != nil {
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

func validateOutboxRecord(record OutboxRecord, scope OutboxScope) error {
	if record.OutboxID < 1 ||
		!record.EventID.Valid() ||
		!record.SessionID.Valid() ||
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

const localEventIDCollisionCode = "local_event_id_collision"

// compactLocalProposal removes an outbox entry only after proving whether its
// local request is the exact proposal that obtained the committed result. A
// different local proposal under the same event ID is terminally abandoned.
func compactLocalProposal(
	conn *sqlite.Conn,
	eventID domain.UUIDv7,
	authoritativeProposal []byte,
	authoritativeDigest Digest,
	terminalCode string,
) error {
	if !eventID.Valid() ||
		len(authoritativeProposal) == 0 ||
		Digest(sha256.Sum256(authoritativeProposal)) != authoritativeDigest ||
		!validCode(terminalCode, false) {
		return ErrLocalStateIntegrity
	}
	var (
		found          bool
		state          LocalRequestState
		localProposal  []byte
		localDigest    Digest
		digestPresent  bool
		storedCode     string
		outboxFound    bool
		outboxProposal []byte
		outboxDigest   Digest
		rowErr         error
	)
	count := 0
	if err := queryArgs(
		conn,
		`SELECT state, signed_proposal_json, proposal_digest, terminal_code
		   FROM local_requests
		  WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			found = true
			state = LocalRequestState(stmt.ColumnText(0))
			if stmt.ColumnType(1) != sqlite.TypeNull {
				localProposal = []byte(stmt.ColumnText(1))
			}
			if stmt.ColumnType(2) != sqlite.TypeNull {
				if err := copyDigestColumn(&localDigest, stmt, 2); err != nil {
					rowErr = err
					return
				}
				digestPresent = true
			}
			if stmt.ColumnType(3) != sqlite.TypeNull {
				storedCode = stmt.ColumnText(3)
			}
		},
	); err != nil {
		return err
	}
	if rowErr != nil || count > 1 {
		return ErrLocalStateIntegrity
	}
	count = 0
	if err := queryArgs(
		conn,
		`SELECT signed_proposal_json, proposal_digest
		   FROM outbox
		  WHERE event_id = ?1;`,
		[]any{string(eventID)},
		func(stmt *sqlite.Stmt) {
			count++
			outboxFound = true
			outboxProposal = []byte(stmt.ColumnText(0))
			if err := copyDigestColumn(&outboxDigest, stmt, 1); err != nil {
				rowErr = err
			}
		},
	); err != nil {
		return err
	}
	if rowErr != nil || count > 1 {
		return ErrLocalStateIntegrity
	}
	if !found {
		if !outboxFound {
			return nil
		}
		if outboxDigest != authoritativeDigest ||
			!bytes.Equal(outboxProposal, authoritativeProposal) {
			return ErrLocalStateIntegrity
		}
		return execute(
			conn,
			"DELETE FROM outbox WHERE event_id = ?1;",
			string(eventID),
		)
	}
	if outboxFound &&
		(Digest(sha256.Sum256(outboxProposal)) != outboxDigest) {
		return ErrLocalStateIntegrity
	}
	switch state {
	case LocalRequestSigned, LocalRequestPending:
		if !digestPresent ||
			len(localProposal) == 0 ||
			Digest(sha256.Sum256(localProposal)) != localDigest ||
			!outboxFound ||
			outboxDigest != localDigest ||
			!bytes.Equal(outboxProposal, localProposal) {
			return ErrLocalStateIntegrity
		}
		exact := localDigest == authoritativeDigest &&
			bytes.Equal(localProposal, authoritativeProposal)
		nextState := LocalRequestResolved
		nextCode := terminalCode
		if !exact {
			nextState = LocalRequestAbandoned
			nextCode = localEventIDCollisionCode
		}
		if err := execute(
			conn,
			"DELETE FROM outbox WHERE event_id = ?1;",
			string(eventID),
		); err != nil {
			return err
		}
		return execute(
			conn,
			`UPDATE local_requests
			    SET state = ?2,
			        publication_metadata_json = NULL,
			        publication_metadata_digest = NULL,
			        artifact_digest = NULL,
			        signed_proposal_json = NULL,
			        terminal_code = ?3
			  WHERE event_id = ?1
			    AND state IN ('signed', 'pending');`,
			string(eventID),
			string(nextState),
			nextCode,
		)
	case LocalRequestResolved:
		if !digestPresent ||
			localDigest != authoritativeDigest ||
			storedCode != terminalCode ||
			outboxFound {
			return ErrLocalStateIntegrity
		}
		return nil
	case LocalRequestAbandoned:
		if storedCode != localEventIDCollisionCode || outboxFound {
			return ErrLocalStateIntegrity
		}
		return nil
	default:
		return ErrLocalStateIntegrity
	}
}
