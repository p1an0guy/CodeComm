package store

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"path/filepath"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/event"
	"zombiezen.com/go/sqlite"
)

const maxLocalIdentityBytes = 1024

type ManagedRootKind string

const (
	ManagedRootPrimary  ManagedRootKind = "primary"
	ManagedRootIsolated ManagedRootKind = "isolated"
	ManagedRootShared   ManagedRootKind = "shared"
)

func (kind ManagedRootKind) valid() bool {
	switch kind {
	case ManagedRootPrimary, ManagedRootIsolated, ManagedRootShared:
		return true
	default:
		return false
	}
}

type RootGuardStatus string

const (
	RootGuardHealthy   RootGuardStatus = "healthy"
	RootGuardBlocked   RootGuardStatus = "blocked"
	RootGuardRepairing RootGuardStatus = "repairing"
)

func (status RootGuardStatus) valid() bool {
	switch status {
	case RootGuardHealthy, RootGuardBlocked, RootGuardRepairing:
		return true
	default:
		return false
	}
}

// ManagedRootRecord is a CodeComm-created and identity-checked filesystem
// root. CanonicalPath never enters replicated state.
type ManagedRootRecord struct {
	ManagedRootID      domain.UUIDv7
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	CanonicalPath      string
	FilesystemIdentity string
	RepositoryIdentity string
	Kind               ManagedRootKind
	GuardStatus        RootGuardStatus
	GuardDetailCode    string
	Active             bool
	LastVerifiedAt     *domain.Timestamp
}

func (record ManagedRootRecord) validate() error {
	if !record.ManagedRootID.Valid() ||
		!record.SessionID.Valid() ||
		!record.WorkspaceID.Valid() ||
		!domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		!record.Kind.valid() ||
		!record.GuardStatus.valid() ||
		record.CanonicalPath == "" ||
		!filepath.IsAbs(record.CanonicalPath) ||
		filepath.Clean(record.CanonicalPath) != record.CanonicalPath ||
		len(record.CanonicalPath) > domain.MaxRepositoryPathBytes ||
		!validLocalIdentity(record.FilesystemIdentity) ||
		!validLocalIdentity(record.RepositoryIdentity) {
		return ErrInvalidLocalState
	}
	if record.GuardDetailCode != "" && !validCode(record.GuardDetailCode, false) {
		return ErrInvalidLocalState
	}
	if record.LastVerifiedAt != nil && !record.LastVerifiedAt.Valid() {
		return ErrInvalidLocalState
	}
	if record.Active &&
		(record.GuardStatus == RootGuardHealthy && record.LastVerifiedAt == nil) {
		return ErrInvalidLocalState
	}
	return nil
}

func validLocalIdentity(value string) bool {
	return len(value) >= 1 &&
		len(value) <= maxLocalIdentityBytes &&
		utf8.ValidString(value)
}

type ConcurrencyMode string

const (
	ConcurrencyIsolated ConcurrencyMode = "isolated"
	ConcurrencyShared   ConcurrencyMode = "shared"
)

func (mode ConcurrencyMode) valid() bool {
	return mode == ConcurrencyIsolated || mode == ConcurrencyShared
}

type LaunchState string

const (
	LaunchPending  LaunchState = "pending"
	LaunchReserved LaunchState = "reserved"
	LaunchConsumed LaunchState = "consumed"
	LaunchRejected LaunchState = "rejected"
	LaunchCleared  LaunchState = "cleared"
)

func (state LaunchState) valid() bool {
	switch state {
	case LaunchPending,
		LaunchReserved,
		LaunchConsumed,
		LaunchRejected,
		LaunchCleared:
		return true
	default:
		return false
	}
}

// LaunchRegistration fixes all operator-selected launch metadata before a
// vendor process starts.
type LaunchRegistration struct {
	LaunchID        domain.UUIDv7
	SelectorDigest  Digest
	SessionID       domain.UUIDv7
	WorkspaceID     domain.UUIDv4
	ClientKind      agentsession.ClientKind
	AgentProfileID  *string
	ConcurrencyMode ConcurrencyMode
	ManagedRootID   domain.UUIDv7
	CreatedAt       domain.Timestamp
}

func (registration LaunchRegistration) validate() error {
	if !registration.LaunchID.Valid() ||
		!registration.SessionID.Valid() ||
		!registration.WorkspaceID.Valid() ||
		!registration.ClientKind.Valid() ||
		!registration.ConcurrencyMode.valid() ||
		!registration.ManagedRootID.Valid() ||
		!registration.CreatedAt.Valid() {
		return ErrInvalidLocalState
	}
	if registration.AgentProfileID != nil {
		profile := *registration.AgentProfileID
		if !utf8.ValidString(profile) ||
			len(profile) < 1 ||
			len(profile) > agentsession.MaxAgentProfileIDBytes {
			return ErrInvalidLocalState
		}
	}
	return nil
}

// LaunchRecord is the complete durable local launch binding.
type LaunchRecord struct {
	LaunchRegistration
	RecoveryGeneration uint64
	State              LaunchState
	ClientInstanceID   domain.UUIDv7
	AgentSessionID     domain.UUIDv7
	WorkingRootID      domain.UUIDv7
	StartEventID       domain.UUIDv7
}

func (record LaunchRecord) validate() error {
	if err := record.LaunchRegistration.validate(); err != nil {
		return err
	}
	if !domain.ValidUnsignedInteger(record.RecoveryGeneration) ||
		!record.State.valid() {
		return ErrLocalStateIntegrity
	}
	if record.State == LaunchPending {
		if record.ClientInstanceID != "" ||
			record.AgentSessionID != "" ||
			record.WorkingRootID != "" ||
			record.StartEventID != "" {
			return ErrLocalStateIntegrity
		}
		return nil
	}
	if !record.ClientInstanceID.Valid() ||
		!record.AgentSessionID.Valid() ||
		!record.WorkingRootID.Valid() ||
		!record.StartEventID.Valid() {
		return ErrLocalStateIntegrity
	}
	return nil
}

// LaunchStartIDs are minted only after a selector reservation has passed all
// lineage, root, capacity, and replay checks.
type LaunchStartIDs struct {
	AgentSessionID domain.UUIDv7
	WorkingRootID  domain.UUIDv7
	EventID        domain.UUIDv7
}

func (ids LaunchStartIDs) validate(launchID, managedRootID domain.UUIDv7) error {
	if !ids.AgentSessionID.Valid() ||
		!ids.WorkingRootID.Valid() ||
		!ids.EventID.Valid() {
		return ErrInvalidLocalState
	}
	values := []domain.UUIDv7{
		ids.AgentSessionID,
		ids.WorkingRootID,
		ids.EventID,
		launchID,
		managedRootID,
	}
	for left := range values {
		for right := left + 1; right < len(values); right++ {
			if values[left] == values[right] {
				return ErrInvalidLocalState
			}
		}
	}
	return nil
}

type LaunchStartIDGenerator func() (LaunchStartIDs, error)

type LaunchStartBuilder func(
	LaunchRecord,
	LaunchStartIDs,
) (event.SignedEvent, error)

type LaunchStart struct {
	Launch  LaunchRecord
	Command LocalCommandRecord
}

type LaunchSettlement struct {
	Launch  LaunchRecord
	Outcome CommandOutcome
}

type ResumeCommitmentMinter func() (Digest, error)

// ResumeBinding is the committed identity restored by a capability. It
// contains no filesystem path or capability material.
type ResumeBinding struct {
	AgentSessionID domain.UUIDv7
	WorkingRootID  domain.UUIDv7
	ManagedRootID  domain.UUIDv7
	ClientKind     agentsession.ClientKind
	AgentProfileID *string
	ResumeState    agentsession.State
	EntityVersion  uint64
}

// AgentSession returns one committed session projection.
func (state LocalState) AgentSession(
	ctx context.Context,
	agentSessionID domain.UUIDv7,
) (agentsession.Session, bool, error) {
	if !agentSessionID.Valid() {
		return agentsession.Session{}, false, ErrInvalidLocalState
	}
	var (
		session agentsession.Session
		found   bool
	)
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		var err error
		session, found, err = readCommittedAgentSession(conn, agentSessionID)
		return err
	})
	if err != nil {
		return agentsession.Session{}, false, err
	}
	return session, found, nil
}

// RegisterManagedRoot durably records a CodeComm-created root after its
// filesystem and repository identities have been verified by the caller.
func (state LocalState) RegisterManagedRoot(
	ctx context.Context,
	record ManagedRootRecord,
) error {
	if err := record.validate(); err != nil {
		return err
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(record.SessionID, record.WorkspaceID) {
			return ErrLocalLineageMismatch
		}
		if record.RecoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalLineageMismatch
		}
		existing, found, err := readManagedRoot(conn, record.ManagedRootID)
		if err != nil {
			return err
		}
		if found {
			if sameManagedRoot(existing, record) {
				return nil
			}
			if !sameManagedRootIdentity(existing, record) {
				return ErrManagedRootConflict
			}
			return execute(
				conn,
				`UPDATE managed_roots
					    SET guard_status = ?2, guard_detail_code = ?3,
					        active = ?4, last_verified_at = ?5
					  WHERE managed_root_id = ?1
					    AND recovery_generation = ?6;`,
				string(record.ManagedRootID),
				string(record.GuardStatus),
				nullableText(record.GuardDetailCode),
				record.Active,
				nullableTimestamp(record.LastVerifiedAt),
				record.RecoveryGeneration,
			)
		}
		var collisions int64
		if err := queryOneArgs(
			conn,
			`SELECT count(*)
			   FROM managed_roots
			  WHERE canonical_path = ?1
			     OR filesystem_identity = ?2
			     OR repository_identity = ?3;`,
			[]any{
				record.CanonicalPath,
				record.FilesystemIdentity,
				record.RepositoryIdentity,
			},
			func(stmt *sqlite.Stmt) {
				collisions = stmt.ColumnInt64(0)
			},
		); err != nil {
			return err
		}
		if collisions != 0 {
			return ErrManagedRootConflict
		}
		return execute(
			conn,
			`INSERT INTO managed_roots(
			    managed_root_id, session_id, workspace_id, recovery_generation,
			    canonical_path, filesystem_identity, repository_identity,
			    root_kind, guard_status, guard_detail_code, active,
			    last_verified_at
			) VALUES (
			    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
			);`,
			string(record.ManagedRootID),
			string(record.SessionID),
			string(record.WorkspaceID),
			record.RecoveryGeneration,
			record.CanonicalPath,
			record.FilesystemIdentity,
			record.RepositoryIdentity,
			string(record.Kind),
			string(record.GuardStatus),
			nullableText(record.GuardDetailCode),
			record.Active,
			nullableTimestamp(record.LastVerifiedAt),
		)
	})
}

// RegisterLaunch inserts one pending one-use launch registration.
func (state LocalState) RegisterLaunch(
	ctx context.Context,
	registration LaunchRegistration,
) error {
	if err := registration.validate(); err != nil {
		return err
	}
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(registration.SessionID, registration.WorkspaceID) {
			return ErrLocalLineageMismatch
		}
		root, found, err := readManagedRoot(conn, registration.ManagedRootID)
		if err != nil {
			return err
		}
		if !found || !launchableRoot(root, registration.ConcurrencyMode) {
			return ErrManagedRootUnavailable
		}
		if root.SessionID != registration.SessionID ||
			root.WorkspaceID != registration.WorkspaceID ||
			root.RecoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalLineageMismatch
		}
		existing, found, err := readLaunchByID(conn, registration.LaunchID)
		if err != nil {
			return err
		}
		if found {
			if existing.State == LaunchPending &&
				sameLaunchRegistration(existing.LaunchRegistration, registration) {
				return nil
			}
			return ErrLaunchConflict
		}
		if registration.ConcurrencyMode == ConcurrencyIsolated {
			occupied, err := isolatedRootOccupied(
				conn,
				registration.ManagedRootID,
			)
			if err != nil {
				return err
			}
			if occupied {
				return ErrManagedRootUnavailable
			}
		}
		selectorCollision, found, err := readLaunchBySelector(
			conn,
			registration.SelectorDigest,
		)
		if err != nil {
			return err
		}
		if found {
			if selectorCollision.LaunchID == registration.LaunchID &&
				selectorCollision.State == LaunchPending &&
				sameLaunchRegistration(
					selectorCollision.LaunchRegistration,
					registration,
				) {
				return nil
			}
			return ErrLaunchConflict
		}
		return execute(
			conn,
			`INSERT INTO agent_launches(
			    launch_id, selector_digest, session_id, workspace_id,
			    recovery_generation, client_kind, agent_profile_id,
			    concurrency_mode, managed_root_id, state, created_at
			) VALUES (
			    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10
			);`,
			string(registration.LaunchID),
			registration.SelectorDigest[:],
			string(registration.SessionID),
			string(registration.WorkspaceID),
			lineage.recoveryGeneration,
			string(registration.ClientKind),
			nullableProfile(registration.AgentProfileID),
			string(registration.ConcurrencyMode),
			string(registration.ManagedRootID),
			string(registration.CreatedAt),
		)
	})
}

// ClearPendingLaunches removes registrations that never reserved a start
// proposal. Reserved and consumed launches remain replayable.
func (state LocalState) ClearPendingLaunches(ctx context.Context) error {
	return state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		return execute(
			conn,
			`DELETE FROM agent_launches
			  WHERE session_id = ?1
			    AND workspace_id = ?2
			    AND recovery_generation = ?3
			    AND state = 'pending';`,
			string(lineage.sessionID),
			string(lineage.workspaceID),
			lineage.recoveryGeneration,
		)
	})
}

// ReserveLaunchStart atomically consumes a pending selector into one exact,
// signed agent.session.started proposal and origin sequence.
func (state LocalState) ReserveLaunchStart(
	ctx context.Context,
	selectorDigest Digest,
	clientInstanceID domain.UUIDv7,
	canonicalRequest []byte,
	originDeviceID domain.DeviceID,
	generateIDs LaunchStartIDGenerator,
	build LaunchStartBuilder,
) (LaunchStart, bool, error) {
	requestDigest, err := validateCanonicalLocalRequest(canonicalRequest)
	if err != nil {
		return LaunchStart{}, false, err
	}
	if !clientInstanceID.Valid() ||
		!originDeviceID.Valid() ||
		generateIDs == nil ||
		build == nil {
		return LaunchStart{}, false, ErrInvalidLocalState
	}
	var (
		result    LaunchStart
		duplicate bool
	)
	err = state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		launch, found, err := readLaunchBySelector(conn, selectorDigest)
		if err != nil {
			return err
		}
		if !found {
			return ErrLaunchNotFound
		}
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(launch.SessionID, launch.WorkspaceID) {
			return ErrLocalLineageMismatch
		}
		if launch.RecoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalLineageMismatch
		}
		if launch.State != LaunchPending {
			if launch.State != LaunchReserved ||
				launch.ClientInstanceID != clientInstanceID {
				return ErrLaunchUnavailable
			}
			record, found, err := readLocalRequestByKey(
				conn,
				clientInstanceID,
				launch.LaunchID,
			)
			if err != nil {
				return err
			}
			if !found ||
				record.RequestDigest != requestDigest ||
				record.SessionID != launch.SessionID ||
				record.WorkspaceID != launch.WorkspaceID ||
				record.RecoveryGeneration != launch.RecoveryGeneration ||
				record.OriginDeviceID != originDeviceID ||
				record.RequestKind != event.KindAgentSessionStarted ||
				record.EventID != launch.StartEventID ||
				record.OriginScopeID != launch.AgentSessionID {
				return ErrLocalIdempotencyConflict
			}
			result = LaunchStart{Launch: launch, Command: record}
			duplicate = true
			return nil
		}

		root, rootFound, err := readManagedRoot(conn, launch.ManagedRootID)
		if err != nil {
			return err
		}
		if !rootFound || !launchableRoot(root, launch.ConcurrencyMode) {
			return ErrManagedRootUnavailable
		}
		if root.SessionID != launch.SessionID ||
			root.WorkspaceID != launch.WorkspaceID ||
			root.RecoveryGeneration != launch.RecoveryGeneration {
			return ErrLocalLineageMismatch
		}
		if err := checkLocalBackpressure(
			conn,
			lineage,
			OriginScopeKindAgent,
			launch.AgentSessionID,
		); err != nil {
			return err
		}
		ids, err := generateIDs()
		if err != nil {
			return fmt.Errorf("store: generate launch IDs: %w", err)
		}
		if err := ids.validate(launch.LaunchID, launch.ManagedRootID); err != nil {
			return err
		}
		if exists, err := originCounterExists(
			conn,
			originDeviceID,
			OriginScopeKindAgent,
			ids.AgentSessionID,
		); err != nil {
			return err
		} else if exists {
			return ErrLaunchConflict
		}
		reserved := launch
		reserved.State = LaunchReserved
		reserved.ClientInstanceID = clientInstanceID
		reserved.AgentSessionID = ids.AgentSessionID
		reserved.WorkingRootID = ids.WorkingRootID
		reserved.StartEventID = ids.EventID
		signed, err := build(reserved, ids)
		if err != nil {
			return fmt.Errorf("store: build launch start: %w", err)
		}
		proposal := signed.Proposal()
		commandInput := LocalCommandInput{
			ClientInstanceID: clientInstanceID,
			RequestID:        launch.LaunchID,
			SessionID:        launch.SessionID,
			WorkspaceID:      launch.WorkspaceID,
			BindingClass:     LocalBindingAgent,
			OriginDeviceID:   originDeviceID,
			OriginScopeKind:  OriginScopeKindAgent,
			OriginScopeID:    ids.AgentSessionID,
			RequestKind:      event.KindAgentSessionStarted,
			CanonicalRequest: canonicalRequest,
			CreatedAt:        proposal.CreatedAt,
		}
		if err := validateReservedProposal(
			commandInput,
			ids.EventID,
			1,
			signed,
		); err != nil {
			return err
		}
		if err := validateLaunchStartProposal(reserved, ids, signed); err != nil {
			return err
		}
		if err := execute(
			conn,
			`UPDATE agent_launches
			    SET state = 'reserved', client_instance_id = ?2,
			        agent_session_id = ?3, working_root_id = ?4,
			        start_event_id = ?5
			  WHERE launch_id = ?1 AND state = 'pending';`,
			string(launch.LaunchID),
			string(clientInstanceID),
			string(ids.AgentSessionID),
			string(ids.WorkingRootID),
			string(ids.EventID),
		); err != nil {
			return err
		}
		if err := advanceOriginCounter(
			conn,
			originDeviceID,
			OriginScopeKindAgent,
			ids.AgentSessionID,
			1,
			false,
		); err != nil {
			return err
		}
		record, err := insertLocalCommand(
			conn,
			lineage,
			commandInput,
			requestDigest,
			signed,
		)
		if err != nil {
			return err
		}
		result = LaunchStart{Launch: reserved, Command: record}
		return nil
	})
	if err != nil {
		return LaunchStart{}, false, err
	}
	return result, duplicate, nil
}

func validateLaunchStartProposal(
	launch LaunchRecord,
	ids LaunchStartIDs,
	signed event.SignedEvent,
) error {
	proposal := signed.Proposal()
	entityID, present := proposal.EntityID.Value()
	if !present ||
		entityID != string(ids.AgentSessionID) ||
		proposal.ExpectedEntityVersion != nil {
		return ErrInvalidLocalState
	}
	profile, profilePresent := proposal.Origin.AgentProfileID()
	if !sameOptionalString(launch.AgentProfileID, profile, profilePresent) {
		return ErrInvalidLocalState
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(proposal.Payload, &members); err != nil ||
		len(members) != 2 {
		return ErrInvalidLocalState
	}
	var clientKind, workingRootID string
	if raw, exists := members["client_kind"]; !exists ||
		json.Unmarshal(raw, &clientKind) != nil {
		return ErrInvalidLocalState
	}
	if raw, exists := members["working_root_id"]; !exists ||
		json.Unmarshal(raw, &workingRootID) != nil {
		return ErrInvalidLocalState
	}
	if agentsession.ClientKind(clientKind) != launch.ClientKind ||
		domain.UUIDv7(workingRootID) != ids.WorkingRootID {
		return ErrInvalidLocalState
	}
	return nil
}

// SettleLaunch observes the durable start result. Rejection consumes the
// registration. Acceptance installs or rotates a resume commitment but leaves
// the launch reserved until the bound client acknowledges receipt.
func (state LocalState) SettleLaunch(
	ctx context.Context,
	launchID domain.UUIDv7,
	createdAt domain.Timestamp,
	mint ResumeCommitmentMinter,
) (LaunchSettlement, error) {
	if !launchID.Valid() || !createdAt.Valid() {
		return LaunchSettlement{}, ErrInvalidLocalState
	}
	var settlement LaunchSettlement
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		launch, found, err := readLaunchByID(conn, launchID)
		if err != nil {
			return err
		}
		if !found {
			return ErrLaunchNotFound
		}
		if launch.State != LaunchReserved {
			return ErrLaunchUnavailable
		}
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(launch.SessionID, launch.WorkspaceID) ||
			launch.RecoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalLineageMismatch
		}
		request, found, err := readLocalRequestByKey(
			conn,
			launch.ClientInstanceID,
			launch.LaunchID,
		)
		if err != nil {
			return err
		}
		if !found ||
			request.SessionID != launch.SessionID ||
			request.WorkspaceID != launch.WorkspaceID ||
			request.RecoveryGeneration != launch.RecoveryGeneration ||
			request.BindingClass != LocalBindingAgent ||
			request.OriginScopeKind != OriginScopeKindAgent ||
			request.OriginScopeID != launch.AgentSessionID ||
			request.EventID != launch.StartEventID ||
			request.RequestKind != event.KindAgentSessionStarted {
			return ErrLocalStateIntegrity
		}
		if request.State != LocalRequestResolved || request.Outcome == nil {
			return ErrLaunchPending
		}
		settlement.Outcome = cloneCommandOutcome(*request.Outcome)
		switch request.Outcome.Status {
		case OutcomeRejected:
			if err := execute(
				conn,
				`UPDATE agent_launches SET state = 'rejected'
				  WHERE launch_id = ?1 AND state = 'reserved';`,
				string(launchID),
			); err != nil {
				return err
			}
			if err := execute(
				conn,
				"DELETE FROM agent_resume_tokens WHERE agent_session_id = ?1;",
				string(launch.AgentSessionID),
			); err != nil {
				return err
			}
			launch.State = LaunchRejected
			settlement.Launch = launch
			return nil
		case OutcomeAccepted:
			if mint == nil {
				return ErrLocalStateIntegrity
			}
		default:
			return ErrLocalStateIntegrity
		}

		session, found, err := readCommittedAgentSession(
			conn,
			launch.AgentSessionID,
		)
		if err != nil {
			return err
		}
		if !found ||
			session.DeviceID != request.OriginDeviceID ||
			session.ClientKind != launch.ClientKind ||
			session.WorkingRootID != launch.WorkingRootID ||
			!sameProfile(session.AgentProfileID, launch.AgentProfileID) ||
			session.State == agentsession.StateEnded {
			return ErrLocalStateIntegrity
		}
		root, found, err := readManagedRoot(conn, launch.ManagedRootID)
		if err != nil {
			return err
		}
		if !found ||
			!launchableRoot(root, launch.ConcurrencyMode) ||
			root.SessionID != launch.SessionID ||
			root.WorkspaceID != launch.WorkspaceID ||
			root.RecoveryGeneration != launch.RecoveryGeneration {
			return ErrManagedRootUnavailable
		}
		commitment, err := mint()
		if err != nil {
			return fmt.Errorf("store: mint resume commitment: %w", err)
		}
		if err := execute(
			conn,
			`INSERT INTO agent_resume_tokens(
			    token_digest, session_id, workspace_id, recovery_generation,
			    device_id, agent_session_id, working_root_id, created_at
			) VALUES (
			    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
			)
			ON CONFLICT(agent_session_id) DO UPDATE SET
			    token_digest = excluded.token_digest,
			    session_id = excluded.session_id,
			    workspace_id = excluded.workspace_id,
			    recovery_generation = excluded.recovery_generation,
			    device_id = excluded.device_id,
			    working_root_id = excluded.working_root_id,
			    created_at = excluded.created_at;`,
			commitment[:],
			string(launch.SessionID),
			string(launch.WorkspaceID),
			request.RecoveryGeneration,
			string(session.DeviceID),
			string(launch.AgentSessionID),
			string(launch.WorkingRootID),
			string(createdAt),
		); err != nil {
			return err
		}
		settlement.Launch = launch
		return nil
	})
	if err != nil {
		return LaunchSettlement{}, err
	}
	return settlement, nil
}

// AcknowledgeLaunch consumes a reserved selector only when the capability
// commitment and every stored binding still match the accepted start.
func (state LocalState) AcknowledgeLaunch(
	ctx context.Context,
	launchID domain.UUIDv7,
	clientInstanceID domain.UUIDv7,
	expectedCommitment Digest,
) (LaunchRecord, error) {
	if !launchID.Valid() || !clientInstanceID.Valid() {
		return LaunchRecord{}, ErrInvalidLocalState
	}
	var acknowledged LaunchRecord
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		launch, found, err := readLaunchByID(conn, launchID)
		if err != nil {
			return err
		}
		if !found {
			return ErrLaunchNotFound
		}
		if (launch.State != LaunchReserved && launch.State != LaunchConsumed) ||
			launch.ClientInstanceID != clientInstanceID {
			return ErrLaunchUnavailable
		}
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(launch.SessionID, launch.WorkspaceID) ||
			launch.RecoveryGeneration != lineage.recoveryGeneration {
			return ErrLocalLineageMismatch
		}
		session, found, err := readCommittedAgentSession(conn, launch.AgentSessionID)
		if err != nil {
			return err
		}
		root, rootFound, err := readManagedRoot(conn, launch.ManagedRootID)
		if err != nil {
			return err
		}
		if !found ||
			!rootFound ||
			session.ClientKind != launch.ClientKind ||
			session.WorkingRootID != launch.WorkingRootID ||
			!sameProfile(session.AgentProfileID, launch.AgentProfileID) ||
			session.State == agentsession.StateEnded ||
			!launchableRoot(root, launch.ConcurrencyMode) ||
			root.SessionID != launch.SessionID ||
			root.WorkspaceID != launch.WorkspaceID ||
			root.RecoveryGeneration != launch.RecoveryGeneration {
			return ErrLaunchUnavailable
		}

		var (
			storedDigest   Digest
			tokenSession   domain.UUIDv7
			tokenWorkspace domain.UUIDv4
			tokenRecovery  int64
			tokenDevice    domain.DeviceID
			tokenAgent     domain.UUIDv7
			tokenRoot      domain.UUIDv7
			createdAt      domain.Timestamp
			rowErr         error
		)
		count := 0
		if err := queryArgs(
			conn,
			`SELECT token_digest, session_id, workspace_id,
			        recovery_generation, device_id, agent_session_id,
			        working_root_id, created_at
			   FROM agent_resume_tokens
			  WHERE agent_session_id = ?1;`,
			[]any{string(launch.AgentSessionID)},
			func(stmt *sqlite.Stmt) {
				count++
				if err := copyDigestColumn(&storedDigest, stmt, 0); err != nil {
					rowErr = err
					return
				}
				tokenSession = domain.UUIDv7(stmt.ColumnText(1))
				tokenWorkspace = domain.UUIDv4(stmt.ColumnText(2))
				tokenRecovery = stmt.ColumnInt64(3)
				tokenDevice = domain.DeviceID(stmt.ColumnText(4))
				tokenAgent = domain.UUIDv7(stmt.ColumnText(5))
				tokenRoot = domain.UUIDv7(stmt.ColumnText(6))
				createdAt = domain.Timestamp(stmt.ColumnText(7))
			},
		); err != nil {
			return err
		}
		if rowErr != nil ||
			count != 1 ||
			tokenRecovery < 0 ||
			subtle.ConstantTimeCompare(
				storedDigest[:],
				expectedCommitment[:],
			) != 1 ||
			tokenSession != launch.SessionID ||
			tokenWorkspace != launch.WorkspaceID ||
			uint64(tokenRecovery) != launch.RecoveryGeneration ||
			tokenDevice != session.DeviceID ||
			tokenAgent != launch.AgentSessionID ||
			tokenRoot != launch.WorkingRootID ||
			!createdAt.Valid() {
			return ErrLaunchUnavailable
		}
		if launch.State == LaunchConsumed {
			acknowledged = launch
			return nil
		}
		if err := execute(
			conn,
			`UPDATE agent_launches SET state = 'consumed'
			  WHERE launch_id = ?1 AND state = 'reserved';`,
			string(launchID),
		); err != nil {
			return err
		}
		launch.State = LaunchConsumed
		acknowledged = launch
		return nil
	})
	if err != nil {
		return LaunchRecord{}, err
	}
	return acknowledged, nil
}

// AuthorizeResume compares every context-matching token commitment without an
// early exit, then validates the committed disconnected session and root.
func (state LocalState) AuthorizeResume(
	ctx context.Context,
	tokenDigest Digest,
	sessionID domain.UUIDv7,
	workspaceID domain.UUIDv4,
	deviceID domain.DeviceID,
) (ResumeBinding, error) {
	if !sessionID.Valid() || !workspaceID.Valid() || !deviceID.Valid() {
		return ResumeBinding{}, ErrInvalidLocalState
	}
	type candidate struct {
		digest       Digest
		binding      ResumeBinding
		sessionState agentsession.State
		launchState  LaunchState
		concurrency  ConcurrencyMode
		rootKind     ManagedRootKind
		rootActive   bool
		rootGuard    RootGuardStatus
		rootVerified bool
		recovery     uint64
	}
	var result ResumeBinding
	err := state.withImmediate(ctx, func(conn *sqlite.Conn) error {
		lineage, err := readLocalLineage(conn)
		if err != nil {
			return err
		}
		if !lineage.matches(sessionID, workspaceID) {
			return ErrResumeRejected
		}
		var (
			candidates []candidate
			rowErr     error
		)
		if err := queryArgs(
			conn,
			`SELECT t.token_digest, t.recovery_generation,
			        t.agent_session_id, t.working_root_id,
			        s.client_kind, s.agent_profile_id, s.state,
			        s.resume_state, s.entity_version,
			        l.managed_root_id, l.state,
			        l.concurrency_mode, r.root_kind,
			        r.active, r.guard_status, r.last_verified_at
			   FROM agent_resume_tokens AS t
			   JOIN agent_sessions AS s
			     ON s.agent_session_id = t.agent_session_id
			    AND s.device_id = t.device_id
			    AND s.working_root_id = t.working_root_id
			   JOIN agent_launches AS l
			     ON l.agent_session_id = t.agent_session_id
			    AND l.session_id = t.session_id
			    AND l.workspace_id = t.workspace_id
			    AND l.recovery_generation = t.recovery_generation
			    AND l.working_root_id = t.working_root_id
			    AND l.client_kind = s.client_kind
			    AND l.agent_profile_id IS s.agent_profile_id
			   JOIN managed_roots AS r
			     ON r.managed_root_id = l.managed_root_id
			    AND r.session_id = t.session_id
			    AND r.workspace_id = t.workspace_id
			    AND r.recovery_generation = t.recovery_generation
			  WHERE t.session_id = ?1
			    AND t.workspace_id = ?2
			    AND t.device_id = ?3
			  ORDER BY t.agent_session_id;`,
			[]any{string(sessionID), string(workspaceID), string(deviceID)},
			func(stmt *sqlite.Stmt) {
				var value candidate
				if err := copyDigestColumn(&value.digest, stmt, 0); err != nil {
					rowErr = err
					return
				}
				generation := stmt.ColumnInt64(1)
				version := stmt.ColumnInt64(8)
				if generation < 0 || version < 1 {
					rowErr = ErrLocalStateIntegrity
					return
				}
				value.recovery = uint64(generation)
				value.binding.AgentSessionID = domain.UUIDv7(stmt.ColumnText(2))
				value.binding.WorkingRootID = domain.UUIDv7(stmt.ColumnText(3))
				value.binding.ClientKind = agentsession.ClientKind(stmt.ColumnText(4))
				if stmt.ColumnType(5) != sqlite.TypeNull {
					profile := stmt.ColumnText(5)
					value.binding.AgentProfileID = &profile
				}
				value.sessionState = agentsession.State(stmt.ColumnText(6))
				if stmt.ColumnType(7) != sqlite.TypeNull {
					value.binding.ResumeState = agentsession.State(
						stmt.ColumnText(7),
					)
				}
				value.binding.EntityVersion = uint64(version)
				value.binding.ManagedRootID = domain.UUIDv7(stmt.ColumnText(9))
				value.launchState = LaunchState(stmt.ColumnText(10))
				value.concurrency = ConcurrencyMode(stmt.ColumnText(11))
				value.rootKind = ManagedRootKind(stmt.ColumnText(12))
				value.rootActive = stmt.ColumnBool(13)
				value.rootGuard = RootGuardStatus(stmt.ColumnText(14))
				value.rootVerified = stmt.ColumnType(15) != sqlite.TypeNull
				candidates = append(candidates, value)
			},
		); err != nil {
			return err
		}
		if rowErr != nil {
			return rowErr
		}
		match := -1
		matches := 0
		for index := range candidates {
			equal := subtle.ConstantTimeCompare(
				tokenDigest[:],
				candidates[index].digest[:],
			)
			if equal == 1 {
				match = index
				matches++
			}
		}
		if matches != 1 {
			return ErrResumeRejected
		}
		selected := candidates[match]
		if selected.recovery != lineage.recoveryGeneration ||
			!selected.binding.AgentSessionID.Valid() ||
			!selected.binding.WorkingRootID.Valid() ||
			!selected.binding.ManagedRootID.Valid() ||
			!selected.binding.ClientKind.Valid() ||
			selected.sessionState != agentsession.StateDisconnected ||
			!selected.binding.ResumeState.Connected() ||
			selected.launchState != LaunchConsumed ||
			!selected.concurrency.valid() ||
			!selected.rootKind.valid() ||
			(selected.concurrency == ConcurrencyIsolated &&
				selected.rootKind != ManagedRootIsolated) ||
			(selected.concurrency == ConcurrencyShared &&
				selected.rootKind != ManagedRootShared) ||
			!selected.rootActive ||
			selected.rootGuard != RootGuardHealthy ||
			!selected.rootVerified ||
			selected.binding.EntityVersion < 1 ||
			!domain.ValidUnsignedInteger(selected.binding.EntityVersion) {
			return ErrResumeRejected
		}
		if selected.binding.AgentProfileID != nil {
			profile := *selected.binding.AgentProfileID
			if !utf8.ValidString(profile) ||
				len(profile) < 1 ||
				len(profile) > agentsession.MaxAgentProfileIDBytes {
				return ErrLocalStateIntegrity
			}
		}
		result = selected.binding
		return nil
	})
	if err != nil {
		return ResumeBinding{}, err
	}
	return result, nil
}

func readManagedRoot(
	conn *sqlite.Conn,
	id domain.UUIDv7,
) (ManagedRootRecord, bool, error) {
	var (
		record ManagedRootRecord
		found  bool
		rowErr error
	)
	count := 0
	err := queryArgs(
		conn,
		`SELECT managed_root_id, session_id, workspace_id,
		        recovery_generation, canonical_path, filesystem_identity,
		        repository_identity, root_kind, guard_status,
		        guard_detail_code, active, last_verified_at
		   FROM managed_roots WHERE managed_root_id = ?1;`,
		[]any{string(id)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			record.ManagedRootID = domain.UUIDv7(stmt.ColumnText(0))
			record.SessionID = domain.UUIDv7(stmt.ColumnText(1))
			record.WorkspaceID = domain.UUIDv4(stmt.ColumnText(2))
			generation := stmt.ColumnInt64(3)
			if generation < 0 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			record.RecoveryGeneration = uint64(generation)
			record.CanonicalPath = stmt.ColumnText(4)
			record.FilesystemIdentity = stmt.ColumnText(5)
			record.RepositoryIdentity = stmt.ColumnText(6)
			record.Kind = ManagedRootKind(stmt.ColumnText(7))
			record.GuardStatus = RootGuardStatus(stmt.ColumnText(8))
			if stmt.ColumnType(9) != sqlite.TypeNull {
				record.GuardDetailCode = stmt.ColumnText(9)
			}
			record.Active = stmt.ColumnBool(10)
			if stmt.ColumnType(11) != sqlite.TypeNull {
				timestamp := domain.Timestamp(stmt.ColumnText(11))
				record.LastVerifiedAt = &timestamp
			}
		},
	)
	if err != nil {
		return ManagedRootRecord{}, false, err
	}
	if rowErr != nil {
		return ManagedRootRecord{}, false, rowErr
	}
	if found {
		if err := record.validate(); err != nil {
			return ManagedRootRecord{}, false, ErrLocalStateIntegrity
		}
	}
	return record, found, nil
}

func readLaunchByID(
	conn *sqlite.Conn,
	id domain.UUIDv7,
) (LaunchRecord, bool, error) {
	return readLaunch(
		conn,
		`WHERE launch_id = ?1`,
		[]any{string(id)},
	)
}

func readLaunchBySelector(
	conn *sqlite.Conn,
	digest Digest,
) (LaunchRecord, bool, error) {
	return readLaunch(
		conn,
		`WHERE selector_digest = ?1`,
		[]any{digest[:]},
	)
}

func readLaunch(
	conn *sqlite.Conn,
	predicate string,
	args []any,
) (LaunchRecord, bool, error) {
	var (
		record LaunchRecord
		found  bool
		rowErr error
	)
	count := 0
	err := queryArgs(
		conn,
		`SELECT launch_id, selector_digest, session_id, workspace_id,
		        recovery_generation, client_kind, agent_profile_id,
		        concurrency_mode, managed_root_id, state,
		        client_instance_id, agent_session_id, working_root_id,
		        start_event_id, created_at
		   FROM agent_launches `+predicate+`;`,
		args,
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			record.LaunchID = domain.UUIDv7(stmt.ColumnText(0))
			if err := copyDigestColumn(&record.SelectorDigest, stmt, 1); err != nil {
				rowErr = err
				return
			}
			record.SessionID = domain.UUIDv7(stmt.ColumnText(2))
			record.WorkspaceID = domain.UUIDv4(stmt.ColumnText(3))
			generation := stmt.ColumnInt64(4)
			if generation < 0 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			record.RecoveryGeneration = uint64(generation)
			record.ClientKind = agentsession.ClientKind(stmt.ColumnText(5))
			if stmt.ColumnType(6) != sqlite.TypeNull {
				profile := stmt.ColumnText(6)
				record.AgentProfileID = &profile
			}
			record.ConcurrencyMode = ConcurrencyMode(stmt.ColumnText(7))
			record.ManagedRootID = domain.UUIDv7(stmt.ColumnText(8))
			record.State = LaunchState(stmt.ColumnText(9))
			if stmt.ColumnType(10) != sqlite.TypeNull {
				record.ClientInstanceID = domain.UUIDv7(stmt.ColumnText(10))
			}
			if stmt.ColumnType(11) != sqlite.TypeNull {
				record.AgentSessionID = domain.UUIDv7(stmt.ColumnText(11))
			}
			if stmt.ColumnType(12) != sqlite.TypeNull {
				record.WorkingRootID = domain.UUIDv7(stmt.ColumnText(12))
			}
			if stmt.ColumnType(13) != sqlite.TypeNull {
				record.StartEventID = domain.UUIDv7(stmt.ColumnText(13))
			}
			record.CreatedAt = domain.Timestamp(stmt.ColumnText(14))
		},
	)
	if err != nil {
		return LaunchRecord{}, false, err
	}
	if rowErr != nil {
		return LaunchRecord{}, false, rowErr
	}
	if found {
		if err := record.validate(); err != nil {
			return LaunchRecord{}, false, err
		}
	}
	return record, found, nil
}

func readCommittedAgentSession(
	conn *sqlite.Conn,
	id domain.UUIDv7,
) (agentsession.Session, bool, error) {
	var (
		session agentsession.Session
		found   bool
		rowErr  error
	)
	count := 0
	err := queryArgs(
		conn,
		`SELECT agent_session_id, device_id, client_kind, agent_profile_id,
		        state, resume_state, working_root_id, end_reason,
		        entity_version
		   FROM agent_sessions WHERE agent_session_id = ?1;`,
		[]any{string(id)},
		func(stmt *sqlite.Stmt) {
			count++
			if count != 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			found = true
			session.ID = domain.UUIDv7(stmt.ColumnText(0))
			session.DeviceID = domain.DeviceID(stmt.ColumnText(1))
			session.ClientKind = agentsession.ClientKind(stmt.ColumnText(2))
			if stmt.ColumnType(3) != sqlite.TypeNull {
				profile := stmt.ColumnText(3)
				session.AgentProfileID = &profile
			}
			session.State = agentsession.State(stmt.ColumnText(4))
			if stmt.ColumnType(5) != sqlite.TypeNull {
				session.ResumeState = agentsession.State(stmt.ColumnText(5))
			}
			session.WorkingRootID = domain.UUIDv7(stmt.ColumnText(6))
			if stmt.ColumnType(7) != sqlite.TypeNull {
				session.EndReason = agentsession.EndReason(stmt.ColumnText(7))
			}
			version := stmt.ColumnInt64(8)
			if version < 1 {
				rowErr = ErrLocalStateIntegrity
				return
			}
			session.EntityVersion = uint64(version)
		},
	)
	if err != nil {
		return agentsession.Session{}, false, err
	}
	if rowErr != nil {
		return agentsession.Session{}, false, rowErr
	}
	if found {
		if err := session.Validate(); err != nil {
			return agentsession.Session{}, false, ErrLocalStateIntegrity
		}
	}
	return session, found, nil
}

func originCounterExists(
	conn *sqlite.Conn,
	deviceID domain.DeviceID,
	scopeKind OriginScopeKind,
	scopeID domain.UUIDv7,
) (bool, error) {
	var count int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*) FROM origin_counters
		  WHERE device_id = ?1 AND scope_kind = ?2 AND scope_id = ?3;`,
		[]any{string(deviceID), scopeKind, string(scopeID)},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return false, err
	}
	if count > 1 {
		return false, ErrLocalStateIntegrity
	}
	return count == 1, nil
}

func launchableRoot(root ManagedRootRecord, mode ConcurrencyMode) bool {
	if !root.Active ||
		root.GuardStatus != RootGuardHealthy ||
		root.LastVerifiedAt == nil {
		return false
	}
	return mode == ConcurrencyIsolated && root.Kind == ManagedRootIsolated ||
		mode == ConcurrencyShared && root.Kind == ManagedRootShared
}

func isolatedRootOccupied(
	conn *sqlite.Conn,
	managedRootID domain.UUIDv7,
) (bool, error) {
	var count int64
	if err := queryOneArgs(
		conn,
		`SELECT count(*)
		   FROM agent_launches
		  WHERE managed_root_id = ?1
		    AND concurrency_mode = 'isolated'
		    AND state IN ('pending', 'reserved', 'consumed');`,
		[]any{string(managedRootID)},
		func(stmt *sqlite.Stmt) {
			count = stmt.ColumnInt64(0)
		},
	); err != nil {
		return false, err
	}
	if count < 0 || count > 1 {
		return false, ErrLocalStateIntegrity
	}
	return count == 1, nil
}

func sameManagedRootIdentity(left, right ManagedRootRecord) bool {
	return left.ManagedRootID == right.ManagedRootID &&
		left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.RecoveryGeneration == right.RecoveryGeneration &&
		left.CanonicalPath == right.CanonicalPath &&
		left.FilesystemIdentity == right.FilesystemIdentity &&
		left.RepositoryIdentity == right.RepositoryIdentity &&
		left.Kind == right.Kind
}

func sameManagedRoot(left, right ManagedRootRecord) bool {
	return sameManagedRootIdentity(left, right) &&
		left.GuardStatus == right.GuardStatus &&
		left.GuardDetailCode == right.GuardDetailCode &&
		left.Active == right.Active &&
		sameTimestamp(left.LastVerifiedAt, right.LastVerifiedAt)
}

func sameLaunchRegistration(left, right LaunchRegistration) bool {
	return left.LaunchID == right.LaunchID &&
		left.SelectorDigest == right.SelectorDigest &&
		left.SessionID == right.SessionID &&
		left.WorkspaceID == right.WorkspaceID &&
		left.ClientKind == right.ClientKind &&
		sameProfile(left.AgentProfileID, right.AgentProfileID) &&
		left.ConcurrencyMode == right.ConcurrencyMode &&
		left.ManagedRootID == right.ManagedRootID &&
		left.CreatedAt == right.CreatedAt
}

func sameProfile(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameTimestamp(left, right *domain.Timestamp) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameOptionalString(expected *string, actual string, present bool) bool {
	if expected == nil {
		return !present && actual == ""
	}
	return present && actual == *expected
}

func nullableProfile(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableTimestamp(value *domain.Timestamp) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func cloneCommandOutcome(outcome CommandOutcome) CommandOutcome {
	return CommandOutcome{
		Status: outcome.Status,
		Code:   outcome.Code,
		JSON:   bytes.Clone(outcome.JSON),
	}
}
