package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ijonahch/codecomm/internal/chain"
	"github.com/ijonahch/codecomm/internal/codec"
	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/agentsession"
	"github.com/ijonahch/codecomm/internal/domain/auditcounter"
	"github.com/ijonahch/codecomm/internal/domain/conflict"
	"github.com/ijonahch/codecomm/internal/domain/controlfile"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthority"
	"github.com/ijonahch/codecomm/internal/domain/credentialauthorization"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/lease"
	"github.com/ijonahch/codecomm/internal/domain/memory"
	"github.com/ijonahch/codecomm/internal/domain/plan"
	"github.com/ijonahch/codecomm/internal/domain/policy"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/task"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
	"github.com/ijonahch/codecomm/internal/peerauth"
	"github.com/ijonahch/codecomm/internal/reducer"
	"github.com/ijonahch/codecomm/internal/store"
)

var ErrInvalidStateView = errors.New("consensus: invalid state view")

type decodedState struct {
	Reducer            reducer.State
	Admission          *peerauth.Snapshot
	identityPublicKeys map[domain.DeviceID]ed25519.PublicKey
	voterDeviceIDs     []domain.DeviceID
}

// IdentityPublicKey returns an independent key copy for an enrolled device.
// Revoked devices remain resolvable for historical signature verification.
func (state decodedState) IdentityPublicKey(
	deviceID domain.DeviceID,
) (ed25519.PublicKey, bool) {
	key, exists := state.identityPublicKeys[deviceID]
	if !exists {
		return nil, false
	}
	return ed25519.PublicKey(bytes.Clone(key)), true
}

// VoterDeviceIDs returns an independent sorted copy of the committed target.
func (state decodedState) VoterDeviceIDs() []domain.DeviceID {
	return append([]domain.DeviceID(nil), state.voterDeviceIDs...)
}

// decodeStateView reconstructs reducer state from one transactionally
// consistent, commitment-verified store view.
func decodeStateView(view store.StateView) (decodedState, error) {
	if err := validateStateViewMetadata(view); err != nil {
		return decodedState{}, err
	}

	recoveryPublicKey, err := recoveryPublicKeyFromGenesis(view)
	if err != nil {
		return decodedState{}, err
	}
	digest, err := chain.StateDigest(
		chain.Versions{
			Digest:           view.Heads.DigestVersion,
			ProjectionSchema: view.Heads.ProjectionSchemaVersion,
		},
		view.ProjectionRows,
	)
	if err != nil {
		return decodedState{}, fmt.Errorf(
			"%w: projection rows: %w",
			ErrInvalidStateView,
			err,
		)
	}
	if store.Digest(digest) != view.ProjectionStateDigest {
		return decodedState{}, fmt.Errorf(
			"%w: projection-state digest mismatch",
			ErrInvalidStateView,
		)
	}

	snapshot := newSnapshot(view, recoveryPublicKey)
	if err := decodeProjectionRows(&snapshot, view.ProjectionRows); err != nil {
		return decodedState{}, err
	}
	state, err := reducer.NewState(snapshot)
	if err != nil {
		return decodedState{}, fmt.Errorf(
			"%w: reducer snapshot: %w",
			ErrInvalidStateView,
			err,
		)
	}
	admission, err := peerauth.NewSnapshot(peerauth.SnapshotInput{
		SessionID:                view.SessionID,
		RecoveryGeneration:       view.RecoveryGeneration,
		AppliedChainIndex:        view.Heads.ChainIndex,
		Devices:                  snapshot.Devices,
		AuditCounters:            snapshot.AuditCounters,
		CredentialAuthorizations: snapshot.CredentialAuthorizations,
	})
	if err != nil {
		return decodedState{}, fmt.Errorf(
			"%w: peer admission snapshot: %w",
			ErrInvalidStateView,
			err,
		)
	}
	return decodedState{
		Reducer:            state,
		Admission:          admission,
		identityPublicKeys: copyIdentityPublicKeys(snapshot.Devices),
		voterDeviceIDs:     snapshot.VoterSet.VoterDeviceIDs(),
	}, nil
}

func validateStateViewMetadata(view store.StateView) error {
	if !view.SessionID.Valid() || !view.WorkspaceID.Valid() {
		return fmt.Errorf("%w: invalid session or workspace ID", ErrInvalidStateView)
	}
	if (view.CurrentTerm == nil) !=
		(view.LastRaftAppliedLogIndex == nil) {
		return fmt.Errorf(
			"%w: partial Raft apply provenance",
			ErrInvalidStateView,
		)
	}
	if !domain.ValidUnsignedInteger(view.RecoveryGeneration) ||
		!domain.ValidUnsignedInteger(view.Heads.ChainIndex) ||
		!domain.ValidUnsignedInteger(view.Heads.ResultIndex) ||
		view.Heads.ChainIndex > view.Heads.ResultIndex {
		return fmt.Errorf("%w: invalid generation or chain positions", ErrInvalidStateView)
	}
	if view.Heads.DigestVersion < 1 ||
		!domain.ValidUnsignedInteger(view.Heads.DigestVersion) ||
		view.Heads.ProjectionSchemaVersion < 1 ||
		!domain.ValidUnsignedInteger(view.Heads.ProjectionSchemaVersion) {
		return fmt.Errorf("%w: invalid projection versions", ErrInvalidStateView)
	}
	if view.CurrentTerm != nil &&
		(*view.CurrentTerm < 1 || !domain.ValidUnsignedInteger(*view.CurrentTerm)) {
		return fmt.Errorf("%w: invalid current term", ErrInvalidStateView)
	}
	if view.LastRaftAppliedLogIndex != nil &&
		(*view.LastRaftAppliedLogIndex < 1 ||
			!domain.ValidUnsignedInteger(*view.LastRaftAppliedLogIndex)) {
		return fmt.Errorf("%w: invalid last applied Raft index", ErrInvalidStateView)
	}
	return nil
}

func recoveryPublicKeyFromGenesis(
	view store.StateView,
) (ed25519.PublicKey, error) {
	canonical, err := codec.CanonicalizeSignedObject(view.GenesisJSON)
	if err != nil || !bytes.Equal(canonical, view.GenesisJSON) {
		return nil, fmt.Errorf(
			"%w: active genesis is not a canonical object: %v",
			ErrInvalidStateView,
			err,
		)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(view.GenesisJSON, &members); err != nil {
		return nil, fmt.Errorf(
			"%w: decode active genesis: %w",
			ErrInvalidStateView,
			err,
		)
	}
	if err := requireGenesisValue(
		members,
		"session_id",
		string(view.SessionID),
	); err != nil {
		return nil, err
	}
	if err := requireGenesisValue(
		members,
		"workspace_id",
		string(view.WorkspaceID),
	); err != nil {
		return nil, err
	}
	rawGeneration, exists := members["recovery_generation"]
	if !exists || bytes.Equal(rawGeneration, []byte("null")) {
		return nil, fmt.Errorf(
			"%w: active genesis omits recovery_generation",
			ErrInvalidStateView,
		)
	}
	var generation uint64
	if err := decodeStrictJSON(rawGeneration, &generation); err != nil ||
		generation != view.RecoveryGeneration {
		return nil, fmt.Errorf(
			"%w: active genesis recovery_generation mismatch",
			ErrInvalidStateView,
		)
	}

	rawKey, exists := members["recovery_public_key"]
	if !exists || bytes.Equal(rawKey, []byte("null")) {
		return nil, fmt.Errorf(
			"%w: active genesis omits recovery_public_key",
			ErrInvalidStateView,
		)
	}
	var encodedKey string
	if err := decodeStrictJSON(rawKey, &encodedKey); err != nil {
		return nil, fmt.Errorf(
			"%w: active genesis recovery_public_key: %w",
			ErrInvalidStateView,
			err,
		)
	}
	key, err := codec.DecodeBase64URLExact(encodedKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: active genesis recovery_public_key: %w",
			ErrInvalidStateView,
			err,
		)
	}
	return ed25519.PublicKey(bytes.Clone(key)), nil
}

func requireGenesisValue(
	members map[string]json.RawMessage,
	name string,
	expected string,
) error {
	raw, exists := members[name]
	if !exists || bytes.Equal(raw, []byte("null")) {
		return fmt.Errorf("%w: active genesis omits %s", ErrInvalidStateView, name)
	}
	var value string
	if err := decodeStrictJSON(raw, &value); err != nil || value != expected {
		return fmt.Errorf("%w: active genesis %s mismatch", ErrInvalidStateView, name)
	}
	return nil
}

func newSnapshot(
	view store.StateView,
	recoveryPublicKey ed25519.PublicKey,
) reducer.Snapshot {
	return reducer.Snapshot{
		SessionID:                view.SessionID,
		WorkspaceID:              view.WorkspaceID,
		RecoveryGeneration:       view.RecoveryGeneration,
		RecoveryPublicKey:        bytes.Clone(recoveryPublicKey),
		CurrentChainIndex:        view.Heads.ChainIndex,
		CurrentResultIndex:       view.Heads.ResultIndex,
		OriginScopes:             make(map[reducer.OriginScopeKey]reducer.OriginScope),
		AuditCounters:            make(map[domain.DeviceID]auditcounter.Counter),
		Devices:                  make(map[domain.DeviceID]device.Device),
		CredentialAuthorizations: make(map[credentialauthorization.Key]credentialauthorization.Authorization),
		AgentSessions:            make(map[domain.UUIDv7]agentsession.Session),
		Tasks:                    make(map[domain.UUIDv7]task.Task),
		PlanRevisions:            make(map[domain.UUIDv7]plan.Revision),
		MemoryRecords:            make(map[domain.UUIDv7]memory.Record),
		Leases:                   make(map[domain.UUIDv7]lease.Lease),
		Publications:             make(map[domain.UUIDv7]publication.Publication),
		ControlFileProposals:     make(map[domain.UUIDv7]controlfile.Proposal),
		MergeConflicts:           make(map[domain.ConflictID]conflict.Conflict),
	}
}

func copyIdentityPublicKeys(
	devices map[domain.DeviceID]device.Device,
) map[domain.DeviceID]ed25519.PublicKey {
	keys := make(map[domain.DeviceID]ed25519.PublicKey, len(devices))
	for id, member := range devices {
		keys[id] = bytes.Clone(member.IdentityPublicKey)
	}
	return keys
}

func decodeProjectionRows(
	snapshot *reducer.Snapshot,
	rows []chain.LogicalRow,
) error {
	singletons := make(map[string]int, 5)
	for index, logical := range rows {
		var err error
		switch logical.Table {
		case "origin_scopes":
			err = decodeOriginScope(snapshot, logical.Row)
		case "audit_counters":
			err = decodeAuditCounter(snapshot, logical.Row)
		case "tasks":
			err = decodeTask(snapshot, logical.Row)
		case "plan_revisions":
			err = decodePlanRevision(snapshot, logical.Row)
		case "plan_current":
			singletons[logical.Table]++
			err = decodePlanCurrent(snapshot, logical.Row)
		case "memory_records":
			err = decodeMemoryRecord(snapshot, logical.Row)
		case "leases":
			err = decodeLease(snapshot, logical.Row)
		case "devices":
			err = decodeDevice(snapshot, logical.Row)
		case "voter_set":
			singletons[logical.Table]++
			err = decodeVoterSet(snapshot, logical.Row)
		case "credential_authority":
			singletons[logical.Table]++
			err = decodeCredentialAuthority(snapshot, logical.Row)
		case "agent_sessions":
			err = decodeAgentSession(snapshot, logical.Row)
		case "canonical_refs":
			singletons[logical.Table]++
			err = decodeCanonicalRef(snapshot, logical.Row)
		case "credential_authorizations":
			err = decodeCredentialAuthorization(snapshot, logical.Row)
		case "publications":
			err = decodePublication(snapshot, logical.Row)
		case "control_file_proposals":
			err = decodeControlFileProposal(snapshot, logical.Row)
		case "merge_conflicts":
			err = decodeMergeConflict(snapshot, logical.Row)
		case "session_policy":
			singletons[logical.Table]++
			err = decodeSessionPolicy(snapshot, logical.Row)
		default:
			err = fmt.Errorf("unknown covered table %q", logical.Table)
		}
		if err != nil {
			return fmt.Errorf(
				"%w: projection row %d table %s: %w",
				ErrInvalidStateView,
				index,
				logical.Table,
				err,
			)
		}
	}
	for _, table := range [...]string{
		"plan_current",
		"voter_set",
		"credential_authority",
		"canonical_refs",
		"session_policy",
	} {
		if singletons[table] != 1 {
			return fmt.Errorf(
				"%w: table %s has %d rows, want exactly 1",
				ErrInvalidStateView,
				table,
				singletons[table],
			)
		}
	}
	return nil
}

type originScopeWire struct {
	DeviceID     string `json:"device_id"`
	ScopeKind    string `json:"scope_kind"`
	ScopeID      string `json:"scope_id"`
	LastSequence uint64 `json:"last_sequence"`
}

func decodeOriginScope(snapshot *reducer.Snapshot, raw []byte) error {
	var wire originScopeWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	key := reducer.OriginScopeKey{
		DeviceID: domain.DeviceID(wire.DeviceID),
		Kind:     reducer.ScopeKind(wire.ScopeKind),
		ScopeID:  domain.UUIDv7(wire.ScopeID),
	}
	if _, exists := snapshot.OriginScopes[key]; exists {
		return errors.New("duplicate origin-scope key")
	}
	snapshot.OriginScopes[key] = reducer.OriginScope{
		OriginScopeKey: key,
		LastSequence:   wire.LastSequence,
	}
	return nil
}

type auditCounterWire struct {
	DeviceID        string `json:"device_id"`
	CredentialEpoch uint64 `json:"credential_epoch"`
	AcceptedCount   uint64 `json:"accepted_count"`
}

func decodeAuditCounter(snapshot *reducer.Snapshot, raw []byte) error {
	var wire auditCounterWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	value := auditcounter.Counter{
		DeviceID:        domain.DeviceID(wire.DeviceID),
		CredentialEpoch: wire.CredentialEpoch,
		AcceptedCount:   wire.AcceptedCount,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.AuditCounters[value.DeviceID]; exists {
		return errors.New("duplicate audit-counter key")
	}
	snapshot.AuditCounters[value.DeviceID] = value
	return nil
}

type taskWire struct {
	TaskID              string          `json:"task_id"`
	Title               string          `json:"title"`
	Body                string          `json:"body"`
	State               string          `json:"state"`
	StateReason         *string         `json:"state_reason"`
	Priority            uint64          `json:"priority"`
	BlockedBy           json.RawMessage `json:"blocked_by"`
	Labels              json.RawMessage `json:"labels"`
	OwnerDeviceID       *string         `json:"owner_device_id"`
	OwnerAgentSessionID *string         `json:"owner_agent_session_id"`
	IntendedDeviceID    *string         `json:"intended_device_id"`
	LastReleaseReason   *string         `json:"last_release_reason"`
	EntityVersion       uint64          `json:"entity_version"`
	CreatedAt           string          `json:"created_at"`
	UpdatedAt           string          `json:"updated_at"`
}

func decodeTask(snapshot *reducer.Snapshot, raw []byte) error {
	var wire taskWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	if wire.Priority > uint64(task.MaxPriority) {
		return fmt.Errorf("priority %d exceeds task priority range", wire.Priority)
	}
	blockedBy, err := decodeArray[domain.UUIDv7](wire.BlockedBy)
	if err != nil {
		return fmt.Errorf("blocked_by: %w", err)
	}
	labels, err := decodeArray[string](wire.Labels)
	if err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	value := task.Task{
		ID:                  domain.UUIDv7(wire.TaskID),
		Title:               wire.Title,
		Body:                wire.Body,
		State:               task.State(wire.State),
		StateReason:         cloneStringPointer(wire.StateReason),
		Priority:            task.Priority(wire.Priority),
		BlockedBy:           blockedBy,
		Labels:              labels,
		OwnerDeviceID:       domain.DeviceID(optionalString(wire.OwnerDeviceID)),
		OwnerAgentSessionID: domain.UUIDv7(optionalString(wire.OwnerAgentSessionID)),
		IntendedDeviceID:    domain.DeviceID(optionalString(wire.IntendedDeviceID)),
		LastReleaseReason:   task.ReleaseReason(optionalString(wire.LastReleaseReason)),
		EntityVersion:       wire.EntityVersion,
		CreatedAt:           domain.Timestamp(wire.CreatedAt),
		UpdatedAt:           domain.Timestamp(wire.UpdatedAt),
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.Tasks[value.ID]; exists {
		return errors.New("duplicate task key")
	}
	snapshot.Tasks[value.ID] = value
	return nil
}

type planRevisionWire struct {
	PlanRevisionID     string          `json:"plan_revision_id"`
	Supersedes         *string         `json:"supersedes"`
	Title              string          `json:"title"`
	Body               string          `json:"body"`
	TaskIDs            json.RawMessage `json:"task_ids"`
	ProposedByDeviceID string          `json:"proposed_by_device_id"`
	CreatedAt          string          `json:"created_at"`
}

func decodePlanRevision(snapshot *reducer.Snapshot, raw []byte) error {
	var wire planRevisionWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	taskIDs, err := decodeArray[domain.UUIDv7](wire.TaskIDs)
	if err != nil {
		return fmt.Errorf("task_ids: %w", err)
	}
	value, err := plan.NewRevision(
		domain.UUIDv7(wire.PlanRevisionID),
		domain.UUIDv7(optionalString(wire.Supersedes)),
		wire.Title,
		wire.Body,
		taskIDs,
		domain.DeviceID(wire.ProposedByDeviceID),
		domain.Timestamp(wire.CreatedAt),
	)
	if err != nil {
		return err
	}
	if _, exists := snapshot.PlanRevisions[value.ID()]; exists {
		return errors.New("duplicate plan-revision key")
	}
	snapshot.PlanRevisions[value.ID()] = value
	return nil
}

type planCurrentWire struct {
	SessionID      string  `json:"session_id"`
	PlanRevisionID *string `json:"plan_revision_id"`
	EntityVersion  uint64  `json:"entity_version"`
}

func decodePlanCurrent(snapshot *reducer.Snapshot, raw []byte) error {
	var wire planCurrentWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	value := plan.Current{
		SessionID:     domain.UUIDv7(wire.SessionID),
		RevisionID:    domain.UUIDv7(optionalString(wire.PlanRevisionID)),
		EntityVersion: wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	snapshot.PlanCurrent = value
	return nil
}

type memoryRecordWire struct {
	MemoryID   string  `json:"memory_id"`
	Scope      string  `json:"scope"`
	TaskID     *string `json:"task_id"`
	Key        string  `json:"key"`
	Body       string  `json:"body"`
	Supersedes *string `json:"supersedes"`
	CreatedAt  string  `json:"created_at"`
}

func decodeMemoryRecord(snapshot *reducer.Snapshot, raw []byte) error {
	var wire memoryRecordWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	value, err := memory.NewRecord(
		domain.UUIDv7(wire.MemoryID),
		memory.Scope(wire.Scope),
		domain.UUIDv7(optionalString(wire.TaskID)),
		wire.Key,
		wire.Body,
		domain.UUIDv7(optionalString(wire.Supersedes)),
		domain.Timestamp(wire.CreatedAt),
	)
	if err != nil {
		return err
	}
	if _, exists := snapshot.MemoryRecords[value.ID()]; exists {
		return errors.New("duplicate memory-record key")
	}
	snapshot.MemoryRecords[value.ID()] = value
	return nil
}

type leaseWire struct {
	LeaseID              string           `json:"lease_id"`
	HolderDeviceID       string           `json:"holder_device_id"`
	HolderAgentSessionID string           `json:"holder_agent_session_id"`
	Scope                string           `json:"scope"`
	TaskID               *string          `json:"task_id"`
	PathGlobs            *json.RawMessage `json:"path_globs"`
	TTLSeconds           uint64           `json:"ttl_seconds"`
	Status               string           `json:"status"`
	ReleaseReason        *string          `json:"release_reason"`
	EntityVersion        uint64           `json:"entity_version"`
}

func decodeLease(snapshot *reducer.Snapshot, raw []byte) error {
	var wire leaseWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	var patterns []string
	var err error
	if wire.PathGlobs != nil {
		patterns, err = decodeArray[string](*wire.PathGlobs)
		if err != nil {
			return fmt.Errorf("path_globs: %w", err)
		}
	}
	value, err := lease.New(
		lease.Fields{
			ID:                   domain.UUIDv7(wire.LeaseID),
			HolderDeviceID:       domain.DeviceID(wire.HolderDeviceID),
			HolderAgentSessionID: domain.UUIDv7(wire.HolderAgentSessionID),
			Scope:                lease.Scope(wire.Scope),
			TaskID:               domain.UUIDv7(optionalString(wire.TaskID)),
			TTLSeconds:           int64(wire.TTLSeconds),
			Status:               lease.Status(wire.Status),
			ReleaseReason:        lease.ReleaseReason(optionalString(wire.ReleaseReason)),
			EntityVersion:        wire.EntityVersion,
		},
		patterns,
	)
	if err != nil {
		return err
	}
	if _, exists := snapshot.Leases[value.ID]; exists {
		return errors.New("duplicate lease key")
	}
	snapshot.Leases[value.ID] = value
	return nil
}

type deviceWire struct {
	DeviceID          string `json:"device_id"`
	Role              string `json:"role"`
	IdentityPublicKey string `json:"identity_public_key"`
	DaemonVersion     string `json:"daemon_version"`
	MaxApplyLevel     uint64 `json:"max_apply_level"`
	Status            string `json:"status"`
	EntityVersion     uint64 `json:"entity_version"`
}

func decodeDevice(snapshot *reducer.Snapshot, raw []byte) error {
	var wire deviceWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	key, err := codec.DecodeBase64URLExact(
		wire.IdentityPublicKey,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return fmt.Errorf("identity_public_key: %w", err)
	}
	value := device.Device{
		ID:                domain.DeviceID(wire.DeviceID),
		Role:              device.Role(wire.Role),
		IdentityPublicKey: ed25519.PublicKey(bytes.Clone(key)),
		DaemonVersion:     wire.DaemonVersion,
		MaxApplyLevel:     wire.MaxApplyLevel,
		Status:            device.Status(wire.Status),
		EntityVersion:     wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.Devices[value.ID]; exists {
		return errors.New("duplicate device key")
	}
	snapshot.Devices[value.ID] = value
	return nil
}

type voterSetWire struct {
	SessionID       string          `json:"session_id"`
	VoterDeviceIDs  json.RawMessage `json:"voter_device_ids"`
	VoterSetVersion uint64          `json:"voter_set_version"`
}

func decodeVoterSet(snapshot *reducer.Snapshot, raw []byte) error {
	var wire voterSetWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	ids, err := decodeArray[domain.DeviceID](wire.VoterDeviceIDs)
	if err != nil {
		return fmt.Errorf("voter_device_ids: %w", err)
	}
	value, err := voterset.New(
		domain.UUIDv7(wire.SessionID),
		ids,
		wire.VoterSetVersion,
	)
	if err != nil {
		return err
	}
	snapshot.VoterSet = value
	return nil
}

type credentialAuthorityWire struct {
	SessionID                   string          `json:"session_id"`
	VoterDeviceIDs              json.RawMessage `json:"voter_device_ids"`
	VoterSetVersion             uint64          `json:"voter_set_version"`
	ActivationSource            string          `json:"activation_source"`
	ActivationCheckpointEventID *string         `json:"activation_checkpoint_event_id"`
	ActivationProofs            json.RawMessage `json:"activation_proofs"`
	PriorAuthoritySigner        *string         `json:"prior_authority_signer"`
	PriorAuthorityHandoff       *string         `json:"prior_authority_handoff"`
}

func decodeCredentialAuthority(snapshot *reducer.Snapshot, raw []byte) error {
	var wire credentialAuthorityWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	voterIDs, err := decodeArray[domain.DeviceID](wire.VoterDeviceIDs)
	if err != nil {
		return fmt.Errorf("voter_device_ids: %w", err)
	}
	proofObjects, err := decodeRawArray(wire.ActivationProofs)
	if err != nil {
		return fmt.Errorf("activation_proofs: %w", err)
	}
	proofs := make([]credentialauthority.ActivationProof, len(proofObjects))
	for index, proof := range proofObjects {
		var voterID domain.DeviceID
		if index < len(voterIDs) {
			voterID = voterIDs[index]
		}
		proofs[index] = credentialauthority.ActivationProof{
			VoterDeviceID: voterID,
			CanonicalJSON: bytes.Clone(proof),
		}
	}
	var handoff *[ed25519.SignatureSize]byte
	if wire.PriorAuthorityHandoff != nil {
		decoded, err := codec.DecodeBase64URLExact(
			*wire.PriorAuthorityHandoff,
			ed25519.SignatureSize,
		)
		if err != nil {
			return fmt.Errorf("prior_authority_handoff: %w", err)
		}
		value := [ed25519.SignatureSize]byte{}
		copy(value[:], decoded)
		handoff = &value
	}
	value := credentialauthority.Authority{
		SessionID:                   domain.UUIDv7(wire.SessionID),
		VoterDeviceIDs:              voterIDs,
		VoterSetVersion:             wire.VoterSetVersion,
		ActivationSource:            credentialauthority.ActivationSource(wire.ActivationSource),
		ActivationCheckpointEventID: domain.UUIDv7(optionalString(wire.ActivationCheckpointEventID)),
		ActivationProofs:            proofs,
		PriorAuthoritySigner:        domain.DeviceID(optionalString(wire.PriorAuthoritySigner)),
		PriorAuthorityHandoff:       handoff,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	snapshot.CredentialAuthority = value
	return nil
}

type agentSessionWire struct {
	AgentSessionID string  `json:"agent_session_id"`
	DeviceID       string  `json:"device_id"`
	ClientKind     string  `json:"client_kind"`
	AgentProfileID *string `json:"agent_profile_id"`
	State          string  `json:"state"`
	ResumeState    *string `json:"resume_state"`
	WorkingRootID  string  `json:"working_root_id"`
	EndReason      *string `json:"end_reason"`
	EntityVersion  uint64  `json:"entity_version"`
}

func decodeAgentSession(snapshot *reducer.Snapshot, raw []byte) error {
	var wire agentSessionWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	value := agentsession.Session{
		ID:             domain.UUIDv7(wire.AgentSessionID),
		DeviceID:       domain.DeviceID(wire.DeviceID),
		ClientKind:     agentsession.ClientKind(wire.ClientKind),
		AgentProfileID: cloneStringPointer(wire.AgentProfileID),
		State:          agentsession.State(wire.State),
		ResumeState:    agentsession.State(optionalString(wire.ResumeState)),
		WorkingRootID:  domain.UUIDv7(wire.WorkingRootID),
		EndReason:      agentsession.EndReason(optionalString(wire.EndReason)),
		EntityVersion:  wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.AgentSessions[value.ID]; exists {
		return errors.New("duplicate agent-session key")
	}
	snapshot.AgentSessions[value.ID] = value
	return nil
}

type canonicalRefWire struct {
	RefName       string `json:"ref_name"`
	CommitOID     string `json:"commit_oid"`
	EntityVersion uint64 `json:"entity_version"`
}

func decodeCanonicalRef(snapshot *reducer.Snapshot, raw []byte) error {
	var wire canonicalRefWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	value := publication.CanonicalRef{
		RefName:       wire.RefName,
		CommitOID:     domain.GitOID(wire.CommitOID),
		EntityVersion: wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	snapshot.CanonicalRef = value
	return nil
}

type credentialAuthorizationWire struct {
	SessionID                string          `json:"session_id"`
	DeviceID                 string          `json:"device_id"`
	Epoch                    uint64          `json:"epoch"`
	EpochPublicKey           string          `json:"epoch_public_key"`
	KeyDigest                string          `json:"key_digest"`
	Role                     string          `json:"role"`
	IssuedAt                 string          `json:"issued_at"`
	NotBefore                string          `json:"not_before"`
	ValiditySeconds          uint64          `json:"validity_seconds"`
	AuthorityVoterSetVersion uint64          `json:"authority_voter_set_version"`
	ClockEndorsements        json.RawMessage `json:"clock_endorsements"`
	BindingSignature         string          `json:"binding_signature"`
	AuthorizationChainIndex  uint64          `json:"authorization_chain_index"`
}

type clockEndorsementWire struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

func decodeCredentialAuthorization(
	snapshot *reducer.Snapshot,
	raw []byte,
) error {
	var wire credentialAuthorizationWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	publicKey, err := codec.DecodeBase64URLExact(
		wire.EpochPublicKey,
		ed25519.PublicKeySize,
	)
	if err != nil {
		return fmt.Errorf("epoch_public_key: %w", err)
	}
	keyDigest, err := codec.DecodeBase64URLExact(wire.KeyDigest, sha256.Size)
	if err != nil {
		return fmt.Errorf("key_digest: %w", err)
	}
	binding, err := codec.DecodeBase64URLExact(
		wire.BindingSignature,
		ed25519.SignatureSize,
	)
	if err != nil {
		return fmt.Errorf("binding_signature: %w", err)
	}
	endorsementObjects, err := decodeRawArray(wire.ClockEndorsements)
	if err != nil {
		return fmt.Errorf("clock_endorsements: %w", err)
	}
	endorsements := make(
		[]credentialauthorization.ClockEndorsement,
		len(endorsementObjects),
	)
	for index, rawEndorsement := range endorsementObjects {
		var endorsementWire clockEndorsementWire
		if err := decodeExactObject(
			rawEndorsement,
			[]string{"device_id", "signature"},
			&endorsementWire,
		); err != nil {
			return fmt.Errorf("clock_endorsements[%d]: %w", index, err)
		}
		signature, err := codec.DecodeBase64URLExact(
			endorsementWire.Signature,
			ed25519.SignatureSize,
		)
		if err != nil {
			return fmt.Errorf(
				"clock_endorsements[%d].signature: %w",
				index,
				err,
			)
		}
		endorsements[index].DeviceID =
			domain.DeviceID(endorsementWire.DeviceID)
		copy(endorsements[index].Signature[:], signature)
	}
	value := credentialauthorization.Authorization{
		SessionID:                domain.UUIDv7(wire.SessionID),
		DeviceID:                 domain.DeviceID(wire.DeviceID),
		Epoch:                    wire.Epoch,
		Role:                     credentialauthorization.Role(wire.Role),
		IssuedAt:                 domain.WholeSecondTimestamp(wire.IssuedAt),
		NotBefore:                domain.WholeSecondTimestamp(wire.NotBefore),
		ValiditySeconds:          wire.ValiditySeconds,
		AuthorityVoterSetVersion: wire.AuthorityVoterSetVersion,
		ClockEndorsements:        endorsements,
		AuthorizationChainIndex:  wire.AuthorizationChainIndex,
	}
	copy(value.EpochPublicKey[:], publicKey)
	copy(value.KeyDigest[:], keyDigest)
	copy(value.BindingSignature[:], binding)
	if err := value.Validate(); err != nil {
		return err
	}
	key := value.PrimaryKey()
	if _, exists := snapshot.CredentialAuthorizations[key]; exists {
		return errors.New("duplicate credential-authorization key")
	}
	snapshot.CredentialAuthorizations[key] = value
	return nil
}

type publicationWire struct {
	PublicationID           string          `json:"publication_id"`
	ProposalEventID         string          `json:"proposal_event_id"`
	SupersedesPublicationID *string         `json:"supersedes_publication_id"`
	TaskID                  *string         `json:"task_id"`
	AuthorDeviceID          string          `json:"author_device_id"`
	AuthorAgentSessionID    string          `json:"author_agent_session_id"`
	BaseCommit              string          `json:"base_commit"`
	CommitOID               string          `json:"commit_oid"`
	TreeOID                 string          `json:"tree_oid"`
	ParentOIDs              json.RawMessage `json:"parent_oids"`
	Paths                   json.RawMessage `json:"paths"`
	ArtifactDigest          string          `json:"artifact_digest"`
	ResolvesConflictIDs     json.RawMessage `json:"resolves_conflict_ids"`
	WorkingRootID           string          `json:"working_root_id"`
	StagingReceipts         json.RawMessage `json:"staging_receipts"`
	State                   string          `json:"state"`
	TerminalSource          *string         `json:"terminal_source"`
	CanonicalLineageMember  bool            `json:"canonical_lineage_member"`
	ReviewVerdict           *string         `json:"review_verdict"`
	ReviewerDeviceID        *string         `json:"reviewer_device_id"`
	ReviewerAgentSessionID  *string         `json:"reviewer_agent_session_id"`
	ReviewActorType         *string         `json:"review_actor_type"`
	DecisionReason          *string         `json:"decision_reason"`
	EntityVersion           uint64          `json:"entity_version"`
}

type stagingReceiptWire struct {
	SessionID                 string `json:"session_id"`
	WorkspaceID               string `json:"workspace_id"`
	VoterSetVersion           uint64 `json:"voter_set_version"`
	PublicationMetadataDigest string `json:"publication_metadata_digest"`
	VoterDeviceID             string `json:"voter_device_id"`
	StagedResultIndex         uint64 `json:"staged_result_index"`
	Signature                 string `json:"signature"`
}

func decodePublication(snapshot *reducer.Snapshot, raw []byte) error {
	var wire publicationWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	parentOIDs, err := decodeArray[domain.GitOID](wire.ParentOIDs)
	if err != nil {
		return fmt.Errorf("parent_oids: %w", err)
	}
	paths, err := decodeArray[domain.RepositoryPath](wire.Paths)
	if err != nil {
		return fmt.Errorf("paths: %w", err)
	}
	conflictIDs, err := decodeArray[domain.ConflictID](
		wire.ResolvesConflictIDs,
	)
	if err != nil {
		return fmt.Errorf("resolves_conflict_ids: %w", err)
	}
	artifactDigest, err := codec.DecodeBase64URLExact(
		wire.ArtifactDigest,
		sha256.Size,
	)
	if err != nil {
		return fmt.Errorf("artifact_digest: %w", err)
	}
	receipts, err := decodeStagingReceipts(wire.StagingReceipts)
	if err != nil {
		return err
	}
	value := publication.Publication{
		Metadata: publication.Metadata{
			PublicationID:           domain.UUIDv7(wire.PublicationID),
			ProposalEventID:         domain.UUIDv7(wire.ProposalEventID),
			SupersedesPublicationID: domain.UUIDv7(optionalString(wire.SupersedesPublicationID)),
			TaskID:                  domain.UUIDv7(optionalString(wire.TaskID)),
			AuthorDeviceID:          domain.DeviceID(wire.AuthorDeviceID),
			AuthorAgentSessionID:    domain.UUIDv7(wire.AuthorAgentSessionID),
			BaseCommit:              domain.GitOID(wire.BaseCommit),
			CommitOID:               domain.GitOID(wire.CommitOID),
			TreeOID:                 domain.GitOID(wire.TreeOID),
			ParentOIDs:              parentOIDs,
			Paths:                   paths,
			ResolvesConflictIDs:     conflictIDs,
			WorkingRootID:           domain.UUIDv7(wire.WorkingRootID),
		},
		StagingReceipts:        receipts,
		State:                  publication.State(wire.State),
		TerminalSource:         publication.TerminalSource(optionalString(wire.TerminalSource)),
		CanonicalLineageMember: wire.CanonicalLineageMember,
		ReviewVerdict:          publication.ReviewVerdict(optionalString(wire.ReviewVerdict)),
		ReviewerDeviceID:       domain.DeviceID(optionalString(wire.ReviewerDeviceID)),
		ReviewerAgentSessionID: domain.UUIDv7(optionalString(wire.ReviewerAgentSessionID)),
		ReviewActorType:        publication.ReviewActorType(optionalString(wire.ReviewActorType)),
		DecisionReason:         cloneStringPointer(wire.DecisionReason),
		EntityVersion:          wire.EntityVersion,
	}
	copy(value.Metadata.ArtifactDigest[:], artifactDigest)
	if err := value.Validate(); err != nil {
		return err
	}
	id := value.Metadata.PublicationID
	if _, exists := snapshot.Publications[id]; exists {
		return errors.New("duplicate publication key")
	}
	snapshot.Publications[id] = value
	return nil
}

func decodeStagingReceipts(
	raw json.RawMessage,
) ([]publication.StagingReceipt, error) {
	objects, err := decodeRawArray(raw)
	if err != nil {
		return nil, fmt.Errorf("staging_receipts: %w", err)
	}
	receipts := make([]publication.StagingReceipt, len(objects))
	fields := []string{
		"session_id",
		"workspace_id",
		"voter_set_version",
		"publication_metadata_digest",
		"voter_device_id",
		"staged_result_index",
		"signature",
	}
	for index, rawReceipt := range objects {
		var wire stagingReceiptWire
		if err := decodeExactObject(rawReceipt, fields, &wire); err != nil {
			return nil, fmt.Errorf("staging_receipts[%d]: %w", index, err)
		}
		digest, err := codec.DecodeBase64URLExact(
			wire.PublicationMetadataDigest,
			sha256.Size,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"staging_receipts[%d].publication_metadata_digest: %w",
				index,
				err,
			)
		}
		signature, err := codec.DecodeBase64URLExact(
			wire.Signature,
			ed25519.SignatureSize,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"staging_receipts[%d].signature: %w",
				index,
				err,
			)
		}
		receipts[index] = publication.StagingReceipt{
			SessionID:         domain.UUIDv7(wire.SessionID),
			WorkspaceID:       domain.UUIDv4(wire.WorkspaceID),
			VoterSetVersion:   wire.VoterSetVersion,
			VoterDeviceID:     domain.DeviceID(wire.VoterDeviceID),
			StagedResultIndex: wire.StagedResultIndex,
		}
		copy(receipts[index].PublicationMetadataDigest[:], digest)
		copy(receipts[index].Signature[:], signature)
	}
	if err := publication.ValidateStagingReceipts(receipts); err != nil {
		return nil, err
	}
	return receipts, nil
}

type controlFileProposalWire struct {
	ProposalEventID    string  `json:"proposal_event_id"`
	SessionID          string  `json:"session_id"`
	Path               string  `json:"path"`
	Operation          string  `json:"operation"`
	ContentDigest      *string `json:"content_digest"`
	ContentSize        uint64  `json:"content_size"`
	Diff               string  `json:"diff"`
	ProposedByDeviceID string  `json:"proposed_by_device_id"`
	ChainIndex         uint64  `json:"chain_index"`
}

func decodeControlFileProposal(
	snapshot *reducer.Snapshot,
	raw []byte,
) error {
	var wire controlFileProposalWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	var contentDigest *controlfile.SHA256Digest
	if wire.ContentDigest != nil {
		decoded, err := codec.DecodeBase64URLExact(
			*wire.ContentDigest,
			sha256.Size,
		)
		if err != nil {
			return fmt.Errorf("content_digest: %w", err)
		}
		value := controlfile.SHA256Digest{}
		copy(value[:], decoded)
		contentDigest = &value
	}
	value := controlfile.Proposal{
		ProposalEventID:    domain.UUIDv7(wire.ProposalEventID),
		SessionID:          domain.UUIDv7(wire.SessionID),
		Path:               domain.RepositoryPath(wire.Path),
		Operation:          controlfile.Operation(wire.Operation),
		ContentDigest:      contentDigest,
		ContentSize:        wire.ContentSize,
		Diff:               wire.Diff,
		ProposedByDeviceID: domain.DeviceID(wire.ProposedByDeviceID),
		ChainIndex:         wire.ChainIndex,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.ControlFileProposals[value.ProposalEventID]; exists {
		return errors.New("duplicate control-file proposal key")
	}
	snapshot.ControlFileProposals[value.ProposalEventID] = value
	return nil
}

type mergeConflictWire struct {
	ConflictID              string          `json:"conflict_id"`
	PublicationID           string          `json:"publication_id"`
	MergeKind               string          `json:"merge_kind"`
	ReplayCommitOID         *string         `json:"replay_commit_oid"`
	MergeBaseOIDs           json.RawMessage `json:"merge_base_oids"`
	CanonicalCommit         string          `json:"canonical_commit"`
	CandidateCommit         string          `json:"candidate_commit"`
	Paths                   json.RawMessage `json:"paths"`
	Status                  string          `json:"status"`
	ResolutionKind          *string         `json:"resolution_kind"`
	ResolutionPublicationID *string         `json:"resolution_publication_id"`
	ForceReason             *string         `json:"force_reason"`
	ResolvedByDeviceID      *string         `json:"resolved_by_device_id"`
	EntityVersion           uint64          `json:"entity_version"`
}

func decodeMergeConflict(snapshot *reducer.Snapshot, raw []byte) error {
	var wire mergeConflictWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	mergeBases, err := decodeArray[domain.GitOID](wire.MergeBaseOIDs)
	if err != nil {
		return fmt.Errorf("merge_base_oids: %w", err)
	}
	paths, err := decodeArray[domain.RepositoryPath](wire.Paths)
	if err != nil {
		return fmt.Errorf("paths: %w", err)
	}
	value := conflict.Conflict{
		ID:                      domain.ConflictID(wire.ConflictID),
		PublicationID:           domain.UUIDv7(wire.PublicationID),
		MergeKind:               conflict.MergeKind(wire.MergeKind),
		ReplayCommitOID:         domain.GitOID(optionalString(wire.ReplayCommitOID)),
		MergeBaseOIDs:           mergeBases,
		CanonicalCommit:         domain.GitOID(wire.CanonicalCommit),
		CandidateCommit:         domain.GitOID(wire.CandidateCommit),
		Paths:                   paths,
		Status:                  conflict.Status(wire.Status),
		ResolutionKind:          conflict.ResolutionKind(optionalString(wire.ResolutionKind)),
		ResolutionPublicationID: domain.UUIDv7(optionalString(wire.ResolutionPublicationID)),
		ForceReason:             optionalString(wire.ForceReason),
		ResolvedByDeviceID:      domain.DeviceID(optionalString(wire.ResolvedByDeviceID)),
		EntityVersion:           wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if _, exists := snapshot.MergeConflicts[value.ID]; exists {
		return errors.New("duplicate merge-conflict key")
	}
	snapshot.MergeConflicts[value.ID] = value
	return nil
}

type sessionPolicyWire struct {
	SessionID     string          `json:"session_id"`
	Values        json.RawMessage `json:"values"`
	EntityVersion uint64          `json:"entity_version"`
}

type policyValuesWire struct {
	CheckpointEvents             int64 `json:"checkpoint_events"`
	CheckpointIntervalSeconds    int64 `json:"checkpoint_interval_seconds"`
	LeaseMinTTLSeconds           int64 `json:"lease_min_ttl_seconds"`
	LeaseDefaultTTLSeconds       int64 `json:"lease_default_ttl_seconds"`
	LeaseMaxTTLSeconds           int64 `json:"lease_max_ttl_seconds"`
	AgentClaimLimit              int64 `json:"agent_claim_limit"`
	AgentLeaseLimit              int64 `json:"agent_lease_limit"`
	DeviceClaimLimit             int64 `json:"device_claim_limit"`
	DeviceLeaseLimit             int64 `json:"device_lease_limit"`
	AdvertisementIntervalSeconds int64 `json:"advertisement_interval_seconds"`
	AuditDepthPerDevicePerEpoch  int64 `json:"audit_depth_per_device_per_epoch"`
	MaxMemberDevices             int64 `json:"max_member_devices"`
	MaxActiveAgentSessions       int64 `json:"max_active_agent_sessions"`
	ClusterMinApplyLevel         int64 `json:"cluster_min_apply_level"`
}

func decodeSessionPolicy(snapshot *reducer.Snapshot, raw []byte) error {
	var wire sessionPolicyWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	fields := []string{
		"checkpoint_events",
		"checkpoint_interval_seconds",
		"lease_min_ttl_seconds",
		"lease_default_ttl_seconds",
		"lease_max_ttl_seconds",
		"agent_claim_limit",
		"agent_lease_limit",
		"device_claim_limit",
		"device_lease_limit",
		"advertisement_interval_seconds",
		"audit_depth_per_device_per_epoch",
		"max_member_devices",
		"max_active_agent_sessions",
		"cluster_min_apply_level",
	}
	var valuesWire policyValuesWire
	if err := decodeExactObject(wire.Values, fields, &valuesWire); err != nil {
		return fmt.Errorf("values: %w", err)
	}
	value := policy.Policy{
		SessionID: domain.UUIDv7(wire.SessionID),
		Values: policy.Values{
			CheckpointEvents:             valuesWire.CheckpointEvents,
			CheckpointIntervalSeconds:    valuesWire.CheckpointIntervalSeconds,
			LeaseMinTTLSeconds:           valuesWire.LeaseMinTTLSeconds,
			LeaseDefaultTTLSeconds:       valuesWire.LeaseDefaultTTLSeconds,
			LeaseMaxTTLSeconds:           valuesWire.LeaseMaxTTLSeconds,
			AgentClaimLimit:              valuesWire.AgentClaimLimit,
			AgentLeaseLimit:              valuesWire.AgentLeaseLimit,
			DeviceClaimLimit:             valuesWire.DeviceClaimLimit,
			DeviceLeaseLimit:             valuesWire.DeviceLeaseLimit,
			AdvertisementIntervalSeconds: valuesWire.AdvertisementIntervalSeconds,
			AuditDepthPerDevicePerEpoch:  valuesWire.AuditDepthPerDevicePerEpoch,
			MaxMemberDevices:             valuesWire.MaxMemberDevices,
			MaxActiveAgentSessions:       valuesWire.MaxActiveAgentSessions,
			ClusterMinApplyLevel:         valuesWire.ClusterMinApplyLevel,
		},
		EntityVersion: wire.EntityVersion,
	}
	if err := value.Validate(); err != nil {
		return err
	}
	snapshot.SessionPolicy = value
	return nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeArray[T any](raw json.RawMessage) ([]T, error) {
	elements, err := decodeRawArray(raw)
	if err != nil {
		return nil, err
	}
	values := make([]T, len(elements))
	for index, element := range elements {
		if err := decodeStrictJSON(element, &values[index]); err != nil {
			return nil, fmt.Errorf("element %d: %w", index, err)
		}
	}
	return values, nil
}

func decodeRawArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, errors.New("must be a non-null array")
	}
	var values []json.RawMessage
	if err := decodeStrictJSON(raw, &values); err != nil {
		return nil, err
	}
	for index, value := range values {
		if bytes.Equal(value, []byte("null")) {
			return nil, fmt.Errorf("element %d must not be null", index)
		}
		values[index] = bytes.Clone(value)
	}
	return values, nil
}

func decodeExactObject(
	raw json.RawMessage,
	requiredFields []string,
	destination any,
) error {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return errors.New("must be a non-null object")
	}
	var members map[string]json.RawMessage
	if err := decodeStrictJSON(raw, &members); err != nil {
		return err
	}
	if len(members) != len(requiredFields) {
		return fmt.Errorf(
			"has %d fields, want %d",
			len(members),
			len(requiredFields),
		)
	}
	for _, field := range requiredFields {
		value, exists := members[field]
		if !exists {
			return fmt.Errorf("omits field %s", field)
		}
		if bytes.Equal(value, []byte("null")) {
			return fmt.Errorf("field %s must not be null", field)
		}
	}
	return decodeStrictJSON(raw, destination)
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
