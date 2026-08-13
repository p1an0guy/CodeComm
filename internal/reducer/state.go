package reducer

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
	"sort"
	"strings"

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
)

// Snapshot is a complete point-in-time view of the digest-covered projections
// needed by implemented reducers. Callers authenticate retained predecessor
// rows through verified replay or snapshot chain/accumulator evidence before
// construction. NewState validates and deep-copies the rows, then derives all
// negative authorization indexes.
type Snapshot struct {
	SessionID          domain.UUIDv7
	WorkspaceID        domain.UUIDv4
	RecoveryGeneration uint64
	RecoveryPublicKey  ed25519.PublicKey
	CurrentChainIndex  uint64
	CurrentResultIndex uint64

	OriginScopes             map[OriginScopeKey]OriginScope
	AuditCounters            map[domain.DeviceID]auditcounter.Counter
	Devices                  map[domain.DeviceID]device.Device
	VoterSet                 voterset.Set
	CredentialAuthority      credentialauthority.Authority
	CredentialAuthorizations map[credentialauthorization.Key]credentialauthorization.Authorization
	AgentSessions            map[domain.UUIDv7]agentsession.Session
	Tasks                    map[domain.UUIDv7]task.Task
	PlanRevisions            map[domain.UUIDv7]plan.Revision
	PlanCurrent              plan.Current
	MemoryRecords            map[domain.UUIDv7]memory.Record
	Leases                   map[domain.UUIDv7]lease.Lease
	SessionPolicy            policy.Policy
	CanonicalRef             publication.CanonicalRef
	Publications             map[domain.UUIDv7]publication.Publication
	ControlFileProposals     map[domain.UUIDv7]controlfile.Proposal
	MergeConflicts           map[domain.ConflictID]conflict.Conflict
}

// State is a validated reducer input. Its fields are private so production
// callers cannot supply claim counts or conflict predicates independently of
// the complete committed snapshot from which they are derived.
type State struct {
	sessionID          domain.UUIDv7
	workspaceID        domain.UUIDv4
	recoveryGeneration uint64
	recoveryPublicKey  ed25519.PublicKey
	currentChainIndex  uint64
	currentResultIndex uint64

	originScopes             map[OriginScopeKey]OriginScope
	agentScopeDevices        map[domain.UUIDv7]domain.DeviceID
	auditCounters            map[domain.DeviceID]auditcounter.Counter
	devices                  map[domain.DeviceID]device.Device
	voterSet                 voterset.Set
	credentialAuthority      credentialauthority.Authority
	credentialAuthorizations map[credentialauthorization.Key]credentialauthorization.Authorization
	credentialKeys           map[[32]byte]credentialauthorization.Key
	agentSessions            map[domain.UUIDv7]agentsession.Session
	tasks                    map[domain.UUIDv7]task.Task
	planRevisions            map[domain.UUIDv7]plan.Revision
	planCurrent              plan.Current
	memoryRecords            map[domain.UUIDv7]memory.Record
	memorySuccessors         map[domain.UUIDv7]domain.UUIDv7
	leases                   map[domain.UUIDv7]lease.Lease
	sessionPolicy            policy.Policy
	canonicalRef             publication.CanonicalRef
	publications             map[domain.UUIDv7]publication.Publication
	controlFileProposals     map[domain.UUIDv7]controlfile.Proposal
	mergeConflicts           map[domain.ConflictID]conflict.Conflict

	claimsByAgent             map[domain.UUIDv7][]domain.UUIDv7
	claimsByDevice            map[domain.DeviceID][]domain.UUIDv7
	activeLeasesByAgent       map[domain.UUIDv7][]domain.UUIDv7
	activeLeasesByDevice      map[domain.DeviceID][]domain.UUIDv7
	activeLeaseIDs            []domain.UUIDv7
	activeAgentSessionCount   int
	unresolvedConflictsByTask map[domain.UUIDv7]uint64
}

// NewState validates a complete committed snapshot and derives bounded lookup
// indexes. It performs no I/O.
func NewState(snapshot Snapshot) (State, error) {
	if !snapshot.SessionID.Valid() || !snapshot.WorkspaceID.Valid() {
		return State{}, invalidState("session or workspace identity")
	}
	if !domain.ValidUnsignedInteger(snapshot.RecoveryGeneration) {
		return State{}, invalidState("recovery generation exceeds protocol bound")
	}
	if !domain.ValidUnsignedInteger(snapshot.CurrentResultIndex) {
		return State{}, invalidState("result index exceeds protocol bound")
	}
	if !domain.ValidUnsignedInteger(snapshot.CurrentChainIndex) ||
		snapshot.CurrentChainIndex > snapshot.CurrentResultIndex {
		return State{}, invalidState(
			"chain index exceeds its protocol or result-index bound",
		)
	}
	if len(snapshot.RecoveryPublicKey) != ed25519.PublicKeySize {
		return State{}, invalidState("recovery public key has invalid length")
	}
	if snapshot.SessionPolicy.SessionID != snapshot.SessionID {
		return State{}, invalidState("session-policy row has wrong session")
	}
	if err := snapshot.SessionPolicy.Validate(); err != nil {
		return State{}, invalidState("session policy: %v", err)
	}
	if err := snapshot.CanonicalRef.Validate(); err != nil {
		return State{}, invalidState("canonical ref: %v", err)
	}

	state := State{
		sessionID:                 snapshot.SessionID,
		workspaceID:               snapshot.WorkspaceID,
		recoveryGeneration:        snapshot.RecoveryGeneration,
		recoveryPublicKey:         append(ed25519.PublicKey(nil), snapshot.RecoveryPublicKey...),
		currentChainIndex:         snapshot.CurrentChainIndex,
		currentResultIndex:        snapshot.CurrentResultIndex,
		originScopes:              make(map[OriginScopeKey]OriginScope, len(snapshot.OriginScopes)),
		agentScopeDevices:         make(map[domain.UUIDv7]domain.DeviceID),
		auditCounters:             make(map[domain.DeviceID]auditcounter.Counter, len(snapshot.AuditCounters)),
		devices:                   make(map[domain.DeviceID]device.Device, len(snapshot.Devices)),
		credentialAuthorizations:  make(map[credentialauthorization.Key]credentialauthorization.Authorization, len(snapshot.CredentialAuthorizations)),
		credentialKeys:            make(map[[32]byte]credentialauthorization.Key, len(snapshot.CredentialAuthorizations)),
		agentSessions:             make(map[domain.UUIDv7]agentsession.Session, len(snapshot.AgentSessions)),
		tasks:                     make(map[domain.UUIDv7]task.Task, len(snapshot.Tasks)),
		planRevisions:             make(map[domain.UUIDv7]plan.Revision, len(snapshot.PlanRevisions)),
		memoryRecords:             make(map[domain.UUIDv7]memory.Record, len(snapshot.MemoryRecords)),
		memorySuccessors:          make(map[domain.UUIDv7]domain.UUIDv7),
		leases:                    make(map[domain.UUIDv7]lease.Lease, len(snapshot.Leases)),
		sessionPolicy:             snapshot.SessionPolicy,
		canonicalRef:              snapshot.CanonicalRef,
		publications:              make(map[domain.UUIDv7]publication.Publication, len(snapshot.Publications)),
		controlFileProposals:      make(map[domain.UUIDv7]controlfile.Proposal, len(snapshot.ControlFileProposals)),
		mergeConflicts:            make(map[domain.ConflictID]conflict.Conflict, len(snapshot.MergeConflicts)),
		claimsByAgent:             make(map[domain.UUIDv7][]domain.UUIDv7),
		claimsByDevice:            make(map[domain.DeviceID][]domain.UUIDv7),
		activeLeasesByAgent:       make(map[domain.UUIDv7][]domain.UUIDv7),
		activeLeasesByDevice:      make(map[domain.DeviceID][]domain.UUIDv7),
		unresolvedConflictsByTask: make(map[domain.UUIDv7]uint64),
	}

	for key, scope := range snapshot.OriginScopes {
		if err := validateOriginScope(key, scope); err != nil {
			return State{}, err
		}
		if key.Kind == ScopeAgent {
			if prior, exists := state.agentScopeDevices[key.ScopeID]; exists &&
				prior != key.DeviceID {
				return State{}, invalidState(
					"agent scope %q is reused by devices %q and %q",
					key.ScopeID,
					prior,
					key.DeviceID,
				)
			}
			state.agentScopeDevices[key.ScopeID] = key.DeviceID
		}
		state.originScopes[key] = scope
	}
	for id, member := range snapshot.Devices {
		if id != member.ID {
			return State{}, invalidState("device map key does not match row")
		}
		if err := member.Validate(); err != nil {
			return State{}, invalidState("device %q: %v", id, err)
		}
		member.IdentityPublicKey = append(
			ed25519.PublicKey(nil),
			member.IdentityPublicKey...,
		)
		state.devices[id] = member
	}
	if err := state.loadMembershipSnapshot(
		snapshot.AuditCounters,
		snapshot.VoterSet,
		snapshot.CredentialAuthority,
	); err != nil {
		return State{}, err
	}
	if err := state.loadCredentialSnapshot(
		snapshot.CredentialAuthorizations,
	); err != nil {
		return State{}, err
	}
	if err := state.loadControlFileSnapshot(
		snapshot.ControlFileProposals,
	); err != nil {
		return State{}, err
	}
	for key := range state.originScopes {
		if _, exists := state.devices[key.DeviceID]; !exists {
			return State{}, invalidState(
				"origin scope references missing device %q",
				key.DeviceID,
			)
		}
	}
	for id, session := range snapshot.AgentSessions {
		if id != session.ID {
			return State{}, invalidState("agent-session map key does not match row")
		}
		if err := session.Validate(); err != nil {
			return State{}, invalidState("agent session %q: %v", id, err)
		}
		if _, exists := state.devices[session.DeviceID]; !exists {
			return State{}, invalidState(
				"agent session %q references missing device %q",
				id,
				session.DeviceID,
			)
		}
		scopeKey := OriginScopeKey{
			DeviceID: session.DeviceID,
			Kind:     ScopeAgent,
			ScopeID:  id,
		}
		_, scopeExists := state.originScopes[scopeKey]
		boundDeviceID, hasAgentScope := state.agentScopeDevices[id]
		recoveryHistorical := session.State == agentsession.StateEnded &&
			session.EndReason == agentsession.EndReasonRecovery
		if recoveryHistorical && hasAgentScope {
			return State{}, invalidState(
				"recovery-ended agent session %q retains an origin scope",
				id,
			)
		}
		if hasAgentScope && boundDeviceID != session.DeviceID {
			return State{}, invalidState(
				"agent session %q has an origin scope bound to device %q",
				id,
				boundDeviceID,
			)
		}
		if !recoveryHistorical && !scopeExists {
			return State{}, invalidState(
				"agent session %q has no matching origin scope",
				id,
			)
		}
		session = cloneAgentSession(session)
		state.agentSessions[id] = session
		if session.State != agentsession.StateEnded {
			state.activeAgentSessionCount++
		}
	}
	for id, deviceID := range state.agentScopeDevices {
		if _, exists := state.agentSessions[id]; exists {
			continue
		}
		scope := state.originScopes[OriginScopeKey{
			DeviceID: deviceID,
			Kind:     ScopeAgent,
			ScopeID:  id,
		}]
		if scope.LastSequence != 1 {
			return State{}, invalidState(
				"orphan agent scope %q advanced beyond rejected start",
				id,
			)
		}
	}
	if int64(state.activeAgentSessionCount) >
		snapshot.SessionPolicy.Values.MaxActiveAgentSessions {
		return State{}, invalidState(
			"active agent-session count %d exceeds policy limit %d",
			state.activeAgentSessionCount,
			snapshot.SessionPolicy.Values.MaxActiveAgentSessions,
		)
	}
	for id, value := range snapshot.Tasks {
		if id != value.ID {
			return State{}, invalidState("task map key does not match row")
		}
		if err := value.Validate(); err != nil {
			return State{}, invalidState("task %q: %v", id, err)
		}
		value = cloneTask(value)
		state.tasks[id] = value
	}
	for id, value := range state.tasks {
		if err := state.validateTaskReferences(value, nil); err != nil {
			return State{}, invalidState("task %q: %v", id, err)
		}
		if value.OwnerDeviceID != "" {
			state.claimsByAgent[value.OwnerAgentSessionID] = append(
				state.claimsByAgent[value.OwnerAgentSessionID],
				id,
			)
			state.claimsByDevice[value.OwnerDeviceID] = append(
				state.claimsByDevice[value.OwnerDeviceID],
				id,
			)
		}
	}
	if err := state.loadPlanMemorySnapshot(
		snapshot.PlanRevisions,
		snapshot.PlanCurrent,
		snapshot.MemoryRecords,
	); err != nil {
		return State{}, err
	}
	for id := range state.claimsByAgent {
		sort.Slice(state.claimsByAgent[id], func(left, right int) bool {
			return state.claimsByAgent[id][left] < state.claimsByAgent[id][right]
		})
	}
	for id := range state.claimsByDevice {
		sort.Slice(state.claimsByDevice[id], func(left, right int) bool {
			return state.claimsByDevice[id][left] < state.claimsByDevice[id][right]
		})
	}
	for id, value := range snapshot.Leases {
		if id != value.ID {
			return State{}, invalidState("lease map key does not match row")
		}
		if err := value.Validate(); err != nil {
			return State{}, invalidState("lease %q: %v", id, err)
		}
		if err := state.validateLeaseReferences(value); err != nil {
			return State{}, invalidState("lease %q: %v", id, err)
		}
		state.leases[id] = value
		state.addActiveLease(value)
	}
	if err := state.validateActiveLeaseSet(); err != nil {
		return State{}, err
	}

	publicationTasks := make(map[domain.UUIDv7]domain.UUIDv7, len(snapshot.Publications))
	proposalEvents := make(map[domain.UUIDv7]domain.UUIDv7, len(snapshot.Publications))
	for id, value := range snapshot.Publications {
		if id != value.Metadata.PublicationID {
			return State{}, invalidState("publication map key does not match row")
		}
		if err := value.Validate(); err != nil {
			return State{}, invalidState("publication %q: %v", id, err)
		}
		if prior, duplicate := proposalEvents[value.Metadata.ProposalEventID]; duplicate {
			return State{}, invalidState(
				"publications %q and %q reuse proposal event %q",
				prior,
				id,
				value.Metadata.ProposalEventID,
			)
		}
		proposalEvents[value.Metadata.ProposalEventID] = id
		if value.Metadata.TaskID != "" {
			if _, exists := state.tasks[value.Metadata.TaskID]; !exists {
				return State{}, invalidState(
					"publication %q references missing task %q",
					id,
					value.Metadata.TaskID,
				)
			}
			publicationTasks[id] = value.Metadata.TaskID
		}
		state.publications[id] = clonePublication(value)
	}
	for id, value := range snapshot.MergeConflicts {
		if id != value.ID {
			return State{}, invalidState("conflict map key does not match row")
		}
		if err := value.Validate(); err != nil {
			return State{}, invalidState("conflict %q: %v", id, err)
		}
		if _, exists := state.publications[value.PublicationID]; !exists {
			return State{}, invalidState(
				"conflict %q references missing publication %q",
				id,
				value.PublicationID,
			)
		}
		if value.Status == conflict.StatusUnresolved {
			if taskID := publicationTasks[value.PublicationID]; taskID != "" {
				count := state.unresolvedConflictsByTask[taskID]
				if count == domain.MaxSafeInteger {
					return State{}, invalidState(
						"task %q unresolved-conflict count is exhausted",
						taskID,
					)
				}
				state.unresolvedConflictsByTask[taskID] = count + 1
			}
		}
		state.mergeConflicts[id] = cloneConflict(value)
	}
	for id, value := range state.publications {
		if err := state.validatePublicationReferences(value); err != nil {
			return State{}, invalidState("publication %q: %v", id, err)
		}
	}
	if err := state.validatePublicationSupersessionGraph(); err != nil {
		return State{}, invalidState("%v", err)
	}
	for id, value := range state.mergeConflicts {
		if err := state.validateConflictReferences(value); err != nil {
			return State{}, invalidState("conflict %q: %v", id, err)
		}
	}
	for id, value := range state.publications {
		for _, conflictID := range value.Metadata.ResolvesConflictIDs {
			if _, exists := state.mergeConflicts[conflictID]; !exists {
				return State{}, invalidState(
					"publication %q resolves missing conflict %q",
					id,
					conflictID,
				)
			}
		}
	}
	if err := state.validateDerivedBounds(); err != nil {
		return State{}, err
	}
	return state, nil
}

// Apply updates a validated in-memory state only after the corresponding
// durable apply transaction commits. It validates the complete change set
// before mutating any row.
func (state *State) Apply(changes Changes) error {
	if state == nil {
		return invalidState("nil reducer state")
	}
	if state.currentResultIndex == domain.MaxSafeInteger {
		return invalidState("result index is exhausted")
	}
	if changes.AdvancesEventChain &&
		state.currentChainIndex == domain.MaxSafeInteger {
		return invalidState("accepted-event chain index is exhausted")
	}
	if changes.AdvancesEventChain {
		if len(changes.OriginScopes) != 1 {
			return invalidState(
				"accepted event must advance exactly one origin scope",
			)
		}
	} else if changesHaveDomainMutations(changes) {
		return invalidState(
			"domain projection changes lack accepted-event chain marker",
		)
	}
	pendingScopes := make(
		map[OriginScopeKey]OriginScope,
		len(changes.OriginScopes),
	)
	pendingAgentScopeDevices := make(map[domain.UUIDv7]domain.DeviceID)
	for _, scope := range changes.OriginScopes {
		if err := validateOriginScope(scope.OriginScopeKey, scope); err != nil {
			return err
		}
		member, exists := state.devices[scope.DeviceID]
		if !exists || member.ID != scope.DeviceID {
			return invalidState(
				"origin-scope change references missing device %q",
				scope.DeviceID,
			)
		}
		if err := member.Validate(); err != nil {
			return invalidState(
				"origin-scope change device %q: %v",
				scope.DeviceID,
				err,
			)
		}
		if _, duplicate := pendingScopes[scope.OriginScopeKey]; duplicate {
			return invalidState("duplicate origin-scope change")
		}
		current, exists := state.originScopes[scope.OriginScopeKey]
		if exists {
			if current.LastSequence == domain.MaxSafeInteger ||
				scope.LastSequence != current.LastSequence+1 {
				return invalidState(
					"origin scope did not advance by exactly one",
				)
			}
		} else if scope.LastSequence != 1 {
			return invalidState("new origin scope must start at sequence 1")
		}
		if scope.Kind == ScopeAgent {
			if !exists {
				if _, retained := state.agentSessions[scope.ScopeID]; retained {
					return invalidState(
						"new agent scope %q reuses a retained session ID",
						scope.ScopeID,
					)
				}
			}
			if prior, exists := state.agentScopeDevices[scope.ScopeID]; exists &&
				prior != scope.DeviceID {
				return invalidState(
					"agent scope %q is already bound to device %q",
					scope.ScopeID,
					prior,
				)
			}
			if prior, exists := pendingAgentScopeDevices[scope.ScopeID]; exists &&
				prior != scope.DeviceID {
				return invalidState(
					"agent scope %q is duplicated across devices",
					scope.ScopeID,
				)
			}
			pendingAgentScopeDevices[scope.ScopeID] = scope.DeviceID
		}
		pendingScopes[scope.OriginScopeKey] = scope
	}

	pendingMembership, err := state.validateMembershipChanges(changes)
	if err != nil {
		return err
	}
	pendingCredentials, err := state.validateCredentialChanges(
		changes,
		pendingMembership,
	)
	if err != nil {
		return err
	}
	pendingPolicy, err := state.validatePolicyChanges(changes.SessionPolicy)
	if err != nil {
		return err
	}
	pendingRepository, err := state.validateRepositoryChanges(changes)
	if err != nil {
		return err
	}
	pendingControlFiles, err := state.validateControlFileChanges(
		changes.ControlFileProposals,
	)
	if err != nil {
		return err
	}
	effectivePolicy := state.sessionPolicy.Values
	if pendingPolicy != nil {
		effectivePolicy = pendingPolicy.Values
	}

	pendingSessions, err := state.validateAgentSessionChanges(
		changes.AgentSessions,
		pendingScopes,
		effectivePolicy,
	)
	if err != nil {
		return err
	}
	for _, scope := range changes.OriginScopes {
		if scope.Kind != ScopeAgent {
			continue
		}
		if _, exists := state.agentSessions[scope.ScopeID]; exists {
			continue
		}
		if _, exists := pendingSessions[scope.ScopeID]; exists {
			continue
		}
		if scope.LastSequence != 1 {
			return invalidState(
				"orphan agent scope %q advanced beyond rejected start",
				scope.ScopeID,
			)
		}
	}

	pendingTasks := make(map[domain.UUIDv7]task.Task, len(changes.Tasks))
	for _, value := range changes.Tasks {
		if err := value.Validate(); err != nil {
			return invalidState("task change %q: %v", value.ID, err)
		}
		if _, duplicate := pendingTasks[value.ID]; duplicate {
			return invalidState("duplicate task change %q", value.ID)
		}
		pendingTasks[value.ID] = value
	}
	pendingTaskIDs := make(map[domain.UUIDv7]struct{}, len(pendingTasks))
	for id := range pendingTasks {
		pendingTaskIDs[id] = struct{}{}
	}
	for _, value := range changes.Tasks {
		if err := state.validateTaskReferences(value, pendingTaskIDs); err != nil {
			return invalidState("task change %q: %v", value.ID, err)
		}
	}
	pendingCoordination, err := state.validatePlanMemoryChanges(
		changes,
		pendingTaskIDs,
	)
	if err != nil {
		return err
	}
	if err := state.validateLeaseChanges(changes.Leases, effectivePolicy); err != nil {
		return err
	}
	pendingLeases := make(map[domain.UUIDv7]lease.Lease, len(changes.Leases))
	for _, value := range changes.Leases {
		pendingLeases[value.ID] = value
	}
	if err := state.validateProspectiveOwnership(
		pendingSessions,
		pendingTasks,
		pendingLeases,
	); err != nil {
		return err
	}
	if err := state.validateSessionEndCascades(
		pendingSessions,
		pendingTasks,
		pendingLeases,
	); err != nil {
		return err
	}

	agentCounts := make(map[domain.UUIDv7]int, len(state.claimsByAgent))
	for id, claims := range state.claimsByAgent {
		agentCounts[id] = len(claims)
	}
	deviceCounts := make(map[domain.DeviceID]int, len(state.claimsByDevice))
	for id, claims := range state.claimsByDevice {
		deviceCounts[id] = len(claims)
	}
	for _, value := range changes.Tasks {
		if previous, exists := state.tasks[value.ID]; exists &&
			previous.OwnerDeviceID != "" {
			agentCounts[previous.OwnerAgentSessionID]--
			deviceCounts[previous.OwnerDeviceID]--
		}
		if value.OwnerDeviceID != "" {
			agentCounts[value.OwnerAgentSessionID]++
			deviceCounts[value.OwnerDeviceID]++
		}
	}
	for id, count := range agentCounts {
		if int64(count) > effectivePolicy.AgentClaimLimit {
			return invalidState(
				"agent session %q would exceed claim policy",
				id,
			)
		}
	}
	for id, count := range deviceCounts {
		if int64(count) > effectivePolicy.DeviceClaimLimit {
			return invalidState("device %q would exceed claim policy", id)
		}
	}
	switch state.policyUseViolation(
		effectivePolicy,
		pendingMembership.devices,
		pendingMembership.auditCounters,
		pendingSessions,
		pendingTasks,
		pendingLeases,
	) {
	case policyUseWithinLimits:
	case policyUseExceedsLimit:
		return invalidState("prospective rows exceed session policy")
	case policyUseUnsupportedApplyLevel:
		return invalidState(
			"an active device does not support the cluster apply level",
		)
	default:
		return invalidState("unknown policy-use validation result")
	}

	for _, scope := range changes.OriginScopes {
		state.originScopes[scope.OriginScopeKey] = scope
		if scope.Kind == ScopeAgent {
			state.agentScopeDevices[scope.ScopeID] = scope.DeviceID
		}
	}
	for id, member := range pendingMembership.devices {
		member.IdentityPublicKey = bytes.Clone(member.IdentityPublicKey)
		state.devices[id] = member
	}
	for id, counter := range pendingMembership.auditCounters {
		state.auditCounters[id] = counter
	}
	if pendingMembership.voterSet != nil {
		state.voterSet = *pendingMembership.voterSet
	}
	if pendingMembership.credentialAuthority != nil {
		state.credentialAuthority =
			pendingMembership.credentialAuthority.Clone()
	}
	for key, value := range pendingCredentials {
		value = value.Clone()
		state.credentialAuthorizations[key] = value
		state.credentialKeys[value.KeyDigest] = key
	}
	for _, value := range changes.AgentSessions {
		if previous, exists := state.agentSessions[value.ID]; exists &&
			previous.State != agentsession.StateEnded {
			state.activeAgentSessionCount--
		}
		value = cloneAgentSession(value)
		state.agentSessions[value.ID] = value
		if value.State != agentsession.StateEnded {
			state.activeAgentSessionCount++
		}
	}
	for _, value := range changes.Tasks {
		if previous, exists := state.tasks[value.ID]; exists {
			state.removeClaim(previous)
		}
		value = cloneTask(value)
		state.tasks[value.ID] = value
		state.addClaim(value)
	}
	for id, value := range pendingCoordination.planRevisions {
		state.planRevisions[id] = value
	}
	if pendingCoordination.planCurrent != nil {
		state.planCurrent = *pendingCoordination.planCurrent
	}
	for id, value := range pendingCoordination.memoryRecords {
		state.memoryRecords[id] = value
		if predecessor, present := value.Supersedes(); present {
			state.memorySuccessors[predecessor] = id
		}
	}
	for _, value := range changes.Leases {
		if previous, exists := state.leases[value.ID]; exists {
			state.removeActiveLease(previous)
		}
		state.leases[value.ID] = value
		state.addActiveLease(value)
	}
	if pendingPolicy != nil {
		state.sessionPolicy = *pendingPolicy
	}
	if pendingRepository.canonicalRef != nil {
		state.canonicalRef = *pendingRepository.canonicalRef
	}
	for id, value := range pendingRepository.publications {
		state.publications[id] = clonePublication(value)
	}
	for id, value := range pendingControlFiles {
		state.controlFileProposals[id] = value.Clone()
	}
	for id, value := range pendingRepository.mergeConflicts {
		state.mergeConflicts[id] = cloneConflict(value)
	}
	if pendingRepository.conflictTaskID != "" {
		if pendingRepository.unresolvedConflictCount == 0 {
			delete(
				state.unresolvedConflictsByTask,
				pendingRepository.conflictTaskID,
			)
		} else {
			state.unresolvedConflictsByTask[pendingRepository.conflictTaskID] =
				pendingRepository.unresolvedConflictCount
		}
	}
	if changes.AdvancesEventChain {
		state.currentChainIndex++
	}
	state.currentResultIndex++
	return nil
}

func changesHaveDomainMutations(changes Changes) bool {
	return len(changes.AuditCounters) != 0 ||
		len(changes.Tasks) != 0 ||
		len(changes.PlanRevisions) != 0 ||
		len(changes.PlanCurrent) != 0 ||
		len(changes.MemoryRecords) != 0 ||
		len(changes.Leases) != 0 ||
		len(changes.Devices) != 0 ||
		len(changes.VoterSet) != 0 ||
		len(changes.CredentialAuthority) != 0 ||
		len(changes.AgentSessions) != 0 ||
		len(changes.CanonicalRefs) != 0 ||
		len(changes.CredentialAuthorizations) != 0 ||
		len(changes.Publications) != 0 ||
		len(changes.ControlFileProposals) != 0 ||
		len(changes.MergeConflicts) != 0 ||
		len(changes.SessionPolicy) != 0
}

func (state State) validateAgentSessionChanges(
	values []agentsession.Session,
	pendingScopes map[OriginScopeKey]OriginScope,
	policyValues policy.Values,
) (map[domain.UUIDv7]agentsession.Session, error) {
	pending := make(
		map[domain.UUIDv7]agentsession.Session,
		len(values),
	)
	activeCount := state.activeAgentSessionCount
	for _, value := range values {
		if err := value.Validate(); err != nil {
			return nil, invalidAgentSessionChange(value.ID, "%v", err)
		}
		if _, duplicate := pending[value.ID]; duplicate {
			return nil, invalidState(
				"duplicate agent-session change %q",
				value.ID,
			)
		}
		member, exists := state.devices[value.DeviceID]
		if !exists || member.ID != value.DeviceID {
			return nil, invalidAgentSessionChange(
				value.ID,
				"references missing device %q",
				value.DeviceID,
			)
		}
		if err := member.Validate(); err != nil {
			return nil, invalidAgentSessionChange(
				value.ID,
				"device %q: %v",
				value.DeviceID,
				err,
			)
		}

		current, exists := state.agentSessions[value.ID]
		if !exists {
			if value.EntityVersion != 1 {
				return nil, invalidAgentSessionChange(
					value.ID,
					"new session must start at entity version 1",
				)
			}
			scopeKey := OriginScopeKey{
				DeviceID: value.DeviceID,
				Kind:     ScopeAgent,
				ScopeID:  value.ID,
			}
			scope, scopeExists := pendingScopes[scopeKey]
			if !scopeExists || scope.LastSequence != 1 {
				return nil, invalidAgentSessionChange(
					value.ID,
					"creation requires its sequence-1 agent scope",
				)
			}
			if _, burned := state.agentScopeDevices[value.ID]; burned {
				return nil, invalidAgentSessionChange(
					value.ID,
					"agent-session ID is already burned",
				)
			}
			if err := agentsession.ValidateTransition(
				agentsession.OperationCreate,
				agentsession.Lifecycle{},
				value.Lifecycle(),
			); err != nil {
				return nil, invalidAgentSessionChange(
					value.ID,
					"invalid creation transition: %v",
					err,
				)
			}
		} else {
			if err := state.validateAgentSessionReferences(current); err != nil {
				return nil, invalidAgentSessionChange(
					value.ID,
					"source: %v",
					err,
				)
			}
			if !sameAgentSessionIdentity(current, value) {
				return nil, invalidAgentSessionChange(
					value.ID,
					"immutable identity fields changed",
				)
			}
			if current.EntityVersion == domain.MaxSafeInteger ||
				value.EntityVersion != current.EntityVersion+1 {
				return nil, invalidAgentSessionChange(
					value.ID,
					"invalid entity-version transition %d -> %d",
					current.EntityVersion,
					value.EntityVersion,
				)
			}
			operation := agentSessionTransitionOperation(current, value)
			if err := agentsession.ValidateTransition(
				operation,
				current.Lifecycle(),
				value.Lifecycle(),
			); err != nil {
				return nil, invalidAgentSessionChange(
					value.ID,
					"invalid lifecycle transition: %v",
					err,
				)
			}
			if current.State != agentsession.StateEnded {
				activeCount--
			}
		}
		if value.State != agentsession.StateEnded {
			activeCount++
		}
		pending[value.ID] = cloneAgentSession(value)
	}
	if int64(activeCount) > policyValues.MaxActiveAgentSessions {
		return nil, invalidState(
			"agent-session changes would exceed active-session policy",
		)
	}
	return pending, nil
}

func (state State) validateProspectiveOwnership(
	pendingSessions map[domain.UUIDv7]agentsession.Session,
	pendingTasks map[domain.UUIDv7]task.Task,
	pendingLeases map[domain.UUIDv7]lease.Lease,
) error {
	sessionState := func(id domain.UUIDv7) (agentsession.State, bool) {
		if value, exists := pendingSessions[id]; exists {
			return value.State, true
		}
		value, exists := state.agentSessions[id]
		return value.State, exists
	}
	for id, value := range pendingTasks {
		if value.OwnerAgentSessionID == "" {
			continue
		}
		ownerState, exists := sessionState(value.OwnerAgentSessionID)
		if !exists || ownerState == agentsession.StateEnded {
			return invalidState(
				"task change %q is owned by a missing or ended agent session",
				id,
			)
		}
	}
	for id, value := range pendingLeases {
		if value.Status != lease.StatusActive {
			continue
		}
		holderState, exists := sessionState(value.HolderAgentSessionID)
		if !exists || holderState == agentsession.StateEnded {
			return invalidState(
				"active lease change %q is held by a missing or ended agent session",
				id,
			)
		}
	}
	return nil
}

func agentSessionTransitionOperation(
	current agentsession.Session,
	next agentsession.Session,
) agentsession.Operation {
	switch {
	case next.State == agentsession.StateEnded:
		switch next.EndReason {
		case agentsession.EndReasonClean:
			return agentsession.OperationCleanEnd
		case agentsession.EndReasonRecovery:
			return agentsession.OperationRecoveryEnd
		default:
			return agentsession.OperationDaemonEnd
		}
	case next.State == agentsession.StateDisconnected:
		return agentsession.OperationDaemonDisconnect
	case current.State == agentsession.StateDisconnected:
		return agentsession.OperationDaemonResume
	default:
		return agentsession.OperationAgentStatusChange
	}
}

func (state State) validateSessionEndCascades(
	pendingSessions map[domain.UUIDv7]agentsession.Session,
	pendingTasks map[domain.UUIDv7]task.Task,
	pendingLeases map[domain.UUIDv7]lease.Lease,
) error {
	for id, nextSession := range pendingSessions {
		currentSession, exists := state.agentSessions[id]
		if !exists ||
			currentSession.State == agentsession.StateEnded ||
			nextSession.State != agentsession.StateEnded {
			continue
		}
		taskReason := task.ReleaseSessionEnd
		leaseReason := lease.ReleaseSessionEnded
		if nextSession.EndReason == agentsession.EndReasonRecovery {
			taskReason = task.ReleaseRecovery
			leaseReason = lease.ReleaseRecovery
		}

		for _, taskID := range state.claimsByAgent[id] {
			current, exists := state.tasks[taskID]
			if !exists || current.ID != taskID {
				return invalidState(
					"session-end claim index references invalid task %q",
					taskID,
				)
			}
			next, included := pendingTasks[taskID]
			if !included {
				return invalidState(
					"session end %q omits claimed task %q",
					id,
					taskID,
				)
			}
			if err := validateSessionEndTaskChange(
				current,
				next,
				taskReason,
			); err != nil {
				return invalidState(
					"session-end task %q: %v",
					taskID,
					err,
				)
			}
		}
		for _, leaseID := range state.activeLeasesByAgent[id] {
			current, exists := state.leases[leaseID]
			if !exists || current.ID != leaseID {
				return invalidState(
					"session-end lease index references invalid lease %q",
					leaseID,
				)
			}
			next, included := pendingLeases[leaseID]
			if !included {
				return invalidState(
					"session end %q omits active lease %q",
					id,
					leaseID,
				)
			}
			if !sameLeaseReservation(current, next) ||
				next.TTLSeconds != current.TTLSeconds ||
				next.Status != lease.StatusReleased ||
				next.ReleaseReason != leaseReason ||
				current.EntityVersion == domain.MaxSafeInteger ||
				next.EntityVersion != current.EntityVersion+1 {
				return invalidState(
					"session-end lease %q has the wrong terminal mutation",
					leaseID,
				)
			}
		}
	}
	return nil
}

func validateSessionEndTaskChange(
	current task.Task,
	next task.Task,
	reason task.ReleaseReason,
) error {
	if current.ID != next.ID ||
		current.Title != next.Title ||
		current.Body != next.Body ||
		current.Priority != next.Priority ||
		!slices.Equal(current.BlockedBy, next.BlockedBy) ||
		!slices.Equal(current.Labels, next.Labels) ||
		current.CreatedAt != next.CreatedAt {
		return fmt.Errorf("immutable task fields changed")
	}
	if next.State != task.StateReady ||
		next.StateReason != nil ||
		next.OwnerDeviceID != "" ||
		next.OwnerAgentSessionID != "" ||
		next.IntendedDeviceID != "" ||
		next.LastReleaseReason != reason {
		return fmt.Errorf("wrong released ownership state")
	}
	if current.EntityVersion == domain.MaxSafeInteger ||
		next.EntityVersion != current.EntityVersion+1 {
		return fmt.Errorf(
			"invalid entity-version transition %d -> %d",
			current.EntityVersion,
			next.EntityVersion,
		)
	}
	if err := task.ValidateTransition(
		task.OperationSessionEnded,
		current.State,
		next.State,
	); reason == task.ReleaseRecovery {
		err = task.ValidateTransition(
			task.OperationRecoveryRelease,
			current.State,
			next.State,
		)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (state State) validatePolicyChanges(
	changes []policy.Policy,
) (*policy.Policy, error) {
	if len(changes) == 0 {
		return nil, nil
	}
	if len(changes) != 1 {
		return nil, invalidState("session-policy change set must contain one row")
	}
	if err := state.validateDerivedBounds(); err != nil {
		return nil, err
	}
	current := state.sessionPolicy
	next := changes[0]
	if err := policy.ValidateTransition(
		policy.OperationChange,
		current,
		next,
	); err != nil {
		return nil, invalidState("session-policy change: %v", err)
	}
	return &next, nil
}

type policyUseResult uint8

const (
	policyUseWithinLimits policyUseResult = iota
	policyUseExceedsLimit
	policyUseUnsupportedApplyLevel
)

func (state State) policyUseViolation(
	values policy.Values,
	pendingDevices map[domain.DeviceID]device.Device,
	pendingAuditCounters map[domain.DeviceID]auditcounter.Counter,
	pendingSessions map[domain.UUIDv7]agentsession.Session,
	pendingTasks map[domain.UUIDv7]task.Task,
	pendingLeases map[domain.UUIDv7]lease.Lease,
) policyUseResult {
	activeMembers := int64(0)
	unsupportedApplyLevel := false
	countMember := func(member device.Device) {
		if member.Status != device.StatusActive {
			return
		}
		activeMembers++
		if member.MaxApplyLevel < uint64(values.ClusterMinApplyLevel) {
			unsupportedApplyLevel = true
		}
	}
	for id, member := range state.devices {
		if next, changed := pendingDevices[id]; changed {
			member = next
		}
		countMember(member)
	}
	for id, member := range pendingDevices {
		if _, exists := state.devices[id]; !exists {
			countMember(member)
		}
	}

	auditDepthExceeded := false
	countAudit := func(counter auditcounter.Counter) {
		if counter.AcceptedCount >
			uint64(values.AuditDepthPerDevicePerEpoch) {
			auditDepthExceeded = true
		}
	}
	for id, counter := range state.auditCounters {
		if next, changed := pendingAuditCounters[id]; changed {
			counter = next
		}
		countAudit(counter)
	}
	for id, counter := range pendingAuditCounters {
		if _, exists := state.auditCounters[id]; !exists {
			countAudit(counter)
		}
	}

	activeSessions := int64(0)
	for id, current := range state.agentSessions {
		if next, changed := pendingSessions[id]; changed {
			current = next
		}
		if current.State != agentsession.StateEnded {
			activeSessions++
		}
	}
	for id, next := range pendingSessions {
		if _, exists := state.agentSessions[id]; !exists &&
			next.State != agentsession.StateEnded {
			activeSessions++
		}
	}

	claimsByAgent := make(map[domain.UUIDv7]int64)
	claimsByDevice := make(map[domain.DeviceID]int64)
	countClaim := func(value task.Task) {
		if value.OwnerDeviceID == "" {
			return
		}
		claimsByAgent[value.OwnerAgentSessionID]++
		claimsByDevice[value.OwnerDeviceID]++
	}
	for id, current := range state.tasks {
		if next, changed := pendingTasks[id]; changed {
			current = next
		}
		countClaim(current)
	}
	for id, next := range pendingTasks {
		if _, exists := state.tasks[id]; !exists {
			countClaim(next)
		}
	}

	leasesByAgent := make(map[domain.UUIDv7]int64)
	leasesByDevice := make(map[domain.DeviceID]int64)
	countLease := func(value lease.Lease) {
		if value.Status != lease.StatusActive {
			return
		}
		leasesByAgent[value.HolderAgentSessionID]++
		leasesByDevice[value.HolderDeviceID]++
	}
	for id, current := range state.leases {
		if next, changed := pendingLeases[id]; changed {
			current = next
		}
		countLease(current)
	}
	for id, next := range pendingLeases {
		if _, exists := state.leases[id]; !exists {
			countLease(next)
		}
	}

	if activeMembers > values.MaxMemberDevices ||
		activeSessions > values.MaxActiveAgentSessions ||
		auditDepthExceeded ||
		anyCountAbove(claimsByAgent, values.AgentClaimLimit) ||
		anyCountAbove(claimsByDevice, values.DeviceClaimLimit) ||
		anyCountAbove(leasesByAgent, values.AgentLeaseLimit) ||
		anyCountAbove(leasesByDevice, values.DeviceLeaseLimit) {
		return policyUseExceedsLimit
	}
	if unsupportedApplyLevel {
		return policyUseUnsupportedApplyLevel
	}
	return policyUseWithinLimits
}

func anyCountAbove[Key comparable](counts map[Key]int64, limit int64) bool {
	for _, count := range counts {
		if count > limit {
			return true
		}
	}
	return false
}

func (state State) validateDerivedBounds() error {
	values := state.sessionPolicy.Values
	activeSessions := 0
	for _, session := range state.agentSessions {
		if session.State != agentsession.StateEnded {
			activeSessions++
		}
	}
	if activeSessions != state.activeAgentSessionCount {
		return invalidState("active agent-session count disagrees with rows")
	}
	if int64(activeSessions) > values.MaxActiveAgentSessions {
		return invalidState(
			"active agent-session count exceeds policy limit",
		)
	}
	activeAgentTotal := 0
	activeDeviceTotal := 0
	for sessionID, ids := range state.claimsByAgent {
		if int64(len(ids)) > values.AgentClaimLimit {
			return invalidState(
				"agent session %q has %d claims above policy limit %d",
				sessionID,
				len(ids),
				values.AgentClaimLimit,
			)
		}
	}
	for deviceID, ids := range state.claimsByDevice {
		if int64(len(ids)) > values.DeviceClaimLimit {
			return invalidState(
				"device %q has %d claims above policy limit %d",
				deviceID,
				len(ids),
				values.DeviceClaimLimit,
			)
		}
	}
	for sessionID, ids := range state.activeLeasesByAgent {
		activeAgentTotal += len(ids)
		if int64(len(ids)) > values.AgentLeaseLimit {
			return invalidState(
				"agent session %q has %d active leases above policy limit %d",
				sessionID,
				len(ids),
				values.AgentLeaseLimit,
			)
		}
	}
	for deviceID, ids := range state.activeLeasesByDevice {
		activeDeviceTotal += len(ids)
		if int64(len(ids)) > values.DeviceLeaseLimit {
			return invalidState(
				"device %q has %d active leases above policy limit %d",
				deviceID,
				len(ids),
				values.DeviceLeaseLimit,
			)
		}
	}
	if activeAgentTotal != len(state.activeLeaseIDs) ||
		activeDeviceTotal != len(state.activeLeaseIDs) {
		return invalidState("active lease indexes disagree")
	}
	switch state.policyUseViolation(values, nil, nil, nil, nil, nil) {
	case policyUseWithinLimits:
		return nil
	case policyUseExceedsLimit:
		return invalidState("replicated use exceeds committed policy")
	case policyUseUnsupportedApplyLevel:
		return invalidState(
			"an active device does not support the cluster apply level",
		)
	default:
		return invalidState("unknown policy-use validation result")
	}
}

func (state *State) removeClaim(value task.Task) {
	if value.OwnerDeviceID == "" {
		return
	}
	state.claimsByAgent[value.OwnerAgentSessionID] = removeSortedUUIDv7(
		state.claimsByAgent[value.OwnerAgentSessionID],
		value.ID,
	)
	state.claimsByDevice[value.OwnerDeviceID] = removeSortedUUIDv7(
		state.claimsByDevice[value.OwnerDeviceID],
		value.ID,
	)
}

func (state *State) addClaim(value task.Task) {
	if value.OwnerDeviceID == "" {
		return
	}
	state.claimsByAgent[value.OwnerAgentSessionID] = insertSortedUUIDv7(
		state.claimsByAgent[value.OwnerAgentSessionID],
		value.ID,
	)
	state.claimsByDevice[value.OwnerDeviceID] = insertSortedUUIDv7(
		state.claimsByDevice[value.OwnerDeviceID],
		value.ID,
	)
}

func (state State) validateLeaseChanges(
	values []lease.Lease,
	policyValues policy.Values,
) error {
	if len(values) == 0 {
		return nil
	}
	pending := make(map[domain.UUIDv7]lease.Lease, len(values))
	for _, value := range values {
		if err := value.Validate(); err != nil {
			return invalidState("lease change %q: %v", value.ID, err)
		}
		if _, duplicate := pending[value.ID]; duplicate {
			return invalidState("duplicate lease change %q", value.ID)
		}
		if err := state.validateLeaseReferences(value); err != nil {
			return invalidState("lease change %q: %v", value.ID, err)
		}
		if err := state.validateLeaseMutation(value, policyValues); err != nil {
			return invalidState("lease change %q: %v", value.ID, err)
		}
		pending[value.ID] = value
	}

	agentCounts := make(map[domain.UUIDv7]int, len(state.activeLeasesByAgent))
	for id, ids := range state.activeLeasesByAgent {
		agentCounts[id] = len(ids)
	}
	deviceCounts := make(map[domain.DeviceID]int, len(state.activeLeasesByDevice))
	for id, ids := range state.activeLeasesByDevice {
		deviceCounts[id] = len(ids)
	}
	for _, value := range values {
		if previous, exists := state.leases[value.ID]; exists &&
			previous.Status == lease.StatusActive {
			agentCounts[previous.HolderAgentSessionID]--
			deviceCounts[previous.HolderDeviceID]--
		}
		if value.Status == lease.StatusActive {
			agentCounts[value.HolderAgentSessionID]++
			deviceCounts[value.HolderDeviceID]++
		}
	}
	for id, count := range agentCounts {
		if int64(count) > policyValues.AgentLeaseLimit {
			return invalidState("agent session %q would exceed lease policy", id)
		}
	}
	for id, count := range deviceCounts {
		if int64(count) > policyValues.DeviceLeaseLimit {
			return invalidState("device %q would exceed lease policy", id)
		}
	}

	for index, candidate := range values {
		if candidate.Status != lease.StatusActive {
			continue
		}
		for _, existingID := range state.activeLeaseIDs {
			if _, replaced := pending[existingID]; replaced {
				continue
			}
			existing, exists := state.leases[existingID]
			if !exists || existing.Status != lease.StatusActive {
				return invalidState(
					"active lease index references invalid row %q",
					existingID,
				)
			}
			intersects, err := lease.ActiveLeasesIntersect(candidate, existing)
			if err != nil {
				return invalidState("lease intersection: %v", err)
			}
			if intersects {
				return invalidState(
					"active lease %q intersects %q",
					candidate.ID,
					existingID,
				)
			}
		}
		for prior := 0; prior < index; prior++ {
			other := values[prior]
			if other.Status != lease.StatusActive {
				continue
			}
			intersects, err := lease.ActiveLeasesIntersect(candidate, other)
			if err != nil {
				return invalidState("lease intersection: %v", err)
			}
			if intersects {
				return invalidState(
					"active lease changes %q and %q intersect",
					candidate.ID,
					other.ID,
				)
			}
		}
	}
	return nil
}

func (state State) validateActiveLeaseSet() error {
	taskOwners := make(map[domain.UUIDv7]domain.UUIDv7)
	pathOwners := make(map[string]domain.UUIDv7)
	prefixOwners := make(map[string]domain.UUIDv7)
	paths := make([]string, 0)

	for _, id := range state.activeLeaseIDs {
		value, exists := state.leases[id]
		if !exists || value.ID != id || value.Status != lease.StatusActive {
			return invalidState("global active lease index references invalid row %q", id)
		}
		switch value.Scope {
		case lease.ScopeTask:
			if owner, occupied := taskOwners[value.TaskID]; occupied && owner != id {
				return invalidState(
					"active task leases %q and %q intersect",
					owner,
					id,
				)
			}
			taskOwners[value.TaskID] = id
		case lease.ScopePath:
			for _, pattern := range value.PathPatterns() {
				path := string(pattern.Path())
				if owner, occupied := pathOwners[path]; occupied && owner != id {
					return invalidState(
						"active path leases %q and %q intersect at %q",
						owner,
						id,
						path,
					)
				}
				if _, occupied := pathOwners[path]; !occupied {
					paths = append(paths, path)
					pathOwners[path] = id
				}
				if pattern.Prefix() {
					if owner, occupied := prefixOwners[path]; occupied && owner != id {
						return invalidState(
							"active path leases %q and %q intersect at %q",
							owner,
							id,
							path,
						)
					}
					prefixOwners[path] = id
				}
			}
		default:
			return invalidState("active lease %q has unknown scope", id)
		}
	}

	sort.Strings(paths)
	for _, path := range paths {
		owner := pathOwners[path]
		ancestor := path
		for {
			separator := strings.LastIndexByte(ancestor, '/')
			if separator < 0 {
				break
			}
			ancestor = ancestor[:separator]
			if prefixOwner, exists := prefixOwners[ancestor]; exists &&
				prefixOwner != owner {
				return invalidState(
					"active path leases %q and %q intersect at %q",
					prefixOwner,
					owner,
					path,
				)
			}
		}
	}
	return nil
}

func (state State) validateLeaseMutation(
	next lease.Lease,
	policyValues policy.Values,
) error {
	current, exists := state.leases[next.ID]
	if !exists {
		if next.EntityVersion != 1 {
			return fmt.Errorf("new lease must start at entity version 1")
		}
		if err := lease.ValidateTransition(
			lease.OperationCreate,
			lease.Lifecycle{},
			next.Lifecycle(),
		); err != nil {
			return err
		}
		return lease.ValidateRequestedTTL(
			next.TTLSeconds,
			policyValues.LeaseMinTTLSeconds,
			policyValues.LeaseMaxTTLSeconds,
		)
	}
	if !sameLeaseReservation(current, next) {
		return fmt.Errorf("immutable reservation fields changed")
	}
	if current.EntityVersion == domain.MaxSafeInteger ||
		next.EntityVersion != current.EntityVersion+1 {
		return fmt.Errorf(
			"invalid entity-version transition %d -> %d",
			current.EntityVersion,
			next.EntityVersion,
		)
	}

	var operation lease.Operation
	switch next.Status {
	case lease.StatusActive:
		operation = lease.OperationRenew
		if err := lease.ValidateRequestedTTL(
			next.TTLSeconds,
			policyValues.LeaseMinTTLSeconds,
			policyValues.LeaseMaxTTLSeconds,
		); err != nil {
			return err
		}
	case lease.StatusReleased:
		if next.TTLSeconds != current.TTLSeconds {
			return fmt.Errorf("release changed TTL")
		}
		switch next.ReleaseReason {
		case lease.ReleaseVoluntary:
			operation = lease.OperationReleaseVoluntary
		case lease.ReleaseForced:
			operation = lease.OperationReleaseForced
		case lease.ReleaseExpired:
			operation = lease.OperationReleaseExpired
		case lease.ReleaseSessionEnded:
			operation = lease.OperationSessionEnded
		case lease.ReleaseRecovery:
			operation = lease.OperationRecoveryRelease
		default:
			return fmt.Errorf("unknown release reason %q", next.ReleaseReason)
		}
	default:
		return fmt.Errorf("unknown lease status %q", next.Status)
	}
	return lease.ValidateTransition(operation, current.Lifecycle(), next.Lifecycle())
}

func sameLeaseReservation(left, right lease.Lease) bool {
	return left.ID == right.ID &&
		left.HolderDeviceID == right.HolderDeviceID &&
		left.HolderAgentSessionID == right.HolderAgentSessionID &&
		left.Scope == right.Scope &&
		left.TaskID == right.TaskID &&
		slices.Equal(left.PathPatterns(), right.PathPatterns())
}

func (state State) validateAgentSessionReferences(
	value agentsession.Session,
) error {
	member, exists := state.devices[value.DeviceID]
	if !exists {
		return fmt.Errorf("references missing device %q", value.DeviceID)
	}
	if member.ID != value.DeviceID {
		return fmt.Errorf("device map key does not match agent-session row")
	}
	if err := member.Validate(); err != nil {
		return fmt.Errorf("device: %v", err)
	}
	scopeKey := OriginScopeKey{
		DeviceID: value.DeviceID,
		Kind:     ScopeAgent,
		ScopeID:  value.ID,
	}
	boundDeviceID, hasAgentScope := state.agentScopeDevices[value.ID]
	recoveryHistorical := value.State == agentsession.StateEnded &&
		value.EndReason == agentsession.EndReasonRecovery
	if recoveryHistorical {
		if hasAgentScope {
			return fmt.Errorf("recovery-ended session retains an agent origin scope")
		}
		return nil
	}
	if hasAgentScope && boundDeviceID != value.DeviceID {
		return fmt.Errorf(
			"agent origin scope is bound to device %q",
			boundDeviceID,
		)
	}
	scope, exists := state.originScopes[scopeKey]
	if !exists {
		if hasAgentScope {
			return fmt.Errorf("agent origin-scope index has no matching row")
		}
		return fmt.Errorf("missing matching agent origin scope")
	}
	if err := validateOriginScope(scopeKey, scope); err != nil {
		return err
	}
	if !hasAgentScope {
		return fmt.Errorf("matching agent origin scope is absent from its index")
	}
	return nil
}

func (state State) validateLeaseReferences(value lease.Lease) error {
	member, exists := state.devices[value.HolderDeviceID]
	if !exists {
		return fmt.Errorf(
			"references missing holder device %q",
			value.HolderDeviceID,
		)
	}
	if member.ID != value.HolderDeviceID {
		return fmt.Errorf("holder device map key does not match row")
	}
	if err := member.Validate(); err != nil {
		return fmt.Errorf("holder device: %v", err)
	}
	session, exists := state.agentSessions[value.HolderAgentSessionID]
	if !exists {
		return fmt.Errorf(
			"references missing holder agent session %q",
			value.HolderAgentSessionID,
		)
	}
	if session.ID != value.HolderAgentSessionID ||
		session.DeviceID != value.HolderDeviceID {
		return fmt.Errorf("holder agent-session binding mismatch")
	}
	if err := session.Validate(); err != nil {
		return fmt.Errorf("holder agent session: %v", err)
	}
	if value.Status == lease.StatusActive &&
		session.State == agentsession.StateEnded {
		return fmt.Errorf("active lease is held by ended agent session")
	}
	if value.TaskID != "" {
		associated, exists := state.tasks[value.TaskID]
		if !exists {
			return fmt.Errorf("references missing task %q", value.TaskID)
		}
		if associated.ID != value.TaskID {
			return fmt.Errorf("task map key does not match lease association")
		}
		if err := associated.Validate(); err != nil {
			return fmt.Errorf("associated task: %v", err)
		}
	}
	return nil
}

func (state *State) removeActiveLease(value lease.Lease) {
	if value.Status != lease.StatusActive {
		return
	}
	state.activeLeasesByAgent[value.HolderAgentSessionID] = removeSortedUUIDv7(
		state.activeLeasesByAgent[value.HolderAgentSessionID],
		value.ID,
	)
	state.activeLeasesByDevice[value.HolderDeviceID] = removeSortedUUIDv7(
		state.activeLeasesByDevice[value.HolderDeviceID],
		value.ID,
	)
	state.activeLeaseIDs = removeSortedUUIDv7(state.activeLeaseIDs, value.ID)
}

func (state *State) addActiveLease(value lease.Lease) {
	if value.Status != lease.StatusActive {
		return
	}
	state.activeLeasesByAgent[value.HolderAgentSessionID] = insertSortedUUIDv7(
		state.activeLeasesByAgent[value.HolderAgentSessionID],
		value.ID,
	)
	state.activeLeasesByDevice[value.HolderDeviceID] = insertSortedUUIDv7(
		state.activeLeasesByDevice[value.HolderDeviceID],
		value.ID,
	)
	state.activeLeaseIDs = insertSortedUUIDv7(state.activeLeaseIDs, value.ID)
}

func (state State) validateTaskReferences(
	value task.Task,
	pendingTasks map[domain.UUIDv7]struct{},
) error {
	for _, dependencyID := range value.BlockedBy {
		if _, exists := state.tasks[dependencyID]; exists {
			continue
		}
		if _, pending := pendingTasks[dependencyID]; !pending {
			return fmt.Errorf("references missing dependency %q", dependencyID)
		}
	}
	if value.OwnerDeviceID != "" {
		if _, exists := state.devices[value.OwnerDeviceID]; !exists {
			return fmt.Errorf(
				"references missing owner device %q",
				value.OwnerDeviceID,
			)
		}
		session, exists := state.agentSessions[value.OwnerAgentSessionID]
		if !exists {
			return fmt.Errorf(
				"references missing owner agent session %q",
				value.OwnerAgentSessionID,
			)
		}
		if session.DeviceID != value.OwnerDeviceID ||
			session.State == agentsession.StateEnded {
			return fmt.Errorf("owner agent-session binding mismatch")
		}
	}
	if value.IntendedDeviceID != "" {
		if _, exists := state.devices[value.IntendedDeviceID]; !exists {
			return fmt.Errorf(
				"references missing intended device %q",
				value.IntendedDeviceID,
			)
		}
	}
	return nil
}

func removeSortedUUIDv7(
	ids []domain.UUIDv7,
	id domain.UUIDv7,
) []domain.UUIDv7 {
	index, exists := slices.BinarySearch(ids, id)
	if !exists {
		return ids
	}
	copy(ids[index:], ids[index+1:])
	return ids[:len(ids)-1]
}

func insertSortedUUIDv7(
	ids []domain.UUIDv7,
	id domain.UUIDv7,
) []domain.UUIDv7 {
	index, exists := slices.BinarySearch(ids, id)
	if exists {
		return ids
	}
	ids = append(ids, "")
	copy(ids[index+1:], ids[index:])
	ids[index] = id
	return ids
}
