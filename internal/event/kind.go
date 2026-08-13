// Package event defines CodeComm's signed V1 event envelope and closed kind
// registry.
package event

// MaxSupportedApplyLevel is the highest reducer apply level implemented by
// this binary. It advances only with implemented, frozen reducer contracts.
const MaxSupportedApplyLevel uint64 = 1

// ActorType identifies the daemon-authenticated local principal class that
// originated an event.
type ActorType string

const (
	ActorAgent  ActorType = "agent"
	ActorHuman  ActorType = "human"
	ActorDaemon ActorType = "daemon"
)

var actorTypes = [...]ActorType{ActorAgent, ActorHuman, ActorDaemon}

// Valid reports whether actor is in the closed V1 actor namespace.
func (actor ActorType) Valid() bool {
	return actor == ActorAgent || actor == ActorHuman || actor == ActorDaemon
}

// ActorTypes returns the closed V1 actor namespace in stable order.
func ActorTypes() []ActorType {
	result := make([]ActorType, len(actorTypes))
	copy(result, actorTypes[:])
	return result
}

// Kind is one V1 event kind.
type Kind string

const (
	KindTaskCreated                    Kind = "task.created"
	KindTaskUpdated                    Kind = "task.updated"
	KindTaskStateChanged               Kind = "task.state_changed"
	KindTaskClaimed                    Kind = "task.claimed"
	KindTaskReleased                   Kind = "task.released"
	KindTaskReassigned                 Kind = "task.reassigned"
	KindTaskCancelled                  Kind = "task.cancelled"
	KindWorkspaceConflictDetected      Kind = "workspace.conflict.detected"
	KindWorkspaceConflictForceResolved Kind = "workspace.conflict.force_resolved"
	KindWorkspaceConflictResolved      Kind = "workspace.conflict.resolved"
	KindPublicationProposed            Kind = "publication.proposed"
	KindPublicationReviewed            Kind = "publication.reviewed"
	KindPublicationApplied             Kind = "publication.applied"
	KindPublicationWithdrawn           Kind = "publication.withdrawn"
	KindPlanRevisionProposed           Kind = "plan.revision_proposed"
	KindPlanCurrentSelected            Kind = "plan.current_selected"
	KindMemoryAppended                 Kind = "memory.appended"
	KindActivityRecorded               Kind = "activity.recorded"
	KindLeaseAcquired                  Kind = "lease.acquired"
	KindLeaseRenewed                   Kind = "lease.renewed"
	KindLeaseReleased                  Kind = "lease.released"
	KindAgentSessionStarted            Kind = "agent.session.started"
	KindAgentSessionStateChanged       Kind = "agent.session.state_changed"
	KindAgentSessionEnded              Kind = "agent.session.ended"
	KindMembershipDeviceAdmitted       Kind = "membership.device_admitted"
	KindMembershipVersionReported      Kind = "membership.version_reported"
	KindMembershipRoleChanged          Kind = "membership.role_changed"
	KindMembershipOwnerRecovered       Kind = "membership.owner_recovered"
	KindMembershipDeviceRevoked        Kind = "membership.device_revoked"
	KindMembershipVoterSetChanged      Kind = "membership.voter_set_changed"
	KindMembershipVoterSetActivated    Kind = "membership.voter_set_activated"
	KindPolicyChanged                  Kind = "policy.changed"
	KindCredentialAuthorized           Kind = "credential.authorized"
	KindControlFileChangeProposed      Kind = "control_file.change_proposed"
	KindConsensusCheckpoint            Kind = "consensus.checkpoint"
	KindAuditRecorded                  Kind = "audit.recorded"
)

// RoleRequirement is the minimum committed application role for a kind.
// RoleNone denotes protocol-authorized kinds whose authority comes from a
// separate proof rather than ordinary membership role ordering.
type RoleRequirement string

const (
	RoleNone   RoleRequirement = "none"
	RoleMember RoleRequirement = "member"
	RoleEditor RoleRequirement = "editor"
	RoleOwner  RoleRequirement = "owner"
)

// CASPolicy describes the envelope-level expected_entity_version contract.
type CASPolicy string

const (
	CASForbidden   CASPolicy = "forbidden"
	CASRequired    CASPolicy = "required"
	CASConditional CASPolicy = "conditional"
	// CASPayload means the kind uses only kind-specific compare-and-set tokens
	// in its payload and prohibits expected_entity_version in the envelope.
	CASPayload CASPolicy = "payload"
)

// EntityIDType identifies the closed syntax required for entity_id.
type EntityIDType string

const (
	EntityUUIDv7         EntityIDType = "uuidv7"
	EntityDeviceID       EntityIDType = "device_id"
	EntitySessionID      EntityIDType = "session_id"
	EntityConflictID     EntityIDType = "conflict_id"
	EntityRepositoryPath EntityIDType = "repository_path"
	EntityNull           EntityIDType = "null"
)

type actorMask uint8

const (
	actorAgentMask actorMask = 1 << iota
	actorHumanMask
	actorDaemonMask
)

// Specification is immutable metadata for one registered V1 kind.
type Specification struct {
	kind            Kind
	minimumRole     RoleRequirement
	actors          actorMask
	cas             CASPolicy
	entity          EntityIDType
	minApplyLevel   uint64
	leaderScheduled bool
}

// Kind returns the registered kind.
func (spec Specification) Kind() Kind {
	return spec.kind
}

// MinimumRole returns the kind's minimum committed application role.
func (spec Specification) MinimumRole() RoleRequirement {
	return spec.minimumRole
}

// CASPolicy returns the kind's expected-entity-version policy.
func (spec Specification) CASPolicy() CASPolicy {
	return spec.cas
}

// EntityIDType returns the required entity-id syntax.
func (spec Specification) EntityIDType() EntityIDType {
	return spec.entity
}

// MinApplyLevel returns the immutable apply level for this V1 kind.
func (spec Specification) MinApplyLevel() uint64 {
	return spec.minApplyLevel
}

// LeaderScheduled reports whether daemon-originated instances of the kind are
// permitted only through the leader's scheduler. Leadership is not a signed
// actor type and reducers still validate every proof carried by the payload.
func (spec Specification) LeaderScheduled() bool {
	return spec.leaderScheduled
}

// AllowsActor reports whether actor may propose the kind.
func (spec Specification) AllowsActor(actor ActorType) bool {
	return spec.actors&maskForActor(actor) != 0
}

// AllowedActors returns the kind's actors in stable protocol order.
func (spec Specification) AllowedActors() []ActorType {
	result := make([]ActorType, 0, len(actorTypes))
	for _, actor := range actorTypes {
		if spec.AllowsActor(actor) {
			result = append(result, actor)
		}
	}
	return result
}

const (
	actorsAgent            = actorAgentMask
	actorsHuman            = actorHumanMask
	actorsDaemon           = actorDaemonMask
	actorsAgentHuman       = actorAgentMask | actorHumanMask
	actorsAgentDaemon      = actorAgentMask | actorDaemonMask
	actorsAgentHumanDaemon = actorAgentMask | actorHumanMask | actorDaemonMask
)

var specifications = [...]Specification{
	newSpecification(KindTaskCreated, RoleEditor, actorsAgentHuman, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindTaskUpdated, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindTaskStateChanged, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindTaskClaimed, RoleEditor, actorsAgent, CASRequired, EntityUUIDv7, false),
	newSpecification(KindTaskReleased, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindTaskReassigned, RoleOwner, actorsHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindTaskCancelled, RoleOwner, actorsHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindWorkspaceConflictDetected, RoleEditor, actorsDaemon, CASForbidden, EntityConflictID, false),
	newSpecification(KindWorkspaceConflictForceResolved, RoleOwner, actorsHuman, CASRequired, EntityConflictID, false),
	newSpecification(KindWorkspaceConflictResolved, RoleEditor, actorsAgentHuman, CASRequired, EntityConflictID, false),
	newSpecification(KindPublicationProposed, RoleEditor, actorsAgent, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindPublicationReviewed, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindPublicationApplied, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindPublicationWithdrawn, RoleEditor, actorsAgentHuman, CASRequired, EntityUUIDv7, false),
	newSpecification(KindPlanRevisionProposed, RoleEditor, actorsAgentHuman, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindPlanCurrentSelected, RoleOwner, actorsHuman, CASRequired, EntitySessionID, false),
	newSpecification(KindMemoryAppended, RoleEditor, actorsAgentHuman, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindActivityRecorded, RoleEditor, actorsAgentHumanDaemon, CASForbidden, EntityNull, false),
	newSpecification(KindLeaseAcquired, RoleEditor, actorsAgent, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindLeaseRenewed, RoleEditor, actorsAgent, CASRequired, EntityUUIDv7, false),
	newSpecification(KindLeaseReleased, RoleEditor, actorsAgentHumanDaemon, CASRequired, EntityUUIDv7, true),
	newSpecification(KindAgentSessionStarted, RoleEditor, actorsAgent, CASForbidden, EntityUUIDv7, false),
	newSpecification(KindAgentSessionStateChanged, RoleEditor, actorsAgentDaemon, CASRequired, EntityUUIDv7, false),
	newSpecification(KindAgentSessionEnded, RoleEditor, actorsAgentDaemon, CASRequired, EntityUUIDv7, false),
	newSpecification(KindMembershipDeviceAdmitted, RoleOwner, actorsHuman, CASConditional, EntityDeviceID, false),
	newSpecification(KindMembershipVersionReported, RoleMember, actorsDaemon, CASRequired, EntityDeviceID, false),
	newSpecification(KindMembershipRoleChanged, RoleOwner, actorsHuman, CASRequired, EntityDeviceID, false),
	newSpecification(KindMembershipOwnerRecovered, RoleNone, actorsHuman, CASRequired, EntityDeviceID, false),
	newSpecification(KindMembershipDeviceRevoked, RoleOwner, actorsHuman, CASRequired, EntityDeviceID, false),
	newSpecification(KindMembershipVoterSetChanged, RoleOwner, actorsHuman, CASRequired, EntitySessionID, false),
	newSpecification(KindMembershipVoterSetActivated, RoleNone, actorsDaemon, CASPayload, EntitySessionID, true),
	newSpecification(KindPolicyChanged, RoleOwner, actorsHuman, CASRequired, EntitySessionID, false),
	newSpecification(KindCredentialAuthorized, RoleMember, actorsDaemon, CASForbidden, EntityDeviceID, true),
	newSpecification(KindControlFileChangeProposed, RoleEditor, actorsAgentHuman, CASForbidden, EntityRepositoryPath, false),
	newSpecification(KindConsensusCheckpoint, RoleNone, actorsDaemon, CASForbidden, EntityNull, true),
	newSpecification(KindAuditRecorded, RoleNone, actorsDaemon, CASForbidden, EntityNull, false),
}

var specificationByKind = buildSpecificationIndex()

func newSpecification(
	kind Kind,
	role RoleRequirement,
	actors actorMask,
	cas CASPolicy,
	entity EntityIDType,
	leaderScheduled bool,
) Specification {
	return Specification{
		kind:            kind,
		minimumRole:     role,
		actors:          actors,
		cas:             cas,
		entity:          entity,
		minApplyLevel:   1,
		leaderScheduled: leaderScheduled,
	}
}

func buildSpecificationIndex() map[Kind]Specification {
	index := make(map[Kind]Specification, len(specifications))
	for _, spec := range specifications {
		if _, duplicate := index[spec.kind]; duplicate {
			panic("event: duplicate kind specification: " + string(spec.kind))
		}
		index[spec.kind] = spec
	}
	return index
}

func maskForActor(actor ActorType) actorMask {
	switch actor {
	case ActorAgent:
		return actorAgentMask
	case ActorHuman:
		return actorHumanMask
	case ActorDaemon:
		return actorDaemonMask
	default:
		return 0
	}
}

// LookupKind returns immutable metadata for kind.
func LookupKind(kind Kind) (Specification, bool) {
	spec, ok := specificationByKind[kind]
	return spec, ok
}

// Kinds returns the complete V1 kind namespace in stable order.
func Kinds() []Kind {
	result := make([]Kind, len(specifications))
	for index, spec := range specifications {
		result[index] = spec.kind
	}
	return result
}
