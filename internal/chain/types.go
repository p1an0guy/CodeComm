// Package chain implements CodeComm's SQLite-independent lineage and
// projection commitments.
package chain

import (
	"errors"
)

const maxSafeInteger = uint64(1<<53 - 1)

// Digest is a SHA-256 digest.
type Digest [32]byte

// Versions identifies the projection encodings committed by a state digest.
type Versions struct {
	Digest           uint64
	ProjectionSchema uint64
}

// Boundary supplies a generation's signed-genesis digest and, for successor
// generations, the verified terminal heads of its predecessor.
type Boundary struct {
	Genesis     Digest
	Generation  uint64
	ChainIndex  uint64
	ResultIndex uint64
	ChainHash   Digest
	ResultHash  Digest
}

// Result is the immutable first-seen outcome committed for one proposal.
// ChainIndex and ChainHash are both nil for a rejection and both non-nil for
// an accepted event.
type Result struct {
	ResultIndex    uint64
	Proposal       []byte
	Outcome        []byte
	ProposalDigest Digest
	ChainIndex     *uint64
	ChainHash      *Digest
}

// Mutation is one exact logical projection-row transition. A nil Before or
// After encodes JSON null; both may not be nil.
type Mutation struct {
	Table      string
	PrimaryKey []byte
	Before     []byte
	After      []byte
}

// LogicalRow is one current covered projection row.
type LogicalRow struct {
	Table      string
	PrimaryKey []byte
	Row        []byte
}

// TableRowCount declares one covered table's row cardinality in registry
// order. It lets StateDigester frame table counts before rows are streamed.
type TableRowCount struct {
	Table string
	Count uint64
}

var (
	// ErrInvalidBoundary reports an inconsistent generation boundary.
	ErrInvalidBoundary = errors.New("chain: invalid generation boundary")
	// ErrInvalidIndex reports a protocol index outside the exact-integer range.
	ErrInvalidIndex = errors.New("chain: invalid index")
	// ErrInvalidVersions reports zero or inexact projection versions.
	ErrInvalidVersions = errors.New("chain: invalid projection versions")
	// ErrInvalidObject reports JSON that is not an exact canonical object.
	ErrInvalidObject = errors.New("chain: invalid canonical object")
	// ErrInvalidResult reports an inconsistent accepted/rejected result shape.
	ErrInvalidResult = errors.New("chain: invalid command result")
	// ErrProposalDigest reports a proposal digest that does not match the
	// canonical proposal bytes.
	ErrProposalDigest = errors.New("chain: proposal digest mismatch")
	// ErrUnknownTable reports a table outside the fixed covered-table registry.
	ErrUnknownTable = errors.New("chain: unknown covered table")
	// ErrInvalidPrimaryKey reports a noncanonical, null, mistyped, or
	// wrong-arity logical primary key.
	ErrInvalidPrimaryKey = errors.New("chain: invalid logical primary key")
	// ErrInvalidMutation reports an invalid before/after row transition.
	ErrInvalidMutation = errors.New("chain: invalid projection mutation")
	// ErrDuplicateMutation reports two mutations for the same logical row.
	ErrDuplicateMutation = errors.New("chain: duplicate projection mutation")
	// ErrMutationSetTooLarge reports a mutation encoding above the bounded V1
	// apply-time cascade ceiling.
	ErrMutationSetTooLarge = errors.New("chain: projection mutation set too large")
	// ErrInvalidLogicalRow reports a malformed row or a row whose embedded
	// primary key differs from its separately framed key.
	ErrInvalidLogicalRow = errors.New("chain: invalid logical row")
	// ErrDuplicateLogicalRow reports two current rows with the same table/key.
	ErrDuplicateLogicalRow = errors.New("chain: duplicate logical row")
	// ErrLogicalRowOrder reports a streaming state-digest input that differs
	// from covered-table and primary-key order.
	ErrLogicalRowOrder = errors.New("chain: logical rows are not canonically ordered")
)

type primaryKeyKind uint8

const (
	primaryKeyString primaryKeyKind = iota
	primaryKeyPositiveInteger
)

type primaryKeyField struct {
	name string
	kind primaryKeyKind
}

type logicalValueKind uint8

const (
	logicalString logicalValueKind = iota
	logicalInteger
	logicalArray
	logicalObject
	logicalBase64URL
	logicalBoolean
)

type logicalField struct {
	name        string
	kind        logicalValueKind
	nullable    bool
	decodedSize int
}

type tableSpec struct {
	name       string
	primaryKey []primaryKeyField
	fields     []logicalField
}

func requiredField(name string, kind logicalValueKind) logicalField {
	return logicalField{name: name, kind: kind}
}

func optionalField(name string, kind logicalValueKind) logicalField {
	return logicalField{name: name, kind: kind, nullable: true}
}

func requiredBlob(name string, decodedSize int) logicalField {
	return logicalField{
		name:        name,
		kind:        logicalBase64URL,
		decodedSize: decodedSize,
	}
}

func optionalBlob(name string, decodedSize int) logicalField {
	field := requiredBlob(name, decodedSize)
	field.nullable = true
	return field
}

var coveredTableRegistry = [...]tableSpec{
	{
		name: "origin_scopes",
		primaryKey: []primaryKeyField{
			{name: "device_id", kind: primaryKeyString},
			{name: "scope_kind", kind: primaryKeyString},
			{name: "scope_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("device_id", logicalString),
			requiredField("scope_kind", logicalString),
			requiredField("scope_id", logicalString),
			requiredField("last_sequence", logicalInteger),
		},
	},
	{
		name:       "audit_counters",
		primaryKey: []primaryKeyField{{name: "device_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("device_id", logicalString),
			requiredField("credential_epoch", logicalInteger),
			requiredField("accepted_count", logicalInteger),
		},
	},
	{
		name:       "tasks",
		primaryKey: []primaryKeyField{{name: "task_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("task_id", logicalString),
			requiredField("title", logicalString),
			requiredField("body", logicalString),
			requiredField("state", logicalString),
			optionalField("state_reason", logicalString),
			requiredField("priority", logicalInteger),
			requiredField("blocked_by", logicalArray),
			requiredField("labels", logicalArray),
			optionalField("owner_device_id", logicalString),
			optionalField("owner_agent_session_id", logicalString),
			optionalField("intended_device_id", logicalString),
			optionalField("last_release_reason", logicalString),
			requiredField("entity_version", logicalInteger),
			requiredField("created_at", logicalString),
			requiredField("updated_at", logicalString),
		},
	},
	{
		name: "plan_revisions",
		primaryKey: []primaryKeyField{
			{name: "plan_revision_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("plan_revision_id", logicalString),
			optionalField("supersedes", logicalString),
			requiredField("title", logicalString),
			requiredField("body", logicalString),
			requiredField("task_ids", logicalArray),
			requiredField("proposed_by_device_id", logicalString),
			requiredField("created_at", logicalString),
		},
	},
	{
		name:       "plan_current",
		primaryKey: []primaryKeyField{{name: "session_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("session_id", logicalString),
			optionalField("plan_revision_id", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name: "memory_records",
		primaryKey: []primaryKeyField{
			{name: "memory_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("memory_id", logicalString),
			requiredField("scope", logicalString),
			optionalField("task_id", logicalString),
			requiredField("key", logicalString),
			requiredField("body", logicalString),
			optionalField("supersedes", logicalString),
			requiredField("created_at", logicalString),
		},
	},
	{
		name:       "leases",
		primaryKey: []primaryKeyField{{name: "lease_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("lease_id", logicalString),
			requiredField("holder_device_id", logicalString),
			requiredField("holder_agent_session_id", logicalString),
			requiredField("scope", logicalString),
			optionalField("task_id", logicalString),
			optionalField("path_globs", logicalArray),
			requiredField("ttl_seconds", logicalInteger),
			requiredField("status", logicalString),
			optionalField("release_reason", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name:       "devices",
		primaryKey: []primaryKeyField{{name: "device_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("device_id", logicalString),
			requiredField("role", logicalString),
			requiredBlob("identity_public_key", 32),
			requiredField("daemon_version", logicalString),
			requiredField("max_apply_level", logicalInteger),
			requiredField("status", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name:       "voter_set",
		primaryKey: []primaryKeyField{{name: "session_id", kind: primaryKeyString}},
		fields: []logicalField{
			requiredField("session_id", logicalString),
			requiredField("voter_device_ids", logicalArray),
			requiredField("voter_set_version", logicalInteger),
		},
	},
	{
		name: "credential_authority",
		primaryKey: []primaryKeyField{
			{name: "session_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("session_id", logicalString),
			requiredField("voter_device_ids", logicalArray),
			requiredField("voter_set_version", logicalInteger),
			requiredField("activation_source", logicalString),
			optionalField("activation_checkpoint_event_id", logicalString),
			requiredField("activation_proofs", logicalArray),
			optionalField("prior_authority_signer", logicalString),
			optionalBlob("prior_authority_handoff", 64),
		},
	},
	{
		name: "agent_sessions",
		primaryKey: []primaryKeyField{
			{name: "agent_session_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("agent_session_id", logicalString),
			requiredField("device_id", logicalString),
			requiredField("client_kind", logicalString),
			optionalField("agent_profile_id", logicalString),
			requiredField("state", logicalString),
			optionalField("resume_state", logicalString),
			requiredField("working_root_id", logicalString),
			optionalField("end_reason", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name: "canonical_refs",
		primaryKey: []primaryKeyField{
			{name: "ref_name", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("ref_name", logicalString),
			requiredField("commit_oid", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name: "credential_authorizations",
		primaryKey: []primaryKeyField{
			{name: "session_id", kind: primaryKeyString},
			{name: "device_id", kind: primaryKeyString},
			{name: "epoch", kind: primaryKeyPositiveInteger},
		},
		fields: []logicalField{
			requiredField("session_id", logicalString),
			requiredField("device_id", logicalString),
			requiredField("epoch", logicalInteger),
			requiredBlob("epoch_public_key", 32),
			requiredBlob("key_digest", 32),
			requiredField("role", logicalString),
			requiredField("issued_at", logicalString),
			requiredField("not_before", logicalString),
			requiredField("validity_seconds", logicalInteger),
			requiredField("authority_voter_set_version", logicalInteger),
			requiredField("clock_endorsements", logicalArray),
			requiredBlob("binding_signature", 64),
			requiredField("authorization_chain_index", logicalInteger),
		},
	},
	{
		name: "publications",
		primaryKey: []primaryKeyField{
			{name: "publication_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("publication_id", logicalString),
			requiredField("proposal_event_id", logicalString),
			optionalField("supersedes_publication_id", logicalString),
			optionalField("task_id", logicalString),
			requiredField("author_device_id", logicalString),
			requiredField("author_agent_session_id", logicalString),
			requiredField("base_commit", logicalString),
			requiredField("commit_oid", logicalString),
			requiredField("tree_oid", logicalString),
			requiredField("parent_oids", logicalArray),
			requiredField("paths", logicalArray),
			requiredBlob("artifact_digest", 32),
			requiredField("resolves_conflict_ids", logicalArray),
			requiredField("working_root_id", logicalString),
			requiredField("staging_receipts", logicalArray),
			requiredField("state", logicalString),
			optionalField("terminal_source", logicalString),
			requiredField("canonical_lineage_member", logicalBoolean),
			optionalField("review_verdict", logicalString),
			optionalField("reviewer_device_id", logicalString),
			optionalField("reviewer_agent_session_id", logicalString),
			optionalField("review_actor_type", logicalString),
			optionalField("decision_reason", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name: "control_file_proposals",
		primaryKey: []primaryKeyField{
			{name: "proposal_event_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("proposal_event_id", logicalString),
			requiredField("session_id", logicalString),
			requiredField("path", logicalString),
			requiredField("operation", logicalString),
			optionalBlob("content_digest", 32),
			requiredField("content_size", logicalInteger),
			requiredField("diff", logicalString),
			requiredField("proposed_by_device_id", logicalString),
			requiredField("chain_index", logicalInteger),
		},
	},
	{
		name: "merge_conflicts",
		primaryKey: []primaryKeyField{
			{name: "conflict_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("conflict_id", logicalString),
			requiredField("publication_id", logicalString),
			requiredField("merge_kind", logicalString),
			optionalField("replay_commit_oid", logicalString),
			requiredField("merge_base_oids", logicalArray),
			requiredField("canonical_commit", logicalString),
			requiredField("candidate_commit", logicalString),
			requiredField("paths", logicalArray),
			requiredField("status", logicalString),
			optionalField("resolution_kind", logicalString),
			optionalField("resolution_publication_id", logicalString),
			optionalField("force_reason", logicalString),
			optionalField("resolved_by_device_id", logicalString),
			requiredField("entity_version", logicalInteger),
		},
	},
	{
		name: "session_policy",
		primaryKey: []primaryKeyField{
			{name: "session_id", kind: primaryKeyString},
		},
		fields: []logicalField{
			requiredField("session_id", logicalString),
			requiredField("values", logicalObject),
			requiredField("entity_version", logicalInteger),
		},
	},
}

// CoveredTables returns the fixed V1 table registry in commitment order.
func CoveredTables() []string {
	tables := make([]string, len(coveredTableRegistry))
	for index := range coveredTableRegistry {
		tables[index] = coveredTableRegistry[index].name
	}
	return tables
}

func lookupTable(name string) (tableSpec, int, bool) {
	for index, spec := range coveredTableRegistry {
		if spec.name == name {
			return spec, index, true
		}
	}
	return tableSpec{}, 0, false
}
