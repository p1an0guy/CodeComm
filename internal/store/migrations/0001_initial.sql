-- CodeComm state schema, migration 0001.
-- The migration runner owns transactions, PRAGMAs, and schema_migrations rows.
-- Canonical JSON columns contain RFC 8785/JCS bytes encoded as SQLite TEXT;
-- SQL validates JSON shape while codecs enforce canonical encoding and schemas.

-- LOCAL METADATA: excluded from replication and projection digests.
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) >= 1),
    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at TEXT NOT NULL CHECK (
        length(applied_at) BETWEEN 20 AND 30
        AND substr(applied_at, 5, 1) = '-'
        AND substr(applied_at, 8, 1) = '-'
        AND substr(applied_at, 11, 1) = 'T'
        AND substr(applied_at, 14, 1) = ':'
        AND substr(applied_at, 17, 1) = ':'
        AND substr(applied_at, -1, 1) = 'Z'
        AND (
            length(applied_at) = 20
            OR (
                substr(applied_at, 20, 1) = '.'
                AND length(applied_at) BETWEEN 22 AND 30
                AND substr(applied_at, -2, 1) <> '0'
            )
        )
    )
) STRICT;

-- SIGNED, CHAIN-BACKED: replicated lineage boundary records; excluded from
-- the projection-state digest because their signatures/digests are verified.
CREATE TABLE genesis_records (
    recovery_generation INTEGER PRIMARY KEY
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    session_id TEXT NOT NULL UNIQUE CHECK (
        length(session_id) = 36
        AND substr(session_id, 9, 1) = '-'
        AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 19, 1) = '-'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36
        AND substr(workspace_id, 9, 1) = '-'
        AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 19, 1) = '-'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    genesis_kind TEXT NOT NULL CHECK (genesis_kind IN ('initial', 'successor')),
    genesis_json TEXT NOT NULL CHECK (json_valid(genesis_json) AND json_type(genesis_json) = 'object'),
    genesis_digest BLOB NOT NULL UNIQUE CHECK (length(genesis_digest) = 32),
    recovery_authorization_json TEXT CHECK (
        recovery_authorization_json IS NULL
        OR (json_valid(recovery_authorization_json) AND json_type(recovery_authorization_json) = 'object')
    ),
    predecessor_chain_index INTEGER CHECK (
        predecessor_chain_index IS NULL
        OR predecessor_chain_index BETWEEN 0 AND 9007199254740991
    ),
    predecessor_chain_hash BLOB CHECK (
        predecessor_chain_hash IS NULL OR length(predecessor_chain_hash) = 32
    ),
    predecessor_result_index INTEGER CHECK (
        predecessor_result_index IS NULL
        OR predecessor_result_index BETWEEN 0 AND 9007199254740991
    ),
    predecessor_result_hash BLOB CHECK (
        predecessor_result_hash IS NULL OR length(predecessor_result_hash) = 32
    ),
    predecessor_projection_accumulator BLOB CHECK (
        predecessor_projection_accumulator IS NULL
        OR length(predecessor_projection_accumulator) = 32
    ),
    boundary_transform_digest BLOB NOT NULL CHECK (length(boundary_transform_digest) = 32),
    CHECK (
        (recovery_generation = 0
         AND genesis_kind = 'initial'
         AND recovery_authorization_json IS NULL
         AND predecessor_chain_index IS NULL
         AND predecessor_chain_hash IS NULL
         AND predecessor_result_index IS NULL
         AND predecessor_result_hash IS NULL
         AND predecessor_projection_accumulator IS NULL)
        OR
        (recovery_generation > 0
         AND genesis_kind = 'successor'
         AND recovery_authorization_json IS NOT NULL
         AND predecessor_chain_index IS NOT NULL
         AND predecessor_chain_hash IS NOT NULL
         AND predecessor_result_index IS NOT NULL
         AND predecessor_result_hash IS NOT NULL
         AND predecessor_projection_accumulator IS NOT NULL)
    )
) STRICT;

CREATE INDEX genesis_records_workspace_generation
    ON genesis_records (workspace_id, recovery_generation);

-- LOCAL SUPPORT: singleton durable apply/head state. The Go runner queries
-- this table with WHERE singleton = 1.
CREATE TABLE consensus_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36
        AND substr(session_id, 9, 1) = '-'
        AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 19, 1) = '-'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    current_term INTEGER CHECK (current_term IS NULL OR current_term >= 0),
    last_raft_applied_log_index INTEGER
        CHECK (last_raft_applied_log_index IS NULL OR last_raft_applied_log_index >= 1),
    chain_index INTEGER NOT NULL CHECK (chain_index BETWEEN 0 AND 9007199254740991),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    result_index INTEGER NOT NULL CHECK (result_index BETWEEN 0 AND 9007199254740991),
    result_hash BLOB NOT NULL CHECK (length(result_hash) = 32),
    projection_accumulator BLOB NOT NULL CHECK (length(projection_accumulator) = 32),
    digest_version INTEGER NOT NULL CHECK (digest_version BETWEEN 1 AND 9007199254740991),
    projection_schema_version INTEGER NOT NULL
        CHECK (projection_schema_version BETWEEN 1 AND 9007199254740991),
    CHECK (chain_index <= result_index)
) STRICT;

-- SIGNED, CHAIN-BACKED: exact accepted origin-signed proposals.
CREATE TABLE events (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 36
        AND substr(event_id, 9, 1) = '-'
        AND substr(event_id, 14, 1) = '-'
        AND substr(event_id, 15, 1) = '7'
        AND substr(event_id, 19, 1) = '-'
        AND substr(event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(event_id, 24, 1) = '-'
        AND length(replace(event_id, '-', '')) = 32
        AND replace(event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 9007199254740991),
    min_apply_level INTEGER NOT NULL CHECK (min_apply_level BETWEEN 1 AND 2147483647),
    kind TEXT NOT NULL CHECK (kind IN (
        'task.created', 'task.updated', 'task.state_changed', 'task.claimed',
        'task.released', 'task.reassigned', 'task.cancelled',
        'workspace.conflict.detected', 'workspace.conflict.force_resolved',
        'workspace.conflict.resolved', 'publication.proposed',
        'publication.reviewed', 'publication.applied', 'publication.withdrawn',
        'plan.revision_proposed', 'plan.current_selected', 'memory.appended',
        'activity.recorded', 'lease.acquired', 'lease.renewed', 'lease.released',
        'agent.session.started', 'agent.session.state_changed', 'agent.session.ended',
        'membership.device_admitted', 'membership.version_reported',
        'membership.role_changed', 'membership.owner_recovered',
        'membership.device_revoked', 'membership.voter_set_changed',
        'membership.voter_set_activated', 'policy.changed',
        'credential.authorized', 'control_file.change_proposed',
        'consensus.checkpoint', 'audit.recorded'
    )),
    entity_id TEXT,
    origin_device_id TEXT NOT NULL CHECK (
        length(origin_device_id) = 67
        AND substr(origin_device_id, 1, 3) = 'cc1'
        AND substr(origin_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    origin_scope_kind TEXT NOT NULL CHECK (origin_scope_kind IN ('agent', 'boot')),
    origin_scope_id TEXT NOT NULL CHECK (
        length(origin_scope_id) = 36 AND substr(origin_scope_id, 15, 1) = '7'
        AND substr(origin_scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(origin_scope_id, 9, 1) = '-' AND substr(origin_scope_id, 14, 1) = '-'
        AND substr(origin_scope_id, 19, 1) = '-' AND substr(origin_scope_id, 24, 1) = '-'
        AND length(replace(origin_scope_id, '-', '')) = 32
        AND replace(origin_scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    origin_sequence INTEGER NOT NULL CHECK (origin_sequence BETWEEN 1 AND 9007199254740991),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('agent', 'human', 'daemon')),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 5, 1) = '-'
        AND substr(created_at, 8, 1) = '-'
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, 14, 1) = ':'
        AND substr(created_at, 17, 1) = ':'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    proposal_json TEXT NOT NULL CHECK (json_valid(proposal_json) AND json_type(proposal_json) = 'object'),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    origin_signature BLOB NOT NULL CHECK (length(origin_signature) = 64),
    UNIQUE (origin_device_id, origin_scope_kind, origin_scope_id, origin_sequence)
) STRICT;

CREATE INDEX events_session_kind_created
    ON events (session_id, kind, created_at, event_id);
CREATE INDEX events_entity
    ON events (kind, entity_id, event_id);

-- LOCAL EVIDENCE: unsigned Raft-FSM provenance; absent on imported results.
CREATE TABLE event_provenance (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE CHECK (
        length(event_id) = 36 AND substr(event_id, 15, 1) = '7'
        AND substr(event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(event_id, 9, 1) = '-' AND substr(event_id, 14, 1) = '-'
        AND substr(event_id, 19, 1) = '-' AND substr(event_id, 24, 1) = '-'
        AND length(replace(event_id, '-', '')) = 32
        AND replace(event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    term INTEGER NOT NULL CHECK (term >= 1),
    log_index INTEGER NOT NULL UNIQUE CHECK (log_index >= 1),
    applied_at TEXT NOT NULL CHECK (
        length(applied_at) BETWEEN 20 AND 30
        AND substr(applied_at, 11, 1) = 'T'
        AND substr(applied_at, -1, 1) = 'Z'
    ),
    chain_index INTEGER NOT NULL UNIQUE CHECK (chain_index BETWEEN 1 AND 9007199254740991),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32)
) STRICT;

-- SIGNED, CHAIN-BACKED: accepted checkpoint objects and authority signatures.
CREATE TABLE chain_checkpoints (
    checkpoint_event_id TEXT PRIMARY KEY REFERENCES events(event_id) CHECK (
        length(checkpoint_event_id) = 36 AND substr(checkpoint_event_id, 15, 1) = '7'
        AND substr(checkpoint_event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(checkpoint_event_id, 9, 1) = '-' AND substr(checkpoint_event_id, 14, 1) = '-'
        AND substr(checkpoint_event_id, 19, 1) = '-' AND substr(checkpoint_event_id, 24, 1) = '-'
        AND length(replace(checkpoint_event_id, '-', '')) = 32
        AND replace(checkpoint_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    authority_voter_set_version INTEGER NOT NULL
        CHECK (authority_voter_set_version BETWEEN 1 AND 9007199254740991),
    signer_device_id TEXT NOT NULL CHECK (
        length(signer_device_id) = 67 AND substr(signer_device_id, 1, 3) = 'cc1'
        AND substr(signer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    term INTEGER NOT NULL CHECK (term >= 1),
    covered_applied_log_index INTEGER NOT NULL CHECK (covered_applied_log_index >= 1),
    covered_chain_index INTEGER NOT NULL
        CHECK (covered_chain_index BETWEEN 0 AND 9007199254740991),
    covered_chain_hash BLOB NOT NULL CHECK (length(covered_chain_hash) = 32),
    covered_result_index INTEGER NOT NULL
        CHECK (covered_result_index BETWEEN 0 AND 9007199254740991),
    covered_result_hash BLOB NOT NULL CHECK (length(covered_result_hash) = 32),
    projection_accumulator BLOB NOT NULL CHECK (length(projection_accumulator) = 32),
    digest_version INTEGER NOT NULL CHECK (digest_version BETWEEN 1 AND 9007199254740991),
    projection_schema_version INTEGER NOT NULL
        CHECK (projection_schema_version BETWEEN 1 AND 9007199254740991),
    checkpoint_json TEXT NOT NULL
        CHECK (json_valid(checkpoint_json) AND json_type(checkpoint_json) = 'object'),
    authority_signature BLOB NOT NULL CHECK (length(authority_signature) = 64),
    CHECK (covered_chain_index <= covered_result_index),
    UNIQUE (session_id, recovery_generation, covered_result_index)
) STRICT;

CREATE INDEX chain_checkpoints_covered_chain
    ON chain_checkpoints (session_id, recovery_generation, covered_chain_index);

-- CHAIN-BACKED: immutable first-seen accepted/rejected outcomes.
CREATE TABLE command_results (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 36 AND substr(event_id, 15, 1) = '7'
        AND substr(event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(event_id, 9, 1) = '-' AND substr(event_id, 14, 1) = '-'
        AND substr(event_id, 19, 1) = '-' AND substr(event_id, 24, 1) = '-'
        AND length(replace(event_id, '-', '')) = 32
        AND replace(event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    schema_version INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL CHECK (length(CAST(kind AS BLOB)) BETWEEN 1 AND 64),
    origin_device_id TEXT NOT NULL CHECK (
        length(origin_device_id) = 67 AND substr(origin_device_id, 1, 3) = 'cc1'
        AND substr(origin_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    origin_scope_kind TEXT NOT NULL CHECK (origin_scope_kind IN ('agent', 'boot')),
    origin_scope_id TEXT NOT NULL CHECK (
        length(origin_scope_id) = 36 AND substr(origin_scope_id, 15, 1) = '7'
        AND substr(origin_scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(origin_scope_id, 9, 1) = '-' AND substr(origin_scope_id, 14, 1) = '-'
        AND substr(origin_scope_id, 19, 1) = '-' AND substr(origin_scope_id, 24, 1) = '-'
        AND length(replace(origin_scope_id, '-', '')) = 32
        AND replace(origin_scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    origin_sequence INTEGER NOT NULL CHECK (origin_sequence BETWEEN 1 AND 9007199254740991),
    proposal_json TEXT NOT NULL CHECK (json_valid(proposal_json) AND json_type(proposal_json) = 'object'),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    outcome_status TEXT NOT NULL CHECK (outcome_status IN ('accepted', 'rejected')),
    outcome_code TEXT NOT NULL CHECK (
        length(CAST(outcome_code AS BLOB)) BETWEEN 1 AND 64
        AND outcome_code NOT GLOB '*[^a-z0-9_]*'
    ),
    outcome_json TEXT NOT NULL CHECK (json_valid(outcome_json) AND json_type(outcome_json) = 'object'),
    projection_mutations_json TEXT NOT NULL CHECK (
        length(CAST(projection_mutations_json AS BLOB)) BETWEEN 2 AND 33554432
        AND json_valid(projection_mutations_json)
        AND json_type(projection_mutations_json) = 'array'
    ),
    chain_index INTEGER CHECK (chain_index IS NULL OR chain_index BETWEEN 1 AND 9007199254740991),
    chain_hash BLOB CHECK (chain_hash IS NULL OR length(chain_hash) = 32),
    result_index INTEGER NOT NULL UNIQUE CHECK (result_index BETWEEN 1 AND 9007199254740991),
    previous_result_hash BLOB NOT NULL CHECK (length(previous_result_hash) = 32),
    result_hash BLOB NOT NULL UNIQUE CHECK (length(result_hash) = 32),
    CHECK (
        (outcome_status = 'accepted' AND chain_index IS NOT NULL AND chain_hash IS NOT NULL)
        OR
        (outcome_status = 'rejected' AND chain_index IS NULL AND chain_hash IS NULL)
    ),
    UNIQUE (chain_index)
) STRICT;

CREATE INDEX command_results_session_result
    ON command_results (session_id, recovery_generation, result_index);
CREATE INDEX command_results_kind_outcome
    ON command_results (kind, outcome_status, outcome_code, result_index);

-- LOCAL SUPPORT: exact Raft command positions applied to SQLite. This includes
-- duplicate and rejected commands and is excluded from replicated projection
-- commitments.
CREATE TABLE raft_command_applications (
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    log_index INTEGER NOT NULL CHECK (log_index >= 1),
    term INTEGER NOT NULL CHECK (term >= 1),
    event_id TEXT NOT NULL REFERENCES command_results(event_id),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    PRIMARY KEY (recovery_generation, log_index)
) STRICT, WITHOUT ROWID;

CREATE INDEX raft_command_applications_event
    ON raft_command_applications (event_id, recovery_generation, log_index);

-- LOCAL EVIDENCE: verified signed batch/snapshot attestations.
CREATE TABLE replication_attestations (
    attestation_id TEXT PRIMARY KEY CHECK (length(CAST(attestation_id AS BLOB)) BETWEEN 1 AND 128),
    attestation_kind TEXT NOT NULL CHECK (attestation_kind IN ('batch', 'snapshot')),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    signer_device_id TEXT NOT NULL CHECK (
        length(signer_device_id) = 67 AND substr(signer_device_id, 1, 3) = 'cc1'
        AND substr(signer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    authority_voter_set_version INTEGER NOT NULL
        CHECK (authority_voter_set_version BETWEEN 1 AND 9007199254740991),
    from_result_index INTEGER NOT NULL
        CHECK (from_result_index BETWEEN 0 AND 9007199254740991),
    to_result_index INTEGER NOT NULL
        CHECK (to_result_index BETWEEN from_result_index AND 9007199254740991),
    start_result_hash BLOB NOT NULL CHECK (length(start_result_hash) = 32),
    end_result_hash BLOB NOT NULL CHECK (length(end_result_hash) = 32),
    start_chain_index INTEGER NOT NULL
        CHECK (start_chain_index BETWEEN 0 AND 9007199254740991),
    end_chain_index INTEGER NOT NULL
        CHECK (end_chain_index BETWEEN start_chain_index AND 9007199254740991),
    start_chain_hash BLOB NOT NULL CHECK (length(start_chain_hash) = 32),
    end_chain_hash BLOB NOT NULL CHECK (length(end_chain_hash) = 32),
    checkpoint_event_id TEXT CHECK (
        checkpoint_event_id IS NULL
        OR (
            length(checkpoint_event_id) = 36 AND substr(checkpoint_event_id, 15, 1) = '7'
            AND substr(checkpoint_event_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(checkpoint_event_id, 9, 1) = '-'
            AND substr(checkpoint_event_id, 14, 1) = '-'
            AND substr(checkpoint_event_id, 19, 1) = '-'
            AND substr(checkpoint_event_id, 24, 1) = '-'
            AND length(replace(checkpoint_event_id, '-', '')) = 32
            AND replace(checkpoint_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    envelope_json TEXT NOT NULL CHECK (json_valid(envelope_json) AND json_type(envelope_json) = 'object'),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    verified_at TEXT NOT NULL CHECK (
        length(verified_at) BETWEEN 20 AND 30
        AND substr(verified_at, 11, 1) = 'T'
        AND substr(verified_at, -1, 1) = 'Z'
    )
) STRICT;

CREATE INDEX replication_attestations_coverage
    ON replication_attestations (session_id, recovery_generation, from_result_index, to_result_index);

-- REPLICATED, DIGEST-COVERED TABLE 1: strict per-origin ordering.
CREATE TABLE origin_scopes (
    device_id TEXT NOT NULL CHECK (
        length(device_id) = 67
        AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('agent', 'boot')),
    scope_id TEXT NOT NULL CHECK (
        length(scope_id) = 36
        AND substr(scope_id, 9, 1) = '-'
        AND substr(scope_id, 14, 1) = '-'
        AND substr(scope_id, 15, 1) = '7'
        AND substr(scope_id, 19, 1) = '-'
        AND substr(scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(scope_id, 24, 1) = '-'
        AND length(replace(scope_id, '-', '')) = 32
        AND replace(scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    last_sequence INTEGER NOT NULL CHECK (last_sequence BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (device_id, scope_kind, scope_id)
) STRICT, WITHOUT ROWID;

-- REPLICATED, DIGEST-COVERED TABLE 2: rejection-audit depth state.
CREATE TABLE audit_counters (
    device_id TEXT PRIMARY KEY CHECK (
        length(device_id) = 67
        AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    credential_epoch INTEGER NOT NULL
        CHECK (credential_epoch BETWEEN 0 AND 9007199254740991),
    accepted_count INTEGER NOT NULL CHECK (accepted_count BETWEEN 0 AND 1024)
) STRICT;

-- REPLICATED, DIGEST-COVERED TABLE 3.
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY CHECK (
        length(task_id) = 36
        AND substr(task_id, 9, 1) = '-'
        AND substr(task_id, 14, 1) = '-'
        AND substr(task_id, 15, 1) = '7'
        AND substr(task_id, 19, 1) = '-'
        AND substr(task_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(task_id, 24, 1) = '-'
        AND length(replace(task_id, '-', '')) = 32
        AND replace(task_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    title TEXT NOT NULL CHECK (length(CAST(title AS BLOB)) BETWEEN 1 AND 200),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) <= 8192),
    state TEXT NOT NULL CHECK (
        state IN ('backlog', 'ready', 'claimed', 'in_progress', 'blocked', 'done', 'cancelled')
    ),
    state_reason TEXT CHECK (
        (state = 'blocked' AND state_reason IS NOT NULL
         AND length(CAST(state_reason AS BLOB)) BETWEEN 1 AND 1024)
        OR
        (state <> 'blocked' AND state_reason IS NULL)
    ),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 3),
    blocked_by_json TEXT NOT NULL CHECK (
        json_valid(blocked_by_json)
        AND json_type(blocked_by_json) = 'array'
        AND json_array_length(blocked_by_json) <= 16
    ),
    labels_json TEXT NOT NULL CHECK (
        json_valid(labels_json)
        AND json_type(labels_json) = 'array'
        AND json_array_length(labels_json) <= 16
    ),
    owner_device_id TEXT CHECK (
        owner_device_id IS NULL
        OR (
            length(owner_device_id) = 67 AND substr(owner_device_id, 1, 3) = 'cc1'
            AND substr(owner_device_id, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    owner_agent_session_id TEXT CHECK (
        owner_agent_session_id IS NULL
        OR (
            length(owner_agent_session_id) = 36 AND substr(owner_agent_session_id, 15, 1) = '7'
            AND substr(owner_agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(owner_agent_session_id, 9, 1) = '-'
            AND substr(owner_agent_session_id, 14, 1) = '-'
            AND substr(owner_agent_session_id, 19, 1) = '-'
            AND substr(owner_agent_session_id, 24, 1) = '-'
            AND length(replace(owner_agent_session_id, '-', '')) = 32
            AND replace(owner_agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    intended_device_id TEXT CHECK (
        intended_device_id IS NULL
        OR (
            length(intended_device_id) = 67 AND substr(intended_device_id, 1, 3) = 'cc1'
            AND substr(intended_device_id, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    last_release_reason TEXT CHECK (
        last_release_reason IS NULL
        OR last_release_reason IN ('voluntary', 'forced', 'session_ended', 'recovery')
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    updated_at TEXT NOT NULL CHECK (
        length(updated_at) BETWEEN 20 AND 30
        AND substr(updated_at, 11, 1) = 'T'
        AND substr(updated_at, -1, 1) = 'Z'
    ),
    CHECK ((owner_device_id IS NULL) = (owner_agent_session_id IS NULL)),
    CHECK (
        (state IN ('claimed', 'in_progress', 'blocked') AND owner_device_id IS NOT NULL)
        OR
        (state NOT IN ('claimed', 'in_progress', 'blocked') AND owner_device_id IS NULL)
    ),
    CHECK (owner_device_id IS NULL OR intended_device_id IS NULL),
    CHECK (state NOT IN ('done', 'cancelled') OR intended_device_id IS NULL),
    CHECK (owner_device_id IS NULL OR last_release_reason IS NULL)
) STRICT;

CREATE INDEX tasks_state_priority_updated
    ON tasks (state, priority, updated_at, task_id);
CREATE INDEX tasks_owner_session
    ON tasks (owner_device_id, owner_agent_session_id, state);
CREATE INDEX tasks_intended_device
    ON tasks (intended_device_id, state);

-- REPLICATED, DIGEST-COVERED TABLE 4.
CREATE TABLE plan_revisions (
    plan_revision_id TEXT PRIMARY KEY CHECK (
        length(plan_revision_id) = 36 AND substr(plan_revision_id, 15, 1) = '7'
        AND substr(plan_revision_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(plan_revision_id, 9, 1) = '-' AND substr(plan_revision_id, 14, 1) = '-'
        AND substr(plan_revision_id, 19, 1) = '-' AND substr(plan_revision_id, 24, 1) = '-'
        AND length(replace(plan_revision_id, '-', '')) = 32
        AND replace(plan_revision_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    supersedes TEXT CHECK (
        supersedes IS NULL
        OR (
            length(supersedes) = 36 AND substr(supersedes, 15, 1) = '7'
            AND substr(supersedes, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(supersedes, 9, 1) = '-' AND substr(supersedes, 14, 1) = '-'
            AND substr(supersedes, 19, 1) = '-' AND substr(supersedes, 24, 1) = '-'
            AND length(replace(supersedes, '-', '')) = 32
            AND replace(supersedes, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    title TEXT NOT NULL CHECK (length(CAST(title AS BLOB)) BETWEEN 1 AND 200),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) <= 65536),
    task_ids_json TEXT NOT NULL CHECK (
        json_valid(task_ids_json)
        AND json_type(task_ids_json) = 'array'
        AND json_array_length(task_ids_json) <= 512
    ),
    proposed_by_device_id TEXT NOT NULL CHECK (
        length(proposed_by_device_id) = 67 AND substr(proposed_by_device_id, 1, 3) = 'cc1'
        AND substr(proposed_by_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    CHECK (supersedes IS NULL OR supersedes <> plan_revision_id)
) STRICT;

CREATE INDEX plan_revisions_created
    ON plan_revisions (created_at, plan_revision_id);
CREATE INDEX plan_revisions_supersedes
    ON plan_revisions (supersedes);

-- REPLICATED, DIGEST-COVERED TABLE 5.
CREATE TABLE plan_current (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    plan_revision_id TEXT REFERENCES plan_revisions(plan_revision_id) CHECK (
        plan_revision_id IS NULL
        OR (
            length(plan_revision_id) = 36 AND substr(plan_revision_id, 15, 1) = '7'
            AND substr(plan_revision_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(plan_revision_id, 9, 1) = '-' AND substr(plan_revision_id, 14, 1) = '-'
            AND substr(plan_revision_id, 19, 1) = '-' AND substr(plan_revision_id, 24, 1) = '-'
            AND length(replace(plan_revision_id, '-', '')) = 32
            AND replace(plan_revision_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    CHECK (plan_revision_id IS NOT NULL OR entity_version = 1)
) STRICT;

CREATE INDEX plan_current_revision
    ON plan_current (plan_revision_id);

-- REPLICATED, DIGEST-COVERED TABLE 6.
CREATE TABLE memory_records (
    memory_id TEXT PRIMARY KEY CHECK (
        length(memory_id) = 36 AND substr(memory_id, 15, 1) = '7'
        AND substr(memory_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(memory_id, 9, 1) = '-' AND substr(memory_id, 14, 1) = '-'
        AND substr(memory_id, 19, 1) = '-' AND substr(memory_id, 24, 1) = '-'
        AND length(replace(memory_id, '-', '')) = 32
        AND replace(memory_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    scope TEXT NOT NULL CHECK (scope IN ('session', 'task')),
    task_id TEXT CHECK (
        task_id IS NULL
        OR (
            length(task_id) = 36 AND substr(task_id, 15, 1) = '7'
            AND substr(task_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(task_id, 9, 1) = '-' AND substr(task_id, 14, 1) = '-'
            AND substr(task_id, 19, 1) = '-' AND substr(task_id, 24, 1) = '-'
            AND length(replace(task_id, '-', '')) = 32
            AND replace(task_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    key TEXT NOT NULL CHECK (length(CAST(key AS BLOB)) BETWEEN 1 AND 128),
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) <= 16384),
    supersedes TEXT UNIQUE CHECK (
        supersedes IS NULL
        OR (
            length(supersedes) = 36 AND substr(supersedes, 15, 1) = '7'
            AND substr(supersedes, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(supersedes, 9, 1) = '-' AND substr(supersedes, 14, 1) = '-'
            AND substr(supersedes, 19, 1) = '-' AND substr(supersedes, 24, 1) = '-'
            AND length(replace(supersedes, '-', '')) = 32
            AND replace(supersedes, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    CHECK (
        (scope = 'session' AND task_id IS NULL)
        OR (scope = 'task' AND task_id IS NOT NULL)
    ),
    CHECK (supersedes IS NULL OR supersedes <> memory_id)
) STRICT;

CREATE INDEX memory_records_scope_key_created
    ON memory_records (scope, task_id, key, created_at, memory_id);

-- REPLICATED, DIGEST-COVERED TABLE 7.
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY CHECK (
        length(lease_id) = 36 AND substr(lease_id, 15, 1) = '7'
        AND substr(lease_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(lease_id, 9, 1) = '-' AND substr(lease_id, 14, 1) = '-'
        AND substr(lease_id, 19, 1) = '-' AND substr(lease_id, 24, 1) = '-'
        AND length(replace(lease_id, '-', '')) = 32
        AND replace(lease_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    holder_device_id TEXT NOT NULL CHECK (
        length(holder_device_id) = 67 AND substr(holder_device_id, 1, 3) = 'cc1'
        AND substr(holder_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    holder_agent_session_id TEXT NOT NULL CHECK (
        length(holder_agent_session_id) = 36 AND substr(holder_agent_session_id, 15, 1) = '7'
        AND substr(holder_agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(holder_agent_session_id, 9, 1) = '-'
        AND substr(holder_agent_session_id, 14, 1) = '-'
        AND substr(holder_agent_session_id, 19, 1) = '-'
        AND substr(holder_agent_session_id, 24, 1) = '-'
        AND length(replace(holder_agent_session_id, '-', '')) = 32
        AND replace(holder_agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    scope TEXT NOT NULL CHECK (scope IN ('task', 'path')),
    task_id TEXT CHECK (
        task_id IS NULL
        OR (
            length(task_id) = 36 AND substr(task_id, 15, 1) = '7'
            AND substr(task_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(task_id, 9, 1) = '-' AND substr(task_id, 14, 1) = '-'
            AND substr(task_id, 19, 1) = '-' AND substr(task_id, 24, 1) = '-'
            AND length(replace(task_id, '-', '')) = 32
            AND replace(task_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    path_globs_json TEXT,
    ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds BETWEEN 30 AND 86400),
    status TEXT NOT NULL CHECK (status IN ('active', 'released')),
    release_reason TEXT CHECK (
        release_reason IS NULL
        OR release_reason IN ('voluntary', 'forced', 'expired', 'session_ended', 'recovery')
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    CHECK (
        (scope = 'task' AND task_id IS NOT NULL AND path_globs_json IS NULL)
        OR
        (scope = 'path'
         AND path_globs_json IS NOT NULL
         AND json_valid(path_globs_json)
         AND json_type(path_globs_json) = 'array'
         AND json_array_length(path_globs_json) BETWEEN 1 AND 32)
    ),
    CHECK (
        (status = 'active' AND release_reason IS NULL)
        OR (status = 'released' AND release_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX leases_holder_status
    ON leases (holder_device_id, holder_agent_session_id, status);
CREATE INDEX leases_task_status
    ON leases (task_id, status);
CREATE INDEX leases_scope_status
    ON leases (scope, status);

-- REPLICATED, DIGEST-COVERED TABLE 8.
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY CHECK (
        length(device_id) = 67
        AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    role TEXT NOT NULL CHECK (role IN ('owner', 'editor')),
    identity_public_key BLOB NOT NULL CHECK (length(identity_public_key) = 32),
    daemon_version TEXT NOT NULL CHECK (
        length(CAST(daemon_version AS BLOB)) BETWEEN 1 AND 64
        AND daemon_version NOT GLOB '*[^ -~]*'
    ),
    max_apply_level INTEGER NOT NULL CHECK (max_apply_level BETWEEN 1 AND 2147483647),
    status TEXT NOT NULL CHECK (status IN ('active', 'requires_readmission', 'revoked')),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE INDEX devices_status_role
    ON devices (status, role, device_id);

-- REPLICATED, DIGEST-COVERED TABLE 9.
CREATE TABLE voter_set (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    voter_device_ids_json TEXT NOT NULL CHECK (
        json_valid(voter_device_ids_json)
        AND json_type(voter_device_ids_json) = 'array'
        AND json_array_length(voter_device_ids_json) IN (1, 3, 5)
    ),
    voter_set_version INTEGER NOT NULL
        CHECK (voter_set_version BETWEEN 1 AND 9007199254740991)
) STRICT;

-- REPLICATED, DIGEST-COVERED TABLE 10.
CREATE TABLE credential_authority (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    voter_device_ids_json TEXT NOT NULL CHECK (
        json_valid(voter_device_ids_json)
        AND json_type(voter_device_ids_json) = 'array'
        AND json_array_length(voter_device_ids_json) IN (1, 3, 5)
    ),
    voter_set_version INTEGER NOT NULL
        CHECK (voter_set_version BETWEEN 1 AND 9007199254740991),
    activation_source TEXT NOT NULL CHECK (activation_source IN ('genesis', 'handoff')),
    activation_checkpoint_event_id TEXT CHECK (
        activation_checkpoint_event_id IS NULL
        OR (
            length(activation_checkpoint_event_id) = 36
            AND substr(activation_checkpoint_event_id, 15, 1) = '7'
            AND substr(activation_checkpoint_event_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(activation_checkpoint_event_id, 9, 1) = '-'
            AND substr(activation_checkpoint_event_id, 14, 1) = '-'
            AND substr(activation_checkpoint_event_id, 19, 1) = '-'
            AND substr(activation_checkpoint_event_id, 24, 1) = '-'
            AND length(replace(activation_checkpoint_event_id, '-', '')) = 32
            AND replace(activation_checkpoint_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    activation_proofs_json TEXT NOT NULL CHECK (
        json_valid(activation_proofs_json)
        AND json_type(activation_proofs_json) = 'array'
        AND json_array_length(activation_proofs_json) <= 5
    ),
    prior_authority_signer TEXT CHECK (
        prior_authority_signer IS NULL
        OR (
            length(prior_authority_signer) = 67
            AND substr(prior_authority_signer, 1, 3) = 'cc1'
            AND substr(prior_authority_signer, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    prior_authority_handoff BLOB CHECK (
        prior_authority_handoff IS NULL OR length(prior_authority_handoff) = 64
    ),
    CHECK (
        (activation_source = 'genesis'
         AND voter_set_version = 1
         AND activation_checkpoint_event_id IS NULL
         AND json_array_length(activation_proofs_json) = 0
         AND prior_authority_signer IS NULL
         AND prior_authority_handoff IS NULL)
        OR
        (activation_source = 'handoff'
         AND voter_set_version > 1
         AND activation_checkpoint_event_id IS NOT NULL
         AND json_array_length(activation_proofs_json) BETWEEN 1 AND 5
         AND prior_authority_signer IS NOT NULL
         AND prior_authority_handoff IS NOT NULL)
    )
) STRICT;

-- REPLICATED, DIGEST-COVERED TABLE 11.
CREATE TABLE agent_sessions (
    agent_session_id TEXT PRIMARY KEY CHECK (
        length(agent_session_id) = 36 AND substr(agent_session_id, 15, 1) = '7'
        AND substr(agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(agent_session_id, 9, 1) = '-' AND substr(agent_session_id, 14, 1) = '-'
        AND substr(agent_session_id, 19, 1) = '-' AND substr(agent_session_id, 24, 1) = '-'
        AND length(replace(agent_session_id, '-', '')) = 32
        AND replace(agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    device_id TEXT NOT NULL CHECK (
        length(device_id) = 67 AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    client_kind TEXT NOT NULL CHECK (client_kind IN ('codex', 'claude', 'other')),
    agent_profile_id TEXT CHECK (
        agent_profile_id IS NULL
        OR length(CAST(agent_profile_id AS BLOB)) BETWEEN 1 AND 128
    ),
    state TEXT NOT NULL CHECK (
        state IN ('starting', 'idle', 'claimed', 'working', 'blocked', 'disconnected', 'ended')
    ),
    resume_state TEXT CHECK (
        resume_state IS NULL
        OR resume_state IN ('starting', 'idle', 'claimed', 'working', 'blocked')
    ),
    working_root_id TEXT NOT NULL CHECK (
        length(working_root_id) = 36 AND substr(working_root_id, 15, 1) = '7'
        AND substr(working_root_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(working_root_id, 9, 1) = '-' AND substr(working_root_id, 14, 1) = '-'
        AND substr(working_root_id, 19, 1) = '-' AND substr(working_root_id, 24, 1) = '-'
        AND length(replace(working_root_id, '-', '')) = 32
        AND replace(working_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    end_reason TEXT CHECK (
        end_reason IS NULL
        OR end_reason IN ('clean', 'disconnect_timeout', 'operator', 'crash_reap', 'recovery')
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    CHECK (
        (state = 'disconnected' AND resume_state IS NOT NULL)
        OR (state <> 'disconnected' AND resume_state IS NULL)
    ),
    CHECK (
        (state = 'ended' AND end_reason IS NOT NULL)
        OR (state <> 'ended' AND end_reason IS NULL)
    )
) STRICT;

CREATE INDEX agent_sessions_device_state
    ON agent_sessions (device_id, state, agent_session_id);
CREATE INDEX agent_sessions_working_root
    ON agent_sessions (working_root_id, state);

-- REPLICATED, DIGEST-COVERED TABLE 12.
CREATE TABLE canonical_refs (
    ref_name TEXT PRIMARY KEY CHECK (ref_name = 'refs/codecomm/canonical'),
    commit_oid TEXT NOT NULL CHECK (
        (length(commit_oid) = 45
         AND substr(commit_oid, 1, 5) = 'sha1:'
         AND substr(commit_oid, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(commit_oid) = 71
         AND substr(commit_oid, 1, 7) = 'sha256:'
         AND substr(commit_oid, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991)
) STRICT;

-- REPLICATED, DIGEST-COVERED TABLE 13.
CREATE TABLE credential_authorizations (
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    device_id TEXT NOT NULL CHECK (
        length(device_id) = 67 AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    epoch_public_key BLOB NOT NULL CHECK (length(epoch_public_key) = 32),
    key_digest BLOB NOT NULL CHECK (length(key_digest) = 32),
    role TEXT NOT NULL CHECK (role IN ('owner', 'editor')),
    issued_at TEXT NOT NULL CHECK (
        length(issued_at) = 20
        AND substr(issued_at, 11, 1) = 'T'
        AND substr(issued_at, -1, 1) = 'Z'
    ),
    not_before TEXT NOT NULL CHECK (
        length(not_before) = 20
        AND substr(not_before, 11, 1) = 'T'
        AND substr(not_before, -1, 1) = 'Z'
    ),
    validity_seconds INTEGER NOT NULL CHECK (validity_seconds >= 1),
    authority_voter_set_version INTEGER NOT NULL
        CHECK (authority_voter_set_version BETWEEN 1 AND 9007199254740991),
    clock_endorsements_json TEXT NOT NULL CHECK (
        json_valid(clock_endorsements_json)
        AND json_type(clock_endorsements_json) = 'array'
        AND json_array_length(clock_endorsements_json) BETWEEN 1 AND 5
    ),
    binding_signature BLOB NOT NULL CHECK (length(binding_signature) = 64),
    authorization_chain_index INTEGER NOT NULL
        CHECK (authorization_chain_index BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (session_id, device_id, epoch)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX credential_authorizations_chain_index
    ON credential_authorizations (authorization_chain_index);
CREATE INDEX credential_authorizations_device_epoch
    ON credential_authorizations (device_id, epoch DESC);

-- REPLICATED, DIGEST-COVERED TABLE 14.
CREATE TABLE publications (
    publication_id TEXT PRIMARY KEY CHECK (
        length(publication_id) = 36 AND substr(publication_id, 15, 1) = '7'
        AND substr(publication_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(publication_id, 9, 1) = '-' AND substr(publication_id, 14, 1) = '-'
        AND substr(publication_id, 19, 1) = '-' AND substr(publication_id, 24, 1) = '-'
        AND length(replace(publication_id, '-', '')) = 32
        AND replace(publication_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    proposal_event_id TEXT NOT NULL UNIQUE CHECK (
        length(proposal_event_id) = 36 AND substr(proposal_event_id, 15, 1) = '7'
        AND substr(proposal_event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(proposal_event_id, 9, 1) = '-' AND substr(proposal_event_id, 14, 1) = '-'
        AND substr(proposal_event_id, 19, 1) = '-' AND substr(proposal_event_id, 24, 1) = '-'
        AND length(replace(proposal_event_id, '-', '')) = 32
        AND replace(proposal_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    supersedes_publication_id TEXT CHECK (
        supersedes_publication_id IS NULL
        OR (
            length(supersedes_publication_id) = 36
            AND substr(supersedes_publication_id, 15, 1) = '7'
            AND substr(supersedes_publication_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(supersedes_publication_id, 9, 1) = '-'
            AND substr(supersedes_publication_id, 14, 1) = '-'
            AND substr(supersedes_publication_id, 19, 1) = '-'
            AND substr(supersedes_publication_id, 24, 1) = '-'
            AND length(replace(supersedes_publication_id, '-', '')) = 32
            AND replace(supersedes_publication_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    task_id TEXT CHECK (
        task_id IS NULL
        OR (
            length(task_id) = 36 AND substr(task_id, 15, 1) = '7'
            AND substr(task_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(task_id, 9, 1) = '-' AND substr(task_id, 14, 1) = '-'
            AND substr(task_id, 19, 1) = '-' AND substr(task_id, 24, 1) = '-'
            AND length(replace(task_id, '-', '')) = 32
            AND replace(task_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    author_device_id TEXT NOT NULL CHECK (
        length(author_device_id) = 67 AND substr(author_device_id, 1, 3) = 'cc1'
        AND substr(author_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    author_agent_session_id TEXT NOT NULL CHECK (
        length(author_agent_session_id) = 36 AND substr(author_agent_session_id, 15, 1) = '7'
        AND substr(author_agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(author_agent_session_id, 9, 1) = '-'
        AND substr(author_agent_session_id, 14, 1) = '-'
        AND substr(author_agent_session_id, 19, 1) = '-'
        AND substr(author_agent_session_id, 24, 1) = '-'
        AND length(replace(author_agent_session_id, '-', '')) = 32
        AND replace(author_agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    base_commit TEXT NOT NULL CHECK (
        (length(base_commit) = 45 AND substr(base_commit, 1, 5) = 'sha1:'
         AND substr(base_commit, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(base_commit) = 71 AND substr(base_commit, 1, 7) = 'sha256:'
         AND substr(base_commit, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    commit_oid TEXT NOT NULL CHECK (
        (length(commit_oid) = 45 AND substr(commit_oid, 1, 5) = 'sha1:'
         AND substr(commit_oid, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(commit_oid) = 71 AND substr(commit_oid, 1, 7) = 'sha256:'
         AND substr(commit_oid, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    tree_oid TEXT NOT NULL CHECK (
        (length(tree_oid) = 45 AND substr(tree_oid, 1, 5) = 'sha1:'
         AND substr(tree_oid, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(tree_oid) = 71 AND substr(tree_oid, 1, 7) = 'sha256:'
         AND substr(tree_oid, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    parent_oids_json TEXT NOT NULL CHECK (
        json_valid(parent_oids_json)
        AND json_type(parent_oids_json) = 'array'
        AND json_array_length(parent_oids_json) BETWEEN 1 AND 16
    ),
    paths_json TEXT NOT NULL CHECK (
        json_valid(paths_json)
        AND json_type(paths_json) = 'array'
        AND json_array_length(paths_json) BETWEEN 1 AND 2048
    ),
    artifact_digest BLOB NOT NULL CHECK (length(artifact_digest) = 32),
    resolves_conflict_ids_json TEXT NOT NULL CHECK (
        json_valid(resolves_conflict_ids_json)
        AND json_type(resolves_conflict_ids_json) = 'array'
        AND json_array_length(resolves_conflict_ids_json) <= 64
    ),
    working_root_id TEXT NOT NULL CHECK (
        length(working_root_id) = 36 AND substr(working_root_id, 15, 1) = '7'
        AND substr(working_root_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(working_root_id, 9, 1) = '-' AND substr(working_root_id, 14, 1) = '-'
        AND substr(working_root_id, 19, 1) = '-' AND substr(working_root_id, 24, 1) = '-'
        AND length(replace(working_root_id, '-', '')) = 32
        AND replace(working_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    staging_receipts_json TEXT NOT NULL CHECK (
        json_valid(staging_receipts_json)
        AND json_type(staging_receipts_json) = 'array'
        AND json_array_length(staging_receipts_json) BETWEEN 1 AND 5
    ),
    state TEXT NOT NULL CHECK (state IN ('proposed', 'approved', 'applied', 'rejected', 'withdrawn')),
    terminal_source TEXT CHECK (
        terminal_source IS NULL OR terminal_source IN ('review', 'apply', 'withdraw', 'recovery')
    ),
    canonical_lineage_member INTEGER NOT NULL CHECK (canonical_lineage_member IN (0, 1)),
    review_verdict TEXT CHECK (review_verdict IS NULL OR review_verdict IN ('approve', 'reject')),
    reviewer_device_id TEXT CHECK (
        reviewer_device_id IS NULL
        OR (
            length(reviewer_device_id) = 67 AND substr(reviewer_device_id, 1, 3) = 'cc1'
            AND substr(reviewer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    reviewer_agent_session_id TEXT CHECK (
        reviewer_agent_session_id IS NULL
        OR (
            length(reviewer_agent_session_id) = 36
            AND substr(reviewer_agent_session_id, 15, 1) = '7'
            AND substr(reviewer_agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(reviewer_agent_session_id, 9, 1) = '-'
            AND substr(reviewer_agent_session_id, 14, 1) = '-'
            AND substr(reviewer_agent_session_id, 19, 1) = '-'
            AND substr(reviewer_agent_session_id, 24, 1) = '-'
            AND length(replace(reviewer_agent_session_id, '-', '')) = 32
            AND replace(reviewer_agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    review_actor_type TEXT CHECK (
        review_actor_type IS NULL OR review_actor_type IN ('agent', 'human')
    ),
    decision_reason TEXT CHECK (
        decision_reason IS NULL OR length(CAST(decision_reason AS BLOB)) BETWEEN 1 AND 1024
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    CHECK (supersedes_publication_id IS NULL OR supersedes_publication_id <> publication_id),
    CHECK (
        (substr(base_commit, 1, 5) = 'sha1:'
         AND substr(commit_oid, 1, 5) = 'sha1:'
         AND substr(tree_oid, 1, 5) = 'sha1:')
        OR
        (substr(base_commit, 1, 7) = 'sha256:'
         AND substr(commit_oid, 1, 7) = 'sha256:'
         AND substr(tree_oid, 1, 7) = 'sha256:')
    ),
    CHECK (
        (review_verdict IS NULL
         AND reviewer_device_id IS NULL
         AND reviewer_agent_session_id IS NULL
         AND review_actor_type IS NULL)
        OR
        (review_verdict IS NOT NULL
         AND reviewer_device_id IS NOT NULL
         AND review_actor_type = 'human'
         AND reviewer_agent_session_id IS NULL)
        OR
        (review_verdict IS NOT NULL
         AND reviewer_device_id IS NOT NULL
         AND review_actor_type = 'agent'
         AND reviewer_agent_session_id IS NOT NULL)
    ),
    CHECK (
        (state IN ('proposed', 'approved') AND terminal_source IS NULL)
        OR
        (state = 'applied' AND terminal_source = 'apply')
        OR
        (state = 'rejected' AND terminal_source = 'review')
        OR
        (state = 'withdrawn' AND terminal_source IN ('withdraw', 'recovery'))
    ),
    CHECK (canonical_lineage_member = 0 OR state = 'applied'),
    CHECK (
        (state = 'proposed'
         AND review_verdict IS NULL
         AND decision_reason IS NULL)
        OR
        (state IN ('approved', 'applied')
         AND review_verdict = 'approve'
         AND decision_reason IS NULL)
        OR
        (state = 'rejected'
         AND review_verdict = 'reject'
         AND decision_reason IS NULL)
        OR
        (state = 'withdrawn'
         AND (review_verdict IS NULL OR review_verdict = 'approve'))
    ),
    CHECK (
        terminal_source <> 'recovery'
        OR decision_reason =
           'session recovery invalidated author binding and staging receipts'
    )
) STRICT;

CREATE INDEX publications_state_author
    ON publications (state, author_device_id, author_agent_session_id, publication_id);
CREATE INDEX publications_task_state
    ON publications (task_id, state);
CREATE INDEX publications_supersedes
    ON publications (supersedes_publication_id);
CREATE INDEX publications_commit_oid
    ON publications (commit_oid);

-- REPLICATED, DIGEST-COVERED TABLE 15.
CREATE TABLE control_file_proposals (
    proposal_event_id TEXT PRIMARY KEY CHECK (
        length(proposal_event_id) = 36 AND substr(proposal_event_id, 15, 1) = '7'
        AND substr(proposal_event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(proposal_event_id, 9, 1) = '-' AND substr(proposal_event_id, 14, 1) = '-'
        AND substr(proposal_event_id, 19, 1) = '-' AND substr(proposal_event_id, 24, 1) = '-'
        AND length(replace(proposal_event_id, '-', '')) = 32
        AND replace(proposal_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    path TEXT NOT NULL CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 512),
    operation TEXT NOT NULL CHECK (operation IN ('upsert', 'delete')),
    content_digest BLOB CHECK (content_digest IS NULL OR length(content_digest) = 32),
    content_size INTEGER NOT NULL CHECK (content_size >= 0),
    diff TEXT NOT NULL CHECK (length(CAST(diff AS BLOB)) <= 65536),
    proposed_by_device_id TEXT NOT NULL CHECK (
        length(proposed_by_device_id) = 67 AND substr(proposed_by_device_id, 1, 3) = 'cc1'
        AND substr(proposed_by_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    chain_index INTEGER NOT NULL UNIQUE CHECK (chain_index BETWEEN 1 AND 9007199254740991),
    CHECK (
        (operation = 'upsert' AND content_digest IS NOT NULL)
        OR
        (operation = 'delete' AND content_digest IS NULL AND content_size = 0)
    )
) STRICT;

CREATE INDEX control_file_proposals_path_latest
    ON control_file_proposals (session_id, path, chain_index DESC);

-- REPLICATED, DIGEST-COVERED TABLE 16.
CREATE TABLE merge_conflicts (
    conflict_id TEXT PRIMARY KEY CHECK (
        length(conflict_id) = 68
        AND substr(conflict_id, 1, 4) = 'ccf1'
        AND substr(conflict_id, 5) NOT GLOB '*[^0-9a-f]*'
    ),
    publication_id TEXT NOT NULL CHECK (
        length(publication_id) = 36 AND substr(publication_id, 15, 1) = '7'
        AND substr(publication_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(publication_id, 9, 1) = '-' AND substr(publication_id, 14, 1) = '-'
        AND substr(publication_id, 19, 1) = '-' AND substr(publication_id, 24, 1) = '-'
        AND length(replace(publication_id, '-', '')) = 32
        AND replace(publication_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    merge_kind TEXT NOT NULL CHECK (merge_kind IN ('merge', 'rebase')),
    replay_commit_oid TEXT CHECK (
        replay_commit_oid IS NULL
        OR (length(replay_commit_oid) = 45 AND substr(replay_commit_oid, 1, 5) = 'sha1:'
            AND substr(replay_commit_oid, 6) NOT GLOB '*[^0-9a-f]*')
        OR (length(replay_commit_oid) = 71 AND substr(replay_commit_oid, 1, 7) = 'sha256:'
            AND substr(replay_commit_oid, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    merge_base_oids_json TEXT NOT NULL CHECK (
        json_valid(merge_base_oids_json)
        AND json_type(merge_base_oids_json) = 'array'
        AND json_array_length(merge_base_oids_json) BETWEEN 0 AND 16
    ),
    canonical_commit TEXT NOT NULL CHECK (
        (length(canonical_commit) = 45 AND substr(canonical_commit, 1, 5) = 'sha1:'
         AND substr(canonical_commit, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(canonical_commit) = 71 AND substr(canonical_commit, 1, 7) = 'sha256:'
         AND substr(canonical_commit, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    candidate_commit TEXT NOT NULL CHECK (
        (length(candidate_commit) = 45 AND substr(candidate_commit, 1, 5) = 'sha1:'
         AND substr(candidate_commit, 6) NOT GLOB '*[^0-9a-f]*')
        OR
        (length(candidate_commit) = 71 AND substr(candidate_commit, 1, 7) = 'sha256:'
         AND substr(candidate_commit, 8) NOT GLOB '*[^0-9a-f]*')
    ),
    paths_json TEXT NOT NULL CHECK (
        json_valid(paths_json)
        AND json_type(paths_json) = 'array'
        AND json_array_length(paths_json) <= 2048
    ),
    status TEXT NOT NULL CHECK (status IN ('unresolved', 'resolved')),
    resolution_kind TEXT CHECK (
        resolution_kind IS NULL OR resolution_kind IN ('publication', 'forced')
    ),
    resolution_publication_id TEXT CHECK (
        resolution_publication_id IS NULL
        OR (
            length(resolution_publication_id) = 36
            AND substr(resolution_publication_id, 15, 1) = '7'
            AND substr(resolution_publication_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(resolution_publication_id, 9, 1) = '-'
            AND substr(resolution_publication_id, 14, 1) = '-'
            AND substr(resolution_publication_id, 19, 1) = '-'
            AND substr(resolution_publication_id, 24, 1) = '-'
            AND length(replace(resolution_publication_id, '-', '')) = 32
            AND replace(resolution_publication_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    force_reason TEXT CHECK (
        force_reason IS NULL OR length(CAST(force_reason AS BLOB)) BETWEEN 1 AND 1024
    ),
    resolved_by_device_id TEXT CHECK (
        resolved_by_device_id IS NULL
        OR (
            length(resolved_by_device_id) = 67
            AND substr(resolved_by_device_id, 1, 3) = 'cc1'
            AND substr(resolved_by_device_id, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    CHECK (
        (merge_kind = 'merge' AND replay_commit_oid IS NULL)
        OR (merge_kind = 'rebase' AND replay_commit_oid IS NOT NULL)
    ),
    CHECK (
        (status = 'unresolved'
         AND resolution_kind IS NULL
         AND resolution_publication_id IS NULL
         AND force_reason IS NULL
         AND resolved_by_device_id IS NULL)
        OR
        (status = 'resolved'
         AND resolution_kind = 'publication'
         AND resolution_publication_id IS NOT NULL
         AND force_reason IS NULL
         AND resolved_by_device_id IS NOT NULL)
        OR
        (status = 'resolved'
         AND resolution_kind = 'forced'
         AND resolution_publication_id IS NULL
         AND force_reason IS NOT NULL
         AND resolved_by_device_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX merge_conflicts_publication_status
    ON merge_conflicts (publication_id, status, conflict_id);

-- REPLICATED, DIGEST-COVERED TABLE 17.
CREATE TABLE session_policy (
    session_id TEXT PRIMARY KEY CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    values_json TEXT NOT NULL CHECK (json_valid(values_json) AND json_type(values_json) = 'object'),
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991)
) STRICT;

-- LOCAL ONLY: context-bound resume-capability commitments.
CREATE TABLE agent_resume_tokens (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    device_id TEXT NOT NULL CHECK (
        length(device_id) = 67 AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    agent_session_id TEXT NOT NULL UNIQUE CHECK (
        length(agent_session_id) = 36 AND substr(agent_session_id, 15, 1) = '7'
        AND substr(agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(agent_session_id, 9, 1) = '-' AND substr(agent_session_id, 14, 1) = '-'
        AND substr(agent_session_id, 19, 1) = '-' AND substr(agent_session_id, 24, 1) = '-'
        AND length(replace(agent_session_id, '-', '')) = 32
        AND replace(agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    working_root_id TEXT NOT NULL UNIQUE CHECK (
        length(working_root_id) = 36 AND substr(working_root_id, 15, 1) = '7'
        AND substr(working_root_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(working_root_id, 9, 1) = '-' AND substr(working_root_id, 14, 1) = '-'
        AND substr(working_root_id, 19, 1) = '-' AND substr(working_root_id, 24, 1) = '-'
        AND length(replace(working_root_id, '-', '')) = 32
        AND replace(working_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    )
) STRICT;

-- LOCAL ONLY: one-use agent launch registrations.
CREATE TABLE agent_launches (
    launch_id TEXT PRIMARY KEY CHECK (
        length(launch_id) = 36 AND substr(launch_id, 15, 1) = '7'
        AND substr(launch_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(launch_id, 9, 1) = '-' AND substr(launch_id, 14, 1) = '-'
        AND substr(launch_id, 19, 1) = '-' AND substr(launch_id, 24, 1) = '-'
        AND length(replace(launch_id, '-', '')) = 32
        AND replace(launch_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    selector_digest BLOB NOT NULL UNIQUE CHECK (length(selector_digest) = 32),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    client_kind TEXT NOT NULL CHECK (client_kind IN ('codex', 'claude', 'other')),
    agent_profile_id TEXT CHECK (
        agent_profile_id IS NULL
        OR length(CAST(agent_profile_id AS BLOB)) BETWEEN 1 AND 128
    ),
    concurrency_mode TEXT NOT NULL CHECK (concurrency_mode IN ('isolated', 'shared')),
    managed_root_id TEXT NOT NULL CHECK (
        length(managed_root_id) = 36 AND substr(managed_root_id, 15, 1) = '7'
        AND substr(managed_root_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(managed_root_id, 9, 1) = '-' AND substr(managed_root_id, 14, 1) = '-'
        AND substr(managed_root_id, 19, 1) = '-' AND substr(managed_root_id, 24, 1) = '-'
        AND length(replace(managed_root_id, '-', '')) = 32
        AND replace(managed_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'reserved', 'consumed', 'rejected', 'cleared')),
    client_instance_id TEXT CHECK (
        client_instance_id IS NULL
        OR (
            length(client_instance_id) = 36 AND substr(client_instance_id, 15, 1) = '7'
            AND substr(client_instance_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(client_instance_id, 9, 1) = '-'
            AND substr(client_instance_id, 14, 1) = '-'
            AND substr(client_instance_id, 19, 1) = '-'
            AND substr(client_instance_id, 24, 1) = '-'
            AND length(replace(client_instance_id, '-', '')) = 32
            AND replace(client_instance_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    agent_session_id TEXT UNIQUE CHECK (
        agent_session_id IS NULL
        OR (
            length(agent_session_id) = 36 AND substr(agent_session_id, 15, 1) = '7'
            AND substr(agent_session_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(agent_session_id, 9, 1) = '-'
            AND substr(agent_session_id, 14, 1) = '-'
            AND substr(agent_session_id, 19, 1) = '-'
            AND substr(agent_session_id, 24, 1) = '-'
            AND length(replace(agent_session_id, '-', '')) = 32
            AND replace(agent_session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    working_root_id TEXT UNIQUE CHECK (
        working_root_id IS NULL
        OR (
            length(working_root_id) = 36 AND substr(working_root_id, 15, 1) = '7'
            AND substr(working_root_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(working_root_id, 9, 1) = '-'
            AND substr(working_root_id, 14, 1) = '-'
            AND substr(working_root_id, 19, 1) = '-'
            AND substr(working_root_id, 24, 1) = '-'
            AND length(replace(working_root_id, '-', '')) = 32
            AND replace(working_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    start_event_id TEXT UNIQUE CHECK (
        start_event_id IS NULL
        OR (
            length(start_event_id) = 36 AND substr(start_event_id, 15, 1) = '7'
            AND substr(start_event_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(start_event_id, 9, 1) = '-'
            AND substr(start_event_id, 14, 1) = '-'
            AND substr(start_event_id, 19, 1) = '-'
            AND substr(start_event_id, 24, 1) = '-'
            AND length(replace(start_event_id, '-', '')) = 32
            AND replace(start_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    CHECK (
        (state = 'pending'
         AND client_instance_id IS NULL
         AND agent_session_id IS NULL
         AND working_root_id IS NULL
         AND start_event_id IS NULL)
        OR
        (state <> 'pending'
         AND client_instance_id IS NOT NULL
         AND agent_session_id IS NOT NULL
         AND working_root_id IS NOT NULL
         AND start_event_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX agent_launches_root_state
    ON agent_launches (managed_root_id, state, launch_id);
CREATE INDEX agent_launches_session_state
    ON agent_launches (session_id, state, launch_id);
CREATE UNIQUE INDEX agent_launches_one_isolated_occupant
    ON agent_launches (managed_root_id)
    WHERE concurrency_mode = 'isolated'
      AND state IN ('pending', 'reserved', 'consumed');

-- LOCAL ONLY: CodeComm-created filesystem roots and guard health.
CREATE TABLE managed_roots (
    managed_root_id TEXT PRIMARY KEY CHECK (
        length(managed_root_id) = 36 AND substr(managed_root_id, 15, 1) = '7'
        AND substr(managed_root_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(managed_root_id, 9, 1) = '-' AND substr(managed_root_id, 14, 1) = '-'
        AND substr(managed_root_id, 19, 1) = '-' AND substr(managed_root_id, 24, 1) = '-'
        AND length(replace(managed_root_id, '-', '')) = 32
        AND replace(managed_root_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    canonical_path TEXT NOT NULL UNIQUE CHECK (
        length(CAST(canonical_path AS BLOB)) BETWEEN 1 AND 512
    ),
    filesystem_identity TEXT NOT NULL UNIQUE
        CHECK (length(CAST(filesystem_identity AS BLOB)) BETWEEN 1 AND 1024),
    repository_identity TEXT NOT NULL UNIQUE CHECK (
        length(CAST(repository_identity AS BLOB)) BETWEEN 1 AND 1024
    ),
    root_kind TEXT NOT NULL CHECK (root_kind IN ('primary', 'isolated', 'shared')),
    guard_status TEXT NOT NULL CHECK (guard_status IN ('healthy', 'blocked', 'repairing')),
    guard_detail_code TEXT CHECK (
        guard_detail_code IS NULL
        OR (
            length(CAST(guard_detail_code AS BLOB)) BETWEEN 1 AND 64
            AND guard_detail_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    last_verified_at TEXT CHECK (
        last_verified_at IS NULL
        OR (
            length(last_verified_at) BETWEEN 20 AND 30
            AND substr(last_verified_at, 11, 1) = 'T'
            AND substr(last_verified_at, -1, 1) = 'Z'
        )
    ),
    CHECK (active = 0 OR guard_status <> 'healthy' OR last_verified_at IS NOT NULL)
) STRICT;

CREATE INDEX managed_roots_session_status
    ON managed_roots (session_id, active, guard_status);

-- DERIVED LOCAL VIEW: projected from accepted event content, never authority.
CREATE TABLE activity (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('agent', 'human', 'daemon')),
    agent_session_id TEXT,
    event_kind TEXT NOT NULL CHECK (length(CAST(event_kind AS BLOB)) BETWEEN 1 AND 64),
    task_id TEXT,
    rationale_summary TEXT NOT NULL CHECK (length(CAST(rationale_summary AS BLOB)) <= 2048),
    capture_level TEXT NOT NULL CHECK (
        capture_level IN ('agent_reported', 'human_reported', 'daemon_observed')
    ),
    actions_json TEXT NOT NULL CHECK (
        json_valid(actions_json)
        AND json_type(actions_json) = 'array'
        AND json_array_length(actions_json) <= 64
    ),
    redaction_json TEXT NOT NULL CHECK (
        json_valid(redaction_json) AND json_type(redaction_json) = 'object'
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    CHECK (
        (actor_type = 'agent' AND agent_session_id IS NOT NULL AND capture_level = 'agent_reported')
        OR
        (actor_type = 'human' AND agent_session_id IS NULL AND capture_level = 'human_reported')
        OR
        (actor_type = 'daemon' AND agent_session_id IS NULL AND capture_level = 'daemon_observed')
    )
) STRICT;

CREATE INDEX activity_session_created
    ON activity (session_id, created_at, event_id);
CREATE INDEX activity_task_created
    ON activity (task_id, created_at, event_id);
CREATE INDEX activity_agent_created
    ON activity (agent_session_id, created_at, event_id);

-- LOCAL EVIDENCE: authenticated peer watermarks.
CREATE TABLE peer_acks (
    device_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    ack_sequence INTEGER NOT NULL CHECK (ack_sequence BETWEEN 1 AND 9007199254740991),
    last_raft_applied_log_index INTEGER
        CHECK (last_raft_applied_log_index IS NULL OR last_raft_applied_log_index >= 1),
    chain_index INTEGER NOT NULL CHECK (chain_index BETWEEN 0 AND 9007199254740991),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    result_index INTEGER NOT NULL CHECK (result_index BETWEEN 0 AND 9007199254740991),
    result_hash BLOB NOT NULL CHECK (length(result_hash) = 32),
    canonical_ref_version INTEGER NOT NULL
        CHECK (canonical_ref_version BETWEEN 1 AND 9007199254740991),
    canonical_object_available INTEGER NOT NULL CHECK (canonical_object_available IN (0, 1)),
    body_digest BLOB NOT NULL CHECK (length(body_digest) = 32),
    received_at TEXT NOT NULL CHECK (
        length(received_at) BETWEEN 20 AND 30
        AND substr(received_at, 11, 1) = 'T'
        AND substr(received_at, -1, 1) = 'Z'
    ),
    PRIMARY KEY (device_id, session_id, recovery_generation),
    UNIQUE (device_id, session_id, recovery_generation, ack_sequence)
) STRICT, WITHOUT ROWID;

CREATE INDEX peer_acks_result_watermark
    ON peer_acks (session_id, recovery_generation, result_index);

-- LOCAL ONLY: signed, observed, and manually configured endpoint candidates.
CREATE TABLE peer_endpoints (
    endpoint_id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('own_signed', 'member_signed', 'raw_discovery', 'authenticated_guess', 'manual')
    ),
    endpoint_sequence INTEGER CHECK (
        endpoint_sequence IS NULL OR endpoint_sequence BETWEEN 1 AND 9007199254740991
    ),
    transport TEXT NOT NULL CHECK (transport IN ('tcp')),
    host TEXT NOT NULL CHECK (length(CAST(host AS BLOB)) BETWEEN 1 AND 255),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    endpoint_set_json TEXT CHECK (
        endpoint_set_json IS NULL
        OR (json_valid(endpoint_set_json) AND json_type(endpoint_set_json) = 'object')
    ),
    observed_at TEXT NOT NULL CHECK (
        length(observed_at) BETWEEN 20 AND 30
        AND substr(observed_at, 11, 1) = 'T'
        AND substr(observed_at, -1, 1) = 'Z'
    ),
    expires_at TEXT CHECK (
        expires_at IS NULL
        OR (
            length(expires_at) BETWEEN 20 AND 30
            AND substr(expires_at, 11, 1) = 'T'
            AND substr(expires_at, -1, 1) = 'Z'
        )
    ),
    UNIQUE (device_id, source_kind, host, port)
) STRICT;

CREATE INDEX peer_endpoints_device_source_expiry
    ON peer_endpoints (device_id, source_kind, expires_at);

-- LOCAL ONLY: same-boot monotonic lease scheduling and display estimates.
CREATE TABLE lease_deadlines (
    lease_id TEXT NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
    entity_version INTEGER NOT NULL CHECK (entity_version BETWEEN 1 AND 9007199254740991),
    origin_boot_id TEXT NOT NULL,
    monotonic_deadline_ns INTEGER NOT NULL CHECK (monotonic_deadline_ns >= 0),
    display_deadline_at TEXT NOT NULL CHECK (
        length(display_deadline_at) BETWEEN 20 AND 30
        AND substr(display_deadline_at, 11, 1) = 'T'
        AND substr(display_deadline_at, -1, 1) = 'Z'
    ),
    PRIMARY KEY (lease_id, entity_version)
) STRICT, WITHOUT ROWID;

-- LOCAL ONLY: per-device control-file consent and approved content references.
CREATE TABLE control_file_approvals (
    proposal_event_id TEXT PRIMARY KEY
        REFERENCES control_file_proposals(proposal_event_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 512),
    operation TEXT NOT NULL CHECK (operation IN ('upsert', 'delete')),
    content_digest BLOB CHECK (content_digest IS NULL OR length(content_digest) = 32),
    decision TEXT NOT NULL CHECK (decision IN ('pending', 'approved', 'declined')),
    content_store_ref TEXT,
    manifest_version INTEGER CHECK (
        manifest_version IS NULL OR manifest_version BETWEEN 1 AND 9007199254740991
    ),
    decided_at TEXT CHECK (
        decided_at IS NULL
        OR (
            length(decided_at) BETWEEN 20 AND 30
            AND substr(decided_at, 11, 1) = 'T'
            AND substr(decided_at, -1, 1) = 'Z'
        )
    ),
    CHECK (
        (operation = 'upsert' AND content_digest IS NOT NULL)
        OR (operation = 'delete' AND content_digest IS NULL)
    ),
    CHECK (
        (decision = 'pending'
         AND decided_at IS NULL
         AND manifest_version IS NULL
         AND content_store_ref IS NULL)
        OR
        (decision = 'approved'
         AND decided_at IS NOT NULL
         AND manifest_version IS NOT NULL
         AND content_store_ref IS NOT NULL)
        OR
        (decision = 'declined'
         AND decided_at IS NOT NULL
         AND manifest_version IS NULL
         AND content_store_ref IS NULL)
    )
) STRICT;

CREATE INDEX control_file_approvals_manifest
    ON control_file_approvals (session_id, decision, path);

-- LOCAL ONLY: resumable and verified Git bundle/artifact state.
CREATE TABLE git_artifacts (
    artifact_digest BLOB PRIMARY KEY CHECK (length(artifact_digest) = 32),
    artifact_kind TEXT NOT NULL CHECK (
        artifact_kind IN ('bootstrap', 'draft', 'publication', 'snapshot')
    ),
    state TEXT NOT NULL CHECK (
        state IN ('reserved', 'downloading', 'downloaded', 'verifying', 'verified', 'imported', 'failed')
    ),
    source_device_id TEXT,
    proposal_event_id TEXT,
    publication_id TEXT,
    metadata_digest BLOB CHECK (metadata_digest IS NULL OR length(metadata_digest) = 32),
    expected_size INTEGER NOT NULL CHECK (expected_size >= 0),
    received_size INTEGER NOT NULL CHECK (received_size BETWEEN 0 AND expected_size),
    staged_result_index INTEGER CHECK (
        staged_result_index IS NULL OR staged_result_index BETWEEN 0 AND 9007199254740991
    ),
    retention_class TEXT NOT NULL CHECK (
        retention_class IN ('quarantine', 'preproposal', 'nonterminal', 'canonical', 'draft', 'bootstrap')
    ),
    local_path TEXT NOT NULL CHECK (length(CAST(local_path AS BLOB)) >= 1),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    updated_at TEXT NOT NULL CHECK (
        length(updated_at) BETWEEN 20 AND 30
        AND substr(updated_at, 11, 1) = 'T'
        AND substr(updated_at, -1, 1) = 'Z'
    ),
    CHECK (
        artifact_kind <> 'publication'
        OR (proposal_event_id IS NOT NULL AND publication_id IS NOT NULL AND metadata_digest IS NOT NULL)
    )
) STRICT;

CREATE INDEX git_artifacts_state_retention
    ON git_artifacts (state, retention_class, updated_at);
CREATE INDEX git_artifacts_publication
    ON git_artifacts (publication_id, proposal_event_id);

-- LOCAL SUPPORT: durable per-peer replication heads and authority context.
CREATE TABLE replication_cursors (
    peer_device_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    authority_voter_set_version INTEGER NOT NULL
        CHECK (authority_voter_set_version BETWEEN 1 AND 9007199254740991),
    chain_index INTEGER NOT NULL CHECK (chain_index BETWEEN 0 AND 9007199254740991),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    result_index INTEGER NOT NULL CHECK (result_index BETWEEN 0 AND 9007199254740991),
    result_hash BLOB NOT NULL CHECK (length(result_hash) = 32),
    updated_at TEXT NOT NULL CHECK (
        length(updated_at) BETWEEN 20 AND 30
        AND substr(updated_at, 11, 1) = 'T'
        AND substr(updated_at, -1, 1) = 'Z'
    ),
    PRIMARY KEY (peer_device_id, session_id, recovery_generation)
) STRICT, WITHOUT ROWID;

CREATE INDEX replication_cursors_session_result
    ON replication_cursors (session_id, recovery_generation, result_index);

-- LOCAL SUPPORT: exact signed proposals awaiting forward, ordered by row ID.
CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE CHECK (
        length(event_id) = 36 AND substr(event_id, 15, 1) = '7'
        AND substr(event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(event_id, 9, 1) = '-' AND substr(event_id, 14, 1) = '-'
        AND substr(event_id, 19, 1) = '-' AND substr(event_id, 24, 1) = '-'
        AND length(replace(event_id, '-', '')) = 32
        AND replace(event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    origin_device_id TEXT NOT NULL CHECK (
        length(origin_device_id) = 67 AND substr(origin_device_id, 1, 3) = 'cc1'
        AND substr(origin_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    origin_scope_kind TEXT NOT NULL CHECK (origin_scope_kind IN ('agent', 'boot')),
    origin_scope_id TEXT NOT NULL CHECK (
        length(origin_scope_id) = 36 AND substr(origin_scope_id, 15, 1) = '7'
        AND substr(origin_scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(origin_scope_id, 9, 1) = '-' AND substr(origin_scope_id, 14, 1) = '-'
        AND substr(origin_scope_id, 19, 1) = '-' AND substr(origin_scope_id, 24, 1) = '-'
        AND length(replace(origin_scope_id, '-', '')) = 32
        AND replace(origin_scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    origin_sequence INTEGER NOT NULL CHECK (origin_sequence BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL CHECK (length(CAST(kind AS BLOB)) BETWEEN 1 AND 64),
    signed_proposal_json TEXT NOT NULL CHECK (
        json_valid(signed_proposal_json) AND json_type(signed_proposal_json) = 'object'
    ),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('queued', 'forwarding')),
    queued_at TEXT NOT NULL CHECK (
        length(queued_at) BETWEEN 20 AND 30
        AND substr(queued_at, 11, 1) = 'T'
        AND substr(queued_at, -1, 1) = 'Z'
    ),
    UNIQUE (origin_device_id, origin_scope_kind, origin_scope_id, origin_sequence)
) STRICT;

CREATE INDEX outbox_scope_order
    ON outbox (
        origin_device_id, origin_scope_kind, origin_scope_id,
        origin_sequence, outbox_id
    );

-- LOCAL ONLY: IPC request idempotency and publication preparation tombstones.
CREATE TABLE local_requests (
    client_instance_id TEXT NOT NULL CHECK (
        length(client_instance_id) = 36 AND substr(client_instance_id, 15, 1) = '7'
        AND substr(client_instance_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(client_instance_id, 9, 1) = '-' AND substr(client_instance_id, 14, 1) = '-'
        AND substr(client_instance_id, 19, 1) = '-' AND substr(client_instance_id, 24, 1) = '-'
        AND length(replace(client_instance_id, '-', '')) = 32
        AND replace(client_instance_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL CHECK (
        length(request_id) = 36 AND substr(request_id, 15, 1) = '7'
        AND substr(request_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(request_id, 9, 1) = '-' AND substr(request_id, 14, 1) = '-'
        AND substr(request_id, 19, 1) = '-' AND substr(request_id, 24, 1) = '-'
        AND length(replace(request_id, '-', '')) = 32
        AND replace(request_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL CHECK (
        length(session_id) = 36 AND substr(session_id, 15, 1) = '7'
        AND substr(session_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 15, 1) = '4'
        AND substr(workspace_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(workspace_id, 9, 1) = '-' AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
        AND length(replace(workspace_id, '-', '')) = 32
        AND replace(workspace_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    binding_class TEXT NOT NULL CHECK (binding_class IN ('operator', 'agent', 'daemon')),
    origin_device_id TEXT NOT NULL CHECK (
        length(origin_device_id) = 67 AND substr(origin_device_id, 1, 3) = 'cc1'
        AND substr(origin_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    origin_scope_kind TEXT NOT NULL CHECK (origin_scope_kind IN ('agent', 'boot')),
    origin_scope_id TEXT NOT NULL CHECK (
        length(origin_scope_id) = 36 AND substr(origin_scope_id, 15, 1) = '7'
        AND substr(origin_scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(origin_scope_id, 9, 1) = '-' AND substr(origin_scope_id, 14, 1) = '-'
        AND substr(origin_scope_id, 19, 1) = '-' AND substr(origin_scope_id, 24, 1) = '-'
        AND length(replace(origin_scope_id, '-', '')) = 32
        AND replace(origin_scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    event_id TEXT NOT NULL UNIQUE CHECK (
        length(event_id) = 36 AND substr(event_id, 15, 1) = '7'
        AND substr(event_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(event_id, 9, 1) = '-' AND substr(event_id, 14, 1) = '-'
        AND substr(event_id, 19, 1) = '-' AND substr(event_id, 24, 1) = '-'
        AND length(replace(event_id, '-', '')) = 32
        AND replace(event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    request_kind TEXT NOT NULL CHECK (length(CAST(request_kind AS BLOB)) BETWEEN 1 AND 64),
    state TEXT NOT NULL CHECK (
        state IN ('preparing', 'signed', 'pending', 'resolved', 'abandoned', 'expired')
    ),
    publication_id TEXT,
    publication_metadata_json TEXT CHECK (
        publication_metadata_json IS NULL
        OR (
            json_valid(publication_metadata_json)
            AND json_type(publication_metadata_json) = 'object'
        )
    ),
    publication_metadata_digest BLOB CHECK (
        publication_metadata_digest IS NULL OR length(publication_metadata_digest) = 32
    ),
    artifact_digest BLOB CHECK (artifact_digest IS NULL OR length(artifact_digest) = 32),
    signed_proposal_json TEXT CHECK (
        signed_proposal_json IS NULL
        OR (json_valid(signed_proposal_json) AND json_type(signed_proposal_json) = 'object')
    ),
    proposal_digest BLOB CHECK (proposal_digest IS NULL OR length(proposal_digest) = 32),
    terminal_code TEXT CHECK (
        terminal_code IS NULL
        OR (
            length(CAST(terminal_code AS BLOB)) BETWEEN 1 AND 64
            AND terminal_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    PRIMARY KEY (client_instance_id, request_id),
    CHECK (
        (state = 'preparing'
         AND signed_proposal_json IS NULL
         AND proposal_digest IS NULL
         AND terminal_code IS NULL)
        OR
        (state IN ('signed', 'pending')
         AND signed_proposal_json IS NOT NULL
         AND proposal_digest IS NOT NULL
         AND terminal_code IS NULL)
        OR
        (state = 'resolved'
         AND signed_proposal_json IS NULL
         AND proposal_digest IS NOT NULL
         AND terminal_code IS NOT NULL)
        OR
        (state IN ('abandoned', 'expired')
         AND signed_proposal_json IS NULL
         AND terminal_code IS NOT NULL)
    ),
    CHECK (
        (publication_id IS NULL
         AND publication_metadata_json IS NULL
         AND publication_metadata_digest IS NULL
         AND artifact_digest IS NULL)
        OR
        (publication_id IS NOT NULL
         AND state IN ('preparing', 'signed', 'pending')
         AND publication_metadata_json IS NOT NULL
         AND publication_metadata_digest IS NOT NULL
         AND artifact_digest IS NOT NULL)
        OR
        (publication_id IS NOT NULL
         AND state IN ('resolved', 'abandoned', 'expired')
         AND publication_metadata_json IS NULL
         AND publication_metadata_digest IS NULL
         AND artifact_digest IS NULL)
    ),
    CHECK (
        state <> 'preparing'
        OR (
            publication_id IS NOT NULL
            AND signed_proposal_json IS NULL
            AND proposal_digest IS NULL
            AND terminal_code IS NULL
        )
    ),
    CHECK (
        (binding_class = 'agent' AND origin_scope_kind = 'agent')
        OR
        (binding_class IN ('operator', 'daemon') AND origin_scope_kind = 'boot')
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX local_requests_session_state
    ON local_requests (session_id, recovery_generation, state);
CREATE INDEX local_requests_scope_state
    ON local_requests (origin_scope_kind, origin_scope_id, state);

-- LOCAL ONLY: reserved offline owner-recovery challenge state/tombstones.
CREATE TABLE owner_recovery_challenges (
    challenge_id TEXT PRIMARY KEY,
    client_instance_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    subject_device_id TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    expected_entity_version INTEGER NOT NULL
        CHECK (expected_entity_version BETWEEN 1 AND 9007199254740991),
    authorization_json TEXT CHECK (
        authorization_json IS NULL
        OR (json_valid(authorization_json) AND json_type(authorization_json) = 'object')
    ),
    authorization_digest BLOB CHECK (
        authorization_digest IS NULL OR length(authorization_digest) = 32
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'finalized', 'expired', 'abandoned')),
    deadline_at TEXT NOT NULL CHECK (
        length(deadline_at) BETWEEN 20 AND 30
        AND substr(deadline_at, 11, 1) = 'T'
        AND substr(deadline_at, -1, 1) = 'Z'
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    UNIQUE (client_instance_id, request_id),
    CHECK (
        (state IN ('pending', 'finalized')
         AND authorization_json IS NOT NULL
         AND authorization_digest IS NOT NULL)
        OR
        (state IN ('expired', 'abandoned')
         AND authorization_json IS NULL
         AND authorization_digest IS NULL)
    )
) STRICT;

CREATE UNIQUE INDEX owner_recovery_one_pending_per_device
    ON owner_recovery_challenges (subject_device_id)
    WHERE state = 'pending';

-- LOCAL ONLY: next sequence allocation; never reducer input.
CREATE TABLE origin_counters (
    device_id TEXT NOT NULL CHECK (
        length(device_id) = 67 AND substr(device_id, 1, 3) = 'cc1'
        AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('agent', 'boot')),
    scope_id TEXT NOT NULL CHECK (
        length(scope_id) = 36 AND substr(scope_id, 15, 1) = '7'
        AND substr(scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(scope_id, 9, 1) = '-' AND substr(scope_id, 14, 1) = '-'
        AND substr(scope_id, 19, 1) = '-' AND substr(scope_id, 24, 1) = '-'
        AND length(replace(scope_id, '-', '')) = 32
        AND replace(scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    next_sequence INTEGER CHECK (next_sequence BETWEEN 1 AND 9007199254740991),
    exhausted INTEGER NOT NULL CHECK (exhausted IN (0, 1)),
    PRIMARY KEY (device_id, scope_kind, scope_id),
    CHECK (
        (exhausted = 0 AND next_sequence IS NOT NULL)
        OR (exhausted = 1 AND next_sequence IS NULL)
    )
) STRICT, WITHOUT ROWID;

-- DERIVED LOCAL VIEW: accepted actions, committed rejections, and bounded
-- pre-result audits; never independent authority.
CREATE TABLE audit_events (
    audit_id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('accepted_event', 'committed_rejection', 'audit_event', 'local_aggregate')
    ),
    event_id TEXT,
    result_index INTEGER CHECK (
        result_index IS NULL OR result_index BETWEEN 1 AND 9007199254740991
    ),
    reporter_device_id TEXT,
    subject_device_id TEXT,
    subject_credential_epoch INTEGER CHECK (
        subject_credential_epoch IS NULL
        OR subject_credential_epoch BETWEEN 0 AND 9007199254740991
    ),
    actor_type TEXT CHECK (actor_type IS NULL OR actor_type IN ('agent', 'human', 'daemon')),
    ipc_channel TEXT CHECK (ipc_channel IS NULL OR ipc_channel IN ('agent', 'operator', 'daemon', 'peer')),
    action_code TEXT NOT NULL CHECK (
        length(CAST(action_code AS BLOB)) BETWEEN 1 AND 64
        AND action_code NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    outcome_code TEXT NOT NULL CHECK (
        length(CAST(outcome_code AS BLOB)) BETWEEN 1 AND 64
        AND outcome_code NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    subject TEXT NOT NULL CHECK (length(CAST(subject AS BLOB)) <= 256),
    details_json TEXT NOT NULL CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
    first_seen_at TEXT NOT NULL CHECK (
        length(first_seen_at) BETWEEN 20 AND 30
        AND substr(first_seen_at, 11, 1) = 'T'
        AND substr(first_seen_at, -1, 1) = 'Z'
    ),
    last_seen_at TEXT NOT NULL CHECK (
        length(last_seen_at) BETWEEN 20 AND 30
        AND substr(last_seen_at, 11, 1) = 'T'
        AND substr(last_seen_at, -1, 1) = 'Z'
    ),
    observation_count INTEGER NOT NULL CHECK (observation_count BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE INDEX audit_events_session_time
    ON audit_events (session_id, first_seen_at, audit_id);
CREATE INDEX audit_events_subject_time
    ON audit_events (subject_device_id, first_seen_at, audit_id);
CREATE INDEX audit_events_event_result
    ON audit_events (event_id, result_index);
