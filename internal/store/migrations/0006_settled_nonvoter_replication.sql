-- Explicit evidence mode for application nonvoters and the signed batch
-- watermark omitted from the original attestation schema.
--
-- A v5 attestation cannot be upgraded safely: it has no signed server
-- watermark to preserve. The guard deliberately aborts before changing the
-- schema if any such evidence exists. An already-v6 physical schema means the
-- matching migration-ledger row was removed outside this transaction; reject
-- that corruption instead of conditionally rebuilding it.
CREATE TABLE migration_0006_schema_guard (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    already_v6 INTEGER NOT NULL CHECK (already_v6 = 0)
) STRICT;

INSERT INTO migration_0006_schema_guard(singleton, already_v6)
SELECT 1, count(*)
  FROM pragma_table_info('replication_attestations')
 WHERE name = 'server_applied_result_index';

DROP TABLE migration_0006_schema_guard;

CREATE TABLE migration_0006_attestation_guard (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    legacy_row_count INTEGER NOT NULL CHECK (legacy_row_count = 0)
) STRICT;

INSERT INTO migration_0006_attestation_guard(singleton, legacy_row_count)
SELECT 1, count(*) FROM replication_attestations;

DROP TABLE migration_0006_attestation_guard;
DROP TRIGGER IF EXISTS replication_batch_watermark_insert;
DROP TRIGGER IF EXISTS replication_batch_watermark_update;
DROP INDEX replication_attestations_coverage;
ALTER TABLE replication_attestations RENAME TO replication_attestations_legacy;

CREATE TABLE replication_attestations (
    attestation_id TEXT PRIMARY KEY CHECK (
        length(CAST(attestation_id AS BLOB)) BETWEEN 1 AND 128
    ),
    attestation_kind TEXT NOT NULL CHECK (
        attestation_kind IN ('batch', 'snapshot')
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
    signer_device_id TEXT NOT NULL CHECK (
        length(signer_device_id) = 67 AND substr(signer_device_id, 1, 3) = 'cc1'
        AND substr(signer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    authority_voter_set_version INTEGER NOT NULL CHECK (
        authority_voter_set_version BETWEEN 1 AND 9007199254740991
    ),
    from_result_index INTEGER NOT NULL
        CHECK (from_result_index BETWEEN 0 AND 9007199254740991),
    to_result_index INTEGER NOT NULL CHECK (
        to_result_index BETWEEN from_result_index AND 9007199254740991
    ),
    server_applied_result_index INTEGER CHECK (
        server_applied_result_index IS NULL
        OR server_applied_result_index
           BETWEEN to_result_index AND 9007199254740991
    ),
    start_result_hash BLOB NOT NULL CHECK (length(start_result_hash) = 32),
    end_result_hash BLOB NOT NULL CHECK (length(end_result_hash) = 32),
    start_chain_index INTEGER NOT NULL
        CHECK (start_chain_index BETWEEN 0 AND 9007199254740991),
    end_chain_index INTEGER NOT NULL CHECK (
        end_chain_index BETWEEN start_chain_index AND 9007199254740991
    ),
    start_chain_hash BLOB NOT NULL CHECK (length(start_chain_hash) = 32),
    end_chain_hash BLOB NOT NULL CHECK (length(end_chain_hash) = 32),
    start_projection_accumulator BLOB CHECK (
        start_projection_accumulator IS NULL
        OR length(start_projection_accumulator) = 32
    ),
    end_projection_accumulator BLOB CHECK (
        end_projection_accumulator IS NULL
        OR length(end_projection_accumulator) = 32
    ),
    start_projection_state_digest BLOB CHECK (
        start_projection_state_digest IS NULL
        OR length(start_projection_state_digest) = 32
    ),
    end_projection_state_digest BLOB CHECK (
        end_projection_state_digest IS NULL
        OR length(end_projection_state_digest) = 32
    ),
    checkpoint_event_id TEXT CHECK (
        checkpoint_event_id IS NULL
        OR (
            length(checkpoint_event_id) = 36
            AND substr(checkpoint_event_id, 15, 1) = '7'
            AND substr(checkpoint_event_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(checkpoint_event_id, 9, 1) = '-'
            AND substr(checkpoint_event_id, 14, 1) = '-'
            AND substr(checkpoint_event_id, 19, 1) = '-'
            AND substr(checkpoint_event_id, 24, 1) = '-'
            AND length(replace(checkpoint_event_id, '-', '')) = 32
            AND replace(checkpoint_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    envelope_json TEXT NOT NULL CHECK (
        json_valid(envelope_json) AND json_type(envelope_json) = 'object'
    ),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    verified_at TEXT NOT NULL CHECK (
        length(verified_at) BETWEEN 20 AND 30
        AND substr(verified_at, 11, 1) = 'T'
        AND substr(verified_at, -1, 1) = 'Z'
    ),
    CHECK (
        (attestation_kind = 'batch'
         AND server_applied_result_index IS NOT NULL
         AND checkpoint_event_id IS NULL
         AND start_projection_accumulator IS NOT NULL
         AND end_projection_accumulator IS NOT NULL
         AND start_projection_state_digest IS NOT NULL
         AND end_projection_state_digest IS NOT NULL)
        OR
        (attestation_kind = 'snapshot'
         AND server_applied_result_index IS NULL)
    )
) STRICT;

DROP TABLE replication_attestations_legacy;

CREATE INDEX replication_attestations_coverage
    ON replication_attestations (
        session_id,
        recovery_generation,
        from_result_index,
        to_result_index
    );

-- Presence is the explicit settled-nonvoter mode marker. Absence retains the
-- strict Raft/boundary startup contract, so deleting this row fails closed.
CREATE TABLE settled_nonvoter_state (
    singleton INTEGER PRIMARY KEY
        REFERENCES consensus_state(singleton) ON DELETE RESTRICT
        CHECK (singleton = 1),
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
    baseline_chain_index INTEGER NOT NULL
        CHECK (baseline_chain_index BETWEEN 0 AND 9007199254740991),
    baseline_chain_hash BLOB NOT NULL CHECK (length(baseline_chain_hash) = 32),
    baseline_result_index INTEGER NOT NULL CHECK (
        baseline_result_index BETWEEN baseline_chain_index
        AND 9007199254740991
    ),
    baseline_result_hash BLOB NOT NULL CHECK (length(baseline_result_hash) = 32),
    baseline_projection_accumulator BLOB NOT NULL CHECK (
        length(baseline_projection_accumulator) = 32
    ),
    digest_version INTEGER NOT NULL
        CHECK (digest_version BETWEEN 1 AND 9007199254740991),
    projection_schema_version INTEGER NOT NULL
        CHECK (projection_schema_version BETWEEN 1 AND 9007199254740991),
    frozen_current_term INTEGER
        CHECK (frozen_current_term IS NULL OR frozen_current_term >= 1),
    frozen_last_raft_applied_log_index INTEGER CHECK (
        frozen_last_raft_applied_log_index IS NULL
        OR frozen_last_raft_applied_log_index >= 1
    ),
    entered_at TEXT NOT NULL CHECK (
        length(entered_at) BETWEEN 20 AND 30
        AND substr(entered_at, 11, 1) = 'T'
        AND substr(entered_at, -1, 1) = 'Z'
    ),
    CHECK (
        (frozen_current_term IS NULL
         AND frozen_last_raft_applied_log_index IS NULL)
        OR
        (frozen_current_term IS NOT NULL
         AND frozen_last_raft_applied_log_index IS NOT NULL)
    )
) STRICT;
