-- A quorum-recovery boundary is signed genesis evidence, not a fabricated
-- domain event. Give it a distinct local audit projection and enforce one row
-- per successor session.
CREATE TABLE migration_0008_schema_guard (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    already_v8 INTEGER NOT NULL CHECK (already_v8 = 0)
) STRICT;

INSERT INTO migration_0008_schema_guard(singleton, already_v8)
SELECT 1, count(*)
  FROM sqlite_schema
 WHERE type = 'index'
   AND name = 'audit_events_recovery_boundary_session';

DROP TABLE migration_0008_schema_guard;
DROP INDEX audit_events_session_time;
DROP INDEX audit_events_subject_time;
DROP INDEX audit_events_event_result;
ALTER TABLE audit_events RENAME TO audit_events_legacy;

CREATE TABLE audit_events (
    audit_id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'accepted_event',
            'committed_rejection',
            'audit_event',
            'local_aggregate',
            'recovery_boundary'
        )
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
    actor_type TEXT CHECK (
        actor_type IS NULL OR actor_type IN ('agent', 'human', 'daemon')
    ),
    ipc_channel TEXT CHECK (
        ipc_channel IS NULL
        OR ipc_channel IN ('agent', 'operator', 'daemon', 'peer')
    ),
    action_code TEXT NOT NULL CHECK (
        length(CAST(action_code AS BLOB)) BETWEEN 1 AND 64
        AND action_code NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    outcome_code TEXT NOT NULL CHECK (
        length(CAST(outcome_code AS BLOB)) BETWEEN 1 AND 64
        AND outcome_code NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    subject TEXT NOT NULL CHECK (
        length(CAST(subject AS BLOB)) <= 256
    ),
    details_json TEXT NOT NULL CHECK (
        json_valid(details_json) AND json_type(details_json) = 'object'
    ),
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
    observation_count INTEGER NOT NULL CHECK (
        observation_count BETWEEN 1 AND 9007199254740991
    ),
    CHECK (
        source_kind <> 'recovery_boundary'
        OR (
            event_id IS NULL
            AND result_index IS NULL
            AND reporter_device_id IS NULL
            AND subject_device_id IS NULL
            AND subject_credential_epoch IS NULL
            AND actor_type = 'human'
            AND ipc_channel = 'operator'
            AND action_code = 'cluster.quorum_recovered'
            AND outcome_code = 'accepted'
            AND observation_count = 1
        )
    ),
    CHECK (
        source_kind <> 'local_aggregate'
        OR (
            (event_id IS NULL AND result_index IS NULL)
            OR (event_id IS NOT NULL AND result_index IS NOT NULL)
        )
    )
) STRICT;

INSERT INTO audit_events(
    audit_id, session_id, source_kind, event_id, result_index,
    reporter_device_id, subject_device_id, subject_credential_epoch,
    actor_type, ipc_channel, action_code, outcome_code, subject,
    details_json, first_seen_at, last_seen_at, observation_count
)
SELECT audit_id, session_id, source_kind, event_id, result_index,
       reporter_device_id, subject_device_id, subject_credential_epoch,
       actor_type, ipc_channel, action_code, outcome_code, subject,
       details_json, first_seen_at, last_seen_at, observation_count
  FROM audit_events_legacy;

DROP TABLE audit_events_legacy;

CREATE INDEX audit_events_session_time
    ON audit_events (session_id, first_seen_at, audit_id);
CREATE INDEX audit_events_subject_time
    ON audit_events (subject_device_id, first_seen_at, audit_id);
CREATE INDEX audit_events_event_result
    ON audit_events (event_id, result_index);

-- Stores upgraded from schema v7 already have signed successor genesis rows
-- but could not represent their recovery audits. Backfill deterministic
-- fields; the sentinel is local display time and is never authoritative.
INSERT INTO audit_events(
    session_id, source_kind, event_id, result_index,
    reporter_device_id, subject_device_id, subject_credential_epoch,
    actor_type, ipc_channel, action_code, outcome_code, subject,
    details_json, first_seen_at, last_seen_at, observation_count
)
SELECT session_id, 'recovery_boundary', NULL, NULL,
       NULL, NULL, NULL, 'human', 'operator',
       'cluster.quorum_recovered', 'accepted',
       'session:' || session_id,
       '{"genesis_digest":"' || lower(hex(genesis_digest)) ||
           '","recovery_generation":' || recovery_generation || '}',
       '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z', 1
  FROM genesis_records
 WHERE recovery_generation > 0
   AND genesis_kind = 'successor';

CREATE UNIQUE INDEX audit_events_recovery_boundary_session
    ON audit_events (session_id)
    WHERE source_kind = 'recovery_boundary';

-- IMMUTABLE LOCAL EVIDENCE: exact generation-zero projection rows. Recovery
-- transforms are intentionally non-invertible, so later generations retain
-- this signed-digest-bound baseline for full logical-snapshot verification.
CREATE TABLE initial_projection_boundary (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    digest_version INTEGER NOT NULL
        CHECK (digest_version BETWEEN 1 AND 9007199254740991),
    projection_schema_version INTEGER NOT NULL
        CHECK (projection_schema_version BETWEEN 1 AND 9007199254740991),
    projection_state_digest BLOB NOT NULL
        CHECK (length(projection_state_digest) = 32),
    row_count INTEGER NOT NULL
        CHECK (row_count BETWEEN 0 AND 9007199254740991)
) STRICT;

CREATE TABLE initial_projection_rows (
    table_index INTEGER NOT NULL CHECK (table_index BETWEEN 0 AND 63),
    table_name TEXT NOT NULL CHECK (
        length(CAST(table_name AS BLOB)) BETWEEN 1 AND 64
        AND table_name NOT GLOB '*[^a-z0-9_]*'
    ),
    primary_key BLOB NOT NULL CHECK (length(primary_key) >= 2),
    row_json BLOB NOT NULL CHECK (length(row_json) >= 2),
    PRIMARY KEY (table_index, primary_key),
    UNIQUE (table_name, primary_key)
) STRICT, WITHOUT ROWID;
