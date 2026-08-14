-- Pairing finalization must retain the verified operator request that granted
-- authority. Unfinished legacy rows cannot prove that link, so they require a
-- fresh invite instead of synthesizing a human event during recovery.
DROP INDEX pairing_attempt_finalizations_state;
ALTER TABLE pairing_attempt_finalizations
    RENAME TO pairing_attempt_finalizations_legacy;

UPDATE pairing_attempts
   SET state = 'revoked',
       terminal_at = coalesce(
           terminal_at,
           local_confirmed_at,
           remote_confirmed_at,
           created_at
       )
 WHERE attempt_id IN (
     SELECT attempt_id
       FROM pairing_attempt_finalizations_legacy
      WHERE state = 'finalizing'
 );

CREATE TABLE pairing_attempt_finalizations (
    attempt_id TEXT PRIMARY KEY REFERENCES pairing_attempts(attempt_id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('new', 'rebootstrap', 'readmission')),
    state TEXT NOT NULL CHECK (state IN ('finalizing', 'completed')),
    started_at TEXT NOT NULL CHECK (
        length(started_at) BETWEEN 20 AND 30
        AND substr(started_at, 11, 1) = 'T'
        AND substr(started_at, -1, 1) = 'Z'
    ),
    completed_at TEXT CHECK (
        completed_at IS NULL
        OR (length(completed_at) BETWEEN 20 AND 30
            AND substr(completed_at, 11, 1) = 'T'
            AND substr(completed_at, -1, 1) = 'Z')
    ),
    authority_status TEXT NOT NULL
        CHECK (authority_status IN ('bound', 'legacy_completed')),
    operator_client_instance_id TEXT CHECK (
        operator_client_instance_id IS NULL
        OR (
            length(operator_client_instance_id) = 36
            AND substr(operator_client_instance_id, 15, 1) = '7'
            AND substr(operator_client_instance_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(operator_client_instance_id, 9, 1) = '-'
            AND substr(operator_client_instance_id, 14, 1) = '-'
            AND substr(operator_client_instance_id, 19, 1) = '-'
            AND substr(operator_client_instance_id, 24, 1) = '-'
            AND length(replace(operator_client_instance_id, '-', '')) = 32
            AND replace(operator_client_instance_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    operator_request_id TEXT CHECK (
        operator_request_id IS NULL
        OR (
            length(operator_request_id) = 36
            AND substr(operator_request_id, 15, 1) = '7'
            AND substr(operator_request_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(operator_request_id, 9, 1) = '-'
            AND substr(operator_request_id, 14, 1) = '-'
            AND substr(operator_request_id, 19, 1) = '-'
            AND substr(operator_request_id, 24, 1) = '-'
            AND length(replace(operator_request_id, '-', '')) = 32
            AND replace(operator_request_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    operator_request_digest BLOB CHECK (
        operator_request_digest IS NULL
        OR length(operator_request_digest) = 32
    ),
    operator_origin_boot_id TEXT CHECK (
        operator_origin_boot_id IS NULL
        OR (
            length(operator_origin_boot_id) = 36
            AND substr(operator_origin_boot_id, 15, 1) = '7'
            AND substr(operator_origin_boot_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(operator_origin_boot_id, 9, 1) = '-'
            AND substr(operator_origin_boot_id, 14, 1) = '-'
            AND substr(operator_origin_boot_id, 19, 1) = '-'
            AND substr(operator_origin_boot_id, 24, 1) = '-'
            AND length(replace(operator_origin_boot_id, '-', '')) = 32
            AND replace(operator_origin_boot_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    admission_event_id TEXT UNIQUE CHECK (
        admission_event_id IS NULL
        OR (
            length(admission_event_id) = 36
            AND substr(admission_event_id, 15, 1) = '7'
            AND substr(admission_event_id, 20, 1) IN ('8', '9', 'a', 'b')
            AND substr(admission_event_id, 9, 1) = '-'
            AND substr(admission_event_id, 14, 1) = '-'
            AND substr(admission_event_id, 19, 1) = '-'
            AND substr(admission_event_id, 24, 1) = '-'
            AND length(replace(admission_event_id, '-', '')) = 32
            AND replace(admission_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        )
    ),
    admission_proposal_digest BLOB CHECK (
        admission_proposal_digest IS NULL
        OR length(admission_proposal_digest) = 32
    ),
    UNIQUE (operator_client_instance_id, operator_request_id),
    CHECK (
        (state = 'finalizing' AND completed_at IS NULL)
        OR (state = 'completed' AND completed_at IS NOT NULL)
    ),
    CHECK (
        (authority_status = 'bound'
         AND operator_client_instance_id IS NOT NULL
         AND operator_request_id IS NOT NULL
         AND operator_request_digest IS NOT NULL
         AND operator_origin_boot_id IS NOT NULL)
        OR
        (authority_status = 'legacy_completed'
         AND state = 'completed'
         AND operator_client_instance_id IS NULL
         AND operator_request_id IS NULL
         AND operator_request_digest IS NULL
         AND operator_origin_boot_id IS NULL
         AND admission_event_id IS NULL
         AND admission_proposal_digest IS NULL)
    ),
    CHECK (
        authority_status = 'legacy_completed'
        OR
        (mode = 'rebootstrap'
         AND admission_event_id IS NULL
         AND admission_proposal_digest IS NULL)
        OR
        (mode IN ('new', 'readmission')
         AND admission_event_id IS NOT NULL
         AND admission_proposal_digest IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

INSERT INTO pairing_attempt_finalizations(
    attempt_id, mode, state, started_at, completed_at, authority_status
)
SELECT attempt_id, mode, state, started_at, completed_at, 'legacy_completed'
  FROM pairing_attempt_finalizations_legacy
 WHERE state = 'completed';

CREATE INDEX pairing_attempt_finalizations_state
    ON pairing_attempt_finalizations (state, started_at, attempt_id);

DROP TABLE pairing_attempt_finalizations_legacy;

-- Outbox work is lineage-bound independently of the signed event envelope.
-- Rebuilding removes a permissive default and proves every legacy row has its
-- exact local-request generation.
DROP INDEX outbox_scope_order;
ALTER TABLE outbox RENAME TO outbox_legacy;

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
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    origin_device_id TEXT NOT NULL CHECK (
        length(origin_device_id) = 67 AND substr(origin_device_id, 1, 3) = 'cc1'
        AND substr(origin_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    origin_scope_kind TEXT NOT NULL CHECK (
        origin_scope_kind IN ('agent', 'boot')
    ),
    origin_scope_id TEXT NOT NULL CHECK (
        length(origin_scope_id) = 36 AND substr(origin_scope_id, 15, 1) = '7'
        AND substr(origin_scope_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(origin_scope_id, 9, 1) = '-' AND substr(origin_scope_id, 14, 1) = '-'
        AND substr(origin_scope_id, 19, 1) = '-' AND substr(origin_scope_id, 24, 1) = '-'
        AND length(replace(origin_scope_id, '-', '')) = 32
        AND replace(origin_scope_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    origin_sequence INTEGER NOT NULL
        CHECK (origin_sequence BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL
        CHECK (length(CAST(kind AS BLOB)) BETWEEN 1 AND 64),
    signed_proposal_json TEXT NOT NULL CHECK (
        json_valid(signed_proposal_json)
        AND json_type(signed_proposal_json) = 'object'
    ),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('queued', 'forwarding')),
    queued_at TEXT NOT NULL CHECK (
        length(queued_at) BETWEEN 20 AND 30
        AND substr(queued_at, 11, 1) = 'T'
        AND substr(queued_at, -1, 1) = 'Z'
    ),
    UNIQUE (
        origin_device_id, origin_scope_kind, origin_scope_id, origin_sequence
    )
) STRICT;

INSERT INTO outbox(
    outbox_id, event_id, session_id, recovery_generation,
    origin_device_id, origin_scope_kind, origin_scope_id, origin_sequence,
    kind, signed_proposal_json, proposal_digest, state, queued_at
)
SELECT legacy.outbox_id, legacy.event_id, legacy.session_id,
       requests.recovery_generation, legacy.origin_device_id,
       legacy.origin_scope_kind, legacy.origin_scope_id,
       legacy.origin_sequence, legacy.kind, legacy.signed_proposal_json,
       legacy.proposal_digest, legacy.state, legacy.queued_at
  FROM outbox_legacy AS legacy
  JOIN local_requests AS requests
    ON requests.event_id = legacy.event_id
   AND requests.session_id = legacy.session_id
   AND requests.origin_device_id = legacy.origin_device_id
   AND requests.origin_scope_kind = legacy.origin_scope_kind
   AND requests.origin_scope_id = legacy.origin_scope_id
   AND requests.request_kind = legacy.kind
   AND requests.signed_proposal_json = legacy.signed_proposal_json
   AND requests.proposal_digest = legacy.proposal_digest
   AND requests.state IN ('signed', 'pending');

CREATE TABLE migration_0004_outbox_guard (
    missing_rows INTEGER NOT NULL CHECK (missing_rows = 0)
) STRICT;

INSERT INTO migration_0004_outbox_guard(missing_rows)
SELECT (SELECT count(*) FROM outbox_legacy) - (SELECT count(*) FROM outbox);

DROP TABLE migration_0004_outbox_guard;
DROP TABLE outbox_legacy;

CREATE INDEX outbox_scope_order
    ON outbox (
        origin_device_id, origin_scope_kind, origin_scope_id,
        origin_sequence, outbox_id
    );
