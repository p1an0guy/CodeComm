-- CodeComm Phase 3 local durability foundations.
-- The migration runner owns transactions, PRAGMAs, and schema_migrations rows.

-- LOCAL RAFT EVIDENCE: latest verified installed-snapshot baseline per generation.
CREATE TABLE raft_snapshot_installs (
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
    source_server_id TEXT NOT NULL CHECK (
        length(source_server_id) = 67 AND substr(source_server_id, 1, 3) = 'cc1'
        AND substr(source_server_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    snapshot_id TEXT NOT NULL CHECK (
        length(CAST(snapshot_id AS BLOB)) BETWEEN 1 AND 128
        AND snapshot_id NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    snapshot_index INTEGER NOT NULL CHECK (snapshot_index BETWEEN 1 AND 9007199254740991),
    snapshot_term INTEGER NOT NULL CHECK (snapshot_term BETWEEN 1 AND 9007199254740991),
    configuration_index INTEGER NOT NULL
        CHECK (configuration_index BETWEEN 1 AND snapshot_index),
    configuration_digest BLOB NOT NULL CHECK (length(configuration_digest) = 32),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    baseline_command_log_index INTEGER CHECK (
        baseline_command_log_index IS NULL
        OR baseline_command_log_index BETWEEN 1 AND snapshot_index
    ),
    baseline_command_term INTEGER CHECK (
        baseline_command_term IS NULL
        OR baseline_command_term BETWEEN 1 AND snapshot_term
    ),
    chain_index INTEGER NOT NULL CHECK (chain_index BETWEEN 0 AND 9007199254740991),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    result_index INTEGER NOT NULL CHECK (result_index BETWEEN 0 AND 9007199254740991),
    result_hash BLOB NOT NULL CHECK (length(result_hash) = 32),
    projection_accumulator BLOB NOT NULL CHECK (length(projection_accumulator) = 32),
    projection_state_digest BLOB NOT NULL CHECK (length(projection_state_digest) = 32),
    digest_version INTEGER NOT NULL CHECK (digest_version BETWEEN 1 AND 9007199254740991),
    projection_schema_version INTEGER NOT NULL
        CHECK (projection_schema_version BETWEEN 1 AND 9007199254740991),
    installed_at TEXT NOT NULL CHECK (
        length(installed_at) BETWEEN 20 AND 30
        AND substr(installed_at, 11, 1) = 'T'
        AND substr(installed_at, -1, 1) = 'Z'
    ),
    PRIMARY KEY (session_id, recovery_generation),
    UNIQUE (session_id, recovery_generation, snapshot_id),
    CHECK (
        (baseline_command_log_index IS NULL AND baseline_command_term IS NULL)
        OR (baseline_command_log_index IS NOT NULL AND baseline_command_term IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

-- LOCAL ONLY: one-use invite metadata. The invite secret and complete invite code
-- are deliberately absent; the secret exists only in the native credential store.
CREATE TABLE pairing_invites (
    invite_id TEXT PRIMARY KEY CHECK (
        length(invite_id) = 36 AND substr(invite_id, 15, 1) = '7'
        AND substr(invite_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(invite_id, 9, 1) = '-' AND substr(invite_id, 14, 1) = '-'
        AND substr(invite_id, 19, 1) = '-' AND substr(invite_id, 24, 1) = '-'
        AND length(replace(invite_id, '-', '')) = 32
        AND replace(invite_id, '-', '') NOT GLOB '*[^0-9a-f]*'
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
    issuer_device_id TEXT NOT NULL CHECK (
        length(issuer_device_id) = 67 AND substr(issuer_device_id, 1, 3) = 'cc1'
        AND substr(issuer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    invite_digest BLOB NOT NULL UNIQUE CHECK (length(invite_digest) = 32),
    mode TEXT NOT NULL CHECK (mode IN ('new', 'rebootstrap', 'readmission')),
    subject_device_id TEXT CHECK (
        subject_device_id IS NULL
        OR (
            length(subject_device_id) = 67 AND substr(subject_device_id, 1, 3) = 'cc1'
            AND substr(subject_device_id, 4) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    expected_entity_version INTEGER CHECK (
        expected_entity_version IS NULL
        OR expected_entity_version BETWEEN 1 AND 9007199254740991
    ),
    role TEXT NOT NULL CHECK (role IN ('owner', 'editor')),
    initial_credential_epoch INTEGER NOT NULL
        CHECK (initial_credential_epoch BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN (
        'preparing', 'outstanding', 'consumed', 'revoked',
        'expired', 'proof_exhausted', 'abandoned'
    )),
    proof_failures INTEGER NOT NULL DEFAULT 0 CHECK (proof_failures BETWEEN 0 AND 3),
    consumed_attempt_id TEXT UNIQUE,
    created_at TEXT NOT NULL CHECK (
        length(created_at) = 20 AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    expires_at TEXT NOT NULL CHECK (
        length(expires_at) = 20 AND substr(expires_at, 11, 1) = 'T'
        AND substr(expires_at, -1, 1) = 'Z'
    ),
    terminal_at TEXT CHECK (
        terminal_at IS NULL
        OR (length(terminal_at) BETWEEN 20 AND 30
            AND substr(terminal_at, 11, 1) = 'T'
            AND substr(terminal_at, -1, 1) = 'Z')
    ),
    CHECK (expires_at > created_at),
    FOREIGN KEY (invite_id, consumed_attempt_id)
        REFERENCES pairing_attempts(invite_id, attempt_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (mode = 'new' AND subject_device_id IS NULL
         AND expected_entity_version IS NULL AND initial_credential_epoch = 1)
        OR
        (mode = 'rebootstrap' AND subject_device_id IS NOT NULL
         AND expected_entity_version IS NULL)
        OR
        (mode = 'readmission' AND subject_device_id IS NOT NULL
         AND expected_entity_version IS NOT NULL AND initial_credential_epoch = 1)
    ),
    CHECK (
        (state = 'preparing' AND proof_failures = 0
         AND consumed_attempt_id IS NULL AND terminal_at IS NULL)
        OR
        (state = 'outstanding' AND invite_digest IS NOT NULL
         AND proof_failures < 3 AND consumed_attempt_id IS NULL AND terminal_at IS NULL)
        OR
        (state = 'consumed' AND invite_digest IS NOT NULL
         AND proof_failures < 3 AND consumed_attempt_id IS NOT NULL AND terminal_at IS NOT NULL)
        OR
        (state IN ('revoked', 'expired') AND invite_digest IS NOT NULL
         AND proof_failures < 3 AND consumed_attempt_id IS NULL AND terminal_at IS NOT NULL)
        OR
        (state = 'proof_exhausted' AND invite_digest IS NOT NULL
         AND proof_failures = 3 AND consumed_attempt_id IS NULL AND terminal_at IS NOT NULL)
        OR
        (state = 'abandoned' AND proof_failures < 3
         AND consumed_attempt_id IS NULL AND terminal_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX pairing_invites_issuer_state_expiry
    ON pairing_invites (issuer_device_id, state, expires_at, invite_id);
CREATE INDEX pairing_invites_lineage_state
    ON pairing_invites (session_id, recovery_generation, state, invite_id);

-- LOCAL ONLY: bounded proof failures and the sole SAS attempt accepted per invite.
CREATE TABLE pairing_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36 AND substr(attempt_id, 15, 1) = '7'
        AND substr(attempt_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(attempt_id, 9, 1) = '-' AND substr(attempt_id, 14, 1) = '-'
        AND substr(attempt_id, 19, 1) = '-' AND substr(attempt_id, 24, 1) = '-'
        AND length(replace(attempt_id, '-', '')) = 32
        AND replace(attempt_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    invite_id TEXT NOT NULL REFERENCES pairing_invites(invite_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    request_core_json TEXT NOT NULL CHECK (
        length(CAST(request_core_json AS BLOB)) BETWEEN 2 AND 65536
        AND json_valid(request_core_json) AND json_type(request_core_json) = 'object'
    ),
    transcript_hash BLOB NOT NULL CHECK (length(transcript_hash) = 32),
    joiner_device_id TEXT NOT NULL CHECK (
        length(joiner_device_id) = 67 AND substr(joiner_device_id, 1, 3) = 'cc1'
        AND substr(joiner_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN (
        'proof_rejected', 'awaiting_sas', 'confirmed',
        'declined', 'expired', 'revoked'
    )),
    local_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (local_confirmed IN (0, 1)),
    remote_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (remote_confirmed IN (0, 1)),
    local_confirmed_at TEXT CHECK (
        local_confirmed_at IS NULL
        OR (length(local_confirmed_at) BETWEEN 20 AND 30
            AND substr(local_confirmed_at, 11, 1) = 'T'
            AND substr(local_confirmed_at, -1, 1) = 'Z')
    ),
    remote_confirmed_at TEXT CHECK (
        remote_confirmed_at IS NULL
        OR (length(remote_confirmed_at) BETWEEN 20 AND 30
            AND substr(remote_confirmed_at, 11, 1) = 'T'
            AND substr(remote_confirmed_at, -1, 1) = 'Z')
    ),
    declined_by TEXT CHECK (declined_by IS NULL OR declined_by IN ('local', 'remote')),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 20 AND 30
        AND substr(created_at, 11, 1) = 'T'
        AND substr(created_at, -1, 1) = 'Z'
    ),
    terminal_at TEXT CHECK (
        terminal_at IS NULL
        OR (length(terminal_at) BETWEEN 20 AND 30
            AND substr(terminal_at, 11, 1) = 'T'
            AND substr(terminal_at, -1, 1) = 'Z')
    ),
    UNIQUE (attempt_id, request_digest),
    UNIQUE (invite_id, attempt_id),
    CHECK (
        (local_confirmed = 0 AND local_confirmed_at IS NULL)
        OR (local_confirmed = 1 AND local_confirmed_at IS NOT NULL)
    ),
    CHECK (
        (remote_confirmed = 0 AND remote_confirmed_at IS NULL)
        OR (remote_confirmed = 1 AND remote_confirmed_at IS NOT NULL)
    ),
    CHECK (
        (state = 'proof_rejected' AND local_confirmed = 0
         AND remote_confirmed = 0 AND declined_by IS NULL AND terminal_at IS NOT NULL)
        OR
        (state = 'awaiting_sas' AND local_confirmed + remote_confirmed < 2
         AND declined_by IS NULL AND terminal_at IS NULL)
        OR
        (state = 'confirmed' AND local_confirmed = 1
         AND remote_confirmed = 1 AND declined_by IS NULL AND terminal_at IS NOT NULL)
        OR
        (state = 'declined' AND declined_by IS NOT NULL AND terminal_at IS NOT NULL)
        OR
        (state IN ('expired', 'revoked') AND declined_by IS NULL AND terminal_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX pairing_attempts_one_accepted_per_invite
    ON pairing_attempts (invite_id)
    WHERE state <> 'proof_rejected';
CREATE INDEX pairing_attempts_invite_created
    ON pairing_attempts (invite_id, created_at, attempt_id);

-- LOCAL ONLY: durable, idempotent native-store deletion work.
CREATE TABLE pairing_secret_deletions (
    invite_id TEXT PRIMARY KEY REFERENCES pairing_invites(invite_id),
    session_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN (
        'consumed', 'revoked', 'expired', 'proof_exhausted',
        'abandoned', 'generation_changed'
    )),
    queued_at TEXT NOT NULL CHECK (
        length(queued_at) BETWEEN 20 AND 30
        AND substr(queued_at, 11, 1) = 'T'
        AND substr(queued_at, -1, 1) = 'Z'
    ),
    failure_count INTEGER NOT NULL DEFAULT 0
        CHECK (failure_count BETWEEN 0 AND 9007199254740991),
    last_failure_at TEXT CHECK (
        last_failure_at IS NULL
        OR (length(last_failure_at) BETWEEN 20 AND 30
            AND substr(last_failure_at, 11, 1) = 'T'
            AND substr(last_failure_at, -1, 1) = 'Z')
    ),
    last_error_code TEXT CHECK (
        last_error_code IS NULL
        OR (length(CAST(last_error_code AS BLOB)) BETWEEN 1 AND 64
            AND last_error_code NOT GLOB '*[^a-z0-9_]*')
    ),
    CHECK (
        (failure_count = 0 AND last_failure_at IS NULL AND last_error_code IS NULL)
        OR (failure_count > 0 AND last_failure_at IS NOT NULL AND last_error_code IS NOT NULL)
    )
) STRICT;

CREATE INDEX pairing_secret_deletions_queue
    ON pairing_secret_deletions (failure_count, queued_at, invite_id);

CREATE TRIGGER pairing_invite_terminal_insert_cleanup
AFTER INSERT ON pairing_invites
WHEN NEW.state IN ('consumed', 'revoked', 'expired', 'proof_exhausted', 'abandoned')
BEGIN
    INSERT OR IGNORE INTO pairing_secret_deletions(
        invite_id, session_id, reason, queued_at, failure_count
    ) VALUES (NEW.invite_id, NEW.session_id, NEW.state, NEW.terminal_at, 0);
END;

CREATE TRIGGER pairing_invite_terminal_update_cleanup
AFTER UPDATE OF state ON pairing_invites
WHEN OLD.state <> NEW.state
 AND NEW.state IN ('consumed', 'revoked', 'expired', 'proof_exhausted', 'abandoned')
BEGIN
    INSERT OR IGNORE INTO pairing_secret_deletions(
        invite_id, session_id, reason, queued_at, failure_count
    ) VALUES (NEW.invite_id, NEW.session_id, NEW.state, NEW.terminal_at, 0);
END;
