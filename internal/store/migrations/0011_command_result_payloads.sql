-- Compact immutable command-result payloads without changing any committed
-- proposal, outcome, mutation, or hash bytes.
CREATE TABLE command_result_payloads (
    result_index INTEGER PRIMARY KEY
        REFERENCES command_results(result_index) ON DELETE CASCADE,
    codec_version INTEGER NOT NULL CHECK (codec_version = 1),
    uncompressed_size INTEGER NOT NULL
        CHECK (uncompressed_size BETWEEN 26 AND 37748736),
    uncompressed_sha256 BLOB NOT NULL
        CHECK (length(uncompressed_sha256) = 32),
    compressed_payload BLOB NOT NULL
        CHECK (length(compressed_payload) BETWEEN 1 AND 37748736)
) STRICT;

-- This marker authenticates the pre-migration source rows independently of
-- the transformed sentinel columns. Later results are outside its fixed cut.
CREATE TABLE command_result_payload_migration (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    source_result_count INTEGER NOT NULL
        CHECK (source_result_count BETWEEN 0 AND 9007199254740991),
    source_fingerprint BLOB NOT NULL CHECK (length(source_fingerprint) = 32),
    sqlite_rebuild_required INTEGER NOT NULL
        CHECK (sqlite_rebuild_required IN (0, 1))
) STRICT;

DROP INDEX local_requests_session_state;
DROP INDEX local_requests_scope_state;

CREATE INDEX local_requests_session_state
    ON local_requests (session_id, recovery_generation, state)
    WHERE state IN ('preparing', 'signed', 'pending');
CREATE INDEX local_requests_scope_state
    ON local_requests (origin_scope_kind, origin_scope_id, state)
    WHERE state IN ('preparing', 'signed', 'pending');
