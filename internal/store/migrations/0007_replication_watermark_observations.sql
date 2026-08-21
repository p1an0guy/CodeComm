-- Independently signed equal-cursor observations are local evidence, not
-- contiguous replication attestations.
CREATE TABLE replication_watermark_observations (
    observation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(CAST(observation_id AS BLOB)) BETWEEN 1 AND 128
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
    recovery_generation INTEGER NOT NULL CHECK (
        recovery_generation BETWEEN 0 AND 9007199254740991
    ),
    relay_peer_device_id TEXT NOT NULL CHECK (
        length(relay_peer_device_id) = 67
        AND substr(relay_peer_device_id, 1, 3) = 'cc1'
        AND substr(relay_peer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    signer_device_id TEXT NOT NULL CHECK (
        length(signer_device_id) = 67
        AND substr(signer_device_id, 1, 3) = 'cc1'
        AND substr(signer_device_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    authority_voter_set_version INTEGER NOT NULL CHECK (
        authority_voter_set_version BETWEEN 1 AND 9007199254740991
    ),
    result_index INTEGER NOT NULL CHECK (
        result_index BETWEEN 0 AND 9007199254740991
    ),
    result_hash BLOB NOT NULL CHECK (length(result_hash) = 32),
    chain_index INTEGER NOT NULL CHECK (
        chain_index BETWEEN 0 AND result_index
    ),
    chain_hash BLOB NOT NULL CHECK (length(chain_hash) = 32),
    projection_accumulator BLOB NOT NULL CHECK (
        length(projection_accumulator) = 32
    ),
    projection_state_digest BLOB NOT NULL CHECK (
        length(projection_state_digest) = 32
    ),
    server_applied_result_index INTEGER NOT NULL CHECK (
        server_applied_result_index = result_index
    ),
    envelope_json TEXT NOT NULL CHECK (
        json_valid(envelope_json) AND json_type(envelope_json) = 'object'
    ),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    verified_at TEXT NOT NULL CHECK (
        length(verified_at) BETWEEN 20 AND 30
        AND substr(verified_at, 5, 1) = '-'
        AND substr(verified_at, 8, 1) = '-'
        AND substr(verified_at, 11, 1) = 'T'
        AND substr(verified_at, 14, 1) = ':'
        AND substr(verified_at, 17, 1) = ':'
        AND substr(verified_at, -1, 1) = 'Z'
        AND substr(verified_at, 1, 4) NOT GLOB '*[^0-9]*'
        AND substr(verified_at, 6, 2) NOT GLOB '*[^0-9]*'
        AND substr(verified_at, 9, 2) NOT GLOB '*[^0-9]*'
        AND substr(verified_at, 12, 2) NOT GLOB '*[^0-9]*'
        AND substr(verified_at, 15, 2) NOT GLOB '*[^0-9]*'
        AND substr(verified_at, 18, 2) NOT GLOB '*[^0-9]*'
        AND CAST(substr(verified_at, 1, 4) AS INTEGER) BETWEEN 1 AND 9999
        AND CAST(substr(verified_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(verified_at, 9, 2) AS INTEGER) BETWEEN 1 AND (
            CASE CAST(substr(verified_at, 6, 2) AS INTEGER)
                WHEN 2 THEN
                    CASE
                        WHEN CAST(substr(verified_at, 1, 4) AS INTEGER) % 400 = 0
                            OR (
                                CAST(substr(verified_at, 1, 4) AS INTEGER) % 4 = 0
                                AND CAST(substr(verified_at, 1, 4) AS INTEGER) % 100 <> 0
                            )
                        THEN 29
                        ELSE 28
                    END
                WHEN 4 THEN 30
                WHEN 6 THEN 30
                WHEN 9 THEN 30
                WHEN 11 THEN 30
                ELSE 31
            END
        )
        AND CAST(substr(verified_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(verified_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(verified_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
        AND (
            length(verified_at) = 20
            OR (
                length(verified_at) BETWEEN 22 AND 30
                AND substr(verified_at, 20, 1) = '.'
                AND substr(
                    verified_at,
                    21,
                    length(verified_at) - 21
                ) NOT GLOB '*[^0-9]*'
            )
        )
    ),
    UNIQUE (
        session_id,
        recovery_generation,
        signer_device_id,
        authority_voter_set_version
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX replication_watermark_observations_lineage_signer_authority
    ON replication_watermark_observations (
        session_id,
        workspace_id,
        recovery_generation,
        signer_device_id,
        authority_voter_set_version
    );

CREATE INDEX replication_watermark_observations_watermark
    ON replication_watermark_observations (
        session_id,
        workspace_id,
        recovery_generation,
        relay_peer_device_id,
        result_index,
        server_applied_result_index
    );
