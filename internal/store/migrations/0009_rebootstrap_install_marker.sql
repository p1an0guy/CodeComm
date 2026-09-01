-- Local-only crash gate for identity-preserving rebootstrap. The marker is
-- written in the same transaction as standalone snapshot installation and is
-- removed only after the local daemon has committed every required crash reap.
CREATE TABLE rebootstrap_install_marker (
    singleton INTEGER PRIMARY KEY
        REFERENCES settled_nonvoter_state(singleton) ON DELETE RESTRICT
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
    device_id TEXT NOT NULL
        REFERENCES devices(device_id) ON DELETE RESTRICT
        CHECK (
            length(device_id) = 67 AND substr(device_id, 1, 3) = 'cc1'
            AND substr(device_id, 4) NOT GLOB '*[^0-9a-f]*'
        ),
    snapshot_attestation_id TEXT NOT NULL
        REFERENCES replication_attestations(attestation_id) ON DELETE RESTRICT
        CHECK (
            length(CAST(snapshot_attestation_id AS BLOB)) BETWEEN 1 AND 128
        ),
    installed_at TEXT NOT NULL CHECK (
        length(installed_at) BETWEEN 20 AND 30
        AND substr(installed_at, 11, 1) = 'T'
        AND substr(installed_at, -1, 1) = 'Z'
    )
) STRICT;
