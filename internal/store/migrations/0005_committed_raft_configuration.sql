-- The consensus FSM persists only configurations delivered after Raft commits
-- them. This local record is authorization evidence, not replicated state.
CREATE TABLE raft_committed_configuration (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
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
    log_index INTEGER NOT NULL
        CHECK (log_index BETWEEN 1 AND 9007199254740991),
    configuration_json TEXT NOT NULL CHECK (
        length(CAST(configuration_json AS BLOB)) BETWEEN 1 AND 4096
        AND json_valid(configuration_json)
        AND json_type(configuration_json) = 'object'
    ),
    configuration_digest BLOB NOT NULL
        CHECK (length(configuration_digest) = 32)
) STRICT;
