-- LOCAL SUPPORT: durable, locally observed checkpoint-scheduling baseline.
-- The row names either the active generation boundary or its latest accepted
-- checkpoint event. It is excluded from projection commitments and snapshot
-- transfer, then rewritten from receiver-local time at every install.
CREATE TABLE checkpoint_cadence_state (
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
    recovery_generation INTEGER NOT NULL
        CHECK (recovery_generation BETWEEN 0 AND 9007199254740991),
    checkpoint_event_id TEXT CHECK (
            checkpoint_event_id IS NULL
            OR (
                length(checkpoint_event_id) = 36
                AND substr(checkpoint_event_id, 9, 1) = '-'
                AND substr(checkpoint_event_id, 14, 1) = '-'
                AND substr(checkpoint_event_id, 15, 1) = '7'
                AND substr(checkpoint_event_id, 19, 1) = '-'
                AND substr(checkpoint_event_id, 20, 1) IN ('8', '9', 'a', 'b')
                AND substr(checkpoint_event_id, 24, 1) = '-'
                AND length(replace(checkpoint_event_id, '-', '')) = 32
                AND replace(checkpoint_event_id, '-', '') NOT GLOB '*[^0-9a-f]*'
            )
        ),
    baseline_chain_index INTEGER NOT NULL
        CHECK (baseline_chain_index BETWEEN 0 AND 9007199254740991),
    baseline_result_index INTEGER NOT NULL
        CHECK (baseline_result_index BETWEEN 0 AND 9007199254740991),
    observed_at TEXT NOT NULL CHECK (
        length(observed_at) BETWEEN 20 AND 30
        AND substr(observed_at, 5, 1) = '-'
        AND substr(observed_at, 8, 1) = '-'
        AND substr(observed_at, 11, 1) = 'T'
        AND substr(observed_at, 14, 1) = ':'
        AND substr(observed_at, 17, 1) = ':'
        AND substr(observed_at, -1, 1) = 'Z'
    ),
    CHECK (baseline_chain_index <= baseline_result_index),
    CHECK (
        checkpoint_event_id IS NULL
        OR (baseline_chain_index >= 1 AND baseline_result_index >= 1)
    )
) STRICT;

-- Existing databases receive a conservative local baseline. The newest
-- pre-migration timestamp is receiver-local; using it can cause one early
-- checkpoint after upgrade but can never postpone one beyond a fresh interval.
WITH active AS (
    SELECT state.session_id,
           genesis.workspace_id,
           state.recovery_generation,
           coalesce(genesis.predecessor_chain_index, 0) AS boundary_chain_index,
           coalesce(genesis.predecessor_result_index, 0) AS boundary_result_index
      FROM consensus_state AS state
      JOIN genesis_records AS genesis
        ON genesis.session_id = state.session_id
       AND genesis.recovery_generation = state.recovery_generation
     WHERE state.singleton = 1
),
latest_checkpoint AS (
    SELECT results.event_id,
           results.chain_index,
           results.result_index
      FROM active
      JOIN chain_checkpoints AS checkpoints
        ON checkpoints.session_id = active.session_id
       AND checkpoints.workspace_id = active.workspace_id
       AND checkpoints.recovery_generation = active.recovery_generation
      JOIN command_results AS results
        ON results.event_id = checkpoints.checkpoint_event_id
       AND results.session_id = active.session_id
       AND results.workspace_id = active.workspace_id
       AND results.recovery_generation = active.recovery_generation
       AND results.kind = 'consensus.checkpoint'
       AND results.outcome_status = 'accepted'
     ORDER BY results.result_index DESC
     LIMIT 1
)
INSERT INTO checkpoint_cadence_state(
    singleton, session_id, workspace_id, recovery_generation,
    checkpoint_event_id, baseline_chain_index, baseline_result_index,
    observed_at
)
SELECT 1,
       active.session_id,
       active.workspace_id,
       active.recovery_generation,
       latest_checkpoint.event_id,
       coalesce(
           latest_checkpoint.chain_index,
           active.boundary_chain_index
       ),
       coalesce(
           latest_checkpoint.result_index,
           active.boundary_result_index
       ),
       (
           SELECT applied_at
             FROM schema_migrations
            ORDER BY version DESC
            LIMIT 1
       )
  FROM active
  LEFT JOIN latest_checkpoint ON 1 = 1;
