-- Pairing SAS agreement is not admission completion. Keep the existing
-- pairing_attempts wire-compatible state while recording durable finalization
-- separately so interrupted admission/rebootstrap can resume idempotently.
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
    CHECK (
        (state = 'finalizing' AND completed_at IS NULL)
        OR (state = 'completed' AND completed_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX pairing_attempt_finalizations_state
    ON pairing_attempt_finalizations (state, started_at, attempt_id);

-- Migration 2 did not revoke unfinished attempts when a successor was
-- installed. They are historical evidence, never successor-generation work.
UPDATE pairing_attempts
   SET state = 'revoked',
       terminal_at = coalesce(
           terminal_at,
           local_confirmed_at,
           remote_confirmed_at,
           created_at
       )
 WHERE state IN ('awaiting_sas', 'confirmed')
   AND NOT EXISTS (
       SELECT 1
         FROM pairing_invites AS invites
         JOIN consensus_state AS consensus
           ON consensus.session_id = invites.session_id
          AND consensus.recovery_generation = invites.recovery_generation
         JOIN genesis_records AS genesis
           ON genesis.session_id = consensus.session_id
          AND genesis.recovery_generation = consensus.recovery_generation
          AND genesis.workspace_id = invites.workspace_id
        WHERE invites.invite_id = pairing_attempts.invite_id
   );

-- Databases created by the preceding migration may contain SAS-complete rows.
-- They must resume finalization; migration must never claim admission finished.
INSERT INTO pairing_attempt_finalizations(attempt_id, mode, state, started_at)
SELECT attempts.attempt_id, invites.mode, 'finalizing', attempts.terminal_at
  FROM pairing_attempts AS attempts
  JOIN pairing_invites AS invites ON invites.invite_id = attempts.invite_id
  JOIN consensus_state AS consensus
    ON consensus.session_id = invites.session_id
   AND consensus.recovery_generation = invites.recovery_generation
  JOIN genesis_records AS genesis
    ON genesis.session_id = consensus.session_id
   AND genesis.recovery_generation = consensus.recovery_generation
   AND genesis.workspace_id = invites.workspace_id
 WHERE attempts.state = 'confirmed';
