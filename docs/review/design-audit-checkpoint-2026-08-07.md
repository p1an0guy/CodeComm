# Design Audit Checkpoint

Paused: 2026-08-07

This file is non-authoritative working state. The split files in `docs/design/` remain the design.
Do not begin implementation until this audit is finished and the owner reviews its final summary.

## Completed

- Read all 14 split design parts and the reading guide.
- Repaired identity/pairing:
  - canonical successor-genesis multi-signature input;
  - canonical UUID, timestamp, and Git OID forms;
  - immutable `primitive_suite_version` and `protocol_policy_version`;
  - consistent `credential_clock_skew_seconds`;
  - revocation advertisement timing;
  - explicit `new`, `rebootstrap`, and recovery `readmission` pairing modes.
- Repaired event/control semantics:
  - nullable `last_raft_applied_log_index` in acknowledgements;
  - one-use agent-launch registration and bind flow;
  - local-only rejection of client-supplied `origin`;
  - post-start agent-profile equality;
  - action-target grammar by action type;
  - settled-nonvoter replication attestations and currency semantics;
  - actionable claims, task-update ownership, blocked-reason, path-lease-count, and publication
    author/origin reducer checks;
  - one audit record per reporter observation rather than global request deduplication.
- Repaired persistence:
  - per-agent context files;
  - `replication_attestations`, `agent_launches`, and `managed_roots`;
  - no fabricated Raft provenance/index from result imports;
  - distinct Raft-participant and settled-nonvoter backups;
  - reducer-level task ownership/actionability checks.
- Repaired agent/MCP semantics:
  - `codecomm agent launch` registration flow;
  - direct vendor/MCP launch fails without a selector;
  - no launch into a pre-existing user root;
  - root-mutating Git operations require zero pending launches and zero live/resumable bindings;
  - publication `terminal_source` and `canonical_lineage_member`;
  - binding-specific generated context and no global context files.
- Repaired architecture/recovery:
  - mode-specific definitions of up-to-date;
  - recovery accepts verified Raft evidence or contiguous signed result attestations;
  - survivor rank uses verified `result_index`, not Raft index;
  - nonterminal publications withdraw at recovery;
  - canonical rollback releases excluded historical publication pins;
  - draft streams retire while retained snapshots remain historical;
  - survivors return through readmission pairing;
  - supervisor registry canonicalizes filesystem and repository identities.
- Repaired Git synchronization:
  - `refs/codecomm/**` is reserved;
  - all final ref writes use expected-old-OID CAS and fail as `ref-tampered`;
  - draft advertisements require active applied membership;
  - revocation blocks future advertisements but preserves already imported immutable snapshots;
  - recovery-excluded applied publications do not pin forever;
  - managed-root launch and mutation wording now matches the agent section;
  - user-repository canonical materialization uses durable expected-old-OID CAS.
- Added primitive/protocol-policy and per-agent-context constants.

Files already edited:

- `docs/design/01-architecture-and-consensus.md`
- `docs/design/02-identity-and-pairing.md`
- `docs/design/03-transport-credentials.md`
- `docs/design/04-control-protocol-and-events.md`
- `docs/design/05-persistence-and-coordination.md`
- `docs/design/06-agents-and-mcp.md`
- `docs/design/07-git-synchronization.md`
- `docs/design/10-implementation-and-constants.md`

## Exact Restart Point

Resume at plan step 2: propagate the settled decisions into:

- `docs/design/00-overview-and-scope.md`
- `docs/design/08-ux-lifecycle-and-failures.md`
- `docs/design/09-security-and-privacy.md`
- `docs/design/12-delivery-targets-and-open-questions.md`

Then update tests and ADRs:

- `docs/design/11-test-strategy.md`
- `docs/design/13-adr-backlog-and-references.md`

Finally update:

- `docs/design/README.md`
- `docs/design.md`

## Required Test Additions

- Settled-nonvoter attestations, backup/restore, recovery eligibility, and absence of fabricated
  Raft provenance.
- Per-agent context files, shared-root isolation, and no global-context cross-talk.
- Launch-selector reservation, crash/rebind, replay/concurrent-consumer rejection, pre-existing-root
  refusal, and root-mutation blocking while a launch is pending.
- Canonical anchor/repository alias rejection.
- Reserved-ref inventory, external tampering, and expected-old-OID CAS failure.
- Recovery withdrawal of nonterminal publications, draft retirement, canonical rollback retention,
  and readmission pairing.
- Canonical UUID/timestamp/Git OID forms and immutable genesis suite/policy versions.
- New reducer preconditions, action-target grammar, and independent-reporter audit multiplicity.

Known stale test text:

- `docs/design/11-test-strategy.md` still describes global `context.json`/`context.md`.
- Its durability bullet still says ambiguous
  `applied_index <= last Raft log index`; use `last_raft_applied_log_index` and scope it to Raft
  participants.
- Integration scenario 19 and delivery phase 6 still say survivors “re-pair”; use explicit
  readmission.

## ADR Work

Allocate ADR-100 onward for:

1. Canonical protocol scalar forms and immutable primitive/protocol-policy versions.
2. Settled-nonvoter evidence, backup, currency, and recovery ranking.
3. One-use launch registrations plus canonical managed-root/repository identities.
4. Binding-specific per-agent context files.
5. Reserved CodeComm refs with expected-old-OID CAS.
6. Recovery publication/draft retention and explicit readmission.
7. Closed reducer preconditions/action targets and per-reporter audit observations.

## Final Verification

Run stale-term scans for:

- generic `applied_index` / `applied log index`;
- global `context.json` / `context.md`;
- old agent-bind wording;
- old clock-skew name;
- generic recovery “re-pair” wording;
- global “one request gets one audit” wording;
- revision `0.13`.

Validate:

- relative Markdown links;
- section references and headings;
- fenced blocks and tables;
- reading-guide line counts;
- all constants referenced by protocol rules;
- all event kinds against entities, reducers, surfaces, and tests;
- revision/status consistency.

Perform a final concision pass. Only after all checks pass, promote the authoritative set from
revision 0.13 to 0.14 and mark it accepted. The final response must give the owner a section-by-
section summary of every fix plus verification results for independent review.

## Backups

- `/tmp/codecomm-design-preaudit-20260807.tgz`
- `/tmp/codecomm-design-prefinal-20260807.tgz`
- `/tmp/codecomm-design-pre-0.14-final-audit.tgz`

No Git repository is present, so these archives are the available pre-audit references.
