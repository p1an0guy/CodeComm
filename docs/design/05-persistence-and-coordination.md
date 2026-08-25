# CodeComm V1 Design — Part 06: Persistence and Coordination Semantics

Part 6 of 14. Contents: §6 domain model, local state, coordination semantics, ownership release and operator override.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 6. Persistence and Coordination Semantics

### 6.1 Domain model

Every entity below is initialized by genesis and/or projected from signed events (§5.2). Mutable entities carry
`entity_version`, starting at 1 and incremented by accepted mutation; immutable append-only rows do
not. Mutations require the version except the explicitly atomic session-end cascade and conditional
admission of §5.4. Bounds are reducer-enforced on every replica. Strings are UTF-8 with byte bounds.

**Task** — the unit of claimable work.

| Field | Type | Notes |
|---|---|---|
| `task_id` | UUIDv7 | Origin-generated |
| `title` | string, 1-200 | Required; single line, control characters rejected |
| `body` | string, ≤8192 | Optional; untrusted display text (§7.3) |
| `state` | enum | §6.3 state machine |
| `state_reason` | string?, ≤1024 | Required only in `blocked`; null in every other state |
| `priority` | integer 0-3 | 0 highest; ordering hint only, never an authorization |
| `blocked_by` | sorted unique [`task_id`], ≤16 | Hard prerequisites; cycles rejected |
| `labels` | [string ≤32], ≤16 | Free-form, deduplicated, sorted on apply |
| `owner_device_id` | `device_id`? | Set on claim, cleared on release |
| `owner_agent_session_id` | `agent_session_id`? | Set with `owner_device_id`; both null or both set |
| `intended_device_id` | `device_id`? | One-shot reassignment target; only that device may claim, and a successful claim clears it |
| `last_release_reason` | enum? | `voluntary`, `forced`, `session_ended`, or `recovery`; cleared on claim |
| `entity_version` | integer ≥1 | Compare-and-set token |
| `created_at`, `updated_at` | RFC 3339 | Display only; never read by a reducer |

`blocks` is **derived**, never stored: it is the reverse index of `blocked_by`. A task is
*actionable*, also derived, when `state = ready`, no unresolved merge conflict references it,
and every `blocked_by` task is `done`; it is claimable by a given device only when
`intended_device_id` is null or names that device. `blocked_by` MUST reference existing tasks in the
same session and MUST NOT reference the task itself. To validate a create/update, the reducer walks
outbound `blocked_by` edges breadth-first. At each depth it unions unseen IDs and visits that level in
ascending ID order, reading each non-subject task once. Naming the subject in the candidate or any
visited edge immediately rejects `dependency_cycle`; otherwise attempting to read distinct task
`task_dependency_walk_max + 1` rejects `dependency_graph_too_complex`. Exactly the limit is allowed.
This fail-closed committed bound makes cycle validation deterministic and prevents one event from
scanning unbounded retained state; accepted edges therefore remain a DAG.

**Plan revision** — an immutable proposal for how work is organized.

| Field | Type | Notes |
|---|---|---|
| `plan_revision_id` | UUIDv7 | Immutable once accepted |
| `supersedes` | `plan_revision_id`? | The revision this was drafted against |
| `title` | string, 1-200 | Required |
| `body` | string, ≤65536 | Markdown; untrusted display text |
| `task_ids` | sorted unique [`task_id`], ≤512 | Existing tasks this revision organizes; membership only, no ordering authority |
| `proposed_by_device_id` | `device_id` | Committed, not self-asserted |
| `created_at` | RFC 3339 | Display only |

Revisions are append-only and never mutated, so they carry no `entity_version`. Exactly
one revision per session is *current*, named by a separate committed pointer holding
`(plan_revision_id, entity_version)`; selecting a new current revision is a
compare-and-set against that pointer.

**Current plan pointer** — one digest-covered row for the active generation.

| Field | Type | Notes |
|---|---|---|
| `session_id` | UUIDv7 | Primary key; remapped by the §3.1 recovery transform |
| `plan_revision_id` | UUIDv7? | Null only at `entity_version = 1` before first selection; otherwise names a retained revision |
| `entity_version` | integer ≥1 | CAS token for `plan.current_selected` |

**Memory record** — durable shared context.

| Field | Type | Notes |
|---|---|---|
| `memory_id` | UUIDv7 | Immutable |
| `scope` | enum: `session`, `task` | Determines whether `task_id` is required |
| `task_id` | `task_id`? | Required when `scope = task`, else null |
| `key` | string, 1-128 | Namespacing hint; not unique |
| `body` | string, ≤16384 | Untrusted display text |
| `supersedes` | `memory_id`? | Forms a chain, never a cycle |
| `created_at` | RFC 3339 | Display only |

Append-only: a correction is a new record superseding the old. A record MUST NOT
supersede one that is already superseded, and both rows must have the same
`(scope, task_id, key)`, keeping correction history a chain rather than a tree or cross-scope alias.

**Lease** — an advisory, expiring reservation.

| Field | Type | Notes |
|---|---|---|
| `lease_id` | UUIDv7 | Immutable |
| `holder_device_id` | `device_id` | From the committed actor binding |
| `holder_agent_session_id` | `agent_session_id` | Released when that session ends (§6.4) |
| `scope` | enum: `task`, `path` | |
| `task_id` | `task_id`? | Required for task scope; optional existing-task association for path scope |
| `path_globs` | sorted unique [string ≤512], 1–32 | Required for path scope and prohibited for task scope; each is an exact canonical path or one terminal-prefix form `dir/**` (§8.4) |
| `ttl_seconds` | integer | Requested lifetime within committed minimum/maximum; resets on accepted renewal |
| `status` | enum: `active`, `released` | Released leases remain for audit/CAS history |
| `release_reason` | enum? | `voluntary`, `forced`, `expired`, `session_ended`, or `recovery` when released |
| `entity_version` | integer ≥1 | |

Expiry is an ordinary CAS-protected `lease.released(expired)` event; a same-process monotonic timer
schedules its proposal but never runs inside a reducer (§6.3). Leases are advisory and cannot stop another
process running as the same OS user from editing a path (§7.2).

**Intersecting active leases are rejected at apply time.** New lease IDs cannot provide CAS against
one another, so the reducer compares scopes directly. Task leases intersect on equal `task_id`.
Acquiring a task-scope lease additionally requires the actor to hold that task; release of the task
does not silently release the lease, so the holder must release it or session end/expiry does.
When a path lease carries the optional `task_id`, that task must exist but need not be held by the
actor; the association supplies activity context and does not grant task or path authority.
Path syntax is deliberately restricted to exact paths and terminal directory prefixes `dir/**`:
exact/exact intersects on equality, prefix/exact when the prefix contains it, and prefix/prefix when
one contains the other. Comparison uses §8.4 canonical case-sensitive bytes, independent of host
filesystem behavior. This finite grammar makes intersection deterministic without implementing a
general glob solver; any other metacharacter is rejected. Thus exactly one strong winner exists for
every overlapping V1 lease scope, although same-UID processes can still ignore the advisory result.

**Activity record** — what an agent/human reports or a daemon directly observes. Bounded,
append-only, and projected
from events rather than separately mutable: `(kind, task_id?, actions[],
rationale_summary, capture_level, redaction)` as carried in the §5.2 envelope.
High-frequency presence is ephemeral and never durable (§7.2).

**Origin scope** — protocol state that makes signed per-origin ordering deterministic.

| Field | Type | Notes |
|---|---|---|
| `device_id` | `device_id` | Composite primary key |
| `scope_kind` | enum: `agent`, `boot` | Selects the scope ID type |
| `scope_id` | UUIDv7 | Agent session or daemon boot ID |
| `last_sequence` | integer ≥1 | Greatest consumed sequence; advances on a structurally valid next command even when its domain outcome rejects (§5.2) |

Agent scopes are created by the first structurally valid `agent.session.started`, even when a later
domain check rejects it; only acceptance creates the agent-session entity, so a rejected start burns
that ID. A boot scope is likewise created by its first structurally valid human/daemon command even
if later checks reject. Exact duplicates do not mutate a scope. Recovery drops all old-generation
scope rows; retained results preserve their history.

**Audit counter** — bounded rejection-audit protocol state, one row per enrolled device.

| Field | Type | Notes |
|---|---|---|
| `device_id` | `device_id` | Primary key |
| `credential_epoch` | integer ≥0 | Latest committed epoch; 0 from genesis/admission until first authorization |
| `accepted_count` | integer ≥0 | Accepted `audit.recorded` events in that epoch |

Genesis and admission create the row at epoch/count zero. `credential.authorized` advances the epoch
and resets the count; an accepted `audit.recorded` increments it. This replaces a history scan and
is reducer input, so both tables are digest-covered.

**Device** — a member, projected from `membership.*`.

| Field | Type | Notes |
|---|---|---|
| `device_id` | string | §4.1 |
| `role` | enum: `owner`, `editor` | Current committed role |
| `identity_public_key` | bytes | Ed25519; retained after revocation for verification (§4.2) |
| `daemon_version` | ASCII SemVer, ≤64 bytes | Last committed product release |
| `max_apply_level` | integer | Reducer compatibility advertised by that release (§5.5) |
| `status` | enum: `active`, `requires_readmission`, `revoked` | Recovery preserves keys but removes authority; revoked keys are never deleted |
| `entity_version` | integer ≥1 | |

Device voter status is a query-time view of membership in `voter_set`; it is neither stored in nor
digest-covered with `devices` (§3).

**Credential authorization** — append-only epoch authority used by content mTLS.

| Field | Type | Notes |
|---|---|---|
| `session_id`, `device_id`, `epoch` | IDs, integer ≥1 | Composite primary key; epoch is contiguous per `(session, device)` |
| `epoch_public_key`, `key_digest` | 32 bytes each | Ed25519 key and SHA-256 digest |
| `role` | enum: `owner`, `editor` | Historical display/audit only; authorization reads current membership |
| `issued_at`, `not_before` | whole-second UTC RFC 3339 | Endorsed values; `not_after = not_before + validity_seconds` |
| `validity_seconds` | integer | Exactly committed `credential_epoch_seconds` |
| `authority_voter_set_version` | integer ≥1 | Activated authority against which endorsements validate |
| `clock_endorsements` | sorted array, ≤5 | Closed objects `(device_id, signature)`, distinct authority majority |
| `binding_signature` | 64 bytes | Subject identity signature (§4.6) |
| `authorization_chain_index` | integer ≥1 | Apply-assigned accepted-event position carried by the certificate; never a proposal field |

Rows are immutable. The currently acceptable rows are derived from committed intervals and local
time; old rows remain for certificate, audit, and recovery verification.
Loading retained predecessor-session rows is not historical authority proof: replay or logical
snapshot import MUST first verify the event/result chains, authority handoffs, and projection
accumulator covering those exact rows. A projection loader can recheck identity signatures and
per-`(session, device)` epoch continuity, but the singleton current `credential_authority` row
cannot reconstruct prior authority membership or quorum. New authorizations always validate
against the current activated authority.

**Control-file proposal** — append-only review input, not replicated consent.

| Field | Type | Notes |
|---|---|---|
| `proposal_event_id` | UUIDv7 | Primary key; the proposing event ID |
| `session_id` | UUIDv7 | Active generation at proposal |
| `path` | canonical repository path | Also the event `entity_id` |
| `operation` | enum: `upsert`, `delete` | Explicit; an empty file is not a deletion |
| `content_digest` | SHA-256? | Required for `upsert`, including empty bytes; null for `delete` |
| `content_size` | integer | `0..control_file_max_bytes` for `upsert`; exactly 0 for `delete` |
| `diff` | UTF-8 string, ≤64 KiB | Review aid only, never transport authority |
| `proposed_by_device_id` | `device_id` | From event origin |
| `chain_index` | integer ≥1 | Apply-assigned position defining the latest proposal per path; never a proposal field |

All proposals remain auditable; the current proposal for a path is the greatest `chain_index`.
`control_file_approvals` keys its local decision by proposal event, operation, and nullable digest,
so a newer proposal never inherits old consent.

**Session policy** — the mutable half of committed genesis policy, projected from
`policy.changed`. One row per session, so `session_id` is both `entity_id` and primary key (§4.2).
Every reducer reads committed policy, so this row is digest-covered (§5.6): a divergent policy row
would silently produce divergent verdicts on every other kind.

| Field | Type | Notes |
|---|---|---|
| `session_id` | string | §4.2; the sole row's key |
| `values` | object | Mutable committed policy keys and their current values, initialized from the genesis record (§4.2). Immutable keys are not stored here and cannot be proposed |
| `entity_version` | integer ≥1 | CAS token for `policy.changed` |

**Agent session** — a running agent instance, projected from `agent.session.*`.

| Field | Type | Notes |
|---|---|---|
| `agent_session_id` | UUIDv7 | Never reused (§4.2) |
| `device_id` | `device_id` | Owning device |
| `client_kind` | enum: `codex`, `claude`, `other` | |
| `agent_profile_id` | string? | Optional stable persona, 1-128 bytes when set; immutable and matched by every later agent origin |
| `state` | enum | `starting`, `idle`, `claimed`, `working`, `blocked`, `disconnected`, or terminal `ended` |
| `resume_state` | enum? | Prior connected state while `disconnected`; null otherwise |
| `working_root_id` | UUIDv7 | Opaque daemon-minted binding; the local path never replicates (§7.2) |
| `end_reason` | enum? | `clean`, `disconnect_timeout`, `operator`, `crash_reap`, or `recovery`; set only on terminal end |
| `entity_version` | integer ≥1 | |

Creation sets `state = starting`, with null `resume_state` and `end_reason`. An agent may report
`starting → idle` and transitions among `idle`, `claimed`, `working`, and `blocked`; these are status,
not substitutes for task/lease authorization. Only the owning device's daemon may move any connected
live state to `disconnected`, atomically storing that state in `resume_state`. After validating the
local resume capability it may move `disconnected` only to that stored state and clear
`resume_state`. `agent.session.ended`, not `state_changed`, enters terminal `ended`, clears
`resume_state`, and sets `end_reason`. Every mutation CASes the same session version, so resume and
reaping cannot both win; no transition leaves `ended`. For `max_active_agent_sessions`, active means
every non-`ended` row, independent of ephemeral presence or current device status; retained ended
rows do not count. Every ordinary retained session has its agent origin scope; the sole missing-scope
case is an `ended(recovery)` historical row carried into a successor after §3.1 drops predecessor
scopes. The transform normalizes both terminal and nonterminal predecessor sessions to that state;
such a row MUST have no successor-generation scope, and its retained ID cannot be rebound.

**Canonical ref** — the replicated repository pointer, initialized to the verified bootstrap
commit. V1 has one row and never maps it directly to a user's branch.

| Field | Type | Notes |
|---|---|---|
| `ref_name` | string | Fixed `refs/codecomm/canonical`; row key, never a user ref |
| `commit_oid` | algorithm-tagged Git OID | Commit selected by the latest applied publication |
| `entity_version` | integer ≥1 | Second CAS token carried by `publication.applied` (§7.2) |

**Merge conflict** — a committed record of an immutable Git merge result.

| Field | Type | Notes |
|---|---|---|
| `conflict_id` | string | Deterministic `ccf1` digest defined in §8.3 |
| `publication_id` | UUIDv7 | Candidate publication; determines task and author |
| `merge_kind` | enum: `merge`, `rebase` | Operation class |
| `replay_commit_oid` | Git OID? | Required for a rebase step; null for merge |
| `merge_base_oids` | [Git OID], ≤16 | Sorted immutable graph inputs |
| `canonical_commit`, `candidate_commit` | Git OIDs | Immutable tips |
| `paths` | [canonical path], ≤2048 | Sorted unique detector output; excluded from ID (§8.3) |
| `status` | enum: `unresolved`, `resolved` | |
| `resolution_kind` | enum?: `publication`, `forced` | Null while unresolved |
| `resolution_publication_id` | UUIDv7? | Required only for `publication`; applied merge containing both tips |
| `force_reason` | string?, ≤1024 | Required only for owner-forced resolution |
| `resolved_by_device_id` | `device_id`? | Event origin; null while unresolved |
| `entity_version` | integer ≥1 | CAS token for resolution |

**Voter set** — the committed consensus target, projected from `membership.voter_set_changed` and
target-voter `membership.device_revoked` events. Revoking a nonvoter validates the row's CAS and exact
unchanged target but emits no voter-set mutation. One row per session, so `session_id` is both
`entity_id` and primary key (§4.2).

| Field | Type | Notes |
|---|---|---|
| `session_id` | string | §4.2; the sole row's key |
| `voter_device_ids` | array of string | The committed target, sorted ascending so the digest is order-independent of proposal order; length 1, 3, or 5 at rest (§3) |
| `voter_set_version` | integer ≥1 | CAS token; `membership.device_revoked` carries it as `expected_voter_set_version` (§3, §5.4) |

This entity is the target, never the Raft library's live configuration. That configuration lives
in the library's own stable store under `consensus/` (§6.2).
`raft_committed_configuration` mirrors only the latest post-commit callback so authorization never
consults the library's possibly uncommitted latest configuration. It is local evidence, not a
projection or protocol-digest-covered state: replicas mid-reconciliation legitimately hold
different live configurations while agreeing on this row (§3, §5.6).

**Credential authority** — the last voter target proven active by §3's handoff, kept separate so an
unreachable desired target cannot deadlock renewal.

| Field | Type | Notes |
|---|---|---|
| `session_id` | UUIDv7 | Primary key and `membership.voter_set_activated` entity ID |
| `voter_device_ids` | sorted array of `device_id` | Exactly one previously committed target; 1, 3, or 5 active devices |
| `voter_set_version` | integer ≥1 | Target version activated by the latest valid handoff; CAS token for the next handoff |
| `activation_source` | enum: `genesis`, `handoff` | Initial and recovery-generation rows use `genesis`; an activation event uses `handoff` |
| `activation_checkpoint_event_id` | UUIDv7? | Exact checkpoint every target proof applied; null only for `genesis` |
| `activation_proofs` | sorted array, ≤5 | Empty only for `genesis`; otherwise one signed target proof per authority member |
| `prior_authority_signer`, `prior_authority_handoff` | `device_id`?, 64 bytes? | Both null only for `genesis`; otherwise active prior-authority signer and signature over the complete activation |

Each generation's genesis initializes this row at version 1 equal to its initial target, with the
handoff fields null/empty. `membership.voter_set_changed` never updates it.
`membership.voter_set_activated` may advance it only to the current target version and only from the
expected prior authority version; it requires every handoff field and does not alter the target's
`voter_set_version`.

The tables above declare the exact covered field set for §5.6; JCS, not DDL column order, orders
object keys. `publications` uses §7.2's field set. DDL may normalize arrays into child tables, but
the logical rows and covered fields above are fixed before implementation and frozen as golden
fixtures.

### 6.2 Local state

**No durable state lives inside the workspace.** `.codecomm/` holds only a workspace marker and
regenerable artifacts:

```text
.codecomm/                 (in the workspace; regenerable)
  session.json                  untrusted hint: workspace_id, active session_id, recovery_generation
  contexts/
    <agent_session_id>.json     atomic generated context for exactly that agent
    <agent_session_id>.md       equivalent read-only fallback
```

Everything durable lives in per-user state, keyed by `workspace_id`:

```text
<per-user config>/codecomm/
  config.toml              device-wide typed local configuration (§11)        (shared)
<per-user state>/codecomm/
  identity/                device identity reference; private key in OS store  (shared)
  registry/                supervisor registry, one entry per joined workspace (§3.2)
  logs/                    supervisor logs
  sessions/<workspace_id>/
    state.db               daemon-owned SQLite/WAL projections and events
    consensus/             production Raft stable store/snapshots for voters
    git/                   session bare store, resumable artifacts, quarantine, draft metadata
    control/               approved local control-file bytes and delete tombstones
    conflicts/             local merge-resolution worktrees/snapshots
    logs/ tmp/             redacted logs, bootstrap staging
```

This placement is a correctness requirement: `git clean -x` ignores `.git/info/exclude`, so
workspace-local state could be deleted by `clean -xdf` or moved by `stash --all`. External state
makes §8.1's survival guarantee structural; §12.2 tests `clean -xdf`, `stash --all`, and
`reset --hard`.

There is one state directory per joined workspace, owned by that workspace's daemon (§3.2).
`.codecomm/` is still added to `.git/info/exclude` by default so the marker does not appear as
untracked; losing it is recoverable, since `session.json` is rebuilt from the registry. Changing
tracked `.gitignore` requires consent. A daemon whose state directory is missing but whose registry
entry survives reports `unreachable` (§9) rather than silently re-initializing.

No client trusts a path, port, socket, PID, or actor claim from the workspace marker. It uses the
IDs only to query the owner-only supervisor registry, which must match the canonical workspace root
or a daemon-registered managed root, native filesystem/repository identity, and active generation
before returning the local IPC endpoint (§§3.2, 5.1). A modified marker therefore
fails selection rather than attaching an agent to another session.

Identity and live content-epoch private keys stay in the OS credential store, never in either tree. Only the owning
`codecommd` opens its `state.db` or its `git/` quarantine; CLI, TUI, and MCP use local IPC.

| Table | Holds |
|---|---|
| `schema_migrations` | Applied migration numbers and checksums |
| `genesis_records` | Initial and successor genesis records, recovery authorizations, and the full boundary projection-state digest: initial state for generation 0, post-transform state for successors (§§3.1, 5.6) |
| `initial_projection_boundary`, `initial_projection_rows` | Immutable exact generation-zero covered rows plus their genesis-bound digest/version/count. Initialization writes them atomically; a pre-recovery legacy upgrade reconstructs them only after full verification. Successor recovery and verified logical snapshots retain them because the recovery transform is non-invertible |
| `consensus_state` | Nullable/historical `last_raft_applied_log_index`, term, event/result heads, and current projection accumulator/version |
| `events` | Accepted events exactly as signed (§5.2) |
| `event_provenance` | Unsigned local `(term, log_index, applied_at, chain_index, chain_hash)` only for accepted events applied by this store's Raft FSM; result-batch/snapshot imports never synthesize it |
| `chain_checkpoints` | Committed checkpoints with authority signature, both covered chain heads, and projection accumulator (§5.2.1) |
| `command_results` | One immutable first-seen record per `event_id`: exact proposal/digest, canonical accepted-or-rejected outcome, exact canonical projection-mutation list, accepted chain tuple or nulls, dense result index, predecessor hash, and result hash. Retained for lineage lifetime, historical replay, and every FSM/logical snapshot (§5.2.1) |
| `raft_command_applications` | **Local Raft evidence**: one immutable `(recovery_generation, log_index, term, event_id, proposal_digest)` binding for every command this FSM applies after its latest installed-snapshot baseline, including exact duplicates. It joins `command_results` by event ID/digest; its application generation may differ from that result's immutable first-seen generation after recovery. Written with the FSM transaction; imports never synthesize it |
| `raft_committed_configuration` | **Local Raft evidence**: the latest generation-bound configuration delivered by Raft's post-commit `ConfigurationStore` callback, as canonical server tuples plus digest and log index. Startup binds it to the exact retained configuration log or snapshot metadata; it is authorization evidence, never replicated projection state |
| `raft_snapshot_installs` | **Local Raft evidence**: the latest successfully installed Raft snapshot baseline, binding authenticated source, exact Raft metadata/configuration, payload digest, imported command/result/event cuts, both heads, accumulator, and full state digest. A standalone logical-snapshot import never creates it |
| `replication_attestations` | **Local evidence**: verified signed batch envelope/signature and covered ranges, plus trusted snapshot-root/checkpoint attestations. Exact `results[]` reconstruct from immutable `command_results`; contiguous coverage supports settled-nonvoter backup/recovery (§5.3) |
| `origin_scopes`, `audit_counters` | Digest-covered protocol projections for strict origin ordering and bounded rejection audit (§§5.2, 5.4, 6.1) |
| `devices` | Membership, role, enrolled identity keys including revoked and superseded ones (§4.2) |
| `voter_set` | The committed voter target and its `voter_set_version` CAS token; one row per session (§3) |
| `credential_authority` | Last target proven/promoted and activated by a prior-authority handoff; credential/checkpoint/batch trust source (§3) |
| `credential_authorizations` | Committed epoch authorizations every mTLS handshake validates against (§4.6) |
| `agent_sessions` | Agent session rows, state, binding, grouped by device |
| `agent_resume_tokens` | **Local only**: context-bound SHA-256 commitments to resume capabilities; raw tokens are never stored or replicated |
| `agent_launches` | **Local only**: one-use launch selector, immutable client/profile/mode, validated managed-root handle, and pending/consumed start mapping; never reducer input |
| `managed_roots` | **Local only**: canonical path/filesystem/repository identity, mode, guard health, and active local bindings for CodeComm-created roots |
| `tasks`, `plan_revisions`, `plan_current`, `memory_records`, `leases` | §6.1 projections; `plan_current` is the single CAS pointer |
| `canonical_refs` | Replicated CodeComm canonical Git pointer and CAS version (§§6.1, 7.2) |
| `activity` | Projected activity records (§6.1), bounded; a local projection of event content, not an independent record (§10.1) |
| `peer_acks` | Durable per-peer closed watermarks from §5.1; nullable `last_raft_applied_log_index`, monotonic result/chain positions/hashes, and canonical-object availability |
| `peer_endpoints` | **Local only**: own durable endpoint sequence; one latest valid exact target-signed set/member; bounded raw-discovery guesses through datagram expiry; signed-set/authenticated-destination guesses through `endpoint_guess_ttl_seconds`; and separately capped operator-configured manual endpoints (§§2.3, 4.4, 11.2) |
| `lease_deadlines` | **Local only**: same-process monotonic timer metadata and display estimate keyed by lease/version; never replicated or trusted across restart |
| `control_file_proposals` | Committed proposals, replicated (§8.4) |
| `control_file_approvals` | **Local only**: this device's durable decisions and approved content-store/tombstone references. Its current approved rows alone derive the monotonic control-manifest version/digest; pending/declined proposals and live-root drift do not. Never replicated, digest-covered, or committed |
| `publications` | §7.2 publication entities; digest-covered |
| `session_policy` | Mutable committed policy values and their CAS token; one row per session (§6.1) |
| `merge_conflicts` | Deterministic operation tuple, detector paths, and resolution state. Exact re-detection is an idempotent no-op; the same ID with different fields is rejected and alarmed, never overwritten. Only `workspace.conflict.resolved` advances status |
| `git_artifacts` | **Local only**: resumable bundle offsets, verification/import state, source, bound proposal event/metadata digest, signed staging position, and retention class |
| `replication_cursors`, `outbox` | Catch-up cursors hold both chain heads, result watermark, and authority version per peer; outbox holds proposals awaiting forward, drained in insertion order by the owning daemon and deleted once committed or rejected |
| `local_requests` | **Local only**: durable `(client_instance_id, request_id) → (request_digest, event_id, publication_preparation?, exact_signed_proposal?, result?)` mapping. A preparation fixes publication ID, immutable metadata/digest, artifact, and active/abandoned state before receipts; abandonment is a generation-lifetime ID tombstone. Ordinary requests write the signed proposal immediately. Retained for the active generation (§5.1) |
| `owner_recovery_challenges` | **Local only**: durable challenge tuple/deadline/state. One unexpired row per device; expiry is a generation-lifetime tombstone, and timely finalize atomically creates the matching `local_requests` row (§5.1) |
| `pairing_invites` | **Local only**: bounded one-use invite metadata and lifecycle; never the secret or complete invite code |
| `pairing_attempts` | **Local only**: bounded failed-proof observations plus the sole consumed invite's exporter-bound request and two-sided SAS decisions |
| `pairing_attempt_finalizations` | **Local only**: `finalizing`/`completed` marker that makes mode-specific admission or rebootstrap retryable without treating SAS agreement as completion |
| `pairing_secret_deletions` | **Local only**: durable idempotent native-credential deletion queue with stable failure codes and retry history |
| `origin_counters` | **Local only**: next sequence per agent-session or daemon-boot scope; advanced atomically with creation of the exact signed proposal |
| `audit_events` | Local projection of accepted action events, first-seen committed rejections, signed-genesis recovery boundaries, and explicit bounded pre-result rejection audits (§§3.1, 5.4, 10.1); never independent authority |

Queryable identity/kind/version/status/time fields are typed and indexed; versioned
payloads use the §4.1 canonical encoding. Network input never becomes SQL; trusted SQL uses
prepared statements. V1 DDL and migration 0001 are a phase-2 deliverable, frozen thereafter
as golden fixtures (§12.2).

`raft_snapshot_installs` is added by the first Phase 3 migration and has one current row per active
generation. It stores `(session_id, workspace_id, recovery_generation, source_server_id,
snapshot_id, snapshot_index, snapshot_term, configuration_index, configuration_digest,
payload_digest, baseline_command_log_index?, baseline_command_term?, chain_index, chain_hash,
result_index, result_hash, projection_accumulator, projection_state_digest, digest_version,
projection_schema_version, installed_at)`. Digests are exact 32-byte values; nullable command
position/term are both null or both positive. The snapshot-store adapter, not the payload, supplies
the Raft `(snapshot_id, index, term, configuration, configuration_index)` and exposes `FSM.Restore`
only after those values match the bounded payload envelope. `configuration_digest` hashes the
canonical ordered server-ID/address/suffrage tuple. `installed_at` is local audit time and grants no
authority.

`local_requests` retains replay identity, not duplicate bulk. After a signed request reaches a
committed result, the row keeps only its keys/digests/event ID and resolves the immutable outcome
from `command_results`. Abandonment deletes artifact/receipt detail and keeps the fixed-size request
digest, event/publication IDs, terminal code, and actor binding; challenge expiry is compacted
similarly. These tombstones are not silently pruned because doing so could turn an old retry into a
new mutation. Their linear growth is intentional local idempotency history, is charged to the
coordination-state warning in §11.2, and is cleared only by §3.1's new generation or session removal.

SQLite MUST enable WAL, `synchronous=FULL`, foreign keys, a 5 s busy timeout (§11.2), and
supported defensive settings. `synchronous=NORMAL` is insufficient: WAL's default loses committed
transactions on power loss, which could make a Raft participant's
`last_raft_applied_log_index` regress below its log or, on a truncated log, exceed it. A store with
Raft state MUST assert `last_raft_applied_log_index <= last Raft log or installed-snapshot command
cut` and that the committed-configuration index does not exceed retained log/snapshot state, then
bind that configuration's exact bytes to its configuration log or snapshot metadata. It fails
closed on any violation. Without an install baseline, every current-generation
command result must have an exact first-seen local command binding and every binding must match a
result. With one, results through its `result_index` are covered by the verified baseline; every
later result needs a first-seen binding, every retained binding must be after the baseline command
cut and match a result, and the latest binding or baseline must equal the SQLite command watermark.
A settled nonvoter leaves that watermark null/historical and validates contiguous signed result
attestations instead.

The §5.3 Raft-FSM apply transaction writes atomically: accepted event or rejection,
accepted-event provenance when applicable, `last_raft_applied_log_index`, chain heads and projection
accumulator, every affected covered protocol/domain row, durable
chained `command_results` with exact projection mutations, the local Raft-command binding, the
accepted event's or committed rejection's audit projection, checkpoint row, lease timer metadata,
and local outbox removal. A later deterministic decision reads nothing outside that transaction.
Peer acknowledgements/cursors and Git transfer progress remain outside because they cannot affect a
reducer. A process that lacks a live same-boot monotonic lease timer arms the full committed TTL;
persisted wall time is display-only and never shortens it.

A settled-nonvoter import scratch-replays the same deterministic transitions, then atomically writes
the batch's results/events/projections/heads, local views/timers, cursor, and
`replication_attestations` row. The signed batch binds both projection-accumulator and full-state
digests at its starting and ending cuts; startup rechecks those commitments against retained
mutations and rows. It neither advances `last_raft_applied_log_index` nor writes event provenance.
Standalone logical-snapshot import does the equivalent replacement transaction with its trusted
checkpoint attestation before any state becomes visible.

A Raft `InstallSnapshot` instead verifies the same logical artifact plus the adapter-supplied Raft
metadata, then atomically replaces SQLite state, removes source-local `event_provenance` and
`raft_command_applications`, writes the matching `raft_snapshot_installs` baseline, and establishes
`last_raft_applied_log_index` only at the envelope's nullable command cut. It never copies or
synthesizes the source's per-command provenance. Failure before the replacement commit leaves the
old state and baseline intact; failure after it is ordinary idempotent Raft restart.

No covered projection may carry an inbound foreign key to a locally-pruned table, and reducer
validation reads only covered state. Foreign-key enforcement runs inside the
deterministic apply transaction, so if one replica pruned a parent row another still holds, the
same event fails on one and succeeds on the other — a divergence in a fail-closed system.
Event/projection/command-result/result-chain/accumulator/outbox and, for Raft FSM apply,
`last_raft_applied_log_index` changes commit atomically. `event_id` and
`result_index` are unique across all results; the origin tuple is unique only across accepted
events because a distinct event that reuses a consumed sequence must retain its committed rejection.
Committed but unapplied Raft entries replay idempotently after crash. Checkpointing and
transactional checksummed migrations are daemon-controlled. The checksum binds the SQL, versioned
post-SQL hook identity, and CI-verified source fingerprint; released hooks are immutable.
Every migration has an explicit reviewed-reversible or verified-backup-required classification;
unclassified and unverified irreversible migrations fail before DDL.

Use the Raft library's production stable store, not a custom log. A Raft participant's backup uses
SQLite online backup plus matching stable-store snapshot metadata, any installed-snapshot baseline,
and `last_raft_applied_log_index`. A settled nonvoter's backup instead carries a verified logical
checkpoint/snapshot plus contiguous signed batch attestations through its result head; it MUST NOT
claim a Raft position it never applied. Never ordinary-copy active DB/WAL files. Startup after unclean exit performs recovery/integrity
and current-head/link checks; a full historical chain scan is reserved for snapshot, export,
recovery, and `state scrub` as §5.2.1 states. Corruption preserves evidence, stops writes, and
offers verified restore or result-stream reconstruction.

Generated context is non-authoritative, provenance-labeled untrusted data.

### 6.3 Coordination semantics

Task states are a graph. Every legal edge is listed; any transition absent from this table is
rejected deterministically on every replica. The table binds **state transitions** however they are
proposed — `task.state_changed`, `task.released`, `task.reassigned`, and `task.cancelled` all move
a task along one of these edges, and each kind carries the additional per-event preconditions of
§5.4. An edge assigned to release, reassignment, or cancellation is not traversable through
`task.state_changed`. The `ready → ready` self-edge exists because an operator must be able to clear a stranded
reassignment intent on a task that is already `ready`; without it the remedy §6.3 promises for a
revoked intended device would itself be a rejected transition. The `Who` column narrows the
`task.state_changed` role floor (§5.4) per edge; "operator override" edges are the human-only
verbs of §6.4, distinct from the `holder` performing a voluntary transition.

| From | To | Who | Notes |
|---|---|---|---|
| — | `backlog` | owner, editor | Create |
| `backlog` | `ready` | owner, editor | Declares it workable |
| `ready` | `backlog` | owner, editor | Withdraw from consideration |
| `ready` | `claimed` | owner, editor | Compare-and-set; exactly one winner |
| `claimed` | `in_progress` | holder | Work started |
| `claimed` | `ready` | holder, or operator override | Dedicated release/reassignment event (§6.4) |
| `in_progress` | `blocked` | holder | Requires `reason` |
| `in_progress` | `ready` | holder, or operator override | Dedicated release/reassignment event |
| `in_progress` | `done` | holder | Refused while an unresolved merge conflict references the task |
| `blocked` | `in_progress` | holder | Unblocked, resume |
| `blocked` | `ready` | holder, or operator override | Dedicated release/reassignment event |
| `ready` | `ready` | operator override | Clears or re-targets a stranded `intended_device_id`; the only self-edge, and what §6.4's `task reassign` and `task force-release` use on an already-`ready` task |
| any non-terminal | `cancelled` | owner | Terminal; abandons the work |
| `done` | — | — | Terminal |

`done` and `cancelled` are terminal: no edge leaves them. Reviving abandoned work means
creating a new task, optionally labelled to point at the old one. A claim sets
`owner_device_id` and `owner_agent_session_id` together, clears a matching
`intended_device_id`, and clears `last_release_reason`. Any release clears owners and records its
reason. `task.state_changed.reason` is required and stored exactly when entering `blocked`, and is
prohibited otherwise; leaving `blocked` clears `state_reason`. **Reaching `done` or `cancelled` also clears both
owner fields and `intended_device_id`** so a terminal task names no session that
could later be reaped (§6.4). A claim from another device while an
intent is set is a deterministic rejection. Reassignment validates that the target is active at
apply time. If that device is later revoked before claiming, the intent remains visibly blocked
until an owner reassigns it or force-releases it; revocation never silently delegates work.

Other entities:

- Plans: immutable revisions plus one compare-and-set current pointer; editors propose,
  owners select (§6.1).
- Memory: append-only records with supersession chains.
- Leases: advisory task or path reservations released by an expiry event.
- Views (derived, never stored): peers/agents, activity, actionable tasks,
  repository/conflicts, and replica watermarks.

Strong task claims apply the common order from §5.3: role, task existence/entity CAS, then the
derived `actionable` predicate, intended-device constraint, and claim limits. New lease IDs use the
deterministic intersection check above. An agent
`task.updated` reducer likewise requires that agent to hold the task or that both owner fields are
null; this is replicated authorization, not merely MCP filtering. Both claim and lease acquisition
execute in the replicated state machine and produce one winner. Local serialization does not make a
request successful before consensus commits.

No reducer reads a wall clock. On applying `lease.acquired` or `lease.renewed`, each running daemon
arms a monotonic `now + ttl_seconds` timer for that version, whether or not it is leader; only the
current leader may turn expiry into `lease.released(expired)`. Renewal and expiry race through the
same CAS, so one wins and a stale timer rejects everywhere. Event volume cannot accelerate expiry.
Because current leadership is volatile consensus state rather than reducer input, the leader-only
rule is enforced by the authenticated proposal-ingress/forwarding path before Raft submission.
Replicas deterministically enforce the daemon actor, lease CAS, and lifecycle transition.

A same-process leadership change may retain the monotonic remaining duration. A daemon restart,
boot change, missing timer, or snapshot import always arms the **full** TTL from new monotonic now.
It may delay this advisory release but can never release early because of wall-clock skew or jumps.
Persisted estimates exist only for display and are labeled reconstructed. The committed release is
authority. Session end and operator override remain immediate committed paths. Heartbeats are
ephemeral and explicitly authorize renewal of that bound session's leases; the owning daemon
coalesces them, constructs the corresponding agent-originated renewals from the live binding, and
proposes no earlier than the final third of TTL.

A majority partition may commit and renew credentials. A minority may edit locally, queue
events, and exchange Git objects directly only while credentials remain valid. On healing, event
IDs deduplicate, the committed log converges, immutable device refs retain concurrent work, and
stale publications require an explicit rebase or merge. CodeComm never claims arbitrary offline
writes are automatically mergeable.

### 6.4 Ownership release and operator override

Because `agent_session_id` is never reused (§4.2), a claim held by an ended agent session
would otherwise be owned forever by an identity that can never return. Two mechanisms
prevent that.

**Automatic release on session end.** Clean shutdown proposes `agent.session.ended` directly. On IPC
loss, the owning daemon starts the local monotonic grace timer and commits
`agent.session.state_changed(disconnected)` with the current version, preserving the prior state in
`resume_state`. A
valid local resume proposes restoration with that disconnected version; grace expiry proposes
`agent.session.ended` with the same version. Their CAS race has one winner: resume restores the exact
stored state and clears it, while end is terminal. A foreign/stale capability or a late resume cannot
change replicated state (§§5.4, 7.2).

On accepted end, one bounded reducer transaction releases everything held by the session; current
per-agent caps, themselves bounded by §11.2's hard maxima of 64 claims and 256 leases, limit the
cascade:

- every owned non-terminal task returns to `ready`, clears owners/intent, and sets
  `last_release_reason = session_ended`;
- every active held lease becomes released with `release_reason = session_ended`;
- `blocked_by` and committed merge-conflict records are untouched, since neither is ownership.

Each affected task/lease and the agent session increments its own `entity_version`; the release is
deterministic on every replica and driven by the committed end event, not the local grace timer.
If the session or any affected child is already at the maximum entity version, the whole event
rejects with `entity_version_exhausted`; reducers inspect sorted task IDs before sorted lease IDs, and
no partial release occurs.

The §3.1 boundary transform performs the same bounded release for every carried old-generation
session but records `recovery` rather than `session_ended`; it is covered by the successor genesis
digest rather than pretending that offline recovery committed one event per abandoned agent.

**Operator override.** For cases session end does not cover — a runaway agent still
heartbeating, an abandoned worktree, a task claimed on a device that is gone for good — an
operator uses the CLI verbs below (§9), each mapping to a committed, audited, expected-version
event of §5.4. All are `human` actor, and the daemon constructs `actor_type` from the accepted IPC binding (§5.2), so none is reachable over MCP (§7.1).

| CLI operation | Event (§5.4) | Effect |
|---|---|---|
| `task force-release` | `task.released` (`forced`) | Clears owners/intent and returns to `ready`; owner for any task, editor only when the owner or intended target is its own device |
| `task reassign` | `task.reassigned` | Force-releases, persists one active `to_device_id`, and leaves the task `ready`; only that device can win the next claim, which clears the intent; owner only |
| `task cancel` | `task.cancelled` | Moves any non-terminal task to `cancelled`; owner only |
| `lease force-release` | `lease.released` (`forced`) | Owner for any lease; editor only for a lease held by its own device |
| `conflicts force-resolve` | `workspace.conflict.force_resolved` | Clears a completion gate whose resolution publication can never be staged, recording that no merge publication was involved; owner only |
| `agent stop` | none | Local request to a local agent session to end; the local daemon only, never a committed event and never a peer (§2.5) |

Every override records the acting `device_id` and lands in `audit_events`, so a forced
release is always distinguishable from a voluntary one. None of these are exposed over MCP
(§7.1): an agent may release *its own* claims and leases, but overriding another session's
ownership is an operator action available only through the TUI and CLI.
Daemon-originated `agent.session.ended(operator)` is not an `operator_override` audit class: it can
end only a session owned by that same daemon, and the accepted end event plus its atomic cascade is
the durable audit record.
