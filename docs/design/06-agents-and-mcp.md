# CodeComm V1 Design — Part 07: Agent Sessions and MCP Integration

Part 7 of 14. Contents: §7 local-only MCP, agent lifecycle and concurrency, generated context.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 7. Agent Sessions and Integration

### 7.1 Local-only MCP

`codecomm mcp serve` is one stdio MCP process per Codex/Claude instance launched through
`codecomm agent launch`. It opens no TCP listener and reaches one owner-restricted session daemon
through a Unix socket or Windows named pipe, resolved once at launch and bound for the process
lifetime. A non-secret inherited launch selector identifies the daemon-created registration; an
independently started adapter has none and is refused. Five local clients produce five distinct
`agent_session_id`s even if names/types match. Clients attached to different sessions on one device
cannot observe or address each other. A remote peer cannot open MCP, invoke a tool, add a tool, launch/stop/resume an
agent, or weaken client sandbox, network, filesystem, or approval policy. The tool set is fixed at
build time; MCP configuration files are §8.4 control files, so a peer's proposed change to them
requires local per-device approval before it takes effect.

The MCP surface is limited to typed coordination operations:

```text
agent.session.get/list   context.get       task.create/list/claim/update
task.state_change        task.release      plan.get/propose
memory.append            activity.append   repo.status
publication.propose/status/review/apply/withdraw  conflict.list/resolve
lease.list/acquire/renew/release            control_file.propose
```

`task.state_change` moves a task the calling session owns along a legal edge of §6.3 (start,
block, unblock, done); it cannot cancel or reassign, which are operator-only (§6.4). `task.release`
and `lease.release` act **only on the calling session's own** holdings; the actor comes from the
IPC binding and cannot be named as an argument. `task.update` is likewise restricted to tasks the
calling session owns, or to unowned tasks: without that scoping any agent could add `blocked_by`
edges to another session's in-progress task and freeze it, since §6.1 makes a task actionable only
when every `blocked_by` task is `done` and the victim cannot clear an edge anyone may add.
`conflict.resolve` requires the caller to author the named resolution publication. `activity.append`
maps to `activity.recorded`; `publication.propose` makes the daemon build metadata and a bundle from
the caller's bound working root, and the client cannot supply another root or artifact.
`publication.review` accepts only publication ID, expected version, and verdict; the reducer rejects
the author and every agent on the author's device, so only an agent on another member device can
supply peer review (§7.2). Override verbs of §6.4 are absent. `publication.withdraw` acts only on
a publication authored by the calling session; before proposal signing the same verb locally
abandons and tombstones that session's preparation without emitting an event (§5.1).
`publication.apply` accepts only an approved
publication ID and both expected versions; staging and canonical CAS remain reducer-enforced.
`control_file.propose` accepts a canonical path and `upsert`/`delete`; for upsert the daemon reads
only that path from the bound managed root, constructs the digest/diff/artifact, and never accepts
content bytes or a host path from MCP. `lease.list` is bounded and paginated so context may keep
lease summaries compact. No tool accepts an executable, shell command, host
path, URL/script, or
actor ID; lease/publication paths use only §8.4 canonical workspace-relative syntax. Mutations use
strict schemas, bounds, roles, and versions. CLI/TUI expose equivalent human operations;
`.codecomm/contexts/<agent_session_id>.md` is that binding's read-only fallback.

Configure clients through supported user-local mechanisms using an absolute, verified CodeComm
path, never synchronized project launchers. Codex's MCP registration is equivalent to:

```text
codex mcp add codecomm -- <absolute-codecomm-executable> mcp serve
```

The operator starts the actual client with
`codecomm agent launch --client codex|claude [--profile ...]`; CodeComm creates the managed root and
registration, then launches the vendor so its MCP child inherits the selector. Direct vendor launch
may start the configured adapter, but its bind fails closed with the launch command required. Use
explicit MCP tool allowlists and write approval. Claude configuration is a versioned
adapter. MCP instructions require context refresh, peer-agent review, task claim, path
lease, version recheck, concise result, and stop on conflict; they begin by declaring
remote text untrusted.

### 7.2 Agent lifecycle and same-device concurrency

`codecomm agent launch` first asks the daemon to create a durable one-use `agent_launches`
registration containing the selected session/workspace, immutable `client_kind` and optional
profile, isolated/shared mode, and a daemon-validated `managed_roots` handle. The launch selector is
random, never reused, and non-secret: same-UID process impersonation is already outside V1, while the
registration prevents model/vendor input from choosing metadata or a host path. It is inherited by
the vendor's `mcp serve` child and is the only new-agent bind argument.

The daemon reserves one registration, mints fresh agent and opaque `working_root_id` values, and
durably maps them to one exact `agent.session.started` proposal. Tools remain unavailable until that
event commits. An exact rebind after crash resumes the pending start; concurrent/replayed consumers
cannot create another. On acceptance, the daemon consumes the selector, returns a 256-bit CSPRNG
resume capability only to adapter memory, and persists only
`SHA-256("codecomm/v1/agent-resume" || 0x00 || token)` bound to session, workspace, device, agent, and
root. On rejection it consumes the registration and burns the agent ID. Validation is constant-time,
survives daemon restart, and rejects every context mismatch; the raw token never enters argv,
environment, file, log, support bundle, or replicated state. Terminal end deletes its commitment and
generated context pair. Recovery clears every pending launch. This local IPC state is not reducer
input: replicas enforce the committed start, owning-daemon authority, stored-state restoration, and
CAS. Heartbeats refresh presence and make held leases eligible for §6.3 renewal.

The connected states are `starting`, `idle`, `claimed`, `working`, and `blocked`; agent-originated
changes may report `starting → idle` and any transition among the latter four. On IPC loss, only the
owning daemon commits `disconnected`, atomically storing the prior state, and starts the 90 s
monotonic grace (§11.2). A valid local capability resumes only to that stored state and clears it.
Resume and grace reaping use the same expected session version, so exactly one wins; end releases
claims/leases and is terminal. Foreign, stale, or post-end capabilities fail, and no ID is reused
(§§6.1, 6.4).

The **daemon**, not the adapter and never model text, constructs every event's `origin` block from
the accepted IPC binding (§5.2); an MCP connection is pinned to `actor_type: agent`, profile, and
`agent_session_id` for its lifetime, and a local MCP request carrying any `origin` field is rejected.
The resulting signed network proposal contains that daemon-built block. This is what makes the operator-only verbs structurally unreachable
here rather than merely undocumented. Durable events record start,
meaningful transitions, and end; high-frequency presence is bounded/ephemeral. All local
instances attached to the same session share that session's daemon and DB, but retain
separate claims, leases, origin sequences, activity, and rows grouped by device.

The fixed `mcp serve` adapter always binds the local IPC connection as `agent`; MCP input has no
client-class field. This prevents actor escalation through the MCP protocol. It is not a sandbox
against arbitrary same-UID native code opening the operator socket, including an agent invoking the
CLI through a separately approved shell/process tool: that broader OS-account impersonation is
explicitly outside V1's boundary (§10, risk 21).

Writable concurrency modes:

- **Isolated worktree (default):** create one Git worktree per launched agent outside the user's
  primary working tree with §8.2's control-path sparse guard, then publish an immutable reviewed
  commit.
- **Shared root (opt-in):** several agents use one separate CodeComm-created managed worktree with
  the same control-path guard and require disjoint advisory path leases. CodeComm never launches an
  agent directly in a pre-existing host/user working tree; arbitrary same-user processes can bypass
  both leases and managed-root policy, so identity provides no filesystem isolation.

Before any CodeComm-invoked checkout, reset, clean, stash, branch, integrate, or other root-mutating
Git operation, the daemon requires zero pending launch registrations and zero live or resumable
agent bindings on that managed root. Shared mode does not weaken this rule: one pending or active
binding blocks mutation for all. The operation refuses with the registration/agent IDs rather than
invalidating their filesystem view.

**Publication** is a replicated proposal to advance the CodeComm canonical ref.

| Field | Type | Notes |
|---|---|---|
| `publication_id` | UUIDv7 | Immutable |
| `proposal_event_id` | UUIDv7 | Immutable; exactly the accepted `publication.proposed` event's `event_id` |
| `supersedes_publication_id` | UUIDv7? | Existing terminal `rejected`/`withdrawn` publication in this rebase/merge lineage; never an applied or nonterminal row |
| `task_id` | `task_id`? | Task this completes, if any |
| `author_device_id`, `author_agent_session_id` | ids | From the committed actor binding |
| `base_commit`, `commit_oid`, `tree_oid` | algorithm-tagged Git OIDs | Exact immutable graph transition; `base_commit` is the tip's first parent |
| `parent_oids` | [Git OID], ≤`publication_parent_max` | Exact ordered tip parents, needed for conflict-resolution validation |
| `paths` | [canonical path], 1–2048 | Nonempty sorted unique union of paths changed on every introduced commit's first-parent edge |
| `artifact_digest` | SHA-256 | Exact bounded Git bundle staged for this publication |
| `resolves_conflict_ids` | [`conflict_id`], ≤64 | Conflicts whose two tips staging voters verified are ancestors of `commit_oid` |
| `working_root_id` | UUIDv7 | Opaque binding from the author's committed agent-session row (§6.1) |
| `staging_receipts` | [signed receipt], ≤5 | Validated set for one `voter_set_version`, sorted by voter `device_id`; each binds `staged_result_index` and the set is replaced at apply |
| `state` | enum: `proposed`, `approved`, `applied`, `rejected`, `withdrawn` | |
| `terminal_source` | enum?: `review`, `apply`, `withdraw`, `recovery` | Null while nonterminal; `recovery` marks §3.1's boundary withdrawal |
| `canonical_lineage_member` | boolean | False until normal apply; §3.1 recomputes applied rows against selected canonical first-parent ancestry |
| `review_verdict` | enum?: `approve`, `reject` | Null until reviewed; retained after apply |
| `reviewer_device_id`, `reviewer_agent_session_id`, `review_actor_type` | IDs/enum? | Null until reviewed; agent session is required only for an agent review, and actor is `agent` or `human` |
| `decision_reason` | string?, ≤1024 | Withdrawal reason; null for a verdict-only review |
| `entity_version` | integer ≥1 | |

Before proposal, the author daemon normalizes the bound root to one publishable tip. A direct
one-commit tip already has `base_commit` as first parent. For linear multi-commit work whose history
contains the base, preserve-history mode creates, with system `git commit-tree`, one integration tip
whose tree is the candidate tree and ordered parents are `[base_commit, candidate_tip]`; squash mode
creates the same tree with only `base_commit` as parent. Generated commits use fixed
`CodeComm Integration <integration@codecomm.invalid>` author/committer, the candidate tip's
committer instant normalized to `+0000`, exact message `CodeComm integration v1\n`, and no optional
headers. If the current base is not an ancestor of the candidate, the daemon first requires an
explicit isolated merge or rebase (§8.3), then wraps or squashes that result. The prepared tip/tree
is durably recorded and surfaced with the preparation; retry never regenerates it.

The daemon asks system Git to create a bounded bundle for `base_commit..commit_oid`. A merge's
second-parent history can make Git emit redundant prerequisite ancestors of `base_commit`. A bounded
bundle-header parser therefore requires every generated prerequisite to equal or be an ancestor of
`base_commit`, replaces those header lines with one prerequisite naming `base_commit`, preserves the
PACK bytes unchanged, and re-runs `git bundle verify` in an isolated repository containing only the
verified complete base closure. The final header has exactly that prerequisite and one advertised
head, `refs/codecomm/artifacts/publications/<publication_id> = commit_oid`; another prerequisite/ref
rejects. Phase 1 freezes v2/v3 header normalization for both object formats and rejects shallow or
filtered base stores.

Before download, a target voter requires content mTLS from the active
`author_device_id` named by the metadata and requires that device to own the named active
`author_agent_session_id` in its applied state. It then quarantines the artifact, verifies
digest/size, object format, exact prerequisite/head, and `git bundle verify`, rejects any object
outside that head's reachable closure relative to the one prerequisite, and imports with hooks,
replace refs/grafts, shallow boundaries, filters, helpers, caller alternates, submodules, and LFS
network disabled. It confirms commit/tree, exact ordered `parent_oids`, and
`parent_oids[0] = base_commit`.

Graph validation is exact and streaming. With replacement history disabled, enumerate the bounded
set `I` from direct-argv
`git rev-list --topo-order --parents commit_oid ^base_commit --`, stopping and rejecting on record
`publication_introduced_commit_max + 1`. Every introduced commit, including the tip and commits
reachable through non-first parents, must have
`1..publication_parent_max` parents. Its first parent `P` must be in `I` or satisfy
`git merge-base --is-ancestor P base_commit`; an introduced root or disconnected first-parent edge
rejects. For each edge `P → C`, stream
`git diff-tree -r --raw -z --no-commit-id --no-renames --no-abbrev P C --`; parse only its
NUL-delimited raw records and reject on changed-edge record
`publication_changed_edge_max + 1`, noncanonical/control paths, gitlinks, symlinks, or another
§8.4-ineligible changed mode. `paths` must equal the sorted unique canonical union and obey its own
event bound. The union MUST be nonempty and `tree_oid` MUST differ from `base_commit`'s tree; an
empty-path or net no-op publication rejects. Thus an intermediate modify-then-revert still requires authority and cannot smuggle an
ineligible path or mode; a move names both deleted and added paths. For every declared resolved
conflict, both committed tips must be ancestors of `commit_oid`. The voter then pins the objects under
`refs/codecomm/publications/<publication_id>`, durably records them, and signs
`(session_id, workspace_id, voter_set_version, publication_metadata_digest, voter_device_id,
staged_result_index)` under `codecomm/v1/git-stage-receipt`; `staged_result_index` is the holder's
durable applied result head after the pin commits. The metadata digest is SHA-256 over the JCS object
containing exactly `proposal_event_id`, `publication_id`,
`supersedes_publication_id`, `task_id`, `author_device_id`,
`author_agent_session_id`, `base_commit`, `commit_oid`, `tree_oid`, `parent_oids`, `paths`,
`artifact_digest`, `resolves_conflict_ids`, and `working_root_id`. It excludes receipts, state, and
`entity_version`, avoiding a recursive preimage. It also excludes every mutable review/terminal
field. `proposal_event_id` is reserved in §5.1 before staging and the eventual
`publication.proposed` reducer requires it to equal that event's envelope `event_id`. Before
download, the holder reserves one of §11.2's pre-proposal staging slots and quota headroom. Restaging
the same `(proposal_event_id, publication_id, metadata digest)` is idempotent; reuse of either ID
with another tuple rejects. A receipt is issued only after durable import.

```text
publication_metadata_digest =
  SHA-256("codecomm/v1/publication-metadata" || 0x00 || JCS(metadata_object))
```

`publication.proposed` and `publication.applied` each require valid receipts from a majority of
the **current committed voter target**, with its exact `voter_set_version`, distinct active target
voters, and matching metadata, including the accepted publication's original `proposal_event_id`
when applying. For each receipt, the reducer first rejects
`staged_result_index > current_result_index`, then subtracts and requires
`current_result_index - staged_result_index <= publication_receipt_window_results`; a future or
stale receipt rejects deterministically without unsigned overflow. This makes committed content available wherever the
configured fault tolerance can survive without making an abandoned pre-proposal pin permanent.
A target change requires new receipts; old-version receipts grant no quorum credit. A one-voter
session necessarily has one durable voter copy and no content failover, matching its consensus
tolerance.

Before `publication.proposed` is accepted, a holder keeps its staging pin until it observes the
committed result for that exact `proposal_event_id`. Rejection releases it immediately. Otherwise,
after processing each result's acceptance/rejection, an unaccepted pin is old only when the local
head is not behind `staged_result_index` and their subtraction exceeds
`publication_receipt_window_results`; implementations never add the window to an index. Acceptance
converts the local record from a
bounded staging slot to §8.1's protected nonterminal-publication retention; later receipt expiry
does not release it, and the holder may sign a fresh receipt from the same durable pin for apply.
An unaccepted expired pin is eligible for deletion under the import/GC mutex. Because every receipt
binds one proposal event, replaying it in a later attempt fails before domain acceptance even if its
result-position window remains open. These rules and the local staging-slot cap bound both abandoned
refs and their metadata; the session Git quota remains the byte bound.

`publication.reviewed(approve)` moves `proposed → approved`;
`publication.reviewed(reject)` moves `proposed|approved → rejected` and sets
`terminal_source = review`. An agent review must come
through `publication.review` on a device other than the author's. `publication.withdrawn` moves
`proposed|approved → withdrawn` and sets `terminal_source = withdraw`; an agent may withdraw only its own publication, while a human owner
may withdraw any and an editor only one authored on its device. Rejected and withdrawn publications
are terminal and distinct in audit/UI. A non-null `supersedes_publication_id` must name an existing
rejected or withdrawn row and cannot name self; requiring the stale attempt to terminate first keeps
one forgotten rebase from pinning every prior attempt indefinitely. `publication.applied` succeeds only when the publication is approved,
`base_commit` equals the replicated canonical `commit_oid`, and both the publication version and
`expected_canonical_ref_version` match. One reducer transaction marks the publication applied, sets
`terminal_source = apply` and `canonical_lineage_member = true`, and advances `canonical_refs`; a
mismatch is a structured stale rejection that leaves the proposal
intact for explicit rebase/merge or rejection. No verification races a changing working tree.
Terminal state then drives only §8.1's local protected-ref retention; no replicated timer/version
baseline is needed.

After applying the event, each local reconciler fetches missing objects from any receipt holder,
revalidates them, and runs compare-and-set `git update-ref refs/codecomm/canonical <new> <old>`.
The SQLite canonical projection is authoritative; an unavailable object leaves the local Git ref
visibly `object-lagging` until retrieval succeeds. CodeComm never updates `HEAD`, the index, a
user branch, or a working tree. A publication changing a §8.4 control file is rejected in favor of
that approval flow.

**Publication authority is reducer-enforced, not instructed.** Staging verification proves a
publication *describes itself honestly* — bundle digest, bounded graph shape, and `paths` matching
the introduced-history union. It says nothing about whether the author was entitled to those paths, and the
canonical advance is a replicated compare-and-set the reducers fully control, so this is the one
place where authority can be enforced for free. `publication.proposed` is therefore rejected
deterministically on every replica unless all four hold:

- **The metadata author equals the signed actor:** `author_device_id = origin.device_id` and
  `author_agent_session_id = origin.agent_session_id`; that active session belongs to that device.
- **Every path is covered by an active path-scope lease held by `author_agent_session_id` at apply
  time**, using §6.1's exact/prefix intersection grammar. Task ownership alone grants no path;
  uncovered paths are a structured rejection naming them.
- **If `task_id` is set, `author_agent_session_id` is that task's committed
  `owner_agent_session_id`.** Publishing for a task you do not hold is a rejection.
- **`working_root_id` equals the author's committed agent-session binding.** The local daemon is the
  sole artifact constructor and reads only that bound root; MCP cannot provide a path, root ID, Git
  metadata, or bundle. Remote reducers can detect a cross-session binding mismatch but cannot prove
  filesystem provenance, so the design does not claim that an opaque ID is cryptographic evidence.

**Review distinguishes agent independence from explicit human judgment.** An agent-originated
`publication.reviewed(approve)` MUST come from a device other than `author_device_id`; a second MCP
client on the same daemon is not an independent peer review. A human-originated verdict may come
from any editor/owner device, including the author's, because one-device sessions otherwise cannot
publish at all. The TUI labels that outcome `human self-review` and never presents it as peer review.
The author agent cannot submit its own verdict under either actor type because the IPC binding fixes
`actor_type` (§5.2).

**Contention is observable, not falsely fair.** A lost canonical CAS is a rejected command and
therefore cannot mutate the digest-covered publication row (§5.3). It leaves the immutable proposal
intact. Rebase/merge creates a new publication with `supersedes_publication_id`, new receipts, and a
new review because its metadata digest changed, after the stale attempt is rejected or withdrawn.
The initiating daemon keeps a local consecutive-
stale count across that lineage and shows `starving` after §11.2's threshold; the count is diagnostic,
not replicated authority. V1 promises no progress under an infinite stream of winners. Tests require
the blocker under sustained contention and successful apply after contention quiesces, not an
impossible fairness guarantee.

### 7.3 Generated context

`context.get` is binding-specific. Its file fallback is one pair per active agent:
`.codecomm/contexts/<agent_session_id>.{json,md}` in that agent's managed root. Shared-root agents
therefore have separate files and `Self` sections; no global `context.{json,md}` exists. Each
Markdown file is a human-readable projection of its paired JSON with controls escaped. Content
derives entirely from committed state plus local status — a projection, never authority.

| Group | Fields |
|---|---|
| Session | `session_id`, `workspace_id`, own `device_id` and role, leader, quorum state, Raft applied/committed indices when this store participates (otherwise `n/a`), `chain_index`, `result_index`, and authority-watermark observation |
| Self | own `agent_session_id`, state, all claimed task IDs, and compact held-lease summaries (`lease_id`, scope/task, path count/digest) |
| Peers | per device: role, online, agent states, claims, and compact lease summaries, grouped by device |
| Work | actionable tasks (§6.1) with `task_id`, title, priority, `blocked_by` and their states; own tasks in any state |
| Plan | current `plan_revision_id`, title, and its `task_ids` |
| Memory | most recent non-superseded records in scope, newest first |
| Activity | newest bounded action/rationale summaries relevant to self/current tasks |
| Repository | canonical commit and local object/ref lag; own and peer draft refs; bounded unresolved-conflict summary/cursor |
| Provenance | for every peer-authored string: origin `device_id`, role, `agent_session_id`, `chain_index` |

Bounds are normative per agent context: at most 200 tasks, 50 memory records, 100 activity entries,
8 devices and 32 total active agent sessions, and 256 KiB per output file. Per-group *counts* alone are not a budget — 200 tasks at
§6.1's 8 KiB `body` bound is already ~1.6 MiB against a 256 KiB cap — so the byte cap is always the
binding constraint and needs an allocation rule, or one group silently evicts another:

- Every budget counts final UTF-8 encoded bytes after escaping, provenance wrapping, and JSON or
  Markdown rendering; each agent's JSON and Markdown independently stay within 256 KiB. The fixed-core schema and a
  maximal 64-claim/256-lease fixture MUST encode within its 64 KiB allocation.
- `Session`, `Self`, and Repository's canonical/lag gates are **never truncated** and are allocated
  first; omitting an agent's own claims or a completion gate is unsafe. Conflict safety is represented
  compactly as total and per-owned-task unresolved counts plus a `conflicts_truncated` flag; full
  conflict IDs/paths are paginated through `conflict.list` and may truncate in context. Reducers
  still refuse task completion regardless of rendering. Full lease path arrays are paginated through
  `lease.list`; the fixed core carries every own lease ID plus a bounded summary, which fits even at
  §11.2's hard per-agent maximum. Peer lease/draft lists are truncatable and use the Peers
  sub-budget. The fixed core has a structural §11.2 ceiling.
- Every remaining group has an explicit byte sub-budget from §11.2 summing below the total, and
  truncates against **its own** sub-budget, so no group can consume another's.
- Long peer-authored strings (`task.body`, `memory.body`, `plan.body`) are truncated to §11.2's
  per-field context length rather than dropping whole records, so a maximal 8 KiB body costs its
  author no advantage and gains it none.
- Within task, memory, and activity groups, per-origin-device fairness applies: one device cannot occupy
  every slot.

Truncation is declared explicitly in the payload, but declaring it does not restore the evicted
facts, which is why the guarantees above are structural rather than advisory. Every affected active
agent pair is regenerated on result-head change, local agent/session status or conflict change, and
on demand, with bursts coalesced. Each file carries the same generation ID and is replaced by
write-fsync-rename; readers never see a partial file. An ended session's pair is removed.

Signed peer text proves provenance, not safety. **Escaping and provenance wrapping happen in the
daemon's context generator**, not in each vendor adapter, so `context.get` and every paired fallback
inherit one implementation; two adapters would otherwise implement the rule twice and drift. The
escape set is normative: C0 and C1 controls, ESC, CSI/OSC/DCS introducers, BiDi overrides
(U+202A–U+202E, U+2066–U+2069), zero-width and invisible characters (U+200B–U+200F), Unicode tag
characters (U+E0000–U+E007F), and NFC normalization. Every peer-authored string is delivered in a
structured envelope carrying its provenance fields as **siblings** of the text, never concatenated
into a prose block. Adapters keep remote text in bounded structured data, never turn it into server
instructions or tool definitions, and never reduce local approvals.

**No field of generated context may be interpreted as an instruction.** The closed list is
`task.title`, `task.body`, `task.state_reason`, `memory.key`, `memory.body`, `plan.title`,
`plan.body`, `rationale_summary`, `labels`, and every `actions[]` string. Escaping does not address
the realistic payload, which is well-formed prose: `memory.appended` is proposable by any editor
agent, is committed and replicated to every device, is rendered into every peer's context, is
retained for the session's lifetime, and per §6.1 can be superseded but never deleted — so one
record from a subverted member is a durable, session-wide, all-devices injection surface that
provenance labelling identifies but does not neutralize (§16). The mitigation that actually holds
is that no protocol decision depends on agent compliance: publication authority, review, task
ownership, and every override are reducer- or IPC-enforced above and in §6.4.

MCP cannot observe every native action. Agents SHOULD report intent, rationale summary, decisions,
affected files, command/tool names and summaries (never raw arguments), tests, and results. V1 does
not install vendor hooks: independently launched hooks cannot safely inherit the bound adapter's
in-memory capability without adding another secret-distribution path. Richer capture is deferred and
does not affect coordination.
