# CodeComm V1 Design — Part 08: Repository Synchronization

Part 8 of 14. Contents: §8 Git object/ref mesh, bootstrap, canonical advancement and conflicts, ignore rules and control files.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 8. Workspace and Git Synchronization

### 8.1 Direct Git object/ref mesh

CodeComm exchanges immutable Git objects and CodeComm-owned refs directly between authorized
peers; no transfer traverses the Raft leader. Each daemon maintains a session-bound bare store under
`<per-user state>/codecomm/sessions/<workspace_id>/git/` — outside the workspace, so no Git
operation the operator runs can delete it (§6.2) — containing only shared objects and these
namespaces:

| Ref | Meaning |
|---|---|
| `refs/codecomm/canonical` | Local materialization of the replicated canonical pointer (§7.2) |
| `refs/codecomm/publications/<publication_id>` | Pinned validated publication commit |
| `refs/codecomm/drafts/<device_id>/<draft_stream_id>` | Monotonic source-owned pointer for one agent/root generation |
| `refs/codecomm/remotes/<device_id>/drafts/<draft_stream_id>` | Receiver tracking copy; never advertised as its own work |
| `refs/codecomm/retention/drafts/<device_id>/<snapshot_id>` | Local-only reachability pin for a retained or explicitly pinned snapshot |

`refs/codecomm/**` is exclusively reserved. Before host, join, adoption, or first user-repository
materialization, CodeComm inventories the namespace and refuses an unexpected pre-existing ref; a
resume accepts only names/OIDs matching durable local metadata. It never assumes an identically named
ref is its own. Every later write uses an expected-old-OID `update-ref` transaction (zero OID for
creation); an external change or new name blocks with `ref-tampered` and is never overwritten. Object
fetch may stage under private temporary names, but no Git child writes a final user-repository
CodeComm ref directly.

The session fixes one Git object format, so `snapshot_id` is the lowercase raw commit-OID hex and is
ref-safe. Artifact bundles advertise exactly one temporary head:
`refs/codecomm/artifacts/drafts/<snapshot_id>` for a draft or
`refs/codecomm/artifacts/publications/<publication_id>` for a publication. Import removes that
temporary name and atomically creates only the destination ref above; any extra advertised ref
rejects the bundle.

The peer API serves this bare store only, never the user's `.git`. It runs allowlisted
`upload-pack` protocol-v2 plumbing and resumable bundle transfer with direct argv, a sanitized
environment, bounded processes/bytes/time, backpressure, and epoch mTLS. It exposes no
`receive-pack`, arbitrary command, repository path, user ref, alternates, or unadvertised-object-ID
surface. Incoming bundles enter a per-session quarantine and are verified before atomic import.
Revocation closes transfer immediately; leader loss does not affect surviving-peer exchange.

“Atomic import” means atomic **visibility of the ref**, not a fictitious transaction spanning pack
files and refs. The receiver verifies in an isolated quarantine repository, requires exactly the
expected synthetic refs, rejects objects outside the declared reachable closure, then holds the
store import/GC mutex while migrating objects, fsyncing required files/directories, and committing
one `update-ref --stdin` transaction. A crash before the ref commit may leave unreachable objects
for later cleanup but exposes no ref and earns no receipt; a crash after it is recoverable from the
durable ref. No accepted event depends on the objects until that pin and receipt are durable.
For a publication bundle's declared base prerequisite, quarantine may read only the daemon-selected
session bare store through Git's quarantine alternate mechanism; repository config, bundle input,
and callers cannot name an alternate, and every new object is still written and enumerated in
quarantine before migration.

Eligible dirty and untracked work is shared as an immutable **sparse draft snapshot**, never as
remote filesystem mutation. After a bounded debounce, and on explicit checkpoint/publish/shutdown,
the daemon computes status against the worktree's `HEAD` with hooks, filters, helpers, submodules,
and LFS network disabled. Watch notifications coalesce to one dirty bit per managed root; queue
overflow triggers one bounded full scan rather than retaining per-path events. It captures only
§8.4-eligible dirty/untracked paths; a clean branch switch
therefore emits nothing. `manifest.jcs` is the exact JCS encoding, without a trailing newline, of
this closed object:

```json
{
  "schema_version": 1,
  "object_format": "sha1",
  "base_commit": "sha1:<hex>",
  "entries": [
    {
      "path": "src/x.go",
      "operation": "upsert",
      "base_blob_oid": "sha1:<hex>",
      "base_mode": "100644",
      "result_blob_oid": "sha1:<hex>",
      "result_mode": "100644"
    }
  ]
}
```

`object_format` is the session's `sha1` or `sha256`; every OID is tagged with that value. Entries are
nonempty and sorted by canonical path bytes, with no duplicate or unchanged path. Base fields are
the `HEAD` blob and mode for a tracked path and both null for an untracked upsert. Result fields are
the worktree blob and mode for `upsert` and both null for a tracked `delete`. Modes are the strings
`100644` or `100755`; every other null/value combination rejects. This records deletion explicitly
rather than silently retaining `HEAD` content. Index/staging distinctions collapse to worktree
content.

The daemon uses a temporary index (`GIT_INDEX_FILE`, never the real one) to create a parentless
synthetic container commit with exactly two root entries: blob `manifest.jcs` and tree `files`,
whose paths, blobs, and modes mirror exactly the manifest upserts; delete-only snapshots use the
empty `files` tree. The sanitized commit is deterministic and non-identifying: author and committer
are exactly `CodeComm Draft <draft@codecomm.invalid>`, both timestamps are Unix 0 `+0000`, the
message is exactly `CodeComm sparse draft v1\n`, and no optional encoding or signature header is
present. Its bundle carries only that commit/tree, manifest, and upsert blobs, with complete
reachable closure. An empty manifest is not emitted.

The manifest digest is
`SHA-256("codecomm/v1/draft-manifest" || 0x00 || JCS(manifest))`. This sparse shape is
load-bearing: seeding a full tree from a local `HEAD` would retransmit the repository on every
snapshot and could carry an excluded secret or unapproved control file merely because it already
existed in that commit. A receiver verifies the exact two-entry container shape, manifest
digest/size/count, tree/manifest equality, modes, and absence of every ineligible path before
making the ref visible. It can inspect and preserve changed bytes without possessing
`base_commit`; restore compares each target blob/mode with the manifest's base fields and surfaces
a conflict rather than overwriting on mismatch. Materializing a normal commit applies the verified
manifest to an operator-selected baseline in an isolated managed worktree; the synthetic container
itself is never cherry-picked or merged.

Capture does not touch the real index, `HEAD`, user refs, or files, and §12.2 asserts byte identity
with a dirty index and detached `HEAD`. A draft does not carry:
`git stash` entries, reflog, local branch topology, an in-progress rebase/merge/cherry-pick or
bisect, submodule working state, file modes beyond the executable bit, and — per §8.4's
non-regular-file exclusion — newly created symlinks. Anything §8.4 excludes (`.env*`, keys,
caches, build outputs, control files, and every `.codecommignore` match) is not shared by default,
so that work lives only on its origin device and is lost with it. `codecomm repo status` names what
is ineligible so this is visible rather than inferred.

**Opt-in inclusion.** Because an excluded path having no off-machine copy is itself a data-loss
risk, an operator MAY include specific excluded paths in that device's drafts through
`codecomm repo include`, subject to all of the following (OQ4 resolved):

- **Per path or explicit glob, never a blanket override.** There is no "include everything"
  setting, and a glob MUST NOT be broader than a single directory level. Including a whole
  ignore-file's worth of paths at once is refused.
- **Preview before consent.** The command lists every file the pattern currently matches with its
  size and a content-class heuristic, and refuses without an interactive confirmation naming the
  count. It MUST NOT accept the confirmation non-interactively in the same invocation.
- **Secret-shaped paths require a second, differently-worded confirmation** and are always named in
  the preview: `.env*`, anything under a `.ssh`, `.gnupg`, or credentials directory, `*.pem`,
  `*.key`, `*.p12`, `*.keystore`, cloud credential files, and any file whose content matches the
  §12.4 secret-scan patterns. The prompt states plainly that **every member device will be able to
  read it, that members may be other people's machines (§2.1), and that inclusion cannot be undone
  for data already replicated** — revocation ends authorization, not possession (§10).
- **Local and per device.** The inclusion list is local configuration, never committed, never
  replicated, and never inherited by a peer: it governs only what *this* device offers. It is
  therefore not a control file and does not go through §8.4's approval flow, since it grants no
  authority over another device.
- **Always visible.** `repo status`, `repo doctor`, and the TUI list active inclusions with their
  match counts, and a session with any secret-shaped inclusion carries a persistent indicator.
  `codecomm repo exclude` removes an inclusion and stops future drafts from carrying it; already
  replicated snapshots are immutable and remain.
- **Control files stay excluded regardless.** Every path classified by §8.4's committed
  `control_path_policy_version` MUST NOT be includable: replicating it as draft content would route
  around the per-device consent boundary.

The security review owns this path (§16), and §12.4 covers it: a blanket pattern is refused, a
secret-shaped path requires the second confirmation, a non-interactive confirmation is refused, an
attempt to include a control file is refused, and the inclusion list never appears in any
replicated projection or digest. Each agent/root generation gets a random never-reused
`draft_stream_id`; restoring local metadata or starting a new agent opens a new stream instead of
resetting a sequence. The closed source-signed advertisement contains `schema_version`,
session/workspace IDs, source device and nullable agent session, stream ID, `sequence`,
`base_commit`, `prior_snapshot_oid`, `snapshot_oid`, manifest digest/encoded size/entry count,
artifact digest/encoded size, and signature under `codecomm/v1/git-ref-advertisement`. Sequence
starts at 1 with null prior; later advertisements name the source's immediate prior stream head.
`base_commit` and all manifest metadata must equal the verified container. Unchanged content emits
no new sequence.

The §11.2 manifest/artifact bounds and workspace-file ceiling are checked streaming before object
visibility. A peer requires the source device to be active in its applied membership, then verifies
namespace ownership, exact synthetic bundle head/reachable closure, and
the sparse-container rules above before CAS-advancing only the matching tracking ref. A source's
locally consented secret-path inclusion is visible in the manifest but is not a receiver-side
rejection, because every member is already an all-read principal (§2.1). Equal/lower sequence is
rollback; an exactly-next sequence requires `prior_snapshot_oid` to match. A forward gap is allowed
after verifying the independent artifact and is recorded as missing history; it never pretends
continuity or requires an earlier draft. A wrong prior OID on an exactly-next advertisement rejects.
Relays preserve source signature, namespace, and bytes. Applying revocation rejects every later
advertisement/advance from that source and stops transfer; it does not erase already imported
immutable snapshots or local retention refs. A stale source may continue signing until it applies
its own revocation, but informed receivers discard those messages.

Draft refs/metadata obey one **ceiling**: retain the newest §11.2 count per source device across all
streams, not per stream. The latest head of each live agent/root stream is protected while that
stream is live and counts toward the ceiling; remaining slots retain newest historical snapshots.
When live heads alone reach the ceiling, creating another stream is refused until one ends. Retired
stream refs/metadata disappear once no retained or explicit-pin ref
needs them. Explicit pins are local, never silently evicted, and capped per session; hitting the pin
cap or storage quota refuses a new pin. The ceiling is not a durability promise for unpinned
history: quota pressure may prune oldest historical snapshots below it, but never a live head or
explicit pin.

Drafts are not strong state and never advance canonical. Status says `replicated` only after one
other active member durably imports the snapshot; otherwise it says `local-only` and retries.
**Reachability, quota, and garbage collection.** Every depended-on object is reachable from a
CodeComm-owned ref before use. An import is pinned under
`refs/codecomm/publications/<publication_id>` (or a draft/retention ref) before a receipt or
advertisement; the import/GC mutex covers migration through durable ref commit. `gc.auto` is disabled
so Git cannot collect mid-import. The daemon may run explicit bounded maintenance **only in its bare
store**, under that mutex, after atomically deleting eligible refs and expired artifacts; it never
runs GC in the user's repository. Pruning honors §11.2's minimum unreachable-object grace.

A publication ref starts as a local **pre-proposal staging pin** carrying its proposal event ID,
metadata digest, and signed `staged_result_index`. It counts against `publication_staging_pin_cap`
until that exact proposal event is accepted; reservation occurs before transfer. Its committed
rejection releases the pin, while a still-unaccepted pin becomes collectible when the nonnegative
`current_result_index - staged_result_index` exceeds the committed window. Result processing
precedes cleanup, and implementations compare before subtracting and never add the window to an
index. Acceptance converts the pin to protected nonterminal retention even after receipt expiry; a
fresh apply receipt binds the accepted publication's original proposal event and needs no reimport.
Crash recovery derives the class from the durable preparation/receipt, replicated publication row,
and command result before deleting any ref.

The session Git quota counts the bare store, quarantines, retained artifacts, control content,
CodeComm conflict worktrees/snapshots, and temporary bundles. Before transfer/import the daemon
reserves §11.2's declared-size headroom. If pruning and serialized bare-store GC cannot make room, it
refuses a new draft, publication receipt, bootstrap, control upsert, conflict worktree, or pin with
`git-storage-full`, without deleting canonical, nonterminal publication/conflict, live-draft-head,
unexpired pre-proposal staging, or explicit-pin reachability. A full staging-slot set returns
`publication-staging-full` before transfer. Lowering local configuration below current use is valid: the daemon
starts `git-storage-over-quota`, performs only safe pruning/GC and deletion/export operations, and
admits no quota-growing work until use falls below the limit or the limit rises. It never refuses
startup or evicts protected data merely because the configured ceiling fell. A committed canonical
ref may remain `object-lagging` on a non-receipt peer, but no voter signs durability it lacks. The
user's `.git` and working files are outside this quota; §11.2's 2x figure is a planning baseline, not
an enforceable filesystem cap.

An accepted publication pin is protected while its publication is nonterminal or any unresolved
`merge_conflicts` row references it. After a terminal transition:

- an `applied` holder keeps the publication ref until its bare-store
  `refs/codecomm/canonical` durably points to that commit or a descendant whose first-parent chain
  contains it, then removes the redundant publication ref under the import/GC mutex; every later
  canonical advance has the prior canonical commit as first parent (§7.2), so canonical reachability
  preserves the objects without an idle-session timer. After §3.1 explicitly selects an earlier
  canonical ancestor, an applied row with `canonical_lineage_member = false` releases as historical
  unless an unresolved conflict protects it;
- a `rejected`/`withdrawn` holder removes the ref immediately when no unresolved conflict references
  it, or immediately after the last such conflict resolves.

Receipts remain historical evidence of staging, not a perpetual availability promise beyond these
rules. An unresolved conflict's `merge_base_oids` and `candidate_commit` may be reachable only
through that pin, so releasing it earlier would make a committed conflict unresolvable. If the operator's
own `gc --prune=now`, `reflog expire`, or `repack -ad` in the working repository does remove an
object a peer's ref needs, the daemon reports `object-lagging` and refetches from a receipt holder
rather than failing; §12.3 injects exactly these operations.

**Staging coverage is continuous, not one-shot.** A later voter-target change must not strand the
current canonical object on departing voters. Each target device that durably imports and validates
the exact canonical commit signs
`(session_id, workspace_id, voter_set_version, canonical_ref_version, commit_oid, voter_device_id)`
under `codecomm/v1/git-canonical-coverage`. Before any Raft configuration call, §3's reconciler
requires receipts from a majority of the current target and rechecks that the canonical version has
not advanced. It MUST NOT remove an old voter while coverage is missing; leader change merely
recollects receipts. `object-coverage-degraded` names missing targets/objects. Uninstall or
`sessions leave` likewise refuses without explicit data-loss override when this device holds the
sole known canonical copy (§10.1).

Retention applies the per-source ceiling and explicit pins on both source and receivers. Workspace
checkout, stash, reset, clean, branch switch, or deletion cannot touch those out-of-tree refs; only
the quota policy above may prune unpinned history. A clean branch switch creates no dirty snapshot
or mass transfer. Inspect, pin, restore, materialize, or discard is explicit; no received draft is
checked out automatically, and raw cherry-pick/merge of its synthetic container is refused.

### 8.2 Initial Git bootstrap

Hosting requires a Git repository with a reachable commit. `git init` or an initial commit requires
explicit consent. Host preflight inventories every §8.4 control path and any working-tree deviation
from its committed bytes; explicit confirmation records the host's current bytes/deletions as that
device's initial local approval and offers a later proposal for deviations. The existing source
working tree remains user-managed and is never an agent-launch root. Destination handling is:
matching `workspace_id` resumes; the same name with a different/no identity requires preview and
adopt/merge; a different name offers `<cwd>/<workspace-name>`; non-empty content is never
overwritten without preview/confirmation.

Bootstrap:

1. Select an up-to-date owner/editor source (§3). It captures eligible dirty/untracked state as
   one immutable draft before freezing the manifest.
2. Source creates a bounded bundle containing the canonical commit, selected CodeComm refs, and
   that draft, with SHA-256, size, object format, source identity, and expiry.
3. Joiner downloads resumably over mTLS, verifies digest/size, runs `git bundle verify`, and clones
   `--no-checkout` with direct argv and isolated configuration.
4. Hooks, recursive submodules, credential helpers, external filters, alternates, and automatic
   Git LFS network access remain disabled. Seed the session bare store from the verified bundle.
5. Build the destination in a private staging directory. Before the first checkout, install
   per-worktree non-cone sparse/skip-worktree rules that exclude every §8.4 control path, then
   materialize the remaining tree and register canonical control bytes as pending local bootstrap
   reviews. Clone therefore never writes unapproved guidance. The intentional missing paths are
   labeled like later local control-file deviations.
6. The primary working tree otherwise stays at canonical. The source draft is visible for explicit
   inspect/apply and is never overlaid automatically. Complete or decline bootstrap control reviews
   before launching agents or shells, then enable direct peer exchange and delete expired staging
   artifacts.

Every CodeComm-created primary, isolated, or shared worktree is a **managed root** and keeps that
guard. Approved upsert bytes are cached outside the workspace; an approved delete is a durable
tombstone. Before creating an agent-launch registration for a root or invoking
checkout/reset/clean/stash/branch there, the daemon verifies the per-worktree sparse config and
index flags. A root-mutating operation additionally requires zero pending launch registrations and
zero live or resumable agent bindings for that root. It removes/caches overlays, runs Git with
control paths excluded, verifies no canonical control byte appeared, then atomically restores each
approved path/tombstone while the root remains unavailable to agents. Failure leaves the root
blocked, not presented as ready. Native
notifications plus scans detect later rule/overlay drift; `repo doctor` names it, and CodeComm
refuses new launch registrations, snapshots, or publications from that root until repair.

This guarantee covers bootstrap and operations CodeComm invokes in managed roots. A user or agent
running arbitrary Git/filesystem commands under the same OS account can clear skip-worktree bits or
write any file; CodeComm cannot interpose on that process and does not claim otherwise (§10).

Preflight shows identities, destination, refs, sizes, ignore policy, submodule/LFS limits, and
rejects or requires resolution for case/Unicode collisions, Windows-reserved/invalid names,
escaping symlinks, and file count/size limits. After join, the CLI may `chdir` and launch a child
TUI/shell but cannot change its parent shell.

### 8.3 Canonical advancement and conflicts

The replicated `canonical_refs` row, not any member's branch, is shared truth. A publication
advances it only through §7.2's reviewed, quorum-staged dual CAS.

**Where the objects live, and how a human reaches them.** The session bare store is the authority
for CodeComm-owned refs and the only store the peer API serves. Because `git` alternates are
disabled and the bare store is not the user's repository, canonical objects would otherwise be
unreachable from the working repository — so on materialization the daemon **also writes the
canonical objects and `refs/codecomm/canonical` into the user's `.git`**, by fetching from the bare
store. The duplication is deliberate and bounded: §11.2 budgets it, and it is what makes every verb
below plain local Git rather than a CodeComm-specific object protocol.

Local materialization updates only `refs/codecomm/canonical` and never `HEAD`, the index, a user
branch, or a working tree. It fetches objects under a private temporary ref, then uses the durable
last-materialized OID as the expected old value in one `update-ref` transaction (zero OID only for
first creation); a missing local record, unexpected ref, or CAS failure blocks as `ref-tampered`
without overwriting. `git status` is therefore silent by design. That silence is a hazard if
unaddressed, so the ahead/behind signal lives in three places: `codecomm repo status` reports the
canonical commit against the working `HEAD`, the TUI labels a working tree whose `HEAD` lags
canonical, and `codecomm repo integrate` performs the operator's chosen merge or rebase of canonical
into the current branch by invoking system Git with the resolved ref. `codecomm repo worktree`
creates a worktree at canonical. Nothing is automatic: a checkout, stash, reset, or branch
operation affects only its origin, and no received draft or canonical advance ever mutates a peer's
tree.

A stale publication is never silently merged. An explicit merge starts from current canonical and
runs system Git `merge-tree --write-tree` in an isolated temporary repository; its publication tip
uses ordered parents `[canonical, candidate]`. Rebase runs system Git in an isolated worktree,
identifies each replayed source commit, then uses §7.2's wrapper/squash profile so canonical is the
final tip's first parent. Both use direct argv, an empty
`core.hooksPath`, no external merge drivers, filters, helpers, submodule/LFS network, or user/global
configuration. Attributes committed in the input trees remain immutable merge inputs; CodeComm does
not claim Git can ignore them. The committed `merge_inputs_version` names the supported Git behavior
profile and fixed rename/conflict settings; phase 1 freezes a cross-platform corpus for every
supported Git release (§12.2).

Conflict identity contains only immutable operation/graph inputs, never detector output:

```text
conflict_id = "ccf1" || lowercase_hex(SHA-256(
  "codecomm/v1/conflict-id" || 0x00 || JCS({
  "workspace_id": workspace_id,
  "merge_inputs_version": merge_inputs_version,
  "merge_kind": "merge" | "rebase",
  "publication_id": publication_id,
  "replay_commit_oid": null | source_commit_being_replayed,
  "merge_base_oids": sorted_unique_merge_base_oids,
  "canonical_commit": canonical_commit,
  "candidate_commit": candidate_commit
})))
```

`merge_base_oids` contains every OID from `git merge-base --all`; it does not invent an OID for an
ort virtual base. `replay_commit_oid` distinguishes each step of an N-commit rebase and is null for
merge. OIDs are algorithm-tagged. Conflicting `paths` are separately sorted in §8.4 canonical form
and carried in the event for display/authorization, but excluding them from the ID prevents two Git
builds from creating duplicate logical rows merely because they report paths differently.

After payload and deterministic-ID validation, the reducer looks up `conflict_id` before consulting
current publication or canonical state. For an existing row, an exact tuple-and-path re-detection is
an idempotent no-op even after canonical advancement or publication termination and never resets a
resolved row. A different immutable tuple rejects with `conflict_immutable_tuple_mismatch`; equal
tuple but different paths rejects with `conflict_detector_paths_mismatch`. Each rejection carries a
deterministic local alarm directive with that code; the apply layer MUST materialize at most one
alarm per committed command-result identity. Directives and alarms are derived local state and MUST
NOT enter events, replicated projections, projection mutations, the accumulator, or the state
digest. For an absent row, the named publication MUST be nonterminal and `canonical_commit` MUST
equal the replicated canonical commit at reduction; otherwise detection rejects. This first-detection
rule keeps the candidate pin available and rejects stale merge inputs without weakening exact
re-detection. Thus convergence does not depend on filesystem case behavior or byte-identical
conflict messages, while the golden merge corpus still requires supported builds to agree on paths.

Staging voters additionally require `base_commit` to be `commit_oid`'s first parent and apply §7.2's
bounded introduced-history walk. A net tip diff is insufficient: a two-commit history can modify an
unleased/control path and revert it, leaving no `base..tip` change while still exposing both commits
and blobs. The union of every introduced commit's no-renames first-parent diff therefore drives
`paths`, mode/control eligibility, and lease authorization. Requiring the base as first parent keeps
canonical ancestry explicit. Clean linear/rebased work is squashed or wrapped under one such tip. A
normal rebased tip does not retain the original candidate as an ancestor, so it cannot resolve a
committed rebase conflict under the two-tip ancestry rule. Such a conflict therefore resolves
through an ancestry-preserving merge publication with `[canonical_commit, candidate_commit]` as
parents and the reviewed resolved tree; V1 does not substitute patch-equivalence heuristics.

Resolution creates and reviews a new publication declaring the conflict ID. Staging voters verify
that `canonical_commit` and `candidate_commit` from the committed conflict row are both ancestors of
the resolution commit and bind that fact into receipts. Accepted `publication.applied` is
authoritative historical proof that its then-current receipt-age and voter-target quorum checks
succeeded. `workspace.conflict.resolved` therefore CAS-links only an applied publication that
declares the conflict and MUST NOT reapply receipt freshness or current-voter-target rules; later
result-index or voter-target changes cannot invalidate that proof. It then sets
`resolution_kind = publication`. The owner-only force path sets
`resolution_kind = forced`, a bounded reason, and no publication ID (§6.4). CodeComm shows graph
inputs/ours/theirs/paths and never chooses a side or silently deletes an immutable ref.

### 8.4 Ignore rules and control files

A **canonical repository path** is 1–512 UTF-8 bytes normalized to NFC, uses `/`, preserves case,
and has no empty, `.`/`..`, absolute/drive/UNC, NUL/control, trailing-dot/space, ADS, or
platform-reserved component. Git permits non-UTF-8 or longer names, but V1 rejects them at preflight
rather than signing platform-dependent bytes. Reducers compare canonical paths case-sensitively
regardless of the checkout filesystem. Event path arrays also obey §11.2's aggregate encoded bound.
Lease patterns are exact paths or one terminal `dir/**` prefix (§6.1).
Symlink containment is checked before local I/O; a path string never authorizes following a link
outside the workspace.

**Control files** configure agent behavior and are the only paths requiring per-device approval.
Always exclude `.git/`, `.codecomm/`, staging paths, non-regular files, selected caches/build
outputs, and configured credentials from drafts. Exclude `.env*`, private keys, cloud credentials,
and signing material by default; opt-in requires preview/warning. `.codecommignore` is
authoritative; `.gitignore` import is optional because semantics differ.

`control_path_policy_version = 1` is a closed canonical-path classifier. To prevent an alias such as
`agents.md` from materializing as `AGENTS.md` on a case-insensitive filesystem, only this classifier
ASCII-folds `A`–`Z` to `a`–`z` before matching. It marks any path whose folded basename is
`agents.md`, `agents.override.md`, `claude.md`, or `.gitignore`, plus these folded repository-root
paths and descendants: `.codex/**`, `.claude/**`, `.mcp.json`, and `.codecommignore`. Prefix
entries include the directory itself. Canonical path identity, leases, sorting, and every other
comparison remain case-sensitive over the original NFC bytes. No local config may alter the
classifier; reducers and staging voters must agree. A future client format requires a new committed
policy version and apply-level gate and MUST NOT reinterpret version 1. Automatic drafts and
ordinary publications exclude every version-1 control path.

Changes use signed bounded `control_file.change_proposed` events carrying path, explicit
`operation`, bounded diff, and operation-valid content metadata. For `upsert`, the SHA-256 digest is
required and `content_size` is `0..control_file_max_bytes` (1 MiB), so an empty file remains
distinct from deletion. For `delete`, digest is null and size is zero. Reducers reject every other
combination and an oversized upsert before fetch. **The diff is for review, not transport**: upsert
content is fetched by digest from `GET /v1/git/artifacts/{sha256}` on the content plane, and the
receiver requires both committed size and digest, then durably caches approved bytes before atomic
overlay. Delete fetches no artifact and uses a containment-checked atomic remove plus a durable local
tombstone. A mismatch discards quarantine; unavailable content or quota stays visible and
unappliable rather than partially applied. The proposal is committed; approval/content/tombstone are
local, never replicated or digest-covered, so one device cannot consent for another (§2.5).
Approval applies exactly the committed operation and records the decision; decline leaves the path
untouched. Approved tracked control files intentionally remain local deviations from the canonical
Git tree; while a managed-root guard remains intact, Git excludes them and `control-files review`
labels their state. A stale digest requires re-proposal. The TUI shows local current and proposed
digests. Presence publishes only the bounded current control-manifest version/digest/count derived
from durable approved content/tombstone rows, never pending proposals or live-root drift; peers fetch
exact paths/digests by that version **and** digest through §5.1's stable paginated endpoint. Neither
is a committed event. A
peer's current digest equalling a proposed digest *is* its approval decision, so the
approval choice is visible to members. Per-device approval prevents remote application; it does not
hide the choice from members who already read the event stream (§2.1).

**Divergence is legitimate and its cost must be visible.** `.codecommignore` and
`AGENTS.md`/`CLAUDE.md` are themselves control files, so two devices can permanently hold different
ignore policies — hence different draft-eligible sets, so the same command shares different files —
and different agent instructions, hence agents that behave differently on the same task.
`codecomm control-files review` lists every path where a peer's current digest differs from the
local one, and `codecomm repo doctor` reports policy divergence as a named condition, so "my agent
behaves differently than yours" is diagnosable rather than mysterious.

Portable guarantees cover regular content and executable intent where supported, not ownership,
ACLs, ADS, xattrs, or exact timestamps. Submodules and LFS require explicit separately
authenticated setup; no publication or draft triggers their network clients.
