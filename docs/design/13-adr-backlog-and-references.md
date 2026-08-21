# CodeComm V1 Design — Part 14: ADR Backlog and References

Part 14 of 14. Contents: §17 ADR backlog, §18 references.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 17. ADR Backlog

- ADR-001: Direct mTLS mesh and replaceable Raft leader.
- ADR-002: **Revised by ADR-064.** Origin-signed append-only events, deterministic projections,
  apply-time integrity chains, and committed authority-signed checkpoints; ordering metadata is
  unsigned local provenance.
- ADR-003: The frozen primitive suite — Ed25519 signatures, SHA-256 digests, RFC 8785 JCS canonical
  form, unpadded base64url, and per-context domain separation. Scope is the suite and its migration
  path only; credential lifetimes belong to ADR-033. Formerly bundled stable identity plus quorum-authorized rotating TLS keys with a committed
  V1 epoch length of 30 minutes and two-minute make-before-break overlap.
- ADR-004: Multicast discovery with manual fallback.
- ADR-005: REST/SSE plus internal Raft and bounded Git artifact/upload-pack endpoints.
- ADR-006: Workspace identity independent of directory name.
- ADR-007: Never copy `.git/` state or remotely mutate a working tree; use validated Git plumbing
  and CodeComm-owned refs.
- ADR-008: Direct Git object/ref mesh with immutable source-namespaced draft snapshots.
- ADR-009: Rationale summaries, not chain-of-thought.
- ADR-010: No V1 relay; Ethernet/user VPN fallback.
- ADR-026: Endpoint hints are gossip with a TTL, never committed state; churn and suspend/resume
  are first-class recovery paths.
- ADR-011: Verified Git bundle bootstrap.
- ADR-012: Local stdio MCP for Codex and Claude Code.
- ADR-013: Per-device approval for control files.
- ADR-014: Native Windows V1 support.
- ADR-015: Direct rotating mTLS authorization for Git object/ref transfer.
- ADR-016: Unique agent sessions and isolated worktrees.
- ADR-017: Per-session SQLite, one database per joined workspace, with logical replication.
- ADR-018: Logical command-result batches/snapshots, never SQLite diffs.
- ADR-024: **Refined by ADR-107.** Frozen reducers per `(kind, schema_version)`; halt rather than
  diverge on an unappliable committed entry; N-1 supported skew.
- ADR-025: **Revised by ADR-080.** Formerly one normative projection digest over declared tables at
  committed checkpoints.
- ADR-019: Permanent regression harness and release gates.
- ADR-020: Maintained embedded Raft and production stable store.
- ADR-021: Production engineering requirements are release criteria.
- ADR-028: Named version floors and one constants table split committed reducer policy from local
  installation limits; member, agent, claim, and lease cardinalities are per session.
- ADR-029: Measurable service targets with named endpoints and enforcing gates; resource budgets
  at daemon and device scope.
- ADR-030: Owner and editor roles only; no read-only role in V1, and no confidentiality
  boundary between members.
- ADR-031: **Revised by ADR-064.** Catch-up replays contiguous first-seen results; a signer is
  authorized only after scratch replay reaches an authority in which it is active. Checkpoint-cut
  snapshots and contiguous tails are position-verifiable; origin signatures alone are not.
- ADR-032: Quorum-staged publication bundles plus an atomic replicated canonical-ref CAS; local
  materialization is asynchronous and touches only CodeComm refs/objects, never `HEAD`, index, user
  refs, or working-tree content.
- ADR-033: 30-minute quorum-authorized content credentials; admission (applied membership) and
  authorization (leader-confirmed membership) are separately gated; only an elected leader that has
  applied through its committed membership index replicates. Owns the epoch/overlap/renewal-lead
  values, which ADR-003 no longer duplicates.
- ADR-039: Two member-plane transport — consensus is authenticated by long-lived device identity
  and never expires; 30-minute epoch credentials are scoped to the content plane. **Supersedes the
  cold-start rekey listener** and the pre-election data-confinement argument it required: a
  consensus channel whose authentication expires cannot recover itself, and the restricted listener
  that worked around this produced an unrecoverable-lockout defect and a proposal-freeze deadlock.
  Revises ADR-003, ADR-015, and ADR-033. ADR text is never edited in place once authored;
  superseded records are marked, not rewritten.
- ADR-040: Git-native object/ref exchange with immutable source-namespaced draft snapshots and
  quorum-staged canonical publications, **superseding live working-tree replication**. Records the
  rejection: excluding `.git/` forces working-tree-only sync, which leaves each peer's `HEAD` and
  index unrelated to arriving files and makes an ordinary checkout or reset an unbounded remote
  edit. Revises ADR-007, ADR-008, ADR-015, and ADR-032.
- ADR-041: The daemon is the sole constructor of an event's `origin` block; `actor_type` is not
  cryptographically distinguishable within a device, so operator-only authority is an IPC-boundary
  property, not a reducer-checkable one.
- ADR-042: **Superseded by ADR-060.** Formerly combined reducer-enforced publication authority with
  a path-derived working-root binding and universal different-device review.
- ADR-043: **Revised by ADR-088.** Accepted domain events are their own audit source;
  `audit.recorded` was reserved for rejected active-member actions and capped per subject/epoch.
- ADR-044: Durable session state lives outside the workspace, because `git clean -x` ignores
  `.git/info/exclude` and would otherwise delete the Raft log and database.
- ADR-045: **Refined by ADR-085.** Pairing uses a one-use high-entropy invite with pinned inviter
  identity, exporter-bound HMAC proof, and mandatory two-sided SAS comparison; V1 does not ship the
  formerly contemplated SPAKE2+ short-code mode.
- ADR-046: No encryption at rest in V1; reliance on full-disk encryption with tri-state detection;
  identity keys retained indefinitely for verification, no rotation within a `device_id`, and no
  key escrow.
- ADR-047: Go as the V1 implementation language; Rust/Tokio/Ratatui is a named alternative requiring
  a superseding ADR rather than a phase-time choice.
- ADR-048: Operator override authority is always available to an owner device, and every override
  records its originating IPC channel.
- ADR-049: Consensus over CRDT/LWW for the small set of strong decisions (§1.1).
- ADR-050: CodeComm is Apache-2.0; system Git is invoked, not redistributed.
- ADR-051: Reassignment persists a one-shot intended device (split from the former combined record).
- ADR-052: Merge-conflict identity is a versioned digest over pinned merge inputs, including all
  merge bases and the merge kind (split from the former combined record).
- ADR-034: Voter changes are committed resulting-set intent plus idempotent ordered single-server
  reconciliation; application membership gates access, the live Raft configuration alone defines
  quorum, promotion requires target-applied checkpoint proof, ADR-059's object-coverage gate
  precedes every configuration call, and ADR-065 separates desired target from activated
  credential authority.
- ADR-035: Same-process monotonic elapsed time schedules a versioned committed release; restart or
  snapshot import arms full TTL, and reducers never read clocks or infer time from event volume.
- ADR-036: Daemon versions are committed device state; cluster minimum raises never read presence.
- ADR-037: **Superseded by ADR-051 and ADR-052.** Formerly combined reassignment and conflict
  identity in one record.
- ADR-027: Offline quorum recovery with a successor genesis record, an offline recovery key, and
  explicit readmission pairing of survivors.
- ADR-022: Device as sole principal; no user or account identity.
- ADR-023: Per-user supervisor service plus one session daemon per joined workspace.

- ADR-053: Solo ownership with a written self-review checklist in place of second-person review for
  crypto, consensus, reducer, and migration changes; recorded as a risk rather than presented as
  equivalent (§16).
- ADR-054: Two-device sessions are supported at one voter, with a `host`/`join` voter-placement
  prompt and a persistent degraded-tolerance indicator, rather than a three-device minimum
  (OQ3).
- ADR-055: Draft eligibility keeps safe defaults plus a preview-gated, per-path, local-only opt-in
  (`repo include`); control files are never includable, since that would route around §8.4
  per-device approval (OQ4).
- ADR-056: Activity capture is names, paths, status, timing, and bounded rationale only; raw
  arguments, output, environment, and private reasoning are excluded before persistence, because
  the record is chain-covered, unprunable, and readable by every member (OQ1).
- ADR-057: One TLS port uses three exact closed ALPN dispatchers: pre-membership pairing,
  identity-authenticated consensus, and epoch-authenticated content; certificate selection occurs
  before application bytes and no dispatcher can reach another's endpoints.
- ADR-058: Successor content credentials retain the renewal-lead lower bound but no prior-expiry
  upper bound; exact activated-authority-majority clock endorsements prevent one fast leader from
  minting a future credential while allowing next-day late renewal.
- ADR-059: **Refined by ADR-109.** Every Raft configuration call requires target-majority signed coverage of the exact
  current canonical object; canonical advance invalidates receipts and missing coverage stalls
  reconciliation without removing an old copy.
- ADR-060: The daemon alone constructs publication artifacts from an opaque committed
  `working_root_id`; active path leases grant path authority. Agent approval requires another
  device, while explicit local human approval is allowed and labeled self-review.
- ADR-061: Canonical repository paths are UTF-8/NFC, slash-separated, case-sensitive bytes with a
  restricted exact/prefix lease grammar; conflict identity hashes immutable graph/operation inputs,
  includes each rebase `replay_commit_oid`, and excludes detector paths.
- ADR-062: Agent disconnect stores the exact connected state; only the owning daemon may disconnect
  or capability-resume, a context-bound local token commitment survives daemon restart without
  storing the bearer, and resume races terminal grace reaping through one session CAS.
- ADR-063: Control-file proposals carry exact size/digest and a 64 KiB review-diff cap; the immutable
  committed 1 MiB content bound is enforced before fetch, and local approval writes only
  exact-size/digest-verified content.
- ADR-064: Two apply-time chains: accepted events provide compact domain history; immutable
  first-seen command results include deterministic rejections and preserve lifetime idempotency.
  Authority-signed checkpoints bind both heads and the projection accumulator. Result catch-up scratch-replays
  authority handoffs before trusting its signer; snapshots are signed by the authority at their cut.
  Revises ADR-002, ADR-018, ADR-025, and ADR-031; revised by ADR-080.
- ADR-065: `voter_set` is desired consensus intent; `credential_authority` changes only after every
  target is promoted, proves one checkpoint, and receives an active prior-authority handoff. The old
  authority remains usable while a target stalls. Revises ADR-033 and ADR-034.
- ADR-066: Local clients use strict HTTP/1.1 over owner-only Unix sockets/Windows pipes, bind once as
  operator or agent, and cannot supply actor/origin IDs. A durable request digest, event ID, and exact
  signed proposal make local retries crash-idempotent; arbitrary same-UID native code remains outside
  V1's boundary.
- ADR-067: Quorum recovery is a deterministic successor-generation transform: verify both chains,
  rotate the recovery key, retain historical credentials only under the old session, reset current
  mutable projection versions to 1, end old agents/release ownership, and invalidate all transport
  and resume state. The successor genesis binds predecessor heads and transformed digest. Revised by
  ADR-077.
- ADR-068: TLS 1.3 0-RTT and PSK/ticket resumption are disabled; every connection reruns membership
  and certificate admission. Content expiry uses asymmetric verifier skew plus a monotonic close
  deadline; consensus identity authentication remains non-expiring.
- ADR-069: Git import promises atomic ref visibility, not a cross-store transaction: validate closure
  in quarantine, hold the import/GC lock, migrate and fsync objects/directories, then commit refs and
  issue receipts only after the durable pin.
- ADR-070: V1 retains all accepted events and first-seen command results for the session lineage.
  SQLite WAL checkpointing and Raft log compaction may reclaim physical storage but never prune that
  logical history; payload compaction is deferred.
- ADR-071: Ordinary membership changes cannot remove the last active owner. While quorum survives,
  the genesis-bound offline recovery key may sign one dedicated event that promotes only the
  submitting active editor; it grants no other mutation and does not bypass Raft. Permanent quorum
  loss continues to require ADR-067's successor recovery.
- ADR-072: Logical snapshots use a bounded signed root, hash-chained bounded descriptor pages,
  independently verified resumable data chunks, and deterministic result-mutation continuations;
  session-lifetime history is never one body or allocation, and a legal 32 MiB mutation set never
  requires an oversized transport chunk.
- ADR-073: Control-file proposals explicitly distinguish upsert from delete, and initial bootstrap
  withholds control paths until local review so cloning cannot activate unapproved agent guidance.
- ADR-074: An active device that retained its identity but lost session state reuses the pairing
  proof/SAS in targeted rebootstrap mode; it preserves `device_id`, commits no admission, and trusts
  neither a workspace marker nor an unauthenticated peer.
- ADR-075: Owner restoration uses an operator-only local challenge/finalize flow: the daemon reserves
  the event tuple, the CLI signs it locally, and only the detached authorization enters IPC.
- ADR-076: Local configuration is strict owner-only versioned TOML with defaults-file-explicit-flag
  precedence, no environment/security override, secrets, session policy, or live reload. Immutable
  reducer bounds and relational/current-use checks constrain every mutable committed policy value;
  multicast group/port and the four-session local cap are immutable in V1.
- ADR-077: Quorum recovery requires a matching active predecessor identity. That identity always
  signs the successor body; an active owner identity or, for an active editor, the predecessor
  recovery key supplies a distinct authorization signature. Revoked, readmission-required, absent,
  and never-admitted identities are ineligible.
- ADR-078: **Revised by ADR-081.** Draft retention is bounded across all streams per source device,
  explicit pins are capped, and a per-session Git/control/artifact quota stops new work rather than
  evicting protected refs. Its signed-anchor rollover is superseded by independent snapshots.
- ADR-079: CodeComm-managed worktrees sparse-exclude control paths before checkout and overlay only
  durable local approvals/tombstones; ordinary managed Git operations cannot materialize canonical
  control bytes.
- ADR-080: Projection integrity uses an incremental mutation accumulator at ordinary checkpoints and
  a full logical-row state digest at genesis, recovery, snapshot, export, and scrub boundaries.
  This removes unbounded checkpoint scans without claiming untouched corruption is detected there.
- ADR-081: A draft is an independent parentless sparse change container: a canonical manifest records
  upserts/deletes and base/result blobs, while its Git tree carries only manifest and upsert content.
  Sequence gaps remain visible but need no predecessor artifact; no excluded/base-only object can
  ride inside a full base tree. Revises ADR-008, ADR-040, ADR-055, and ADR-078.
- ADR-082: Strict origin scopes consume every structurally valid next sequence even on later domain
  rejection; digest-covered scope rows and per-device/epoch audit counters replace history scans.
  A rejected agent start burns its ID rather than leaving an unrepresentable partial session.
- ADR-083: Identity-preserving rebootstrap is owner-targeted pairing, allowed only after removal from
  target and live Raft configuration; it rejects revoked/mismatched identities and reaps stale local
  agent sessions before accepting new work.
- ADR-084: The maintained Raft framed transport is carried unmodified over RFC 8441 extended CONNECT
  with an exact protocol/path and first-SETTINGS requirement; CodeComm adapts a byte stream and does
  not implement Raft framing.
- ADR-085: **Refined by ADR-110.** Pairing uses one exact TLS exporter label/context and
  length-framed role-ordered transcript; identity/content certificates use fixed critical
  UUID-derived OIDs and closed DER
  schemas. Golden fixtures therefore define one interoperable proof and certificate profile rather
  than leaving security framing to each implementation. Refines ADR-045 and ADR-057.
- ADR-086: Sparse drafts use a closed self-describing JCS manifest, fixed non-identifying synthetic
  commit metadata, one exact artifact ref, and strict stream sequencing; control paths use one
  committed closed classifier. Local configuration cannot change either wire/security
  classification. Refines ADR-063, ADR-079, and ADR-081.
- ADR-087: Staging receipts bind one preallocated proposal event, immutable publication metadata,
  and the holder's applied result position; they are usable only within an immutable committed result
  window, and a local cap bounds unaccepted pins. Rejection or subtraction-based window expiry
  releases an unaccepted pin; acceptance converts it to protected publication retention. Its
  canonical-advance terminal-retention clause is superseded by ADR-094.
- ADR-088: Accepted events and first-seen committed rejections are their own audit sources.
  `audit.recorded` is only for active-member request rejections with neither source, shows reporter
  and subject, and caps accepted audit records without claiming to remove general authorized-member
  result-chain exhaustion. Revises ADR-043.
- ADR-089: A publication tip has canonical base as first parent, and staging authorizes a committed-
  bounded union of every introduced commit's no-renames first-parent diff. This prevents intermediate
  modify-then-revert history from bypassing path leases or control-path exclusion; linear work is
  squashed or integrated under one tip, and merge publications put canonical first.
- ADR-090: Relayed endpoint sets are target-identity-signed, sequence/TTL/cap bounded, and contain
  literal selected-interface IP/port pairs only. Raw UDP sources remain unrelayed guesses; successful
  target authentication or explicit manual configuration is required for other retained endpoints.
- ADR-091: **Refines ADR-090.** Endpoint sets use one closed fixture-frozen schema, canonical literal
  ordering, a durable time-assisted sequence, and an expiring high-water mark so restored local
  state cannot cause permanent lockout. Relays preserve exact bytes; selected-route checks and
  expected-member TLS precede application data. ADR-095 closes local-guess retention.
- ADR-092: **Refines ADR-089.** Publication validation disables replacement history, bounds parents
  on every introduced commit, and freezes the streaming `rev-list`/first-parent `diff-tree` walk for
  both Git object formats. Multi-commit/rebased work uses a canonical-first wrapper or squash;
  conflicted rebases resolve through an ancestry-preserving merge rather than patch equivalence.
  ADR-098 closes artifact cardinality and raw-path parsing.
- ADR-093: Control-file divergence uses a compact presence commitment plus version-bound paginated
  entries, not an unbounded presence body. Completed local request mappings and abandoned/challenge
  records retain compact generation-lifetime idempotency tombstones without duplicate artifacts or
  event bodies. ADR-096 strengthens pagination against restored local version reuse.
- ADR-094: **Supersedes ADR-087's terminal-retention clause.** Applied publication refs release only
  after durable local canonical first-parent ancestry protects their commit; rejected/withdrawn refs
  release immediately unless an unresolved conflict protects them. This removes idle-session leaks
  without weakening reachability.
- ADR-095: **Refines ADR-091.** Relays carry opaque exact endpoint-set bytes; signed-set and
  authenticated-destination guesses expire after seven days, raw discovery expires with its
  datagram, manual entries persist, and every dial source obeys selected-interface routing.
- ADR-096: **Refines ADR-093.** A control manifest derives only from durable current approved
  content/tombstone rows. Presence, requests, and cursors bind both monotonic local version and
  content digest, so DB restore cannot reuse a version for different pages.
- ADR-097: Deterministic-input closure defines the domain-separated complete-signed-genesis digest,
  bounds sorted task-dependency traversal with fail-closed complexity rejection, and closes activity
  redaction, duration, substantive-content, and capture-source schemas.
- ADR-098: **Refines ADR-092.** A publication bundle has exactly one base prerequisite and one
  synthetic head; redundant Git-generated prerequisite ancestors are header-normalized and
  reverified without changing PACK bytes. Staging authenticates the author device, all introduced
  parents are bounded, changed paths use NUL-delimited raw Git records, and empty/net-no-op
  publications reject. Nested `.gitignore` is always a control path.
- ADR-099: Revocation always validates the voter-set CAS, but revoking a nonvoter requires the exact
  unchanged target and does not increment its version or trigger an identical-target authority
  handoff.
- ADR-100: Protocol scalar forms are closed: UUIDs use canonical RFC 9562 text, timestamps use one
  canonical UTC RFC 3339 form, and Git OIDs are lowercase algorithm-tagged values. Both successor-
  genesis signatures cover the same signature-free body; immutable primitive-suite and protocol-
  policy versions are explicit genesis inputs. Refines ADR-003 and ADR-097.
- ADR-101: **Refined by ADR-108.** Replica currency and recovery evidence are mode-specific. Raft participants retain real
  `last_raft_applied_log_index` provenance; settled nonvoters retain contiguous authority-signed batch/snapshot
  attestations and never synthesize it. Backups preserve the corresponding evidence, and quorum
  recovery ranks verified survivors by `result_index`, not a Raft index unavailable to nonvoters.
  Refines ADR-031 and ADR-067.
- ADR-102: Agent creation requires a durable one-use launch registration fixing session, client,
  profile, mode, and daemon-validated managed root before vendor start. Native filesystem and Git-
  repository identities reject aliases/pre-existing user roots; root mutation waits for zero
  pending/live/resumable bindings. Refines ADR-016, ADR-066, and ADR-079.
- ADR-103: Generated fallback context is binding-specific:
  `.codecomm/contexts/<agent_session_id>.{json,md}`. Shared-root agents retain distinct files and
  `Self` projections; there is no global context file that can cross-wire simultaneous agents.
- ADR-104: `refs/codecomm/**` is exclusive. Host/join/resume inventories names and durable OIDs;
  every final bare-store or user-repository write uses expected-old-OID `update-ref` CAS. External
  changes are preserved and block as `ref-tampered`, never overwritten. Refines ADR-007, ADR-040,
  and ADR-069.
- ADR-105: Successor recovery withdraws every nonterminal publication, recomputes applied
  publication membership against the selected canonical first-parent lineage, releases rollback-
  excluded pins unless conflict-protected, retires predecessor draft streams while retaining
  selected historical snapshots, and returns survivors only through conditional same-key
  readmission. Refines ADR-067, ADR-074, ADR-083, and ADR-094.
- ADR-107: `hashicorp/raft` exposes no follower-without-campaigning mode. A version-halted daemon
  stops its Raft instance and consensus routes; the persisted configuration still defines quorum,
  so compatible majorities progress and smaller sets fail closed until upgrade. Refines ADR-024.
- ADR-108: A verified Raft snapshot install records one adapter-metadata-bound local baseline for
  its compacted prefix and exact local command bindings thereafter; it never copies or synthesizes
  source provenance. Standalone logical imports never establish a Raft watermark. Refines ADR-101.
- ADR-106: Reducer/schema closure explicitly enforces actionable claims, task-update ownership,
  blocked-state reasons, path-lease cardinality, publication author/origin equality, and type-
  specific activity targets. Rejection audit deduplication is per reporter's local request mapping;
  independent reporter observations remain distinct attributed records. Refines ADR-082 and
  ADR-088.
- ADR-109: The canonical-coverage gate has no bypass. Phase 3 freezes and enforces the signed
  provider contract with verified fixture repositories, Phase 4 supplies local Git verification,
  and Phase 5 supplies peer acquisition/repair. Missing coverage issues no Raft configuration call.
  Refines ADR-059.
- ADR-110: Go's X.509 parser rejects X.667's single 128-bit UUID arc before custom verification.
  Certificate extensions therefore use protocol-fixed OIDs under `2.25.0` followed by the UUID's
  eight unsigned 16-bit words. This injective compatibility encoding is frozen in DER fixtures;
  authority comes from the closed pinned profile, not public OID registration. Refines ADR-085.

Numbers are allocation order and never reused. Materialized ADR bodies are immutable; this backlog
may annotate supersession but does not rewrite them. Next free number: ADR-111.

## 18. References

Protocol and format:

- RFC 2119 / RFC 8174, requirement keywords: <https://www.rfc-editor.org/rfc/rfc8174>
- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
- RFC 8032, Ed25519: <https://www.rfc-editor.org/rfc/rfc8032>
- RFC 9562, UUID v7: <https://www.rfc-editor.org/rfc/rfc9562>
- RFC 8446, TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446>
- RFC 8441, HTTP/2 extended CONNECT: <https://www.rfc-editor.org/rfc/rfc8441>
- RFC 5280, X.509 certificate profiles: <https://www.rfc-editor.org/rfc/rfc5280>
- ITU-T X.667 / X.690, UUID-derived OIDs and DER: <https://www.itu.int/rec/T-REC-X.667> /
  <https://www.itu.int/rec/T-REC-X.690>
- RFC 9112, HTTP/1.1 message syntax: <https://www.rfc-editor.org/rfc/rfc9112>
- SPAKE2+: <https://www.rfc-editor.org/rfc/rfc9383>

Dependencies:

- Raft paper: <https://raft.github.io/raft.pdf>
- `hashicorp/raft`, the candidate library: <https://github.com/hashicorp/raft>
- Git bundles: <https://git-scm.com/docs/git-bundle>
- Git protocol v2: <https://git-scm.com/docs/protocol-v2>
- Git `upload-pack`: <https://git-scm.com/docs/git-upload-pack>
- Git `update-ref`: <https://git-scm.com/docs/git-update-ref>
- Git `commit-tree`: <https://git-scm.com/docs/git-commit-tree>
- Git `merge-tree`: <https://git-scm.com/docs/git-merge-tree>
- Git worktrees: <https://git-scm.com/docs/git-worktree>
- `git write-tree`: <https://git-scm.com/docs/git-write-tree>
- `git merge-base` (incl. `--is-ancestor`, `--all`): <https://git-scm.com/docs/git-merge-base>
- `git gc` and reachability: <https://git-scm.com/docs/git-gc>
- `git prune`: <https://git-scm.com/docs/git-prune>
- Git repository layout and ref namespaces: <https://git-scm.com/docs/gitrepository-layout>
- `git check-ref-format`: <https://git-scm.com/docs/git-check-ref-format>
- `git index-pack` and pack format: <https://git-scm.com/docs/git-index-pack>
- `git fsck`: <https://git-scm.com/docs/git-fsck>

Storage and platform:

- SQLite WAL mode: <https://sqlite.org/wal.html>
- SQLite `PRAGMA` reference: <https://sqlite.org/pragma.html>
- SQLite online backup API: <https://sqlite.org/backup.html>
- RFC 4648 §5, base64url: <https://www.rfc-editor.org/rfc/rfc4648#section-5>
- RFC 3339, timestamps: <https://www.rfc-editor.org/rfc/rfc3339>
- RFC 7301, ALPN: <https://www.rfc-editor.org/rfc/rfc7301>
- RFC 2365, administratively scoped IPv4 multicast: <https://www.rfc-editor.org/rfc/rfc2365>
- RFC 4291 / RFC 7346, IPv6 multicast scoping: <https://www.rfc-editor.org/rfc/rfc7346>
- `SO_PEERCRED` and Unix socket credentials: <https://man7.org/linux/man-pages/man7/unix.7.html>

Agent integration:

- Model Context Protocol: <https://modelcontextprotocol.io/specification>
- Codex MCP: <https://developers.openai.com/codex/mcp>
- Codex `AGENTS.md`: <https://agents.md>
- Claude Code MCP configuration: <https://docs.claude.com/en/docs/claude-code/mcp>
