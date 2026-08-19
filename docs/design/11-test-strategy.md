# CodeComm V1 Design — Part 12: Regression and Test Strategy

Part 12 of 14. Contents: §12 policy and tiers, unit/compatibility coverage, integration harness, security/platform, gates.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 12. Regression and Test Strategy

### 12.1 Policy and tiers

Every bug fix starts with a failing reproducer at the lowest meaningful layer; the permanent
test MUST fail on unfixed code. Security fixes include exploit and nearby negative cases.
Random tests record seed/trace. Flaky quarantine requires owner, issue, reason, and near
expiry. Protocol, migration, reducer, consensus, or security changes cannot merge without
compatibility coverage. Redefining the outcome of an already-released
`(kind, schema_version)` pair cannot merge at all (§5.5). Fixtures use no production keys,
repositories, or activity.

| Tier | Gate |
|---|---|
| Unit | Every commit |
| Component, contract, integration | Every PR |
| Native system matrix | Main/nightly and release |
| Fuzz, fault, performance, soak | Nightly |
| Signed multi-device acceptance | Release candidate |

Production components expose constructor/test-build seams for clocks, secure randomness,
network/fault proxy, Raft transport/store faults, filesystem/disk, process/Git,
credential store, and SQLite failpoints. Production wiring always uses real secure
implementations. Every daemon test uses isolated config/workspace/DB/credentials/ports/
Git store/quarantine, an isolated supervisor registry root, and never user configuration or the real
per-user state location.

Reducer and reconciliation tests also run under a deterministic scheduler. Every randomized,
property, model, fuzz, or chaos failure records a replayable seed plus minimized operation/fault
trace. Linearizability checks cover task/lease claims, entity and canonical-ref CAS, local request
deduplication, and resume/reap races against the committed-result history.

### 12.2 Unit, component, and compatibility coverage

Required unit/component subjects:

- JCS canonicalization against the RFC 8785 test vectors; acceptance of exact ±`(2^53-1)` integer
  bounds and rejection beyond them or of floating-point values in signed fields; verification of an
  object carrying an unknown field; rejection of a
  correct signature presented under the wrong domain label; `device_id` derivation vectors;
  canonical acceptance and noncanonical rejection vectors for UUIDv4/UUIDv7 text, whole/fractional
  UTC RFC 3339 timestamps, and algorithm-tagged `sha1`/`sha256` Git OIDs;
  identical signed bytes and signatures for the same object on Linux, macOS, and Windows; exact
  domain-separated genesis digest over each complete signed generation-0/successor record, with any
  body or authorization-signature change changing the digest; both successor signatures cover the
  same body with both signature fields absent; every genesis carries exact immutable
  `primitive_suite_version = 1` and `protocol_policy_version = 1`; exact
  pairing exporter label/empty context, role ordering, length framing, invite digest, proof, and SAS
  vectors; both fixed portable certificate-extension OIDs and DER schemas reject wrong lengths,
  nonminimal/
  negative/overflow integers, trailing bytes, wrong profile, or more than one CodeComm extension;
- task/plan states; signatures/auth/idempotency; canonical encoding/compression; a duplicate
  `event_id` verifies and returns its durable chained outcome after restart, snapshot, recovery
  generation, and arbitrarily later events without re-evaluation; changed proposal bytes return
  `idempotency_conflict` without altering either head;
- event kinds: every §5.4 kind accepted with a minimal valid payload; an unknown kind or unsupported
  apply level halts before the entry without a result, consumed sequence, or Raft watermark; a
  payload with an unknown field rejected at
  `schema_version` 1; each kind rejected when proposed by an insufficient role or a
  disallowed `actor_type`; CAS kinds rejected without `expected_entity_version`; create
  kinds rejected when one is supplied;
- surface completeness: every human event kind has one CLI/TUI command, every agent event kind has
  one allowlisted MCP or adapter-lifecycle mapping (including `task.create` and
  `control_file.propose`), and no operator-only kind has one;
- generated context: every §7.3 group present, bounds enforced with truncation declared in the
  payload, and one binding-specific `.codecomm/contexts/<agent_session_id>.{json,md}` pair with a
  shared generation ID; Markdown renders the paired JSON fields, peer-authored strings carry
  provenance, controls are escaped, atomic replacement exposes no partial file, shared-root agents
  never overwrite each other's pair, and no global `context.{json,md}` is created;
- snapshot plus replay equivalence and deterministic projection rebuild;
- projection commitments (§5.6): identical accumulators only within the same
  `(session_id, recovery_generation, result_index, digest_version, projection_schema_version)`;
  accepted and rejected outcomes apply the exact ordered before/after mutation set, and a
  structurally valid domain rejection consumes its origin sequence while a gap/reuse does not;
  full state digests are unchanged by vacuum, rowid reuse, DDL/insertion order, change on every
  covered-field mutation, ignore excluded tables, and frame variable-length values unambiguously.
  Reducer divergence fails at a checkpoint; untouched row corruption is detected by snapshot,
  export, recovery, or scrub rather than falsely promised at every incremental checkpoint;
- version skew: every §5.5 halt rule, including that a halted replica never stores a local rejection
  for an entry a newer replica accepted and a too-old daemon refuses to join; each event's
  `min_apply_level` is frozen for its `(kind, schema_version)`; a `cluster_min_apply_level` raise
  reads only committed device reports, rejects while any active report is old, and has the same
  verdict under contradictory ephemeral presence; reports are self-device-only and a binary below
  the committed floor cannot report or serve;
- result batches (§5.3): reorder, omission, insertion, mutation, wrong outcome, wrong starting/end
  head, or incomplete authority handoff leaves both cursors unchanged; scratch replay must establish
  that the signer is active in the authority at `to_result_index` before its signature is trusted;
  a batch may cross multiple valid activations but cannot stop before its signer is authorized;
  `snapshot_required` is returned when the byte bound prevents that, and `after_result=M` is a
  `result_index`, never a `chain_index`;
- successor lineage (§3.1): event/result/accumulator seeds bind predecessor heads, successor genesis,
  and post-transform state digest; neither dense index restarts, and each boundary head changes at the unchanged position only under
  the new session/generation tuple; old credential rows remain historical under the old session,
  current epochs restart at 1, origin scopes reset, audit counters start at epoch/count zero, and
  deterministic replay plus the version-1 transform reproduces accumulator and state digest; the recovering identity always signs the exact
  successor body and the owner identity or recovery key supplies the distinct quorum-recovery
  signature, with any canonical-data-loss confirmation covered by both; nonterminal publications
  become `withdrawn` with `terminal_source = recovery`, applied rows recompute
  `canonical_lineage_member` against the selected first-parent lineage, rollback-excluded pins
  release unless conflict-protected, old draft streams stop advertising while retained snapshots
  remain historical, pending launches clear, and survivors require conditional readmission;
- credential objects (§4.6): a peer verifies discovery using `epoch_public_key` from the committed
  authorization alone; a certificate whose fields disagree with that object is refused; a peer that
  has not applied the authorization refuses and retries; authority version, endorsement ordering,
  signer uniqueness, active signer membership, a majority of the **full activated authority set**
  without revocation denominator shrinkage, signatures, and exact endorsed tuple are reducer-validated;
- publications (§7.2): quarantine rejects a bad bundle digest, zero/multiple/wrong prerequisites,
  zero/multiple/wrong advertised heads, objects outside the declared closure, malformed graph, a tip
  whose first parent is not base, an introduced root/disconnected first-parent chain, either
  introduced-history bound, an over-parent tip or nested introduced commit,
  replacement-ref/graft/shallow history, empty paths, net base-tree no-op, metadata/path mismatch,
  proposal author device/session fields unequal to the signed origin, and staging requested by a
  caller other than the active `author_device_id` or for an agent session it does not own; raw
  `diff-tree --raw -z` fixtures cover spaces, tabs, newlines, non-ASCII names,
  deletes, and type changes without quoted-path parsing; wrong signer or voter-set version,
  duplicate signer, and a
  below-majority receipt set; the metadata digest changes with every immutable proposal field but
  not receipts, review/terminal state, or `entity_version`;
  `proposal_event_id` equals the proposing envelope ID, changes the metadata digest, and makes a
  receipt from a committed rejected attempt invalid in every later event; a voter receipt is issued
  only after durable import and signs its exact applied `staged_result_index`; future and
  one-past-window receipts reject while both window boundaries accept, including near integer limits
  without addition overflow;
  concurrent applies on one canonical version produce one winner; canonical CAS and publication
  state update atomically; a target-set change invalidates old quorum credit; local ref
  reconciliation never touches `HEAD`, index, working tree, or user refs; an agent cannot publish
  another session's root or review its own publication; same-device agent approval is refused while
  an explicit local human approval succeeds and is labeled `human self-review`; direct, wrapped,
  squashed, merged, and clean-rebased publications validate under both `sha1` and `sha256`, while a
  conflicted rebase resolves only through the ancestry-preserving two-tip merge form. Bundle v2/v3
  fixtures prove redundant generated prerequisites are all base ancestors, normalization changes
  only bounded header bytes, and the result verifies/imports from a store holding only the complete
  base closure; a nonancestor prerequisite or shallow/filtered base rejects;
- control-file approval (§8.4): approving on one device never propagates, the approval row is absent
  from every replicated table and digest, and applying performs the exact verified operation
  atomically (upsert writes; delete removes) on a path that remains excluded from drafts and
  publications; each CodeComm-invoked checkout/reset/stash/clean/branch operation refuses while any
  launch registration is pending or agent binding is live/resumable, then verifies the managed
  guard, materializes no canonical control byte, and restores only the durable local
  overlay/tombstone before unblocking the root; a proposal above
  `control_file_max_bytes` or with a diff above `control_file_diff_max_bytes` rejects before fetch,
  while an artifact with the wrong exact size or digest is discarded; an empty-file upsert and a
  deletion are distinct, delete has null digest/zero size and fetches nothing, and every invalid
  operation/digest/size combination rejects; host preflight records its explicit initial local
  decision, bootstrap/isolated/shared managed roots install the guard before checkout, and
  presence carries only a bounded manifest summary derived from durable current approved rows;
  pending/declined proposals and live-root drift do not change it. Stable pages reproduce its
  domain-separated digest, every request/cursor binds version and digest, either changing invalidates
  the cursor, and restoring the same version with different rows cannot reuse it; differing ephemeral current digests are
  shown by `control-files review`/`repo doctor`; deliberate
  direct-Git bypass is detected and never misreported as protected; every version-1 classifier
  positive and ASCII case variant is protected, including `.gitignore` at every depth;
  extension/placement near-misses for the other root-scoped formats are not, local config
  cannot alter classification, and another policy version is rejected in V1;
- halted voter (§5.5): leaves the blocked entry and apply watermark untouched, latches the required
  level, attempts at most one bounded leadership transfer, then stops Raft and every consensus
  route; a compatible configured majority progresses, a smaller set cannot, and upgrade resumes
  before the same entry;
- chain construction (§5.2.1): golden vectors for both seeds, links, and generation boundaries;
  accepted events alone densely advance `chain_index`, every first-seen accepted or rejected ID
  densely advances `result_index`, and duplicates/collisions advance neither; result preimages
  exclude stored link hashes; independent replicas produce identical heads; snapshot/export/
  recovery/`state scrub` detect any historical mutation, while an exact duplicate performs the
  specified O(1) row-link check;
- checkpoints (§5.2.1): the signed object binds session/workspace/generation, signer and authority
  version, both heads, log position, and projection versions/digest; the signer is active in the
  authority at the cut and may differ from the leader; an interleaving after capture commits
  `stale_checkpoint`, while equal positions with a different head/digest integrity-halt without
  recording a rejection or advancing apply; a snapshot signer outside the cut's authority fails;
  a session-sized snapshot uses the exact typed length-framed record order, bounded signed root,
  hash-chained JCS descriptor pages, and bounded chunks; root encoding and expanded/compressed
  totals are binding, page/chunk indices are contiguous, chunk hashes cover transmitted bytes,
  artifact/state digests cover expanded records/rows, and resume rejects empty, duplicate, missing,
  reordered, oversized, wrong-encoding/length/digest pages or chunks without history-sized allocation;
- proof that no signed proposal contains ordering metadata, and that a replica never
  requires a pre-commit index from the Raft library (§5.2);
- ID generation/binding/non-reuse; `origin_boot_id` required and never reused for human/daemon
  origins, null for agents; first sequence 1 and strict next-sequence acceptance; one unresolved
  local command per scope prevents reorder; a valid next sequence is consumed by later domain
  rejection, while gap/reuse and exact duplicate semantics match §5.2 across crash/replay; a
  structurally valid but domain-rejected `agent.session.started` creates its scope, burns that
  agent ID, and a fresh ID can start normally;
- launch registration (§§5.1, 7.2): one durable registration fixes session/workspace, client/profile,
  mode, and a canonical daemon-managed root before vendor start; one consumer reserves its
  never-reused selector, concurrent/replayed consumers fail, and crash/rebind resumes only the exact
  pending start. Acceptance consumes it and returns one in-memory resume capability; rejection
  consumes it and burns the ID. Direct adapter launch, selector/context mismatch, a pre-existing user
  root, or a root/repository alias that conflicts with registry identity fails before tools open;
- agent lifecycle (§§6.1, 7.2): only the owning daemon enters `disconnected`, preserving the exact
  connected `resume_state`; only a valid local capability restores that state and clears it; foreign,
  stale, and post-end capabilities fail; the persisted context-bound token commitment survives a
  daemon restart while the raw token appears in no file/log/support bundle; concurrent resume and
  grace reaping use one session CAS so exactly one wins; `ended` is terminal and its cascade runs
  once; agent/daemon end-reason allowlists reject spoofed operator/crash/recovery attribution;
- ownership release (§6.4): one CAS-protected `agent.session.ended` atomically returns every bounded
  nonterminal claim to `ready` with `last_release_reason = session_ended` and releases every active
  lease, incrementing every affected entity version with no follow-up events to lose; another agent
  can then claim; reassignment persists
  `intended_device_id`, refuses every other device, clears intent on target claim, and remains visibly
  blocked if that target is revoked; force-release clears owners/intent; overrides are audited,
  reject insufficient authority, and are absent from MCP; unresolved merge conflict blocks `done`;
- owner continuity (§4.3): ordinary role change/revocation cannot remove the last active owner;
  `membership.owner_recovered` accepts only the same active editor as origin/subject plus a valid
  genesis-bound recovery-key signature over the exact session/generation/event/subject/version
  tuple; wrong key, replay, stale version, another subject, MCP origin, or missing quorum fails, and
  the operator-only challenge reserves one event ID and is retry/crash-idempotent; its one-per-device
  cap and five-minute deadline survive restart without extension; finalize accepts
  only the matching client/request/tuple/signature, the MCP adapter reaches neither operation, and
  the recovery private key appears in no daemon input, process metadata, event, log, or support bundle;
- lease expiry (§6.3): an idle same-process lease expires by monotonic elapsed time and event volume
  cannot accelerate it; renewal-before-expiry and expiry-before-renewal each produce one CAS winner;
  an old timer cannot release a renewed version; same-process leadership change preserves monotonic
  remaining time, while restart, boot change, missing timer, or snapshot import arms a full TTL and
  therefore may release late but never early under wall-clock jumps;
- task graph: every edge in the §6.3 table accepted, every absent edge rejected identically
  on all replicas, and each edge accepts only its assigned event kind, so `task.state_changed`
  cannot bypass release/reassignment/cancellation projections; entering `blocked` requires a
  nonempty reason and every other state prohibits one; an agent update is limited to its held or an unowned task; a claim requires the derived
  actionable predicate and intended-device match; terminal states admit no outgoing edge;
  dependency cycles rejected,
  including a cycle that only closes when two concurrently proposed edges are both applied; the
  sorted traversal accepts a complete walk of exactly `task_dependency_walk_max` distinct rows,
  rejects before row `max+1` with `dependency_graph_too_complex`, and still returns
  `dependency_cycle` when an edge from the last allowed row names the subject;
- simultaneous claims/path overlaps; path leases accept exactly 1 and 32 canonical patterns but
  reject 0 and 33; actor-argument spoof rejection;
- admission limits (§§2.2, 10): per-agent and per-member-device claim/lease depths and the 8-member/
  32-active-agent caps are enforced independently in each session; another session neither consumes
  nor extends them; every replica reaches the same verdict, while installation-wide process caps
  remain local;
- credential epochs/revocation; membership/voter/old-term validation;
- pairing (§4.5): an exact post-consumption request retry on the same TLS channel returns the same
  acknowledgment, while replay on a second connection fails channel binding and a process crash
  between consumption and response leaves the invite consumed; three proof failures
  void it; the outstanding-invite cap and TTL are enforced; SAS mismatch voids the invite
  with no retry; two approvals report `finalizing` until mode-specific durable completion, and a
  crash in that interval resumes the exact idempotent finalizer without reporting `confirmed`;
  a durable finalizer rejection reports `revoked`, cannot starve later attempts, and requires a new
  invite; changed requests reusing one attempt ID still consume the three-failure budget;
  startup abandons `preparing` rows, continuously expires stale attempts, bounds/scrubs failed-proof
  rows, and retries native-secret deletion with backoff;
  issuer ownership and every mode-specific subject/version/epoch/voter precondition are rechecked
  atomically at consumption, while live-configuration exclusion is held against reconciliation;
  concurrent valid proofs have exactly one winner;
  successor installation revokes unfinished predecessor attempts and selects no predecessor
  finalizer after the lineage changes;
  both sides derive the same proof/SAS from the exact exporter transcript; wrong
  exporter label/context or inviter/joiner ordering fails; encoded invite/hints/messages hit their
  exact bounds; `new`, `rebootstrap`, and `readmission` enforce their distinct subject/version/status
  fields, with only `new` generating an installation identity, both existing-device modes requiring
  the invite-named enrolled key, and only readmission conditionally committing admission; an
  unavailable or mismatched retained key fails, and no short numeric-code path ships in V1;
- ALPN/plane isolation (§§4.5–4.6): pairing, consensus, and content use exactly
  `codecomm-{pairing,consensus,content}/1`; absent, multiple, unknown, and cross-profile offers fail;
  pairing reaches only request/confirm, and consensus reaches only guarded Raft plus renew, endorse,
  closed consensus proof, and status — no content REST/SSE, Git, workspace, agent, membership, or policy
  surface. An identity-key certificate is accepted by pairing under pinned invite rules and by
  consensus only after membership admission; an unadmitted joiner fails consensus. Identity
  certificates fail content, epoch certificates fail pairing/consensus, and cross-session/generation
  bindings and Web PKI roots fail; identity certificates enforce the fixed
  extension/KU/EKU/serial profile and wide non-authorizing validity interval; renewal succeeds
  without a current content credential; 0-RTT, PSK, and session-ticket resumption are refused, so
  every connection reruns certificate admission;
- Raft HTTP/2 transport (§5.1): the first SETTINGS enables extended CONNECT; only
  `CONNECT /v1/consensus/raft` with `:protocol = codecomm-raft` reaches the maintained framed
  transport; absent/wrong pseudo-headers fail before Raft bytes; full-duplex flow control,
  half-close, cancellation, bounded streams, pooled-connection reuse, and peer/configuration
  admission match the selected library under race and fault injection;
- credential authorization (§4.6): reducers reject an epoch other than current+1, validity other
  than 1800 s, a successor `issued_at` below the renewal-lead floor, incorrect deterministic
  `not_before`, reused key, role mismatch, stale authority version, or invalid/non-majority clock
  endorsements, including one from a revoked authority member; endorsers refuse timestamps outside
  local skew before signing; overlap never extends the old credential and more than one future
  authorization cannot be stockpiled;
- late-renewal/fast-clock regression (§4.6): there is no prior-expiry upper clamp; an expired device
  renews hours or a workday late with majority clock endorsements and activates at endorsed current
  time, while one leader hours ahead cannot collect a majority for its far-future timestamp or lock
  the subject out;
- role is read live, not from the credential (§4.6): a device demoted after its authorization was
  committed is refused owner-level operations for the remainder of that epoch;
- leader-only replication (§4.6): a non-leader serves no entries/snapshot, asserted on exchanged
  bytes; an elected leader that has not applied through committed membership replicates nothing;
  after cold restart with a zero volatile commit index and a shared unapplied committed tail, only
  no-op-only commit probes flow, mixed/command/configuration/snapshot transfer remains blocked, and
  the quorum re-establishes commitment and applies the tail before ordinary replication resumes;
  once eligible it replicates only to active live voters and staging nonvoters, never settled
  application nonvoters; a compacted staging target catches up by leader `InstallSnapshot` before
  producing its checkpoint proof, while settled nonvoters use signed batches/snapshots;
- revocation admission (§3, §4.6): a peer that has applied a revocation refuses both planes; a
  not-yet-applied peer may admit and exchange votes but transfers no entries; renewal requires
  leader-confirmed active membership; a revoked live-config voter is refused and the resulting
  quorum loss fails closed; revoking an active nonvoter still validates the voter-set CAS and exact
  target but leaves its version/row, credential authority, and reconciliation unchanged;
- all-asleep recovery (§4.6): a cluster whose every content credential expired over multiple epochs
  re-elects on the consensus plane and re-authorizes with no operator action and no distinct
  cold-start path; a minority awake authorizes nothing;
- quorum authority (§3): a cluster with two replicas halted at different indices and a third current
  computes one identical quorum size from the committed configuration; a replica whose applied
  membership differs is proven not to alter vote counting;
- activated credential authority (§3): genesis/recovery rows use `activation_source = genesis` with
  empty handoff fields; a target change alone leaves the old authority usable; every target must be
  promoted and prove one fresh checkpoint before activation; the prior active authority signer,
  target/current versions, complete proof set, and handoff signature are reducer-validated; a crash,
  target change, revoked signer, missing proof, or unpromoted target fails without changing authority;
- version-halt interaction (§5.5, §4.6): stopped voters grant no votes, replication, or clock
  endorsements; a compatible configured majority still elects and authorizes, while a smaller set
  fails closed and surfaces the required release. Upgrade resumes from persisted Raft state and
  §3.1 is never offered solely for version halt;
- origin construction (§5.2, §7.1): client-supplied `origin` is a schema rejection; MCP cannot assert
  `human`, while TUI/CLI cannot assert `agent` or borrow an `agent_session_id`; daemon restarts mint a
  fresh `origin_boot_id`; every §6.4 override records its originating IPC channel;
- local IPC (§5.1): byte-level HTTP/1.1 fixtures over Unix sockets and Windows pipes cover ACL/peer
  identity, bind-before-use, immutable `operator`/`agent` class, session pinning, size/framing limits,
  no pipelining, protocol mismatch, and operation allowlists; exact local request replay returns one
  pending/final event while changed bytes under the same key return
  `local_idempotency_conflict`; crash after each mapping/proposal/result write resends only the exact
  persisted signed proposal and never reuses/regresses the atomically allocated origin sequence;
  crash at each publication-preparation/artifact/receipt/signing boundary resumes the same reserved
  proposal event and immutable metadata, while a failed committed attempt cannot lend receipts to a
  newly reserved one; abandoning before signing or ending the author session tombstones the IDs,
  releases local pending capacity, emits no event/sequence, and never causes an early remote-pin
  release; completed mappings and abandoned/challenge tombstones compact to their fixed fields
  without losing exact/changed retry behavior or retaining artifact bytes;
  per-origin/session pending ceilings return `local_backpressure` before allocating a mapping,
  event ID, or origin sequence and recover as pending work drains;
  owner-recovery challenge/finalize crash boundaries preserve one reserved event and expose only the
  detached signature; a new-agent bind accepts only the registered selector, cannot override any
  registration field, and exposes no tools before its exact start commits; the MCP adapter cannot
  request `operator`;
- local configuration (§11): strict versioned TOML accepts only documented typed keys; precedence is
  defaults < file < explicit foreground flags; duplicate/unknown keys, malformed values, symlinks,
  wrong ownership/ACLs, environment overrides, secrets, session policy, and insecure switches reject;
  an over-1-MiB file rejects before TOML parsing/allocation; validation is side-effect-free and
  atomic, local hard ranges such as the Git quota and selected-interface cap hold,
  `config show` reports sources, and no live reload occurs;
- publication authority (§7.2): every changed path requires an active path-scope lease held by the
  author; task ownership grants no paths; an unowned `task_id` and mismatched `working_root_id` are
  rejected. Same-device **agent** approval is refused, explicit same-device **human** approval is
  accepted and labeled self-review, reviewer device/session/actor are stored exactly, MCP apply
  accepts only IDs/versions, and non-ancestor `base_commit`/`commit_oid` fails staging;
- publication contention (§7.2): a lost canonical CAS leaves the publication intact and mutates no
  replicated counter; a superseding proposal rejects until its named stale predecessor is rejected or
  withdrawn, then uses new receipts/review; only the initiating daemon's local lineage count surfaces
  `starving`, and apply succeeds after induced contention quiesces (no fairness promise under endless
  winners);
- audit tiers (§5.4, §10.1): accepted domain events produce one audit projection and no duplicate
  `audit.recorded`; first-seen committed rejections likewise project directly; only an authenticated
  request with neither retained source may commit `audit.recorded` with the subject's latest
  credential epoch, and the view shows distinct reporter and subject; `audit_counters` resets on the
  next authorization, increments atomically, is
  accumulator/state-digest covered, and rejects beyond `audit_depth_per_device_per_epoch` without a
  history scan; exact local retry produces no second report, while two peers independently observing
  the same request may each commit one row with distinct reporter origins; excess,
  unauthenticated, revoked, unknown, and stale-epoch attempts only update a bounded local aggregate;
- leader ingress limiting (§10): a member fanning proposals out to all peers concurrently is first
  bounded independently by each receiver's control/proposal budgets and finally at the leader by one
  signed-origin-keyed `leader_ingress_rate_per_device` budget, not N forwarding-peer budgets;
  inactive historical origins share one bounded aggregate without churning active-origin state,
  malformed events consume both receiver budgets, a hop-1 request never forwards again, ordinary
  authenticated control consumes the control budget, and bounded bulk does not double-count;
- unbounded-source resistance (§4.4, §4.6): datagrams and handshake attempts from thousands of
  forged source addresses do not grow discovery or handshake source maps past their independent
  count/byte ceilings; discovery eviction is oldest-source-first, handshake buckets expire after ten
  idle minutes and evict the oldest idle source, and neither path logs per attempt;
- runtime ceilings (§5.1, §11.2): header/body/page/handler, handshake, HTTP/2 stream/connection,
  local-IPC connection/handler, pending-command, Git-transfer, ephemeral-aggregate, child deadline,
  temporary-artifact, Git-bundle-header byte/record, and supervisor-restart limits reject or
  backpressure at the named boundary and recover after release; the content upload stream window is
  `max_event_bytes`, so a pre-SETTINGS default-window event cannot cause a flow-control reset while
  the connection-wide buffer stays bounded; a saturated bulk connection cannot starve control/SSE,
  stalled streams and request bodies time out resumably, and no rejection allocates beyond its ceiling;
- endpoint retention (§2.3): gossip never retains more than 16 hints/member or 128/session, expires
  then evicts oldest stale hints deterministically, a current signed set replaces its predecessor
  atomically, and a seventeenth per-member or 129th session manual endpoint is refused without
  replacing an existing operator entry;
- conflict identity across platforms (§8.3): the complete immutable operation tuple yields one
  `conflict_id` across supported OS/Git builds; detector `paths` are excluded, so path-reporting
  differences do not create duplicate rows; criss-cross bases sort stably; merge versus rebase and
  distinct `replay_commit_oid` steps produce different IDs; exact re-detection is idempotent without
  resetting status, while changed tuple/path fields under one ID reject and alarm; task blocking is
  derived once; first detection after publication termination rejects, but exact re-detection of an
  existing row remains idempotent; only an applied publication with staging-verified ancestry
  resolves it; freeze `ccf1`;
- draft snapshot fidelity (§8.1): a worktree deletion is a sparse-manifest `delete`, never silently
  retained at `HEAD` content; the closed manifest's version/object format/base and every null/mode/
  OID rule are enforced for both `sha1` and `sha256` repositories, its exact JCS bytes have no newline, and the container has exactly
  `manifest.jcs` plus a `files/` tree equal to its upserts. Fixed author/committer/timestamps/message
  leak no local Git identity, and the exact temporary artifact ref is the bundle's sole advertised
  head; no base, ignored, excluded, or control-path object rides merely because local `HEAD` does.
  Dirty-index/detached-`HEAD` capture leaves real index, `HEAD`, user refs, and files byte-identical;
  each artifact has one parentless synthetic container and complete sparse closure. Restore applies
  only on matching base blob/mode and surfaces mismatch as conflict;
  raw cherry-pick/merge is refused. Equal/lower sequence and wrong contiguous prior OID reject; a
  verified forward gap advances with missing-history status. Metadata restore or a new agent opens
  a never-reused stream; the 100-snapshot cross-stream ceiling protects each live head, prunes oldest
  history first, and leaves no orphan refs/metadata;
  a relay that re-signs or renames an advertisement is rejected;
- state survives operator Git (§6.2): `git clean -xdf`, `git stash --all`, and `git reset --hard`
  in the workspace leave `state.db`, `consensus/`, and the session bare store intact;
- object reachability (§8.1): operator `gc --prune=now`, `repack -ad`, and `reflog expire` in the
  user repository, attempted `gc.auto`, and explicit bare-store GC racing an import leave every
  referenced OID reachable or
  surface `object-lagging` and refetch; a publication pin is not released while an unresolved
  conflict references a rejected/withdrawn publication; an applied holder releases its publication
  ref only after its durable local canonical ref reaches that commit or a first-parent descendant,
  while an unreferenced rejected/withdrawn ref releases immediately, including in an otherwise idle
  session; receipt quorum ends at terminal state; an accepted proposal converts its local staging slot before
  same-result cleanup, a committed rejection or one-past-window result releases an unaccepted pin,
  cleanup uses checked subtraction near integer limits, and stale/future/cross-proposal receipts
  never authorize a proposal or apply; the staging cap is reserved before
  transfer and crash recovery never misclassifies an accepted pin; bounded explicit pins and live draft heads survive destructive Git
  operations; exact quota headroom is reserved, explicit bare-store GC serializes with import, and
  quota pressure/refusal or a lowered-below-use configuration never evicts protected reachability.
  Host/join/adoption inventories all `refs/codecomm/**`; resume requires durable name/OID agreement;
  every bare-store and user-repository final ref write uses the recorded expected old OID, and an
  unexpected name, missing record, external mutation, or CAS loss blocks as `ref-tampered` without
  overwrite;
- staging coverage after a target change (§§3, 8.1): before **every** Raft configuration call, a
  majority of the current target must hold the exact current canonical version/commit; missing or
  old-version receipts surface `object-coverage-degraded` and prevent old-voter removal; a concurrent
  canonical advance invalidates the check; absent/permissive providers fail closed, Phase 3 fixture
  providers verify real pre-seeded objects, and a lying receipt holder is an audited integrity blocker;
- catch-up completeness (§5.3): a server that withholds the tail is detected by comparing its signed
  `server_applied_result_index` against closed peer watermarks, and a regressing value or a
  same-position different head is an audited blocker; a receiver does not treat catch-up as complete
  while any peer advertises a higher result watermark;
- snapshot provenance (§§5.3, 6.2): `InstallSnapshot` cross-checks adapter-supplied index, term,
  configuration/index, source, and payload digest before atomic visibility; it records one baseline,
  imports no foreign command/event provenance, requires exact bindings for every later command, and
  survives restore/reopen. A metadata/payload mismatch, copied binding, missing post-baseline
  binding, or standalone import claiming a Raft watermark fails closed;
- settled-nonvoter evidence (§§3, 5.3, 6.2): batch/snapshot imports retain contiguous authorized
  attestations and never create `event_provenance` or advance `last_raft_applied_log_index`; currency
  is relative to the greatest observed authority-signed result watermark. Its backup/restore carries
  a verified checkpoint/snapshot plus contiguous attestations, while a Raft participant requires a
  matching stable-store snapshot and SQLite backup. Quorum recovery validates either evidence mode,
  ranks survivors by verified `result_index`, and never prefers or fabricates a Raft index;
- non-destructive projection recovery (§5.6, §9): after injected divergence, `codecomm state
  recover` rebuilds from both retained verified chains or a verified logical checkpoint snapshot
  plus contiguous result tail, preserves every committed outcome, never copies another device's
  SQLite database, pages, WAL, or unverified projection, and converges to comparable
  heads/accumulator/state digest;
  §3.1 is not offered;
- terminal ownership (§6.3, §6.4): reaching `done` or `cancelled` clears owner fields and
  `intended_device_id`, and a subsequent `agent.session.ended` for the completing session does
  **not** return the terminal task to `ready`;
- override edge (§6.3): `ready → ready` clears or re-targets a stranded `intended_device_id`, and
  an intent naming a revoked device is escapable by exactly that edge;
- lease overlap (§6.1): equal task leases reject; path exact/exact equality, prefix/exact containment,
  and containing prefix/prefix pairs reject identically on every replica, while disjoint scopes
  succeed; metacharacters outside exact paths and one terminal `dir/**` are rejected;
- policy entity (§5.4, §6.1): `policy.changed` is rejected on a stale `session_policy` CAS token;
  V1 attempts to change credential timing, `max_event_bytes`, `event_path_array_max_bytes`,
  `activity_duration_max_ms`, `task_dependency_walk_max`, `control_file_max_bytes`,
  `control_path_policy_version`,
  `publication_receipt_window_results`, either publication graph bound, the publication parent
  bound, or multicast group/port are
  rejected; every genesis/default/update value satisfies §11.2's hard ranges and relational rules;
  cap reductions below current replicated use and a nonmonotonic or unsupported
  `cluster_min_apply_level` reject atomically; `session_policy` participates in both projection
  commitments;
- discovery cadence (§4.4): every allowed configured interval preserves the configured endpoint-set
  TTL while multicast cadence clamps at 48 seconds; jitter remains within ±25%, advertisement
  expiry remains within 60 seconds, and mandatory native Linux/macOS/Windows jobs prove same-port
  multicast exchange rather than converting capability failures into skips;
- durability write set (§6.2): a failpoint at each §5.3 step-7 boundary leaves event/rejection,
  provenance, consensus state, projections, lifetime `command_results`, audit, checkpoint, lease
  timer metadata, and outbox removal all committed or all absent; separate failpoints prove the local
  request digest/event/proposal mapping precedes forwarding and its final result update is
  idempotent; missing same-boot timer state arms full TTL; `synchronous=FULL` and
  `last_raft_applied_log_index <= last Raft log index` are asserted only for a store with Raft state;
- context allocation (§7.3): one member filling every group with maximal bodies cannot evict another
  member's claims, leases, or repository state; `Session`/`Self`/`Repository` are never truncated;
  all own claim/lease IDs and compact summaries fit at hard maxima while full path arrays paginate;
  long peer strings are truncated per field rather than dropping records; per-origin fairness holds;
  the escape set is applied by the daemon so `context.get` and that binding's two files agree; two
  agents sharing one root retain distinct `Self` sections and files through concurrent regeneration;
  final encoded bytes
  after escaping/provenance/rendering obey every sub-budget independently, including the 64 KiB
  maximal fixed-core fixture in both JSON and Markdown;
- MCP scoping (§7.1): `task.update` on a task the caller does not own is refused, so a peer cannot
  freeze another session's work by adding `blocked_by`; `conflict.resolve` requires authorship of
  the named resolution publication; `publication.review` exposes only ID/version/verdict, permits an
  eligible agent on another device, and rejects the author, every same-device agent, and actor
  spoofing;
- SAS derivation (§4.5): both sides derive the same string from the transcript, and a frozen golden
  vector pins the byte-level rendering so two implementations cannot disagree;
- promotion proof (§3): the staging response echoes every captured checkpoint/event field and the
  target's stored accumulator comparison only after its FSM/SQLite apply; missing/mismatching
  data cannot promote and is not claimed as cryptographic execution proof; an existing live voter is
  eligible for transfer after fresh barrier/contact, so `{A}→{B}` and 3→1 terminate;
- successor uniqueness (§3.1): two partitions that both run recovery produce mutually incompatible
  successors because peers compare the complete signed genesis binding both predecessor heads,
  recovering device, new session, and recovery key; they refuse to interoperate and name both
  recovering devices;
- quorum-recovery eligibility (§3.1): only an active predecessor owner with its matching local
  identity or an active predecessor editor with that identity plus the recovery key may recover;
  revoked, `requires_readmission`, absent, never-admitted, mismatched-key, and editor-without-recovery-
  key candidates fail before successor state is written;
- discovery receiver rules (§4.4): cheap checks precede signature work, a future or expired
  `expires_at` is rejected, the nonce cache is bounded per source and evicts oldest-first, a
  repeated nonce is dropped, a sibling session's datagram is ignored without penalty, and
  an advertisement signed by a latest-but-expired epoch key is only an endpoint hint and never
  authenticates a content connection, and per-source state stays bounded under forged sources;
- endpoint-set authorization (§§2.3, 4.4): a member can sign only its own closed literal-IP set;
  golden vectors freeze exact JCS/signature bytes, canonical IPv4/IPv6 sorting, sequence generation,
  issued/expiry bounds, and opaque base64url relay bytes. Wrong signer/member/session/workspace/
  generation, future `issued_at`, invalid/expired/too-long window, same-sequence changed bytes, stale
  sequence, noncanonical or forbidden address, hostname, link-local gossip, byte/count cap, and
  ordering overflow reject; relays preserve exact bytes. Expiry removes the relay object/watermark,
  a restored lower counter recovers after that bound, raw discovery expires with its datagram,
  signed-set/authenticated-destination guesses expire at `endpoint_guess_ttl_seconds`, and an
  authenticated dial retains only its exact destination/listener tuple. Manual IPv6 link-local
  requires a valid local selected-interface zone; every manual/stale/signed route must leave on a
  selected interface; a spoofed UDP source never becomes relayed;
- opt-in draft inclusion (§8.1): a blanket or multi-level glob is refused; a control file is
  refused; a non-interactive confirmation is refused; a secret-shaped path requires the second
  confirmation and is named in the preview; the inclusion list appears in no replicated table and
  in no projection commitment; `repo exclude` stops future drafts while already-replicated snapshots
  remain immutable;
- activity capture (§5.2): standalone `activity.recorded` and mutation-envelope activity project the
  same bounded closed schema; standalone empty rationale/actions rejects, `redaction.policy` accepts
  only `default`, `fields_removed` accepts only the sorted unique closed categories, action target/
  summary/digest/time fields hit both boundaries; each action type accepts only its defined target
  grammar, so file paths, ASCII executable basenames without arguments, ASCII tool identifiers,
  stable test names, decision topics, and repository/class artifacts cannot be substituted;
  `duration_ms`
  accepts 0 and
  `activity_duration_max_ms` but rejects either neighbor outside the range. Raw arguments, output,
  environment, secrets, and private reasoning are absent from persisted records/support bundles;
  agent/human/daemon origins require `agent_reported`/`human_reported`/`daemon_observed`
  respectively, and relaying a client report never upgrades it to observed; no V1 adapter installs
  or accepts an independently launched vendor activity hook;
- canonical paths (§8.4): UTF-8/NFC `/` form is case-sensitive across platforms; invalid Unicode,
  over-512-byte paths, aggregate event path arrays above `event_path_array_max_bytes`,
  case/normalization collisions, dot/empty/reserved/ADS/control components, escaping symlinks, and
  non-UTF-8 repositories fail closed; canonical identity remains case-sensitive while every ASCII
  case variant of a frozen control basename/root prefix is classified as control on every platform,
  and nested `.gitignore` is always control; extension and placement near-misses for root-scoped
  formats remain ordinary paths; terminal sanitization and redaction;
- Git argv/environment, bare-store/ref allowlists, quarantine, bundle/draft/publication metadata,
  and proof that checkout/reset/stash/clean/branch switching on one peer never mutates another;
- Git import crash boundaries (§§7.2, 8.1): reject extra refs/objects, missing closure, ineligible
  modes, wrong prerequisites, oversized/over-record/malformed bundle headers, and object/ref
  mismatch; fail before/during object migration,
  fsync, and `update-ref` while an import/GC lock is held; pre-ref crashes expose no ref/receipt,
  post-ref crashes recover the durable pin, concurrent GC cannot prune a depended-on object, and an
  external ref change between validation and final expected-old-OID CAS is preserved and blocks;
- real SQLite WAL/transactions/checkpoint/migration/corruption/recovery plus both §6.2 backup modes;
- real three-voter Raft election/replication/membership/snapshot/replay.

Do not mock SQLite or Raft when testing their behavior. Immutable golden fixtures cover canonical
UUID/timestamp/Git-OID forms, primitive/protocol-policy genesis versions,
the complete-signed-genesis digest preimage, the `ccf1` `conflict_id` preimage, the publication metadata-digest preimage including
`proposal_event_id`, the §5.6
projection-accumulator mutation/seed preimages and full projection-state digest at
`digest_version` 1 and `projection_schema_version` 1,
event/result seed and link vectors including accepted/rejected/duplicate commands and a
generation boundary, the deterministic recovery transform, the SAS/invite transcript rendering,
reducer-outcome fixtures per released
`(kind, schema_version)` pair, §4.1-canonical events/batches/signatures, voters/credentials,
identity and content certificates
and exact DER extensions/nonce/exporter proofs, sparse draft manifests/container commit OIDs,
the version-1 control-path classifier corpus,
  snapshot roots/descriptor-page chains/chunks, signed endpoint sets, REST/capabilities, MCP schemas/instructions,
local-IPC framing/binds/idempotency, control-file proposals, Git metadata, and every released DB
schema. Prove previous protocol
interop, unknown optional/required behavior, cross-platform signature stability, all
historical migrations, migration+replay digest, snapshot+tail equivalence, and recoverable
failed migration. Fixture changes require explicit protocol/schema review.

### 12.3 Integration harness

`internal/testharness` is a V1 deliverable. It launches supervisors with isolated registries,
1/3/5 voters, nonvoters, current/retained prior daemons, devices joined to several workspaces
at once, many simulated Codex/Claude clients, and real Git
repos/worktrees, fault proxy, and isolated fake native stores where native behavior is not
under test.

Faults: partitions including **asymmetric one-way** partitions, latency, duplication, truncation;
**Raft stable-store and snapshot corruption**; a SQLite failpoint inside the §5.3 step-7 transaction
and during WAL checkpoint; backward and forward clock jumps asserting neither releases a lease early
nor cascades releases; operator `git gc`/`repack`/`reflog expire`, attempted `gc.auto`, and explicit
bare-store GC concurrent with import; leader/voter/peer crashes at
Raft/SQLite boundaries; connection closure; skew/clock jumps/30-minute rollover; disk full,
permission, short write, rename failure; Git child crash/hang, truncated artifact and quarantine
failure; dropped agent heartbeats;
host suspend and resume; local address change and interface disappearance; one or every
voter waking after multiple expired epochs, with and without a reachable majority.

After quiescence, replicas in the same `(session_id, recovery_generation)` at the same
`result_index`, `digest_version`, and `projection_schema_version` MUST have equal projection
accumulators (§5.6); non-comparable projections are not partially compared. Snapshot/export/scrub
cuts additionally require equal full projection-state digests. Replicas at the same `result_index`
MUST have equal result heads, and the accepted tuple in every result must agree with the event head.
A mixed-version cluster MUST additionally show that an older replica
applied each entry identically or halted cleanly before a `min_apply_level` it cannot satisfy. All
replicas MUST have valid SQLite, unique IDs/sequences, expected listener exposure, and no leaked
child/port/temp root. Security cases require audit events and invite/credential artifact scans.

Core scenarios:

1. Pair and verified Git bootstrap under both `sha1` and `sha256`; the destination is built privately with control paths
   sparse-excluded before first checkout and withheld pending local review. After canonical checkout,
   source dirty/untracked content arrives as an
   inspectable draft without changing that working-tree/index/`HEAD`/user-ref baseline.
2. Multiple same-device Codex-only, Claude-only, and mixed sessions: one-use selectors survive
   launch/daemon crashes, admit one consumer, reject replay/direct launch/pre-existing roots, and
   yield distinct per-agent context pairs even in a shared root. Accept 32 active and refuse the
   33rd in that session without consuming another session's cap.
3. Local/remote task races; one winner; overlapping/non-overlapping worktrees.
4. Shared-root exact/prefix lease conflicts; monotonic idle expiry unaffected by event rate or wall
   jumps; renewal/expiry CAS races; same-process leader transfer; restart/snapshot full-TTL fallback;
   disconnect stores prior state; resume/reap CAS races; foreign/stale capability refusal; ID non-reuse.
5. Kill an agent mid-task: its claim and leases release automatically, another agent claims
   the same task, and operator force-release plus reassign works on a task whose owning
   device never returns; every non-target device is refused before the named device claims.
6. Isolate one of three voters: majority commits, minority queues, then converges.
7. Prove minority cannot commit, self-promote, or renew credentials.
8. Drop/duplicate/delay/truncate result catch-up; cross one and several activated-authority
   handoffs; reject a signer not active at the batch end; prove failed scratch replay advances no
   cursor; force `snapshot_required`, import a snapshot signed by the authority at its cut plus a
   contiguous result tail, and reach equal heads/accumulator/state digest.
9. Current/previous version and schema replication; snapshot-at-`N` plus tail; a
   v1.0 follower in a v1.1-led cluster halts safely at an entry it cannot apply,
   reports a version blocker, and converges after upgrade rather than diverging; a minimum-version
   raise uses committed reports and is unaffected by contradictory presence.
10. Crash after Raft commit before SQLite apply and at every event/result-chain transaction boundary;
    replay to one outcome and equal heads. Crash local IPC after request mapping, proposal signing,
    forwarding, and result receipt; exact retry never creates another event.
11. Restart during Git bootstrap, quarantine object migration/fsync/ref commit, and local ref
    reconciliation; recover deterministically, issue no premature receipt, and expose no partial
    ref. Inject unexpected/missing/external `refs/codecomm/**` changes in the bare store and user
    repository before final CAS; preserve them, enter `ref-tampered`, and never overwrite.
12. Rotate 30-minute credentials make-before-break during active control/Git transfer and election;
    old links close at original expiry with no acknowledged loss. Make one leader hours fast and
    prove it cannot collect endorsements, then complete on-time and next-workday late renewal.
    The production-composition proof advances one shared injected credential clock used by
    authorization, certificate selection, ingress, and outbound verification; routing timestamps
    remain independent.
13. Suspend a device past its epoch and change its address while asleep, then wake it:
    it re-dials on the consensus plane, renews its content credential, and converges with no
    operator action. Then
    suspend every voter overnight for multiple epochs and wake a majority with no valid
    content credential: they authenticate by device identity on the consensus plane, elect/catch up,
    authorize fresh epochs, and restore ordinary Raft. Repeat with only a minority awake:
    no credential or ordinary traffic is authorized, local reads still work, and recovery
    occurs automatically when enough voters return. Exercise the 3-voter sequence with one voter
    awake (no leader or credential), then two (quorum and fresh epoch), then all three (catch-up and
    restored content traffic), followed by store reopen and commitment verification.
14. Revoke during artifact transfer and reconnection attempts; every peer that has applied it
    closes consensus, content, and Git access; a stale peer that admits the device still sends it no entries or
    snapshot; the committed voter target excludes it and the leader reconciles the live
    configuration; and a stale minority cannot renew the former member. Separately revoke an active
    nonvoter and prove its access closes while target/version, credential authority, and
    reconciliation remain byte-identical.
15. Run checkout, stash, reset, clean, and branch switches while peers hold divergent work; no
    operation mutates a peer. Replicate, inspect, restore, and materialize sparse drafts without
    transmitting excluded/control/base-only objects; race two publications from one base to one
    canonical winner, exercise the exact parent-bounded introduced-history walk, derive one conflict
    row from duplicate detectors, and resolve it through a reviewed ancestry-verified publication
    without losing either side. Churn and prune across
    hundreds of sequential agent streams without exceeding per-device retention or leaving orphan
    refs; abandon staging requests through the receipt-window boundary, prove no early remote release
    or cross-attempt receipt replay, fill/recover the staging cap, and hit pin/storage quotas while
    preserving every protected ref. Refuse every managed-root mutation while a launch is pending or
    an agent is live/resumable. In an idle session, apply one publication and release its
    publication ref as soon as local canonical first-parent ancestry protects it; reject/withdraw
    another and release immediately unless an already-committed unresolved conflict holds it.
16. Hold control-file changes for independent local approval; distinguish empty upsert from delete,
    fetch nothing for delete, and reject invalid metadata, over-limit upserts before fetch, and
    exact-size/digest mismatches before write. Across checkout/reset/stash/clean/branch operations,
    canonical control bytes never materialize in a managed worktree and only the durable approved
    overlay or tombstone is restored. Page one device's manifest by version+digest, mutate it between
    pages, and restore a DB snapshot that reuses a version with different approved rows; both old
    cursors fail rather than combining states.
17. Kill leader during transfer between survivors; transfer continues and a new
    leader resumes strong commits.
18. Remove a permanently lost voter, add a caught-up replacement, and retain trust; exercise
    `{A}→{B}`, unreachable-extra 3→1, leader transfer, crash after every step, target change
    mid-transit, and indefinite stall; before every configuration call require fresh target-majority
    canonical-coverage receipts from actually verified fixture repositories and invalidate them on
    canonical advance; prove a missing provider issues no configuration call. Prove a stalled target
    leaves the prior authority able to renew; activation occurs only after every target proof plus an
    active prior-authority handoff. Force-leave one voter while the other two retain quorum and prove
    no implicit membership/configuration change, then replace it explicitly; force-leave the sole
    voter separately and prove the UI names quorum recovery rather than `reconciling`.
19. With quorum intact, lose the sole owner identity and restore only the local active editor's owner
    role through the recovery-key event; then lose quorum, fail closed, let every credential expire, and recover offline —
    once authorized by an active surviving owner's matching identity, and once by the recovery key
    plus an active editor's matching identity with no owner device present. Verify both predecessor
    chains, rotate the recovery key, apply the exact
    version-1/reset transform, preserve revoked status and historical credentials, restart current
    epochs at 1, withdraw every nonterminal publication, recompute applied canonical lineage and pin
    release after an explicit rollback, retire draft streams while preserving retained historical
    snapshots, then conditionally readmit survivors with the same keys and expected row versions.
    Repeat candidate selection with revoked,
    `requires_readmission`, absent, never-admitted, mismatched-key, and keyless-editor identities and
    prove recovery writes no successor state.
20. Prove a recovered session and a survivor of the prior generation refuse to
    interoperate; prove same-generation sibling successors with different signed genesis digests
    also refuse, recompute each digest from the complete signed record byte-for-byte, and prove a
    signature-only change changes it; a minority cannot run recovery without operator authorization.
21. Exhaust Raft/SQLite/Git/control-store disk and the configured Git quota; no acknowledged event or
    publication loss, no ref update without durable verified objects, and no protected ref evicted.
22. Prove an MCP client cannot select `operator`, assert `actor_type: human`, reach an override verb,
    or borrow another session's identity; exercise Unix/Windows peer checks and bind classes; replay
    exact and changed local request IDs across restart; every override is audited with its IPC channel.
23. Prove a publication naming paths without the author's active path leases, an unowned task, or a
    mismatched `working_root_id` is rejected; an introduced commit that changes then reverts an
    unleased/control path is also rejected even though the net tip diff is clean. Reject staging from
    a device other than `author_device_id`, bundles without exactly one base prerequisite and one
    synthetic head, an over-parent nested commit, empty-path history, and a tip tree equal to base;
    cross-device
    `publication.review` succeeds, same-device agent review fails, explicit local human review
    succeeds and is labeled self-review, and only the daemon constructs artifacts.
24. Prove a session's aggregate outbound connections reach only multicast, explicit manual
    endpoints, direct discovery guesses on selected interfaces, and admitted members' valid
    target-signed or successfully authenticated endpoints, with no DNS or telemetry destination;
    replay/replace/expire signed endpoint sets and restore an older local endpoint counter without
    indefinite lockout; expire nonmanual guesses at seven days, retain manual entries, accept a
    manual IPv6 link-local endpoint only with a valid local zone, and reject every route that no
    longer leaves on a selected interface —
    the egress assertion for "content stays in the authorized set".
25. Inject a reducer divergence, current covered-row corruption, old result/event mutation, and
    same-position head mismatch. Prove stale checkpoint interleaving is only a replicated rejection;
    actual integrity failure stops apply, preserves evidence, and never self-repairs; incremental
    checkpoint catches current projection/head mismatch, full `state scrub` catches historical
    mutation, and `state recover` rebuilds without forking the session.
26. Delete one active member's local session state while retaining its installation identity. Prove
   a marker or unauthenticated peer cannot restore trust; an owner-targeted invite, identity match,
   exporter proof, and two-sided SAS rebootstrap the same `device_id` without a second admission,
   while a revoked device or different key fails; all stale sessions owned by that device end and
   release their claims/leases before a new local agent can start.
27. Catch up a staging Raft nonvoter through a compacted `InstallSnapshot`, verify its local
    snapshot baseline and post-baseline command bindings across restart, then promote it. Separately
    catch up a settled nonvoter solely through signed result batches/snapshots, back it up, restore
    it, and recover quorum from it after voter loss. Verify contiguous attestation coverage,
    authority handoffs, equal heads/state, greatest-`result_index` survivor selection, and canonical
    object availability; at no point may it create Raft provenance or advance
    `last_raft_applied_log_index`.

Same-device regression additionally proves hundreds of sequential unique **agent** sessions within
one CodeComm session with at most 32 active, identical labels remaining distinct, no actor/origin
cross-talk, correct grouped presence/claims/leases, local visibility without network, worktree
ownership, selector non-reuse, per-agent context files/Self sections, shared-root honesty, and
32-agent responsiveness.

Multi-session regression proves, on one device with two or more joined workspaces: correct
daemon selection by flag, by working-directory ancestry, and by sole-registry-entry fallback,
with an explicit failure listing candidates when ambiguous; no shared state, port, socket, or
Git store/quarantine/ref namespace between sessions; one device identity key reused across sessions while
credential epochs and roles stay independent; a killed session daemon restarting without
disturbing its sibling; supervisor restart reconciling a registry containing one live and one
dead entry; native filesystem/Git-common-directory identity rejecting symlink, junction, case, and
copied-marker aliases; refusal to start a second daemon for one workspace; the concurrent-session cap
refusing rather than evicting; and an MCP client remaining bound to its resolved session for
its lifetime.

### 12.4 Security, platform, and longevity

Security tests cover spoofed discovery/genesis, invite replay/guessing/leakage, exact-ALPN downgrade/
confusion attempts, expired/revoked/stale credentials, cross-profile certificates or content-API
access from pairing/consensus connections, 0-RTT/ticket/PSK resumption attempts, stale-minority
renewal and forged clock endorsements,
identity-proof replay, stale leaders/unauthorized voters, forged and
replayed checkpoints/handoffs, a tampered event or rejection inside an otherwise valid exported range, a chain
segment spliced from a different session, cross-context signature reuse under the wrong
domain label, cross-session Git store/ref/receipt confusion, network reachability of local APIs,
local bind/request-ID/actor/resume spoofing, remote agent control attempts, `receive-pack`/user-ref/arbitrary-OID
requests, launch-selector replay/metadata/root spoofing, reserved-ref tampering, malicious control
files, tampered bundles/binaries/updates, shell metacharacters,
hooks/helpers/filters/alternates/submodules/LFS,
traversal/symlink/Windows names, forged/replayed/oversized events and control-file artifacts,
control-path materialization through Git operations, decompression bombs, inert
SQL/page/WAL payloads, secrets, and terminal escapes.

Continuously fuzz discovery, signed endpoint sets, invites, event/result-batch/snapshot-root/page/chunk decoding, paths, ignore rules, MCP
args, REST, Git ref advertisements/staging receipts/draft and artifact manifests, both certificate extension
forms, every consensus-proof mode, local HTTP framing/bind transitions, and the JCS canonicalizer differentially against a reference
implementation; retain minimized crashes. Also run a structure-aware differential reducer fuzzer
driving two independently constructed replicas from one command stream, asserting equal event/result
heads, canonical outcomes, and projection accumulator at every comparable result index, plus equal
full state digests at sampled trust boundaries. A model checker explores
bounded election, duplicate, CAS, authority-transition, lease-timer, and crash schedules and replays
counterexample traces against the real harness. CI runs
secret/dependency/license/SBOM/static scans
and verifies artifacts after signing.

Native tests use Linux case-sensitive FS, default macOS APFS plus one case-sensitive volume,
and native Windows NTFS/named pipes/Credential Manager/Task Scheduler/Firewall on supported
x86-64/ARM64. Cover service lifecycle, IPC ACL, credential store, firewall, multicast
interfaces, config ownership/ACLs, Ethernet/VPN, Git, path limits, sleep/wake, and reboot. PRs use MCP
simulators; nightly/release smoke supported installed Codex/Claude versions. TUI golden/PTY
tests cover narrow/normal/wide terminals, long IDs, hostile control characters, `NO_COLOR`,
and a monochrome profile proving every state at §9 is distinguishable without color.

Benchmarks track command/event/result transaction and projection throughput, catch-up at
1/10k/1M results with mixed acceptance, one
session at 8 devices/32 agents/100k files/2 GiB, one device at the concurrent-session cap
running that many daemons and Git stores at once, bootstrap/publication/draft bundles, and large
TUI histories by commit/OS. Material regression requires review. Seeded nightly soak/chaos
spans many credential epochs, authority/voter changes, elections, artifact resumes, agent churn,
checkpoints, drafts, publications, and restarts.

### 12.5 Gates

Every PR: format/lint/static/dependency policy, unit/component, race detection,
contract/golden/migration, deterministic model/trace replay and bounded linearizability,
bounded multi-daemon, same-device multi-agent, security regression,
critical-module coverage floors without unexplained decrease, **a deterministic-failpoint durability
subset** (crash between Raft commit and SQLite apply, a failpoint on the §5.3 step-7 transaction, and
one ENOSPC on each of the Raft, SQLite, and Git-artifact paths), and **a current + N-1 mixed-version
bounded cluster including scenario 9** — the last two promoted from nightly because they are the sole
proofs of the acknowledged-loss, idempotent-resumption, and no-divergence invariants, and a
regression found nightly has already merged.

The mechanically checkable part of §11's production-quality criterion maps to named gates:

| §11 requirement | Enforcing gate |
|---|---|
| Explicit boundaries, acyclic dependencies | Import-cycle and layering lint |
| No ignored errors on security/durability/process/network paths | `errcheck`-class lint, no blanket suppressions |
| Deadlines and cancellation propagated | `lostcancel`-class lint plus a context-propagation test at each boundary |
| Peer, repository, or input errors never panic the daemon | Panic-boundary test driven by the existing fuzz corpus |
| Every bound has a normative value | Conformance test maps every field to its closed owning schema and every allocation/queue/cross-cutting limit to §11.2; it checks all mutable-policy ranges, relations, and current-use guards |
| No secrets in URLs, argv, env, or logs | Artifact scan over logs, crash reports, and process metadata |
| Insecure dev wiring absent from releases | Build-tag check that no release artifact contains it |

The judgement-based remainder of §11 — naming, altitude, documentation quality — is a review
checklist item, not a gate.

Nightly/main: full native matrix, fuzz, fault, performance, and soak.

Release: all OS/architecture packages; upgrades from supported DB/protocol versions;
install/reboot/join/revoke/elect/replace-voter/recover-quorum/uninstall/rollback; physical or
VM Ethernet/VPN multi-device run including all voters waking with expired credentials;
Codex/Claude smoke; SBOM/dependency/signature verification; zero unresolved critical/high
security or data-loss failures. Retained diagnostics MUST be redacted; leaking test artifacts
block release.
