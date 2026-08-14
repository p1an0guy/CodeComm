# CodeComm V1 Design — Part 13: Delivery, Service Targets, Open Questions, and Risks

Part 13 of 14. Contents: §13 delivery phases, §14 service targets, §15 open questions, §16 key risks.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 13. Delivery

1. **Security/dependency spikes:** threat model/ADRs; Raft/library/store review and 3-voter
   crash/election spike; prove one-port, plane-specific ALPN certificate selection and closed
   dispatch with full handshakes and no 0-RTT/resumption; prove RFC 8441 Raft CONNECT framing,
   pseudo-headers, SETTINGS, flow control, half-close, cancellation, and stream bounds; confirm the leader-side apply
   barrier and the production stable store's crash/fsync behavior on the real API, and prove §3's target-applied
   checkpoint fallback and remote authority-signing mode without a public `matchIndex`; prove
   settled-nonvoter attestation/backup evidence without fabricated Raft provenance; freeze canonical
   UUID/timestamp/OID, genesis-version, event/result-chain, checkpoint/snapshot, local-IPC, and
   recovery-transform fixtures; mTLS
   pairing with exact exporter transcript and DER certificate profiles, revocation, quorum clock
   endorsements, on-time and next-day 30-minute content renewal,
   and all-devices-asleep recovery by ordinary election;
   multicast/Ethernet/VPN on all OSes; system-Git `sha1`/`sha256`
   bundle/protocol-v2/quarantine/fsync/ref-policy spike;
   prove local APIs unreachable; establish native CI/harness.
2. **Local coordination:** daemon/SQLite/reducers/local API/TUI; one-use agent-launch registry,
   MCP/CLI adapters, per-agent contexts, canonical managed-root registry, both apply-time chains,
   durable local request mapping, worktrees, control-file review; permanent local multi-agent and DB recovery
   tests.
3. **Secure mesh:** discovery/pairing/membership/roles/revocation; direct mTLS, SSE/resume;
   Raft replication/election/voter changes; activated-authority handoff and result catch-up;
   identity-authenticated consensus plane and 30-minute quorum-authorized content credentials.
4. **Git bootstrap:** bounded bundle transfer/verification/no-checkout clone, immutable
   dirty/untracked draft, sparse control-path guard, progress/cancel/expiry/recovery, cross-platform
   preflight.
5. **Git object/ref mesh:** session bare stores, exclusive expected-old-OID-CAS CodeComm refs,
   read-only upload-pack, independent sparse drafts, quorum-staged publications, canonical-ref CAS,
   deterministic merge conflicts, bounded stream retention/storage, explicit bare-store GC, and
   revocation.
6. **Hardening:** signed installers/services, native E2E/security/performance, backup/export,
   physical Raft/SQLite compaction without logical-history pruning, and voter/quorum recovery.

Every phase retains foreground development mode and automated gates. No phase adds custom
consensus, crypto, Git-object, or merge engines. Every phase MUST also close the open questions §15
assigns to it before it exits.

Phase 2 is the **walking skeleton**: one device, one session, a real single-voter Raft per §3,
real SQLite, two MCP clients, and a task claimed by one and observed by the other. It
exercises the whole vertical — event, consensus, reducer, projection, context, adapter — and
every later phase widens it rather than replacing a layer.

Exit criteria as demonstrable facts:

| Phase | Exits when |
|---|---|
| 1 | The real Raft library needs no pre-commit index; staging apply and authority checkpoint signing work through the closed proof endpoint; targeted transfer, single-server reconciliation, snapshot catch-up, `{A}→{B}`, unreachable-voter 3→1, canonical-coverage gating, activated-authority handoff, and crash at every step pass. Stable-store fsync/apply barriers are proven or the library is replaced. Exact pairing-exporter/DER profiles, ALPN/certificate dispatch, and TLS no-resumption rules pass; next-day renewal works; canonical IDs/times/OIDs, immutable genesis suite/policy versions, signed-genesis/event/result vectors, result batches across authority changes, cut-authorized snapshots, settled-nonvoter attestations/backups, exact recovery transform, and local-IPC framing/binds are frozen; Git merge/quarantine/import fixtures, including exact publication prerequisite/head and raw-NUL path parsing, pass on all OSes and both object formats; local APIs are remotely unreachable |
| 2 | The walking skeleton runs; concurrent MCP clients have distinct IDs and binding-specific context pairs; launch reservation/crash/replay and shared-root no-cross-talk pass; pre-existing roots and canonical repository aliases are refused; exact/changed local request replay and crash recovery pass; disconnect/resume/reap CAS and stored-state restoration pass; both chains and every §5.4 outcome round-trip; task/lease races and per-agent/device/session caps pass; dependency walks enforce their exact boundary; idle/busy lease expiry and intended-device claims pass; a `SIGKILL`ed daemon recovers with equal heads/digest; closed activity/audit projections and version+digest-bound control manifests are frozen fixtures |
| 3 | Two devices pair with SAS confirmation and no manual endpoint entry; exact target-signed endpoint sets relay as opaque bytes, validate issued/expiry time, expire, reject rollback, age out guesses, obey selected-interface routes, and recover after local-state loss. A 3-voter cluster elects, replicates, changes voters, and preserves the old credential authority until every target proof and handoff commits; every configuration call is blocked by the no-bypass canonical-coverage gate and succeeds in integration only from actually verified pre-seeded fixture repositories. Revoking a nonvoter changes no target/authority version; a stalled target does not block renewal. Credentials rotate under load; all-sleep wake restores ordinary Raft; revocation meets §14; a minority commits, promotes, and authorizes nothing; result catch-up crosses authority transitions and converges to equal heads/accumulator/state digest; divergence fails closed; the documented two-device degraded run and voter-placement prompt pass |
| 4 | A joiner bootstraps from a verified bundle over mTLS into a private destination whose control paths are sparse-excluded before first checkout and held for local review; dirty/untracked work arrives only in the exact self-describing/non-identifying sparse container; interrupted transfer resumes; draft import leaves index, `HEAD`, user refs, and working tree untouched; the production local-Git coverage provider verifies exact canonical possession before signing |
| 5 | Eight devices exchange sparse drafts/publications directly in both object formats; draft artifacts contain only manifest/upsert closure and survive sequence gaps without predecessor artifacts; publications enforce the parent/commit/edge-bounded exact introduced-history walk rather than a net tip diff, reject empty/no-op history, and conflicted rebases resolve through ancestry-preserving merge publications. Staging and canonical-coverage receipts survive voter replacement; each staging receipt is bound to one reserved proposal event, rejected-attempt replay fails, abandoned pins obey their result window/cap, applied pins release only after canonical ancestry protects them, and rejected/withdrawn pins release unless a conflict protects them; concurrent canonical CAS has one winner; reserved-ref inventory and expected-old-OID tamper tests pass in the bare store and user repository; cross-device MCP review succeeds while same-device agent review fails; starvation surfaces and clears after quiescence; branch/reset/stash remain local; duplicate conflict detectors converge and a reviewed merge resolves; revocation stops object access; stream churn, quota, restore/refetch/retention/GC preserve protected refs; OQ2 and `repo include` consent rules close; the ASCII-folded frozen control-path classifier, including nested `.gitignore`, and managed guards prevent canonical control bytes from materializing; oversized or mismatched control artifacts never apply |
| 6 | Signed installers on all three OSes; §14 targets are confirmed or revised with evidence; Raft and settled-nonvoter backups/export and physical compaction preserve full logical history; active-owner-identity and active-editor-plus-recovery-key quorum recovery verify predecessor evidence, rotate the key, withdraw nonterminal publications, retire draft streams, preserve only selected canonical lineage pins, and readmit survivors end to end |

## 14. Service Targets

Each latency target names its start point, end point, and enforcing gate. Workload is one
session at 3 voters, 8 devices, 32 agents, 100k files, and 2 GiB on a quiet gigabit LAN unless
stated.

| Metric | From | To | Target | Gate |
|---|---|---|---|---|
| Coordination visibility | `POST /v1/events` accepted at the origin | that event applied and visible in a peer's `context.get` | p95 <500 ms | Nightly performance |
| Same-device visibility | MCP call accepted | visible to another agent on the same daemon | p95 <100 ms | Per-PR multi-agent |
| Draft visibility | eligible last write closed on the origin | immutable draft ref and verified 1 MiB object available on one peer | p95 <10 s | Nightly performance |
| Canonical materialization | `publication.applied` committed | verified object and `refs/codecomm/canonical` updated on a reachable peer | p95 <2 s | Nightly performance |
| Reconnect after brief drop | link restored | control and Git transfer available | p95 <5 s | Nightly fault |
| Leader replacement | leader process killed | new leader committing | p95 <5 s | Nightly fault |
| Revocation effect | `membership.device_revoked` committed | every active reachable peer has applied it and refuses the device on both planes that applied it | <5 s | Per-PR security |
| Single-device wake recovery | expired member resumes while a current voter quorum is reachable | ordinary credential renewed and peer/Git links restored | p95 <15 s | Nightly fault |
| All-expired recovery | last voter needed for majority resumes after every device exceeded multiple epochs | fresh content credentials issued and normal Raft commits again | p95 <30 s | Nightly fault |
| Catch-up | settled nonvoter starts 10k mixed command results behind | verified result/event heads, accumulator, and state equal the source at one result cut; `last_raft_applied_log_index` remains null/historical | p95 <30 s | Nightly performance |

Resource budgets, at two scopes because §3.2 allows several session daemons per device:

| Budget | Ceiling |
|---|---|
| Idle session daemon RSS | 150 MiB |
| Idle session daemon CPU | <1% of one core |
| Device at the concurrent-session cap | 800 MiB RSS and <4% of one core total |
| Supervisor | 30 MiB RSS, <0.1% CPU; it holds no session state |
| Coordination state growth (`state.db` + `consensus/`, excluding Git objects/artifacts) | ≤50 MiB per 10,000 events in the fixed benchmark mix below |
| Session Git/control/artifact storage | Never admit work above `session_git_storage_limit_bytes`; canonical/conflict/explicit-pin refs are never quota-evicted |
| Unpinned retained drafts | ≤100 snapshots per source device across all streams; ≤256 explicit local pins per session |

The growth target uses a frozen representative mix of bounded task/lease/activity events; it is not
a worst-case claim against 256 KiB events, whose retained bytes are necessarily linear.

Confirmation is split by plane, because three targets measure mechanisms that do not exist until
phase 5: consensus and control targets plus the coordination-growth budget confirm at **phase 3**;
draft-visibility, canonical-materialization, bootstrap, publication, and every disk budget confirm
at **phase 5**. Phase 6 is the revision-review gate, not the first measurement. These values are
provisional until their own phase's benchmarks in §12.4 confirm or revise them with recorded
evidence; each MUST be confirmed or revised before phase 6, and a revision requires
review. They are not advisory in the meantime: a regression against the current recorded value
fails its gate.

The following are invariants, not targets, and live in §2.5: no acknowledged event loss, commits
continuing after one voter loss with three voters, surviving-peer transfers continuing through
leader loss, exactly one winner for concurrent strong claims, no duplicate or reused active
agent IDs, no silent conflict loss, and no remotely reachable MCP or write-capable Git endpoint.

## 15. Open Questions

Only OQ2 remains open, and it is empirical rather than an implementation blocker.

**OQ1 — Activity privacy. RESOLVED (2026-08-06).** Persist names, paths, status, timing, and bounded
summaries; exclude raw arguments/output/environment/secrets/private reasoning (§§5.2, 10.1).

**OQ2 — Scale.** Validate 2–8 devices, 100k files, 2 GiB, 100 MiB/file, and four concurrent sessions.
*Owner:* product. *Close by:* phase 5 benchmark review, when the repository plane exists. The answer changes §11.2 limits, not protocol
shape.

**OQ3 — Two-device posture. RESOLVED (2026-08-06).** Support 1 voter + 1 nonvoter with the persistent
degraded indicator and voter-placement prompt (§§1, 3, 9).

**OQ4 — Draft eligibility. RESOLVED (2026-08-06).** Safe defaults plus local preview-gated per-path
inclusion; secret-shaped paths need a second confirmation and control files are never includable
(§8.1).

Also resolved: owners select current plans; editors propose. Repository synchronization is Git-native
objects/refs and immutable drafts, never mutable working-tree replication.

## 16. Key Risks

1. Authorized source/docs are durable prompt-injection input; provenance cannot replace sandbox and
   approvals (§7.3).
2. Strong writes and credential authorization require quorum; two-device sessions cannot tolerate
   loss of their sole voter.
3. Raft transport/store/snapshot/configuration integration can violate safety; phase 1 must prove the
   exact library APIs or replace the library.
4. Consensus identity credentials do not expire; admission checks, closed ALPN dispatch, applied-
   leader gating, and leader-only replication are load-bearing (§4.6).
5. Clock endorsements depend on an activated-credential-authority majority's clocks and identity
   keys; one-voter sessions have no independent clock witness.
6. A compromised local OS account indefinitely impersonates its installation; recovery is revoke
   and re-pair, not key rotation within `device_id` (§10).
7. One dishonest voter can lie in a result batch, checkpoint, or staging/canonical receipt because
   V1 is not Byzantine tolerant; cross-checks/refetch detect some lies but cannot prevent them (§10).
8. Git objects and publication events are separate durability planes; receipt, pin, canonical-
   ancestry, quarantine, coverage, and reconciliation defects can strand data. Logical-time expiry
   plus a local cap bounds abandoned pre-proposal pins, but an idle session can remain staging-full
   until result progress, rejection, or quota relief.
9. Eight-device meshes and four local sessions amplify connections, Git children, CPU, and disk;
   every queue/process/artifact has admission bounds, but protected refs can fill the configured Git
   quota and then stop repository progress.
10. Filesystem case/Unicode/Windows names/symlinks and supported-Git merge differences can reject a
    repository or conflict result; preflight and golden corpora fail closed.
11. Shared-root agents can ignore advisory leases; immutable commits preserve evidence but do not
    prevent edits.
12. MCP cannot observe all native actions; `capture_level` must remain honest.
13. Session-lifetime event retention means an authorized member can consume disk despite rate/size
    bounds; activity has no fictitious reducer acknowledgement depth.
14. Opt-in draft inclusion can irreversibly share secrets with every member (§8.1).
15. Git reachability/retention depends on ref and GC semantics operators can override; expected-old-
    OID CAS blocks rather than repairs tampering, and refetch needs a surviving receipt holder.
16. LFS, submodules, filters, alternates, ACLs, ADS, and xattrs exceed V1 plain-bundle semantics.
17. Solo self-review is weaker than a second specialist; frozen fixtures and mechanical gates are
    compensating controls, not equivalence.
18. Offline quorum recovery can discard entries acknowledged by the lost majority but absent from
    the chosen survivor; explicit authorization and survivor-head comparison expose rather than
    eliminate that loss (§3.1).
19. The offline recovery key is a break-glass governance root: theft plus control of an active editor
    identity permits owner restoration with quorum or a sibling successor after quorum loss. It
    cannot revive revoked, readmission-required, absent, or never-admitted identities; it is exported
    once, never retained by CodeComm, and rotated only by successor recovery (§§3.1, 10.1).
20. Sparse control-path guards prevent ordinary managed Git operations from activating canonical
    instructions, but the frozen classifier must be revised when a supported client adds a control
    format, and an operator or arbitrary same-account process can deliberately bypass the guard;
    both are explicit release/security-review obligations, while same-account bypass is part of
    risk 6 (§§8.2, 10).
21. MCP class binding does not sandbox a coding agent's separate shell/process tools: a same-account
    process can invoke the operator CLI, and V1 has no sound way to distinguish it from the human
    account owner. Client sandbox/approval policy is therefore the boundary for such invocations;
    the TUI MUST not describe MCP-only verb separation as OS-level agent isolation (§§5.1, 7.1, 10).
22. An admitted member can sign a routed literal it does not own and induce bounded TLS ClientHello
    traffic to it. Literal/special-address checks, selected-route policy, backoff, and expected-member
    authentication prevent DNS, application data, or retained false success, but do not prove address
    ownership (§§4.4, 10).
