# CodeComm V1 Design — Part 11: Implementation, Versions, and Constants

Part 11 of 14. Contents: §11 language/dependency choices, §11.1 version floors, §11.2 constants, production-quality criteria.
Section map, review status, and reading order: [README.md](README.md)

Authoritative revision 0.14; maintained only in this split set.

Normative terms follow RFC 2119/8174; declarative requirements and table rows headed "MUST" or
"Required" are equally normative.

---

## 11. Implementation and Production Engineering

V1 is implemented in Go due to networking/TLS, deployment, cross-compilation, concurrency, and
ecosystem fit. Candidate dependencies, after maintenance/license/security review:

- Bubble Tea-equivalent TUI, `net/http` TLS 1.3, maintained SQLite driver;
- maintained embedded Raft plus production stable store;
- maintained MCP SDK;
- stdlib `crypto/ed25519` and `crypto/sha256`; a reviewed RFC 8785 JCS canonicalizer, or a
  small audited in-tree implementation, since the test vectors are fixed and the primitive
  is frozen by §12.2 fixtures;
- system Git;
- Unix sockets, Windows named pipes, native credential-store adapters.

Rust/Tokio/Axum/Ratatui/SQLite remains a documented alternative, not an unresolved choice; switching
before phase 1 requires a superseding ADR and revised platform/tooling gates. Do not implement
cryptography, PAKE, consensus, a Git object database, or a merge engine.

**Configuration contract.** V1 reads one strict, versioned TOML file:
`<OS user-config dir>/codecomm/config.toml`, where the directory comes from the native platform API
(`XDG_CONFIG_HOME`/`~/.config`, macOS Application Support, or Windows AppData). `config_version = 1`
is required; duplicate or unknown keys, unknown enum values, type/range errors, and trailing
documents reject the whole file before listeners, stores, or child processes start. The
`codecomm/` directory and file are created owner-only (`0700`/`0600` on Unix; an equivalent
current-user DACL on Windows); the file must be regular, non-symlinked, and owned by the current
user. Its encoded size is checked against §11.2 before TOML parsing or proportional allocation; an
oversized file rejects as one configuration error.

Precedence is built-in defaults, then file, then schema-allowlisted explicit flags on a foreground
invocation. CodeComm defines no environment-variable configuration overrides, and flags cannot
disable authentication, validation, durability, redaction, limits, or another production safeguard.
The file contains only local operating choices such as selected interfaces, listen port, logging,
and resource concurrency. It contains no secret/private key, invite, capability, session membership,
committed protocol policy, or insecure development switch. Configuration is parsed into a typed
immutable value and validated atomically; there is no live reload in V1, so a valid edit takes effect
only on the next supervisor or session-daemon start. `codecomm config validate [--file PATH]` performs
the same parse without side effects, and `codecomm config show` prints effective non-secret values
with their default/file/flag source.

Schema validation does not reject a valid Git quota merely because existing session data already
exceeds it. On daemon start, actual charged use determines §8.1's `git-storage-over-quota` admission
state; protected data remains available and only quota-growing work stops.

### 11.1 Supported versions

| Component | Floor | Why this floor |
|---|---|---|
| Go | 1.26 | Supported toolchain baseline; release builds also test the current stable release |
| Git | 2.38 | Bundle v3, protocol v2, stable `bundle verify`, `merge-tree`, and mature `worktree`/plumbing |
| SQLite | 3.42 | `PRAGMA optimize`, defensive settings, stable WAL behavior |
| Windows | 11 24H2 / Server 2022 | Native security/service APIs; EOL Windows 10 is not a release target |
| macOS | 14 | Supported Keychain/APFS baseline |
| Linux | glibc 2.31 or musl 1.2, kernel 5.10 | Secret Service, `SO_PEERCRED`, `systemd --user` |
| Codex CLI, Claude Code | the two most recent minor releases of each, restated per CodeComm release | MCP surfaces move faster than this doc |

V1 supports and tests repositories whose Git object format is `sha1` or `sha256`; a session fixes one
format in genesis and never mixes them. CodeComm's SHA-256 artifact digest is independent of that
repository format. On an unsupported version CodeComm refuses to start with the detected and
required versions named, except for Codex and Claude Code, where an unsupported client is admitted
with a visible warning.

### 11.2 Constants

This section owns cross-cutting policy and operational constants. Fixed field-level bounds remain in
their owning closed schemas (§§5–8) and generated contract fixtures; they are not duplicated here.
The Scope column uses **Committed** (genesis agreement; mutability follows §4.2), **Local** (fixed or
configured per installation and never reducer input), **Derived**, and **Local at issue** (the
issuer-local invite cap). A reducer input MUST be Committed; reading Local state is a divergence
defect.

| Constant | Value | Scope |
|---|---|---|
| `credential_epoch_seconds` | 1800; fixed in V1 | Committed |
| `credential_overlap_seconds` | 120; fixed in V1 | Committed |
| `credential_renewal_lead_seconds` | 300; fixed in V1 | Committed |
| `checkpoint_events` / `checkpoint_interval_seconds` | 500 / 300 | Committed |
| `lease_min_ttl_seconds` / `lease_default_ttl_seconds` / `lease_max_ttl_seconds` | 30 / 900 / 3600 | Committed |
| `agent_claim_limit` / `agent_lease_limit` | 8 / 32 | Committed |
| `primitive_suite_version` / `protocol_policy_version` | 1 / 1 | Committed, immutable in V1 |
| `digest_version` / `projection_schema_version` | 1 / 1 | Committed, immutable in V1 |
| Event-chain / result-chain version | 1 / 1 | Committed, immutable in V1 |
| Maximum signed-JSON nesting depth | 32 | Committed, immutable in V1; strict decode before signature work |
| `cluster_min_apply_level` | 1 at V1 creation | Committed |
| `multicast_ipv4_group` / `multicast_ipv6_group` / `multicast_port` | `239.192.71.31` / `ff12::c0de:c031` / 47831 | Committed, immutable in V1; IPv4 must be in `239.192.0.0/14`, IPv6 transient scope 2-8, port 1024-65535 |
| `advertisement_interval_seconds` | 20; multicast base cadence `min(value, 48 s)` with independently sampled uniform jitter ±25%; TTL/hop-limit 1; ≤1200 bytes | Committed |
| `endpoint_hint_ttl_seconds` | `8 * advertisement_interval_seconds` | Derived |
| `voter_reconcile_deadline` | 30 s; an unfinished voter-set transit past this surfaces the `reconciling` state (§3, §9) | Local |
| HTTPS port | 47831 default, configurable; per session, so concurrent sessions take the next free port | Local |
| Invite TTL / outstanding cap | 15 min / 8 | Local at issue |
| Owner-recovery challenge TTL / outstanding cap | 5 min from durable reservation creation / 1 per device | Local |
| Discovery `expires_at` window | ≤60 s future | Local |
| `endpoint_guess_ttl_seconds` | 604,800 (7 days) from latest local observation/authentication | Local; applies to expired signed-set addresses and authenticated destinations, never raw discovery or manual endpoints |
| `credential_clock_skew_seconds` | 120; activation check is lenient, expiry has no added grace (§4.6) | Local |
| Discovery nonce cache | 256 per source, 5 min TTL | Local |
| Agent heartbeat / disconnect grace | 10 s / 90 s | Local |
| Draft debounce / minimum snapshot interval | 2 s / 5 s | Local |
| Draft manifest expanded maximum | 128 MiB and at most the 100,000-file workspace ceiling | Local hard input bound; parsed streaming before object visibility |
| Draft retention ceiling / explicit-pin cap | newest 100 unpinned snapshots per source device across streams / 256 pins per session | Local |
| Concurrent sessions per device | 4, fixed in V1 | Local hard ceiling |
| `config_file_max_bytes` | 1 MiB | Local hard input bound; enforce before TOML parsing |
| `selected_interfaces_max` | 32 per installation | Local hard configuration bound; interface addresses are further limited by endpoint-set caps |
| `max_event_bytes` | 256 KiB | Committed, immutable in V1; reducers reject larger signed events |
| `event_path_array_max_bytes` | 192 KiB JCS-encoded per event `paths[]` array | Committed, immutable in V1; combines with the 512-byte path and item-count bounds |
| `activity_duration_max_ms` | 604,800,000 (7 days) | Committed, immutable in V1; bounds optional `actions[].duration_ms` |
| `task_dependency_walk_max` | 4,096 distinct task rows | Committed, immutable in V1; bounded deterministic cycle walk rejects before visiting row 4,097 |
| `control_file_max_bytes` | 1 MiB | Committed, immutable in V1; reject before artifact fetch (§8.4) |
| `control_file_diff_max_bytes` | 64 KiB | Committed, immutable in V1; review aid only (§8.4) |
| `control_path_policy_version` | 1 | Committed, immutable in V1; exact classifier in §8.4 |
| Snapshot signed-root / descriptor-page encoded maximum | 64 KiB / 4 MiB | Local, enforced before allocation |
| Snapshot data-chunk compressed / expanded maximum | 4 MiB / 64 MiB | Local, enforced before allocation |
| Replication-batch compressed / expanded limit | 4 MiB / 64 MiB | Local, enforced before allocation |
| Local IPC JSON body maximum | 1 MiB | Local; event payload remains subject to `max_event_bytes` |
| Local IPC endpoint maximum | Unix socket path: 103 bytes; Windows named-pipe path: 256 ASCII characters | Local; registry-issued endpoint fails before listen/dial when exceeded |
| Generated context cap | 256 KiB per agent/output file (§7.3) | Local |
| Context record counts | 200 tasks / 50 memory / 100 activity / 8 devices / 32 active agents | Local maxima subordinate to encoded-byte budgets (§7.3) |
| SQLite busy timeout | 5 s | Local |
| Reconnect backoff | 250 ms base, ×2, cap 30 s, ±25% jitter | Local |
| Log retention | 7 days or 100 MiB per session, whichever first | Local |
| Pairing message / invite endpoint-hint count | 64 KiB / 16 | Local hard input bounds; invite secret and nonce lengths remain protocol-fixed (§4.5) |
| Signed endpoint-set encoded maximum | 16 KiB | Local hard input bound before JCS/signature work (§4.4) |
| `endpoint_hints_per_member_max` / `manual_endpoints_per_member_max` / `endpoint_hints_per_session_max` / `manual_endpoints_per_session_max` | 16 / 16 / 128 / 128 | Local hard ceilings; latest valid signed sets replace atomically, nonmanual guesses expire then evict oldest, and manual additions refuse at capacity (§§2.3, 4.4) |
| TLS/pairing handshake timeout / pending cap / source rate | 10 s / 32 per daemon / 10 attempts per source IP per minute, burst 20 | Local, before expensive certificate/pairing state |
| `handshake_tracked_sources_max` / `handshake_source_idle_seconds` / `handshake_state_max_bytes` | 1,024 / 600 / 8 MiB | Local; expire then evict oldest idle source, otherwise silently drop excess attempts (§4.6) |
| Peer HTTP limits | 32 KiB headers; 1 MiB JSON body unless an endpoint-specific bound applies; 256 list items/page; 128 active handlers/daemon | Local hard ceilings |
| Peer HTTP/2 limits | 32 control streams/connection; 128 inbound connections/daemon; per peer/direction, 1 consensus and 1 content-control + 2 content-bulk connections | Local hard ceilings; bulk carries one artifact stream; rollover permits one draining predecessor per content slot with no new streams |
| Connection/stream liveness | 10 s request-header timeout; 120 s idle connection; 30 s stream no-progress timeout; SSE keepalive 15 s | Local; long transfers resume by digest/offset |
| Local IPC limits | 128 connections and 64 active handlers/daemon; 32 KiB headers; 10 s header and 120 s body/idle timeout | Local hard ceilings; one non-pipelined request/connection at a time |
| Pending local work | 256 unresolved commands/origin scope, 4,096/session; 64 queued Git transfers/session | Local hard ceilings; refusal occurs before request mapping/signing |
| Ephemeral state | Presence expires after 30 s; rejection aggregates hold at most 1,024 keys/session, oldest-first | Local |
| Child-process deadline | Git child 30 min, then 5 s graceful termination before force-kill | Local hard ceiling |
| Temporary artifact retention | Incomplete/unreferenced artifacts expire after 24 h idle; retain at most 2 completed logical snapshots | Local; protected Git refs follow §8.1 instead |
| Supervisor restart circuit | 5 failures in 10 min, then blocked until explicit retry or configuration change | Local |
| `merge_inputs_version` / merge profile | 1 / `merge.renameLimit=10000`, `merge.renames=true`, `merge.conflictStyle=zdiff3`; publication path diff always `--no-renames` | Committed, immutable in V1 (§§7.2, 8.3) |
| `device_claim_limit` / `device_lease_limit` | 64 / 256 | Committed aggregate bound (§10) |
| `audit_depth_per_device_per_epoch` | 256 `audit.recorded` events per subject/latest credential epoch | Committed — bounds explicit rejection audits (§5.4) |
| `publication_receipt_window_results` | 100,000 result positions | Committed, immutable in V1 — bounds use and retention of pre-proposal staging receipts (§§7.2, 8.1) |
| `publication_introduced_commit_max` / `publication_changed_edge_max` / `publication_parent_max` | 4,096 commits / 100,000 changed path-edge records / 16 parents per introduced commit | Committed, immutable in V1; bounds §7.2's full introduced-history authorization walk |
| `publication_staging_pin_cap` | 64 per session | Local hard ceiling; reserve before transfer and release the slot on proposal acceptance, committed rejection, or receipt-window expiry (§8.1) |
| `publication_starvation_threshold` | 5 consecutive stale lineage attempts | Local diagnostic; no rejected command mutates projections (§7.2) |
| Context encoded-byte sub-budgets: fixed core / Peers+drafts / Work / Plan / Memory / Activity | 64 / 32 / 64 / 16 / 40 / 24 KiB | Local; total 240 KiB leaves 16 KiB structural overhead (§7.3) |
| Per-field context string length | 1024 bytes | Local — truncate long peer-authored bodies rather than dropping whole records (§7.3) |
| `max_member_devices` / `max_active_agent_sessions` | 8 / 32 | Committed; reducers count active rows only (§2.2) |
| Discovery rate limit / `discovery_tracked_sources_max` / discovery state ceiling | 20 datagrams per source per minute / 1024 sources / 8 MiB | Local, enforced before signature work (§4.4) |
| Invite-proof attempts per invite / per source per minute | 3 / 10 | Local (§4.5) |
| `peer_control_rate_per_device` / `peer_proposal_rate_per_device` | 200/s sustained, burst 800 / 50/s sustained, burst 200 | Local per receiver; authenticated non-bulk requests consume control budget and event proposals consume both (§5.1) |
| `leader_ingress_rate_per_device` | 50 proposals/s sustained, burst 200 | Local, applied on the leader before `raft.Apply` (§10) |
| Bare-store unreachable-object/reflog grace | 14 days / 14 days; `gc.auto` disabled, explicit GC holds the import/GC mutex | Local (§8.1) |
| Live canonical duplication baseline | Two object copies: session bare store plus user `.git`; retained history is additional and quota-charged | Local (§8.1) |
| `session_git_storage_limit_bytes` | 16 GiB default, configurable 8 GiB-1 TiB; includes bare store, quarantine, artifacts, control content, conflict worktrees, and temporary bundles | Local hard admission quota (§8.1) |
| Git import reservation | `2 × declared artifact bytes + 64 MiB`; the complete reservation must fit the session quota and available disk before transfer | Local (§8.1) |
| Workspace / single file hard preflight | 100,000 files / 2 GiB / 100 MiB | Local; reject before Git bootstrap/draft capture |
| Bootstrap / draft-publication artifact maximum | 4 GiB / 2 GiB | Local hard input bounds |
| Git bundle header encoded / record maximum | 1 MiB / 16,384 prerequisite+ref records before PACK | Local hard input bound; publication normalization further requires one final prerequisite and head |
| Concurrent Git children | 4 per daemon, 12 per installation | Local; queued with backpressure |
| Coordination-state growth warning threshold | 2 GiB combined `state.db` + `consensus/` | Local — history is unprunable in V1 (§10.1) |
| Projection-mutation encoding ceiling | 32 MiB | Local hard ceiling above the worst valid 64-claim/256-lease session-end cascade; exceeding it is an implementation/integrity failure, not a replicated domain rejection |

Committed values are set at `host`; only §4.2's mutable allowlist may later change through an
owner-proposed `policy.changed`. Genesis and every update MUST satisfy these immutable V1 bounds:

| Mutable key | Inclusive hard range / relation |
|---|---|
| `checkpoint_events` / `checkpoint_interval_seconds` | 100–10,000 / 60–3,600 |
| `lease_min_ttl_seconds`, `lease_default_ttl_seconds`, `lease_max_ttl_seconds` | Each 30–86,400; min ≤ default ≤ max |
| `agent_claim_limit` / `agent_lease_limit` | 1–64 / 1–256 |
| `device_claim_limit` / `device_lease_limit` | 1–256 / 1–1,024; each ≥ its per-agent counterpart |
| `advertisement_interval_seconds` | 5–300 |
| `audit_depth_per_device_per_epoch` | 16–1,024 |
| `max_member_devices` / `max_active_agent_sessions` | 1–8 / 1–32 |
| `cluster_min_apply_level` | 1–2,147,483,647; monotonic and no greater than any active device's committed `max_apply_level` |

A policy update validates the complete resulting object atomically and cannot lower a member,
agent, claim, or lease cap below replicated current use. TTL and checkpoint units are integer
seconds. The hard ranges are reducer constants: configuration cannot override them, and changing
them requires a new protocol-policy version and ADR. Other immutable values likewise require a new
protocol-policy version and session, not an event.

Production quality is a release criterion:

- Maintain explicit domain/consensus/transport/storage/repository/agent/UI/platform boundaries and
  acyclic dependencies.
- Decode untrusted input once into bounded typed versioned structures; avoid untyped
  business data, reflection-driven logic, and string protocols.
- Validate every external value/transition. Return stable structured errors with causal
  context; peer/repository/input errors MUST NOT panic the daemon.
- Propagate deadlines/cancellation through network, DB, Git, child processes, and
  shutdown. Bound queues, tasks/goroutines, bodies, expansion, retries, connections, caches,
  and child resources.
- Use backpressure; never silently drop durable work. Retry only transient errors with
  capped exponential backoff and jitter.
- Make startup/shutdown idempotent and crash-safe: drain accepted work, close listeners,
  persist/checkpoint, reap children, and recover every boundary.
- Use atomic replacement, explicit modes/ACLs, canonical paths, symlink checks, required
  directory durability, direct argv, and sanitized child environments.
- Keep config typed/versioned/validated/secure by default. Insecure test/dev wiring MUST be
  constructor/build-only, visibly reported, never remotely enabled, and absent from releases
  when it weakens security.
- Use redacting secret types; exclude secrets from URLs/argv/logs, minimize lifetime/copies,
  and erase mutable buffers where meaningful.
- Emit structured rate-limited logs and bounded metrics for correlation IDs, queues, quorum,
  replication/object lag, Git child failures, and DB latency without source content. Distinguish
  liveness, readiness, quorum, peer, and repository health.
- Make migrations/wire changes checksummed, replayable, crash-safe, fixture tested, and
  reversible or guarded by verified backup/rollback boundary.
- Pin dependencies/lock metadata, verify signatures/checksums, generate SBOM, review
  licenses, scan vulnerabilities, remove unused/convenience attack surface, and support
  signed reproducible packaging/rollback.
- Require formatting, lint/static analysis, race detection where available, parser fuzzing,
  and no ignored errors in security/durability/process/network paths. Every suppression
  needs reason, owner, and review.
- Document public interfaces, invariants, lock/order rules, failure/recovery, security
  assumptions, and operator runbooks. Material changes require ADR and compatibility review.
- Require focused review for crypto, identity/auth, consensus, migrations, paths, process
  execution, and updates. No critical path ships with placeholder behavior, unowned TODO,
  fail-open flag, skipped test, or platform-disabled security/durability.
- Implement native Windows/macOS/Linux adapters and tests; do not fake parity by weakening
  the hardest platform.
